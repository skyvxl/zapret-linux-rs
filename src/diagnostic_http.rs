use crate::{
    diagnostic_targets::{Check, Target, valid_url},
    error::{AppError, Result},
    process::{Captured, Managed},
};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

const TRANSFER_LIMIT: u64 = 8 * 1024 * 1024;
const PREFIX_LIMIT: u64 = 65536;

pub struct Probe {
    binary: PathBuf,
    timeout: Duration,
    ca_file: Option<PathBuf>,
    http3: bool,
}

fn setup(message: impl Into<String>) -> AppError {
    AppError::new("curl", message)
}
fn io_error(error: io::Error) -> AppError {
    setup(error.to_string())
}

fn command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    // No implicit proxies, CA overrides, SSLKEYLOGFILE, or curl configuration.
    command
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin:/bin")
        .env("LC_ALL", "C")
        .arg("--disable");
    command
}

fn capture(
    mut running: Managed,
    timeout: Duration,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<Option<Captured>> {
    let start = Instant::now();
    loop {
        tick()?;
        if running.poll()?.is_some() {
            return Ok(Some(running.stop(Duration::ZERO)?.0));
        }
        if start.elapsed() >= timeout {
            running.stop(Duration::ZERO)?;
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

impl Probe {
    pub fn new(
        binary: &Path,
        timeout: Duration,
        ca_file: Option<&Path>,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Self> {
        tick()?;
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(setup("Timeout должен быть >0 и <=60 секунд"));
        }
        let binary = binary.canonicalize().map_err(io_error)?;
        if !binary.is_file() {
            return Err(setup("curl должен быть обычным исполняемым файлом"));
        }
        let ca_file = ca_file
            .map(|p| {
                let p = p.canonicalize().map_err(io_error)?;
                if !p.is_file() {
                    return Err(setup("CA должен быть обычным файлом"));
                }
                Ok(p)
            })
            .transpose()?;
        let mut cmd = command(&binary);
        cmd.arg("--version");
        let output = capture(Managed::spawn(cmd)?, Duration::from_secs(2), tick)?
            .ok_or_else(|| setup("curl --version: timeout"))?;
        if !output.status.success() || output.truncated || !output.stdout_valid_utf8 {
            return Err(setup("Не удалось проверить curl --version"));
        }
        let mut words = output.stdout.split_whitespace();
        if words.next() != Some("curl") {
            return Err(setup("Ожидается версия curl"));
        }
        let version = words
            .next()
            .unwrap_or("")
            .split('.')
            .take(3)
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| setup("Неверная версия curl"))?;
        // 8.4 made max-filesize enforce the cap even without Content-Length.
        if version.len() != 3 || (version[0], version[1], version[2]) < (8, 4, 0) {
            return Err(setup(
                "Требуется curl >=8.4.0 для ограничения потокового тела",
            ));
        }
        let http3 = output
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("Features:"))
            .is_some_and(|l| l.split_whitespace().any(|w| w == "HTTP3"));
        Ok(Self {
            binary,
            timeout,
            ca_file,
            http3,
        })
    }

    pub fn check(
        &self,
        target: &Target,
        quic: bool,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<Value> {
        tick()?;
        let mut result = json!({
            "target":target.id,"service":target.service,"url":target.url,"required":target.required,
            "check":target.check.json(),"transport":if quic {"quic"} else {"tcp"},
            "status":"failed","reason":"request failed","route":"direct",
            "http_status":0,"http_version":null,"effective_url":null,"curl_exit_code":null,
            "timings":{"dns_ms":null,"connect_ms":null,"tls_ms":null,"total_ms":null},
            "timing_basis":"curl cumulative milliseconds since request start",
            "bytes_downloaded":0,"body_prefix_bytes":0,"body_complete":false,
            "transfer_limit_bytes":TRANSFER_LIMIT,"body_prefix_limit_bytes":PREFIX_LIMIT,
            "coverage":"HTTP only; not video playback, websocket session or voice"
        });
        if quic && (!self.http3 || !target.url.starts_with("https://")) {
            result["status"] = json!("unsupported");
            result["reason"] = json!(if !self.http3 {
                "curl has no HTTP3 support"
            } else {
                "HTTP3 requires an HTTPS target"
            });
            return Ok(result);
        }
        if !valid_url(&target.url, &["http", "https"]) {
            return Err(setup("Неверный URL цели"));
        }
        // Anonymous body storage is distinct from Managed's bounded stdout.
        // No path on disk or named temporary file can be replaced by a symlink.
        // SAFETY: static NUL-terminated name; successful fd becomes File-owned.
        let fd = unsafe { libc::memfd_create(c"zapret-http-body".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        // SAFETY: fd was just returned by memfd_create and has no other owner.
        let body = unsafe { File::from_raw_fd(fd) };
        let mut cmd = command(&self.binary);
        cmd.args([
            "--silent",
            "--show-error",
            "--globoff",
            "--proxy",
            "",
            "--noproxy",
            "*",
            "--disallow-username-in-url",
            "--proto",
            "=http,https",
            "--proto-redir",
            if target.url.starts_with("https://") {
                "=https"
            } else {
                "=http,https"
            },
            "--location",
            "--max-redirs",
            "5",
            "--max-filesize",
        ])
        .arg(TRANSFER_LIMIT.to_string())
        .args([
            "--max-time",
            &format!("{:.3}", self.timeout.as_secs_f64()),
            "--connect-timeout",
            &format!("{:.3}", self.timeout.as_secs_f64()),
            if quic { "--http3-only" } else { "--http1.1" },
            "--output",
        ])
        .arg(format!("/proc/self/fd/{}", body.as_raw_fd()))
        .args(["--write-out", "%{json}"]);
        if let Some(ca) = &self.ca_file {
            cmd.arg("--cacert").arg(ca);
        }
        cmd.arg("--url").arg(&target.url);
        // SAFETY: child-only scalar fcntl call; the parent retains CLOEXEC.
        // Managed adds its own pre_exec handler after this one.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = capture(
            Managed::spawn(cmd)?,
            self.timeout + Duration::from_millis(250),
            tick,
        )?;
        let Some(output) = output else {
            result["reason"] = json!("request exceeded bounded timeout");
            return Ok(result);
        };
        result["curl_exit_code"] = json!(output.status.code());
        if output.truncated || !output.stdout_valid_utf8 {
            result["reason"] = json!("curl metadata output invalid or exceeded limit");
            return Ok(result);
        }
        let metadata: Value = match serde_json::from_str(&output.stdout) {
            Ok(v) => v,
            Err(_) => {
                result["reason"] = json!("curl returned invalid metadata");
                return Ok(result);
            }
        };
        let Some(meta) = Metadata::parse(&metadata) else {
            result["reason"] = json!("curl returned missing or inconsistent metadata");
            return Ok(result);
        };
        result["http_status"] = json!(meta.code);
        result["http_version"] = json!(meta.version);
        result["effective_url"] = json!(meta.url);
        result["bytes_downloaded"] = json!(meta.bytes);
        result["timings"] = json!({"dns_ms":meta.dns*1000.0,"connect_ms":meta.connect*1000.0,"tls_ms":meta.tls*1000.0,"total_ms":meta.total*1000.0});
        result["phases"] = json!({"dns":if meta.dns>0.0 {"observed"} else {"unconfirmed"},"tcp_connect":if quic {"not_applicable"} else if meta.connect>0.0 {"observed"} else {"unconfirmed"},"tls":if !meta.url.starts_with("https://") && meta.tls == 0.0 {"not_applicable"} else if meta.tls>0.0 {"observed"} else {"unconfirmed"}});
        let length = body.metadata().map_err(io_error)?.len();
        let mut prefix = Vec::new();
        body.take(PREFIX_LIMIT)
            .read_to_end(&mut prefix)
            .map_err(io_error)?;
        result["body_prefix_bytes"] = json!(prefix.len());
        result["body_complete"] =
            json!(output.status.success() && length == meta.bytes && length <= TRANSFER_LIMIT);
        let reason = if !output.status.success() {
            match output.status.code() {
                Some(5 | 6) => "DNS resolution failed",
                Some(7) => "connection failed",
                Some(28) => "request timeout",
                Some(35 | 51 | 58 | 60 | 77 | 80 | 82 | 83 | 90 | 91) => {
                    "TLS or certificate verification failed"
                }
                Some(63) => "response exceeded transfer limit",
                Some(47) => "redirect limit exceeded",
                Some(1 | 3 | 67) => "URL, credentials or redirect protocol rejected",
                _ => "curl transfer failed",
            }
        } else if !valid_url(
            meta.url,
            if target.url.starts_with("https://") {
                &["https"]
            } else {
                &["http", "https"]
            },
        ) {
            "unsafe effective URL"
        } else if meta.bytes != length || length > TRANSFER_LIMIT {
            "body size is inconsistent or exceeds limit"
        } else if quic && meta.version != "3" {
            "QUIC requested but HTTP3 was not negotiated"
        } else if !quic && !["1", "1.0", "1.1", "2"].contains(&meta.version) {
            "TCP requested but no valid TCP HTTP protocol was negotiated"
        } else if !(100..=599).contains(&meta.code) {
            "no HTTP response received"
        } else {
            match &target.check {
                Check::HttpReachable => {
                    result["status"] = json!("passed");
                    "HTTP node reachable; HTTP status does not establish service functionality"
                }
                _ if !(200..=299).contains(&meta.code) => "HTTP status is not successful",
                Check::HttpSuccess => {
                    result["status"] = json!("passed");
                    "successful HTTP response"
                }
                Check::BodyContains(marker) => {
                    if prefix
                        .windows(marker.len())
                        .any(|w| w.eq_ignore_ascii_case(marker.as_bytes()))
                    {
                        result["status"] = json!("passed");
                        "successful HTTP response and marker found in bounded body prefix"
                    } else {
                        "body marker absent from bounded prefix"
                    }
                }
                Check::GatewayJson => {
                    if length > PREFIX_LIMIT {
                        "JSON response exceeds complete-body validation limit"
                    } else if serde_json::from_slice::<Value>(&prefix)
                        .ok()
                        .and_then(|v| {
                            v.get("url")
                                .and_then(Value::as_str)
                                .map(|s| valid_url(s, &["wss"]))
                        })
                        .unwrap_or(false)
                    {
                        result["status"] = json!("passed");
                        "successful HTTP response with a valid gateway WSS URL"
                    } else {
                        "response is not complete gateway JSON with a valid WSS URL"
                    }
                }
            }
        };
        result["reason"] = json!(reason);
        Ok(result)
    }
}

struct Metadata<'a> {
    code: u64,
    version: &'a str,
    url: &'a str,
    bytes: u64,
    dns: f64,
    connect: f64,
    tls: f64,
    total: f64,
}
impl<'a> Metadata<'a> {
    fn parse(v: &'a Value) -> Option<Self> {
        let number = |key: &str| v.get(key)?.as_f64().filter(|n| n.is_finite() && *n >= 0.0);
        let code = v.get("http_code")?.as_u64().filter(|n| *n <= 599)?;
        // curl write-out represents HTTP/1.0 as "1".
        let version = v
            .get("http_version")?
            .as_str()
            .filter(|s| ["0", "1", "1.0", "1.1", "2", "3"].contains(s))?;
        let url = v
            .get("url_effective")?
            .as_str()
            .filter(|s| s.len() <= 2048)?;
        let bytes = number("size_download")?;
        if bytes.fract() != 0.0 || bytes > TRANSFER_LIMIT as f64 {
            return None;
        }
        Some(Self {
            code,
            version,
            url,
            bytes: bytes as u64,
            dns: number("time_namelookup")?,
            connect: number("time_connect")?,
            tls: number("time_appconnect")?,
            total: number("time_total")?,
        })
    }
}
