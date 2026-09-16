use crate::{
    app_arch,
    app_paths::AppPaths,
    error::{AppError, Result},
    process,
    service_fs::{self, Dir},
};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

pub const NFQWS_ARCHIVE_NAME: &str = "zapret-v72.9.tar.gz";
pub const STRATEGIES_ARCHIVE_NAME: &str =
    "strategies-ef19845a801e4e743f7bdfdbd58f9745c6adbd60.tar.gz";
pub const NFQWS_URL: &str =
    "https://github.com/bol-van/zapret/releases/download/v72.9/zapret-v72.9.tar.gz";
pub const STRATEGIES_URL: &str = "https://codeload.github.com/Flowseal/zapret-discord-youtube/tar.gz/ef19845a801e4e743f7bdfdbd58f9745c6adbd60";
pub const NFQWS_SHA256: &str = "1e14dc6320dd7b5a1f28ab8145ac76d7a7010ca3cbe71824aa4aa407f7279ddf";
pub const STRATEGIES_SHA256: &str =
    "9bd06fde016909131d3d07529f4019655ceb9f3e453bd38e229db21c275c323c";
const NFQWS_LIMIT: u64 = 32 * 1024 * 1024;
const STRATEGIES_LIMIT: u64 = 16 * 1024 * 1024;
const FLOWSEAL_ROOT: &str = "zapret-discord-youtube-ef19845a801e4e743f7bdfdbd58f9745c6adbd60";

pub const STRATEGIES: &[&str] = &[
    "general (ALT).bat",
    "general (ALT10).bat",
    "general (ALT11).bat",
    "general (ALT12).bat",
    "general (ALT2).bat",
    "general (ALT3).bat",
    "general (ALT4).bat",
    "general (ALT5).bat",
    "general (ALT6).bat",
    "general (ALT7).bat",
    "general (ALT8).bat",
    "general (ALT9).bat",
    "general (FAKE TLS AUTO ALT).bat",
    "general (FAKE TLS AUTO ALT2).bat",
    "general (FAKE TLS AUTO ALT3).bat",
    "general (FAKE TLS AUTO).bat",
    "general (SIMPLE FAKE ALT).bat",
    "general (SIMPLE FAKE ALT2).bat",
    "general (SIMPLE FAKE).bat",
    "general.bat",
];

pub const ASSETS: &[&str] = &[
    "bin/quic_initial_dbankcloud_ru.bin",
    "bin/quic_initial_www_google_com.bin",
    "bin/stun.bin",
    "bin/tls_clienthello_4pda_to.bin",
    "bin/tls_clienthello_max_ru.bin",
    "bin/tls_clienthello_www_google_com.bin",
    "lists/ipset-all.txt",
    "lists/ipset-all.txt.backup",
    "lists/ipset-exclude.txt",
    "lists/list-exclude.txt",
    "lists/list-general.txt",
    "lists/list-google.txt",
];

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("archive", message)
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verify(bytes: Vec<u8>, path: &Path, expected: &str) -> Result<Vec<u8>> {
    let actual = hash(&bytes);
    if actual != expected {
        return Err(fail(format!(
            "{}: неверный SHA256 {actual}, ожидался {expected}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_verified(path: &Path, limit: u64, expected: &str) -> Result<Vec<u8>> {
    let bytes = service_fs::source(path, limit, false)
        .map_err(|error| fail(format!("{}: {}", path.display(), error.message)))?;
    verify(bytes, path, expected)
}

fn read_cached_verified(
    directory: &Dir,
    directory_path: &Path,
    name: &str,
    limit: u64,
    expected: &str,
) -> Result<Vec<u8>> {
    let path = directory_path.join(name);
    let bytes = directory
        .read(name, 0o600, limit)
        .map_err(|error| fail(format!("{}: {}", path.display(), error.message)))?;
    verify(bytes, &path, expected)
}

pub fn find_executable(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let mut directories = env::var_os("PATH")
        .map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    for fallback in [
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
    ] {
        let fallback = PathBuf::from(fallback);
        if !directories.contains(&fallback) {
            directories.push(fallback);
        }
    }
    directories.into_iter().find_map(|directory| {
        let candidate = directory.canonicalize().ok()?.join(name);
        let metadata = fs::metadata(&candidate).ok()?;
        (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).then_some(candidate)
    })
}

fn download(paths: &AppPaths, name: &str, url: &str, limit: u64, digest: &str) -> Result<Vec<u8>> {
    let archive_dir = paths.ensure_private_child(&paths.cache_dir, "archives")?;
    let directory =
        Dir::absolute(&archive_dir, false, false).map_err(|error| fail(error.message))?;
    if directory
        .exists(name)
        .map_err(|error| fail(error.message))?
    {
        return read_cached_verified(&directory, &archive_dir, name, limit, digest);
    }
    let curl = find_executable("curl")
        .ok_or_else(|| fail("curl не найден; установите системные зависимости"))?;
    let temporary_name = format!(
        ".download-{}.tmp",
        service_fs::random_id().map_err(|error| fail(error.message))?
    );
    let temporary = archive_dir.join(&temporary_name);
    let mut command = Command::new(curl);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "5",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "15",
            "--max-time",
            "180",
            "--max-filesize",
        ])
        .arg(limit.to_string())
        .arg("--output")
        .arg(&temporary)
        .arg("--url")
        .arg(url);
    let output = match process::capture(command, &[], Duration::from_secs(185)) {
        Ok(output) => output,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if !output.status.success() {
        let _ = fs::remove_file(&temporary);
        return Err(fail(format!(
            "curl завершился с {}: {}",
            output.status, output.stderr
        )));
    }
    directory
        .open(&temporary_name, libc::O_RDONLY, 0)
        .and_then(|file| {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(service_fs::fail)
        })
        .map_err(|error| fail(error.message))?;
    let bytes = match read_cached_verified(&directory, &archive_dir, &temporary_name, limit, digest)
    {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    match directory.rename(&temporary_name, &directory, name) {
        Ok(()) => Ok(bytes),
        Err(_error) if directory.exists(name).unwrap_or(false) => {
            let _ = directory.unlink(&temporary_name, false);
            read_cached_verified(&directory, &archive_dir, name, limit, digest)
        }
        Err(error) => {
            let _ = directory.unlink(&temporary_name, false);
            Err(fail(error.message))
        }
    }
}

pub struct Archives {
    pub nfqws: Vec<u8>,
    pub strategies: Vec<u8>,
}

pub fn acquire(paths: &AppPaths, offline: Option<&Path>) -> Result<Archives> {
    if let Some(directory) = offline {
        if !directory.is_absolute() {
            return Err(fail("--archive-dir должен быть абсолютным путём"));
        }
        Dir::absolute(directory, false, false)
            .map_err(|error| fail(format!("{}: {}", directory.display(), error.message)))?;
        return Ok(Archives {
            nfqws: read_verified(
                &directory.join(NFQWS_ARCHIVE_NAME),
                NFQWS_LIMIT,
                NFQWS_SHA256,
            )?,
            strategies: read_verified(
                &directory.join(STRATEGIES_ARCHIVE_NAME),
                STRATEGIES_LIMIT,
                STRATEGIES_SHA256,
            )?,
        });
    }
    Ok(Archives {
        nfqws: download(
            paths,
            NFQWS_ARCHIVE_NAME,
            NFQWS_URL,
            NFQWS_LIMIT,
            NFQWS_SHA256,
        )?,
        strategies: download(
            paths,
            STRATEGIES_ARCHIVE_NAME,
            STRATEGIES_URL,
            STRATEGIES_LIMIT,
            STRATEGIES_SHA256,
        )?,
    })
}

pub fn engine_spec() -> Result<app_arch::EngineSpec> {
    app_arch::engine_spec_for(env::consts::ARCH, cfg!(target_endian = "little"))
        .map_err(|message| AppError::new("architecture", message))
}

pub struct PayloadFile {
    pub relative: PathBuf,
    pub bytes: Vec<u8>,
    pub executable: bool,
}

fn extract_members(archive: &Path, destination: &Path, members: &[String]) -> Result<()> {
    let tar =
        find_executable("tar").ok_or_else(|| fail("tar не найден; установите зависимости"))?;
    let mut command = Command::new(tar);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args(["--extract", "--gzip", "--file"])
        .arg(archive)
        .arg("--directory")
        .arg(destination)
        .args(["--no-same-owner", "--no-same-permissions", "--"])
        .args(members);
    let output = process::capture(command, &[], Duration::from_secs(3))
        .map_err(|error| fail(format!("tar: {}", error.message)))?;
    if !output.status.success() || output.truncated {
        return Err(fail(format!(
            "tar не извлёк закреплённые файлы ({}): {}{}",
            output.status,
            output.stderr,
            if output.truncated {
                "\nВывод tar усечён"
            } else {
                ""
            }
        )));
    }
    Ok(())
}

fn extracted(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    service_fs::source(path, maximum, false)
        .map_err(|error| fail(format!("{}: {}", path.display(), error.message)))
}

pub fn payload(stage: &Dir, stage_path: &Path, archives: &Archives) -> Result<Vec<PayloadFile>> {
    stage
        .write(".nfqws.tar.gz", &archives.nfqws, 0o600)
        .map_err(|error| fail(error.message))?;
    stage
        .write(".strategies.tar.gz", &archives.strategies, 0o600)
        .map_err(|error| fail(error.message))?;
    let nfqws_archive = stage_path.join(".nfqws.tar.gz");
    let strategies_archive = stage_path.join(".strategies.tar.gz");
    let engine = engine_spec()?;
    let engine_member = format!("zapret-v72.9/binaries/{}/nfqws", engine.directory);
    let strategy_members = STRATEGIES
        .iter()
        .chain(ASSETS.iter())
        .map(|name| format!("{FLOWSEAL_ROOT}/{name}"))
        .collect::<Vec<_>>();
    let nfqws_extract = stage
        .mkdir(".nfqws-extract", 0o700)
        .map_err(|error| fail(error.message))?;
    let strategies_extract = stage
        .mkdir(".strategies-extract", 0o700)
        .map_err(|error| fail(error.message))?;
    drop(nfqws_extract);
    drop(strategies_extract);
    let nfqws_extract_path = stage_path.join(".nfqws-extract");
    let strategies_extract_path = stage_path.join(".strategies-extract");
    extract_members(
        &nfqws_archive,
        &nfqws_extract_path,
        std::slice::from_ref(&engine_member),
    )?;
    extract_members(
        &strategies_archive,
        &strategies_extract_path,
        &strategy_members,
    )?;
    let bytes = extracted(&nfqws_extract_path.join(&engine_member), engine.size as u64)?;
    if bytes.len() != engine.size || hash(&bytes) != engine.sha256 {
        return Err(fail("Извлечённый nfqws не совпадает с закреплённым файлом"));
    }
    let mut files = vec![PayloadFile {
        relative: PathBuf::from("bin/nfqws"),
        bytes,
        executable: true,
    }];
    for name in STRATEGIES {
        files.push(PayloadFile {
            relative: Path::new("strategies").join(name),
            bytes: extracted(
                &strategies_extract_path.join(FLOWSEAL_ROOT).join(name),
                64 * 1024,
            )?,
            executable: false,
        });
    }
    for name in ASSETS {
        files.push(PayloadFile {
            relative: Path::new("assets").join(name),
            bytes: extracted(
                &strategies_extract_path.join(FLOWSEAL_ROOT).join(name),
                2 * 1024 * 1024,
            )?,
            executable: false,
        });
    }
    fs::remove_dir_all(&nfqws_extract_path).map_err(|error| fail(error.to_string()))?;
    fs::remove_dir_all(&strategies_extract_path).map_err(|error| fail(error.to_string()))?;
    stage
        .unlink(".nfqws.tar.gz", false)
        .map_err(|error| fail(error.message))?;
    stage
        .unlink(".strategies.tar.gz", false)
        .map_err(|error| fail(error.message))?;
    Ok(files)
}
