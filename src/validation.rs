use crate::{
    config::Config,
    error::{AppError, Result},
    runtime::{FWMARK, QUEUE_NUM},
    strategy::Plan,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn run(options: &[&str]) -> Result<Value> {
    let mut values = BTreeMap::new();
    let mut dry = false;
    let mut index = 0;
    while index < options.len() {
        let key = options[index];
        if key == "--dry-run" && !dry {
            dry = true;
            index += 1;
            continue;
        }
        if ![
            "--config",
            "--strategies",
            "--assets",
            "--nfqws",
            "--timeout-ms",
        ]
        .contains(&key)
        {
            return Err(AppError::new(
                "usage",
                format!("Неизвестный или повторный параметр: {key}"),
            ));
        }
        let value = options
            .get(index + 1)
            .ok_or_else(|| AppError::new("usage", format!("Нет значения для {key}")))?;
        if value.starts_with("--") || values.insert(key, *value).is_some() {
            return Err(AppError::new(
                "usage",
                format!("Нет значения или повторный параметр: {key}"),
            ));
        }
        index += 2;
    }
    if !dry {
        return Err(AppError::new(
            "usage",
            "На этом этапе поддерживается только run --dry-run",
        ));
    }
    // SAFETY: geteuid takes no pointers and has no failure case.
    if unsafe { libc::geteuid() } == 0 {
        return Err(AppError::new(
            "permissions",
            "Запускайте проверку обычным пользователем, без sudo",
        ));
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| AppError::new("usage", format!("Требуется {key}")))
    };
    let timeout: u64 = values
        .get("--timeout-ms")
        .unwrap_or(&"5000")
        .parse()
        .ok()
        .filter(|n| (1..=60000).contains(n))
        .ok_or_else(|| AppError::new("usage", "--timeout-ms: ожидается 1..60000"))?;
    let config = Config::load(Path::new(required("--config")?))?;
    let file = resolve_strategy(Path::new(required("--strategies")?), &config.strategy)?;
    let plan = Plan::load(
        &file,
        Path::new(required("--assets")?),
        config.gamefiltertcp,
        config.gamefilterudp,
    )?;
    let binary = Path::new(required("--nfqws")?)
        .canonicalize()
        .map_err(|e| AppError::new("engine", format!("nfqws: {e}")))?;
    if !binary.is_file() {
        return Err(AppError::new(
            "engine",
            "nfqws должен быть обычным исполняемым файлом",
        ));
    }
    let validation = validate_engine(&binary, &plan, Duration::from_millis(timeout))?;
    Ok(
        json!({"config": config.json(), "strategy_file": file, "plan": plan.json(true), "validation": validation}),
    )
}

fn normalized(name: &str) -> String {
    let lower = name.to_lowercase();
    let stem = lower.strip_suffix(".bat").unwrap_or(&lower);
    stem.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == '_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

pub fn resolve_strategy(directory: &Path, name: &str) -> Result<PathBuf> {
    let directory = directory
        .canonicalize()
        .map_err(|e| AppError::new("strategy", e.to_string()))?;
    let exact = directory.join(name);
    let resolved = if exact.is_file() {
        exact
    } else {
        let target = normalized(name);
        let mut matches = Vec::new();
        for item in
            fs::read_dir(&directory).map_err(|e| AppError::new("strategy", e.to_string()))?
        {
            let path = item
                .map_err(|e| AppError::new("strategy", e.to_string()))?
                .path();
            if !path.is_file()
                || !path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("bat"))
            {
                continue;
            }
            let candidate = normalized(&path.file_name().unwrap().to_string_lossy());
            if candidate == target || candidate == format!("general_{target}") {
                matches.push(path);
            }
        }
        match matches.len() {
            0 => {
                return Err(AppError::new(
                    "strategy",
                    format!("Стратегия не найдена: {name}"),
                ));
            }
            1 => matches.remove(0),
            _ => {
                return Err(AppError::new(
                    "strategy",
                    format!("Неоднозначное имя стратегии: {name}; укажите точное имя файла"),
                ));
            }
        }
    };
    let resolved = resolved
        .canonicalize()
        .map_err(|e| AppError::new("strategy", e.to_string()))?;
    if !resolved.starts_with(&directory) {
        return Err(AppError::new(
            "strategy",
            "Стратегия находится за пределами указанного каталога",
        ));
    }
    Ok(resolved)
}

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        // Child::kill does nothing after a successfully reaped exit status.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn nonblocking(pipe: &impl AsRawFd) -> io::Result<()> {
    // SAFETY: the descriptor is owned by a live pipe. fcntl receives no pointers.
    unsafe {
        let flags = libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL);
        if flags == -1
            || libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, truncated: &mut bool) -> io::Result<()> {
    let mut buffer = [0; 4096];
    // Bound each iteration so a noisy child cannot starve the timeout check.
    for _ in 0..32 {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let retain = count.min(65536 - output.len());
                output.extend_from_slice(&buffer[..retain]);
                *truncated |= retain < count;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn validate_engine(binary: &Path, plan: &Plan, timeout: Duration) -> Result<Value> {
    let mut command = Command::new(binary);
    command
        .args([
            "--dry-run".to_string(),
            format!("--qnum={QUEUE_NUM}"),
            format!("--dpi-desync-fwmark={FWMARK:#x}"),
        ])
        .args(&plan.args)
        .current_dir(&plan.assets)
        .env_clear()
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: these Linux syscalls take scalar arguments only. The pre_exec closure
    // performs no allocation or locking and kills the child if its parent has died.
    unsafe {
        let parent = libc::getpid();
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(125);
            }
            Ok(())
        });
    }
    let mut running = RunningChild(
        command
            .spawn()
            .map_err(|e| AppError::new("engine", format!("Запуск {}: {e}", binary.display())))?,
    );
    let mut stdout = running
        .0
        .stdout
        .take()
        .ok_or_else(|| AppError::new("engine", "Нет stdout"))?;
    let mut stderr = running
        .0
        .stderr
        .take()
        .ok_or_else(|| AppError::new("engine", "Нет stderr"))?;
    let io_error = |e: io::Error| AppError::new("engine", e.to_string());
    nonblocking(&stdout).map_err(io_error)?;
    nonblocking(&stderr).map_err(io_error)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut truncated = false;
    let start = Instant::now();
    let status = loop {
        drain(&mut stdout, &mut out, &mut truncated).map_err(io_error)?;
        drain(&mut stderr, &mut err, &mut truncated).map_err(io_error)?;
        if let Some(status) = running.0.try_wait().map_err(io_error)? {
            break status;
        }
        if start.elapsed() >= timeout {
            return Err(AppError::new(
                "timeout",
                format!(
                    "Проверка nfqws превысила {} мс; дочерний процесс остановлен",
                    timeout.as_millis()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    };
    drain(&mut stdout, &mut out, &mut truncated).map_err(io_error)?;
    drain(&mut stderr, &mut err, &mut truncated).map_err(io_error)?;
    let stdout = String::from_utf8_lossy(&out);
    let stderr = String::from_utf8_lossy(&err);
    if !status.success() {
        return Err(AppError::new(
            "engine",
            format!("nfqws: {status}\n{stderr}\n{stdout}"),
        ));
    }
    Ok(
        json!({"mode": "dry-run", "status": "passed", "exit_code": status.code(),
        "stdout": stdout, "stderr": stderr, "output_truncated": truncated,
        "network_validation": "not_run"}),
    )
}
