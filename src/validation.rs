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
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
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
            "Укажите явный режим: run --dry-run, run --isolated или run --host",
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

pub fn validate_engine(binary: &Path, plan: &Plan, timeout: Duration) -> Result<Value> {
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
        .env("LANG", "C");
    if crate::service_fs::uid() == 0 {
        // Match runtime identity restrictions so dry-run can read private snapshots
        // and cannot clear Managed's parent-death signal by switching UID/GID.
        // SAFETY: restrict_child_ids uses only stack buffers and syscalls after fork.
        unsafe {
            command.pre_exec(crate::host_run::restrict_child_ids);
        }
    }
    validate_command(command, timeout)
}

pub fn validate_command(command: Command, timeout: Duration) -> Result<Value> {
    let output = crate::process::capture(command, &[], timeout).map_err(|e| {
        AppError::new(
            if e.kind == "timeout" {
                "timeout"
            } else {
                "engine"
            },
            format!("nfqws: {}", e.message),
        )
    })?;
    if !output.status.success() {
        return Err(AppError::new(
            "engine",
            format!(
                "nfqws: {}\n{}\n{}",
                output.status, output.stderr, output.stdout
            ),
        ));
    }
    Ok(
        json!({"mode": "dry-run", "status": "passed", "exit_code": output.status.code(),
        "stdout": output.stdout, "stderr": output.stderr, "output_truncated": output.truncated,
        "network_validation": "not_run"}),
    )
}
