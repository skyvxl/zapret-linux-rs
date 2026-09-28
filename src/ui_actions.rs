use crate::{
    app_archive,
    app_paths::AppPaths,
    app_setup,
    config::Config,
    diagnose,
    error::{AppError, Result, combine},
    lifecycle, output, service_cli,
    service_fs::{self, Dir},
    state_cli,
    state_dir::{Lease, StateDir},
    ui_terminal,
};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
};
pub const MANUAL_STATE: &str = "/var/lib/zapret-linux-rs-manual";
pub enum Action {
    Recover,
    Run { allow_pause: bool },
    Diagnose { allow_pause: bool },
    Service(String),
    Apply { expected_installation_id: String },
}
pub fn execute(
    action: &Action,
    inputs: Option<&crate::ui_model::PreparedInputs>,
    on_event: &mut dyn FnMut(&serde_json::Value) -> Result<()>,
) -> Result<crate::ui_model::ActionOutcome> {
    output::reset_dashboard();
    crate::ui_events::supervise(&mut command(action, inputs)?, on_event)
}
pub fn command(
    action: &Action,
    inputs: Option<&crate::ui_model::PreparedInputs>,
) -> Result<Command> {
    let mut args = vec!["ui".to_owned(), "worker".into(), "--events".into()];
    if matches!(
        action,
        Action::Run { allow_pause: true } | Action::Diagnose { allow_pause: true }
    ) {
        args.push("--allow-pause".into());
    }
    if let Action::Apply {
        expected_installation_id,
    } = action
    {
        args.extend(["--expected-id".into(), expected_installation_id.clone()]);
    }
    if let Some(i) = inputs {
        args.extend([
            "--input-hashes".into(),
            i.config_sha256.clone(),
            i.bundle_sha256.clone(),
        ]);
    }
    match action {
        Action::Recover => args.push("recover".into()),
        Action::Run { .. } => args.push("run".into()),
        Action::Diagnose { .. } => args.push("diagnose".into()),
        Action::Service(s) => args.extend(["service".into(), s.clone()]),
        Action::Apply { .. } => args.extend(["service".into(), "apply".into()]),
    }
    if let Some(i) = inputs {
        args.extend([path(&i.config)?.into(), path(&i.bundle)?.into()]);
    }
    let exe = std::env::current_exe().map_err(fail)?;
    let mut command = if service_fs::uid() == 0 {
        Command::new(exe)
    } else {
        let mut c = Command::new(tool("sudo")?);
        if !ui_terminal::is_terminal() {
            c.arg("-n");
        }
        c.arg("--").arg(exe);
        c
    };
    command.args(args);
    Ok(command)
}
pub fn apply(
    inputs: &crate::ui_model::PreparedInputs,
    expected_installation_id: &str,
) -> Result<crate::ui_model::ActionOutcome> {
    execute(
        &Action::Apply {
            expected_installation_id: expected_installation_id.into(),
        },
        Some(inputs),
        &mut |_| Ok(()),
    )
}
fn fail(message: impl ToString) -> AppError {
    AppError::new("ui", message.to_string())
}
fn path(p: &Path) -> Result<&str> {
    p.to_str().ok_or_else(|| fail("Путь должен быть UTF-8"))
}
fn tool(name: &str) -> Result<PathBuf> {
    app_archive::find_executable(name).ok_or_else(|| {
        fail(format!(
            "Не найден {name}. Запустите ./service.sh deps --install"
        ))
    })
}
pub fn valid_service(action: &str) -> bool {
    [
        "install",
        "apply",
        "recover",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
        "status",
        "remove",
        "uninstall",
    ]
    .contains(&action)
}

pub fn launch(action: &str, service: Option<&str>) -> Result<()> {
    if service.is_some_and(|s| !valid_service(s)) {
        return Err(AppError::new("usage", "Неизвестное действие service"));
    }
    let mut arguments = vec!["ui".to_string(), "worker".into(), action.into()];
    if let Some(s) = service {
        arguments.push(s.into());
    }
    if action == "run"
        || action == "diagnose"
        || service.is_some_and(|s| ["install", "apply"].contains(&s))
    {
        let paths = AppPaths::discover()?;
        eprintln!("Проверка конфигурации и закреплённого набора данных...");
        let bundle = app_setup::setup(&paths, None)?;
        arguments.extend([path(&paths.config_file)?.into(), path(&bundle.root)?.into()]);
        for name in ["nft", "iptables-legacy-save", "ip6tables-legacy-save"] {
            tool(name)?;
        }
        if action == "diagnose" {
            tool("curl")?;
        }
    }
    if action == "service" {
        tool("systemctl")?;
    }
    let exe = std::env::current_exe().map_err(fail)?;
    let mut command = if service_fs::uid() == 0 {
        Command::new(exe)
    } else {
        let mut command = Command::new(tool("sudo")?);
        if !ui_terminal::is_terminal() {
            command.arg("-n");
        }
        command.arg("--").arg(exe);
        command
    };
    command.args(arguments);
    eprintln!("Для выбранного действия нужны права root. Ctrl+C останавливает действие.");
    ui_terminal::supervise(&mut command)
}

fn private(dir: &Dir) -> Result<()> {
    let m = dir.0.metadata().map_err(fail)?;
    if m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o700 {
        return Err(fail(
            "Ожидается каталог root:root 0700; существующий путь сохранён без изменений",
        ));
    }
    Ok(())
}
fn manual_state() -> Result<(Dir, File)> {
    let parent = Dir::absolute(Path::new("/var/lib"), true, false)?;
    let name = "zapret-linux-rs-manual";
    let dir = if parent.exists(name)? {
        parent.child(name)?
    } else {
        match parent.mkdir(name, 0o700) {
            Ok(d) => d,
            Err(error) => {
                if parent.exists(name)? {
                    parent.child(name)?
                } else {
                    return Err(error);
                }
            }
        }
    };
    private(&dir)?;
    let lock = if dir.exists("ui.lock")? {
        dir.open("ui.lock", libc::O_RDWR, 0)?
    } else {
        match dir.open(
            "ui.lock",
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(f) => {
                service_fs::own(&f)?;
                f
            }
            Err(_) => dir.open("ui.lock", libc::O_RDWR, 0)?,
        }
    };
    service_fs::trusted_file(&lock, 0o600)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("Другое действие уже использует ручное состояние"));
    }
    Ok((dir, lock))
}
fn recover(state: &Dir) -> Result<()> {
    let nft = tool("nft")?;
    recover_with(state, &nft, false)
}
fn recover_with(state: &Dir, nft: &Path, quiet: bool) -> Result<()> {
    let result = state_cli::run(&[
        "recover",
        "--state-dir",
        MANUAL_STATE,
        "--nft",
        path(nft)?,
        "--allow-previous-boot",
    ])?;
    clean_recovered(state)?;
    output::record_cleanup(true);
    if !output::is_protocol() && !quiet {
        println!(
            "Ручное состояние: {}; очистка: {}",
            result["state"]["status"].as_str().unwrap_or("unknown"),
            result["state"]["cleanup"].as_str().unwrap_or("unknown")
        );
    }
    Ok(())
}
fn staged_paths(root: &Path) -> AppPaths {
    AppPaths {
        config_dir: root.into(),
        config_file: root.join("config.env"),
        data_dir: root.into(),
        cache_dir: root.into(),
        bundle_dir: root.join("bundle"),
    }
}
const DIRS: &[&str] = &["bin", "strategies", "assets", "assets/bin", "assets/lists"];
/// Revalidate the private root copy before executing any engine.
fn snapshot(
    state: &Dir,
    config: &Path,
    source: &Path,
) -> Result<(String, AppPaths, app_setup::Bundle)> {
    for p in [config, source] {
        service_fs::path_ok(p)?;
        if !p.is_absolute() {
            return Err(fail("Worker требует абсолютные входные пути"));
        }
    }
    let name = format!("inputs-{}", service_fs::random_id()?);
    let stage = state.mkdir(&name, 0o700)?;
    stage.write("owner", name.as_bytes(), 0o600)?;
    let root = Path::new(MANUAL_STATE).join(&name);
    let result = (|| {
        let bytes = service_fs::source(config, 64 * 1024, false)?;
        let config = Config::parse(std::str::from_utf8(&bytes).map_err(fail)?)?;
        let manifest_bytes = service_fs::source(&source.join("manifest.json"), 1024 * 1024, false)?;
        let inventory = app_setup::checked_manifest(&manifest_bytes)?;
        if !inventory.contains(&format!("strategies/{}", config.strategy)) {
            return Err(fail("Стратегия отсутствует в bundle"));
        }
        stage.write("config.env", &bytes, 0o600)?;
        stage.mkdir("bundle", 0o700)?;
        for rel in DIRS {
            let p = Path::new(rel);
            let parent = match p.parent().filter(|p| !p.as_os_str().is_empty()) {
                Some(p) => Dir::absolute(&root.join("bundle").join(p), false, false)?,
                None => Dir::absolute(&root.join("bundle"), false, false)?,
            };
            parent.mkdir(
                p.file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| fail("Имя каталога"))?,
                0o700,
            )?;
        }
        let destination = Dir::absolute(&root.join("bundle"), false, false)?;
        destination.write("manifest.json", &manifest_bytes, 0o600)?;
        for rel in inventory {
            let p = Path::new(&rel);
            let bytes = service_fs::source(&source.join(p), 2 * 1024 * 1024, false)?;
            let dest = Dir::absolute(
                &root
                    .join("bundle")
                    .join(p.parent().unwrap_or(Path::new(""))),
                false,
                false,
            )?;
            dest.write(
                p.file_name()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| fail("Имя файла"))?,
                &bytes,
                if rel == "bin/nfqws" { 0o700 } else { 0o600 },
            )?;
        }
        let paths = staged_paths(&root);
        let bundle = app_setup::validate_bundle(&paths)?;
        Ok((paths, bundle))
    })();
    match result {
        Ok((p, b)) => Ok((name, p, b)),
        Err(e) => combine(Err(e), remove_snapshot(state, &name)),
    }
}
/// Ownership and constrained directory roles authorize deletion, independently
/// of the runnable bundle/catalog. Validate everything before deleting; owner last.
fn remove_snapshot(state: &Dir, name: &str) -> Result<()> {
    let result = (|| {
        let suffix = name
            .strip_prefix("inputs-")
            .ok_or_else(|| fail("Неизвестный snapshot"))?;
        if suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(fail("Некорректный идентификатор snapshot"));
        }
        let stage = state.child(name)?;
        private(&stage)?;
        if stage.names()?.is_empty() {
            return state.unlink(name, true);
        }
        if stage
            .read("owner", 0o600, 100)
            .map_err(|e| fail(format!("owner: {}", e.message)))?
            != name.as_bytes()
        {
            return Err(fail("owner: Snapshot не принадлежит этому действию"));
        }
        fn directory(prefix: &str, name: &str) -> bool {
            matches!(
                (prefix, name),
                ("", "bundle")
                    | ("bundle", "bin" | "strategies" | "assets")
                    | ("bundle/assets", "bin" | "lists")
            )
        }
        fn check(dir: &Dir, prefix: &str, remaining: &mut usize) -> Result<()> {
            private(dir)?;
            for name in dir.names()? {
                let rel = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let result = (|| {
                    *remaining = remaining
                        .checked_sub(1)
                        .ok_or_else(|| fail("Превышен лимит 4096 записей snapshot"))?;
                    if directory(prefix, &name) {
                        check(&dir.child(&name)?, &rel, remaining)
                    } else {
                        let allowed = match prefix {
                            "" => ["owner", "config.env"].contains(&name.as_str()),
                            "bundle" => name == "manifest.json",
                            "bundle/bin" => name == "nfqws",
                            "bundle/strategies" => {
                                service_fs::owned_data_basename(&name) && name.ends_with(".bat")
                            }
                            "bundle/assets/bin" | "bundle/assets/lists" => {
                                service_fs::owned_data_basename(&name)
                            }
                            _ => false,
                        };
                        if !allowed {
                            return Err(fail("Неизвестная роль файла/каталога"));
                        }
                        let f = dir.open(&name, libc::O_RDONLY, 0)?;
                        service_fs::trusted_file(
                            &f,
                            if rel == "bundle/bin/nfqws" {
                                0o700
                            } else {
                                0o600
                            },
                        )
                    }
                })();
                result.map_err(|e| fail(format!("{rel}: {}", e.message)))?;
            }
            Ok(())
        }
        check(&stage, "", &mut 4096)?;
        fn remove(dir: &Dir, prefix: &str) -> Result<()> {
            for name in dir.names()? {
                if prefix.is_empty() && name == "owner" {
                    continue;
                }
                let rel = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let result = if directory(prefix, &name) {
                    remove(&dir.child(&name)?, &rel).and_then(|()| dir.unlink(&name, true))
                } else {
                    dir.unlink(&name, false)
                };
                result.map_err(|e| fail(format!("{rel}: {}", e.message)))?;
            }
            Ok(())
        }
        remove(&stage, "")?;
        stage
            .unlink("owner", false)
            .map_err(|e| fail(format!("owner: {}", e.message)))?;
        state.unlink(name, true)
    })();
    result.map_err(|e| {
        fail(format!(
            "{MANUAL_STATE}/{name}: очистка снимка не подтверждена: {}",
            e.message
        ))
    })
}
fn empty_manual_state() -> Result<Lease> {
    // Core writes the journal before spawning and clears it only after removing
    // rules and reaping. Hold its lock through deletion, including preflight errors.
    let lease = StateDir::open(Path::new(MANUAL_STATE))?.lock()?;
    if lease.read()?.is_some() {
        return Err(fail(
            "Очистка runtime не подтверждена: журнал состояния сохранён",
        ));
    }
    Ok(lease)
}
fn clean_recovered(state: &Dir) -> Result<()> {
    let _lease = empty_manual_state()?;
    for name in state.names()? {
        if name.starts_with("inputs-") {
            remove_snapshot(state, &name)?;
        }
    }
    Ok(())
}
fn source_args(paths: &AppPaths, bundle: &app_setup::Bundle) -> Result<Vec<String>> {
    let mut a = Vec::new();
    for (key, p) in [
        ("--config", &paths.config_file),
        ("--strategies", &bundle.strategies),
        ("--assets", &bundle.assets),
        ("--nfqws", &bundle.nfqws),
    ] {
        a.extend([key.into(), path(p)?.into()]);
    }
    for (key, name) in [
        ("--nft", "nft"),
        ("--iptables-save", "iptables-legacy-save"),
        ("--ip6tables-save", "ip6tables-legacy-save"),
    ] {
        a.extend([key.into(), path(&tool(name)?)?.into()]);
    }
    Ok(a)
}
pub fn worker(args: &[&str]) -> Result<()> {
    worker_inner(args, None, false, None)
}
pub fn recover_for_service() -> Result<()> {
    let (state, _lock) = manual_state()?;
    recover_with(&state, Path::new("/opt/zapret-linux-rs/bin/nft"), true)
}
fn worker_inner(
    args: &[&str],
    expected_id: Option<&str>,
    allow_pause: bool,
    hashes: Option<(&str, &str)>,
) -> Result<()> {
    if service_fs::uid() != 0 {
        return Err(AppError::new(
            "permissions",
            "Worker запускается только с правами root через guided UI",
        ));
    }
    let (action, service, inputs) = match args {
        ["run", c, b] => ("run", None, Some((*c, *b))),
        ["diagnose", c, b] => ("diagnose", None, Some((*c, *b))),
        ["recover"] => ("recover", None, None),
        ["service", s @ ("install" | "apply"), c, b] => ("service", Some(*s), Some((*c, *b))),
        ["service", s] if valid_service(s) && !["install", "apply"].contains(s) => {
            ("service", Some(*s), None)
        }
        _ => {
            return Err(AppError::new(
                "usage",
                "ui worker run|diagnose CONFIG BUNDLE; recover; service install CONFIG BUNDLE; service ACTION",
            ));
        }
    };
    let _human = output::Human::enter();
    if let Some(s) = service {
        tool("systemctl")?;
        if inputs.is_none() {
            let opts = if ["remove", "uninstall"].contains(&s) {
                vec![s, "--stop"]
            } else {
                vec![s]
            };
            return show_service(service_cli::run(&opts)?);
        }
    }
    let (state, _lock) = manual_state()?;
    if action != "service" {
        output::record_cleanup(false);
        recover(&state)?;
    }
    let Some((config, bundle)) = inputs else {
        return Ok(());
    };
    let mut operation = || {
        let (name, paths, bundle) = snapshot(&state, Path::new(config), Path::new(bundle))?;
        let result = (|| {
            if let Some((config_hash, bundle_hash)) = hashes
                && (service_fs::digest(&service_fs::source(&paths.config_file, 65536, false)?)
                    != config_hash
                    || service_fs::digest(&bundle.manifest_bytes) != bundle_hash)
            {
                return Err(AppError::new(
                    "inputs_changed",
                    "Настройки или данные изменились до запуска. Откройте действие заново",
                ));
            }
            let mut args = source_args(&paths, &bundle)?;
            if action == "service" {
                args.insert(0, service.unwrap().into());
                return show_service(service_cli::run_with_expected(
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                    expected_id,
                )?);
            }
            args.extend(["--state-dir".into(), MANUAL_STATE.into()]);
            if action == "run" {
                output::record_cleanup(false);
                args.insert(0, "--host".into());
                lifecycle::run(&args.iter().map(String::as_str).collect::<Vec<_>>())
            } else {
                output::record_cleanup(false);
                args.extend([
                    "--curl".into(),
                    path(&tool("curl")?)?.into(),
                    "--quic".into(),
                ]);
                if !output::is_protocol() {
                    println!(
                        "Диагностика всех {} стратегий. Выбранная конфигурация не изменится.",
                        bundle.strategy_count
                    );
                }
                diagnose::run(&args.iter().map(String::as_str).collect::<Vec<_>>())
            }
        })();
        let cleanup = (|| {
            // Installation owns a separate immutable copy and its own journal.
            let _lease = if action == "service" {
                None
            } else {
                Some(empty_manual_state()?)
            };
            remove_snapshot(&state, &name)
        })();
        if cleanup.is_err() {
            eprintln!(
                "Не подтверждена очистка входных данных: {}. После устранения причины: ./service.sh recover",
                paths.data_dir.display()
            );
        }
        output::record_cleanup(cleanup.is_ok());
        combine(result, cleanup)
    };
    if ["run", "diagnose"].contains(&action) && output::is_protocol() {
        crate::service_install::with_paused_service(allow_pause, &mut operation)
    } else {
        operation()
    }
}
fn show_service(value: serde_json::Value) -> Result<()> {
    if output::is_protocol() {
        let signals = crate::signals::Signals::install()?;
        return output::emit(
            serde_json::json!({"event":"service_result","service":value["service"]}),
            &signals,
            std::time::Duration::from_secs(5),
            false,
        );
    }
    let s = &value["service"];
    println!(
        "Служба: {}. Состояние: {}. Автозапуск: {}.",
        s["status"].as_str().unwrap_or("unknown"),
        s["runtime"].as_str().unwrap_or("unknown"),
        if s["enabled"] == true {
            "включён"
        } else {
            "выключен"
        }
    );
    if let Some(strategy) = s["strategy"].as_str() {
        println!("Стратегия установленного снимка: {strategy}");
    }
    Ok(())
}

pub fn worker_events(args: &[&str]) -> Result<()> {
    use crate::ui_model::{ActionOutcome, ActionStatus};
    let _protocol = output::Protocol::enter();
    let signals = crate::signals::Signals::install()?;
    let (args, allow_pause) = if args.first() == Some(&"--allow-pause") {
        (&args[1..], true)
    } else {
        (args, false)
    };
    let (args, expected_id) = if args.first() == Some(&"--expected-id") && args.len() > 2 {
        (&args[2..], Some(args[1]))
    } else {
        (args, None)
    };
    let (args, hashes) = if args.first() == Some(&"--input-hashes") && args.len() > 3 {
        (&args[3..], Some((args[1], args[2])))
    } else {
        (args, None)
    };
    output::emit(
        serde_json::json!({"event":"worker_ready"}),
        &signals,
        std::time::Duration::from_secs(5),
        false,
    )?;
    let result = worker_inner(args, expected_id, allow_pause, hashes);
    if result.as_ref().err().is_some_and(|e| e.kind == "usage") {
        return result;
    }
    let (data, cleanup) = output::action_result();
    let recovery = result
        .as_ref()
        .err()
        .is_some_and(|e| e.kind == "recovery_required");
    let status = if cleanup == Some(false) || recovery {
        ActionStatus::NeedsRecovery
    } else {
        match &result {
            Ok(()) if signals.requested().is_some() => ActionStatus::Cancelled,
            Ok(()) => ActionStatus::Completed,
            Err(e) if e.kind == "interrupted" || e.message.contains("SIGINT") => {
                ActionStatus::Cancelled
            }
            Err(_) => ActionStatus::Failed,
        }
    };
    let outcome = ActionOutcome {
        status,
        data,
        cleanup: match cleanup {
            Some(true) => "confirmed",
            Some(false) => "unknown",
            None => "not_needed",
        }
        .into(),
        restoration: if recovery {
            "unknown"
        } else if output::restoration() == Some(true) {
            "restored"
        } else if output::restoration() == Some(false) {
            "unknown"
        } else {
            "not_needed"
        }
        .into(),
        error: result.as_ref().err().map(|e| e.json()["error"].clone()),
    };
    crate::ui_events::emit_finished(&outcome, &signals)?;
    match status {
        ActionStatus::Completed => Ok(()),
        ActionStatus::Cancelled => Err(AppError::new("cancelled", "Действие отменено")),
        _ => Err(AppError::new(
            "action",
            "Действие не завершено; подробности переданы в меню",
        )),
    }
}
