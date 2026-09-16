//! Guided actions resolve inputs once, then reuse the checked core authorities.
use crate::{
    app_archive,
    app_paths::AppPaths,
    app_setup,
    config::Config,
    diagnose,
    error::{AppError, Result},
    lifecycle, output, service_cli,
    service_fs::{self, Dir},
    state_cli, ui_terminal,
};
use std::{
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
};
pub const MANUAL_STATE: &str = "/var/lib/zapret-linux-rs-manual";
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
    if action == "run" || action == "diagnose" || service == Some("install") {
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
        // Noninteractive actions never wait for invisible authentication.
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
fn recover() -> Result<()> {
    let nft = tool("nft")?;
    let result = state_cli::run(&[
        "recover",
        "--state-dir",
        MANUAL_STATE,
        "--nft",
        path(&nft)?,
        "--allow-previous-boot",
    ])?;
    println!(
        "Ручное состояние: {}; очистка: {}",
        result["state"]["status"].as_str().unwrap_or("unknown"),
        result["state"]["cleanup"].as_str().unwrap_or("unknown")
    );
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
fn bundle_files() -> Vec<String> {
    let mut files = vec!["manifest.json".into(), "bin/nfqws".into()];
    files.extend(
        app_archive::STRATEGIES
            .iter()
            .map(|s| format!("strategies/{s}")),
    );
    files.extend(app_archive::ASSETS.iter().map(|s| format!("assets/{s}")));
    files.extend(
        [
            "list-general-user.txt",
            "list-exclude-user.txt",
            "ipset-exclude-user.txt",
        ]
        .iter()
        .map(|s| format!("assets/lists/{s}")),
    );
    files
}
const DIRS: &[&str] = &["bin", "strategies", "assets", "assets/bin", "assets/lists"];
/// Only fixed expected basenames enter a new, exclusively owned root directory.
/// Revalidate the root copy against pinned digests before executing any engine.
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
        if !app_archive::STRATEGIES.contains(&config.strategy.as_str()) {
            return Err(fail("Стратегия отсутствует в закреплённом наборе"));
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
        for rel in bundle_files() {
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
        Err(e) => {
            let _ = remove_snapshot(state, &name, false);
            Err(e)
        }
    }
}
/// Never delete by prefix alone: root ownership, exact marker and a fixed
/// allowlist are checked. Unknown content is preserved for inspection.
fn remove_snapshot(state: &Dir, name: &str, complete: bool) -> Result<()> {
    let suffix = name
        .strip_prefix("inputs-")
        .ok_or_else(|| fail("Неизвестный snapshot"))?;
    if suffix.len() != 32 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(fail("Некорректный идентификатор snapshot"));
    }
    let stage = state.child(name)?;
    private(&stage)?;
    if stage.read("owner", 0o600, 100)? != name.as_bytes() {
        return Err(fail("Snapshot не принадлежит этому действию"));
    }
    if complete {
        app_setup::validate_bundle(&staged_paths(&Path::new(MANUAL_STATE).join(name)))?;
    }
    let mut allowed = bundle_files()
        .into_iter()
        .map(|p| format!("bundle/{p}"))
        .collect::<Vec<_>>();
    allowed.extend(["owner".into(), "config.env".into()]);
    let mut dirs = DIRS
        .iter()
        .map(|d| format!("bundle/{d}"))
        .collect::<Vec<_>>();
    dirs.push("bundle".into());
    fn check(dir: &Dir, prefix: &str, files: &[String], dirs: &[String]) -> Result<()> {
        private(dir)?;
        for name in dir.names()? {
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if dirs.contains(&rel) {
                check(&dir.child(&name)?, &rel, files, dirs)?;
            } else if files.contains(&rel) {
                let f = dir.open(&name, libc::O_RDONLY, 0)?;
                service_fs::trusted_file(
                    &f,
                    if rel == "bundle/bin/nfqws" {
                        0o700
                    } else {
                        0o600
                    },
                )?;
            } else {
                return Err(fail("Неожиданный файл в snapshot; каталог сохранён"));
            }
        }
        Ok(())
    }
    check(&stage, "", &allowed, &dirs)?;
    fn remove(dir: &Dir) -> Result<()> {
        for name in dir.names()? {
            if let Ok(child) = dir.child(&name) {
                remove(&child)?;
                dir.unlink(&name, true)?;
            } else {
                dir.unlink(&name, false)?;
            }
        }
        Ok(())
    }
    remove(&stage)?;
    state.unlink(name, true)
}
fn clean_recovered(state: &Dir) -> Result<()> {
    for name in state.names()? {
        if name.starts_with("inputs-") {
            remove_snapshot(state, &name, true)?;
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
        ["service", "install", c, b] => ("service", Some("install"), Some((*c, *b))),
        ["service", s] if valid_service(s) && *s != "install" => ("service", Some(*s), None),
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
        recover()?;
        clean_recovered(&state)?;
    }
    let Some((config, bundle)) = inputs else {
        return Ok(());
    };
    let (name, paths, bundle) = snapshot(&state, Path::new(config), Path::new(bundle))?;
    let result = (|| {
        let mut args = source_args(&paths, &bundle)?;
        if action == "service" {
            args.insert(0, "install".into());
            return show_service(service_cli::run(
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
            )?);
        }
        args.extend(["--state-dir".into(), MANUAL_STATE.into()]);
        if action == "run" {
            args.insert(0, "--host".into());
            lifecycle::run(&args.iter().map(String::as_str).collect::<Vec<_>>())
        } else {
            args.extend([
                "--curl".into(),
                path(&tool("curl")?)?.into(),
                "--quic".into(),
            ]);
            println!(
                "Диагностика всех {} стратегий. Выбранная конфигурация не изменится.",
                app_archive::STRATEGIES.len()
            );
            diagnose::run(&args.iter().map(String::as_str).collect::<Vec<_>>())
        }
    })();
    if result.is_ok() {
        remove_snapshot(&state, &name, true)?;
    } else {
        eprintln!(
            "Снимок входных данных сохранён: {}. После устранения причины: ./service.sh recover",
            paths.data_dir.display()
        );
    }
    result
}
fn show_service(value: serde_json::Value) -> Result<()> {
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
