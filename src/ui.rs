use crate::{
    app_paths::AppPaths,
    app_setup,
    config::Config,
    error::{AppError, Result},
    ui_actions, ui_terminal,
};
use serde_json::json;
use std::process::Command;
fn usage() -> AppError {
    AppError::new(
        "usage",
        "ui menu|setup|update [--archive-dir DIR] [--json]|doctor [--json]|paths|run|diagnose|config [--json] [--strategy NAME] [--interface NAME] [--gamefilter-tcp true|false] [--gamefilter-udp true|false]|service install|start|stop|restart|enable|disable|status|remove|recover",
    )
}
pub fn human_error(error: &AppError) {
    eprintln!("Ошибка ({}): {}", error.kind, error.message);
    if ["paths", "config", "bundle"].contains(&error.kind) {
        eprintln!(
            "Проверьте ./service.sh doctor. Неисправные/чужие файлы сохранены; для первой подготовки: ./service.sh setup."
        );
    }
    if ["state", "ownership", "host", "service"].contains(&error.kind) {
        eprintln!(
            "Проверьте ./service.sh doctor и service status. Ручное состояние: ./service.sh recover. Чужие службы и правила не удаляются."
        );
    }
}
fn config_text(c: &Config) {
    println!(
        "Стратегия: {}\nИнтерфейс: {}\nGameFilter TCP: {}; UDP: {}\nFirewall: {}",
        c.strategy,
        c.interface,
        c.gamefiltertcp,
        c.gamefilterudp,
        c.backend.name()
    );
    println!(
        "Эти настройки используются при ручном запуске и следующей установке службы. Уже установленный снимок не меняется; его параметры: ./service.sh service status."
    );
}
fn boolean(s: &str) -> Result<bool> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AppError::new(
            "usage",
            "GameFilter: ожидается true или false",
        )),
    }
}
fn config(args: &[&str]) -> Result<()> {
    let paths = AppPaths::discover()?;
    let mut changes = crate::app_paths::ConfigChanges::default();
    let mut json = false;
    let mut changed = false;
    let mut seen = std::collections::BTreeSet::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i];
        if !seen.insert(key) {
            return Err(usage());
        }
        if key == "--json" {
            json = true;
            i += 1;
            continue;
        }
        let val = *args.get(i + 1).ok_or_else(usage)?;
        match key {
            "--strategy" => {
                if !crate::app_flowseal::strategy_name(val) {
                    return Err(AppError::new("config", "Недопустимое имя стратегии"));
                }
                changes.strategy = Some(val.into());
            }
            "--interface" => changes.interface = Some(val.into()),
            "--gamefilter-tcp" => changes.gamefiltertcp = Some(boolean(val)?),
            "--gamefilter-udp" => changes.gamefilterudp = Some(boolean(val)?),
            _ => return Err(usage()),
        }
        changed = true;
        i += 2;
    }
    let c = if changed {
        paths.update_config(changes)?
    } else if std::fs::symlink_metadata(&paths.config_file).is_ok() {
        paths.load_config()?
    } else {
        AppPaths::defaults()
    };
    if json {
        println!("{}", json!({"config":c.json()}));
    } else {
        config_text(&c);
    }
    Ok(())
}
fn doctor() -> Result<()> {
    let p = AppPaths::discover()?;
    let v = app_setup::doctor(&p);
    ui_terminal::title("Диагностика окружения");
    println!(
        "Конфигурация: {} ({})\nДанные: {} ({})",
        v["config"]["status"],
        p.config_file.display(),
        v["bundle"]["status"],
        p.bundle_dir.display()
    );
    for key in ["config", "bundle"] {
        if let Some(message) = v[key]["error"]["message"].as_str() {
            println!("{key}: {message}");
        }
    }
    for (name, value) in v["dependencies"].as_object().into_iter().flatten() {
        if name != "http3" {
            println!(
                "{name}: {} — {}",
                value["status"].as_str().unwrap_or("unknown"),
                value["path"].as_str().unwrap_or("не найден")
            );
        }
    }
    println!(
        "HTTP/3 (QUIC): {}",
        if v["dependencies"]["http3"] == true {
            "доступен"
        } else {
            "не поддерживается установленным curl; QUIC проверки будут отмечены unsupported"
        }
    );
    println!(
        "Ручное состояние: {} (проверка и восстановление: ./service.sh recover)\nНедостающие зависимости: ./service.sh deps --install\nПодготовка данных: ./service.sh setup\nСостояние установленной службы: ./service.sh service status",
        ui_actions::MANUAL_STATE
    );
    Ok(())
}
fn setup(args: &[&str]) -> Result<()> {
    let value = app_setup::ui(args)?;
    if args.contains(&"--json") {
        println!("{value}");
    } else {
        println!(
            "{}: {} стратегий; nfqws dry-run: {}.\nКонфигурация: {}",
            if args.first() == Some(&"update") {
                "Стратегии обновлены и проверены"
            } else {
                "Данные проверены"
            },
            value["bundle"]["strategy_count"],
            value["bundle"]["validation"]["status"],
            value["config"]["strategy"]
        );
    }
    Ok(())
}
pub(crate) fn preparation() -> Result<()> {
    let launcher = std::env::var_os("ZAPRET_LAUNCHER").ok_or_else(|| {
        AppError::new(
            "ui",
            "Для установки зависимостей запустите ./service.sh deps --install, затем setup",
        )
    })?;
    println!("Будет выполнена установка недостающих системных пакетов, затем проверка данных.");
    ui_terminal::supervise(Command::new(launcher).args(["deps", "--install"]))?;
    setup(&["setup"])
}
pub fn run(args: &[&str]) -> Result<()> {
    if args.last().is_some_and(|a| ["--help", "-h"].contains(a)) {
        let command = args.first().copied().unwrap_or("menu");
        if ![
            "--help", "-h", "menu", "setup", "update", "run", "diagnose", "config", "doctor",
            "paths", "status", "recover", "service",
        ]
        .contains(&command)
        {
            return Err(usage());
        }
        println!(
            "zapret-linux-rs — меню запуска\n\nПример: ./service.sh\nСтрелки — выбрать, Enter — открыть, Esc — назад.\n\nКоманды: menu, setup, update, run, diagnose, config, doctor, paths, status, recover, service.\n./service.sh status — краткое состояние без sudo\n./service.sh run — запуск до Ctrl+C\n./service.sh diagnose — проверить все стратегии\n./service.sh config --strategy \"general (ALT11).bat\" — сохранить выбор\n./service.sh service apply — применить сохранённые настройки\n./service.sh service recover — восстановить прерванную операцию\n./service.sh service start|stop|restart|enable|disable|status|install|remove\n\nsetup и update: --archive-dir DIR, --json.\nconfig: --json, --strategy NAME, --interface NAME, --gamefilter-tcp true|false, --gamefilter-udp true|false.\ndoctor и status: --json. Выбор из результатов подбора доступен в меню."
        );
        return Ok(());
    }
    match args {
        ["job", name] => crate::ui_tui::job(name),
        ["status"] | ["status", "--json"] => {
            let s = crate::service_status::observe();
            if args.contains(&"--json") {
                println!("{}", json!({"service":s.json()}));
            } else {
                println!("Состояние: {}", s.state.label());
                println!(
                    "Стратегия: {}",
                    s.running_strategy
                        .as_deref()
                        .unwrap_or("Не удалось определить")
                );
                if let Some(detail) = s.detail {
                    println!("{detail}");
                }
            }
            Ok(())
        }
        [] | ["menu"] if crate::ui_tui::supported() => crate::ui_tui::run(),
        [] | ["menu"] => crate::ui_screens::run(),
        ["paths"] | ["doctor", "--json"] => {
            println!("{}", app_setup::ui(args)?);
            Ok(())
        }
        ["doctor"] => doctor(),
        ["setup" | "update", ..] => setup(args),
        ["config", rest @ ..] => config(rest),
        ["run"] => ui_actions::launch("run", None),
        ["diagnose"] => ui_actions::launch("diagnose", None),
        ["recover"] => ui_actions::launch("recover", None),
        ["service"] => crate::ui_diagnostics::help(&AppPaths::discover()?).map(|_| ()),
        ["service", action] => ui_actions::launch("service", Some(action)),
        ["worker", "--events", rest @ ..] => ui_actions::worker_events(rest),
        ["worker", rest @ ..] => ui_actions::worker(rest),
        _ => Err(usage()),
    }
}
