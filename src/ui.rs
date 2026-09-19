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
fn preparation() -> Result<()> {
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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Navigation {
    Back,
    Exit,
}
fn acknowledge() -> Result<Navigation> {
    Ok(
        if ui_terminal::prompt("Нажмите Enter для продолжения: ")?.is_some() {
            Navigation::Back
        } else {
            Navigation::Exit
        },
    )
}
fn show_result(result: Result<()>) -> Result<()> {
    if let Err(error) = result {
        if error.kind == "shutdown" {
            return Err(error);
        }
        human_error(&error);
    }
    Ok(())
}
fn choose_strategy() -> Result<Navigation> {
    ui_terminal::redraw();
    ui_terminal::title("Выбор стратегии (0 — назад)");
    let paths = AppPaths::discover()?;
    let bundle = app_setup::validate_bundle(&paths)?;
    for (i, name) in bundle.strategy_names.iter().enumerate() {
        println!(" {}. {name}", i + 1);
    }
    loop {
        let Some(choice) = ui_terminal::prompt("Номер стратегии: ")? else {
            return Ok(Navigation::Back);
        };
        if choice == "0" {
            return Ok(Navigation::Back);
        }
        if let Ok(i) = choice.parse::<usize>()
            && i > 0
            && let Some(name) = bundle.strategy_names.get(i - 1)
        {
            show_result(config(&["--strategy", name]))?;
            return acknowledge();
        }
        println!("Неверный номер стратегии.");
        if acknowledge()? == Navigation::Exit {
            return Ok(Navigation::Exit);
        }
        ui_terminal::redraw();
        ui_terminal::title("Выбор стратегии (0 — назад)");
        for (i, name) in bundle.strategy_names.iter().enumerate() {
            println!(" {}. {name}", i + 1);
        }
    }
}
fn settings() -> Result<Navigation> {
    loop {
        let paths = AppPaths::discover()?;
        let c = paths.load_or_create_config()?;
        ui_terminal::redraw();
        ui_terminal::title("Настройки");
        config_text(&c);
        println!(
            "1. Интерфейс\n2. Переключить GameFilter TCP\n3. Переключить GameFilter UDP\n0. Назад"
        );
        let Some(choice) = ui_terminal::prompt("Выбор: ")? else {
            return Ok(Navigation::Back);
        };
        let result = match choice.as_str() {
            "0" => return Ok(Navigation::Back),
            "1" => {
                let Some(interface) = ui_terminal::prompt("Интерфейс (any — все): ")?
                else {
                    return Ok(Navigation::Back);
                };
                config(&["--interface", &interface])
            }
            "2" => config(&[
                "--gamefilter-tcp",
                if c.gamefiltertcp { "false" } else { "true" },
            ]),
            "3" => config(&[
                "--gamefilter-udp",
                if c.gamefilterudp { "false" } else { "true" },
            ]),
            _ => {
                println!("Неверный выбор.");
                if acknowledge()? == Navigation::Exit {
                    return Ok(Navigation::Exit);
                }
                continue;
            }
        };
        show_result(result)?;
        if acknowledge()? == Navigation::Exit {
            return Ok(Navigation::Exit);
        }
    }
}
fn service_menu() -> Result<Navigation> {
    loop {
        ui_terminal::redraw();
        ui_terminal::title("Системная служба");
        println!(
            "Служба хранит отдельный неизменяемый снимок настроек. Для замены: удалить, затем установить. Удаление останавливает только принадлежащую приложению службу."
        );
        println!(
            "1. Установить выбранную конфигурацию\n2. Запустить\n3. Остановить\n4. Перезапустить\n5. Автозапуск: включить\n6. Автозапуск: выключить\n7. Статус и установленная стратегия\n8. Удалить службу\n0. Назад"
        );
        let Some(choice) = ui_terminal::prompt("Выбор: ")? else {
            return Ok(Navigation::Back);
        };
        let action = match choice.as_str() {
            "0" => return Ok(Navigation::Back),
            "1" => "install",
            "2" => "start",
            "3" => "stop",
            "4" => "restart",
            "5" => "enable",
            "6" => "disable",
            "7" => "status",
            "8" => "remove",
            _ => {
                println!("Неверный выбор.");
                if acknowledge()? == Navigation::Exit {
                    return Ok(Navigation::Exit);
                }
                continue;
            }
        };
        show_result(ui_actions::launch("service", Some(action)))?;
        if acknowledge()? == Navigation::Exit {
            return Ok(Navigation::Exit);
        }
    }
}
fn menu() -> Result<()> {
    if !ui_terminal::is_terminal() {
        return Err(AppError::new(
            "usage",
            "Меню требует интерактивный терминал; используйте ./service.sh --help или doctor",
        ));
    }
    loop {
        ui_terminal::redraw();
        ui_terminal::title("zapret-linux-rs");
        match AppPaths::discover().and_then(|p| p.load_or_create_config()) {
            Ok(c) => println!(
                "{} | {} | GameFilter TCP {} / UDP {}",
                c.strategy, c.interface, c.gamefiltertcp, c.gamefilterudp
            ),
            Err(e) => human_error(&e),
        }
        println!(
            "1. Подготовить зависимости и данные\n2. Запустить до Ctrl+C\n3. Диагностика всех стратегий\n4. Выбрать стратегию\n5. Настройки\n6. Системная служба\n7. Диагностика окружения\n8. Восстановить ручное состояние\n9. Обновить стратегии (явно, с загрузкой)\n0. Выход"
        );
        let Some(choice) = ui_terminal::prompt("Выбор: ")? else {
            return Ok(());
        };
        let result = match choice.as_str() {
            "0" => return Ok(()),
            "1" => preparation(),
            "2" => ui_actions::launch("run", None),
            "3" => ui_actions::launch("diagnose", None),
            "4" => match choose_strategy() {
                Ok(Navigation::Exit) => return Ok(()),
                Ok(Navigation::Back) => continue,
                Err(error) => Err(error),
            },
            "5" => match settings() {
                Ok(Navigation::Exit) => return Ok(()),
                Ok(Navigation::Back) => continue,
                Err(error) => Err(error),
            },
            "6" => match service_menu() {
                Ok(Navigation::Exit) => return Ok(()),
                Ok(Navigation::Back) => continue,
                Err(error) => Err(error),
            },
            "7" => doctor(),
            "8" => ui_actions::launch("recover", None),
            "9" => setup(&["update"]),
            _ => {
                println!("Неверный выбор. Введите число от 0 до 9.");
                if acknowledge()? == Navigation::Exit {
                    return Ok(());
                }
                continue;
            }
        };
        show_result(result)?;
        if acknowledge()? == Navigation::Exit {
            return Ok(());
        }
    }
}
pub fn run(args: &[&str]) -> Result<()> {
    match args {
        [] | ["menu"] => menu(),
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
        ["service"] => service_menu().map(|_| ()),
        ["service", action] => ui_actions::launch("service", Some(action)),
        ["worker", rest @ ..] => ui_actions::worker(rest),
        _ => Err(usage()),
    }
}
