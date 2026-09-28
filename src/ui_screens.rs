use crate::{
    app_paths::AppPaths,
    app_setup,
    error::{AppError, Result},
    service_status,
    ui_actions::{self, Action},
    ui_model::{ActionOutcome, ActionStatus, InstalledConfig, RuntimeState},
    ui_store::{self, RunMode},
    ui_terminal::{self, MenuItem, Selection},
};
use serde_json::Value;
thread_local! {static LAST_ERROR:std::cell::RefCell<Option<String>>=const{std::cell::RefCell::new(None)};}
pub fn last_error() -> String {
    LAST_ERROR
        .with(|e| e.borrow().clone())
        .unwrap_or_else(|| "Ошибок в этой сессии нет".into())
}
pub fn acknowledge() -> Result<Selection> {
    Ok(if ui_terminal::prompt("Enter — вернуться: ")?.is_some() {
        Selection::Back
    } else {
        Selection::Exit
    })
}
pub fn problem(e: &AppError) -> Result<()> {
    if e.kind == "shutdown" {
        return Err(AppError::new("shutdown", e.message.clone()));
    }
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(format!("{}: {}", e.kind, e.message)));
    let text = match e.kind {
        "apply_failed_restored" => {
            "Новые настройки не запустились. Прежняя установка восстановлена. Выберите другую стратегию."
        }
        "recovery_required" => {
            "Операция не завершена. Состояние запуска требует проверки. Откройте «Помощь и диагностика → Восстановление»."
        }
        "config_changed" | "inputs_changed" | "installation_changed" => {
            "Настройки изменились в другом окне. Откройте форму заново."
        }
        "protocol" => {
            "Не получен надёжный итог действия. Проверьте сообщения sudo и состояние службы."
        }
        "preflight" | "ownership" => {
            "Запуск остановлен проверкой окружения. Откройте диагностику и подробности ошибки."
        }
        _ => "Не удалось завершить действие. Откройте подробности ошибки в разделе помощи.",
    };
    println!("\n{text}");
    Ok(())
}
pub fn outcome(o: &ActionOutcome) -> Result<bool> {
    if o.restoration == "restored" {
        println!("Прежний фоновый запуск восстановлен.");
    }
    match o.status {
        ActionStatus::Completed => {
            let s = &o.data["service"];
            if s["runtime"] == "active" {
                println!(
                    "Работает в фоне. Стратегия: {}.\nАвтозапуск: {}.",
                    s["strategy"].as_str().unwrap_or("не удалось определить"),
                    if s["enabled"] == true {
                        "включён"
                    } else {
                        "выключен"
                    }
                );
            } else if s["runtime"] == "inactive" {
                println!(
                    "Фоновый запуск остановлен. Автозапуск: {}.",
                    if s["enabled"] == true {
                        "включён"
                    } else {
                        "выключен"
                    }
                );
            } else {
                println!("Действие выполнено.");
            }
            Ok(true)
        }
        ActionStatus::Cancelled => {
            println!(
                "Действие отменено. Очистка: {}.",
                if o.cleanup == "confirmed" {
                    "подтверждена"
                } else {
                    "не требовалась"
                }
            );
            Ok(false)
        }
        _ => {
            let message = o
                .error
                .as_ref()
                .and_then(|e| e["message"].as_str())
                .unwrap_or("Итог действия неизвестен");
            let kind = if o.status == ActionStatus::NeedsRecovery {
                "recovery_required"
            } else if o
                .error
                .as_ref()
                .is_some_and(|e| e["kind"] == "apply_failed_restored")
            {
                "apply_failed_restored"
            } else {
                "action"
            };
            problem(&AppError::new(kind, message))?;
            Ok(false)
        }
    }
}
pub fn service(action: &str) -> Result<bool> {
    outcome(&ui_actions::execute(
        &Action::Service(action.into()),
        None,
        &mut |_| Ok(()),
    )?)
}
pub fn allow_pause() -> Result<Option<bool>> {
    let s = service_status::observe();
    if s.state == RuntimeState::Running {
        return Ok(ui_terminal::confirm("Временная остановка","На время проверки zapret будет остановлен.\nПосле проверки восстановим текущую стратегию.")?.then_some(true));
    }
    if matches!(
        s.state,
        RuntimeState::Starting
            | RuntimeState::Stopping
            | RuntimeState::Unknown
            | RuntimeState::RecoveryRequired
    ) && s.installed.is_some()
    {
        return Err(AppError::new(
            "recovery_required",
            "Состояние службы не позволяет начать проверку",
        ));
    }
    Ok(Some(false))
}
pub fn matches_installed(
    installed: &InstalledConfig,
    config: &crate::config::Config,
    bundle: &app_setup::Bundle,
) -> bool {
    if installed.config != *config {
        return false;
    }
    let Ok(manifest) = serde_json::from_slice::<Value>(&bundle.manifest_bytes) else {
        return false;
    };
    let Some(files) = manifest["files"].as_array() else {
        return false;
    };
    files
        .iter()
        .filter(|f| {
            f["path"].as_str().is_some_and(|p| {
                p.starts_with("assets/")
                    || p == "bin/nfqws"
                    || p == format!("strategies/{}", config.strategy)
            })
        })
        .all(|f| {
            let path = f["path"].as_str().unwrap();
            let path = if path.starts_with("strategies/") {
                "strategies/selected.bat"
            } else {
                path
            };
            installed.inventory[path]["sha256"] == f["sha256"]
        })
}
pub fn ready(paths: &AppPaths) -> bool {
    app_setup::validate_bundle(paths)
        .and_then(|b| app_setup::validate_config(&ui_store::load_draft(paths)?.config, &b))
        .is_ok()
}
pub fn ensure_ready(paths: &AppPaths) -> Result<bool> {
    if ready(paths) {
        return Ok(true);
    }
    if !ui_terminal::confirm(
        "Нужна подготовка",
        "Проверим зависимости и загрузим проверенные данные.\nДля установки недостающих пакетов может потребоваться пароль.",
    )? {
        return Ok(false);
    }
    crate::ui::preparation()?;
    Ok(true)
}
pub fn mode_choice() -> Result<Option<RunMode>> {
    let state = service_status::observe();
    let mut bg = MenuItem::new("background", "Работать в фоне");
    if matches!(
        state.state,
        RuntimeState::Unavailable | RuntimeState::Unknown
    ) {
        bg.enabled = false;
        bg.detail =
            Some("Не удалось подтвердить доступность systemd. Можно запустить в терминале.".into());
    }
    Ok(
        match ui_terminal::select(
            "Режим запуска",
            &[
                MenuItem::new("terminal", "Попробовать до закрытия терминала"),
                bg,
            ],
            0,
            false,
        )? {
            Selection::Item(s) if s == "terminal" => Some(RunMode::Terminal),
            Selection::Item(_) => Some(RunMode::Background),
            _ => None,
        },
    )
}
pub fn trial(paths: &AppPaths, config: &crate::config::Config) -> Result<()> {
    if !ensure_ready(paths)? {
        return Ok(());
    }
    let Some(allow_pause) = allow_pause()? else {
        return Ok(());
    };
    let inputs = ui_store::prepare_inputs(paths, config)?;
    println!(
        "Стратегия: {}\nCtrl+C — остановить и вернуться",
        config.strategy
    );
    let result = ui_actions::execute(&Action::Run { allow_pause }, Some(&inputs), &mut |v| {
        print!("{}", crate::output::render_event(v));
        Ok(())
    });
    let result = crate::error::combine(result, ui_store::remove_inputs(paths, &inputs))?;
    outcome(&result)?;
    Ok(())
}
pub fn start(paths: &AppPaths) -> Result<()> {
    if !ensure_ready(paths)? {
        return Ok(());
    }
    let paths = AppPaths::discover()?;
    let mode = match ui_store::load_mode(&paths)? {
        Some(m) => m,
        None => {
            let Some(m) = mode_choice()? else {
                return Ok(());
            };
            ui_store::save_mode(&paths, m)?;
            m
        }
    };
    let config = ui_store::load_draft(&paths)?.config;
    let inputs = ui_store::prepare_inputs(&paths, &config)?;
    let result = (|| {
        if mode == RunMode::Terminal {
            let Some(allow_pause) = allow_pause()? else {
                return Ok(());
            };
            println!(
                "Стратегия: {}\nCtrl+C — остановить и вернуться",
                config.strategy
            );
            let r = ui_actions::execute(&Action::Run { allow_pause }, Some(&inputs), &mut |v| {
                print!("{}", crate::output::render_event(v));
                Ok(())
            })?;
            outcome(&r)?;
        } else {
            let state = service_status::observe();
            if let Some(installed) = state.installed {
                let b = app_setup::validate_bundle(&paths)?;
                if !matches_installed(&installed, &config, &b) {
                    if !ui_terminal::confirm(
                        "Применить выбранные настройки?",
                        &format!(
                            "Установлено: {}\nВыбрано: {}\nБудет заменена конфигурация фонового запуска.",
                            installed.strategy, config.strategy
                        ),
                    )? {
                        return Ok(());
                    }
                    if !outcome(&ui_actions::apply(&inputs, &installed.installation_id)?)? {
                        return Ok(());
                    }
                }
            } else {
                if state.state != RuntimeState::Absent {
                    return Err(AppError::new(
                        "service",
                        "Фоновый режим сейчас недоступен; выберите запуск в терминале",
                    ));
                }
                let enable = match ui_terminal::select(
                    "Запускать при включении компьютера?",
                    &[
                        MenuItem::new("off", "Нет — запускать из меню"),
                        MenuItem::new("on", "Да — включить автозапуск"),
                    ],
                    0,
                    false,
                )? {
                    Selection::Item(s) => s == "on",
                    _ => return Ok(()),
                };
                if !outcome(&ui_actions::execute(
                    &Action::Service("install".into()),
                    Some(&inputs),
                    &mut |_| Ok(()),
                )?)? {
                    return Ok(());
                }
                if enable && !service("enable")? {
                    return Ok(());
                }
            }
            service("start")?;
        }
        Ok(())
    })();
    crate::error::combine(result, ui_store::remove_inputs(&paths, &inputs))
}
pub fn setup_wizard(paths: &AppPaths) -> Result<Selection> {
    if !ensure_ready(paths)? {
        return Ok(Selection::Back);
    }
    let paths = AppPaths::discover()?;
    match ui_terminal::select(
        "Первый запуск · стратегия",
        &[
            MenuItem::new("diagnose", "Подобрать по результатам проверки"),
            MenuItem::new("manual", "Выбрать вручную"),
        ],
        0,
        false,
    )? {
        Selection::Item(s) if s == "diagnose" => match crate::ui_diagnostics::diagnose(&paths)? {
            Selection::Item(_) => (),
            other => return Ok(other),
        },
        Selection::Item(_) => {
            let mut draft = ui_store::load_draft(&paths)?;
            match crate::ui_settings::choose_strategy(&paths, &mut draft)? {
                Selection::Item(_) => {
                    ui_store::save_draft(&paths, &draft)?;
                }
                other => return Ok(other),
            }
        }
        other => return Ok(other),
    }
    let Some(mode) = mode_choice()? else {
        return Ok(Selection::Back);
    };
    ui_store::save_mode(&paths, mode)?;
    start(&paths)?;
    acknowledge()
}
pub fn run() -> Result<()> {
    let signals = crate::signals::Signals::install()?;
    if !ui_terminal::is_terminal() {
        return Err(AppError::new(
            "usage",
            "Меню требует интерактивный терминал; используйте ./service.sh --help",
        ));
    }
    loop {
        let paths = AppPaths::discover()?;
        let state = service_status::observe();
        let draft = ui_store::load_draft(&paths);
        let prepared = ready(&paths);
        let first = if state.state == RuntimeState::RecoveryRequired {
            "Разобраться с ошибкой"
        } else if state.state == RuntimeState::Running {
            "Остановить"
        } else if !prepared {
            "Настроить и запустить"
        } else {
            match state.state {
                RuntimeState::Running => "Остановить",
                RuntimeState::Failed
                | RuntimeState::RecoveryRequired
                | RuntimeState::Unknown
                | RuntimeState::Starting
                | RuntimeState::Stopping => "Разобраться с ошибкой",
                _ => "Запустить",
            }
        };
        let mut heading = format!(
            "ZAPRET\nСостояние: {}\nРаботает с: {}\nАвтозапуск: {}",
            state.state.label(),
            state
                .running_strategy
                .as_deref()
                .unwrap_or(if state.state == RuntimeState::Running {
                    "Не удалось определить"
                } else {
                    "—"
                }),
            state
                .enabled
                .map(|e| if e {
                    "Включён"
                } else {
                    "Выключен"
                })
                .unwrap_or("Не удалось определить")
        );
        if let Ok(draft) = &draft {
            heading.push_str(&format!(
                "\nВыбрано для применения: {}",
                draft.config.strategy
            ));
        }
        let choice = ui_terminal::select(
            &heading,
            &[
                MenuItem::new("primary", first),
                MenuItem::new("diagnose", "Подобрать стратегию"),
                MenuItem::new("settings", "Настройки"),
                MenuItem::new("update", "Обновление"),
                MenuItem::new("help", "Помощь и диагностика"),
            ],
            0,
            false,
        )?;
        let Selection::Item(action) = choice else {
            return Ok(());
        };
        let result = match action.as_str() {
            "primary" if first == "Разобраться с ошибкой" => {
                crate::ui_diagnostics::help(&paths)
            }
            "primary" if state.state == RuntimeState::Running => {
                service("stop").and_then(|_| acknowledge())
            }
            "primary" if !prepared => setup_wizard(&paths),
            "primary" if first == "Разобраться с ошибкой" => {
                crate::ui_diagnostics::help(&paths)
            }
            "primary" => start(&paths).and_then(|_| acknowledge()),
            "diagnose" => crate::ui_diagnostics::run(&paths),
            "settings" => crate::ui_settings::run(&paths),
            "update" => crate::ui_diagnostics::update(&paths),
            _ => crate::ui_diagnostics::help(&paths),
        };
        signals.clear_interrupt();
        match result {
            Ok(Selection::Exit) => return Ok(()),
            Err(e) => {
                problem(&e)?;
                if acknowledge()? == Selection::Exit {
                    return Ok(());
                }
            }
            _ => (),
        }
    }
}
