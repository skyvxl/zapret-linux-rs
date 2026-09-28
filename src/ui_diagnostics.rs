use crate::{
    app_paths::AppPaths,
    app_setup,
    error::Result,
    ui_actions::{self, Action},
    ui_screens, ui_settings,
    ui_store::{self, DiagnosisRecord},
    ui_terminal::{self, MenuItem, Selection},
};
use serde_json::{Value, json};
fn targets() -> Result<Value> {
    Ok(json!(
        crate::diagnostic_targets::load(None)?
            .iter()
            .map(|t| t.json())
            .collect::<Vec<_>>()
    ))
}
pub fn diagnose(paths: &AppPaths) -> Result<Selection> {
    if !ui_screens::ensure_ready(paths)? {
        return Ok(Selection::Back);
    }
    let paths = AppPaths::discover()?;
    let Some(allow_pause) = ui_screens::allow_pause()? else {
        return Ok(Selection::Back);
    };
    let config = ui_store::load_draft(&paths)?.config;
    let bundle = app_setup::validate_bundle(&paths)?;
    let fingerprint = ui_store::fingerprint(&config, &bundle.manifest_bytes, &targets()?)?;
    let inputs = ui_store::prepare_inputs(&paths, &config)?;
    let mut report = None;
    let result = ui_actions::execute(&Action::Diagnose { allow_pause }, Some(&inputs), &mut |v| {
        if v["event"] == "diagnosis_complete" {
            report = Some(v["report"].clone());
        }
        print!("{}", crate::output::render_event(v));
        Ok(())
    });
    let remove = ui_store::remove_inputs(&paths, &inputs);
    let record = report.map(|report| DiagnosisRecord {
        fingerprint,
        report,
        cleanup_confirmed: result.as_ref().is_ok_and(|r| r.cleanup == "confirmed"),
        restoration_confirmed: result
            .as_ref()
            .is_ok_and(|r| ["restored", "not_needed"].contains(&r.restoration.as_str())),
    });
    if let Some(r) = &record
        && let Err(e) = ui_store::save_diagnosis(&paths, r)
    {
        println!("Проверка завершилась, но сохранить отчёт не удалось.");
        ui_screens::problem(&e)?;
    }
    let result = crate::error::combine(result, remove)?;
    ui_screens::outcome(&result)?;
    if let Some(r) = record {
        results(&paths, &r)
    } else {
        ui_screens::acknowledge()
    }
}
pub fn results(paths: &AppPaths, record: &DiagnosisRecord) -> Result<Selection> {
    let draft = ui_store::load_draft(paths)?;
    let current = app_setup::validate_bundle(paths)
        .and_then(|b| ui_store::fingerprint(&draft.config, &b.manifest_bytes, &targets()?));
    let stale = current.as_ref().is_ok_and(|s| s != &record.fingerprint) || current.is_err();
    let passed = record.report["tcp_passed"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut rows = record.report["strategies"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    rows.sort_by_key(|r| !passed.contains(&r["strategy"]));
    let title = format!(
        "Результаты подбора{}{}\nПроверяется доступ к сайтам. Видео и голосовую связь проверьте отдельно",
        if stale {
            " · устаревший отчёт"
        } else {
            ""
        },
        if record.report["status"] == "aborted" {
            " · проверка прервана"
        } else {
            ""
        }
    );
    if rows.is_empty() {
        println!("Проверенных стратегий пока нет.");
        return ui_screens::acknowledge();
    }
    loop {
        let items: Vec<_> = rows
            .iter()
            .map(|r| {
                let name = r["strategy"].as_str().unwrap_or("?");
                let tcp = if passed.contains(&r["strategy"]) {
                    "TCP: пройдено"
                } else if r["status"] == "not_run" {
                    "Не проверена"
                } else {
                    "TCP: не пройдено"
                };
                let quic = if record.report["quic_passed"]
                    .as_array()
                    .is_some_and(|a| a.contains(&r["strategy"]))
                {
                    "QUIC: пройдено"
                } else if r["checks"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|c| c["transport"] == "quic" && c["status"] == "unsupported")
                }) {
                    "QUIC: не поддерживается"
                } else {
                    "QUIC: не пройдено"
                };
                MenuItem::new(
                    name,
                    format!("{} · {tcp} · {quic}", name.trim_end_matches(".bat")),
                )
            })
            .collect();
        let Selection::Item(name) = ui_terminal::select(&title, &items, 0, true)? else {
            return Ok(Selection::Back);
        };
        let row = rows.iter().find(|r| r["strategy"] == name).unwrap();
        let mut choose = MenuItem::new("choose", "Выбрать эту стратегию");
        choose.enabled = record.cleanup_confirmed && record.restoration_confirmed;
        if !choose.enabled {
            choose.detail = Some(
                "Сначала подтвердите очистку и восстановите службу через раздел помощи".into(),
            );
        }
        match ui_terminal::select(
            &format!(
                "{name}\n{}",
                if stale {
                    "Данные изменились: рекомендуется повторить подбор"
                } else {
                    "Результат относится к последней проверке"
                }
            ),
            &[choose, MenuItem::new("details", "Подробности проверки")],
            0,
            false,
        )? {
            Selection::Item(s) if s == "choose" => {
                let mut draft = ui_store::load_draft(paths)?;
                draft.config.strategy = name.clone();
                let b = app_setup::validate_bundle(paths)?;
                app_setup::validate_config(&draft.config, &b)?;
                if ui_settings::finish_draft(paths, &draft)? {
                    return Ok(if ui_screens::acknowledge()? == Selection::Exit {
                        Selection::Exit
                    } else {
                        Selection::Item(name)
                    });
                }
            }
            Selection::Item(_) => {
                println!("{}", serde_json::to_string_pretty(row).unwrap_or_default());
                if ui_screens::acknowledge()? == Selection::Exit {
                    return Ok(Selection::Exit);
                }
            }
            Selection::Exit => return Ok(Selection::Exit),
            _ => (),
        }
    }
}
pub fn run(paths: &AppPaths) -> Result<Selection> {
    loop {
        match ui_terminal::select(
            "Подбор стратегии",
            &[
                MenuItem::new("check", "Проверить все стратегии"),
                MenuItem::new("last", "Результаты последнего подбора"),
                MenuItem::new("manual", "Выбрать вручную"),
            ],
            0,
            false,
        )? {
            Selection::Item(s) if s == "check" => return diagnose(paths),
            Selection::Item(s) if s == "last" => {
                if let Some(r) = ui_store::load_diagnosis(paths)? {
                    return results(paths, &r);
                }
                println!("Сохранённых результатов пока нет.");
                if ui_screens::acknowledge()? == Selection::Exit {
                    return Ok(Selection::Exit);
                }
            }
            Selection::Item(_) => {
                let mut draft = ui_store::load_draft(paths)?;
                if let Selection::Item(_) = ui_settings::choose_strategy(paths, &mut draft)? {
                    ui_settings::finish_draft(paths, &draft)?;
                    return ui_screens::acknowledge();
                }
            }
            other => return Ok(other),
        }
    }
}
pub fn update(paths: &AppPaths) -> Result<Selection> {
    if !ui_terminal::confirm(
        "Обновление стратегий и данных",
        "Загрузим новый набор и проверим его.\nРаботающая служба продолжит использовать прежний набор до применения.",
    )? {
        return Ok(Selection::Back);
    }
    crate::ui::run(&["update"])?;
    let paths = AppPaths::discover().unwrap_or_else(|_| paths.clone());
    if crate::service_status::observe().installed.is_some() {
        ui_settings::finish_draft(&paths, &ui_store::load_draft(&paths)?)?;
    }
    ui_screens::acknowledge()
}
pub fn help(paths: &AppPaths) -> Result<Selection> {
    loop {
        let s = ui_terminal::select(
            "Помощь и диагностика\nСтратегия — набор способов обхода. Фон работает после закрытия меню.\nАвтозапуск включает фоновый режим при включении компьютера.",
            &[
                MenuItem::new("doctor", "Проверить окружение"),
                MenuItem::new("status", "Подробное состояние службы"),
                MenuItem::new("results", "Последний подбор"),
                MenuItem::new("error", "Подробности последней ошибки"),
                MenuItem::new("recover", "Восстановление после прерванного запуска"),
                MenuItem::new("prepare", "Подготовить зависимости и данные"),
                MenuItem::new("remove", "Удалить фоновую службу"),
            ],
            0,
            false,
        )?;
        let Selection::Item(s) = s else { return Ok(s) };
        match s.as_str() {
            "doctor" => crate::ui::run(&["doctor"])?,
            "status" => {
                let result =
                    ui_actions::execute(&Action::Service("status".into()), None, &mut |_| Ok(()))?;
                if ui_screens::outcome(&result)? {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result.data).unwrap_or_default()
                    );
                }
            }
            "results" => {
                if let Some(r) = ui_store::load_diagnosis(paths)? {
                    if results(paths, &r)? == Selection::Exit {
                        return Ok(Selection::Exit);
                    }
                    continue;
                }
                println!("Сохранённых результатов пока нет.");
            }
            "error" => println!("{}", ui_screens::last_error()),
            "recover" => {
                if ui_terminal::confirm(
                    "Восстановление",
                    "Проверим журнал операции и принадлежащие zapret правила.\nПри необходимости восстановим прежнюю службу.",
                )? {
                    ui_screens::service("recover")?;
                    ui_actions::launch("recover", None)?;
                }
            }
            "prepare" => {
                if ui_terminal::confirm(
                    "Подготовка",
                    "Установить недостающие пакеты и проверить данные?",
                )? {
                    crate::ui::preparation()?;
                }
            }
            "remove"
                if ui_terminal::confirm(
                    "Удалить фоновую службу?",
                    "Служба будет остановлена и удалена.\nВаши настройки и загруженные стратегии сохранятся.",
                )? =>
            {
                ui_screens::service("remove")?;
            }
            _ => (),
        }
        if ui_screens::acknowledge()? == Selection::Exit {
            return Ok(Selection::Exit);
        }
    }
}
