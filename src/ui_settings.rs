use crate::{
    app_paths::AppPaths,
    app_setup,
    error::{AppError, Result},
    service_status, ui_actions,
    ui_model::RuntimeState,
    ui_screens,
    ui_store::{self, Draft},
    ui_terminal::{self, MenuItem, Selection},
};
fn switch(v: bool) -> &'static str {
    if v {
        "Включён"
    } else {
        "Выключен"
    }
}
pub fn choose_strategy(paths: &AppPaths, draft: &mut Draft) -> Result<Selection> {
    if !ui_screens::ensure_ready(paths)? {
        return Ok(Selection::Back);
    }
    let paths = AppPaths::discover()?;
    let bundle = app_setup::validate_bundle(&paths)?;
    let items: Vec<_> = bundle
        .strategy_names
        .iter()
        .map(|name| {
            let mut item = MenuItem::new(name, name.trim_end_matches(".bat"));
            item.detail = Some(name.clone());
            item
        })
        .collect();
    let selected = bundle
        .strategy_names
        .iter()
        .position(|n| n == &draft.config.strategy)
        .unwrap_or(0);
    let choice = ui_terminal::select("Выбор стратегии · / поиск", &items, selected, true)?;
    if let Selection::Item(name) = &choice {
        draft.config.strategy = name.clone();
    }
    Ok(choice)
}
fn interface(draft: &mut Draft) -> Result<Selection> {
    let mut items = vec![MenuItem::new("any", "Все подключения (рекомендуется)")];
    let mut names = std::fs::read_dir("/sys/class/net")
        .map_err(crate::service_fs::fail)?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(crate::service_fs::fail)?;
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let name = e.file_name().to_string_lossy().into_owned();
        let state = std::fs::read_to_string(e.path().join("operstate")).unwrap_or_default();
        items.push(MenuItem::new(
            &name,
            format!(
                "{name} — {}",
                match state.trim() {
                    "up" => "активно",
                    "down" => "не активно",
                    _ => "состояние неизвестно",
                }
            ),
        ));
    }
    let selected = items
        .iter()
        .position(|i| i.id == draft.config.interface)
        .unwrap_or(0);
    let title = if draft.config.interface != "any" && selected == 0 {
        format!(
            "Сетевое подключение\nСохранённое {} сейчас отсутствует",
            draft.config.interface
        )
    } else {
        "Сетевое подключение".into()
    };
    let s = ui_terminal::select(&title, &items, selected, false)?;
    if let Selection::Item(name) = &s {
        crate::host_run::check_interface(name)?;
        draft.config.interface = name.clone();
    }
    Ok(s)
}
pub fn finish_draft(paths: &AppPaths, draft: &Draft) -> Result<bool> {
    let state = service_status::observe();
    let mut items = vec![MenuItem::new(
        "later",
        if state.installed.is_some() {
            "Сохранить на потом"
        } else {
            "Сохранить"
        },
    )];
    if state.installed.is_some() {
        let mut apply = MenuItem::new(
            "apply",
            if state.state == RuntimeState::Running {
                "Применить и перезапустить"
            } else {
                "Применить"
            },
        );
        apply.enabled = matches!(
            state.state,
            RuntimeState::Running | RuntimeState::Stopped | RuntimeState::Failed
        );
        if !apply.enabled {
            apply.detail = Some("Сначала проверьте состояние службы в разделе помощи".into());
        }
        items.push(apply);
    }
    let Selection::Item(action) = ui_terminal::select(
        &format!(
            "Сохранение настроек\nСтратегия: {}\nПодключение: {}",
            draft.config.strategy, draft.config.interface
        ),
        &items,
        0,
        false,
    )?
    else {
        return Ok(false);
    };
    crate::host_run::check_interface(&draft.config.interface)?;
    ui_store::save_draft(paths, draft)?;
    println!("Настройки сохранены для следующего запуска.");
    if action == "apply" {
        let inputs = ui_store::prepare_inputs(paths, &draft.config)?;
        let result = ui_actions::apply(&inputs, &state.installed.unwrap().installation_id);
        let cleanup = ui_store::remove_inputs(paths, &inputs);
        let outcome = crate::error::combine(result, cleanup)?;
        if !ui_screens::outcome(&outcome)? {
            println!(
                "Пользовательские настройки сохранены. Результат применения к службе указан выше."
            );
        }
    }
    Ok(true)
}
pub fn run(paths: &AppPaths) -> Result<Selection> {
    let mut draft = ui_store::load_draft(paths)?;
    loop {
        let mode = ui_store::load_mode(paths)?
            .map(|m| m.label())
            .unwrap_or("Выбрать при запуске");
        let title = format!(
            "Настройки · Esc отменяет несохранённые изменения\nСтратегия: {}\nРежим: {mode}",
            draft.config.strategy
        );
        let items = [
            MenuItem::new("strategy", "Стратегия"),
            MenuItem::new("mode", "Режим работы"),
            MenuItem::new("autostart", "Автозапуск компьютера"),
            MenuItem::new(
                "interface",
                format!(
                    "Сетевое подключение: {}",
                    if draft.config.interface == "any" {
                        "Все подключения"
                    } else {
                        &draft.config.interface
                    }
                ),
            ),
            MenuItem::new(
                "tcp",
                format!("GameFilter TCP: {}", switch(draft.config.gamefiltertcp)),
            ),
            MenuItem::new(
                "udp",
                format!("GameFilter UDP: {}", switch(draft.config.gamefilterudp)),
            ),
            MenuItem::new("lists", "Списки и ipset"),
            MenuItem::new("save", "Завершить редактирование"),
            MenuItem::new("trial", "Пробный запуск в терминале"),
        ];
        let Selection::Item(action) = ui_terminal::select(&title, &items, 0, false)? else {
            return Ok(Selection::Back);
        };
        match action.as_str() {
            "trial" => {
                ui_screens::trial(paths, &draft.config)?;
                if ui_screens::acknowledge()? == Selection::Exit {
                    return Ok(Selection::Exit);
                }
            }
            "lists" => {
                lists(paths)?;
            }
            "strategy" => {
                if choose_strategy(paths, &mut draft)? == Selection::Exit {
                    return Ok(Selection::Exit);
                }
            }
            "interface" => {
                if interface(&mut draft)? == Selection::Exit {
                    return Ok(Selection::Exit);
                }
            }
            "tcp" | "udp" => {
                let selected = if action == "tcp" {
                    draft.config.gamefiltertcp
                } else {
                    draft.config.gamefilterudp
                };
                if let Selection::Item(s) = ui_terminal::select(
                    "GameFilter · дополнительные порты из стратегии\nНе гарантирует работу всех игр или звонков.",
                    &[
                        MenuItem::new("off", "Выключен"),
                        MenuItem::new("on", "Включён"),
                    ],
                    usize::from(selected),
                    false,
                )? {
                    if action == "tcp" {
                        draft.config.gamefiltertcp = s == "on";
                    } else {
                        draft.config.gamefilterudp = s == "on";
                    }
                }
            }
            "mode" => {
                if let Some(m) = ui_screens::mode_choice()?
                    && ui_terminal::confirm("Сохранить режим запуска?", m.label())?
                {
                    ui_store::save_mode(paths, m)?;
                }
            }
            "autostart" => {
                let state = service_status::observe();
                if state.installed.is_none() {
                    println!("Автозапуск предлагается при первом запуске в фоне.");
                    ui_screens::acknowledge()?;
                    continue;
                }
                if let Selection::Item(s) = ui_terminal::select(
                    "Автозапуск при включении компьютера",
                    &[
                        MenuItem::new("disable", "Выключить"),
                        MenuItem::new("enable", "Включить"),
                    ],
                    usize::from(state.enabled == Some(true)),
                    false,
                )? && ui_terminal::confirm(
                    "Изменить автозапуск?",
                    "Текущий запуск продолжится. Изменится запуск при включении компьютера.",
                )? {
                    ui_screens::service(&s)?;
                    ui_screens::acknowledge()?;
                }
            }
            "save" if finish_draft(paths, &draft)? => return ui_screens::acknowledge(),
            _ => (),
        }
    }
}

pub fn lists(paths: &AppPaths) -> Result<()> {
    loop {
        let mode = crate::user_lists::load_ipset_mode(paths)?;
        let count = |name: &str| {
            crate::user_lists::read(paths, name)
                .map(|b| {
                    String::from_utf8_lossy(&b)
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .count()
                })
                .unwrap_or(0)
        };
        let heading = format!(
            "СПИСКИ И IPSET\nРедактируемые списки применяются при следующем запуске.\nРежим ipset-all: {}\nКаталог: {}",
            mode.label(),
            crate::user_lists::dir(paths).display()
        );
        let choice = ui_terminal::select(
            &heading,
            &[
                MenuItem::new(
                    "general",
                    format!(
                        "list-general-user.txt — свои домены (строк: {})",
                        count("list-general-user.txt")
                    ),
                ),
                MenuItem::new(
                    "exclude",
                    format!(
                        "list-exclude-user.txt — исключить домены (строк: {})",
                        count("list-exclude-user.txt")
                    ),
                ),
                MenuItem::new(
                    "ipset-exclude",
                    format!(
                        "ipset-exclude-user.txt — исключить IP/подсети (строк: {})",
                        count("ipset-exclude-user.txt")
                    ),
                ),
                MenuItem::new("ipset", format!("Режим ipset-all: {}", mode.label())),
                MenuItem::new(
                    "ipset-custom",
                    format!(
                        "ipset-all.txt.custom — свой список ipset (строк: {})",
                        count(crate::user_lists::IPSET_CUSTOM)
                    ),
                ),
                MenuItem::new("back", "Вернуться в меню"),
            ],
            0,
            false,
        )?;
        let Selection::Item(action) = choice else {
            return Ok(());
        };
        match action.as_str() {
            "general" => crate::user_lists::edit(paths, "list-general-user.txt")?,
            "exclude" => crate::user_lists::edit(paths, "list-exclude-user.txt")?,
            "ipset-exclude" => crate::user_lists::edit(paths, "ipset-exclude-user.txt")?,
            "ipset-custom" => crate::user_lists::edit(paths, crate::user_lists::IPSET_CUSTOM)?,
            "ipset" => {
                let modes = [
                    crate::user_lists::IpsetMode::None,
                    crate::user_lists::IpsetMode::Any,
                    crate::user_lists::IpsetMode::Loaded,
                    crate::user_lists::IpsetMode::Custom,
                ];
                let items: Vec<_> = modes
                    .iter()
                    .map(|m| {
                        let mut item =
                            MenuItem::new(m.name(), format!("{} — {}", m.label(), m.detail()));
                        item.detail = Some(m.detail().to_string());
                        if *m == mode {
                            item.detail = Some(format!("{} (текущий)", m.detail()));
                        }
                        item
                    })
                    .collect();
                if let Selection::Item(name) =
                    ui_terminal::select("Режим ipset-all", &items, 0, false)?
                {
                    let selected = crate::user_lists::IpsetMode::parse(&name)
                        .ok_or_else(|| AppError::new("lists", "Неизвестный режим"))?;
                    crate::user_lists::save_ipset_mode(paths, selected)?;
                    println!(
                        "Режим ipset-all: {}. Применится при следующем запуске.",
                        selected.label()
                    );
                }
            }
            _ => return Ok(()),
        }
    }
}
