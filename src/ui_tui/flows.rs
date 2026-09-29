use super::*;
pub(super) enum SaveResult {
    Cancelled,
    Saved,
    Applied,
    SavedNotApplied,
}
impl SaveResult {
    pub(super) fn leave_editor(&self) -> bool {
        matches!(self, Self::Saved | Self::Applied)
    }
}
fn switch(v: bool) -> &'static str {
    if v {
        "включён"
    } else {
        "выключен"
    }
}
impl App {
    pub(super) fn home_items(&self) -> Vec<Item> {
        let (id, label) = match self.observer.value["state"].as_str().unwrap_or("unknown") {
            "running" => ("stop", "Остановить"),
            "recovery_required" => ("recover", "Восстановить"),
            "starting" | "stopping" => ("status", "Проверить состояние"),
            "unknown" => ("status", "Проверить состояние"),
            _ => ("start", "Запустить"),
        };
        vec![
            Item::new(id, label),
            Item::new("strategies", "Стратегии"),
            Item::new("settings", "Настройки"),
            Item::new("update", "Обновление"),
            Item::new("help", "Помощь и диагностика"),
        ]
    }
    fn service_strategy_text(&self) -> String {
        let status = &self.observer.value;
        if let Some(strategy) = status["running_strategy"].as_str() {
            format!("Работает с: {strategy}")
        } else if let Some(strategy) = status["installed"]["strategy"].as_str() {
            format!("Стратегия службы: {strategy}")
        } else if status["state"] == "absent" {
            "Стратегия службы: не установлена".into()
        } else {
            "Стратегия службы: нет данных".into()
        }
    }
    pub(super) fn home_text(&self) -> String {
        let s = &self.observer.value;
        let draft = ui_store::load_draft(&self.paths);
        let selected = draft
            .as_ref()
            .map(|d| d.config.strategy.as_str())
            .unwrap_or("Не удалось прочитать");
        let unapplied = draft.as_ref().is_ok_and(|d| {
            !s["installed"].is_null() && s["installed"]["config"] != d.config.json()
        });
        format!(
            "Состояние: {}\n{}\nВыбрано: {}{}\nАвтозапуск: {}",
            s["label"].as_str().unwrap_or("Не удалось определить"),
            self.service_strategy_text(),
            selected,
            if unapplied {
                " (не применено)"
            } else {
                ""
            },
            match s["enabled"].as_bool() {
                Some(v) => switch(v),
                None => "неизвестен",
            }
        )
    }
    pub(super) fn home(&mut self) -> Result<()> {
        loop {
            let Some(id) = self.menu("Главное меню", "", &[], false)? else {
                return Ok(());
            };
            self.notice.clear();
            let result = match id.as_str() {
                "start" => self.start().map(|_| ()),
                "stop" => self.service("stop").map(|_| ()),
                "recover" => self.recover(),
                "status" => self.refresh_status(),
                "strategies" => self.strategies(),
                "settings" => self.settings(),
                "update" => self.update(),
                _ => self.help(),
            };
            if let Err(e) = result {
                self.problem(e)?;
            }
        }
    }
    fn prepare(&mut self) -> Result<bool> {
        if !self.confirm(
            "Подготовка",
            "Установить недостающие зависимости и загрузить проверенные данные?",
        )? {
            return Ok(false);
        }
        if let Some(launcher) = std::env::var_os("ZAPRET_LAUNCHER") {
            self.observer.stop();
            self.session.suspend();
            let result =
                crate::ui_terminal::supervise(Command::new(launcher).args(["deps", "--install"]));
            self.session.resume()?;
            self.signals.clear_interrupt();
            result?;
        } else {
            self.notice = "Для установки пакетов используйте ./service.sh deps --install".into();
        }
        Ok(self.local("setup", "Подготовка данных")?.status == ActionStatus::Completed)
    }
    pub(super) fn ready(&mut self) -> Result<bool> {
        if let Ok(bundle) = app_setup::validate_bundle(&self.paths) {
            let mut draft = ui_store::load_draft(&self.paths)?;
            if app_setup::validate_config(&draft.config, &bundle).is_ok() {
                return Ok(true);
            }
            self.notice = "Сохранённая стратегия недоступна. Выберите другую.".into();
            if !self.choose(&mut draft)? {
                return Ok(false);
            }
            ui_store::save_draft(&self.paths, &draft)?;
            return Ok(true);
        }
        self.prepare()
    }
    fn mode(&mut self) -> Result<Option<RunMode>> {
        self.refresh_status()?;
        let mut background = Item::new("background", "В фоне (рекомендуется)");
        background.enabled = !["unknown", "unavailable", "recovery_required"]
            .contains(&self.observer.value["state"].as_str().unwrap_or("unknown"));
        Ok(match self.menu("Режим работы","Фон продолжает работать после закрытия меню.\nВ терминале: до Esc или Ctrl+C. Автозапуск настраивается отдельно.",&[background,Item::new("terminal","В этом терминале")],false)?.as_deref(){Some("background")=>Some(RunMode::Background),Some(_)=>Some(RunMode::Terminal),None=>None})
    }
    pub(super) fn pause(&mut self) -> Result<Option<bool>> {
        self.refresh_status()?;
        match self.observer.value["state"].as_str().unwrap_or("unknown") {
            "running"=>Ok(self.confirm("Временная остановка","На время проверки остановим фоновую службу.\nПосле завершения восстановим прежний запуск.")?.then_some(true)),
            "starting"|"stopping"|"unknown"|"recovery_required"=>Err(AppError::new("recovery_required","Сначала проверьте состояние службы")),
            _=>Ok(Some(false)),
        }
    }
    pub(super) fn start(&mut self) -> Result<bool> {
        let first = !crate::ui_screens::ready(&self.paths);
        if !self.ready()? {
            return Ok(false);
        }
        if first {
            let mut draft = ui_store::load_draft(&self.paths)?;
            if !self.choose(&mut draft)? {
                return Ok(false);
            }
            ui_store::save_draft(&self.paths, &draft)?;
        }
        let mode = match ui_store::load_mode(&self.paths)? {
            Some(m) => m,
            None => {
                let Some(m) = self.mode()? else {
                    return Ok(false);
                };
                ui_store::save_mode(&self.paths, m)?;
                m
            }
        };
        let config = ui_store::load_draft(&self.paths)?.config;
        if mode == RunMode::Terminal {
            if let Some(allow_pause) = self.pause()? {
                self.action(
                    "Запуск в терминале",
                    Action::Run { allow_pause },
                    Some(&config),
                )?;
            }
            return Ok(false);
        }
        self.refresh_status()?;
        if let Some(id) = self.observer.value["installed"]["installation_id"]
            .as_str()
            .map(str::to_owned)
        {
            if !self.installed_matches(&config)? {
                if !self.confirm("Применить выбранные настройки?","Конфигурация фоновой службы будет заменена. При ошибке запуска восстановим прежнюю.")? {return Ok(false);}
                if self
                    .action(
                        "Применение настроек",
                        Action::Apply {
                            expected_installation_id: id,
                        },
                        Some(&config),
                    )?
                    .0
                    .status
                    != ActionStatus::Completed
                {
                    return Ok(false);
                }
            }
        } else {
            if self.observer.value["state"] != "absent" {
                return Err(AppError::new("service", "Фоновый запуск сейчас недоступен"));
            }
            if self
                .action(
                    "Подготовка фонового запуска",
                    Action::Service("install".into()),
                    Some(&config),
                )?
                .0
                .status
                != ActionStatus::Completed
            {
                return Ok(false);
            }
        }
        self.service("start")
    }
    fn installed_matches(&self, config: &Config) -> Result<bool> {
        let installed = &self.observer.value["installed"];
        let b = app_setup::validate_bundle(&self.paths)?;
        let manifest: Value = serde_json::from_slice(&b.manifest_bytes).map_err(terminal::error)?;
        Ok(installed["config"] == config.json()
            && manifest["files"].as_array().is_some_and(|files| {
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
                        let p = f["path"].as_str().unwrap();
                        let p = if p.starts_with("strategies/") {
                            "strategies/selected.bat"
                        } else {
                            p
                        };
                        installed["inventory"][p]["sha256"] == f["sha256"]
                    })
            }))
    }
    pub(super) fn choose(&mut self, draft: &mut Draft) -> Result<bool> {
        let b = app_setup::validate_bundle(&self.paths)?;
        let items: Vec<_> = b
            .strategy_names
            .iter()
            .map(|n| {
                Item::new(
                    n,
                    format!(
                        "{}{}",
                        n.trim_end_matches(".bat"),
                        if n == &draft.config.strategy {
                            "  ✓"
                        } else {
                            ""
                        }
                    ),
                )
            })
            .collect();
        if let Some(name) = self.menu(
            "Выбор стратегии",
            "Выберите стратегию. Применение предложим следующим шагом.",
            &items,
            true,
        )? {
            draft.config.strategy = name;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn save(&mut self, draft: &mut Draft) -> Result<SaveResult> {
        self.refresh_status()?;
        let id = self.observer.value["installed"]["installation_id"]
            .as_str()
            .map(str::to_owned);
        let mut items = vec![Item::new("later", "Сохранить на потом")];
        if id.is_some() {
            let mut i = Item::new("apply", "Сохранить и применить сейчас");
            i.enabled = ["running", "stopped", "failed"]
                .contains(&self.observer.value["state"].as_str().unwrap_or(""));
            items.insert(0, i);
        } else {
            items.insert(0, Item::new("start", "Сохранить и запустить"));
        }
        let Some(choice) = self.menu(
            "Сохранение настроек",
            &format!(
                "Выбрано: {}\n{}",
                draft.config.strategy,
                self.service_strategy_text()
            ),
            &items,
            false,
        )?
        else {
            return Ok(SaveResult::Cancelled);
        };
        crate::host_run::check_interface(&draft.config.interface)?;
        ui_store::save_draft(&self.paths, draft)?;
        *draft = ui_store::load_draft(&self.paths)?;
        self.notice = "Настройки сохранены для следующего запуска".into();
        let applied = if choice == "apply" {
            self.action(
                "Применение настроек",
                Action::Apply {
                    expected_installation_id: id.unwrap(),
                },
                Some(&draft.config),
            )
            .map(|r| r.0.status == ActionStatus::Completed)
        } else if choice == "start" {
            self.start()
        } else {
            return Ok(SaveResult::Saved);
        };
        match applied {
            Ok(true) => Ok(SaveResult::Applied),
            result => {
                if let Err(e) = result {
                    self.problem(e)?;
                }
                let restored = self.notice.contains("Прежний запуск восстановлен");
                self.notice = if restored {
                    "Настройки сохранены, но не применены. Прежний запуск восстановлен."
                } else {
                    "Настройки сохранены, но не применены. Подробности в помощи."
                }
                .into();
                Ok(SaveResult::SavedNotApplied)
            }
        }
    }
    pub(super) fn installed_text(&self) -> String {
        let s = &self.observer.value;
        let c = &s["installed"]["config"];
        format!(
            "Состояние: {}\nУстановлено: {} · TCP: {} · UDP: {}",
            s["label"].as_str().unwrap_or("неизвестно"),
            s["installed"]["strategy"]
                .as_str()
                .unwrap_or("нет подтверждённой установки"),
            c["gamefiltertcp"]
                .as_bool()
                .map(switch)
                .unwrap_or("неизвестно"),
            c["gamefilterudp"]
                .as_bool()
                .map(switch)
                .unwrap_or("неизвестно")
        )
    }
    fn settings(&mut self) -> Result<()> {
        let mut draft = ui_store::load_draft(&self.paths)?;
        let mut baseline = draft.config.clone();
        loop {
            let items = vec![
                Item::new("strategy", format!("Стратегия: {}", draft.config.strategy)),
                Item::new(
                    "interface",
                    format!("Подключение: {}", draft.config.interface),
                ),
                Item::new(
                    "tcp",
                    format!("GameFilter TCP: {}", switch(draft.config.gamefiltertcp)),
                ),
                Item::new(
                    "udp",
                    format!("GameFilter UDP: {}", switch(draft.config.gamefilterudp)),
                ),
                Item::new("mode", "Режим запуска (сохранить отдельно)"),
                Item::new("autostart", "Автозапуск компьютера"),
                Item::new("trial", "Пробный запуск с этими настройками"),
                Item::new("save", "Сохранить настройки"),
            ];
            let choice = self.menu(
                "Настройки",
                "Параметры стратегии сохраняются в конце формы.\nРежим и автозапуск настраиваются отдельно.",
                &items,
                false,
            )?;
            if choice.is_none() {
                if draft.config == baseline {
                    return Ok(());
                }
                match self
                    .menu(
                        "Несохранённые изменения",
                        "Что сделать с изменениями?",
                        &[
                            Item::new("continue", "Продолжить редактирование"),
                            Item::new("save", "Сохранить"),
                            Item::new("discard", "Отменить изменения"),
                        ],
                        false,
                    )?
                    .as_deref()
                {
                    Some("discard") => return Ok(()),
                    Some("save") => {
                        if self.save(&mut draft)?.leave_editor() {
                            return Ok(());
                        }
                        baseline = ui_store::load_draft(&self.paths)?.config;
                    }
                    _ => (),
                }
                continue;
            }
            let result = (|| {
                match choice.as_deref().unwrap() {
                    "strategy" => {
                        self.choose(&mut draft)?;
                    }
                    "tcp" => draft.config.gamefiltertcp = !draft.config.gamefiltertcp,
                    "udp" => draft.config.gamefilterudp = !draft.config.gamefilterudp,
                    "interface" => {
                        let mut items = vec![Item::new("any", "Все подключения (рекомендуется)")];
                        for entry in std::fs::read_dir("/sys/class/net").map_err(terminal::error)? {
                            let name = entry
                                .map_err(terminal::error)?
                                .file_name()
                                .to_string_lossy()
                                .into_owned();
                            if name != "lo" {
                                items.push(Item::new(&name, &name));
                            }
                        }
                        if let Some(i) = self.menu(
                            "Подключение",
                            "Обычно подходит «Все подключения».",
                            &items,
                            false,
                        )? {
                            draft.config.interface = i;
                        }
                    }
                    "mode" => {
                        if let Some(m) = self.mode()? {
                            ui_store::save_mode(&self.paths, m)?;
                            self.notice = "Режим следующего запуска сохранён".into();
                        }
                    }
                    "autostart" => {
                        self.refresh_status()?;
                        if self.observer.value["installed"].is_null() {
                            self.notice = "Сначала настройте фоновый запуск".into();
                        } else if let Some(s) = self.menu(
                            "Автозапуск",
                            "Запускать при включении компьютера? Текущий запуск продолжится.",
                            &[
                                Item::new("disable", "Выключить"),
                                Item::new("enable", "Включить"),
                            ],
                            false,
                        )? {
                            self.service(&s)?;
                        }
                    }
                    "trial" => {
                        if let Some(allow_pause) = self.pause()? {
                            self.action(
                                "Пробный запуск",
                                Action::Run { allow_pause },
                                Some(&draft.config),
                            )?;
                        }
                    }
                    "save" => {
                        if self.save(&mut draft)?.leave_editor() {
                            return Ok(true);
                        }
                        baseline = ui_store::load_draft(&self.paths)?.config;
                    }
                    _ => (),
                }
                Ok(false)
            })();
            match result {
                Ok(true) => return Ok(()),
                Ok(false) => (),
                Err(e) => self.problem(e)?,
            }
        }
    }
    fn update(&mut self) -> Result<()> {
        if self.confirm("Обновление","Загрузить и проверить новый набор данных?\nРаботающая служба продолжит использовать прежний набор до применения.")? && self.local("update","Обновление данных")?.status==ActionStatus::Completed {
                self.notice="Данные обновлены. Для службы примените настройки отдельно.".into();
                let mut draft=ui_store::load_draft(&self.paths)?;
                if app_setup::validate_bundle(&self.paths).and_then(|b|app_setup::validate_config(&draft.config,&b)).is_err() {
                    self.notice="Прежней стратегии нет в новом наборе. Выберите другую.".into();
                    if self.choose(&mut draft)? {self.save(&mut draft)?;}
                }
        }
        Ok(())
    }
    fn recover(&mut self) -> Result<()> {
        if self.confirm(
            "Восстановление",
            "Проверить журнал операции и восстановить принадлежащие zapret ресурсы?",
        )? && self.service("recover")?
        {
            self.action("Восстановление ручного запуска", Action::Recover, None)?;
        }
        Ok(())
    }
    fn help(&mut self) -> Result<()> {
        loop {
            let Some(id)=self.menu("Помощь и диагностика","Стратегия: набор способов обхода. Фон работает после закрытия меню.\nВидео и голосовую связь после подбора проверьте отдельно.",&[Item::new("doctor","Проверить окружение"),Item::new("status","Состояние службы"),Item::new("results","Последний подбор"),Item::new("error","Подробности последней ошибки"),Item::new("recover","Восстановление"),Item::new("prepare","Подготовить зависимости и данные"),Item::new("remove","Удалить фоновую службу")],false)? else{return Ok(());};
            let r = (|| {
                match id.as_str(){
                "doctor"=>{let o=self.local("doctor","Проверка окружения")?;if o.status==ActionStatus::Completed {let d=&o.data["doctor"];let mut text=format!("Конфигурация: {}\nДанные: {}\n",d["config"]["status"],d["bundle"]["status"]);for (name,v)in d["dependencies"].as_object().into_iter().flatten(){text.push_str(&format!("{name}: {}\n",v["status"]));}text.push_str(&format!("\nПодробности\n{}",serde_json::to_string_pretty(d).unwrap_or_default()));self.details("Окружение",&text)?;}},
                "status"=>{self.refresh_status()?;self.details("Состояние службы",&format!("{}\n\n{}",self.home_text(),serde_json::to_string_pretty(&self.observer.value).unwrap_or_default()))?;},
                "results"=>self.last_results()?,"error"=>self.details("Последняя ошибка",&if self.last_error.is_empty(){"Ошибок в этой сессии нет".into()}else{self.last_error.clone()})?,"recover"=>self.recover()?,"prepare"=>{self.prepare()?;},
                "remove" if self.confirm("Удалить фоновую службу?","Служба будет остановлена и удалена.\nНастройки и загруженные стратегии сохранятся.")? => {self.service("remove")?;},_=>(),
            }
                Ok(())
            })();
            if let Err(e) = r {
                self.problem(e)?;
            }
        }
    }
}
