use super::*;
fn targets() -> Result<Value> {
    Ok(json!(
        crate::diagnostic_targets::load(None)?
            .iter()
            .map(|t| t.json())
            .collect::<Vec<_>>()
    ))
}
impl App {
    pub(super) fn strategies(&mut self) -> Result<()> {
        loop {
            let Some(id) = self.menu(
                "Стратегии",
                "Проверка поможет выбрать подходящий вариант для вашей сети.",
                &[
                    Item::new("check", "Проверить все стратегии"),
                    Item::new("last", "Результаты последнего подбора"),
                    Item::new("manual", "Выбрать вручную"),
                ],
                false,
            )?
            else {
                return Ok(());
            };
            let r = match id.as_str() {
                "check" => self.diagnose(),
                "last" => self.last_results(),
                _ => {
                    if self.ready()? {
                        let mut d = ui_store::load_draft(&self.paths)?;
                        if self.choose(&mut d)? {
                            self.save(&mut d)?;
                        }
                    }
                    Ok(())
                }
            };
            if let Err(e) = r {
                self.problem(e)?;
            }
        }
    }
    fn diagnose(&mut self) -> Result<()> {
        if !self.ready()? {
            return Ok(());
        }
        let Some(allow_pause) = self.pause()? else {
            return Ok(());
        };
        let config = ui_store::load_draft(&self.paths)?.config;
        let bundle = app_setup::validate_bundle(&self.paths)?;
        let fingerprint = ui_store::fingerprint(&config, &bundle.manifest_bytes, &targets()?)?;
        let (o, events) = self.action(
            "Проверка стратегий",
            Action::Diagnose { allow_pause },
            Some(&config),
        )?;
        let report = events
            .iter()
            .find(|v| v["event"] == "diagnosis_complete")
            .map(|v| v["report"].clone())
            .or_else(|| o.data.get("strategies").map(|_| o.data.clone()));
        if let Some(report) = report {
            let record = ui_store::DiagnosisRecord {
                fingerprint,
                report,
                cleanup_confirmed: o.cleanup == "confirmed",
                restoration_confirmed: ["restored", "not_needed"].contains(&o.restoration.as_str()),
            };
            ui_store::save_diagnosis(&self.paths, &record)?;
            self.results(&record)?;
        }
        Ok(())
    }
    pub(super) fn last_results(&mut self) -> Result<()> {
        if let Some(r) = ui_store::load_diagnosis(&self.paths)? {
            self.results(&r)
        } else {
            self.notice = "Сохранённых результатов пока нет".into();
            Ok(())
        }
    }
    fn result_table(
        &mut self,
        table: &mut diagnostic_table::DiagnosticTable,
        body: &str,
    ) -> Result<Option<String>> {
        let mut dirty = true;
        let mut size = (0, 0);
        loop {
            self.check_exit()?;
            self.observer.tick()?;
            let now = crossterm::terminal::size().map_err(terminal::error)?;
            if now != size {
                size = now;
                dirty = true;
            }
            if dirty {
                let color = self.color;
                let frame = self
                    .session
                    .terminal
                    .as_mut()
                    .unwrap()
                    .draw(|f| table.draw(f, "Результаты подбора", body, false, false, color))
                    .map_err(terminal::error)?;
                self.background = Some(frame.buffer.clone());
                dirty = false;
            }
            if !event::poll(Duration::from_millis(50)).map_err(terminal::error)? {
                continue;
            }
            let input = event::read().map_err(terminal::error)?;
            match &input {
                Event::Resize(_, _) => dirty = true,
                Event::Key(k) if k.kind != KeyEventKind::Release => match k.code {
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Err(AppError::new("ui_exit", "Выход"));
                    }
                    KeyCode::Enter if table.selected().is_some() => return Ok(table.selected()),
                    _ => (),
                },
                _ => (),
            }
            dirty |= table.input(&input, true);
        }
    }
    fn results(&mut self, record: &ui_store::DiagnosisRecord) -> Result<()> {
        let passed = record.report["tcp_passed"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut rows = record.report["strategies"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        rows.sort_by_key(|r| !passed.contains(&r["strategy"]));
        let mut table = diagnostic_table::DiagnosticTable::report(&record.report);
        table.rows = rows.clone();
        loop {
            let draft = ui_store::load_draft(&self.paths)?;
            let fresh = app_setup::validate_bundle(&self.paths)
                .and_then(|b| ui_store::fingerprint(&draft.config, &b.manifest_bytes, &targets()?))
                .is_ok_and(|s| s == record.fingerprint);
            let body = format!(
                "{}\n{}Видео и голосовую связь проверьте отдельно.",
                if fresh {
                    "Последняя проверка"
                } else {
                    "Устаревший отчёт. Рекомендуется повторить проверку."
                },
                if record.report["status"] == "aborted" {
                    "Проверка прервана. "
                } else {
                    ""
                }
            );
            if rows.is_empty() {
                self.notice = "Проверенных стратегий пока нет".into();
                return Ok(());
            }
            let Some(name) = self.result_table(&mut table, &body)? else {
                return Ok(());
            };
            let row = rows.iter().find(|r| r["strategy"] == name).unwrap();
            let mut choose = Item::new("choose", "Выбрать эту стратегию");
            choose.enabled = record.cleanup_confirmed && record.restoration_confirmed;
            let note = if choose.enabled {
                body.clone()
            } else {
                "Выбор недоступен: очистка или восстановление не подтверждены. Откройте помощь."
                    .into()
            };
            match self
                .menu(
                    &name,
                    &note,
                    &[choose, Item::new("details", "Подробности проверки")],
                    false,
                )?
                .as_deref()
            {
                Some("choose") => {
                    let mut draft = ui_store::load_draft(&self.paths)?;
                    draft.config.strategy = name;
                    let bundle = app_setup::validate_bundle(&self.paths)?;
                    if !bundle.strategy_names.contains(&draft.config.strategy) {
                        self.notice =
                            "Этой стратегии нет в текущем наборе. Выберите другую.".into();
                        if !self.choose(&mut draft)? {
                            continue;
                        }
                    }
                    app_setup::validate_config(&draft.config, &bundle)?;
                    if self.save(&mut draft)?.leave_editor() {
                        return Ok(());
                    }
                }
                Some("details") => self.details(
                    "Подробности проверки",
                    &serde_json::to_string_pretty(row).unwrap_or_default(),
                )?,
                _ => (),
            }
        }
    }
}
