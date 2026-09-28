use super::*;
impl App {
    pub(super) fn work(
        &mut self,
        title: &str,
        command: &mut Command,
        authentication: bool,
    ) -> Result<(ActionOutcome, Vec<Value>)> {
        self.observer.stop();
        if authentication {
            self.session.suspend();
            eprintln!("{title}\nЕсли sudo запросит пароль, введите его в терминале.");
        }
        let result = self.work_inner(title, command, authentication);
        let resume = self.session.resume();
        self.signals.clear_interrupt();
        self.observer.refresh();
        crate::error::combine(result, resume)
    }
    fn work_inner(
        &mut self,
        title: &str,
        command: &mut Command,
        authentication: bool,
    ) -> Result<(ActionOutcome, Vec<Value>)> {
        let status_job = command.get_args().any(|a| a == "job")
            && command.get_args().last().is_some_and(|a| a == "status");
        let started = Instant::now();
        let mut timed_out = false;
        let mut operation = Operation::spawn(command)?;
        let mut ready = !authentication;
        let mut cancelling = false;
        let mut dirty = true;
        let mut size = (0, 0);
        let mut text = "Подготовка к выполнению…".to_string();
        let mut events = Vec::new();
        let mut stderr = String::new();
        loop {
            if status_job && started.elapsed() >= Duration::from_secs(5) && !timed_out {
                timed_out = true;
                operation.cancel(CancelSignal::Terminate);
                text = "Проверка состояния превысила время ожидания".into();
                dirty = true;
            }
            let update = match operation.poll() {
                Ok(u) => u,
                Err(e) => {
                    self.last_error = format!("{}\n{}", e.message, stderr);
                    return Err(e);
                }
            };
            for line in update.stderr {
                if !ready {
                    eprint!("{line}");
                }
                stderr.push_str(&line);
            }
            for v in update.events {
                if v["event"] == "worker_ready" {
                    ready = true;
                    self.session.resume()?;
                    dirty = true;
                }
                let rendered = match v["event"].as_str().unwrap_or("") {
                    "ready" => format!(
                        "Запущено: {}. Очередь и firewall проверены.\nEsc / Ctrl+C: остановить",
                        v["config"]["strategy"]
                            .as_str()
                            .unwrap_or("выбранная стратегия")
                    ),
                    "stopped" => "Процесс завершён. Проверяем очистку и восстановление.".into(),
                    "probe_started" => format!(
                        "Проверяем {}: {} ({})",
                        v["strategy"].as_str().unwrap_or(""),
                        v["target"].as_str().unwrap_or(""),
                        v["transport"].as_str().unwrap_or("")
                    ),
                    "diagnosis_started" => "Проверка стратегий началась".into(),
                    "diagnosis_complete" => {
                        "Проверка завершена. Ждём очистки и восстановления.".into()
                    }
                    _ => String::new(),
                };
                if !rendered.is_empty() {
                    text = rendered;
                    dirty = true;
                }
                // Keep the final report and completed strategy rows, not an unbounded event log.
                if v["event"] == "diagnosis_complete" {
                    events.retain(|e: &Value| e["event"] != "diagnosis_complete");
                    events.push(v.clone());
                }
                if v["event"] == "strategy_complete" {
                    if events.len() < 4096 {
                        events.push(v.clone());
                    }
                    text = diagnosis::progress(&events);
                    dirty = true;
                }
                if v["event"] == "strategy_started" {
                    text = format!(
                        "Проверяем: {}\n\n{}",
                        v["strategy"].as_str().unwrap_or(""),
                        diagnosis::progress(&events)
                    );
                    dirty = true;
                }
                if v["event"] == "running" {
                    text =
                        "Zapret работает в этом терминале.\nДля остановки нажмите Esc или Ctrl+C."
                            .into();
                    dirty = true;
                }
            }
            if let Some(o) = update.outcome {
                if timed_out {
                    return Err(AppError::new("status", "Состояние не получено за 5 секунд"));
                }
                if !stderr.is_empty() || o.status != ActionStatus::Completed {
                    self.last_error = format!(
                        "{}\n{}",
                        serde_json::to_string_pretty(&o.json()).unwrap_or_default(),
                        stderr
                    );
                }
                self.notice = match o.status {
                    ActionStatus::Completed => "Действие выполнено",
                    ActionStatus::Cancelled => "Действие отменено",
                    ActionStatus::NeedsRecovery => "Требуется восстановление. Откройте помощь",
                    ActionStatus::Failed => "Действие не выполнено. Подробности в помощи",
                }
                .into();
                if o.restoration == "restored" {
                    self.notice.push_str(". Прежний запуск восстановлен");
                }
                return Ok((o, events));
            }
            if self.signals.requested().is_some() {
                cancelling = true;
                dirty = true;
            }
            if ready {
                let new = crossterm::terminal::size().map_err(terminal::error)?;
                if size != new {
                    size = new;
                    dirty = true;
                }
                if dirty {
                    let color = self.color;
                    self.session
                        .terminal
                        .as_mut()
                        .unwrap()
                        .draw(|f| view::operation(f, title, &text, cancelling, color))
                        .map_err(terminal::error)?;
                    dirty = false;
                }
                if event::poll(Duration::from_millis(30)).map_err(terminal::error)? {
                    match event::read().map_err(terminal::error)? {
                        Event::Resize(_, _) => dirty = true,
                        Event::Key(k)
                            if k.kind != KeyEventKind::Release
                                && (k.code == KeyCode::Esc
                                    || (k.code == KeyCode::Char('c')
                                        && k.modifiers.contains(KeyModifiers::CONTROL))) =>
                        {
                            operation.cancel(CancelSignal::Interrupt);
                            cancelling = true;
                            dirty = true;
                        }
                        _ => (),
                    }
                }
            } else {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    pub(super) fn action(
        &mut self,
        title: &str,
        action: Action,
        config: Option<&Config>,
    ) -> Result<(ActionOutcome, Vec<Value>)> {
        let inputs = config
            .map(|c| ui_store::prepare_inputs(&self.paths, c))
            .transpose()?;
        let result = (|| {
            let mut command = ui_actions::command(&action, inputs.as_ref())?;
            self.work(title, &mut command, crate::service_fs::uid() != 0)
        })();
        let remove = inputs
            .as_ref()
            .map(|i| ui_store::remove_inputs(&self.paths, i))
            .unwrap_or(Ok(()));
        crate::error::combine(result, remove)
    }
    pub(super) fn service(&mut self, name: &str) -> Result<bool> {
        Ok(self
            .action("Фоновая служба", Action::Service(name.into()), None)?
            .0
            .status
            == ActionStatus::Completed)
    }
    pub(super) fn local(&mut self, name: &str, title: &str) -> Result<ActionOutcome> {
        Ok(self.work(title, &mut job::command(name)?, false)?.0)
    }
    pub(super) fn refresh_status(&mut self) -> Result<()> {
        let o = self.local("status", "Проверяем состояние")?;
        if o.status == ActionStatus::Completed {
            self.observer.value = o.data;
            Ok(())
        } else {
            Err(AppError::new(
                "status",
                "Не удалось проверить состояние службы",
            ))
        }
    }
}
