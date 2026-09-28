mod action;
mod diagnosis;
mod flows;
mod job;
mod status;
mod terminal;
mod view;
use crate::{
    app_paths::AppPaths,
    app_setup,
    config::Config,
    error::{AppError, Result},
    signals::Signals,
    ui_actions::{self, Action},
    ui_events::{CancelSignal, Operation, plain},
    ui_model::{ActionOutcome, ActionStatus},
    ui_store::{self, Draft, RunMode},
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
pub use job::run as job;
use ratatui::widgets::ListState;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    process::Command,
    time::{Duration, Instant},
};
pub fn supported() -> bool {
    crate::ui_terminal::is_terminal()
        && std::env::var("TERM").is_ok_and(|s| !s.is_empty() && s != "dumb")
}
pub fn run() -> Result<()> {
    let signals = Signals::install()?;
    let mut app = App {
        session: terminal::Session::enter()?,
        signals,
        paths: AppPaths::discover()?,
        observer: status::Observer::new(),
        notice: String::new(),
        last_error: String::new(),
        positions: HashMap::new(),
        background: None,
        color: std::env::var_os("NO_COLOR").is_none(),
    };
    let result = app.home();
    app.observer.stop();
    match result {
        Err(e) if e.kind == "ui_exit" => Ok(()),
        other => other,
    }
}
struct App {
    session: terminal::Session,
    signals: Signals,
    paths: AppPaths,
    observer: status::Observer,
    notice: String,
    last_error: String,
    positions: HashMap<String, usize>,
    background: Option<ratatui::buffer::Buffer>,
    color: bool,
}
#[derive(Clone)]
struct Item {
    id: String,
    label: String,
    enabled: bool,
}
impl Item {
    fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            enabled: true,
        }
    }
}
impl App {
    fn check_exit(&self) -> Result<()> {
        match self.signals.requested() {
            Some("SIGTERM") => Err(AppError::new("shutdown", "Завершение по SIGTERM")),
            Some(_) => Err(AppError::new("ui_exit", "Выход")),
            None => Ok(()),
        }
    }
    fn menu(
        &mut self,
        title: &str,
        body: &str,
        items: &[Item],
        searchable: bool,
    ) -> Result<Option<String>> {
        let mut state =
            ListState::default().with_selected(Some(*self.positions.get(title).unwrap_or(&0)));
        let mut query = String::new();
        let mut dirty = true;
        let mut size = (0, 0);
        loop {
            self.check_exit()?;
            dirty |= self.observer.tick()?;
            let now = crossterm::terminal::size().map_err(terminal::error)?;
            if size != now {
                size = now;
                dirty = true;
            }
            let home = title == "Главное меню";
            let choices = if home {
                self.home_items()
            } else {
                items.to_vec()
            };
            let visible: Vec<_> = choices
                .iter()
                .filter(|i| i.label.to_lowercase().contains(&query.to_lowercase()))
                .cloned()
                .collect();
            let selected = state
                .selected()
                .unwrap_or(0)
                .min(visible.len().saturating_sub(1));
            state.select(Some(selected));
            if dirty {
                let text = if home {
                    self.home_text()
                } else if title == "Настройки" {
                    format!("{}\n{}", body, self.installed_text())
                } else {
                    body.into()
                };
                let color = self.color;
                let notice = self.notice.clone();
                let frame = self
                    .session
                    .terminal
                    .as_mut()
                    .unwrap()
                    .draw(|f| {
                        view::menu(
                            f,
                            title,
                            &text,
                            &visible,
                            &mut state,
                            searchable.then_some(query.as_str()),
                            &notice,
                            color,
                        )
                    })
                    .map_err(terminal::error)?;
                self.background = Some(frame.buffer.clone());
                dirty = false;
            }
            if !event::poll(Duration::from_millis(50)).map_err(terminal::error)? {
                continue;
            }
            let input = event::read().map_err(terminal::error)?;
            let mut movement = 0isize;
            match input {
                Event::Resize(_, _) => dirty = true,
                Event::Mouse(m) => match m.kind {
                    MouseEventKind::ScrollDown => movement = 1,
                    MouseEventKind::ScrollUp => movement = -1,
                    _ => (),
                },
                Event::Key(k) if k.kind != KeyEventKind::Release => match k.code {
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Err(AppError::new("ui_exit", "Выход"));
                    }
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Down => movement = 1,
                    KeyCode::Up => movement = -1,
                    KeyCode::PageDown => movement = 8,
                    KeyCode::PageUp => movement = -8,
                    KeyCode::Home => {
                        state.select(Some(0));
                        dirty = true;
                    }
                    KeyCode::End => {
                        state.select(Some(visible.len().saturating_sub(1)));
                        dirty = true;
                    }
                    KeyCode::Enter => {
                        if let Some(i) = visible.get(selected)
                            && i.enabled
                        {
                            self.positions.insert(title.into(), selected);
                            return Ok(Some(i.id.clone()));
                        }
                    }
                    KeyCode::Backspace if searchable => {
                        query.pop();
                        state.select(Some(0));
                        dirty = true;
                    }
                    KeyCode::Char(c)
                        if searchable && !k.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        query.push(c);
                        state.select(Some(0));
                        dirty = true;
                    }
                    _ => (),
                },
                _ => (),
            }
            if movement != 0 {
                state.select(Some(
                    (selected as isize + movement)
                        .clamp(0, visible.len().saturating_sub(1) as isize)
                        as usize,
                ));
                dirty = true;
            }
        }
    }
    fn confirm(&mut self, title: &str, body: &str) -> Result<bool> {
        let background = self.background.clone();
        let mut yes = false;
        let mut dirty = true;
        let mut size = (0, 0);
        loop {
            self.check_exit()?;
            self.observer.tick()?;
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
                    .draw(|f| view::confirm(f, background.as_ref(), title, body, yes, color))
                    .map_err(terminal::error)?;
                dirty = false;
            }
            if !event::poll(Duration::from_millis(50)).map_err(terminal::error)? {
                continue;
            }
            match event::read().map_err(terminal::error)? {
                Event::Resize(_, _) => dirty = true,
                Event::Mouse(m) => match m.kind {
                    MouseEventKind::ScrollDown => {
                        yes = true;
                        dirty = true;
                    }
                    MouseEventKind::ScrollUp => {
                        yes = false;
                        dirty = true;
                    }
                    _ => (),
                },
                Event::Key(k) if k.kind != KeyEventKind::Release => match k.code {
                    KeyCode::Esc => return Ok(false),
                    KeyCode::Enter => return Ok(yes),
                    KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        yes = !yes;
                        dirty = true;
                    }
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Err(AppError::new("ui_exit", "Выход"));
                    }
                    _ => (),
                },
                _ => (),
            }
        }
    }
    fn details(&mut self, title: &str, text: &str) -> Result<()> {
        let mut scroll = 0u16;
        let mut dirty = true;
        let mut size = (0, 0);
        loop {
            self.check_exit()?;
            dirty |= self.observer.tick()?;
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
                    .draw(|f| view::details(f, title, text, scroll, color))
                    .map_err(terminal::error)?;
                dirty = false;
            }
            if !event::poll(Duration::from_millis(50)).map_err(terminal::error)? {
                continue;
            }
            let delta = match event::read().map_err(terminal::error)? {
                Event::Resize(_, _) => {
                    dirty = true;
                    0
                }
                Event::Key(k) if k.kind != KeyEventKind::Release => match k.code {
                    KeyCode::Esc | KeyCode::Enter => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Err(AppError::new("ui_exit", "Выход"));
                    }
                    KeyCode::Down => 1,
                    KeyCode::Up => -1,
                    KeyCode::PageDown => 10,
                    KeyCode::PageUp => -10,
                    _ => 0,
                },
                Event::Mouse(m) => match m.kind {
                    MouseEventKind::ScrollDown => 3,
                    MouseEventKind::ScrollUp => -3,
                    _ => 0,
                },
                _ => 0,
            };
            if delta != 0 {
                scroll = (scroll as i32 + delta).clamp(
                    0,
                    ratatui::widgets::Paragraph::new(plain(text))
                        .wrap(ratatui::widgets::Wrap { trim: false })
                        .line_count(size.0.saturating_sub(4).min(92).saturating_sub(2))
                        .saturating_sub(1)
                        .min(u16::MAX as usize) as i32,
                ) as u16;
                dirty = true;
            }
        }
    }
    fn problem(&mut self, e: AppError) -> Result<()> {
        if ["shutdown", "ui_exit"].contains(&e.kind) {
            return Err(e);
        }
        self.last_error = format!("{}: {}", e.kind, plain(&e.message));
        self.notice = match e.kind {
            "config_changed" => "Настройки изменились в другом окне. Откройте форму заново.",
            "recovery_required" => "Требуется восстановление. Откройте раздел помощи.",
            _ => "Не удалось завершить действие. Подробности доступны в помощи.",
        }
        .into();
        Ok(())
    }
}
