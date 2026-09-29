use super::*;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState},
};

#[derive(Default)]
pub(super) struct DiagnosticTable {
    pub rows: Vec<Value>,
    targets: Vec<String>,
    pub state: TableState,
    query: String,
    quic: bool,
    column: usize,
    active: Option<(String, String, String)>,
    pub started: bool,
    follow: bool,
}
impl DiagnosticTable {
    pub fn report(report: &Value) -> Self {
        let mut table = Self {
            rows: report["strategies"].as_array().cloned().unwrap_or_default(),
            started: true,
            ..Self::default()
        };
        table.targets(&report["targets"]);
        for row in table.rows.clone() {
            for check in row["checks"].as_array().into_iter().flatten() {
                table.target(check["target"].as_str().unwrap_or("Проверка"));
            }
        }
        table
    }
    fn target(&mut self, id: &str) {
        if !self.targets.iter().any(|t| t == id) {
            self.targets.push(id.into());
        }
    }
    fn targets(&mut self, targets: &Value) {
        for t in targets.as_array().into_iter().flatten() {
            if let Some(id) = t["id"].as_str() {
                self.target(id);
            }
        }
    }
    pub fn update(&mut self, event: &Value) -> bool {
        match event["event"].as_str().unwrap_or("") {
            "diagnosis_started" => {
                *self = Self {
                    started: true,
                    follow: true,
                    ..Self::default()
                };
                self.targets(&event["targets"]);
                self.rows = event["strategy_order"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|name| json!({"strategy":name,"status":"not_run","checks":[]}))
                    .collect();
            }
            "strategy_started" | "probe_started" | "probe_result" | "strategy_complete" => {
                let name = if event["event"] == "strategy_complete" {
                    &event["result"]["strategy"]
                } else {
                    &event["strategy"]
                };
                let Some(index) = self.rows.iter().position(|r| &r["strategy"] == name) else {
                    return false;
                };
                if self.follow {
                    self.state.select(Some(index));
                }
                match event["event"].as_str().unwrap_or("") {
                    "strategy_started" => self.rows[index]["status"] = json!("running"),
                    "probe_started" => {
                        self.active = Some((
                            name.as_str().unwrap_or("").into(),
                            event["target"].as_str().unwrap_or("").into(),
                            event["transport"].as_str().unwrap_or("").into(),
                        ));
                    }
                    "probe_result" => {
                        let check = &event["result"];
                        self.target(check["target"].as_str().unwrap_or("Проверка"));
                        let checks = self.rows[index]["checks"].as_array_mut().unwrap();
                        checks.retain(|c| {
                            c["target"] != check["target"] || c["transport"] != check["transport"]
                        });
                        checks.push(check.clone());
                        self.active = None;
                    }
                    _ => {
                        self.rows[index] = event["result"].clone();
                        self.active = None;
                    }
                }
            }
            "diagnosis_complete" => {
                self.rows = event["report"]["strategies"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                self.targets(&event["report"]["targets"]);
                self.active = None;
            }
            _ => return false,
        }
        true
    }
    fn visible(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                r["strategy"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&self.query.to_lowercase())
            })
            .map(|(i, _)| i)
            .collect()
    }
    pub fn selected(&self) -> Option<String> {
        self.visible()
            .get(self.state.selected().unwrap_or(0))
            .map(|i| self.rows[*i]["strategy"].as_str().unwrap_or("").to_owned())
    }
    fn has_quic(&self) -> bool {
        self.rows.iter().any(|r| {
            r["checks"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|c| c["transport"] == "quic" && c["status"] != "unsupported")
        })
    }
    pub fn input(&mut self, event: &Event, search: bool) -> bool {
        let mut movement = 0isize;
        match event {
            Event::Mouse(m) => match m.kind {
                MouseEventKind::ScrollDown => movement = 1,
                MouseEventKind::ScrollUp => movement = -1,
                _ => return false,
            },
            Event::Key(k) if k.kind != KeyEventKind::Release => match k.code {
                KeyCode::Down => movement = 1,
                KeyCode::Up => movement = -1,
                KeyCode::PageDown => movement = 8,
                KeyCode::PageUp => movement = -8,
                KeyCode::Home => self.state.select(Some(0)),
                KeyCode::End => self
                    .state
                    .select(Some(self.visible().len().saturating_sub(1))),
                KeyCode::Left => self.column = self.column.saturating_sub(1),
                KeyCode::Right => {
                    self.column = (self.column + 1).min(self.targets.len().saturating_sub(1))
                }
                KeyCode::Tab if self.has_quic() => self.quic = !self.quic,
                KeyCode::Backspace if search => {
                    self.query.pop();
                    self.state.select(Some(0));
                }
                KeyCode::Char(c) if search && !k.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.query.push(c);
                    self.state.select(Some(0));
                }
                _ => return false,
            },
            _ => return false,
        }
        if movement != 0 {
            self.state.select(Some(
                (self.state.selected().unwrap_or(0) as isize + movement)
                    .clamp(0, self.visible().len().saturating_sub(1) as isize)
                    as usize,
            ));
        }
        self.follow = false;
        true
    }
    fn cell(&self, row: &Value, target: &str, live: bool) -> (&'static str, Color) {
        let transport = if self.quic { "quic" } else { "tcp" };
        if self
            .active
            .as_ref()
            .is_some_and(|(s, t, p)| row["strategy"] == *s && t == target && p == transport)
        {
            return ("Проверка", Color::Cyan);
        }
        if let Some(c) = row["checks"].as_array().into_iter().flatten().find(|c| {
            c["transport"] == transport && c["target"].as_str().unwrap_or("Проверка") == target
        }) {
            return match c["status"].as_str().unwrap_or("") {
                "passed" => ("OK", Color::Green),
                "unsupported" => ("Нет HTTP/3", Color::DarkGray),
                "failed" => ("Ошибка", Color::Red),
                _ => ("Стоп", Color::Yellow),
            };
        }
        match row["status"].as_str().unwrap_or("") {
            "not_run" if !live => ("Не провер.", Color::DarkGray),
            "not_run" | "running" => ("Ожидание", Color::DarkGray),
            "tested" => ("Нет данных", Color::DarkGray),
            "aborted" => ("Стоп", Color::Yellow),
            _ => ("Сбой", Color::Red),
        }
    }
    pub fn draw(
        &mut self,
        f: &mut Frame,
        title: &str,
        note: &str,
        live: bool,
        cancelling: bool,
        color: bool,
    ) {
        let full = f.area();
        if full.width < 38 || full.height < 12 {
            f.render_widget(
                Paragraph::new("Увеличьте терминал до 38 × 12\nEsc: назад / остановить"),
                full,
            );
            return;
        }
        let width = full.width.saturating_sub(4).min(140);
        let height = full.height.saturating_sub(2).min(36);
        let a = Rect::new(
            (full.width - width) / 2,
            (full.height - height) / 2,
            width,
            height,
        );
        let compact = height < 16;
        let p = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(if compact { 1 } else { 2 }),
            Constraint::Length(if live { 0 } else { 1 }),
            Constraint::Min(3),
            Constraint::Length(if compact { 2 } else { 3 }),
        ])
        .split(a);
        let accent = if color {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        f.render_widget(
            Paragraph::new(format!("ZAPRET · {title}")).style(accent),
            p[0],
        );
        let complete = self
            .rows
            .iter()
            .filter(|r| r["status"] != "not_run" && r["status"] != "running")
            .count();
        let status = if live {
            format!(
                "Проверено: {complete} / {}\n{}",
                self.rows.len(),
                plain(note)
            )
        } else {
            plain(note)
        };
        f.render_widget(Paragraph::new(status), p[1]);
        if !live {
            f.render_widget(
                Paragraph::new(format!("Поиск: {}", plain(&self.query))),
                p[2],
            );
        }
        let name_width = (width / 3).clamp(16, 48);
        let count = ((width.saturating_sub(name_width + 4)) / 11).max(1) as usize;
        self.column = self.column.min(self.targets.len().saturating_sub(count));
        let targets: Vec<_> = self.targets.iter().skip(self.column).take(count).collect();
        let mut headers = vec![Cell::from("Стратегия")];
        for target in &targets {
            headers.push(Cell::from(label(target)));
        }
        let indices = self.visible();
        self.state.select(Some(
            self.state
                .selected()
                .unwrap_or(0)
                .min(indices.len().saturating_sub(1)),
        ));
        let rows: Vec<_> = indices
            .iter()
            .map(|i| {
                let r = &self.rows[*i];
                let mut cells = vec![Cell::from(plain(r["strategy"].as_str().unwrap_or("")))];
                for target in &targets {
                    let (text, fg) = self.cell(r, target, live);
                    cells.push(Cell::from(text).style(if color {
                        Style::default().fg(fg)
                    } else {
                        Style::default()
                    }));
                }
                Row::new(cells)
            })
            .collect();
        let mut widths = vec![Constraint::Length(name_width)];
        widths.extend(targets.iter().map(|_| Constraint::Min(10)));
        f.render_stateful_widget(
            Table::new(rows, widths)
                .header(Row::new(headers).height(2).style(accent))
                .column_spacing(1)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .title(if self.quic { " QUIC " } else { " TCP " }),
                )
                .row_highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol("› "),
            p[3],
            &mut self.state,
        );
        if indices.is_empty() {
            f.render_widget(
                Paragraph::new("Ничего не найдено"),
                Rect::new(p[3].x + 2, p[3].y + 3, p[3].width.saturating_sub(4), 1),
            );
        }
        let action = if cancelling {
            "Останавливаем и ждём очистки…"
        } else if live {
            "Esc / Ctrl+C: остановить и дождаться очистки"
        } else {
            "Enter: открыть · Текст: поиск · Esc: назад"
        };
        let hint = if self.targets.len() > count {
            "↑↓ / колесо: строки · ←→: столбцы"
        } else {
            "↑↓ / колесо: строки"
        };
        let footer = if compact {
            format!(
                "↑↓ строки · ←→ сайты{}\n{}",
                if self.has_quic() { " · Tab" } else { "" },
                if cancelling {
                    "Ждём очистки…"
                } else if live {
                    "Esc / Ctrl+C: остановить"
                } else {
                    "Enter: открыть · Esc: назад"
                }
            )
        } else {
            format!(
                "{}\n{hint}{}\n{action}",
                plain(&self.selected().unwrap_or_default()),
                if self.has_quic() {
                    " · Tab: TCP / QUIC"
                } else {
                    ""
                }
            )
        };
        f.render_widget(Paragraph::new(footer), p[4]);
    }
}
fn label(id: &str) -> String {
    match id {
        "youtube-main" => "YouTube\nСайт".into(),
        "youtube-cdn" => "YouTube\nCDN".into(),
        "discord-main" => "Discord\nСайт".into(),
        "discord-gateway" => "Discord\nGateway".into(),
        _ => plain(id),
    }
}
