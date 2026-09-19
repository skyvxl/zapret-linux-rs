use serde_json::{Value, json};
use std::io::{self, IsTerminal};

#[derive(Default)]
pub(super) struct Dashboard {
    rows: Vec<Value>,
    targets: Vec<Value>,
    current: usize,
    stage: String,
    detail: String,
    quic: bool,
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}
fn fit(s: &str, width: usize) -> String {
    let s = clean(s);
    if s.chars().count() <= width {
        s
    } else {
        s.chars()
            .take(width.saturating_sub(1))
            .chain(['…'])
            .collect()
    }
}
fn label(id: &str) -> &str {
    match id {
        "youtube-main" => "YouTube: сайт",
        "youtube-cdn" => "YouTube: сервер Google Video",
        "discord-main" => "Discord: сайт",
        "discord-gateway" => "Discord: API",
        _ => id,
    }
}
fn result_name(status: &str) -> &'static str {
    match status {
        "passed" => "✓ Прошла",
        "failed" => "✗ Не прошла",
        "unsupported" => "— Не поддерживается",
        _ => "· Ожидает",
    }
}
fn reason(v: &Value) -> String {
    match v["curl_exit_code"].as_i64() {
        Some(6) => "Ошибка DNS".into(),
        Some(7) => "Не удалось подключиться".into(),
        Some(28) => "Таймаут".into(),
        Some(35 | 60) => "Ошибка TLS".into(),
        _ if v["status"] == "unsupported" => "Не поддерживается".into(),
        _ if v["http_status"].as_u64().is_some_and(|n| n >= 400) => {
            format!("HTTP {}", v["http_status"])
        }
        _ => clean(text(v, "reason")),
    }
}
fn screen() -> Option<(usize, usize)> {
    if !io::stdout().is_terminal()
        || std::env::var("TERM").map_or(true, |t| t.is_empty() || t == "dumb")
    {
        return None;
    }
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: ioctl writes only the winsize structure through a valid pointer.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } != 0
        || size.ws_col == 0
        || size.ws_row < 6
    {
        None
    } else {
        Some((
            usize::from(size.ws_col).saturating_sub(1),
            usize::from(size.ws_row),
        ))
    }
}
fn paint(s: &str, color: bool) -> String {
    if !color {
        return s.to_owned();
    }
    let mut out = String::new();
    for c in s.chars() {
        let code = match c {
            '✓' => Some(32),
            '✗' => Some(31),
            '…' => Some(36),
            '·' | '—' => Some(90),
            _ => None,
        };
        if let Some(code) = code {
            out.push_str(&format!("\x1b[{code}m{c}\x1b[0m"));
        } else {
            out.push(c);
        }
    }
    out
}

impl Dashboard {
    fn checks<'a>(&self, row: &'a Value) -> Vec<&'a Value> {
        row["checks"]
            .as_array()
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }
    fn aggregate(&self, row: &Value, service: Option<&str>, transport: &str) -> &'static str {
        let targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| t["required"] == true && service.is_none_or(|s| t["service"] == s))
            .collect();
        if targets.is_empty() || (transport == "quic" && !self.quic) {
            return "—";
        }
        let checks = self.checks(row);
        let statuses: Vec<_> = targets
            .iter()
            .map(|t| {
                checks
                    .iter()
                    .find(|c| c["target"] == t["id"] && c["transport"] == transport)
                    .map(|c| text(c, "status"))
            })
            .collect();
        if statuses.contains(&Some("failed")) {
            "✗"
        } else if statuses.iter().all(|s| *s == Some("passed")) {
            "✓"
        } else if statuses.contains(&Some("unsupported")) {
            "—"
        } else if row["status"] == "running" {
            "…"
        } else {
            "·"
        }
    }
    fn verdict(&self, row: &Value) -> &'static str {
        match text(row, "status") {
            "tested" if row["cleanup_confirmed"] == true => {
                if self.aggregate(row, None, "tcp") == "✓" {
                    "✓ Прошла"
                } else {
                    "✗ Не прошла"
                }
            }
            "failed" | "tested" => "✗ Ошибка",
            "running" => "… Проверяется",
            _ => "· Ожидает",
        }
    }
    pub(super) fn update(&mut self, event: &Value) -> Option<String> {
        let kind = text(event, "event");
        if !matches!(
            kind,
            "diagnosis_started"
                | "strategy_started"
                | "strategy_ready"
                | "probe_started"
                | "probe_result"
                | "strategy_complete"
                | "diagnosis_complete"
        ) {
            return None;
        }
        if kind == "diagnosis_started" {
            *self = Self::default();
            self.targets = event["targets"].as_array().cloned().unwrap_or_default();
            self.quic = event["quic"] == true;
            self.rows = event["strategy_order"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|n| json!({"strategy":n,"status":"not_run","checks":[]}))
                .collect();
            self.stage = "Подготовка диагностики".into();
        }
        let name = if kind == "strategy_complete" {
            text(&event["result"], "strategy")
        } else {
            text(event, "strategy")
        };
        if let Some(i) = self.rows.iter().position(|r| r["strategy"] == name) {
            self.current = i;
        }
        let mut plain = String::new();
        if let Some(row) = self.rows.get_mut(self.current) {
            match kind {
                "strategy_started" | "strategy_ready" | "probe_started" => {
                    row["status"] = json!("running");
                    self.stage = match kind {
                        "strategy_started" => format!("{} → подготовка и запуск", name),
                        "strategy_ready" => format!("{} → подключение готово", name),
                        _ => format!(
                            "{} → {} ({})",
                            name,
                            label(text(event, "target")),
                            text(event, "transport").to_uppercase()
                        ),
                    };
                    self.detail.clear();
                    plain = format!("Сейчас: {}\n", clean(&self.stage));
                }
                "probe_result" => {
                    let r = &event["result"];
                    if let Some(checks) = row["checks"].as_array_mut() {
                        checks.push(r.clone());
                    }
                    self.detail = format!(
                        "{}: {} — {}",
                        label(text(r, "target")),
                        result_name(text(r, "status")),
                        reason(r)
                    );
                    plain = format!(
                        "{} · {}: {}\n",
                        clean(name),
                        text(r, "transport").to_uppercase(),
                        self.detail
                    );
                }
                "strategy_complete" => {
                    *row = event["result"].clone();
                    self.detail = if row["error"].is_object() {
                        format!(
                            "Ошибка ({}): {}",
                            text(&row["error"], "kind"),
                            clean(text(&row["error"], "message"))
                        )
                    } else {
                        String::new()
                    };
                    self.stage = format!("{} → проверка завершена", name);
                }
                _ => {}
            }
        }
        let finished = kind == "diagnosis_complete";
        if finished {
            if let Some(rows) = event["report"]["strategies"].as_array() {
                self.rows = rows.clone();
            }
            self.stage = if event["report"]["status"] == "aborted" {
                "Остановлено"
            } else {
                "Готово"
            }
            .into();
            self.detail = clean(text(&event["report"], "abort_reason"));
        }
        let dimensions = screen();
        if dimensions.is_none() && !finished {
            return Some(if kind == "diagnosis_started" {
                format!("Проверка {} стратегий: YouTube, Discord\n", self.rows.len())
            } else if kind == "strategy_complete" {
                format!(
                    "{}: {}. {}\n",
                    clean(name),
                    self.verdict(&event["result"]),
                    self.detail
                )
            } else {
                plain
            });
        }
        let (width, height) = dimensions.unwrap_or((100, usize::MAX));
        let color = dimensions.is_some() && std::env::var_os("NO_COLOR").is_none();
        let compact = width < 70;
        let done = self
            .rows
            .iter()
            .filter(|r| matches!(text(r, "status"), "tested" | "failed"))
            .count();
        let mut lines = vec![
            format!(
                "Проверка стратегий · {done}/{} · {}",
                self.rows.len(),
                if finished {
                    &self.stage
                } else {
                    "выполняется"
                }
            ),
            if compact {
                "Стратегия / YouTube · Discord · QUIC / Итог".into()
            } else {
                format!(
                    "{:<30} {:<8} {:<8} {:<6} Итог",
                    "Стратегия", "YouTube", "Discord", "QUIC"
                )
            },
        ];
        let count = if finished {
            self.rows.len()
        } else {
            height.saturating_sub(9 + self.targets.len().min(4)).max(1)
                / if compact { 2 } else { 1 }
        }
        .max(1);
        let start = if finished {
            0
        } else {
            self.current
                .saturating_sub(count / 2)
                .min(self.rows.len().saturating_sub(count))
        };
        for row in self.rows.iter().skip(start).take(count) {
            let name = text(row, "strategy").trim_end_matches(".bat");
            let y = self.aggregate(row, Some("youtube"), "tcp");
            let d = self.aggregate(row, Some("discord"), "tcp");
            let q = self.aggregate(row, None, "quic");
            if compact {
                lines.push(clean(name));
                lines.push(format!("  {y} · {d} · {q}  {}", self.verdict(row)));
            } else {
                lines.push(format!(
                    "{:<30} {y:<8} {d:<8} {q:<6} {}",
                    fit(name, 30),
                    self.verdict(row)
                ));
            }
        }
        if !finished {
            lines.push(format!(
                "Строки {}–{} из {}",
                start + 1,
                (start + count).min(self.rows.len()),
                self.rows.len()
            ));
            lines.push(format!("Сейчас: {}", self.stage));
            if let Some(row) = self.rows.get(self.current) {
                let checks = self.checks(row);
                for target in self.targets.iter().take(4) {
                    let status = |transport| {
                        checks
                            .iter()
                            .find(|c| c["target"] == target["id"] && c["transport"] == transport)
                            .map(|c| result_name(text(c, "status")))
                            .unwrap_or("· Ожидает")
                    };
                    lines.push(format!(
                        "{}: TCP {} / QUIC {}",
                        label(text(target, "id")),
                        status("tcp"),
                        if self.quic { status("quic") } else { "—" }
                    ));
                }
            }
            lines.push(self.detail.clone());
        } else {
            lines.push(self.detail.clone());
            let passed: Vec<_> = self
                .rows
                .iter()
                .filter(|r| self.verdict(r) == "✓ Прошла")
                .map(|r| clean(text(r, "strategy")))
                .collect();
            lines.push(format!(
                "Прошли TCP-проверки: {}",
                if passed.is_empty() {
                    "нет".into()
                } else {
                    passed.join(", ")
                }
            ));
            for row in &self.rows {
                let error = text(&row["error"], "message");
                if !error.is_empty() {
                    lines.push(format!(
                        "{}: Ошибка ({}): {}",
                        text(row, "strategy"),
                        text(&row["error"], "kind"),
                        error
                    ));
                }
                for check in self
                    .checks(row)
                    .into_iter()
                    .filter(|c| c["status"] == "failed")
                {
                    lines.push(format!(
                        "{} · {} ({}): {}",
                        text(row, "strategy"),
                        label(text(check, "target")),
                        text(check, "transport"),
                        reason(check)
                    ));
                }
            }
            lines.push("Проверена доступность сайтов; видео и голос проверьте отдельно.".into());
        }
        lines.push("✓ прошла  ✗ ошибка  … проверяется  · ожидает  — недоступно".into());
        lines.push("Итог — обязательные TCP-проверки. QUIC оценивается отдельно.".into());
        if !finished {
            lines.push("Ctrl+C — остановить и показать результаты".into());
        }
        let mut out = if dimensions.is_some() {
            "\x1b[2J\x1b[H".to_owned()
        } else {
            String::new()
        };
        for line in lines.into_iter().take(if finished {
            usize::MAX
        } else {
            height.saturating_sub(1)
        }) {
            let line = if finished {
                clean(&line)
            } else {
                fit(&line, width)
            };
            out.push_str(&paint(&line, color));
            out.push('\n');
        }
        Some(out)
    }
}
