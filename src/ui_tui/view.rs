use super::*;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap},
};
fn accent(color: bool) -> Style {
    if color {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    }
}
fn area(f: &mut Frame, home: bool) -> Option<Rect> {
    let a = f.area();
    if a.width < 38 || a.height < 12 {
        f.render_widget(
            Paragraph::new("Увеличьте терминал до 38 × 12\nCtrl+C: выход"),
            a,
        );
        return None;
    }
    let width = a.width.saturating_sub(4).min(92);
    let height = a.height.saturating_sub(2).min(if home { 18 } else { 30 });
    Some(Rect::new(
        a.x + (a.width - width) / 2,
        a.y + (a.height - height) / 2,
        width,
        height,
    ))
}
fn block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(format!(" {title} "))
}
#[allow(clippy::too_many_arguments)]
pub(super) fn menu(
    f: &mut Frame,
    title: &str,
    body: &str,
    items: &[Item],
    state: &mut ListState,
    query: Option<&str>,
    notice: &str,
    color: bool,
) {
    let Some(a) = area(f, title == "Главное меню") else {
        return;
    };
    let body = plain(body);
    if a.height < 16 {
        let parts = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(if title == "Главное меню" {
                4
            } else {
                2
            }),
            Constraint::Length(if query.is_some() { 1 } else { 0 }),
            Constraint::Min(2),
            Constraint::Length(if notice.is_empty() { 2 } else { 3 }),
        ])
        .split(a);
        f.render_widget(
            Paragraph::new(format!("ZAPRET · {title}")).style(accent(color)),
            parts[0],
        );
        f.render_widget(Paragraph::new(body.clone()), parts[1]);
        if let Some(q) = query {
            f.render_widget(Paragraph::new(format!("Поиск: {q}")), parts[2]);
        }
        let rows: Vec<_> = items
            .iter()
            .map(|i| {
                ListItem::new(plain(&i.label)).style(if i.enabled {
                    Style::default()
                } else {
                    Style::default().add_modifier(Modifier::DIM)
                })
            })
            .collect();
        f.render_stateful_widget(
            List::new(rows)
                .highlight_symbol("› ")
                .highlight_style(accent(color).add_modifier(Modifier::BOLD)),
            parts[3],
            state,
        );
        f.render_widget(
            Paragraph::new(if notice.is_empty() {
                "↑↓: выбор · Enter: открыть\nEsc: назад · Ctrl+C: выход".into()
            } else {
                format!("{}\nEnter: выбрать · Esc: назад", plain(notice))
            })
            .wrap(Wrap { trim: false }),
            parts[4],
        );
        return;
    }
    let body_height = (body.lines().count() as u16 + 2).min(a.height.saturating_sub(9));
    let parts = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(body_height),
        Constraint::Length(if query.is_some() { 3 } else { 0 }),
        Constraint::Min(3),
        Constraint::Length(3),
    ])
    .split(a);
    f.render_widget(
        Paragraph::new("ZAPRET").style(accent(color).add_modifier(Modifier::BOLD)),
        parts[0],
    );
    f.render_widget(
        Paragraph::new(body)
            .block(block(title))
            .wrap(Wrap { trim: false }),
        parts[1],
    );
    if let Some(q) = query {
        f.render_widget(
            Paragraph::new(plain(q)).block(block("Поиск: просто печатайте")),
            parts[2],
        );
    }
    let rows: Vec<_> = items
        .iter()
        .map(|i| {
            ListItem::new(plain(&i.label)).style(if i.enabled {
                Style::default()
            } else {
                Style::default().add_modifier(Modifier::DIM)
            })
        })
        .collect();
    f.render_stateful_widget(
        List::new(rows)
            .highlight_symbol("› ")
            .highlight_style(accent(color).add_modifier(Modifier::BOLD)),
        parts[3],
        state,
    );
    let hint = if query.is_some() {
        "↑↓ / колесо: выбор · Enter: открыть · Текст: поиск"
    } else {
        "↑↓ / колесо: выбор · Enter: открыть"
    };
    f.render_widget(
        Paragraph::new(vec![
            Line::from(plain(notice)),
            Line::from(hint),
            Line::from("Esc: назад · Ctrl+C: выход"),
        ]),
        parts[4],
    );
}
pub(super) fn details(f: &mut Frame, title: &str, text: &str, scroll: u16, color: bool) {
    let Some(a) = area(f, false) else {
        return;
    };
    let p = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(a);
    f.render_widget(Paragraph::new("ZAPRET").style(accent(color)), p[0]);
    f.render_widget(
        Paragraph::new(plain(text))
            .block(block(title))
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        p[1],
    );
    f.render_widget(
        Paragraph::new("↑↓ / колесо: прокрутить · Esc / Enter: назад"),
        p[2],
    );
}
pub(super) fn operation(f: &mut Frame, title: &str, text: &str, cancelling: bool, color: bool) {
    let Some(a) = area(f, false) else {
        return;
    };
    let p = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(a);
    f.render_widget(Paragraph::new("ZAPRET").style(accent(color)), p[0]);
    f.render_widget(
        Paragraph::new(plain(text))
            .block(block(title))
            .wrap(Wrap { trim: false }),
        p[1],
    );
    f.render_widget(
        Paragraph::new(if cancelling {
            "Завершаем действие и ждём очистки…"
        } else {
            "Esc / Ctrl+C: остановить и дождаться очистки"
        }),
        p[2],
    );
}

pub(super) fn confirm(
    f: &mut Frame,
    background: Option<&ratatui::buffer::Buffer>,
    title: &str,
    body: &str,
    yes: bool,
    color: bool,
) {
    use ratatui::{
        buffer::Buffer,
        widgets::{Clear, Padding},
    };
    let a = f.area();
    if let Some(b) = background.filter(|b| b.area == a) {
        let mut dim: Buffer = b.clone();
        for cell in &mut dim.content {
            cell.set_style(Style::default().add_modifier(Modifier::DIM));
            if color {
                cell.set_fg(Color::DarkGray);
            }
        }
        *f.buffer_mut() = dim;
    }
    if a.width < 38 || a.height < 12 {
        f.render_widget(Clear, a);
        f.render_widget(
            Paragraph::new("Увеличьте терминал до 38 × 12\nEsc: отмена"),
            a,
        );
        return;
    }
    let width = a.width.saturating_sub(2).min(62);
    let height = a.height.saturating_sub(2).min(14);
    let modal = Rect::new(
        (a.width - width) / 2,
        (a.height - height) / 2,
        width,
        height,
    );
    f.render_widget(Clear, modal);
    let border = block(title)
        .style(accent(color))
        .padding(Padding::horizontal(1));
    let inner = border.inner(modal);
    f.render_widget(border, modal);
    let parts = Layout::vertical([
        Constraint::Min(2),
        Constraint::Length(2),
        Constraint::Length(1),
    ])
    .split(inner);
    f.render_widget(
        Paragraph::new(plain(body)).wrap(Wrap { trim: false }),
        parts[0],
    );
    let mut state = ListState::default().with_selected(Some(usize::from(yes)));
    f.render_stateful_widget(
        List::new(["Отмена", "Продолжить"])
            .highlight_symbol("› ")
            .highlight_style(accent(color).add_modifier(Modifier::BOLD)),
        parts[1],
        &mut state,
    );
    f.render_widget(Paragraph::new("Enter: выбрать · Esc: отмена"), parts[2]);
}
