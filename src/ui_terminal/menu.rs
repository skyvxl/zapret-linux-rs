use crate::{
    error::{AppError, Result},
    signals::Signals,
};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

pub struct MenuItem {
    pub id: String,
    pub label: String,
    pub detail: Option<String>,
    pub enabled: bool,
}
impl MenuItem {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            detail: None,
            enabled: true,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Selection {
    Item(String),
    Back,
    Exit,
}

struct Terminal {
    original: libc::termios,
}
impl Terminal {
    fn enter() -> Result<Self> {
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut original) } != 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        let mut mode = original;
        mode.c_lflag &= !(libc::ICANON | libc::ECHO);
        mode.c_cc[libc::VMIN] = 1;
        mode.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &mode) } != 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        print!("\x1b[?1049h\x1b[?25l");
        Ok(Self { original })
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.original);
        }
        print!("\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = io::stdout().flush();
    }
}
fn fail(e: impl ToString) -> AppError {
    AppError::new("terminal", e.to_string())
}
enum Key {
    Byte(u8),
    Timeout,
    Back,
    Exit,
}
fn read(signals: &Signals, timeout: Option<Duration>) -> Result<Key> {
    let started = Instant::now();
    loop {
        match signals.requested() {
            Some("SIGTERM") => return Err(AppError::new("shutdown", "Завершение по SIGTERM")),
            Some(_) => {
                signals.clear_interrupt();
                return Ok(Key::Back);
            }
            None => (),
        }
        if timeout.is_some_and(|t| started.elapsed() >= t) {
            return Ok(Key::Timeout);
        }
        let mut fd = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut fd, 1, 25) };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(fail(io::Error::last_os_error()));
        }
        if n == 0 {
            continue;
        }
        let mut b = 0u8;
        let n = unsafe { libc::read(0, (&mut b as *mut u8).cast(), 1) };
        if n == 0 {
            return Ok(Key::Exit);
        }
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(fail(io::Error::last_os_error()));
        }
        return Ok(Key::Byte(b));
    }
}
fn dimensions() -> (usize, usize) {
    let mut s: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut s) } == 0 && s.ws_col > 0 && s.ws_row > 0 {
        (
            usize::from(s.ws_col).saturating_sub(1).max(8),
            usize::from(s.ws_row).max(5),
        )
    } else {
        (79, 24)
    }
}
unsafe extern "C" {
    fn wcwidth(c: libc::wchar_t) -> libc::c_int;
}
fn clipped(text: &str, width: usize) -> String {
    let mut result = String::new();
    let mut used = 0;
    for c in text.chars() {
        if c.is_control() {
            continue;
        }
        let w = unsafe { wcwidth(c as libc::wchar_t) };
        let (c, w) = if w < 0 { ('?', 1) } else { (c, w as usize) };
        if used + w > width.saturating_sub(1) {
            result.push('…');
            break;
        }
        result.push(c);
        used += w;
    }
    result
}
fn frame(
    title: &str,
    items: &[MenuItem],
    visible: &[usize],
    selected: usize,
    query: Option<&str>,
    input: &str,
    notice: &str,
) -> Vec<u8> {
    let (width, height) = dimensions();
    let header: Vec<_> = title
        .lines()
        .take(height.saturating_sub(7).max(1))
        .collect();
    let lines = height.saturating_sub(5 + header.len()).max(1);
    let pos = visible.iter().position(|i| *i == selected).unwrap_or(0);
    let start = pos.saturating_sub(lines - 1);
    let mut frame = Vec::new();
    write!(frame, "\x1b[H").unwrap();
    let color = std::env::var_os("NO_COLOR").is_none();
    if color {
        write!(frame, "\x1b[1;36m").unwrap();
    }
    for line in header {
        writeln!(frame, "{}\x1b[K", clipped(line, width)).unwrap();
    }
    if color {
        write!(frame, "\x1b[0m").unwrap();
    }
    if let Some(query) = query {
        writeln!(
            frame,
            "{}\x1b[K",
            clipped(&format!("Поиск: {query}"), width)
        )
        .unwrap();
    } else {
        writeln!(frame, "\x1b[K").unwrap();
    }
    if visible.is_empty() {
        writeln!(frame, "{}\x1b[K", clipped("Ничего не найдено", width)).unwrap();
    }
    for &i in visible.iter().skip(start).take(lines) {
        let marker = if i == selected { "›" } else { " " };
        let suffix = if items[i].enabled {
            ""
        } else {
            " (недоступно)"
        };
        writeln!(
            frame,
            "{}\x1b[K",
            clipped(
                &format!("{marker} {}. {}{suffix}", i + 1, items[i].label),
                width
            )
        )
        .unwrap();
    }
    let detail = items
        .get(selected)
        .and_then(|i| i.detail.as_deref())
        .unwrap_or("");
    writeln!(
        frame,
        "{}\x1b[K",
        clipped(if notice.is_empty() { detail } else { notice }, width)
    )
    .unwrap();
    writeln!(
        frame,
        "{}\x1b[K",
        clipped(
            if query.is_some() {
                "↑↓ Выбрать · Enter Открыть · / Поиск"
            } else {
                "↑↓ Выбрать · Enter Открыть"
            },
            width
        )
    )
    .unwrap();
    write!(
        frame,
        "{}",
        clipped(&format!("Esc / 0 Назад    Выбор: {input}"), width)
    )
    .unwrap();
    write!(frame, "\x1b[J").unwrap();
    frame
}
fn fallback(title: &str, items: &[MenuItem], searchable: bool) -> Result<Selection> {
    let signals = Signals::install()?;
    let mut query = String::new();
    loop {
        println!("\n{title}");
        for (i, item) in items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.label.to_lowercase().contains(&query.to_lowercase()))
        {
            println!(
                "{}. {}{}",
                i + 1,
                item.label,
                if item.enabled {
                    ""
                } else {
                    " (недоступно)"
                }
            );
            if !item.enabled
                && let Some(detail) = &item.detail
            {
                println!("   {detail}");
            }
        }
        if searchable {
            println!("/текст — поиск по имени");
        }
        println!("0. Назад");
        print!("Выбор: ");
        io::stdout().flush().map_err(fail)?;
        let mut bytes = Vec::new();
        loop {
            match read(&signals, None)? {
                Key::Back => return Ok(Selection::Back),
                Key::Exit => return Ok(Selection::Exit),
                Key::Byte(b'\n' | b'\r') => break,
                Key::Byte(b) if bytes.len() < 4096 => bytes.push(b),
                Key::Byte(_) => return Err(fail("Слишком длинный ввод")),
                Key::Timeout => (),
            }
        }
        let line = String::from_utf8(bytes).map_err(fail)?;
        let line = line.trim();
        if line == "0" {
            return Ok(Selection::Back);
        }
        if searchable && let Some(q) = line.strip_prefix('/') {
            query = q.into();
            continue;
        }
        if let Ok(n) = line.parse::<usize>()
            && let Some(item) = n.checked_sub(1).and_then(|i| items.get(i))
            && item.enabled
            && item.label.to_lowercase().contains(&query.to_lowercase())
        {
            return Ok(Selection::Item(item.id.clone()));
        }
        println!("Выберите доступный пункт из списка.");
    }
}

pub fn select(
    title: &str,
    items: &[MenuItem],
    initial: usize,
    searchable: bool,
) -> Result<Selection> {
    if !super::is_terminal() {
        return Err(AppError::new(
            "usage",
            "Меню требует интерактивный терминал; справка: ./service.sh --help",
        ));
    }
    if !super::supports_screen() {
        return fallback(title, items, searchable);
    }
    // This program is single-threaded; establish libc's Unicode width handling once.
    static LOCALE: std::sync::Once = std::sync::Once::new();
    LOCALE.call_once(|| unsafe {
        libc::setlocale(libc::LC_CTYPE, c"".as_ptr());
    });
    let signals = Signals::install()?;
    let _terminal = Terminal::enter()?;
    let mut selected = initial.min(items.len().saturating_sub(1));
    let mut query = Vec::new();
    let mut searching = false;
    let mut number = String::new();
    let mut notice = String::new();
    let mut previous_frame = Vec::new();
    let mut previous_size = dimensions();
    loop {
        let q = String::from_utf8_lossy(&query).to_string();
        let visible: Vec<_> = items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.label.to_lowercase().contains(&q.to_lowercase()))
            .map(|(i, _)| i)
            .collect();
        if !visible.contains(&selected) {
            selected = visible.first().copied().unwrap_or(0);
        }
        let frame = frame(
            title,
            items,
            &visible,
            selected,
            searchable.then_some(q.as_str()),
            &number,
            &notice,
        );
        let size = dimensions();
        if frame != previous_frame || size != previous_size {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&frame).map_err(fail)?;
            stdout.flush().map_err(fail)?;
            previous_frame = frame;
            previous_size = size;
        }
        match read(&signals, Some(Duration::from_millis(200)))? {
            Key::Back => return Ok(Selection::Back),
            Key::Exit => return Ok(Selection::Exit),
            Key::Timeout => continue,
            Key::Byte(4) => return Ok(Selection::Exit),
            Key::Byte(27) => match read(&signals, Some(Duration::from_millis(100)))? {
                Key::Timeout => return Ok(Selection::Back),
                Key::Exit => return Ok(Selection::Exit),
                Key::Back => return Ok(Selection::Back),
                Key::Byte(b'[' | b'O') => {
                    if let Key::Byte(direction @ (b'A' | b'B')) =
                        read(&signals, Some(Duration::from_millis(100)))?
                        && !visible.is_empty()
                    {
                        let pos = visible.iter().position(|i| *i == selected).unwrap_or(0);
                        selected = visible[if direction == b'A' {
                            pos.saturating_sub(1)
                        } else {
                            (pos + 1).min(visible.len() - 1)
                        }];
                        number.clear();
                        notice.clear();
                    }
                }
                Key::Byte(_) => (),
            },
            Key::Byte(b'\r' | b'\n') => {
                if searching {
                    searching = false;
                    continue;
                }
                if number == "0" {
                    return Ok(Selection::Back);
                }
                let pick = if number.is_empty() {
                    Some(selected)
                } else {
                    number.parse::<usize>().ok().and_then(|n| n.checked_sub(1))
                };
                number.clear();
                if let Some(i) = pick
                    && visible.contains(&i)
                    && items[i].enabled
                {
                    return Ok(Selection::Item(items[i].id.clone()));
                }
                notice = "Выберите доступный пункт из списка".into();
            }
            Key::Byte(b'/') if searchable && !searching => {
                searching = true;
                query.clear();
                number.clear();
            }
            Key::Byte(127 | 8) => {
                if searching {
                    query.pop();
                    while !query.is_empty() && std::str::from_utf8(&query).is_err() {
                        query.pop();
                    }
                } else {
                    number.pop();
                }
            }
            Key::Byte(b) if searching && !b.is_ascii_control() && query.len() < 256 => {
                query.push(b);
            }
            Key::Byte(b) if b.is_ascii_digit() && number.len() < 6 => {
                number.push(b as char);
            }
            Key::Byte(_) => (),
        }
    }
}
pub fn confirm(title: &str, description: &str) -> Result<bool> {
    let mut yes = MenuItem::new("yes", "Продолжить");
    yes.detail = Some(description.into());
    Ok(select(
        &format!("{title}\n{description}"),
        &[MenuItem::new("no", "Отмена"), yes],
        0,
        false,
    )? == Selection::Item("yes".into()))
}
