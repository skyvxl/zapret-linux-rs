#[path = "output/dashboard.rs"]
mod dashboard;
use crate::{
    error::{AppError, Result},
    signals::Signals,
};
use serde_json::Value;
use std::{
    io,
    os::fd::AsRawFd,
    thread,
    time::{Duration, Instant},
};

thread_local! { static DASHBOARD: std::cell::RefCell<dashboard::Dashboard> = Default::default(); }
thread_local! { static HUMAN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
thread_local! { static PROTOCOL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
thread_local! { static RESULT: std::cell::RefCell<Value> = const { std::cell::RefCell::new(Value::Null) }; }
thread_local! { static CLEANUP: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) }; }
thread_local! { static RESTORATION: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) }; }
pub struct Protocol(bool);
impl Protocol {
    pub fn enter() -> Self {
        RESULT.with(|v| *v.borrow_mut() = Value::Null);
        CLEANUP.set(None);
        RESTORATION.set(None);
        Self(PROTOCOL.replace(true))
    }
}
impl Drop for Protocol {
    fn drop(&mut self) {
        PROTOCOL.set(self.0);
    }
}
pub fn is_protocol() -> bool {
    PROTOCOL.get()
}
pub fn record_cleanup(confirmed: bool) {
    if is_protocol() {
        CLEANUP.set(Some(confirmed));
    }
}
pub fn action_result() -> (Value, Option<bool>) {
    (RESULT.with(|v| v.borrow().clone()), CLEANUP.get())
}
pub fn record_restoration(confirmed: bool) {
    if is_protocol() {
        RESTORATION.set(Some(confirmed));
    }
}
pub fn restoration() -> Option<bool> {
    RESTORATION.get()
}

/// Explicit worker-only presentation; no environment-driven legacy changes.
pub struct Human(bool);
impl Human {
    pub fn enter() -> Self {
        Self(HUMAN.replace(true))
    }
}
impl Drop for Human {
    fn drop(&mut self) {
        HUMAN.set(self.0);
    }
}

pub fn is_human() -> bool {
    HUMAN.get()
}

pub fn render_event(value: &Value) -> String {
    if let Some(rendered) = DASHBOARD.with(|d| d.borrow_mut().update(value)) {
        return rendered;
    }
    match value["event"].as_str() {
        Some("ready") => format!(
            "Запущено: {}. Очередь и firewall проверены. Для остановки Ctrl+C.\n",
            value["config"]["strategy"].as_str().unwrap_or("unknown")
        ),
        Some("stopped") if value["cleanup"] == "removed" => {
            "Остановлено: правила удалены, процесс завершён, очистка подтверждена.\n".into()
        }
        _ => format!("{value}\n"),
    }
}
pub fn reset_dashboard() {
    DASHBOARD.with(|d| *d.borrow_mut() = Default::default());
}

struct Flags {
    fd: libc::c_int,
    original: libc::c_int,
}

impl Drop for Flags {
    fn drop(&mut self) {
        // SAFETY: stdout remains locked and open until after this guard drops.
        unsafe {
            libc::fcntl(self.fd, libc::F_SETFL, self.original);
        }
    }
}

pub fn emit(value: Value, signals: &Signals, timeout: Duration, interruptible: bool) -> Result<()> {
    if is_protocol() {
        match value["event"].as_str() {
            Some("diagnosis_complete") => {
                RESULT.with(|v| *v.borrow_mut() = value["report"].clone())
            }
            Some("service_result") => RESULT.with(|v| *v.borrow_mut() = value.clone()),
            _ => (),
        }
    }
    let stdout = io::stdout().lock();
    write(
        stdout.as_raw_fd(),
        &if is_protocol() {
            let (kind, payload) = if value["event"] == "ui_finished" {
                ("finished", &value["outcome"])
            } else {
                ("progress", &value)
            };
            format!(
                "{}\n",
                serde_json::json!({"ui_version":1,"type":kind,"payload":payload})
            )
        } else if HUMAN.get() {
            render_event(&value)
        } else {
            format!("{value}\n")
        },
        "stdout",
        signals,
        timeout,
        interruptible,
    )
}

pub fn stderr(text: &str, signals: &Signals, timeout: Duration) -> Result<()> {
    let stderr = io::stderr().lock();
    write(stderr.as_raw_fd(), text, "stderr", signals, timeout, false)
}

fn write(
    fd: libc::c_int,
    text: &str,
    name: &str,
    signals: &Signals,
    timeout: Duration,
    interruptible: bool,
) -> Result<()> {
    // SAFETY: valid locked stdout descriptor; fcntl uses scalar arguments.
    let original = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if original < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, original | libc::O_NONBLOCK) } < 0 {
        return Err(AppError::new(
            "output",
            io::Error::last_os_error().to_string(),
        ));
    }
    let _restore = Flags { fd, original };
    let bytes = text.as_bytes();
    let mut sent = 0;
    let start = Instant::now();
    while sent < bytes.len() {
        // Finish a started JSON record even if interrupted, within the same
        // bounded timeout. Otherwise the next report would append to half a line.
        if interruptible && sent == 0 {
            signals.check()?;
        }
        if start.elapsed() >= timeout {
            return Err(AppError::new(
                "timeout",
                format!(
                    "{name}: вывод заблокирован более {} мс",
                    timeout.as_millis()
                ),
            ));
        }
        // SAFETY: the byte slice is live and exactly len-sent bytes are readable.
        // Raw write avoids std's line buffer hiding a retrying blocking flush.
        let count = unsafe { libc::write(fd, bytes[sent..].as_ptr().cast(), bytes.len() - sent) };
        if count > 0 {
            sent += count as usize;
            continue;
        }
        if count == 0 {
            return Err(AppError::new("output", format!("{name}: запись вернула 0")));
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Err(AppError::new("output", error.to_string()));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
