//! Canonical terminal input and scoped supervision of interactive subprocesses.
use crate::{
    error::{AppError, Result},
    signals::Signals,
};
use std::{
    io::{self, IsTerminal, Write},
    process::Command,
    thread,
    time::Duration,
};

pub fn is_terminal() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}
pub fn title(text: &str) {
    if is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|v| v != "dumb")
    {
        println!("\n\x1b[1;36m{text}\x1b[0m");
    } else {
        println!("\n{text}");
    }
}
/// Read one canonical line without std::read_line's automatic EINTR retries.
/// The signal guard ends before an action installs its own core handlers.
pub fn prompt(label: &str) -> Result<Option<String>> {
    if !is_terminal() {
        return Err(AppError::new(
            "usage",
            "Нужен интерактивный терминал; используйте ./service.sh --help",
        ));
    }
    let signals = Signals::install()?;
    print!("{label}");
    io::stdout()
        .flush()
        .map_err(|e| AppError::new("terminal", e.to_string()))?;
    let mut bytes = Vec::new();
    loop {
        if let Some(signal) = signals.requested() {
            println!();
            if signal == "SIGTERM" {
                return Err(AppError::new("shutdown", "Завершение по SIGTERM"));
            }
            return Ok(None);
        }
        let mut p = libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut p, 1, 100) };
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(AppError::new(
                "terminal",
                io::Error::last_os_error().to_string(),
            ));
        }
        if ready == 0 {
            continue;
        }
        let mut byte = 0u8;
        let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
        if n == 0 {
            return Ok(None);
        }
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(AppError::new(
                "terminal",
                io::Error::last_os_error().to_string(),
            ));
        }
        if byte == b'\n' {
            return String::from_utf8(bytes)
                .map(|s| Some(s.trim().to_string()))
                .map_err(|_| AppError::new("terminal", "Ввод должен быть UTF-8"));
        }
        if bytes.len() >= 4096 {
            return Err(AppError::new("terminal", "Слишком длинный ввод"));
        }
        bytes.push(byte);
    }
}
/// Keep sudo and its worker in the foreground terminal group, with inherited
/// stdio for authentication. Reap before restoring signals or returning to menu.
/// Direct SIGTERM/SIGINT sent only to this parent is relayed once to sudo (which
/// relays to its command); terminal group signals are safe to receive twice.
pub fn supervise(command: &mut Command) -> Result<()> {
    let signals = Signals::install()?;
    let mut child = command
        .spawn()
        .map_err(|e| AppError::new("launch", e.to_string()))?;
    let mut forwarded = false;
    loop {
        if !forwarded && let Some(signal) = signals.requested() {
            unsafe {
                libc::kill(
                    child.id() as i32,
                    if signal == "SIGTERM" {
                        libc::SIGTERM
                    } else {
                        libc::SIGINT
                    },
                );
            }
            forwarded = true;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if signals.requested() == Some("SIGTERM") {
                    return Err(AppError::new(
                        "shutdown",
                        "Завершение по SIGTERM после ожидания дочернего действия; результат очистки указан самим действием выше",
                    ));
                }
                if status.success() {
                    return Ok(());
                }
                return Err(AppError::new(
                    "action",
                    format!(
                        "Действие завершилось с {status}. Если sudo отменён, повторите выбранное действие. При ошибке очистки используйте «Восстановить состояние»; причина приведена выше."
                    ),
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // Do not abandon an operation whose status is unknown.
                let _ = child.wait();
                return Err(AppError::new("launch", e.to_string()));
            }
        }
    }
}
