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
    let stdout = io::stdout().lock();
    write(
        stdout.as_raw_fd(),
        &format!("{value}\n"),
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
