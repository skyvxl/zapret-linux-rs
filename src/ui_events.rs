use crate::{
    error::{AppError, Result},
    signals::Signals,
    ui_model::ActionOutcome,
};
use serde_json::Value;
use std::{
    io::{ErrorKind, Read},
    os::fd::AsRawFd,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
const MAX_RECORD: usize = 8 * 1024 * 1024;
const MAX_STDERR: usize = 256 * 1024;
fn fail(s: impl Into<String>) -> AppError {
    AppError::new("protocol", s)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CancelSignal {
    Interrupt,
    Terminate,
}
pub struct OperationUpdate {
    pub events: Vec<Value>,
    pub outcome: Option<ActionOutcome>,
    pub stderr: Vec<String>,
}
pub struct Operation {
    child: Child,
    pipe: ChildStdout,
    stderr: ChildStderr,
    signals: Signals,
    pending: Vec<u8>,
    scanned: usize,
    finished: Option<ActionOutcome>,
    error: Option<AppError>,
    exit: Option<ExitStatus>,
    exited_at: Option<Instant>,
    eof: bool,
    stderr_eof: bool,
    forwarded: Option<CancelSignal>,
    log: Vec<u8>,
    truncated: bool,
    done: bool,
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(fail("Не удалось открыть канал результата"));
    }
    Ok(())
}
pub fn plain(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}
impl Operation {
    pub fn spawn(command: &mut Command) -> Result<Self> {
        let signals = Signals::install()?;
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| AppError::new("launch", e.to_string()))?;
        let pipe = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        if let Err(e) = nonblocking(pipe.as_raw_fd()).and_then(|_| nonblocking(stderr.as_raw_fd()))
        {
            let _ = child.kill();
            drop(pipe);
            drop(stderr);
            let _ = child.wait();
            return Err(e);
        }
        Ok(Self {
            child,
            pipe,
            stderr,
            signals,
            pending: Vec::new(),
            scanned: 0,
            finished: None,
            error: None,
            exit: None,
            exited_at: None,
            eof: false,
            stderr_eof: false,
            forwarded: None,
            log: Vec::new(),
            truncated: false,
            done: false,
        })
    }
    pub fn cancel(&mut self, signal: CancelSignal) {
        if self.exit.is_none()
            && (self.forwarded.is_none()
                || (signal == CancelSignal::Terminate && self.forwarded != Some(signal)))
        {
            unsafe {
                libc::kill(
                    self.child.id() as i32,
                    if signal == CancelSignal::Terminate {
                        libc::SIGTERM
                    } else {
                        libc::SIGINT
                    },
                );
            }
            self.forwarded = Some(signal);
        }
    }
    pub fn abort(&mut self, error: AppError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
        self.cancel(CancelSignal::Interrupt);
    }
    pub fn poll(&mut self) -> Result<OperationUpdate> {
        let mut update = OperationUpdate {
            events: Vec::new(),
            outcome: None,
            stderr: Vec::new(),
        };
        if self.done {
            return Err(fail("Действие уже завершено"));
        }
        let mut bytes = [0u8; 16384];
        match self.stderr.read(&mut bytes) {
            Ok(0) => self.stderr_eof = true,
            Ok(n) => {
                let take = n.min(MAX_STDERR.saturating_sub(self.log.len()));
                self.log.extend_from_slice(&bytes[..take]);
                if take > 0 {
                    update
                        .stderr
                        .push(plain(&String::from_utf8_lossy(&bytes[..take])));
                }
                if take < n && !self.truncated {
                    self.truncated = true;
                    update.stderr.push("\nЖурнал сокращён.\n".into());
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => (),
            Err(_) => self.stderr_eof = true,
        }
        match self.pipe.read(&mut bytes) {
            Ok(0) => self.eof = true,
            Ok(n) if self.error.is_none() => {
                self.pending.extend_from_slice(&bytes[..n]);
                while let Some(relative) = self.pending[self.scanned..]
                    .iter()
                    .position(|b| *b == b'\n')
                {
                    let end = self.scanned + relative;
                    let line: Vec<_> = self.pending.drain(..=end).collect();
                    self.scanned = 0;
                    let parsed = (|| {
                        if end > MAX_RECORD || self.finished.is_some() {
                            return Err(fail("Лишние данные после итога действия"));
                        }
                        let v: Value = serde_json::from_slice(&line)
                            .map_err(|_| fail("Повреждён канал результата действия"))?;
                        if v["ui_version"] != 1
                            || v.as_object()
                                .is_none_or(|o| o.len() != 3 || !o.contains_key("payload"))
                        {
                            return Err(fail("Неизвестная версия результата"));
                        }
                        match v["type"].as_str() {
                            Some("progress") => update.events.push(v["payload"].clone()),
                            Some("finished") => {
                                self.finished = Some(ActionOutcome::parse(&v["payload"])?)
                            }
                            _ => return Err(fail("Неизвестное событие действия")),
                        }
                        Ok(())
                    })();
                    if let Err(e) = parsed {
                        self.abort(e);
                        self.pending.clear();
                        break;
                    }
                }
                self.scanned = self.pending.len();
                if self.pending.len() > MAX_RECORD {
                    self.abort(fail("Слишком большой результат действия"));
                    self.pending.clear();
                    self.scanned = 0;
                }
            }
            Ok(_) => (),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => (),
            Err(e) => {
                self.eof = true;
                self.abort(fail(e.to_string()));
            }
        }
        match self.signals.requested() {
            Some("SIGTERM") => self.cancel(CancelSignal::Terminate),
            Some(_) => self.cancel(CancelSignal::Interrupt),
            None => (),
        }
        if self.exit.is_none() {
            match self.child.try_wait() {
                Ok(Some(s)) => {
                    self.exit = Some(s);
                    self.exited_at = Some(Instant::now());
                }
                Ok(None) => (),
                Err(e) if e.kind() == ErrorKind::Interrupted => (),
                Err(e) => {
                    self.abort(fail(e.to_string()));
                }
            }
        }
        if self.exit.is_some()
            && ((self.eof && self.stderr_eof)
                || self
                    .exited_at
                    .is_some_and(|t| t.elapsed() > Duration::from_secs(1)))
        {
            self.done = true;
            if self.signals.requested() == Some("SIGTERM") {
                return Err(AppError::new(
                    "shutdown",
                    "Завершение по SIGTERM после ожидания действия",
                ));
            }
            self.signals.clear_interrupt();
            let result = (|| {
                if let Some(e) = self.error.take() {
                    return Err(e);
                }
                if !self.eof || !self.pending.is_empty() {
                    return Err(fail("Неполный итог действия; откройте проверку состояния"));
                }
                let outcome = self.finished.take().ok_or_else(|| {
                    fail("Не получен итог действия. Проверьте сообщение sudo и состояние службы")
                })?;
                if self.exit.and_then(|s| s.code()) != Some(outcome.status.code()) {
                    return Err(fail("Итог действия не совпадает с завершением процесса"));
                }
                Ok(outcome)
            })();
            match result {
                Ok(outcome) => update.outcome = Some(outcome),
                Err(mut e) => {
                    if !self.log.is_empty() {
                        e.message
                            .push_str(&format!("\n{}", plain(&String::from_utf8_lossy(&self.log))));
                    }
                    return Err(e);
                }
            }
        }
        Ok(update)
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        // Callers normally poll to completion. Never leave a privileged child behind on an error.
        if self.exit.is_none() {
            self.cancel(CancelSignal::Interrupt);
            while self.exit.is_none() {
                let _ = self.poll();
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
pub fn supervise(
    command: &mut Command,
    on_event: &mut dyn FnMut(&Value) -> Result<()>,
) -> Result<ActionOutcome> {
    let mut operation = Operation::spawn(command)?;
    let mut callback_error = None;
    loop {
        let update = operation.poll()?;
        for line in update.stderr {
            eprint!("{line}");
        }
        for event in update.events {
            if let Err(e) = on_event(&event) {
                callback_error = Some(AppError::new(e.kind, e.message.clone()));
                operation.abort(e);
            }
        }
        if let Some(outcome) = update.outcome {
            return match callback_error {
                Some(e) => Err(e),
                None => Ok(outcome),
            };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub fn emit_finished(outcome: &ActionOutcome, signals: &Signals) -> Result<()> {
    crate::output::emit(
        serde_json::json!({"event":"ui_finished","outcome":outcome.json()}),
        signals,
        Duration::from_secs(5),
        false,
    )
}
