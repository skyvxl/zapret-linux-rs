use crate::error::{AppError, Result};
use std::{
    env, io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
    thread,
    time::{Duration, Instant},
};

pub struct Notifier {
    socket: UnixDatagram,
}

fn error(message: impl Into<String>) -> AppError {
    AppError::new("notify", message)
}

impl Notifier {
    pub fn from_env(required: bool) -> Result<Option<Self>> {
        if !required {
            return Ok(None);
        }
        let address = env::var_os("NOTIFY_SOCKET")
            .ok_or_else(|| error("Нет NOTIFY_SOCKET для --systemd-notify"))?;
        let bytes = address.as_bytes();
        let address = if let Some(name) = bytes.strip_prefix(b"@") {
            if name.is_empty() || name.contains(&0) {
                return Err(error("Некорректный abstract NOTIFY_SOCKET"));
            }
            SocketAddr::from_abstract_name(name)
        } else {
            if !bytes.starts_with(b"/") || bytes.contains(&0) {
                return Err(error(
                    "NOTIFY_SOCKET должен быть абсолютным путём или @именем",
                ));
            }
            SocketAddr::from_pathname(&address)
        }
        .map_err(|e| error(e.to_string()))?;
        let socket = UnixDatagram::unbound().map_err(|e| error(e.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| error(e.to_string()))?;
        socket
            .connect_addr(&address)
            .map_err(|e| error(format!("NOTIFY_SOCKET: {e}")))?;
        Ok(Some(Self { socket }))
    }

    pub fn ready(&self, timeout: Duration, tick: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let start = Instant::now();
        let message = b"READY=1\nSTATUS=Packet queue ready";
        loop {
            tick()?;
            match self.socket.send(message) {
                Ok(n) if n == message.len() => return Ok(()),
                Ok(_) => return Err(error("Неполное уведомление systemd")),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(error(format!("systemd READY: {e}"))),
            }
            if start.elapsed() >= timeout {
                return Err(error("systemd READY: время ожидания истекло"));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn stopping(&self) {
        // Best effort, nonblocking: notification must never prevent cleanup.
        let _ = self
            .socket
            .send(b"STOPPING=1\nSTATUS=Removing owned packet rules");
    }
}
