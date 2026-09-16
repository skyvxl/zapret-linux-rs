use crate::error::{AppError, Result};
use std::{
    io,
    sync::atomic::{AtomicI32, Ordering},
};

static REQUESTED: AtomicI32 = AtomicI32::new(0);

extern "C" fn request(signal: libc::c_int) {
    let _ = REQUESTED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

pub struct Signals {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Signals {
    pub fn install() -> Result<Self> {
        REQUESTED.store(0, Ordering::Relaxed);
        let mut guard = Self {
            previous: Vec::new(),
        };
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: zeroed sigaction is initialized below; valid pointers are
            // passed to sigaction. The handler only changes a lock-free atomic.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                let mut previous: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = request as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, &mut previous) == -1 {
                    return Err(AppError::new(
                        "signal",
                        io::Error::last_os_error().to_string(),
                    ));
                }
                guard.previous.push((signal, previous));
            }
        }
        Ok(guard)
    }

    pub fn requested(&self) -> Option<&'static str> {
        match REQUESTED.load(Ordering::Relaxed) {
            libc::SIGINT => Some("SIGINT"),
            libc::SIGTERM => Some("SIGTERM"),
            _ => None,
        }
    }

    pub fn check(&self) -> Result<()> {
        if let Some(signal) = self.requested() {
            return Err(AppError::new(
                "interrupted",
                format!("Запуск прерван: {signal}"),
            ));
        }
        Ok(())
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.iter().rev() {
            // SAFETY: restores the actions saved by successful sigaction calls.
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}
