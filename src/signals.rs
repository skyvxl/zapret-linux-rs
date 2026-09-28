use crate::error::{AppError, Result};
use std::{
    cell::RefCell,
    io,
    rc::{Rc, Weak},
    sync::atomic::{AtomicI32, Ordering},
};

static REQUESTED: AtomicI32 = AtomicI32::new(0);

extern "C" fn request(signal: libc::c_int) {
    if signal == libc::SIGTERM {
        REQUESTED.store(signal, Ordering::Relaxed);
    } else {
        let _ = REQUESTED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
    }
}

pub struct Signals {
    _registration: Rc<Registration>,
}
struct Registration {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}
thread_local! {static REGISTRATION: RefCell<Weak<Registration>> = const {RefCell::new(Weak::new())};}

impl Signals {
    pub fn install() -> Result<Self> {
        if let Some(registration) = REGISTRATION.with(|slot| slot.borrow().upgrade()) {
            return Ok(Self {
                _registration: registration,
            });
        }
        REQUESTED.store(0, Ordering::Relaxed);
        let mut guard = Registration {
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
        let registration = Rc::new(guard);
        REGISTRATION.with(|slot| *slot.borrow_mut() = Rc::downgrade(&registration));
        Ok(Self {
            _registration: registration,
        })
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
    pub fn clear_interrupt(&self) {
        let _ = REQUESTED.compare_exchange(libc::SIGINT, 0, Ordering::Relaxed, Ordering::Relaxed);
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.iter().rev() {
            // SAFETY: restores the actions saved by successful sigaction calls.
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}
