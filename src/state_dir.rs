use crate::error::{AppError, Result};
use serde_json::Value;
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: u64 = 65536;

fn error(stage: &str, error: impl std::fmt::Display) -> AppError {
    AppError::new("state", format!("Состояние {stage}: {error}"))
}

pub struct StateDir {
    directory: File,
}
pub struct Lease {
    directory: StateDir,
    _lock: File,
}

impl StateDir {
    pub fn open(path: &Path) -> Result<Self> {
        // Trailing '/' or '/.' would make open follow a final symlink despite
        // O_NOFOLLOW. Components removes these redundant suffixes first.
        let path: std::path::PathBuf = path.components().collect();
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| error("каталог", e))?;
        let metadata = directory.metadata().map_err(|e| error("каталог", e))?;
        // SAFETY: geteuid has no arguments or error cases.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
            return Err(error(
                "каталог",
                "требуется собственный каталог с правами 0700",
            ));
        }
        Ok(Self { directory })
    }

    fn open_file(&self, name: &CStr, flags: libc::c_int) -> io::Result<File> {
        // SAFETY: directory fd and NUL-terminated name are live, flags scalar.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a new owned descriptor from a successful openat.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn trusted(file: &File) -> Result<()> {
        let metadata = file.metadata().map_err(|e| error("файл", e))?;
        // SAFETY: geteuid has no arguments or error cases.
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(error(
                "файл",
                "требуется собственный обычный файл 0600 без hardlink",
            ));
        }
        Ok(())
    }

    pub fn read(&self) -> Result<Option<Value>> {
        let file = match self.open_file(c"state.json", libc::O_RDONLY) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(error("чтение", e)),
        };
        Self::trusted(&file)?;
        let mut bytes = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| error("чтение", e))?;
        if bytes.len() as u64 > LIMIT {
            return Err(error("чтение", "журнал превышает 64 KiB"));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| error("JSON", e))
    }

    pub fn lock(self) -> Result<Lease> {
        let lock = self
            .open_file(c"lock", libc::O_RDWR | libc::O_CREAT)
            .map_err(|e| error("lock", e))?;
        Self::trusted(&lock)?;
        // SAFETY: a live regular file descriptor and scalar flock operations.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            return Err(if e.kind() == io::ErrorKind::WouldBlock {
                AppError::new(
                    "locked",
                    "Этот каталог состояния уже занят другим процессом",
                )
            } else {
                error("lock", e)
            });
        }
        Ok(Lease {
            directory: self,
            _lock: lock,
        })
    }

    fn unlink(&self, name: &CStr) -> io::Result<()> {
        // SAFETY: live directory descriptor and NUL-terminated basename.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Lease {
    pub fn read(&self) -> Result<Option<Value>> {
        self.directory.read()
    }

    pub fn write(&self, value: &Value) -> Result<()> {
        // Do not overwrite corrupt/unsafe existing state; recovery needs evidence.
        self.read()?;
        let bytes = serde_json::to_vec(value).map_err(|e| error("JSON", e))?;
        if bytes.len() as u64 > LIMIT {
            return Err(error("запись", "журнал превышает 64 KiB"));
        }
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| error("время", e))?
            .as_nanos();
        let name = CString::new(format!(".state-{}-{stamp}.tmp", std::process::id()))
            .map_err(|e| error("имя", e))?;
        let mut file = self
            .directory
            .open_file(&name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
            .map_err(|e| error("временный файл", e))?;
        let result = (|| {
            StateDir::trusted(&file)?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| error("запись/fsync", e))?;
            // SAFETY: both basenames and directory descriptors remain live.
            if unsafe {
                libc::renameat(
                    self.directory.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.directory.as_raw_fd(),
                    c"state.json".as_ptr(),
                )
            } != 0
            {
                return Err(error("rename", io::Error::last_os_error()));
            }
            self.directory
                .directory
                .sync_all()
                .map_err(|e| error("fsync каталога", e))
        })();
        if result.is_err() {
            let _ = self.directory.unlink(&name);
        }
        result
    }

    pub fn clear(&self) -> Result<()> {
        if self.read()?.is_some() {
            self.directory
                .unlink(c"state.json")
                .map_err(|e| error("удаление", e))?;
            self.directory
                .directory
                .sync_all()
                .map_err(|e| error("fsync каталога", e))?;
        }
        // The lock inode must remain stable between invocations.
        Ok(())
    }
}
