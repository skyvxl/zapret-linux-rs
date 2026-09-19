//! Small no-follow directory handles for the installer. Paths passed to a handle
//! are validated basenames; payload deletion never consumes manifest paths.
use crate::error::{AppError, Result};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

pub fn fail(message: impl std::fmt::Display) -> AppError {
    AppError::new("service", message.to_string())
}
pub fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
pub fn gid() -> u32 {
    if uid() == 0 {
        0
    } else {
        unsafe { libc::getegid() }
    }
}
pub fn own(file: &File) -> Result<()> {
    let m = file.metadata().map_err(fail)?;
    if (m.uid() != uid() || m.gid() != gid())
        && unsafe { libc::fchown(file.as_raw_fd(), uid(), gid()) } != 0
    {
        return Err(fail(io::Error::last_os_error()));
    }
    Ok(())
}
pub fn path_ok(path: &Path) -> Result<()> {
    if path
        .as_os_str()
        .to_str()
        .is_none_or(|s| s.is_empty() || s.chars().any(char::is_control))
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(fail("Invalid path: traversal, controls or non-UTF-8"));
    }
    Ok(())
}
/// Stable owned-data format; producers may impose narrower size/suffix rules.
pub fn owned_data_basename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('.')
        && !value
            .chars()
            .any(|c| c.is_control() || "/\\:\"'<>|?*".contains(c))
}
fn name(value: &str) -> Result<CString> {
    if value.is_empty()
        || value.contains('/')
        || [".", ".."].contains(&value)
        || value.chars().any(char::is_control)
    {
        return Err(fail("Invalid basename"));
    }
    CString::new(value).map_err(fail)
}
pub fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub struct Dir(pub File);
impl Dir {
    pub fn absolute(path: &Path, trusted: bool, offline: bool) -> Result<Self> {
        path_ok(path)?;
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().map_err(fail)?.join(path)
        };
        let mut dir = Self(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")
                .map_err(fail)?,
        );
        for component in path.components() {
            if let Component::Normal(s) = component {
                if trusted {
                    dir.ancestor(offline)?;
                }
                dir = dir.child(s.to_str().ok_or_else(|| fail("Non-UTF-8 component"))?)?;
            }
        }
        if trusted {
            dir.ancestor(offline)?;
        }
        Ok(dir)
    }
    pub fn ancestor(&self, offline: bool) -> Result<()> {
        let m = self.0.metadata().map_err(fail)?;
        let owner = if offline {
            m.uid() == 0 || m.uid() == uid()
        } else {
            m.uid() == 0
        };
        let sticky = offline && m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !owner || (m.mode() & 0o022 != 0 && !sticky) {
            return Err(fail("Untrusted writable destination ancestor"));
        }
        Ok(())
    }
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
    }
    pub fn child(&self, value: &str) -> Result<Self> {
        self.open(value, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map(Self)
    }
    pub fn open(&self, value: &str, flags: i32, mode: u32) -> Result<File> {
        let n = name(value)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                n.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                mode as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub fn exists(&self, value: &str) -> Result<bool> {
        name(value)?;
        match fs::symlink_metadata(self.path().join(value)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(fail(e)),
        }
    }
    pub fn mkdir(&self, value: &str, mode: u32) -> Result<Self> {
        let n = name(value)?;
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), n.as_ptr(), mode) } != 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        let d = self.child(value)?;
        own(&d.0)?;
        d.0.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(fail)?;
        self.sync()?;
        Ok(d)
    }
    pub fn ensure(&self, value: &str) -> Result<Self> {
        let d = if self.exists(value)? {
            self.child(value)?
        } else {
            self.mkdir(value, 0o755)?
        };
        d.ancestor(uid() != 0)?;
        Ok(d)
    }
    pub fn mode(&self, mode: u32) -> Result<()> {
        self.0
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(fail)
    }
    pub fn sync(&self) -> Result<()> {
        self.0.sync_all().map_err(fail)
    }
    pub fn write(&self, value: &str, bytes: &[u8], mode: u32) -> Result<()> {
        let mut f = self.open(value, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)?;
        own(&f)?;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(fail)?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(fail)?;
        self.sync()
    }
    pub fn read(&self, value: &str, mode: u32, limit: u64) -> Result<Vec<u8>> {
        let f = self.open(value, libc::O_RDONLY, 0)?;
        trusted_file(&f, mode)?;
        read_stable(f, limit)
    }
    pub fn names(&self) -> Result<Vec<String>> {
        let mut v = Vec::new();
        for e in fs::read_dir(self.path()).map_err(fail)? {
            if v.len() >= 20032 {
                return Err(fail("Directory entry limit exceeded"));
            }
            let s = e
                .map_err(fail)?
                .file_name()
                .into_string()
                .map_err(|_| fail("Non-UTF-8 filename"))?;
            name(&s)?;
            v.push(s);
        }
        v.sort();
        Ok(v)
    }
    pub fn rename(&self, old: &str, dest: &Self, new: &str) -> Result<()> {
        let a = name(old)?;
        let b = name(new)?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.0.as_raw_fd(),
                a.as_ptr(),
                dest.0.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(fail(io::Error::last_os_error()));
        }
        self.sync().and_then(|_| dest.sync()).map_err(|e| {
            AppError::new(
                "outcome_unknown",
                format!(
                    "rename completed but directory fsync failed; preserve published object: {}",
                    e.message
                ),
            )
        })
    }
    pub fn unlink(&self, value: &str, directory: bool) -> Result<()> {
        let n = name(value)?;
        if unsafe {
            libc::unlinkat(
                self.0.as_raw_fd(),
                n.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        } != 0
        {
            return Err(fail(io::Error::last_os_error()));
        }
        self.sync()
    }
}
pub fn trusted_file(f: &File, mode: u32) -> Result<()> {
    let m = f.metadata().map_err(fail)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != uid()
        || m.gid() != gid()
        || m.mode() & 0o7777 != mode
    {
        return Err(fail("Unowned, linked or incorrectly permissioned file"));
    }
    Ok(())
}
pub fn read_stable(mut f: File, limit: u64) -> Result<Vec<u8>> {
    let before = f.metadata().map_err(fail)?;
    if !before.is_file() || before.len() > limit {
        return Err(fail("Nonregular or oversized source"));
    }
    let mut b = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut b).map_err(fail)?;
    if b.len() as u64 > limit
        || b.len() as u64 != before.len()
        || !same(&before, &f.metadata().map_err(fail)?)
    {
        return Err(fail("Source changed during read"));
    }
    Ok(b)
}
pub fn source(path: &Path, limit: u64, executable: bool) -> Result<Vec<u8>> {
    path_ok(path)?;
    let path = if executable {
        path.canonicalize().map_err(fail)?
    } else {
        path.to_path_buf()
    };
    let parent = Dir::absolute(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
        false,
        false,
    )?;
    let f = parent.open(
        path.file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| fail("Missing source filename"))?,
        libc::O_RDONLY,
        0,
    )?;
    let m = f.metadata().map_err(fail)?;
    if !executable && m.nlink() != 1 {
        return Err(fail("Source hardlinks are not supported"));
    }
    if executable && m.mode() & 0o111 == 0 {
        return Err(fail("Source binary is not executable"));
    }
    read_stable(f, limit)
}
pub fn random_id() -> Result<String> {
    let mut b = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(fail)?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
