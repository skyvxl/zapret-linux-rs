use crate::error::{AppError, Result};
use serde_json::{Value, json};
use std::{fs, io};

fn fail(error: impl std::fmt::Display) -> AppError {
    AppError::new(
        "namespace",
        format!("Не удалось создать изолированную сеть; nft не запускался: {error}"),
    )
}

fn identity(kind: &str) -> Result<String> {
    fs::read_link(format!("/proc/self/ns/{kind}"))
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(fail)
}

pub fn enter() -> Result<Value> {
    // SAFETY: identity syscalls take no pointers and cannot fail.
    let (uid, gid, euid) = unsafe { (libc::getuid(), libc::getgid(), libc::geteuid()) };
    if uid == 0 || euid != uid {
        return Err(AppError::new(
            "permissions",
            "Запускайте изолированную проверку обычным пользователем, без sudo",
        ));
    }
    let parent_net = identity("net")?;
    let parent_user = identity("user")?;
    // SAFETY: scalar flags only. Both namespaces must be created before any nft
    // subprocess; failure is terminal, never a fallback to the caller's network.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return Err(fail(io::Error::last_os_error()));
    }
    let net = identity("net")?;
    let user = identity("user")?;
    if parent_net == net || parent_user == user {
        return Err(fail("Идентификаторы namespaces не изменились"));
    }
    fs::write("/proc/self/setgroups", "deny").map_err(fail)?;
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")).map_err(fail)?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")).map_err(fail)?;
    // SAFETY: scalar Linux prctl arguments; prevents privilege gains on exec.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(fail(io::Error::last_os_error()));
    }
    Ok(json!({"parent_net": parent_net, "net": net, "parent_user": parent_user, "user": user}))
}

pub fn loopback_up() -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // Called only after enter() succeeds, so this ioctl affects the new network.
    // SAFETY: socket returns an owned fd; ifreq is zeroed and contains 'lo\0'.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        let socket = OwnedFd::from_raw_fd(fd);
        let mut request: libc::ifreq = std::mem::zeroed();
        request.ifr_name[0] = b'l' as libc::c_char;
        request.ifr_name[1] = b'o' as libc::c_char;
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) < 0 {
            return Err(fail(io::Error::last_os_error()));
        }
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(socket.as_raw_fd(), libc::SIOCSIFFLAGS, &request) < 0 {
            return Err(fail(io::Error::last_os_error()));
        }
    }
    Ok(())
}
