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
            "Запускайте firewall verify обычным пользователем, без sudo",
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
