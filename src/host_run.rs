use crate::{
    error::{AppError, Result},
    host, process,
};
use serde_json::{Value, json};
use std::{
    fs, io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            net::{SocketAddr, UnixListener},
            process::CommandExt,
        },
    },
    path::Path,
    process::Command,
    time::Duration,
};

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("preflight", message)
}

pub fn context() -> Result<Value> {
    // SAFETY: scalar identity and prctl calls; no privilege escalation.
    unsafe {
        if libc::getuid() != 0 || libc::geteuid() != 0 {
            return Err(AppError::new(
                "permissions",
                "Режим текущей сети требует UID=EUID=0; автоматического повышения прав нет",
            ));
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(AppError::new(
                "permissions",
                io::Error::last_os_error().to_string(),
            ));
        }
    }
    let namespace = |kind| {
        fs::read_link(format!("/proc/self/ns/{kind}"))
            .map(|s| s.to_string_lossy().into_owned())
            .map_err(|e| fail(e.to_string()))
    };
    Ok(json!({"net":namespace("net")?,"user":namespace("user")?}))
}

pub fn lock_network() -> Result<UnixListener> {
    let address = SocketAddr::from_abstract_name(b"zapret-linux-rs.host.v1")
        .map_err(|e| fail(e.to_string()))?;
    UnixListener::bind_addr(&address).map_err(|e| {
        AppError::new(
            if e.kind() == io::ErrorKind::AddrInUse {
                "locked"
            } else {
                "preflight"
            },
            format!("Не удалось получить блокировку текущей сети: {e}"),
        )
    })
}

pub fn check_interface(name: &str) -> Result<()> {
    if name == "any" {
        return Ok(());
    }
    let name = std::ffi::CString::new(name).map_err(|_| fail("Некорректное имя интерфейса"))?;
    // SAFETY: a live, NUL-terminated interface name; this call only reads.
    if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
        return Err(fail(format!(
            "Нет указанного интерфейса в текущей сети: {}",
            name.to_string_lossy()
        )));
    }
    Ok(())
}

pub fn preflight(nft: &Path, ipv4: &Path, ipv6: &Path, timeout: Duration) -> Result<()> {
    let report = host::inspect_nft(nft, timeout);
    let mut conflicts = Vec::new();
    if let Some(tables) = report["known_tables"].as_array() {
        for table in tables.iter().take(4) {
            conflicts.push(format!(
                "таблица {} {}",
                host::diagnostic_label(table["family"].as_str().unwrap_or("?")),
                host::diagnostic_label(table["name"].as_str().unwrap_or("?"))
            ));
        }
    }
    if report["queues"].as_array().is_some_and(|v| !v.is_empty()) {
        conflicts.push("правила NFQUEUE".into());
    }
    // Positive evidence is actionable even when some unrelated rules are unknown.
    if !conflicts.is_empty() {
        return Err(fail(format!(
            "Конфликт в текущей сети: {}. Остановите предыдущий zapret через его собственное меню и повторите запуск; если правила NFQUEUE принадлежат другой программе, сначала устраните конфликт в ней.",
            conflicts.join(", ")
        )));
    }
    if report["complete"] != true {
        let details = report["inspection_details"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .take(8)
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                report["diagnostic"]
                    .as_str()
                    .unwrap_or("причина неизвестна")
                    .to_owned()
            });
        return Err(fail(format!(
            "Не удалось полностью проверить nft ruleset: {}. {}",
            report["status"].as_str().unwrap_or("unknown"),
            details
        )));
    }
    for (binary, applet) in [
        (ipv4, "iptables-legacy-save"),
        (ipv6, "ip6tables-legacy-save"),
    ] {
        let mut command = Command::new(binary);
        // The resolved executable may be xtables-legacy-multi. Its argv[0]
        // selects the family and the read-only save operation.
        command
            .arg0(applet)
            .current_dir("/")
            .env_clear()
            .env("LC_ALL", "C");
        let output = process::capture(command, &[], timeout)
            .map_err(|e| fail(format!("{applet}: {}", e.message)))?;
        if !output.status.success() || output.truncated || !output.stdout_valid_utf8 {
            return Err(fail(format!("Не удалось достоверно прочитать {applet}")));
        }
        if output.stdout.lines().any(|line| {
            let s = line.trim();
            !s.is_empty() && !s.starts_with('#')
        }) {
            return Err(fail(format!(
                "{applet}: непустые legacy-таблицы пока не поддержаны"
            )));
        }
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn restrict_child_ids() -> io::Result<()> {
    // SAFETY: called before exec; stack-only capget/capset ABI v3 buffers and
    // scalar prctl calls. Managed registers PDEATHSIG after this hook.
    unsafe {
        for cap in [6, 7] {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) == -1
                || libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_LOWER, cap, 0, 0) == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        let header = CapHeader {
            version: 0x20080522,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
        let mask = !((1 << 6) | (1 << 7));
        data[0].effective &= mask;
        data[0].permitted &= mask;
        data[0].inheritable &= mask;
        if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
