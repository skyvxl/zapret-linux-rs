//! Read-only observations. None of these paths create locks or authorize actions.
use crate::{
    config::Config,
    error::{AppError, Result},
    service_control::{Manager, Status},
    service_fs::{self, Dir},
    service_unit,
    ui_model::{InstalledConfig, RuntimeState, ServiceView},
};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

fn read_public(dir: &Dir, name: &str, limit: u64) -> Result<Vec<u8>> {
    let file = dir.open(name, libc::O_RDONLY, 0)?;
    let m = file.metadata().map_err(service_fs::fail)?;
    if !m.is_file() || m.uid() != 0 || m.gid() != 0 || m.nlink() != 1 || m.mode() & 0o7777 != 0o644
    {
        return Err(service_fs::fail(
            "Не удалось проверить владельца данных службы",
        ));
    }
    service_fs::read_stable(file, limit)
}
fn installed() -> Result<Option<InstalledConfig>> {
    let root = Path::new("/opt/zapret-linux-rs");
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(service_fs::fail(e)),
        Ok(_) => (),
    }
    let dir = Dir::absolute(root, true, false)?;
    let manifest: Value =
        serde_json::from_slice(&read_public(&dir, "manifest.json", 8 * 1024 * 1024)?)
            .map_err(service_fs::fail)?;
    let text = read_public(&dir, "config.env", 65536)?;
    let mut config = Config::parse(std::str::from_utf8(&text).map_err(service_fs::fail)?)?;
    let id = manifest["installation_id"].as_str().unwrap_or("");
    let strategy = manifest["sources"]["strategy_name"].as_str().unwrap_or("");
    if manifest["schema"] != 1
        || manifest["product"] != "zapret-linux-rs"
        || id.len() != 32
        || !id.bytes().all(|b| b.is_ascii_hexdigit())
        || !crate::app_flowseal::strategy_name(strategy)
        || manifest["inventory"]["config.env"]["sha256"] != service_fs::digest(&text)
        || manifest["config"] != config.json()
    {
        return Err(service_fs::fail(
            "Данные установленной службы не прошли проверку",
        ));
    }
    config.strategy = strategy.into();
    Ok(Some(InstalledConfig {
        installation_id: id.into(),
        strategy: strategy.into(),
        config,
        inventory: manifest["inventory"].clone(),
    }))
}

pub fn from_observation(
    manager: Result<Status>,
    installed: Result<Option<InstalledConfig>>,
) -> ServiceView {
    let mut view = ServiceView {
        state: RuntimeState::Unknown,
        enabled: None,
        installed: None,
        running_strategy: None,
        detail: None,
    };
    match installed {
        Ok(i) => view.installed = i,
        Err(e) => view.detail = Some(e.message),
    }
    let s = match manager {
        Ok(s) => s,
        Err(e) => {
            view.detail = Some(e.message);
            return view;
        }
    };
    if s.get("LoadState") == "not-found" && s.absent().is_ok() {
        view.state = if view.installed.is_none() && view.detail.is_none() {
            RuntimeState::Absent
        } else {
            RuntimeState::Unknown
        };
        return view;
    }
    if s.get("LoadState") != "loaded"
        || s.get("FragmentPath") != service_unit::UNIT
        || !s.get("DropInPaths").is_empty()
    {
        view.detail =
            Some("Служба изменена извне или недоступна; откройте подробную диагностику".into());
        return view;
    }
    view.enabled = match s.get("UnitFileState") {
        "enabled" => Some(true),
        "disabled" => Some(false),
        _ => None,
    };
    view.state = match (s.get("ActiveState"), s.get("SubState")) {
        ("active", "running") if s.get("MainPID").parse::<u32>().is_ok_and(|p| p > 0) => {
            RuntimeState::Running
        }
        ("inactive", _) if s.idle() => RuntimeState::Stopped,
        ("activating", _) => RuntimeState::Starting,
        ("deactivating", _) => RuntimeState::Stopping,
        ("failed", _) => RuntimeState::Failed,
        _ => RuntimeState::Unknown,
    };
    view
}

pub fn observe() -> ServiceView {
    match fs::symlink_metadata("/var/lib/zapret-linux-rs-operation.pending") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => {
            let checked = Dir::absolute(Path::new("/var/lib"), true, false)
                .and_then(|d| read_public(&d, "zapret-linux-rs-operation.pending", 128));
            let valid = checked.is_ok_and(|b| b == b"zapret-linux-rs operation pending v1\n");
            return ServiceView {
                state: if valid {
                    RuntimeState::RecoveryRequired
                } else {
                    RuntimeState::Unknown
                },
                enabled: None,
                installed: installed().ok().flatten(),
                running_strategy: None,
                detail: Some("Проверьте незавершённую операцию: service recover".into()),
            };
        }
    }
    let m = match Manager::new() {
        Ok(m) => m,
        Err(e) => {
            let mut v = from_observation(Err(AppError::new("service", e.message)), installed());
            if v.installed.is_none() {
                v.state = RuntimeState::Unavailable;
            }
            return v;
        }
    };
    let status = m.show();
    let pid = status
        .as_ref()
        .ok()
        .and_then(|s| s.get("MainPID").parse::<u32>().ok());
    let mut view = from_observation(status, installed());
    if view.state == RuntimeState::Running
        && let (Some(pid), Some(i)) = (pid, &view.installed)
    {
        let live = fs::metadata(format!("/proc/{pid}/exe"));
        let saved = fs::metadata("/opt/zapret-linux-rs/bin/zapret-linux-rs");
        if let (Ok(a), Ok(b)) = (live, saved)
            && a.dev() == b.dev()
            && a.ino() == b.ino()
        {
            view.running_strategy = Some(i.strategy.clone());
        }
    }
    view
}
