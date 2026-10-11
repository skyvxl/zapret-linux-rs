//! User-editable lists and the ipset mode, kept in the private config
//! directory and overlaid onto the verified bundle at run time.
use crate::{
    app_paths::{self, AppPaths},
    app_setup,
    error::{AppError, Result},
    service_fs::digest,
    ui_store,
};
use serde_json::{Value, json};
use std::{path::Path, process::Command};

/// The three user list files the strategies reference (Flowseal's
/// `load_user_lists`); empty means "not restricted".
pub const USER_LISTS: &[&str] = &[
    "list-general-user.txt",
    "list-exclude-user.txt",
    "ipset-exclude-user.txt",
];
pub const IPSET_CUSTOM: &str = "ipset-all.txt.custom";
pub const IPSET_ALL: &str = "ipset-all.txt";
pub const IPSET_BACKUP: &str = "ipset-all.txt.backup";
/// The placeholder that disables the ipset inclusion (TEST-NET-3).
pub const IPSET_STUB: &str = "203.0.113.113/32";
pub const LIMIT: u64 = 1024 * 1024;

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("lists", message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpsetMode {
    None,
    Any,
    Loaded,
    Custom,
}

impl IpsetMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Any => "any",
            Self::Loaded => "loaded",
            Self::Custom => "custom",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "Не обходить IP-адреса (режим None)",
            Self::Any => "Обходить любые IP-адреса (режим Any)",
            Self::Loaded => "Загруженный список ipset-all (режим Loaded)",
            Self::Custom => "Свой список ipset-all (режим Custom)",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::None => "ipset-all.txt содержит заглушку 203.0.113.113/32",
            Self::Any => "ipset-all.txt пустой — подходит любой адрес",
            Self::Loaded => "ipset-all.txt восстанавливается из .backup архива",
            Self::Custom => "ipset-all.txt берётся из вашего файла ipset-all.txt.custom",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "any" => Some(Self::Any),
            "loaded" => Some(Self::Loaded),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

pub fn dir(paths: &AppPaths) -> std::path::PathBuf {
    paths.config_dir.join("lists")
}

pub fn user_list_path(paths: &AppPaths, name: &str) -> Result<std::path::PathBuf> {
    if !USER_LISTS.contains(&name) && name != IPSET_CUSTOM {
        return Err(fail(format!("Неизвестный список: {name}")));
    }
    Ok(dir(paths).join(name))
}

/// Read a user list; missing files read as empty.
pub fn read(paths: &AppPaths, name: &str) -> Result<Vec<u8>> {
    let path = user_list_path(paths, name)?;
    match std::fs::metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => return Err(fail(e.to_string())),
        Ok(_) => read_limited(&path),
    }
}

pub fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).map_err(|e| fail(format!("{}: {e}", path.display())))?;
    if bytes.len() as u64 > LIMIT {
        return Err(fail(format!(
            "Список {} превышает {} КиБ",
            path.display(),
            LIMIT / 1024
        )));
    }
    Ok(bytes)
}

/// Atomically replace a user list.
pub fn write(paths: &AppPaths, name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > LIMIT {
        return Err(fail(format!(
            "Список {name} превышает {} КиБ",
            LIMIT / 1024
        )));
    }
    paths.ensure_private_dirs()?;
    let parent = paths.ensure_private_child(&paths.config_dir, "lists")?;
    let temporary = format!(
        ".list-{}",
        crate::service_fs::random_id().map_err(|e| fail(e.message))?
    );
    {
        let dir = app_paths::private_existing(&parent)?;
        dir.write(&temporary, bytes, 0o600)?;
    }
    app_paths::rename_entry(
        &app_paths::private_existing(&parent)?,
        &temporary,
        name,
        true,
    )?;
    Ok(())
}

pub fn load_ipset_mode(paths: &AppPaths) -> Result<IpsetMode> {
    let value = ui_store::load_ui(paths)?;
    match value["ipset_mode"].as_str() {
        Some(name) => {
            IpsetMode::parse(name).ok_or_else(|| fail(format!("Неизвестный режим ipset: {name}")))
        }
        None => Ok(IpsetMode::None),
    }
}

pub fn save_ipset_mode(paths: &AppPaths, mode: IpsetMode) -> Result<()> {
    paths.ensure_private_dirs()?;
    let _lock = app_setup::lock(paths)?;
    let mut value = ui_store::load_ui(paths)?;
    value["ipset_mode"] = json!(mode.name());
    ui_store::save_ui_locked(paths, &value)
}

/// Stable digest of the staged lists, so a run can be rejected when the
/// lists or the mode changed after confirmation. `stage` is the inputs
/// directory holding `lists-*` files written by `prepare_inputs`.
pub fn staged_fingerprint(stage: &Path) -> Result<String> {
    let mut material = String::new();
    for name in [USER_LISTS, &[IPSET_CUSTOM]].concat() {
        let bytes = staged_read(stage, &format!("lists-{name}"));
        material.push_str(&format!("{name}={}\n", digest(&bytes)));
    }
    let mode = staged_mode(stage)?;
    material.push_str(&format!("ipset={}\n", mode.name()));
    Ok(digest(material.as_bytes()))
}

fn staged_read(stage: &Path, name: &str) -> Vec<u8> {
    crate::service_fs::source(&stage.join(name), LIMIT, false).unwrap_or_default()
}

fn staged_mode(stage: &Path) -> Result<IpsetMode> {
    let path = stage.join("ipset-mode");
    if std::fs::metadata(&path).is_err() {
        return Ok(IpsetMode::None);
    }
    let bytes = crate::service_fs::source(&path, 64, false)?;
    let name = String::from_utf8_lossy(&bytes).trim().to_string();
    IpsetMode::parse(&name).ok_or_else(|| fail(format!("Неизвестный режим ipset: {name}")))
}

/// Apply the staged user lists and the ipset mode onto a freshly copied
/// bundle (`root`), updating the copied manifest in place. `stage` is the
/// inputs directory written by `prepare_inputs`.
pub fn overlay_from_stage(stage: &Path, root: &Path) -> Result<()> {
    let lists_dir = root.join("assets/lists");
    if !lists_dir.is_dir() {
        return Err(fail("Bundle не содержит assets/lists"));
    }
    let manifest_bytes = std::fs::read(root.join("manifest.json"))
        .map_err(|e| fail(format!("manifest.json: {e}")))?;
    let mut values: Value =
        serde_json::from_slice(&manifest_bytes).map_err(|e| fail(format!("manifest: {e}")))?;
    let files = values["files"]
        .as_array_mut()
        .ok_or_else(|| fail("Manifest без files"))?;
    let mode = staged_mode(stage)?;
    let mut replace = |name: &str, bytes: Vec<u8>| -> Result<()> {
        if bytes.len() as u64 > LIMIT {
            return Err(fail(format!(
                "Список {name} превышает {} КиБ",
                LIMIT / 1024
            )));
        }
        std::fs::write(lists_dir.join(name), &bytes).map_err(|e| fail(e.to_string()))?;
        let entry = files
            .iter_mut()
            .find(|e| e["path"].as_str() == Some(&format!("assets/lists/{name}")))
            .ok_or_else(|| fail(format!("В bundle нет списка {name}")))?;
        entry["size"] = json!(bytes.len());
        entry["sha256"] = json!(digest(&bytes));
        Ok(())
    };
    for name in USER_LISTS {
        let bytes = staged_read(stage, &format!("lists-{name}"));
        replace(name, bytes)?;
    }
    let ipset = match mode {
        IpsetMode::None => format!("{IPSET_STUB}\n").into_bytes(),
        IpsetMode::Any => Vec::new(),
        IpsetMode::Loaded => std::fs::read(lists_dir.join(IPSET_BACKUP)).unwrap_or_default(),
        IpsetMode::Custom => staged_read(stage, &format!("lists-{IPSET_CUSTOM}")),
    };
    replace(IPSET_ALL, ipset)?;
    values["ipset_mode"] = json!(mode.name());
    let bytes = serde_json::to_vec_pretty(&values).map_err(|e| fail(e.to_string()))?;
    std::fs::write(root.join("manifest.json"), &bytes)
        .map_err(|e| fail(format!("manifest.json: {e}")))?;
    Ok(())
}

fn editor() -> Result<Command> {
    let name = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .filter(|s| !s.is_empty())
        .or_else(|| {
            ["nano", "vim", "vi"]
                .iter()
                .find_map(|c| crate::app_archive::find_executable(c).map(|p| p.into_os_string()))
        })
        .ok_or_else(|| fail("Не найден текстовый редактор. Установите nano или задайте EDITOR."))?;
    Ok(Command::new(name))
}

/// Open a user list in `$VISUAL`/`$EDITOR` (fallback nano/vi) after creating
/// it if missing. The caller is responsible for terminal suspend/resume.
pub fn edit(paths: &AppPaths, name: &str) -> Result<()> {
    let path = {
        let target = user_list_path(paths, name)?;
        if std::fs::metadata(&target).is_err() {
            write(paths, name, b"")?;
        }
        target
    };
    println!(
        "\nФайл: {}\nПо окончании закройте редактор, чтобы вернуться в меню.",
        path.display()
    );
    let mut command = editor()?;
    command.arg(&path);
    crate::ui_terminal::supervise(&mut command)?;
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > LIMIT {
        return Err(fail(format!(
            "Файл {} слишком большой; измените его вручную до {} КиБ",
            path.display(),
            LIMIT / 1024
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipset_mode_roundtrip() {
        assert_eq!(IpsetMode::parse("none"), Some(IpsetMode::None));
        assert_eq!(IpsetMode::parse("any"), Some(IpsetMode::Any));
        assert_eq!(IpsetMode::parse("loaded"), Some(IpsetMode::Loaded));
        assert_eq!(IpsetMode::parse("custom"), Some(IpsetMode::Custom));
        assert_eq!(IpsetMode::parse("bogus"), None);
        for mode in [
            IpsetMode::None,
            IpsetMode::Any,
            IpsetMode::Loaded,
            IpsetMode::Custom,
        ] {
            assert_eq!(IpsetMode::parse(mode.name()), Some(mode));
        }
    }

    #[test]
    fn overlay_replaces_user_lists_and_ipset() {
        let base = std::env::temp_dir().join(format!("zapret-lists-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let stage = base.join("stage");
        let root = base.join("bundle");
        for dir in [&base, &stage, &root, &root.join("assets")] {
            std::fs::create_dir_all(dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        std::fs::create_dir_all(stage.join("bundle").join("assets").join("lists")).unwrap();
        std::fs::create_dir_all(root.join("assets").join("lists")).unwrap();
        let mut files =
            vec![json!({"path": "bin/nfqws", "size": 1, "sha256": digest(b"x"), "mode": 0o600})];
        for name in [USER_LISTS, &[IPSET_ALL, IPSET_BACKUP]].concat() {
            files.push(json!({"path": format!("assets/lists/{name}"), "size": 0, "sha256": digest(b""), "mode": 0o600}));
        }
        let manifest = serde_json::to_vec(&json!({"schema": 2, "files": files})).unwrap();
        std::fs::write(root.join("manifest.json"), &manifest).unwrap();
        std::fs::write(
            root.join("assets").join("lists").join(IPSET_BACKUP),
            "1.2.3.4/32\n",
        )
        .unwrap();
        let stage_files = [
            ("lists-list-general-user.txt", "a.example\nb.example\n"),
            ("lists-list-exclude-user.txt", "c.example\n"),
            ("lists-ipset-exclude-user.txt", "10.0.0.0/8\n"),
            ("lists-ipset-all.txt.custom", "5.6.7.8/32\n"),
            ("ipset-mode", "custom\n"),
        ];
        for (name, content) in stage_files {
            std::fs::write(stage.join(name), content).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(stage.join(name), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        overlay_from_stage(&stage, &root).unwrap();
        let text = std::fs::read_to_string(
            root.join("assets")
                .join("lists")
                .join("list-general-user.txt"),
        )
        .unwrap();
        assert_eq!(text, "a.example\nb.example\n");
        let ipset =
            std::fs::read_to_string(root.join("assets").join("lists").join(IPSET_ALL)).unwrap();
        assert_eq!(ipset, "5.6.7.8/32\n");
        let updated: Value =
            serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(updated["ipset_mode"], "custom");
        let entry = updated["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"] == "assets/lists/ipset-all.txt")
            .unwrap();
        assert_eq!(entry["sha256"], digest(b"5.6.7.8/32\n"));
        std::fs::write(stage.join("ipset-mode"), "none\n").unwrap();
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    stage.join("ipset-mode"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
        }
        overlay_from_stage(&stage, &root).unwrap();
        let ipset =
            std::fs::read_to_string(root.join("assets").join("lists").join(IPSET_ALL)).unwrap();
        assert_eq!(ipset.trim(), IPSET_STUB);
        std::fs::write(stage.join("ipset-mode"), "loaded\n").unwrap();
        overlay_from_stage(&stage, &root).unwrap();
        let ipset =
            std::fs::read_to_string(root.join("assets").join("lists").join(IPSET_ALL)).unwrap();
        assert_eq!(ipset, "1.2.3.4/32\n");
        let _ = std::fs::remove_dir_all(&base);
    }
}
