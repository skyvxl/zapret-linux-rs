use crate::{
    app_paths::{self, AppPaths},
    app_setup,
    config::Config,
    error::{AppError, Result},
    service_fs::{self, digest},
    ui_model::PreparedInputs,
};
use serde_json::{Value, json};
use std::path::Path;
pub struct Draft {
    pub config: Config,
    pub baseline_sha256: Option<String>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Terminal,
    Background,
}
impl RunMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Background => "background",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Terminal => "В этом терминале",
            Self::Background => "В фоне",
        }
    }
}
fn fail(s: impl ToString) -> AppError {
    AppError::new("ui_store", s.to_string())
}
fn read(parent: &Path, name: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(parent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(fail(e)),
        Ok(_) => (),
    }
    let dir = app_paths::private_existing(parent)?;
    if !dir.exists(name)? {
        return Ok(None);
    }
    dir.read(name, 0o600, limit).map(Some)
}
fn atomic(parent: &Path, name: &str, bytes: &[u8], limit: u64) -> Result<()> {
    if bytes.len() as u64 > limit {
        return Err(fail("Результат слишком большой; прежний файл сохранён"));
    }
    read(parent, name, limit)?;
    let dir = app_paths::private_existing(parent)?;
    let temp = format!(".ui-{}.tmp", service_fs::random_id()?);
    dir.write(&temp, bytes, 0o600)?;
    app_paths::rename_entry(&dir, &temp, name, true)
}
pub fn load_draft(paths: &AppPaths) -> Result<Draft> {
    let bytes = read(&paths.config_dir, "config.env", 65536)?;
    let config = match &bytes {
        Some(b) => Config::parse(std::str::from_utf8(b).map_err(fail)?)?,
        None => AppPaths::defaults(),
    };
    Ok(Draft {
        config,
        baseline_sha256: bytes.as_ref().map(|b| digest(b)),
    })
}
pub fn save_draft(paths: &AppPaths, draft: &Draft) -> Result<Config> {
    paths.ensure_private_dirs()?;
    let _lock = app_setup::lock(paths)?;
    if load_draft(paths)?.baseline_sha256 != draft.baseline_sha256 {
        return Err(AppError::new(
            "config_changed",
            "Настройки изменены в другом окне. Откройте форму заново",
        ));
    }
    let mut active = paths.clone();
    active.bundle_dir = paths.active_bundle()?;
    if std::fs::symlink_metadata(&active.bundle_dir).is_ok() {
        let bundle = app_setup::validate_bundle(&active)?;
        app_setup::validate_config(&draft.config, &bundle)?;
    }
    app_paths::write_config(
        &app_paths::private_existing(&paths.config_dir)?,
        app_paths::config_text(&draft.config)?.as_bytes(),
        true,
    )?;
    Ok(draft.config.clone())
}
pub fn load_mode(paths: &AppPaths) -> Result<Option<RunMode>> {
    let Some(bytes) = read(&paths.config_dir, "ui.json", 65536)? else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&bytes).map_err(fail)?;
    if v["schema"] != 1 {
        return Err(fail("Неизвестный формат настроек меню"));
    }
    match v["run_mode"].as_str() {
        Some("terminal") => Ok(Some(RunMode::Terminal)),
        Some("background") => Ok(Some(RunMode::Background)),
        _ => Err(fail("Неизвестный режим запуска")),
    }
}
pub fn save_mode(paths: &AppPaths, mode: RunMode) -> Result<()> {
    paths.ensure_private_dirs()?;
    let _lock = app_setup::lock(paths)?;
    load_mode(paths)?;
    atomic(
        &paths.config_dir,
        "ui.json",
        &serde_json::to_vec(&json!({"schema":1,"run_mode":mode.name()})).map_err(fail)?,
        65536,
    )
}
pub fn prepare_inputs(paths: &AppPaths, config: &Config) -> Result<PreparedInputs> {
    paths.ensure_private_dirs()?;
    let _lock = app_setup::lock(paths)?;
    let mut active = paths.clone();
    active.bundle_dir = paths.active_bundle()?;
    let bundle = app_setup::validate_bundle(&active)?;
    app_setup::validate_config(config, &bundle)?;
    let name = format!("inputs-{}", service_fs::random_id()?);
    let dir = app_paths::private_existing(&paths.cache_dir)?.mkdir(&name, 0o700)?;
    let bytes = app_paths::config_text(config)?.into_bytes();
    dir.write("config.env", &bytes, 0o600)?;
    Ok(PreparedInputs {
        config: paths.cache_dir.join(name).join("config.env"),
        bundle: bundle.root,
        config_sha256: digest(&bytes),
        bundle_sha256: digest(&bundle.manifest_bytes),
    })
}
pub fn remove_inputs(paths: &AppPaths, inputs: &PreparedInputs) -> Result<()> {
    let p = inputs
        .config
        .parent()
        .ok_or_else(|| fail("Некорректный путь временных настроек"))?;
    let name = p
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| fail("Некорректный путь"))?;
    if p.parent() != Some(paths.cache_dir.as_path())
        || !name
            .strip_prefix("inputs-")
            .is_some_and(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(fail("Чужие временные настройки"));
    }
    let d = app_paths::private_existing(p)?;
    if d.names()? != ["config.env"] {
        return Err(fail("Изменились временные настройки"));
    }
    if digest(&d.read("config.env", 0o600, 65536)?) != inputs.config_sha256 {
        return Err(fail("Изменились временные настройки"));
    }
    d.unlink("config.env", false)?;
    app_paths::private_existing(&paths.cache_dir)?.unlink(name, true)
}
pub struct DiagnosisRecord {
    pub fingerprint: String,
    pub report: Value,
    pub cleanup_confirmed: bool,
    pub restoration_confirmed: bool,
}
pub fn fingerprint(config: &Config, manifest: &[u8], targets: &Value) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({"schema":1,"manifest":digest(manifest),"interface":config.interface,"backend":config.backend.name(),"tcp":config.gamefiltertcp,"udp":config.gamefilterudp,"targets":targets})).map_err(fail)?))
}
pub fn save_diagnosis(paths: &AppPaths, r: &DiagnosisRecord) -> Result<()> {
    paths.ensure_private_dirs()?;
    let _lock = app_setup::lock(paths)?;
    atomic(&paths.cache_dir,"last-diagnosis.json",&serde_json::to_vec(&json!({"schema":1,"fingerprint":r.fingerprint,"report":r.report,"cleanup_confirmed":r.cleanup_confirmed,"restoration_confirmed":r.restoration_confirmed})).map_err(fail)?,8*1024*1024)
}
pub fn load_diagnosis(paths: &AppPaths) -> Result<Option<DiagnosisRecord>> {
    let Some(bytes) = read(&paths.cache_dir, "last-diagnosis.json", 8 * 1024 * 1024)? else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&bytes).map_err(fail)?;
    if v["schema"] != 1
        || v["fingerprint"]
            .as_str()
            .is_none_or(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        || !v["report"].is_object()
        || !v["cleanup_confirmed"].is_boolean()
        || !v["restoration_confirmed"].is_boolean()
    {
        return Err(fail("Повреждён сохранённый отчёт; файл сохранён"));
    }
    Ok(Some(DiagnosisRecord {
        fingerprint: v["fingerprint"].as_str().unwrap().into(),
        report: v["report"].clone(),
        cleanup_confirmed: v["cleanup_confirmed"].as_bool().unwrap(),
        restoration_confirmed: v["restoration_confirmed"].as_bool().unwrap(),
    }))
}
