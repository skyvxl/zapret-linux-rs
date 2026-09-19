use crate::{
    app_archive::{self, NFQWS_SHA256},
    app_flowseal::{self, GENERATED_LISTS},
    app_paths::AppPaths,
    config::Config,
    error::{AppError, Result},
    process as child_process,
    service_fs::{self, Dir},
    validation,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const MANIFEST: &str = "manifest.json";
fn fail(message: impl Into<String>) -> AppError {
    AppError::new("bundle", message)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn string_path(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| fail(format!("Путь не является UTF-8: {}", path.display())))
}

pub(crate) struct SetupLock(File);

impl Drop for SetupLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub(crate) fn lock(paths: &AppPaths) -> Result<SetupLock> {
    let directory =
        Dir::absolute(&paths.cache_dir, false, false).map_err(|error| fail(error.message))?;
    if !directory
        .exists("setup.lock")
        .map_err(|error| fail(error.message))?
    {
        match directory.write("setup.lock", b"", 0o600) {
            Ok(()) => {}
            Err(_)
                if directory
                    .exists("setup.lock")
                    .map_err(|error| fail(error.message))? => {}
            Err(error) => return Err(fail(error.message)),
        }
    }
    let file = directory
        .open("setup.lock", libc::O_RDWR, 0)
        .map_err(|error| fail(error.message))?;
    service_fs::trusted_file(&file, 0o600).map_err(|error| fail(error.message))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(fail(std::io::Error::last_os_error().to_string()));
    }
    Ok(SetupLock(file))
}

#[derive(Debug, Clone)]
pub struct Bundle {
    pub root: PathBuf,
    pub nfqws: PathBuf,
    pub strategies: PathBuf,
    pub assets: PathBuf,
    pub manifest: PathBuf,
    pub strategy_count: usize,
    pub strategy_names: Vec<String>,
    pub files: Vec<String>,
    pub manifest_bytes: Vec<u8>,
    pub reused: bool,
    pub validation: Value,
}

impl Bundle {
    fn at(root: PathBuf) -> Self {
        Self {
            nfqws: root.join("bin/nfqws"),
            strategies: root.join("strategies"),
            assets: root.join("assets"),
            manifest: root.join(MANIFEST),
            root,
            strategy_count: 0,
            strategy_names: Vec::new(),
            files: Vec::new(),
            manifest_bytes: Vec::new(),
            reused: false,
            validation: json!({"status": "not_run"}),
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "root": self.root,
            "nfqws": self.nfqws,
            "strategies": self.strategies,
            "assets": self.assets,
            "manifest": self.manifest,
            "strategy_count": self.strategy_count,
            "strategy_names": self.strategy_names,
            "reused": self.reused,
            "validation": self.validation,
        })
    }
}

/// Parse once at the privilege boundary; these bounded paths are copy authority, never deletion authority.
pub fn checked_manifest(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() > 1024 * 1024 {
        return Err(fail("Manifest слишком большой"));
    }
    let manifest: Value = serde_json::from_slice(bytes).map_err(|e| fail(e.to_string()))?;
    if !matches!(manifest["schema"].as_u64(), Some(1 | 2))
        || manifest["nfqws_archive_sha256"] != NFQWS_SHA256
        || manifest["engine_arch"] != std::env::consts::ARCH
        || manifest["engine_sha256"] != app_archive::engine_spec()?.sha256
    {
        return Err(fail("Manifest имеет неизвестную схему или другой nfqws"));
    }
    let entries = manifest["files"]
        .as_array()
        .ok_or_else(|| fail("Manifest не содержит файлы"))?;
    if entries.len() > app_flowseal::ENTRY_LIMIT {
        return Err(fail("Слишком много файлов manifest"));
    }
    let mut files = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    let mut total = 0;
    for entry in entries {
        let path = entry["path"]
            .as_str()
            .ok_or_else(|| fail("Некорректный путь manifest"))?;
        let limit =
            app_flowseal::file_limit(path).ok_or_else(|| fail("Недопустимый путь manifest"))?;
        let size = entry["size"]
            .as_u64()
            .filter(|n| *n <= limit)
            .ok_or_else(|| fail("Некорректный размер manifest"))?;
        if GENERATED_LISTS
            .iter()
            .any(|name| path == format!("assets/lists/{name}"))
            && (size != 0 || entry["sha256"] != digest(b""))
        {
            return Err(fail(
                "Локальные пользовательские списки должны оставаться пустыми",
            ));
        }
        total += size;
        if total > app_flowseal::EXPANDED_LIMIT
            || !files.insert(path.to_string())
            || !aliases.insert(path.to_lowercase())
        {
            return Err(fail("Повторный путь или превышение лимита manifest"));
        }
        if entry["mode"].as_u64() != Some(if path == "bin/nfqws" { 0o700 } else { 0o600 })
            || !entry["sha256"]
                .as_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(fail("Некорректный режим или SHA256 manifest"));
        }
    }
    if !files.contains("bin/nfqws")
        || !files.iter().any(|s| s.starts_with("strategies/"))
        || GENERATED_LISTS
            .iter()
            .any(|s| !files.contains(&format!("assets/lists/{s}")))
    {
        return Err(fail("Manifest не содержит обязательные файлы"));
    }
    Ok(files.into_iter().collect())
}

fn inspect_tree(root: &Path) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    fn recurse(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
        directories: &mut BTreeSet<String>,
    ) -> Result<()> {
        for item in fs::read_dir(directory).map_err(|error| fail(error.to_string()))? {
            let path = item.map_err(|error| fail(error.to_string()))?.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| fail(error.to_string()))?;
            let relative = path
                .strip_prefix(root)
                .map_err(|error| fail(error.to_string()))?
                .to_str()
                .ok_or_else(|| fail("Bundle содержит имя не в UTF-8"))?
                .to_string();
            if metadata.file_type().is_symlink() {
                return Err(fail(format!(
                    "Bundle содержит символьную ссылку: {relative}"
                )));
            }
            if metadata.is_dir() {
                if metadata.uid() != service_fs::uid()
                    || metadata.gid() != service_fs::gid()
                    || metadata.mode() & 0o7777 != 0o700
                {
                    return Err(fail(format!(
                        "Некорректный владелец или режим каталога: {relative}"
                    )));
                }
                if !["bin", "strategies", "assets", "assets/bin", "assets/lists"]
                    .contains(&relative.as_str())
                {
                    return Err(fail("Bundle содержит неизвестный каталог"));
                }
                directories.insert(relative);
                recurse(root, &path, files, directories)?;
            } else if metadata.is_file() {
                if files.len() > app_flowseal::ENTRY_LIMIT {
                    return Err(fail("Bundle содержит слишком много файлов"));
                }
                files.insert(relative);
            } else {
                return Err(fail("Bundle содержит не обычный файл или каталог"));
            }
        }
        Ok(())
    }
    let metadata = fs::symlink_metadata(root).map_err(|error| fail(error.to_string()))?;
    if !metadata.is_dir()
        || metadata.uid() != service_fs::uid()
        || metadata.gid() != service_fs::gid()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(fail(
            "Bundle должен быть приватным каталогом 0700 текущего пользователя",
        ));
    }
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    recurse(root, root, &mut files, &mut directories)?;
    Ok((files, directories))
}

pub fn validate_bundle(paths: &AppPaths) -> Result<Bundle> {
    let root = &paths.bundle_dir;
    let directory = Dir::absolute(root, false, false)
        .map_err(|error| fail(format!("{}: {}", root.display(), error.message)))?;
    let manifest_bytes = directory
        .read(MANIFEST, 0o600, 1024 * 1024)
        .map_err(|error| fail(format!("manifest: {}", error.message)))?;
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).map_err(|error| fail(error.to_string()))?;
    let engine = app_archive::engine_spec()?;
    let expected: BTreeSet<_> = checked_manifest(&manifest_bytes)?.into_iter().collect();
    let entries = manifest["files"]
        .as_array()
        .ok_or_else(|| fail("Manifest без files"))?;
    let mut recorded = BTreeSet::new();
    for entry in entries {
        let relative = entry
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("Manifest содержит некорректный путь"))?;
        if !expected.contains(relative) || !recorded.insert(relative.to_string()) {
            return Err(fail(format!(
                "Неожиданный или повторный файл в manifest: {relative}"
            )));
        }
        let mode = if relative == "bin/nfqws" {
            0o700
        } else {
            0o600
        };
        if entry.get("mode").and_then(Value::as_u64) != Some(mode) {
            return Err(fail(format!(
                "Manifest содержит неверный режим: {relative}"
            )));
        }
        let path = root.join(relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| fail(format!("{relative}: {error}")))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.uid() != service_fs::uid()
            || metadata.gid() != service_fs::gid()
            || metadata.mode() & 0o7777 != mode as u32
        {
            return Err(fail(format!("Некорректный файл bundle: {relative}")));
        }
        let bytes = service_fs::source(&path, 2 * 1024 * 1024, relative == "bin/nfqws")
            .map_err(|error| fail(format!("{relative}: {}", error.message)))?;
        if entry.get("size").and_then(Value::as_u64) != Some(bytes.len() as u64)
            || entry.get("sha256").and_then(Value::as_str) != Some(digest(&bytes).as_str())
        {
            return Err(fail(format!("Файл bundle изменён: {relative}")));
        }
        if relative == "bin/nfqws"
            && (bytes.len() != engine.size || digest(&bytes) != engine.sha256)
        {
            return Err(fail(
                "nfqws в bundle не совпадает с закреплённым бинарным файлом",
            ));
        }
    }
    if recorded != expected {
        return Err(fail("Manifest не содержит полный набор файлов"));
    }
    let (actual_files, actual_directories) = inspect_tree(root)?;
    let mut expected_with_manifest = expected.clone();
    expected_with_manifest.insert(MANIFEST.to_string());
    let expected_directories = BTreeSet::from([
        "assets".to_string(),
        "assets/bin".to_string(),
        "assets/lists".to_string(),
        "bin".to_string(),
        "strategies".to_string(),
    ]);
    if actual_files != expected_with_manifest || actual_directories != expected_directories {
        return Err(fail("Bundle содержит неожиданные или отсутствующие пути"));
    }
    let mut bundle = Bundle::at(root.clone());
    bundle.files = expected.into_iter().collect();
    bundle.strategy_names = bundle
        .files
        .iter()
        .filter_map(|s| s.strip_prefix("strategies/").map(str::to_string))
        .collect();
    bundle.strategy_count = bundle.strategy_names.len();
    bundle.manifest_bytes = manifest_bytes;
    bundle.reused = true;
    Ok(bundle)
}

fn write_payload(stage: &Dir, payload: Vec<app_archive::PayloadFile>) -> Result<Vec<Value>> {
    let bin = stage
        .mkdir("bin", 0o700)
        .map_err(|error| fail(error.message))?;
    let strategies = stage
        .mkdir("strategies", 0o700)
        .map_err(|error| fail(error.message))?;
    let assets = stage
        .mkdir("assets", 0o700)
        .map_err(|error| fail(error.message))?;
    let asset_bin = assets
        .mkdir("bin", 0o700)
        .map_err(|error| fail(error.message))?;
    let lists = assets
        .mkdir("lists", 0o700)
        .map_err(|error| fail(error.message))?;
    let mut manifest = Vec::new();
    for file in payload {
        let relative = string_path(&file.relative)?.to_string();
        let name = file
            .relative
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| fail("Некорректное имя файла payload"))?;
        let directory = if relative == "bin/nfqws" {
            &bin
        } else if relative.starts_with("strategies/") {
            &strategies
        } else if relative.starts_with("assets/bin/") {
            &asset_bin
        } else if relative.starts_with("assets/lists/") {
            &lists
        } else {
            return Err(fail(format!("Неизвестный путь payload: {relative}")));
        };
        let mode = if file.executable { 0o700 } else { 0o600 };
        directory
            .write(name, &file.bytes, mode)
            .map_err(|error| fail(error.message))?;
        manifest.push(json!({
            "path": relative,
            "size": file.bytes.len(),
            "sha256": digest(&file.bytes),
            "mode": mode,
        }));
    }
    for name in GENERATED_LISTS {
        lists
            .write(name, b"", 0o600)
            .map_err(|error| fail(error.message))?;
        manifest.push(json!({
            "path": format!("assets/lists/{name}"),
            "size": 0,
            "sha256": digest(b""),
            "mode": 0o600,
        }));
    }
    manifest.sort_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap_or("")
            .cmp(right["path"].as_str().unwrap_or(""))
    });
    Ok(manifest)
}

pub fn validate_config(config: &Config, bundle: &Bundle) -> Result<Value> {
    if !bundle.strategy_names.contains(&config.strategy) {
        return Err(fail(format!(
            "Стратегия отсутствует в bundle: {}",
            config.strategy
        )));
    }
    let plan = crate::strategy::Plan::load(
        &bundle.strategies.join(&config.strategy),
        &bundle.assets,
        config.gamefiltertcp,
        config.gamefilterudp,
    )?;
    validation::validate_engine(&bundle.nfqws, &plan, Duration::from_secs(10))
}
fn dry_run(paths: &AppPaths, bundle: &Bundle) -> Result<Value> {
    validate_config(&paths.load_config()?, bundle)
}

fn build_bundle(paths: &AppPaths, archives: app_archive::Archives) -> Result<Bundle> {
    let data = Dir::absolute(&paths.data_dir, false, false).map_err(|error| fail(error.message))?;
    let stage_name = format!(
        ".bundle-stage-{}",
        service_fs::random_id().map_err(|error| fail(error.message))?
    );
    let stage = data
        .mkdir(&stage_name, 0o700)
        .map_err(|error| fail(error.message))?;
    let stage_real = paths.data_dir.join(&stage_name);
    let result = (|| {
        let payload = app_archive::payload(&stage, &stage_real, &archives)?;
        let files = write_payload(&stage, payload)?;
        let engine = app_archive::engine_spec()?;
        let manifest = json!({
            "schema": 2,
            "nfqws_archive_sha256": NFQWS_SHA256,
            "source": archives.source,
            "engine_arch": std::env::consts::ARCH,
            "engine_sha256": engine.sha256,
            "files": files,
        });
        let manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|error| fail(error.to_string()))?;
        stage
            .write(MANIFEST, &manifest_bytes, 0o600)
            .map_err(|error| fail(error.message))?;
        let mut candidate_paths = paths.clone();
        candidate_paths.bundle_dir = stage_real.clone();
        let staged = validate_bundle(&candidate_paths)?;
        let validation = dry_run(paths, &staged)?;
        let generation = format!("bundle-{}", digest(&manifest_bytes));
        let generation_path = paths.data_dir.join(&generation);
        let reused = data.exists(&generation)?;
        if reused {
            candidate_paths.bundle_dir = generation_path.clone();
            if validate_bundle(&candidate_paths)?.manifest_bytes != manifest_bytes {
                return Err(fail("Существующее поколение конфликтует с кандидатом"));
            }
            fs::remove_dir_all(&stage_real).map_err(|e| fail(e.to_string()))?;
        } else {
            data.rename(&stage_name, &data, &generation)?;
        }
        // Generation is retained even if the pointer rename succeeds but its fsync fails.
        paths.publish_bundle(&generation)?;
        candidate_paths.bundle_dir = generation_path;
        let mut bundle = validate_bundle(&candidate_paths)?;
        bundle.reused = reused;
        bundle.validation = validation;
        Ok(bundle)
    })();
    drop(stage);
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage_real);
    }
    result
}

pub fn setup(paths: &AppPaths, archive_dir: Option<&Path>) -> Result<Bundle> {
    prepare(paths, archive_dir, false)
}
pub fn update(paths: &AppPaths, archive_dir: Option<&Path>) -> Result<Bundle> {
    prepare(paths, archive_dir, true)
}
fn prepare(paths: &AppPaths, archive_dir: Option<&Path>, refresh: bool) -> Result<Bundle> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(AppError::new(
            "permissions",
            "Подготовку пользовательских данных запускайте без sudo",
        ));
    }
    paths.ensure_private_dirs()?;
    let _lock = lock(paths)?;
    paths.load_or_create_config()?;
    let mut paths = paths.clone();
    paths.bundle_dir = paths.active_bundle()?;
    if fs::symlink_metadata(&paths.bundle_dir).is_ok() {
        let mut bundle = validate_bundle(&paths)?;
        if !refresh {
            bundle.validation = dry_run(&paths, &bundle)?;
            return Ok(bundle);
        }
    }
    let archives = app_archive::acquire(&paths, archive_dir)?;
    build_bundle(&paths, archives)
}

fn command_version(path: &Path) -> Option<String> {
    let mut command = Command::new(path);
    command.env_clear().env("LC_ALL", "C").arg("--version");
    let output = child_process::capture(command, &[], Duration::from_millis(750)).ok()?;
    if !output.status.success() || output.truncated || !output.stdout_valid_utf8 {
        return None;
    }
    Some(output.stdout)
}

fn dependency_status() -> Value {
    let mut dependencies = Map::new();
    let curl_path = app_archive::find_executable("curl");
    let curl_version = curl_path.as_deref().and_then(command_version);
    dependencies.insert(
        "curl".to_string(),
        json!({
            "status": if curl_path.is_none() {
                "missing"
            } else if curl_version.is_some() {
                "available"
            } else {
                "unavailable"
            },
            "path": curl_path,
            "version": curl_version.as_ref().and_then(|value| value.lines().next()),
        }),
    );
    for name in [
        "tar",
        "nft",
        "ip",
        "iptables-legacy-save",
        "ip6tables-legacy-save",
    ] {
        let path = app_archive::find_executable(name);
        dependencies.insert(
            name.to_string(),
            json!({
                "status": if path.is_some() { "available" } else { "missing" },
                "path": path,
            }),
        );
    }
    let http3 = curl_version
        .as_deref()
        .and_then(|version| {
            version
                .lines()
                .find_map(|line| line.strip_prefix("Features:"))
                .map(|features| features.split_whitespace().any(|word| word == "HTTP3"))
        })
        .unwrap_or(false);
    dependencies.insert("http3".to_string(), json!(http3));
    Value::Object(dependencies)
}

pub fn doctor(paths: &AppPaths) -> Value {
    let config = if fs::symlink_metadata(&paths.config_file).is_err() {
        json!({"status": "missing", "path": paths.config_file})
    } else {
        match paths.load_config() {
            Ok(config) => {
                json!({"status": "valid", "path": paths.config_file, "value": config.json()})
            }
            Err(error) => json!({"status": "invalid", "path": paths.config_file,
                "error": {"kind": error.kind, "message": error.message}}),
        }
    };
    let bundle = if fs::symlink_metadata(&paths.bundle_dir).is_err() {
        json!({"status": "missing", "path": paths.bundle_dir})
    } else {
        match validate_bundle(paths) {
            Ok(bundle) => json!({"status": "valid", "value": bundle.json()}),
            Err(error) => json!({"status": "invalid", "path": paths.bundle_dir,
                "error": {"kind": error.kind, "message": error.message}}),
        }
    };
    json!({
        "paths": paths.json(),
        "config": config,
        "bundle": bundle,
        "dependencies": dependency_status(),
    })
}

pub fn ui(options: &[&str]) -> Result<Value> {
    let paths = AppPaths::discover()?;
    match options {
        ["paths"] => Ok(json!({"paths": paths.json()})),
        ["doctor"] | ["doctor", "--json"] => Ok(json!({"doctor": doctor(&paths)})),
        [action @ ("setup" | "update")] | [action @ ("setup" | "update"), "--json"] => {
            let bundle = prepare(&paths, None, *action == "update")?;
            let config: Config = paths.load_config()?;
            Ok(json!({"config": config.json(), "bundle": bundle.json()}))
        }
        [action @ ("setup" | "update"), "--archive-dir", directory]
        | [
            action @ ("setup" | "update"),
            "--archive-dir",
            directory,
            "--json",
        ]
        | [
            action @ ("setup" | "update"),
            "--json",
            "--archive-dir",
            directory,
        ] => {
            let bundle = if *action == "update" {
                update(&paths, Some(Path::new(directory)))?
            } else {
                setup(&paths, Some(Path::new(directory)))?
            };
            let config: Config = paths.load_config()?;
            Ok(json!({"config": config.json(), "bundle": bundle.json()}))
        }
        _ => Err(AppError::new(
            "usage",
            format!(
                "ui setup|update [--archive-dir DIR] | ui doctor | ui paths; offline names: {}, {}",
                app_archive::NFQWS_ARCHIVE_NAME,
                "flowseal.tar.gz (or strategies-<revision>.tar.gz)"
            ),
        )),
    }
}
