use crate::{
    app_archive::{self, ASSETS, NFQWS_SHA256, STRATEGIES, STRATEGIES_SHA256},
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
const GENERATED_LISTS: &[&str] = &[
    "list-general-user.txt",
    "list-exclude-user.txt",
    "ipset-exclude-user.txt",
];
const FLOWSEAL_TREE_SHA256: &str =
    "2fd7d7c43c7ddd6386e3369b69aead094ce7702dc334c239a0c97cca6e33f402";

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

struct SetupLock(File);

impl Drop for SetupLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn lock(paths: &AppPaths) -> Result<SetupLock> {
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
            strategy_count: STRATEGIES.len(),
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
            "reused": self.reused,
            "validation": self.validation,
        })
    }
}

fn expected_files() -> BTreeSet<String> {
    let mut files = BTreeSet::from(["bin/nfqws".to_string()]);
    files.extend(STRATEGIES.iter().map(|name| format!("strategies/{name}")));
    files.extend(ASSETS.iter().map(|name| format!("assets/{name}")));
    files.extend(
        GENERATED_LISTS
            .iter()
            .map(|name| format!("assets/lists/{name}")),
    );
    files
}

fn flowseal_tree_digest(entries: &[Value]) -> Result<String> {
    let mut rows = entries
        .iter()
        .filter_map(|entry| {
            let path = entry.get("path")?.as_str()?;
            (path != "bin/nfqws").then(|| {
                Ok((
                    path.to_string(),
                    entry
                        .get("size")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| fail("Manifest содержит некорректный размер"))?,
                    entry
                        .get("sha256")
                        .and_then(Value::as_str)
                        .ok_or_else(|| fail("Manifest содержит некорректный digest"))?
                        .to_string(),
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort();
    let mut hasher = Sha256::new();
    for (path, size, digest) in rows {
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(size.to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("{:x}", hasher.finalize()))
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
                directories.insert(relative);
                recurse(root, &path, files, directories)?;
            } else if metadata.is_file() {
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
    if manifest.get("schema") != Some(&json!(1))
        || manifest.get("nfqws_archive_sha256") != Some(&json!(NFQWS_SHA256))
        || manifest.get("strategies_archive_sha256") != Some(&json!(STRATEGIES_SHA256))
        || manifest.get("engine_arch") != Some(&json!(std::env::consts::ARCH))
    {
        return Err(fail(
            "Manifest bundle имеет неизвестную версию или источник",
        ));
    }
    let engine = app_archive::engine_spec()?;
    if manifest.get("engine_sha256") != Some(&json!(engine.sha256)) {
        return Err(fail("Manifest содержит другой nfqws"));
    }
    let entries = manifest
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("Manifest не содержит список файлов"))?;
    if flowseal_tree_digest(entries)? != FLOWSEAL_TREE_SHA256 {
        return Err(fail(
            "Manifest не совпадает с закреплённым набором Flowseal",
        ));
    }
    let expected = expected_files();
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
    let mut expected_with_manifest = expected;
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

fn dry_run(paths: &AppPaths, bundle: &Bundle) -> Result<Value> {
    let options = [
        "--dry-run",
        "--config",
        string_path(&paths.config_file)?,
        "--strategies",
        string_path(&bundle.strategies)?,
        "--assets",
        string_path(&bundle.assets)?,
        "--nfqws",
        string_path(&bundle.nfqws)?,
        "--timeout-ms",
        "10000",
    ];
    let result = validation::run(&options)?;
    Ok(result
        .get("validation")
        .cloned()
        .unwrap_or_else(|| json!({"status": "passed"})))
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
            "schema": 1,
            "nfqws_archive_sha256": NFQWS_SHA256,
            "strategies_archive_sha256": STRATEGIES_SHA256,
            "engine_arch": std::env::consts::ARCH,
            "engine_sha256": engine.sha256,
            "files": files,
        });
        if flowseal_tree_digest(manifest["files"].as_array().unwrap_or(&Vec::new()))?
            != FLOWSEAL_TREE_SHA256
        {
            return Err(fail(
                "Извлечённые файлы не совпадают с закреплённым набором Flowseal",
            ));
        }
        let manifest_bytes =
            serde_json::to_vec_pretty(&manifest).map_err(|error| fail(error.to_string()))?;
        stage
            .write(MANIFEST, &manifest_bytes, 0o600)
            .map_err(|error| fail(error.message))?;
        let staged = Bundle::at(stage_real.clone());
        let validation = dry_run(paths, &staged)?;
        data.rename(&stage_name, &data, "bundle")
            .map_err(|error| fail(error.message))?;
        let mut bundle = validate_bundle(paths)?;
        bundle.reused = false;
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
    if unsafe { libc::geteuid() } == 0 {
        return Err(AppError::new(
            "permissions",
            "Подготовку пользовательских данных запускайте без sudo",
        ));
    }
    paths.ensure_private_dirs()?;
    let _lock = lock(paths)?;
    paths.load_or_create_config()?;
    let data = Dir::absolute(&paths.data_dir, false, false).map_err(|error| fail(error.message))?;
    if data.exists("bundle").map_err(|error| fail(error.message))? {
        let mut bundle = validate_bundle(paths)?;
        bundle.validation = dry_run(paths, &bundle)?;
        return Ok(bundle);
    }
    let archives = app_archive::acquire(paths, archive_dir)?;
    build_bundle(paths, archives)
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
        ["setup"] | ["setup", "--json"] => {
            let bundle = setup(&paths, None)?;
            let config: Config = paths.load_config()?;
            Ok(json!({"config": config.json(), "bundle": bundle.json()}))
        }
        ["setup", "--archive-dir", directory]
        | ["setup", "--archive-dir", directory, "--json"]
        | ["setup", "--json", "--archive-dir", directory] => {
            let bundle = setup(&paths, Some(Path::new(directory)))?;
            let config: Config = paths.load_config()?;
            Ok(json!({"config": config.json(), "bundle": bundle.json()}))
        }
        _ => Err(AppError::new(
            "usage",
            format!(
                "ui setup [--archive-dir DIR] | ui doctor | ui paths; offline names: {}, {}",
                app_archive::NFQWS_ARCHIVE_NAME,
                app_archive::STRATEGIES_ARCHIVE_NAME
            ),
        )),
    }
}
