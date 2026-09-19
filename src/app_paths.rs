use crate::{
    config::{Backend, Config},
    error::{AppError, Result},
    service_fs::{self, Dir},
};
use serde_json::{Value, json};
use std::{
    env,
    ffi::CString,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

const APP: &str = "zapret-linux-rs";
const CONFIG_NAME: &str = "config.env";
const CONFIG_LIMIT: u64 = 64 * 1024;

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("paths", message)
}

fn checked_absolute(name: &str, value: PathBuf) -> Result<PathBuf> {
    let text = value
        .to_str()
        .ok_or_else(|| fail(format!("{name}: путь должен быть UTF-8")))?;
    if text.is_empty()
        || text.chars().any(char::is_control)
        || !value.is_absolute()
        || value
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(fail(format!(
            "{name}: требуется абсолютный путь UTF-8 без управляющих символов и '..'"
        )));
    }
    Ok(value)
}

fn environment_path(name: &str) -> Result<Option<PathBuf>> {
    match env::var_os(name) {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => checked_absolute(name, PathBuf::from(value)).map(Some),
    }
}

fn home() -> Result<PathBuf> {
    environment_path("HOME")?.ok_or_else(|| fail("HOME не задан"))
}

fn require_private(directory: &Dir, path: &Path) -> Result<()> {
    let metadata = directory
        .0
        .metadata()
        .map_err(|error| fail(error.to_string()))?;
    if metadata.uid() != service_fs::uid()
        || metadata.gid() != service_fs::gid()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(fail(format!(
            "{}: ожидается принадлежащий текущему пользователю каталог с режимом 0700",
            path.display()
        )));
    }
    Ok(())
}

fn open_or_create_private(path: &Path) -> Result<Dir> {
    checked_absolute("каталог приложения", path.to_path_buf())?;
    let mut directory =
        Dir::absolute(Path::new("/"), false, false).map_err(|error| fail(error.message))?;
    let parts = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return Err(fail(
            "Корень файловой системы не может быть каталогом приложения",
        ));
    }
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        directory = if directory
            .exists(part)
            .map_err(|error| fail(error.message))?
        {
            directory
                .child(part)
                .map_err(|error| fail(format!("{}: {}", path.display(), error.message)))?
        } else {
            match directory.mkdir(part, 0o700) {
                Ok(created) => created,
                Err(create_error) => {
                    let appeared = directory.child(part).map_err(|_| {
                        fail(format!("{}: {}", path.display(), create_error.message))
                    })?;
                    require_private(&appeared, path)?;
                    appeared
                }
            }
        };
        if last {
            require_private(&directory, path)?;
        }
    }
    Ok(directory)
}

fn private_existing(path: &Path) -> Result<Dir> {
    let directory = Dir::absolute(path, false, false).map_err(|error| fail(error.message))?;
    require_private(&directory, path)?;
    Ok(directory)
}

fn config_text(config: &Config) -> Result<String> {
    let strategy = if config
        .strategy
        .bytes()
        .all(|value| value.is_ascii_alphanumeric() || b"_.-()".contains(&value))
    {
        config.strategy.clone()
    } else {
        if config.strategy.contains(['\'', '"']) {
            return Err(AppError::new(
                "config",
                "Имя стратегии с кавычками нельзя сохранить",
            ));
        }
        format!("'{}'", config.strategy)
    };
    let text = format!(
        "interface={}\ngamefiltertcp={}\ngamefilterudp={}\nstrategy={}\nfirewall_backend={}\n",
        config.interface,
        config.gamefiltertcp,
        config.gamefilterudp,
        strategy,
        config.backend.name()
    );
    Config::parse(&text)?;
    Ok(text)
}

fn rename_entry(directory: &Dir, old: &str, new: &str, replace: bool) -> Result<()> {
    let old = CString::new(old).map_err(|error| fail(error.to_string()))?;
    let new = CString::new(new).map_err(|error| fail(error.to_string()))?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.0.as_raw_fd(),
            old.as_ptr(),
            directory.0.as_raw_fd(),
            new.as_ptr(),
            if replace { 0 } else { libc::RENAME_NOREPLACE },
        )
    };
    if result != 0 {
        return Err(fail(std::io::Error::last_os_error().to_string()));
    }
    directory.sync().map_err(|error| fail(error.message))
}

fn write_config(directory: &Dir, content: &[u8], replace: bool) -> Result<()> {
    let temporary = format!(
        ".config-{}.tmp",
        service_fs::random_id().map_err(|e| fail(e.message))?
    );
    if let Err(error) = directory.write(&temporary, content, 0o600) {
        let _ = directory.unlink(&temporary, false);
        return Err(fail(error.message));
    }
    let result = rename_entry(directory, &temporary, CONFIG_NAME, replace);
    if result.is_err() {
        let _ = directory.unlink(&temporary, false);
    }
    result
}

#[derive(Default)]
pub struct ConfigChanges {
    pub interface: Option<String>,
    pub strategy: Option<String>,
    pub gamefiltertcp: Option<bool>,
    pub gamefilterudp: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub bundle_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let home = home()?;
        let config_base =
            environment_path("XDG_CONFIG_HOME")?.unwrap_or_else(|| home.join(".config"));
        let data_base =
            environment_path("XDG_DATA_HOME")?.unwrap_or_else(|| home.join(".local/share"));
        let cache_base = environment_path("XDG_CACHE_HOME")?.unwrap_or_else(|| home.join(".cache"));
        let config_dir = checked_absolute("config", config_base.join(APP))?;
        let data_dir = checked_absolute("data", data_base.join(APP))?;
        let cache_dir = checked_absolute("cache", cache_base.join(APP))?;
        let mut paths = Self {
            config_file: config_dir.join(CONFIG_NAME),
            bundle_dir: data_dir.join("bundle"),
            config_dir,
            data_dir,
            cache_dir,
        };
        paths.bundle_dir = paths.active_bundle()?;
        Ok(paths)
    }

    pub fn active_bundle(&self) -> Result<PathBuf> {
        if !self
            .data_dir
            .try_exists()
            .map_err(|e| fail(e.to_string()))?
        {
            return Ok(self.data_dir.join("bundle"));
        }
        let directory = private_existing(&self.data_dir)?;
        if !directory.exists("active-bundle")? {
            return Ok(self.data_dir.join("bundle"));
        }
        let bytes = directory.read("active-bundle", 0o600, 100)?;
        let name = std::str::from_utf8(&bytes).map_err(|e| fail(e.to_string()))?;
        if !name.strip_prefix("bundle-").is_some_and(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(fail("Некорректный указатель active-bundle"));
        }
        let path = self.data_dir.join(name);
        private_existing(&path)?;
        Ok(path)
    }

    pub fn publish_bundle(&self, name: &str) -> Result<()> {
        let directory = private_existing(&self.data_dir)?;
        if !name
            .strip_prefix("bundle-")
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(fail("Некорректное имя поколения"));
        }
        private_existing(&self.data_dir.join(name))?;
        // Refuse unsafe existing pointer without chmod or ownership takeover.
        self.active_bundle()?;
        let temporary = format!(".active-{}.tmp", service_fs::random_id()?);
        directory.write(&temporary, name.as_bytes(), 0o600)?;
        let old = CString::new(temporary.as_str()).map_err(|e| fail(e.to_string()))?;
        let new = CString::new("active-bundle").map_err(|e| fail(e.to_string()))?;
        if unsafe {
            libc::renameat(
                directory.0.as_raw_fd(),
                old.as_ptr(),
                directory.0.as_raw_fd(),
                new.as_ptr(),
            )
        } != 0
        {
            let error = fail(std::io::Error::last_os_error().to_string());
            let _ = directory.unlink(&temporary, false);
            return Err(error);
        }
        directory.sync().map_err(|e| {
            let active = self.active_bundle().map(|p| p.display().to_string()).unwrap_or_else(|e| e.message);
            AppError::new("outcome_unknown", format!("Указатель переименован, fsync не подтверждён; поколение сохранено; active={active}: {}", e.message))
        })
    }

    pub fn json(&self) -> Value {
        json!({
            "config": self.config_dir,
            "config_file": self.config_file,
            "data": self.data_dir,
            "cache": self.cache_dir,
            "bundle": self.bundle_dir,
        })
    }

    pub fn defaults() -> Config {
        Config {
            interface: "any".to_string(),
            gamefiltertcp: false,
            gamefilterudp: false,
            strategy: "general (ALT11).bat".to_string(),
            backend: Backend::Nftables,
        }
    }

    pub fn ensure_private_dirs(&self) -> Result<()> {
        open_or_create_private(&self.config_dir)?;
        open_or_create_private(&self.data_dir)?;
        open_or_create_private(&self.cache_dir)?;
        Ok(())
    }

    pub fn ensure_private_child(&self, parent: &Path, name: &str) -> Result<PathBuf> {
        if name.is_empty() || name.contains('/') || [".", ".."].contains(&name) {
            return Err(fail("Некорректное имя дочернего каталога"));
        }
        private_existing(parent)?;
        let path = parent.join(name);
        open_or_create_private(&path)?;
        Ok(path)
    }

    pub fn load_config(&self) -> Result<Config> {
        let directory = private_existing(&self.config_dir)?;
        let bytes = directory
            .read(CONFIG_NAME, 0o600, CONFIG_LIMIT)
            .map_err(|error| AppError::new("config", error.message))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| AppError::new("config", "Конфигурация должна быть UTF-8"))?;
        Config::parse(&text)
    }

    pub fn update_config(&self, changes: ConfigChanges) -> Result<Config> {
        self.ensure_private_dirs()?;
        let _lock = crate::app_setup::lock(self)?;
        let directory = open_or_create_private(&self.config_dir)?;
        let mut config = if directory.exists(CONFIG_NAME)? {
            self.load_config()?
        } else {
            Self::defaults()
        };
        if let Some(value) = changes.interface {
            config.interface = value;
        }
        if let Some(value) = changes.strategy {
            config.strategy = value;
        }
        if let Some(value) = changes.gamefiltertcp {
            config.gamefiltertcp = value;
        }
        if let Some(value) = changes.gamefilterudp {
            config.gamefilterudp = value;
        }

        let mut paths = self.clone();
        paths.bundle_dir = self.active_bundle()?;
        if std::fs::symlink_metadata(&paths.bundle_dir).is_ok() {
            let bundle = crate::app_setup::validate_bundle(&paths)?;
            crate::app_setup::validate_config(&config, &bundle)?;
        }
        write_config(&directory, config_text(&config)?.as_bytes(), true)?;
        Ok(config)
    }

    pub fn load_or_create_config(&self) -> Result<Config> {
        let directory = open_or_create_private(&self.config_dir)?;
        if directory
            .exists(CONFIG_NAME)
            .map_err(|error| fail(error.message))?
        {
            return self.load_config();
        }
        let defaults = Self::defaults();
        match write_config(&directory, config_text(&defaults)?.as_bytes(), false) {
            Ok(()) => Ok(defaults),
            Err(_)
                if directory
                    .exists(CONFIG_NAME)
                    .map_err(|error| fail(error.message))? =>
            {
                self.load_config()
            }
            Err(error) => Err(error),
        }
    }
}
