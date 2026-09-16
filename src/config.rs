use crate::{
    error::{AppError, Result},
    input::read_text,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Copy)]
pub enum Backend {
    Auto,
    Nftables,
    Iptables,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub interface: String,
    pub gamefiltertcp: bool,
    pub gamefilterudp: bool,
    pub strategy: String,
    pub backend: Backend,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&read_text(path)?)
    }

    pub fn parse(content: &str) -> Result<Self> {
        let mut fields = BTreeMap::new();
        for (index, line) in content.trim_start_matches('\u{feff}').lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fail =
                |message: &str| AppError::new("config", format!("Строка {}: {message}", index + 1));
            let (key, raw) = line
                .split_once('=')
                .ok_or_else(|| fail("ожидается ключ=значение"))?;
            let key = key.trim();
            if ![
                "interface",
                "gamefiltertcp",
                "gamefilterudp",
                "strategy",
                "firewall_backend",
            ]
            .contains(&key)
            {
                return Err(fail("неизвестный ключ"));
            }
            let value = parse_value(raw).map_err(|e| fail(&e))?;
            if fields.insert(key.to_string(), value).is_some() {
                return Err(fail("повторный ключ"));
            }
        }
        let required = |key: &str| {
            fields
                .get(key)
                .cloned()
                .ok_or_else(|| AppError::new("config", format!("Отсутствует поле {key}")))
        };
        let boolean = |key: &str| -> Result<bool> {
            match required(key)?.as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(AppError::new(
                    "config",
                    format!("{key}: ожидается true или false"),
                )),
            }
        };
        let interface = required("interface")?;
        if interface.len() > 15
            || !interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
            || [".", ".."].contains(&interface.as_str())
        {
            return Err(AppError::new("config", "Некорректное имя интерфейса"));
        }
        let strategy = required("strategy")?;
        if strategy.contains(['/', '\\']) || [".", ".."].contains(&strategy.as_str()) {
            return Err(AppError::new(
                "config",
                "Стратегия должна быть именем, без пути",
            ));
        }
        let backend = match fields
            .get("firewall_backend")
            .map(String::as_str)
            .unwrap_or("auto")
        {
            "auto" => Backend::Auto,
            "nftables" => Backend::Nftables,
            "iptables" => Backend::Iptables,
            _ => return Err(AppError::new("config", "Неизвестный firewall_backend")),
        };
        Ok(Self {
            interface,
            strategy,
            gamefiltertcp: boolean("gamefiltertcp")?,
            gamefilterudp: boolean("gamefilterudp")?,
            backend,
        })
    }

    pub fn json(&self) -> Value {
        json!({"interface": self.interface, "strategy": self.strategy,
            "gamefiltertcp": self.gamefiltertcp, "gamefilterudp": self.gamefilterudp,
            "firewall_backend": self.backend.name()})
    }
}

fn parse_value(raw: &str) -> std::result::Result<String, String> {
    let raw = raw.trim();
    let value = if raw.starts_with(['\'', '"']) {
        let quote = raw.chars().next().unwrap();
        let end = raw[1..].find(quote).ok_or("незакрытая кавычка")? + 1;
        let tail = raw[end + 1..].trim();
        if !tail.is_empty() && !tail.starts_with('#') {
            return Err("лишний текст после значения".into());
        }
        raw[1..end].to_string()
    } else {
        let value = raw.split(" #").next().unwrap().trim();
        if value.chars().any(char::is_whitespace) {
            return Err("значение с пробелами требует кавычек".into());
        }
        value.to_string()
    };
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_control() || "$`;&|<>\\".contains(c))
    {
        return Err("пустое значение или неподдерживаемая shell-конструкция".into());
    }
    Ok(value)
}
