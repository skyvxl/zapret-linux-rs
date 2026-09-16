use crate::{
    error::{AppError, Result},
    owned_table::OwnedTable,
};
use serde_json::{Value, json};
use std::{fs, io};

fn invalid(message: impl Into<String>) -> AppError {
    AppError::new("state", message)
}

fn object(value: &Value, fields: &[&str]) -> Result<()> {
    if value.as_object().is_none_or(|map| {
        map.len() != fields.len() || fields.iter().any(|key| !map.contains_key(*key))
    }) {
        return Err(invalid("Некорректные поля журнала"));
    }
    Ok(())
}

fn namespace(value: &Value, kind: &str) -> Result<()> {
    if value
        .as_str()
        .and_then(|s| s.strip_prefix(&format!("{kind}:[")))
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|s| s.parse::<u64>().ok())
        .is_none_or(|n| n == 0)
    {
        return Err(invalid("Некорректный идентификатор namespace"));
    }
    Ok(())
}

fn boot_id() -> Result<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .map_err(|e| invalid(e.to_string()))
}

fn ns(kind: &str) -> Result<String> {
    fs::read_link(format!("/proc/self/ns/{kind}"))
        .map(|s| s.to_string_lossy().into_owned())
        .map_err(|e| invalid(e.to_string()))
}

fn check_procfs() -> Result<()> {
    let stat = fs::read_to_string("/proc/self/stat").map_err(|e| invalid(e.to_string()))?;
    if stat
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        != Some(std::process::id())
    {
        return Err(invalid("procfs не соответствует текущему PID namespace"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Identity {
    pid: u32,
    start_ticks: u64,
}

impl Identity {
    fn parse(value: &Value) -> Result<Self> {
        object(value, &["pid", "start_ticks"])?;
        let pid = value["pid"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= i32::MAX as u64)
            .ok_or_else(|| invalid("Некорректный PID"))? as u32;
        let start_ticks = value["start_ticks"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(|| invalid("Некорректное время старта процесса"))?;
        Ok(Self { pid, start_ticks })
    }

    fn read(pid: u32) -> Result<Option<(Self, bool)>> {
        check_procfs()?;
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(invalid(format!("Нельзя проверить процесс {pid}: {e}"))),
        };
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .ok_or_else(|| invalid("Некорректный proc stat"))?
            .1
            .split_whitespace()
            .collect();
        let start_ticks = fields
            .get(19)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| invalid("Нет времени старта процесса"))?;
        let alive = !matches!(fields.first().copied(), Some("Z" | "X"));
        Ok(Some((Self { pid, start_ticks }, alive)))
    }

    fn json(self) -> Value {
        json!({"pid":self.pid,"start_ticks":self.start_ticks})
    }

    fn alive(self) -> Result<bool> {
        Ok(Self::read(self.pid)?
            .is_some_and(|(current, alive)| current.start_ticks == self.start_ticks && alive))
    }
}

pub struct Record {
    value: Value,
    owner: Identity,
    engine: Option<Identity>,
    tables: Vec<OwnedTable>,
}

impl Record {
    pub fn new(isolation: Value, tables: &[&OwnedTable]) -> Result<Self> {
        check_procfs()?;
        let (owner, _) =
            Identity::read(std::process::id())?.ok_or_else(|| invalid("Нет текущего процесса"))?;
        Self::parse(
            json!({"version":1,"scope":"isolated_network_namespace","boot_id":boot_id()?,
            "pid_namespace":ns("pid")?,"owner":owner.json(),"engine":null,"isolation":isolation,
            "tables":tables.iter().map(|table|table.record()).collect::<Vec<_>>()}),
        )
    }

    pub fn parse(value: Value) -> Result<Self> {
        object(
            &value,
            &[
                "version",
                "scope",
                "boot_id",
                "pid_namespace",
                "owner",
                "engine",
                "isolation",
                "tables",
            ],
        )?;
        if value["version"] != 1 || value["scope"] != "isolated_network_namespace" {
            return Err(invalid("Неподдерживаемая версия или область журнала"));
        }
        let boot = value["boot_id"]
            .as_str()
            .ok_or_else(|| invalid("Нет boot_id"))?;
        if boot.len() != 36
            || !boot.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
        {
            return Err(invalid("Некорректный boot_id"));
        }
        namespace(&value["pid_namespace"], "pid")?;
        let isolation = &value["isolation"];
        object(isolation, &["net", "user", "parent_net", "parent_user"])?;
        for (key, kind) in [
            ("net", "net"),
            ("parent_net", "net"),
            ("user", "user"),
            ("parent_user", "user"),
        ] {
            namespace(&isolation[key], kind)?;
        }
        if isolation["net"] == isolation["parent_net"]
            || isolation["user"] == isolation["parent_user"]
        {
            return Err(invalid(
                "Журнал не подтверждает создание изолированных namespaces",
            ));
        }
        let owner = Identity::parse(&value["owner"])?;
        let engine = if value["engine"].is_null() {
            None
        } else {
            Some(Identity::parse(&value["engine"])?)
        };
        let entries = value["tables"]
            .as_array()
            .filter(|list| list.len() == 2)
            .ok_or_else(|| invalid("Требуются две таблицы журнала"))?;
        let tables = entries
            .iter()
            .map(OwnedTable::restore)
            .collect::<Result<Vec<_>>>()?;
        if entries[0]["name"] == entries[1]["name"] {
            return Err(invalid("Повторная таблица в журнале"));
        }
        Ok(Self {
            value,
            owner,
            engine,
            tables,
        })
    }

    pub fn json(&self) -> Value {
        self.value.clone()
    }

    pub fn set_engine(&mut self, pid: u32) -> Result<()> {
        let (engine, _) =
            Identity::read(pid)?.ok_or_else(|| invalid("Дочерний процесс уже исчез"))?;
        self.engine = Some(engine);
        self.value["engine"] = engine.json();
        Ok(())
    }

    pub fn tables(&self) -> &[OwnedTable] {
        &self.tables
    }

    pub fn owner_alive(&self) -> Result<bool> {
        if self.value["boot_id"] != boot_id()? || self.value["pid_namespace"] != ns("pid")? {
            return Err(invalid(
                "Нельзя проверить владельца журнала из другой загрузки системы или PID namespace",
            ));
        }
        self.owner.alive()
    }

    pub fn validate_recovery(&self) -> Result<()> {
        if self.value["boot_id"] != boot_id()?
            || self.value["pid_namespace"] != ns("pid")?
            || self.value["isolation"]["net"] != ns("net")?
            || self.value["isolation"]["user"] != ns("user")?
        {
            return Err(invalid(
                "Восстановление разрешено только в той же загрузке системы и тех же namespaces",
            ));
        }
        if self.owner.alive()? {
            return Err(invalid("Владелец журнала ещё работает"));
        }
        if let Some(engine) = self.engine
            && engine.alive()?
        {
            return Err(invalid(
                "Записанный nfqws ещё работает; автоматическое завершение запрещено",
            ));
        }
        Ok(())
    }
}
