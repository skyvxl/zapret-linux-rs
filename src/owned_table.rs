use crate::{
    error::{AppError, Result},
    nft::Nft,
};
use serde_json::{Value, json};
use std::{fs::File, io::Read};

pub struct OwnedTable {
    name: &'static str,
    marker: String,
}

impl OwnedTable {
    pub fn record(&self) -> Value {
        json!({"name":self.name,"marker":self.marker})
    }

    pub fn restore(value: &Value) -> Result<Self> {
        let name = match value.get("name").and_then(Value::as_str) {
            Some("zapret_rs") => "zapret_rs",
            Some("zapret_rs_probe") => "zapret_rs_probe",
            _ => return Err(AppError::new("state", "Неизвестная таблица в журнале")),
        };
        let marker = value
            .get("marker")
            .and_then(Value::as_str)
            .and_then(|text| text.strip_prefix("zapret-linux-rs:"))
            .filter(|text| {
                text.len() == 32
                    && text
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            .ok_or_else(|| AppError::new("state", "Некорректный маркер таблицы"))?;
        if value.as_object().is_none_or(|object| object.len() != 2) {
            return Err(AppError::new("state", "Лишние поля таблицы в журнале"));
        }
        Ok(Self {
            name,
            marker: format!("zapret-linux-rs:{marker}"),
        })
    }

    pub fn new(name: &'static str) -> Result<Self> {
        if !["zapret_rs", "zapret_rs_probe"].contains(&name) {
            return Err(AppError::new("firewall", "Неизвестная управляемая таблица"));
        }
        let mut random = [0; 16];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(|e| AppError::new("firewall", format!("Маркер владения: {e}")))?;
        let marker = format!(
            "zapret-linux-rs:{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        Ok(Self { name, marker })
    }

    pub fn apply(&self, nft: &Nft<'_>, stage: &str, batch: &str) -> Result<()> {
        let (first, rest) = batch
            .split_once('\n')
            .ok_or_else(|| AppError::new("firewall", "Нет create table в batch"))?;
        let expected = format!("create table inet {}", self.name);
        if first != expected && !first.starts_with(&format!("{expected} {{")) {
            return Err(AppError::new("firewall", "Batch создаёт другую таблицу"));
        }
        let owned = format!("{expected} {{ comment \"{}\"; }}\n{rest}", self.marker);
        match nft.run(stage, &["--file", "-"], &owned) {
            Ok(_) => Ok(()),
            // The kernel may have committed even if nft timed out or returned
            // unreadable output. Reconcile using the marker from that same batch.
            Err(error) => crate::error::combine(Err(error), self.remove(nft)),
        }
    }

    fn handle(&self, nft: &Nft<'_>) -> Result<Option<u64>> {
        let entries = nft.list("ownership", &["--json", "list", "tables"])?;
        for table in entries.iter().filter_map(|entry| entry.get("table")) {
            if table["family"] == "inet" && table["name"] == self.name {
                if table["comment"] != self.marker {
                    return Err(AppError::new(
                        "firewall",
                        format!(
                            "Таблица {} принадлежит другому запуску; удаление отменено",
                            self.name
                        ),
                    ));
                }
                return table["handle"].as_u64().map(Some).ok_or_else(|| {
                    AppError::new("firewall", "nft ownership: нет числового handle")
                });
            }
        }
        Ok(None)
    }

    pub fn remove(&self, nft: &Nft<'_>) -> Result<()> {
        if let Some(handle) = self.handle(nft)? {
            // A replacement between inspection and deletion has a different
            // handle; deletion by handle cannot erase that replacement by name.
            nft.run(
                "cleanup",
                &["--file", "-"],
                &format!("delete table inet handle {handle}\n"),
            )?;
            if self.handle(nft)?.is_some() {
                return Err(AppError::new(
                    "firewall",
                    format!("nft cleanup: таблица {} осталась", self.name),
                ));
            }
        }
        Ok(())
    }
}
