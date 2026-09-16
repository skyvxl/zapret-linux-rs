use crate::{
    error::{AppError, Result},
    nft::Nft,
};
use std::{fs::File, io::Read};

pub struct OwnedTable {
    name: &'static str,
    marker: String,
}

impl OwnedTable {
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
