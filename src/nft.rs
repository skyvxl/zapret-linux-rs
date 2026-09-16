use crate::{
    error::{AppError, Result},
    firewall::{FirewallPlan, TABLE},
    process,
};
use serde_json::Value;
use std::{path::Path, process::Command, time::Duration};

pub struct Nft<'a> {
    pub binary: &'a Path,
    pub timeout: Duration,
}

impl Nft<'_> {
    pub fn run(&self, stage: &str, args: &[&str], input: &str) -> Result<String> {
        let mut command = Command::new(self.binary);
        command
            .args(args)
            .current_dir("/")
            .env_clear()
            .env("LC_ALL", "C");
        let output =
            process::capture(command, input.as_bytes(), self.timeout).map_err(|error| {
                AppError::new(error.kind, format!("nft {stage}: {}", error.message))
            })?;
        if !output.status.success() {
            return Err(AppError::new(
                "firewall",
                format!(
                    "nft {stage}: {}\n{}\n{}",
                    output.status, output.stderr, output.stdout
                ),
            ));
        }
        if output.truncated {
            return Err(AppError::new(
                "firewall",
                format!("nft {stage}: вывод превышает лимит; результат не подтверждён"),
            ));
        }
        if !output.stdout_valid_utf8 {
            return Err(AppError::new(
                "firewall",
                format!("nft {stage}: stdout содержит некорректный UTF-8"),
            ));
        }
        Ok(output.stdout)
    }

    pub fn list(&self, stage: &str, args: &[&str]) -> Result<Vec<Value>> {
        let output = self.run(stage, args, "")?;
        let value: Value = serde_json::from_str(&output).map_err(|e| {
            AppError::new("firewall", format!("nft {stage}: некорректный JSON: {e}"))
        })?;
        value
            .get("nftables")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| AppError::new("firewall", format!("nft {stage}: нет массива nftables")))
    }
    pub fn inspect(&self, plan: &FirewallPlan) -> Result<()> {
        let entries = self.list("inspect", &["--json", "list", "table", "inet", TABLE])?;
        let own_table = entries
            .iter()
            .filter_map(|e| e.get("table"))
            .any(|t| t["family"] == "inet" && t["name"] == TABLE);
        let chains = entries
            .iter()
            .filter_map(|e| e.get("chain"))
            .filter(|c| c["family"] == "inet" && c["table"] == TABLE)
            .count();
        let rules = entries
            .iter()
            .filter_map(|e| e.get("rule"))
            .filter(|r| r["family"] == "inet" && r["table"] == TABLE)
            .count();
        if !own_table || chains != 2 || rules != plan.rule_count() {
            return Err(AppError::new(
                "firewall",
                "nft inspect: установленные объекты не соответствуют плану",
            ));
        }
        Ok(())
    }

    pub fn remove(&self, plan: &FirewallPlan) -> Result<()> {
        self.run("cleanup", &["--file", "-"], &plan.rollback())?;
        let entries = self.list("cleanup-inspect", &["--json", "list", "tables"])?;
        if entries
            .iter()
            .filter_map(|e| e.get("table"))
            .any(|t| t["family"] == "inet" && t["name"] == TABLE)
        {
            return Err(AppError::new(
                "firewall",
                "nft cleanup: таблица осталась после удаления",
            ));
        }
        Ok(())
    }
}
