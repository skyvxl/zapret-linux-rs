use crate::{
    error::{AppError, Result},
    firewall::{FirewallPlan, TABLE},
    namespace, process,
};
use serde_json::{Value, json};
use std::{path::Path, process::Command, time::Duration};

struct Nft<'a> {
    binary: &'a Path,
    timeout: Duration,
}

impl Nft<'_> {
    fn run(&self, stage: &str, args: &[&str], input: &str) -> Result<String> {
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

    fn list(&self, stage: &str, args: &[&str]) -> Result<Vec<Value>> {
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
}

pub fn verify(plan: &FirewallPlan, binary: &Path, timeout: Duration) -> Result<Value> {
    let binary = binary
        .canonicalize()
        .map_err(|e| AppError::new("firewall", format!("nft: {e}")))?;
    if !binary.is_file() {
        return Err(AppError::new(
            "firewall",
            "nft должен быть обычным исполняемым файлом",
        ));
    }
    let isolation = namespace::enter()?;
    let nft = Nft {
        binary: &binary,
        timeout,
    };
    let batch = plan.batch();
    nft.run("check", &["--check", "--file", "-"], &batch)?;
    nft.run("apply", &["--file", "-"], &batch)?;

    // Only a successful create authorizes explicit deletion. The entire namespace
    // disappears on exit, including an uncertain apply result after a timeout.
    let inspection = (|| {
        let entries = nft.list("inspect", &["--json", "list", "table", "inet", TABLE])?;
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
    })();
    let cleanup = (|| {
        nft.run("cleanup", &["--file", "-"], &plan.rollback())?;
        let entries = nft.list("cleanup-inspect", &["--json", "list", "tables"])?;
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
    })();
    match (inspection, cleanup) {
        (Err(first), Err(second)) => {
            return Err(AppError::new(
                first.kind,
                format!("{}; {}", first.message, second.message),
            ));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    Ok(
        json!({"status": "passed", "scope": "isolated_network_namespace", "isolation": isolation,
        "rule_count": plan.rule_count(), "cleanup": "removed", "network_validation": "not_run"}),
    )
}
