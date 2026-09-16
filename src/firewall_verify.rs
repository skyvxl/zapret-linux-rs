use crate::{
    error::{AppError, Result},
    firewall::FirewallPlan,
    namespace,
    nft::Nft,
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

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
    let inspection = nft.inspect(plan);
    let cleanup = nft.remove(plan);
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
