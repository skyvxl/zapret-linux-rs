use crate::{
    config::Config,
    error::{AppError, Result},
    firewall::FirewallPlan,
    strategy::Plan,
    validation::resolve_strategy,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

pub fn run(args: &[&str]) -> Result<Value> {
    let (operation, args) = args
        .split_first()
        .ok_or_else(|| AppError::new("usage", "Требуется firewall plan"))?;
    if !["plan", "verify"].contains(operation) {
        return Err(AppError::new(
            "usage",
            "Поддерживается firewall plan или verify",
        ));
    }
    let mut values = BTreeMap::new();
    let (chunks, remainder) = args.as_chunks::<2>();
    for pair in chunks {
        let allowed = ["--config", "--strategies", "--assets"].contains(&pair[0])
            || (*operation == "verify" && ["--nft", "--timeout-ms"].contains(&pair[0]));
        if !allowed || pair[1].starts_with("--") || values.insert(pair[0], pair[1]).is_some() {
            return Err(AppError::new(
                "usage",
                format!(
                    "Неизвестный, повторный параметр или нет значения: {}",
                    pair[0]
                ),
            ));
        }
    }
    if !remainder.is_empty() {
        return Err(AppError::new("usage", "Параметр без значения"));
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| AppError::new("usage", format!("Требуется {key}")))
    };
    let config = Config::load(Path::new(required("--config")?))?;
    let strategy_file = resolve_strategy(Path::new(required("--strategies")?), &config.strategy)?;
    let strategy = Plan::load(
        &strategy_file,
        Path::new(required("--assets")?),
        config.gamefiltertcp,
        config.gamefilterudp,
    )?;
    let firewall = FirewallPlan::new(&config, &strategy)?;
    let mut result = json!({"config": config.json(), "strategy_file": strategy_file, "firewall": firewall.json()});
    if *operation == "verify" {
        let timeout: u64 = values
            .get("--timeout-ms")
            .unwrap_or(&"5000")
            .parse()
            .ok()
            .filter(|n| (1..=60000).contains(n))
            .ok_or_else(|| AppError::new("usage", "--timeout-ms: ожидается 1..60000"))?;
        result["validation"] = crate::firewall_verify::verify(
            &firewall,
            Path::new(required("--nft")?),
            std::time::Duration::from_millis(timeout),
        )?;
        result["firewall"]["kernel_validation"] = json!("passed");
    }
    Ok(result)
}
