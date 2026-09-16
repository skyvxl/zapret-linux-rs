use crate::{
    error::{AppError, Result},
    service_install::{self, Options},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub fn run(args: &[&str]) -> Result<Value> {
    let Some((&action, args)) = args.split_first() else {
        return Err(AppError::new("usage", "service requires an action"));
    };
    if ![
        "install",
        "uninstall",
        "remove",
        "status",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
    ]
    .contains(&action)
    {
        return Err(AppError::new("usage", "Unknown service action"));
    }
    let mut values = BTreeMap::new();
    let mut flags = BTreeSet::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i];
        if ["--start", "--enable", "--stop"].contains(&key) {
            if !flags.insert(key) {
                return Err(AppError::new("usage", "Repeated service flag"));
            }
            i += 1;
            continue;
        }
        if ![
            "--root",
            "--config",
            "--strategies",
            "--assets",
            "--nfqws",
            "--nft",
            "--iptables-save",
            "--ip6tables-save",
        ]
        .contains(&key)
        {
            return Err(AppError::new("usage", "Unknown service option"));
        }
        let value = args
            .get(i + 1)
            .filter(|s| !s.is_empty() && !s.starts_with("--"))
            .ok_or_else(|| AppError::new("usage", "Missing service option value"))?;
        if values.insert(key, *value).is_some() {
            return Err(AppError::new("usage", "Repeated service option"));
        }
        i += 2;
    }
    if (action != "install" && values.keys().any(|k| *k != "--root"))
        || flags.iter().any(|f| match *f {
            "--stop" => !["remove", "uninstall"].contains(&action),
            _ => action != "install",
        })
    {
        return Err(AppError::new(
            "usage",
            "Option is not supported for this service action",
        ));
    }
    if action == "install" {
        for key in [
            "--config",
            "--strategies",
            "--assets",
            "--nfqws",
            "--nft",
            "--iptables-save",
            "--ip6tables-save",
        ] {
            if !values.contains_key(key) {
                return Err(AppError::new("usage", format!("Required {key}")));
            }
        }
    }
    let options = Options {
        root: values.get("--root").copied().unwrap_or("/"),
        values,
        start: flags.contains("--start"),
        enable: flags.contains("--enable"),
        stop: flags.contains("--stop"),
    };
    service_install::run(action, &options)
}
