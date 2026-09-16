mod config;
mod error;
mod firewall;
mod firewall_cli;
mod firewall_verify;
mod host;
mod input;
mod lifecycle;
mod namespace;
mod nft;
mod output;
mod owned_table;
mod process;
mod queue_probe;
mod runtime;
mod signals;
mod state_cli;
mod state_dir;
mod state_record;
mod strategy;
mod validation;

use error::{AppError, Result};
use serde_json::json;
use std::{env, path::Path, process::ExitCode};

fn run() -> Result<()> {
    let args: Vec<String> = env::args_os()
        .skip(1)
        .map(|a| {
            a.into_string()
                .map_err(|_| AppError::new("usage", "Аргументы должны быть UTF-8"))
        })
        .collect::<Result<_>>()?;
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--help"] | ["-h"] => {
            println!(
                "zapret-linux-rs — проверка конфигурации\n\nconfig validate FILE\nstrategy explain FILE --assets DIR [-gt] [-gu]\nrun --dry-run --config FILE --strategies DIR --assets DIR --nfqws FILE [--timeout-ms N]\nrun --isolated --config FILE --strategies DIR --assets DIR --nfqws FILE --nft FILE [--timeout-ms N] [--run-for-ms N] [--state-dir DIR]\nfirewall plan --config FILE --strategies DIR --assets DIR\nfirewall verify --config FILE --strategies DIR --assets DIR --nft FILE [--timeout-ms N]\nhost inspect --nft FILE [--timeout-ms N]\nstate inspect --state-dir DIR\nstate recover --state-dir DIR --nft FILE [--timeout-ms N]\n--help"
            );
            Ok(())
        }
        ["config", "validate", file] => {
            let config = config::Config::load(Path::new(file))?;
            println!("{}", json!({"config": config.json()}));
            Ok(())
        }
        ["strategy", "explain", file, "--assets", assets, flags @ ..] => {
            let mut tcp = false;
            let mut udp = false;
            for flag in flags {
                match *flag {
                    "-gt" | "--gamefilter-tcp" if !tcp => tcp = true,
                    "-gu" | "--gamefilter-udp" if !udp => udp = true,
                    _ => {
                        return Err(AppError::new(
                            "usage",
                            "Неизвестный или повторный флаг GameFilter",
                        ));
                    }
                }
            }
            let plan = strategy::Plan::load(Path::new(file), Path::new(assets), tcp, udp)?;
            println!("{}", json!({"plan": plan.json(false)}));
            Ok(())
        }
        ["run", options @ ..] => {
            if options.contains(&"--isolated") {
                return lifecycle::run(options);
            }
            println!("{}", validation::run(options)?);
            Ok(())
        }
        ["firewall", options @ ..] => {
            println!("{}", firewall_cli::run(options)?);
            Ok(())
        }
        ["state", options @ ..] => {
            println!("{}", state_cli::run(options)?);
            Ok(())
        }
        ["host", options @ ..] => {
            println!("{}", host::run(options)?);
            Ok(())
        }
        _ => Err(AppError::new(
            "usage",
            "Использование: config validate FILE; справка: --help",
        )),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.json());
            ExitCode::from(if error.kind == "usage" { 2 } else { 1 })
        }
    }
}
