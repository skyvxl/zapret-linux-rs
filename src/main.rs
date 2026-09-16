mod config;
mod error;
mod input;

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
            println!("zapret-linux-rs — проверка конфигурации\n\nconfig validate FILE\n--help");
            Ok(())
        }
        ["config", "validate", file] => {
            let config = config::Config::load(Path::new(file))?;
            println!("{}", json!({"config": config.json()}));
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
