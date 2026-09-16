use crate::{
    error::{AppError, Result},
    input::read_text,
};
use serde_json::{Value, json};
use std::path::{Component, Path, PathBuf};

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("strategy", message)
}

pub struct Plan {
    pub args: Vec<String>,
    pub tcp_ports: String,
    pub udp_ports: String,
    pub profile_count: usize,
    pub assets: PathBuf,
}

impl Plan {
    pub fn load(file: &Path, assets: &Path, tcp: bool, udp: bool) -> Result<Self> {
        let assets = assets
            .canonicalize()
            .map_err(|e| fail(format!("Каталог данных: {e}")))?;
        if !assets.is_dir() {
            return Err(fail("Данные должны находиться в каталоге"));
        }
        let tokens = command_tokens(&read_text(file)?)?;
        let mut tcp_ports = None;
        let mut udp_ports = None;
        let mut groups: Vec<(Vec<String>, bool)> = Vec::new();
        let mut current = Vec::new();
        for token in tokens {
            if let Some(raw) = token.strip_prefix("--wf-tcp=") {
                if tcp_ports.is_some() || !current.is_empty() || !groups.is_empty() {
                    return Err(fail("Повторный или misplaced --wf-tcp"));
                }
                tcp_ports = Some(ports(raw, tcp, udp)?);
            } else if let Some(raw) = token.strip_prefix("--wf-udp=") {
                if udp_ports.is_some() || !current.is_empty() || !groups.is_empty() {
                    return Err(fail("Повторный или misplaced --wf-udp"));
                }
                udp_ports = Some(ports(raw, tcp, udp)?);
            } else if token == "--new" {
                if current.is_empty() {
                    return Err(fail("Пустой профиль перед --new"));
                }
                groups.push((std::mem::take(&mut current), true));
            } else {
                validate_option(&token)?;
                current.push(token);
            }
        }
        if !current.is_empty() {
            groups.push((current, false));
        }
        if tcp_ports.is_none() && udp_ports.is_none() {
            return Err(fail("Нет --wf-tcp или --wf-udp"));
        }
        let mut args = Vec::new();
        let mut count = 0;
        for (group, has_separator) in groups {
            let mut transports = group.iter().filter(|token| {
                token.starts_with("--filter-tcp=") || token.starts_with("--filter-udp=")
            });
            let transport = transports
                .next()
                .ok_or_else(|| fail("Профиль должен содержать --filter-tcp или --filter-udp"))?;
            if transports.next().is_some() {
                return Err(fail("Поддерживается один транспортный фильтр на профиль"));
            }
            let raw = transport.split_once('=').unwrap().1;
            let selected_ports = ports(raw, tcp, udp)?;
            if selected_ports.is_empty() {
                continue;
            }
            count += 1;
            for token in group {
                let (key, value) = token.split_once('=').unwrap_or((&token, ""));
                if ["--filter-tcp", "--filter-udp"].contains(&key) {
                    let value = ports(value, tcp, udp)?;
                    if value.is_empty() {
                        return Err(fail("Пустой дополнительный фильтр"));
                    }
                    args.push(format!("{key}={value}"));
                } else if is_file_option(key) {
                    let value = asset_value(key, value, &assets)?;
                    args.push(format!("{key}={value}"));
                } else {
                    if value.contains('%') {
                        return Err(fail(format!("Неизвестная переменная: {token}")));
                    }
                    args.push(token);
                }
            }
            if has_separator {
                args.push("--new".to_string());
            }
        }
        if count == 0 {
            return Err(fail("Нет активных профилей"));
        }
        if args.len() > 4096 {
            return Err(fail("Слишком много аргументов"));
        }
        Ok(Self {
            args,
            tcp_ports: tcp_ports.unwrap_or_default(),
            udp_ports: udp_ports.unwrap_or_default(),
            profile_count: count,
            assets,
        })
    }

    pub fn json(&self, engine_validated: bool) -> Value {
        json!({"args": self.args, "tcp_ports": self.tcp_ports, "udp_ports": self.udp_ports,
            "profile_count": self.profile_count, "assets": self.assets,
            "engine_validation": if engine_validated { "passed" } else { "not_run" },
            "network_validation": "not_run"})
    }
}

fn command_tokens(content: &str) -> Result<Vec<String>> {
    let mut collected = String::new();
    let mut logical = String::new();
    let mut started = false;
    let mut saw_start = false;
    for (index, physical) in content.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = physical.trim();
        let lower = line.to_ascii_lowercase();
        if logical.is_empty()
            && (line.is_empty()
                || lower.starts_with("rem ")
                || lower == "rem"
                || lower.starts_with("::"))
        {
            continue;
        }
        let carets = line.chars().rev().take_while(|&c| c == '^').count();
        if carets % 2 == 1 {
            logical.push_str(&line[..line.len() - 1]);
            logical.push(' ');
            continue;
        }
        logical.push_str(line);
        let text = logical.trim();
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("start ") {
            if started || saw_start {
                return Err(fail("Несколько команд запуска не поддерживаются"));
            }
            let tokens = tokenize(text)?;
            let exe = tokens
                .iter()
                .position(|s| {
                    s.eq_ignore_ascii_case("%BIN%winws.exe") || s.eq_ignore_ascii_case("winws.exe")
                })
                .ok_or_else(|| fail("Не найдена команда winws.exe"))?;
            // Only the known launcher wrapper is accepted, never interpreted as a shell.
            for token in &tokens[1..exe] {
                if !token.eq_ignore_ascii_case("/min")
                    && !token.to_ascii_lowercase().starts_with("zapret")
                {
                    return Err(fail("Неизвестный параметр Windows start"));
                }
            }
            if exe + 1 == tokens.len() {
                return Err(fail("Команда без аргументов"));
            }
            collected.push_str(
                &tokens[exe + 1..]
                    .iter()
                    .map(|s| format!("\"{s}\" "))
                    .collect::<String>(),
            );
            started = true;
            saw_start = true;
        } else if text.starts_with("--") {
            collected.push_str(text);
            collected.push(' ');
            started = true;
        } else if !started && known_preamble(&lower) {
            // Flowseal's UI/setup preamble is imported as metadata, never run.
        } else if !text.is_empty() {
            return Err(fail(format!(
                "Строка {}: неподдерживаемая BAT-конструкция",
                index + 1
            )));
        }
        logical.clear();
    }
    if !logical.is_empty() {
        return Err(fail("Незавершённое продолжение строки ^"));
    }
    tokenize(&collected)
}

fn known_preamble(lower: &str) -> bool {
    lower == "@echo off"
        || lower == "echo off"
        || lower == "echo:"
        || lower.starts_with("chcp ")
        || lower.starts_with("cd /d ")
        || lower.starts_with("set \"bin=")
        || lower.starts_with("set \"lists=")
        || [
            "status_zapret",
            "check_updates",
            "load_game_filter",
            "load_user_lists",
        ]
        .iter()
        .any(|s| lower == format!("call service.bat {s}"))
}

fn tokenize(text: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '^' => match chars.next() {
                Some('!') => current.push('!'),
                _ => return Err(fail("Неподдерживаемое экранирование ^")),
            },
            '&' | '|' | '<' | '>' | '`' | '$' | ';' => {
                return Err(fail("Shell-операторы в команде не поддерживаются"));
            }
            c if c.is_control() && !c.is_whitespace() => {
                return Err(fail("Управляющий символ в команде"));
            }
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if quoted {
        return Err(fail("Незакрытая кавычка в BAT"));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn ports(raw: &str, tcp: bool, udp: bool) -> Result<String> {
    let mut values = Vec::new();
    for part in raw.split(',') {
        let replacement = match part {
            "%GameFilter%" if tcp || udp => "1024-65535",
            "%GameFilterTCP%" if tcp => "1024-65535",
            "%GameFilterUDP%" if udp => "1024-65535",
            "%GameFilterTCP%" | "%GameFilterUDP%" if tcp || udp => "12",
            "%GameFilter%" | "%GameFilterTCP%" | "%GameFilterUDP%" => continue,
            _ => part,
        };
        let mut ends = replacement.split('-');
        let parse = |s: &str| s.parse::<u16>().ok().filter(|&v| v > 0);
        let low = ends
            .next()
            .and_then(parse)
            .ok_or_else(|| fail(format!("Некорректный порт: {part}")))?;
        if let Some(high) = ends.next()
            && (parse(high).is_none_or(|h| h < low) || ends.next().is_some())
        {
            return Err(fail(format!("Некорректный диапазон: {part}")));
        }
        values.push(replacement);
    }
    Ok(values.join(","))
}

// Exact names supported by the nfqws v72.9 importer. Unknown options require
// explicit classification: getopt abbreviations and future file/process controls
// must never bypass path validation or change profile boundaries silently.
const FILE_OPTIONS: &[&str] = &[
    "--hostlist",
    "--hostlist-exclude",
    "--ipset",
    "--ipset-exclude",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-udplen-pattern",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-syndata",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-wireguard",
    "--dpi-desync-fake-dht",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown-udp",
];

const SCALAR_OPTIONS: &[&str] = &[
    "--comment",
    "--wsize",
    "--wssize",
    "--wssize-cutoff",
    "--wssize-forced-cutoff",
    "--synack-split",
    "--ctrack-timeouts",
    "--ctrack-disable",
    "--ipcache-lifetime",
    "--ipcache-hostname",
    "--hostcase",
    "--hostspell",
    "--hostnospace",
    "--domcase",
    "--methodeol",
    "--ip-id",
    "--dpi-desync",
    "--dup",
    "--dup-ttl",
    "--dup-ttl6",
    "--dup-autottl",
    "--dup-autottl6",
    "--dup-tcp-flags-set",
    "--dup-tcp-flags-unset",
    "--dup-fooling",
    "--dup-ts-increment",
    "--dup-badseq-increment",
    "--dup-badack-increment",
    "--dup-replace",
    "--dup-ip-id",
    "--dup-start",
    "--dup-cutoff",
    "--orig-ttl",
    "--orig-ttl6",
    "--orig-autottl",
    "--orig-autottl6",
    "--orig-tcp-flags-set",
    "--orig-tcp-flags-unset",
    "--orig-mod-start",
    "--orig-mod-cutoff",
    "--dpi-desync-ttl",
    "--dpi-desync-ttl6",
    "--dpi-desync-autottl",
    "--dpi-desync-autottl6",
    "--dpi-desync-tcp-flags-set",
    "--dpi-desync-tcp-flags-unset",
    "--dpi-desync-fooling",
    "--dpi-desync-repeats",
    "--dpi-desync-skip-nosni",
    "--dpi-desync-split-pos",
    "--dpi-desync-split-http-req",
    "--dpi-desync-split-tls",
    "--dpi-desync-split-seqovl",
    "--dpi-desync-fakedsplit-mod",
    "--dpi-desync-hostfakesplit-midhost",
    "--dpi-desync-hostfakesplit-mod",
    "--dpi-desync-ipfrag-pos-tcp",
    "--dpi-desync-ipfrag-pos-udp",
    "--dpi-desync-ts-increment",
    "--dpi-desync-badseq-increment",
    "--dpi-desync-badack-increment",
    "--dpi-desync-any-protocol",
    "--dpi-desync-fake-tcp-mod",
    "--dpi-desync-fake-tls-mod",
    "--dpi-desync-udplen-increment",
    "--dpi-desync-cutoff",
    "--dpi-desync-start",
    "--hostlist-domains",
    "--hostlist-exclude-domains",
    "--filter-l3",
    "--filter-tcp",
    "--filter-udp",
    "--filter-l7",
    "--ipset-ip",
    "--ipset-exclude-ip",
    "--bind-fix4",
    "--bind-fix6",
];

fn validate_option(token: &str) -> Result<()> {
    let key = token.split('=').next().unwrap();
    if !is_file_option(key) && !SCALAR_OPTIONS.contains(&key) {
        return Err(fail(format!(
            "Неподдерживаемый параметр: {key}; нужны полные имена поддержанных параметров nfqws, без управления процессом или профилями"
        )));
    }
    Ok(())
}

fn is_file_option(key: &str) -> bool {
    FILE_OPTIONS.contains(&key)
}

fn asset_value(key: &str, value: &str, assets: &Path) -> Result<String> {
    if key == "--dpi-desync-fake-tls"
        && (value == "!"
            || value
                .strip_prefix("!+")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())))
    {
        return Ok(value.to_string());
    }

    if key.starts_with("--dpi-desync-")
        && value.starts_with("0x")
        && value.len() > 2
        && value[2..].bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Ok(value.to_string());
    }
    let replaced = value
        .replace("%LISTS%", "lists/")
        .replace("%BIN%", "bin/")
        .replace('\\', "/");
    if replaced.contains('%') || replaced.is_empty() {
        return Err(fail(format!("Некорректный путь: {value}")));
    }
    let path = Path::new(&replaced);
    if path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(fail(
            "Файлы стратегии должны находиться внутри каталога данных",
        ));
    }
    let resolved = assets
        .join(path)
        .canonicalize()
        .map_err(|e| fail(format!("{value}: {e}")))?;
    if !resolved.starts_with(assets) || !resolved.is_file() {
        return Err(fail(format!("Недопустимый файл данных: {value}")));
    }
    resolved
        .into_os_string()
        .into_string()
        .map_err(|_| fail("Путь данных должен быть UTF-8"))
}
