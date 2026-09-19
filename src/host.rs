use crate::{
    error::{AppError, Result},
    process,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

const QUEUE: u64 = 220;

pub fn run(args: &[&str]) -> Result<Value> {
    let Some(("inspect", options)) = args.split_first().map(|(head, tail)| (*head, tail)) else {
        return Err(AppError::new(
            "usage",
            "Требуется host inspect --nft FILE [--timeout-ms N]",
        ));
    };
    let mut values = BTreeMap::new();
    let (pairs, rest) = options.as_chunks::<2>();
    for [key, value] in pairs {
        if !["--nft", "--timeout-ms"].contains(key)
            || value.is_empty()
            || value.starts_with("--")
            || values.insert(*key, *value).is_some()
        {
            return Err(AppError::new(
                "usage",
                "Неизвестный, повторный параметр или нет значения",
            ));
        }
    }
    if !rest.is_empty() {
        return Err(AppError::new("usage", "Параметр без значения"));
    }
    let binary = values
        .get("--nft")
        .ok_or_else(|| AppError::new("usage", "Требуется --nft"))?;
    let millis = values
        .get("--timeout-ms")
        .unwrap_or(&"5000")
        .parse::<u64>()
        .ok()
        .filter(|n| (1..=60000).contains(n))
        .ok_or_else(|| AppError::new("usage", "--timeout-ms: ожидается 1..60000"))?;
    let timeout = Duration::from_millis(millis);
    let net = namespace("/proc/self/ns/net");
    let user = namespace("/proc/self/ns/user");
    let processes = inspect_processes(net.as_deref(), timeout);
    let legacy = inspect_legacy();
    let nft = inspect_nft(Path::new(binary), timeout);
    let complete = net.is_some()
        && user.is_some()
        && processes["complete"] == true
        && legacy["complete"] == true
        && nft["complete"] == true;
    let conflict = processes["nfqws"]
        .as_array()
        .is_some_and(|entries| entries.iter().any(|entry| entry["network"] == "same"))
        || nft["known_tables"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
        || nft["queues"].as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry["conflicts_with_queue220"] == true || entry["kind"] == "xt")
        });
    Ok(json!({"host": {
        "status": if conflict { "conflicts" } else if complete { "clear" } else { "incomplete" },
        "complete": complete,
        "scope": "current_network_namespace",
        "namespaces": {"net": net, "user": user},
        "host_run_supported": true,
        "inspection_authorizes_run": false,
        "queue": QUEUE,
        "nft": nft,
        "processes": processes,
        "legacy_iptables": legacy,
        "limitations": [
            "Read-only snapshot; processes and firewall rules can change during or after inspection.",
            "Inactive services that may start later are not inspected.",
            "Process discovery uses visible /proc executable names and comm names; it cannot identify renamed binaries or processes hidden by another PID namespace.",
            "Unsupported nft objects/statements and dynamic queues remain incomplete; rule reachability is not inferred.",
            "Legacy iptables rules are not enumerated; nonempty or unavailable table lists remain incomplete."
        ]
    }}))
}

fn namespace(path: impl AsRef<Path>) -> Option<String> {
    let value = fs::read_link(path)
        .ok()?
        .into_os_string()
        .into_string()
        .ok()?;
    let (kind, id) = value.split_once(":[")?;
    let number = id.strip_suffix(']')?;
    if !["net", "user"].contains(&kind) || number.parse::<u64>().ok()? == 0 {
        return None;
    }
    Some(value)
}

fn bounded_text(path: impl AsRef<Path>, limit: u64) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("read limit exceeded"));
    }
    String::from_utf8(bytes).map_err(|_| std::io::Error::other("invalid UTF-8"))
}

fn nfqws_name(name: &str) -> bool {
    name.strip_suffix(" (deleted)")
        .unwrap_or(name)
        .starts_with("nfqws")
}

fn inspect_processes(net: Option<&str>, timeout: Duration) -> Value {
    let mut matches = Vec::new();
    let mut unreadable = 0_u64;
    let mut scanned = 0_u64;
    let mut bounded = false;
    let started = Instant::now();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries {
            if scanned >= 65536 || started.elapsed() >= timeout {
                bounded = true;
                break;
            }
            let Ok(entry) = entry else {
                unreadable += 1;
                continue;
            };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            scanned += 1;
            let dir = entry.path();
            let stat = bounded_text(dir.join("stat"), 8192);
            let Some(fields) = stat
                .as_ref()
                .ok()
                .and_then(|s| s.rsplit_once(") "))
                .map(|(_, s)| s)
            else {
                unreadable += 1;
                continue;
            };
            let mut fields = fields.split_whitespace();
            let state = fields.next();
            if matches!(state, Some("Z" | "X" | "x")) {
                continue;
            }
            if !matches!(state, Some("R" | "S" | "D" | "T" | "t" | "W" | "I" | "P")) {
                unreadable += 1;
                continue;
            }
            // stat field 9 is flags; kernel threads have no executable image.
            if fields
                .nth(5)
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|flags| flags & 0x0020_0000 != 0)
            {
                continue;
            }
            let comm = bounded_text(dir.join("comm"), 256);
            let exe = fs::read_link(dir.join("exe"));
            let known = comm.as_ref().ok().is_some_and(|s| nfqws_name(s.trim_end()))
                || exe
                    .as_ref()
                    .ok()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                    .is_some_and(nfqws_name);
            if comm.is_err() || exe.is_err() {
                unreadable += 1;
            }
            if !known {
                continue;
            }
            if matches.len() >= 1024 {
                bounded = true;
                break;
            }
            let process_net = namespace(dir.join("ns/net"));
            let network = match (net, process_net.as_deref()) {
                (Some(current), Some(other)) if current == other => "same",
                (Some(_), Some(_)) => "other",
                _ => {
                    unreadable += 1;
                    "unknown"
                }
            };
            matches.push(json!({"pid": pid, "network": network, "net": process_net}));
        }
    } else {
        unreadable += 1;
    }
    // hidepid can omit entire directories, so successful visible reads are insufficient.
    let restricted_proc = bounded_text("/proc/mounts", 65536)
        .map(|mounts| {
            mounts.lines().any(|line| {
                line.split_whitespace().nth(2) == Some("proc")
                    && line.split_whitespace().nth(3).is_some_and(|options| {
                        options
                            .split(',')
                            .any(|option| option.starts_with("hidepid=") && option != "hidepid=0")
                    })
            })
        })
        .unwrap_or(true);
    // A complete visible scan cannot prove coverage of the network: a fresh
    // procfs in a child PID namespace hides processes in the same network.
    // NS_GET_PARENT cannot prove initial namespace membership either: EPERM
    // also means the parent is inaccessible. Do not certify global coverage.
    json!({"complete": false, "scope": "visible_proc",
        "coverage": "unverified_pid_namespace_coverage",
        "visible_scan_complete": unreadable == 0 && !bounded && !restricted_proc && net.is_some(),
        "scanned": scanned, "unreadable": unreadable, "bounded": bounded,
        "restricted_proc": restricted_proc, "nfqws": matches})
}

fn inspect_legacy() -> Value {
    let mut complete = true;
    let families: Vec<Value> = [
        ("ipv4", "/proc/net/ip_tables_names"),
        ("ipv6", "/proc/net/ip6_tables_names"),
    ]
    .into_iter()
    .map(|(family, path)| {
        let (status, tables) = match bounded_text(path, 8192) {
            Ok(text) => {
                let names: Vec<&str> = text.lines().collect();
                if names.iter().any(|name| {
                    name.is_empty()
                        || name.len() > 32
                        || !name
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                }) {
                    ("malformed", Vec::new())
                } else if names.is_empty() {
                    ("empty", Vec::new())
                } else {
                    (
                        "requires_inspection",
                        names.into_iter().map(str::to_owned).collect(),
                    )
                }
            }
            Err(_) => ("unavailable", Vec::new()),
        };
        complete &= status == "empty";
        json!({"family": family, "path": path, "status": status, "tables": tables})
    })
    .collect();
    json!({"complete": complete, "families": families})
}

fn nft_failure(status: &str, diagnostic: &str) -> Value {
    json!({"status": status, "complete": false, "known_tables": [], "queues": [], "diagnostic": diagnostic})
}

pub(crate) fn inspect_nft(binary: &Path, timeout: Duration) -> Value {
    let Ok(binary) = binary.canonicalize() else {
        return nft_failure("unavailable", "Cannot resolve the explicit nft executable");
    };
    let mut command = Command::new(binary);
    command
        .args(["--json", "list", "ruleset"])
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C");
    let output = match process::capture(command, &[], timeout) {
        Ok(output) => output,
        Err(error) => {
            return nft_failure(
                if error.kind == "timeout" {
                    "timeout"
                } else {
                    "unavailable"
                },
                "The read-only nft command could not complete; captured rule text is omitted",
            );
        }
    };
    if output.truncated {
        return nft_failure("truncated", "nft output exceeded the capture limit");
    }
    if !output.status.success() {
        let mut report = nft_failure(
            "failed",
            "nft list ruleset exited unsuccessfully; rule text is omitted",
        );
        report["exit_code"] = json!(output.status.code());
        return report;
    }
    if !output.stdout_valid_utf8 {
        return nft_failure("invalid_utf8", "nft stdout is not UTF-8");
    }
    let Ok(value) = serde_json::from_str::<Value>(&output.stdout) else {
        return nft_failure("malformed", "nft stdout is not valid JSON");
    };
    inspect_ruleset(&value)
}

fn name(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty() && name.len() <= 256 && !name.contains('\0'))
}

fn family(value: &Value) -> bool {
    value
        .get("family")
        .and_then(Value::as_str)
        .is_some_and(|family| ["inet", "ip", "ip6", "arp", "bridge", "netdev"].contains(&family))
}

// libnftables-json(5): statements that cannot enqueue packets are inspected
// by their documented outer shape, not by reimplementing firewall semantics.
fn fields(body: &Value, allowed: &[&str]) -> bool {
    body.as_object()
        .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
}

fn optional(body: &Value, key: &str, valid: impl FnOnce(&Value) -> bool) -> bool {
    body.get(key).is_none_or(valid)
}

fn nonnull(value: &Value) -> bool {
    !value.is_null()
}

fn flags(value: &Value, allowed: &[&str]) -> bool {
    let valid = |v: &Value| v.as_str().is_some_and(|s| allowed.contains(&s));
    valid(value)
        || value
            .as_array()
            .is_some_and(|items| items.iter().all(valid))
}

pub(crate) fn diagnostic_label(value: &str) -> String {
    value
        .chars()
        .take(64)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[derive(Default)]
struct Statements {
    queues: Vec<Value>,
    malformed: bool,
    unsupported: bool,
    dynamic: bool,
    details: BTreeSet<String>,
}

impl Statements {
    fn detail(&mut self, message: String) {
        if self.details.len() < 8 {
            self.details.insert(message);
        }
    }

    fn inspect(&mut self, statement: &Value, rule: &Value, depth: usize) {
        if depth > 32 {
            self.unsupported = true;
            self.detail("statement nesting limit".into());
            return;
        }
        let Some(object) = statement.as_object().filter(|o| o.len() == 1) else {
            self.malformed = true;
            self.detail("malformed statement".into());
            return;
        };
        let (kind, body) = object.iter().next().expect("one statement");
        let valid = match kind.as_str() {
            "queue" => {
                let (item, valid, uncertain) = inspect_queue(body, rule);
                self.queues.push(item);
                self.dynamic |= uncertain;
                if uncertain {
                    self.detail("dynamic queue".into());
                }
                valid
            }
            "accept" | "drop" | "continue" | "return" | "notrack" => body.is_null(),
            "jump" | "goto" => fields(body, &["target"]) && name(body, "target"),
            "counter" => {
                fields(body, &["packets", "bytes"])
                    && body["packets"].as_u64().is_some()
                    && body["bytes"].as_u64().is_some()
            }
            "match" => {
                fields(body, &["op", "left", "right"])
                    && name(body, "op")
                    && body.get("left").is_some_and(nonnull)
                    && body.get("right").is_some_and(nonnull)
            }
            "xt" => {
                if !fields(body, &["type", "name"]) || !name(body, "type") || !name(body, "name") {
                    false
                } else {
                    let target = body["name"].as_str().unwrap();
                    match body["type"].as_str().unwrap() {
                        // xt matches return a match result, never a verdict.
                        "match" => true,
                        "target" if matches!(target, "NFQUEUE" | "QUEUE") => {
                            // Compat JSON omits the target payload, including queue number.
                            self.queues.push(
                                json!({"family": rule["family"], "table": rule["table"],
                                "chain": rule["chain"], "kind": "xt", "target": target,
                                "conflicts_with_queue220": null}),
                            );
                            self.dynamic = true;
                            self.detail(format!("xt target {target}: queue number unavailable"));
                            true
                        }
                        "target"
                            if matches!(
                                target,
                                "LOG" | "REJECT" | "DNAT" | "SNAT" | "MASQUERADE" | "REDIRECT"
                            ) =>
                        {
                            true
                        }
                        "target" | "watcher" => {
                            self.unsupported = true;
                            self.detail(format!(
                                "xt {} {}",
                                diagnostic_label(body["type"].as_str().unwrap()),
                                diagnostic_label(target)
                            ));
                            true
                        }
                        _ => false,
                    }
                }
            }
            "limit" => {
                fields(
                    body,
                    &["rate", "rate_unit", "per", "burst", "burst_unit", "inv"],
                ) && body["rate"].as_u64().is_some()
                    && name(body, "per")
                    && optional(body, "burst", |v| v.as_u64().is_some())
                    && optional(body, "inv", Value::is_boolean)
                    && optional(body, "rate_unit", Value::is_string)
                    && optional(body, "burst_unit", Value::is_string)
            }
            "log" => {
                body.is_null()
                    || (fields(
                        body,
                        &[
                            "prefix",
                            "group",
                            "snaplen",
                            "queue-threshold",
                            "level",
                            "flags",
                        ],
                    ) && optional(body, "prefix", Value::is_string)
                        && ["group", "snaplen", "queue-threshold"]
                            .iter()
                            .all(|k| optional(body, k, |v| v.as_u64().is_some()))
                        && optional(body, "level", |v| {
                            flags(
                                v,
                                &[
                                    "emerg", "alert", "crit", "err", "warn", "notice", "info",
                                    "debug", "audit",
                                ],
                            ) && v.is_string()
                        })
                        && optional(body, "flags", |v| {
                            flags(
                                v,
                                &[
                                    "tcp sequence",
                                    "tcp options",
                                    "ip options",
                                    "skuid",
                                    "ether",
                                    "all",
                                ],
                            )
                        }))
            }
            "reject" => {
                body.is_null()
                    || (fields(body, &["type", "expr"])
                        && optional(body, "type", |v| {
                            v.as_str().is_some_and(|s| {
                                ["tcp reset", "icmpx", "icmp", "icmpv6"].contains(&s)
                            })
                        })
                        && optional(body, "expr", nonnull))
            }
            "snat" | "dnat" | "masquerade" | "redirect" => {
                let address = matches!(kind.as_str(), "snat" | "dnat");
                (!address && body.is_null())
                    || (fields(
                        body,
                        if address {
                            &["addr", "family", "port", "flags"]
                        } else {
                            &["port", "flags"]
                        },
                    ) && optional(body, "addr", nonnull)
                        && optional(body, "port", nonnull)
                        && optional(body, "family", |v| {
                            v.as_str().is_some_and(|s| ["ip", "ip6"].contains(&s))
                        })
                        && optional(body, "flags", |v| {
                            flags(v, &["random", "fully-random", "persistent"])
                        }))
            }
            "mangle" => {
                fields(body, &["key", "value"])
                    && body.get("key").is_some_and(Value::is_object)
                    && body.get("value").is_some_and(nonnull)
            }
            "meter" => {
                // Unlike ordinary expressions, stmt contains an executable statement.
                // Inspect it even if another meter property is malformed.
                if let Some(nested) = body.get("stmt") {
                    self.inspect(nested, rule, depth + 1);
                }
                fields(body, &["name", "key", "stmt"])
                    && name(body, "name")
                    && body.get("key").is_some_and(nonnull)
                    && body.get("stmt").is_some()
            }
            _ => {
                self.unsupported = true;
                self.detail(format!("statement {}", diagnostic_label(kind)));
                true
            }
        };
        if !valid {
            self.malformed = true;
            self.detail(format!("malformed {}", diagnostic_label(kind)));
        }
    }
}

fn inspect_ruleset(value: &Value) -> Value {
    let Some(entries) = value
        .as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get("nftables"))
        .and_then(Value::as_array)
    else {
        return nft_failure("malformed", "Expected one nftables array");
    };
    let mut known_tables = Vec::new();
    let mut inspected = Statements::default();
    let mut tables = BTreeSet::new();
    let mut chains = BTreeSet::new();
    let mut malformed = false;

    for entry in entries {
        let Some(object) = entry.as_object().filter(|o| o.len() == 1) else {
            malformed = true;
            continue;
        };
        let (kind, data) = object.iter().next().expect("one entry");
        if !data.is_object() {
            malformed = true;
            continue;
        }
        match kind.as_str() {
            "metainfo" => {
                if data["json_schema_version"] != 1 || !name(data, "version") {
                    malformed = true;
                }
            }
            "table" => {
                if !family(data) || !name(data, "name") {
                    malformed = true;
                    continue;
                }
                if !tables.insert((
                    data["family"].as_str().unwrap(),
                    data["name"].as_str().unwrap(),
                )) {
                    malformed = true;
                }
                if ["zapret", "zapretunix", "zapret_rs", "zapret_rs_probe"]
                    .contains(&data["name"].as_str().unwrap())
                {
                    known_tables.push(json!({"family": data["family"], "name": data["name"]}));
                }
            }
            "chain" => {
                if !family(data) || !name(data, "table") || !name(data, "name") {
                    malformed = true;
                    continue;
                }
                if !chains.insert((
                    data["family"].as_str().unwrap(),
                    data["table"].as_str().unwrap(),
                    data["name"].as_str().unwrap(),
                )) {
                    malformed = true;
                }
            }
            "rule" => {
                if !family(data) || !name(data, "table") || !name(data, "chain") {
                    malformed = true;
                    continue;
                }
                let Some(statements) = data["expr"].as_array() else {
                    malformed = true;
                    continue;
                };
                for statement in statements {
                    inspected.inspect(statement, data, 0);
                }
            }
            _ => {
                inspected.unsupported = true;
                inspected.detail(format!("object {}", diagnostic_label(kind)));
            }
        }
    }
    for (family, table, _) in &chains {
        malformed |= !tables.contains(&(*family, *table));
    }
    for entry in entries {
        if let Some(rule) = entry.get("rule")
            && let (Some(f), Some(t), Some(c)) = (
                rule["family"].as_str(),
                rule["table"].as_str(),
                rule["chain"].as_str(),
            )
        {
            malformed |= !chains.contains(&(f, t, c));
        }
    }
    malformed |= inspected.malformed;
    let unsupported = inspected.unsupported;
    let dynamic = inspected.dynamic;
    let complete = !malformed && !unsupported && !dynamic;
    json!({"status": if malformed { "malformed" } else if unsupported || dynamic { "incomplete" } else { "inspected" },
        "complete": complete, "known_tables": known_tables, "queues": inspected.queues,
        "inspection_details": inspected.details,
        "unsupported_objects_or_statements": unsupported, "dynamic_queues": dynamic,
        "diagnostic": if malformed { Some("Invalid nft object structure or references") } else if unsupported || dynamic {
            Some("Unsupported nft objects/statements or a dynamic queue prevent complete inspection")
        } else { None }})
}

fn inspect_queue(body: &Value, rule: &Value) -> (Value, bool, bool) {
    let mut item = json!({"family": rule["family"], "table": rule["table"], "chain": rule["chain"],
        "kind": "invalid", "conflicts_with_queue220": null});
    let Some(body) = body.as_object() else {
        return (item, false, false);
    };
    if body
        .keys()
        .any(|key| !["num", "flags"].contains(&key.as_str()))
    {
        return (item, false, false);
    }
    if let Some(flags) = body.get("flags") {
        let flag = |v: &Value| {
            v.as_str()
                .is_some_and(|s| ["bypass", "fanout"].contains(&s))
        };
        if !flag(flags) && !flags.as_array().is_some_and(|a| a.iter().all(flag)) {
            return (item, false, false);
        }
    }
    // An omitted num is nft's default queue 0.
    let zero = json!(0);
    let num = body.get("num").unwrap_or(&zero);
    if let Some(number) = num.as_u64().filter(|n| *n <= 65535) {
        item["kind"] = json!("number");
        item["number"] = json!(number);
        item["conflicts_with_queue220"] = json!(number == QUEUE);
        return (item, true, false);
    }
    if let Some(range) = num.get("range") {
        if num.as_object().is_none_or(|o| o.len() != 1) {
            return (item, false, false);
        }
        if let Some(range) = range.as_array().filter(|a| a.len() == 2)
            && let (Some(start), Some(end)) = (range[0].as_u64(), range[1].as_u64())
            && start <= end
            && end <= 65535
        {
            item["kind"] = json!("range");
            item["range"] = json!([start, end]);
            item["conflicts_with_queue220"] = json!((start..=end).contains(&QUEUE));
            return (item, true, false);
        }
        return (item, false, false);
    }
    if num.is_object() || num.is_string() {
        item["kind"] = json!("dynamic");
        return (item, true, true);
    }
    (item, false, false)
}
