use crate::{
    config::{Backend, Config},
    error::{AppError, Result},
    runtime::{FWMARK, QUEUE_NUM},
    strategy::Plan,
};
use serde_json::{Value, json};

pub const TABLE: &str = "zapret_rs";

fn fail(message: impl Into<String>) -> AppError {
    AppError::new("firewall", message)
}

struct PortSet(Vec<(u16, u16)>);

impl PortSet {
    fn parse(text: &str) -> Result<Self> {
        let mut ranges = Vec::new();
        if text.is_empty() {
            return Ok(Self(ranges));
        }
        for part in text.split(',') {
            let (low, high) = part.split_once('-').unwrap_or((part, part));
            let parse = |text: &str| -> Result<u16> {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(fail("Порт должен состоять из цифр"));
                }
                text.parse::<u16>()
                    .ok()
                    .filter(|n| *n != 0)
                    .ok_or_else(|| fail("Порт должен находиться в диапазоне 1..65535"))
            };
            let (low, high) = (parse(low)?, parse(high)?);
            if low > high {
                return Err(fail("Начало диапазона портов больше конца"));
            }
            ranges.push((low, high));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::new();
        for (low, high) in ranges {
            if let Some(last) = merged.last_mut()
                && u32::from(low) <= u32::from(last.1) + 1
            {
                last.1 = last.1.max(high);
            } else {
                merged.push((low, high));
            }
        }
        Ok(Self(merged))
    }

    fn text(&self) -> String {
        self.0
            .iter()
            .map(|(low, high)| {
                if low == high {
                    low.to_string()
                } else {
                    format!("{low}-{high}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

pub struct FirewallPlan {
    tcp: PortSet,
    udp: PortSet,
    interface: Option<String>,
}

impl FirewallPlan {
    pub fn new(config: &Config, strategy: &Plan) -> Result<Self> {
        if matches!(config.backend, Backend::Iptables) {
            return Err(fail(
                "Backend iptables ещё не реализован; автоматическая смена запрещена",
            ));
        }
        let tcp = PortSet::parse(&strategy.tcp_ports)?;
        let udp = PortSet::parse(&strategy.udp_ports)?;
        if tcp.0.is_empty() && udp.0.is_empty() {
            return Err(fail("Нет портов для правил firewall"));
        }
        Ok(Self {
            tcp,
            udp,
            interface: (config.interface != "any").then(|| config.interface.clone()),
        })
    }

    pub fn rule_count(&self) -> usize {
        usize::from(!self.tcp.0.is_empty()) * 2 + usize::from(!self.udp.0.is_empty())
    }

    pub fn batch(&self) -> String {
        let mut batch = format!(
            "create table inet {TABLE} {{ comment \"zapret-linux-rs\"; }}\n\
             add chain inet {TABLE} post {{ type filter hook postrouting priority -150; policy accept; }}\n\
             add chain inet {TABLE} pre {{ type filter hook prerouting priority 0; policy accept; }}\n"
        );
        let interface = |direction| {
            self.interface
                .as_ref()
                .map(|name| format!("{direction}ifname \"{name}\" "))
                .unwrap_or_default()
        };
        for (protocol, ports) in [("tcp", &self.tcp), ("udp", &self.udp)] {
            if !ports.0.is_empty() {
                batch.push_str(&format!(
                    "add rule inet {TABLE} post {}meta mark & {FWMARK:#x} == 0 ct direction original {protocol} dport {{ {} }} ct original packets 1-6 counter queue num {QUEUE_NUM} bypass\n",
                    interface("o"), ports.text()
                ));
            }
        }
        if !self.tcp.0.is_empty() {
            batch.push_str(&format!(
                "add rule inet {TABLE} pre {}meta mark & {FWMARK:#x} == 0 ct direction reply tcp sport {{ {} }} ct reply packets 1-3 counter queue num {QUEUE_NUM} bypass\n",
                interface("i"), self.tcp.text()
            ));
        }
        batch
    }

    pub fn rollback(&self) -> String {
        format!("delete table inet {TABLE}\n")
    }

    pub fn json(&self) -> Value {
        json!({"backend": "nftables", "family": "inet", "table": TABLE,
            "tcp_ports": self.tcp.text(), "udp_ports": self.udp.text(),
            "interface": self.interface.as_deref().unwrap_or("any"),
            "queue_num": QUEUE_NUM, "fwmark": format!("{FWMARK:#x}"),
            "rule_count": self.rule_count(), "nft_batch": self.batch(), "rollback_batch": self.rollback(),
            "kernel_validation": "not_run", "network_validation": "not_run"})
    }
}
