use crate::{
    error::{AppError, Result},
    input,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::Ipv6Addr, path::Path};

#[derive(Clone)]
pub enum Check {
    HttpSuccess,
    HttpReachable,
    BodyContains(String),
    GatewayJson,
}

impl Check {
    pub fn json(&self) -> Value {
        match self {
            Self::HttpSuccess => json!("http-success"),
            Self::HttpReachable => json!("http-reachable"),
            Self::BodyContains(marker) => json!({"type":"body-contains", "marker":marker}),
            Self::GatewayJson => json!("gateway-json"),
        }
    }
}

#[derive(Clone)]
pub struct Target {
    pub id: String,
    pub service: String,
    pub url: String,
    pub check: Check,
    pub required: bool,
}

fn invalid(message: &str) -> AppError {
    AppError::new("targets", message)
}

// Deliberately narrow URL grammar; curl still performs the actual URL parsing.
// Keeping the authority ASCII and escape-free prevents hidden credentials and
// disagreements about backslashes, percent-encoded delimiters or empty hosts.
pub fn valid_url(url: &str, schemes: &[&str]) -> bool {
    if url.len() > 2048
        || !url.is_ascii()
        || url
            .bytes()
            .any(|b| b <= b' ' || b == 127 || b == b'\\' || b == b'#')
    {
        return false;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !schemes.contains(&scheme) {
        return false;
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains(['@', '%']) {
        return false;
    }
    let port = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((address, suffix)) = ipv6.split_once(']') else {
            return false;
        };
        if address.parse::<Ipv6Addr>().is_err() {
            return false;
        }
        if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        }
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.len() > 253
            || host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return false;
        }
        if host.trim_end_matches('.').split('.').any(|part| {
            part.is_empty() || part.len() > 63 || part.starts_with('-') || part.ends_with('-')
        }) {
            return false;
        }
        port
    };
    port.is_none_or(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|n| n != 0)
    })
}

impl Target {
    pub fn json(&self) -> Value {
        json!({"id":self.id,"service":self.service,"url":self.url,"check":self.check.json(),"required":self.required})
    }
}

pub fn load(path: Option<&Path>) -> Result<Vec<Target>> {
    let data: Value = if let Some(path) = path {
        serde_json::from_str(&input::read_text(path)?)
            .map_err(|e| invalid(&format!("Неверный JSON целей: {e}")))?
    } else {
        json!([
            {"id":"youtube-main","service":"youtube","url":"https://www.youtube.com/","check":{"type":"body-contains","marker":"youtube"},"required":true},
            {"id":"youtube-cdn","service":"youtube","url":"https://redirector.googlevideo.com/","check":"http-reachable","required":true},
            {"id":"discord-main","service":"discord","url":"https://discord.com/","check":"http-success","required":true},
            {"id":"discord-gateway","service":"discord","url":"https://discord.com/api/v10/gateway","check":"gateway-json","required":true}
        ])
    };
    let list = data
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 32)
        .ok_or_else(|| invalid("Ожидается массив от 1 до 32 целей"))?;
    let mut ids = BTreeSet::new();
    list.iter()
        .map(|item| {
            let object = item
                .as_object()
                .filter(|o| {
                    o.len() == 5
                        && o.keys().all(|k| {
                            ["id", "service", "url", "check", "required"].contains(&k.as_str())
                        })
                })
                .ok_or_else(|| invalid("Цель: нужны только id, service, url, check, required"))?;
            let token = |name: &str| -> Result<String> {
                let value = object[name]
                    .as_str()
                    .filter(|s| {
                        !s.is_empty()
                            && s.len() <= 64
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    })
                    .ok_or_else(|| {
                        invalid("id/service: ожидается 1..64 ASCII букв, цифр, '-', '_' или '.'")
                    })?;
                Ok(value.to_owned())
            };
            let id = token("id")?;
            if !ids.insert(id.clone()) {
                return Err(invalid("Повторный id цели"));
            }
            let service = token("service")?;
            let url = object["url"]
                .as_str()
                .filter(|s| valid_url(s, &["http", "https"]))
                .ok_or_else(|| invalid("Неверный HTTP/HTTPS URL или URL с учётными данными"))?
                .to_owned();
            let required = object["required"]
                .as_bool()
                .ok_or_else(|| invalid("required должен быть boolean"))?;
            let check = match &object["check"] {
                Value::String(s) if s == "http-success" => Check::HttpSuccess,
                Value::String(s) if s == "http-reachable" => Check::HttpReachable,
                Value::String(s) if s == "gateway-json" => Check::GatewayJson,
                Value::Object(o)
                    if o.len() == 2
                        && o.get("type").and_then(Value::as_str) == Some("body-contains") =>
                {
                    let marker = o
                        .get("marker")
                        .and_then(Value::as_str)
                        .filter(|s| {
                            !s.is_empty()
                                && s.len() <= 256
                                && s.is_ascii()
                                && !s.bytes().any(|b| b.is_ascii_control())
                        })
                        .ok_or_else(|| {
                            invalid("body-contains.marker: 1..256 печатных ASCII символов")
                        })?;
                    Check::BodyContains(marker.to_ascii_lowercase())
                }
                _ => return Err(invalid("Неизвестный check")),
            };
            Ok(Target {
                id,
                service,
                url,
                check,
                required,
            })
        })
        .collect()
}
