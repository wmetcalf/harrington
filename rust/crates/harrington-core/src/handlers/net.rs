use crate::env::Environment;
use crate::handlers::util::split_words;
use crate::traits::{NetUseInfo, Trait};

pub fn h_net(raw: &str, env: &mut Environment) {
    let lower = raw.to_ascii_lowercase();
    if !lower.starts_with("net use") || lower.starts_with("net user") {
        return;
    }
    let tokens: Vec<String> = split_words(raw);
    if tokens.len() <= 2 {
        return;
    }
    let mut info = NetUseInfo::default();
    let mut extras: Vec<String> = Vec::new();
    for p in tokens.iter().skip(2) {
        let pl = p.to_ascii_lowercase();
        let p_unquoted = p.trim_matches('"').trim_matches('\'').to_string();
        if pl.starts_with("/sa") {
            info.options.push("savecred".into());
            continue;
        }
        if pl.starts_with("/sm") {
            info.options.push("smartcard".into());
            continue;
        }
        if pl.starts_with("/d") {
            let v = if pl.split(':').nth(1).is_some_and(|x| x.starts_with('n')) {
                "not-delete"
            } else {
                "delete"
            };
            info.options.push(v.into());
            continue;
        }
        if pl.starts_with("/p") {
            let v = if pl.split(':').nth(1).is_some_and(|x| x.starts_with('n')) {
                "not-persistent"
            } else {
                "persistent"
            };
            info.options.push(v.into());
            continue;
        }
        if pl.starts_with("/u") {
            if let Some(v) = p.split(':').nth(1) {
                info.user = Some(v.to_string());
            }
            continue;
        }
        if pl.starts_with("/y") {
            info.options.push("auto-accept".into());
            continue;
        }
        if pl.starts_with("/n") {
            info.options.push("auto-decline".into());
            continue;
        }
        extras.push(p_unquoted);
    }
    if extras.is_empty() {
        return;
    }
    let first = extras[0].clone();
    if first == "*" || (first.len() == 2 && first.ends_with(':')) {
        info.devicename = Some(extras.remove(0));
    }
    if !extras.is_empty() {
        info.server = Some(extras.remove(0));
    }
    if !extras.is_empty() {
        info.password = Some(extras.remove(0));
    }
    if !extras.is_empty() {
        let server = info.server.take().unwrap_or_default();
        let pwd = info.password.take().unwrap_or_default();
        let combined = format!("{} {} {}", server, pwd, extras.join(" "));
        info.server = Some(combined.trim().to_string());
    }
    env.traits.push(Trait::NetUse {
        cmd: raw.to_string(),
        info,
    });
}
