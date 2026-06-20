//! Pass-through admin commands — emits an AdminCommand trait so analysts
//! can filter on these without inspecting the deobfuscated text.

#![allow(clippy::expect_used)]

use crate::env::Environment;
use crate::traits::Trait;

macro_rules! make_handler {
    ($fn_name:ident, $cmd_name:literal) => {
        pub fn $fn_name(raw: &str, env: &mut Environment) {
            env.traits.push(Trait::AdminCommand {
                name: $cmd_name.to_string(),
                cmd: raw.to_string(),
            });
        }
    };
}

make_handler!(h_del, "del");
make_handler!(h_cls, "cls");
make_handler!(h_timeout, "timeout");

/// `reg add` handler. Pushes the existing AdminCommand trait for backward
/// compat, and additionally emits a Persistence trait when the target key
/// is a well-known Windows autorun hive (Run / RunOnce / RunServices /
/// Userinit / Image File Execution Options). Recognised by a substring
/// match on the lowercased key path.
pub fn h_reg(raw: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    env.traits.push(Trait::AdminCommand {
        name: "reg".to_string(),
        cmd: raw.to_string(),
    });
    let lower = raw.to_ascii_lowercase();
    if !lower.contains("reg") || !lower.contains("add") {
        return;
    }
    // Match `reg add <key> /v <name> /d <data>` — `key` is quoted or
    // unquoted up to the next space/`/v`. `data` extends to end of line
    // (or `/f`/`/t`). Tolerate the optional `.exe` and any flag order.
    static REG_ADD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)reg(?:\.exe)?\s+add\s+(?:"([^"]+)"|(\S+))"#).expect("reg add regex")
    });
    // Separate regexes for /v and /d so each can scan the rest of the
    // line independently (a single lazy regex would skip the /d match).
    let Some(caps) = REG_ADD_RE.captures(raw) else {
        return;
    };
    let key = caps
        .get(1)
        .or_else(|| caps.get(2))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    if key.is_empty() {
        return;
    }
    let key_lower = key.to_ascii_lowercase();
    let value_name = flag_value(raw, "/v").unwrap_or_default();
    let command = flag_value(raw, "/d").unwrap_or_default();
    // Defender registry tampering — `reg add …\Windows Defender\… /v
    // Disable…` pattern. AV evasion IOC even when the key isn't a
    // persistence path. d5033dd..., eae19989..., 864eedb8..., 68ee8152...
    // families flip DisableBehaviorMonitoring / DisableAntiSpyware /
    // DisableEnhancedNotifications via this exact form.
    if (key_lower.contains("\\windows defender") || key_lower.contains("/windows defender"))
        && value_name.to_ascii_lowercase().starts_with("disable")
    {
        env.traits.push(Trait::DefenderEvasion {
            action: format!("regset-{}", value_name.to_ascii_lowercase()),
            target: command.clone(),
        });
    }
    // Persistence keys — case-insensitive substring match on the key path.
    const PERSISTENCE_PATHS: &[&str] = &[
        r"\currentversion\run",
        r"\currentversion\runonce",
        r"\currentversion\runservices",
        r"\currentversion\runservicesonce",
        r"\currentversion\explorer\run",
        r"\currentversion\policies\explorer\run",
        r"\currentversion\shell\open\command",
        r"\winlogon\userinit",
        r"\winlogon\shell",
        r"\image file execution options\",
        r"\currentversion\app paths\",
        r"\currentversion\winlogon\shell",
    ];
    let value_lower = value_name.to_ascii_lowercase();
    let winlogon_value_persistence =
        key_lower.contains("\\winlogon") && matches!(value_lower.as_str(), "shell" | "userinit");
    if !winlogon_value_persistence && !PERSISTENCE_PATHS.iter().any(|p| key_lower.contains(p)) {
        return;
    }
    // Split hive from sub-key for clarity.
    let (hive, subkey) = if let Some(idx) = key.find('\\') {
        (key[..idx].to_string(), key[idx + 1..].to_string())
    } else {
        (key.clone(), String::new())
    };
    env.traits.push(Trait::Persistence {
        hive,
        key: subkey,
        value_name,
        command: command.clone(),
    });
    queue_registry_persisted_command(command, env);
}

make_handler!(h_attrib, "attrib");
make_handler!(h_mkdir, "mkdir");
make_handler!(h_md, "md");
make_handler!(h_move, "move");
make_handler!(h_rmdir, "rmdir");
make_handler!(h_rd, "rd");
make_handler!(h_taskkill, "taskkill");
make_handler!(h_tasklist, "tasklist");
/// `schtasks` handler. Pushes AdminCommand; if the invocation creates a
/// scheduled task (`schtasks /create /tn X /tr Y`), also emits a
/// Persistence trait — scheduled tasks are a primary autorun mechanism.
pub fn h_schtasks(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::AdminCommand {
        name: "schtasks".to_string(),
        cmd: raw.to_string(),
    });
    let lower = raw.to_ascii_lowercase();
    if !lower.contains("/create") {
        return;
    }
    let task_name = flag_value(raw, "/tn").unwrap_or_default();
    let task_run = flag_value(raw, "/tr")
        .or_else(|| flag_value(raw, "/xml").map(|path| format!("xml:{path}")))
        .unwrap_or_default();
    env.traits.push(Trait::Persistence {
        hive: "ScheduledTask".to_string(),
        key: task_name,
        value_name: String::new(),
        command: task_run.clone(),
    });
    queue_child_command(task_run, env);
}

fn flag_value(raw: &str, flag: &str) -> Option<String> {
    let mut i = 0usize;
    let bytes = raw.as_bytes();
    while i < raw.len() {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= raw.len() {
            break;
        }
        let token_start = i;
        while i < raw.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let token = &raw[token_start..i];
        if token.eq_ignore_ascii_case(flag) {
            while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            return parse_flag_value(raw, i);
        }
    }
    None
}

fn parse_flag_value(raw: &str, start: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let quote = *bytes.get(start)?;
    if quote == b'"' || quote == b'\'' {
        let quote_char = quote as char;
        let mut out = String::new();
        let mut i = start + 1;
        while i < raw.len() {
            let Some(ch) = raw.get(i..).and_then(|s| s.chars().next()) else {
                break;
            };
            if ch == '\\'
                && bytes.get(i + 1) == Some(&quote)
                && has_later_unescaped_quote(bytes, i + 2, quote)
            {
                out.push(quote_char);
                i += 2;
                continue;
            }
            if ch == quote_char {
                return Some(out);
            }
            out.push(ch);
            i += ch.len_utf8();
        }
        return Some(out);
    }
    let end = raw[start..]
        .find(char::is_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    Some(raw[start..end].to_string())
}

fn has_later_unescaped_quote(bytes: &[u8], mut start: usize, quote: u8) -> bool {
    while start < bytes.len() {
        if bytes[start] == quote && (start == 0 || bytes.get(start - 1) != Some(&b'\\')) {
            return true;
        }
        start += 1;
    }
    false
}

fn queue_registry_persisted_command(command: String, env: &mut Environment) {
    if !persisted_command_looks_dispatchable(&command) {
        return;
    }
    queue_child_command(command, env);
}

fn queue_child_command(command: String, env: &mut Environment) {
    if command.is_empty() {
        return;
    }
    if let Some(inner) = super::cmd::extract_cmd_inner(&command) {
        env.exec_cmd.push(inner);
        env.exec_cmd_delayed
            .push(super::cmd::has_v_on_raw(&command));
    } else {
        env.exec_cmd.push(command);
        env.exec_cmd_delayed.push(false);
    }
}

fn persisted_command_looks_dispatchable(command: &str) -> bool {
    let trimmed = command.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.ends_with('\\') || trimmed.ends_with('/') {
        return false;
    }
    trimmed.bytes().any(|b| b.is_ascii_whitespace())
}

make_handler!(h_sc, "sc");
make_handler!(h_ping, "ping");
make_handler!(h_xcopy, "xcopy");
make_handler!(h_title, "title");
make_handler!(h_pause, "pause");
make_handler!(h_color, "color");
make_handler!(h_doskey, "doskey");
make_handler!(h_chcp, "chcp");
make_handler!(h_ver, "ver");
make_handler!(h_whoami, "whoami");
