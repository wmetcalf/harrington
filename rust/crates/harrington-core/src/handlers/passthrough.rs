//! Pass-through admin commands — emits an AdminCommand trait so analysts
//! can filter on these without inspecting the deobfuscated text.

#![allow(clippy::expect_used)]

use crate::env::Environment;
use crate::handlers::util::{split_words, strip_outer_quotes};
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
    let task_run = flag_value_separated(raw, "/tr")
        .or_else(|| {
            flag_value_attached(raw, "/tr")
                .filter(|command| persisted_command_looks_dispatchable(command))
        })
        .or_else(|| flag_value_separated(raw, "/xml").map(|path| format!("xml:{path}")))
        .unwrap_or_default();
    env.traits.push(Trait::Persistence {
        hive: "ScheduledTask".to_string(),
        key: task_name,
        value_name: String::new(),
        command: task_run.clone(),
    });
    queue_registry_persisted_command(task_run, env);
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
        if raw[i..]
            .get(..flag.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(flag))
        {
            let value_start = i + flag.len();
            match bytes.get(value_start) {
                Some(b':') | Some(b'=') => return parse_flag_value(raw, value_start + 1),
                Some(b) if b.is_ascii_whitespace() => {
                    i = value_start;
                    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                        i += 1;
                    }
                    return parse_flag_value(raw, i);
                }
                None => return None,
                _ => {}
            }
        }
        i = next_arg_start(raw, i);
    }
    None
}

fn flag_value_separated(raw: &str, flag: &str) -> Option<String> {
    let mut i = 0usize;
    let bytes = raw.as_bytes();
    while i < raw.len() {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= raw.len() {
            break;
        }
        if raw[i..]
            .get(..flag.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(flag))
            && bytes
                .get(i + flag.len())
                .is_some_and(u8::is_ascii_whitespace)
        {
            i += flag.len();
            while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            return parse_flag_value(raw, i);
        }
        i = next_arg_start(raw, i);
    }
    None
}

fn flag_value_attached(raw: &str, flag: &str) -> Option<String> {
    let mut i = 0usize;
    let bytes = raw.as_bytes();
    while i < raw.len() {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= raw.len() {
            break;
        }
        if raw[i..]
            .get(..flag.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(flag))
        {
            let value_start = i + flag.len();
            if matches!(bytes.get(value_start), Some(b':') | Some(b'=')) {
                return parse_flag_value(raw, value_start + 1);
            }
        }
        i = next_arg_start(raw, i);
    }
    None
}

fn next_arg_start(raw: &str, mut i: usize) -> usize {
    let bytes = raw.as_bytes();
    let quote = bytes.get(i).copied().filter(|b| *b == b'"' || *b == b'\'');
    if let Some(quote) = quote {
        i += 1;
        while i < raw.len() {
            if bytes[i] == quote {
                return i + 1;
            }
            i += 1;
        }
        return raw.len();
    }
    while i < raw.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn parse_flag_value(raw: &str, start: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut start = start;
    while bytes.get(start).is_some_and(u8::is_ascii_whitespace) {
        start += 1;
    }
    let quote = *bytes.get(start)?;
    if quote == b'"' || quote == b'\'' {
        let quote_char = quote as char;
        let mut out = String::new();
        let mut i = start + 1;
        while i < raw.len() {
            let Some(ch) = raw[i..].chars().next() else {
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
    if let Some((child, delayed)) = persisted_command_child(&command) {
        env.exec_cmd.push(child);
        env.exec_cmd_delayed.push(delayed);
    }
}

fn persisted_command_looks_dispatchable(command: &str) -> bool {
    let trimmed = command.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.ends_with('\\') || trimmed.ends_with('/') {
        return false;
    }
    trimmed.bytes().any(|b| b.is_ascii_whitespace())
}

pub(crate) fn persisted_command_child(command: &str) -> Option<(String, bool)> {
    if let Some(inner) = super::cmd::extract_cmd_inner(command) {
        return Some((inner, super::cmd::has_v_on_raw(command)));
    }
    if persisted_command_looks_dispatchable(command) {
        return Some((command.to_string(), false));
    }
    None
}

pub(crate) fn sc_service_binpath(raw: &str) -> Option<(String, String)> {
    let tokens = split_words(raw);
    let command = tokens.first()?;
    let name = command
        .trim_start_matches(['@', '"', '('])
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    if name.strip_suffix(".exe").unwrap_or(&name) != "sc" {
        return None;
    }
    let is_service_binpath_subcommand = tokens
        .get(1)
        .is_some_and(|token| matches!(token.to_ascii_lowercase().as_str(), "create" | "config"));
    if !is_service_binpath_subcommand {
        return None;
    }
    let service_name = tokens
        .get(2)
        .map(|token| strip_outer_quotes(token).to_string())
        .filter(|token| !token.is_empty())?;
    let bin_path = flag_value(raw, "binPath")?;
    Some((service_name, bin_path))
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{h_reg, h_schtasks, persisted_command_child, sc_service_binpath};
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn schtasks_colon_bound_task_run_is_persisted_and_queued() {
        let mut env = Environment::new(&Config::default());
        h_schtasks(
            r#"schtasks /create /tn:Updater /tr:"cmd.exe /c echo colon-task" /sc once"#,
            &mut env,
        );

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Persistence { hive, key, command, .. }
                    if hive == "ScheduledTask"
                        && key == "Updater"
                        && command == "cmd.exe /c echo colon-task"
            )),
            "colon-bound /tr was not persisted: {:?}",
            env.traits
        );
        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo colon-task"),
            "colon-bound /tr child was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn reg_add_equals_bound_data_is_persisted_and_queued() {
        let mut env = Environment::new(&Config::default());
        h_reg(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d="cmd.exe /c echo reg-equals" /f"#,
            &mut env,
        );

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Persistence { hive, command, .. }
                    if hive == "HKCU" && command == "cmd.exe /c echo reg-equals"
            )),
            "equals-bound /d was not persisted: {:?}",
            env.traits
        );
        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo reg-equals"),
            "equals-bound /d child was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn sc_create_binpath_accepts_spaced_equals_value() {
        let (service_name, bin_path) =
            sc_service_binpath(r#"sc create UpdateSvc binPath= "cmd.exe /c echo hi""#)
                .expect("sc create binPath should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
    }

    #[test]
    fn sc_create_binpath_accepts_attached_equals_value() {
        let (service_name, bin_path) =
            sc_service_binpath(r#"sc.exe create "Update Svc" binPath="cmd.exe /c echo hi""#)
                .expect("attached sc create binPath should parse");

        assert_eq!(service_name, "Update Svc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
    }

    #[test]
    fn sc_config_binpath_accepts_spaced_equals_value() {
        let (service_name, bin_path) =
            sc_service_binpath(r#"sc config UpdateSvc binPath= "cmd.exe /c echo hi""#)
                .expect("sc config binPath should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
    }

    #[test]
    fn persisted_command_child_extracts_cmd_body_and_delayed_flag() {
        let (child, delayed) = persisted_command_child(r#"cmd.exe /V:ON /c echo !USERPROFILE!"#)
            .expect("cmd child should parse");

        assert_eq!(child, "echo !USERPROFILE!");
        assert!(delayed);
    }
}
