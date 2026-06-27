//! Pass-through admin commands — emits an AdminCommand trait so analysts
//! can filter on these without inspecting the deobfuscated text.

#![allow(clippy::expect_used)]

use crate::env::Environment;
use crate::handlers::util::{contains_ascii_case_insensitive, split_words, strip_outer_quotes};
use crate::traits::Trait;
use crate::util::find_ascii_case_insensitive_from;

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

make_handler!(h_cls, "cls");
make_handler!(h_timeout, "timeout");

pub fn h_del(raw: &str, env: &mut Environment) {
    h_delete_like(raw, env, "del");
}

pub fn h_erase(raw: &str, env: &mut Environment) {
    h_delete_like(raw, env, "erase");
}

fn h_delete_like(raw: &str, env: &mut Environment, name: &str) {
    env.traits.push(Trait::AdminCommand {
        name: name.to_string(),
        cmd: raw.to_string(),
    });
    for candidate in delete_targets(raw) {
        remove_tracked_file(env, &candidate);
    }
}

fn command_token_basename(token: &str) -> String {
    token
        .trim_start_matches(|ch: char| {
            ch.is_ascii_whitespace() || matches!(ch, '@' | '"' | '\'' | '(' | ';' | ',')
        })
        .trim_matches(['"', '\''])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase()
}

fn delete_targets(raw: &str) -> Vec<String> {
    split_words(raw)
        .iter()
        .skip(1)
        .map(|token| strip_outer_quotes(token).trim().to_string())
        .filter(|token| !token.is_empty())
        .filter(|token| !is_delete_option(token))
        .filter(|token| !token.contains(['*', '?']))
        .collect()
}

fn is_delete_option(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "/f" | "/q" | "/s" | "/p" | "/a" | "-f" | "-q" | "-s" | "-p" | "-a"
    ) || lower.starts_with("/a:")
        || lower.starts_with("-a:")
}

fn remove_tracked_file(env: &mut Environment, candidate: &str) {
    let key = candidate.to_ascii_lowercase();
    env.modified_filesystem.remove(&key);
    if let Some(name) = current_dir_basename(candidate) {
        env.modified_filesystem.remove(&name.to_ascii_lowercase());
    }
}

fn current_dir_basename(path: &str) -> Option<&str> {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .and_then(windows_basename)
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

pub fn h_rmdir(raw: &str, env: &mut Environment) {
    h_rmdir_like(raw, env, "rmdir");
}

pub fn h_rd(raw: &str, env: &mut Environment) {
    h_rmdir_like(raw, env, "rd");
}

fn h_rmdir_like(raw: &str, env: &mut Environment, name: &str) {
    env.traits.push(Trait::AdminCommand {
        name: name.to_string(),
        cmd: raw.to_string(),
    });
    for candidate in directory_delete_targets(raw) {
        remove_tracked_directory(env, &candidate);
    }
}

fn directory_delete_targets(raw: &str) -> Vec<String> {
    split_words(raw)
        .iter()
        .skip(1)
        .map(|token| strip_outer_quotes(token).trim().to_string())
        .filter(|token| !token.is_empty())
        .filter(|token| !is_rmdir_option(token))
        .filter(|token| !token.contains(['*', '?']))
        .collect()
}

fn is_rmdir_option(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "/s" | "/q" | "-s" | "-q"
    )
}

fn remove_tracked_directory(env: &mut Environment, candidate: &str) {
    let mut prefix = candidate.trim_end_matches(['\\', '/']).to_ascii_lowercase();
    if prefix.is_empty() {
        return;
    }
    env.modified_filesystem.remove(&prefix);
    prefix.push('\\');
    env.modified_filesystem.retain(|path, _| {
        !path.eq_ignore_ascii_case(&prefix[..prefix.len() - 1]) && !path.starts_with(&prefix)
    });
}

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
    if !contains_ascii_case_insensitive(raw, "reg") || !contains_ascii_case_insensitive(raw, "add")
    {
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
    static V_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/v(?:\s+|=)(?:"([^"]+)"|(\S+))"#).expect("/v regex"));
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
    let value_name = V_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();
    let command = reg_data_value(raw)
        .map(|s| trim_reg_data_tail(&s).to_string())
        .unwrap_or_default();
    // Defender registry tampering — `reg add …\Windows Defender\… /v
    // Disable…` pattern. AV evasion IOC even when the key isn't a
    // persistence path. d5033dd..., eae19989..., 864eedb8..., 68ee8152...
    // families flip DisableBehaviorMonitoring / DisableAntiSpyware /
    // DisableEnhancedNotifications via this exact form.
    if let Some(suffix) = defender_regset_suffix(&key, &value_name) {
        env.traits.push(Trait::DefenderEvasion {
            action: format!("regset-{suffix}"),
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
    if !PERSISTENCE_PATHS
        .iter()
        .any(|p| contains_ascii_case_insensitive(&key, p))
    {
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

fn reg_data_value(raw: &str) -> Option<String> {
    let mut cursor = 0usize;
    while let Some(pos) = find_ascii_case_insensitive_from(raw, "/d", cursor) {
        let mut value_start = pos + 2;
        let next = raw.as_bytes().get(value_start).copied()?;
        if next != b'=' && !next.is_ascii_whitespace() {
            cursor = value_start;
            continue;
        }
        while matches!(raw.as_bytes().get(value_start), Some(b'=' | b' ' | b'\t')) {
            value_start += 1;
        }
        if raw.as_bytes().get(value_start) == Some(&b'"') {
            let mut idx = value_start + 1;
            let mut escaped = false;
            while idx < raw.len() {
                let byte = raw.as_bytes()[idx];
                if byte == b'"' && !escaped {
                    return Some(raw[value_start + 1..idx].to_string());
                }
                escaped = byte == b'\\' && !escaped;
                if byte != b'\\' {
                    escaped = false;
                }
                idx += 1;
            }
            return Some(raw[value_start + 1..].to_string());
        }
        return Some(raw[value_start..].to_string());
    }
    None
}

fn defender_regset_suffix(key: &str, value_name: &str) -> Option<&'static str> {
    if !(contains_ascii_case_insensitive(key, "\\windows defender")
        || contains_ascii_case_insensitive(key, "/windows defender"))
        || !contains_ascii_case_insensitive(value_name, "disable")
    {
        return None;
    }
    crate::deob_scan::defender_evasion_action_suffix(value_name)
}

fn trim_reg_data_tail(command: &str) -> &str {
    const OPTIONS: &[&str] = &["/f", "/reg:32", "/reg:64", "/t", "/v", "/ve", "/va"];
    let mut end = command.len();
    let lower = command.to_ascii_lowercase();
    for opt in OPTIONS {
        let needle = format!(" {opt}");
        if let Some(pos) = lower.find(&needle) {
            end = end.min(pos);
        }
    }
    command[..end].trim()
}

make_handler!(h_attrib, "attrib");
make_handler!(h_mkdir, "mkdir");
make_handler!(h_md, "md");
make_handler!(h_move, "move");
make_handler!(h_taskkill, "taskkill");
make_handler!(h_tasklist, "tasklist");
/// `schtasks` handler. Pushes AdminCommand; if the invocation creates or
/// changes a scheduled task action (`schtasks /create|/change /tn X /tr Y`), also emits a
/// Persistence trait — scheduled tasks are a primary autorun mechanism.
pub fn h_schtasks(raw: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    env.traits.push(Trait::AdminCommand {
        name: "schtasks".to_string(),
        cmd: raw.to_string(),
    });
    let is_create = contains_ascii_case_insensitive(raw, "/create");
    let is_change = contains_ascii_case_insensitive(raw, "/change");
    if !is_create && !is_change {
        return;
    }
    static TN_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/tn(?:\s+|[:=])(?:"([^"]+)"|(\S+))"#).expect("/tn regex"));
    static TR_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/tr(?:\s+|[:=])(?:"([^"]+)"|(.+))"#).expect("/tr regex"));
    let task_name = TN_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();
    let task_run = TR_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .map(|s| trim_schtasks_tr_tail(&s).to_string())
        .unwrap_or_default();
    if is_change && task_run.is_empty() {
        return;
    }
    env.traits.push(Trait::Persistence {
        hive: "ScheduledTask".to_string(),
        key: task_name,
        value_name: String::new(),
        command: task_run.clone(),
    });
    queue_child_command(task_run, env);
}

fn queue_registry_persisted_command(command: String, env: &mut Environment) {
    if !persisted_command_looks_dispatchable(&command) {
        return;
    }
    queue_child_command(command, env);
}

fn trim_schtasks_tr_tail(command: &str) -> &str {
    const OPTIONS: &[&str] = &[
        "/change", "/create", "/delete", "/query", "/run", "/end", "/showsid", "/tn", "/sc", "/mo",
        "/d", "/m", "/i", "/st", "/ri", "/du", "/k", "/sd", "/ed", "/et", "/ru", "/rp", "/rl",
        "/it", "/np", "/z", "/xml", "/v1", "/f", "/h",
    ];
    let mut end = command.len();
    let lower = command.to_ascii_lowercase();
    for opt in OPTIONS {
        let needle = format!(" {opt}");
        if let Some(pos) = lower.find(&needle) {
            end = end.min(pos);
        }
    }
    command[..end].trim()
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

pub fn h_at(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::AdminCommand {
        name: "at".to_string(),
        cmd: raw.to_string(),
    });
    let Some((time, command)) = at_scheduled_command(raw) else {
        return;
    };
    if let Some(target_host) = at_remote_host(raw) {
        env.traits.push(Trait::LateralMovement {
            tool: "at".to_string(),
            target_host,
        });
    }
    env.traits.push(Trait::Persistence {
        hive: "AtJob".to_string(),
        key: time,
        value_name: "command".to_string(),
        command: command.clone(),
    });
    queue_registry_persisted_command(command, env);
}

pub fn h_runas(raw: &str, env: &mut Environment) {
    let Some(command) = runas_child_command(raw) else {
        return;
    };
    if let Some((target, args)) = command_target_and_args(&command) {
        env.traits.push(Trait::SelfElevation {
            target,
            args: args.filter(|value| !value.is_empty()),
        });
    }
    queue_child_command(command, env);
}

pub fn h_psexec(raw: &str, env: &mut Environment) {
    let Some((_host, command)) = psexec_child_command(raw) else {
        return;
    };
    queue_child_command(command, env);
}

pub fn h_winrs(raw: &str, env: &mut Environment) {
    let Some((_host, command)) = winrs_child_command(raw) else {
        return;
    };
    queue_child_command(command, env);
}

pub fn h_winrm(raw: &str, env: &mut Environment) {
    let Some((_host, command)) = winrm_child_command(raw) else {
        return;
    };
    queue_child_command(command, env);
}

fn runas_child_command(raw: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "runas" {
        return None;
    }

    let mut idx = 1usize;
    while let Some(span) = spans.get(idx) {
        let token = strip_outer_quotes(&raw[span.clone()]);
        let lower = token.to_ascii_lowercase();
        if lower == "/user" || lower == "/trustlevel" {
            idx += 2;
            continue;
        }
        if lower.starts_with("/user:") || lower.starts_with("/trustlevel:") {
            idx += 1;
            continue;
        }
        if matches!(
            lower.as_str(),
            "/profile"
                | "/noprofile"
                | "/env"
                | "/netonly"
                | "/savecred"
                | "/smartcard"
                | "/showtrustlevels"
        ) {
            idx += 1;
            continue;
        }
        break;
    }

    let command_start = spans.get(idx)?.start;
    let command = strip_outer_quotes(raw[command_start..].trim()).trim();
    (!command.is_empty()).then(|| command.to_string())
}

pub(crate) fn psexec_child_command(raw: &str) -> Option<(String, String)> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "psexec" {
        return None;
    }

    let mut idx = 1usize;
    let mut host = None;
    while let Some(span) = spans.get(idx) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        if token.starts_with("\\\\") {
            host = Some(token.trim_start_matches('\\').to_string());
            idx += 1;
            break;
        }
        idx += psexec_option_span_width(token, true)?;
    }
    let host = host?;

    while let Some(span) = spans.get(idx) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        if token.starts_with("\\\\") {
            idx += 1;
            continue;
        }
        let Some(width) = psexec_option_span_width(token, false) else {
            break;
        };
        idx += width;
    }

    let command_start = spans.get(idx)?.start;
    let command = strip_outer_quotes(raw[command_start..].trim()).trim();
    (!command.is_empty()).then(|| (host, command.to_string()))
}

pub(crate) fn winrs_child_command(raw: &str) -> Option<(String, String)> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "winrs" {
        return None;
    }

    let mut idx = 1usize;
    let mut host = None;
    while let Some(span) = spans.get(idx) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        let lower = token.to_ascii_lowercase();
        if lower == "-r" || lower == "/r" || lower == "-remote" || lower == "/remote" {
            let host_span = spans.get(idx + 1)?;
            host = Some(strip_outer_quotes(&raw[host_span.clone()]).to_string());
            idx += 2;
            continue;
        }
        if let Some(value) = lower
            .strip_prefix("-r:")
            .or_else(|| lower.strip_prefix("-r="))
            .or_else(|| lower.strip_prefix("/r:"))
            .or_else(|| lower.strip_prefix("/r="))
            .or_else(|| lower.strip_prefix("-remote:"))
            .or_else(|| lower.strip_prefix("-remote="))
            .or_else(|| lower.strip_prefix("/remote:"))
            .or_else(|| lower.strip_prefix("/remote="))
        {
            let value_start = span.end - value.len();
            host = Some(strip_outer_quotes(&raw[value_start..span.end]).to_string());
            idx += 1;
            continue;
        }
        let Some(width) = winrs_option_span_width(token, host.is_none()) else {
            break;
        };
        idx += width;
    }

    let host = host?.trim_matches(['"', '\'']).to_string();
    if host.is_empty() {
        return None;
    }
    let command_start = spans.get(idx)?.start;
    let command = strip_outer_quotes(raw[command_start..].trim()).trim();
    (!command.is_empty()).then(|| (host, command.to_string()))
}

pub(crate) fn winrm_child_command(raw: &str) -> Option<(String, String)> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    let command_name = command_name
        .strip_suffix(".cmd")
        .or_else(|| command_name.strip_suffix(".exe"))
        .unwrap_or(&command_name);
    if command_name != "winrm" {
        return None;
    }

    let mut host = None;
    for (idx, span) in spans.iter().enumerate().skip(1) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        let lower = token.to_ascii_lowercase();
        if lower == "-r" || lower == "/r" || lower == "-remote" || lower == "/remote" {
            let host_span = spans.get(idx + 1)?;
            host = Some(strip_outer_quotes(&raw[host_span.clone()]).to_string());
            break;
        }
        if let Some(value) = lower
            .strip_prefix("-r:")
            .or_else(|| lower.strip_prefix("-r="))
            .or_else(|| lower.strip_prefix("/r:"))
            .or_else(|| lower.strip_prefix("/r="))
            .or_else(|| lower.strip_prefix("-remote:"))
            .or_else(|| lower.strip_prefix("-remote="))
            .or_else(|| lower.strip_prefix("/remote:"))
            .or_else(|| lower.strip_prefix("/remote="))
        {
            let value_start = span.end - value.len();
            host = Some(strip_outer_quotes(&raw[value_start..span.end]).to_string());
            break;
        }
    }

    let host = host?.trim_matches(['"', '\'']).to_string();
    if host.is_empty() {
        return None;
    }
    let command = winrm_commandline_value(raw)?;
    Some((host, command))
}

fn winrm_commandline_value(raw: &str) -> Option<String> {
    let marker = find_ascii_case_insensitive_from(raw, "CommandLine", 0)?;
    let mut idx = marker + "CommandLine".len();
    let bytes = raw.as_bytes();
    while bytes.get(idx).is_some_and(u8::is_ascii_whitespace) {
        idx += 1;
    }
    if bytes.get(idx) != Some(&b'=') {
        return None;
    }
    idx += 1;
    while bytes.get(idx).is_some_and(u8::is_ascii_whitespace) {
        idx += 1;
    }
    parse_winrm_flag_value(raw, idx)
}

fn parse_winrm_flag_value(raw: &str, start: usize) -> Option<String> {
    if raw.as_bytes().get(start) == Some(&b'"') {
        let mut idx = start + 1;
        let mut escaped = false;
        while idx < raw.len() {
            let byte = raw.as_bytes()[idx];
            if byte == b'"' && !escaped {
                let value = raw[start + 1..idx].trim();
                return (!value.is_empty()).then(|| value.to_string());
            }
            escaped = byte == b'\\' && !escaped;
            if byte != b'\\' {
                escaped = false;
            }
            idx += 1;
        }
        let value = raw[start + 1..].trim();
        return (!value.is_empty()).then(|| value.to_string());
    }

    let end = raw[start..]
        .find([';', '}'])
        .map(|offset| start + offset)
        .unwrap_or(raw.len());
    let value = raw[start..end].trim().trim_matches(['"', '\'']).trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn winrs_option_span_width(token: &str, before_host: bool) -> Option<usize> {
    let lower = token.to_ascii_lowercase();
    let option = lower.strip_prefix(['-', '/'])?;
    if option.is_empty() {
        return None;
    }
    if matches!(
        option,
        "u" | "username" | "p" | "password" | "a" | "encoding"
    ) {
        return Some(2);
    }
    if option.starts_with("u:")
        || option.starts_with("u=")
        || option.starts_with("username:")
        || option.starts_with("username=")
        || option.starts_with("p:")
        || option.starts_with("p=")
        || option.starts_with("password:")
        || option.starts_with("password=")
        || option.starts_with("a:")
        || option.starts_with("a=")
        || option.starts_with("encoding:")
        || option.starts_with("encoding=")
    {
        return Some(1);
    }
    if matches!(
        option,
        "unencrypted" | "usessl" | "skipcncheck" | "skipcacheck" | "skiprevocationcheck"
    ) {
        return Some(1);
    }
    before_host.then_some(1)
}

fn psexec_option_span_width(token: &str, before_host: bool) -> Option<usize> {
    let lower = token.to_ascii_lowercase();
    if lower.is_empty() {
        return Some(1);
    }
    let option = lower.strip_prefix(['-', '/'])?;
    if option.is_empty() {
        return None;
    }
    if matches!(
        option,
        "u" | "p" | "n" | "i" | "w" | "r" | "a" | "g" | "priority"
    ) {
        return Some(2);
    }
    if option.starts_with('u')
        || option.starts_with('p')
        || option.starts_with('n')
        || option.starts_with('i')
        || option.starts_with('w')
        || option.starts_with('r')
        || option.starts_with('a')
        || option.starts_with('g')
    {
        return Some(1);
    }
    if matches!(
        option,
        "accepteula"
            | "nobanner"
            | "s"
            | "h"
            | "d"
            | "c"
            | "f"
            | "v"
            | "e"
            | "l"
            | "x"
            | "realtime"
            | "high"
            | "abovenormal"
            | "belownormal"
            | "low"
            | "background"
    ) {
        return Some(1);
    }
    before_host.then_some(1)
}

fn command_target_and_args(command: &str) -> Option<(String, Option<String>)> {
    let spans = split_word_spans(command);
    let target_span = spans.first()?;
    let target = strip_outer_quotes(&command[target_span.clone()]).to_string();
    if target.is_empty() {
        return None;
    }
    let args = command[target_span.end..].trim();
    Some((
        target,
        (!args.is_empty()).then(|| strip_outer_quotes(args).to_string()),
    ))
}

fn at_scheduled_command(raw: &str) -> Option<(String, String)> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "at" {
        return None;
    }

    let mut idx = 1usize;
    if spans
        .get(idx)
        .is_some_and(|span| raw[span.clone()].starts_with("\\\\"))
    {
        idx += 1;
    }
    let time_span = spans.get(idx)?;
    let time = strip_outer_quotes(&raw[time_span.clone()]);
    if !at_token_looks_like_time(time) {
        return None;
    }
    idx += 1;
    while let Some(span) = spans.get(idx) {
        let token = strip_outer_quotes(&raw[span.clone()]).to_ascii_lowercase();
        if token == "/interactive" || token.starts_with("/every:") || token.starts_with("/next:") {
            idx += 1;
            continue;
        }
        break;
    }
    let command_start = spans.get(idx)?.start;
    let command = raw[command_start..].trim();
    if command.is_empty() {
        return None;
    }
    Some((time.to_string(), command.to_string()))
}

fn at_remote_host(raw: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "at" {
        return None;
    }
    let host = raw[spans.get(1)?.clone()].trim_matches(['"', '\'']);
    host.strip_prefix("\\\\")
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_string)
}

fn at_token_looks_like_time(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower == "now" || lower.contains(':')
}

fn split_word_spans(raw: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quote = None;
    for (idx, ch) in raw.char_indices() {
        if start.is_none() {
            if ch.is_whitespace() {
                continue;
            }
            start = Some(idx);
        }
        if matches!(ch, '"' | '\'') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
            continue;
        }
        if ch.is_whitespace() && quote.is_none() {
            if let Some(start_idx) = start.take() {
                out.push(start_idx..idx);
            }
        }
    }
    if let Some(start_idx) = start {
        out.push(start_idx..raw.len());
    }
    out
}

pub fn h_sc(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::AdminCommand {
        name: "sc".to_string(),
        cmd: raw.to_string(),
    });
    if let Some((service_name, bin_path)) = sc_service_binpath(raw) {
        env.traits.push(Trait::ServiceInstall {
            service_name,
            bin_path: bin_path.clone(),
        });
        queue_registry_persisted_command(bin_path, env);
        return;
    }
    if let Some((service_name, command)) = sc_failure_command(raw) {
        env.traits.push(Trait::Persistence {
            hive: "ServiceFailureCommand".to_string(),
            key: service_name,
            value_name: "command".to_string(),
            command: command.clone(),
        });
        queue_registry_persisted_command(command, env);
    }
}

pub(crate) fn sc_service_binpath(raw: &str) -> Option<(String, String)> {
    let (subcommand, service_name) = sc_subcommand_and_service(raw)?;
    if !matches!(subcommand.as_str(), "create" | "config") {
        return None;
    }
    let bin_path = command_value_after_key(raw, "binpath")?;
    Some((service_name, bin_path))
}

pub(crate) fn sc_failure_command(raw: &str) -> Option<(String, String)> {
    let (subcommand, service_name) = sc_subcommand_and_service(raw)?;
    if subcommand != "failure" {
        return None;
    }
    let command = command_value_after_key(raw, "command")?;
    Some((service_name, command))
}

fn sc_subcommand_and_service(raw: &str) -> Option<(String, String)> {
    let tokens = split_words(raw);
    let command = tokens.first()?;
    let command_name = command_token_basename(command);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "sc" {
        return None;
    }
    let subcommand_index = if tokens.get(1).is_some_and(|token| {
        strip_outer_quotes(token)
            .trim_matches('"')
            .starts_with(r"\\")
    }) {
        2
    } else {
        1
    };
    let subcommand = tokens.get(subcommand_index).map(|token| {
        strip_outer_quotes(token)
            .trim_matches('"')
            .to_ascii_lowercase()
    })?;
    let service_name = tokens
        .get(subcommand_index + 1)
        .map(|token| strip_outer_quotes(token).to_string())
        .filter(|token| !token.is_empty())?;
    Some((subcommand, service_name))
}

fn command_value_after_key(raw: &str, key: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    for (idx, span) in spans.iter().enumerate() {
        let raw_token = &raw[span.clone()];
        let token = raw_token.trim_matches(['"', '\'']);
        if token.eq_ignore_ascii_case(key) {
            let value_span = spans.get(idx + 1)?;
            return sc_command_value(raw, value_span.start, &spans[idx + 1..]);
        }
        let Some(value_offset) = sc_attached_value_offset(token, key) else {
            continue;
        };
        let raw_token_quote_offset = raw_token.len() - token.len();
        let attached_value_start = span.start + value_offset + raw_token_quote_offset;
        let value_start = if attached_value_start >= span.end {
            spans.get(idx + 1)?.start
        } else {
            attached_value_start
        };
        let value_spans = if attached_value_start >= span.end {
            &spans[idx + 1..]
        } else {
            &spans[idx..]
        };
        return sc_command_value(raw, value_start, value_spans);
    }
    None
}

fn sc_attached_value_offset(token: &str, key: &str) -> Option<usize> {
    let head = token.get(..key.len())?;
    if !head.eq_ignore_ascii_case(key) {
        return None;
    }
    let delimiter = token.as_bytes().get(key.len()).copied()?;
    matches!(delimiter, b'=' | b':').then_some(key.len() + 1)
}

fn sc_command_value(
    raw: &str,
    start: usize,
    value_spans: &[std::ops::Range<usize>],
) -> Option<String> {
    let bytes = raw.as_bytes();
    let quote = *bytes.get(start)?;
    if quote == b'"' || quote == b'\'' {
        let quote_char = quote as char;
        let mut out = String::new();
        let mut i = start + 1;
        while i < raw.len() {
            let Some(ch) = raw[i..].chars().next() else {
                break;
            };
            if ch == quote_char {
                return Some(out);
            }
            out.push(ch);
            i += ch.len_utf8();
        }
        return Some(out);
    }
    let end = sc_unquoted_value_end(raw, value_spans);
    Some(raw[start..end].trim_end().to_string()).filter(|value| !value.is_empty())
}

fn sc_unquoted_value_end(raw: &str, value_spans: &[std::ops::Range<usize>]) -> usize {
    for span in value_spans.iter().skip(1) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        if sc_option_token(token) {
            return span.start;
        }
    }
    value_spans.last().map_or(raw.len(), |span| span.end)
}

fn sc_option_token(token: &str) -> bool {
    let Some((name, _)) = token.split_once(['=', ':']) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "type"
            | "start"
            | "error"
            | "binpath"
            | "group"
            | "tag"
            | "depend"
            | "obj"
            | "displayname"
            | "password"
            | "reset"
            | "reboot"
            | "command"
            | "actions"
    )
}

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
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn reg_run_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_reg(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "cmd /c echo hidden" /f"#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "registry persistence command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn reg_run_unquoted_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_reg(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d cmd /c echo hidden /f"#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "unquoted registry persistence command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn reg_run_equals_flags_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_reg(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v=Updater /d="cmd /c echo hidden" /f"#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "equals-form registry persistence command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn schtasks_tr_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_schtasks(
            r#"schtasks /create /tn Updater /tr "cmd /c echo hidden""#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "scheduled task command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn schtasks_unquoted_tr_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_schtasks(
            r#"schtasks /create /tn Updater /tr cmd /c echo hidden /sc minute /mo 7"#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "unquoted scheduled task command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn schtasks_equals_flags_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_schtasks(
            r#"schtasks /create /tn=Updater /tr="cmd /c echo hidden" /sc minute /mo 7"#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "equals-form scheduled task command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn schtasks_attached_flags_are_case_insensitive() {
        let mut env = Environment::new(&Config::default());
        h_schtasks(
            r#"schtasks /Create /Tn:Updater /Tr:"cmd.exe /c echo mixed-case-task" /Sc once"#,
            &mut env,
        );

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Persistence { hive, key, command, .. }
                    if hive == "ScheduledTask"
                        && key == "Updater"
                        && command == "cmd.exe /c echo mixed-case-task"
            )),
            "mixed-case attached schtasks flags were not persisted: {:?}",
            env.traits
        );
        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo mixed-case-task"),
            "mixed-case attached /Tr child was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn psexec_child_command_skips_host_auth_and_flags() {
        let (host, command) = psexec_child_command(
            r#"psexec \\target.example -accepteula -u admin -p pass -s cmd.exe /c echo remote"#,
        )
        .expect("psexec child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo remote");
    }

    #[test]
    fn psexec_child_command_accepts_slash_options() {
        let (host, command) = psexec_child_command(
            r#"psexec \\target.example /accepteula /u admin /p pass /s cmd.exe /c echo remote"#,
        )
        .expect("psexec slash-option child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo remote");
    }

    #[test]
    fn psexec_child_command_accepts_options_before_host() {
        let (host, command) =
            psexec_child_command(r#"psexec -accepteula \\target.example powershell.exe -nop"#)
                .expect("psexec child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "powershell.exe -nop");
    }

    #[test]
    fn psexec_child_command_accepts_delimiter_prefix() {
        let (host, command) =
            psexec_child_command(r#"@;psexec \\target.example cmd.exe /c echo remote"#)
                .expect("delimiter-prefixed psexec child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo remote");
    }

    #[test]
    fn winrs_child_command_accepts_attached_remote_host() {
        let (host, command) = winrs_child_command(r#"winrs -r:target.example cmd.exe /c echo hi"#)
            .expect("winrs child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn winrs_child_command_skips_auth_options() {
        let (host, command) =
            winrs_child_command(r#"winrs /r target.example -u admin -p pass powershell.exe -nop"#)
                .expect("winrs child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "powershell.exe -nop");
    }

    #[test]
    fn winrs_child_command_accepts_delimiter_prefix() {
        let (host, command) =
            winrs_child_command(r#"@;winrs -r:target.example cmd.exe /c echo hi"#)
                .expect("delimiter-prefixed winrs child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn winrm_child_command_extracts_remote_commandline() {
        let (host, command) = winrm_child_command(
            r#"winrm invoke Create wmicimv2/Win32_Process -r:target.example @{CommandLine="cmd.exe /c echo hi";CurrentDirectory="C:\Windows"}"#,
        )
        .expect("winrm child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn winrm_child_command_accepts_spaced_remote_host() {
        let (host, command) = winrm_child_command(
            r#"winrm.cmd i Create wmicimv2/Win32_Process /remote target.example @{CommandLine = "powershell.exe -nop"}"#,
        )
        .expect("winrm child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "powershell.exe -nop");
    }

    #[test]
    fn winrm_child_command_accepts_exe_suffix() {
        let (host, command) = winrm_child_command(
            r#"winrm.exe invoke Create wmicimv2/Win32_Process -r:target.example @{CommandLine="cmd.exe /c echo winrm-exe"}"#,
        )
        .expect("winrm.exe child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo winrm-exe");
    }

    #[test]
    fn sc_remote_create_binpath_accepts_host_before_subcommand() {
        let (service_name, bin_path) = sc_service_binpath(
            r#"sc \\target.example create UpdateSvc binPath= "cmd.exe /c echo hi""#,
        )
        .expect("remote sc create binPath should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
    }

    #[test]
    fn sc_create_binpath_accepts_attached_unquoted_value() {
        let (service_name, bin_path) =
            sc_service_binpath(r#"sc create UpdateSvc binPath=cmd.exe /c echo hi"#)
                .expect("attached unquoted sc create binPath should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
    }

    #[test]
    fn sc_remote_failure_command_accepts_host_before_subcommand() {
        let (service_name, command) = sc_failure_command(
            r#"sc.exe \\target.example failure UpdateSvc command= "cmd.exe /c echo hi""#,
        )
        .expect("remote sc failure command should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn sc_failure_command_accepts_attached_unquoted_value() {
        let (service_name, command) =
            sc_failure_command(r#"sc failure UpdateSvc command=cmd.exe /c echo fail"#)
                .expect("attached unquoted sc failure command should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(command, "cmd.exe /c echo fail");
    }

    #[test]
    fn at_scheduled_command_accepts_delimiter_prefix() {
        let (time, command) = at_scheduled_command(r#"@;at 23:59 cmd.exe /c echo hi"#)
            .expect("delimiter-prefixed at should parse");

        assert_eq!(time, "23:59");
        assert_eq!(command, "cmd.exe /c echo hi");
    }
}
