//! PowerShell handler — captures -EncodedCommand / -Command into env.exec_ps1.
//!
//! Mirrors powershell.exe parameter binding for any unambiguous shorthand:
//! literal prefixes (`-Enc`, `-Encoded`) and CamelCase initials (`-Ec`,
//! `-Ex`, `-WindowS`, `-NoP`). The obfuscator-friendly variants all resolve
//! to the same canonical form here so the URL-extraction pipeline sees the
//! decoded payload regardless of which spelling the sample used.
#![allow(clippy::expect_used)]

use super::util::{
    filesystem_entry_for_path, filesystem_storage_key, split_words,
    starts_with_ascii_case_insensitive,
};
use crate::env::{Environment, FsEntry};
use base64::Engine;

// (canonical_camel, takes_value). Listed in PowerShell.exe's canonical
// CamelCase so that initial-letter matching (`-Ec` -> EncodedCommand) can
// reconstruct the abbreviation rule.
const PS_FLAGS: &[(&str, bool)] = &[
    ("PSConsoleFile", true),
    ("Version", true),
    ("NoLogo", false),
    ("NoExit", false),
    ("Sta", false),
    ("Mta", false),
    ("NoProfile", false),
    ("NonInteractive", false),
    ("InputFormat", true),
    ("OutputFormat", true),
    ("WindowStyle", true),
    ("EncodedCommand", true),
    ("ConfigurationName", true),
    ("File", true),
    ("ExecutionPolicy", true),
    ("Command", true),
    ("SettingsFile", true),
    ("Help", false),
];

fn camel_initials_eq_ignore_ascii_case(name: &str, stripped: &str) -> bool {
    let mut initials = name
        .as_bytes()
        .iter()
        .copied()
        .filter(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    let mut token = stripped.as_bytes().iter().copied();
    loop {
        match (initials.next(), token.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(&b) => continue,
            _ => return false,
        }
    }
}

/// PowerShell.exe disambiguates a handful of prefix-ambiguous shortcuts via
/// internal precedence rather than erroring. These match the host's actual
/// behavior (and what malware relies on).
const SHORTCUT_OVERRIDES: &[(&str, &str)] = &[
    // `-e` is a prefix of both EncodedCommand and ExecutionPolicy; PS resolves
    // it to EncodedCommand (the encoded shortcut is the documented "-E").
    ("e", "EncodedCommand"),
    // `-co` is a prefix of both Command and ConfigurationName. The pre-rewrite
    // CMD_FLAG_RE accepted every prefix of `-command`; preserve that legacy
    // semantics so `powershell -co \"...\"` still routes through the
    // Command branch.
    ("co", "Command"),
];

/// Resolve a token like `-Ec`, `/W`, `-NoP` to its canonical powershell.exe
/// flag name (e.g. `EncodedCommand`). Returns `None` for non-flag tokens,
/// unknown flags, and ambiguous abbreviations not covered by an explicit
/// PS-precedence override.
pub(crate) fn canonical_ps_flag(token: &str) -> Option<&'static str> {
    let stripped = token
        .strip_prefix('/')
        .or_else(|| token.strip_prefix('-'))?;
    if stripped.is_empty() {
        return None;
    }
    let mut prefix_hit: Option<&'static str> = None;
    let mut prefix_multi = false;
    let mut initials_hit: Option<&'static str> = None;
    let mut initials_multi = false;
    for (name, _) in PS_FLAGS {
        if name.eq_ignore_ascii_case(stripped) {
            // Exact match always wins.
            return Some(*name);
        }
        if starts_with_ascii_case_insensitive(name, stripped) {
            if prefix_hit.is_some() {
                prefix_multi = true;
            } else {
                prefix_hit = Some(*name);
            }
        }
        if camel_initials_eq_ignore_ascii_case(name, stripped) {
            if initials_hit.is_some() {
                initials_multi = true;
            } else {
                initials_hit = Some(*name);
            }
        }
    }
    if prefix_multi {
        if let Some((_, override_to)) = SHORTCUT_OVERRIDES
            .iter()
            .find(|(prefix, _)| prefix.eq_ignore_ascii_case(stripped))
        {
            return Some(*override_to);
        }
    } else if let Some(hit) = prefix_hit {
        return Some(hit);
    }
    if !initials_multi {
        if let Some(hit) = initials_hit {
            return Some(hit);
        }
    }
    None
}

fn attached_ps_flag_value(token: &str) -> Option<(&'static str, &str)> {
    let stripped = token
        .strip_prefix('/')
        .or_else(|| token.strip_prefix('-'))?;
    let delimiter = stripped.find([':', '='])?;
    let flag_end = token.len() - stripped.len() + delimiter;
    let flag = canonical_ps_flag(&token[..flag_end])?;
    let value = &stripped[delimiter + 1..];
    if value.is_empty() || !flag_takes_value(flag) {
        return None;
    }
    Some((flag, value))
}

fn flag_takes_value(flag: &str) -> bool {
    PS_FLAGS
        .iter()
        .find(|(name, _)| *name == flag)
        .map(|(_, takes_value)| *takes_value)
        .unwrap_or(false)
}

fn is_command_flag(flag: &str) -> bool {
    flag == "Command"
}
fn is_encoded_flag(flag: &str) -> bool {
    flag == "EncodedCommand"
}
fn is_file_flag(flag: &str) -> bool {
    flag == "File"
}

pub fn h_powershell(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if tokens.is_empty() {
        return;
    }
    let mut i = 1usize;
    while i < tokens.len() {
        let t = &tokens[i];
        if let Some((flag, value)) = attached_ps_flag_value(t) {
            if is_encoded_flag(flag) {
                let s = collect_encoded_argument_with_prefix(value, &tokens[i + 1..]);
                if !s.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) {
                        env.exec_ps1.push(decoded);
                    }
                }
                return;
            }
            if is_command_flag(flag) {
                let body = command_body_from_attached_value(value, &tokens[i + 1..]);
                if !body.is_empty() {
                    record_powershell_side_effects(&body, env);
                    env.exec_ps1.push(body.as_bytes().to_vec());
                }
                return;
            }
            if is_file_flag(flag) {
                queue_file_payload_or_url(raw, value, env);
                return;
            }
            i += 1;
            continue;
        }
        match canonical_ps_flag(t) {
            Some(flag) if is_encoded_flag(flag) => {
                let s = collect_encoded_argument(&tokens[i + 1..]);
                if !s.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) {
                        env.exec_ps1.push(decoded);
                    }
                }
                return;
            }
            Some(flag) if is_command_flag(flag) => {
                let body = tokens[i + 1..].join(" ");
                let body = body.trim();
                let body = body.trim_matches('"').trim_matches('\'');
                if !body.is_empty() {
                    record_powershell_side_effects(body, env);
                    env.exec_ps1.push(body.as_bytes().to_vec());
                }
                return;
            }
            Some(flag) if is_file_flag(flag) => {
                if let Some(path) = tokens.get(i + 1) {
                    queue_file_payload_or_url(raw, path, env);
                }
                return;
            }
            Some(flag) => {
                i += if flag_takes_value(flag) { 2 } else { 1 };
                continue;
            }
            None => {}
        }
        i += 1;
    }
    // No -Command/-EncodedCommand/-File flag was found. The PowerShell command
    // is in the positional arguments. Skip PS-meta flags (and their values
    // when they take one) and push the remainder as the script body.
    let body = skip_ps_meta_flags(&tokens[1..]);
    if !body.is_empty() {
        record_powershell_side_effects(&body, env);
        env.exec_ps1.push(body.as_bytes().to_vec());
    }
}

fn record_powershell_side_effects(body: &str, env: &mut Environment) {
    record_download_side_effects(body, env);
    record_copy_item_side_effects(body, env);
    record_set_content_value_side_effects(body, env);
    record_get_content_set_content_side_effects(body, env);
}

fn record_download_side_effects(body: &str, env: &mut Environment) {
    for (src, dst) in crate::ps1_scan::ps_download_side_effects(body) {
        env.modified_filesystem
            .insert(filesystem_storage_key(&dst), FsEntry::Download { src });
    }
}

fn record_get_content_set_content_side_effects(body: &str, env: &mut Environment) {
    let tokens = split_words(body);
    for i in 0..tokens.len() {
        if !is_get_content_token(&tokens[i]) {
            continue;
        }
        let Some((src, src_idx)) = powershell_content_path_arg(&tokens, i + 1) else {
            continue;
        };
        if let Some(dst) = powershell_stdout_redirect_destination(&tokens, src_idx + 1) {
            let Some(entry) = tracked_transfer_entry(&src, env) else {
                continue;
            };
            env.modified_filesystem
                .insert(filesystem_storage_key(&dst), entry);
            continue;
        }
        let Some(set_idx) = tokens
            .iter()
            .enumerate()
            .skip(src_idx + 1)
            .find_map(|(idx, token)| is_content_write_token(token).then_some(idx))
        else {
            continue;
        };
        let Some((dst, _)) = powershell_content_path_arg(&tokens, set_idx + 1) else {
            continue;
        };
        let Some(entry) = tracked_transfer_entry(&src, env) else {
            continue;
        };
        env.modified_filesystem
            .insert(filesystem_storage_key(&dst), entry);
    }
}

fn record_copy_item_side_effects(body: &str, env: &mut Environment) {
    let tokens = split_words(body);
    for i in 0..tokens.len() {
        if !is_copy_item_token(&tokens[i]) {
            continue;
        }
        let Some((src, dst)) = powershell_copy_item_paths(&tokens, i + 1) else {
            continue;
        };
        let Some(entry) = tracked_transfer_entry(&src, env) else {
            continue;
        };
        env.modified_filesystem
            .insert(filesystem_storage_key(&dst), entry);
    }
}

fn record_set_content_value_side_effects(body: &str, env: &mut Environment) {
    let tokens = split_words(body);
    for i in 0..tokens.len() {
        let Some(append) = direct_content_write_append_mode(&tokens, i) else {
            continue;
        };
        let Some((dst, content)) = powershell_set_content_paths_and_value(&tokens, i + 1) else {
            continue;
        };
        write_powershell_content(env, &dst, content.into_bytes(), append);
    }
}

fn write_powershell_content(env: &mut Environment, dst: &str, content: Vec<u8>, append: bool) {
    let key = filesystem_storage_key(dst);
    if append {
        if let Some(FsEntry::Content {
            content: prior,
            append: prior_append,
        }) = env.modified_filesystem.get_mut(&key)
        {
            prior.extend_from_slice(&content);
            *prior_append = true;
            return;
        }
    }
    env.modified_filesystem
        .insert(key, FsEntry::Content { content, append });
}

fn queue_file_payload_or_url(raw: &str, path: &str, env: &mut Environment) {
    let path = strip_quotes(path);
    if let Some(content) = tracked_script_content(path, env) {
        if !env.exec_ps1.iter().any(|existing| existing == &content) {
            env.exec_ps1.push(content);
        }
    }
    if let Some(url) = tracked_download_url(path, env) {
        if !env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::UrlArgument { cmd, url: existing }
                    if cmd == raw && existing == &url
            )
        }) {
            env.traits.push(crate::traits::Trait::UrlArgument {
                cmd: raw.to_string(),
                url,
            });
        }
    }
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_from_entry(filesystem_entry_for_path(env, path)) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(filesystem_entry_for_path(env, stripped));
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return tracked_script_content_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    tracked_script_content_by_basename(path, env)
}

fn tracked_script_content_by_basename(path: &str, env: &Environment) -> Option<Vec<u8>> {
    for (tracked_path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(tracked_path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(path) {
            return content_from_entry(Some(entry));
        }
    }
    None
}

fn tracked_download_url(path: &str, env: &Environment) -> Option<String> {
    if let Some(FsEntry::Download { src }) = filesystem_entry_for_path(env, path) {
        return Some(src.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return match filesystem_entry_for_path(env, stripped) {
                Some(FsEntry::Download { src }) => Some(src.clone()),
                _ => None,
            };
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return tracked_download_url_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    tracked_download_url_by_basename(path, env)
}

fn tracked_download_url_by_basename(path: &str, env: &Environment) -> Option<String> {
    for (tracked_path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(tracked_path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(path) {
            if let FsEntry::Download { src } = entry {
                return Some(src.clone());
            }
        }
    }
    None
}

fn tracked_transfer_entry(path: &str, env: &Environment) -> Option<FsEntry> {
    let entry = filesystem_entry_for_path(env, path)?;
    match entry {
        FsEntry::Content { .. }
        | FsEntry::Decoded { .. }
        | FsEntry::Download { .. }
        | FsEntry::Copy { .. } => Some(entry.clone()),
        FsEntry::Directory => None,
    }
}

fn is_get_content_token(token: &str) -> bool {
    matches!(
        strip_quotes(token).to_ascii_lowercase().as_str(),
        "get-content" | "gc" | "cat" | "type"
    )
}

fn is_content_write_token(token: &str) -> bool {
    matches!(
        strip_quotes(token).to_ascii_lowercase().as_str(),
        "set-content" | "sc" | "out-file"
    )
}

fn is_copy_item_token(token: &str) -> bool {
    matches!(
        strip_quotes(token).to_ascii_lowercase().as_str(),
        "copy-item" | "copy" | "cp" | "cpi"
    )
}

fn direct_content_write_append_mode(tokens: &[String], idx: usize) -> Option<bool> {
    match strip_quotes(tokens.get(idx)?).to_ascii_lowercase().as_str() {
        "set-content" | "sc" => Some(false),
        "add-content" | "ac" => Some(true),
        "out-file" => Some(powershell_has_switch(tokens, idx + 1, "-append")),
        _ => None,
    }
}

fn powershell_has_switch(tokens: &[String], start: usize, switch: &str) -> bool {
    for token in tokens.iter().skip(start) {
        let token = strip_quotes(token);
        if token == "|" || token == ";" {
            break;
        }
        if token.eq_ignore_ascii_case(switch) {
            return true;
        }
    }
    false
}

fn powershell_stdout_redirect_destination(tokens: &[String], start: usize) -> Option<String> {
    let token = strip_quotes(tokens.get(start)?);
    for op in [">>", "1>>", ">", "1>"] {
        if token == op {
            return tokens
                .get(start + 1)
                .map(|value| strip_quotes(value).to_string());
        }
        if let Some(dst) = token.strip_prefix(op) {
            if !dst.is_empty() {
                return Some(strip_quotes(dst).to_string());
            }
        }
    }
    None
}

fn powershell_set_content_paths_and_value(
    tokens: &[String],
    start: usize,
) -> Option<(String, String)> {
    let mut path: Option<String> = None;
    let mut value: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = start;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        if token == "|" || token == ";" {
            break;
        }
        let lower = token.to_ascii_lowercase();
        if lower == "-path" || lower == "-literalpath" || lower == "-filepath" {
            path = Some(strip_quotes(tokens.get(i + 1)?).to_string());
            i += 2;
            continue;
        }
        if let Some(path_value) = attached_ps_path_value(token) {
            path = Some(path_value.to_string());
            i += 1;
            continue;
        }
        if lower == "-value" || lower == "-inputobject" {
            value = Some(strip_quotes(tokens.get(i + 1)?).to_string());
            i += 2;
            continue;
        }
        if let Some(content_value) = attached_ps_value_value(token) {
            value = Some(content_value.to_string());
            i += 1;
            continue;
        }
        if let Some(content_value) = attached_ps_input_object_value(token) {
            value = Some(content_value.to_string());
            i += 1;
            continue;
        }
        if !token.starts_with('-') {
            positional.push(token.to_string());
        }
        i += 1;
    }
    let path = path.or_else(|| positional.first().cloned())?;
    let value = value.or_else(|| positional.get(1).cloned())?;
    Some((path, value))
}

fn powershell_content_path_arg(tokens: &[String], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        if token == "|" || token == ";" || token.starts_with('>') || token.starts_with("1>") {
            return None;
        }
        let lower = token.to_ascii_lowercase();
        if lower == "-path" || lower == "-literalpath" || lower == "-filepath" {
            let value = strip_quotes(tokens.get(i + 1)?).to_string();
            return Some((value, i + 1));
        }
        if let Some(value) = attached_ps_path_value(token) {
            return Some((value.to_string(), i));
        }
        if !token.starts_with('-') {
            return Some((token.to_string(), i));
        }
        i += 1;
    }
    None
}

fn powershell_copy_item_paths(tokens: &[String], start: usize) -> Option<(String, String)> {
    let mut src: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = start;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        if token == "|" || token == ";" {
            break;
        }
        let lower = token.to_ascii_lowercase();
        if lower == "-path" || lower == "-literalpath" {
            src = Some(strip_quotes(tokens.get(i + 1)?).to_string());
            i += 2;
            continue;
        }
        if let Some(value) = attached_ps_path_value(token) {
            src = Some(value.to_string());
            i += 1;
            continue;
        }
        if lower == "-destination" || lower == "-dest" {
            dst = Some(strip_quotes(tokens.get(i + 1)?).to_string());
            i += 2;
            continue;
        }
        if let Some(value) = attached_ps_destination_value(token) {
            dst = Some(value.to_string());
            i += 1;
            continue;
        }
        if !token.starts_with('-') {
            positional.push(token.to_string());
        }
        i += 1;
    }
    let src = src.or_else(|| positional.first().cloned())?;
    let dst = dst.or_else(|| positional.get(1).cloned())?;
    Some((src, dst))
}

fn attached_ps_value_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    let rest = lower.strip_prefix("-value")?;
    let original_rest = &token[token.len() - rest.len()..];
    let value = original_rest.trim_start_matches([':', '=']);
    (!value.is_empty()).then(|| strip_quotes(value))
}

fn attached_ps_input_object_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    let rest = lower.strip_prefix("-inputobject")?;
    let original_rest = &token[token.len() - rest.len()..];
    let value = original_rest.trim_start_matches([':', '=']);
    (!value.is_empty()).then(|| strip_quotes(value))
}

fn attached_ps_path_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for flag in ["-path", "-literalpath", "-filepath"] {
        let Some(rest) = lower.strip_prefix(flag) else {
            continue;
        };
        let original_rest = &token[token.len() - rest.len()..];
        let value = original_rest.trim_start_matches([':', '=']);
        if !value.is_empty() {
            return Some(strip_quotes(value));
        }
    }
    None
}

fn attached_ps_destination_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for flag in ["-destination", "-dest"] {
        let Some(rest) = lower.strip_prefix(flag) else {
            continue;
        };
        let original_rest = &token[token.len() - rest.len()..];
        let value = original_rest.trim_start_matches([':', '=']);
        if !value.is_empty() {
            return Some(strip_quotes(value));
        }
    }
    None
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn content_from_entry(entry: Option<&FsEntry>) -> Option<Vec<u8>> {
    match entry {
        Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
            Some(content.clone())
        }
        _ => None,
    }
}

fn skip_ps_meta_flags(tokens: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if attached_ps_flag_value(t).is_some() {
            i += 1;
            continue;
        }
        if let Some(flag) = canonical_ps_flag(t) {
            i += if flag_takes_value(flag) { 2 } else { 1 };
            continue;
        }
        out.push(t.clone());
        i += 1;
    }
    out.join(" ")
}

fn command_body_from_attached_value(value: &str, rest: &[String]) -> String {
    let first = strip_quotes(value);
    if rest.is_empty() {
        first.to_string()
    } else {
        let mut body = String::from(first);
        body.push(' ');
        body.push_str(&rest.join(" "));
        body.trim().trim_matches('"').trim_matches('\'').to_string()
    }
}

fn collect_encoded_argument_with_prefix(first: &str, rest: &[String]) -> String {
    let mut out = String::new();
    let first = strip_quotes(first);
    if first.bytes().all(is_base64_byte) {
        out.push_str(first);
    }
    if first.ends_with('=') {
        return out;
    }
    for token in rest {
        let s = strip_quotes(token);
        if s.is_empty() || !s.bytes().all(is_base64_byte) {
            break;
        }
        out.push_str(s);
        if s.ends_with('=') {
            break;
        }
    }
    out
}

fn collect_encoded_argument(tokens: &[String]) -> String {
    let mut out = String::new();
    for token in tokens {
        let s = strip_quotes(token);
        if s.is_empty() || !s.bytes().all(is_base64_byte) {
            break;
        }
        out.push_str(s);
        if s.ends_with('=') {
            break;
        }
    }
    out
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn strip_quotes(s: &str) -> &str {
    s.trim().trim_matches(['"', '\''])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine;

    fn encode_utf16le_b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(
            s.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn canonical_resolves_prefix_shorthand() {
        assert_eq!(canonical_ps_flag("-Enc"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("-Encoded"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("-NoP"), Some("NoProfile"));
        assert_eq!(canonical_ps_flag("-NonI"), Some("NonInteractive"));
        assert_eq!(canonical_ps_flag("-NoE"), Some("NoExit"));
        assert_eq!(canonical_ps_flag("-NoL"), Some("NoLogo"));
        assert_eq!(canonical_ps_flag("-Sta"), Some("Sta"));
        assert_eq!(canonical_ps_flag("-V"), Some("Version"));
        assert_eq!(canonical_ps_flag("/c"), Some("Command"));
        assert_eq!(canonical_ps_flag("-F"), Some("File"));
        assert_eq!(canonical_ps_flag("-W"), Some("WindowStyle"));
    }

    #[test]
    fn canonical_resolves_camelcase_initials() {
        // Initials like `Ec` come from EncodedCommand (E + C), and aren't a
        // literal prefix of any flag name — exercise the initials path.
        assert_eq!(canonical_ps_flag("-Ec"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("-Ep"), Some("ExecutionPolicy"));
        assert_eq!(canonical_ps_flag("-Ws"), Some("WindowStyle"));
        assert_eq!(canonical_ps_flag("-Np"), Some("NoProfile"));
        assert_eq!(canonical_ps_flag("-Ni"), Some("NonInteractive"));
        assert_eq!(canonical_ps_flag("-If"), Some("InputFormat"));
        assert_eq!(canonical_ps_flag("-Of"), Some("OutputFormat"));
        assert_eq!(canonical_ps_flag("-Cn"), Some("ConfigurationName"));
    }

    #[test]
    fn canonical_returns_none_for_ambiguous_or_unknown() {
        // `-No` is a prefix of NoProfile/NonInteractive/NoExit/NoLogo and
        // not an exact match — ambiguous, no override.
        assert_eq!(canonical_ps_flag("-No"), None);
        // Not a flag at all.
        assert_eq!(canonical_ps_flag("BypASs"), None);
        assert_eq!(canonical_ps_flag(""), None);
    }

    #[test]
    fn dash_e_resolves_to_encodedcommand_via_override() {
        // `-e` is prefix-ambiguous between EncodedCommand and ExecutionPolicy.
        // PS resolves it to EncodedCommand by internal precedence.
        assert_eq!(canonical_ps_flag("-e"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("/e"), Some("EncodedCommand"));
    }

    #[test]
    fn ex_resolves_to_executionpolicy_not_encodedcommand() {
        // `-Ex` is a literal prefix of -ExecutionPolicy and is also the
        // CamelCase abbreviation of `-ExecutionPolicy` (E+x lower = ex). It
        // must NOT match -EncodedCommand.
        assert_eq!(canonical_ps_flag("-Ex"), Some("ExecutionPolicy"));
        assert_eq!(canonical_ps_flag("-eX"), Some("ExecutionPolicy"));
    }

    #[test]
    fn dash_co_resolves_to_command_via_override() {
        // `-co` is prefix-ambiguous between Command and ConfigurationName.
        // Old CMD_FLAG_RE accepted -co / -com / -comm / -comma / -comman as
        // Command shortcuts; preserve that legacy via SHORTCUT_OVERRIDES.
        assert_eq!(canonical_ps_flag("-co"), Some("Command"));
        assert_eq!(canonical_ps_flag("/co"), Some("Command"));
        assert_eq!(canonical_ps_flag("-Co"), Some("Command"));
        // Longer prefixes are unambiguous via the prefix path and resolve
        // to Command without needing the override.
        assert_eq!(canonical_ps_flag("-com"), Some("Command"));
        assert_eq!(canonical_ps_flag("-Command"), Some("Command"));
    }

    #[test]
    fn attached_encodedcommand_value_is_decoded() {
        let encoded = encode_utf16le_b64("Write-Host attached");
        let mut env = Environment::new(&crate::Config::default());

        h_powershell(&format!("powershell -NoP -enc:{encoded}"), &mut env);

        let units = env.exec_ps1[0]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let decoded = String::from_utf16_lossy(&units);
        assert!(
            decoded.contains("Write-Host attached"),
            "attached encoded command was not decoded: {:?}",
            env.exec_ps1
        );
    }
}
