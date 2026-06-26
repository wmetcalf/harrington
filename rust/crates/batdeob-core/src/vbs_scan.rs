//! VBScript payload post-processing: extract URLs from VBS payloads.
//! Common patterns: MSXML2.XMLHTTP, WinHTTP.WinHTTPRequest, URLDownloadToFile.

use crate::env::Environment;
use crate::traits::Trait;
use crate::util::{
    find_ascii_case_insensitive_from, snippet_prefix, snippet_suffix,
    starts_with_ascii_case_insensitive,
};
use once_cell::sync::Lazy;
use regex::Regex;

const MAX_EXECUTE_COUNT: usize = 100;
const MAX_EXECUTE_EXPANSION_BYTES: usize = 1024 * 1024;

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
    Regex::new(
        r#"(?i)\bURLDownloadToFile(?:A|W)?\b\s*\(?\s*(?:[^,\r\n]+,\s*)?([A-Za-z_][A-Za-z0-9_]*)\b"#,
    )
    .expect("urldown variable")
});

#[allow(clippy::expect_used)]
static RESPONSE_REDIRECT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bResponse\.Redirect\s*\(?\s*"([^"]+)""#).expect("response redirect")
});

pub fn scan_vbs_payloads(env: &mut Environment) {
    extract_vbs_execute_inners(env);

    let payloads: Vec<Vec<u8>> = env.all_extracted_vbs.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    let mut seen_launches: std::collections::HashSet<(usize, String)> =
        std::collections::HashSet::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let raw = String::from_utf8_lossy(payload);
        let text = join_vbs_line_continuations(&raw);
        let bindings = collect_vbs_string_bindings(&text);
        let dst_hint: Option<String> = SAVETOFILE_RE
            .captures(&text)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let regexes: &[&Lazy<Regex>] = &[&XMLHTTP_OPEN_RE, &URLDOWN_RE];
        for re in regexes {
            for caps in re.captures_iter(&text) {
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
                let snippet = snippet_prefix(&text, 120);
                let dst = urldownload_dst_for_url(&text, url_match.as_str(), &url, &bindings)
                    .or_else(|| dst_hint.clone());
                env.traits.push(Trait::Download {
                    cmd: format!("(vbs #{idx}) {snippet}"),
                    src: url,
                    dst,
                });
            }
        }

        for caps in RESPONSE_REDIRECT_RE.captures_iter(&text) {
            let Some(url_match) = caps.get(1) else {
                continue;
            };
            let Some(url) = crate::deob_scan::normalize_liberal_url_token(url_match.as_str())
            else {
                continue;
            };
            if !seen_launches.insert((idx, url.clone())) {
                continue;
            }
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::UrlLaunch {
                cmd: format!("(vbs #{idx}) {snippet}"),
                url,
            });
        }

        for url in extract_shell_run_url_exprs(&text, &bindings) {
            if !seen_launches.insert((idx, url.clone())) {
                continue;
            }
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::UrlLaunch {
                cmd: format!("(vbs #{idx}) {snippet}"),
                url,
            });
        }

        for expr in extract_xmlhttp_open_url_exprs(&text) {
            let Some(url) = eval_vbs_string_expr(expr, &bindings)
                .and_then(|value| crate::deob_scan::normalize_liberal_url_token(&value))
            else {
                continue;
            };
            if !seen.insert((idx, url.clone())) {
                continue;
            }
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst_hint.clone(),
            });
        }

        for caps in XMLHTTP_OPEN_VAR_RE.captures_iter(&text) {
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
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst_hint.clone(),
            });
        }

        for caps in URLDOWN_VAR_RE.captures_iter(&text) {
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
            let snippet = snippet_prefix(&text, 120);
            let dst = urldownload_dst_for_url(&text, var_match.as_str(), &url, &bindings)
                .or_else(|| dst_hint.clone());
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst,
            });
        }

        for (url, dst) in extract_urldownload_expr_downloads(&text, &bindings) {
            if !seen.insert((idx, url.clone())) {
                continue;
            }
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst.or_else(|| dst_hint.clone()),
            });
        }
    }
}

fn extract_shell_run_url_exprs(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    let mut urls = Vec::new();
    for line in text.lines() {
        let Some(run_pos) = find_ascii_case_insensitive_from(line, ".run", 0) else {
            continue;
        };
        let mut args = line[run_pos + ".run".len()..].trim();
        if let Some(stripped) = args.strip_prefix('(') {
            args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
        }
        let Some(first_arg) = split_vbs_args(args).first().copied() else {
            continue;
        };
        let Some(value) = eval_vbs_string_expr(first_arg, bindings) else {
            continue;
        };
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(&value) {
            urls.push(url);
        }
    }
    urls
}

fn extract_urldownload_expr_downloads(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !crate::util::contains_ascii_case_insensitive(line, "urldownloadtofile") {
            continue;
        }
        let args = urldownload_args(line);
        for idx in 0..args.len() {
            let Some(value) = eval_vbs_string_expr(args[idx].trim(), bindings) else {
                continue;
            };
            let Some(url) = crate::deob_scan::normalize_liberal_url_token(&value) else {
                continue;
            };
            let dst = args
                .get(idx + 1)
                .and_then(|arg| eval_vbs_string_expr(arg.trim(), bindings))
                .filter(|candidate| {
                    crate::deob_scan::normalize_liberal_url_token(candidate).is_none()
                });
            out.push((url, dst));
        }
    }
    out
}

fn urldownload_dst_for_url(
    text: &str,
    url_arg_hint: &str,
    normalized_url: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for line in text.lines() {
        if !crate::util::contains_ascii_case_insensitive(line, "urldownloadtofile")
            || !line.contains(url_arg_hint)
        {
            continue;
        }
        let args = urldownload_args(line);
        for idx in 0..args.len() {
            let Some(value) = eval_vbs_string_expr(args[idx].trim(), bindings) else {
                continue;
            };
            let Some(url) = crate::deob_scan::normalize_liberal_url_token(&value) else {
                continue;
            };
            if url != normalized_url {
                continue;
            }
            return args
                .get(idx + 1)
                .and_then(|arg| eval_vbs_string_expr(arg.trim(), bindings))
                .filter(|dst| crate::deob_scan::normalize_liberal_url_token(dst).is_none());
        }
    }
    None
}

fn urldownload_args(line: &str) -> Vec<&str> {
    let Some(start) = find_ascii_case_insensitive_from(line, "urldownloadtofile", 0) else {
        return Vec::new();
    };
    let mut rest = &line[start + "urldownloadtofile".len()..];
    rest = rest.trim_start();
    if matches!(rest.as_bytes().first(), Some(b'A' | b'a' | b'W' | b'w')) {
        rest = &rest[1..];
        rest = rest.trim_start();
    }
    if let Some(stripped) = rest.strip_prefix('(') {
        rest = stripped;
    }
    let rest = rest.trim_end().strip_suffix(')').unwrap_or(rest);
    split_vbs_args(rest)
}

fn extract_vbs_execute_inners(env: &mut Environment) {
    let mut seen_payloads: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_vbs.iter().cloned().collect();
    let mut queue = env.all_extracted_vbs.clone();
    let mut execute_count = 0usize;
    let mut expanded_bytes = 0usize;
    let mut added: Vec<Vec<u8>> = Vec::new();
    let mut cursor = 0usize;

    while cursor < queue.len()
        && execute_count < MAX_EXECUTE_COUNT
        && expanded_bytes < MAX_EXECUTE_EXPANSION_BYTES
    {
        let payload = queue[cursor].clone();
        cursor += 1;
        let raw = String::from_utf8_lossy(&payload);
        let text = join_vbs_line_continuations(&raw);
        let bindings = collect_vbs_string_bindings(&text);

        for line in text.lines() {
            let Some(expr) = vbs_execute_expr(line) else {
                continue;
            };
            let Some(decoded) = eval_vbs_string_expr(expr, &bindings) else {
                continue;
            };
            let decoded = decoded.trim();
            if decoded.is_empty() {
                continue;
            }
            expanded_bytes = expanded_bytes.saturating_add(decoded.len());
            if expanded_bytes > MAX_EXECUTE_EXPANSION_BYTES {
                break;
            }
            execute_count += 1;
            let bytes = decoded.as_bytes().to_vec();
            if seen_payloads.insert(bytes.clone()) {
                queue.push(bytes.clone());
                added.push(bytes);
            }
            if execute_count >= MAX_EXECUTE_COUNT {
                break;
            }
        }
    }

    env.all_extracted_vbs.extend(added);
}

fn collect_vbs_string_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut bindings = std::collections::HashMap::new();
    for line in text.lines() {
        for statement in split_vbs_statements(line) {
            let Some(caps) = VBS_STRING_ASSIGN_RE.captures(statement) else {
                continue;
            };
            let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let Some(value) = eval_vbs_string_expr(value.as_str(), &bindings) else {
                continue;
            };
            bindings.insert(name.as_str().to_ascii_lowercase(), value);
        }
    }
    bindings
}

fn vbs_execute_expr(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if !starts_with_ascii_case_insensitive(trimmed, "execute") {
        return None;
    }
    let mut rest = &trimmed["execute".len()..];
    rest = rest.trim_start();
    if let Some(stripped) = rest.strip_prefix('(') {
        rest = stripped.trim_start();
    }
    let rest = rest.trim_end();
    let rest = rest.strip_suffix(')').unwrap_or(rest).trim_end();
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}

fn extract_xmlhttp_open_url_exprs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut cursor = 0usize;
        while let Some(open_start) = find_ascii_case_insensitive_from(line, ".open", cursor) {
            let args_start = open_start + ".open".len();
            let next = line.as_bytes().get(args_start).copied();
            if !next.is_some_and(|b| b.is_ascii_whitespace() || b == b'(') {
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
    bindings: &std::collections::HashMap<String, String>,
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
        if let Some(value) = parse_vbs_string_transform(part, bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_split_index(part, bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_cstr(part, bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_replace(part, bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        if let Some(value) = parse_vbs_mid(part, bindings) {
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
    let trimmed = part.trim();
    let inner = if starts_with_ascii_case_insensitive(trimmed, "chrw(") {
        trimmed.get("chrw(".len()..)?
    } else if starts_with_ascii_case_insensitive(trimmed, "chr(") {
        trimmed.get("chr(".len()..)?
    } else {
        return None;
    };
    let inner = inner.strip_suffix(')')?;
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
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if let Some(inner) = vbs_function_args(part, "strreverse") {
        let value = eval_vbs_string_expr(inner, bindings)?;
        return Some(reverse_vbs_string(&value));
    }
    if let Some(inner) = vbs_function_args(part, "lcase") {
        return Some(eval_vbs_string_expr(inner, bindings)?.to_ascii_lowercase());
    }
    if let Some(inner) = vbs_function_args(part, "ucase") {
        return Some(eval_vbs_string_expr(inner, bindings)?.to_ascii_uppercase());
    }
    if let Some(inner) = vbs_function_args(part, "trim") {
        return Some(eval_vbs_string_expr(inner, bindings)?.trim().to_string());
    }
    if let Some(inner) = vbs_function_args(part, "ltrim") {
        return Some(
            eval_vbs_string_expr(inner, bindings)?
                .trim_start()
                .to_string(),
        );
    }
    if let Some(inner) = vbs_function_args(part, "rtrim") {
        return Some(
            eval_vbs_string_expr(inner, bindings)?
                .trim_end()
                .to_string(),
        );
    }
    if let Some(inner) = vbs_function_args(part, "join") {
        let args = split_vbs_args(inner);
        if args.len() < 2 {
            return None;
        }
        let values = parse_vbs_array_values(args[0], bindings)?;
        let separator = eval_vbs_string_expr(args[1], bindings)?;
        return Some(values.join(&separator));
    }
    if starts_with_ascii_case_insensitive(part.trim(), "left(") {
        let args = split_vbs_args(vbs_function_args(part, "left")?);
        if args.len() < 2 {
            return None;
        }
        let value = eval_vbs_string_expr(args[0], bindings)?;
        let count = parse_vbs_integer(args[1])? as usize;
        return Some(snippet_prefix(&value, count));
    }
    if starts_with_ascii_case_insensitive(part.trim(), "right(") {
        let args = split_vbs_args(vbs_function_args(part, "right")?);
        if args.len() < 2 {
            return None;
        }
        let value = eval_vbs_string_expr(args[0], bindings)?;
        let count = parse_vbs_integer(args[1])? as usize;
        return Some(snippet_suffix(&value, count));
    }
    None
}

fn parse_vbs_split_index(
    part: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let trimmed = part.trim();
    if !starts_with_ascii_case_insensitive(trimmed, "split(") || !trimmed.ends_with(')') {
        return None;
    }
    let idx_start = trimmed.rfind(")(")?;
    let call = &trimmed[..idx_start + 1];
    let index = parse_vbs_integer(trimmed[idx_start + 2..trimmed.len() - 1].trim())? as usize;
    let pieces = parse_vbs_split_values(call, bindings)?;
    pieces.get(index).cloned()
}

fn parse_vbs_split_values(
    expr: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<Vec<String>> {
    let inner = vbs_function_args(expr, "split")?;
    let args = split_vbs_args(inner);
    if args.is_empty() {
        return None;
    }
    let source = eval_vbs_string_expr(args[0], bindings)?;
    let separator = if let Some(sep_expr) = args.get(1) {
        eval_vbs_string_expr(sep_expr, bindings)?
    } else {
        " ".to_string()
    };
    Some(if separator.is_empty() {
        source.chars().map(|c| c.to_string()).collect()
    } else {
        source.split(&separator).map(|s| s.to_string()).collect()
    })
}

fn parse_vbs_array_values(
    expr: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<Vec<String>> {
    if let Some(values) = parse_vbs_split_values(expr, bindings) {
        return Some(values);
    }
    let inner = vbs_function_args(expr, "array")?;
    let mut values = Vec::new();
    for arg in split_vbs_args(inner) {
        let value = eval_vbs_string_expr(arg, bindings)?;
        values.push(value);
    }
    Some(values)
}

fn parse_vbs_cstr(
    part: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let inner = vbs_function_args(part, "cstr")?;
    eval_vbs_string_expr(inner, bindings)
}

fn parse_vbs_replace(
    part: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let inner = vbs_function_args(part, "replace")?;
    let args = split_vbs_args(inner);
    if args.len() < 3 {
        return None;
    }
    let source = eval_vbs_string_expr(args[0], bindings)?;
    let find = eval_vbs_string_expr(args[1], bindings)?;
    let replacement = eval_vbs_string_expr(args[2], bindings)?;
    Some(source.replace(&find, &replacement))
}

fn parse_vbs_mid(
    part: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let inner = vbs_function_args(part, "mid")?;
    let args = split_vbs_args(inner);
    if args.len() < 2 {
        return None;
    }
    let source = eval_vbs_string_expr(args[0], bindings)?;
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
    let prefix_len = name.len();
    if !starts_with_ascii_case_insensitive(part, name)
        || part.as_bytes().get(prefix_len) != Some(&b'(')
    {
        return None;
    }
    let inner = part.get(prefix_len + 1..part.len().checked_sub(1)?)?;
    part.ends_with(')').then_some(inner)
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

fn reverse_vbs_string(s: &str) -> String {
    if s.is_ascii() {
        return s.bytes().rev().map(|b| b as char).collect();
    }
    s.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_vbs_string_transform, reverse_vbs_string};

    #[test]
    fn parse_vbs_string_transform_matches_mixed_case_left_and_right() {
        let bindings = std::collections::HashMap::new();
        assert_eq!(
            parse_vbs_string_transform("lEfT(\"abcd\", 2)", &bindings),
            Some("ab".to_string())
        );
        assert_eq!(
            parse_vbs_string_transform("rIgHt(\"abcd\", 2)", &bindings),
            Some("cd".to_string())
        );
    }

    #[test]
    fn reverse_vbs_string_fast_paths_ascii_and_preserves_unicode() {
        assert_eq!(reverse_vbs_string("abcd"), "dcba");
        assert_eq!(reverse_vbs_string("héllo"), "olléh");
    }
}
