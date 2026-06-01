//! JScript payload post-processing: extract URLs from JS payloads.
//! Catches GetObject(str+str+str), WScript.Shell.Run("..."), \uXXXX-encoded eval, etc.

use crate::env::Environment;
use crate::traits::Trait;
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

#[allow(clippy::expect_used)]
static URL_IN_JS_RE: Lazy<Regex> = Lazy::new(|| {
    // Generic URL match — picks up any http(s) in the JS text.
    // Case-insensitive + Windows-liberal slashes (`http:\\` / `http:/`
    // / `http:////` all valid). JS obfuscation often splits the scheme
    // with `+` concat — these get joined to mixed case.
    Regex::new(r#"(?i)((?:script:|)(?:https?|ftp|file):[\x2f\x5c]+[^\s"'<>(){}\[\]|^&]+)"#)
        .expect("url-in-js")
});

#[allow(clippy::expect_used)]
static U_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    // Sequences of \uXXXX hex escapes (4 or more consecutive)
    Regex::new(r"((?:\\u[0-9a-fA-F]{4}){4,})").expect("u-escape")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\(\s*([0-9xa-f+\-\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode")
});

#[allow(clippy::expect_used)]
static JS_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)(?:\b(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"#)
        .expect("js assignment")
});

pub fn scan_js_payloads(env: &mut Environment) {
    let payloads: Vec<Vec<u8>> = env.all_extracted_jscript.clone();
    let mut seen: HashSet<(usize, String)> = HashSet::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let raw = String::from_utf8_lossy(payload).into_owned();
        // First pass: decode \uXXXX escapes
        let decoded = decode_u_escapes(&raw);
        // Second pass: collapse "a"+"b"+"c" concat
        let concat_resolved = expand_js_string_concat(&decoded);
        let mut candidates = vec![concat_resolved.clone()];
        candidates.extend(decoded_js_percent_literals(&concat_resolved));
        candidates.extend(decoded_js_fromcharcode_literals(&concat_resolved));
        candidates.extend(decoded_js_atob_literals(&concat_resolved));
        candidates.extend(decoded_js_split_reverse_join_literals(&concat_resolved));
        candidates.extend(decoded_js_array_join_literals(&concat_resolved));
        candidates.extend(decoded_js_string_bindings(&concat_resolved));

        // Now scan for URLs
        for candidate in candidates {
            for caps in URL_IN_JS_RE.captures_iter(&candidate) {
                let Some(m) = caps.get(1) else { continue };
                let mut url = m.as_str().to_string();
                // Strip "script:" prefix that GetObject uses
                if url.to_ascii_lowercase().starts_with("script:") {
                    url = url["script:".len()..].to_string();
                }
                // Trim trailing punctuation
                while let Some(last) = url.chars().last() {
                    if matches!(
                        last,
                        ',' | '.' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '!' | '?'
                    ) {
                        url.pop();
                    } else {
                        break;
                    }
                }
                let Some(url) = crate::deob_scan::normalize_liberal_url_token(&url) else {
                    continue;
                };
                if crate::deob_scan::is_noise_url(&url) {
                    continue;
                }
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                let snippet: String = concat_resolved.chars().take(120).collect();
                env.traits.push(Trait::Download {
                    cmd: format!("(js #{idx}) {snippet}"),
                    src: url,
                    dst: None,
                });
            }
        }
    }
}

fn decoded_js_percent_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for name in ["decodeURIComponent", "unescape"] {
        let lower = text.to_ascii_lowercase();
        let needle = name.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find(&needle) {
            let name_start = cursor + rel;
            let name_end = name_start + name.len();
            let open = skip_ascii_ws(text, name_end);
            if text.as_bytes().get(open) != Some(&b'(') {
                cursor = name_end;
                continue;
            }
            let literal_start = skip_ascii_ws(text, open + 1);
            let Some((literal_end, value)) = parse_js_string_literal_at(text, literal_start) else {
                cursor = open + 1;
                continue;
            };
            if value.len() <= 8192 {
                out.push(percent_decode_lenient(&value));
            }
            cursor = literal_end;
        }
    }
    out
}

fn percent_decode_lenient(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 5 < bytes.len() && matches!(bytes[i + 1], b'u' | b'U') {
            if let (Some(h1), Some(h2), Some(h3), Some(h4)) = (
                (bytes[i + 2] as char).to_digit(16),
                (bytes[i + 3] as char).to_digit(16),
                (bytes[i + 4] as char).to_digit(16),
                (bytes[i + 5] as char).to_digit(16),
            ) {
                let codepoint = (h1 << 12) + (h2 << 8) + (h3 << 4) + h4;
                if let Some(ch) = char::from_u32(codepoint) {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    i += 6;
                    continue;
                }
            }
        }
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((h1 * 16 + h2) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decoded_js_fromcharcode_literals(text: &str) -> Vec<String> {
    JS_FROMCHARCODE_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let nums = caps.get(1)?.as_str();
            let mut out = String::new();
            for part in nums.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let n = eval_js_numeric_expr(part)?;
                out.push(char::from_u32(n)?);
            }
            (!out.is_empty()).then_some(out)
        })
        .collect()
}

fn decoded_js_atob_literals(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("atob") {
        let name_start = cursor + rel;
        let name_end = name_start + "atob".len();
        let prev = text[..name_start].chars().next_back();
        let next = text[name_end..].chars().next();
        if prev.is_some_and(is_js_ident_char) || next.is_some_and(is_js_ident_char) {
            cursor = name_end;
            continue;
        }

        let open = skip_ascii_ws(text, name_end);
        if text.as_bytes().get(open) != Some(&b'(') {
            cursor = name_end;
            continue;
        }
        let literal_start = skip_ascii_ws(text, open + 1);
        let Some((literal_end, value)) = parse_js_string_literal_at(text, literal_start) else {
            cursor = open + 1;
            continue;
        };
        if value.len() <= 16384 {
            let cleaned: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            if let Ok(decoded) =
                base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes())
            {
                if decoded.len() <= 8192 {
                    out.push(String::from_utf8_lossy(&decoded).into_owned());
                }
            }
        }
        cursor = literal_end;
    }
    out
}

fn decoded_js_split_reverse_join_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < text.len() {
        let Some((literal_end, value)) = parse_js_string_literal_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };

        let Some((after_split, split_arg)) =
            consume_js_string_arg_method(text, literal_end, "split")
        else {
            cursor = literal_end;
            continue;
        };
        if !split_arg.is_empty() {
            cursor = after_split;
            continue;
        }
        let Some(after_reverse) = consume_js_no_arg_method(text, after_split, "reverse") else {
            cursor = after_split;
            continue;
        };
        let Some((after_join, join_arg)) =
            consume_js_string_arg_method(text, after_reverse, "join")
        else {
            cursor = after_reverse;
            continue;
        };
        if join_arg.is_empty() && value.len() <= 8192 {
            out.push(value.chars().rev().collect());
        }
        cursor = after_join;
    }
    out
}

fn decoded_js_array_join_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < text.len() {
        let Some((array_end, parts)) = parse_js_string_array_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };
        let Some((join_end, sep)) = consume_js_string_arg_method(text, array_end, "join") else {
            cursor = array_end;
            continue;
        };
        if parts.len() <= 128 && sep.len() <= 64 {
            let joined = parts.join(&sep);
            if joined.len() <= 8192 {
                out.push(joined);
            }
        }
        cursor = join_end;
    }
    out
}

fn decoded_js_string_bindings(text: &str) -> Vec<String> {
    let mut bindings = HashMap::new();
    let mut values = Vec::new();
    for caps in JS_ASSIGN_RE.captures_iter(text).take(256) {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr_start) = caps.get(0).map(|m| m.end()) else {
            continue;
        };
        let Some((expr_end, value)) = eval_js_string_expr(text, expr_start, &bindings) else {
            continue;
        };
        if expr_end.saturating_sub(expr_start) > 8192 || value.len() > 8192 {
            continue;
        }
        bindings.insert(name.to_string(), value.clone());
        values.push(value);
    }
    values
}

fn parse_js_string_array_at(text: &str, start: usize) -> Option<(usize, Vec<String>)> {
    if text.as_bytes().get(start) != Some(&b'[') {
        return None;
    }
    let mut parts = Vec::new();
    let mut cursor = skip_ascii_ws(text, start + 1);
    if text.as_bytes().get(cursor) == Some(&b']') {
        return Some((cursor + 1, parts));
    }

    loop {
        let (literal_end, value) = parse_js_string_literal_at(text, cursor)?;
        parts.push(value);
        if parts.len() > 128 {
            return None;
        }
        cursor = skip_ascii_ws(text, literal_end);
        match text.as_bytes().get(cursor) {
            Some(b',') => {
                cursor = skip_ascii_ws(text, cursor + 1);
            }
            Some(b']') => return Some((cursor + 1, parts)),
            _ => return None,
        }
    }
}

fn eval_js_string_expr(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, String)> {
    let mut cursor = skip_ascii_ws(text, start);
    let (mut end, mut out) = parse_js_string_expr_term(text, cursor, bindings)?;
    let mut terms = 1usize;

    loop {
        cursor = skip_ascii_ws(text, end);
        if text.as_bytes().get(cursor) != Some(&b'+') {
            break;
        }
        let next_start = skip_ascii_ws(text, cursor + 1);
        let Some((next_end, value)) = parse_js_string_expr_term(text, next_start, bindings) else {
            break;
        };
        out.push_str(&value);
        terms += 1;
        if terms > 128 || out.len() > 8192 {
            return None;
        }
        end = next_end;
    }

    Some((end, out))
}

fn parse_js_string_expr_term(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, String)> {
    if let Some((end, value)) = parse_js_string_literal_at(text, start) {
        return Some((end, value));
    }

    let (end, name) = parse_js_identifier_at(text, start)?;
    bindings.get(name).cloned().map(|value| (end, value))
}

fn parse_js_identifier_at(text: &str, start: usize) -> Option<(usize, &str)> {
    let mut chars = text[start..].char_indices();
    let (_, first) = chars.next()?;
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return None;
    }
    let mut end = start + first.len_utf8();
    for (rel, ch) in chars {
        if is_js_ident_char(ch) {
            end = start + rel + ch.len_utf8();
        } else {
            break;
        }
    }
    Some((end, &text[start..end]))
}

fn consume_js_string_arg_method(text: &str, idx: usize, name: &str) -> Option<(usize, String)> {
    let open = consume_js_method_open(text, idx, name)?;
    let arg_start = skip_ascii_ws(text, open + 1);
    let (arg_end, arg) = parse_js_string_literal_at(text, arg_start)?;
    let close = skip_ascii_ws(text, arg_end);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some((close + 1, arg))
}

fn consume_js_no_arg_method(text: &str, idx: usize, name: &str) -> Option<usize> {
    let open = consume_js_method_open(text, idx, name)?;
    let close = skip_ascii_ws(text, open + 1);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some(close + 1)
}

fn consume_js_method_open(text: &str, idx: usize, name: &str) -> Option<usize> {
    let dot = skip_ascii_ws(text, idx);
    if text.as_bytes().get(dot) != Some(&b'.') {
        return None;
    }
    let name_start = skip_ascii_ws(text, dot + 1);
    let name_end = name_start.checked_add(name.len())?;
    if text.get(name_start..name_end) != Some(name) {
        return None;
    }
    if text[name_end..]
        .chars()
        .next()
        .is_some_and(is_js_ident_char)
    {
        return None;
    }
    let open = skip_ascii_ws(text, name_end);
    if text.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    Some(open)
}

fn is_js_ident_char(c: char) -> bool {
    c == '_' || c == '$' || c.is_ascii_alphanumeric()
}

fn eval_js_numeric_expr(expr: &str) -> Option<u32> {
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    let mut total: i64 = 0;
    let mut saw_term = false;
    let mut sign: i64 = 1;

    while i < bytes.len() {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        match bytes[i] {
            b'+' => {
                sign = 1;
                i += 1;
                continue;
            }
            b'-' => {
                sign = -1;
                i += 1;
                continue;
            }
            _ => {}
        }

        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_hexdigit()
                || bytes.get(i).is_some_and(|b| *b == b'x' || *b == b'X'))
        {
            i += 1;
        }
        if i == start {
            return None;
        }
        let term = &expr[start..i];
        let value = if let Some(hex) = term.strip_prefix("0x").or_else(|| term.strip_prefix("0X")) {
            i64::from(u32::from_str_radix(hex, 16).ok()?)
        } else {
            i64::from(term.parse::<u32>().ok()?)
        };
        total += sign * value;
        sign = 1;
        saw_term = true;
    }

    if saw_term && total >= 0 {
        u32::try_from(total).ok()
    } else {
        None
    }
}

pub fn decode_u_escapes(text: &str) -> String {
    let mut out = text.to_string();
    let matches: Vec<(usize, usize, String)> = U_ESCAPE_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let s = caps.get(1)?.as_str();
            let mut decoded = String::new();
            for chunk in s.as_bytes().chunks(6) {
                // \uXXXX = 6 bytes
                if chunk.len() != 6 {
                    continue;
                }
                let hex_str = std::str::from_utf8(&chunk[2..6]).ok()?;
                let code = u32::from_str_radix(hex_str, 16).ok()?;
                decoded.push(char::from_u32(code)?);
            }
            Some((full.start(), full.end(), decoded))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

pub fn expand_js_string_concat(text: &str) -> String {
    let mut out = text.to_string();
    let matches = find_js_string_concat_matches(text);
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn find_js_string_concat_matches(text: &str) -> Vec<(usize, usize, String)> {
    let mut matches = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let Some((first_end, first)) = parse_js_string_literal_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };

        let mut end = first_end;
        let mut combined = first;
        let mut parts = 1usize;
        loop {
            let plus = skip_ascii_ws(text, end);
            if text.as_bytes().get(plus) != Some(&b'+') {
                break;
            }
            let next_start = skip_ascii_ws(text, plus + 1);
            let Some((next_end, next)) = parse_js_string_literal_at(text, next_start) else {
                break;
            };
            combined.push_str(&next);
            parts += 1;
            end = next_end;
        }

        if parts > 1 {
            matches.push((
                cursor,
                end,
                format!("\"{}\"", escape_js_double_quoted(&combined)),
            ));
            cursor = end;
        } else {
            cursor = first_end;
        }
    }
    matches
}

fn parse_js_string_literal_at(text: &str, start: usize) -> Option<(usize, String)> {
    let quote_byte = *text.as_bytes().get(start)?;
    if quote_byte != b'\'' && quote_byte != b'"' {
        return None;
    }
    let quote_char = quote_byte as char;

    let mut value = String::new();
    let inner = &text[start + 1..];
    let mut chars = inner.char_indices().peekable();
    while let Some((rel, c)) = chars.next() {
        // Compare against the char form of the quote so a non-ASCII char
        // (e.g. 'ħ' U+0127, low byte 0x27 == `'`) doesn't terminate the
        // string prematurely.
        if c == quote_char {
            return Some((start + 1 + rel + c.len_utf8(), value));
        }
        if c != '\\' {
            value.push(c);
            continue;
        }
        // Decode the escape per JS string semantics so downstream URL
        // extraction sees `\x2f` as `/`. For unrecognized escapes,
        // preserve `\<c>` verbatim so a later decoder can still see the
        // original token.
        let Some(&(_, next)) = chars.peek() else {
            // Trailing lone backslash — preserve as literal.
            value.push('\\');
            break;
        };
        match next {
            'n' => value.push('\n'),
            't' => value.push('\t'),
            'r' => value.push('\r'),
            '\\' => value.push('\\'),
            '\'' => value.push('\''),
            '"' => value.push('"'),
            '`' => value.push('`'),
            'b' => value.push('\u{08}'),
            'f' => value.push('\u{0c}'),
            'v' => value.push('\u{0b}'),
            '0' => value.push('\0'),
            'x' => {
                // \xNN — two hex digits
                let _ = chars.next();
                let h1 = chars.next().map(|(_, c)| c);
                let h2 = chars.next().map(|(_, c)| c);
                if let (Some(h1), Some(h2)) = (h1, h2) {
                    if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                        if let Some(ch) = char::from_u32(d1 * 16 + d2) {
                            value.push(ch);
                            continue;
                        }
                    }
                    // Malformed — preserve literal.
                    value.push('\\');
                    value.push('x');
                    value.push(h1);
                    value.push(h2);
                } else {
                    value.push('\\');
                    value.push('x');
                    if let Some(h) = h1 {
                        value.push(h);
                    }
                }
                continue;
            }
            'u' => {
                let _ = chars.next();
                // \u{...} or \uNNNN
                if matches!(chars.peek(), Some(&(_, '{'))) {
                    let _ = chars.next();
                    let mut hex = String::new();
                    while let Some(&(_, ch)) = chars.peek() {
                        if ch == '}' {
                            let _ = chars.next();
                            break;
                        }
                        if ch.is_ascii_hexdigit() && hex.len() < 6 {
                            hex.push(ch);
                            let _ = chars.next();
                        } else {
                            break;
                        }
                    }
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            value.push(ch);
                            continue;
                        }
                    }
                    value.push_str("\\u{");
                    value.push_str(&hex);
                    value.push('}');
                    continue;
                }
                let mut hex = String::new();
                for _ in 0..4 {
                    if let Some(&(_, ch)) = chars.peek() {
                        if ch.is_ascii_hexdigit() {
                            hex.push(ch);
                            let _ = chars.next();
                        } else {
                            break;
                        }
                    }
                }
                if hex.len() == 4 {
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            value.push(ch);
                            continue;
                        }
                    }
                }
                value.push_str("\\u");
                value.push_str(&hex);
                continue;
            }
            other => {
                // Unrecognized escape — push the next char raw (JS spec)
                // but DO NOT drop the backslash for non-letter chars so
                // shapes like `\\\\` and `\\/` survive downstream regexes.
                let _ = chars.next();
                if other.is_ascii_alphabetic() {
                    value.push(other);
                } else {
                    value.push('\\');
                    value.push(other);
                }
                continue;
            }
        }
        let _ = chars.next();
    }
    None
}

fn skip_ascii_ws(text: &str, mut idx: usize) -> usize {
    while let Some(byte) = text.as_bytes().get(idx) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        idx += 1;
    }
    idx
}

fn escape_js_double_quoted(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}
