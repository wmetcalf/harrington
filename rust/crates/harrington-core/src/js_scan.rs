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
static JS_FROMCHARCODE_MEMBER_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\(\s*([0-9xa-f+\-\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode member variable")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_APPLY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\.\s*apply\s*\(\s*[^,\r\n]{0,128},\s*\[\s*([0-9xa-f+\-\s,]{5,8192})\s*\]\s*\)"#,
    )
    .expect("js fromCharCode member apply")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\.\s*call\s*\(\s*[^,\r\n]{0,128},\s*([0-9xa-f+\-\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode member call")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_SPREAD_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\(\s*\.\.\.\s*\[\s*([0-9xa-f+\-\s,]{5,8192})\s*\]\s*\)"#,
    )
    .expect("js fromCharCode member spread array")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_APPLY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\.\s*apply\s*\(\s*[^,\r\n]{0,128},\s*\[\s*([0-9xa-f+\-\s,]{5,8192})\s*\]\s*\)"#,
    )
    .expect("js fromCharCode apply")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_APPLY_ARRAY_CTOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\.\s*apply\s*\(\s*[^,\r\n]{0,128},\s*(?:new\s+)?Array\s*\(\s*([0-9xa-f+\-\s,]{5,8192})\s*\)\s*\)"#,
    )
    .expect("js fromCharCode apply Array constructor")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\.\s*call\s*\(\s*[^,\r\n]{0,128},\s*([0-9xa-f+\-\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode call")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_SPREAD_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\(\s*\.\.\.\s*\[\s*([0-9xa-f+\-\s,]{5,8192})\s*\]\s*\)"#,
    )
    .expect("js fromCharCode spread array")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_SPREAD_ARRAY_CTOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\(\s*\.\.\.\s*(?:new\s+)?Array\s*\(\s*([0-9xa-f+\-\s,]{5,8192})\s*\)\s*\)"#,
    )
    .expect("js fromCharCode spread Array constructor")
});

#[allow(clippy::expect_used)]
static JS_NUM_ARRAY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\b(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[\s*([0-9xa-f+\-\s,]{5,8192})\s*\]"#,
    )
    .expect("js numeric array assignment")
});

#[allow(clippy::expect_used)]
static JS_NUM_ARRAY_CTOR_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\b(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?Array\s*\(\s*([0-9xa-f+\-\s,]{5,8192})\s*\)"#,
    )
    .expect("js numeric array constructor assignment")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_APPLY_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\.\s*apply\s*\(\s*[^,\r\n]{0,128},\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)"#,
    )
    .expect("js fromCharCode apply variable")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_SPREAD_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*fromCharCode|\[\s*['"]fromCharCode['"]\s*\])\s*\(\s*\.\.\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)"#,
    )
    .expect("js fromCharCode spread variable")
});

#[allow(clippy::expect_used)]
static JS_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)(?:\b(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*(\+?=)\s*"#)
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
        candidates.extend(decoded_js_percent_alias_calls(&concat_resolved));
        candidates.extend(decoded_js_fromcharcode_literals(&concat_resolved));
        candidates.extend(decoded_js_fromcharcode_array_bindings(&concat_resolved));
        candidates.extend(decoded_js_atob_literals(&concat_resolved));
        candidates.extend(decoded_js_atob_alias_calls(&concat_resolved));
        candidates.extend(decoded_js_bound_decoder_calls(&concat_resolved));
        candidates.extend(decoded_js_split_reverse_join_literals(&concat_resolved));
        candidates.extend(decoded_js_array_from_reverse_join_literals(
            &concat_resolved,
        ));
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
    let (bindings, _) = collect_js_string_bindings(text);
    let mut cursor = 0usize;
    while cursor < text.len() && out.len() < 128 {
        let Some((ident_end, _)) = parse_js_identifier_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };
        if let Some((call_end, decoded)) = parse_js_percent_call_at(text, cursor, &bindings) {
            out.push(decoded);
            cursor = call_end;
            continue;
        }
        cursor = ident_end;
    }
    out
}

fn decoded_js_percent_alias_calls(text: &str) -> Vec<String> {
    let mut aliases = HashSet::new();
    for name in ["decodeURIComponent", "decodeURI", "unescape"] {
        aliases.extend(collect_js_decoder_aliases(text, name));
    }
    decoded_js_decoder_alias_calls(text, &aliases, |encoded| {
        Some(percent_decode_lenient(encoded))
    })
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
    let mut out: Vec<String> = JS_FROMCHARCODE_RE
        .captures_iter(text)
        .chain(JS_FROMCHARCODE_APPLY_RE.captures_iter(text))
        .chain(JS_FROMCHARCODE_APPLY_ARRAY_CTOR_RE.captures_iter(text))
        .chain(JS_FROMCHARCODE_CALL_RE.captures_iter(text))
        .chain(JS_FROMCHARCODE_SPREAD_ARRAY_RE.captures_iter(text))
        .chain(JS_FROMCHARCODE_SPREAD_ARRAY_CTOR_RE.captures_iter(text))
        .filter_map(|caps| decode_js_fromcharcode_args(caps.get(1)?.as_str()))
        .collect();

    let (bindings, _) = collect_js_string_bindings(text);
    for caps in JS_FROMCHARCODE_MEMBER_VAR_RE.captures_iter(text).take(128) {
        let (Some(name), Some(nums)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if bindings.get(name.as_str()).map(String::as_str) != Some("fromCharCode") {
            continue;
        }
        if let Some(decoded) = decode_js_fromcharcode_args(nums.as_str()) {
            out.push(decoded);
        }
    }
    for caps in JS_FROMCHARCODE_MEMBER_APPLY_RE
        .captures_iter(text)
        .take(128)
    {
        let (Some(name), Some(nums)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if bindings.get(name.as_str()).map(String::as_str) != Some("fromCharCode") {
            continue;
        }
        if let Some(decoded) = decode_js_fromcharcode_args(nums.as_str()) {
            out.push(decoded);
        }
    }
    for caps in JS_FROMCHARCODE_MEMBER_CALL_RE.captures_iter(text).take(128) {
        let (Some(name), Some(nums)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if bindings.get(name.as_str()).map(String::as_str) != Some("fromCharCode") {
            continue;
        }
        if let Some(decoded) = decode_js_fromcharcode_args(nums.as_str()) {
            out.push(decoded);
        }
    }
    for caps in JS_FROMCHARCODE_MEMBER_SPREAD_ARRAY_RE
        .captures_iter(text)
        .take(128)
    {
        let (Some(name), Some(nums)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if bindings.get(name.as_str()).map(String::as_str) != Some("fromCharCode") {
            continue;
        }
        if let Some(decoded) = decode_js_fromcharcode_args(nums.as_str()) {
            out.push(decoded);
        }
    }
    out
}

fn decode_js_fromcharcode_args(nums: &str) -> Option<String> {
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
}

fn decoded_js_fromcharcode_array_bindings(text: &str) -> Vec<String> {
    let mut arrays = HashMap::new();
    for caps in JS_NUM_ARRAY_ASSIGN_RE
        .captures_iter(text)
        .chain(JS_NUM_ARRAY_CTOR_ASSIGN_RE.captures_iter(text))
        .take(128)
    {
        let (Some(name), Some(nums)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if let Some(decoded) = decode_js_fromcharcode_args(nums.as_str()) {
            arrays.insert(name.as_str().to_string(), decoded);
        }
    }

    JS_FROMCHARCODE_APPLY_VAR_RE
        .captures_iter(text)
        .chain(JS_FROMCHARCODE_SPREAD_VAR_RE.captures_iter(text))
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            arrays.get(name).cloned()
        })
        .collect()
}

fn decoded_js_atob_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (bindings, _) = collect_js_string_bindings(text);
    let mut cursor = 0usize;
    while cursor < text.len() && out.len() < 128 {
        let Some((ident_end, _)) = parse_js_identifier_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };
        if let Some((call_end, decoded)) = parse_js_atob_call_at(text, cursor, &bindings) {
            out.push(decoded);
            cursor = call_end;
            continue;
        }
        cursor = ident_end;
    }
    out
}

fn decoded_js_atob_alias_calls(text: &str) -> Vec<String> {
    let aliases = collect_js_decoder_aliases(text, "atob");
    decoded_js_decoder_alias_calls(text, &aliases, decode_js_base64_string)
}

fn decoded_js_decoder_alias_calls<F>(
    text: &str,
    aliases: &HashSet<String>,
    decode: F,
) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    if aliases.is_empty() {
        return Vec::new();
    }
    let (bindings, _) = collect_js_string_bindings(text);
    let arrays = collect_js_string_array_bindings(text, &bindings);
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < text.len() && out.len() < 128 {
        let Some((ident_end, ident)) = parse_js_identifier_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };
        if !aliases.contains(ident) {
            cursor = ident_end;
            continue;
        }
        let (arg_end, encoded) = if let Some((arg_end, encoded)) =
            parse_js_string_decoder_call_method_arg(text, ident_end, &bindings)
        {
            (arg_end, encoded)
        } else {
            let open = skip_ascii_ws(text, ident_end);
            if text.as_bytes().get(open) != Some(&b'(') {
                cursor = ident_end;
                continue;
            }
            let arg_start = skip_ascii_ws(text, open + 1);
            match parse_js_decoder_string_arg(text, arg_start, &bindings, &arrays) {
                Some(parsed) => parsed,
                None => {
                    cursor = ident_end;
                    continue;
                }
            }
        };
        let close = skip_ascii_ws(text, arg_end);
        if text.as_bytes().get(close) != Some(&b')') {
            cursor = arg_end;
            continue;
        }
        if let Some(decoded) = decode(&encoded) {
            out.push(decoded);
        }
        cursor = close + 1;
    }
    out
}

fn collect_js_decoder_aliases(text: &str, decoder: &str) -> HashSet<String> {
    let (bindings, _) = collect_js_string_bindings(text);
    let mut aliases = HashSet::new();
    for caps in JS_ASSIGN_RE.captures_iter(text).take(256) {
        let (Some(name), Some(op), Some(expr)) = (caps.get(1), caps.get(2), caps.get(0)) else {
            continue;
        };
        if op.as_str() != "=" {
            continue;
        }
        let rhs_start = expr.end();
        let Some(decoder_end) = parse_js_named_callee_end(text, rhs_start, decoder)
            .or_else(|| parse_js_bound_member_callee_end(text, rhs_start, decoder, &bindings))
        else {
            continue;
        };
        if !js_decoder_alias_rhs_allowed(text, decoder_end) {
            continue;
        }
        aliases.insert(name.as_str().to_string());
    }
    aliases
}

fn js_decoder_alias_rhs_allowed(text: &str, decoder_end: usize) -> bool {
    let next = skip_ascii_ws(text, decoder_end);
    match text.as_bytes().get(next) {
        Some(b'(') => false,
        Some(b'.') => consume_js_method_open(text, decoder_end, "bind").is_some(),
        Some(b'[') => false,
        _ => true,
    }
}

fn decoded_js_bound_decoder_calls(text: &str) -> Vec<String> {
    let (bindings, _) = collect_js_string_bindings(text);
    if bindings.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < text.len() && out.len() < 128 {
        let Some((ident_end, _)) = parse_js_identifier_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };
        if let Some((call_end, decoded)) = parse_js_atob_call_at(text, cursor, &bindings) {
            out.push(decoded);
            cursor = call_end;
            continue;
        }
        if let Some((call_end, decoded)) = parse_js_percent_call_at(text, cursor, &bindings) {
            out.push(decoded);
            cursor = call_end;
            continue;
        }
        cursor = ident_end;
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

fn decoded_js_array_from_reverse_join_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < text.len() {
        if !js_word_at(text, cursor, "Array") {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        }
        let dot = skip_ascii_ws(text, cursor + "Array".len());
        if text.as_bytes().get(dot) != Some(&b'.') {
            cursor += "Array".len();
            continue;
        }
        let from_start = skip_ascii_ws(text, dot + 1);
        if !js_word_at(text, from_start, "from") {
            cursor = from_start;
            continue;
        }
        let open = skip_ascii_ws(text, from_start + "from".len());
        if text.as_bytes().get(open) != Some(&b'(') {
            cursor = from_start + "from".len();
            continue;
        }
        let literal_start = skip_ascii_ws(text, open + 1);
        let Some((literal_end, value)) = parse_js_string_literal_at(text, literal_start) else {
            cursor = open + 1;
            continue;
        };
        let close = skip_ascii_ws(text, literal_end);
        if text.as_bytes().get(close) != Some(&b')') {
            cursor = literal_end;
            continue;
        }
        let Some(after_reverse) = consume_js_no_arg_method(text, close + 1, "reverse") else {
            cursor = close + 1;
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
        if let Some((join_end, sep)) = consume_js_string_arg_method(text, array_end, "join") {
            if parts.len() <= 128 && sep.len() <= 64 {
                let joined = parts.join(&sep);
                if joined.len() <= 8192 {
                    out.push(joined);
                }
            }
            cursor = join_end;
            continue;
        }
        let Some(after_reverse) = consume_js_no_arg_method(text, array_end, "reverse") else {
            cursor = array_end;
            continue;
        };
        let Some((join_end, sep)) = consume_js_string_arg_method(text, after_reverse, "join")
        else {
            cursor = after_reverse;
            continue;
        };
        if parts.len() <= 128 && sep.len() <= 64 {
            let mut reversed = parts;
            reversed.reverse();
            let joined = reversed.join(&sep);
            if joined.len() <= 8192 {
                out.push(joined);
            }
        }
        cursor = join_end;
    }

    let mut arrays = HashMap::new();
    for caps in JS_ASSIGN_RE.captures_iter(text).take(256) {
        let (Some(name), Some(op), Some(expr)) = (caps.get(1), caps.get(2), caps.get(0)) else {
            continue;
        };
        if op.as_str() != "=" {
            continue;
        }
        let expr_start = expr.end();
        let Some((expr_end, parts)) = parse_js_string_array_at(text, expr_start) else {
            arrays.remove(name.as_str());
            continue;
        };
        if expr_end.saturating_sub(expr_start) <= 8192 && parts.len() <= 128 {
            arrays.insert(name.as_str().to_string(), parts);
        }
    }

    let mut cursor = 0usize;
    while cursor < text.len() {
        let Some((ident_end, name)) = parse_js_identifier_at(text, cursor) else {
            cursor += text[cursor..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
            continue;
        };
        let Some(parts) = arrays.get(name) else {
            cursor = ident_end;
            continue;
        };
        if let Some((join_end, sep)) = consume_js_string_arg_method(text, ident_end, "join") {
            if sep.len() <= 64 {
                let joined = parts.join(&sep);
                if joined.len() <= 8192 {
                    out.push(joined);
                }
            }
            cursor = join_end;
            continue;
        }
        let Some(after_reverse) = consume_js_no_arg_method(text, ident_end, "reverse") else {
            cursor = ident_end;
            continue;
        };
        let Some((join_end, sep)) = consume_js_string_arg_method(text, after_reverse, "join")
        else {
            cursor = after_reverse;
            continue;
        };
        if sep.len() <= 64 {
            let mut reversed = parts.clone();
            reversed.reverse();
            let joined = reversed.join(&sep);
            if joined.len() <= 8192 {
                out.push(joined);
            }
        }
        cursor = join_end;
    }
    out
}

fn decoded_js_string_bindings(text: &str) -> Vec<String> {
    let (_, values) = collect_js_string_bindings(text);
    values
}

fn collect_js_string_bindings(text: &str) -> (HashMap<String, String>, Vec<String>) {
    let mut bindings = HashMap::new();
    let mut arrays = HashMap::new();
    let mut values = Vec::new();
    for caps in JS_ASSIGN_RE.captures_iter(text).take(256) {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(op) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr_start) = caps.get(0).map(|m| m.end()) else {
            continue;
        };
        if op == "=" {
            if let Some((expr_end, parts)) =
                parse_js_string_array_arg_at(text, expr_start, &bindings)
            {
                if expr_end.saturating_sub(expr_start) <= 8192
                    && parts.iter().all(|part| part.len() <= 8192)
                {
                    arrays.insert(name.to_string(), parts);
                }
                continue;
            }
        }
        let Some((expr_end, value)) = eval_js_string_expr(text, expr_start, &bindings)
            .or_else(|| parse_js_array_index_arg(text, expr_start, &arrays))
            .or_else(|| parse_js_array_method_arg(text, expr_start, &arrays))
            .or_else(|| parse_js_array_join_arg(text, expr_start, &bindings, &arrays))
        else {
            continue;
        };
        let value = if op == "+=" {
            let Some(existing) = bindings.get(name) else {
                continue;
            };
            format!("{existing}{value}")
        } else {
            value
        };
        if expr_end.saturating_sub(expr_start) > 8192 || value.len() > 8192 {
            continue;
        }
        bindings.insert(name.to_string(), value.clone());
        values.push(value);
    }
    (bindings, values)
}

fn parse_js_string_array_at(text: &str, start: usize) -> Option<(usize, Vec<String>)> {
    parse_js_string_array_arg_at(text, start, &HashMap::new())
}

fn parse_js_string_array_arg_at(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, Vec<String>)> {
    let (open, close_byte) = if text.as_bytes().get(start) == Some(&b'[') {
        (start, b']')
    } else {
        (parse_js_array_constructor_open(text, start)?, b')')
    };

    let mut parts = Vec::new();
    let mut cursor = skip_ascii_ws(text, open + 1);
    if text.as_bytes().get(cursor) == Some(&close_byte) {
        return Some((cursor + 1, parts));
    }

    loop {
        let (literal_end, value) = parse_js_string_or_bound_arg(text, cursor, bindings)?;
        parts.push(value);
        if parts.len() > 128 {
            return None;
        }
        cursor = skip_ascii_ws(text, literal_end);
        match text.as_bytes().get(cursor) {
            Some(b',') => {
                cursor = skip_ascii_ws(text, cursor + 1);
            }
            Some(byte) if *byte == close_byte => return Some((cursor + 1, parts)),
            _ => return None,
        }
    }
}

fn collect_js_string_array_bindings(
    text: &str,
    bindings: &HashMap<String, String>,
) -> HashMap<String, Vec<String>> {
    let mut arrays = HashMap::new();
    for caps in JS_ASSIGN_RE.captures_iter(text).take(256) {
        let (Some(name), Some(op), Some(expr)) = (caps.get(1), caps.get(2), caps.get(0)) else {
            continue;
        };
        if op.as_str() != "=" {
            continue;
        }
        let Some((expr_end, parts)) = parse_js_string_array_arg_at(text, expr.end(), bindings)
        else {
            continue;
        };
        if expr_end.saturating_sub(expr.end()) > 8192 || parts.iter().any(|part| part.len() > 8192)
        {
            continue;
        }
        arrays.insert(name.as_str().to_string(), parts);
    }
    arrays
}

fn parse_js_array_constructor_open(text: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    if js_word_at(text, cursor, "new") {
        cursor = skip_ascii_ws(text, cursor + "new".len());
    }
    if !js_word_at(text, cursor, "Array") {
        return None;
    }
    let open = skip_ascii_ws(text, cursor + "Array".len());
    if text.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    Some(open)
}

fn js_word_at(text: &str, start: usize, word: &str) -> bool {
    let Some(end) = start.checked_add(word.len()) else {
        return false;
    };
    if text.get(start..end) != Some(word) {
        return false;
    }
    let prev = text[..start].chars().next_back();
    let next = text[end..].chars().next();
    !prev.is_some_and(is_js_ident_char) && !next.is_some_and(is_js_ident_char)
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
        return Some(consume_js_string_transform_chain(text, end, value));
    }
    if let Some((end, value)) = parse_js_atob_call_at(text, start, bindings) {
        return Some(consume_js_string_transform_chain(text, end, value));
    }
    if let Some((end, value)) = parse_js_percent_call_at(text, start, bindings) {
        return Some(consume_js_string_transform_chain(text, end, value));
    }

    let (end, name) = parse_js_identifier_at(text, start)?;
    bindings
        .get(name)
        .cloned()
        .map(|value| consume_js_string_transform_chain(text, end, value))
}

fn parse_js_percent_call_at(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, String)> {
    let arrays = collect_js_string_array_bindings(text, bindings);
    for name in ["decodeURIComponent", "decodeURI", "unescape"] {
        let Some(name_end) = parse_js_named_callee_end(text, start, name)
            .or_else(|| parse_js_bound_member_callee_end(text, start, name, bindings))
        else {
            continue;
        };
        let (arg_end, encoded) = if let Some((arg_end, encoded)) =
            parse_js_string_decoder_call_method_arg(text, name_end, bindings)
        {
            (arg_end, encoded)
        } else {
            let open = skip_ascii_ws(text, name_end);
            if text.as_bytes().get(open) != Some(&b'(') {
                continue;
            }
            let arg_start = skip_ascii_ws(text, open + 1);
            parse_js_decoder_string_arg(text, arg_start, bindings, &arrays)?
        };
        let close = skip_ascii_ws(text, arg_end);
        if text.as_bytes().get(close) != Some(&b')') {
            continue;
        }
        return Some((close + 1, percent_decode_lenient(&encoded)));
    }
    None
}

fn parse_js_atob_call_at(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, String)> {
    let arrays = collect_js_string_array_bindings(text, bindings);
    let name_end = parse_js_named_callee_end(text, start, "atob")
        .or_else(|| parse_js_bound_member_callee_end(text, start, "atob", bindings))?;
    let (arg_end, encoded) = if let Some((arg_end, encoded)) =
        parse_js_string_decoder_call_method_arg(text, name_end, bindings)
    {
        (arg_end, encoded)
    } else {
        let open = skip_ascii_ws(text, name_end);
        if text.as_bytes().get(open) != Some(&b'(') {
            return None;
        }
        let arg_start = skip_ascii_ws(text, open + 1);
        parse_js_decoder_string_arg(text, arg_start, bindings, &arrays)?
    };
    let close = skip_ascii_ws(text, arg_end);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    decode_js_base64_string(&encoded).map(|decoded| (close + 1, decoded))
}

fn parse_js_string_decoder_call_method_arg(
    text: &str,
    callee_end: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, String)> {
    if let Some(open) = consume_js_method_open(text, callee_end, "call") {
        let comma = find_js_call_comma(text, skip_ascii_ws(text, open + 1))?;
        let arg_start = skip_ascii_ws(text, comma + 1);
        let arrays = collect_js_string_array_bindings(text, bindings);
        return parse_js_decoder_string_arg(text, arg_start, bindings, &arrays);
    }

    let open = consume_js_method_open(text, callee_end, "apply")?;
    let comma = find_js_call_comma(text, skip_ascii_ws(text, open + 1))?;
    let arg_start = skip_ascii_ws(text, comma + 1);
    if let Some((array_end, mut parts)) = parse_js_string_array_arg_at(text, arg_start, bindings) {
        let mut end = array_end;
        if let Some((slice_end, sliced)) = consume_js_slice_call(text, array_end, &parts) {
            end = slice_end;
            parts = sliced;
        }
        return if parts.len() == 1 {
            parts.into_iter().next().map(|value| (end, value))
        } else {
            None
        };
    }
    let (arg_end, name) = parse_js_identifier_at(text, arg_start)?;
    let arrays = collect_js_string_array_bindings(text, bindings);
    let mut parts = arrays.get(name)?.clone();
    let mut end = arg_end;
    if let Some((slice_end, sliced)) = consume_js_slice_call(text, arg_end, &parts) {
        end = slice_end;
        parts = sliced;
    }
    (parts.len() == 1).then(|| (end, parts[0].clone()))
}

fn parse_js_string_or_bound_arg(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
) -> Option<(usize, String)> {
    if let Some((arg_end, value)) = parse_js_string_literal_at(text, start) {
        Some((arg_end, value))
    } else {
        let (arg_end, name) = parse_js_identifier_at(text, start)?;
        Some((arg_end, bindings.get(name)?.clone()))
    }
}

fn parse_js_decoder_string_arg(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
    arrays: &HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    eval_js_string_expr(text, start, bindings)
        .or_else(|| parse_js_array_index_arg(text, start, arrays))
        .or_else(|| parse_js_array_method_arg(text, start, arrays))
        .or_else(|| parse_js_array_join_arg(text, start, bindings, arrays))
}

fn parse_js_array_index_arg(
    text: &str,
    start: usize,
    arrays: &HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    let (ident_end, name) = parse_js_identifier_at(text, start)?;
    let open = skip_ascii_ws(text, ident_end);
    if text.as_bytes().get(open) != Some(&b'[') {
        return None;
    }
    let index_start = skip_ascii_ws(text, open + 1);
    let mut index_end = index_start;
    while text
        .as_bytes()
        .get(index_end)
        .is_some_and(u8::is_ascii_digit)
    {
        index_end += 1;
    }
    if index_end == index_start {
        return None;
    }
    let index = text[index_start..index_end].parse::<usize>().ok()?;
    let close = skip_ascii_ws(text, index_end);
    if text.as_bytes().get(close) != Some(&b']') {
        return None;
    }
    arrays
        .get(name)?
        .get(index)
        .cloned()
        .map(|value| (close + 1, value))
}

fn parse_js_array_method_arg(
    text: &str,
    start: usize,
    arrays: &HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    let (ident_end, name) = parse_js_identifier_at(text, start)?;
    let values = arrays.get(name)?;
    if let Some(end) = consume_js_no_arg_method(text, ident_end, "shift") {
        return values.first().cloned().map(|value| (end, value));
    }
    if let Some(end) = consume_js_no_arg_method(text, ident_end, "pop") {
        return values.last().cloned().map(|value| (end, value));
    }
    None
}

fn parse_js_array_join_arg(
    text: &str,
    start: usize,
    bindings: &HashMap<String, String>,
    arrays: &HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    let start = skip_ascii_ws(text, start);
    if let Some((array_end, parts)) = parse_js_string_array_arg_at(text, start, bindings) {
        return consume_js_array_join_chain(text, array_end, parts);
    }

    let (ident_end, name) = parse_js_identifier_at(text, start)?;
    consume_js_array_join_chain(text, ident_end, arrays.get(name)?.clone())
}

fn consume_js_array_join_chain(
    text: &str,
    mut idx: usize,
    mut parts: Vec<String>,
) -> Option<(usize, String)> {
    if let Some((slice_end, sliced)) = consume_js_slice_call(text, idx, &parts) {
        idx = slice_end;
        parts = sliced;
    }

    if let Some((join_end, sep)) = consume_js_string_arg_method(text, idx, "join") {
        return join_js_string_parts(parts, &sep).map(|joined| (join_end, joined));
    }

    let mut after_reverse = consume_js_no_arg_method(text, idx, "reverse")?;
    parts.reverse();
    if let Some((slice_end, sliced)) = consume_js_slice_call(text, after_reverse, &parts) {
        after_reverse = slice_end;
        parts = sliced;
    }
    let (join_end, sep) = consume_js_string_arg_method(text, after_reverse, "join")?;
    join_js_string_parts(parts, &sep).map(|joined| (join_end, joined))
}

fn consume_js_slice_call(text: &str, idx: usize, parts: &[String]) -> Option<(usize, Vec<String>)> {
    let open = consume_js_method_open(text, idx, "slice")?;
    let mut cursor = skip_ascii_ws(text, open + 1);
    let len = parts.len();

    if text.as_bytes().get(cursor) == Some(&b')') {
        return Some((cursor + 1, parts.to_vec()));
    }

    let (start_end, start_arg) = parse_js_signed_integer_at(text, cursor)?;
    cursor = skip_ascii_ws(text, start_end);

    let mut end_arg = None;
    if text.as_bytes().get(cursor) == Some(&b',') {
        cursor = skip_ascii_ws(text, cursor + 1);
        if text.as_bytes().get(cursor) != Some(&b')') {
            let (end_end, parsed_end) = parse_js_signed_integer_at(text, cursor)?;
            end_arg = Some(parsed_end);
            cursor = skip_ascii_ws(text, end_end);
        }
    }

    if text.as_bytes().get(cursor) != Some(&b')') {
        return None;
    }

    let start = js_slice_bound(start_arg, len);
    let end = end_arg
        .map(|arg| js_slice_bound(arg, len))
        .unwrap_or(len)
        .max(start);
    Some((cursor + 1, parts[start..end].to_vec()))
}

fn parse_js_signed_integer_at(text: &str, start: usize) -> Option<(usize, isize)> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    let sign = match bytes.get(cursor) {
        Some(b'-') => {
            cursor += 1;
            -1isize
        }
        Some(b'+') => {
            cursor += 1;
            1isize
        }
        _ => 1isize,
    };

    let digits_start = cursor;
    let mut value = 0isize;
    while let Some(byte) = bytes.get(cursor) {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as isize)?;
        cursor += 1;
        if cursor.saturating_sub(digits_start) > 8 {
            return None;
        }
    }
    (cursor != digits_start).then_some((cursor, value * sign))
}

fn js_slice_bound(index: isize, len: usize) -> usize {
    let len = len as isize;
    if index < 0 {
        (len + index).clamp(0, len) as usize
    } else {
        index.min(len) as usize
    }
}

fn join_js_string_parts(parts: Vec<String>, sep: &str) -> Option<String> {
    if parts.len() > 128 || sep.len() > 64 || parts.iter().any(|part| part.len() > 8192) {
        return None;
    }
    let joined = parts.join(sep);
    (joined.len() <= 8192).then_some(joined)
}

fn consume_js_string_transform_chain(text: &str, idx: usize, value: String) -> (usize, String) {
    let mut idx = idx;
    let mut value = value;
    for _ in 0..16 {
        let (replace_end, replaced) = consume_js_replace_chain(text, idx, value);
        if replace_end != idx {
            idx = replace_end;
            value = replaced;
            continue;
        }
        value = replaced;

        if let Some((trim_end, trimmed)) = consume_js_string_trim_call(text, idx, &value) {
            idx = trim_end;
            value = trimmed;
        } else if let Some((slice_end, sliced)) = consume_js_string_slice_call(text, idx, &value) {
            idx = slice_end;
            value = sliced;
        } else if let Some((substr_end, substr)) = consume_js_string_substr_call(text, idx, &value)
        {
            idx = substr_end;
            value = substr;
        } else if let Some((substring_end, substring)) =
            consume_js_string_substring_call(text, idx, &value)
        {
            idx = substring_end;
            value = substring;
        } else if let Some((reverse_join_end, reversed)) =
            consume_js_split_reverse_join_chain(text, idx, &value)
        {
            idx = reverse_join_end;
            value = reversed;
        } else {
            break;
        }

        if value.len() > 8192 {
            break;
        }
    }
    (idx, value)
}

fn consume_js_string_trim_call(text: &str, idx: usize, value: &str) -> Option<(usize, String)> {
    if let Some(end) = consume_js_no_arg_method(text, idx, "trim") {
        return Some((end, value.trim().to_string()));
    }
    if let Some(end) = consume_js_no_arg_method(text, idx, "trimStart")
        .or_else(|| consume_js_no_arg_method(text, idx, "trimLeft"))
    {
        return Some((end, value.trim_start().to_string()));
    }
    if let Some(end) = consume_js_no_arg_method(text, idx, "trimEnd")
        .or_else(|| consume_js_no_arg_method(text, idx, "trimRight"))
    {
        return Some((end, value.trim_end().to_string()));
    }
    None
}

fn consume_js_string_slice_call(text: &str, idx: usize, value: &str) -> Option<(usize, String)> {
    let open = consume_js_method_open(text, idx, "slice")?;
    let mut cursor = skip_ascii_ws(text, open + 1);
    let len = value.chars().count();

    let (start_end, start_arg) = parse_js_signed_integer_at(text, cursor)?;
    cursor = skip_ascii_ws(text, start_end);

    let mut end_arg = None;
    if text.as_bytes().get(cursor) == Some(&b',') {
        cursor = skip_ascii_ws(text, cursor + 1);
        if text.as_bytes().get(cursor) != Some(&b')') {
            let (end_end, parsed_end) = parse_js_signed_integer_at(text, cursor)?;
            end_arg = Some(parsed_end);
            cursor = skip_ascii_ws(text, end_end);
        }
    }

    if text.as_bytes().get(cursor) != Some(&b')') {
        return None;
    }

    let start = js_slice_bound(start_arg, len);
    let end = end_arg
        .map(|arg| js_slice_bound(arg, len))
        .unwrap_or(len)
        .max(start);
    let sliced: String = value.chars().skip(start).take(end - start).collect();
    (sliced.len() <= 8192).then_some((cursor + 1, sliced))
}

fn consume_js_string_substr_call(text: &str, idx: usize, value: &str) -> Option<(usize, String)> {
    let open = consume_js_method_open(text, idx, "substr")?;
    let mut cursor = skip_ascii_ws(text, open + 1);
    let len = value.chars().count();

    let (start_end, start_arg) = parse_js_signed_integer_at(text, cursor)?;
    cursor = skip_ascii_ws(text, start_end);

    let mut count_arg = None;
    if text.as_bytes().get(cursor) == Some(&b',') {
        cursor = skip_ascii_ws(text, cursor + 1);
        if text.as_bytes().get(cursor) != Some(&b')') {
            let (count_end, parsed_count) = parse_js_signed_integer_at(text, cursor)?;
            count_arg = Some(parsed_count.max(0) as usize);
            cursor = skip_ascii_ws(text, count_end);
        }
    }

    if text.as_bytes().get(cursor) != Some(&b')') {
        return None;
    }

    let start = js_slice_bound(start_arg, len);
    let count = count_arg.unwrap_or_else(|| len.saturating_sub(start));
    let sliced: String = value.chars().skip(start).take(count).collect();
    (sliced.len() <= 8192).then_some((cursor + 1, sliced))
}

fn consume_js_string_substring_call(
    text: &str,
    idx: usize,
    value: &str,
) -> Option<(usize, String)> {
    let open = consume_js_method_open(text, idx, "substring")?;
    let mut cursor = skip_ascii_ws(text, open + 1);
    let len = value.chars().count();

    let (start_end, start_arg) = parse_js_signed_integer_at(text, cursor)?;
    cursor = skip_ascii_ws(text, start_end);

    let mut end_arg = None;
    if text.as_bytes().get(cursor) == Some(&b',') {
        cursor = skip_ascii_ws(text, cursor + 1);
        if text.as_bytes().get(cursor) != Some(&b')') {
            let (end_end, parsed_end) = parse_js_signed_integer_at(text, cursor)?;
            end_arg = Some(parsed_end);
            cursor = skip_ascii_ws(text, end_end);
        }
    }

    if text.as_bytes().get(cursor) != Some(&b')') {
        return None;
    }

    let mut start = start_arg.max(0) as usize;
    let mut end = end_arg.map(|arg| arg.max(0) as usize).unwrap_or(len);
    start = start.min(len);
    end = end.min(len);
    if start > end {
        std::mem::swap(&mut start, &mut end);
    }
    let sliced: String = value.chars().skip(start).take(end - start).collect();
    (sliced.len() <= 8192).then_some((cursor + 1, sliced))
}

fn consume_js_split_reverse_join_chain(
    text: &str,
    idx: usize,
    value: &str,
) -> Option<(usize, String)> {
    let (after_split, split_arg) = consume_js_string_arg_method(text, idx, "split")?;
    if !split_arg.is_empty() {
        return None;
    }
    let after_reverse = consume_js_no_arg_method(text, after_split, "reverse")?;
    let (after_join, join_arg) = consume_js_string_arg_method(text, after_reverse, "join")?;
    if !join_arg.is_empty() || value.len() > 8192 {
        return None;
    }
    Some((after_join, value.chars().rev().collect()))
}

fn find_js_call_comma(text: &str, mut cursor: usize) -> Option<usize> {
    let limit = cursor.saturating_add(128).min(text.len());
    while cursor < limit {
        if text.as_bytes().get(cursor) == Some(&b',') {
            return Some(cursor);
        }
        if text.as_bytes().get(cursor) == Some(&b')') {
            return None;
        }
        if let Some((literal_end, _)) = parse_js_string_literal_at(text, cursor) {
            cursor = literal_end;
            continue;
        }
        cursor += text[cursor..].chars().next().map(char::len_utf8)?;
    }
    None
}

fn parse_js_named_callee_end(text: &str, start: usize, name: &str) -> Option<usize> {
    if js_word_at(text, start, name) {
        return Some(start + name.len());
    }

    let (object_end, _) = parse_js_identifier_at(text, start)?;
    let member_start = skip_ascii_ws(text, object_end);
    match text.as_bytes().get(member_start) {
        Some(b'.') => {
            let name_start = skip_ascii_ws(text, member_start + 1);
            js_word_at(text, name_start, name).then_some(name_start + name.len())
        }
        Some(b'[') => {
            let literal_start = skip_ascii_ws(text, member_start + 1);
            let (literal_end, property) = parse_js_string_literal_at(text, literal_start)?;
            if property != name {
                return None;
            }
            let close = skip_ascii_ws(text, literal_end);
            (text.as_bytes().get(close) == Some(&b']')).then_some(close + 1)
        }
        _ => None,
    }
}

fn parse_js_bound_member_callee_end(
    text: &str,
    start: usize,
    name: &str,
    bindings: &HashMap<String, String>,
) -> Option<usize> {
    let (object_end, _) = parse_js_identifier_at(text, start)?;
    let member_start = skip_ascii_ws(text, object_end);
    if text.as_bytes().get(member_start) != Some(&b'[') {
        return None;
    }
    let ident_start = skip_ascii_ws(text, member_start + 1);
    let (ident_end, ident) = parse_js_identifier_at(text, ident_start)?;
    if bindings.get(ident).map(String::as_str) != Some(name) {
        return None;
    }
    let close = skip_ascii_ws(text, ident_end);
    (text.as_bytes().get(close) == Some(&b']')).then_some(close + 1)
}

fn decode_js_base64_string(encoded: &str) -> Option<String> {
    if encoded.len() > 16384 {
        return None;
    }
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let decoded = decode_base64_maybe_unpadded(&cleaned)?;
    (decoded.len() <= 8192).then(|| String::from_utf8_lossy(&decoded).into_owned())
}

fn decode_base64_maybe_unpadded(cleaned: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(cleaned.as_bytes()) {
        return Some(decoded);
    }
    let remainder = cleaned.len() % 4;
    if remainder == 1 {
        return None;
    }
    let mut padded = cleaned.to_string();
    for _ in 0..((4 - remainder) % 4) {
        padded.push('=');
    }
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()
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

fn consume_js_replace_chain(text: &str, mut idx: usize, mut value: String) -> (usize, String) {
    let mut replacements = 0usize;
    while let Some((next_idx, needle, replacement, global)) = consume_js_replace_call(text, idx) {
        if !needle.is_empty() {
            value = if global {
                value.replace(&needle, &replacement)
            } else {
                value.replacen(&needle, &replacement, 1)
            };
        }
        idx = next_idx;
        replacements += 1;
        if replacements > 16 || value.len() > 8192 {
            break;
        }
    }
    (idx, value)
}

fn consume_js_replace_call(text: &str, idx: usize) -> Option<(usize, String, String, bool)> {
    let (open, force_global) = if let Some(open) = consume_js_method_open(text, idx, "replaceAll") {
        (open, true)
    } else {
        (consume_js_method_open(text, idx, "replace")?, false)
    };
    let first_start = skip_ascii_ws(text, open + 1);
    let (first_end, needle, global) =
        if let Some((first_end, first)) = parse_js_string_literal_at(text, first_start) {
            (first_end, first, false)
        } else {
            let (first_end, pattern, flags) = parse_js_regex_literal_at(text, first_start)?;
            (
                first_end,
                regex_literal_pattern_to_needle(&pattern)?,
                flags.contains('g'),
            )
        };
    let comma = skip_ascii_ws(text, first_end);
    if text.as_bytes().get(comma) != Some(&b',') {
        return None;
    }
    let second_start = skip_ascii_ws(text, comma + 1);
    let (second_end, second) = parse_js_string_literal_at(text, second_start)?;
    let close = skip_ascii_ws(text, second_end);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some((close + 1, needle, second, force_global || global))
}

fn parse_js_regex_literal_at(text: &str, start: usize) -> Option<(usize, String, String)> {
    if text.as_bytes().get(start) != Some(&b'/') {
        return None;
    }
    let mut pattern = String::new();
    let mut escaped = false;
    for (rel, ch) in text[start + 1..].char_indices() {
        if ch == '\r' || ch == '\n' {
            return None;
        }
        if escaped {
            pattern.push('\\');
            pattern.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '/' {
            let mut end = start + 1 + rel + ch.len_utf8();
            let flags_start = end;
            while text[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            {
                let ch_len = text[end..].chars().next().map(char::len_utf8)?;
                end += ch_len;
            }
            return Some((end, pattern, text[flags_start..end].to_string()));
        }
        pattern.push(ch);
    }
    None
}

fn regex_literal_pattern_to_needle(pattern: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars.next()?;
            if matches!(
                escaped,
                '/' | '\\'
                    | '.'
                    | '^'
                    | '$'
                    | '*'
                    | '+'
                    | '?'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '|'
            ) {
                out.push(escaped);
                continue;
            }
            return None;
        }
        if matches!(
            ch,
            '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            return None;
        }
        out.push(ch);
    }
    Some(out)
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
