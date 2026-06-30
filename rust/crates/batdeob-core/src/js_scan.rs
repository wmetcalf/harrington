//! JScript payload post-processing: extract URLs from JS payloads.
//! Catches GetObject(str+str+str), WScript.Shell.Run("..."), \uXXXX-encoded eval, etc.

use crate::env::Environment;
use crate::traits::Trait;
use crate::util::{
    find_ascii_case_insensitive, find_ascii_case_insensitive_from, snippet_prefix,
    starts_with_ascii_case_insensitive,
};
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;

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
        r#"(?is)String\s*(?:\.\s*from(?:CharCode|CodePoint)|\[\s*["']from(?:CharCode|CodePoint)["']\s*\])\s*\(\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\)"#,
    )
        .expect("js fromCharCode/fromCodePoint")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_BIND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*(?:\.\s*from(?:CharCode|CodePoint)|\[\s*["']from(?:CharCode|CodePoint)["']\s*\])\s*\.\s*bind\s*\(\s*[^)\r\n]{0,128}\)\s*\(\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode/fromCodePoint bind")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\(\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode member variable")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_APPLY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\.\s*apply\s*\(\s*[^,\r\n]{0,128},\s*\[\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\]\s*\)"#,
    )
    .expect("js fromCharCode member apply")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\.\s*call\s*\(\s*[^,\r\n]{0,128},\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode member call")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_SPREAD_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\(\s*\.\.\.\s*\[\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\]\s*\)"#,
    )
    .expect("js fromCharCode member spread array")
});

#[allow(clippy::expect_used)]
static JS_FROMCHARCODE_MEMBER_BIND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)String\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\]\s*\.\s*bind\s*\(\s*[^)\r\n]{0,128}\)\s*\(\s*([0-9xa-f+\-\^\s,]{5,8192})\s*\)"#,
    )
    .expect("js fromCharCode member bind")
});

#[allow(clippy::expect_used)]
static JS_STRING_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:^|[;\r\n])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,127})\s*=\s*([^;\r\n]{1,4096})"#,
    )
    .expect("js string assign")
});

pub fn scan_js_payloads(env: &mut Environment) {
    let payloads: Vec<Vec<u8>> = env.all_extracted_jscript.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let raw = String::from_utf8_lossy(payload).into_owned();
        // First pass: decode \uXXXX escapes
        let decoded = decode_u_escapes(&raw);
        // Second pass: collapse "a"+"b"+"c" concat
        let concat_resolved = expand_js_string_concat(&decoded);
        let mut candidates = vec![concat_resolved.clone()];
        candidates.extend(decoded_js_percent_literals(&concat_resolved));
        candidates.extend(decoded_js_fromcharcode_literals(&concat_resolved));
        candidates.extend(decoded_js_array_join_literals(&concat_resolved));
        candidates.extend(decoded_js_atob_literals(&concat_resolved));
        candidates.extend(decoded_js_textdecoder_literals(&concat_resolved));
        candidates.extend(decoded_js_buffer_literals(&concat_resolved));
        candidates.extend(decoded_js_variable_string_bindings(&concat_resolved));

        // Now scan for URLs
        for candidate in candidates {
            if find_ascii_case_insensitive_from(&candidate, ".run", 0).is_some()
                || find_ascii_case_insensitive_from(&candidate, ".exec", 0).is_some()
                || find_ascii_case_insensitive_from(&candidate, ".shellexecute", 0).is_some()
                || find_js_bracket_shell_command_method_from(&candidate, 0).is_some()
            {
                let bindings = collect_js_string_literal_bindings(&candidate);
                let arrays = collect_js_string_array_bindings(&candidate, &bindings);
                push_downloads_from_js_shell_command_calls(
                    env,
                    idx,
                    &concat_resolved,
                    &candidate,
                    &bindings,
                    &arrays,
                    &mut seen,
                );
            }
            for caps in URL_IN_JS_RE.captures_iter(&candidate) {
                let Some(m) = caps.get(1) else { continue };
                let mut url = m.as_str().to_string();
                // Strip "script:" prefix that GetObject uses
                if starts_with_ascii_case_insensitive(&url, "script:") {
                    url = url["script:".len()..].to_string();
                }
                url.truncate(
                    url.trim_end_matches([',', '.', ';', ':', ')', ']', '}', '"', '\'', '!', '?'])
                        .len(),
                );
                let Some(url) = crate::deob_scan::normalize_liberal_url_token(&url) else {
                    continue;
                };
                if crate::deob_scan::is_noise_url(&url) {
                    continue;
                }
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                let snippet = snippet_prefix(&concat_resolved, 120);
                env.traits.push(Trait::Download {
                    cmd: format!("(js #{idx}) {snippet}"),
                    src: url,
                    dst: None,
                });
            }
        }
    }
}

fn push_downloads_from_js_shell_command_calls(
    env: &mut Environment,
    idx: usize,
    snippet_source: &str,
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
    seen: &mut std::collections::HashSet<(usize, String)>,
) {
    for (method, requires_shell_context) in [(".run", false), (".exec", true)] {
        let mut cursor = 0usize;
        while let Some(method_start) = find_ascii_case_insensitive_from(text, method, cursor) {
            let method_end = method_start + method.len();
            if requires_shell_context && !has_nearby_wscript_shell_context(text, method_start) {
                cursor = method_end;
                continue;
            }
            let Some(open) = consume_js_call_open(text, method_end) else {
                cursor = method_end;
                continue;
            };
            let arg_start = skip_ascii_ws(text, open + 1);
            let Some((_, command)) = parse_js_command_arg_at(text, arg_start, bindings, arrays)
            else {
                cursor = open + 1;
                continue;
            };
            push_downloads_from_js_command(env, idx, snippet_source, &command, seen);
            cursor = open + 1;
        }
    }

    let mut cursor = 0usize;
    while let Some(method_start) = find_ascii_case_insensitive_from(text, ".shellexecute", cursor) {
        let method_end = method_start + ".shellexecute".len();
        if !has_nearby_js_shell_execute_context(text, method_start) {
            cursor = method_end;
            continue;
        }
        let Some(open) = consume_js_call_open(text, method_end) else {
            cursor = method_end;
            continue;
        };
        let arg_start = skip_ascii_ws(text, open + 1);
        let Some((program_end, mut command)) =
            parse_js_command_arg_at(text, arg_start, bindings, arrays)
        else {
            cursor = open + 1;
            continue;
        };
        let program = command.clone();
        let mut args_value = None;
        let comma = skip_ascii_ws(text, program_end);
        let mut args_end = program_end;
        if text.as_bytes().get(comma) == Some(&b',') {
            let args_start = skip_ascii_ws(text, comma + 1);
            if let Some((parsed_args_end, args)) =
                parse_js_command_arg_at(text, args_start, bindings, arrays)
            {
                args_end = parsed_args_end;
                if !args.trim().is_empty() {
                    command.push(' ');
                    command.push_str(&args);
                    args_value = Some(args);
                }
            }
        }
        if let Some(verb) = parse_js_shell_execute_verb_arg(text, args_end, bindings, arrays) {
            push_js_shell_execute_self_elevation(env, &program, args_value.as_deref(), &verb);
        }
        push_downloads_from_js_command(env, idx, snippet_source, &command, seen);
        cursor = open + 1;
    }

    let mut cursor = 0usize;
    while let Some((method_start, method_end, kind)) =
        find_js_bracket_shell_command_method_from(text, cursor)
    {
        let has_context = match kind {
            JsShellCommandKind::Command => has_nearby_wscript_shell_context(text, method_start),
            JsShellCommandKind::ShellExecute => {
                has_nearby_js_shell_execute_context(text, method_start)
            }
        };
        if !has_context {
            cursor = method_end;
            continue;
        }
        let Some(open) = consume_js_call_open(text, method_end) else {
            cursor = method_end;
            continue;
        };
        let arg_start = skip_ascii_ws(text, open + 1);
        let Some((arg_end, mut command)) =
            parse_js_command_arg_at(text, arg_start, bindings, arrays)
        else {
            cursor = open + 1;
            continue;
        };
        if matches!(kind, JsShellCommandKind::ShellExecute) {
            let comma = skip_ascii_ws(text, arg_end);
            let program = command.clone();
            let mut args_end = arg_end;
            let mut args_value = None;
            if text.as_bytes().get(comma) == Some(&b',') {
                let args_start = skip_ascii_ws(text, comma + 1);
                if let Some((parsed_args_end, args)) =
                    parse_js_command_arg_at(text, args_start, bindings, arrays)
                {
                    args_end = parsed_args_end;
                    if !args.trim().is_empty() {
                        command.push(' ');
                        command.push_str(&args);
                        args_value = Some(args);
                    }
                }
            }
            if let Some(verb) = parse_js_shell_execute_verb_arg(text, args_end, bindings, arrays) {
                push_js_shell_execute_self_elevation(env, &program, args_value.as_deref(), &verb);
            }
        }
        push_downloads_from_js_command(env, idx, snippet_source, &command, seen);
        cursor = open + 1;
    }
}

fn parse_js_shell_execute_verb_arg(
    text: &str,
    args_end: usize,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<String> {
    let comma = skip_ascii_ws(text, args_end);
    if text.as_bytes().get(comma) != Some(&b',') {
        return None;
    }
    let dir_start = skip_ascii_ws(text, comma + 1);
    let (dir_end, _) = parse_js_command_arg_at(text, dir_start, bindings, arrays)?;
    let comma = skip_ascii_ws(text, dir_end);
    if text.as_bytes().get(comma) != Some(&b',') {
        return None;
    }
    let verb_start = skip_ascii_ws(text, comma + 1);
    parse_js_command_arg_at(text, verb_start, bindings, arrays).map(|(_, verb)| verb)
}

fn push_js_shell_execute_self_elevation(
    env: &mut Environment,
    target: &str,
    args: Option<&str>,
    verb: &str,
) {
    if !verb.trim().eq_ignore_ascii_case("runas") {
        return;
    }
    env.traits.push(Trait::SelfElevation {
        target: target.to_string(),
        args: args
            .map(str::to_string)
            .filter(|value| !value.trim().is_empty()),
    });
}

fn parse_js_command_arg_at(
    text: &str,
    start: usize,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    if let Some(value) = parse_js_string_value_arg_at(text, start, bindings) {
        return Some(value);
    }

    let (array_end, parts) = parse_js_string_array_arg_at(text, start, bindings)?;
    consume_js_array_join_chain(text, array_end, parts, bindings, arrays)
}

#[derive(Clone, Copy)]
enum JsShellCommandKind {
    Command,
    ShellExecute,
}

fn find_js_bracket_shell_command_method_from(
    text: &str,
    start: usize,
) -> Option<(usize, usize, JsShellCommandKind)> {
    let bytes = text.as_bytes();
    let mut cursor = start.min(bytes.len());
    while cursor < bytes.len() {
        let rel = bytes[cursor..].iter().position(|byte| *byte == b'[')?;
        let member_start = cursor + rel;
        let literal_start = skip_ascii_ws(text, member_start + 1);
        let Some((literal_end, property)) = parse_js_string_literal_at(text, literal_start) else {
            cursor = member_start + 1;
            continue;
        };
        let close = skip_ascii_ws(text, literal_end);
        if bytes.get(close) != Some(&b']') {
            cursor = member_start + 1;
            continue;
        }
        if property.eq_ignore_ascii_case("run") || property.eq_ignore_ascii_case("exec") {
            return Some((member_start, close + 1, JsShellCommandKind::Command));
        }
        if property.eq_ignore_ascii_case("shellexecute") {
            return Some((member_start, close + 1, JsShellCommandKind::ShellExecute));
        }
        cursor = member_start + 1;
    }
    None
}

fn has_nearby_wscript_shell_context(text: &str, idx: usize) -> bool {
    let start = idx.saturating_sub(256);
    let prefix = &text[start..idx];
    crate::util::contains_ascii_case_insensitive(prefix, "wscript.shell")
        || crate::util::contains_ascii_case_insensitive(prefix, "activexobject")
}

fn has_nearby_js_shell_execute_context(text: &str, idx: usize) -> bool {
    if has_nearby_wscript_shell_context(text, idx) {
        return true;
    }
    let start = idx.saturating_sub(256);
    let prefix = &text[start..idx];
    crate::util::contains_ascii_case_insensitive(prefix, "shell.application")
}

fn push_downloads_from_js_command(
    env: &mut Environment,
    idx: usize,
    snippet_source: &str,
    command: &str,
    seen: &mut std::collections::HashSet<(usize, String)>,
) {
    for url in js_command_download_urls(command) {
        if crate::deob_scan::is_noise_url(&url) || !seen.insert((idx, url.clone())) {
            continue;
        }
        let snippet = snippet_prefix(snippet_source, 120);
        env.traits.push(Trait::Download {
            cmd: format!("(js #{idx}) {snippet}"),
            src: url,
            dst: None,
        });
    }
}

fn js_command_download_urls(command: &str) -> Vec<String> {
    let mut parts = command.split_ascii_whitespace();
    if parts.next().is_none() || parts.clone().next().is_none() {
        return Vec::new();
    }

    let mut urls = Vec::new();
    for token in parts {
        let candidate = token.trim_matches(['"', '\'', '(', ')', '[', ']', '{', '}', ',', ';']);
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(candidate)
            .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(candidate))
        {
            urls.push(url);
        }
    }
    urls
}

fn decoded_js_percent_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for name in ["decodeURIComponent", "unescape"] {
        let mut cursor = 0usize;
        while let Some(rel) = find_ascii_case_insensitive(&text[cursor..], name) {
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

fn decoded_js_variable_string_bindings(text: &str) -> Vec<String> {
    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut out = Vec::new();

    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if vars.len() >= 256 && !vars.contains_key(name) {
            continue;
        }
        let Some(value) = eval_js_string_expr(expr, &vars) else {
            continue;
        };
        if value.len() > 16384 {
            continue;
        }
        vars.insert(name.to_string(), value.clone());
        out.push(value);
    }

    out
}

fn eval_js_string_expr(
    expr: &str,
    vars: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let mut cursor = 0usize;
    let mut out = String::new();
    let mut saw_term = false;

    loop {
        cursor = skip_ascii_ws(expr, cursor);
        if cursor >= expr.len() {
            break;
        }

        let (mut next, mut value) =
            if let Some((end, literal)) = parse_js_string_literal_at(expr, cursor) {
                (end, literal)
            } else if let Some((end, name)) = parse_js_identifier_at(expr, cursor) {
                let value = vars.get(name)?.clone();
                (end, value)
            } else {
                return None;
            };

        let mut replacements = 0usize;
        while let Some((end, replaced)) = consume_js_replace_call(expr, next, value.clone(), vars) {
            value = replaced;
            next = end;
            replacements += 1;
            if replacements > 16 || value.len() > 16384 {
                return None;
            }
        }

        out.push_str(&value);
        if out.len() > 16384 {
            return None;
        }
        saw_term = true;
        cursor = skip_ascii_ws(expr, next);
        if cursor >= expr.len() {
            break;
        }
        if expr.as_bytes().get(cursor) != Some(&b'+') {
            return None;
        }
        cursor += 1;
    }

    saw_term.then_some(out)
}

#[derive(Clone, Copy)]
struct JsReplaceOptions {
    global: bool,
    case_insensitive: bool,
}

fn consume_js_replace_call(
    text: &str,
    idx: usize,
    value: String,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    let (open, force_global) = if let Some(open) = consume_js_method_open(text, idx, "replaceAll") {
        (open, true)
    } else {
        (consume_js_method_open(text, idx, "replace")?, false)
    };

    let first_start = skip_ascii_ws(text, open + 1);
    let (first_end, needle, options) = if let Some((first_end, first)) =
        parse_js_string_or_bound_arg(text, first_start, bindings)
    {
        (
            first_end,
            first,
            JsReplaceOptions {
                global: false,
                case_insensitive: false,
            },
        )
    } else {
        let (first_end, pattern, flags) = parse_js_regex_literal_at(text, first_start)?;
        (
            first_end,
            regex_literal_pattern_to_string(&pattern)?,
            JsReplaceOptions {
                global: flags.contains('g'),
                case_insensitive: flags.contains('i'),
            },
        )
    };

    let comma = skip_ascii_ws(text, first_end);
    if text.as_bytes().get(comma) != Some(&b',') {
        return None;
    }
    let second_start = skip_ascii_ws(text, comma + 1);
    let (second_end, replacement) = parse_js_string_or_bound_arg(text, second_start, bindings)?;
    let close = skip_ascii_ws(text, second_end);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }

    let options = JsReplaceOptions {
        global: force_global || options.global,
        ..options
    };
    Some((
        close + 1,
        apply_js_string_replacement(value, &needle, &replacement, options),
    ))
}

fn apply_js_string_replacement(
    value: String,
    needle: &str,
    replacement: &str,
    options: JsReplaceOptions,
) -> String {
    if needle.is_empty() {
        return value;
    }
    if options.case_insensitive && needle.is_ascii() {
        return replace_ascii_case_insensitive(value, needle, replacement, options.global);
    }
    if options.global {
        value.replace(needle, replacement)
    } else {
        value.replacen(needle, replacement, 1)
    }
}

fn replace_ascii_case_insensitive(
    value: String,
    needle: &str,
    replacement: &str,
    global: bool,
) -> String {
    let value_lower = value.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;
    let mut replaced = false;

    while let Some(rel) = value_lower[cursor..].find(&needle_lower) {
        if replaced && !global {
            break;
        }
        let start = cursor + rel;
        out.push_str(&value[cursor..start]);
        out.push_str(replacement);
        cursor = start + needle.len();
        replaced = true;
    }
    out.push_str(&value[cursor..]);
    out
}

fn parse_js_regex_literal_at(text: &str, start: usize) -> Option<(usize, String, String)> {
    if text.as_bytes().get(start) != Some(&b'/') {
        return None;
    }
    let mut pattern = String::new();
    let mut cursor = start + 1;
    let mut escaped = false;
    while cursor < text.len() {
        let ch = text[cursor..].chars().next()?;
        cursor += ch.len_utf8();
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
            let flags_start = cursor;
            while text
                .as_bytes()
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphabetic())
            {
                cursor += 1;
            }
            return Some((cursor, pattern, text[flags_start..cursor].to_string()));
        }
        if ch == '\r' || ch == '\n' {
            return None;
        }
        pattern.push(ch);
    }
    None
}

fn regex_literal_pattern_to_string(pattern: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if matches!(
                ch,
                '.' | '*' | '+' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
            ) {
                return None;
            }
            out.push(ch);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            '\\' | '/' | '.' | '*' | '+' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}'
            | '|' => out.push(escaped),
            'x' => {
                let h1 = chars.next()?;
                let h2 = chars.next()?;
                let value = u32::from_str_radix(&format!("{h1}{h2}"), 16).ok()?;
                out.push(char::from_u32(value)?);
            }
            'u' => {
                let hex = (0..4).map(|_| chars.next()).collect::<Option<String>>()?;
                let value = u32::from_str_radix(&hex, 16).ok()?;
                out.push(char::from_u32(value)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn parse_js_identifier_at(text: &str, start: usize) -> Option<(usize, &str)> {
    let bytes = text.as_bytes();
    let first = *bytes.get(start)?;
    if !is_js_ident_start_byte(first) {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|b| is_js_ident_continue_byte(*b))
    {
        end += 1;
    }
    Some((end, &text[start..end]))
}

fn is_js_ident_start_byte(b: u8) -> bool {
    b == b'_' || b == b'$' || b.is_ascii_alphabetic()
}

fn is_js_ident_continue_byte(b: u8) -> bool {
    is_js_ident_start_byte(b) || b.is_ascii_digit()
}

fn decoded_js_fromcharcode_literals(text: &str) -> Vec<String> {
    let mut out: Vec<String> = JS_FROMCHARCODE_RE
        .captures_iter(text)
        .chain(JS_FROMCHARCODE_BIND_RE.captures_iter(text))
        .filter_map(|caps| decode_js_fromcharcode_args(caps.get(1)?.as_str()))
        .collect();
    let bindings = collect_js_string_literal_bindings(text);
    extend_js_fromcharcode_member_matches(
        &mut out,
        text,
        &bindings,
        &JS_FROMCHARCODE_MEMBER_VAR_RE,
    );
    extend_js_fromcharcode_member_matches(
        &mut out,
        text,
        &bindings,
        &JS_FROMCHARCODE_MEMBER_APPLY_RE,
    );
    extend_js_fromcharcode_member_matches(
        &mut out,
        text,
        &bindings,
        &JS_FROMCHARCODE_MEMBER_CALL_RE,
    );
    extend_js_fromcharcode_member_matches(
        &mut out,
        text,
        &bindings,
        &JS_FROMCHARCODE_MEMBER_SPREAD_ARRAY_RE,
    );
    extend_js_fromcharcode_member_matches(
        &mut out,
        text,
        &bindings,
        &JS_FROMCHARCODE_MEMBER_BIND_RE,
    );
    out.extend(decoded_js_fromcharcode_apply_bindings(text));
    out
}

fn extend_js_fromcharcode_member_matches(
    out: &mut Vec<String>,
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
    regex: &Regex,
) {
    for caps in regex.captures_iter(text).take(128) {
        let (Some(name), Some(nums)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if !bindings
            .get(name.as_str())
            .is_some_and(|value| is_js_string_code_decoder(value))
        {
            continue;
        }
        if let Some(decoded) = decode_js_fromcharcode_args(nums.as_str()) {
            out.push(decoded);
        }
    }
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

fn is_js_string_code_decoder(value: &str) -> bool {
    matches!(value, "fromCharCode" | "fromCodePoint")
}

fn decoded_js_fromcharcode_apply_bindings(text: &str) -> Vec<String> {
    let bindings = collect_js_typed_byte_array_bindings(text);
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = text[cursor..].find("String") {
        let start = cursor + rel;
        let Some((string_end, name)) = parse_js_identifier_at(text, start) else {
            cursor = start + "String".len();
            continue;
        };
        if name != "String" {
            cursor = string_end;
            continue;
        }
        let Some(fromcharcode_end) = consume_js_method_member_end(text, string_end, "fromCharCode")
        else {
            cursor = string_end;
            continue;
        };
        let Some(apply_open) = consume_js_method_open(text, fromcharcode_end, "apply") else {
            cursor = fromcharcode_end;
            continue;
        };
        let Some(first_arg_end) = skip_js_call_arg(text, apply_open + 1) else {
            cursor = apply_open + 1;
            continue;
        };
        let comma = skip_ascii_ws(text, first_arg_end);
        if text.as_bytes().get(comma) != Some(&b',') {
            cursor = apply_open + 1;
            continue;
        }
        let arg_start = skip_ascii_ws(text, comma + 1);
        if let Some((arg_end, decoded)) = parse_js_typed_byte_array_arg(text, arg_start) {
            let close = skip_ascii_ws(text, arg_end);
            if text.as_bytes().get(close) == Some(&b')') {
                out.push(decoded);
                if out.len() >= 128 {
                    break;
                }
                cursor = close + 1;
                continue;
            }
        }
        let Some((var_end, var_name)) = parse_js_identifier_at(text, arg_start) else {
            cursor = arg_start;
            continue;
        };
        let close = skip_ascii_ws(text, var_end);
        if text.as_bytes().get(close) != Some(&b')') {
            cursor = var_end;
            continue;
        }
        if let Some(decoded) = bindings.get(var_name) {
            out.push(decoded.clone());
            if out.len() >= 128 {
                break;
            }
        }
        cursor = close + 1;
    }
    out
}

fn skip_js_call_arg(text: &str, start: usize) -> Option<usize> {
    let cursor = skip_ascii_ws(text, start);
    if let Some((end, _)) = parse_js_identifier_at(text, cursor) {
        return Some(end);
    }
    consume_js_quoted_bytes(text, cursor)
}

fn decoded_js_atob_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let string_bindings = collect_js_string_literal_bindings(text);
    let array_bindings = collect_js_string_array_bindings(text, &string_bindings);
    let mut cursor = 0usize;
    while let Some(rel) = find_ascii_case_insensitive(&text[cursor..], "atob") {
        let name_start = cursor + rel;
        let name_end = name_start + "atob".len();
        let bytes = text.as_bytes();
        let prev = name_start
            .checked_sub(1)
            .and_then(|idx| bytes.get(idx).copied());
        let next = bytes.get(name_end).copied();
        if prev.is_some_and(is_js_ident_continue_byte)
            || next.is_some_and(is_js_ident_continue_byte)
        {
            cursor = name_end;
            continue;
        }

        let Some((arg_end, value)) =
            parse_js_atob_string_arg(text, name_end, &string_bindings, &array_bindings)
        else {
            cursor = name_end;
            continue;
        };
        if value.len() <= 16384 {
            let bytes = value.as_bytes();
            let cleaned = if bytes.iter().any(|b| b.is_ascii_whitespace()) {
                std::borrow::Cow::Owned(
                    bytes
                        .iter()
                        .copied()
                        .filter(|b| !b.is_ascii_whitespace())
                        .collect::<Vec<u8>>(),
                )
            } else {
                std::borrow::Cow::Borrowed(bytes)
            };
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
                if decoded.len() <= 8192 {
                    out.push(String::from_utf8_lossy(&decoded).into_owned());
                }
            }
        }
        cursor = arg_end;
    }
    out
}

fn parse_js_atob_string_arg(
    text: &str,
    callee_end: usize,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    if let Some(open) = consume_js_call_open(text, callee_end) {
        let arg_start = skip_ascii_ws(text, open + 1);
        return parse_js_string_value_arg_at(text, arg_start, bindings);
    }

    if let Some(open) = consume_js_method_open(text, callee_end, "call") {
        let comma = find_js_call_comma(text, skip_ascii_ws(text, open + 1))?;
        let arg_start = skip_ascii_ws(text, comma + 1);
        return parse_js_string_value_arg_at(text, arg_start, bindings);
    }

    if let Some(open) = consume_js_method_open(text, callee_end, "apply") {
        let first_arg_end = skip_js_call_arg(text, skip_ascii_ws(text, open + 1))?;
        let comma = skip_ascii_ws(text, first_arg_end);
        if text.as_bytes().get(comma) != Some(&b',') {
            return None;
        }
        let array_start = skip_ascii_ws(text, comma + 1);
        let (array_end, parts) =
            parse_js_string_array_value_arg_at(text, array_start, bindings, arrays)?;
        let close = skip_ascii_ws(text, array_end);
        if text.as_bytes().get(close) != Some(&b')') {
            return None;
        }
        let value = parts.into_iter().find(|part| !part.is_empty())?;
        return Some((close + 1, value));
    }

    if let Some(bind_open) = consume_js_method_open(text, callee_end, "bind") {
        let bind_close = find_js_call_close(text, bind_open + 1)?;
        let open = consume_js_call_open(text, bind_close + 1)?;
        let arg_start = skip_ascii_ws(text, open + 1);
        return parse_js_string_value_arg_at(text, arg_start, bindings);
    }

    None
}

fn parse_js_string_array_value_arg_at(
    text: &str,
    start: usize,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<(usize, Vec<String>)> {
    let start = skip_ascii_ws(text, start);
    let (mut cursor, mut parts) =
        if let Some((end, parts)) = parse_js_string_array_arg_at(text, start, bindings) {
            (end, parts)
        } else {
            let (end, name) = parse_js_identifier_at(text, start)?;
            (end, arrays.get(name)?.clone())
        };

    if let Some((slice_end, sliced)) = consume_js_array_slice_chain(text, cursor, parts.clone()) {
        cursor = slice_end;
        parts = sliced;
    }

    Some((cursor, parts))
}

fn consume_js_array_slice_chain(
    text: &str,
    idx: usize,
    parts: Vec<String>,
) -> Option<(usize, Vec<String>)> {
    let open = consume_js_method_open(text, idx, "slice")?;
    let args_close = find_js_call_close(text, open + 1)?;
    let args = text[open + 1..args_close].trim();
    let (start, end) = parse_js_slice_bounds(args, parts.len())?;
    if start > end || end > parts.len() {
        return None;
    }
    Some((args_close + 1, parts[start..end].to_vec()))
}

fn parse_js_slice_bounds(args: &str, len: usize) -> Option<(usize, usize)> {
    let mut parts = args.split(',').map(str::trim);
    let start = parts.next()?.parse::<usize>().ok()?;
    let end = parts
        .next()
        .and_then(|part| {
            if part.is_empty() {
                None
            } else {
                part.parse::<usize>().ok()
            }
        })
        .unwrap_or(len);
    if parts.next().is_some() {
        return None;
    }
    Some((start.min(len), end.min(len)))
}

fn find_js_call_comma(text: &str, mut cursor: usize) -> Option<usize> {
    let limit = cursor.saturating_add(512).min(text.len());
    while cursor < limit {
        match text.as_bytes().get(cursor) {
            Some(b',') => return Some(cursor),
            Some(b')') => return None,
            Some(b'\'') | Some(b'"') | Some(b'`') => {
                let (literal_end, _) = parse_js_string_literal_at(text, cursor)?;
                cursor = literal_end;
            }
            Some(byte) if byte.is_ascii() => cursor += 1,
            Some(_) => cursor += text[cursor..].chars().next()?.len_utf8(),
            None => return None,
        }
    }
    None
}

fn parse_js_string_value_arg_at(
    text: &str,
    start: usize,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    let (mut cursor, mut value) =
        if let Some((end, literal)) = parse_js_string_literal_at(text, start) {
            (end, literal)
        } else {
            let (end, name) = parse_js_identifier_at(text, start)?;
            (end, bindings.get(name)?.clone())
        };
    loop {
        if let Some(end) = consume_js_no_arg_method(text, cursor, "trim") {
            value = value.trim().to_string();
            cursor = end;
            continue;
        }
        if let Some(end) = consume_js_no_arg_method(text, cursor, "trimStart") {
            value = value.trim_start().to_string();
            cursor = end;
            continue;
        }
        if let Some(end) = consume_js_no_arg_method(text, cursor, "trimEnd") {
            value = value.trim_end().to_string();
            cursor = end;
            continue;
        }
        break;
    }
    Some((cursor, value))
}

fn decoded_js_buffer_literals(text: &str) -> Vec<String> {
    let byte_bindings = collect_js_byte_array_literal_byte_bindings(text);
    let string_bindings = collect_js_string_literal_bindings(text);
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = text[cursor..].find("Buffer") {
        let start = cursor + rel;
        if let Some((end, decoded)) =
            parse_js_buffer_from_call_at(text, start, &byte_bindings, &string_bindings)
        {
            out.push(decoded);
            if out.len() >= 128 {
                break;
            }
            cursor = end;
        } else {
            cursor = start + "Buffer".len();
        }
    }
    out
}

fn collect_js_string_literal_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut bindings = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if bindings.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some(value) = eval_js_string_expr(expr, &bindings) else {
            continue;
        };
        if value.len() > 16384 {
            continue;
        }
        bindings.insert(name.to_string(), value);
    }
    bindings
}

fn decoded_js_array_join_literals(text: &str) -> Vec<String> {
    let string_bindings = collect_js_string_literal_bindings(text);
    let array_bindings = collect_js_string_array_bindings(text, &string_bindings);
    let mut out = Vec::new();

    let mut cursor = 0usize;
    while cursor < text.len() {
        if let Some((array_end, parts)) =
            parse_js_string_array_arg_at(text, cursor, &string_bindings)
        {
            if let Some((join_end, joined)) = consume_js_array_join_chain(
                text,
                array_end,
                parts,
                &string_bindings,
                &array_bindings,
            ) {
                out.push(joined);
                if out.len() >= 128 {
                    break;
                }
                cursor = join_end;
                continue;
            }
            cursor = array_end;
            continue;
        }
        cursor += text[cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1);
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
        let Some(parts) = array_bindings.get(name) else {
            cursor = ident_end;
            continue;
        };
        if let Some((join_end, joined)) = consume_js_array_join_chain(
            text,
            ident_end,
            parts.clone(),
            &string_bindings,
            &array_bindings,
        ) {
            out.push(joined);
            if out.len() >= 128 {
                break;
            }
            cursor = join_end;
            continue;
        }
        cursor = ident_end;
    }

    out
}

fn collect_js_string_array_bindings(
    text: &str,
    string_bindings: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, Vec<String>> {
    let mut arrays = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if arrays.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some((end, parts)) = parse_js_string_array_arg_at(expr, 0, string_bindings) else {
            continue;
        };
        if skip_ascii_ws(expr, end) != expr.len()
            || parts.len() > 128
            || parts.iter().any(|part| part.len() > 8192)
        {
            continue;
        }
        arrays.insert(name.to_string(), parts);
    }
    arrays
}

fn parse_js_string_array_arg_at(
    text: &str,
    start: usize,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, Vec<String>)> {
    let start = skip_ascii_ws(text, start);
    let (open, close_byte) = if text.as_bytes().get(start) == Some(&b'[') {
        (start, b']')
    } else {
        let (open, kind) = parse_js_array_constructor_open(text, start)?;
        if matches!(kind, JsArrayConstructorKind::From) {
            let arg_start = skip_ascii_ws(text, open + 1);
            if text.as_bytes().get(arg_start) != Some(&b'[') {
                return None;
            }
            let (array_end, parts) = parse_js_string_array_arg_at(text, arg_start, bindings)?;
            let close = skip_ascii_ws(text, array_end);
            if text.as_bytes().get(close) != Some(&b')') {
                return None;
            }
            return Some((close + 1, parts));
        }
        (open, b')')
    };

    let mut parts = Vec::new();
    let mut cursor = skip_ascii_ws(text, open + 1);
    if text.as_bytes().get(cursor) == Some(&close_byte) {
        return Some((cursor + 1, parts));
    }

    loop {
        let (part_end, value) = parse_js_string_or_bound_arg(text, cursor, bindings)?;
        parts.push(value);
        if parts.len() > 128 {
            return None;
        }
        cursor = skip_ascii_ws(text, part_end);
        match text.as_bytes().get(cursor) {
            Some(b',') => cursor = skip_ascii_ws(text, cursor + 1),
            Some(byte) if *byte == close_byte => return Some((cursor + 1, parts)),
            _ => return None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum JsArrayConstructorKind {
    Plain,
    Of,
    From,
}

fn parse_js_array_constructor_open(
    text: &str,
    start: usize,
) -> Option<(usize, JsArrayConstructorKind)> {
    let mut cursor = start;
    if js_word_at(text, cursor, "new") {
        cursor = skip_ascii_ws(text, cursor + "new".len());
    }
    if !js_word_at(text, cursor, "Array") {
        return None;
    }
    cursor = skip_ascii_ws(text, cursor + "Array".len());
    let mut kind = JsArrayConstructorKind::Plain;
    if text.as_bytes().get(cursor) == Some(&b'.') {
        let method_start = skip_ascii_ws(text, cursor + 1);
        if js_word_at(text, method_start, "of") {
            kind = JsArrayConstructorKind::Of;
            cursor = skip_ascii_ws(text, method_start + "of".len());
        } else if js_word_at(text, method_start, "from") {
            kind = JsArrayConstructorKind::From;
            cursor = skip_ascii_ws(text, method_start + "from".len());
        } else {
            return None;
        }
    }
    let open = skip_ascii_ws(text, cursor);
    (text.as_bytes().get(open) == Some(&b'(')).then_some((open, kind))
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

fn is_js_ident_char(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
}

fn consume_js_array_join_chain(
    text: &str,
    mut idx: usize,
    mut parts: Vec<String>,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<(usize, String)> {
    if let Some((concat_end, concat_parts)) =
        consume_js_concat_chain(text, idx, parts.clone(), bindings, arrays)
    {
        idx = concat_end;
        parts = concat_parts;
    }

    if let Some((filter_end, filter_parts)) =
        consume_js_array_filter_chain(text, idx, parts.clone())
    {
        idx = filter_end;
        parts = filter_parts;
    }

    if let Some((join_end, sep)) = consume_js_string_arg_method(text, idx, "join") {
        let joined = join_js_string_parts(parts, &sep)?;
        return Some(consume_js_join_string_transforms(
            text, join_end, joined, bindings,
        ));
    }

    let mut after_reverse = consume_js_no_arg_method(text, idx, "reverse")?;
    parts.reverse();
    if let Some((concat_end, concat_parts)) =
        consume_js_concat_chain(text, after_reverse, parts.clone(), bindings, arrays)
    {
        after_reverse = concat_end;
        parts = concat_parts;
    }
    if let Some((filter_end, filter_parts)) =
        consume_js_array_filter_chain(text, after_reverse, parts.clone())
    {
        after_reverse = filter_end;
        parts = filter_parts;
    }
    let (join_end, sep) = consume_js_string_arg_method(text, after_reverse, "join")?;
    let joined = join_js_string_parts(parts, &sep)?;
    Some(consume_js_join_string_transforms(
        text, join_end, joined, bindings,
    ))
}

fn consume_js_array_filter_chain(
    text: &str,
    mut idx: usize,
    mut parts: Vec<String>,
) -> Option<(usize, Vec<String>)> {
    let mut consumed = false;
    while let Some(open) = consume_js_method_open(text, idx, "filter") {
        let close = find_js_balanced_paren_close(text, open + 1)?;
        let arg = text[open + 1..close].trim();
        if !is_js_identity_filter_arg(arg) {
            return None;
        }
        parts.retain(|part| !part.is_empty());
        idx = close + 1;
        consumed = true;
    }
    consumed.then_some((idx, parts))
}

fn is_js_identity_filter_arg(arg: &str) -> bool {
    if arg == "Boolean" {
        return true;
    }
    if let Some((lhs, rhs)) = arg.split_once("=>") {
        let lhs = lhs.trim().trim_matches(['(', ')', ' ']);
        let rhs = rhs.trim().trim_matches(['(', ')', ' ']);
        return !lhs.is_empty() && lhs == rhs;
    }
    if !arg.trim_start().starts_with("function") {
        return false;
    }
    let Some(paren_open) = arg.find('(') else {
        return false;
    };
    let Some(paren_close_rel) = arg[paren_open + 1..].find(')') else {
        return false;
    };
    let param = arg[paren_open + 1..paren_open + 1 + paren_close_rel].trim();
    !param.is_empty() && arg.contains(&format!("return {param}"))
}

fn consume_js_concat_chain(
    text: &str,
    mut idx: usize,
    mut parts: Vec<String>,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<(usize, Vec<String>)> {
    let mut consumed = false;
    while let Some(open) = consume_js_method_open(text, idx, "concat") {
        let mut cursor = skip_ascii_ws(text, open + 1);
        if text.as_bytes().get(cursor) == Some(&b')') {
            idx = cursor + 1;
            consumed = true;
            continue;
        }
        loop {
            if let Some((arg_end, mut arg_parts)) =
                parse_js_string_array_arg_at(text, cursor, bindings)
            {
                parts.append(&mut arg_parts);
                cursor = skip_ascii_ws(text, arg_end);
            } else if let Some((arg_end, value)) =
                parse_js_string_or_bound_arg(text, cursor, bindings)
            {
                parts.push(value);
                cursor = skip_ascii_ws(text, arg_end);
            } else {
                let (arg_end, name) = parse_js_identifier_at(text, cursor)?;
                parts.extend(arrays.get(name)?.iter().cloned());
                cursor = skip_ascii_ws(text, arg_end);
            }
            if parts.len() > 128 {
                return None;
            }
            match text.as_bytes().get(cursor) {
                Some(b',') => cursor = skip_ascii_ws(text, cursor + 1),
                Some(b')') => {
                    idx = cursor + 1;
                    consumed = true;
                    break;
                }
                _ => return None,
            }
        }
    }
    consumed.then_some((idx, parts))
}

fn consume_js_string_arg_method(text: &str, idx: usize, method: &str) -> Option<(usize, String)> {
    let open = consume_js_method_open(text, idx, method)?;
    let arg_start = skip_ascii_ws(text, open + 1);
    let (arg_end, value) = parse_js_string_literal_at(text, arg_start)?;
    let close = skip_ascii_ws(text, arg_end);
    (text.as_bytes().get(close) == Some(&b')')).then_some((close + 1, value))
}

fn join_js_string_parts(parts: Vec<String>, sep: &str) -> Option<String> {
    if parts.len() > 128 || sep.len() > 64 {
        return None;
    }
    let joined = parts.join(sep);
    (joined.len() <= 8192).then_some(joined)
}

fn consume_js_join_string_transforms(
    text: &str,
    idx: usize,
    mut value: String,
    bindings: &std::collections::HashMap<String, String>,
) -> (usize, String) {
    let (mut idx, replaced) = consume_js_array_replace_chain(text, idx, value, bindings);
    value = replaced;
    if let Some((reverse_end, reversed)) = consume_js_split_reverse_join_chain(text, idx, &value) {
        idx = reverse_end;
        value = reversed;
    }
    (idx, value)
}

fn consume_js_array_replace_chain(
    text: &str,
    mut idx: usize,
    mut value: String,
    bindings: &std::collections::HashMap<String, String>,
) -> (usize, String) {
    for _ in 0..16 {
        let Some((replace_end, replaced)) =
            consume_js_replace_call(text, idx, value.clone(), bindings)
        else {
            break;
        };
        idx = replace_end;
        value = replaced;
        if value.len() > 8192 {
            break;
        }
    }
    (idx, value)
}

fn consume_js_split_reverse_join_chain(
    text: &str,
    idx: usize,
    value: &str,
) -> Option<(usize, String)> {
    let (split_end, sep) = consume_js_string_arg_method(text, idx, "split")?;
    if !sep.is_empty() {
        return None;
    }
    let reverse_end = consume_js_no_arg_method(text, split_end, "reverse")?;
    let (join_end, join_sep) = consume_js_string_arg_method(text, reverse_end, "join")?;
    if !join_sep.is_empty() {
        return None;
    }
    Some((join_end, value.chars().rev().collect()))
}

fn collect_js_byte_array_literal_byte_bindings(
    text: &str,
) -> std::collections::HashMap<String, Vec<u8>> {
    let mut bindings = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if bindings.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some((end, bytes)) = parse_js_byte_array_literal_bytes(expr, 0) else {
            continue;
        };
        if skip_ascii_ws(expr, end) != expr.len() {
            continue;
        }
        bindings.insert(name.to_string(), bytes);
    }
    bindings
}

fn collect_js_buffer_byte_bindings(
    text: &str,
    byte_bindings: &std::collections::HashMap<String, Vec<u8>>,
    string_bindings: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, Vec<u8>> {
    let mut bindings = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if bindings.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some((end, bytes)) =
            parse_js_buffer_from_arg_bytes(expr, 0, byte_bindings, string_bindings)
        else {
            continue;
        };
        if skip_ascii_ws(expr, end) != expr.len() {
            continue;
        }
        bindings.insert(name.to_string(), bytes);
    }
    bindings
}

fn parse_js_buffer_from_arg_bytes(
    text: &str,
    start: usize,
    byte_bindings: &std::collections::HashMap<String, Vec<u8>>,
    string_bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, Vec<u8>)> {
    let (buffer_end, name) = parse_js_identifier_at(text, start)?;
    if name != "Buffer" {
        return None;
    }
    let open = consume_js_method_or_bound_immediate_call_open(text, buffer_end, "from")?;
    let arg_start = skip_ascii_ws(text, open + 1);
    if let Some((arg_end, bytes)) =
        parse_js_byte_array_literal_bytes(text, arg_start).or_else(|| {
            let (arg_end, name) = parse_js_identifier_at(text, arg_start)?;
            byte_bindings
                .get(name)
                .map(|bytes| (arg_end, bytes.clone()))
        })
    {
        let close = skip_ascii_ws(text, arg_end);
        if text.as_bytes().get(close) == Some(&b')') {
            return Some((close + 1, bytes));
        }
    }

    let (arg_end, encoded) = parse_js_buffer_string_arg(text, arg_start, string_bindings)?;
    let comma = skip_ascii_ws(text, arg_end);
    if text.as_bytes().get(comma) != Some(&b',') {
        return None;
    }
    let encoding_start = skip_ascii_ws(text, comma + 1);
    let (encoding_end, input_encoding) = parse_js_string_literal_at(text, encoding_start)?;
    let bytes = decode_js_buffer_input_bytes(&encoded, &input_encoding)?;
    let close = skip_ascii_ws(text, encoding_end);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some((close + 1, bytes))
}

fn parse_js_buffer_from_call_at(
    text: &str,
    start: usize,
    byte_bindings: &std::collections::HashMap<String, Vec<u8>>,
    string_bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    let (buffer_end, bytes) =
        parse_js_buffer_from_arg_bytes(text, start, byte_bindings, string_bindings)?;
    let (end, output_encoding) = consume_js_to_string_optional_encoding(text, buffer_end)?;
    Some((end, decode_js_buffer_string_bytes(&bytes, output_encoding)?))
}

fn parse_js_buffer_string_arg(
    text: &str,
    start: usize,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    parse_js_string_literal_at(text, start).or_else(|| {
        let (end, name) = parse_js_identifier_at(text, start)?;
        bindings.get(name).map(|value| (end, value.clone()))
    })
}

#[derive(Clone, Copy)]
enum JsBufferStringEncoding {
    Utf8Like,
    Utf16Le,
}

fn consume_js_to_string_optional_encoding(
    text: &str,
    idx: usize,
) -> Option<(usize, JsBufferStringEncoding)> {
    let open = consume_js_method_open(text, idx, "toString")?;
    let cursor = skip_ascii_ws(text, open + 1);
    if text.as_bytes().get(cursor) == Some(&b')') {
        return Some((cursor + 1, JsBufferStringEncoding::Utf8Like));
    }
    let (arg_end, encoding) = parse_js_string_literal_at(text, cursor)?;
    let encoding = match encoding.to_ascii_lowercase().as_str() {
        "utf8" | "utf-8" | "ascii" | "latin1" | "binary" => JsBufferStringEncoding::Utf8Like,
        "utf16le" | "utf-16le" | "ucs2" | "ucs-2" => JsBufferStringEncoding::Utf16Le,
        _ => return None,
    };
    let close = skip_ascii_ws(text, arg_end);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some((close + 1, encoding))
}

fn parse_js_byte_array_literal_bytes(text: &str, start: usize) -> Option<(usize, Vec<u8>)> {
    if text.as_bytes().get(start) != Some(&b'[') {
        return None;
    }
    let close = find_js_byte_array_close(text, start + 1)?;
    let bytes = decode_js_byte_array_values(&text[start + 1..close])?;
    Some((close + 1, bytes))
}

fn decode_js_buffer_string_bytes(bytes: &[u8], encoding: JsBufferStringEncoding) -> Option<String> {
    match encoding {
        JsBufferStringEncoding::Utf8Like => Some(String::from_utf8_lossy(bytes).into_owned()),
        JsBufferStringEncoding::Utf16Le => decode_js_utf16_bytes(bytes, u16::from_le_bytes),
    }
}

fn decode_js_buffer_input_bytes(encoded: &str, encoding: &str) -> Option<Vec<u8>> {
    match encoding.to_ascii_lowercase().as_str() {
        "hex" => decode_js_hex_bytes(encoded),
        "base64" => decode_js_base64_bytes(encoded),
        "base64url" => decode_js_base64url_bytes(encoded),
        _ => None,
    }
}

fn decode_js_hex_bytes(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() > 16384 {
        return None;
    }
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut decoded = Vec::with_capacity(cleaned.len() / 2);
    let mut chars = cleaned.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi = hi.to_digit(16)?;
        let lo = lo.to_digit(16)?;
        decoded.push(((hi << 4) | lo) as u8);
    }
    (decoded.len() <= 8192).then_some(decoded)
}

fn decode_js_base64_bytes(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() > 16384 {
        return None;
    }
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let decoded = decode_base64_maybe_unpadded(&cleaned)?;
    (decoded.len() <= 8192).then_some(decoded)
}

fn decode_js_base64url_bytes(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() > 16384 {
        return None;
    }
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    let decoded = decode_base64_maybe_unpadded(&cleaned)?;
    (decoded.len() <= 8192).then_some(decoded)
}

fn decode_base64_maybe_unpadded(cleaned: &str) -> Option<Vec<u8>> {
    let mut padded = cleaned.to_string();
    match padded.len() % 4 {
        0 => {}
        2 => padded.push_str("=="),
        3 => padded.push('='),
        _ => return None,
    }
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()
}

fn decoded_js_textdecoder_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let string_bindings = collect_js_string_literal_bindings(text);
    let decoder_bindings = collect_js_textdecoder_bindings(text, &string_bindings);
    let typed_array_bindings = collect_js_typed_byte_array_bindings(text);
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
        if let Some((call_end, decoded)) = parse_js_textdecoder_decode_call_at(
            text,
            cursor,
            &typed_array_bindings,
            &string_bindings,
        ) {
            out.push(decoded);
            cursor = call_end;
            continue;
        }
        if let Some((call_end, decoded)) = parse_js_textdecoder_instance_decode_call_at(
            text,
            cursor,
            &typed_array_bindings,
            &decoder_bindings,
        ) {
            out.push(decoded);
            cursor = call_end;
            continue;
        }
        cursor = ident_end;
    }
    out
}

fn collect_js_typed_byte_array_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut bindings = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if bindings.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some((end, decoded)) = parse_js_typed_byte_array_arg(expr, 0) else {
            continue;
        };
        if skip_ascii_ws(expr, end) != expr.len() {
            continue;
        }
        bindings.insert(name.to_string(), decoded);
    }
    bindings
}

fn collect_js_typed_byte_array_byte_bindings(
    text: &str,
) -> std::collections::HashMap<String, Vec<u8>> {
    let mut bindings = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if bindings.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some((end, bytes)) = parse_js_typed_byte_array_arg_bytes(expr, 0) else {
            continue;
        };
        if skip_ascii_ws(expr, end) != expr.len() {
            continue;
        }
        bindings.insert(name.to_string(), bytes);
    }
    bindings
}

fn parse_js_textdecoder_decode_call_at(
    text: &str,
    start: usize,
    typed_array_bindings: &std::collections::HashMap<String, String>,
    string_bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    let (new_end, encoding) = parse_js_textdecoder_new_expr_at(text, start, string_bindings)?;
    let decode_open = consume_js_method_or_bound_immediate_call_open(text, new_end, "decode")?;
    parse_js_textdecoder_decode_args_at(text, decode_open, encoding, typed_array_bindings)
}

fn parse_js_textdecoder_instance_decode_call_at(
    text: &str,
    start: usize,
    typed_array_bindings: &std::collections::HashMap<String, String>,
    decoder_bindings: &std::collections::HashMap<String, JsTextDecoderEncoding>,
) -> Option<(usize, String)> {
    let (ident_end, name) = parse_js_identifier_at(text, start)?;
    let encoding = *decoder_bindings.get(name)?;
    let decode_open = consume_js_method_or_bound_immediate_call_open(text, ident_end, "decode")?;
    parse_js_textdecoder_decode_args_at(text, decode_open, encoding, typed_array_bindings)
}

fn parse_js_textdecoder_new_expr_at(
    text: &str,
    start: usize,
    string_bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, JsTextDecoderEncoding)> {
    let (new_end, new_name) = parse_js_identifier_at(text, start)?;
    if new_name != "new" {
        return None;
    }
    let decoder_start = skip_ascii_ws(text, new_end);
    let decoder_end = parse_js_textdecoder_constructor_name_end(text, decoder_start)?;
    let open = skip_ascii_ws(text, decoder_end);
    if text.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let (close, encoding) = parse_js_textdecoder_constructor_close(text, open, string_bindings)?;
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some((close + 1, encoding))
}

fn parse_js_textdecoder_decode_args_at(
    text: &str,
    decode_open: usize,
    encoding: JsTextDecoderEncoding,
    typed_array_bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    let arg_start = skip_ascii_ws(text, decode_open + 1);
    let (arg_end, decoded) = match encoding {
        JsTextDecoderEncoding::Utf8 => {
            let byte_bindings = collect_js_byte_array_literal_byte_bindings(text);
            let string_bindings = collect_js_string_literal_bindings(text);
            let buffer_bindings =
                collect_js_buffer_byte_bindings(text, &byte_bindings, &string_bindings);
            parse_js_typed_byte_array_arg(text, arg_start)
                .or_else(|| {
                    parse_js_buffer_from_arg_bytes(
                        text,
                        arg_start,
                        &byte_bindings,
                        &string_bindings,
                    )
                    .map(|(arg_end, bytes)| (arg_end, String::from_utf8_lossy(&bytes).into_owned()))
                })
                .or_else(|| {
                    let (arg_end, name) = parse_js_identifier_at(text, arg_start)?;
                    if let Some(decoded) = typed_array_bindings.get(name) {
                        return Some((arg_end, decoded.clone()));
                    }
                    buffer_bindings
                        .get(name)
                        .map(|bytes| (arg_end, String::from_utf8_lossy(bytes).into_owned()))
                })?
        }
        JsTextDecoderEncoding::Utf16Le | JsTextDecoderEncoding::Utf16Be => {
            let byte_bindings = collect_js_byte_array_literal_byte_bindings(text);
            let string_bindings = collect_js_string_literal_bindings(text);
            let buffer_bindings =
                collect_js_buffer_byte_bindings(text, &byte_bindings, &string_bindings);
            let raw_array_bindings = collect_js_typed_byte_array_byte_bindings(text);
            let (arg_end, bytes) = parse_js_typed_byte_array_arg_bytes(text, arg_start)
                .or_else(|| {
                    parse_js_buffer_from_arg_bytes(
                        text,
                        arg_start,
                        &byte_bindings,
                        &string_bindings,
                    )
                })
                .or_else(|| {
                    let (arg_end, name) = parse_js_identifier_at(text, arg_start)?;
                    raw_array_bindings
                        .get(name)
                        .or_else(|| buffer_bindings.get(name))
                        .map(|bytes| (arg_end, bytes.clone()))
                })?;
            (arg_end, decode_js_textdecoder_bytes(&bytes, encoding)?)
        }
    };
    let decode_close = skip_ascii_ws(text, arg_end);
    if text.as_bytes().get(decode_close) != Some(&b')') {
        return None;
    }
    Some((decode_close + 1, decoded))
}

fn collect_js_textdecoder_bindings(
    text: &str,
    string_bindings: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, JsTextDecoderEncoding> {
    let mut bindings = std::collections::HashMap::new();
    for caps in JS_STRING_ASSIGN_RE.captures_iter(text) {
        if bindings.len() >= 256 {
            break;
        }
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str().trim()) else {
            continue;
        };
        let Some((end, encoding)) = parse_js_textdecoder_new_expr_at(expr, 0, string_bindings)
        else {
            continue;
        };
        if skip_ascii_ws(expr, end) != expr.len() {
            continue;
        }
        bindings.insert(name.to_string(), encoding);
    }
    bindings
}

#[derive(Clone, Copy)]
enum JsTextDecoderEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

fn parse_js_textdecoder_constructor_name_end(text: &str, start: usize) -> Option<usize> {
    let (first_end, first_name) = parse_js_identifier_at(text, start)?;
    if first_name == "TextDecoder" {
        return Some(first_end);
    }
    if !matches!(first_name, "window" | "self" | "globalThis") {
        return None;
    }
    let member = skip_ascii_ws(text, first_end);
    if text.as_bytes().get(member) == Some(&b'.') {
        let member_start = skip_ascii_ws(text, member + 1);
        let (member_end, member_name) = parse_js_identifier_at(text, member_start)?;
        return (member_name == "TextDecoder").then_some(member_end);
    }
    if text.as_bytes().get(member) == Some(&b'[') {
        let literal_start = skip_ascii_ws(text, member + 1);
        let (literal_end, member_name) = parse_js_string_literal_at(text, literal_start)?;
        let close = skip_ascii_ws(text, literal_end);
        if text.as_bytes().get(close) == Some(&b']') && member_name == "TextDecoder" {
            return Some(close + 1);
        }
    }
    None
}

fn parse_js_textdecoder_constructor_close(
    text: &str,
    open: usize,
    string_bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, JsTextDecoderEncoding)> {
    let mut cursor = skip_ascii_ws(text, open + 1);
    if text.as_bytes().get(cursor) == Some(&b')') {
        return Some((cursor, JsTextDecoderEncoding::Utf8));
    }

    let (arg_end, encoding) = parse_js_string_or_bound_arg(text, cursor, string_bindings)?;
    let encoding = parse_js_textdecoder_label(&encoding)?;
    cursor = skip_ascii_ws(text, arg_end);
    if text.as_bytes().get(cursor) == Some(&b')') {
        return Some((cursor, encoding));
    }

    if text.as_bytes().get(cursor) != Some(&b',') {
        return None;
    }
    cursor = skip_ascii_ws(text, cursor + 1);
    let options_end = consume_js_balanced_literal(text, cursor, b'{', b'}')?;
    let close = skip_ascii_ws(text, options_end);
    (text.as_bytes().get(close) == Some(&b')')).then_some((close, encoding))
}

fn parse_js_string_or_bound_arg(
    text: &str,
    start: usize,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<(usize, String)> {
    parse_js_string_literal_at(text, start).or_else(|| {
        let (end, name) = parse_js_identifier_at(text, start)?;
        bindings.get(name).map(|value| (end, value.clone()))
    })
}

fn parse_js_textdecoder_label(label: &str) -> Option<JsTextDecoderEncoding> {
    if label.eq_ignore_ascii_case("utf-8")
        || label.eq_ignore_ascii_case("utf8")
        || label.eq_ignore_ascii_case("unicode-1-1-utf-8")
    {
        return Some(JsTextDecoderEncoding::Utf8);
    }
    if label.eq_ignore_ascii_case("utf-16le")
        || label.eq_ignore_ascii_case("utf-16")
        || label.eq_ignore_ascii_case("unicode")
    {
        return Some(JsTextDecoderEncoding::Utf16Le);
    }
    if label.eq_ignore_ascii_case("utf-16be") {
        return Some(JsTextDecoderEncoding::Utf16Be);
    }
    None
}

fn consume_js_balanced_literal(
    text: &str,
    start: usize,
    open_byte: u8,
    close_byte: u8,
) -> Option<usize> {
    const MAX_BALANCED_LITERAL_LEN: usize = 1024;

    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&open_byte) {
        return None;
    }

    let mut stack = vec![close_byte];
    let mut cursor = start + 1;
    while cursor < bytes.len() && cursor.saturating_sub(start) <= MAX_BALANCED_LITERAL_LEN {
        match bytes[cursor] {
            b'\'' | b'"' | b'`' => {
                cursor = consume_js_quoted_bytes(text, cursor)?;
            }
            b'{' => {
                stack.push(b'}');
                cursor += 1;
            }
            b'[' => {
                stack.push(b']');
                cursor += 1;
            }
            b'(' => {
                stack.push(b')');
                cursor += 1;
            }
            b'}' | b']' | b')' => {
                if stack.pop()? != bytes[cursor] {
                    return None;
                }
                cursor += 1;
                if stack.is_empty() {
                    return Some(cursor);
                }
            }
            _ => cursor += 1,
        }
    }
    None
}

fn consume_js_quoted_bytes(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let quote = *bytes.get(start)?;
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                cursor = cursor.saturating_add(2);
            }
            b'\r' | b'\n' if quote != b'`' => return None,
            b if b == quote => return Some(cursor + 1),
            _ => cursor += 1,
        }
    }
    None
}

fn consume_js_call_open(text: &str, start: usize) -> Option<usize> {
    let open = skip_ascii_ws(text, start);
    if text.as_bytes().get(open) == Some(&b'(') {
        return Some(open);
    }
    if text.as_bytes().get(open) == Some(&b'?') && text.as_bytes().get(open + 1) == Some(&b'.') {
        let optional_open = skip_ascii_ws(text, open + 2);
        if text.as_bytes().get(optional_open) == Some(&b'(') {
            return Some(optional_open);
        }
    }
    None
}

fn consume_js_no_arg_method(text: &str, start: usize, method: &str) -> Option<usize> {
    let open = consume_js_method_open(text, start, method)?;
    let close = skip_ascii_ws(text, open + 1);
    (text.as_bytes().get(close) == Some(&b')')).then_some(close + 1)
}

fn consume_js_method_open(text: &str, start: usize, method: &str) -> Option<usize> {
    let method_end = consume_js_method_member_end(text, start, method)?;
    consume_js_call_open(text, method_end)
}

fn consume_js_method_or_bound_immediate_call_open(
    text: &str,
    start: usize,
    method: &str,
) -> Option<usize> {
    if let Some(open) = consume_js_method_open(text, start, method) {
        return Some(open);
    }
    let method_end = consume_js_method_member_end(text, start, method)?;
    let bind_open = consume_js_method_open(text, method_end, "bind")?;
    let bind_close = find_js_call_close(text, bind_open + 1)?;
    consume_js_call_open(text, bind_close + 1)
}

fn consume_js_method_member_end(text: &str, start: usize, method: &str) -> Option<usize> {
    let member = skip_ascii_ws(text, start);
    let method_start = if text.as_bytes().get(member) == Some(&b'.') {
        skip_ascii_ws(text, member + 1)
    } else if text.as_bytes().get(member) == Some(&b'?')
        && text.as_bytes().get(member + 1) == Some(&b'.')
    {
        skip_ascii_ws(text, member + 2)
    } else {
        return None;
    };
    let (method_end, name) = parse_js_identifier_at(text, method_start)?;
    if name != method {
        return None;
    }
    Some(method_end)
}

fn parse_js_typed_byte_array_arg(text: &str, start: usize) -> Option<(usize, String)> {
    parse_js_typed_byte_array_arg_bytes(text, start)
        .map(|(end, bytes)| (end, String::from_utf8_lossy(&bytes).into_owned()))
}

fn parse_js_typed_byte_array_arg_bytes(text: &str, start: usize) -> Option<(usize, Vec<u8>)> {
    let (first_end, first_name) = parse_js_identifier_at(text, start)?;
    let (array_end, array_name) = if first_name == "new" {
        let array_start = skip_ascii_ws(text, first_end);
        let (array_end, array_name) = parse_js_identifier_at(text, array_start)?;
        (array_end, array_name)
    } else {
        (first_end, first_name)
    };
    if !is_js_byte_array_ctor(array_name) {
        return None;
    }
    if let Some(open) = consume_js_method_open(text, array_end, "of") {
        let close = find_js_call_close(text, open + 1)?;
        let bytes = decode_js_byte_array_values(&text[open + 1..close])?;
        return Some((close + 1, bytes));
    }
    if let Some(open) = consume_js_method_open(text, array_end, "from") {
        let bracket_open = skip_ascii_ws(text, open + 1);
        if text.as_bytes().get(bracket_open) != Some(&b'[') {
            return None;
        }
        let bracket_close = find_js_byte_array_close(text, bracket_open + 1)?;
        let bytes = decode_js_byte_array_values(&text[bracket_open + 1..bracket_close])?;
        let close = skip_ascii_ws(text, bracket_close + 1);
        if text.as_bytes().get(close) != Some(&b')') {
            return None;
        }
        return Some((close + 1, bytes));
    }
    let open = skip_ascii_ws(text, array_end);
    if text.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let bracket_open = skip_ascii_ws(text, open + 1);
    if text.as_bytes().get(bracket_open) != Some(&b'[') {
        return None;
    }
    let bracket_close = find_js_byte_array_close(text, bracket_open + 1)?;
    let bytes = decode_js_byte_array_values(&text[bracket_open + 1..bracket_close])?;
    let close = skip_ascii_ws(text, bracket_close + 1);
    if text.as_bytes().get(close) != Some(&b')') {
        return None;
    }
    Some((close + 1, bytes))
}

fn is_js_byte_array_ctor(name: &str) -> bool {
    matches!(name, "Uint8Array" | "Uint8ClampedArray" | "Int8Array")
}

fn find_js_call_close(text: &str, mut cursor: usize) -> Option<usize> {
    while cursor < text.len() {
        match text.as_bytes()[cursor] {
            b')' => return Some(cursor),
            b'[' | b']' | b'(' | b'{' | b'}' => return None,
            b'\'' | b'"' => return None,
            byte if byte.is_ascii() => cursor += 1,
            _ => {
                cursor += text[cursor..].chars().next()?.len_utf8();
            }
        }
    }
    None
}

fn find_js_balanced_paren_close(text: &str, mut cursor: usize) -> Option<usize> {
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    while cursor < text.len() {
        match text.as_bytes()[cursor] {
            b'\'' | b'"' | b'`' => {
                let (end, _) = parse_js_string_literal_at(text, cursor)?;
                cursor = end;
            }
            b'(' => {
                paren_depth += 1;
                cursor += 1;
            }
            b')' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                return Some(cursor);
            }
            b')' => {
                paren_depth = paren_depth.saturating_sub(1);
                cursor += 1;
            }
            b'[' => {
                bracket_depth += 1;
                cursor += 1;
            }
            b']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                cursor += 1;
            }
            b'{' => {
                brace_depth += 1;
                cursor += 1;
            }
            b'}' => {
                brace_depth = brace_depth.saturating_sub(1);
                cursor += 1;
            }
            byte if byte.is_ascii() => cursor += 1,
            _ => cursor += text[cursor..].chars().next()?.len_utf8(),
        }
    }
    None
}

fn find_js_byte_array_close(text: &str, mut cursor: usize) -> Option<usize> {
    while cursor < text.len() {
        match text.as_bytes()[cursor] {
            b']' => return Some(cursor),
            b'[' | b'(' | b')' | b'{' | b'}' => return None,
            b'\'' | b'"' => return None,
            byte if byte.is_ascii() => cursor += 1,
            _ => {
                cursor += text[cursor..].chars().next()?.len_utf8();
            }
        }
    }
    None
}

fn decode_js_byte_array_values(values: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in values.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let value = eval_js_numeric_expr(part)?;
        let byte = match value {
            0..=255 => value as u8,
            0xffff_ff80..=0xffff_ffff => value as u8,
            _ => return None,
        };
        out.push(byte);
        if out.len() > 8192 {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn decode_js_textdecoder_bytes(bytes: &[u8], encoding: JsTextDecoderEncoding) -> Option<String> {
    match encoding {
        JsTextDecoderEncoding::Utf8 => Some(String::from_utf8_lossy(bytes).into_owned()),
        JsTextDecoderEncoding::Utf16Le => decode_js_utf16_bytes(bytes, u16::from_le_bytes),
        JsTextDecoderEncoding::Utf16Be => decode_js_utf16_bytes(bytes, u16::from_be_bytes),
    }
}

fn decode_js_utf16_bytes(bytes: &[u8], read_u16: fn([u8; 2]) -> u16) -> Option<String> {
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let units = bytes
        .chunks_exact(2)
        .map(|chunk| read_u16([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    let decoded = String::from_utf16_lossy(&units);
    Some(
        decoded
            .strip_prefix('\u{feff}')
            .unwrap_or(&decoded)
            .to_string(),
    )
}

fn eval_js_numeric_expr(expr: &str) -> Option<u32> {
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    let mut total = eval_js_additive_numeric_expr(bytes, expr, &mut i)?;

    loop {
        while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= bytes.len() {
            return Some(total);
        }
        if bytes.get(i) != Some(&b'^') {
            return None;
        }
        i += 1;
        total ^= eval_js_additive_numeric_expr(bytes, expr, &mut i)?;
    }
}

fn eval_js_additive_numeric_expr(bytes: &[u8], expr: &str, i: &mut usize) -> Option<u32> {
    let mut total: i64 = 0;
    let mut saw_term = false;
    let mut sign: i64 = 1;

    while *i < bytes.len() {
        while bytes.get(*i).is_some_and(u8::is_ascii_whitespace) {
            *i += 1;
        }
        if *i >= bytes.len() || bytes.get(*i) == Some(&b'^') {
            break;
        }
        match bytes[*i] {
            b'+' => {
                sign = 1;
                *i += 1;
                continue;
            }
            b'-' => {
                sign = -1;
                *i += 1;
                continue;
            }
            _ => {}
        }

        let start = *i;
        while *i < bytes.len()
            && (bytes[*i].is_ascii_hexdigit()
                || bytes.get(*i).is_some_and(|b| *b == b'x' || *b == b'X'))
        {
            *i += 1;
        }
        if *i == start {
            return None;
        }
        let term = &expr[start..*i];
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
            let byte = text.as_bytes()[cursor];
            cursor += if byte.is_ascii() {
                1
            } else {
                text[cursor..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(1)
            };
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
    if quote_byte != b'\'' && quote_byte != b'"' && quote_byte != b'`' {
        return None;
    }
    let quote_char = quote_byte as char;
    let is_template = quote_byte == b'`';

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
        if is_template && c == '$' && matches!(chars.peek(), Some(&(_, '{'))) {
            return None;
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
