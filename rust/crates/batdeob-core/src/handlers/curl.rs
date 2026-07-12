//! curl handler — extracts URL + output target. Mirrors interpret_curl.

use super::util::{filesystem_storage_key, split_words, strip_outer_quotes};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_curl(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let mut output: Option<String> = None;
    let mut output_dir: Option<String> = None;
    let mut remote_name = false;
    let mut urls: Vec<String> = Vec::new();
    let mut i = 1;
    while i < tokens.len() {
        let t = &tokens[i];
        match t.as_str() {
            "-o" => {
                if let Some(v) = tokens.get(i + 1) {
                    output = Some(strip_outer_quotes(v).to_string());
                }
                i += 2;
                continue;
            }
            _ if t.eq_ignore_ascii_case("--output") => {
                if let Some(v) = tokens.get(i + 1) {
                    output = Some(strip_outer_quotes(v).to_string());
                }
                i += 2;
                continue;
            }
            _ if t.eq_ignore_ascii_case("--output-dir") => {
                if let Some(v) = tokens.get(i + 1) {
                    output_dir = Some(strip_outer_quotes(v).to_string());
                }
                i += 2;
                continue;
            }
            "-K" => {
                if let Some(v) = tokens.get(i + 1) {
                    apply_config_file(
                        strip_outer_quotes(v),
                        env,
                        &mut urls,
                        &mut output,
                        &mut output_dir,
                        &mut remote_name,
                    );
                }
                i += 2;
                continue;
            }
            _ if t.eq_ignore_ascii_case("--config") => {
                if let Some(v) = tokens.get(i + 1) {
                    apply_config_file(
                        strip_outer_quotes(v),
                        env,
                        &mut urls,
                        &mut output,
                        &mut output_dir,
                        &mut remote_name,
                    );
                }
                i += 2;
                continue;
            }
            _ if t.starts_with("-K") && t.len() > 2 => {
                apply_config_file(
                    strip_outer_quotes(&t[2..]),
                    env,
                    &mut urls,
                    &mut output,
                    &mut output_dir,
                    &mut remote_name,
                );
                i += 1;
                continue;
            }
            _ if t.starts_with("-o") && t.len() > 2 => {
                output = Some(strip_outer_quotes(&t[2..]).to_string());
                i += 1;
                continue;
            }
            _ if compact_short_output_arg(t).is_some() => {
                let attached = compact_short_output_arg(t).unwrap_or_default();
                if attached.is_empty() {
                    if let Some(v) = tokens.get(i + 1) {
                        output = Some(strip_outer_quotes(v).to_string());
                    }
                    i += 2;
                } else {
                    output = Some(strip_outer_quotes(attached).to_string());
                    i += 1;
                }
                continue;
            }
            _ if case_insensitive_value_prefix(t, "--output=")
                .or_else(|| case_insensitive_value_prefix(t, "--output:"))
                .is_some() =>
            {
                let value = case_insensitive_value_prefix(t, "--output=")
                    .or_else(|| case_insensitive_value_prefix(t, "--output:"))
                    .unwrap_or_default();
                if !value.is_empty() {
                    output = Some(strip_outer_quotes(value).to_string());
                }
                i += 1;
                continue;
            }
            _ if case_insensitive_value_prefix(t, "--output-dir=")
                .or_else(|| case_insensitive_value_prefix(t, "--output-dir:"))
                .is_some() =>
            {
                let value = case_insensitive_value_prefix(t, "--output-dir=")
                    .or_else(|| case_insensitive_value_prefix(t, "--output-dir:"))
                    .unwrap_or_default();
                if !value.is_empty() {
                    output_dir = Some(strip_outer_quotes(value).to_string());
                }
                i += 1;
                continue;
            }
            _ if case_insensitive_value_prefix(t, "--config=")
                .or_else(|| case_insensitive_value_prefix(t, "--config:"))
                .is_some() =>
            {
                let value = case_insensitive_value_prefix(t, "--config=")
                    .or_else(|| case_insensitive_value_prefix(t, "--config:"))
                    .unwrap_or_default();
                if !value.is_empty() {
                    apply_config_file(
                        strip_outer_quotes(value),
                        env,
                        &mut urls,
                        &mut output,
                        &mut output_dir,
                        &mut remote_name,
                    );
                }
                i += 1;
                continue;
            }
            _ if case_insensitive_value_prefix(t, "--url=")
                .or_else(|| case_insensitive_value_prefix(t, "--url:"))
                .is_some() =>
            {
                let value = strip_outer_quotes(
                    case_insensitive_value_prefix(t, "--url=")
                        .or_else(|| case_insensitive_value_prefix(t, "--url:"))
                        .unwrap_or_default(),
                );
                if let Some(url) = normalize_curl_url(value) {
                    urls.push(url);
                }
                i += 1;
                continue;
            }
            "-O" => {
                remote_name = true;
                i += 1;
                continue;
            }
            _ if t.eq_ignore_ascii_case("--remote-name")
                || t.eq_ignore_ascii_case("--remote-name-all") =>
            {
                remote_name = true;
                i += 1;
                continue;
            }
            _ if is_compact_remote_name_flag(t) => {
                remote_name = true;
                i += 1;
                continue;
            }
            // Skip values for known one-arg flags
            _ if is_one_arg_flag(t) => {
                i += 2;
                continue;
            }
            _ => {
                if t.starts_with('-') {
                    i += 1;
                    continue;
                }
                let candidate = strip_outer_quotes(t);
                if let Some(url) = normalize_curl_url(candidate) {
                    urls.push(url);
                }
                i += 1;
            }
        }
    }
    if urls.is_empty() {
        return;
    }

    for url in urls {
        let dst = if let Some(o) = output.clone() {
            Some(resolve_output_path(output_dir.as_deref(), o))
        } else if remote_name {
            url_basename(&url).map(|name| {
                output_dir
                    .as_deref()
                    .map(|dir| join_dir_and_name(dir, &name))
                    .unwrap_or(name)
            })
        } else {
            None
        };

        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: url.clone(),
            dst: dst.clone(),
        });
        if let Some(d) = dst {
            env.modified_filesystem
                .insert(filesystem_storage_key(&d), FsEntry::Download { src: url });
        }
    }
}

fn apply_config_file(
    path: &str,
    env: &Environment,
    urls: &mut Vec<String>,
    output: &mut Option<String>,
    output_dir: &mut Option<String>,
    remote_name: &mut bool,
) {
    let key = path.to_ascii_lowercase();
    let Some(FsEntry::Content { content, .. }) = env.modified_filesystem.get(&key) else {
        return;
    };
    let text = String::from_utf8_lossy(content);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim().trim_start_matches('-').to_ascii_lowercase();
        let value = strip_outer_quotes(value.trim()).to_string();
        match name.as_str() {
            "url" => {
                if let Some(url) = normalize_curl_url(&value) {
                    urls.push(url);
                }
            }
            "output" | "o" => {
                *output = Some(value);
            }
            "output-dir" => {
                *output_dir = Some(value);
            }
            "remote-name" => {
                *remote_name = true;
            }
            _ => {}
        }
    }
}

fn normalize_curl_url(s: &str) -> Option<String> {
    if s.contains("%%") {
        return None;
    }
    crate::deob_scan::normalize_liberal_url_token(s)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(s))
}

fn compact_short_output_arg(token: &str) -> Option<&str> {
    if !token.starts_with('-') || token.starts_with("--") || token.len() <= 2 {
        return None;
    }
    if is_attached_one_arg_short_flag(token) {
        return None;
    }
    let flag = token[1..].find('o')?;
    Some(&token[1 + flag + 1..])
}

fn is_compact_remote_name_flag(token: &str) -> bool {
    token.starts_with('-')
        && !token.starts_with("--")
        && token.len() > 2
        && token[1..].contains('O')
}

fn is_one_arg_flag(token: &str) -> bool {
    const SHORT_FLAGS: &[&str] = &[
        "-d", "-H", "-X", "-A", "-e", "-b", "-c", "-u", "-m", "-T", "-F", "-x",
    ];
    const LONG_FLAGS: &[&str] = &[
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--header",
        "--request",
        "--user-agent",
        "--referer",
        "--cookie",
        "--cookie-jar",
        "--user",
        "--proxy",
        "--connect-timeout",
        "--max-time",
        "--upload-file",
        "--form",
        "--form-string",
        "--retry",
        "--retry-delay",
    ];
    SHORT_FLAGS.contains(&token)
        || LONG_FLAGS
            .iter()
            .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn is_attached_one_arg_short_flag(token: &str) -> bool {
    const SHORT_FLAGS: &[&str] = &[
        "-d", "-H", "-X", "-A", "-e", "-b", "-c", "-u", "-m", "-T", "-F", "-x",
    ];
    SHORT_FLAGS
        .iter()
        .any(|flag| token.starts_with(flag) && token.len() > flag.len())
}

fn case_insensitive_value_prefix<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    let head = token.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&token[prefix.len()..])
    } else {
        None
    }
}

fn url_basename(url: &str) -> Option<String> {
    let path_part = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .trim_end_matches(['/', '\\']);
    let last = path_part.rsplit(['/', '\\']).next()?.trim();
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}

fn join_dir_and_name(dir: &str, name: &str) -> String {
    let dir = dir.trim_matches(['"', '\'']);
    if dir.is_empty() {
        return name.to_string();
    }
    let sep = if dir.contains('\\') { '\\' } else { '/' };
    let mut out = String::with_capacity(dir.len() + 1 + name.len());
    out.push_str(dir.trim_end_matches(['\\', '/']));
    out.push(sep);
    out.push_str(name);
    out
}

fn resolve_output_path(output_dir: Option<&str>, output: String) -> String {
    output_dir
        .filter(|_| !is_windows_rooted_path(&output))
        .map(|dir| join_dir_and_name(dir, &output))
        .unwrap_or(output)
}

fn is_windows_rooted_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['\\', '/'])
        || bytes
            .get(0..2)
            .is_some_and(|head| head[0].is_ascii_alphabetic() && head[1] == b':')
}
