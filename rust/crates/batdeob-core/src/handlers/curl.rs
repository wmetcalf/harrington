//! curl handler — extracts URL + output target. Mirrors interpret_curl.

use super::util::{split_words, strip_outer_quotes};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_curl(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let mut output: Option<String> = None;
    let mut remote_name = false;
    let mut url: Option<String> = None;
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
            _ if case_insensitive_value_prefix(t, "--url=")
                .or_else(|| case_insensitive_value_prefix(t, "--url:"))
                .is_some() =>
            {
                let value = strip_outer_quotes(
                    case_insensitive_value_prefix(t, "--url=")
                        .or_else(|| case_insensitive_value_prefix(t, "--url:"))
                        .unwrap_or_default(),
                );
                if url.is_none() {
                    url = crate::deob_scan::normalize_liberal_url_token(value);
                }
                i += 1;
                continue;
            }
            "-O" => {
                remote_name = true;
                i += 1;
                continue;
            }
            _ if t.eq_ignore_ascii_case("--remote-name") => {
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
                if url.is_none() {
                    url = crate::deob_scan::normalize_liberal_url_token(candidate);
                }
                i += 1;
            }
        }
    }
    let Some(url) = url else { return };

    let dst = if let Some(o) = output {
        Some(o)
    } else if remote_name {
        url_basename(&url)
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
            .insert(d.to_ascii_lowercase(), FsEntry::Download { src: url });
    }
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
        "-d", "-H", "-X", "-A", "-e", "-b", "-c", "-u", "-m", "-T", "-F",
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
        "-d", "-H", "-X", "-A", "-e", "-b", "-c", "-u", "-m", "-T", "-F",
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
    let path_part = url.split(['?', '#']).next()?;
    let last = path_part.rsplit('/').next()?;
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}
