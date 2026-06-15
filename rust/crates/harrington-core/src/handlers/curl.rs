//! curl handler — extracts URL + output target. Mirrors interpret_curl.

use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_curl(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let mut output: Option<String> = None;
    let mut output_dir: Option<String> = None;
    let mut remote_name = false;
    let mut url: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let t = &tokens[i];
        if let Some(value) = short_option_cluster_output(t) {
            if value.is_empty() {
                if let Some(v) = tokens.get(i + 1) {
                    output = Some(strip_quotes(v).to_string());
                }
                i += 2;
            } else {
                output = Some(strip_quotes(value).to_string());
                i += 1;
            }
            continue;
        }
        if t == "-o" || t.eq_ignore_ascii_case("--output") {
            if let Some(v) = tokens.get(i + 1) {
                output = Some(strip_quotes(v).to_string());
            }
            i += 2;
            continue;
        }
        if t == "-O"
            || t.eq_ignore_ascii_case("--remote-name")
            || t.eq_ignore_ascii_case("--remote-name-all")
        {
            remote_name = true;
            i += 1;
            continue;
        }
        if short_option_cluster_remote_name(t) {
            remote_name = true;
            i += 1;
            continue;
        }
        if t.eq_ignore_ascii_case("--output-dir") {
            if let Some(v) = tokens.get(i + 1) {
                output_dir = Some(strip_quotes(v).to_string());
            }
            i += 2;
            continue;
        }
        match t.as_str() {
            _ if t.eq_ignore_ascii_case("--url") => {
                if let Some(v) = tokens.get(i + 1) {
                    url = normalize_curl_url(strip_quotes(v));
                }
                i += 2;
                continue;
            }
            _ if strip_ascii_case_insensitive_prefix(t, "--output=")
                .or_else(|| strip_ascii_case_insensitive_prefix(t, "--output:"))
                .is_some() =>
            {
                let value = strip_ascii_case_insensitive_prefix(t, "--output=")
                    .or_else(|| strip_ascii_case_insensitive_prefix(t, "--output:"))
                    .unwrap_or_default();
                if !value.is_empty() {
                    output = Some(strip_quotes(value).to_string());
                }
                i += 1;
                continue;
            }
            _ if strip_ascii_case_insensitive_prefix(t, "--output-dir=")
                .or_else(|| strip_ascii_case_insensitive_prefix(t, "--output-dir:"))
                .is_some() =>
            {
                let value = strip_ascii_case_insensitive_prefix(t, "--output-dir=")
                    .or_else(|| strip_ascii_case_insensitive_prefix(t, "--output-dir:"))
                    .unwrap_or_default();
                if !value.is_empty() {
                    output_dir = Some(strip_quotes(value).to_string());
                }
                i += 1;
                continue;
            }
            _ if t.starts_with("-o") && t.len() > 2 => {
                let value = &t["-o".len()..];
                if !value.starts_with('-') {
                    output = Some(strip_quotes(value).to_string());
                }
                i += 1;
                continue;
            }
            _ if strip_ascii_case_insensitive_prefix(t, "--url=")
                .or_else(|| strip_ascii_case_insensitive_prefix(t, "--url:"))
                .is_some() =>
            {
                let value = strip_quotes(
                    strip_ascii_case_insensitive_prefix(t, "--url=")
                        .or_else(|| strip_ascii_case_insensitive_prefix(t, "--url:"))
                        .unwrap_or_default(),
                );
                if url.is_none() {
                    url = normalize_curl_url(value);
                }
                i += 1;
                continue;
            }
            // Skip values for known one-arg flags.
            _ if curl_value_flag(t) => {
                i += 2;
                continue;
            }
            _ => {
                if t.starts_with('-') {
                    i += 1;
                    continue;
                }
                let candidate = strip_quotes(t);
                if url.is_none() {
                    url = normalize_curl_url(candidate);
                }
                i += 1;
            }
        }
    }
    let Some(url) = url else { return };

    let dst = if let Some(o) = output {
        Some(
            output_dir
                .as_deref()
                .filter(|_| !is_windows_rooted_path(&o))
                .map(|dir| join_windows_path(dir, &o))
                .unwrap_or(o),
        )
    } else if remote_name {
        url_basename(&url).map(|name| {
            output_dir
                .as_deref()
                .map(|dir| join_windows_path(dir, &name))
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
            .insert(d.to_ascii_lowercase(), FsEntry::Download { src: url });
    }
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}

fn strip_ascii_case_insensitive_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn looks_like_url(s: &str) -> bool {
    // Tolerate Windows-liberal slashes after the colon — `http:\\X`,
    // `http:/X`, `http:////X` are all accepted by WinINet/IE/curl.exe
    // (curl on Windows normalises them). Obfuscators use mixed slashes.
    let lower = s.to_ascii_lowercase();
    for scheme in &["http:", "https:", "ftp:", "file:"] {
        if let Some(rest) = lower.strip_prefix(scheme) {
            let c = rest.chars().next();
            if matches!(c, Some('/') | Some('\\')) {
                return true;
            }
        }
    }
    false
}

fn normalize_curl_url(s: &str) -> Option<String> {
    if looks_like_url(s) {
        return crate::deob_scan::normalize_liberal_url_token(s).or_else(|| Some(s.to_string()));
    }
    crate::deob_scan::normalize_schemeless_domain_path_token(s)
}

fn curl_value_flag(token: &str) -> bool {
    matches!(
        token,
        "-d" | "-H" | "-X" | "-A" | "-e" | "-b" | "-c" | "-u" | "-x" | "-m" | "-T" | "-F"
    ) || [
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
    ]
    .iter()
    .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn short_option_cluster_output(token: &str) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find('o')?;
    Some(&cluster[idx + 1..])
}

fn short_option_cluster_remote_name(token: &str) -> bool {
    let Some(cluster) = token.strip_prefix('-') else {
        return false;
    };
    !cluster.starts_with('-') && cluster.len() > 1 && cluster.contains('O')
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

fn join_windows_path(prefix: &str, name: &str) -> String {
    if prefix.ends_with(['\\', '/']) {
        format!("{prefix}{name}")
    } else {
        format!("{prefix}\\{name}")
    }
}

fn is_windows_rooted_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['\\', '/'])
        || bytes
            .get(0..2)
            .is_some_and(|head| head[0].is_ascii_alphabetic() && head[1] == b':')
}
