//! curl handler — extracts URL + output target. Mirrors interpret_curl.

use super::util::split_words;
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
        match t.as_str() {
            "-o" | "--output" => {
                if let Some(v) = tokens.get(i + 1) {
                    output = Some(strip_quotes(v).to_string());
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
            "-O" | "--remote-name" => {
                remote_name = true;
                i += 1;
                continue;
            }
            // Skip values for known one-arg flags
            "-d" | "--data" | "--data-ascii" | "--data-binary" | "--data-raw"
            | "--data-urlencode" | "-H" | "--header" | "-X" | "--request" | "-A"
            | "--user-agent" | "-e" | "--referer" | "-b" | "--cookie" | "-c" | "--cookie-jar"
            | "-u" | "--user" | "-x" | "--proxy" | "--connect-timeout" | "-m" | "--max-time"
            | "-T" | "--upload-file" | "-F" | "--form" | "--form-string" | "--retry"
            | "--retry-delay" => {
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
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
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

fn short_option_cluster_output(token: &str) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find('o')?;
    Some(&cluster[idx + 1..])
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
