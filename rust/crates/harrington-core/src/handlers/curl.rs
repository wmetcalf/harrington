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
        match t.as_str() {
            "-o" | "--output" => {
                if let Some(v) = tokens.get(i + 1) {
                    output = Some(strip_quotes(v).to_string());
                }
                i += 2;
                continue;
            }
            _ if t.starts_with("--output=") || t.starts_with("--output:") => {
                let value = &t["--output=".len()..];
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
                if url.is_none() && looks_like_url(candidate) {
                    url = Some(candidate.to_string());
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

fn url_basename(url: &str) -> Option<String> {
    let path_part = url.split(['?', '#']).next()?;
    let last = path_part.rsplit('/').next()?;
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}
