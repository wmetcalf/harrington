//! regsvr32 handler — surfaces remote scriptlet URLs and WebDAV/UNC targets.

use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_regsvr32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if regsvr32_remote_unc_target_after(&tokens, 1) || regsvr32_local_target_after(&tokens, 1) {
        push_lolbas(raw, env);
    }
    if let Some(url) = regsvr32_webdav_url_after(&tokens, 1) {
        push_url_argument(raw, url, env);
    }
    if let Some(url) = regsvr32_scriptlet_url_after(&tokens, 1) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
    if let Some(url) = regsvr32_prior_download_url(&tokens, env) {
        push_url_argument(raw, url, env);
    }
}

fn regsvr32_scriptlet_url_after(tokens: &[String], start: usize) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        let candidate = if lower.starts_with("/i:") || lower.starts_with("-i:") {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens.get(i + 1).map(|next| strip_quotes(next))
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = trim_url_suffix(candidate);
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(candidate)
            .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(candidate))
        {
            return Some(url);
        }
    }
    None
}

fn regsvr32_remote_unc_target_after(tokens: &[String], start: usize) -> bool {
    let limit = tokens.len().min(start.saturating_add(12));
    tokens[start..limit]
        .iter()
        .map(|token| strip_quotes(token))
        .any(regsvr32_unc_load_target)
}

fn regsvr32_local_target_after(tokens: &[String], start: usize) -> bool {
    let limit = tokens.len().min(start.saturating_add(12));
    tokens[start..limit].iter().any(|token| {
        let candidate = trim_url_suffix(strip_quotes(token)).trim();
        !candidate.is_empty() && !candidate.starts_with(['/', '-']) && !candidate.starts_with(r"\\")
    })
}

fn regsvr32_webdav_url_after(tokens: &[String], start: usize) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    tokens[start..limit]
        .iter()
        .map(|token| strip_quotes(token))
        .find_map(webdav_url_for_candidate)
}

fn regsvr32_unc_load_target(token: &str) -> bool {
    let candidate = trim_url_suffix(strip_quotes(token)).trim();
    candidate.starts_with(r"\\") && regsvr32_loadable_target(candidate)
}

fn regsvr32_loadable_target(token: &str) -> bool {
    let trimmed = trim_url_suffix(token).to_ascii_lowercase();
    [".dll", ".sct", ".ocx", ".cpl"]
        .iter()
        .any(|suffix| trimmed.ends_with(suffix))
}

fn regsvr32_prior_download_url(tokens: &[String], env: &Environment) -> Option<String> {
    let limit = tokens.len().min(13);
    for i in 1..limit {
        let token = strip_quotes(&tokens[i]).trim();
        let lower = token.to_ascii_lowercase();
        let candidate = if lower.starts_with("/i:") || lower.starts_with("-i:") {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens.get(i + 1).map(|next| strip_quotes(next).trim())
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = trim_url_suffix(candidate).trim();
        if candidate.is_empty() {
            continue;
        }
        if let Some(src) = downloaded_src_for_candidate(candidate, env) {
            return Some(src);
        }
    }
    for token in tokens.iter().skip(1).take(12) {
        let candidate = trim_url_suffix(strip_quotes(token)).trim();
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if !regsvr32_loadable_target(candidate) {
            continue;
        }
        if let Some(src) = downloaded_src_for_candidate(candidate, env) {
            return Some(src);
        }
    }
    None
}

fn downloaded_src_for_candidate(candidate: &str, env: &Environment) -> Option<String> {
    let key = candidate.to_ascii_lowercase();
    if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
        return Some(src.clone());
    }
    if candidate.contains(['\\', '/']) {
        return None;
    }
    for (path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(candidate) {
            if let FsEntry::Download { src } = entry {
                return Some(src.clone());
            }
        }
    }
    None
}

fn webdav_url_for_candidate(candidate: &str) -> Option<String> {
    let candidate = trim_url_suffix(strip_quotes(candidate)).trim();
    if !candidate.starts_with(r"\\")
        || !contains_ascii_case_insensitive(candidate, r"\davwwwroot\")
        || !candidate.contains('@')
        || !regsvr32_loadable_target(candidate)
    {
        return None;
    }
    let parts: Vec<&str> = candidate
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    let host_port = parts.first()?;
    let (host, port) = host_port.split_once('@')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    Some(crate::deob_scan::unc_webdav_to_http_url(
        host, port, candidate,
    ))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn push_url_argument(raw: &str, url: String, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument { cmd, url: existing }
                if cmd == raw && existing == &url
        )
    }) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Lolbas { name, cmd } if name == "regsvr32" && cmd == raw
        )
    }) {
        env.traits.push(Trait::Lolbas {
            name: "regsvr32".to_string(),
            cmd: raw.to_string(),
        });
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

fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}
