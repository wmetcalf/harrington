//! regsvr32 handler - surfaces remote scriptlet URLs passed via /i.

use super::util::{filesystem_entry_for_path, split_words, strip_outer_quotes, windows_basename};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;
use crate::util::contains_ascii_case_insensitive;

pub fn h_regsvr32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = regsvr32_scriptlet_url_after(&tokens, 1, env)
        .or_else(|| regsvr32_webdav_url_after(&tokens, 1))
    else {
        return;
    };

    env.traits.push(Trait::UrlArgument {
        cmd: raw.to_string(),
        url,
    });
}

fn regsvr32_scriptlet_url_after(
    tokens: &[String],
    start: usize,
    env: &Environment,
) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let token = strip_outer_quotes(tokens[i].trim());
        let lower = token.to_ascii_lowercase();
        let candidate = if regsvr32_attached_i_arg(&lower) {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens
                .get(i + 1)
                .map(|next| strip_outer_quotes(next.trim()))
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
        if let Some(url) = downloaded_src_for_candidate(candidate, env) {
            return Some(url);
        }
    }
    None
}

fn regsvr32_webdav_url_after(tokens: &[String], start: usize) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for token in tokens.iter().take(limit).skip(start) {
        let token = trim_url_suffix(strip_outer_quotes(token));
        if let Some(url) = webdav_url_for_candidate(token) {
            return Some(url);
        }
    }
    None
}

fn webdav_url_for_candidate(candidate: &str) -> Option<String> {
    let candidate = candidate.trim();
    if !candidate.starts_with(r"\\") || !regsvr32_loadable_target(candidate) {
        return None;
    }
    let parts: Vec<&str> = candidate
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    let host_port = parts.first()?;
    if let Some((host, port)) = host_port.split_once('@') {
        if host.is_empty()
            || port.is_empty()
            || !contains_ascii_case_insensitive(candidate, r"\davwwwroot\")
        {
            return None;
        }
        return Some(crate::deob_scan::unc_webdav_to_http_url(
            host, port, candidate,
        ));
    }
    if parts.len() < 3 || !parts[1].eq_ignore_ascii_case("webdav") || parts[2].is_empty() {
        return None;
    }
    Some(crate::deob_scan::unc_webdav_to_http_url(
        host_port, "80", candidate,
    ))
}

fn regsvr32_loadable_target(token: &str) -> bool {
    windows_basename(token).is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        matches!(
            lower.as_str(),
            "scrobj.dll" | "scrobj" | "c2.dll" | "c2.sct"
        ) || lower.ends_with(".dll")
            || lower.ends_with(".sct")
            || lower.ends_with(".ocx")
    })
}

fn downloaded_src_for_candidate(candidate: &str, env: &Environment) -> Option<String> {
    if let Some(FsEntry::Download { src }) = filesystem_entry_for_path(env, candidate) {
        return Some(src.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(candidate) {
        if stripped.contains(['\\', '/']) {
            return match filesystem_entry_for_path(env, stripped) {
                Some(FsEntry::Download { src }) => Some(src.clone()),
                _ => None,
            };
        }
    }
    if let Some(name) = current_dir_basename(candidate) {
        return downloaded_src_by_basename(name, env);
    }
    if candidate.contains(['\\', '/']) {
        return None;
    }
    downloaded_src_by_basename(candidate, env)
}

fn downloaded_src_by_basename(candidate: &str, env: &Environment) -> Option<String> {
    let basename = windows_basename(candidate)?;
    env.modified_filesystem
        .iter()
        .find_map(|(path, entry)| {
            windows_basename(path)
                .is_some_and(|name| name.eq_ignore_ascii_case(basename))
                .then_some(entry)
        })
        .and_then(|entry| match entry {
            FsEntry::Download { src } => Some(src.clone()),
            _ => None,
        })
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn trim_url_suffix(url: &str) -> &str {
    crate::deob_scan::trim_liberal_url_suffix(url)
}

fn regsvr32_attached_i_arg(lower: &str) -> bool {
    lower.starts_with("/i:")
        || lower.starts_with("-i:")
        || lower.starts_with("/i=")
        || lower.starts_with("-i=")
}
