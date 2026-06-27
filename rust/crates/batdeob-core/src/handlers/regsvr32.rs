//! regsvr32 handler - surfaces remote scriptlet URLs passed via /i.

use super::util::{filesystem_entry_for_path, split_words, strip_outer_quotes, windows_basename};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_regsvr32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = regsvr32_scriptlet_url_after(&tokens, 1, env) else {
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
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}

fn regsvr32_attached_i_arg(lower: &str) -> bool {
    lower.starts_with("/i:")
        || lower.starts_with("-i:")
        || lower.starts_with("/i=")
        || lower.starts_with("-i=")
}
