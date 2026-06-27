//! msiexec handler - surfaces direct URL package arguments.

use super::util::{split_words, strip_outer_quotes, windows_basename};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_msiexec(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if let Some(url) = tokens
        .iter()
        .skip(1)
        .filter_map(|token| {
            let token = strip_outer_quotes(token.trim());
            msiexec_url_from_token(token)
        })
        .next()
    {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
        push_lolbas(raw, env);
        return;
    }

    if let Some(url) = msiexec_prior_download_url(&tokens, env) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
        push_lolbas(raw, env);
        return;
    }

    if tokens
        .iter()
        .skip(1)
        .map(|token| strip_outer_quotes(token.trim()))
        .any(msiexec_administrative_install_token)
    {
        push_lolbas(raw, env);
    }
}

fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}

fn msiexec_url_from_token(token: &str) -> Option<String> {
    let normalized_token = trim_url_suffix(token);
    if let Some(url) = crate::deob_scan::normalize_liberal_url_token(normalized_token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(normalized_token))
    {
        return Some(url);
    }

    let token = token.trim();
    let lower = token.to_ascii_lowercase();
    for prefix in [
        "/i", "-i", "/a", "-a", "/package", "-package", "/update", "-update",
    ] {
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        let original_rest = &token[token.len() - rest.len()..];
        let candidate = original_rest.trim_start_matches([':', '=']);
        if candidate.is_empty() {
            continue;
        }
        let candidate = trim_url_suffix(candidate);
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(candidate)
            .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(candidate))
        {
            return Some(url);
        }
    }
    None
}

fn msiexec_prior_download_url(tokens: &[String], env: &Environment) -> Option<String> {
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        let token = strip_outer_quotes(token.trim());
        let candidate = msiexec_local_package_from_token(token).or_else(|| {
            tokens.get(idx.wrapping_sub(1)).and_then(|prev| {
                msiexec_package_option(strip_outer_quotes(prev.trim())).then_some(token)
            })
        });
        let Some(candidate) = candidate else {
            continue;
        };
        if let Some(url) = downloaded_source_for_path(env, candidate) {
            return Some(url);
        }
    }
    None
}

fn msiexec_local_package_from_token(token: &str) -> Option<&str> {
    for prefix in [
        "/i", "-i", "/a", "-a", "/package", "-package", "/update", "-update",
    ] {
        let Some(rest) = token.strip_prefix(prefix) else {
            continue;
        };
        let candidate = rest.trim_start_matches([':', '=']);
        if is_local_package_path(candidate) {
            return Some(candidate);
        }
    }
    is_local_package_path(token).then_some(token)
}

fn msiexec_package_option(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "/i" | "-i" | "/a" | "-a" | "/package" | "-package" | "/update" | "-update"
    )
}

fn is_local_package_path(token: &str) -> bool {
    if token.is_empty()
        || crate::deob_scan::normalize_liberal_url_token(token).is_some()
        || crate::deob_scan::normalize_schemeless_domain_path_token(token).is_some()
    {
        return false;
    }
    windows_basename(token).is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        lower.ends_with(".msi") || lower.ends_with(".msp")
    })
}

fn downloaded_source_for_path(env: &Environment, path: &str) -> Option<String> {
    let mut key = path.to_ascii_lowercase();
    for _ in 0..8 {
        match env.modified_filesystem.get(&key) {
            Some(FsEntry::Download { src }) => return Some(src.clone()),
            Some(FsEntry::Copy { src }) => key = src.to_ascii_lowercase(),
            Some(FsEntry::Content { .. } | FsEntry::Decoded { .. }) => return None,
            None => return downloaded_source_for_current_dir_path(env, path),
        }
    }
    None
}

fn downloaded_source_for_current_dir_path(env: &Environment, path: &str) -> Option<String> {
    let name = current_dir_basename(path)?;
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, _)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked_name| tracked_name.eq_ignore_ascii_case(name))
                .then(|| downloaded_source_for_path(env, tracked_path))
        })
        .flatten()
}

fn current_dir_basename(path: &str) -> Option<&str> {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .and_then(windows_basename)
}

fn msiexec_administrative_install_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower == "/a"
        || lower == "-a"
        || lower
            .strip_prefix("/a")
            .or_else(|| lower.strip_prefix("-a"))
            .is_some_and(|rest| {
                rest.starts_with([':', '='])
                    || crate::deob_scan::normalize_liberal_url_token(rest).is_some()
                    || crate::deob_scan::normalize_schemeless_domain_path_token(rest).is_some()
            })
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "msiexec" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "msiexec".to_string(),
            cmd: raw.to_string(),
        });
    }
}
