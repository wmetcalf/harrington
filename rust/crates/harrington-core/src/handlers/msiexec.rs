//! msiexec handler — surfaces URL package arguments.

use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_msiexec(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if msiexec_has_package_argument(&tokens) {
        push_lolbas(raw, env);
    }
    if let Some(url) = tokens
        .iter()
        .skip(1)
        .filter_map(|token| {
            let token = strip_quotes(token);
            msiexec_url_from_token(token)
        })
        .next()
    {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }

    if let Some(url) = msiexec_prior_download_url(&tokens, env) {
        let already = env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::UrlArgument { cmd, url: existing }
                    if cmd == raw && existing == &url
            )
        });
        if !already {
            env.traits.push(Trait::UrlArgument {
                cmd: raw.to_string(),
                url,
            });
        }
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Lolbas { name, cmd } if name == "msiexec" && cmd == raw
        )
    }) {
        env.traits.push(Trait::Lolbas {
            name: "msiexec".to_string(),
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
        "/i", "-i", "/p", "-p", "/package", "-package", "/update", "-update",
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

fn msiexec_has_package_argument(tokens: &[String]) -> bool {
    tokens
        .iter()
        .enumerate()
        .skip(1)
        .any(|(idx, token)| msiexec_package_candidate(token, tokens.get(idx + 1)).is_some())
}

fn msiexec_prior_download_url(tokens: &[String], env: &Environment) -> Option<String> {
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        if let Some(candidate) = msiexec_package_candidate(token, tokens.get(idx + 1)) {
            let key = candidate.to_ascii_lowercase();
            if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
                return Some(src.clone());
            }
            if !candidate.contains(['\\', '/']) {
                for (path, entry) in &env.modified_filesystem {
                    let Some(name) = windows_basename(path) else {
                        continue;
                    };
                    if name.eq_ignore_ascii_case(&candidate) {
                        if let FsEntry::Download { src } = entry {
                            return Some(src.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn msiexec_package_candidate<'a>(token: &'a str, next: Option<&'a String>) -> Option<String> {
    let token = strip_quotes(token).trim();
    let lower = token.to_ascii_lowercase();
    for prefix in [
        "/i", "-i", "/p", "-p", "/package", "-package", "/update", "-update",
    ] {
        if lower == prefix {
            return next
                .map(|value| trim_url_suffix(strip_quotes(value)).trim().to_string())
                .filter(|candidate| !candidate.is_empty());
        }
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        let original_rest = &token[token.len() - rest.len()..];
        let candidate = trim_url_suffix(original_rest.trim_start_matches([':', '=']))
            .trim()
            .to_string();
        if !candidate.is_empty() {
            return Some(candidate);
        }
    }
    None
}
