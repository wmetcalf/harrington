//! msiexec handler - surfaces direct URL package arguments.

use super::util::{split_words, strip_outer_quotes};
use crate::env::Environment;
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
