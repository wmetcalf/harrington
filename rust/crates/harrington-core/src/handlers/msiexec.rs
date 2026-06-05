//! msiexec handler — surfaces URL package arguments.

use super::util::split_words;
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_msiexec(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = tokens
        .iter()
        .skip(1)
        .filter_map(|token| {
            let token = strip_quotes(token);
            msiexec_url_from_token(token)
        })
        .next()
    else {
        return;
    };

    env.traits.push(Trait::UrlArgument {
        cmd: raw.to_string(),
        url,
    });
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
    for prefix in ["/i", "-i", "/package", "-package", "/update", "-update"] {
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
