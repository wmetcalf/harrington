//! msiexec handler - surfaces direct URL package arguments.

use super::util::{split_words, strip_outer_quotes};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_msiexec(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = tokens
        .iter()
        .skip(1)
        .filter_map(|token| {
            let token = strip_outer_quotes(token.trim());
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

fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}

fn msiexec_url_from_token(token: &str) -> Option<String> {
    if let Some(url) = crate::deob_scan::normalize_liberal_url_token(trim_url_suffix(token)) {
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
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(trim_url_suffix(candidate))
        {
            return Some(url);
        }
    }
    None
}
