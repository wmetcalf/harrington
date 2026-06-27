//! certoc handler - surfaces remote GetCACAPS downloads.

use super::util::{split_words, strip_outer_quotes};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_certoc(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = getcacaps_url(&tokens) else {
        return;
    };
    env.traits.push(Trait::Download {
        cmd: raw.to_string(),
        src: url,
        dst: None,
    });
}

fn getcacaps_url(tokens: &[String]) -> Option<String> {
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
        if token.eq_ignore_ascii_case("-getcacaps") || token.eq_ignore_ascii_case("/getcacaps") {
            if let Some(next) = tokens.get(i + 1) {
                if let Some(url) = normalize_url(strip_outer_quotes(next)) {
                    return Some(url);
                }
            }
            i += 2;
            continue;
        }
        if let Some(value) = attached_getcacaps_value(token) {
            if let Some(url) = normalize_url(value) {
                return Some(url);
            }
        }
        i += 1;
    }
    None
}

fn attached_getcacaps_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for prefix in ["-getcacaps:", "/getcacaps:", "-getcacaps=", "/getcacaps="] {
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        let offset = token.len() - rest.len();
        let value = &token[offset..];
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn normalize_url(token: &str) -> Option<String> {
    let token = crate::deob_scan::trim_url_suffix(strip_outer_quotes(token));
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}
