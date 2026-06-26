//! regsvr32 handler - surfaces remote scriptlet URLs passed via /i.

use super::util::{split_words, strip_outer_quotes};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_regsvr32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = regsvr32_scriptlet_url_after(&tokens, 1) else {
        return;
    };

    env.traits.push(Trait::UrlArgument {
        cmd: raw.to_string(),
        url,
    });
}

fn regsvr32_scriptlet_url_after(tokens: &[String], start: usize) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let token = strip_outer_quotes(tokens[i].trim());
        let lower = token.to_ascii_lowercase();
        let candidate = if lower.starts_with("/i:") || lower.starts_with("-i:") {
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
    }
    None
}

fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}
