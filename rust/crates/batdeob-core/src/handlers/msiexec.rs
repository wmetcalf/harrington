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
            crate::deob_scan::normalize_liberal_url_token(trim_url_suffix(token))
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
