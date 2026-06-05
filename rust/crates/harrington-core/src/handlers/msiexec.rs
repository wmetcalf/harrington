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
