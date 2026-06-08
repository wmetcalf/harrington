//! Direct URL launcher handlers for browsers and Explorer.

use super::util::{normalize_url_like_token, split_words};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_url_launch(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = url_argument(&tokens) else {
        return;
    };
    if !env.traits.iter().any(
        |t| matches!(t, Trait::UrlLaunch { cmd, url: existing } if cmd == raw && existing == &url),
    ) {
        env.traits.push(Trait::UrlLaunch {
            cmd: raw.to_string(),
            url,
        });
    }
}

fn url_argument(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .skip(1)
        .find_map(|token| normalize_url_like_token(token))
}
