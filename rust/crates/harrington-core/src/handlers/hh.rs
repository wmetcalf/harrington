//! hh.exe handler - surfaces HTML Help URL launches.

use super::util::{normalize_url_like_token, split_words};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_hh(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = html_help_url(&tokens) else {
        return;
    };
    env.traits.push(Trait::UrlLaunch {
        cmd: raw.to_string(),
        url,
    });
    push_lolbas(env, raw);
}

fn html_help_url(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .skip(1)
        .find_map(|token| normalize_url_like_token(token))
}

fn push_lolbas(env: &mut Environment, raw: &str) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "hh" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "hh".to_string(),
            cmd: raw.to_string(),
        });
    }
}
