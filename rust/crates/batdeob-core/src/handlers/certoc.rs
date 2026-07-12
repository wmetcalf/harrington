//! certoc handler - surfaces remote GetCACAPS downloads.

use super::util::{flag_url_value_after, split_words};
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
    push_lolbas(raw, env);
}

fn getcacaps_url(tokens: &[String]) -> Option<String> {
    flag_url_value_after(tokens, 1, &["-getcacaps", "/getcacaps"])
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "certoc" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "certoc".to_string(),
            cmd: raw.to_string(),
        });
    }
}
