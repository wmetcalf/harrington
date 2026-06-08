//! msconfig.exe handler - surfaces legacy UAC bypass launch.

use super::util::{split_words, strip_outer_quotes};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_msconfig(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if !has_four_flag(&tokens) {
        return;
    }
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::UacBypass { technique } if technique == "msconfig-4"))
    {
        env.traits.push(Trait::UacBypass {
            technique: "msconfig-4".to_string(),
        });
    }
    push_lolbas(env, raw);
}

fn has_four_flag(tokens: &[String]) -> bool {
    tokens
        .iter()
        .skip(1)
        .map(|token| strip_outer_quotes(token))
        .any(|token| token == "/4" || token == "-4")
}

fn push_lolbas(env: &mut Environment, raw: &str) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "msconfig" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "msconfig".to_string(),
            cmd: raw.to_string(),
        });
    }
}
