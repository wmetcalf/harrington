//! cmstp.exe handler - surfaces silent auto-elevated INF install use.

use super::util::{split_words, strip_outer_quotes};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_cmstp(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if !has_au_flag(&tokens) {
        return;
    }
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::UacBypass { technique } if technique == "cmstp-au"))
    {
        env.traits.push(Trait::UacBypass {
            technique: "cmstp-au".to_string(),
        });
    }
    push_lolbas(env, raw);
}

fn has_au_flag(tokens: &[String]) -> bool {
    tokens
        .iter()
        .skip(1)
        .map(|token| strip_outer_quotes(token))
        .any(|token| token.eq_ignore_ascii_case("/au") || token.eq_ignore_ascii_case("-au"))
}

fn push_lolbas(env: &mut Environment, raw: &str) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "cmstp" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "cmstp".to_string(),
            cmd: raw.to_string(),
        });
    }
}
