//! Auto-elevate LOLBin handlers used in UAC bypass chains.

use crate::env::Environment;
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_auto_elevate(raw: &str, env: &mut Environment) {
    let Some(name) = auto_elevate_name(raw) else {
        return;
    };
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::UacBypass { technique } if technique == name))
    {
        env.traits.push(Trait::UacBypass {
            technique: name.to_string(),
        });
    }
    push_lolbas(name, raw, env);
}

fn auto_elevate_name(raw: &str) -> Option<&'static str> {
    let tokens = split_words(raw);
    let first = tokens.first()?.trim_matches(['"', '\'']);
    let base = first
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(first)
        .trim_end_matches('.');
    let base = if base
        .get(base.len().saturating_sub(4)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".exe"))
    {
        &base[..base.len() - 4]
    } else {
        base
    };
    if base.eq_ignore_ascii_case("fodhelper") {
        Some("fodhelper")
    } else if base.eq_ignore_ascii_case("eventvwr") {
        Some("eventvwr")
    } else if base.eq_ignore_ascii_case("sdclt") {
        Some("sdclt")
    } else if base.eq_ignore_ascii_case("computerdefaults") {
        Some("computerdefaults")
    } else if base.eq_ignore_ascii_case("wsreset") {
        Some("wsreset")
    } else {
        None
    }
}

fn push_lolbas(name: &str, raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(
        |t| matches!(t, Trait::Lolbas { name: got_name, cmd } if got_name == name && cmd == raw),
    ) {
        env.traits.push(Trait::Lolbas {
            name: name.to_string(),
            cmd: raw.to_string(),
        });
    }
}
