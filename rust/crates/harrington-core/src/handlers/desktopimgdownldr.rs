//! desktopimgdownldr handler - surfaces /lockscreenurl downloads.

use super::util::{flag_url_value_after, split_words};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_desktopimgdownldr(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = lockscreen_url(&tokens) else {
        return;
    };
    env.traits.push(Trait::Download {
        cmd: raw.to_string(),
        src: url,
        dst: None,
    });
    push_lolbas(env, raw);
}

fn lockscreen_url(tokens: &[String]) -> Option<String> {
    flag_url_value_after(tokens, 1, &["/lockscreenurl", "-lockscreenurl"])
}

fn push_lolbas(env: &mut Environment, raw: &str) {
    if !env.traits.iter().any(
        |t| matches!(t, Trait::Lolbas { name, cmd } if name == "desktopimgdownldr" && cmd == raw),
    ) {
        env.traits.push(Trait::Lolbas {
            name: "desktopimgdownldr".to_string(),
            cmd: raw.to_string(),
        });
    }
}
