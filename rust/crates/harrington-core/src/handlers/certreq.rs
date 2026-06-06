//! certreq handler - surfaces remote -config endpoints.

use super::util::{flag_url_value_after, split_words};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_certreq(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(url) = certreq_config_url(&tokens) else {
        return;
    };
    env.traits.push(Trait::UrlArgument {
        cmd: raw.to_string(),
        url,
    });
}

fn certreq_config_url(tokens: &[String]) -> Option<String> {
    flag_url_value_after(tokens, 1, &["-config", "/config"])
}
