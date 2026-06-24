use super::util::{looks_like_liberal_url, split_words, strip_outer_quotes};
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_mshta(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::Mshta {
        cmd: raw.to_string(),
    });

    for token in split_words(raw).iter().skip(1) {
        let url = strip_outer_quotes(token);
        if looks_like_liberal_url(url) {
            let url = crate::deob_scan::normalize_liberal_url_token(url)
                .unwrap_or_else(|| url.to_string());
            env.traits.push(Trait::Download {
                cmd: raw.to_string(),
                src: url,
                dst: None,
            });
            break;
        }
    }
}
