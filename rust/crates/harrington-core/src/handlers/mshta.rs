use super::util::split_words;
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_mshta(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::Mshta {
        cmd: raw.to_string(),
    });

    for token in split_words(raw).iter().skip(1) {
        let url = strip_quotes(token);
        if let Some(src) = crate::deob_scan::normalize_liberal_url_token(url) {
            env.traits.push(Trait::Download {
                cmd: raw.to_string(),
                src,
                dst: None,
            });
            break;
        }
    }
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
