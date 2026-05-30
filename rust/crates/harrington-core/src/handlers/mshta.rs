use super::util::split_words;
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_mshta(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::Mshta {
        cmd: raw.to_string(),
    });

    for token in split_words(raw).iter().skip(1) {
        let url = strip_quotes(token);
        if looks_like_url(url) {
            env.traits.push(Trait::Download {
                cmd: raw.to_string(),
                src: url.to_string(),
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

fn looks_like_url(s: &str) -> bool {
    // mshta accepts `hTtps://X`, `http:\\X`, `http:/X` etc — Windows
    // URL parsing is liberal about scheme case and slash count/type.
    let lower = s.to_ascii_lowercase();
    for scheme in &["http:", "https:", "ftp:", "file:"] {
        if let Some(rest) = lower.strip_prefix(scheme) {
            let c = rest.chars().next();
            if matches!(c, Some('/') | Some('\\')) {
                return true;
            }
        }
    }
    false
}
