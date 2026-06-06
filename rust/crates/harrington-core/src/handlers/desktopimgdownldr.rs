//! desktopimgdownldr handler - surfaces /lockscreenurl downloads.

use super::util::split_words;
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
}

fn lockscreen_url(tokens: &[String]) -> Option<String> {
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        if token.eq_ignore_ascii_case("/lockscreenurl")
            || token.eq_ignore_ascii_case("-lockscreenurl")
        {
            if let Some(next) = tokens.get(i + 1) {
                if let Some(url) = normalize_url(strip_quotes(next)) {
                    return Some(url);
                }
            }
            i += 2;
            continue;
        }
        if let Some(value) = attached_lockscreen_url(token) {
            if let Some(url) = normalize_url(value) {
                return Some(url);
            }
        }
        i += 1;
    }
    None
}

fn attached_lockscreen_url(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for prefix in [
        "/lockscreenurl:",
        "-lockscreenurl:",
        "/lockscreenurl=",
        "-lockscreenurl=",
    ] {
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        let offset = token.len() - rest.len();
        let value = &token[offset..];
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

fn normalize_url(token: &str) -> Option<String> {
    let token = trim_url_suffix(strip_quotes(token));
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}

fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
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
