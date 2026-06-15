//! Direct URL launcher handlers for browsers and Explorer.

use super::util::{normalize_url_like_token, split_words};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_url_launch(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if let Some(url) = url_argument(&tokens) {
        if !env.traits.iter().any(
            |t| matches!(t, Trait::UrlLaunch { cmd, url: existing } if cmd == raw && existing == &url),
        ) {
            env.traits.push(Trait::UrlLaunch {
                cmd: raw.to_string(),
                url,
            });
        }
        return;
    }
    let Some(target) = launcher_target(&tokens) else {
        return;
    };
    if let Some(url) = prior_download_url(&target, env) {
        push_url_argument(raw, url, env);
    }
}

fn url_argument(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .skip(1)
        .find_map(|token| normalize_url_like_token(token))
}

fn launcher_target(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .skip(1)
        .map(|token| {
            token
                .trim()
                .trim_matches(['"', '\''])
                .trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
        })
        .find(|token| !token.is_empty() && !token.starts_with(['/', '-']))
        .map(str::to_string)
}

fn prior_download_url(path: &str, env: &Environment) -> Option<String> {
    let key = path.to_ascii_lowercase();
    if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
        return Some(src.clone());
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|name| name.eq_ignore_ascii_case(path))
                .then_some(entry)
        })
        .and_then(|entry| match entry {
            FsEntry::Download { src } => Some(src.clone()),
            _ => None,
        })
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn push_url_argument(raw: &str, url: String, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument { cmd, url: existing } if cmd == raw && existing == &url
        )
    }) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
}
