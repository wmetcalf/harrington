//! hh.exe handler - surfaces HTML Help URL launches.

use super::util::{normalize_url_like_token, split_words};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_hh(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if let Some(url) = html_help_url(&tokens) {
        env.traits.push(Trait::UrlLaunch {
            cmd: raw.to_string(),
            url,
        });
        push_lolbas(env, raw);
        return;
    }
    let Some(target) = html_help_target(&tokens) else {
        return;
    };
    if let Some(url) = prior_download_url(&target, env) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
        push_lolbas(env, raw);
    }
}

fn html_help_url(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .skip(1)
        .find_map(|token| normalize_url_like_token(token))
}

fn html_help_target(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .skip(1)
        .map(|token| token.trim_matches(['"', '\'']))
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

fn push_lolbas(env: &mut Environment, raw: &str) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "hh" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "hh".to_string(),
            cmd: raw.to_string(),
        });
    }
}
