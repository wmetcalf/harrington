//! aria2c handler - extracts URL + output target for common downloader forms.

use super::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    normalize_url_like_token, split_words,
};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_aria2c(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let downloads = parse_aria2c_downloads(&tokens, env);
    if downloads.is_empty() {
        return;
    }

    for (url, dst) in downloads {
        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: url.clone(),
            dst: dst.clone(),
        });
        if let Some(dst) = dst {
            env.modified_filesystem
                .insert(filesystem_storage_key(&dst), FsEntry::Download { src: url });
        } else if let Some(name) = url_basename(&url) {
            env.modified_filesystem
                .insert(name.to_ascii_lowercase(), FsEntry::Download { src: url });
        }
    }
}

pub(crate) fn parse_aria2c_downloads(
    tokens: &[String],
    env: &Environment,
) -> Vec<(String, Option<String>)> {
    let mut last_url: Option<String> = None;
    let mut urls: Vec<String> = Vec::new();
    let mut output: Option<String> = None;
    let mut directory: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let token = tokens[i].trim_matches(['"', '\'', ')']);
        let lower = token.to_ascii_lowercase();
        if token == "-o" && tokens.get(i + 1).is_some() {
            output = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            i += 2;
            continue;
        }
        if lower == "--out" && tokens.get(i + 1).is_some() {
            output = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            i += 2;
            continue;
        }
        if let Some(rest) = token
            .strip_prefix("-o")
            .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
        {
            output = nonempty_trimmed_value(rest);
            i += 1;
            continue;
        }
        if let Some(rest) = crate::util::strip_ascii_case_insensitive_prefix(token, "--out=")
            .or_else(|| crate::util::strip_ascii_case_insensitive_prefix(token, "--out:"))
            .filter(|rest| !rest.is_empty())
        {
            output = nonempty_trimmed_value(rest);
            i += 1;
            continue;
        }
        if token == "-d" && tokens.get(i + 1).is_some() {
            directory = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            i += 2;
            continue;
        }
        if lower == "--dir" && tokens.get(i + 1).is_some() {
            directory = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            i += 2;
            continue;
        }
        if let Some(rest) = token
            .strip_prefix("-d")
            .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
        {
            directory = nonempty_trimmed_value(rest);
            i += 1;
            continue;
        }
        if let Some(rest) = crate::util::strip_ascii_case_insensitive_prefix(token, "--dir=")
            .or_else(|| crate::util::strip_ascii_case_insensitive_prefix(token, "--dir:"))
            .filter(|rest| !rest.is_empty())
        {
            directory = nonempty_trimmed_value(rest);
            i += 1;
            continue;
        }
        if lower == "-i" && tokens.get(i + 1).is_some() {
            if let Some(candidate) = tokens.get(i + 1) {
                for found in aria2_input_sources(candidate.trim_matches(['"', '\'', ')']), env) {
                    last_url = Some(found.clone());
                    urls.push(found);
                }
            }
            i += 2;
            continue;
        }
        if lower == "--input-file" && tokens.get(i + 1).is_some() {
            if let Some(candidate) = tokens.get(i + 1) {
                for found in aria2_input_sources(candidate.trim_matches(['"', '\'', ')']), env) {
                    last_url = Some(found.clone());
                    urls.push(found);
                }
            }
            i += 2;
            continue;
        }
        if let Some(rest) = token
            .strip_prefix("-i")
            .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
        {
            for found in aria2_input_sources(rest.trim_matches(['"', '\'', ')']), env) {
                last_url = Some(found.clone());
                urls.push(found);
            }
            i += 1;
            continue;
        }
        if let Some(rest) = crate::util::strip_ascii_case_insensitive_prefix(token, "--input-file=")
            .or_else(|| crate::util::strip_ascii_case_insensitive_prefix(token, "--input-file:"))
            .filter(|rest| !rest.is_empty())
        {
            for found in aria2_input_sources(rest.trim_matches(['"', '\'', ')']), env) {
                last_url = Some(found.clone());
                urls.push(found);
            }
            i += 1;
            continue;
        }
        if aria2_value_flag(&lower) {
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_url_like_token(token) {
            last_url = Some(normalized.clone());
            urls.push(normalized);
        }
        i += 1;
    }

    if urls.is_empty() {
        if let Some(url) = last_url {
            urls.push(url);
        }
    }

    let multi = urls.len() > 1;
    urls.into_iter()
        .map(|url| {
            let dst =
                aria2_destination_for_url(&url, output.as_deref(), directory.as_deref(), multi);
            (url, dst)
        })
        .collect()
}

fn nonempty_trimmed_value(value: &str) -> Option<String> {
    let value = value.trim_matches(['"', '\'', ')']);
    (!value.is_empty()).then(|| value.to_string())
}

fn aria2_input_sources(candidate: &str, env: &Environment) -> Vec<String> {
    if let Some(url) = normalize_url_like_token(candidate) {
        return vec![url];
    }
    filesystem_entry_for_path(env, candidate)
        .and_then(|entry| match entry {
            FsEntry::Content { content, .. } | FsEntry::Decoded { content, .. } => {
                urls_in_content(content)
            }
            _ => None,
        })
        .unwrap_or_default()
}

fn urls_in_content(content: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(content);
    let urls = text
        .split_whitespace()
        .filter_map(normalize_url_like_token)
        .collect::<Vec<_>>();
    (!urls.is_empty()).then_some(urls)
}

fn aria2_destination_for_url(
    url: &str,
    output: Option<&str>,
    directory: Option<&str>,
    multi: bool,
) -> Option<String> {
    match (directory, output) {
        (Some(dir), Some(out)) if !multi && !is_windows_rooted_path(out) => {
            Some(join_windows_path_preserving_separator(dir, out))
        }
        (_, Some(out)) if !multi => Some(out.to_string()),
        (Some(dir), _) => {
            url_basename(url).map(|name| join_windows_path_preserving_separator(dir, &name))
        }
        (None, _) => None,
    }
}

fn aria2_value_flag(lower: &str) -> bool {
    matches!(
        lower,
        "--all-proxy"
            | "--http-proxy"
            | "--https-proxy"
            | "--ftp-proxy"
            | "--timeout"
            | "--connect-timeout"
            | "--retry-wait"
            | "--max-tries"
            | "--max-connection-per-server"
            | "--split"
            | "--max-concurrent-downloads"
            | "--min-split-size"
            | "--header"
            | "--user-agent"
            | "--referer"
            | "--load-cookies"
            | "--save-cookies"
            | "-j"
            | "-k"
            | "-m"
    )
}

fn url_basename(url: &str) -> Option<String> {
    let path = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .trim_end_matches(['/', '\\']);
    let name = path.rsplit(['/', '\\']).next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn is_windows_rooted_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with("\\\\")
        || path.starts_with("//")
        || (bytes.len() >= 3
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
            && bytes[0].is_ascii_alphabetic())
}
