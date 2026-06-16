//! wget handler — extracts URL + output target for native wget/get.exe calls.

use super::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    split_words,
};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_wget(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let downloads = parse_wget_like_downloads(&tokens, env);
    if downloads.is_empty() {
        return;
    };

    for (url, dst) in downloads {
        let dst_path = dst
            .as_ref()
            .map(WgetDestination::as_path)
            .map(str::to_string);

        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: url.clone(),
            dst: dst_path.clone(),
        });
        if let Some(d) = dst_path.as_ref() {
            env.modified_filesystem.insert(
                filesystem_storage_key(d),
                FsEntry::Download { src: url.clone() },
            );
        }
        if let Some(WgetDestination::DirectoryPrefix(prefix)) = dst {
            if let Some(name) = url_basename(&url) {
                let path = join_windows_path_preserving_separator(&prefix, &name);
                env.modified_filesystem.insert(
                    filesystem_storage_key(&path),
                    FsEntry::Download { src: url },
                );
            }
        } else if dst_path.is_none() {
            if let Some(name) = url_basename(&url) {
                env.modified_filesystem
                    .insert(name.to_ascii_lowercase(), FsEntry::Download { src: url });
            }
        }
    }
}

#[derive(Clone)]
enum WgetDestination {
    OutputDocument(String),
    DirectoryPrefix(String),
}

impl WgetDestination {
    fn as_path(&self) -> &str {
        match self {
            Self::OutputDocument(path) | Self::DirectoryPrefix(path) => path,
        }
    }
}

fn parse_wget_like_downloads(
    tokens: &[String],
    env: &Environment,
) -> Vec<(String, Option<WgetDestination>)> {
    let mut url: Option<String> = None;
    let mut urls: Vec<String> = Vec::new();
    let mut dst: Option<WgetDestination> = None;
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        let lower = raw_token.to_ascii_lowercase();
        if raw_token == "-o" && tokens.get(i + 1).is_some() {
            i += 2;
            continue;
        }
        if raw_token == "-O" && tokens.get(i + 1).is_some() {
            dst = tokens.get(i + 1).map(|s| {
                WgetDestination::OutputDocument(s.trim_matches(['"', '\'', ')']).to_string())
            });
            i += 2;
            continue;
        }
        if lower == "--output-document" && tokens.get(i + 1).is_some() {
            dst = tokens.get(i + 1).map(|s| {
                WgetDestination::OutputDocument(s.trim_matches(['"', '\'', ')']).to_string())
            });
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-O") {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(WgetDestination::OutputDocument(
                    rest.trim_matches(['"', '\'', ')']).to_string(),
                ));
                i += 1;
                continue;
            }
        }
        if let Some(rest) = short_option_cluster_output(raw_token) {
            if rest.is_empty() {
                dst = tokens.get(i + 1).map(|s| {
                    WgetDestination::OutputDocument(s.trim_matches(['"', '\'', ')']).to_string())
                });
                i += 2;
            } else {
                dst = Some(WgetDestination::OutputDocument(
                    rest.trim_matches(['"', '\'', ')']).to_string(),
                ));
                i += 1;
            }
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--output-document=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--output-document:"))
        {
            if !rest.is_empty() {
                dst = Some(WgetDestination::OutputDocument(
                    rest.trim_matches(['"', '\'', ')']).to_string(),
                ));
            }
            i += 1;
            continue;
        }
        if raw_token == "-P" && tokens.get(i + 1).is_some() {
            dst = tokens.get(i + 1).map(|s| {
                WgetDestination::DirectoryPrefix(s.trim_matches(['"', '\'', ')']).to_string())
            });
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-P") {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(WgetDestination::DirectoryPrefix(
                    rest.trim_matches(['"', '\'', ')']).to_string(),
                ));
                i += 1;
                continue;
            }
        }
        if let Some(rest) = short_option_cluster_directory_prefix(raw_token) {
            if rest.is_empty() {
                dst = tokens.get(i + 1).map(|s| {
                    WgetDestination::DirectoryPrefix(s.trim_matches(['"', '\'', ')']).to_string())
                });
                i += 2;
            } else {
                dst = Some(WgetDestination::DirectoryPrefix(
                    rest.trim_matches(['"', '\'', ')']).to_string(),
                ));
                i += 1;
            }
            continue;
        }
        if lower == "--directory-prefix" && tokens.get(i + 1).is_some() {
            dst = tokens.get(i + 1).map(|s| {
                WgetDestination::DirectoryPrefix(s.trim_matches(['"', '\'', ')']).to_string())
            });
            i += 2;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix:"))
        {
            if !rest.is_empty() {
                dst = Some(WgetDestination::DirectoryPrefix(
                    rest.trim_matches(['"', '\'', ')']).to_string(),
                ));
            }
            i += 1;
            continue;
        }
        if lower == "-i" && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .unwrap_or_default();
            for normalized in wget_input_sources(candidate, env) {
                url = Some(normalized.clone());
                urls.push(normalized);
            }
            i += 2;
            continue;
        }
        if lower == "--input-file" && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .unwrap_or_default();
            for normalized in wget_input_sources(candidate, env) {
                url = Some(normalized.clone());
                urls.push(normalized);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-i") {
            if !rest.is_empty() && !rest.starts_with('-') {
                for normalized in wget_input_sources(rest.trim_matches(['"', '\'', ')']), env) {
                    url = Some(normalized.clone());
                    urls.push(normalized);
                }
                i += 1;
                continue;
            }
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--input-file=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--input-file:"))
        {
            if !rest.is_empty() {
                for normalized in wget_input_sources(rest.trim_matches(['"', '\'', ')']), env) {
                    url = Some(normalized.clone());
                    urls.push(normalized);
                }
            }
            i += 1;
            continue;
        }
        if wget_value_flag(raw_token) {
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_wget_url_token(raw_token) {
            url = Some(normalized.clone());
            urls.push(normalized);
        }
        i += 1;
    }
    if urls.is_empty() {
        if let Some(url) = url {
            urls.push(url);
        }
    }
    let multi = urls.len() > 1;
    urls.into_iter()
        .map(|url| (url, wget_destination_for_count(dst.clone(), multi)))
        .collect()
}

fn wget_destination_for_count(
    dst: Option<WgetDestination>,
    multi: bool,
) -> Option<WgetDestination> {
    match dst {
        Some(WgetDestination::OutputDocument(_)) if multi => None,
        other => other,
    }
}

fn normalize_wget_url_token(token: &str) -> Option<String> {
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}

fn wget_input_sources(candidate: &str, env: &Environment) -> Vec<String> {
    if let Some(url) = normalize_wget_url_token(candidate) {
        return vec![url];
    }
    let urls = filesystem_entry_for_path(env, candidate).and_then(|entry| match entry {
        FsEntry::Content { content, .. } | FsEntry::Decoded { content, .. } => {
            urls_in_content(content)
        }
        _ => None,
    });
    urls.unwrap_or_default()
}

fn urls_in_content(content: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(content);
    let urls = text
        .split_whitespace()
        .filter_map(normalize_wget_url_token)
        .collect::<Vec<_>>();
    (!urls.is_empty()).then_some(urls)
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

fn wget_value_flag(token: &str) -> bool {
    matches!(token, "-e" | "-U")
        || [
            "--execute",
            "--header",
            "--user-agent",
            "--referer",
            "--post-data",
            "--post-file",
            "--body-data",
            "--body-file",
            "--method",
            "--load-cookies",
            "--save-cookies",
            "--proxy-user",
            "--proxy-password",
            "--bind-address",
            "--ca-certificate",
            "--certificate",
            "--private-key",
        ]
        .iter()
        .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn short_option_cluster_output(token: &str) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find('O')?;
    Some(&cluster[idx + 1..])
}

fn short_option_cluster_directory_prefix(token: &str) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find('P')?;
    Some(&cluster[idx + 1..])
}

fn strip_ascii_case_insensitive_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}
