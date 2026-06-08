//! wget handler — extracts URL + output target for native wget/get.exe calls.

use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_wget(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((url, dst)) = parse_wget_like_download(&tokens) else {
        return;
    };

    env.traits.push(Trait::Download {
        cmd: raw.to_string(),
        src: url.clone(),
        dst: dst.clone(),
    });
    if let Some(d) = dst {
        env.modified_filesystem
            .insert(d.to_ascii_lowercase(), FsEntry::Download { src: url });
    }
}

fn parse_wget_like_download(tokens: &[String]) -> Option<(String, Option<String>)> {
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        let lower = raw_token.to_ascii_lowercase();
        if raw_token == "-o" && tokens.get(i + 1).is_some() {
            i += 2;
            continue;
        }
        if raw_token == "-O" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if lower == "--output-document" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-O") {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = short_option_cluster_output(raw_token) {
            if rest.is_empty() {
                dst = tokens
                    .get(i + 1)
                    .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
                i += 2;
            } else {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
            }
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--output-document=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--output-document:"))
        {
            if !rest.is_empty() {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if raw_token == "-P" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if lower == "--directory-prefix" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix:"))
        {
            if !rest.is_empty() {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if lower == "-i" && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .unwrap_or_default();
            if let Some(normalized) = normalize_wget_url_token(candidate) {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if wget_value_flag(raw_token) {
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_wget_url_token(raw_token) {
            url = Some(normalized);
        }
        i += 1;
    }
    url.map(|u| (u, dst))
}

fn normalize_wget_url_token(token: &str) -> Option<String> {
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
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

fn strip_ascii_case_insensitive_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}
