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
        if (lower == "-o" || lower == "--output-document") && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token
            .strip_prefix("-O")
            .or_else(|| raw_token.strip_prefix("-o"))
        {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = raw_token
            .strip_prefix("--output-document=")
            .or_else(|| raw_token.strip_prefix("--output-document:"))
        {
            if !rest.is_empty() {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if lower == "-p" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if lower == "-i" && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']))
                .unwrap_or_default();
            if let Some(normalized) = crate::deob_scan::normalize_liberal_url_token(candidate) {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if let Some(normalized) = crate::deob_scan::normalize_liberal_url_token(raw_token) {
            url = Some(normalized);
        }
        i += 1;
    }
    url.map(|u| (u, dst))
}
