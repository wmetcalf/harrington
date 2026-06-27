//! wget handler - extracts URL + output target for native wget/get.exe calls.

use super::util::{split_words, strip_outer_quotes};
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
        let raw_token = strip_outer_quotes(tokens[i].trim_matches(')'));
        if (crate::deob_scan::wget_flag_matches_ci(raw_token, "-o")
            || raw_token.eq_ignore_ascii_case("--output-document"))
            && tokens.get(i + 1).is_some()
        {
            dst = tokens
                .get(i + 1)
                .map(|s| strip_outer_quotes(s.trim_matches(')')).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token
            .strip_prefix("-O")
            .or_else(|| raw_token.strip_prefix("-o"))
        {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(strip_outer_quotes(rest.trim_matches(')')).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = short_option_cluster_output(raw_token) {
            if rest.is_empty() {
                dst = tokens
                    .get(i + 1)
                    .map(|s| strip_outer_quotes(s.trim_matches(')')).to_string());
                i += 2;
            } else {
                dst = Some(strip_outer_quotes(rest.trim_matches(')')).to_string());
                i += 1;
            }
            continue;
        }
        if let Some(rest) =
            crate::util::strip_ascii_case_insensitive_prefix(raw_token, "--output-document=")
                .or_else(|| {
                    crate::util::strip_ascii_case_insensitive_prefix(
                        raw_token,
                        "--output-document:",
                    )
                })
        {
            if !rest.is_empty() {
                dst = Some(strip_outer_quotes(rest.trim_matches(')')).to_string());
            }
            i += 1;
            continue;
        }
        if raw_token.eq_ignore_ascii_case("--input-file") && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| strip_outer_quotes(s.trim_matches(')')))
                .unwrap_or_default();
            if let Some(normalized) = normalize_wget_url_token(candidate) {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-i") {
            if !rest.is_empty() && !rest.starts_with('-') {
                if let Some(normalized) =
                    normalize_wget_url_token(strip_outer_quotes(rest.trim_matches(')')))
                {
                    url = Some(normalized);
                }
                i += 1;
                continue;
            }
        }
        if let Some(rest) =
            crate::util::strip_ascii_case_insensitive_prefix(raw_token, "--input-file=").or_else(
                || crate::util::strip_ascii_case_insensitive_prefix(raw_token, "--input-file:"),
            )
        {
            if !rest.is_empty() {
                if let Some(normalized) =
                    normalize_wget_url_token(strip_outer_quotes(rest.trim_matches(')')))
                {
                    url = Some(normalized);
                }
            }
            i += 1;
            continue;
        }
        if wget_value_flag(raw_token) {
            i += 2;
            continue;
        }
        if wget_attached_value_flag(raw_token) {
            i += 1;
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
    WGET_VALUE_FLAGS
        .iter()
        .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn wget_attached_value_flag(token: &str) -> bool {
    WGET_VALUE_FLAGS.iter().any(|flag| {
        let Some(head) = token.get(..flag.len()) else {
            return false;
        };
        let tail = &token[flag.len()..];
        !tail.is_empty() && head.eq_ignore_ascii_case(flag) && tail.starts_with(['=', ':'])
    })
}

const WGET_VALUE_FLAGS: &[&str] = &[
    "-e",
    "-U",
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
    "--keep-session-cookies",
    "--proxy-user",
    "--proxy-password",
    "--bind-address",
    "--ca-certificate",
    "--certificate",
    "--private-key",
];

fn short_option_cluster_output(token: &str) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find('O')?;
    Some(&cluster[idx + 1..])
}
