//! wget handler - extracts URL + output target for native wget/get.exe calls.

use super::util::{
    filesystem_storage_key, join_windows_path_preserving_separator, split_words, strip_outer_quotes,
};
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
    if let Some(d) = dst.as_ref() {
        env.modified_filesystem
            .insert(filesystem_storage_key(d), FsEntry::Download { src: url });
    } else if let Some(name) = url_basename(&url) {
        env.modified_filesystem
            .insert(name.to_ascii_lowercase(), FsEntry::Download { src: url });
    }
}

fn parse_wget_like_download(tokens: &[String]) -> Option<(String, Option<String>)> {
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut output_dir: Option<String> = None;
    let mut url_from_input_file = false;
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
        if crate::deob_scan::wget_flag_matches_ci(raw_token, "-p") && tokens.get(i + 1).is_some() {
            output_dir = tokens
                .get(i + 1)
                .map(|s| strip_outer_quotes(s.trim_matches(')')).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-P") {
            if !rest.is_empty() && !rest.starts_with('-') {
                output_dir = Some(strip_outer_quotes(rest.trim_matches(')')).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) =
            crate::util::strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix=")
                .or_else(|| {
                    crate::util::strip_ascii_case_insensitive_prefix(
                        raw_token,
                        "--directory-prefix:",
                    )
                })
        {
            if !rest.is_empty() {
                output_dir = Some(strip_outer_quotes(rest.trim_matches(')')).to_string());
            }
            i += 1;
            continue;
        }
        if raw_token.eq_ignore_ascii_case("--directory-prefix") && tokens.get(i + 1).is_some() {
            output_dir = tokens
                .get(i + 1)
                .map(|s| strip_outer_quotes(s.trim_matches(')')).to_string());
            i += 2;
            continue;
        }
        if raw_token.eq_ignore_ascii_case("--input-file") && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| strip_outer_quotes(s.trim_matches(')')))
                .unwrap_or_default();
            if let Some(normalized) = normalize_wget_url_token(candidate) {
                url = Some(normalized);
                url_from_input_file = true;
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
                    url_from_input_file = true;
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
                    url_from_input_file = true;
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
            url_from_input_file = false;
        }
        i += 1;
    }
    if dst.is_none() && !url_from_input_file {
        dst = output_dir.and_then(|dir| {
            url.as_deref()
                .and_then(url_basename)
                .map(|name| join_windows_path_preserving_separator(&dir, &name))
        });
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

fn url_basename(url: &str) -> Option<String> {
    let path_part = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .trim_end_matches(['/', '\\']);
    let last = path_part.rsplit(['/', '\\']).next()?.trim();
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}
