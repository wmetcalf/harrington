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
        if let Some(normalized) = crate::deob_scan::normalize_liberal_url_token(raw_token) {
            url = Some(normalized);
        }
        i += 1;
    }
    url.map(|u| (u, dst))
}

fn short_option_cluster_output(token: &str) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find('O')?;
    Some(&cluster[idx + 1..])
}
