//! aria2c handler - extracts URL + output target for common downloader forms.

use super::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    normalize_url_like_token, split_words,
};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_aria2c(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((url, dst)) = parse_aria2c_download(&tokens, env) else {
        return;
    };

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

pub(crate) fn parse_aria2c_download(
    tokens: &[String],
    env: &Environment,
) -> Option<(String, Option<String>)> {
    let mut url: Option<String> = None;
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
            output = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            i += 1;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(token, "--out=")
            .or_else(|| strip_ascii_case_insensitive_prefix(token, "--out:"))
            .filter(|rest| !rest.is_empty())
        {
            output = Some(rest.trim_matches(['"', '\'', ')']).to_string());
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
            directory = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            i += 1;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(token, "--dir=")
            .or_else(|| strip_ascii_case_insensitive_prefix(token, "--dir:"))
            .filter(|rest| !rest.is_empty())
        {
            directory = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            i += 1;
            continue;
        }
        if lower == "-i" && tokens.get(i + 1).is_some() {
            if let Some(candidate) = tokens.get(i + 1) {
                url = normalize_aria2_input_source(candidate.trim_matches(['"', '\'', ')']), env);
            }
            i += 2;
            continue;
        }
        if lower == "--input-file" && tokens.get(i + 1).is_some() {
            if let Some(candidate) = tokens.get(i + 1) {
                url = normalize_aria2_input_source(candidate.trim_matches(['"', '\'', ')']), env);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = token
            .strip_prefix("-i")
            .filter(|rest| !rest.is_empty() && !rest.starts_with('-'))
        {
            url = normalize_aria2_input_source(rest.trim_matches(['"', '\'', ')']), env);
            i += 1;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(token, "--input-file=")
            .or_else(|| strip_ascii_case_insensitive_prefix(token, "--input-file:"))
            .filter(|rest| !rest.is_empty())
        {
            url = normalize_aria2_input_source(rest.trim_matches(['"', '\'', ')']), env);
            i += 1;
            continue;
        }
        if aria2_value_flag(&lower) {
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_url_like_token(token) {
            url = Some(normalized);
        }
        i += 1;
    }

    let dst = match (directory, output) {
        (Some(dir), Some(out)) if !is_windows_rooted_path(&out) => {
            Some(join_windows_path_preserving_separator(&dir, &out))
        }
        (_, Some(out)) => Some(out),
        (Some(dir), None) => url
            .as_deref()
            .and_then(url_basename)
            .map(|name| join_windows_path_preserving_separator(&dir, &name)),
        (None, None) => None,
    };
    url.map(|u| (u, dst))
}

fn normalize_aria2_input_source(candidate: &str, env: &Environment) -> Option<String> {
    normalize_url_like_token(candidate).or_else(|| {
        filesystem_entry_for_path(env, candidate).and_then(|entry| match entry {
            FsEntry::Content { content, .. } | FsEntry::Decoded { content, .. } => {
                first_url_in_content(content)
            }
            _ => None,
        })
    })
}

fn first_url_in_content(content: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(content);
    text.split_whitespace().find_map(normalize_url_like_token)
}

fn aria2_value_flag(lower: &str) -> bool {
    matches!(
        lower,
        "-x" | "-s"
            | "-j"
            | "-k"
            | "-m"
            | "--max-connection-per-server"
            | "--split"
            | "--max-concurrent-downloads"
            | "--min-split-size"
            | "--max-tries"
            | "--header"
            | "--user-agent"
            | "--referer"
            | "--load-cookies"
            | "--save-cookies"
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

fn strip_ascii_case_insensitive_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}
