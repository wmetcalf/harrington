//! Shared helpers for command-handler implementations.

use crate::env::{Environment, FsEntry};

/// Split a whitespace-separated command line into tokens, keeping
/// double-quoted and single-quoted spans as single tokens. Quote
/// characters are retained in the output tokens (callers strip as needed).
///
/// **Known limitations** (acceptable for our current corpus, but worth
/// noting before publishing): does NOT understand the PowerShell backtick
/// escape (`-Command \`"hi\`"`), here-strings (`@"..."@` / `@'...'@`),
/// `@(...)` subexpression brackets, or `${var}` interpolation. CMD-side
/// callers expect raw arg tokens with quotes preserved, which this gives;
/// the PS handler then applies its own normalization. If a future corpus
/// shape lands that mangles PS args, replace this with a proper tokenizer
/// that emits `(text, quoted)` tuples and update `h_powershell` /
/// `collect_encoded_argument` to honor the `quoted` flag.
pub(crate) fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    for c in s.chars() {
        if c == '"' && !in_sq {
            in_dq = !in_dq;
            cur.push(c);
            continue;
        }
        if c == '\'' && !in_dq {
            in_sq = !in_sq;
            cur.push(c);
            continue;
        }
        if c.is_whitespace() && !in_dq && !in_sq {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub(crate) fn flag_url_value_after(
    tokens: &[String],
    start: usize,
    flags: &[&str],
) -> Option<String> {
    let mut i = start;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
        if flags.iter().any(|flag| token.eq_ignore_ascii_case(flag)) {
            if let Some(next) = tokens.get(i + 1) {
                if let Some(url) = normalize_url_like_token(strip_outer_quotes(next)) {
                    return Some(url);
                }
            }
            i += 2;
            continue;
        }
        if let Some(value) = attached_flag_value(token, flags) {
            if let Some(url) = normalize_url_like_token(value) {
                return Some(url);
            }
        }
        i += 1;
    }
    None
}

pub(crate) fn attached_flag_value<'a>(token: &'a str, flags: &[&str]) -> Option<&'a str> {
    for flag in flags {
        for separator in [':', '='] {
            let Some(rest) = strip_ascii_case_prefix(token, flag) else {
                continue;
            };
            let Some(value) = rest.strip_prefix(separator) else {
                continue;
            };
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn strip_ascii_case_prefix<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    let prefix_len = prefix.len();
    if token.len() < prefix_len {
        return None;
    }
    let (head, tail) = token.split_at(prefix_len);
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

pub(crate) fn normalize_url_like_token(token: &str) -> Option<String> {
    let token = trim_url_suffix(strip_outer_quotes(token));
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}

pub(crate) fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}

pub(crate) fn strip_outer_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}

pub(crate) fn normalize_wildcard_path(path: &str) -> String {
    path.to_ascii_lowercase()
        .replace('/', "\\")
        .replace("*.*", "*")
}

pub(crate) fn filesystem_storage_key(path: &str) -> String {
    normalize_filesystem_storage_path(path).to_ascii_lowercase()
}

pub(crate) fn normalize_filesystem_storage_path(path: &str) -> String {
    collapse_repeated_separator(strip_current_dir_prefix(path), '\\')
}

fn strip_current_dir_prefix(path: &str) -> &str {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .unwrap_or(path)
}

pub(crate) fn filesystem_entry_for_path<'a>(
    env: &'a Environment,
    path: &str,
) -> Option<&'a FsEntry> {
    let key = path.to_ascii_lowercase();
    if let Some(entry) = env.modified_filesystem.get(&key) {
        return Some(entry);
    }
    let normalized = normalize_windows_path(path);
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            (normalize_windows_path(tracked_path) == normalized).then_some(entry)
        })
}

fn normalize_windows_path(path: &str) -> String {
    path.to_ascii_lowercase().replace('/', "\\")
}

pub(crate) fn join_windows_path_preserving_separator(dir: &str, file: &str) -> String {
    let separator = if dir.contains('/') && !dir.contains('\\') {
        '/'
    } else {
        '\\'
    };
    let mut out = dir.trim_end_matches(['\\', '/']).to_string();
    out.push(separator);
    out.push_str(file.trim_start_matches(['\\', '/']));
    collapse_repeated_separator(&out, separator)
}

fn collapse_repeated_separator(s: &str, separator: char) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = '\0';
    for c in s.chars() {
        if c == separator && prev == separator {
            continue;
        }
        out.push(c);
        prev = c;
    }
    out
}

pub(crate) fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_text = 0usize;
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star = Some(pi);
            pi += 1;
            star_text = ti;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            star_text += 1;
            ti = star_text;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}
