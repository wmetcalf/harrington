//! Shared helpers for command-handler implementations.

use crate::env::{Environment, FsEntry};

pub(crate) use crate::util::{
    contains_ascii_case_insensitive, ends_with_ascii_case_insensitive, looks_like_liberal_url,
    starts_with_ascii_case_insensitive, strip_outer_quotes,
};

pub(crate) const MAX_FILESYSTEM_FALLBACK_SCAN_ENTRIES: usize = 2048;

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

pub(crate) fn normalize_wildcard_path(path: &str) -> String {
    path.to_ascii_lowercase()
        .replace('/', "\\")
        .replace("*.*", "*")
}

pub(crate) fn filesystem_storage_key(path: &str) -> String {
    normalize_filesystem_storage_path(path).to_ascii_lowercase()
}

pub(crate) fn normalize_filesystem_storage_path(path: &str) -> String {
    collapse_current_dir_segments(&collapse_repeated_separator(
        strip_current_dir_prefix(path),
        '\\',
    ))
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
    let storage_key = filesystem_storage_key(path);
    if storage_key != key {
        if let Some(entry) = env.modified_filesystem.get(&storage_key) {
            return Some(entry);
        }
    }
    if env.modified_filesystem.len() > MAX_FILESYSTEM_FALLBACK_SCAN_ENTRIES {
        return None;
    }
    let normalized = normalize_windows_path(path);
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            (normalize_windows_path(tracked_path) == normalized).then_some(entry)
        })
}

fn normalize_windows_path(path: &str) -> String {
    let normalized = path.to_ascii_lowercase().replace('/', "\\");
    collapse_current_dir_segments(&collapse_repeated_separator(&normalized, '\\'))
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

fn collapse_current_dir_segments(path: &str) -> String {
    path.split('\\')
        .filter(|part| *part != ".")
        .collect::<Vec<_>>()
        .join("\\")
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

pub(crate) fn normalize_url_like_token(token: &str) -> Option<String> {
    let token = trim_url_suffix(strip_outer_quotes(token));
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}

pub(crate) fn trim_url_suffix(url: &str) -> &str {
    crate::deob_scan::trim_liberal_url_suffix(url)
}

fn strip_ascii_case_prefix<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    let prefix_len = prefix.len();
    if token.len() < prefix_len {
        return None;
    }
    let head = token.get(..prefix_len)?;
    let tail = token.get(prefix_len..)?;
    head.eq_ignore_ascii_case(prefix).then_some(tail)
}

/// Lowercased Windows-style basename helper for handler path comparisons.
/// Trims outer quotes and accepts both `\` and `/` separators.
pub(crate) fn windows_basename(path: &str) -> Option<&str> {
    strip_outer_quotes(path)
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

/// Strip a case-insensitive keyword prefix followed by either end-of-input or
/// a permitted separator. Returns the slice AFTER the keyword, or None if the
/// input doesn't start with that keyword.
pub(crate) fn strip_keyword_ci<'a>(s: &'a str, kw: &str, allowed_follow: &[u8]) -> Option<&'a str> {
    let kw = kw.as_bytes();
    let prefix = s.as_bytes().get(..kw.len())?;
    if !prefix.eq_ignore_ascii_case(kw) || !s.is_char_boundary(kw.len()) {
        return None;
    }
    let rest = &s[kw.len()..];
    let Some(&next) = rest.as_bytes().first() else {
        return Some(rest);
    };
    if next.is_ascii_whitespace() || allowed_follow.contains(&next) {
        Some(rest)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{strip_keyword_ci, strip_outer_quotes, windows_basename};
    use crate::util::contains_ascii_case_insensitive;

    #[test]
    fn windows_basename_trims_quotes_and_separators() {
        assert_eq!(
            windows_basename(r#""C:\Windows\System32\certutil.exe""#),
            Some("certutil.exe")
        );
        assert_eq!(
            windows_basename(r#"'C:/Windows/System32/cscript.exe'"#),
            Some("cscript.exe")
        );
        assert_eq!(windows_basename(r#"payload.bin"#), Some("payload.bin"));
    }

    #[test]
    fn strip_keyword_ci_accepts_allowed_separators() {
        assert_eq!(strip_keyword_ci("GoTo:", "goto", b":/;"), Some(":"));
        assert_eq!(
            strip_keyword_ci("call:label", "call", b":/"),
            Some(":label")
        );
        assert_eq!(strip_keyword_ci("exit /b", "exit", b"/:"), Some(" /b"));
        assert_eq!(strip_keyword_ci("gotoX", "goto", b":/;"), None);
    }

    #[test]
    fn strip_keyword_ci_rejects_non_ascii_without_panic() {
        assert_eq!(strip_keyword_ci("óó", "set", b":/;"), None);
    }

    #[test]
    fn contains_ascii_case_insensitive_matches_mixed_case() {
        assert!(contains_ascii_case_insensitive("SeT /A", "set"));
        assert!(contains_ascii_case_insensitive(
            "EnableDelayedExpansion",
            "enabledelayedexpansion"
        ));
        assert!(!contains_ascii_case_insensitive("echo", "setlocal"));
    }

    #[test]
    fn strip_outer_quotes_removes_matching_quotes_after_trim() {
        assert_eq!(strip_outer_quotes(r#"  "abc"  "#), "abc");
        assert_eq!(strip_outer_quotes(r#"  'abc'  "#), "abc");
        assert_eq!(strip_outer_quotes(r#"abc"#), "abc");
    }
}
