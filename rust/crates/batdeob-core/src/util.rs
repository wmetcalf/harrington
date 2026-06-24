//! Crate-wide helpers shared across scanners and handlers.

/// ASCII case-insensitive substring search.
pub(crate) fn contains_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let hay = text.as_bytes();
    let needle = needle.as_bytes();
    hay.windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// ASCII case-insensitive prefix search.
pub(crate) fn starts_with_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    let Some(prefix) = text.as_bytes().get(..needle.len()) else {
        return false;
    };
    prefix.eq_ignore_ascii_case(needle)
}

/// Strip an ASCII case-insensitive prefix and return the remainder.
pub(crate) fn strip_ascii_case_insensitive_prefix<'a>(
    text: &'a str,
    needle: &str,
) -> Option<&'a str> {
    let needle = needle.as_bytes();
    let prefix = text.as_bytes().get(..needle.len())?;
    if prefix.eq_ignore_ascii_case(needle) {
        Some(&text[needle.len()..])
    } else {
        None
    }
}

/// Liberal URL shape check used by curl/mshta-style handlers.
pub(crate) fn looks_like_liberal_url(s: &str) -> bool {
    // Tolerate Windows-liberal slashes after the colon — `http:\\X`,
    // `http:/X`, `http:////X` are all accepted by WinINet/IE/curl.exe.
    // Obfuscators use mixed slashes, so the scheme prefix must be
    // case-insensitive and the slash run may be either `/` or `\`.
    for scheme in &["http:", "https:", "ftp:", "file:"] {
        if let Some(rest) = strip_ascii_case_insensitive_prefix(s, scheme) {
            if matches!(rest.as_bytes().first(), Some(b'/') | Some(b'\\')) {
                return true;
            }
        }
    }
    false
}

/// ASCII case-insensitive suffix search.
pub(crate) fn ends_with_ascii_case_insensitive(text: &str, suffix: &str) -> bool {
    text.len() >= suffix.len() && text[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// ASCII case-insensitive substring search from a given byte offset.
pub(crate) fn find_ascii_case_insensitive_from(
    text: &str,
    needle: &str,
    start: usize,
) -> Option<usize> {
    if needle.is_empty() {
        return Some(start.min(text.len()));
    }
    let hay = text.as_bytes();
    let needle = needle.as_bytes();
    if start > hay.len() || needle.len() > hay.len().saturating_sub(start) {
        return None;
    }
    hay[start..]
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
        .map(|pos| start + pos)
}

/// ASCII case-insensitive substring search from the start of the text.
pub(crate) fn find_ascii_case_insensitive(text: &str, needle: &str) -> Option<usize> {
    find_ascii_case_insensitive_from(text, needle, 0)
}

/// Trim outer matching single or double quotes after trimming whitespace.
pub(crate) fn strip_outer_quotes(s: &str) -> &str {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes.first() == Some(&b'"') && bytes.last() == Some(&b'"'))
            || (bytes.first() == Some(&b'\'') && bytes.last() == Some(&b'\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Return a prefix snippet capped at `max_chars`, fast-pathing ASCII.
pub(crate) fn snippet_prefix(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if text.is_ascii() {
        return text[..text.len().min(max_chars)].to_string();
    }
    text.chars().take(max_chars).collect()
}

/// Return a suffix snippet capped at `max_chars`, fast-pathing ASCII.
pub(crate) fn snippet_suffix(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if text.is_ascii() {
        return text[text.len().saturating_sub(max_chars)..].to_string();
    }
    let start = text
        .char_indices()
        .rev()
        .nth(max_chars.saturating_sub(1))
        .map(|(idx, _)| idx)
        .unwrap_or(0);
    text[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        contains_ascii_case_insensitive, ends_with_ascii_case_insensitive,
        find_ascii_case_insensitive, find_ascii_case_insensitive_from, looks_like_liberal_url,
        snippet_prefix, snippet_suffix, starts_with_ascii_case_insensitive,
        strip_ascii_case_insensitive_prefix, strip_outer_quotes,
    };

    #[test]
    fn matches_mixed_case() {
        assert!(contains_ascii_case_insensitive("SeT /A", "set"));
        assert!(contains_ascii_case_insensitive(
            "EnableDelayedExpansion",
            "enabledelayedexpansion"
        ));
        assert!(!contains_ascii_case_insensitive("echo", "setlocal"));
    }

    #[test]
    fn strips_outer_quotes_and_whitespace() {
        assert_eq!(strip_outer_quotes(r#"  "hello"  "#), "hello");
        assert_eq!(strip_outer_quotes(r#"  'hello'  "#), "hello");
        assert_eq!(strip_outer_quotes("plain"), "plain");
    }

    #[test]
    fn starts_with_ascii_case_insensitive_matches_mixed_case() {
        assert!(starts_with_ascii_case_insensitive("Net Use", "net use"));
        assert!(starts_with_ascii_case_insensitive(
            "PSConsoleFile",
            "psconsole"
        ));
        assert!(!starts_with_ascii_case_insensitive("echo", "set"));
    }

    #[test]
    fn strips_ascii_case_insensitive_prefix_and_returns_remainder() {
        assert_eq!(
            strip_ascii_case_insensitive_prefix("HtTpS://example", "https:"),
            Some("//example")
        );
        assert_eq!(
            strip_ascii_case_insensitive_prefix("file:///C:/Temp", "FILE:"),
            Some("///C:/Temp")
        );
        assert_eq!(
            strip_ascii_case_insensitive_prefix("ftp://x", "https:"),
            None
        );
    }

    #[test]
    fn liberal_url_shape_matches_mixed_case_schemes() {
        assert!(looks_like_liberal_url("hTtPs://example"));
        assert!(looks_like_liberal_url("FiLe:///C:/Temp/payload.exe"));
        assert!(!looks_like_liberal_url("curl payload.exe"));
    }

    #[test]
    fn ends_with_ascii_case_insensitive_matches_mixed_case() {
        assert!(ends_with_ascii_case_insensitive("payload.VBS", ".vbs"));
        assert!(ends_with_ascii_case_insensitive("payload.JSe", ".jse"));
        assert!(!ends_with_ascii_case_insensitive("payload.txt", ".vbs"));
    }

    #[test]
    fn finds_ascii_case_insensitive_with_start_offsets() {
        assert_eq!(
            find_ascii_case_insensitive_from("abcDeFabc", "def", 0),
            Some(3)
        );
        assert_eq!(
            find_ascii_case_insensitive_from("abcDeFabc", "abc", 4),
            Some(6)
        );
        assert_eq!(find_ascii_case_insensitive("abcDeFabc", "def"), Some(3));
        assert_eq!(find_ascii_case_insensitive_from("abc", "abcd", 0), None);
    }

    #[test]
    fn snippet_prefix_fast_paths_ascii_and_preserves_unicode() {
        assert_eq!(snippet_prefix("ABCDE", 3), "ABC");
        assert_eq!(snippet_prefix("hé🙂llo", 3), "hé🙂");
    }

    #[test]
    fn snippet_suffix_fast_paths_ascii_and_preserves_unicode() {
        assert_eq!(snippet_suffix("ABCDE", 3), "CDE");
        assert_eq!(snippet_suffix("hé🙂llo", 3), "llo");
    }
}
