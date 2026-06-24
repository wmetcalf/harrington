//! Extract structured facts from PowerShell source text.
//!
//! All helpers operate on `&str` and return either captured slices or
//! decoded byte vectors. They are tolerant of variation across the
//! observed malware variants (function-name randomization, ordering of
//! Key vs IV, single vs double `.Replace`, etc.).

use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;

/// All single-quoted PS string literals whose body length is >= min_len.
///
/// PS single-quoted strings cannot contain a literal `'` (the doubled
/// form `''` is the escape, but we accept either reading — both are rare
/// inside the long base64 / replace strings we care about).
#[allow(dead_code)]
pub fn find_single_quoted_long(text: &str, min_len: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\'' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != b'\'' {
            j += 1;
        }
        if j > bytes.len() {
            break;
        }
        if j - start >= min_len {
            if let Ok(s) = std::str::from_utf8(&bytes[start..j]) {
                out.push(s);
            }
        }
        i = j + 1;
    }
    out
}

#[allow(clippy::expect_used)]
static REPLACE_PAIR_RE: Lazy<Regex> = Lazy::new(|| {
    // Match both `.Replace('A','B')` and `-replace 'A','B'` / `-replace "A","B"`.
    // The needle is what we actually care about; replacement is usually empty.
    Regex::new(
        r#"(?ix)
            (?: \.\s*Replace \s* \(    # .Replace(
                | -replace                # -replace
            )
            \s* ['"] ([^'"]{1,80}) ['"]   # needle
            \s* , \s* ['"] ([^'"]{0,80}) ['"]   # replacement
            \s* \)?                       # optional close-paren for .Replace
        "#,
    )
    .expect("replace pair re")
});

/// All `(needle, replacement)` pairs from `.Replace(...)` and `-replace ...`.
/// Maximum number of `.Replace(...)` / `-replace` pairs surfaced from a
/// single PowerShell body. Real droppers use 1-3 markers; this cap keeps a
/// hostile sample from forcing thousands of replace operations later.
pub const MAX_REPLACE_PAIRS: usize = 32;

pub fn find_replace_chain(text: &str) -> Vec<(String, String)> {
    REPLACE_PAIR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let n = caps.get(1)?.as_str().to_string();
            let r = caps.get(2)?.as_str().to_string();
            Some((n, r))
        })
        .take(MAX_REPLACE_PAIRS)
        .collect()
}

#[allow(clippy::expect_used)]
static AES_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
          (?:\$ \w+\s*\.)?              # optional $var.
          \b Key \s* =
          \s* \[ (?:System\.)? Convert \] \s* :: \s* FromBase64String \s* \(
          \s* ['\x22] ([A-Za-z0-9+/=]{16,}) ['\x22] \s* \)
        ",
    )
    .expect("aes key re")
});

#[allow(clippy::expect_used)]
static AES_IV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
          (?:\$ \w+\s*\.)?
          \b IV \s* =
          \s* \[ (?:System\.)? Convert \] \s* :: \s* FromBase64String \s* \(
          \s* ['\x22] ([A-Za-z0-9+/=]{16,}) ['\x22] \s* \)
        ",
    )
    .expect("aes iv re")
});

/// Extract AES key+IV bytes from stage-3 PS. Returns `None` if either is
/// missing or fails base64 decode.
pub fn find_aes_key_iv(text: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let key_b64 = AES_KEY_RE.captures(text)?.get(1)?.as_str();
    let iv_b64 = AES_IV_RE.captures(text)?.get(1)?.as_str();
    let key = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .ok()?;
    let iv = base64::engine::general_purpose::STANDARD
        .decode(iv_b64)
        .ok()?;
    Some((key, iv))
}

/// Find which line-prefix the loader filters on. Returns the prefix
/// string the malware uses to locate its embedded payload lines.
#[allow(dead_code)]
pub fn find_payload_line_prefix(text: &str) -> Option<String> {
    // Prefer `:: ` (3-char with trailing space) since that is the
    // stage-3 single-line payload format. `:::*` is stage-2 multi-line.
    if text.contains(".StartsWith(':: ')") || text.contains(".StartsWith(\":: \")") {
        return Some(":: ".to_string());
    }
    if text.contains("':::*'")
        || text.contains("\":::*\"")
        || text.contains("-like \":::*\"")
        || text.contains("-like ':::*'")
    {
        return Some(":::".to_string());
    }
    None
}

#[allow(clippy::expect_used)]
static INLINE_GZIPPED_B64_RE: Lazy<Regex> = Lazy::new(|| {
    // The gzip magic 1f 8b 08 00 base64-encodes to `H4sIA...`. Look for a
    // single-quoted PS literal that starts that way.
    Regex::new(r"'(H4sIA[A-Za-z0-9+/=]{100,})'").expect("inline gz b64")
});

/// Find an inline gzipped base64 literal (used by the stage-2 -> stage-3
/// gunzip handoff).
pub fn find_inline_gzipped_b64(text: &str) -> Option<&str> {
    INLINE_GZIPPED_B64_RE
        .captures(text)?
        .get(1)
        .map(|m| m.as_str())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn find_single_quoted_long_picks_long_only() {
        let text = "x='ab' y='abcdefghij' z='kk'";
        let out = find_single_quoted_long(text, 5);
        assert_eq!(out, vec!["abcdefghij"]);
    }

    #[test]
    fn find_replace_chain_dot_replace() {
        let text = "$x.Replace('aa','') .Replace('bb','cc')";
        let out = find_replace_chain(text);
        assert!(out.contains(&("aa".into(), "".into())));
        assert!(out.contains(&("bb".into(), "cc".into())));
    }

    #[test]
    fn find_replace_chain_dash_replace() {
        let text = r#"$x -replace "limestrawberry","" -replace 'ugiwuhkkfiquilr',''"#;
        let out = find_replace_chain(text);
        assert!(out.iter().any(|(n, _)| n == "limestrawberry"));
        assert!(out.iter().any(|(n, _)| n == "ugiwuhkkfiquilr"));
    }

    #[test]
    fn aes_key_iv_extracted() {
        let text = "$a.Key=[System.Convert]::FromBase64String('YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=');\
                    $a.IV=[System.Convert]::FromBase64String('PcWh4S5zqexZ2ueefstJ6A==');";
        let (key, iv) = find_aes_key_iv(text).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn aes_key_iv_handles_iv_before_key() {
        let text = "$a.IV=[Convert]::FromBase64String('PcWh4S5zqexZ2ueefstJ6A==');\
                    $a.Key=[Convert]::FromBase64String('YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=');";
        let (key, iv) = find_aes_key_iv(text).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn payload_prefix_colon_space() {
        let text = "foreach($l in $lines){if($l.StartsWith(':: ')){...}}";
        assert_eq!(find_payload_line_prefix(text).as_deref(), Some(":: "));
    }

    #[test]
    fn payload_prefix_triple_colon() {
        let text = "$rawLines=gc $banana|?{$_ -like \":::*\"}";
        assert_eq!(find_payload_line_prefix(text).as_deref(), Some(":::"));
    }

    #[test]
    fn inline_gzipped_b64_found() {
        let text = "$orange='H4sIAAAAAAAAAQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ='; foo;";
        let out = find_inline_gzipped_b64(text);
        assert!(out.is_some(), "got: {:?}", out);
        assert!(out.unwrap().starts_with("H4sIA"));
    }
}
