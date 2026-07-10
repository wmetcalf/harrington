//! Extract structured facts from PowerShell source text.
//!
//! All helpers operate on `&str` and return either captured slices or
//! decoded byte vectors. They are tolerant of variation across the
//! observed malware variants (function-name randomization, ordering of
//! Key vs IV, single vs double `.Replace`, etc.).

use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;

const MAX_AES_BYTE_ARRAY_FIELD_MATCHES: usize = 1024;

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
    Regex::new(&format!(
        r"(?ix)
          (?:\$ \w+\s*\.)?              # optional $var.
          \b Key \s* =
          \s* \[ (?:System\.)? Convert \] \s* :: \s* {decode} \s* \(
          \s* ['\x22] ([A-Za-z0-9+/=]{{16,}}) ['\x22] \s* \)
        ",
        decode = CONVERT_DECODE_METHOD,
    ))
    .expect("aes key re")
});

#[allow(clippy::expect_used)]
static AES_IV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!(
        r"(?ix)
          (?:\$ \w+\s*\.)?
          \b IV \s* =
          \s* \[ (?:System\.)? Convert \] \s* :: \s* {decode} \s* \(
          \s* ['\x22] ([A-Za-z0-9+/=]{{16,}}) ['\x22] \s* \)
        ",
        decode = CONVERT_DECODE_METHOD,
    ))
    .expect("aes iv re")
});

const CONVERT_DECODE_METHOD: &str = r"(?:FromBase64String|\(\s*\$\w+\s*\[\s*\d+\s*\]\s*\))";

#[cfg(test)]
#[allow(clippy::expect_used)]
static FROMBASE64_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?ix)
          \[ (?:System\.)? Convert \] \s* :: \s* FromBase64String \s* \(
          \s* ['\x22] ([A-Za-z0-9+/=]{16,}) ['\x22] \s* \)
        ",
    )
    .expect("frombase64 literal re")
});

/// Extract AES key+IV bytes from stage-3 PS. Returns `None` if either is
/// missing or fails base64 decode.
pub fn find_aes_key_iv(text: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = AES_KEY_RE
        .captures(text)
        .and_then(|caps| caps.get(1))
        .and_then(|m| {
            base64::engine::general_purpose::STANDARD
                .decode(m.as_str())
                .ok()
        })
        .or_else(|| find_aes_byte_array_assignment(text, "Key"))?;
    let iv = AES_IV_RE
        .captures(text)
        .and_then(|caps| caps.get(1))
        .and_then(|m| {
            base64::engine::general_purpose::STANDARD
                .decode(m.as_str())
                .ok()
        })
        .or_else(|| find_aes_byte_array_assignment(text, "IV"))?;
    Some((key, iv))
}

#[cfg(test)]
fn collect_base64_blobs(text: &str) -> Vec<Vec<u8>> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for caps in FROMBASE64_LITERAL_RE.captures_iter(text) {
        let Some(b64) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !seen.insert(b64.to_string()) {
            continue;
        }
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64) {
            out.push(bytes);
        }
    }
    out
}

fn find_aes_byte_array_assignment(text: &str, field: &str) -> Option<Vec<u8>> {
    let mut search_start = 0usize;
    let mut matches_seen = 0usize;
    while let Some(pos) = find_ascii_case_insensitive(text, field, search_start) {
        matches_seen += 1;
        if matches_seen > MAX_AES_BYTE_ARRAY_FIELD_MATCHES {
            return None;
        }
        let after_field = skip_ascii_ws(text, pos + field.len());
        if text.as_bytes().get(after_field) != Some(&b'=') {
            search_start = pos + field.len();
            continue;
        }
        let after_equals = skip_ascii_ws(text, after_field + 1);
        let after_type = match ps_byte_array_type_len(text.get(after_equals..)?) {
            Some(len) => skip_ascii_ws(text, after_equals + len),
            None => {
                search_start = pos + field.len();
                continue;
            }
        };
        if text.as_bytes().get(after_type) != Some(&b'@') {
            search_start = pos + field.len();
            continue;
        }
        let open = skip_ascii_ws(text, after_type + 1);
        if text.as_bytes().get(open) != Some(&b'(') {
            search_start = pos + field.len();
            continue;
        }
        let close = text[open + 1..].find(')')? + open + 1;
        let bytes = parse_ps_byte_array(&text[open + 1..close])?;
        if matches!(
            (field.to_ascii_lowercase().as_str(), bytes.len()),
            ("key", 16 | 24 | 32) | ("iv", 16)
        ) {
            return Some(bytes);
        }
        search_start = pos + field.len();
    }
    None
}

fn ps_byte_array_type_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    i = skip_ascii_ws(text, i);
    let type_name = "byte";
    if text
        .get(i..i + type_name.len())?
        .eq_ignore_ascii_case(type_name)
    {
        i += type_name.len();
    } else {
        return None;
    }
    i = skip_ascii_ws(text, i);
    if bytes.get(i) != Some(&b'[') || bytes.get(i + 1) != Some(&b']') {
        return None;
    }
    i += 2;
    i = skip_ascii_ws(text, i);
    if bytes.get(i) != Some(&b']') {
        return None;
    }
    Some(i + 1)
}

fn parse_ps_byte_array(body: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for raw in body.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            return None;
        }
        let value = if let Some(hex) = token
            .strip_prefix("0x")
            .or_else(|| token.strip_prefix("0X"))
        {
            u8::from_str_radix(hex, 16).ok()?
        } else {
            token.parse::<u8>().ok()?
        };
        out.push(value);
    }
    (!out.is_empty()).then_some(out)
}

fn find_ascii_case_insensitive(text: &str, needle: &str, start: usize) -> Option<usize> {
    crate::util::find_ascii_case_insensitive_from(text, needle, start)
}

fn skip_ascii_ws(text: &str, mut idx: usize) -> usize {
    while let Some(byte) = text.as_bytes().get(idx) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        idx += 1;
    }
    idx
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
    fn aes_key_iv_indirect_array_method_call() {
        let text =
            "$a.Key=[System.Convert]::($kNLs[12])('YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=');\
                    $a.IV=[System.Convert]::($kNLs[12])('PcWh4S5zqexZ2ueefstJ6A==');";
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
    fn collect_base64_blobs_finds_all_literals() {
        let text = "x=[Convert]::FromBase64String('AAAAAAAAAAAAAAAAAAAAAA=='); \
                    y=[System.Convert]::FromBase64String('YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=')";
        let blobs = collect_base64_blobs(text);
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].len(), 16);
        assert_eq!(blobs[1].len(), 32);
    }

    #[test]
    fn aes_key_iv_byte_array_hex_literals_extracted() {
        let text = "$aes.Key=[byte[]]@(0xFA,0xB2,0x9A,0x62,0x85,0x3F,0x9E,0xED,0x91,0xF4,0x73,0x7C,0xFA,0xBF,0x8C,0x9E);\
                    $aes.IV=[byte[]]@(0xFE,0x6A,0x14,0x2C,0x64,0xB9,0x42,0x68,0x05,0xA9,0x3B,0xB7,0x26,0x98,0x6B,0xEF);";
        let (key, iv) = find_aes_key_iv(text).unwrap();
        assert_eq!(
            key,
            vec![
                0xFA, 0xB2, 0x9A, 0x62, 0x85, 0x3F, 0x9E, 0xED, 0x91, 0xF4, 0x73, 0x7C, 0xFA, 0xBF,
                0x8C, 0x9E
            ]
        );
        assert_eq!(
            iv,
            vec![
                0xFE, 0x6A, 0x14, 0x2C, 0x64, 0xB9, 0x42, 0x68, 0x05, 0xA9, 0x3B, 0xB7, 0x26, 0x98,
                0x6B, 0xEF
            ]
        );
    }

    #[test]
    fn aes_key_iv_byte_array_decimal_literals_extracted() {
        let text = "$aes.Key = [Byte []]@(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24);\
                    $aes.IV = [BYTE[]]@(101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116);";
        let (key, iv) = find_aes_key_iv(text).unwrap();
        assert_eq!(key, (1u8..=24).collect::<Vec<_>>());
        assert_eq!(iv, (101u8..=116).collect::<Vec<_>>());
    }

    #[test]
    fn aes_byte_array_assignment_scan_is_bounded() {
        let mut text = String::new();
        for _ in 0..2_000 {
            text.push_str("$aes.Key : [byte[]]@(1,2,3,4);\n");
        }
        text.push_str("$aes.Key = [byte[]]@(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);\n");

        assert_eq!(find_aes_byte_array_assignment(&text, "Key"), None);
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
