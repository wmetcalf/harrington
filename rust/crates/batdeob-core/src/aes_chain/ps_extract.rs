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
    //
    // PS escape support: inside an OUTER `'…'` string, a literal single
    // quote is written as `''`. When the obfuscator emits its `.Replace`
    // call as a string to `iex`, the captures look like `''quwd''` —
    // a doubled single-quote pair around the needle. We accept either
    // `'…'` or `''…''` as the delimiter. The `as.ps1` / `zp.ps1` family
    // is the motivating case.
    Regex::new(
        r#"(?ix)
            (?: \.\s*Replace \s* \(    # .Replace(
                | -replace                # -replace
            )
            \s*
            (?: '' ([^']{1,80}) ''      # PS-escaped needle ''A''
              | ['"] ([^'"]{1,80}) ['"] # plain quoted needle 'A' / "A"
            )
            \s* , \s*
            (?: '' ([^']{0,80}) ''      # PS-escaped replacement ''B''
              | ['"] ([^'"]{0,80}) ['"] # plain quoted replacement
            )
            \s* \)?                     # optional close-paren for .Replace
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
            // Try the PS-escaped capture first (groups 1, 3), fall back to
            // the plain-quoted capture (groups 2, 4). At least one of each
            // pair is set per match.
            let n = caps.get(1).or_else(|| caps.get(2))?.as_str().to_string();
            let r = caps.get(3).or_else(|| caps.get(4))?.as_str().to_string();
            Some((n, r))
        })
        .take(MAX_REPLACE_PAIRS)
        .collect()
}

// Method-name form: `FromBase64String` literal, OR an indirected lookup
// like `($kNLs[12])` / `($z[7])` where the obfuscator builds a string
// array of method names and indexes into it. The 1895041a55e8… /
// "(DHL) Original BL CI Copie.bat" family uses this exact pattern.
//
// Matching either form keeps Key/IV detection working across the
// straight `[Convert]::FromBase64String(...)` samples (dwm.bat family)
// AND the indirected `[Convert]::($var[N])(...)` samples without
// requiring us to evaluate the array build-up first.
const CONVERT_DECODE_METHOD: &str = r"(?:FromBase64String|\(\s*\$\w+\s*\[\s*\d+\s*\]\s*\))";

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

/// Find every `[Convert]::FromBase64String('<b64>')` literal in `text` and
/// return the decoded bytes that match valid AES key/IV lengths
/// (16/24/32 for keys, 16 for IVs). Used by `find_aes_pair_with_oracle`
/// as the candidate pool when the regex-based AES_KEY_RE / AES_IV_RE miss
/// the assignment because the field name isn't literally `Key` / `IV`
/// (e.g. `.KeyBytes`, `$cfg.Aes.Key = ...` with nested dots, or fields
/// renamed to `K` / `Vector`).
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

/// Cryptographically-validated AES key/IV pair search. When the regex-
/// driven `find_aes_key_iv` misses (field name isn't literally `Key`/`IV`,
/// the assignment goes through a nested property, the blob is built via
/// concat, etc.), this enumerates every base64 literal in `text` and tries
/// every (key in {16,24,32}, iv = 16) pair against `test_ct`. The pair
/// wins if AES-CBC decrypt succeeds AND the plaintext starts with a
/// gzip magic (`1f 8b`) or PE magic (`MZ`) — i.e. the very signal the
/// orchestrator's downstream pipeline expects.
pub fn find_aes_pair_with_oracle(text: &str, test_ct: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let blobs = collect_base64_blobs(text);
    if blobs.len() < 2 {
        return None;
    }
    let keys: Vec<&Vec<u8>> = blobs
        .iter()
        .filter(|b| matches!(b.len(), 16 | 24 | 32))
        .collect();
    let ivs: Vec<&Vec<u8>> = blobs.iter().filter(|b| b.len() == 16).collect();
    for k in &keys {
        for v in &ivs {
            // Don't pair a blob with itself when key and iv are both 16
            // bytes — that pair is degenerate.
            if std::ptr::eq(*k, *v) {
                continue;
            }
            if let Ok(pt) = super::crypto::aes_cbc_decrypt(k, v, test_ct) {
                if pt.starts_with(&[0x1f, 0x8b]) || pt.starts_with(b"MZ") {
                    return Some(((*k).clone(), (*v).clone()));
                }
            }
        }
    }
    None
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
        // 1895041a55e8… / (DHL) Original BL CI Copie.bat family: the
        // method name `FromBase64String` is hidden behind an array
        // index lookup like `($kNLs[12])`, where `$kNLs` was built up
        // earlier from `.Replace`-stripped fragments. AES_KEY_RE /
        // AES_IV_RE must accept this indirected form or we silently
        // skip the entire family.
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
    fn pair_oracle_recovers_renamed_field_aes_pair() {
        // Build a valid AES-CBC ciphertext of `1f 8b ...` (a fake gzip
        // header) and embed key+IV under unconventional field names
        // (`KeyBytes` / `Vector`) that AES_KEY_RE / AES_IV_RE both miss.
        // The oracle should still recover the pair by trying every
        // (key, iv) and accepting the one whose decrypted output starts
        // with `1f 8b`.
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let plaintext: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut buf = vec![0u8; 32];
        let ct_len = Aes256CbcEnc::new(&key.into(), &iv.into())
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut buf)
            .unwrap()
            .len();
        buf.truncate(ct_len);

        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let text = format!(
            "$cfg.AesCfg.KeyBytes=[Convert]::FromBase64String('{key_b64}'); \
             $cfg.AesCfg.Vector=[Convert]::FromBase64String('{iv_b64}');"
        );

        // The regex path can't find these because the field names aren't `Key`/`IV`.
        assert!(find_aes_key_iv(&text).is_none());

        // The oracle path validates against the ciphertext and recovers them.
        let (recovered_key, recovered_iv) = find_aes_pair_with_oracle(&text, &buf)
            .expect("oracle should recover key/iv via AES-CBC validation");
        assert_eq!(recovered_key, key);
        assert_eq!(recovered_iv, iv);
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
