//! Scan raw decrypted bytes (typically a .NET assembly) for URL literals.
//!
//! URLs in .NET PE files appear in both UTF-8 (in `.rsrc`, `#Strings`) and
//! UTF-16LE (in `#US` user-string streams). We scan for both encodings.

use once_cell::sync::Lazy;
use regex::bytes::Regex as ByteRegex;

#[allow(clippy::expect_used)]
static URL_UTF8_RE: Lazy<ByteRegex> =
    Lazy::new(|| ByteRegex::new(r"(?i)https?://[\x21-\x7e]{4,300}").expect("url utf8 re"));

const NOISE: &[&str] = &[
    "digicert",
    "sectigo",
    "microsoft.com",
    "adobe.com",
    "w3.org",
    "doubleclick",
    "schemas",
    "googleapis",
    "windows.com",
    "crl.",
    "ocsp.",
    "symantec",
    "verisign",
    "licenses.nuget",
    "aka.ms",
    "openxmlformats",
    "xmlsoap",
    "dublincore",
    "purl.org",
    "go.microsoft",
    "thawte",
    "comodoca",
];

fn is_noise(url: &str) -> bool {
    NOISE
        .iter()
        .any(|needle| ascii_case_insensitive_contains(url, needle))
}

fn ascii_case_insensitive_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn trim_trailing(url: &str) -> &str {
    url.trim_end_matches([
        ',', '.', ';', ':', ')', ']', '}', '"', '\'', '!', '?', '>', '<',
    ])
}

pub fn scan_urls(bytes: &[u8], limit: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // UTF-8 / ASCII pass.
    for m in URL_UTF8_RE.find_iter(bytes) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            let cleaned = trim_trailing(s).to_string();
            if cleaned.len() < 8 {
                continue;
            }
            if is_noise(&cleaned) {
                continue;
            }
            if seen.insert(cleaned.clone()) {
                out.push(cleaned);
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }

    // UTF-16LE pass: convert pairs to bytes, then scan that as a string.
    // We check both alignments because embedded user strings and appended
    // blobs do not always start on an even byte offset.
    if bytes.len() >= 16 {
        let mut decoded = String::with_capacity(bytes.len() / 2);
        for offset in [0usize, 1] {
            decoded.clear();
            let mut i = offset;
            while i + 1 < bytes.len() {
                let lo = bytes[i];
                let hi = bytes[i + 1];
                if hi == 0 && (0x20..=0x7e).contains(&lo) {
                    decoded.push(lo as char);
                } else {
                    decoded.push('\0');
                }
                i += 2;
            }
            // Re-run the UTF-8 url regex on this ASCII-projected text.
            for m in URL_UTF8_RE.find_iter(decoded.as_bytes()) {
                if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
                    let cleaned = trim_trailing(s).to_string();
                    if cleaned.len() < 8 {
                        continue;
                    }
                    if is_noise(&cleaned) {
                        continue;
                    }
                    if seen.insert(cleaned.clone()) {
                        out.push(cleaned);
                        if out.len() >= limit {
                            return out;
                        }
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn finds_utf8_url() {
        let bytes = b"junk\x00\x00http://evil.example.com/payload.dll\x00more junk";
        let urls = scan_urls(bytes, 16);
        assert!(
            urls.iter()
                .any(|u| u == "http://evil.example.com/payload.dll"),
            "got: {:?}",
            urls
        );
    }

    #[test]
    fn finds_utf16le_url() {
        // Encode "https://utf16.example.org/p" as UTF-16LE.
        let s = "https://utf16.example.org/p";
        let mut bytes = Vec::new();
        for c in s.chars() {
            let cp = c as u32;
            bytes.push((cp & 0xff) as u8);
            bytes.push(((cp >> 8) & 0xff) as u8);
        }
        let urls = scan_urls(&bytes, 16);
        assert!(urls.iter().any(|u| u == s), "got: {:?}", urls);
    }

    #[test]
    fn finds_unaligned_utf16le_url() {
        let s = "https://odd-offset.example.org/p";
        let mut bytes = vec![0x41];
        for c in s.chars() {
            let cp = c as u32;
            bytes.push((cp & 0xff) as u8);
            bytes.push(((cp >> 8) & 0xff) as u8);
        }
        let urls = scan_urls(&bytes, 16);
        assert!(urls.iter().any(|u| u == s), "got: {:?}", urls);
    }

    #[test]
    fn filters_known_noise() {
        let bytes = b"https://OCSP.DigiCert.com/crl http://real.evil.example.com/x";
        let urls = scan_urls(bytes, 16);
        assert!(
            !urls
                .iter()
                .any(|u| u.eq_ignore_ascii_case("https://ocsp.digicert.com/crl")),
            "got: {:?}",
            urls
        );
        assert!(urls.iter().any(|u| u.contains("real.evil.example.com")));
    }

    #[test]
    fn dedups_repeated_urls() {
        let bytes = b"http://x.example.com/p http://x.example.com/p http://x.example.com/p";
        let urls = scan_urls(bytes, 16);
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn respects_limit() {
        let mut bytes = Vec::new();
        for i in 0..30 {
            bytes.extend_from_slice(format!("http://e{i}.example.com/p ").as_bytes());
        }
        let urls = scan_urls(&bytes, 5);
        assert!(urls.len() <= 5);
    }
}
