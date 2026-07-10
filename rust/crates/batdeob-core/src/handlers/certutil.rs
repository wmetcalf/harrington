//! certutil handler — handles -decode, -decodehex, -urlcache for LOLBAS use.

use crate::env::{DecodeKind, Environment, FsEntry};
use crate::handlers::util::{
    filesystem_entry_for_path, filesystem_storage_key, split_words, strip_outer_quotes,
    windows_basename,
};
use crate::traits::Trait;
use base64::Engine;

pub fn h_certutil(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    push_lolbas(raw, env);

    // -urlcache -split -f URL DST / -verifyctl -f URL DST
    if tokens
        .iter()
        .any(|t| certutil_flag_eq(t, "urlcache") || certutil_flag_eq(t, "verifyctl"))
    {
        if let Some(url) = find_first_url(&tokens) {
            let dst = find_dst_after_url(&tokens, &url).or_else(|| url_basename(&url));
            env.traits.push(Trait::CertutilDownload {
                url: url.clone(),
                dst: dst.clone().unwrap_or_default(),
            });
            if let Some(d) = dst {
                env.modified_filesystem
                    .insert(filesystem_storage_key(&d), FsEntry::Download { src: url });
            }
        }
        return;
    }

    // -decode SRC DST  /  -decodehex SRC DST
    let (method, flag) = if let Some(p) = tokens.iter().position(|t| certutil_flag_eq(t, "decode"))
    {
        (DecodeKind::Base64, p)
    } else if let Some(p) = tokens.iter().position(|t| certutil_flag_eq(t, "decodehex")) {
        (DecodeKind::Hex, p)
    } else {
        return;
    };

    let Some((src, dst)) = certutil_decode_paths_after_flag(&tokens, flag + 1) else {
        return;
    };

    let src_content = resolve_tracked_source(&src, env).or_else(|| resolve_self_source(&src, env));

    let src_resolved = src_content.is_some();
    env.traits.push(Trait::CertutilDecode {
        src: src.clone(),
        dst: dst.clone(),
        src_resolved,
    });

    if let Some(bytes) = src_content {
        let decoded: Option<Vec<u8>> = (|| -> Option<Vec<u8>> {
            match method {
                DecodeKind::Base64 => {
                    // Real `certutil -decode` accepts PEM-style base64 with
                    // embedded newlines (the `(echo a\necho b) > f` idiom),
                    // so strip all ASCII whitespace before decoding.
                    let s = std::str::from_utf8(&bytes).ok()?;
                    let compact = if let Some(pem) = extract_pem_base64(s) {
                        pem
                    } else {
                        s.bytes()
                            .filter(|b| !b.is_ascii_whitespace())
                            .map(char::from)
                            .collect()
                    };
                    base64::engine::general_purpose::STANDARD
                        .decode(compact.as_str())
                        .ok()
                }
                DecodeKind::Hex => {
                    let s = std::str::from_utf8(&bytes).ok()?;
                    decode_certutil_hex_text(s)
                }
            }
        })();
        if let Some(d) = decoded {
            publish_printable_decoded_payload(&dst, &d, env);
            env.modified_filesystem.insert(
                filesystem_storage_key(&dst),
                FsEntry::Decoded {
                    content: d,
                    src,
                    method,
                },
            );
        }
    }
}

fn publish_printable_decoded_payload(dst: &str, bytes: &[u8], env: &mut Environment) {
    if !is_printable_text_payload(bytes) {
        return;
    }
    let lower_dst = dst.to_ascii_lowercase();
    let text = String::from_utf8_lossy(bytes);
    let lower_text = text.to_ascii_lowercase();
    if lower_dst.ends_with(".bat") || lower_dst.ends_with(".cmd") {
        return;
    }
    if lower_dst.ends_with(".ps1") || looks_like_powershell_text(&lower_text) {
        env.push_extracted_ps1(bytes.to_vec());
    } else if lower_dst.ends_with(".vbs")
        || lower_dst.ends_with(".vbe")
        || looks_like_vbs_text(&lower_text)
    {
        env.push_extracted_vbs(bytes.to_vec());
    } else if lower_dst.ends_with(".js")
        || lower_dst.ends_with(".jse")
        || lower_dst.ends_with(".hta")
        || looks_like_js_text(&lower_text)
    {
        env.push_extracted_jscript(bytes.to_vec());
    }
}

fn is_printable_text_payload(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return false;
    }
    std::str::from_utf8(bytes).is_ok()
        && bytes
            .iter()
            .all(|b| matches!(*b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
}

fn looks_like_powershell_text(lower: &str) -> bool {
    lower.contains("powershell")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-expression")
        || lower.contains("new-object net.webclient")
        || lower.contains("frombase64string")
}

fn looks_like_vbs_text(lower: &str) -> bool {
    lower.contains("createobject")
        || lower.contains("wscript")
        || lower.contains("xmlhttp")
        || lower.contains("option explicit")
        || lower.contains("\ndim ")
        || lower.starts_with("dim ")
}

fn looks_like_js_text(lower: &str) -> bool {
    lower.contains("activexobject")
        || lower.contains("getobject(")
        || lower.contains("function ")
        || lower.contains("var ")
        || lower.contains("eval(")
        || lower.contains("document.")
        || lower.contains("window.")
}

pub(crate) fn decode_certutil_hex_text(text: &str) -> Option<Vec<u8>> {
    let mut dump_bytes = Vec::new();
    let mut saw_offset_dump = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 2
            && parse_hex_offset(tokens[0]).is_some_and(|offset| offset == dump_bytes.len())
        {
            let before_len = dump_bytes.len();
            for token in &tokens[1..] {
                let Some(byte) = parse_hex_byte_token(token) else {
                    break;
                };
                dump_bytes.push(byte);
            }
            if dump_bytes.len() == before_len {
                return None;
            }
            saw_offset_dump = true;
            continue;
        }
        if saw_offset_dump {
            return None;
        }
    }

    if saw_offset_dump {
        return Some(dump_bytes);
    }

    hex::decode(text.trim().replace([' ', '\n', '\r', '\t'], "")).ok()
}

fn parse_hex_offset(token: &str) -> Option<usize> {
    if !(4..=8).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(token, 16).ok()
}

fn parse_hex_byte_token(token: &str) -> Option<u8> {
    if token.len() != 2 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(token, 16).ok()
}

fn resolve_self_source(src: &str, env: &Environment) -> Option<Vec<u8>> {
    let is_self = src.eq_ignore_ascii_case("%~f0")
        || src.eq_ignore_ascii_case("%0")
        || env
            .file_path
            .as_ref()
            .map(|p| {
                let path = p.to_string_lossy();
                path.eq_ignore_ascii_case(src)
                    || windows_basename(&path)
                        .map(|name| name.eq_ignore_ascii_case(src))
                        .unwrap_or(false)
            })
            .unwrap_or(false);
    if is_self {
        env.input_bytes.as_deref().map(|b| b.to_vec())
    } else {
        None
    }
}

fn resolve_tracked_source(src: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_from_entry(filesystem_entry_for_path(env, src)) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(src) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(filesystem_entry_for_path(env, stripped));
        }
    }
    if let Some(name) = current_dir_basename(src) {
        return resolve_tracked_source_by_basename(name, env);
    }
    if src.contains(['\\', '/']) {
        return None;
    }
    resolve_tracked_source_by_basename(src, env)
}

fn resolve_tracked_source_by_basename(src: &str, env: &Environment) -> Option<Vec<u8>> {
    for (path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(src) {
            if let Some(content) = content_from_entry(Some(entry)) {
                return Some(content);
            }
        }
    }
    None
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn content_from_entry(entry: Option<&FsEntry>) -> Option<Vec<u8>> {
    match entry {
        Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
            Some(content.clone())
        }
        _ => None,
    }
}

pub(crate) fn extract_pem_base64(text: &str) -> Option<String> {
    const BOUNDARIES: &[(&str, &str)] = &[
        ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"),
        (
            "-----BEGIN CERTIFICATE REQUEST-----",
            "-----END CERTIFICATE REQUEST-----",
        ),
        (
            "-----BEGIN NEW CERTIFICATE REQUEST-----",
            "-----END NEW CERTIFICATE REQUEST-----",
        ),
        ("-----BEGIN X509 CRL-----", "-----END X509 CRL-----"),
    ];
    BOUNDARIES
        .iter()
        .find_map(|(begin, end)| extract_pem_base64_between(text, begin, end))
}

fn extract_pem_base64_between(text: &str, begin: &str, end: &str) -> Option<String> {
    let mut collecting = false;
    let mut out = String::new();
    for line in text.lines() {
        if !collecting {
            if let Some(idx) = line.find(begin) {
                collecting = true;
                let tail = &line[idx + begin.len()..];
                let tail = match tail.find(end) {
                    Some(end_idx) => &tail[..end_idx],
                    None => tail,
                };
                out.extend(tail.bytes().filter(|b| is_base64_byte(*b)).map(char::from));
                if line[idx + begin.len()..].contains(end) {
                    return if out.is_empty() { None } else { Some(out) };
                }
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(end_idx) = trimmed.find(end) {
            out.extend(
                trimmed[..end_idx]
                    .bytes()
                    .filter(|b| is_base64_byte(*b))
                    .map(char::from),
            );
            break;
        }
        if trimmed
            .bytes()
            .all(|b| b.is_ascii_whitespace() || is_base64_byte(b))
        {
            out.extend(
                trimmed
                    .bytes()
                    .filter(|b| is_base64_byte(*b))
                    .map(char::from),
            );
            continue;
        }
        break;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn certutil_decode_paths_after_flag(tokens: &[String], start: usize) -> Option<(String, String)> {
    let mut positional = tokens
        .iter()
        .skip(start)
        .filter(|token| !is_certutil_option(strip_outer_quotes(token)));
    let src = strip_outer_quotes(positional.next()?).to_string();
    let dst = strip_outer_quotes(positional.next()?).to_string();
    Some((src, dst))
}

fn certutil_flag_eq(token: &str, flag: &str) -> bool {
    token
        .strip_prefix(['-', '/'])
        .is_some_and(|value| value.eq_ignore_ascii_case(flag))
}

fn is_certutil_option(token: &str) -> bool {
    token.starts_with('-') || token.starts_with('/')
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn find_first_url(tokens: &[String]) -> Option<String> {
    tokens.iter().find_map(|t| normalize_certutil_url(t))
}

fn find_dst_after_url(tokens: &[String], url: &str) -> Option<String> {
    let mut found_url = false;
    for t in tokens {
        if !found_url {
            if normalize_certutil_url(t).as_deref() == Some(url) {
                found_url = true;
            }
            continue;
        }
        if !is_certutil_option(strip_outer_quotes(t)) {
            return Some(strip_outer_quotes(t).to_string());
        }
    }
    None
}

fn normalize_certutil_url(token: &str) -> Option<String> {
    let token = strip_outer_quotes(token);
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}

fn url_basename(url: &str) -> Option<String> {
    let path_part = url.split(['?', '#']).next()?;
    let last = path_part.rsplit('/').next()?;
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "certutil" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "certutil".to_string(),
            cmd: raw.to_string(),
        });
    }
}
