//! certutil handler — handles -decode, -decodehex, -urlcache for LOLBAS use.

use crate::env::{DecodeKind, Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;
use base64::Engine;

pub fn h_certutil(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();

    // -urlcache -split -f URL DST
    if lower.iter().any(|t| t == "-urlcache" || t == "/urlcache") {
        if let Some(url) = find_first_url(&tokens) {
            let dst = find_dst_after_url(&tokens, &url);
            env.traits.push(Trait::CertutilDownload {
                url: url.clone(),
                dst: dst.clone().unwrap_or_default(),
            });
            if let Some(d) = dst {
                env.modified_filesystem
                    .insert(d.to_ascii_lowercase(), FsEntry::Download { src: url });
            }
        }
        return;
    }

    // -decode SRC DST  /  -decodehex SRC DST
    let (method, flag) = if let Some(p) = lower.iter().position(|t| t == "-decode") {
        (DecodeKind::Base64, p)
    } else if let Some(p) = lower.iter().position(|t| t == "-decodehex") {
        (DecodeKind::Hex, p)
    } else {
        return;
    };

    let Some((src, dst)) = certutil_decode_paths_after_flag(&tokens, flag + 1) else {
        return;
    };

    let src_key = src.to_ascii_lowercase();
    let src_content = env
        .modified_filesystem
        .get(&src_key)
        .and_then(|e| match e {
            FsEntry::Content { content, .. } => Some(content.clone()),
            FsEntry::Decoded { content, .. } => Some(content.clone()),
            _ => None,
        })
        .or_else(|| resolve_self_source(&src, env));

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
                        s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
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
            if decoded_looks_like_pe(&d) {
                let label = format!("certutil-decode:{dst}");
                if !env
                    .recovered_pe
                    .iter()
                    .any(|(existing, blob)| existing == &label && blob == &d)
                {
                    env.recovered_pe.push((label, d.clone()));
                }
            }
            env.modified_filesystem.insert(
                dst.to_ascii_lowercase(),
                FsEntry::Decoded {
                    content: d,
                    src,
                    method,
                },
            );
        }
    }
}

fn decode_certutil_hex_text(text: &str) -> Option<Vec<u8>> {
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

fn decoded_looks_like_pe(content: &[u8]) -> bool {
    if content.len() < 0x40 || content.get(0..2) != Some(b"MZ") {
        return false;
    }
    let Some(pe_off_bytes) = content.get(0x3c..0x40) else {
        return false;
    };
    let pe_off = u32::from_le_bytes([
        pe_off_bytes[0],
        pe_off_bytes[1],
        pe_off_bytes[2],
        pe_off_bytes[3],
    ]) as usize;
    pe_off
        .checked_add(4)
        .and_then(|end| content.get(pe_off..end))
        == Some(b"PE\0\0")
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

fn extract_pem_base64(text: &str) -> Option<String> {
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
                out.extend(tail.chars().filter(|c| is_base64_char(*c)));
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
            out.extend(trimmed[..end_idx].chars().filter(|c| is_base64_char(*c)));
            break;
        }
        if trimmed
            .chars()
            .all(|c| c.is_ascii_whitespace() || is_base64_char(c))
        {
            out.extend(trimmed.chars().filter(|c| is_base64_char(*c)));
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

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}

fn certutil_decode_paths_after_flag(tokens: &[String], start: usize) -> Option<(String, String)> {
    let mut positional = tokens.iter().skip(start).filter(|token| {
        let token = strip_quotes(token);
        !token.starts_with('-') && !token.starts_with('/')
    });
    let src = strip_quotes(positional.next()?).to_string();
    let dst = strip_quotes(positional.next()?).to_string();
    Some((src, dst))
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
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
        let t = strip_quotes(t);
        if !t.starts_with('-') && !t.starts_with('/') {
            return Some(t.to_string());
        }
    }
    None
}

fn normalize_certutil_url(token: &str) -> Option<String> {
    let token = strip_quotes(token);
    crate::deob_scan::normalize_liberal_url_token(token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
}
