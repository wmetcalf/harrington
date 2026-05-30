//! certutil handler — handles -decode, -decodehex, -urlcache for LOLBAS use.

use crate::env::{DecodeKind, Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;
use base64::Engine;

pub fn h_certutil(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();

    // -urlcache -split -f URL DST
    if lower.iter().any(|t| t == "-urlcache") {
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

    let src = match tokens.get(flag + 1) {
        Some(s) => strip_quotes(s).to_string(),
        None => return,
    };
    let dst = match tokens.get(flag + 2) {
        Some(s) => strip_quotes(s).to_string(),
        None => return,
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
                    hex::decode(s.trim().replace([' ', '\n', '\r', '\t'], "")).ok()
                }
            }
        })();
        if let Some(d) = decoded {
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

fn resolve_self_source(src: &str, env: &Environment) -> Option<Vec<u8>> {
    let is_self = src.eq_ignore_ascii_case("%~f0")
        || src.eq_ignore_ascii_case("%0")
        || env
            .file_path
            .as_ref()
            .map(|p| p.to_string_lossy().eq_ignore_ascii_case(src))
            .unwrap_or(false);
    if is_self {
        env.input_bytes.as_deref().map(|b| b.to_vec())
    } else {
        None
    }
}

fn extract_pem_base64(text: &str) -> Option<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut collecting = false;
    let mut out = String::new();
    for line in text.lines() {
        if !collecting {
            if let Some(idx) = line.find(BEGIN) {
                collecting = true;
                let tail = &line[idx + BEGIN.len()..];
                let tail = match tail.find(END) {
                    Some(end_idx) => &tail[..end_idx],
                    None => tail,
                };
                out.extend(tail.chars().filter(|c| is_base64_char(*c)));
                if line[idx + BEGIN.len()..].contains(END) {
                    return if out.is_empty() { None } else { Some(out) };
                }
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(end_idx) = trimmed.find(END) {
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

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

fn find_first_url(tokens: &[String]) -> Option<String> {
    tokens
        .iter()
        .find_map(|t| crate::deob_scan::normalize_liberal_url_token(strip_quotes(t)))
}

fn find_dst_after_url(tokens: &[String], url: &str) -> Option<String> {
    let mut found_url = false;
    for t in tokens {
        if !found_url {
            if crate::deob_scan::normalize_liberal_url_token(strip_quotes(t)).as_deref()
                == Some(url)
            {
                found_url = true;
            }
            continue;
        }
        if !t.starts_with('-') {
            return Some(strip_quotes(t).to_string());
        }
    }
    None
}
