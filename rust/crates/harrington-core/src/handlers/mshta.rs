use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_mshta(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::Mshta {
        cmd: raw.to_string(),
    });
    queue_inline_script_payload(raw, env);

    let tokens = split_words(raw);
    let mut matched_lolbas = false;
    for token in tokens.iter().skip(1) {
        let url = strip_quotes(token);
        if let Some(src) = crate::deob_scan::normalize_liberal_url_token(url)
            .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(url))
        {
            env.traits.push(Trait::Download {
                cmd: raw.to_string(),
                src,
                dst: None,
            });
            matched_lolbas = true;
            break;
        }
    }
    if let Some(url) = prior_download_url(&tokens, env) {
        push_url_argument(raw, url, env);
        matched_lolbas = true;
    }
    if matched_lolbas {
        push_lolbas(raw, env);
    }
    queue_local_hta_script_blocks(&tokens, env);
}

fn queue_inline_script_payload(raw: &str, env: &mut Environment) {
    const MAX_INLINE_SCRIPT_BYTES: usize = 256 * 1024;

    if let Some(body) = inline_payload_after(raw, "vbscript:") {
        if body.len() <= MAX_INLINE_SCRIPT_BYTES {
            let payload = body.as_bytes().to_vec();
            if !env
                .all_extracted_vbs
                .iter()
                .any(|existing| existing == &payload)
            {
                env.all_extracted_vbs.push(payload);
            }
        }
    }
    if let Some(body) =
        inline_payload_after(raw, "javascript:").or_else(|| inline_payload_after(raw, "jscript:"))
    {
        if body.len() <= MAX_INLINE_SCRIPT_BYTES {
            let payload = body.as_bytes().to_vec();
            if !env
                .all_extracted_jscript
                .iter()
                .any(|existing| existing == &payload)
            {
                env.all_extracted_jscript.push(payload);
            }
        }
    }
}

fn inline_payload_after<'a>(raw: &'a str, marker: &str) -> Option<&'a str> {
    let start = find_ascii_case_insensitive(raw, marker)? + marker.len();
    let body = raw[start..].trim().trim_matches(['"', '\'']);
    (!body.is_empty()).then_some(body)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}

fn prior_download_url(tokens: &[String], env: &Environment) -> Option<String> {
    for token in tokens.iter().skip(1).take(8) {
        let candidate = strip_quotes(token)
            .trim()
            .trim_end_matches(['"', '\'', ')', ']', '}', ';', ',']);
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if !is_hta_target(candidate) {
            continue;
        }
        let key = candidate.to_ascii_lowercase();
        if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
            return Some(src.clone());
        }
        if !candidate.contains(['\\', '/']) {
            for (path, entry) in &env.modified_filesystem {
                let Some(name) = windows_basename(path) else {
                    continue;
                };
                if name.eq_ignore_ascii_case(candidate) {
                    if let FsEntry::Download { src } = entry {
                        return Some(src.clone());
                    }
                }
            }
        }
    }
    None
}

fn queue_local_hta_script_blocks(tokens: &[String], env: &mut Environment) {
    for token in tokens.iter().skip(1).take(8) {
        let candidate = strip_quotes(token)
            .trim()
            .trim_end_matches(['"', '\'', ')', ']', '}', ';', ',']);
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if !is_hta_target(candidate) {
            continue;
        }
        let Some(content) = tracked_hta_content(candidate, env) else {
            continue;
        };
        crate::pre_scan_polyglot_script_block(&content, env);
        break;
    }
}

fn tracked_hta_content(candidate: &str, env: &Environment) -> Option<Vec<u8>> {
    let key = candidate.to_ascii_lowercase();
    if let Some(content) = content_from_entry(env.modified_filesystem.get(&key)) {
        return Some(content);
    }
    if candidate.contains(['\\', '/']) {
        return None;
    }
    for (path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(candidate) {
            if let Some(content) = content_from_entry(Some(entry)) {
                return Some(content);
            }
        }
    }
    None
}

fn content_from_entry(entry: Option<&FsEntry>) -> Option<Vec<u8>> {
    match entry {
        Some(FsEntry::Content { content, .. }) => Some(content.clone()),
        Some(FsEntry::Decoded { content, .. }) => Some(content.clone()),
        _ => None,
    }
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn is_hta_target(candidate: &str) -> bool {
    let lower = candidate.to_ascii_lowercase();
    [".hta", ".htm", ".html"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn push_url_argument(raw: &str, url: String, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument { cmd, url: existing } if cmd == raw && existing == &url
        )
    }) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "mshta" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "mshta".to_string(),
            cmd: raw.to_string(),
        });
    }
}
