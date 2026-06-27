use super::util::{looks_like_liberal_url, split_words, strip_outer_quotes, windows_basename};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;
use crate::util::find_ascii_case_insensitive_from;

pub fn h_mshta(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::Mshta {
        cmd: raw.to_string(),
    });

    let mut matched_lolbas = queue_inline_script_payload(raw, env);
    for token in split_words(raw).iter().skip(1) {
        if let Some(url) = mshta_token_url(token) {
            env.traits.push(Trait::Download {
                cmd: raw.to_string(),
                src: url,
                dst: None,
            });
            matched_lolbas = true;
            break;
        }
        if let Some(url) = downloaded_source_for_path(env, strip_outer_quotes(token)) {
            env.traits.push(Trait::UrlArgument {
                cmd: raw.to_string(),
                url,
            });
            matched_lolbas = true;
            break;
        }
        if queue_tracked_hta_content(strip_outer_quotes(token), env) {
            matched_lolbas = true;
        }
    }
    if matched_lolbas {
        push_lolbas(raw, env);
    }
}

fn queue_inline_script_payload(raw: &str, env: &mut Environment) -> bool {
    const MAX_INLINE_SCRIPT_BYTES: usize = 256 * 1024;
    let mut queued = false;

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
            queued = true;
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
            queued = true;
        }
    }

    queued
}

fn inline_payload_after<'a>(raw: &'a str, marker: &str) -> Option<&'a str> {
    let start = find_ascii_case_insensitive_from(raw, marker, 0)? + marker.len();
    let body = raw[start..].trim().trim_matches(['"', '\'']);
    (!body.is_empty()).then_some(body)
}

fn downloaded_source_for_path(env: &Environment, path: &str) -> Option<String> {
    let mut key = path.to_ascii_lowercase();
    for _ in 0..8 {
        match env.modified_filesystem.get(&key) {
            Some(FsEntry::Download { src }) => return Some(src.clone()),
            Some(FsEntry::Copy { src }) => key = src.to_ascii_lowercase(),
            Some(FsEntry::Directory | FsEntry::Content { .. } | FsEntry::Decoded { .. }) => {
                return None;
            }
            None => return downloaded_source_for_current_dir_path(env, path),
        }
    }
    None
}

fn downloaded_source_for_current_dir_path(env: &Environment, path: &str) -> Option<String> {
    let name = current_dir_basename(path)?;
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, _)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked_name| tracked_name.eq_ignore_ascii_case(name))
                .then(|| downloaded_source_for_path(env, tracked_path))
        })
        .flatten()
}

fn queue_tracked_hta_content(path: &str, env: &mut Environment) -> bool {
    let Some(content) = tracked_hta_content(path, env) else {
        return false;
    };
    let text = String::from_utf8_lossy(&content);
    let mut queued = false;
    let mut idx = 0usize;
    while let Some(open) = find_ascii_case_insensitive_from(&text, "<script", idx) {
        let Some(tag_end_rel) = text[open..].find('>') else {
            break;
        };
        let tag_end = open + tag_end_rel;
        let body_start = tag_end + 1;
        let Some(close) = find_ascii_case_insensitive_from(&text, "</script>", body_start) else {
            break;
        };
        let body = text[body_start..close].trim();
        if !body.is_empty() {
            let payload = body.as_bytes().to_vec();
            let tag = &text[open..=tag_end];
            if find_ascii_case_insensitive_from(tag, "vbscript", 0).is_some() {
                if !env
                    .all_extracted_vbs
                    .iter()
                    .any(|existing| existing == &payload)
                {
                    env.all_extracted_vbs.push(payload);
                }
            } else if !env
                .all_extracted_jscript
                .iter()
                .any(|existing| existing == &payload)
            {
                env.all_extracted_jscript.push(payload);
            }
            queued = true;
        }
        idx = close + "</script>".len();
    }
    queued
}

fn tracked_hta_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    let key = path.to_ascii_lowercase();
    if let Some(content) = content_from_entry(env.modified_filesystem.get(&key)) {
        return Some(content);
    }
    let name = current_dir_basename(path)?;
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked_name| tracked_name.eq_ignore_ascii_case(name))
                .then(|| content_from_entry(Some(entry)))
        })
        .flatten()
}

fn content_from_entry(entry: Option<&FsEntry>) -> Option<Vec<u8>> {
    match entry {
        Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
            Some(content.clone())
        }
        _ => None,
    }
}

fn current_dir_basename(path: &str) -> Option<&str> {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .and_then(windows_basename)
}

fn mshta_token_url(token: &str) -> Option<String> {
    let token = strip_outer_quotes(token);
    if looks_like_liberal_url(token) {
        return crate::deob_scan::normalize_liberal_url_token(token);
    }
    if let Some(url) = crate::deob_scan::normalize_schemeless_domain_path_token(token) {
        return Some(url);
    }
    for scheme in ["https:", "http:", "ftp:", "file:"] {
        if let Some(idx) = find_ascii_case_insensitive_from(token, scheme, 0) {
            let candidate = crate::deob_scan::trim_url_suffix(&token[idx..]);
            if let Some(url) = crate::deob_scan::normalize_liberal_url_token(candidate) {
                return Some(url);
            }
        }
    }
    None
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
