use super::util::{looks_like_liberal_url, split_words, strip_outer_quotes};
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
        match env.modified_filesystem.get(&key)? {
            FsEntry::Download { src } => return Some(src.clone()),
            FsEntry::Copy { src } => key = src.to_ascii_lowercase(),
            FsEntry::Content { .. } | FsEntry::Decoded { .. } => return None,
        }
    }
    None
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
