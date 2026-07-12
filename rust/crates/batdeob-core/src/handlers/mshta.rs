use super::util::{
    filesystem_entry_for_path, looks_like_liberal_url, split_words, strip_outer_quotes,
    windows_basename,
};
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
            env.push_extracted_vbs(payload);
            queued = true;
        }
    }
    if let Some(body) =
        inline_payload_after(raw, "javascript:").or_else(|| inline_payload_after(raw, "jscript:"))
    {
        if body.len() <= MAX_INLINE_SCRIPT_BYTES {
            let payload = body.as_bytes().to_vec();
            env.push_extracted_jscript(payload);
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
        match filesystem_entry_for_path(env, &key) {
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
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return match filesystem_entry_for_path(env, stripped) {
                Some(FsEntry::Download { src }) => Some(src.clone()),
                _ => None,
            };
        }
    }
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
            let lower_body = body.to_ascii_lowercase();
            if find_ascii_case_insensitive_from(tag, "vbscript", 0).is_some()
                || (find_ascii_case_insensitive_from(tag, "jscript", 0).is_none()
                    && find_ascii_case_insensitive_from(tag, "javascript", 0).is_none()
                    && find_ascii_case_insensitive_from(tag, "ecmascript", 0).is_none()
                    && looks_like_vbs_script_body(&lower_body))
            {
                env.push_extracted_vbs(payload);
            } else {
                env.push_extracted_jscript(payload);
            }
            queued = true;
        }
        idx = close + "</script>".len();
    }
    queued
}

fn looks_like_vbs_script_body(lower: &str) -> bool {
    lower.contains("createobject")
        || lower.contains("wscript")
        || lower.contains("xmlhttp")
        || lower.contains("option explicit")
        || lower.contains("private function")
        || lower.contains("\ndim ")
        || lower.starts_with("dim ")
        || lower.contains("\nsub ")
        || lower.starts_with("sub ")
        || lower.contains("\npublic sub ")
        || lower.starts_with("public sub ")
        || lower.contains("\nprivate sub ")
        || lower.starts_with("private sub ")
        || lower.contains("\npublic function ")
        || lower.starts_with("public function ")
        || ((lower.contains("\nfunction ") || lower.starts_with("function "))
            && lower.contains("end function"))
}

fn tracked_hta_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_from_entry(filesystem_entry_for_path(env, path)) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(filesystem_entry_for_path(env, stripped));
        }
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
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
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
