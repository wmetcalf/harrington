//! cscript / wscript handlers — extract VBScript/JScript payloads.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{
    ends_with_ascii_case_insensitive, filesystem_entry_for_path, normalize_url_like_token,
    split_words, strip_outer_quotes, windows_basename,
};
use crate::traits::Trait;

pub fn h_cscript(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let path = match find_script_arg(&tokens) {
        Some(p) => p,
        None => return,
    };
    extract_script(
        raw,
        "cscript",
        path,
        env,
        Trait::CscriptExec {
            src: path.to_string(),
        },
    );
}

pub fn h_wscript(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let path = match find_script_arg(&tokens) {
        Some(p) => p,
        None => return,
    };
    extract_script(
        raw,
        "wscript",
        path,
        env,
        Trait::WscriptExec {
            src: path.to_string(),
        },
    );
}

fn find_script_arg(tokens: &[String]) -> Option<&str> {
    for t in tokens.iter().skip(1) {
        let unq = strip_outer_quotes(t);
        // Skip flags starting with // (cscript host-options) or / (generic flags)
        if unq.starts_with("//") || unq.starts_with('/') {
            continue;
        }
        return Some(unq.trim_end_matches('.'));
    }
    None
}

fn extract_script(
    raw: &str,
    lolbas_name: &str,
    path: &str,
    env: &mut Environment,
    trait_evt: Trait,
) {
    let mut resolved_remote_source = false;
    if let Some(url) = normalize_url_like_token(path) {
        push_url_argument(raw, &url, env);
        resolved_remote_source = true;
    }
    if let Some(url) = downloaded_source_for_path(env, path) {
        push_url_argument(raw, &url, env);
        resolved_remote_source = true;
    }
    if resolved_remote_source {
        push_lolbas(raw, lolbas_name, env);
    }
    env.traits.push(trait_evt);
    let content = tracked_script_content(path, env);
    if let Some(c) = content {
        if ends_with_ascii_case_insensitive(path, ".vbs")
            || ends_with_ascii_case_insensitive(path, ".vbe")
        {
            push_unique_payload(&mut env.all_extracted_vbs, c.clone());
            push_unique_payload(&mut env.exec_vbs, c);
        } else if (ends_with_ascii_case_insensitive(path, ".js")
            || ends_with_ascii_case_insensitive(path, ".jse"))
            && env.push_extracted_jscript(c.clone())
        {
            push_unique_payload(&mut env.exec_jscript, c);
        }
    }
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_from_entry(filesystem_entry_for_path(env, path)) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(filesystem_entry_for_path(env, stripped));
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return tracked_script_content_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    tracked_script_content_by_basename(path, env)
}

fn tracked_script_content_by_basename(path: &str, env: &Environment) -> Option<Vec<u8>> {
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked_name| tracked_name.eq_ignore_ascii_case(path))
                .then(|| content_from_entry(Some(entry)))
        })
        .flatten()
}

fn push_unique_payload(queue: &mut Vec<Vec<u8>>, content: Vec<u8>) {
    if !queue.iter().any(|existing| existing == &content) {
        queue.push(content);
    }
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

fn downloaded_source_for_path(env: &Environment, path: &str) -> Option<String> {
    let mut key = path.to_ascii_lowercase();
    for _ in 0..8 {
        match filesystem_entry_for_path(env, &key) {
            Some(FsEntry::Download { src }) => return Some(src.clone()),
            Some(FsEntry::Copy { src }) => key = src.to_ascii_lowercase(),
            Some(FsEntry::Directory | FsEntry::Content { .. } | FsEntry::Decoded { .. }) => {
                return None;
            }
            None => return downloaded_source_for_unresolved_path(env, path),
        }
    }
    None
}

fn downloaded_source_for_unresolved_path(env: &Environment, path: &str) -> Option<String> {
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return downloaded_source_for_path(env, stripped);
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return downloaded_source_by_basename(env, name);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    downloaded_source_by_basename(env, path)
}

fn downloaded_source_by_basename(env: &Environment, name: &str) -> Option<String> {
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, _)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked_name| tracked_name.eq_ignore_ascii_case(name))
                .then(|| downloaded_source_for_path(env, tracked_path))
        })
        .flatten()
}

fn push_url_argument(raw: &str, url: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::UrlArgument { cmd, url: got } if cmd == raw && got == url))
    {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url: url.to_string(),
        });
    }
}

fn push_lolbas(raw: &str, name: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name: got, cmd } if got == name && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: name.to_string(),
            cmd: raw.to_string(),
        });
    }
}
