//! cscript / wscript handlers — extract VBScript/JScript payloads.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
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
        &path,
        env,
        Trait::CscriptExec { src: path.clone() },
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
        &path,
        env,
        Trait::WscriptExec { src: path.clone() },
    );
}

fn find_script_arg(tokens: &[String]) -> Option<String> {
    for t in tokens.iter().skip(1) {
        let unq = t.trim_matches('"');
        // Skip flags starting with // (cscript host-options) or / (generic flags)
        if unq.starts_with("//") || unq.starts_with('/') {
            continue;
        }
        return Some(unq.to_string());
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
    if let Some(url) = crate::handlers::util::normalize_url_like_token(path) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
        resolved_remote_source = true;
    }
    if let Some(url) = prior_download_url(path, env) {
        let already = env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::UrlArgument { cmd, url: existing }
                    if cmd == raw && existing == &url
            )
        });
        if !already {
            env.traits.push(Trait::UrlArgument {
                cmd: raw.to_string(),
                url,
            });
        }
        resolved_remote_source = true;
    }
    if resolved_remote_source {
        push_lolbas(env, lolbas_name, raw);
    }
    env.traits.push(trait_evt);
    let content = tracked_script_content(path, env);
    if let Some(c) = content {
        let ext_lower = path.to_ascii_lowercase();
        if ext_lower.ends_with(".vbs") || ext_lower.ends_with(".vbe") {
            push_unique_payload(&mut env.all_extracted_vbs, c.clone());
            push_unique_payload(&mut env.exec_vbs, c);
        } else if ext_lower.ends_with(".js") || ext_lower.ends_with(".jse") {
            push_unique_payload(&mut env.all_extracted_jscript, c.clone());
            push_unique_payload(&mut env.exec_jscript, c);
        }
    }
}

fn push_unique_payload(payloads: &mut Vec<Vec<u8>>, payload: Vec<u8>) {
    if !payloads.iter().any(|existing| existing == &payload) {
        payloads.push(payload);
    }
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    let key = path.to_ascii_lowercase();
    if let Some(content) = content_from_entry(env.modified_filesystem.get(&key)) {
        return Some(content);
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
    for (tracked_path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(tracked_path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(path) {
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

fn prior_download_url(path: &str, env: &Environment) -> Option<String> {
    let key = path.to_ascii_lowercase();
    if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
        return Some(src.clone());
    }
    if let Some(name) = current_dir_basename(path) {
        return prior_download_url_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    prior_download_url_by_basename(path, env)
}

fn prior_download_url_by_basename(path: &str, env: &Environment) -> Option<String> {
    for (tracked_path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(tracked_path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(path) {
            if let FsEntry::Download { src } = entry {
                return Some(src.clone());
            }
        }
    }
    None
}

fn current_dir_basename(path: &str) -> Option<&str> {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .and_then(windows_basename)
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn push_lolbas(env: &mut Environment, name: &str, raw: &str) {
    if !env.traits.iter().any(
        |t| matches!(t, Trait::Lolbas { name: got_name, cmd } if got_name == name && cmd == raw),
    ) {
        env.traits.push(Trait::Lolbas {
            name: name.to_string(),
            cmd: raw.to_string(),
        });
    }
}
