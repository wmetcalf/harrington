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
    extract_script(raw, &path, env, Trait::CscriptExec { src: path.clone() });
}

pub fn h_wscript(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let path = match find_script_arg(&tokens) {
        Some(p) => p,
        None => return,
    };
    extract_script(raw, &path, env, Trait::WscriptExec { src: path.clone() });
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

fn extract_script(raw: &str, path: &str, env: &mut Environment, trait_evt: Trait) {
    if let Some(url) = crate::handlers::util::normalize_url_like_token(path) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
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
    }
    env.traits.push(trait_evt);
    let key = path.to_ascii_lowercase();
    let content: Option<Vec<u8>> = match env.modified_filesystem.get(&key) {
        Some(FsEntry::Content { content, .. }) => Some(content.clone()),
        Some(FsEntry::Decoded { content, .. }) => Some(content.clone()),
        _ => None,
    };
    if let Some(c) = content {
        let ext_lower = path.to_ascii_lowercase();
        if ext_lower.ends_with(".vbs") || ext_lower.ends_with(".vbe") {
            env.all_extracted_vbs.push(c.clone());
            env.exec_vbs.push(c);
        } else if ext_lower.ends_with(".js") || ext_lower.ends_with(".jse") {
            env.all_extracted_jscript.push(c.clone());
            env.exec_jscript.push(c);
        }
    }
}

fn prior_download_url(path: &str, env: &Environment) -> Option<String> {
    let key = path.to_ascii_lowercase();
    if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
        return Some(src.clone());
    }
    if path.contains(['\\', '/']) {
        return None;
    }
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

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}
