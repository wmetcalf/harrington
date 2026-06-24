//! cscript / wscript handlers — extract VBScript/JScript payloads.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{ends_with_ascii_case_insensitive, split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_cscript(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let path = match find_script_arg(&tokens) {
        Some(p) => p,
        None => return,
    };
    extract_script(
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

fn extract_script(path: &str, env: &mut Environment, trait_evt: Trait) {
    env.traits.push(trait_evt);
    let key = path.to_ascii_lowercase();
    let content: Option<Vec<u8>> = match env.modified_filesystem.get(&key) {
        Some(FsEntry::Content { content, .. }) => Some(content.clone()),
        Some(FsEntry::Decoded { content, .. }) => Some(content.clone()),
        _ => None,
    };
    if let Some(c) = content {
        if ends_with_ascii_case_insensitive(path, ".vbs")
            || ends_with_ascii_case_insensitive(path, ".vbe")
        {
            env.all_extracted_vbs.push(c.clone());
            env.exec_vbs.push(c);
        } else if ends_with_ascii_case_insensitive(path, ".js")
            || ends_with_ascii_case_insensitive(path, ".jse")
        {
            env.all_extracted_jscript.push(c.clone());
            env.exec_jscript.push(c);
        }
    }
}
