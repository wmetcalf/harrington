//! extrac32 handler — CAB extraction LOLBAS. Tracks self-extraction patterns.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, windows_basename};
use crate::traits::Trait;

pub fn h_extrac32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    // Skip command name + flags like /y /e /a
    let positional: Vec<String> = tokens
        .iter()
        .skip(1)
        .filter(|t| !t.starts_with('/'))
        .map(|t| t.trim_matches(['"', '\'']).to_string())
        .collect();
    if positional.len() < 2 {
        return;
    }
    let src = positional[0].clone();
    let dst = positional[1].clone();

    // Self-reference if the src path matches our synthetic input path.
    let self_reference = extrac32_self_reference(&src, env);
    env.traits.push(Trait::Extrac32 {
        src: src.clone(),
        dst: dst.clone(),
        self_reference,
    });
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), FsEntry::Copy { src });
}

fn extrac32_self_reference(src: &str, env: &Environment) -> bool {
    if src.eq_ignore_ascii_case("%~f0") || src.eq_ignore_ascii_case("%0") {
        return true;
    }
    if src.to_ascii_lowercase().contains("script.bat") {
        return true;
    }
    env.file_path
        .as_ref()
        .map(|path| {
            let path = path.to_string_lossy();
            path.eq_ignore_ascii_case(src)
                || windows_basename(&path)
                    .map(|name| name.eq_ignore_ascii_case(src))
                    .unwrap_or(false)
        })
        .unwrap_or(false)
}
