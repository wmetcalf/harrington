//! extrac32 handler — CAB extraction LOLBAS. Tracks self-extraction patterns.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_extrac32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    // Skip command name + flags like /y /e /a
    let positional: Vec<String> = tokens
        .iter()
        .skip(1)
        .filter(|t| !t.starts_with('/'))
        .map(|t| t.trim_matches('"').to_string())
        .collect();
    if positional.len() < 2 {
        return;
    }
    let src = positional[0].clone();
    let dst = positional[1].clone();

    // Self-reference if the src path matches our synthetic input path.
    let self_reference = src.contains("script.bat");
    env.traits.push(Trait::Extrac32 {
        src: src.clone(),
        dst: dst.clone(),
        self_reference,
    });
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), FsEntry::Copy { src });
}
