//! extrac32 handler — CAB extraction LOLBAS. Tracks self-extraction patterns.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, strip_outer_quotes, windows_basename};
use crate::traits::Trait;

pub fn h_extrac32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src, dst)) = parse_extrac32_paths(&tokens) else {
        return;
    };

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

fn parse_extrac32_paths(tokens: &[String]) -> Option<(String, String)> {
    let mut output_dir: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        if lower == "/l" || lower == "-l" {
            if let Some(value) = tokens.get(i + 1).map(|s| strip_outer_quotes(s)) {
                output_dir = Some(value.to_string());
                i += 2;
                continue;
            }
            return None;
        }
        if let Some(value) = lower
            .strip_prefix("/l:")
            .or_else(|| lower.strip_prefix("-l:"))
        {
            let offset = token.len() - value.len();
            let value = token[offset..].trim();
            if !value.is_empty() {
                output_dir = Some(value.to_string());
            }
            i += 1;
            continue;
        }
        if token.starts_with('/') || token.starts_with('-') {
            i += 1;
            continue;
        }
        positional.push(token.to_string());
        i += 1;
    }
    let src = positional.first()?.clone();
    let dst = positional
        .get(1)
        .cloned()
        .or(output_dir)
        .filter(|s| !s.is_empty())?;
    Some((src, dst))
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
