//! extrac32 handler — CAB extraction LOLBAS. Tracks self-extraction patterns.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_extrac32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src, dst)) = parse_extrac32_paths(&tokens) else {
        return;
    };

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

fn parse_extrac32_paths(tokens: &[String]) -> Option<(String, String)> {
    let mut output_dir: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        if lower == "/l" || lower == "-l" {
            if let Some(value) = tokens.get(i + 1).map(|s| strip_quotes(s)) {
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

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}
