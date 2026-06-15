//! extrac32 handler — CAB extraction LOLBAS. Tracks self-extraction patterns.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_extrac32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src, dst)) = parse_extrac32_paths(&tokens) else {
        return;
    };

    push_lolbas("extrac32", raw, env);
    // Self-reference if the src path matches our synthetic input path.
    let self_reference = src.contains("script.bat");
    env.traits.push(Trait::Extrac32 {
        src: src.clone(),
        dst: dst.clone(),
        self_reference,
    });
    if is_windows_util_copy(&src, &dst) {
        env.traits.push(Trait::WindowsUtilManip {
            cmd: raw.to_string(),
            src: src.clone(),
            dst: dst.clone(),
        });
    }
    let entry = match downloaded_src_for_candidate(&src, env) {
        Some(src) => FsEntry::Download { src },
        None => FsEntry::Copy { src },
    };
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry);
}

pub fn h_expand(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src, dst)) = parse_expand_paths(&tokens) else {
        return;
    };

    push_lolbas("expand", raw, env);
    let entry = match downloaded_src_for_candidate(&src, env) {
        Some(src) => FsEntry::Download { src },
        None => FsEntry::Copy { src },
    };
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry);
}

fn downloaded_src_for_candidate(candidate: &str, env: &Environment) -> Option<String> {
    let key = candidate.to_ascii_lowercase();
    if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
        return Some(src.clone());
    }
    if let Some(name) = current_dir_basename(candidate) {
        return downloaded_src_by_basename(name, env);
    }
    if candidate.contains(['\\', '/']) {
        return None;
    }
    downloaded_src_by_basename(candidate, env)
}

fn downloaded_src_by_basename(candidate: &str, env: &Environment) -> Option<String> {
    for (path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(candidate) {
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

fn parse_extrac32_paths(tokens: &[String]) -> Option<(String, String)> {
    let mut output_dir: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        if lower == "/l" || lower == "-l" {
            if let Some(value) = tokens.get(i + 1).map(|s| strip_quotes(s)) {
                output_dir = Some(collapse_slashes(value));
                i += 2;
                continue;
            }
            return None;
        }
        if let Some(value) = lower
            .strip_prefix("/l:")
            .or_else(|| lower.strip_prefix("-l:"))
            .or_else(|| lower.strip_prefix("/l="))
            .or_else(|| lower.strip_prefix("-l="))
        {
            let offset = token.len() - value.len();
            let value = token[offset..].trim();
            if !value.is_empty() {
                output_dir = Some(collapse_slashes(strip_quotes(value)));
            }
            i += 1;
            continue;
        }
        if token.starts_with('/') || token.starts_with('-') {
            i += 1;
            continue;
        }
        positional.push(collapse_slashes(token));
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

fn parse_expand_paths(tokens: &[String]) -> Option<(String, String)> {
    let mut positional: Vec<String> = Vec::new();
    let mut selected_member: Option<String> = None;
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        if lower == "-f" || lower == "/f" {
            if let Some(value) = tokens
                .get(i + 1)
                .and_then(|value| expand_member_name(value))
            {
                selected_member = Some(value);
            }
            i += 2;
            continue;
        }
        if let Some(value) = lower
            .strip_prefix("-f:")
            .or_else(|| lower.strip_prefix("/f:"))
            .or_else(|| lower.strip_prefix("-f="))
            .or_else(|| lower.strip_prefix("/f="))
        {
            let offset = token.len() - value.len();
            if let Some(member) = expand_member_name(&token[offset..]) {
                selected_member = Some(member);
            }
            i += 1;
            continue;
        }
        if token.starts_with(['-', '/']) {
            i += 1;
            continue;
        }
        positional.push(collapse_slashes(token));
        i += 1;
    }
    let src = positional.first()?.clone();
    let mut dst = positional.get(1)?.clone();
    if let Some(member) = selected_member {
        if !windows_basename(&dst).is_some_and(|name| name.eq_ignore_ascii_case(&member)) {
            dst = join_windows_path(&dst, &member);
        }
    }
    (!dst.is_empty()).then_some((src, dst))
}

fn expand_member_name(selector: &str) -> Option<String> {
    let selector = strip_quotes(selector).trim();
    if selector.is_empty() || selector.contains(['*', '?']) {
        return None;
    }
    windows_basename(selector).map(str::to_string)
}

fn is_windows_util_copy(src: &str, dst: &str) -> bool {
    let src_lower = src.to_ascii_lowercase();
    let dst_lower = dst.to_ascii_lowercase();
    (src_lower.starts_with("c:\\windows\\system32")
        || src_lower.starts_with("c:\\windows\\syswow64"))
        && !(dst_lower.starts_with("c:\\windows\\system32")
            || dst_lower.starts_with("c:\\windows\\syswow64"))
}

fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = '\0';
    for c in s.chars() {
        if c == '\\' && prev == '\\' {
            continue;
        }
        out.push(c);
        prev = c;
    }
    out
}

fn join_windows_path(prefix: &str, name: &str) -> String {
    if prefix.ends_with(['\\', '/']) {
        collapse_slashes(&format!("{prefix}{name}"))
    } else {
        collapse_slashes(&format!("{prefix}\\{name}"))
    }
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

fn push_lolbas(name: &str, raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(
        |t| matches!(t, Trait::Lolbas { name: existing, cmd } if existing == name && cmd == raw),
    ) {
        env.traits.push(Trait::Lolbas {
            name: name.to_string(),
            cmd: raw.to_string(),
        });
    }
}
