//! replace.exe handler — tracks source files copied into a destination directory.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{join_windows_path_preserving_separator, split_words};
use crate::traits::Trait;

pub fn h_replace(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src, dst_dir)) = parse_replace_args(&tokens) else {
        return;
    };
    env.traits.push(Trait::AdminCommand {
        name: "replace".to_string(),
        cmd: raw.to_string(),
    });
    let Some(dst) = destination_path(&src, &dst_dir) else {
        return;
    };
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src });
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry);
}

fn parse_replace_args(tokens: &[String]) -> Option<(String, String)> {
    let args = tokens
        .iter()
        .skip(1)
        .map(|token| strip_quotes(token))
        .filter(|token| !token.starts_with(['/', '-']))
        .map(collapse_slashes)
        .collect::<Vec<_>>();
    Some((args.first()?.clone(), args.get(1)?.clone()))
}

fn copied_entry(src: &str, env: &Environment) -> Option<FsEntry> {
    if let Some(entry) = crate::handlers::util::filesystem_entry_for_path(env, src) {
        return Some(entry.clone());
    }
    if let Some(name) = current_dir_basename(src) {
        return copied_entry_by_basename(name, env);
    }
    if src.contains(['\\', '/', ':']) {
        return None;
    }
    copied_entry_by_basename(src, env)
}

fn copied_entry_by_basename(src: &str, env: &Environment) -> Option<FsEntry> {
    let basename = windows_basename(src)?;
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked| tracked.eq_ignore_ascii_case(basename))
                .then(|| entry.clone())
        })
}

fn current_dir_basename(path: &str) -> Option<&str> {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .and_then(windows_basename)
}

fn destination_path(src: &str, dst_dir: &str) -> Option<String> {
    let basename = windows_basename(src)?;
    Some(join_windows_path_preserving_separator(dst_dir, basename))
}

fn windows_basename(path: &str) -> Option<&str> {
    path.trim_matches('"')
        .trim_matches('\'')
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
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

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}
