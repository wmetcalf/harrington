//! robocopy handler — tracks simple file copies between directories.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{join_windows_path_preserving_separator, split_words};
use crate::traits::Trait;

pub fn h_robocopy(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src_dir, dst_dir, files)) = parse_robocopy_args(&tokens) else {
        return;
    };
    env.traits.push(Trait::AdminCommand {
        name: "robocopy".to_string(),
        cmd: raw.to_string(),
    });
    for file in files {
        if file_contains_wildcard(&file) {
            continue;
        }
        let src = join_windows_path_preserving_separator(&src_dir, &file);
        let dst = join_windows_path_preserving_separator(&dst_dir, &file);
        let entry = copied_entry(
            &src,
            &file,
            source_dir_allows_basename_fallback(&src_dir),
            env,
        )
        .unwrap_or(FsEntry::Copy { src });
        env.modified_filesystem
            .insert(dst.to_ascii_lowercase(), entry);
    }
}

fn parse_robocopy_args(tokens: &[String]) -> Option<(String, String, Vec<String>)> {
    let mut args = Vec::new();
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        if lower.starts_with('/') || lower.starts_with('-') {
            i += 1 + robocopy_option_value_count(&lower);
            continue;
        }
        args.push(collapse_slashes(token));
        i += 1;
    }
    let src_dir = args.first()?.clone();
    let dst_dir = args.get(1)?.clone();
    let files = args.into_iter().skip(2).collect::<Vec<_>>();
    if files.is_empty() {
        return None;
    }
    Some((src_dir, dst_dir, files))
}

fn robocopy_option_value_count(option: &str) -> usize {
    if option.contains(':') {
        return 0;
    }
    match option {
        "/log" | "/log+" | "/unilog" | "/unilog+" | "/xd" | "/xf" | "/job" | "/save" => 1,
        _ => 0,
    }
}

fn copied_entry(
    src: &str,
    filename: &str,
    allow_basename_fallback: bool,
    env: &Environment,
) -> Option<FsEntry> {
    let key = src.to_ascii_lowercase();
    if let Some(entry) = env.modified_filesystem.get(&key) {
        return Some(entry.clone());
    }
    if !allow_basename_fallback {
        return None;
    }
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|tracked| tracked.eq_ignore_ascii_case(filename))
                .then(|| entry.clone())
        })
}

fn source_dir_allows_basename_fallback(src_dir: &str) -> bool {
    let trimmed = src_dir
        .trim_matches(['"', '\''])
        .trim_end_matches(['\\', '/']);
    matches!(trimmed, "." | ".\\." | "./.")
}

fn file_contains_wildcard(file: &str) -> bool {
    file.contains(['*', '?'])
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
