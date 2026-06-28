//! robocopy handler - tracks simple file copies between directories.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    normalize_wildcard_path, split_words, strip_outer_quotes, wildcard_match,
};
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

    if files.is_empty() {
        copy_default_file_set(&src_dir, &dst_dir, env);
        return;
    }

    for file in files {
        if file_contains_wildcard(&file) {
            copy_wildcard_file_set(&src_dir, &dst_dir, &file, env);
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
            .insert(filesystem_storage_key(&dst), entry);
    }
}

fn parse_robocopy_args(tokens: &[String]) -> Option<(String, String, Vec<String>)> {
    let mut args = Vec::new();
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
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
    if let Some(entry) = filesystem_entry_for_path(env, src) {
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

fn copy_default_file_set(src_dir: &str, dst_dir: &str, env: &mut Environment) {
    let Some(src_prefix) = normalized_dir_prefix(src_dir) else {
        return;
    };
    let copied = env
        .modified_filesystem
        .iter()
        .filter_map(|(tracked_path, entry)| {
            if matches!(entry, FsEntry::Directory) {
                return None;
            }
            let comparable = normalize_wildcard_path(tracked_path);
            let relative = comparable.strip_prefix(&src_prefix)?;
            if relative.is_empty() || relative.contains('\\') {
                return None;
            }
            let filename = windows_basename(tracked_path)?;
            let dst = join_windows_path_preserving_separator(dst_dir, filename);
            Some((filesystem_storage_key(&dst), entry.clone()))
        })
        .collect::<Vec<_>>();
    for (dst, entry) in copied {
        env.modified_filesystem.insert(dst, entry);
    }
}

fn copy_wildcard_file_set(src_dir: &str, dst_dir: &str, pattern: &str, env: &mut Environment) {
    let Some(src_prefix) = normalized_dir_prefix(src_dir) else {
        return;
    };
    let pattern = normalize_wildcard_path(pattern);
    let copied = env
        .modified_filesystem
        .iter()
        .filter_map(|(tracked_path, entry)| {
            if matches!(entry, FsEntry::Directory) {
                return None;
            }
            let comparable = normalize_wildcard_path(tracked_path);
            let relative = comparable.strip_prefix(&src_prefix)?;
            if relative.is_empty() || relative.contains('\\') || !wildcard_match(&pattern, relative)
            {
                return None;
            }
            let filename = windows_basename(tracked_path)?;
            let dst = join_windows_path_preserving_separator(dst_dir, filename);
            Some((filesystem_storage_key(&dst), entry.clone()))
        })
        .collect::<Vec<_>>();
    for (dst, entry) in copied {
        env.modified_filesystem.insert(dst, entry);
    }
}

fn normalized_dir_prefix(dir: &str) -> Option<String> {
    let normalized = normalize_wildcard_path(dir.trim_matches(['"', '\'']));
    let normalized = normalized.trim_end_matches('\\');
    if normalized.is_empty() {
        return None;
    }
    Some(format!("{normalized}\\"))
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
