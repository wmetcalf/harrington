//! replace.exe handler - tracks source files copied into a destination directory.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    normalize_filesystem_storage_path, normalize_wildcard_path, split_words, strip_outer_quotes,
    wildcard_match,
};
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

    if src.contains(['*', '?']) {
        copy_wildcard_sources(&src, &dst_dir, env);
        return;
    }

    let Some(dst) = destination_path(&src, &dst_dir) else {
        return;
    };
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src });
    env.modified_filesystem
        .insert(filesystem_storage_key(&dst), entry);
}

fn parse_replace_args(tokens: &[String]) -> Option<(String, String)> {
    let args = tokens
        .iter()
        .skip(1)
        .map(|token| strip_outer_quotes(token))
        .filter(|token| !token.starts_with(['/', '-']))
        .map(collapse_slashes)
        .collect::<Vec<_>>();
    Some((args.first()?.clone(), args.get(1)?.clone()))
}

fn copied_entry(src: &str, env: &Environment) -> Option<FsEntry> {
    if let Some(entry) = filesystem_entry_for_path(env, src) {
        return Some(entry.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(src) {
        if stripped.contains(['\\', '/']) {
            return filesystem_entry_for_path(env, stripped).cloned();
        }
    }
    if let Some(name) = current_dir_basename(src) {
        return copied_entry_by_basename(name, env);
    }
    if src.contains(['\\', '/', ':']) {
        return None;
    }
    copied_entry_by_basename(src, env)
}

fn copy_wildcard_sources(src_pattern: &str, dst_dir: &str, env: &mut Environment) {
    let copied = env
        .modified_filesystem
        .iter()
        .filter_map(|(tracked_path, entry)| {
            if matches!(entry, FsEntry::Directory)
                || !wildcard_source_matches(src_pattern, tracked_path)
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

fn wildcard_source_matches(pattern: &str, tracked_path: &str) -> bool {
    let normalized_pattern = normalize_wildcard_path(&normalize_filesystem_storage_path(pattern));
    let normalized_path = normalize_wildcard_path(tracked_path);
    if normalized_pattern.contains('\\') {
        let Some((pattern_dir, pattern_name)) = normalized_pattern.rsplit_once('\\') else {
            return false;
        };
        let Some((tracked_dir, tracked_name)) = normalized_path.rsplit_once('\\') else {
            return false;
        };
        return pattern_dir == tracked_dir && wildcard_match(pattern_name, tracked_name);
    }
    windows_basename(tracked_path).is_some_and(|name| {
        !tracked_path.contains(['\\', '/', ':'])
            && wildcard_match(&normalized_pattern, &normalize_wildcard_path(name))
    })
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
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
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
