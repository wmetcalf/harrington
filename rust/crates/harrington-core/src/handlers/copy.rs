use super::util::{join_windows_path_preserving_separator, normalize_wildcard_path, split_words};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_copy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words(raw);
    let general_opts = ["/v", "/n", "/l", "/y", "/-y", "/z"];
    let file_opts = ["/a", "/b", "/d"];
    let mut args: Vec<String> = Vec::new();
    for t in tokens.iter().skip(1) {
        let lt = t.to_ascii_lowercase();
        if general_opts.contains(&lt.as_str()) || file_opts.contains(&lt.as_str()) {
            continue;
        }
        push_copy_arg_parts(&mut args, t);
    }

    // Multi-source form: A + B + C dst  (args contain "+" separators)
    if args.iter().any(|a| a == "+") {
        let non_plus: Vec<String> = args.iter().filter(|a| a.as_str() != "+").cloned().collect();
        if non_plus.len() < 2 {
            return;
        }
        let (sources, dst_slice) = non_plus.split_at(non_plus.len() - 1);
        let dst = collapse_slashes(&dst_slice[0]);

        // Try to concatenate content from modified_filesystem
        let mut combined: Vec<u8> = Vec::new();
        let mut all_resolved = true;
        for src in sources {
            match copied_entry(src, env) {
                Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
                    combined.extend_from_slice(&content);
                }
                _ => {
                    all_resolved = false;
                }
            }
        }
        if all_resolved && !combined.is_empty() {
            env.modified_filesystem.insert(
                dst.to_ascii_lowercase(),
                FsEntry::Content {
                    content: combined,
                    append: false,
                },
            );
        } else {
            env.modified_filesystem.insert(
                dst.to_ascii_lowercase(),
                FsEntry::Copy {
                    src: sources.join("+"),
                },
            );
        }
        env.traits.push(Trait::CommandGrouping {
            cmd: raw.to_string(),
            normalized: format!("copy /b {} \u{2192} {}", sources.join("+"), dst),
        });
        return;
    }

    // Single-source form (existing behavior)
    if args.len() != 2 {
        return;
    }
    let src = collapse_slashes(&args[0]);
    let dst = collapse_slashes(&args[1]);
    if is_windows_util_copy(&src, &dst) {
        env.traits.push(Trait::WindowsUtilManip {
            cmd: raw.to_string(),
            src: src.clone(),
            dst: dst.clone(),
        });
    }
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src: src.clone() });
    insert_copied_entry(env, &src, &dst, entry);
}

pub fn h_xcopy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words(raw);
    let mut args: Vec<String> = Vec::new();
    let mut assume_directory_dst = false;
    for t in tokens.iter().skip(1) {
        let stripped = strip_quotes(t);
        if stripped.eq_ignore_ascii_case("/i") || stripped.eq_ignore_ascii_case("-i") {
            assume_directory_dst = true;
            continue;
        }
        if stripped.starts_with('/') || stripped.starts_with('-') {
            continue;
        }
        args.push(stripped.to_string());
    }
    if args.len() < 2 {
        return;
    }
    let src = collapse_slashes(&args[args.len() - 2]);
    let dst = collapse_slashes(&args[args.len() - 1]);
    if is_windows_util_copy(&src, &dst) {
        env.traits.push(Trait::WindowsUtilManip {
            cmd: raw.to_string(),
            src: src.clone(),
            dst: dst.clone(),
        });
    }
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src: src.clone() });
    insert_copied_entry(env, &src, &dst, entry);
    if assume_directory_dst && xcopy_dst_looks_like_directory(&dst) {
        let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src: src.clone() });
        insert_copied_directory_entry(env, &src, &dst, entry);
    }
}

pub fn h_move(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::AdminCommand {
        name: "move".to_string(),
        cmd: raw.to_string(),
    });
    track_rename_like(raw, env, &["/y", "/-y"], true);
}

pub fn h_ren(raw: &str, env: &mut Environment) {
    track_rename_like(raw, env, &[], false);
}

fn track_rename_like(
    raw: &str,
    env: &mut Environment,
    options: &[&str],
    allow_directory_dst: bool,
) {
    let tokens: Vec<String> = split_words(raw);
    let mut args: Vec<String> = Vec::new();
    for t in tokens.iter().skip(1) {
        let stripped = strip_quotes(t);
        let lower = stripped.to_ascii_lowercase();
        if options.contains(&lower.as_str()) {
            continue;
        }
        args.push(stripped.to_string());
    }
    if args.len() != 2 {
        return;
    }
    let src = collapse_slashes(&args[0]);
    let dst = collapse_slashes(&args[1]);
    if is_windows_util_copy(&src, &dst) || is_windows_util_rename(&src, &dst) {
        env.traits.push(Trait::WindowsUtilManip {
            cmd: raw.to_string(),
            src: src.clone(),
            dst: dst.clone(),
        });
    }
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src: src.clone() });
    if allow_directory_dst {
        insert_copied_entry(env, &src, &dst, entry);
    } else {
        env.modified_filesystem
            .insert(dst.to_ascii_lowercase(), entry.clone());
        if let Some(joined) = rename_destination_in_source_directory(&src, &dst) {
            env.modified_filesystem
                .insert(joined.to_ascii_lowercase(), entry);
        }
    }
    remove_renamed_source(env, &src, &dst);
}

fn copied_entry(src: &str, env: &Environment) -> Option<FsEntry> {
    let key = src.to_ascii_lowercase();
    if let Some(entry) = env.modified_filesystem.get(&key) {
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
    let basename = windows_basename(src)?.to_ascii_lowercase();
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            if windows_basename(tracked_path)
                .is_some_and(|tracked| tracked.eq_ignore_ascii_case(&basename))
            {
                Some(entry.clone())
            } else {
                None
            }
        })
}

fn current_dir_basename(path: &str) -> Option<&str> {
    path.strip_prefix(r".\")
        .or_else(|| path.strip_prefix("./"))
        .and_then(windows_basename)
}

fn remove_renamed_source(env: &mut Environment, src: &str, dst: &str) {
    if src.eq_ignore_ascii_case(dst) {
        return;
    }
    env.modified_filesystem.remove(&src.to_ascii_lowercase());
    if let Some(name) = current_dir_basename(src) {
        env.modified_filesystem.remove(&name.to_ascii_lowercase());
    }
}

fn insert_copied_entry(env: &mut Environment, src: &str, dst: &str, entry: FsEntry) {
    let tracked_dir_dst = copy_tracked_directory_destination_path(env, src, dst);
    if tracked_dir_dst.is_none() {
        env.modified_filesystem
            .insert(dst.to_ascii_lowercase(), entry.clone());
    }
    if let Some(joined) = copy_directory_destination_path(src, dst) {
        env.modified_filesystem
            .insert(joined.to_ascii_lowercase(), entry);
    } else if let Some(joined) = tracked_dir_dst {
        env.modified_filesystem
            .insert(joined.to_ascii_lowercase(), entry);
    }
}

fn insert_copied_directory_entry(env: &mut Environment, src: &str, dst_dir: &str, entry: FsEntry) {
    if let Some(joined) = copy_directory_destination_path(src, &directory_destination(dst_dir)) {
        env.modified_filesystem
            .insert(joined.to_ascii_lowercase(), entry);
    }
}

fn directory_destination(dst_dir: &str) -> String {
    let separator = if dst_dir.contains('/') && !dst_dir.contains('\\') {
        '/'
    } else {
        '\\'
    };
    format!("{dst_dir}{separator}")
}

fn copy_directory_destination_path(src: &str, dst: &str) -> Option<String> {
    if !dst.ends_with(['\\', '/']) {
        return None;
    }
    let basename = windows_basename(src)?;
    let mut out = dst.to_string();
    out.push_str(basename);
    Some(collapse_slashes(&out))
}

fn copy_tracked_directory_destination_path(
    env: &Environment,
    src: &str,
    dst: &str,
) -> Option<String> {
    let key = normalize_wildcard_path(dst.trim_end_matches(['\\', '/']));
    if !env.modified_filesystem.iter().any(|(path, entry)| {
        matches!(entry, FsEntry::Directory) && normalize_wildcard_path(path) == key
    }) {
        return None;
    }
    let basename = windows_basename(src)?;
    let separator = if dst.contains('/') && !dst.contains('\\') {
        '/'
    } else {
        '\\'
    };
    Some(collapse_slashes(&format!("{dst}{separator}{basename}")))
}

fn rename_destination_in_source_directory(src: &str, dst: &str) -> Option<String> {
    if dst.contains(['\\', '/', ':']) {
        return None;
    }
    let (dir, _) = src.rsplit_once(['\\', '/'])?;
    if dir.is_empty() || dst.is_empty() {
        return None;
    }
    Some(join_windows_path_preserving_separator(dir, dst))
}

fn windows_basename(path: &str) -> Option<&str> {
    path.trim_matches('"')
        .trim_matches('\'')
        .rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn xcopy_dst_looks_like_directory(dst: &str) -> bool {
    if dst.ends_with(['\\', '/']) {
        return true;
    }
    windows_basename(dst).is_some_and(|name| !name.contains('.'))
}

fn is_windows_util_copy(src: &str, dst: &str) -> bool {
    let src_lower = src.to_ascii_lowercase();
    let dst_lower = dst.to_ascii_lowercase();
    is_windows_system_path(&src_lower)
        && !(dst_lower.starts_with("c:\\windows\\system32")
            || dst_lower.starts_with("c:\\windows\\syswow64"))
}

fn is_windows_util_rename(src: &str, dst: &str) -> bool {
    let src_lower = src.to_ascii_lowercase();
    let dst_lower = dst.to_ascii_lowercase();
    is_windows_system_path(&src_lower)
        && windows_basename(&src_lower)
            .zip(windows_basename(&dst_lower))
            .is_some_and(|(src_name, dst_name)| src_name != dst_name)
}

fn is_windows_system_path(path: &str) -> bool {
    path.starts_with("c:\\windows\\system32") || path.starts_with("c:\\windows\\syswow64")
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}

fn push_copy_arg_parts(args: &mut Vec<String>, token: &str) {
    let mut current = String::new();
    let mut parts = Vec::new();
    let mut in_dq = false;
    let mut in_sq = false;
    let mut saw_separator = false;

    for ch in token.chars() {
        if ch == '"' && !in_sq {
            in_dq = !in_dq;
            current.push(ch);
            continue;
        }
        if ch == '\'' && !in_dq {
            in_sq = !in_sq;
            current.push(ch);
            continue;
        }
        if ch == '+' && !in_dq && !in_sq {
            if !current.is_empty() {
                parts.push(strip_quotes(&current).to_string());
                current.clear();
            }
            parts.push("+".to_string());
            saw_separator = true;
            continue;
        }
        current.push(ch);
    }

    if !current.is_empty() {
        parts.push(strip_quotes(&current).to_string());
    }

    if saw_separator {
        args.extend(parts);
    } else {
        args.push(strip_quotes(token).to_string());
    }
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
