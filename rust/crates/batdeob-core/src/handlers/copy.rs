use super::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    normalize_wildcard_path, split_words, starts_with_ascii_case_insensitive, strip_outer_quotes,
};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_copy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words(raw);
    let general_opts = ["/v", "/n", "/l", "/y", "/-y", "/z"];
    let file_opts = ["/a", "/b", "/d"];
    let mut args: Vec<String> = Vec::new();
    for t in tokens.iter().skip(1) {
        if general_opts.iter().any(|opt| t.eq_ignore_ascii_case(opt))
            || file_opts.iter().any(|opt| t.eq_ignore_ascii_case(opt))
        {
            continue;
        }
        push_copy_arg(&mut args, strip_outer_quotes(t));
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
            let key = src.to_ascii_lowercase();
            match env.modified_filesystem.get(&key) {
                Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
                    combined.extend_from_slice(content);
                }
                _ => {
                    all_resolved = false;
                }
            }
        }
        if all_resolved && !combined.is_empty() {
            insert_filesystem_entry(
                env,
                &dst,
                FsEntry::Content {
                    content: combined,
                    append: false,
                },
            );
        } else {
            insert_filesystem_entry(
                env,
                &dst,
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

fn push_copy_arg(args: &mut Vec<String>, token: &str) {
    let mut parts = token.split('+').peekable();
    while let Some(part) = parts.next() {
        if !part.is_empty() {
            args.push(part.to_string());
        }
        if parts.peek().is_some() {
            args.push("+".to_string());
        }
    }
}

pub fn h_xcopy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words(raw);
    let mut args: Vec<String> = Vec::new();
    let mut assume_directory_dst = false;
    for t in tokens.iter().skip(1) {
        let stripped = strip_outer_quotes(t);
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
        let stripped = strip_outer_quotes(t);
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
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src: src.clone() });
    if allow_directory_dst {
        insert_copied_entry(env, &src, &dst, entry);
    } else {
        insert_filesystem_entry(env, &dst, entry.clone());
        if let Some(joined) = rename_destination_in_source_directory(&src, &dst) {
            insert_filesystem_entry(env, &joined, entry);
        }
    }
    remove_renamed_source(env, &src, &dst);
}

fn is_windows_util_copy(src: &str, dst: &str) -> bool {
    let src_system = starts_with_ascii_case_insensitive(src, "c:\\windows\\system32")
        || starts_with_ascii_case_insensitive(src, "c:\\windows\\syswow64");
    let dst_system = starts_with_ascii_case_insensitive(dst, "c:\\windows\\system32")
        || starts_with_ascii_case_insensitive(dst, "c:\\windows\\syswow64");
    src_system && !dst_system
}

fn copied_entry(src: &str, env: &Environment) -> Option<FsEntry> {
    if let Some(entry) = filesystem_entry_for_path(env, src) {
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
    env.modified_filesystem.iter().find_map(|(path, entry)| {
        windows_basename(path)
            .filter(|name| name.eq_ignore_ascii_case(basename))
            .map(|_| entry.clone())
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
    let key = normalize_wildcard_path(src);
    env.modified_filesystem
        .retain(|path, _| normalize_wildcard_path(path) != key);
    if let Some(name) = current_dir_basename(src) {
        env.modified_filesystem.remove(&name.to_ascii_lowercase());
    }
}

fn insert_copied_entry(env: &mut Environment, src: &str, dst: &str, entry: FsEntry) {
    let tracked_dir_dst = copy_tracked_directory_destination_path(env, src, dst);
    if tracked_dir_dst.is_none() {
        insert_filesystem_entry(env, dst, entry.clone());
    }
    if let Some(joined) = copy_directory_destination_path(src, dst) {
        insert_filesystem_entry(env, &joined, entry);
    } else if let Some(joined) = tracked_dir_dst {
        insert_filesystem_entry(env, &joined, entry);
    }
}

fn insert_copied_directory_entry(env: &mut Environment, src: &str, dst_dir: &str, entry: FsEntry) {
    if let Some(joined) = copy_directory_destination_path(src, &directory_destination(dst_dir)) {
        insert_filesystem_entry(env, &joined, entry);
    }
}

fn insert_filesystem_entry(env: &mut Environment, path: &str, entry: FsEntry) {
    env.modified_filesystem
        .insert(filesystem_storage_key(path), entry);
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

fn collapse_slashes(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut emitted = 0usize;
    let mut prev_was_slash = false;

    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b'\\' {
            if prev_was_slash {
                out.push_str(&s[emitted..i]);
                emitted = i + 1;
            }
            prev_was_slash = true;
        } else {
            prev_was_slash = false;
        }
    }
    if emitted == 0 {
        return s.to_string();
    }
    out.push_str(&s[emitted..]);
    out
}

#[cfg(test)]
mod tests {
    use super::collapse_slashes;

    #[test]
    fn collapse_slashes_preserves_unicode_and_reduces_runs() {
        assert_eq!(
            collapse_slashes(r"C:\\Temp\\héllo\\payload.exe"),
            r"C:\Temp\héllo\payload.exe"
        );
    }
}
