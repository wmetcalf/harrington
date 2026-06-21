use super::util::{split_words, strip_outer_quotes, windows_basename};
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
        args.push(strip_outer_quotes(t).to_string());
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
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src });
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry);
}

pub fn h_xcopy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words(raw);
    let mut args: Vec<String> = Vec::new();
    for t in tokens.iter().skip(1) {
        let stripped = strip_outer_quotes(t);
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
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src });
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry);
}

pub fn h_move(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::AdminCommand {
        name: "move".to_string(),
        cmd: raw.to_string(),
    });
    track_rename_like(raw, env, &["/y", "/-y"]);
}

pub fn h_ren(raw: &str, env: &mut Environment) {
    track_rename_like(raw, env, &[]);
}

fn track_rename_like(raw: &str, env: &mut Environment, options: &[&str]) {
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
    if is_windows_util_copy(&src, &dst) || is_windows_util_rename(&src, &dst) {
        env.traits.push(Trait::WindowsUtilManip {
            cmd: raw.to_string(),
            src: src.clone(),
            dst: dst.clone(),
        });
    }
    let entry = copied_entry(&src, env).unwrap_or(FsEntry::Copy { src });
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry);
}

fn copied_entry(src: &str, env: &Environment) -> Option<FsEntry> {
    let key = src.to_ascii_lowercase();
    if let Some(entry) = env.modified_filesystem.get(&key) {
        return Some(entry.clone());
    }

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
