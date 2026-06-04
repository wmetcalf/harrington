use super::util::split_words;
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
        args.push(strip_quotes(t).to_string());
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
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), FsEntry::Copy { src });
}

pub fn h_xcopy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words(raw);
    let mut args: Vec<String> = Vec::new();
    for t in tokens.iter().skip(1) {
        let stripped = strip_quotes(t);
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
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), FsEntry::Copy { src });
}

fn is_windows_util_copy(src: &str, dst: &str) -> bool {
    let src_lower = src.to_ascii_lowercase();
    let dst_lower = dst.to_ascii_lowercase();
    (src_lower.starts_with("c:\\windows\\system32")
        || src_lower.starts_with("c:\\windows\\syswow64"))
        && !(dst_lower.starts_with("c:\\windows\\system32")
            || dst_lower.starts_with("c:\\windows\\syswow64"))
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
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
