//! esentutl.exe handler — tracks `/y SRC /d DST` copy-style LOLBAS use.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{attached_flag_value, split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_esentutl(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some((src, dst)) = parse_esentutl_copy(&tokens) else {
        return;
    };

    push_lolbas(raw, env);
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

fn parse_esentutl_copy(tokens: &[String]) -> Option<(String, String)> {
    let mut src: Option<String> = None;
    let mut dst: Option<String> = None;
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
        if token.eq_ignore_ascii_case("/y") || token.eq_ignore_ascii_case("-y") {
            src = tokens
                .get(i + 1)
                .map(|value| normalize_path_arg(strip_outer_quotes(value)));
            i += 2;
            continue;
        }
        if token.eq_ignore_ascii_case("/d") || token.eq_ignore_ascii_case("-d") {
            dst = tokens
                .get(i + 1)
                .map(|value| normalize_path_arg(strip_outer_quotes(value)));
            i += 2;
            continue;
        }
        if let Some(value) = attached_flag_value(token, &["/y", "-y"]) {
            src = Some(normalize_path_arg(value));
        } else if let Some(value) = attached_flag_value(token, &["/d", "-d"]) {
            dst = Some(normalize_path_arg(value));
        }
        i += 1;
    }
    let src = src.filter(|value| !value.is_empty())?;
    let dst = dst.filter(|value| !value.is_empty())?;
    Some((src, dst))
}

fn normalize_path_arg(value: &str) -> String {
    collapse_slashes(strip_outer_quotes(value))
}

fn is_windows_util_copy(src: &str, dst: &str) -> bool {
    let src_lower = src.to_ascii_lowercase();
    let dst_lower = dst.to_ascii_lowercase();
    (src_lower.starts_with("c:\\windows\\system32")
        || src_lower.starts_with("c:\\windows\\syswow64"))
        && !(dst_lower.starts_with("c:\\windows\\system32")
            || dst_lower.starts_with("c:\\windows\\syswow64"))
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

fn insert_copied_entry(env: &mut Environment, src: &str, dst: &str, entry: FsEntry) {
    env.modified_filesystem
        .insert(dst.to_ascii_lowercase(), entry.clone());
    if let Some(joined) = copy_directory_destination_path(src, dst) {
        env.modified_filesystem
            .insert(joined.to_ascii_lowercase(), entry);
    }
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

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Lolbas { name, cmd } if name == "esentutl" && cmd == raw
        )
    }) {
        env.traits.push(Trait::Lolbas {
            name: "esentutl".to_string(),
            cmd: raw.to_string(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::parse_esentutl_copy;
    use crate::handlers::util::split_words;

    #[test]
    fn parses_spaced_y_and_d_arguments() {
        let tokens = split_words(
            r#"esentutl /y C:\Windows\System32\cmd.exe /d C:\Users\Public\alpha.pif /o"#,
        );
        assert_eq!(
            parse_esentutl_copy(&tokens),
            Some((
                r#"C:\Windows\System32\cmd.exe"#.to_string(),
                r#"C:\Users\Public\alpha.pif"#.to_string()
            ))
        );
    }

    #[test]
    fn parses_attached_colon_and_equals_arguments() {
        let tokens = split_words(
            r#"esentutl /y:"C:\Windows\System32\cmd.exe" /d=C:\Users\Public\alpha.pif /o"#,
        );
        assert_eq!(
            parse_esentutl_copy(&tokens),
            Some((
                r#"C:\Windows\System32\cmd.exe"#.to_string(),
                r#"C:\Users\Public\alpha.pif"#.to_string()
            ))
        );
    }
}
