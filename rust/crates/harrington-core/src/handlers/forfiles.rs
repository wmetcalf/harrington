//! forfiles.exe handler — extracts the `/c` command child.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{
    normalize_filesystem_storage_path, normalize_wildcard_path, wildcard_match,
};
use crate::traits::Trait;

pub fn extract_forfiles_inner(raw: &str) -> Option<String> {
    let tokens = split_forfiles_tokens(raw);
    let first = tokens.first()?;
    if command_basename_no_ext(first) != "forfiles" {
        return None;
    }
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        let lower = token.to_ascii_lowercase();
        if lower == "/c" || lower == "-c" {
            let inner = tokens[idx + 1..].join(" ");
            return (!inner.trim().is_empty()).then(|| inner.trim().to_string());
        }
        if let Some(rest) = lower
            .strip_prefix("/c:")
            .or_else(|| lower.strip_prefix("-c:"))
            .or_else(|| lower.strip_prefix("/c="))
            .or_else(|| lower.strip_prefix("-c="))
        {
            let offset = token.len() - rest.len();
            let inner = token[offset..].trim();
            if !inner.is_empty() {
                let mut command = inner.to_string();
                let tail = tokens[idx + 1..].join(" ");
                if !tail.is_empty() {
                    command.push(' ');
                    command.push_str(&tail);
                }
                return Some(command);
            }
        }
    }
    None
}

pub fn extract_forfiles_inner_with_env(raw: &str, env: &Environment) -> Option<String> {
    extract_forfiles_inners_with_env(raw, env).and_then(|inners| inners.into_iter().next())
}

pub fn extract_forfiles_inners_with_env(raw: &str, env: &Environment) -> Option<Vec<String>> {
    let inner = extract_forfiles_inner(raw)?;
    if !inner.contains('@') {
        return Some(vec![inner]);
    }
    let tokens = split_forfiles_tokens(raw);
    let root = forfiles_option_value(&tokens, "/p").unwrap_or_default();
    let paths = tracked_forfiles_paths(raw, env);
    if paths.is_empty() {
        return Some(vec![inner]);
    }
    Some(
        paths
            .into_iter()
            .map(|path| substitute_forfiles_placeholders(&inner, &path, &root))
            .collect(),
    )
}

pub fn h_forfiles(raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Lolbas { name, cmd } if name == "forfiles" && cmd == raw
        )
    }) {
        env.traits.push(Trait::Lolbas {
            name: "forfiles".to_string(),
            cmd: raw.to_string(),
        });
    }
}

fn tracked_forfiles_paths(raw: &str, env: &Environment) -> Vec<String> {
    let tokens = split_forfiles_tokens(raw);
    let root = forfiles_option_value(&tokens, "/p").unwrap_or_default();
    let mask = forfiles_option_value(&tokens, "/m").unwrap_or_else(|| "*".to_string());
    let recursive = tokens
        .iter()
        .skip(1)
        .any(|token| token.eq_ignore_ascii_case("/s") || token.eq_ignore_ascii_case("-s"));
    let normalized_root = normalize_wildcard_path(&normalize_filesystem_storage_path(&root))
        .trim_end_matches('\\')
        .to_string();
    let normalized_mask = normalize_wildcard_path(&mask);
    let mut matched = env
        .modified_filesystem
        .iter()
        .filter_map(|(path, entry)| {
            if matches!(entry, FsEntry::Directory)
                || !forfiles_path_under_root(path, &normalized_root, recursive)
                || !windows_basename(path).is_some_and(|name| {
                    wildcard_match(&normalized_mask, &normalize_wildcard_path(name))
                })
            {
                return None;
            }
            Some(path.clone())
        })
        .collect::<Vec<_>>();
    matched.sort();
    matched
}

fn forfiles_option_value(tokens: &[String], flag: &str) -> Option<String> {
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        if token.eq_ignore_ascii_case(flag) || token.eq_ignore_ascii_case(&flag.replace('/', "-")) {
            return tokens
                .get(idx + 1)
                .map(|value| value.trim_matches(['"', '\'']).to_string());
        }
        for sep in [':', '='] {
            let prefix = format!("{flag}{sep}");
            let dash_prefix = format!("-{}{sep}", flag.trim_start_matches('/'));
            let lower = token.to_ascii_lowercase();
            if lower.starts_with(&prefix) || lower.starts_with(&dash_prefix) {
                let offset = token.find(sep)? + 1;
                let value = token[offset..].trim_matches(['"', '\'']).to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn forfiles_path_under_root(path: &str, normalized_root: &str, recursive: bool) -> bool {
    if normalized_root.is_empty() {
        return recursive || !path.contains(['\\', '/', ':']);
    }
    let normalized_path = normalize_wildcard_path(path);
    let Some(rest) = normalized_path.strip_prefix(normalized_root) else {
        return false;
    };
    let rest = rest.trim_start_matches('\\');
    !rest.is_empty() && (recursive || !rest.contains('\\'))
}

fn substitute_forfiles_placeholders(inner: &str, path: &str, root: &str) -> String {
    let file = windows_basename(path).unwrap_or(path);
    let (fname, ext) = split_filename_ext(file);
    let relpath = forfiles_relative_path(path, root);
    let mut out = replace_ascii_ci(inner, "@path", &format!("\"{path}\""));
    out = replace_ascii_ci(&out, "@relpath", &relpath);
    out = replace_ascii_ci(&out, "@file", file);
    out = replace_ascii_ci(&out, "@fname", fname);
    out = replace_ascii_ci(&out, "@ext", ext);
    replace_ascii_ci(&out, "@isdir", "FALSE")
}

fn forfiles_relative_path(path: &str, root: &str) -> String {
    let normalized_path = normalize_wildcard_path(path);
    let normalized_root = normalize_wildcard_path(&normalize_filesystem_storage_path(root))
        .trim_end_matches('\\')
        .to_string();
    let rest = normalized_path
        .strip_prefix(&normalized_root)
        .map(|rest| rest.trim_start_matches('\\'))
        .filter(|rest| !rest.is_empty())
        .unwrap_or(path);
    format!(r".\{rest}")
}

fn split_filename_ext(file: &str) -> (&str, &str) {
    let Some(dot) = file.rfind('.') else {
        return (file, "");
    };
    if dot == 0 {
        return (file, "");
    }
    file.split_at(dot)
}

fn replace_ascii_ci(input: &str, needle: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let lower = input.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find(&needle_lower) {
        let abs = pos + rel;
        out.push_str(&input[pos..abs]);
        out.push_str(replacement);
        pos = abs + needle.len();
    }
    out.push_str(&input[pos..]);
    out
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn command_basename_no_ext(token: &str) -> String {
    let trimmed = token
        .trim_start_matches(|ch: char| {
            ch.is_ascii_whitespace() || matches!(ch, '@' | '"' | '\'' | '(' | ';' | ',')
        })
        .trim_matches(['"', '\''])
        .to_ascii_lowercase();
    let last_sep = trimmed.rfind(['\\', '/']).map(|idx| idx + 1).unwrap_or(0);
    let base = &trimmed[last_sep..];
    base.strip_suffix(".exe").unwrap_or(base).to_string()
}

fn split_forfiles_tokens(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_dq = false;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' {
            in_dq = !in_dq;
            continue;
        }
        if !in_dq && c.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            while chars.peek().is_some_and(|next| next.is_whitespace()) {
                chars.next();
            }
            continue;
        }
        current.push(c);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        extract_forfiles_inner, extract_forfiles_inner_with_env, extract_forfiles_inners_with_env,
    };
    use crate::env::{Config, Environment, FsEntry};

    #[test]
    fn extracts_quoted_c_command() {
        assert_eq!(
            extract_forfiles_inner(r#"forfiles /p C:\ /c "cmd /c echo hi""#).as_deref(),
            Some("cmd /c echo hi")
        );
    }

    #[test]
    fn extracts_echo_suppressed_forfiles_command() {
        assert_eq!(
            extract_forfiles_inner(r#"@forfiles /p C:\ /c "cmd /c echo hi""#).as_deref(),
            Some("cmd /c echo hi")
        );
    }

    #[test]
    fn extracts_delimiter_prefixed_forfiles_command() {
        assert_eq!(
            extract_forfiles_inner(r#"@;forfiles /p C:\ /c "cmd /c echo hi""#).as_deref(),
            Some("cmd /c echo hi")
        );
    }

    #[test]
    fn extracts_unquoted_c_command() {
        assert_eq!(
            extract_forfiles_inner(r#"forfiles /p C:\ /c cmd /c echo hi"#).as_deref(),
            Some("cmd /c echo hi")
        );
    }

    #[test]
    fn extracts_colon_attached_c_command() {
        assert_eq!(
            extract_forfiles_inner(r#"forfiles.exe /c:"cmd /c echo hi""#).as_deref(),
            Some("cmd /c echo hi")
        );
    }

    #[test]
    fn extracts_attached_unquoted_c_command() {
        assert_eq!(
            extract_forfiles_inner(r#"forfiles /p C:\ /c=cmd /c echo hi"#).as_deref(),
            Some("cmd /c echo hi")
        );
    }

    #[test]
    fn ignores_non_forfiles_command() {
        assert!(extract_forfiles_inner(r#"notforfiles /c "cmd /c echo hi""#).is_none());
    }

    #[test]
    fn substitutes_path_placeholder_from_tracked_file() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert(
            r"c:\work\run.js".to_string(),
            FsEntry::Content {
                content: b"fetch('https://example.invalid')".to_vec(),
                append: false,
            },
        );

        assert_eq!(
            extract_forfiles_inner_with_env(
                r#"forfiles /p C:\Work /m *.js /c "cmd /c @path""#,
                &env
            )
            .as_deref(),
            Some(r#"cmd /c "c:\work\run.js""#)
        );
    }

    #[test]
    fn substitutes_path_placeholder_for_each_tracked_file() {
        let mut env = Environment::new(&Config::default());
        for path in [r"c:\work\a.js", r"c:\work\b.js"] {
            env.modified_filesystem.insert(
                path.to_string(),
                FsEntry::Content {
                    content: b"fetch('https://example.invalid')".to_vec(),
                    append: false,
                },
            );
        }

        assert_eq!(
            extract_forfiles_inners_with_env(
                r#"forfiles /p C:\Work /m *.js /c "cmd /c @path""#,
                &env
            )
            .unwrap(),
            vec![r#"cmd /c "c:\work\a.js""#, r#"cmd /c "c:\work\b.js""#]
        );
    }

    #[test]
    fn substitutes_name_and_extension_placeholders() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert(
            r"c:\work\run.js".to_string(),
            FsEntry::Content {
                content: b"fetch('https://example.invalid')".to_vec(),
                append: false,
            },
        );

        assert_eq!(
            extract_forfiles_inner_with_env(
                r#"forfiles /p C:\Work /m *.js /c "cmd /c C:\Work\@fname@ext""#,
                &env
            )
            .as_deref(),
            Some(r"cmd /c C:\Work\run.js")
        );
    }

    #[test]
    fn substitutes_relative_path_placeholder() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert(
            r"c:\work\sub\run.js".to_string(),
            FsEntry::Content {
                content: b"fetch('https://example.invalid')".to_vec(),
                append: false,
            },
        );

        assert_eq!(
            extract_forfiles_inner_with_env(
                r#"forfiles /p C:\Work /s /m *.js /c "cmd /c C:\Work\@relpath""#,
                &env
            )
            .as_deref(),
            Some(r"cmd /c C:\Work\.\sub\run.js")
        );
    }
}
