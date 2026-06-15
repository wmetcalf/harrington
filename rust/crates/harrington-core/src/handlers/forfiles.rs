//! forfiles.exe handler — extracts the `/c` command child.

use crate::env::Environment;
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

fn command_basename_no_ext(token: &str) -> String {
    let trimmed = token.trim_matches(['"', '\'']).to_ascii_lowercase();
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
    use super::extract_forfiles_inner;

    #[test]
    fn extracts_quoted_c_command() {
        assert_eq!(
            extract_forfiles_inner(r#"forfiles /p C:\ /c "cmd /c echo hi""#).as_deref(),
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
}
