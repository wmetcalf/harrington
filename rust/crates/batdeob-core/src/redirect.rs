//! Extract redirection targets from a normalized command string.

#![expect(clippy::expect_used, reason = "static regex construction")] // static regex compile

use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectionSet {
    pub stdout: Option<RedirTarget>,
    pub stderr: Option<RedirTarget>,
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirTarget {
    Trunc(String),
    Append(String),
}

impl RedirTarget {
    pub fn path(&self) -> &str {
        match self {
            RedirTarget::Trunc(p) | RedirTarget::Append(p) => p,
        }
    }
    pub fn append(&self) -> bool {
        matches!(self, RedirTarget::Append(_))
    }
}

static REDIR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?P<lead>^|\s)(?P<fd>[012])?(?P<op>>>|>|<)\s*(?P<tgt>""(?:[^"]|"")*""|"(?:[^"]|"")*"|'(?:[^']|'')*'|[^\s|&<>]+)"#,
    )
        .expect("redir regex compiles")
});

pub fn extract_redirections(cmd: &str) -> (String, RedirectionSet) {
    let mut set = RedirectionSet::default();
    let mut cleaned = cmd.to_string();
    while let Some(m) = REDIR_RE.captures(&cleaned) {
        let fd: u8 = m
            .name("fd")
            .map(|s| s.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let op = m.name("op").map(|x| x.as_str()).unwrap_or(">");
        let tgt = unquote_redirection_target(m.name("tgt").map(|x| x.as_str()).unwrap_or(""));
        match op {
            "<" => set.stdin = Some(tgt),
            ">" | ">>" => {
                let target = if op == ">>" {
                    RedirTarget::Append(tgt)
                } else {
                    RedirTarget::Trunc(tgt)
                };
                if fd == 2 {
                    set.stderr = Some(target);
                } else {
                    set.stdout = Some(target);
                }
            }
            _ => {}
        }
        let range = m.get(0).map(|x| x.range()).unwrap_or(0..0);
        cleaned.replace_range(range, " ");
    }
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    (cleaned, set)
}

fn unquote_redirection_target(token: &str) -> String {
    if token.starts_with(r#""""#) && token.ends_with(r#""""#) && token.len() >= 4 {
        return token[2..token.len() - 2].to_string();
    }
    if ((token.starts_with('"') && token.ends_with('"'))
        || (token.starts_with('\'') && token.ends_with('\'')))
        && token.len() >= 2
    {
        return token[1..token.len() - 1].to_string();
    }
    token.to_string()
}

#[cfg(test)]
mod tests {
    use super::{extract_redirections, RedirTarget};

    #[test]
    fn doubled_quoted_stdout_target_is_not_parsed_as_empty() {
        let (cleaned, redir) = extract_redirections(
            r#"echo payload > ""C:\Users\puncher\AppData\Local\Temp\getadmin.vbs"""#,
        );

        assert_eq!(cleaned, "echo payload");
        assert_eq!(
            redir.stdout,
            Some(RedirTarget::Trunc(
                r#"C:\Users\puncher\AppData\Local\Temp\getadmin.vbs"#.to_string()
            ))
        );
    }
}
