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
        r#"(?P<lead>^|\s)(?P<fd>[012])?(?P<op>>>|>|<)\s*(?P<tgt>"(?:[^"]|"")*"|'(?:[^']|'')*'|[^\s|&<>]+)"#,
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
        let mut tgt = m.name("tgt").map(|x| x.as_str()).unwrap_or("").to_string();
        if ((tgt.starts_with('"') && tgt.ends_with('"'))
            || (tgt.starts_with('\'') && tgt.ends_with('\'')))
            && tgt.len() >= 2
        {
            tgt = tgt[1..tgt.len() - 1].to_string();
        }
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
