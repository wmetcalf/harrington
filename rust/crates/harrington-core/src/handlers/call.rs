//! call — either `call :label args…` (subroutine) or `call <cmd>` (re-feed).

use crate::env::{CursorAction, Environment, Frame};
use crate::handlers::util::split_words;
use crate::traits::Trait;

/// Strip a case-insensitive keyword prefix followed by either end-of-input or
/// a non-alphanumeric char. Returns the slice AFTER the keyword, or None if
/// the input doesn't start with that keyword.
fn strip_keyword_ci<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    if s.len() < kw.len() {
        return None;
    }
    if !s
        .get(..kw.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(kw))
    {
        return None;
    }
    let rest = &s[kw.len()..];
    // Must be followed by whitespace, EOF, or a colon (for `call:label`).
    match rest.chars().next() {
        None => Some(rest),
        Some(c) if c.is_whitespace() || c == ':' || c == '/' => Some(rest),
        _ => None,
    }
}

pub fn h_call(raw: &str, env: &mut Environment) {
    let body = call_body(raw).unwrap_or("");

    if let Some(after_colon) = body.strip_prefix(':') {
        let parts = split_words(after_colon);
        if parts.is_empty() {
            return;
        }
        let label = parts[0].to_ascii_lowercase();
        let args: Vec<String> = parts[1..].to_vec();
        if let Some(line_idx) = env.label_index.get(&label).copied() {
            let return_line = env.current_line.map(|l| l + 1).unwrap_or(0);
            env.call_stack.push(Frame {
                return_line,
                args: args.clone(),
                locals_snapshot: None,
            });
            env.pending_action = Some(CursorAction::GotoLine(line_idx));
            env.traits.push(Trait::Subroutine { label, args });
        } else {
            env.traits.push(Trait::GotoUnresolved {
                from_line: env.current_line.unwrap_or(0),
                to_label: label,
            });
        }
        return;
    }

    if !body.is_empty() {
        crate::interp::interpret_line(body, env);
    }
}

pub(crate) fn call_body(raw: &str) -> Option<&str> {
    let rest = raw.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
    });
    let after = strip_keyword_ci(rest, "call")?;
    Some(after.trim_start())
}

#[cfg(test)]
mod tests {
    use super::call_body;

    #[test]
    fn call_body_accepts_echo_suppressed_prefix() {
        assert_eq!(call_body("@call payload.cmd"), Some("payload.cmd"));
    }
}
