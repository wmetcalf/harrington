//! goto / exit handlers — control-flow signals via env.pending_action.

use crate::env::{CursorAction, Environment};
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
    // Must be followed by whitespace, EOF, or a colon (for `goto:label`).
    match rest.chars().next() {
        None => Some(rest),
        Some(c) if c.is_whitespace() || c == ':' || c == '/' => Some(rest),
        _ => None,
    }
}

pub fn h_goto(raw: &str, env: &mut Environment) {
    let rest = raw.trim_start();
    let after = strip_keyword_ci(rest, "goto").unwrap_or("");
    // Real CMD treats `;`, `,` (and whitespace/`:`) as ignorable label
    // prefix AND as token delimiters within the label. xeno-class goto-
    // bytecode obfuscators rely on this: `goto ,;;; 311144` resolves
    // to `goto 311144` because the leading `,;;;` is delimiter prefix
    // and the actual label is the first whitespace/`,`/`;`-bounded
    // alphanumeric token. Without stripping these we report
    // GotoUnresolved for the whole xeno chain and never follow the
    // bytecode that assembles the URL via char-substitution tables.
    let stripped =
        after.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == ';' || c == ',');
    let target: String = stripped
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ';' && *c != ',')
        .collect::<String>()
        .to_ascii_lowercase();
    if target == "eof" || target.is_empty() {
        env.pending_action = Some(CursorAction::PopFrame);
        return;
    }
    let target_line = env.label_index.get(&target).copied().or_else(|| {
        let current = env.current_line.unwrap_or(0);
        let trailing_colon = format!("{target}:");
        env.label_index
            .get(&trailing_colon)
            .copied()
            .filter(|line_idx| *line_idx > current)
    });
    if let Some(line_idx) = target_line {
        env.pending_action = Some(CursorAction::GotoLine(line_idx));
    } else {
        env.traits.push(Trait::GotoUnresolved {
            from_line: env.current_line.unwrap_or(0),
            to_label: target,
        });
    }
}

pub fn h_exit(raw: &str, env: &mut Environment) {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("/b") {
        env.pending_action = Some(CursorAction::PopFrame);
    } else {
        env.pending_action = Some(CursorAction::Halt);
    }
}
