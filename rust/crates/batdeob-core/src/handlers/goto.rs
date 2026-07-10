//! goto / exit handlers — control-flow signals via env.pending_action.

use crate::env::{CursorAction, Environment};
use crate::handlers::util::{contains_ascii_case_insensitive, strip_keyword_ci};
use crate::traits::Trait;

pub fn h_goto(raw: &str, env: &mut Environment) {
    let rest = raw.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
    });
    let after = strip_keyword_ci(rest, "goto", b":/;,").unwrap_or("");
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
    let end = stripped
        .as_bytes()
        .iter()
        .position(|b| b.is_ascii_whitespace() || *b == b';' || *b == b',')
        .unwrap_or(stripped.len());
    let target = stripped[..end].to_ascii_lowercase();
    if target == "eof" || target.is_empty() {
        env.pending_action = Some(CursorAction::PopFrame);
        return;
    }
    if let Some(line_idx) = env.label_index.get(&target).copied() {
        let from_line = env.current_line.unwrap_or(0);
        if line_idx <= from_line && env.line_visit_count.contains_key(&line_idx) {
            env.traits.push(Trait::GotoUnresolved {
                from_line,
                to_label: target,
            });
        } else {
            env.pending_action = Some(CursorAction::GotoLine(line_idx));
        }
    } else {
        env.traits.push(Trait::GotoUnresolved {
            from_line: env.current_line.unwrap_or(0),
            to_label: target,
        });
    }
}

pub fn h_exit(raw: &str, env: &mut Environment) {
    if contains_ascii_case_insensitive(raw, "/b") {
        env.pending_action = Some(CursorAction::PopFrame);
    } else {
        env.pending_action = Some(CursorAction::Halt);
    }
}

#[cfg(test)]
mod tests {
    use super::h_goto;
    use crate::env::{CursorAction, Environment};

    #[test]
    fn goto_accepts_echo_suppressed_prefix() {
        let mut env = Environment::default();
        env.label_index.insert("target".to_string(), 7);

        h_goto("@goto target", &mut env);

        assert_eq!(env.pending_action, Some(CursorAction::GotoLine(7)));
    }
}
