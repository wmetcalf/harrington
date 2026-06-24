//! goto / exit handlers — control-flow signals via env.pending_action.

use crate::env::{CursorAction, Environment};
use crate::handlers::util::{contains_ascii_case_insensitive, strip_keyword_ci};
use crate::traits::Trait;

pub fn h_goto(raw: &str, env: &mut Environment) {
    let rest = raw.trim_start();
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
        env.pending_action = Some(CursorAction::GotoLine(line_idx));
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
