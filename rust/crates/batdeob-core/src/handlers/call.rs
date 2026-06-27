//! call — either `call :label args…` (subroutine) or `call <cmd>` (re-feed).

use crate::env::{CursorAction, Environment, Frame};
use crate::handlers::util::{split_words, strip_keyword_ci};
use crate::traits::Trait;

pub fn h_call(raw: &str, env: &mut Environment) {
    let body = call_body(raw).unwrap_or("");

    if let Some(after_colon) = body.strip_prefix(':') {
        let parts = split_words(after_colon);
        if parts.is_empty() {
            return;
        }
        let label = parts[0].trim_matches(['"', '\'']);
        let args: Vec<String> = parts[1..]
            .iter()
            .map(|s| s.trim_matches(['"', '\'']).to_string())
            .collect();
        let label_key = label.to_ascii_lowercase();
        if let Some(line_idx) = env.label_index.get(&label_key).copied() {
            let return_line = env.current_line.map(|l| l + 1).unwrap_or(0);
            env.call_stack.push(Frame {
                return_line,
                args: args.clone(),
                locals_snapshot: None,
            });
            env.pending_action = Some(CursorAction::GotoLine(line_idx));
            env.traits.push(Trait::Subroutine {
                label: label.to_string(),
                args,
            });
        } else {
            env.traits.push(Trait::GotoUnresolved {
                from_line: env.current_line.unwrap_or(0),
                to_label: label_key,
            });
        }
        return;
    }

    if !body.is_empty() {
        crate::interp::interpret_line(body, env);
    }
}

pub(crate) fn call_body(raw: &str) -> Option<&str> {
    let rest = raw.trim_start();
    let after = strip_keyword_ci(rest, "call", b":/")?;
    Some(after.trim_start())
}
