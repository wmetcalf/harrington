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
        if let Some(inner) = crate::handlers::cmd::extract_cmd_inner(body) {
            env.exec_cmd.push(unescape_outer_caret_bangs(&inner));
            env.exec_cmd_delayed
                .push(crate::handlers::cmd::has_v_on_raw(body));
            return;
        }
        if call_body_is_set_assignment(body) {
            crate::handlers::set::h_set(body, env);
            return;
        }
        if env.enter_child_script(body) {
            crate::interp::interpret_line(body, env);
        }
    }
}

pub(crate) fn call_body(raw: &str) -> Option<&str> {
    let rest = raw.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ')' || c == ';' || c == ',' || c.is_whitespace()
    });
    let after = strip_keyword_ci(rest, "call", b":/;,")?;
    Some(after.trim_start_matches(|c: char| c == ';' || c == ',' || c.is_whitespace()))
}

fn unescape_outer_caret_bangs(command: &str) -> String {
    command.replace("^!", "!")
}

fn call_body_is_set_assignment(body: &str) -> bool {
    let tokens = split_words(body);
    tokens.first().is_some_and(|cmd| {
        let cmd = cmd.trim_start_matches('@').trim_matches(['"', '\'']);
        cmd.eq_ignore_ascii_case("set")
    })
}

#[cfg(test)]
mod tests {
    use super::{call_body, call_body_is_set_assignment};

    #[test]
    fn call_body_accepts_echo_suppressed_prefix() {
        assert_eq!(call_body("@call payload.cmd"), Some("payload.cmd"));
    }

    #[test]
    fn call_body_accepts_wrapper_and_separator_prefix() {
        assert_eq!(call_body("(CalL;netstat /ano)"), Some("netstat /ano)"));
    }

    #[test]
    fn call_set_body_is_assignment_not_child_script() {
        assert!(call_body_is_set_assignment(r#"set "X=value""#));
        assert!(call_body_is_set_assignment(r#"@set X=value"#));
        assert!(!call_body_is_set_assignment("payload.cmd"));
    }
}
