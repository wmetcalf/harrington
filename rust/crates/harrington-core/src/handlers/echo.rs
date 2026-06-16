//! `echo` handler — records redirected output into modified_filesystem.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::filesystem_storage_key;
use crate::redirect::extract_redirections;
use crate::traits::Trait;

pub fn h_echo(raw: &str, env: &mut Environment) {
    let (mut cleaned, mut redir) = extract_redirections(raw);
    if redir.stdout.is_none() {
        if let Some((without_redir, target)) = extract_inline_echo_stdout_redirect(&cleaned) {
            cleaned = without_redir;
            redir.stdout = Some(target);
        }
    }
    if redir.stdout.is_some() && has_unquoted_pipe(&cleaned) {
        return;
    }
    let echo = strip_echo_prefix(&cleaned);
    let after_echo = echo.map(|prefix| prefix.body).unwrap_or(&cleaned);
    let payload = after_echo.trim_start();

    let Some(target) = redir.stdout else {
        update_echo_state(payload, env);
        return;
    };
    let path = target.path().to_string();
    let append = target.append();

    let payload = if payload.is_empty() && !echo.is_some_and(|prefix| prefix.literal_empty) {
        if env.echo_enabled {
            "ECHO is on.".to_string()
        } else {
            "ECHO is off.".to_string()
        }
    } else {
        payload.to_string()
    };
    let mut content = payload.into_bytes();
    content.extend_from_slice(b"\r\n");
    let key = filesystem_storage_key(&path);
    let redirected_chunk = content.clone();
    env.traits.push(Trait::EchoRedirect {
        content: redirected_chunk,
        target: path,
        append,
    });
    let cap = env.limits.max_output_bytes as usize;
    if append {
        if let Some(FsEntry::Content {
            content: prior,
            append: prior_append,
        }) = env.modified_filesystem.get_mut(&key)
        {
            // Per-FsEntry cap so `:loop\necho A>>z.txt\ngoto loop` cannot
            // balloon to GB; max_output_bytes only limits the `out` String.
            let room = cap.saturating_sub(prior.len());
            let take = content.len().min(room);
            if take > 0 {
                prior.extend_from_slice(&content[..take]);
            }
            *prior_append = true;
            return;
        }
    }
    let mut bounded = content;
    if bounded.len() > cap {
        bounded.truncate(cap);
    }
    env.modified_filesystem.insert(
        key,
        FsEntry::Content {
            content: bounded,
            append,
        },
    );
}

#[derive(Debug, Clone, Copy)]
struct EchoPrefix<'a> {
    body: &'a str,
    literal_empty: bool,
}

fn strip_echo_prefix(raw: &str) -> Option<EchoPrefix<'_>> {
    let trimmed = raw.trim_start();
    let trimmed = trimmed.strip_prefix('@').unwrap_or(trimmed).trim_start();
    if trimmed.len() >= 4 && trimmed[..4].eq_ignore_ascii_case("echo") {
        let body = &trimmed[4..];
        if let Some(separator) = body.chars().next() {
            if matches!(separator, '.' | ':' | '/' | '(') {
                return Some(EchoPrefix {
                    body: &body[separator.len_utf8()..],
                    literal_empty: true,
                });
            }
        }
        return Some(EchoPrefix {
            body,
            literal_empty: false,
        });
    }
    None
}

fn update_echo_state(payload: &str, env: &mut Environment) {
    let state = payload.trim();
    if state.eq_ignore_ascii_case("off") {
        env.echo_enabled = false;
    } else if state.eq_ignore_ascii_case("on") {
        env.echo_enabled = true;
    }
}

fn has_unquoted_pipe(raw: &str) -> bool {
    let mut in_double = false;
    let mut in_single = false;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '^' {
            chars.next();
            continue;
        }
        match c {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '|' if !in_double && !in_single => return true,
            _ => {}
        }
    }
    false
}

fn extract_inline_echo_stdout_redirect(
    raw: &str,
) -> Option<(String, crate::redirect::RedirTarget)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut op_start = None;
    let bytes = raw.as_bytes();
    for (idx, c) in raw.char_indices() {
        match c {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '>' if !in_double && !in_single => op_start = Some(idx),
            _ => {}
        }
    }
    let op = op_start?;
    if op == 0 {
        return None;
    }
    let append = bytes.get(op.wrapping_sub(1)) == Some(&b'>');
    let content_end = if append { op - 1 } else { op };
    let before_op = raw[..content_end].trim_end();
    if before_op.is_empty() {
        return None;
    }
    let mut target = raw[op + 1..].trim_start();
    if target.is_empty() {
        return None;
    }
    if let Some(rest) = target.strip_prefix('"') {
        let end = rest.find('"')?;
        target = &rest[..end];
    } else {
        target = target
            .split(|c: char| c.is_whitespace() || matches!(c, '|' | '&' | '<' | '>'))
            .next()
            .unwrap_or("");
    }
    if target.is_empty() {
        return None;
    }
    let redir = if append {
        crate::redirect::RedirTarget::Append(target.to_string())
    } else {
        crate::redirect::RedirTarget::Trunc(target.to_string())
    };
    Some((before_op.to_string(), redir))
}
