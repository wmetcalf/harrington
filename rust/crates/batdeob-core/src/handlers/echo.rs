//! `echo` handler — records redirected output into modified_filesystem.

use crate::env::{Environment, FsEntry};
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
    // Strip leading `echo` (case-insensitive)
    let body = cleaned.trim_start();
    let after_echo = if body.len() >= 4 && body[..4].eq_ignore_ascii_case("echo") {
        &body[4..]
    } else {
        &cleaned
    };
    let payload = after_echo.trim_start().to_string();

    let Some(target) = redir.stdout else { return };
    let path = target.path().to_string();
    let append = target.append();

    let mut content = payload.into_bytes();
    content.extend_from_slice(b"\r\n");
    let key = path.to_ascii_lowercase();
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
