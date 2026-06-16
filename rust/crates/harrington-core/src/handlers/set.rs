//! `set` command handler. Mirrors batch_interpreter.py:interpret_set.

use crate::env::{Environment, FsEntry};
use crate::traits::Trait;
use crate::{arith, redirect};

pub fn h_set(raw: &str, env: &mut Environment) {
    let cleaned_prefix;
    let rest = if let Some(rest) = strip_set_prefix(raw) {
        rest
    } else {
        cleaned_prefix = redirect::extract_redirections(raw).0;
        match strip_set_prefix(&cleaned_prefix) {
            Some(rest) => rest,
            None => return,
        }
    };
    if rest.trim().is_empty() {
        return;
    }

    let trimmed = rest.trim_start();

    // Detect /a flag (case-insensitive)
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("/a") {
        // Skip past "/a" (2 chars) and any leading whitespace
        let after = trimmed[2..].trim_start();
        do_set_a(after, env);
        return;
    }
    if lower.starts_with("/p") {
        do_set_p(raw, env);
        return;
    }

    let body = trimmed;

    // Quoted form: set "NAME=VALUE"
    if let Some(inner) = quoted_form(body) {
        if let Some((name, value)) = split_eq(inner) {
            env.set(name, value);
        }
        return;
    }

    // CMD auto-closes a `set "X=value` line that lacks the closing `"`
    // (the value extends to EOL). Detect this so the variable name is
    // stored without the leading `"`. Without this, `%S1VlS0Nh%` looks
    // up `"S1VlS0Nh` (with leading quote) and returns empty, breaking
    // marker-strip chains like `%X:WJesB=%`.
    let body = if let Some(stripped) = body.strip_prefix('"') {
        if !stripped.contains('"') {
            stripped
        } else {
            body
        }
    } else {
        body
    };

    // Unquoted form: strip a single trailing close-paren if present
    // (matches a wrapping `(set k=value)` group at the shell level).
    // We DON'T trim trailing whitespace from the value — CMD preserves
    // it (`set EXP=43 ` stores "43 ").
    let body = if let Some(rest) = body.strip_suffix(')') {
        rest
    } else {
        body
    };

    if let Some((name, value)) = split_eq(body) {
        env.set(name, value);
    }
}

fn do_set_p(raw: &str, env: &mut Environment) {
    let (cleaned, redirections) = redirect::extract_redirections(raw);
    let raw_rest = if let Some(rest) = strip_set_prefix(raw) {
        rest
    } else {
        match strip_set_prefix(&cleaned) {
            Some(rest) => rest,
            None => return,
        }
    };
    let raw_after_flag = raw_rest.trim_start();
    if !raw_after_flag.to_ascii_lowercase().starts_with("/p") {
        return;
    }
    let raw_body = raw_after_flag[2..].trim_start();
    let body = strip_set_prefix(&cleaned)
        .and_then(|rest| {
            let after_flag = rest.trim_start();
            after_flag
                .to_ascii_lowercase()
                .starts_with("/p")
                .then(|| after_flag[2..].trim_start())
        })
        .unwrap_or(raw_body);
    let Some(name) = set_p_name(body) else {
        return;
    };
    let stdin = redirections
        .stdin
        .or_else(|| set_p_attached_stdin(raw_body));
    let Some(stdin) = stdin else {
        env.seed(name, &format!("%{name}%"));
        return;
    };
    let Some(value) = first_line_from_tracked_file(&stdin, env) else {
        return;
    };
    env.set(name, &value);
}

fn set_p_attached_stdin(body: &str) -> Option<String> {
    let (_, value) = body.split_once('=')?;
    let target = value.trim_start().strip_prefix('<')?.trim_start();
    if target.is_empty() {
        return None;
    }
    if let Some(rest) = target.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    let end = target
        .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '&' | '|'))
        .unwrap_or(target.len());
    (end > 0).then(|| target[..end].to_string())
}

fn set_p_name(body: &str) -> Option<&str> {
    let name = body.split_once('=').map_or(body, |(name, _)| name).trim();
    (!name.is_empty()).then_some(name)
}

fn first_line_from_tracked_file(path: &str, env: &Environment) -> Option<String> {
    let entry = crate::handlers::util::filesystem_entry_for_path(env, path)?;
    let content = match entry {
        FsEntry::Content { content, .. } | FsEntry::Decoded { content, .. } => content,
        FsEntry::Download { .. } | FsEntry::Copy { .. } | FsEntry::Directory => return None,
    };
    let end = content
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .unwrap_or(content.len());
    Some(String::from_utf8_lossy(&content[..end]).into_owned())
}

fn do_set_a(body: &str, env: &mut Environment) {
    // body may be: NAME=EXPR  OR  "NAME = EXPR"
    let inner = if let Some(q) = quoted_form(body) {
        q.to_string()
    } else {
        body.to_string()
    };
    let inner = inner.trim();

    // Skip evaluation entirely if the expression contains unresolved sigils.
    // These will never be valid arithmetic and produce noisy parse-error events.
    if inner.contains('%') || inner.contains('!') {
        return;
    }

    // Evaluate the whole expression — the Pratt parser handles assignment itself.
    match arith::eval(inner, env) {
        Ok(value) => {
            // CMD's set /a truncates to int32 at assignment; arith
            // engine now keeps full i64 intermediates so shifts of
            // 40-bit hex literals (`0x6b84031624 >> 4`) preserve the
            // upper bits. Final result wrapped to i32 for the trait.
            env.traits.push(Trait::Arithmetic {
                expr: inner.to_string(),
                value: value as i32,
            });
        }
        Err(_) => {
            env.traits.push(Trait::ArithmeticParseError {
                expr: inner.to_string(),
            });
        }
    }
}

fn strip_set_prefix(raw: &str) -> Option<&str> {
    // CMD's `()` groups commands at shell level; the inner command sees
    // its arguments without the parens. `(set k=value)` is a valid way
    // to set k=value — the dispatcher already strips leading `(` for
    // command-name detection, so we do the same here to keep behavior
    // consistent.
    // Match command_name's prefix handling: `@` (echo-suppress), `(` (block),
    // `;`/`,` (CMD token delimiters), and whitespace are all ignorable before
    // the command word. Obfuscators interleave them (`@;@@@set …`).
    let raw = raw.trim_start_matches(|c: char| {
        c == '(' || c == '@' || c == ';' || c == ',' || c.is_whitespace()
    });
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("set") {
        let rest = &raw[3..];
        if let Some(c) = rest.chars().next() {
            if c.is_whitespace() || c == '/' || c == '"' {
                return Some(rest);
            }
        }
        if rest.is_empty() {
            return Some(rest);
        }
    }
    None
}

fn quoted_form(body: &str) -> Option<&str> {
    let body = body.trim_start();
    let bytes = body.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let last = body.rfind('"')?;
    if last == 0 {
        return None;
    }
    Some(&body[1..last])
}

fn split_eq(s: &str) -> Option<(&str, &str)> {
    let eq = s.find('=')?;
    Some((&s[..eq], &s[eq + 1..]))
}
