//! `set` command handler. Mirrors batch_interpreter.py:interpret_set.

use crate::arith;
use crate::env::Environment;
use crate::handlers::util::starts_with_ascii_case_insensitive;
use crate::traits::Trait;

pub fn h_set(raw: &str, env: &mut Environment) {
    let rest = match strip_set_prefix(raw) {
        Some(r) => r,
        None => return,
    };
    if rest.trim().is_empty() {
        return;
    }

    let trimmed = rest.trim_start();

    // Detect /a flag (case-insensitive)
    if starts_with_ascii_case_insensitive(trimmed, "/a") {
        // Skip past "/a" (2 chars) and any leading whitespace
        let after = trimmed[2..].trim_start();
        do_set_a(after, env);
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
                value,
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
    if starts_with_ascii_case_insensitive(raw, "set") {
        let rest = &raw[3..];
        if rest.is_empty()
            || rest
                .as_bytes()
                .first()
                .is_some_and(|c| c.is_ascii_whitespace() || *c == b'/' || *c == b'"')
        {
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

#[cfg(test)]
mod tests {
    use super::strip_set_prefix;

    #[test]
    fn strip_set_prefix_accepts_ascii_separators() {
        assert_eq!(strip_set_prefix("sEt /a X=1"), Some(" /a X=1"));
        assert_eq!(strip_set_prefix("set\"X=1"), Some("\"X=1"));
        assert_eq!(strip_set_prefix("set"), Some(""));
    }

    #[test]
    fn strip_set_prefix_rejects_non_separator_suffix() {
        assert_eq!(strip_set_prefix("setx"), None);
        assert_eq!(strip_set_prefix("setα"), None);
    }
}
