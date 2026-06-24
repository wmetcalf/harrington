//! `if` handler — evaluates the condition and signals body suppression via env.suppress_until_eol.

use crate::env::Environment;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex is a compile-time constant; .expect on a literal panic-at-startup is a developer error.
#[allow(clippy::expect_used)]
static IF_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*if\s+(?P<neg>not\s+)?(?P<rest>.*)$").expect("if regex"));

pub fn h_if(raw: &str, env: &mut Environment) {
    let Some(caps) = IF_RE.captures(raw) else {
        return;
    };
    let negate = caps.name("neg").is_some();
    let rest = caps.name("rest").map(|m| m.as_str()).unwrap_or("");
    let result = evaluate(rest, env);
    let final_result = match result {
        Some(b) => {
            if negate {
                !b
            } else {
                b
            }
        }
        None => {
            env.traits.push(crate::traits::Trait::IfNotResolved {
                condition: rest.to_string(),
            });
            return;
        }
    };
    if !final_result {
        env.suppress_until_eol = true;
        return;
    }
    // Condition resolves true: if there's an inline body (the rest of the
    // condition string after the operator + RHS), re-dispatch it.
    if let Some(body) = extract_inline_body(rest) {
        let body = body.trim().to_string();
        if !body.is_empty() && !body.starts_with('(') {
            crate::interp::interpret_line(&body, env);
        }
    }
}

fn evaluate(rest: &str, env: &Environment) -> Option<bool> {
    let trimmed = rest.trim_start();

    if let Some(after) = strip_kw(trimmed, "defined") {
        let var = next_token(after).unwrap_or("");
        if var.is_empty() {
            return None;
        }
        return Some(env.contains_var(var));
    }

    if let Some(after) = strip_kw(trimmed, "exist") {
        let path = next_token(after).unwrap_or("");
        if path.is_empty() {
            return None;
        }
        return Some(
            env.modified_filesystem
                .keys()
                .any(|key| key.len() == path.len() && key.eq_ignore_ascii_case(path)),
        );
    }

    if strip_kw(trimmed, "errorlevel").is_some() {
        return Some(false);
    }

    if strip_kw(trimmed, "cmdextversion").is_some() {
        return Some(true);
    }

    let (case_insensitive, body) = if let Some(after) = strip_kw(trimmed, "/i") {
        (true, after.trim_start())
    } else {
        (false, trimmed)
    };
    if let Some(eq_pos) = body.find("==") {
        let lhs = body[..eq_pos].trim().trim_matches('"');
        let rhs_full = body[eq_pos + 2..].trim_start();
        let rhs_end = token_end(rhs_full);
        let rhs = rhs_full[..rhs_end].trim().trim_matches('"');
        if lhs.contains('%') || lhs.contains('!') || rhs.contains('%') || rhs.contains('!') {
            return None;
        }
        let eq = if case_insensitive {
            lhs.eq_ignore_ascii_case(rhs)
        } else {
            lhs == rhs
        };
        return Some(eq);
    }

    // Relational operators: EQU NEQ LSS LEQ GTR GEQ (case-insensitive, word-bounded)
    let upper = body.to_ascii_uppercase();
    for (op_str, op_kind) in [
        (" EQU ", "eq"),
        (" NEQ ", "ne"),
        (" LSS ", "lt"),
        (" LEQ ", "le"),
        (" GTR ", "gt"),
        (" GEQ ", "ge"),
    ] {
        if let Some(pos) = upper.find(op_str) {
            let lhs = body[..pos].trim().trim_matches('"');
            let rhs_start = pos + op_str.len();
            let rhs_full = body[rhs_start..].trim_start();
            let rhs_end = token_end(rhs_full);
            let rhs = rhs_full[..rhs_end].trim().trim_matches('"');
            if lhs.contains('%') || lhs.contains('!') || rhs.contains('%') || rhs.contains('!') {
                return None;
            }
            // Try numeric first
            let l_n = lhs.parse::<i64>().ok();
            let r_n = rhs.parse::<i64>().ok();
            if let (Some(l), Some(r)) = (l_n, r_n) {
                return Some(match op_kind {
                    "eq" => l == r,
                    "ne" => l != r,
                    "lt" => l < r,
                    "le" => l <= r,
                    "gt" => l > r,
                    "ge" => l >= r,
                    _ => return None,
                });
            }
            // Fall back to case-insensitive string compare for eq/ne
            if case_insensitive {
                return Some(match op_kind {
                    "eq" => lhs.eq_ignore_ascii_case(rhs),
                    "ne" => !lhs.eq_ignore_ascii_case(rhs),
                    _ => return None,
                });
            }
            return Some(match op_kind {
                "eq" => lhs == rhs,
                "ne" => lhs != rhs,
                _ => return None,
            });
        }
    }

    None
}

fn token_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return 0;
    };
    if matches!(first, b'"' | b'\'') {
        for (idx, byte) in rest.iter().copied().enumerate() {
            if byte == first {
                return idx + 2;
            }
        }
        return bytes.len();
    }
    for (idx, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_whitespace() || byte == b')' {
            return idx;
        }
    }
    bytes.len()
}

fn strip_kw<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    if s.len() < kw.len() {
        return None;
    }
    if !s[..kw.len()].eq_ignore_ascii_case(kw) {
        return None;
    }
    let rest = &s[kw.len()..];
    if rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t') {
        return Some(rest);
    }
    None
}

fn next_token(s: &str) -> Option<&str> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix('"') {
        let end = rest
            .as_bytes()
            .iter()
            .position(|b| *b == b'"')
            .unwrap_or(rest.len());
        return Some(&rest[..end]);
    }
    if let Some(rest) = s.strip_prefix('\'') {
        let end = rest
            .as_bytes()
            .iter()
            .position(|b| *b == b'\'')
            .unwrap_or(rest.len());
        return Some(&rest[..end]);
    }
    let end = s
        .as_bytes()
        .iter()
        .position(|b| b.is_ascii_whitespace() || *b == b')')
        .unwrap_or(s.len());
    Some(&s[..end])
}

/// Given the `rest` of an `if` statement (everything after `if [not]`),
/// return the inline body that follows the condition. Returns `None` when
/// the condition is followed by `(` (block form) or nothing.
fn extract_inline_body(rest: &str) -> Option<String> {
    let trimmed = rest.trim_start();

    // defined X / exist X / errorlevel N / cmdextversion N
    // body is everything after the single operand
    for kw in ["defined", "exist", "errorlevel", "cmdextversion"] {
        if let Some(after_kw) = strip_kw(trimmed, kw) {
            if after_kw.starts_with(' ') || after_kw.starts_with('\t') {
                let rest_after_kw = after_kw.trim_start();
                let body = skip_one_token(rest_after_kw);
                return (!body.is_empty()).then(|| body.to_string());
            }
        }
    }

    // optional /i prefix
    let rest2 = if let Some(after_i) = strip_kw(trimmed, "/i") {
        after_i.trim_start()
    } else {
        trimmed
    };

    // "lhs" == "rhs" body
    if let Some(eq_pos) = rest2.find("==") {
        let after = rest2[eq_pos + 2..].trim_start();
        return Some(skip_one_token(after).to_string());
    }

    // EQU / NEQ / LSS / LEQ / GTR / GEQ body
    let upper = rest2.to_ascii_uppercase();
    for op in [" EQU ", " NEQ ", " LSS ", " LEQ ", " GTR ", " GEQ "] {
        if let Some(pos) = upper.find(op) {
            let after = rest2[pos + op.len()..].trim_start();
            return Some(skip_one_token(after).to_string());
        }
    }

    None
}

/// Skip one whitespace-delimited token (quoted or unquoted) and return
/// everything that follows, with leading whitespace stripped.
fn skip_one_token(s: &str) -> &str {
    let s = s.trim_start();
    if let Some(inner) = s.strip_prefix('"') {
        if let Some(end) = inner.find('"') {
            return inner[end + 1..].trim_start();
        }
        return "";
    }
    if let Some(inner) = s.strip_prefix('\'') {
        if let Some(end) = inner.find('\'') {
            return inner[end + 1..].trim_start();
        }
        return "";
    }
    match s.as_bytes().iter().position(|b| b.is_ascii_whitespace()) {
        Some(p) => s[p..].trim_start(),
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::next_token;

    #[test]
    fn next_token_keeps_quoted_unicode_content_intact() {
        assert_eq!(next_token(r#"  "héllo world" tail"#), Some("héllo world"));
        assert_eq!(next_token(r#"  'héllo world' tail"#), Some("héllo world"));
        assert_eq!(next_token(r#"  token) tail"#), Some("token"));
    }
}
