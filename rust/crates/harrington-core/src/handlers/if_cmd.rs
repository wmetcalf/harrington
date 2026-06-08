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
    let inline_body = extract_inline_body(rest);
    let allow_errorlevel_invariants = !inline_body
        .as_deref()
        .is_some_and(|body| body.trim_start().starts_with('('));
    let result = evaluate(rest, env, allow_errorlevel_invariants);
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
        if let Some((_, else_body)) = inline_body
            .as_deref()
            .and_then(split_parenthesized_else_branches)
        {
            dispatch_if_branch(else_body, env);
            return;
        }
        env.suppress_until_eol = true;
        return;
    }
    // Condition resolves true: if there's an inline body (the rest of the
    // condition string after the operator + RHS), re-dispatch it.
    if let Some(body) = inline_body {
        if let Some((then_body, _)) = split_parenthesized_else_branches(&body) {
            dispatch_if_branch(then_body, env);
        } else {
            let body = body.trim().to_string();
            if !body.is_empty() && !body.starts_with('(') {
                crate::interp::interpret_line(&body, env);
            }
        }
    }
}

fn evaluate(rest: &str, env: &Environment, allow_errorlevel_invariants: bool) -> Option<bool> {
    let trimmed = rest.trim_start();

    if let Some(after) = strip_kw(trimmed, "defined") {
        let var = after.split_whitespace().next().unwrap_or("");
        if var.is_empty() {
            return None;
        }
        return Some(env.contains_var(var));
    }

    if let Some(after) = strip_kw(trimmed, "exist") {
        let path = after.split_whitespace().next().unwrap_or("");
        if path.is_empty() {
            return None;
        }
        return Some(
            env.modified_filesystem
                .contains_key(&path.to_ascii_lowercase()),
        );
    }

    if let Some(after) = strip_kw(trimmed, "errorlevel") {
        return match parse_errorlevel_threshold(after) {
            Some(0) => Some(true),
            Some(_) => None,
            None => None,
        };
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
        let rhs_end = rhs_full
            .find(|c: char| c.is_whitespace() || c == ')')
            .unwrap_or(rhs_full.len());
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
            let rhs_end = rhs_full
                .find(|c: char| c.is_whitespace() || c == ')')
                .unwrap_or(rhs_full.len());
            let rhs = rhs_full[..rhs_end].trim().trim_matches('"');
            if allow_errorlevel_invariants {
                if let Some(result) = evaluate_errorlevel_nonnegative_invariant(lhs, op_kind, rhs) {
                    return Some(result);
                }
            }
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
                let l_cmp = lhs.to_ascii_lowercase();
                let r_cmp = rhs.to_ascii_lowercase();
                return Some(match op_kind {
                    "eq" => l_cmp == r_cmp,
                    "ne" => l_cmp != r_cmp,
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

fn evaluate_errorlevel_nonnegative_invariant(lhs: &str, op_kind: &str, rhs: &str) -> Option<bool> {
    let lhs_is_errorlevel = is_errorlevel_reference(lhs);
    let rhs_is_errorlevel = is_errorlevel_reference(rhs);
    let lhs_num = parse_quoted_i64(lhs);
    let rhs_num = parse_quoted_i64(rhs);

    match (
        lhs_is_errorlevel,
        rhs_num,
        lhs_num,
        rhs_is_errorlevel,
        op_kind,
    ) {
        // CMD exit codes are non-negative in the obfuscation gates this targets.
        // Fold only comparisons that are invariant under that model; keep
        // EQU/NEQ and block-form branches dynamic.
        (true, Some(0), _, _, "ge") => Some(true),
        (true, Some(0), _, _, "lt") => Some(false),
        (_, _, Some(0), true, "le") => Some(true),
        (_, _, Some(0), true, "gt") => Some(false),
        _ => None,
    }
}

fn is_errorlevel_reference(s: &str) -> bool {
    let s = s.trim().trim_matches('"').trim_matches('\'');
    let Some(inner) = s
        .strip_prefix('%')
        .and_then(|s| s.strip_suffix('%'))
        .or_else(|| s.strip_prefix('!').and_then(|s| s.strip_suffix('!')))
    else {
        return false;
    };
    inner.eq_ignore_ascii_case("errorlevel")
}

fn parse_quoted_i64(s: &str) -> Option<i64> {
    s.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .parse::<i64>()
        .ok()
}

fn parse_errorlevel_threshold(s: &str) -> Option<i64> {
    let s = s.trim_start();
    if let Some(inner) = s.strip_prefix('"') {
        let end = inner.find('"')?;
        return inner[..end].trim().parse::<i64>().ok();
    }
    if let Some(inner) = s.strip_prefix('\'') {
        let end = inner.find('\'')?;
        return inner[..end].trim().parse::<i64>().ok();
    }
    let end = s
        .find(|c: char| !(c == '+' || c == '-' || c.is_ascii_digit()))
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    s[..end].parse::<i64>().ok()
}

fn strip_kw<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let lower = s.to_ascii_lowercase();
    if let Some(stripped) = lower.strip_prefix(kw) {
        if stripped.is_empty() || stripped.starts_with(' ') || stripped.starts_with('\t') {
            let consumed = s.len() - stripped.len();
            return Some(&s[consumed..]);
        }
    }
    None
}

/// Given the `rest` of an `if` statement (everything after `if [not]`),
/// return the inline body that follows the condition. Returns `None` when
/// the condition is followed by `(` (block form) or nothing.
fn extract_inline_body(rest: &str) -> Option<String> {
    let trimmed = rest.trim_start();

    // defined X / exist X / errorlevel N / cmdextversion N
    // body is everything after the single operand
    for kw in ["defined", "exist", "errorlevel", "cmdextversion"] {
        let lower = trimmed.to_ascii_lowercase();
        if let Some(after_kw) = lower.strip_prefix(kw) {
            if after_kw.starts_with(' ') || after_kw.starts_with('\t') {
                let consumed = trimmed.len() - after_kw.len();
                let rest_after_kw = trimmed[consumed..].trim_start();
                let mut parts = rest_after_kw.splitn(2, |c: char| c.is_whitespace());
                let _operand = parts.next()?;
                return parts.next().map(|s| s.to_string());
            }
        }
    }

    // optional /i prefix
    let rest2 = if let Some(after_i) = trimmed.to_ascii_lowercase().strip_prefix("/i") {
        if after_i.starts_with(' ') || after_i.starts_with('\t') {
            trimmed[2..].trim_start()
        } else {
            trimmed
        }
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
    match s.find(char::is_whitespace) {
        Some(p) => s[p..].trim_start(),
        None => "",
    }
}

fn split_parenthesized_else_branches(body: &str) -> Option<(&str, &str)> {
    let body = body.trim();
    let then_inner = body.strip_prefix('(')?;
    let close = matching_close_paren(then_inner)?;
    let then_body = &then_inner[..close];
    let rest = then_inner[close + 1..].trim_start();
    let else_rest = strip_kw(rest, "else")?.trim_start();
    if let Some(else_inner) = else_rest.strip_prefix('(') {
        let else_close = matching_close_paren(else_inner)?;
        return Some((then_body, &else_inner[..else_close]));
    }
    Some((then_body, else_rest))
}

fn matching_close_paren(s: &str) -> Option<usize> {
    let mut depth = 1i32;
    let mut in_dq = false;
    let mut in_sq = false;
    let mut escaped = false;
    for (idx, c) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '^' {
            escaped = true;
            continue;
        }
        if c == '"' && !in_sq {
            in_dq = !in_dq;
            continue;
        }
        if c == '\'' && !in_dq {
            in_sq = !in_sq;
            continue;
        }
        if in_dq || in_sq {
            continue;
        }
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn dispatch_if_branch(body: &str, env: &mut Environment) {
    let body = body.trim();
    if !body.is_empty() {
        crate::interp::interpret_line(body, env);
    }
}
