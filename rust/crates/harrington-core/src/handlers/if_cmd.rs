//! `if` handler — evaluates the condition and signals body suppression via env.suppress_until_eol.

use crate::env::Environment;
use crate::handlers::util::{filesystem_entry_for_path, normalize_wildcard_path, wildcard_match};
use crate::lex::lex;
use crate::normalize::normalize_to_string;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex is a compile-time constant; .expect on a literal panic-at-startup is a developer error.
#[allow(clippy::expect_used)]
static IF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[\s@(;,]*if\s+(?P<neg>not\s+)?(?P<rest>.*)$").expect("if regex")
});

pub fn h_if(raw: &str, env: &mut Environment) {
    let Some(caps) = IF_RE.captures(raw) else {
        return;
    };
    let mut negate = caps.name("neg").is_some();
    let original_rest = caps.name("rest").map(|m| m.as_str()).unwrap_or("");
    let mut rest = original_rest;
    let rest_with_slash_i = strip_kw(rest.trim_start(), "/i").and_then(|after_i| {
        let after_not = strip_kw(after_i.trim_start(), "not")?;
        negate = !negate;
        Some(format!("/i {}", after_not.trim_start()))
    });
    if let Some(rest_with_slash_i) = rest_with_slash_i.as_deref() {
        rest = rest_with_slash_i;
    }
    let inline_body = extract_inline_body(rest);
    let allow_errorlevel_invariants = !inline_body
        .as_deref()
        .is_some_and(|body| body.trim_start().starts_with('('));
    let unresolved_unknown_quoted_space_exist = negate
        && inline_body
            .as_deref()
            .is_some_and(|body| body.trim_start().to_ascii_lowercase().starts_with("goto"));
    let result = evaluate(
        rest,
        env,
        allow_errorlevel_invariants,
        unresolved_unknown_quoted_space_exist,
    );
    let final_result = match result {
        Some(b) => {
            if negate {
                !b
            } else {
                b
            }
        }
        None => {
            if looks_like_vbs_if_then(original_rest) {
                return;
            }
            env.traits.push(crate::traits::Trait::IfNotResolved {
                condition: original_rest.to_string(),
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
        } else if let Some(then_body) = parenthesized_branch_body(&body) {
            dispatch_if_branch(then_body, env);
        } else {
            let body = body.trim().to_string();
            if !body.is_empty() && !body.starts_with('(') {
                crate::interp::interpret_line(&body, env);
            }
        }
    }
}

pub(crate) fn inline_body_needs_raw_dispatch(raw: &str) -> bool {
    let Some(caps) = IF_RE.captures(raw) else {
        return false;
    };
    let rest = caps.name("rest").map(|m| m.as_str()).unwrap_or("");
    let Some(body) = extract_inline_body(rest) else {
        return false;
    };
    let body = body.trim();
    if let Some((then_body, else_body)) = split_parenthesized_else_branches(body) {
        return if_body_needs_raw_dispatch(then_body) || if_body_needs_raw_dispatch(else_body);
    }
    if let Some(then_body) = parenthesized_branch_body(body) {
        return if_body_needs_raw_dispatch(then_body);
    }
    if_body_needs_raw_dispatch(body)
}

fn if_body_needs_raw_dispatch(body: &str) -> bool {
    let body = body.trim();
    body.contains('!')
        && (crate::handlers::cmd::extract_cmd_inner(body).is_some()
            || crate::handlers::cmd::start_child_command(body).is_some()
            || crate::handlers::call::call_body(body).is_some())
}

fn evaluate(
    rest: &str,
    env: &Environment,
    allow_errorlevel_invariants: bool,
    unresolved_unknown_quoted_space_exist: bool,
) -> Option<bool> {
    let trimmed = rest.trim_start();

    if let Some(after) = strip_kw(trimmed, "defined") {
        let var = after.split_whitespace().next().unwrap_or("");
        if var.is_empty() {
            return None;
        }
        return Some(env.contains_var(var));
    }

    if let Some(after) = strip_kw(trimmed, "exist") {
        let raw_path = first_condition_token_raw(after)?;
        if raw_path.is_empty() {
            return None;
        }
        let raw_key = raw_path.to_ascii_lowercase();
        let unquoted_path = unquote_condition_token(raw_path);
        let unquoted_key = unquoted_path.to_ascii_lowercase();
        let is_simple_quoted_space =
            is_simple_quoted_token(raw_path) && unquoted_path.contains(char::is_whitespace);
        let exists = tracked_path_exists(raw_path, &raw_key, env)
            || (is_simple_quoted_space && tracked_path_exists(unquoted_path, &unquoted_key, env));
        if !exists && is_simple_quoted_space && unresolved_unknown_quoted_space_exist {
            return None;
        }
        return Some(exists);
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
        let lhs_raw = body[..eq_pos].trim().trim_matches('"');
        let rhs_full = body[eq_pos + 2..].trim_start();
        let rhs_end = rhs_full
            .find(|c: char| c.is_whitespace() || c == ')')
            .unwrap_or(rhs_full.len());
        let rhs_raw = rhs_full[..rhs_end].trim().trim_matches('"');
        let lhs = normalize_comparison_operand(lhs_raw, env)?;
        let rhs = normalize_comparison_operand(rhs_raw, env)?;
        let eq = if case_insensitive {
            lhs.eq_ignore_ascii_case(&rhs)
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
            let lhs_raw = body[..pos].trim().trim_matches('"');
            let rhs_start = pos + op_str.len();
            let rhs_full = body[rhs_start..].trim_start();
            let rhs_end = rhs_full
                .find(|c: char| c.is_whitespace() || c == ')')
                .unwrap_or(rhs_full.len());
            let rhs_raw = rhs_full[..rhs_end].trim().trim_matches('"');
            if allow_errorlevel_invariants {
                if let Some(result) =
                    evaluate_errorlevel_nonnegative_invariant(lhs_raw, op_kind, rhs_raw)
                {
                    return Some(result);
                }
            }
            let lhs = normalize_comparison_operand(lhs_raw, env)?;
            let rhs = normalize_comparison_operand(rhs_raw, env)?;
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

fn tracked_path_exists(path: &str, key: &str, env: &Environment) -> bool {
    env.modified_filesystem.contains_key(key)
        || filesystem_entry_for_path(env, path).is_some()
        || current_dir_nested_path_exists(path, env)
        || current_dir_path_exists(path, env)
        || wildcard_path_exists(path, env)
}

fn current_dir_nested_path_exists(path: &str, env: &Environment) -> bool {
    let Some(stripped) = strip_current_dir_prefix(path) else {
        return false;
    };
    if !stripped.contains(['\\', '/']) {
        return false;
    }
    env.modified_filesystem
        .contains_key(&stripped.to_ascii_lowercase())
        || filesystem_entry_for_path(env, stripped).is_some()
}

fn wildcard_path_exists(pattern: &str, env: &Environment) -> bool {
    if !pattern.contains(['*', '?']) {
        return false;
    }
    if let Some(basename_pattern) = current_dir_basename(pattern) {
        let basename_pattern = normalize_wildcard_path(basename_pattern);
        return env.modified_filesystem.keys().any(|path| {
            windows_basename(path).is_some_and(|name| {
                wildcard_match(&basename_pattern, &normalize_wildcard_path(name))
            })
        });
    }
    let normalized_pattern = normalize_wildcard_path(pattern);
    env.modified_filesystem
        .keys()
        .any(|path| wildcard_match(&normalized_pattern, &normalize_wildcard_path(path)))
}

fn current_dir_path_exists(path: &str, env: &Environment) -> bool {
    let Some(name) = current_dir_basename(path) else {
        return false;
    };
    env.modified_filesystem
        .contains_key(&name.to_ascii_lowercase())
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn looks_like_vbs_if_then(rest: &str) -> bool {
    let trimmed = rest.trim();
    let lower = trimmed.to_ascii_lowercase();
    let Some(before_then) = lower.strip_suffix("then") else {
        return false;
    };
    if !before_then.ends_with(char::is_whitespace) {
        return false;
    }
    let condition = trimmed[..trimmed.len() - "then".len()].trim_end();
    if condition.is_empty() {
        return false;
    }
    let condition_lower = condition.to_ascii_lowercase();
    if ["defined", "exist", "errorlevel", "cmdextversion", "/i"]
        .iter()
        .any(|kw| strip_kw(&condition_lower, kw).is_some())
    {
        return false;
    }
    condition.contains('.') || condition.contains('(') || condition.contains("<>")
}

fn normalize_comparison_operand(operand: &str, env: &Environment) -> Option<String> {
    if operand.contains('!') {
        return None;
    }
    if operand.contains('%') && !has_only_positional_percent_refs(operand) {
        return None;
    }
    if !operand.contains('%') {
        return Some(operand.to_string());
    }
    let mut scratch = env.clone();
    let normalized = normalize_to_string(&lex(operand), &mut scratch);
    if normalized.contains('%') || normalized.contains('!') {
        return None;
    }
    Some(normalized)
}

fn has_only_positional_percent_refs(operand: &str) -> bool {
    let bytes = operand.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        let Some(next) = bytes.get(i + 1).copied() else {
            return false;
        };
        if next == b'%' {
            return false;
        }
        if next == b'*' || next.is_ascii_digit() {
            i += 2;
            continue;
        }
        if next != b'~' {
            return false;
        }
        let mut j = i + 2;
        while let Some(byte) = bytes.get(j) {
            if *byte == b'*' || byte.is_ascii_digit() {
                i = j + 1;
                break;
            }
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'$' | b':' | b'-') {
                j += 1;
                continue;
            }
            return false;
        }
        if i != j + 1 {
            return false;
        }
    }
    true
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
                first_condition_token_raw(rest_after_kw)?;
                return Some(skip_one_token(rest_after_kw).to_string());
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

fn first_condition_token_raw(s: &str) -> Option<&str> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(inner) = s.strip_prefix('"') {
        if let Some(end) = inner.find('"') {
            let after = &inner[end + 1..];
            if after.is_empty()
                || after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_whitespace() || c == ')')
            {
                return Some(&s[..end + 2]);
            }
        }
    }
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    Some(&s[..end])
}

fn unquote_condition_token(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(s)
}

fn is_simple_quoted_token(s: &str) -> bool {
    s.len() >= 2 && s.starts_with('"') && s.ends_with('"')
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

fn parenthesized_branch_body(body: &str) -> Option<&str> {
    let body = body.trim();
    let inner = body.strip_prefix('(')?;
    let close = matching_close_paren(inner)?;
    inner.get(..close)
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

#[cfg(test)]
mod tests {
    use super::h_if;
    use crate::env::Environment;

    #[test]
    fn if_accepts_echo_suppressed_prefix() {
        let mut env = Environment::default();

        h_if(r#"@if "a"=="b" echo match"#, &mut env);

        assert!(env.suppress_until_eol);
    }
}
