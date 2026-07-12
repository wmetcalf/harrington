//! `set` command handler. Mirrors batch_interpreter.py:interpret_set.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{filesystem_storage_key, starts_with_ascii_case_insensitive};
use crate::traits::Trait;
use crate::util::contains_ascii_case_insensitive;
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
    if starts_with_ascii_case_insensitive(trimmed, "/a") {
        // Skip past "/a" (2 chars) and any leading whitespace
        let after = trimmed[2..].trim_start();
        do_set_a(after, env);
        return;
    }
    if starts_with_ascii_case_insensitive(trimmed, "/p") {
        do_set_p(raw, env);
        return;
    }

    let body = trimmed;

    // Quoted form: set "NAME=VALUE"
    if let Some(inner) = quoted_form(body) {
        if let Some((name, value)) = split_eq(inner) {
            set_assignment(name, value, env);
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
        set_assignment(name, value, env);
    }
}

fn set_assignment(name: &str, value: &str, env: &mut Environment) {
    if unresolved_self_substitution_value(name, value, env) {
        return;
    }
    let value = materialize_direct_self_reference(name, value, env);
    env.set(name, &value);
}

/// `set PATH=prefix;%PATH%` resolves `%PATH%` before assigning the new value.
/// Raw pre-dispatch paths bypass the normal command renderer, so preserve that
/// CMD behavior here rather than storing a recursive variable definition.
pub(crate) fn materialize_direct_self_reference(
    name: &str,
    value: &str,
    env: &mut Environment,
) -> String {
    if !has_direct_self_reference(name, value, env) {
        return value.to_string();
    }
    crate::normalize::normalize_to_string(&crate::lex::lex(value), env)
}

pub(crate) fn has_direct_self_reference(name: &str, value: &str, env: &Environment) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    let percent_ref = format!("%{name}%");
    let delayed_ref = format!("!{name}!");
    contains_ascii_case_insensitive(value, &percent_ref)
        || (env.delayed_expansion && contains_ascii_case_insensitive(value, &delayed_ref))
}

fn unresolved_self_substitution_value(name: &str, value: &str, env: &Environment) -> bool {
    if let Some(existing) = env.get(name) {
        if !existing.contains('%') && !existing.contains('!') {
            return false;
        }
    }
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    let value = value.trim_start();
    if value
        .get(..name.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(name))
        && value[name.len()..].starts_with(':')
        && value[name.len() + 1..].contains('"')
        && value.ends_with('=')
    {
        return true;
    }
    let Some(rest) = value.strip_prefix('%').or_else(|| value.strip_prefix('!')) else {
        return false;
    };
    let Some((candidate, _op)) = rest.split_once(':') else {
        return false;
    };
    candidate.eq_ignore_ascii_case(name)
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
    if !starts_with_ascii_case_insensitive(raw_after_flag, "/p") {
        return;
    }
    let raw_body = raw_after_flag[2..].trim_start();
    let stdout = redirections.stdout.clone();
    let stdin = redirections
        .stdin
        .clone()
        .or_else(|| set_p_inline_stdin(raw_body))
        .or_else(|| set_p_attached_stdin(raw_body));
    let body = strip_set_prefix(&cleaned)
        .and_then(|rest| {
            let after_flag = rest.trim_start();
            starts_with_ascii_case_insensitive(after_flag, "/p")
                .then(|| after_flag[2..].trim_start())
        })
        .unwrap_or(raw_body);
    if stdin
        .as_deref()
        .is_some_and(|path| path.eq_ignore_ascii_case("nul"))
    {
        if let (Some(target), Some(prompt)) = (stdout, set_p_prompt_payload(body)) {
            write_set_p_prompt_redirect(target, prompt.into_bytes(), env);
            if let Some(tail) = unquoted_pipeline_tail(raw) {
                crate::interp::interpret_line(tail, env);
            }
            return;
        }
    }
    let Some(name) = set_p_name(body) else {
        return;
    };
    let Some(stdin) = stdin else {
        env.set(name, &format!("%{name}%"));
        return;
    };
    let Some(value) = first_line_from_tracked_file(&stdin, env) else {
        return;
    };
    env.set(name, &value);
}

fn set_p_prompt_payload(body: &str) -> Option<String> {
    let (_, prompt) = body.split_once('=')?;
    let prompt = prompt.trim_start();
    if prompt.is_empty() {
        return Some(String::new());
    }
    if let Some(rest) = prompt.strip_prefix('"') {
        let end = rest.find('"').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    if let Some(rest) = prompt.strip_prefix('\'') {
        let end = rest.find('\'').unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    let end = prompt.find(['<', '>', '&', '|']).unwrap_or(prompt.len());
    Some(prompt[..end].trim_end().to_string())
}

fn write_set_p_prompt_redirect(
    target: crate::redirect::RedirTarget,
    content: Vec<u8>,
    env: &mut Environment,
) {
    let path = target.path().to_string();
    let append = target.append();
    let cap = env.limits.max_output_bytes as usize;
    let redirected_chunk = if cap > 0 && content.len() > cap {
        env.note_output_capped(cap as u64);
        content[..cap].to_vec()
    } else {
        content.clone()
    };
    env.traits.push(Trait::EchoRedirect {
        content: redirected_chunk,
        target: path.clone(),
        append,
    });

    let key = filesystem_storage_key(&path);
    if append {
        if let Some(FsEntry::Content {
            content: prior,
            append: prior_append,
        }) = env.modified_filesystem.get_mut(&key)
        {
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

fn unquoted_pipeline_tail(raw: &str) -> Option<&str> {
    let mut in_double = false;
    let mut in_single = false;
    for (idx, ch) in raw.char_indices() {
        match ch {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '|' if !in_double && !in_single => {
                let tail = raw[idx + ch.len_utf8()..].trim();
                return (!tail.is_empty()).then_some(tail);
            }
            _ => {}
        }
    }
    None
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

fn set_p_inline_stdin(body: &str) -> Option<String> {
    let mut in_double = false;
    let mut in_single = false;
    for (idx, ch) in body.char_indices() {
        match ch {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '<' if !in_double && !in_single => {
                let target = body[idx + ch.len_utf8()..].trim_start();
                if target.is_empty() {
                    return None;
                }
                if let Some(rest) = target.strip_prefix('"') {
                    let end = rest.find('"')?;
                    return Some(rest[..end].to_string());
                }
                if let Some(rest) = target.strip_prefix('\'') {
                    let end = rest.find('\'')?;
                    return Some(rest[..end].to_string());
                }
                let end = target
                    .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '&' | '|'))
                    .unwrap_or(target.len());
                return (end > 0).then(|| target[..end].to_string());
            }
            _ => {}
        }
    }
    None
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
    use super::{h_set, strip_set_prefix};
    use crate::env::{Config, Environment};

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

    #[test]
    fn raw_self_referential_path_assignment_uses_prior_value() {
        let mut env = Environment::new(&Config::default());
        env.set("BASEDIR", r"C:\Cache");

        h_set(r"set PATH=%BASEDIR%;%BASEDIR%\Scripts;%PATH%", &mut env);

        assert!(env.get("PATH").is_some(), "PATH must remain defined");
        let path = env.get("PATH").unwrap_or_default();
        assert!(
            path.starts_with(r"C:\Cache;C:\Cache\Scripts;C:\WINDOWS\system32"),
            "self-referential assignment retained an unresolved value: {path}"
        );
        assert!(
            !path.contains("%PATH%"),
            "self-referential assignment must not store a recursive reference: {path}"
        );
    }
}
