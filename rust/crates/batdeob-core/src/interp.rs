//! Interpreter — dispatches a normalized command string to its handler.

use crate::env::Environment;
use crate::handlers;
use crate::handlers::util::{
    ends_with_ascii_case_insensitive, filesystem_entry_for_path, filesystem_storage_key,
    split_words, strip_outer_quotes, windows_basename,
};

/// Result of the pre-normalize dispatch hook. Some commands need to operate
/// on the RAW (pre-normalize) command text instead of the normalized text,
/// because normalization strips information (caret, %%, %~f0 self-references)
/// that the handler needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreDispatch {
    /// If true, drive() should skip the normal lex+normalize+interpret_line path
    /// for this command. The pre-dispatch hook handled it fully.
    pub consumed: bool,
    /// Optional child-cmd to push BEFORE the post-dispatch drain. Used by
    /// `cmd /c "..."` to push the inner-as-original-text.
    pub child_cmd_to_push: Option<String>,
    /// If a child cmd is being pushed, should it run with delayed_expansion=true?
    pub child_cmd_delayed: bool,
    /// The command is only a launcher for a non-trivial child that will be
    /// rendered recursively; suppress the launcher line in deob output.
    pub suppress_normalized_output: bool,
}

/// Single pre-normalize dispatch entry point for `drive()`.
///
/// Called on the RAW (pre-normalize) command text. Returns a [`PreDispatch`]
/// that tells `drive()` whether to skip normal dispatch and/or enqueue a child.
pub fn pre_dispatch(raw: &str, env: &mut Environment) -> PreDispatch {
    let mut result = PreDispatch::default();
    if let Some(pre) = pre_dispatch_raw_marker_set(raw, env) {
        return pre;
    }
    if !raw_may_need_pre_dispatch(raw, env) {
        return result;
    }

    if raw_invokes_powershell(raw) {
        crate::handlers::powershell::h_powershell(raw, env);
        result.consumed = true;
        return result;
    }

    // for handler: operates on raw text because lex strips %%A
    if crate::handlers::for_cmd::run_for_from_raw(raw, env) {
        result.consumed = true;
        return result;
    }

    if let Some(child) = conhost_child_command(raw) {
        if raw_invokes_powershell(&child) {
            crate::handlers::powershell::h_powershell(&child, env);
            result.consumed = true;
            return result;
        }
        if let Some(inner) = crate::handlers::cmd::extract_cmd_inner(&child) {
            result.suppress_normalized_output =
                !crate::handlers::cmd::child_is_trivial_for_dedup(&inner);
            result.child_cmd_to_push = Some(inner);
            result.child_cmd_delayed = crate::handlers::cmd::has_v_on_raw(&child);
            result.consumed = true;
            return result;
        }
    }

    if let Some(inners) = crate::handlers::forfiles::extract_forfiles_inners_with_env(raw, env) {
        let original = crate::handlers::forfiles::extract_forfiles_inner(raw);
        let has_substitution = original
            .as_ref()
            .is_some_and(|original| inners.iter().any(|inner| original != inner));
        if has_substitution {
            for inner in inners {
                if let Some(cmd_inner) = crate::handlers::cmd::extract_cmd_inner(&inner) {
                    env.exec_cmd.push(unescape_outer_caret_bangs(&cmd_inner));
                    env.exec_cmd_delayed
                        .push(crate::handlers::cmd::has_v_on_raw(&inner));
                } else {
                    env.exec_cmd.push(unescape_outer_caret_bangs(&inner));
                    env.exec_cmd_delayed.push(false);
                }
            }
        } else if let Some(inner) = inners.into_iter().next() {
            result.child_cmd_delayed = crate::handlers::cmd::has_v_on_raw(&inner);
            result.child_cmd_to_push = Some(unescape_outer_caret_bangs(&inner));
        }
    }

    // cmd /c handler: extract child from raw text so var refs aren't expanded
    if let Some(inner) = crate::handlers::cmd::extract_cmd_inner(raw) {
        result.suppress_normalized_output =
            !crate::handlers::cmd::child_is_trivial_for_dedup(&inner);
        result.child_cmd_to_push = Some(inner);
        result.child_cmd_delayed = crate::handlers::cmd::has_v_on_raw(raw);
        // We still want interpret_line to run on the normalized text below
        // (so the line gets rendered to deobfuscated output and the cmd handler
        // emits its trait). The child push happens regardless.
    }

    if crate::handlers::if_cmd::inline_body_needs_raw_dispatch(raw) {
        crate::handlers::if_cmd::h_if(raw, env);
        result.consumed = true;
        return result;
    }

    if let Some(inner) = crate::handlers::wmic::wmic_process_create_inner(raw) {
        if inner.contains('!')
            && (crate::handlers::cmd::extract_cmd_inner(&inner).is_some()
                || crate::handlers::cmd::start_child_command(&inner).is_some()
                || crate::handlers::call::call_body(&inner).is_some())
        {
            crate::handlers::wmic::h_wmic(raw, env);
            result.consumed = true;
            return result;
        }
    }

    if let Some(inner) = crate::handlers::cmd::start_child_command(raw) {
        if let Some(child) = crate::handlers::cmd::extract_cmd_inner(inner) {
            result.suppress_normalized_output =
                !crate::handlers::cmd::child_is_trivial_for_dedup(&child);
        }
        crate::handlers::cmd::h_start(raw, env);
        result.consumed = true;
        return result;
    }

    if crate::handlers::bitsadmin::h_bitsadmin_preserve_escaped_notify(raw, env) {
        result.consumed = true;
        return result;
    }

    if replay_copied_filesystem_alias(raw, env) {
        result.consumed = true;
        return result;
    }

    if let Some((_time, command)) = crate::handlers::passthrough::at_scheduled_command(raw) {
        if command.contains('!') && crate::handlers::cmd::extract_cmd_inner(&command).is_some() {
            crate::handlers::passthrough::h_at(raw, env);
            result.consumed = true;
            return result;
        }
    }

    if let Some(body) = crate::handlers::call::call_body(raw) {
        let raw_wrapper_needs_bang_preservation = body.contains('!')
            && (crate::handlers::cmd::extract_cmd_inner(body).is_some()
                || crate::handlers::cmd::start_child_command(body).is_some());
        if raw_wrapper_needs_bang_preservation {
            crate::handlers::call::h_call(raw, env);
            result.consumed = true;
            return result;
        }
    }

    if let Some((_host, command)) = crate::handlers::passthrough::psexec_child_command(raw) {
        if command.contains('!')
            && (crate::handlers::cmd::extract_cmd_inner(&command).is_some()
                || crate::handlers::cmd::start_child_command(&command).is_some()
                || crate::handlers::call::call_body(&command).is_some())
        {
            crate::handlers::passthrough::h_psexec(raw, env);
            result.consumed = true;
            return result;
        }
    }

    if let Some((_host, command)) = crate::handlers::passthrough::winrs_child_command(raw) {
        if command.contains('!')
            && (crate::handlers::cmd::extract_cmd_inner(&command).is_some()
                || crate::handlers::cmd::start_child_command(&command).is_some()
                || crate::handlers::call::call_body(&command).is_some())
        {
            crate::handlers::passthrough::h_winrs(raw, env);
            result.consumed = true;
            return result;
        }
    }

    if let Some((_host, command)) = crate::handlers::passthrough::winrm_child_command(raw) {
        if command.contains('!')
            && (crate::handlers::cmd::extract_cmd_inner(&command).is_some()
                || crate::handlers::cmd::start_child_command(&command).is_some()
                || crate::handlers::call::call_body(&command).is_some())
        {
            crate::handlers::passthrough::h_winrm(raw, env);
            result.consumed = true;
            return result;
        }
    }

    if let Some((_service_name, command)) = crate::handlers::passthrough::sc_service_binpath(raw)
        .or_else(|| crate::handlers::passthrough::sc_failure_command(raw))
    {
        if command.contains('!')
            && (crate::handlers::cmd::extract_cmd_inner(&command).is_some()
                || crate::handlers::cmd::start_child_command(&command).is_some()
                || crate::handlers::call::call_body(&command).is_some())
        {
            crate::handlers::passthrough::h_sc(raw, env);
            result.consumed = true;
            return result;
        }
    }

    result
}

pub(crate) fn pre_dispatch_raw_marker_set(raw: &str, env: &mut Environment) -> Option<PreDispatch> {
    if consume_raw_caret_percent_marker_set(raw, env) || consume_raw_self_substitution_set(raw, env)
    {
        Some(PreDispatch {
            consumed: true,
            suppress_normalized_output: true,
            ..PreDispatch::default()
        })
    } else if consume_marker_polluted_set_command(raw, env) {
        Some(PreDispatch {
            consumed: true,
            ..PreDispatch::default()
        })
    } else {
        None
    }
}

fn consume_marker_polluted_set_command(raw: &str, env: &mut Environment) -> bool {
    let trimmed = raw.trim_start_matches(|c: char| {
        c == '(' || c == '@' || c == ';' || c == ',' || c.is_whitespace()
    });
    let Some((token, rest)) = split_marker_polluted_command_token(trimmed) else {
        return false;
    };
    if token.eq_ignore_ascii_case("set") || token.is_ascii() {
        return false;
    }
    let cleaned: String = token
        .chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .collect();
    if !cleaned.eq_ignore_ascii_case("set") {
        return false;
    }
    let body = rest.trim_start();
    if body.is_empty()
        || body
            .as_bytes()
            .first()
            .is_some_and(|b| *b == b'/' || *b == b'?')
    {
        return false;
    }
    let synthetic = format!("set{rest}");
    crate::handlers::set::h_set(&synthetic, env);
    true
}

fn split_marker_polluted_command_token(command: &str) -> Option<(&str, &str)> {
    let mut end = None;
    for (idx, ch) in command.char_indices() {
        if ch.is_whitespace() || matches!(ch, '"' | '/' | '<' | '>' | '&' | '|') {
            end = Some(idx);
            break;
        }
    }
    let end = end.unwrap_or(command.len());
    (end > 0).then_some((&command[..end], &command[end..]))
}

fn consume_raw_caret_percent_marker_set(raw: &str, env: &mut Environment) -> bool {
    let Some((command, rest)) = caret_percent_marker_command_prefix(raw) else {
        return false;
    };
    if !command.eq_ignore_ascii_case("set") {
        return false;
    }
    let trimmed = rest.trim_start();
    if trimmed.is_empty()
        || !(trimmed.starts_with('"')
            || trimmed
                .get(..2)
                .is_some_and(|flag| flag.eq_ignore_ascii_case("/a"))
            || trimmed
                .get(..2)
                .is_some_and(|flag| flag.eq_ignore_ascii_case("/p")))
    {
        return false;
    }

    let synthetic = format!("set{rest}");
    crate::handlers::set::h_set(&synthetic, env);
    true
}

pub(crate) fn decode_caret_percent_marker_command(raw: &str) -> Option<String> {
    let (command, rest) = caret_percent_marker_command_prefix(raw)?;
    Some(format!("{command}{rest}"))
}

fn caret_percent_marker_command_prefix(raw: &str) -> Option<(String, &str)> {
    let prefix_len = raw
        .char_indices()
        .find(|(_, ch)| !matches!(ch, '@' | '(' | ';' | ',' if ch.is_ascii()))
        .map_or(raw.len(), |(idx, _)| idx);
    let leading = &raw[..prefix_len];
    if !leading
        .chars()
        .all(|ch| matches!(ch, '@' | '(' | ';' | ',' | ' ' | '\t'))
    {
        return None;
    }
    let mut cursor = prefix_len;
    let mut command = String::new();
    loop {
        let rest = raw.get(cursor..)?;
        let after_marker = rest.strip_prefix("%^%")?;
        let mut chars = after_marker.char_indices();
        let (_, letter) = chars.next()?;
        if !letter.is_ascii_alphabetic() {
            return None;
        }
        command.push(letter);
        let letter_len = letter.len_utf8();
        let noise_start = cursor + "%^%".len() + letter_len;
        let noise = raw.get(noise_start..)?;
        if let Some(next_pos) = noise.find("%%^%") {
            cursor = noise_start + next_pos + 1;
            if command.len() > 16 {
                return None;
            }
            continue;
        }
        let end_pos = noise.char_indices().find_map(|(idx, ch)| {
            (ch == '%')
                .then(|| noise[idx + 1..].chars().next())
                .flatten()
                .filter(|next| {
                    next.is_ascii_whitespace()
                        || matches!(*next, '"' | '/' | '-' | ':' | '>' | '<' | '&' | '|')
                })
                .map(|_| idx)
        })?;
        let rest_start = noise_start + end_pos + 1;
        let tail = raw.get(rest_start..)?;
        return (command.len() >= 2).then_some((command, tail));
    }
}

fn consume_raw_self_substitution_set(raw: &str, env: &mut Environment) -> bool {
    let Some(rest) = strip_raw_set_prefix(raw) else {
        return false;
    };
    let body = rest.trim_start();
    if body
        .as_bytes()
        .first()
        .is_some_and(|b| *b == b'/' || *b == b'?')
    {
        return false;
    }
    let Some(inner) = raw_set_quoted_body(body) else {
        return false;
    };
    let Some((target, value)) = inner.split_once('=') else {
        return false;
    };
    let target = target.trim();
    if target.is_empty() {
        return false;
    }
    let value = value.trim();
    if !target.is_ascii() {
        let cleaned_target = crate::marker_noise::strip_line(target);
        if cleaned_target != target
            && !cleaned_target.is_empty()
            && cleaned_target
                .bytes()
                .all(|b| !matches!(b, b'%' | b'!' | b'^' | b'&' | b'|' | b'<' | b'>' | b'"'))
        {
            env.set(&cleaned_target, value);
            return true;
        }
    }
    if should_preserve_raw_marker_set_value(value) {
        env.set(target, value);
        return true;
    }
    if !value.starts_with('%') || !value.ends_with('%') || value.len() < 3 {
        return false;
    }
    let body = &value[1..value.len() - 1];
    let Some((source, op)) = body.split_once(':') else {
        return false;
    };
    if !source.eq_ignore_ascii_case(target) {
        return false;
    }
    let Some(crate::lex::VarOp::Substitute {
        needle,
        replacement,
        leading_wildcard,
    }) = crate::lex::parse_substitute(op)
    else {
        return false;
    };
    let Some(raw_value) = env.get(source) else {
        return false;
    };
    let cleaned =
        crate::normalize::apply_substitute(&raw_value, &needle, &replacement, leading_wildcard);
    if cleaned == raw_value {
        return false;
    }
    env.set(target, &cleaned);
    true
}

fn should_preserve_raw_marker_set_value(value: &str) -> bool {
    value.len() <= 64 * 1024
        && !value.is_ascii()
        && (value.contains('$')
            || value.contains("::")
            || value.contains('[')
            || value.contains(']')
            || value.contains('(')
            || value.contains(')')
            || value.contains(".")
            || value.contains("<<BASE64_")
            || crate::util::contains_ascii_case_insensitive(value, "powershell"))
}

fn strip_raw_set_prefix(raw: &str) -> Option<&str> {
    let raw = raw.trim_start_matches(|c: char| {
        c == '(' || c == '@' || c == ';' || c == ',' || c.is_whitespace()
    });
    let prefix = raw.get(..3)?;
    if !prefix.eq_ignore_ascii_case("set") {
        return None;
    }
    let rest = &raw[3..];
    if rest.is_empty()
        || rest
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_whitespace() || *c == b'/' || *c == b'"')
    {
        Some(rest)
    } else {
        None
    }
}

fn raw_set_quoted_body(body: &str) -> Option<&str> {
    let body = body.trim_start();
    let rest = body.strip_prefix('"')?;
    let end = rest.rfind('"')?;
    Some(&rest[..end])
}

fn raw_may_need_pre_dispatch(raw: &str, env: &Environment) -> bool {
    if crate::handlers::for_cmd::raw_might_start_with_for(raw) {
        return true;
    }
    let Some(name) = command_name(raw) else {
        return false;
    };
    if command_basename_is(&name, "powershell")
        || command_basename_is(&name, "pwsh")
        || command_basename_is(&name, "for")
        || command_basename_is(&name, "forfiles")
        || command_basename_is(&name, "conhost")
        || command_basename_is(&name, "cmd")
        || command_basename_is(&name, "if")
        || command_basename_is(&name, "wmic")
        || command_basename_is(&name, "start")
        || command_basename_is(&name, "bitsadmin")
        || command_basename_is(&name, "at")
        || command_basename_is(&name, "call")
        || command_basename_is(&name, "psexec")
        || command_basename_is(&name, "winrs")
        || command_basename_is(&name, "winrm")
        || command_basename_is(&name, "sc")
    {
        return true;
    }
    let lower_name = name.to_ascii_lowercase();
    if lower_name == "%comspec%"
        || lower_name == "!comspec!"
        || lower_name.contains("comspec:")
        || lower_name.ends_with(r"\cmd.exe")
        || lower_name.ends_with("/cmd.exe")
    {
        return true;
    }
    if !has_copied_pre_dispatch_alias_source(env) {
        return false;
    }
    command_matches_copied_alias(&name, env, &["robocopy", "robocopy.exe"])
        || command_matches_copied_alias(&name, env, &["replace", "replace.exe"])
        || command_matches_copied_alias(&name, env, &["xcopy", "xcopy.exe"])
        || command_matches_copied_alias(&name, env, &["at", "at.exe"])
}

fn has_copied_pre_dispatch_alias_source(env: &Environment) -> bool {
    env.traits.iter().any(|t| {
        let crate::traits::Trait::WindowsUtilManip { src, .. } = t else {
            return false;
        };
        let src_base = command_basename_lower(src);
        matches!(
            src_base.as_str(),
            "robocopy"
                | "robocopy.exe"
                | "replace"
                | "replace.exe"
                | "xcopy"
                | "xcopy.exe"
                | "at"
                | "at.exe"
        )
    })
}

pub fn should_preserve_raw_at_schedule(raw: &str, env: &Environment) -> bool {
    let Some(replay) = at_schedule_replay_command(raw, env) else {
        return false;
    };
    let Some((_time, command)) = crate::handlers::passthrough::at_scheduled_command(&replay) else {
        return false;
    };
    command.contains("&&") && crate::handlers::cmd::extract_cmd_inner(&command).is_some()
}

fn at_schedule_replay_command(raw: &str, env: &Environment) -> Option<String> {
    let name = command_name(raw)?;
    if command_basename_is(&name, "at") {
        return Some(raw.trim().to_string());
    }
    if !command_matches_copied_alias(&name, env, &["at", "at.exe"]) {
        return None;
    }
    let rest_start = raw.find(&name)? + name.len();
    let rest = raw[rest_start..].trim_start();
    (!rest.is_empty()).then(|| format!("at.exe {rest}"))
}

fn unescape_outer_caret_bangs(command: &str) -> String {
    command.replace("^!", "!")
}

fn replay_copied_filesystem_alias(raw: &str, env: &mut Environment) -> bool {
    let Some(name) = command_name(raw) else {
        return false;
    };
    let replay_command = if command_matches_copied_alias(&name, env, &["robocopy", "robocopy.exe"])
    {
        "robocopy.exe"
    } else if command_matches_copied_alias(&name, env, &["replace", "replace.exe"]) {
        "replace.exe"
    } else if command_matches_copied_alias(&name, env, &["xcopy", "xcopy.exe"]) {
        "xcopy.exe"
    } else if command_matches_copied_alias(&name, env, &["at", "at.exe"]) {
        "at.exe"
    } else {
        return false;
    };
    let Some(rest_start) = raw.find(&name).map(|idx| idx + name.len()) else {
        return false;
    };
    let rest = raw[rest_start..].trim_start();
    if rest.is_empty() {
        return false;
    }
    push_manipulated_exec_once(env, raw, &name);
    let replay = format!("{replay_command} {rest}");
    match replay_command {
        "robocopy.exe" => crate::handlers::robocopy::h_robocopy(&replay, env),
        "replace.exe" => crate::handlers::replace::h_replace(&replay, env),
        "xcopy.exe" => crate::handlers::copy::h_xcopy(&replay, env),
        "at.exe" => crate::handlers::passthrough::h_at(&replay, env),
        _ => return false,
    }
    true
}

fn command_matches_copied_alias(name: &str, env: &Environment, source_bases: &[&str]) -> bool {
    let name_trimmed = strip_outer_quotes(name);
    let name_base = command_basename_lower(name_trimmed);
    env.traits.iter().any(|t| {
        let crate::traits::Trait::WindowsUtilManip { src, dst, .. } = t else {
            return false;
        };
        let src_base = command_basename_lower(src);
        if !source_bases
            .iter()
            .any(|base| src_base.eq_ignore_ascii_case(base))
        {
            return false;
        }
        let dst_trimmed = strip_outer_quotes(dst);
        name_trimmed.eq_ignore_ascii_case(dst_trimmed)
            || name_base.eq_ignore_ascii_case(&command_basename_lower(dst_trimmed))
    })
}

fn push_manipulated_exec_once(env: &mut Environment, raw: &str, target: &str) {
    let target = strip_outer_quotes(target).to_string();
    if env.traits.iter().any(|t| {
        matches!(
            t,
            crate::traits::Trait::ManipulatedExec {
                cmd: existing_cmd,
                target: existing_target
            } if existing_cmd == raw && existing_target.eq_ignore_ascii_case(&target)
        )
    }) {
        return;
    }
    env.traits.push(crate::traits::Trait::ManipulatedExec {
        cmd: raw.to_string(),
        target,
    });
}

fn command_basename_lower(path: &str) -> String {
    windows_basename(path)
        .unwrap_or(path)
        .trim_end_matches(['.', ' '])
        .to_ascii_lowercase()
}

fn conhost_child_command(raw: &str) -> Option<String> {
    let name = command_name(raw)?;
    if !command_basename_is(&name, "conhost") {
        return None;
    }

    for (start, end) in command_token_spans(raw).into_iter().skip(1) {
        let token = raw[start..end].trim_matches(['"', '\'']);
        if command_basename_is(token, "cmd")
            || command_basename_is(token, "powershell")
            || command_basename_is(token, "pwsh")
            || crate::handlers::cmd::extract_cmd_inner(&raw[start..]).is_some()
        {
            return Some(raw[start..].trim().to_string());
        }
    }
    None
}

fn command_token_spans(raw: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        while raw.as_bytes().get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= raw.len() {
            break;
        }
        let start = i;
        let quote = raw.as_bytes()[i];
        if quote == b'"' || quote == b'\'' {
            i += 1;
            while i < raw.len() {
                let ch = raw.as_bytes()[i];
                i += 1;
                if ch == quote {
                    break;
                }
            }
        } else {
            while i < raw.len() && !raw.as_bytes()[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        spans.push((start, i));
    }
    spans
}

fn raw_invokes_powershell(raw: &str) -> bool {
    let Some(name) = command_name(raw) else {
        return false;
    };
    command_basename_is(&name, "powershell") || command_basename_is(&name, "pwsh")
}

fn command_basename_is(name: &str, expected: &str) -> bool {
    let name = name.trim_start_matches(['@', '"', '(', '\'']);
    let basename = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let lower = basename.trim_matches(['"', '\'']).to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower) == expected
}

pub fn interpret_line(line: &str, env: &mut Environment) {
    if let Some(tail) = xcopy_pipeline_tail(line) {
        crate::handlers::copy::h_xcopy(tail, env);
    }
    if let Some(payload) = piped_echo_powershell_stdin_payload(line, env) {
        let payload = payload.into_bytes();
        if !env.exec_ps1.iter().any(|existing| existing == &payload) {
            env.exec_ps1.push(payload);
        }
        return;
    }
    let Some(name) = command_name(line) else {
        return;
    };
    if let Some(handler) = handlers::lookup(&name) {
        handler(line, env);
        return;
    }
    // Implicit script-host dispatch: when the command name is a path
    // ending in `.jS`/`.js`/`.vbs`/`.vbe`/`.wsf`/`.wsh`/`.hta`/`.chm` and
    // there's no matching handler (which is the case for `call X.jS`
    // — the call handler re-feeds via interpret_line which lands here),
    // Windows shellexecutes wscript/cscript/mshta to run it. Surface
    // the implicit launcher as a trait so CAPE-vs-batdeob compare can
    // see the spawned binary; the URL/payload extraction has already
    // happened via the recursive certutil-decode + JS scan path.
    let has_wscript_exec = env
        .traits
        .iter()
        .any(|t| matches!(t, crate::traits::Trait::WscriptExec { src } if src.eq_ignore_ascii_case(&name)));
    let has_mshta_lolbas = env
        .traits
        .iter()
        .any(|t| matches!(t, crate::traits::Trait::Lolbas { name: n, .. } if n == "mshta"));
    let has_hh_lolbas = env
        .traits
        .iter()
        .any(|t| matches!(t, crate::traits::Trait::Lolbas { name: n, .. } if n == "hh"));
    if let Some(ext) =
        script_host_extension(&name).filter(|_| implicit_script_target_is_plausible(&name))
    {
        match ext {
            "js" | "jse" | "wsf" | "wsh" | "vbs" | "vbe" if !has_wscript_exec => {
                push_implicit_download_source_url(&name, env);
                queue_implicit_script_content(&name, ext, env);
                env.traits
                    .push(crate::traits::Trait::WscriptExec { src: name.clone() });
            }
            "hta" if !has_mshta_lolbas => {
                push_implicit_download_source_url(&name, env);
                // Mshta trait exists but takes different fields — use a Lolbas.
                env.traits.push(crate::traits::Trait::Lolbas {
                    name: "mshta".to_string(),
                    cmd: name.clone(),
                });
            }
            "chm" if !has_hh_lolbas => {
                push_implicit_download_source_url(&name, env);
                env.traits.push(crate::traits::Trait::Lolbas {
                    name: "hh".to_string(),
                    cmd: name.clone(),
                });
            }
            _ => {}
        }
    }
    capture_synthetic_stdout_redirect(line, env);
    capture_synthetic_option_output(line, env);
}

fn implicit_script_target_is_plausible(name: &str) -> bool {
    let target = name.trim_matches(['"', '\'']).trim();
    if target.is_empty()
        || target.starts_with('=')
        || target.starts_with("://")
        || target.starts_with('-')
    {
        return false;
    }
    if let Some(idx) = target.find("://") {
        let scheme = &target[..idx];
        return matches!(
            scheme.to_ascii_lowercase().as_str(),
            "http" | "https" | "file"
        );
    }
    true
}

fn push_implicit_download_source_url(path: &str, env: &mut Environment) {
    let Some(url) = prior_download_url(path, env) else {
        return;
    };
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            crate::traits::Trait::UrlArgument { cmd, url: existing }
                if cmd == path && existing == &url
        )
    }) {
        env.traits.push(crate::traits::Trait::UrlArgument {
            cmd: path.to_string(),
            url,
        });
    }
}

fn prior_download_url(path: &str, env: &Environment) -> Option<String> {
    if let Some(crate::env::FsEntry::Download { src }) = filesystem_entry_for_path(env, path) {
        return Some(src.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return match filesystem_entry_for_path(env, stripped) {
                Some(crate::env::FsEntry::Download { src }) => Some(src.clone()),
                _ => None,
            };
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return prior_download_url_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    prior_download_url_by_basename(path, env)
}

fn prior_download_url_by_basename(path: &str, env: &Environment) -> Option<String> {
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|name| name.eq_ignore_ascii_case(path))
                .then_some(entry)
        })
        .and_then(|entry| match entry {
            crate::env::FsEntry::Download { src } => Some(src.clone()),
            _ => None,
        })
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn queue_implicit_script_content(path: &str, ext: &str, env: &mut Environment) {
    let Some(content) = tracked_script_content(path, env) else {
        return;
    };
    match ext {
        "js" | "jse" => {
            if env.push_extracted_jscript(content.clone()) {
                push_unique_payload(&mut env.exec_jscript, content);
            }
        }
        "vbs" | "vbe" => {
            if env.push_extracted_vbs(content.clone()) {
                push_unique_payload(&mut env.exec_vbs, content);
            }
        }
        _ => {}
    }
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_for_path_following_copy(path, env) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_for_path_following_copy(stripped, env);
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return tracked_script_content_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    tracked_script_content_by_basename(path, env)
}

fn tracked_script_content_by_basename(path: &str, env: &Environment) -> Option<Vec<u8>> {
    for (tracked_path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(tracked_path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(path) {
            return content_from_entry_following_copy(Some(entry), env);
        }
    }
    None
}

fn content_for_path_following_copy(path: &str, env: &Environment) -> Option<Vec<u8>> {
    content_from_entry_following_copy(filesystem_entry_for_path(env, path), env)
}

fn content_from_entry_following_copy(
    entry: Option<&crate::env::FsEntry>,
    env: &Environment,
) -> Option<Vec<u8>> {
    let mut entry = entry;
    for _ in 0..8 {
        match entry {
            Some(crate::env::FsEntry::Content { content, .. })
            | Some(crate::env::FsEntry::Decoded { content, .. }) => return Some(content.clone()),
            Some(crate::env::FsEntry::Copy { src }) => {
                entry = filesystem_entry_for_path(env, src);
            }
            _ => return None,
        }
    }
    None
}

fn push_unique_payload(payloads: &mut Vec<Vec<u8>>, payload: Vec<u8>) {
    if !payloads.iter().any(|existing| existing == &payload) {
        payloads.push(payload);
    }
}

pub(crate) fn script_host_extension(name: &str) -> Option<&'static str> {
    let basename = windows_basename(name)?.trim_end_matches(['.', ' ']);
    if ends_with_ascii_case_insensitive(basename, ".js") {
        return Some("js");
    }
    if ends_with_ascii_case_insensitive(basename, ".jse") {
        return Some("jse");
    }
    if ends_with_ascii_case_insensitive(basename, ".wsf") {
        return Some("wsf");
    }
    if ends_with_ascii_case_insensitive(basename, ".wsh") {
        return Some("wsh");
    }
    if ends_with_ascii_case_insensitive(basename, ".vbs") {
        return Some("vbs");
    }
    if ends_with_ascii_case_insensitive(basename, ".vbe") {
        return Some("vbe");
    }
    if ends_with_ascii_case_insensitive(basename, ".hta") {
        return Some("hta");
    }
    if ends_with_ascii_case_insensitive(basename, ".chm") {
        return Some("chm");
    }
    None
}

fn xcopy_pipeline_tail(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once('|')?;
    let tail = tail.trim();
    let name = command_name(tail)?;
    let base = windows_basename(&name)?;
    let base = base.trim_end_matches('.');
    let base = if ends_with_ascii_case_insensitive(base, ".exe") {
        &base[..base.len() - 4]
    } else {
        base
    };
    if base.eq_ignore_ascii_case("xcopy") {
        Some(tail)
    } else {
        None
    }
}

fn piped_echo_powershell_stdin_payload(line: &str, env: &Environment) -> Option<String> {
    let (head, tail) = line.split_once('|')?;
    let payload = echo_payload(head)?;
    let tail = tail.trim();
    let command = crate::handlers::cmd::extract_cmd_inner(tail).unwrap_or_else(|| tail.to_string());
    if !raw_invokes_powershell(&command) || !powershell_reads_stdin(&command) {
        return None;
    }
    Some(expand_piped_powershell_env_refs(payload, env))
}

fn echo_payload(command: &str) -> Option<&str> {
    let command = command.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
    });
    let rest = command.get(4..)?;
    if !command[..4].eq_ignore_ascii_case("echo")
        || rest
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return None;
    }
    Some(rest.trim_start_matches(['.', ':', '/', '(']).trim_start())
}

fn powershell_reads_stdin(command: &str) -> bool {
    let tokens = split_words(command);
    if tokens.len() <= 1 {
        return true;
    }

    let mut saw_non_mode_arg = false;
    let mut skip_next_value = false;
    for token in tokens.iter().skip(1).map(|token| strip_outer_quotes(token)) {
        if skip_next_value {
            skip_next_value = false;
            continue;
        }
        if token == "-" {
            return true;
        }
        let lower = token.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-command"
                | "-c"
                | "/command"
                | "/c"
                | "-encodedcommand"
                | "-enc"
                | "-e"
                | "/encodedcommand"
                | "/enc"
                | "/e"
                | "-file"
                | "-f"
                | "/file"
                | "/f"
        ) {
            return false;
        }
        if powershell_option_takes_plain_value(&lower) {
            skip_next_value = true;
            continue;
        }
        if !lower.starts_with('-') && !lower.starts_with('/') {
            saw_non_mode_arg = true;
        }
    }
    !saw_non_mode_arg
}

fn powershell_option_takes_plain_value(token: &str) -> bool {
    matches!(
        token,
        "-windowstyle"
            | "-w"
            | "/windowstyle"
            | "/w"
            | "-executionpolicy"
            | "-ep"
            | "/executionpolicy"
            | "/ep"
            | "-inputformat"
            | "-input"
            | "/inputformat"
            | "/input"
            | "-outputformat"
            | "-output"
            | "/outputformat"
            | "/output"
            | "-configurationname"
            | "-config"
            | "/configurationname"
            | "/config"
    )
}

fn expand_piped_powershell_env_refs(payload: &str, env: &Environment) -> String {
    let payload = expand_piped_powershell_batch_refs(payload, env);
    let mut out = String::with_capacity(payload.len());
    let mut i = 0usize;
    while i < payload.len() {
        let Some(rel) = payload[i..].to_ascii_lowercase().find("$env:") else {
            out.push_str(&payload[i..]);
            break;
        };
        let start = i + rel;
        out.push_str(&payload[i..start]);
        let name_start = start + "$env:".len();
        let mut name_end = name_start;
        for (offset, ch) in payload[name_start..].char_indices() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name_end = name_start + offset + ch.len_utf8();
            } else {
                break;
            }
        }
        if name_end == name_start {
            out.push_str("$env:");
            i = name_start;
            continue;
        }
        let name = &payload[name_start..name_end];
        if let Some(value) = env.get(name) {
            out.push('\'');
            out.push_str(&value.replace('\'', "''"));
            out.push('\'');
        } else {
            out.push_str(&payload[start..name_end]);
        }
        i = name_end;
    }
    out
}

fn expand_piped_powershell_batch_refs(payload: &str, env: &Environment) -> String {
    let Some(_) = payload.as_bytes().iter().position(|b| *b == b'%') else {
        return payload.to_string();
    };
    let mut out = String::with_capacity(payload.len());
    let mut i = 0usize;
    while i < payload.len() {
        let Some(rel) = payload[i..].find('%') else {
            out.push_str(&payload[i..]);
            break;
        };
        let start = i + rel;
        out.push_str(&payload[i..start]);
        let name_start = start + 1;
        let Some(end_rel) = payload[name_start..].find('%') else {
            out.push_str(&payload[start..]);
            break;
        };
        let end = name_start + end_rel;
        let name = &payload[name_start..end];
        if !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'(' | b')'))
        {
            if let Some(value) = env.get(name) {
                out.push_str(&value);
            } else {
                out.push_str(&payload[start..=end]);
            }
        } else {
            out.push_str(&payload[start..=end]);
        }
        i = end + 1;
    }
    out
}

fn capture_synthetic_stdout_redirect(line: &str, env: &mut Environment) {
    let (cleaned, redir) = crate::redirect::extract_redirections(line);
    let Some(stdout) = redir.stdout else {
        return;
    };
    let command = cleaned.trim();
    if command.is_empty() || cleaned == line || is_block_delimiter(command) {
        return;
    }
    if !crate::synth::can_run_pipeline(&cleaned) {
        return;
    }
    let lines = crate::synth::run_pipeline(&cleaned, env);
    if lines.is_empty() {
        return;
    }
    write_synthetic_lines(stdout.path(), stdout.append(), lines, env);
}

fn capture_synthetic_option_output(line: &str, env: &mut Environment) {
    let Some((command, output_path)) = sort_output_file_command(line) else {
        return;
    };
    if !crate::synth::can_run_pipeline(&command) {
        return;
    }
    let lines = crate::synth::run_pipeline(&command, env);
    if lines.is_empty() {
        return;
    }
    write_synthetic_lines(&output_path, false, lines, env);
}

fn sort_output_file_command(line: &str) -> Option<(String, String)> {
    let (cleaned, redir) = crate::redirect::extract_redirections(line);
    if redir.stdout.is_some() {
        return None;
    }
    let tokens = split_words(cleaned.trim());
    let cmd = tokens.first()?;
    if !sort_command_name(cmd) {
        return None;
    }
    let mut output_path = None;
    let mut kept = vec!["sort".to_string()];
    let mut i = 1;
    while i < tokens.len() {
        let stripped = strip_outer_quotes(&tokens[i]);
        if stripped.eq_ignore_ascii_case("/o") {
            if let Some(path) = tokens.get(i + 1) {
                output_path = Some(strip_outer_quotes(path).to_string());
                i += 2;
                continue;
            }
        }
        if stripped.len() >= 3 && stripped[..3].eq_ignore_ascii_case("/o:") {
            output_path = Some(strip_outer_quotes(&stripped[3..]).to_string());
            i += 1;
            continue;
        }
        kept.push(tokens[i].clone());
        i += 1;
    }
    output_path.map(|path| (kept.join(" "), path))
}

fn sort_command_name(cmd: &str) -> bool {
    let trimmed = strip_outer_quotes(cmd);
    let basename = windows_basename(trimmed).unwrap_or(trimmed);
    let lower = basename.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower) == "sort"
}

fn write_synthetic_lines(path: &str, append: bool, lines: Vec<String>, env: &mut Environment) {
    let mut content = lines.join("\r\n").into_bytes();
    content.extend_from_slice(b"\r\n");
    let key = filesystem_storage_key(path);
    let cap = env.limits.max_output_bytes as usize;
    if append {
        if let Some(crate::env::FsEntry::Content {
            content: existing,
            append,
        }) = env.modified_filesystem.get_mut(&key)
        {
            // Per-FsEntry cap so a `:loop\necho A>>z.txt\ngoto loop` cannot
            // balloon to GB even when max_output_bytes only limits `out`.
            let room = cap.saturating_sub(existing.len());
            let take = content.len().min(room);
            if take > 0 {
                existing.extend_from_slice(&content[..take]);
            }
            *append = true;
            return;
        }
    }
    let mut bounded = content;
    if bounded.len() > cap {
        bounded.truncate(cap);
    }
    env.modified_filesystem.insert(
        key,
        crate::env::FsEntry::Content {
            content: bounded,
            append,
        },
    );
}

fn is_block_delimiter(command: &str) -> bool {
    matches!(command, "(" | ")")
}

/// Extract the command name from a normalized line: the first token before
/// whitespace, '/' (for `set/p`-style), or a redirection operator.
/// Handles leading redirections by skipping past them to find the actual command.
pub fn command_name(line: &str) -> Option<String> {
    // CMD treats leading `@` (echo-suppress), `;` and `,` (token delimiters),
    // parens from wrapper blocks, and whitespace as ignorable prefix before the command
    // token. Obfuscators interleave them (e.g. `@;@@@set …`), so all must be
    // stripped — stripping only `@`/`(` left `;@@@set` and broke dispatch,
    // which silently dropped `set`-defined alphabet vars in char-substitution
    // packers (mangling the recovered URL).
    let trimmed = line.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ')' || c == ';' || c == ',' || c.is_whitespace()
    });
    if trimmed.is_empty() {
        return None;
    }

    // Skip leading redirections and their targets
    let mut s = trimmed;
    while let Some((op_start, op_len)) = leading_redirection_operator(s) {
        s = &s[op_start + op_len..];
        if s.starts_with('>') {
            s = &s[1..];
        }
        s = s.trim_start();
        let mut in_quotes = false;
        let mut found_space = false;
        let mut target_end = 0;
        for (i, c) in s.char_indices() {
            if c == '"' {
                in_quotes = !in_quotes;
            } else if !in_quotes
                && (c.is_whitespace() || c == '<' || c == '>' || c == '&' || c == '|')
            {
                target_end = i;
                found_space = true;
                break;
            }
        }
        if !found_space {
            target_end = s.len();
        }
        s = &s[target_end..];
        s = s.trim_start();
    }

    if s.is_empty() {
        return None;
    }
    let mut name = String::new();
    if let Some(quote @ ('"' | '\'')) = s.chars().next() {
        let rest = &s[quote.len_utf8()..];
        if let Some(end) = rest.find(quote) {
            name.push_str(&rest[..end]);
        } else {
            for c in rest.chars() {
                if c == '<' || c == '>' || c == '&' || c == '|' {
                    break;
                }
                name.push(c);
            }
        }
    } else {
        for c in s.chars() {
            if c.is_whitespace()
                || (c == '/' && !name.ends_with(':') && !name.contains(":/"))
                || c == ','
                || c == ';'
                || c == '<'
                || c == '>'
                || c == '&'
                || c == '|'
            {
                break;
            }
            name.push(c);
        }
    }
    if name.is_empty() {
        return None;
    }
    let name = name.trim_matches(['"', '\'']).to_string();
    if name
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("echo"))
        && name[4..]
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, '.' | ':' | '/' | '('))
    {
        return Some("echo".to_string());
    }
    // `echo.` (and `echo..` etc.) is a common obfuscation for empty echo output.
    // Strip trailing dots and normalise to "echo" if that's what remains.
    let name_trimmed = name.trim_end_matches('.');
    if name_trimmed.eq_ignore_ascii_case("echo") {
        return Some("echo".to_string());
    }
    Some(name)
}

fn leading_redirection_operator(s: &str) -> Option<(usize, usize)> {
    let mut chars = s.char_indices().peekable();
    while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_digit()) {
        chars.next();
    }
    let (idx, ch) = chars.peek().copied()?;
    if matches!(ch, '<' | '>') {
        Some((idx, ch.len_utf8()))
    } else {
        None
    }
}

#[cfg(test)]
mod pre_dispatch_gate_tests {
    use super::{command_name, pre_dispatch, raw_may_need_pre_dispatch};
    use crate::{Config, Environment};

    #[test]
    fn plain_set_and_percent_substitution_lines_skip_pre_dispatch() {
        let env = Environment::new(&Config::default());

        assert!(!raw_may_need_pre_dispatch("set X=value", &env));
        assert!(!raw_may_need_pre_dispatch(
            r#"%KCUR:JBUQBBdafyQknrwjyDMNqXNKxHuQhdYuHwOUWHNN=%"CBda==""#,
            &env
        ));
    }

    #[test]
    fn child_launchers_still_need_pre_dispatch() {
        let env = Environment::new(&Config::default());

        assert!(raw_may_need_pre_dispatch("cmd /c echo hi", &env));
        assert!(raw_may_need_pre_dispatch(
            "powershell -nop -c Write-Host hi",
            &env
        ));
        assert!(raw_may_need_pre_dispatch(
            "for %%A in (*) do echo %%A",
            &env
        ));
    }

    #[test]
    fn wrapped_for_with_leading_close_paren_needs_pre_dispatch() {
        let env = Environment::new(&Config::default());

        assert!(raw_may_need_pre_dispatch(
            ") foR %a iN (1 2 3) dO (sEt X=!X!!Y:~ %a,1!)",
            &env
        ));
    }

    #[test]
    fn caret_obfuscated_for_needs_pre_dispatch() {
        let env = Environment::new(&Config::default());

        assert!(raw_may_need_pre_dispatch(
            ",; fo^R;,;%%^a,;; i^N;,,;(1 2 3),;,;d^O,,echo %%^a",
            &env
        ));
    }

    #[test]
    fn raw_self_substitution_set_preserves_powershell_punctuation() {
        let mut env = Environment::new(&Config::default());
        let marker = "⎱ ㉁ ❏ ㇎ ⫼";
        env.set(
            "frag",
            &format!("{marker}$url = [System.Text.Encoding]::UTF8.GetString({marker}$bytes);"),
        );

        let pre = pre_dispatch(&format!(r#"set "frag=%frag:{marker}=%""#), &mut env);

        assert!(pre.consumed);
        assert!(pre.suppress_normalized_output);
        assert_eq!(
            env.get("frag").as_deref(),
            Some("$url = [System.Text.Encoding]::UTF8.GetString($bytes);")
        );
    }

    #[test]
    fn raw_marker_literal_set_defers_payload_fragment_normalization() {
        let mut env = Environment::new(&Config::default());
        let marker = "⎱ ㉁ ❏ ㇎ ⫼";

        let pre = pre_dispatch(
            &format!(
                r#"set "frag={marker}$url = [System.Text.Encoding]::UTF8.GetString({marker}$bytes);""#
            ),
            &mut env,
        );

        assert!(pre.consumed);
        assert!(pre.suppress_normalized_output);
        assert_eq!(
            env.get("frag").as_deref(),
            Some("⎱ ㉁ ❏ ㇎ ⫼$url = [System.Text.Encoding]::UTF8.GetString(⎱ ㉁ ❏ ㇎ ⫼$bytes);")
        );
    }

    #[test]
    fn raw_marker_set_name_is_stored_under_clean_name() {
        let mut env = Environment::new(&Config::default());
        let marker = "⎱ ㉁ ❏ ㇎ ⫼";

        let pre = pre_dispatch(
            &format!(r#"set "{marker}ur{marker}lBase64=aHR0cHM6Ly9leGFtcGxlLmNvbS8=""#),
            &mut env,
        );

        assert!(pre.consumed);
        assert_eq!(
            env.get("urlBase64").as_deref(),
            Some("aHR0cHM6Ly9leGFtcGxlLmNvbS8=")
        );
    }

    #[test]
    fn command_name_stops_at_cmd_separator_punctuation() {
        assert_eq!(
            command_name("( iF,%a==+1337,(CalL;%fInAl:~-12%))").as_deref(),
            Some("iF")
        );
        assert_eq!(command_name("(CalL;netstat /ano)").as_deref(), Some("CalL"));
    }
}
