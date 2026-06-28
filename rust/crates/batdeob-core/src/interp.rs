//! Interpreter — dispatches a normalized command string to its handler.

use crate::env::Environment;
use crate::handlers;
use crate::handlers::util::{
    ends_with_ascii_case_insensitive, filesystem_entry_for_path, windows_basename,
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
}

/// Single pre-normalize dispatch entry point for `drive()`.
///
/// Called on the RAW (pre-normalize) command text. Returns a [`PreDispatch`]
/// that tells `drive()` whether to skip normal dispatch and/or enqueue a child.
pub fn pre_dispatch(raw: &str, env: &mut Environment) -> PreDispatch {
    let mut result = PreDispatch::default();

    // for handler: operates on raw text because lex strips %%A
    if crate::handlers::for_cmd::run_for_from_raw(raw, env) {
        result.consumed = true;
        return result;
    }

    // cmd /c handler: extract child from raw text so var refs aren't expanded
    if let Some(inner) = crate::handlers::cmd::extract_cmd_inner(raw) {
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

    if crate::handlers::cmd::start_child_command(raw).is_some() {
        crate::handlers::cmd::h_start(raw, env);
        result.consumed = true;
        return result;
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

pub fn interpret_line(line: &str, env: &mut Environment) {
    if let Some(tail) = xcopy_pipeline_tail(line) {
        crate::handlers::copy::h_xcopy(tail, env);
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
    if let Some(ext) = script_host_extension(&name) {
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
            push_unique_payload(&mut env.all_extracted_jscript, content.clone());
            push_unique_payload(&mut env.exec_jscript, content);
        }
        "vbs" | "vbe" => {
            push_unique_payload(&mut env.all_extracted_vbs, content.clone());
            push_unique_payload(&mut env.exec_vbs, content);
        }
        _ => {}
    }
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_from_entry(filesystem_entry_for_path(env, path)) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(filesystem_entry_for_path(env, stripped));
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
            return content_from_entry(Some(entry));
        }
    }
    None
}

fn content_from_entry(entry: Option<&crate::env::FsEntry>) -> Option<Vec<u8>> {
    match entry {
        Some(crate::env::FsEntry::Content { content, .. })
        | Some(crate::env::FsEntry::Decoded { content, .. }) => Some(content.clone()),
        _ => None,
    }
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
    let mut content = lines.join("\r\n").into_bytes();
    content.extend_from_slice(b"\r\n");
    let key = crate::handlers::util::filesystem_storage_key(stdout.path());
    let cap = env.limits.max_output_bytes as usize;
    if stdout.append() {
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
            append: stdout.append(),
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
    // `(` (block open), and whitespace as ignorable prefix before the command
    // token. Obfuscators interleave them (e.g. `@;@@@set …`), so all must be
    // stripped — stripping only `@`/`(` left `;@@@set` and broke dispatch,
    // which silently dropped `set`-defined alphabet vars in char-substitution
    // packers (mangling the recovered URL).
    let trimmed = line.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
    });
    if trimmed.is_empty() {
        return None;
    }

    // Skip leading redirections and their targets
    let mut s = trimmed;
    loop {
        if s.starts_with('>') || s.starts_with('<') || s.starts_with("2>") {
            // Skip the redirection operator
            if s.starts_with("2>") {
                s = &s[2..];
            } else {
                s = &s[1..];
            }
            // Skip additional > if it's >>
            if s.starts_with('>') {
                s = &s[1..];
            }
            // Skip whitespace
            s = s.trim_start();
            // Skip the target (quoted or unquoted)
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
        } else {
            break;
        }
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
    // `echo.` (and `echo..` etc.) is a common obfuscation for empty echo output.
    // Strip trailing dots and normalise to "echo" if that's what remains.
    let name_trimmed = name.trim_end_matches('.');
    if name_trimmed.eq_ignore_ascii_case("echo") {
        return Some("echo".to_string());
    }
    Some(name)
}
