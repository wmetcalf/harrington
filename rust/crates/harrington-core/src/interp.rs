//! Interpreter — dispatches a normalized command string to its handler.

use crate::env::Environment;
use crate::handlers;

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

    if let Some(inner) = crate::handlers::forfiles::extract_forfiles_inner(raw) {
        result.child_cmd_to_push = Some(inner);
        result.child_cmd_delayed = false;
    }

    // cmd /c handler: extract child from raw text so var refs aren't expanded
    if let Some(inner) = crate::handlers::cmd::extract_cmd_inner(raw) {
        result.child_cmd_to_push = Some(inner);
        result.child_cmd_delayed = crate::handlers::cmd::has_v_on_raw(raw);
        // We still want interpret_line to run on the normalized text below
        // (so the line gets rendered to deobfuscated output and the cmd handler
        // emits its trait). The child push happens regardless.
    }

    if let Some((service_name, bin_path)) = crate::handlers::passthrough::sc_service_binpath(raw) {
        if !env.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::ServiceInstall {
                    service_name: existing,
                    ..
                } if existing == &service_name
            )
        }) {
            env.traits.push(crate::traits::Trait::ServiceInstall {
                service_name,
                bin_path: bin_path.clone(),
            });
        }
        if let Some((child, delayed)) =
            crate::handlers::passthrough::persisted_command_child(&bin_path)
        {
            result.child_cmd_to_push = Some(child);
            result.child_cmd_delayed = delayed;
        }
    }

    if let Some((service_name, command)) = crate::handlers::passthrough::sc_failure_command(raw) {
        env.traits.push(crate::traits::Trait::Persistence {
            hive: "ServiceFailureCommand".to_string(),
            key: service_name,
            value_name: "command".to_string(),
            command: command.clone(),
        });
        if let Some((child, delayed)) =
            crate::handlers::passthrough::persisted_command_child(&command)
        {
            result.child_cmd_to_push = Some(child);
            result.child_cmd_delayed = delayed;
        }
    }

    if let Some((time, command)) = crate::handlers::passthrough::at_scheduled_command(raw) {
        if let Some(target_host) = crate::handlers::passthrough::at_remote_host(raw) {
            env.traits.push(crate::traits::Trait::LateralMovement {
                tool: "at".to_string(),
                target_host,
            });
        }
        env.traits.push(crate::traits::Trait::Persistence {
            hive: "AtJob".to_string(),
            key: time,
            value_name: "command".to_string(),
            command: command.clone(),
        });
        if let Some((child, delayed)) =
            crate::handlers::passthrough::persisted_command_child(&command)
        {
            result.child_cmd_to_push = Some(child);
            result.child_cmd_delayed = delayed;
        }
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

    if let Some(command) = crate::handlers::passthrough::runas_child_command(raw) {
        crate::handlers::passthrough::h_runas(raw, env);
        if let Some((child, delayed)) =
            crate::handlers::passthrough::persisted_command_child(&command)
        {
            result.child_cmd_to_push = Some(child);
            result.child_cmd_delayed = delayed;
        }
        result.consumed = true;
        return result;
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

    if raw_invokes_powershell(raw) {
        crate::handlers::powershell::h_powershell(raw, env);
        result.consumed = true;
    }

    result
}

fn raw_invokes_powershell(raw: &str) -> bool {
    let Some(name) = command_name(raw) else {
        return false;
    };
    let name = name.trim_start_matches(['@', '"', '(']);
    let basename = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let lower = basename.trim_matches('"').to_ascii_lowercase();
    matches!(
        lower.strip_suffix(".exe").unwrap_or(&lower),
        "powershell" | "pwsh"
    )
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
    // ending in `.jS`/`.js`/`.vbs`/`.vbe`/`.wsf`/`.wsh`/`.hta` and
    // there's no matching handler (which is the case for `call X.jS`
    // — the call handler re-feeds via interpret_line which lands here),
    // Windows shellexecutes wscript/cscript/mshta to run it. Surface
    // the implicit launcher as a trait so CAPE-vs-harrington compare can
    // see the spawned binary; the URL/payload extraction has already
    // happened via the recursive certutil-decode + JS scan path.
    let lower = name.to_ascii_lowercase();
    let stripped = lower.trim_start_matches(['@', '"', '(']);
    let ext = stripped.rsplit('.').next().unwrap_or("");
    let has_wscript_exec = env
        .traits
        .iter()
        .any(|t| matches!(t, crate::traits::Trait::WscriptExec { src } if src == &name));
    let has_mshta_lolbas = env
        .traits
        .iter()
        .any(|t| matches!(t, crate::traits::Trait::Lolbas { name: n, .. } if n == "mshta"));
    let has_hh_lolbas = env
        .traits
        .iter()
        .any(|t| matches!(t, crate::traits::Trait::Lolbas { name: n, .. } if n == "hh"));
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
    capture_synthetic_stdout_redirect(line, env);
    capture_synthetic_option_output(line, env);
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
    if let Some(crate::env::FsEntry::Download { src }) =
        crate::handlers::util::filesystem_entry_for_path(env, path)
    {
        return Some(src.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return match crate::handlers::util::filesystem_entry_for_path(env, stripped) {
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
    if let Some(content) =
        content_from_entry(crate::handlers::util::filesystem_entry_for_path(env, path))
    {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(crate::handlers::util::filesystem_entry_for_path(
                env, stripped,
            ));
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

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn push_unique_payload(payloads: &mut Vec<Vec<u8>>, payload: Vec<u8>) {
    if !payloads.iter().any(|existing| existing == &payload) {
        payloads.push(payload);
    }
}

fn xcopy_pipeline_tail(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once('|')?;
    let tail = tail.trim();
    let name = command_name(tail)?;
    let lower = name.to_ascii_lowercase();
    let stripped = lower.trim_matches(['"', '\'']);
    let file_name = stripped.rsplit(['\\', '/']).next().unwrap_or(stripped);
    let base = file_name.strip_suffix(".exe").unwrap_or(file_name);
    if base == "xcopy" {
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
    write_synthetic_lines(stdout.path(), stdout.append(), lines, env);
}

fn capture_synthetic_option_output(line: &str, env: &mut Environment) {
    let Some((cleaned, output_path)) = sort_output_file_command(line) else {
        return;
    };
    let lines = crate::synth::run_pipeline(&cleaned, env);
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
    let words = crate::handlers::util::split_words(&cleaned);
    let command = words.first()?;
    let base = command
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    if base != "sort" {
        return None;
    }

    let mut output = None;
    let mut kept = Vec::new();
    kept.push("sort".to_string());
    let mut i = 1;
    while i < words.len() {
        let arg = words[i].trim_matches('"');
        let lower = arg.to_ascii_lowercase();
        if lower == "/o" {
            if let Some(next) = words.get(i + 1) {
                output = Some(next.trim_matches('"').to_string());
                i += 2;
                continue;
            }
        } else if lower.starts_with("/o:") && arg.len() > 3 {
            output = Some(arg[3..].trim_matches('"').to_string());
            i += 1;
            continue;
        }
        kept.push(words[i].clone());
        i += 1;
    }
    let output = output.filter(|path| !path.is_empty())?;
    Some((kept.join(" "), output))
}

fn write_synthetic_lines(path: &str, append: bool, lines: Vec<String>, env: &mut Environment) {
    let mut content = lines.join("\r\n").into_bytes();
    content.extend_from_slice(b"\r\n");
    let key = crate::handlers::util::filesystem_storage_key(path);
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
        name.push(quote);
        for c in s[quote.len_utf8()..].chars() {
            name.push(c);
            if c == quote {
                break;
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
    // `echo.`, `echo:`, `echo/`, and `echo(` are common syntax variants
    // for emitting literal text or blank lines without ambiguity around
    // `echo on/off`. Normalize them before handler dispatch even when the
    // payload is attached (`echo.hello>out`).
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
