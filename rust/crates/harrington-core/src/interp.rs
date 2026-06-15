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

    if let Some((service_name, bin_path)) = crate::handlers::passthrough::sc_create_binpath(raw) {
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
    match ext {
        "js" | "jse" | "wsf" | "wsh" | "vbs" | "vbe" if !has_wscript_exec => {
            env.traits
                .push(crate::traits::Trait::WscriptExec { src: name.clone() });
        }
        "hta" if !has_mshta_lolbas => {
            // Mshta trait exists but takes different fields — use a Lolbas.
            env.traits.push(crate::traits::Trait::Lolbas {
                name: "mshta".to_string(),
                cmd: name.clone(),
            });
        }
        _ => {}
    }
    capture_synthetic_stdout_redirect(line, env);
}

fn xcopy_pipeline_tail(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once('|')?;
    let tail = tail.trim();
    let name = command_name(tail)?;
    if name.eq_ignore_ascii_case("xcopy") {
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
    let key = stdout.path().to_ascii_lowercase();
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
        name.push(quote);
        for c in s[quote.len_utf8()..].chars() {
            name.push(c);
            if c == quote {
                break;
            }
        }
    } else {
        for c in s.chars() {
            if c.is_whitespace() || c == '/' || c == '<' || c == '>' || c == '&' || c == '|' {
                break;
            }
            name.push(c);
        }
    }
    if name.is_empty() {
        return None;
    }
    // `echo.` (and `echo..` etc.) is a common obfuscation for empty echo output.
    // Strip trailing dots and normalise to "echo" if that's what remains.
    let name_trimmed = name.trim_end_matches('.');
    if name_trimmed.eq_ignore_ascii_case("echo") {
        return Some("echo".to_string());
    }
    Some(name)
}
