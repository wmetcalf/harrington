//! cmd / cmd.exe / *cmd.exe handler — extracts the /c or /r body.
#![allow(clippy::expect_used)]

use crate::env::{Environment, FsEntry};
use crate::util::find_ascii_case_insensitive_from;
use once_cell::sync::Lazy;
use regex::Regex;

/// Find the `cmd[.exe]` executable token at the start of `raw` and return
/// the byte index just after it. Handles optional `@`, `(`, leading
/// whitespace, optional quotes, optional path prefix, optional `.exe`,
/// and an optional second cmd path (CMD's own `cmd.exe cmd /c X` form).
fn find_cmd_executable_end(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len()
        && (bytes[i] == b'@' || bytes[i] == b'(' || bytes[i].is_ascii_whitespace())
    {
        i += 1;
    }
    let start = i;
    // First cmd: scan a non-whitespace token, accept if its tail matches
    // `cmd` or `cmd.exe` (case-insensitive), possibly wrapped in quotes.
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if !is_cmd_token(&raw[start..i]) && !is_comspec_token(&raw[start..i]) {
        return None;
    }
    // Optional second cmd token (e.g. `cmd.exe cmd /c X`).
    let mut j = i;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    let tok2_start = j;
    while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if tok2_start < j
        && (is_cmd_token(&raw[tok2_start..j]) || is_comspec_token(&raw[tok2_start..j]))
    {
        i = j;
    }
    Some(i)
}

fn is_comspec_token(tok: &str) -> bool {
    let tok = tok.trim_matches(['"', '\'', '\\']);
    if tok.eq_ignore_ascii_case("%comspec%") {
        return true;
    }
    comspec_expanded_token(tok)
        .as_deref()
        .is_some_and(is_cmd_token)
}

fn comspec_expanded_token(tok: &str) -> Option<String> {
    comspec_substring_token(tok).or_else(|| comspec_substitute_token(tok))
}

fn comspec_substring_token(tok: &str) -> Option<String> {
    const COMSPEC: &str = r"C:\WINDOWS\system32\cmd.exe";
    let lower = tok.to_ascii_lowercase();
    let body = lower.strip_prefix("%comspec:~")?.strip_suffix('%')?;
    let (start_text, len_text) = body.split_once(',').map_or((body, None), |(start, len)| {
        (start.trim(), Some(len.trim()))
    });
    let start = start_text.trim().parse::<isize>().ok()?;
    let len = len_text.map(str::parse::<isize>).transpose().ok()?;

    let total = COMSPEC.len() as isize;
    let mut begin = if start < 0 { total + start } else { start };
    begin = begin.clamp(0, total);
    let mut end = match len {
        Some(len) if len < 0 => total + len,
        Some(len) => begin + len,
        None => total,
    };
    end = end.clamp(begin, total);
    Some(COMSPEC[begin as usize..end as usize].to_string())
}

fn comspec_substitute_token(tok: &str) -> Option<String> {
    const COMSPEC: &str = r"C:\WINDOWS\system32\cmd.exe";
    let lower = tok.to_ascii_lowercase();
    if !lower.starts_with("%comspec:") || !tok.ends_with('%') {
        return None;
    }
    let body = &tok["%comspec:".len()..tok.len() - 1];
    let (needle, replacement) = body.split_once('=')?;
    let (wildcard, needle) = needle
        .strip_prefix('*')
        .map_or((false, needle), |needle| (true, needle));
    Some(crate::normalize::apply_substitute(
        COMSPEC,
        needle,
        replacement,
        wildcard,
    ))
}

fn is_cmd_token(tok: &str) -> bool {
    // Tolerant cmd-token detector. Strip any leading/trailing quote /
    // backslash noise that obfuscators stick on (e.g. `\"cmd`, `'cmd.exe'`,
    // `"C:\Windows\cmd.exe"`), then verify the suffix is `cmd` or
    // `cmd.exe` in a case-insensitive way.
    let t = tok.trim_matches(['"', '\'', '\\']).trim_end_matches('.');
    let bare = t.rfind(['\\', '/']).map(|i| &t[i + 1..]).unwrap_or(t);
    bare.eq_ignore_ascii_case("cmd") || bare.eq_ignore_ascii_case("cmd.exe")
}

/// Parse a CMD invocation: skip the `cmd[.exe]` executable and the flag
/// list, find the `/c`/`/k`/`/r` trigger (in any order among other flags,
/// possibly concatenated like `/V/D/c`), and return the body that
/// follows. Returns `None` if no trigger or no body was found.
fn split_cmd_body(raw: &str) -> Option<&str> {
    let mut i = find_cmd_executable_end(raw)?;
    let bytes = raw.as_bytes();
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] != b'/' && bytes[i] != b'-' {
            return None;
        }
        let token_start = i;
        i += 1;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let token = &raw[token_start..i];

        // The flag token can be either a single `/x` form or a concatenated
        // `/V/D/c` mash. Split on `/` and look for `c`/`k`/`r` as a
        // standalone sub-flag — that's the body trigger.
        let mut sub_start = 0usize;
        for (sub_idx, ch) in token
            .as_bytes()
            .iter()
            .copied()
            .enumerate()
            .chain(std::iter::once((token.len(), b'/')))
        {
            if ch == b'/' || ch == b'-' {
                if sub_idx > sub_start {
                    let sub = &token[sub_start..sub_idx];
                    if let Some(trigger) = cmd_body_trigger_prefix_len(sub) {
                        // CMD accepts attached forms such as `/c"echo hi"`
                        // and `/cecho hi`; preserve everything after the
                        // trigger as the body.
                        let trigger_abs_end = token_start + sub_start + trigger;
                        if trigger_abs_end < token_start + token.len() {
                            let after = &raw[trigger_abs_end..];
                            return Some(after.trim_start());
                        }
                        let mut j = i;
                        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        return Some(&raw[j..]);
                    }
                }
                sub_start = sub_idx + 1;
            }
        }
    }
}

fn cmd_body_trigger_prefix_len(sub: &str) -> Option<usize> {
    let first = sub.as_bytes().first()?;
    matches!(first.to_ascii_lowercase(), b'c' | b'k' | b'r').then_some(1)
}

/// Detect whether `/V:ON` (or `/V` without qualifier) is present in a cmd invocation.
/// Returns true if the flags section contains `/v` or `/v:on` (case-insensitive).
/// Exposed as `has_v_on_raw` for use in `drive()`.
pub fn has_v_on_raw(raw: &str) -> bool {
    has_v_on(raw)
}

fn has_v_on(raw: &str) -> bool {
    // Walk the flags between the `cmd[.exe]` token and the `/c`/`/k`/`/r`
    // trigger using the same parser as `split_cmd_body`. Respects
    // cmd.exe's LAST-`/v:*`-wins rule.
    static V_FLAG_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)/v(?::(on|off))?\b").expect("/v flag regex"));
    let Some(flags) = cmd_flags_section(raw) else {
        return false;
    };
    let mut state: Option<bool> = None;
    for m in V_FLAG_RE.captures_iter(flags) {
        let off = m
            .get(1)
            .is_some_and(|g| g.as_str().eq_ignore_ascii_case("off"));
        state = Some(!off);
    }
    state.unwrap_or(false)
}

/// Return the slice of `raw` between the `cmd[.exe]` token and the
/// `/c`/`/k`/`/r` trigger (exclusive). Empty slice if no flags. None if
/// the line isn't a cmd invocation with a trigger.
fn cmd_flags_section(raw: &str) -> Option<&str> {
    let start = find_cmd_executable_end(raw)?;
    let bytes = raw.as_bytes();
    let mut i = start;
    let flags_begin = {
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        j
    };
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] != b'/' && bytes[i] != b'-' {
            return None;
        }
        let flag_start = i;
        i += 1;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let flag = &raw[flag_start..i];
        // Mashed-flag form: `/V/D/c` is a single whitespace-delimited
        // token but logically three sub-flags. We must detect `/c`/`/k`/
        // `/r` even when it appears in the MIDDLE of the token, otherwise
        // has_v_on (which calls us) misses `/V` because we never return
        // the flags slice and the caller bails. Without this, `cmd /V/D/c`
        // doesn't enable delayed expansion in batdeob and `!VAR!` refs
        // inside the body stay literal (Brazilian banker JS-droppers,
        // SOSTENER variants).
        let mut sub_start = 0usize;
        for (sub_idx, ch) in flag
            .as_bytes()
            .iter()
            .copied()
            .enumerate()
            .chain(std::iter::once((flag.len(), b'/')))
        {
            if ch == b'/' || ch == b'-' {
                if sub_idx > sub_start {
                    let sub = &flag[sub_start..sub_idx];
                    if let Some(trigger) = cmd_body_trigger_prefix_len(sub) {
                        // Trigger found — flags span ends at the token start
                        // PLUS any pre-trigger sub-flags. Include those as
                        // flags so `cmd /V/D/c …` exposes the `/V`.
                        return Some(&raw[flags_begin..flag_start + sub_start + trigger]);
                    }
                }
                sub_start = sub_idx + 1;
            }
        }
    }
}

/// Extract the inner command from a cmd /c or /r invocation.
/// Returns Some(inner_command) if this is a cmd command, None otherwise.
pub fn extract_cmd_inner(raw: &str) -> Option<String> {
    let body = split_cmd_body(raw)?;
    let mut inner = body.trim().to_string();
    if inner.starts_with('"') && inner.ends_with('"') && inner.len() >= 2 {
        // CMD's documented body-extraction (without `/S`): strip the FIRST
        // and LAST `"`. Correctly handles nested same-line pairs like
        // `SET "x=val"` because the outer pair are the body bounds.
        inner = inner[1..inner.len() - 1].to_string();
    } else if inner.starts_with('"') {
        // Pathological: body opens with `"` but doesn't end with one. Use
        // the last `"` as a best-effort close. Trailing-redirect samples
        // like `cmd /c "..." 2>nul && echo "done"` shouldn't actually
        // reach this branch because split.rs splits at the top-level
        // `&&` before we get here.
        let trimmed = &inner[1..];
        if let Some(last_quote) = trimmed.rfind('"') {
            inner = trimmed[..last_quote].to_string();
        }
    }
    if !inner.is_empty() {
        Some(inner)
    } else {
        None
    }
}

pub fn h_cmd(raw: &str, env: &mut Environment) {
    if let Some(inner) = extract_cmd_inner(raw) {
        let delayed = has_v_on(raw);
        env.exec_cmd.push(inner);
        env.exec_cmd_delayed.push(delayed);
    }
}

/// True when the child of a `cmd /c <inner>` is a single trivial command
/// (no operators, variable refs, caret/bang escapes, or redirects). The
/// wrapper line already renders the command after variable expansion, so
/// recursing into the child only duplicates the same text in the deob
/// output. The child is still tracked in `all_extracted_cmd` for trait
/// extraction; only the duplicate deob-output line is suppressed.
pub fn child_is_trivial_for_dedup(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    // Operators that signal "multiple commands or scripted structure":
    // these are what would make a recursive deob different from the
    // wrapper's normalize. `%X%` / `!X!` are ALREADY expanded by the
    // wrapper's normalize, so they don't add information when emitted
    // a second time by the child — exclude them from the structure
    // test. Quotes likewise don't change rendering.
    // `|` keeps a pipeline together in split.rs and renders identically
    // in the wrapper, so it's NOT a structural reason to re-emit. Only
    // multi-command separators (`&`, `&&`, `||`) signal that recursion
    // would deobfuscate something the wrapper line didn't.
    !contains_top_level(t, &['&']) && !t.contains('^') && !t.contains('<') && !t.contains('>')
}

fn contains_top_level(s: &str, ops: &[char]) -> bool {
    let mut in_dq = false;
    for byte in s.bytes() {
        if byte == b'"' {
            in_dq = !in_dq;
            continue;
        }
        if in_dq {
            continue;
        }
        if ops.iter().any(|&op| op as u32 == byte as u32) {
            return true;
        }
    }
    false
}

pub fn h_start(raw: &str, env: &mut Environment) {
    let Some(inner_raw) = start_child_command(raw) else {
        return;
    };
    if inner_raw.is_empty() {
        return;
    }
    // `start "" "URL"` and `start "" firefox -url URL` both open the URL in
    // the default app / specified browser. Detect the URL on `inner_raw`
    // BEFORE strip_leading_quoted_title (which would treat `"URL"` as a
    // title and strip the URL away).
    if let Some(url) = find_liberal_url_in_start_arg(inner_raw) {
        env.traits.push(crate::traits::Trait::Download {
            src: url,
            dst: None,
            cmd: format!("start {}", inner_raw),
        });
    } else if let Some(url) = start_prior_download_url(inner_raw, env) {
        push_start_url_argument(inner_raw, url, env);
    }
    let inner = unquote_start_executable(inner_raw);
    if inner.is_empty() {
        return;
    }
    if let Some(child) = extract_cmd_inner(inner.as_ref()) {
        env.exec_cmd.push(unescape_outer_caret_bangs(&child));
        env.exec_cmd_delayed.push(has_v_on_raw(inner.as_ref()));
        return;
    }
    // Recurse: interpret the inner command inline.
    crate::interp::interpret_line(inner.as_ref(), env);
}

fn unescape_outer_caret_bangs(command: &str) -> String {
    command.replace("^!", "!")
}

pub(crate) fn start_child_command(raw: &str) -> Option<&str> {
    let mut rest = strip_start_command(raw)?.trim_start();
    let mut title_consumed = false;
    loop {
        if rest.is_empty() {
            return None;
        }
        let (arg, after_arg) = split_start_arg(rest);
        if let Some(after_option) = start_option_remainder(arg, after_arg) {
            rest = after_option.trim_start();
            continue;
        }
        if !title_consumed && arg.starts_with('"') {
            title_consumed = true;
            rest = after_arg.trim_start();
            continue;
        }
        return Some(rest);
    }
}

fn strip_start_command(raw: &str) -> Option<&str> {
    let raw = raw.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
    });
    let lower = raw.to_ascii_lowercase();
    for prefix in ["start.exe", "start"] {
        let Some(rest) = lower.strip_prefix(prefix) else {
            continue;
        };
        if rest.is_empty() {
            return Some("");
        }
        if rest.starts_with(char::is_whitespace) {
            return Some(&raw[prefix.len()..]);
        }
    }
    None
}

fn split_start_arg(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    if let Some(after_open) = s.strip_prefix('"') {
        let mut escaped = false;
        for (idx, ch) in after_open.char_indices() {
            if ch == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if ch == '"' && !escaped {
                let end = idx + 2;
                return (&s[..end], &s[end..]);
            }
            escaped = false;
        }
        return (s, "");
    }
    let end = s
        .char_indices()
        .find_map(|(idx, ch)| ch.is_whitespace().then_some(idx))
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

fn start_option_remainder<'a>(arg: &str, after_arg: &'a str) -> Option<&'a str> {
    let option = arg.trim_matches('"').to_ascii_lowercase();
    let option = option.strip_prefix(['/', '-'])?;
    if option == "d" {
        let (_value, after_value) = split_start_arg(after_arg);
        return Some(after_value);
    }
    if option
        .strip_prefix('d')
        .is_some_and(|value| !value.is_empty())
    {
        return Some(after_arg);
    }
    if matches!(option, "node" | "affinity" | "machine") {
        let (_value, after_value) = split_start_arg(after_arg);
        return Some(after_value);
    }
    matches!(
        option,
        "min"
            | "max"
            | "wait"
            | "low"
            | "normal"
            | "abovenormal"
            | "belownormal"
            | "high"
            | "realtime"
            | "b"
            | "i"
            | "w"
            | "separate"
            | "shared"
    )
    .then_some(after_arg)
}

/// Extract a URL from the start of `s`, stopping at whitespace, quotes,
/// angle brackets, or shell-grouping characters. Parens terminate
/// because `start powershell ... iex(irm https://host/p.png)` would
/// otherwise include the trailing `)` of the cmd group — leaving the URL
/// as `https://host/p.png)`, which then duplicates a clean copy extracted
/// from the PS body. Bracketed URL paths are preserved and unmatched trailing
/// brackets are trimmed by URL normalization.
fn extract_url_at(s: &str) -> String {
    let bytes = s.as_bytes();
    let end = bytes
        .iter()
        .position(|b| {
            b.is_ascii_whitespace()
                || matches!(*b, b'"' | b'\'' | b'<' | b'>' | b'(' | b')' | b'|' | b'&')
        })
        .unwrap_or(bytes.len());
    s[..end].to_string()
}

fn find_liberal_url_in_start_arg(s: &str) -> Option<String> {
    let start = ["https:", "http:", "ftp:", "file:"]
        .iter()
        .filter_map(|scheme| find_ascii_case_insensitive_from(s, scheme, 0))
        .min()?;
    let raw = extract_url_at(&s[start..]);
    crate::deob_scan::normalize_liberal_url_token(&raw).or({
        if raw.is_empty() {
            None
        } else {
            Some(raw)
        }
    })
}

fn start_prior_download_url(inner_raw: &str, env: &Environment) -> Option<String> {
    let (first, _) = split_start_arg(inner_raw);
    let first = strip_quotes(first.trim())
        .trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
        .to_string();
    if first.is_empty() || first.starts_with(['/', '-']) {
        return None;
    }
    downloaded_src_for_candidate(&first, env)
}

fn strip_quotes(token: &str) -> &str {
    token.trim_matches(['"', '\''])
}

fn downloaded_src_for_candidate(candidate: &str, env: &Environment) -> Option<String> {
    if let Some(FsEntry::Download { src }) =
        crate::handlers::util::filesystem_entry_for_path(env, candidate)
    {
        return Some(src.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(candidate) {
        if stripped.contains(['\\', '/']) {
            return match crate::handlers::util::filesystem_entry_for_path(env, stripped) {
                Some(FsEntry::Download { src }) => Some(src.clone()),
                _ => None,
            };
        }
    }
    if let Some(name) = current_dir_basename(candidate) {
        return downloaded_src_for_basename(name, env);
    }
    if candidate.contains(['\\', '/']) {
        return None;
    }
    downloaded_src_for_basename(candidate, env)
}

fn downloaded_src_for_basename(candidate: &str, env: &Environment) -> Option<String> {
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|name| name.eq_ignore_ascii_case(candidate))
                .then_some(entry)
        })
        .and_then(|entry| match entry {
            FsEntry::Download { src } => Some(src.clone()),
            _ => None,
        })
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

fn push_start_url_argument(inner_raw: &str, url: String, env: &mut Environment) {
    let cmd = format!("start {inner_raw}");
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            crate::traits::Trait::UrlArgument { cmd: existing_cmd, url: existing_url }
                if existing_cmd == &cmd && existing_url == &url
        )
    }) {
        env.traits
            .push(crate::traits::Trait::UrlArgument { cmd, url });
    }
}

fn split_first_cmd_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(after_open) = s.strip_prefix('"') {
        if let Some(close_idx) = after_open.find('"') {
            let end = 1 + close_idx + 1;
            return Some((&s[..end], &s[end..]));
        }
    }
    let end = s
        .as_bytes()
        .iter()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

fn unquote_start_executable(s: &str) -> std::borrow::Cow<'_, str> {
    let Some((head, rest)) = split_first_cmd_token(s) else {
        return std::borrow::Cow::Borrowed("");
    };
    if head.starts_with('"') && head.ends_with('"') && head.len() >= 2 {
        let exe = &head[1..head.len() - 1];
        let rest = rest.trim_start();
        if rest.is_empty() {
            std::borrow::Cow::Owned(exe.to_string())
        } else {
            std::borrow::Cow::Owned(format!("{exe} {rest}"))
        }
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod has_v_on_tests {
    use super::has_v_on_raw;

    #[test]
    fn bare_v_enables_delayed_expansion() {
        assert!(has_v_on_raw("cmd /v /c echo hi"));
    }

    #[test]
    fn v_on_enables_delayed_expansion() {
        assert!(has_v_on_raw("cmd /V:ON /c echo hi"));
    }

    #[test]
    fn v_off_disables_delayed_expansion() {
        assert!(!has_v_on_raw("cmd /V:OfF /c echo hi"));
    }

    #[test]
    fn last_v_flag_wins_off_after_on() {
        // Regression: substring `contains` ignored ordering — `cmd /V:ON /V:OFF`
        // used to return true (delayed expansion on) but cmd.exe applies the
        // LAST `/v:*` and turns it OFF.
        assert!(!has_v_on_raw("cmd /V:ON /V:OFF /c echo hi"));
    }

    #[test]
    fn last_v_flag_wins_on_after_off() {
        // Symmetric: `cmd /V:OFF /V:ON` is delayed-expansion ON.
        assert!(has_v_on_raw("cmd /V:OFF /V:ON /c echo hi"));
    }

    #[test]
    fn last_v_flag_wins_bare_after_off() {
        // A bare `/v` after `/v:off` re-enables delayed expansion.
        assert!(has_v_on_raw("cmd /V:OFF /V /c echo hi"));
    }

    #[test]
    fn no_v_flag_is_off() {
        assert!(!has_v_on_raw("cmd /c echo hi"));
    }

    #[test]
    fn attached_body_does_not_count_as_flag_section() {
        assert!(!has_v_on_raw("cmd /v:off /c/v:on echo hi"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cmd_token_tests {
    use super::is_cmd_token;

    #[test]
    fn dotted_cmd_token_is_recognized() {
        assert!(is_cmd_token("cmd."));
        assert!(is_cmd_token("\"cmd.exe.\""));
        assert!(is_cmd_token("C:\\Windows\\System32\\cmd.exe."));
        assert!(is_cmd_token("C:\\Windows\\System32\\CmD.ExE."));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod extract_cmd_inner_tests {
    use super::extract_cmd_inner;
    use super::has_v_on_raw;

    #[test]
    fn simple_quoted_body() {
        let r = extract_cmd_inner("cmd /c \"echo hi\"").unwrap();
        assert_eq!(r, "echo hi");
    }

    #[test]
    fn body_with_inner_set_quote_pair() {
        // `SET "x=val"` lives inside the body; the outer pair are the
        // body bounds. CMD's documented rule: strip first and last `"`.
        let r = extract_cmd_inner("cmd /c \"SET \"x=val\" & echo !x!\"").unwrap();
        assert_eq!(r, "SET \"x=val\" & echo !x!");
    }

    #[test]
    fn cmd_exe_cmd_form_extracts_inner_body() {
        let r = extract_cmd_inner("cmd.exe cmd /c echo hi").unwrap();
        assert_eq!(r, "echo hi");
    }

    #[test]
    fn cmd_exe_cmd_form_preserves_v_flag_state() {
        assert!(has_v_on_raw("cmd.exe cmd /V:ON /c echo hi"));
    }

    #[test]
    fn slash_c_attached_quoted_body() {
        let r = extract_cmd_inner("cmd.exe /d /c\"echo attached-body\"").unwrap();
        assert_eq!(r, "echo attached-body");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod start_child_tests {
    use super::start_child_command;

    #[test]
    fn start_accepts_echo_suppressed_prefix() {
        let child = start_child_command(r#"@start "" /min cmd.exe /c echo child"#).unwrap();
        assert_eq!(child, "cmd.exe /c echo child");
    }

    #[test]
    fn start_skips_separate_and_shared_flags() {
        let child = start_child_command(r#"start /separate /shared cmd.exe /c echo child"#)
            .expect("start child should parse");
        assert_eq!(child, "cmd.exe /c echo child");
    }

    #[test]
    fn start_attached_d_option_skips_working_directory() {
        let child =
            start_child_command(r#"start /D"C:\Users\Public" /min cmd.exe /c echo child"#).unwrap();
        assert_eq!(child, "cmd.exe /c echo child");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod child_dedup_tests {
    use super::child_is_trivial_for_dedup;

    #[test]
    fn quoted_ampersand_is_not_treated_as_top_level_structure() {
        assert!(child_is_trivial_for_dedup(r#"echo "a&b""#));
    }

    #[test]
    fn unquoted_ampersand_is_treated_as_structure() {
        assert!(!child_is_trivial_for_dedup("echo a&b"));
    }
}
