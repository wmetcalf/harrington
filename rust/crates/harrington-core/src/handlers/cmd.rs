//! cmd / cmd.exe / *cmd.exe handler — extracts the /c or /r body.
#![allow(clippy::expect_used)]

use crate::env::Environment;
use crate::handlers::util::split_words;
use once_cell::sync::Lazy;
use regex::Regex;
use std::borrow::Cow;

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
    if !is_cmd_token(&raw[start..i]) {
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
    if tok2_start < j && is_cmd_token(&raw[tok2_start..j]) {
        i = j;
    }
    if tok2_start < j && is_comspec_token(&raw[tok2_start..j]) {
        i = j;
    }
    Some(i)
}

fn is_comspec_token(tok: &str) -> bool {
    tok.trim_matches(['"', '\'', '\\'])
        .eq_ignore_ascii_case("%comspec%")
}

fn is_cmd_token(tok: &str) -> bool {
    // Tolerant cmd-token detector. Strip any leading/trailing quote /
    // backslash noise that obfuscators stick on (e.g. `\"cmd`, `'cmd.exe'`,
    // `"C:\Windows\cmd.exe"`), then verify the lowercased suffix is `cmd`
    // or `cmd.exe`. Falls back to a bare `ends_with("cmd")` check so we
    // don't lose CMD detection on weirdly-quoted shapes.
    let t = tok.trim_matches(['"', '\'', '\\']).to_ascii_lowercase();
    let bare = t.strip_suffix(".exe").unwrap_or(&t);
    let last_sep = bare.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    if &bare[last_sep..] == "cmd" {
        return true;
    }
    let lower = tok.to_ascii_lowercase();
    lower.ends_with("cmd") || lower.ends_with("cmd.exe")
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
        let lower = token.to_ascii_lowercase();
        let mut sub_start = 0usize;
        for (sub_idx, ch) in lower
            .char_indices()
            .chain(std::iter::once((lower.len(), '/')))
        {
            if ch == '/' || ch == '-' {
                if sub_idx > sub_start {
                    let sub = &lower[sub_start..sub_idx];
                    if matches!(sub, "c" | "k" | "r") {
                        // Body starts after the rest of this token plus
                        // any trailing whitespace.
                        let trigger_abs_end = token_start + sub_idx;
                        if trigger_abs_end < token_start + token.len() {
                            // Something after the trigger inside the SAME
                            // token (e.g. `/c/q`). CMD treats that as body.
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
        let off = matches!(
            m.get(1).map(|g| g.as_str().to_ascii_lowercase()),
            Some(ref s) if s == "off"
        );
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
        // doesn't enable delayed expansion in harrington and `!VAR!` refs
        // inside the body stay literal (Brazilian banker JS-droppers,
        // SOSTENER variants).
        let lower = flag.to_ascii_lowercase();
        let mut sub_start = 0usize;
        for (sub_idx, ch) in lower
            .char_indices()
            .chain(std::iter::once((lower.len(), '/')))
        {
            if ch == '/' || ch == '-' {
                if sub_idx > sub_start {
                    let sub = &lower[sub_start..sub_idx];
                    if matches!(sub, "c" | "k" | "r") {
                        // Trigger found — flags span ends at the token start
                        // PLUS any pre-trigger sub-flags. Include those as
                        // flags so `cmd /V/D/c …` exposes the `/V`.
                        return Some(&raw[flags_begin..flag_start + sub_idx]);
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
    for c in s.chars() {
        if c == '"' {
            in_dq = !in_dq;
            continue;
        }
        if in_dq {
            continue;
        }
        if ops.contains(&c) {
            return true;
        }
    }
    false
}

pub fn h_start(raw: &str, env: &mut Environment) {
    let Some(inner_raw) = start_child_command(raw) else {
        return;
    };
    // `start "" "URL"` and `start "" firefox -url URL` open the URL in
    // the default handler / specified browser. Classify only those direct
    // launch forms here; nested commands such as `start powershell ... iwr URL`
    // are handled by the recursive interpretation below.
    if let Some(url) = start_url_launch(inner_raw) {
        env.traits.push(crate::traits::Trait::UrlLaunch {
            cmd: format!("start {}", inner_raw),
            url,
        });
    }
    // The regex consumes the optional title. If the real command is a
    // quoted executable, remove only that executable's quotes before dispatch.
    let inner = unquote_start_executable(inner_raw);
    if inner.is_empty() {
        return;
    }
    // Recurse: interpret the inner command inline.
    crate::interp::interpret_line(inner.as_ref(), env);
}

fn start_child_command(raw: &str) -> Option<&str> {
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
    let raw = raw.trim_start();
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
    if matches!(option, "d" | "node" | "affinity" | "machine") {
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
    )
    .then_some(after_arg)
}

/// Extract a URL from the start of `s`, stopping at whitespace, quotes,
/// angle brackets, or shell-grouping characters. Parens/brackets terminate
/// because `start powershell ... iex(irm https://host/p.png)` would
/// otherwise include the trailing `)` of the cmd group — leaving the URL
/// as `https://host/p.png)`, which then duplicates a clean copy extracted
/// from the PS body.
fn extract_url_at(s: &str) -> String {
    s.chars()
        .take_while(|c| {
            !c.is_whitespace()
                && *c != '"'
                && *c != '\''
                && *c != '<'
                && *c != '>'
                && *c != '('
                && *c != ')'
                && *c != '['
                && *c != ']'
                && *c != '|'
                && *c != '&'
        })
        .collect()
}

fn start_url_launch(inner_raw: &str) -> Option<String> {
    let tokens = split_words(inner_raw);
    let first = tokens.first().map(|token| strip_quotes(token.trim()))?;
    if let Some(url) = normalize_start_url_token(first) {
        return Some(url);
    }
    if !is_known_url_launcher(first) {
        return None;
    }
    tokens
        .iter()
        .skip(1)
        .filter_map(|token| normalize_start_url_token(strip_quotes(token.trim())))
        .next()
}

fn normalize_start_url_token(token: &str) -> Option<String> {
    let token = token.trim_start_matches(['"', '\'']);
    let token = if token.contains("\"\"") || token.contains("''") {
        Cow::Owned(token.replace("\"\"", "").replace("''", ""))
    } else {
        Cow::Borrowed(token)
    };
    let token = extract_url_at(&token);
    if token.is_empty() {
        return None;
    }
    crate::deob_scan::normalize_liberal_url_token(&token)
        .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&token))
}

fn is_known_url_launcher(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    let basename = lower
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(lower.as_str())
        .trim_end_matches(".exe");
    matches!(
        basename,
        "explorer"
            | "iexplore"
            | "msedge"
            | "edge"
            | "chrome"
            | "firefox"
            | "brave"
            | "opera"
            | "vivaldi"
    )
}

fn strip_quotes(s: &str) -> &str {
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn unquote_start_executable(s: &str) -> Cow<'_, str> {
    let s = s.trim_start();
    if !s.starts_with('"') {
        return Cow::Borrowed(s);
    }
    let after_open = &s[1..];
    let Some(close_idx) = after_open.find('"') else {
        return Cow::Borrowed(s);
    };
    let executable = &after_open[..close_idx];
    let rest = after_open[close_idx + 1..].trim_start();
    if rest.is_empty() {
        Cow::Owned(executable.to_string())
    } else {
        Cow::Owned(format!("{executable} {rest}"))
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
        assert!(!has_v_on_raw("cmd /V:OFF /c echo hi"));
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod extract_cmd_inner_tests {
    use super::extract_cmd_inner;

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
}
