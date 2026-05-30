//! `for` handler — parses /F, /L and plain forms, runs body per iteration.
//!
//! Because the lexer strips `%%A` loop variables during normalization, this handler
//! must work on the **raw** (pre-normalization) line text.  The public entry point
//! used by `drive()` is `run_for_from_raw`; `h_for` (called on the *normalized* line)
//! is a no-op so that no double-execution occurs.

use crate::env::Environment;
use crate::for_loop::run_body;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex is a compile-time constant; .expect on a literal panic-at-startup is a developer error.
#[allow(clippy::expect_used)]
static FOR_F_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)^\s*for\s+/F\s*(?:"(?P<opts>[^"]*)")?\s*%%?(?P<var>[A-Za-z])\s+in\s*\(\s*(?P<src>.+?)\s*\)\s*do\s+(?P<body>.+)$"#
    ).expect("for /F regex")
});

// Regex is a compile-time constant; .expect on a literal panic-at-startup is a developer error.
#[allow(clippy::expect_used)]
static FOR_L_RE: Lazy<Regex> = Lazy::new(|| {
    // Accept both comma-separated "(11,-1,0)" and space-separated "(11 -1 0)" forms.
    Regex::new(
        r"(?i)^\s*for\s+/L\s+%%?(?P<var>[A-Za-z])\s+in\s*\(\s*(?P<start>[-+]?\d+)[\s,]+(?P<step>[-+]?\d+)[\s,]+(?P<end>[-+]?\d+)\s*\)\s*do\s+(?P<body>.+)$"
    ).expect("for /L regex")
});

// Regex is a compile-time constant; .expect on a literal panic-at-startup is a developer error.
#[allow(clippy::expect_used)]
static FOR_PLAIN_RE: Lazy<Regex> = Lazy::new(|| {
    // CMD accepts both `)do command` and `) do command`; `\s*do\s*` covers
    // either, plus the obfuscator-friendly `)do(` block form.
    Regex::new(
        r"(?i)^\s*for\s+%%?(?P<var>[A-Za-z])\s+in\s*\(\s*(?P<set>[^)]+)\)\s*do\s+(?P<body>.+)$",
    )
    .expect("for plain regex")
});

// ── /F helpers ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct FOpts {
    tokens: Vec<usize>,
    tokens_star: bool,
    delims: String,
    skip: usize,
    // Parsed for spec completeness; behavior not yet implemented.
    #[allow(dead_code)]
    usebackq: bool,
}

fn parse_f_opts(opts: &str) -> FOpts {
    let mut o = FOpts {
        tokens: vec![1],
        tokens_star: false,
        delims: " \t".to_string(),
        skip: 0,
        usebackq: false,
    };
    for kv in opts.split_whitespace() {
        if let Some(eq) = kv.find('=') {
            let key = kv[..eq].to_ascii_lowercase();
            let val = &kv[eq + 1..];
            match key.as_str() {
                "tokens" => {
                    o.tokens.clear();
                    o.tokens_star = false;
                    for part in val.split(',') {
                        let part = part.trim();
                        if part.is_empty() {
                            continue;
                        }
                        if part == "*" {
                            o.tokens_star = true;
                        } else if let Some((start, end)) = parse_token_range(part) {
                            o.tokens.extend(start..=end);
                        } else if let Ok(n) = part.parse::<usize>() {
                            o.tokens.push(n);
                        }
                    }
                    if o.tokens.is_empty() && !o.tokens_star {
                        o.tokens.push(1);
                    }
                }
                "delims" => o.delims = val.to_string(),
                "skip" => {
                    o.skip = val.parse().unwrap_or(0);
                }
                _ => {}
            }
        } else if kv.eq_ignore_ascii_case("usebackq") {
            o.usebackq = true;
        }
    }
    o
}

/// Hard cap on the `for /F tokens=N-M` range. CMD itself only meaningfully
/// indexes tokens 1..=31 (max distinct loop vars); accepting wider attacker-
/// supplied ranges just allocates a huge Vec<usize> and OOMs.
const MAX_TOKEN_RANGE_LEN: usize = 64;

fn parse_token_range(part: &str) -> Option<(usize, usize)> {
    let (start, end) = part.split_once('-')?;
    let start = start.trim().parse::<usize>().ok()?;
    let end = end.trim().parse::<usize>().ok()?;
    if start > end {
        return None;
    }
    // Clamp the range so a malicious `tokens=1-2147483647` cannot allocate
    // billions of usizes.
    let end = end.min(start.saturating_add(MAX_TOKEN_RANGE_LEN.saturating_sub(1)));
    Some((start, end))
}

/// Parse the options string carefully: `delims=` may be followed by a space
/// that is the actual delimiter, so we cannot use a simple `split_whitespace`
/// approach for the whole string.  Instead we scan key=value pairs manually.
fn parse_f_opts_full(opts: &str) -> FOpts {
    // Handle the common `delims=<chars>` where chars could include spaces and
    // be terminated only by the end of the options string or another known key.
    // Strategy: find "delims=" and treat everything after it (up to the next
    // recognised keyword boundary) as the delimiter set.
    let mut base = parse_f_opts(opts);

    // Re-parse delims more carefully.
    if let Some(pos) = opts.to_ascii_lowercase().find("delims=") {
        let after = &opts[pos + "delims=".len()..];
        // The delimiter set ends at EOF or at the start of another keyword
        // ("tokens=", "skip=", "usebackq") preceded by whitespace.
        let keywords = ["tokens=", "skip=", "usebackq"];
        let lower_after = after.to_ascii_lowercase();
        let end = keywords
            .iter()
            .filter_map(|kw| {
                // Find keyword, but only if preceded by whitespace (or at start).
                let mut search_from = 0;
                loop {
                    if let Some(idx) = lower_after[search_from..].find(kw) {
                        let abs = search_from + idx;
                        if abs == 0 || lower_after.as_bytes()[abs - 1].is_ascii_whitespace() {
                            return Some(abs);
                        }
                        search_from = abs + 1;
                    } else {
                        return None;
                    }
                }
            })
            .min()
            .unwrap_or(after.len());
        // When a keyword follows the delimiter set, strip only the single
        // whitespace separator.  When delims is at end-of-opts, keep the
        // value verbatim (a trailing space IS a delimiter, e.g. `delims= `).
        let raw_delims = &after[..end];
        base.delims = if end < after.len() {
            raw_delims.trim_end().to_string()
        } else {
            raw_delims.to_string()
        };
    }

    base
}

fn extract_tokens(line: &str, opts: &FOpts) -> Option<Vec<String>> {
    // tokens=* means capture the entire remainder of the line as-is.
    if opts.tokens_star && opts.tokens.is_empty() {
        return Some(vec![line.to_string()]);
    }
    if opts.delims.is_empty() {
        return Some(vec![line.to_string()]);
    }
    let parts: Vec<&str> = if opts.delims == " \t" {
        line.split_whitespace().collect()
    } else {
        line.split(|c: char| opts.delims.contains(c))
            .filter(|s| !s.is_empty())
            .collect()
    };
    let values: Vec<String> = opts
        .tokens
        .iter()
        .filter_map(|idx| parts.get(idx.saturating_sub(1)).map(|s| s.to_string()))
        .collect();
    if !values.is_empty() {
        return Some(values);
    }
    None
}

fn resolve_f_source(src: &str, env: &mut crate::env::Environment) -> Vec<String> {
    let s = src.trim();
    // Double-quoted string: literal data (one line).
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        return vec![inner.to_string()];
    }
    // Single-quoted: `for /F ... in ('command')` — run as pipeline command.
    if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        let pipeline = &s[1..s.len() - 1];
        return crate::synth::run_pipeline(pipeline, env);
    }
    // Backtick-quoted: run as pipeline (usebackq style).
    if s.starts_with('`') && s.ends_with('`') {
        let pipeline = &s[1..s.len() - 1];
        return crate::synth::run_pipeline(pipeline, env);
    }
    let file_lines = crate::synth::run_pipeline(&format!("type {}", s), env);
    if !file_lines.is_empty() {
        return file_lines;
    }
    env.traits.push(crate::traits::Trait::ForUnresolvedSource {
        pipeline: s.to_string(),
    });
    Vec::new()
}

// ── public entry point ───────────────────────────────────────────────────────

/// Strip obfuscation noise so the FOR regex can match the keyword. Removes
/// `^X` caret escapes (CMD treats `^X` as literal `X`) and `%X%` variable
/// references whose name is non-ASCII *and* not defined in `env` (the AbObUs-
/// style emoji/Arabic/Chinese noise vars that expand to empty). Preserves
/// `%%X` loop-variable references intact so the iteration body's `%%a` refs
/// still work post-strip. UTF-8 safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForZone {
    PreParens,
    InList,
    PostListPreDo,
    Body,
}

fn strip_for_header_noise(raw: &str, env: &Environment) -> String {
    let mut out = String::with_capacity(raw.len());
    let chars: Vec<(usize, char)> = raw.char_indices().collect();
    let mut i = 0usize;
    // FE DOSfuscation "Commas & Semicolons" — `,` and `;` between
    // FOR header tokens (`fo^R;,;%%a,;; i^N,,;( …` and `),;,;dO,,(…`)
    // act as token separators. We collapse them to spaces in three
    // header-shaped zones:
    //   (1) start of line → first `(` (FOR keyword + `/F`/`/L` + var + IN)
    //   (2) inside the IN list, ONLY when we know the IN list is shaped
    //       like a number/value list (no `,` collapse if quotes appear,
    //       since `for /F "delims=,"` etc. uses `,` as data)
    //   (3) IN list closing `)` → `do`
    // After `do` we hand off the body verbatim — substring syntax
    // `!VAR:~N,M!` and inline PS statements need their commas/semicolons.
    let mut zone = ForZone::PreParens;
    let mut paren_depth: i32 = 0;
    let mut in_dq = false;
    while i < chars.len() {
        let (_, c) = chars[i];
        if c == '^' && i + 1 < chars.len() {
            // Caret escape — CMD consumes the `^` and the next char keeps
            // its semantic role (a `^%` still opens a var ref; `^&` is a
            // literal `&` etc.). Just drop the `^` and reprocess from
            // the next position so `%X%` after `^` still triggers var-
            // expansion logic below.
            i += 1;
            continue;
        }
        if c == '"' {
            in_dq = !in_dq;
            out.push(c);
            i += 1;
            continue;
        }
        if !in_dq {
            match c {
                '(' => {
                    paren_depth += 1;
                    if zone == ForZone::PreParens {
                        zone = ForZone::InList;
                    }
                }
                ')' => {
                    paren_depth -= 1;
                    if paren_depth == 0 && zone == ForZone::InList {
                        zone = ForZone::PostListPreDo;
                    }
                }
                _ => {}
            }
            // Detect the `do` keyword at zone PostListPreDo to switch into
            // body-passthrough mode. Step past any caret-escape sigils
            // between `d` and `o` (FE DOSfuscation `d^O`) — the `^`
            // gets dropped on output but `chars[i+1]` still sees it.
            // `^X` consumes the `^` and uses `X` as the escaped char, so
            // we skip JUST the `^` (one char) to land on the `X`.
            if zone == ForZone::PostListPreDo && (c == 'd' || c == 'D') {
                fn skip_carets(chars: &[(usize, char)], mut p: usize, limit: usize) -> usize {
                    let stop = (p + limit).min(chars.len());
                    while p < stop && chars[p].1 == '^' {
                        p += 1;
                    }
                    p
                }
                let p = skip_carets(&chars, i + 1, 4);
                let next_o = chars.get(p).map(|(_, c)| *c);
                if next_o == Some('o') || next_o == Some('O') {
                    let q = skip_carets(&chars, p + 1, 4);
                    let after = chars.get(q).map(|(_, c)| *c);
                    let is_keyword = match after {
                        None => true,
                        Some(c) => c.is_whitespace() || matches!(c, '(' | ',' | ';'),
                    };
                    if is_keyword {
                        out.push(c);
                        out.push(next_o.unwrap_or('o'));
                        // FOR_PLAIN_RE / FOR_F_RE / FOR_L_RE require `do\s+`
                        // before the body. The original char after `do`
                        // (post-strip) might be a non-whitespace separator
                        // like `(`/`,`/`;` (FE DOSfuscation `d^O,,(;(;sEt…`).
                        // Inject a single space so the regex can match. The
                        // body lex re-collapses surrounding whitespace.
                        if !matches!(after, Some(c) if c.is_whitespace()) {
                            out.push(' ');
                        }
                        i = p + 1;
                        zone = ForZone::Body;
                        continue;
                    }
                }
            }
        }
        let collapse_here = !in_dq
            && (c == ',' || c == ';')
            && (zone == ForZone::PreParens
                || zone == ForZone::PostListPreDo
                || (zone == ForZone::InList && paren_depth == 1));
        if collapse_here {
            let mut j = i;
            while j < chars.len() && matches!(chars[j].1, ',' | ';' | ' ' | '\t') {
                j += 1;
            }
            if !out.ends_with(' ') {
                out.push(' ');
            }
            i = j;
            continue;
        }
        if c == '%' {
            // `%%X` is a loop-var reference (or escaped `%`). Preserve the
            // `%%` and the following identifier verbatim so substitution
            // still works. This only fires when we're at a fresh `%` whose
            // neighbour is also `%` — adjacent var refs `%a%%b%` do NOT hit
            // this because the close `%` of `a` is consumed with the ref
            // below (i jumps past it), so the next `%` we see opens `b`.
            if i + 1 < chars.len() && chars[i + 1].1 == '%' {
                out.push('%');
                out.push('%');
                i += 2;
                continue;
            }
            // Find the closing `%` (same line). The span between is a var ref.
            let mut j = i + 1;
            while j < chars.len() && chars[j].1 != '%' && chars[j].1 != '\n' {
                j += 1;
            }
            if j < chars.len() && chars[j].1 == '%' && j > i + 1 {
                let name = &raw[chars[i + 1].0..chars[j].0];
                // Reject spans that aren't real `%VAR%` env refs: a leading
                // `~` (parameter modifier like `%~f0`), or whitespace/quotes
                // inside (which mean the closing `%` we found belongs to a
                // *later* ref and this `%` is a stray literal — `%~f0"') do`
                // must not be swallowed). Leave such `%` literal.
                if name.starts_with('~')
                    || name
                        .chars()
                        .any(|c| c.is_whitespace() || c == '"' || c == '\'')
                {
                    out.push('%');
                    i += 1;
                    continue;
                }
                // Strip embedded carets from the name (obfuscators split
                // names across them, e.g. `%ﯤ◯ﺼ^تكت%`). The op part
                // (`:~i,n` / `:a=b`) is kept for the lookup decision: a
                // substring of a defined var stays; of an unset var drops.
                let name_clean: String = name.chars().filter(|c| *c != '^').collect();
                let base = name_clean.split(':').next().unwrap_or(&name_clean);
                let lc = base.to_ascii_lowercase();
                // Runtime-only vars are intentionally unset in the baseline
                // but should stay visible, not be silently dropped.
                let runtime_only = matches!(
                    lc.as_str(),
                    "errorlevel"
                        | "cmdcmdline"
                        | "cmdextversion"
                        | "dirstack"
                        | "highestnumanodenumber"
                        | "random"
                        | "time"
                        | "date"
                );
                let defined = env.get(base).is_some();
                if !defined && !runtime_only {
                    // Unset var → expands to empty in CMD. Drop the span.
                    i = j + 1;
                    continue;
                }
                // Defined (or runtime-only): keep the WHOLE `%name%` verbatim
                // and jump past the closing `%`, so the close isn't re-read
                // as the start of a `%%` with the next ref.
                out.push_str(&raw[chars[i].0..=chars[j].0]);
                i = j + 1;
                continue;
            }
            // No closing `%` — literal.
            out.push('%');
            i += 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Called by `drive()` on the **raw** (pre-normalization) command string.
/// Returns true if this was a FOR command that was handled.
pub fn run_for_from_raw(raw: &str, env: &mut Environment) -> bool {
    // Trim leading `@` and whitespace (echo-suppression prefix).
    // Build a noise-stripped copy so the keyword regex can match even when
    // the FOR header is shrouded in caret escapes + non-ASCII-named empty
    // var references (AbObUsObfuscator and friends). The cleaned form is
    // also what we use to extract the IN list and body so the iteration
    // works on a clean template; `%%X` loop refs are preserved through the
    // strip, so substitution still works.
    let cleaned = strip_for_header_noise(raw, env);
    let raw = cleaned.as_str();
    let trimmed = raw.trim_start_matches('@').trim();

    // /F must be tried first (more specific than plain for).
    if let Some(caps) = FOR_F_RE.captures(trimmed) {
        let opts = caps
            .name("opts")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let var = caps
            .name("var")
            .and_then(|m| m.as_str().chars().next())
            .unwrap_or('A');
        let src = caps
            .name("src")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let body = caps
            .name("body")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        let parsed = parse_f_opts_full(&opts);
        let lines = resolve_f_source(&src, env);
        let values: Vec<Vec<String>> = lines
            .into_iter()
            .skip(parsed.skip)
            .filter_map(|line| extract_tokens(&line, &parsed))
            .collect();

        if values.is_empty() {
            // Source was unresolvable. Still run the body once for IOC
            // scanning, but skip iter_output emission — the FOR header
            // line already contains the body text verbatim and the
            // sentinel substitution (`%%i` → `%%i`) is a no-op, so
            // appending it again would duplicate the line in the deob.
            let sentinel = format!("%%{var}");
            run_iter_body_inner(&body, var, vec![sentinel].into_iter(), env, false);
        } else {
            run_iter_body_multi(&body, var, values.into_iter(), env);
        }
        return true;
    }

    if let Some(caps) = FOR_L_RE.captures(trimmed) {
        let var = caps
            .name("var")
            .and_then(|m| m.as_str().chars().next())
            .unwrap_or('A');
        let start: i64 = caps
            .name("start")
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let step: i64 = caps
            .name("step")
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(1);
        let end: i64 = caps
            .name("end")
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let body = caps
            .name("body")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        if step == 0 {
            return true;
        }

        // Generate values lazily so run_body's iteration cap fires correctly.
        let values = numeric_range(start, step, end);
        run_iter_body(&body, var, values, env);
        return true;
    }

    if let Some(caps) = FOR_PLAIN_RE.captures(trimmed) {
        let var = caps
            .name("var")
            .and_then(|m| m.as_str().chars().next())
            .unwrap_or('A');
        let set = caps
            .name("set")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let body = caps
            .name("body")
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        // Split on whitespace AND `,`/`;` (FE DOSfuscation FORcoding lists
        // sometimes use them interchangeably with whitespace). Also drop
        // a leading explicit `+` sign on signed integers — `+1` is the
        // same iter value as `1`, but the literal `+1` would be retained
        // by `split_whitespace` alone and used verbatim in the substring
        // index (`!unique:~+1,1!` works, but only because parse_substr
        // accepts the leading sign — for safety we drop it here too).
        let values: Vec<String> = set
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .filter(|s| !s.is_empty())
            .map(|s| {
                if let Some(rest) = s.strip_prefix('+') {
                    rest.to_string()
                } else {
                    s.to_string()
                }
            })
            .collect();
        run_iter_body(&body, var, values.into_iter(), env);
        return true;
    }

    false
}

/// No-op: `drive()` uses `run_for_from_raw` on the raw line before normalization.
/// This is registered in the handler table so `interp::interpret_line` doesn't
/// dispatch an unknown-command no-op for the normalized `for …` text.
pub fn h_for(_raw: &str, _env: &mut Environment) {
    // Intentionally empty — all work is done by run_for_from_raw in drive().
}

/// Build a lazy iterator over the numeric range `start, start+step, ..., end`.
/// The iterator stops when the value passes `end` (direction inferred from `step` sign).
/// This is lazy so `run_body`'s iteration cap fires before values are generated.
fn numeric_range(start: i64, step: i64, end: i64) -> impl Iterator<Item = String> {
    let mut current = start;
    let forward = step > 0;
    std::iter::from_fn(move || {
        if forward && current > end {
            return None;
        }
        if !forward && current < end {
            return None;
        }
        let v = current.to_string();
        current = current.saturating_add(step);
        Some(v)
    })
}

fn run_iter_body(
    body: &str,
    var: char,
    values: impl Iterator<Item = String>,
    env: &mut Environment,
) {
    run_iter_body_inner(body, var, values, env, true);
}

fn run_iter_body_multi(
    body: &str,
    var: char,
    values: impl Iterator<Item = Vec<String>>,
    env: &mut Environment,
) {
    if body.trim().is_empty() || body.trim() == "(" {
        return;
    }
    let body_inner = strip_outer_parens(body);
    for row in values {
        if env.limits.iterations >= env.limits.max_iterations {
            if !env
                .traits
                .iter()
                .any(|t| matches!(t, crate::traits::Trait::IterationCapped { .. }))
            {
                env.traits.push(crate::traits::Trait::IterationCapped {
                    command: body.to_string(),
                });
            }
            break;
        }
        env.limits.iterations += 1;
        let substituted = substitute_loop_vars(body_inner, var, &row);
        let toks = crate::lex::lex(&substituted);
        let normalized = crate::normalize::normalize_to_string(&toks, env);
        // If the iteration body is itself a FOR command (nested loop),
        // recursively dispatch it through run_for_from_raw so the inner
        // loop also unrolls. interpret_line doesn't handle FOR (h_for is
        // a no-op), so without this nested FORs are silently dropped.
        if !run_for_from_raw(&normalized, env) {
            crate::interp::interpret_line(&normalized, env);
        }
        env.iter_output.push_str(&normalized);
        env.iter_output.push_str("\r\n");
    }
}

fn substitute_loop_vars(body: &str, first_var: char, values: &[String]) -> String {
    let mut out = body.to_string();
    for (offset, value) in values.iter().enumerate().rev() {
        let Some(var) = char::from_u32((first_var as u32).saturating_add(offset as u32)) else {
            continue;
        };
        out = crate::for_loop::substitute_loop_var(&out, var, value);
    }
    out
}

fn run_iter_body_inner(
    body: &str,
    var: char,
    values: impl Iterator<Item = String>,
    env: &mut Environment,
    emit_to_iter_output: bool,
) {
    // Multi-line FOR (`for %%f in (...) do (\n...\n)`) where the body
    // is on subsequent physical lines: line_reader does NOT fold them
    // into one logical line, so the regex captures only the `(` from
    // `do (`. With body == `(`, iter_output would emit a redundant `(`
    // right after the FOR header's own trailing `(`, doubling the
    // open-paren in the deob. The subsequent physical lines are
    // already processed independently by drive(), so we can simply
    // skip the iter emit for empty/paren-only bodies.
    if body.trim().is_empty() || body.trim() == "(" {
        return;
    }
    // The body of an inline `for ... do ( ... )` is a parenthesized
    // block when the whole loop fits on one logical line. The wrapper
    // FOR line is emitted with its trailing `(`, so emitting the
    // body's `(...)` again would produce a double-`(` in the deob.
    // Strip a matching outer pair so iter_output renders the inner
    // statements on their own line.
    let body_inner = strip_outer_parens(body);
    run_body(body_inner, var, values, env, |env, iter_cmd| {
        // Lex + normalize + interpret each iteration's substituted command.
        let toks = crate::lex::lex(iter_cmd);
        let normalized = crate::normalize::normalize_to_string(&toks, env);
        // Recurse into nested FOR so loops like `for /l %%i in (1 1 1) do
        // for %%a in (...) do ...` unroll to the leaf body. interpret_line
        // alone won't do this — h_for is a deliberate no-op.
        if !run_for_from_raw(&normalized, env) {
            crate::interp::interpret_line(&normalized, env);
        }
        if emit_to_iter_output {
            // Append normalized text to iter_output so drive() can include it in output.
            env.iter_output.push_str(&normalized);
            env.iter_output.push_str("\r\n");
        }
    });
}

fn strip_outer_parens(s: &str) -> &str {
    // Iteratively peel matching outer pairs so the FE DOSfuscation
    // wrapped FORcoding/Reversal body `( ( sEt fINal=… ))` (two layers
    // of parens at the same depth) collapses to the bare SET that
    // interpret_line can dispatch. Also skip leading `,;` / `;,` runs
    // (FE comma-and-semicolon obfuscation can leave them before the
    // first `(` after our header-zone strip switches to body
    // passthrough mode).
    let mut cur = s;
    loop {
        let t = cur
            .trim_start_matches(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .trim_end_matches(|c: char| c.is_whitespace() || c == ',' || c == ';');
        if !t.starts_with('(') || !t.ends_with(')') || t.len() < 2 {
            return if t.len() == cur.len() { cur } else { t };
        }
        // Confirm the leading `(` matches the trailing `)` (nesting-aware,
        // double-quote aware). If not balanced as a single outer group,
        // leave the body untouched.
        let mut depth: i32 = 0;
        let mut in_dq = false;
        let bytes = t.as_bytes();
        let mut paired = true;
        for (i, &b) in bytes.iter().enumerate() {
            match b as char {
                '"' => in_dq = !in_dq,
                '(' if !in_dq => depth += 1,
                ')' if !in_dq => {
                    depth -= 1;
                    if depth == 0 && i + 1 != bytes.len() {
                        paired = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !paired || depth != 0 {
            return cur;
        }
        cur = &t[1..t.len() - 1];
    }
}
