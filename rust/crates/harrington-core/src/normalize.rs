//! Variable expansion. Walks a token stream and produces a string by
//! resolving %VAR%, !VAR!, substring, and substitution against an
//! Environment. Recursively re-lexes resolved values so techniques
//! like `ec%a%ho` (with %a% empty) collapse to `echo`.

use crate::env::Environment;
use crate::lex::{lex, Token, VarOp};
use crate::marker_noise;
use crate::traits::Trait;

const MAX_REEXPAND_DEPTH: u32 = 32;

/// Render a token stream to its normalized string form against `env`.
pub fn normalize_to_string(tokens: &[Token], env: &mut Environment) -> String {
    let normalized = normalize_inner(tokens, env, 0);
    // POST-PASS: caret-process the output. CMD's actual order is
    // var-expand-FIRST then caret-process. Our lex strips most `^X`
    // eagerly (before expansion); only the carets PRESERVED by
    // CaretBeforeSigil (when the following var was empty) remain in
    // the output. Those carets still need their escape semantics:
    //   `^^` → `^`  (escape-self)
    //   `^>` → `>`  (escape metachar; for arith this becomes plain `>`
    //                which arith re-interprets as shift operator)
    //   `^X` → `X`  (no-op for normal chars)
    //   `^`  at EOL → drop
    // Without this pass, xeno-class arith inside `set/a EXPR` has
    // `^>^>` left intact and arith errors out, breaking the dynamic-
    // goto chain.
    let processed = caret_postprocess(&normalized);
    if is_base64_fragment_set_assignment(&processed) || has_replace_marker_operation(&processed) {
        processed
    } else {
        strip_marker_noise(&processed)
    }
}

pub(crate) fn normalize_literal_command_fast(input: &str) -> Option<String> {
    if let Some(set) = normalize_quoted_set_assignment_fast(input) {
        return Some(set);
    }
    if let Some(caret_plain) = normalize_caret_plain_command_fast(input) {
        return Some(caret_plain);
    }
    if input.is_empty() || input.starts_with(' ') || input.ends_with(' ') {
        return None;
    }
    let mut prev_space = false;
    for &b in input.as_bytes() {
        if b == b' ' {
            if prev_space {
                return None;
            }
            prev_space = true;
            continue;
        }
        prev_space = false;
        if matches!(
            b,
            b'%' | b'!'
                | b'^'
                | b'"'
                | b'\t'
                | b'\r'
                | b'\n'
                | b','
                | b';'
                | b'&'
                | b'|'
                | b'<'
                | b'>'
                | b'('
                | b')'
        ) {
            return None;
        }
    }
    if marker_noise::has_repeated_sandwich_candidate_shape(input) {
        return None;
    }
    Some(input.to_string())
}

fn normalize_caret_plain_command_fast(input: &str) -> Option<String> {
    if !input.contains('^') || input.is_empty() || input.starts_with(' ') || input.ends_with(' ') {
        return None;
    }
    let mut prev_space = false;
    for &b in input.as_bytes() {
        if b == b' ' {
            if prev_space {
                return None;
            }
            prev_space = true;
            continue;
        }
        prev_space = false;
        if matches!(
            b,
            b'%' | b'!'
                | b'"'
                | b'\t'
                | b'\r'
                | b'\n'
                | b','
                | b';'
                | b'&'
                | b'|'
                | b'<'
                | b'>'
                | b'('
                | b')'
        ) {
            return None;
        }
    }
    let processed = caret_postprocess(input);
    if marker_noise::has_repeated_sandwich_candidate_shape(&processed) {
        return None;
    }
    if is_base64_fragment_set_assignment(&processed) || has_replace_marker_operation(&processed) {
        Some(processed)
    } else {
        Some(strip_marker_noise(&processed))
    }
}

fn normalize_quoted_set_assignment_fast(input: &str) -> Option<String> {
    if input
        .bytes()
        .any(|b| matches!(b, b'%' | b'!' | b'^' | b'\t' | b'\r' | b'\n'))
    {
        return None;
    }
    let trimmed = input.trim();
    if !trimmed.get(0..4)?.eq_ignore_ascii_case("set ") {
        return None;
    }
    let quoted = trimmed[4..].strip_prefix('"')?.strip_suffix('"')?;
    if !quoted.contains('=') {
        return None;
    }
    let mut in_double_quote = true;
    for &b in &trimmed.as_bytes()[5..trimmed.len() - 1] {
        if b == b'"' {
            in_double_quote = !in_double_quote;
        } else if !in_double_quote
            && matches!(b, b',' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')')
        {
            return None;
        }
    }
    if !in_double_quote {
        return None;
    }
    let processed = input.to_string();
    if is_base64_fragment_set_assignment(&processed) || has_replace_marker_operation(&processed) {
        Some(processed)
    } else {
        Some(strip_marker_noise(&processed))
    }
}

/// CMD caret-process post-pass. See `normalize_to_string` for context.
/// Only operates on `^` chars that survived normalization (i.e., were
/// preserved by CaretBeforeSigil-with-empty-var); doesn't touch the
/// ~99% of `^`-less output.
///
/// CMD semantics: `^` is a metacharacter escape OUTSIDE double quotes
/// and a LITERAL char inside double quotes (the latter is what `set /a
/// "(0xA ^ 0xFDE3)"` relies on to use `^` as XOR). We mirror that.
fn caret_postprocess(s: &str) -> String {
    if !s.contains('^') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut in_dq = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            in_dq = !in_dq;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '^' && !in_dq {
            if i + 1 < chars.len() {
                // Escape next char: emit next char literal, skip both.
                out.push(chars[i + 1]);
                i += 2;
            } else {
                // Trailing `^` — drop (CMD line continuation, no next line
                // here to join).
                i += 1;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Render a `VarOp` back to the source-form text (the part after `:` inside
/// `%VAR:...%` or `!VAR:...!`). Used when echoing a var reference verbatim
/// — for example a `!VAR:OLD=NEW!` token at a scope where delayed expansion
/// is currently off, so the marker-strip happens later in a `cmd /V/D/c`
/// child.
fn render_var_op(op: &crate::lex::VarOp) -> String {
    use crate::lex::VarOp;
    match op {
        VarOp::Substr { index, length } => match length {
            Some(n) => format!("~{index},{n}"),
            None => format!("~{index}"),
        },
        VarOp::Substitute {
            needle,
            replacement,
            leading_wildcard,
        } => {
            let lead = if *leading_wildcard { "*" } else { "" };
            format!("{lead}{needle}={replacement}")
        }
        VarOp::Raw(s) => s.clone(),
    }
}

fn strip_marker_noise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for chunk in text.split_inclusive('\n') {
        let (line, newline) = match chunk.strip_suffix('\n') {
            Some(line) => (line, "\n"),
            None => (chunk, ""),
        };
        if has_replace_marker_operation(line) {
            out.push_str(line);
        } else {
            out.push_str(&strip_marker_noise_preserving_base64(line));
        }
        out.push_str(newline);
    }
    out
}

fn has_replace_marker_operation(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(".replace(") || lower.contains("::replace(") || lower.contains("-replace")
}

fn is_base64_fragment_set_assignment(text: &str) -> bool {
    let trimmed = text.trim_start_matches(|c: char| c == '@' || c == '(' || c.is_whitespace());
    let Some(rest) = trimmed
        .strip_prefix("set")
        .or_else(|| trimmed.strip_prefix("SET"))
    else {
        return false;
    };
    if !rest
        .chars()
        .next()
        .is_some_and(|c| c.is_whitespace() || c == '"')
    {
        return false;
    }
    let rest = rest.trim_start();
    if rest
        .get(..2)
        .is_some_and(|flag| flag.eq_ignore_ascii_case("/a"))
    {
        return false;
    }
    let body = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.strip_suffix('"').unwrap_or(stripped)
    } else {
        rest
    };
    let Some((_, value)) = body.split_once('=') else {
        return false;
    };
    let value = value.trim();
    value.len() >= 16
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        && match value.bytes().position(|b| b == b'=') {
            Some(idx) => value[idx..].bytes().all(|b| b == b'='),
            None => true,
        }
}

fn strip_marker_noise_preserving_base64(text: &str) -> String {
    if text.len() > marker_noise::MAX_SCAN_BYTES {
        return text.to_string();
    }
    let spans = marker_noise::decodable_base64_spans(text);
    if spans.is_empty() {
        return marker_noise::strip_line(text);
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end) in spans {
        if start > cursor {
            out.push_str(&marker_noise::strip_line(&text[cursor..start]));
        }
        out.push_str(&text[start..end]);
        cursor = end;
    }
    if cursor < text.len() {
        out.push_str(&marker_noise::strip_line(&text[cursor..]));
    }
    out
}

pub(crate) fn normalize_inner(tokens: &[Token], env: &mut Environment, depth: u32) -> String {
    let mut out = String::new();
    // Tracks whether a `CaretBeforeSigil` was just emitted. The next
    // VarPercent/VarBang resolves it: if the expansion is empty, the
    // pending caret renders as a literal `^` (preserves XOR semantics
    // in arith context — `0x6b84^%empty%^%empty%031624` → `0x6b84^^031624`).
    // If non-empty, the caret is dropped (CMD's escape-first-char rule
    // is a no-op for normal chars in the expanded value).
    let mut pending_caret = false;
    for tok in tokens {
        match tok {
            Token::CaretBeforeSigil => {
                pending_caret = true;
                continue;
            }
            Token::Word(s) => out.push_str(s),
            Token::DoubleQuoted(s) => {
                out.push('"');
                out.push_str(&expand_vars_in_string(s, env, depth));
                out.push('"');
            }
            Token::Whitespace => out.push(' '),
            Token::OpAnd => out.push('&'),
            Token::OpAndAnd => out.push_str("&&"),
            Token::OpOr => out.push('|'),
            Token::OpOrOr => out.push_str("||"),
            Token::OpRedirect { fd, append } => {
                if *fd != 1 {
                    out.push_str(&fd.to_string());
                }
                out.push('>');
                if *append {
                    out.push('>');
                }
            }
            Token::OpInput => out.push('<'),
            Token::OpenParen => out.push('('),
            Token::CloseParen => out.push(')'),
            Token::VarPercent { name, op } => {
                let before = out.len();
                expand_var(env, name, op.as_ref(), &mut out, depth, false);
                let expanded_empty = out.len() == before;
                if pending_caret {
                    if expanded_empty {
                        // var empty → caret remains literal. The final
                        // caret_postprocess() pass will resolve it
                        // (`^^`→`^`, `^X`→`X`, trailing→drop).
                        out.insert(before, '^');
                    }
                    // else: var non-empty → caret was a no-op escape; dropped
                    pending_caret = false;
                }
            }
            Token::VarBang { name, op } => {
                if env.delayed_expansion {
                    if !env
                        .traits
                        .iter()
                        .any(|t| matches!(t, Trait::DelayedExpansionUsed))
                    {
                        env.traits.push(Trait::DelayedExpansionUsed);
                    }
                    let before = out.len();
                    expand_var(env, name, op.as_ref(), &mut out, depth, true);
                    let expanded_empty = out.len() == before;
                    if pending_caret {
                        if expanded_empty {
                            // caret_postprocess() handles the rest.
                            out.insert(before, '^');
                        }
                        pending_caret = false;
                    }
                } else {
                    // Delayed expansion is off: echo the reference verbatim so
                    // downstream stages (e.g. a cmd /V/D/c that enables it)
                    // still see the original `!VAR:OLD=NEW!` form. Previously
                    // we dropped the operator, which silently broke marker
                    // stripping in the bad.bat-style HTA droppers.
                    out.push('!');
                    out.push_str(name);
                    if let Some(op) = op {
                        out.push(':');
                        out.push_str(&render_var_op(op));
                    }
                    out.push('!');
                }
            }
            Token::PositionalArg(n) => {
                if let Some(frame) = env.call_stack.last() {
                    if *n == 0 {
                        out.push_str("script.bat");
                    } else if let Some(arg) = frame.args.get((*n as usize).saturating_sub(1)) {
                        out.push_str(arg);
                    }
                } else if *n == 0 {
                    out.push_str("script.bat");
                }
            }
            Token::AllArgs => {
                if let Some(frame) = env.call_stack.last() {
                    out.push_str(&frame.args.join(" "));
                }
            }
            Token::PercentTilde { flags, arg_index } => {
                out.push_str(&render_percent_tilde(env, *flags, *arg_index));
            }
            Token::ForVar(c) => {
                // Loop variable seen outside an iterating FOR body —
                // preserve the source `%%X` form rather than dropping
                // the sigil. (When a FOR loop actually runs, the
                // handler substitutes `%%X` -> value before this lex
                // pass, so this branch only fires for unresolved bodies.)
                out.push('%');
                out.push('%');
                out.push(*c);
            }
        }
        // Any token other than a sigil (consumed above) discards a
        // pending caret — `^` only escapes if it immediately precedes
        // its target on emission.
        if pending_caret
            && !matches!(
                tok,
                Token::VarPercent { .. } | Token::VarBang { .. } | Token::CaretBeforeSigil
            )
        {
            // Strange — shouldn't reach here because CaretBeforeSigil is
            // only emitted before a sigil. Defensive drop.
            pending_caret = false;
        }
    }
    out
}

fn expand_var(
    env: &mut Environment,
    name: &str,
    op: Option<&VarOp>,
    out: &mut String,
    depth: u32,
    _is_bang: bool,
) {
    // Pre-expand any nested `%X%` / `!X!` refs in the var NAME — AbObUs-
    // family char-substitution packers build the var name itself from a
    // chain of `%alphabet:~N,1%` substring extractions (e.g.
    // `!%A:~18,1%%PTBhumIOyCSiIO:~0,1%…!` → `!QFeKjKNuT!`). The lex'd name
    // still contains those `%…%` literals; without resolving them the
    // env.get lookup always fails. Skip on plain ASCII alnum names — the
    // common case — to avoid pointless work.
    let name_owned: String;
    let name = if (name.contains('%') || name.contains('!')) && depth + 1 < MAX_REEXPAND_DEPTH {
        name_owned = expand_vars_in_string(name, env, depth + 1);
        name_owned.as_str()
    } else {
        name
    };
    let raw = match env.get(name) {
        Some(v) => v,
        None => {
            // Obfuscator noise fallback: AbObUsObfuscator-style packers
            // wrap defined variable references with non-ASCII prefix /
            // suffix garbage, e.g. `%<emoji-junk>豆埃阿埃%`. The full
            // name lookup misses, but the trailing ASCII/CJK-letter suffix
            // is the real variable. Try the longest defined suffix (only
            // when the missed name contains non-ASCII chars, so legit
            // unset ASCII vars like `%SOMEVAR%` still collapse to empty).
            let has_non_ascii = !name.is_ascii();
            let mut found = None;
            if has_non_ascii {
                let mut starts: Vec<usize> = name.char_indices().map(|(i, _)| i).collect();
                starts.push(name.len());
                // Try suffix-strip first (longest defined suffix wins).
                for &start in starts.iter().skip(1) {
                    if start >= name.len() {
                        break;
                    }
                    let candidate = &name[start..];
                    if candidate.is_empty() {
                        continue;
                    }
                    if let Some(v) = env.get(candidate) {
                        found = Some(v);
                        break;
                    }
                }
                // Then try prefix-strip from the other end.
                if found.is_none() {
                    let ends: Vec<usize> = name.char_indices().map(|(i, _)| i).collect();
                    for &end in ends.iter().rev().skip(1) {
                        let candidate = &name[..end];
                        if candidate.is_empty() {
                            continue;
                        }
                        if let Some(v) = env.get(candidate) {
                            found = Some(v);
                            break;
                        }
                    }
                }
            }
            if let Some(v) = found {
                v
            } else {
                // Known runtime-only vars (errorlevel etc.) are intentionally
                // unset in the baseline so we don't fold conditional logic
                // to constants. Render them as the source `%name%` literal
                // so the analyst can still see what was being checked,
                // rather than letting the deob collapse `if %errorlevel%
                // NEQ 0` to `if  NEQ 0`.
                let lc = name.to_ascii_lowercase();
                if matches!(
                    lc.as_str(),
                    "errorlevel"
                        | "cmdcmdline"
                        | "cmdextversion"
                        | "dirstack"
                        | "highestnumanodenumber"
                ) {
                    if _is_bang {
                        out.push('!');
                        out.push_str(name);
                        out.push('!');
                    } else {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                return;
            }
        }
    };
    let value = match op {
        None => raw,
        Some(VarOp::Substr { index, length }) => apply_substr(&raw, *index, *length),
        Some(VarOp::Substitute {
            needle,
            replacement,
            leading_wildcard,
        }) => {
            // Needle and replacement may themselves contain `%X%` / `!X!`
            // refs (e.g. `!S:%M%=!`). Expand both before applying.
            let (n_expanded, r_expanded) = if depth + 1 < MAX_REEXPAND_DEPTH
                && (needle.contains('%')
                    || needle.contains('!')
                    || replacement.contains('%')
                    || replacement.contains('!'))
            {
                (
                    expand_vars_in_string(needle, env, depth + 1),
                    expand_vars_in_string(replacement, env, depth + 1),
                )
            } else {
                (needle.clone(), replacement.clone())
            };
            apply_substitute(&raw, &n_expanded, &r_expanded, *leading_wildcard)
        }
        Some(VarOp::Raw(op_str)) => {
            // Expand any nested %X%/!X! refs in the op body, then re-parse
            // the result as a Substr or Substitute. If the post-expansion
            // op still can't parse, fall back to the raw value.
            let expanded = if depth + 1 < MAX_REEXPAND_DEPTH {
                expand_vars_in_string(op_str, env, depth + 1)
            } else {
                op_str.clone()
            };
            let parsed = if expanded.trim_start().starts_with('~') {
                crate::lex::parse_substr(&expanded)
            } else {
                crate::lex::parse_substitute(&expanded)
            };
            match parsed {
                Some(VarOp::Substr { index, length }) => apply_substr(&raw, index, length),
                Some(VarOp::Substitute {
                    needle,
                    replacement,
                    leading_wildcard,
                }) => apply_substitute(&raw, &needle, &replacement, leading_wildcard),
                _ => raw,
            }
        }
    };
    // Re-lex/re-normalize the resolved value so nested %X% / carets
    // resolve. Only do this when the value looks like it could contain
    // a nested reference — bare `%%` (the literal-percent escape) or
    // bare `^` runs would otherwise collapse to a SINGLE `%` / drop the
    // caret during re-normalize, corrupting analyst-visible literals.
    if depth + 1 >= MAX_REEXPAND_DEPTH {
        out.push_str(&value);
        return;
    }
    if value_likely_has_nested_ref(&value) {
        let inner = lex(&value);
        out.push_str(&normalize_inner(&inner, env, depth + 1));
    } else {
        out.push_str(&value);
    }
}

fn value_likely_has_nested_ref(s: &str) -> bool {
    // Look for `%<name>%` or `!<name>!` patterns. A bare `%%` (with no
    // closing `%`) is the percent-escape literal — don't re-lex that.
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let sigil = bytes[i];
        if sigil == b'%' || sigil == b'!' {
            // Need at least one name char after, then a closing same-sigil.
            let mut j = i + 1;
            let mut has_name = false;
            while j < bytes.len() && bytes[j] != sigil {
                if bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_' {
                    has_name = true;
                    j += 1;
                } else {
                    break;
                }
            }
            if has_name && j < bytes.len() && bytes[j] == sigil {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Variable expansion that walks a string char-by-char, expanding `%VAR%` and
/// `!VAR!` (when delayed expansion is on) but preserving everything else
/// (including operators like `;`, `&`, `|` that the lexer would otherwise
/// collapse to whitespace). Used inside double-quoted strings.
fn expand_vars_in_string(s: &str, env: &mut Environment, depth: u32) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '%' => {
                // `%%X`/`%%X:op%%`/`%%~xX` inside quotes are FOR-var refs
                // that the lex would have emitted as Word/ForVar at the
                // top level. Inside DoubleQuoted content the same forms
                // need to be preserved verbatim so the analyst sees what
                // the FOR body actually does.
                if chars.get(i + 1) == Some(&'%') {
                    let mut k = i + 2;
                    let mut had_tilde = false;
                    if chars.get(k) == Some(&'~') {
                        had_tilde = true;
                        k += 1;
                        while k < chars.len()
                            && matches!(
                                chars[k],
                                'f' | 'd' | 'p' | 'n' | 'x' | 's' | 'a' | 't' | 'z' | '$'
                            )
                        {
                            k += 1;
                        }
                    }
                    if let Some(&c2) = chars.get(k) {
                        if c2.is_ascii_alphabetic() {
                            // %%X:op%% — substitute/substring on FOR var.
                            if !had_tilde && chars.get(k + 1) == Some(&':') {
                                let mut m = k + 2;
                                while m + 1 < chars.len() {
                                    if chars[m] == '%' && chars[m + 1] == '%' {
                                        break;
                                    }
                                    m += 1;
                                }
                                if m + 1 < chars.len() && chars[m] == '%' && chars[m + 1] == '%' {
                                    let raw: String = chars[i..m + 2].iter().collect();
                                    out.push_str(&raw);
                                    i = m + 2;
                                    continue;
                                }
                            }
                            // Plain `%%X` or `%%~xX` — emit verbatim.
                            let raw: String = chars[i..=k].iter().collect();
                            out.push_str(&raw);
                            i = k + 1;
                            continue;
                        }
                    }
                    // `%%` not followed by a letter → literal `%` (CMD
                    // collapses doubled percent during var-expansion).
                    if !had_tilde {
                        out.push('%');
                        i += 2;
                        continue;
                    }
                }
                // If followed by '~' this is a %~flags0 / %~f1 PercentTilde construct —
                // NOT a %VARNAME% reference.  Emit the '%' literally and continue; the
                // rest of the modifier (e.g. `~f0`) will be emitted as normal characters
                // by the `_ =>` arm.  This avoids consuming large swaths of text up to
                // the next unrelated '%'.
                if chars.get(i + 1) == Some(&'~') {
                    out.push('%');
                    i += 1;
                    continue;
                }
                // Find matching %; if not found, emit the % literally and advance.
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() && chars[j] != '%' {
                    name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && !name.is_empty() {
                    // Got a closing %; resolve VAR (with possible :op)
                    let value = resolve_var_ref(&name, env, false, depth);
                    out.push_str(&value);
                    i = j + 1;
                } else {
                    // No closing % or empty name — emit literally
                    out.push('%');
                    i += 1;
                }
            }
            '!' if env.delayed_expansion => {
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() && chars[j] != '!' {
                    name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && !name.is_empty() {
                    // Pre-expand any nested `%X%` / `!X!` refs in the var
                    // NAME. AbObUs-family char-substitution packers build the
                    // delayed-expansion var name itself from a chain of
                    // `%alphabet:~N,1%` substring extractions, e.g.
                    //     !%A:~18,1%%PTBhumIOyCSiIO:~0,1%…!  →  !QFeKjKNuT!
                    // Without this the inner `%…%` survives as part of the
                    // lookup key and env.get always fails, dropping all
                    // chars assembled by the fragment-var concat that the
                    // line then performs.
                    let resolved_name = if (name.contains('%') || name.contains('!'))
                        && depth + 1 < MAX_REEXPAND_DEPTH
                    {
                        expand_vars_in_string(&name, env, depth + 1)
                    } else {
                        name.clone()
                    };
                    let value = resolve_var_ref(&resolved_name, env, true, depth);
                    out.push_str(&value);
                    i = j + 1;
                } else {
                    out.push('!');
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Resolve a single var-ref body (the part between sigils). Handles bare
/// `NAME` plus `NAME:~i,n` substring and `NAME:s1=s2` substitution forms.
fn resolve_var_ref(body: &str, env: &mut Environment, _is_bang: bool, depth: u32) -> String {
    let (name, op_str) = match body.find(':') {
        Some(p) => (&body[..p], Some(&body[p + 1..])),
        None => (body, None),
    };
    let raw = match env.get(name) {
        Some(v) => v,
        None => return String::new(),
    };
    let value = match op_str {
        None => raw,
        Some(op) => {
            // Real-corpus loops do things like
            //     set RMZ=!CHAR:~%R%,1!%RMZ%
            // where the substring index lives in a percent-resolved
            // variable. Pre-expand any `%X%` / `!X!` references inside the
            // op string before parsing. Without this `parse_substr("~%R%,1")`
            // fails and the fallback returns the whole `raw` value,
            // silently breaking the obfuscator's character-picker loop.
            // (Lex's VarOp::Raw path uses the same idea for the percent
            // form; this branch handles the body-collected bang form in
            // `expand_vars_in_string`.)
            let op_owned: String;
            let op = if (op.contains('%') || op.contains('!')) && depth + 1 < MAX_REEXPAND_DEPTH {
                op_owned = expand_vars_in_string(op, env, depth + 1);
                op_owned.as_str()
            } else {
                op
            };
            if op.trim_start().starts_with('~') {
                if let Some(crate::lex::VarOp::Substr { index, length }) =
                    crate::lex::parse_substr(op)
                {
                    apply_substr(&raw, index, length)
                } else {
                    raw
                }
            } else if let Some(crate::lex::VarOp::Substitute {
                needle,
                replacement,
                leading_wildcard,
            }) = crate::lex::parse_substitute(op)
            {
                apply_substitute(&raw, &needle, &replacement, leading_wildcard)
            } else {
                raw
            }
        }
    };
    // Re-lex/re-normalize if the resolved value itself contains %/!/^
    if depth + 1 >= MAX_REEXPAND_DEPTH {
        return value;
    }
    if value.contains('%') || value.contains('!') || value.contains('^') {
        let inner = lex(&value);
        normalize_inner(&inner, env, depth + 1)
    } else {
        value
    }
}

fn render_percent_tilde(
    env: &crate::env::Environment,
    flags: crate::lex::PercentTildeFlags,
    arg_index: u8,
) -> String {
    // Mirrors batch_interpreter.py::percent_tilde (line 910).
    let bare = if arg_index == 0 {
        percent_tilde_arg0_path(env)
    } else if let Some(frame) = env.call_stack.last() {
        frame
            .args
            .get((arg_index as usize).saturating_sub(1))
            .cloned()
            .unwrap_or_default()
    } else {
        String::new()
    };

    if !flags.f
        && !flags.d
        && !flags.p
        && !flags.n
        && !flags.x
        && !flags.s
        && !flags.a
        && !flags.t
        && !flags.z
    {
        return bare.trim_matches('"').to_string();
    }

    let mut out = String::new();
    if flags.a {
        out.push_str("--a-------- ");
    }
    if flags.t {
        out.push_str("12/30/2022 11:41 AM ");
    }
    if flags.z {
        if let Some(p) = &env.file_path {
            match std::fs::metadata(p) {
                Ok(m) => out.push_str(&format!("{} ", m.len())),
                Err(_) => out.push_str("700 "),
            }
        } else {
            out.push_str("700 ");
        }
    }

    let arg0_parts = percent_tilde_path_parts(&bare);
    if flags.f {
        out.push_str(&arg0_parts.full);
    } else {
        if flags.d {
            out.push_str(&arg0_parts.drive);
        }
        if flags.p {
            out.push_str(&arg0_parts.parent);
        }
        if flags.n {
            out.push_str(&arg0_parts.stem);
        }
        if flags.x {
            out.push_str(&arg0_parts.extension);
        }
        if flags.s && out.is_empty() {
            out.push_str(&arg0_parts.full);
        }
    }
    out.trim().to_string()
}

struct PercentTildePathParts {
    full: String,
    drive: String,
    parent: String,
    stem: String,
    extension: String,
}

fn percent_tilde_arg0_path(env: &crate::env::Environment) -> String {
    env.file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "C:\\Users\\al\\Downloads\\script.bat".to_string())
}

fn percent_tilde_path_parts(path: &str) -> PercentTildePathParts {
    let full = path.trim_matches('"').to_string();
    let last_sep = full.rfind(['\\', '/']);
    let (parent, file_name) = match last_sep {
        Some(idx) => (full[..=idx].to_string(), &full[idx + 1..]),
        None => ("\\Users\\al\\Downloads\\".to_string(), full.as_str()),
    };
    let drive = if full.as_bytes().get(1) == Some(&b':') {
        full[..2].to_string()
    } else {
        "C:".to_string()
    };
    let (stem, extension) = match file_name.rfind('.') {
        Some(idx) if idx > 0 => (file_name[..idx].to_string(), file_name[idx..].to_string()),
        _ => (file_name.to_string(), String::new()),
    };

    PercentTildePathParts {
        full,
        drive,
        parent,
        stem,
        extension,
    }
}

pub(crate) fn apply_substr(s: &str, index: i64, length: Option<i64>) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len() as i64;
    let mut start = if index < 0 {
        (len + index).max(0)
    } else {
        index.min(len)
    };
    if start < 0 {
        start = 0;
    }
    let end = match length {
        None => len,
        Some(n) if n >= 0 => (start + n).min(len),
        Some(n) => (len + n).max(start),
    };
    if end <= start {
        return String::new();
    }
    chars[start as usize..end as usize].iter().collect()
}

pub(crate) fn apply_substitute(s: &str, needle: &str, repl: &str, wildcard: bool) -> String {
    if needle.is_empty() {
        return s.to_string();
    }
    let lower = s.to_ascii_lowercase();
    let nlower = needle.to_ascii_lowercase();
    if wildcard {
        if let Some(pos) = lower.find(&nlower) {
            let after = &s[pos + needle.len()..];
            let mut o = String::with_capacity(repl.len() + after.len());
            o.push_str(repl);
            o.push_str(after);
            return o;
        }
        return s.to_string();
    }
    // Case-insensitive replace-all, char-boundary safe
    let mut out = String::with_capacity(s.len());
    let nlen = needle.len();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Only attempt a match if i + nlen is on a char boundary (prevents
        // slicing mid-char when `needle` is shorter than a multi-byte char).
        if i + nlen <= bytes.len()
            && s.is_char_boundary(i + nlen)
            && s[i..i + nlen].eq_ignore_ascii_case(needle)
        {
            out.push_str(repl);
            i += nlen;
        } else {
            // Advance by one char (not one byte) so `i` stays on a boundary.
            let c = match s[i..].chars().next() {
                Some(c) => c,
                None => break,
            };
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod dosfuscation_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    fn nm(input: &str) -> String {
        let mut env = Environment::new(&Config::default());
        normalize_to_string(&lex(input), &mut env)
    }

    #[test]
    fn double_percent_literal_in_value_not_collapsed_to_one() {
        // Value containing literal `%%` (FOR-var sentinel) was being
        // re-lexed and collapsed to `%` on render. The substring of
        // `%%J` (3 chars, drop last) is `%%` — that must render as
        // `%%`, not `%`. Regression test for the `set AdqoiHFHHoup=
        // %AdqoiHFHHoup:~0,-1%` rendering bug in Snup.bat.
        let mut env = Environment::new(&Config::default());
        env.set("X", "%%J");
        let got = normalize_to_string(&lex("%X:~0,-1%"), &mut env);
        assert_eq!(got, "%%", "got: {:?}", got);
    }

    #[test]
    fn nested_var_ref_in_value_still_re_expands() {
        // The guard must NOT block legitimate nested expansion:
        // `set A=foo`; `set B=%A%bar` => `%B%` resolves to `foobar`.
        let mut env = Environment::new(&Config::default());
        env.set("a", "foo");
        env.set("b", "%a%bar");
        let got = normalize_to_string(&lex("%b%"), &mut env);
        assert_eq!(got, "foobar", "got: {:?}", got);
    }

    #[test]
    fn nested_ref_detector_handles_percent_bang_and_literals() {
        assert!(super::value_likely_has_nested_ref("%A%"));
        assert!(super::value_likely_has_nested_ref("pre!name_1!post"));
        assert!(!super::value_likely_has_nested_ref("%%J"));
        assert!(!super::value_likely_has_nested_ref("%A-"));
        assert!(!super::value_likely_has_nested_ref("plain text"));
    }

    // From batch_deobfuscator/tests/test_FE_DOSfuscation.py::test_variable_manipulation
    #[test]
    fn comspec_plain() {
        assert_eq!(nm("%COMSPEC%"), "C:\\WINDOWS\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_zero() {
        assert_eq!(nm("%COMSPEC:~0%"), "C:\\WINDOWS\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_zero_27() {
        assert_eq!(nm("%COMSPEC:~0,27%"), "C:\\WINDOWS\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_neg7() {
        assert_eq!(nm("%COMSPEC:~-7%"), "cmd.exe");
    }
    #[test]
    fn comspec_neg27() {
        assert_eq!(nm("%COMSPEC:~-27%"), "C:\\WINDOWS\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_neg7_neg4() {
        assert_eq!(nm("%COMSPEC:~-7,-4%"), "cmd");
    }
    #[test]
    fn comspec_neg7_3() {
        assert_eq!(nm("%COMSPEC:~-7,3%"), "cmd");
    }
    #[test]
    fn comspec_zero_huge() {
        assert_eq!(nm("%COMSPEC:~0,1337%"), "C:\\WINDOWS\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_huge_neg() {
        assert_eq!(nm("%COMSPEC:~-1337%"), "C:\\WINDOWS\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_huge_neg_huge() {
        assert_eq!(
            nm("%COMSPEC:~-1337,1337%"),
            "C:\\WINDOWS\\system32\\cmd.exe"
        );
    }
    #[test]
    fn comspec_neg40_3() {
        assert_eq!(nm("%COMSPEC:~-40,3%"), "C:\\");
    }
    #[test]
    fn comspec_neg1_1() {
        assert_eq!(nm("%COMSPEC:~-1,1%"), "e");
    }

    #[test]
    fn comspec_slash_swap() {
        assert_eq!(nm("%COMSPEC:\\=/%"), "C:/WINDOWS/system32/cmd.exe");
    }
    #[test]
    fn comspec_no_match() {
        assert_eq!(
            nm("%COMSPEC:KeepMatt=Happy%"),
            "C:\\WINDOWS\\system32\\cmd.exe"
        );
    }
    #[test]
    fn comspec_wildcard_strip() {
        assert_eq!(nm("%COMSPEC:*System32\\=%"), "cmd.exe");
    }
    #[test]
    fn comspec_wildcard_no_match() {
        assert_eq!(
            nm("%COMSPEC:*Tea=Coffee%"),
            "C:\\WINDOWS\\system32\\cmd.exe"
        );
    }
    #[test]
    fn comspec_wildcard_lower_e() {
        assert_eq!(nm("%COMSPEC:*e=z%"), "zm32\\cmd.exe");
    }
    #[test]
    fn comspec_wildcard_upper_e() {
        assert_eq!(nm("%COMSPEC:*e=Z%"), "Zm32\\cmd.exe");
    }
    #[test]
    fn comspec_s_to_z() {
        assert_eq!(nm("%COMSPEC:s=z%"), "C:\\WINDOWz\\zyztem32\\cmd.exe");
    }
    #[test]
    fn comspec_drop_s() {
        assert_eq!(nm("%COMSPEC:s=%"), "C:\\WINDOW\\ytem32\\cmd.exe");
    }
    #[test]
    fn comspec_wildcard_caps() {
        assert_eq!(nm("%COMSPEC:*S=A%"), "A\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_wildcard_lower() {
        assert_eq!(nm("%COMSPEC:*s=A%"), "A\\system32\\cmd.exe");
    }
    #[test]
    fn comspec_case_swap() {
        assert_eq!(nm("%COMSPEC:cMD=BlA%"), "C:\\WINDOWS\\system32\\BlA.exe");
    }

    #[test]
    fn whitespace_in_op() {
        assert_eq!(nm("%coMSPec:~   -7,    +3%"), "cmd");
    }
    #[test]
    fn whitespace_tabs_in_op() {
        assert_eq!(nm("%coMSPec:~\t-7,\t+3%"), "cmd");
    }

    #[test]
    fn literal_command_fast_path_accepts_plain_single_spaced_text() {
        assert_eq!(
            super::normalize_literal_command_fast("cmd.exe /c dir C:\\Temp"),
            Some("cmd.exe /c dir C:\\Temp".to_string())
        );
    }

    #[test]
    fn literal_command_fast_path_accepts_quoted_set_assignments_like_full_normalizer() {
        for input in [
            r#" set "A=value with spaces" "#,
            r#"set "A=& star""#,
            r#"set "B=t "" /""#,
            r#"set "A=aXYZbXYZ cXYZdXYZ""#,
        ] {
            let full = nm(input);
            assert_eq!(
                super::normalize_literal_command_fast(input).as_deref(),
                Some(full.as_str()),
                "fast path diverged for {input:?}"
            );
        }
    }

    #[test]
    fn literal_command_fast_path_rejects_lexer_sensitive_text() {
        for input in [
            "echo %COMSPEC%",
            "echo !VAR!",
            "echo ^&",
            r#"echo "quoted""#,
            r#"set "A=%COMSPEC%""#,
            r#"set "A=!VAR!""#,
            r#"set "A=value"#,
            r#"set "A""#,
            "echo one  two",
            "echo a,b",
            "echo a;b",
            "echo a&b",
            "echo a|b",
            "echo > out.txt",
            "(echo hi)",
        ] {
            assert!(
                super::normalize_literal_command_fast(input).is_none(),
                "fast path unexpectedly accepted {input:?}"
            );
        }
    }

    #[test]
    fn literal_command_fast_path_accepts_caret_plain_text_like_full_normalizer() {
        let input = "r^e^m payload ABC123+/=";
        let full = nm(input);
        assert_eq!(
            super::normalize_literal_command_fast(input).as_deref(),
            Some(full.as_str())
        );
    }

    #[test]
    fn literal_command_fast_path_rejects_marker_noise_shape() {
        let input = "pXYZoXYZwershell eXYZcXYZho";
        assert!(super::normalize_literal_command_fast(input).is_none());
    }
    #[test]
    fn assembled_set_token() {
        assert_eq!(nm("%comspec:~-16,1%%comspec:~-1%%comspec:~-13,1%"), "set");
    }

    // From test_FE_DOSfuscation.py::test_empty_var
    // Note: with delayed expansion OFF, `!` inside double quotes is preserved literally
    // (not dropped). The old re-lex approach dropped it as an unclosed sigil; the
    // char-level expand_vars_in_string correctly preserves it.
    #[test]
    fn empty_var_sandwich() {
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex(r#"ec%a%ho "Fi%b%nd Ev%c%il!""#), &mut env);
        assert_eq!(out, r#"echo "Find Evil!""#);
    }

    #[test]
    fn bang_substitute_inside_double_quotes_with_delayed() {
        // `!VAR:OLD=NEW!` inside a `"..."` literal must apply the substring
        // substitution; corpus sample `bad.bat` uses
        //   set/p X="!HVVT:Q4B=!!L9X:YSUTZ=/!"
        // to strip its delim markers before writing the .hta payload.
        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = true;
        env.set("VAR", "heXYZllo");
        env.set("VAR2", "worAAld");
        let out = normalize_to_string(&lex(r#"echo "!VAR:XYZ=!!VAR2:AA=/!""#), &mut env);
        assert_eq!(out, r#"echo "hellowor/ld""#);
    }

    #[test]
    fn bang_substitute_outside_quotes_with_delayed() {
        // The non-quoted form already works; pin it as a regression baseline.
        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = true;
        env.set("VAR", "heXYZllo");
        let out = normalize_to_string(&lex(r#"echo !VAR:XYZ=!"#), &mut env);
        assert_eq!(out, "echo hello");
    }

    #[test]
    fn bang_substitute_inside_quotes_with_setp_prefix() {
        // Real-corpus shape from bad.bat:
        //   set/p X="!VAR:OLD=NEW!"
        // The lexer sees `X=` then `"!VAR:OLD=NEW!"`. Substitution must apply.
        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = true;
        env.set("VAR", "heXYZllo");
        let out = normalize_to_string(&lex(r#"set/p X="!VAR:XYZ=!""#), &mut env);
        assert_eq!(out, r#"set/p X="hello""#);
    }

    #[test]
    fn bang_substring_with_percent_resolved_index() {
        // Real-corpus pp.cmd shape: substring INDEX is %R%, not a literal.
        // Previously this returned the whole raw value because
        // parse_substr("~%R%,1") couldn't parse the embedded `%R%`.
        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = true;
        env.set("CHAR", "ABCDEFGHIJ");
        env.set("R", "3");
        let out = normalize_to_string(&lex(r#"echo !CHAR:~%R%,1!"#), &mut env);
        assert_eq!(out, "echo D");
    }

    #[test]
    fn percent_substring_with_percent_resolved_index() {
        // Same bug in the %VAR% form.
        let mut env = Environment::new(&Config::default());
        env.set("CHAR", "ABCDEFGHIJ");
        env.set("R", "3");
        let out = normalize_to_string(&lex(r#"echo %CHAR:~%R%,1%"#), &mut env);
        // CMD evaluates %CHAR:~%R%,1% with %R% pre-expanded → "D"
        assert!(
            out.contains('D') && !out.contains("ABCDEFGHIJ"),
            "expected substring to resolve, got: {}",
            out
        );
    }

    #[test]
    fn caret_inside_quotes_is_literal_xor_operator() {
        // `^` inside a `"..."` is literal in CMD. The XOR operator inside
        // `set /a "_k=(0xA ^ 0xFDE3)"` depends on this; if we strip the
        // caret like we do outside quotes, `set /a` sees `(0xA  0xFDE3)`
        // (two values, no operator) and emits ArithmeticParseError.
        let out = normalize_to_string(
            &lex(r#"echo "_k=(0xA ^ 0xFDE3)""#),
            &mut Environment::new(&Config::default()),
        );
        assert_eq!(out, r#"echo "_k=(0xA ^ 0xFDE3)""#);
    }

    #[test]
    fn caret_outside_quotes_still_escapes() {
        // Regression check: the inside-quotes change must not affect the
        // outside-quotes caret-escape semantics that DOSfuscation relies on.
        let out = normalize_to_string(
            &lex(r#"s^e^t X=hi"#),
            &mut Environment::new(&Config::default()),
        );
        assert_eq!(out, "set X=hi");
    }

    #[test]
    fn random_returns_varying_values() {
        // Real `%random%` returns a different 0..32767 each read.
        // Constant `4` was an unhelpful stub for loops that index by it.
        let mut env = Environment::new(&Config::default());
        let a = normalize_to_string(&lex("echo %random%"), &mut env);
        let b = normalize_to_string(&lex("echo %random%"), &mut env);
        let c = normalize_to_string(&lex("echo %random%"), &mut env);
        assert_ne!(a, b, "expected distinct values, got {} == {}", a, b);
        assert_ne!(b, c, "expected distinct values, got {} == {}", b, c);
    }

    #[test]
    fn doubled_percent_collapses_to_one_in_set_a() {
        // In batch source, `%%` is the escape for a literal `%`. The
        // CMD variable-expansion phase collapses `%%` to a single `%`
        // before the command runs. Inside `set /a "..."` that single
        // percent is the modulo operator.
        //
        // Real-corpus repro: `set /a numa=%random% %% 999 +1000` in
        // c.cmd previously deobbed as `set /a numa=0  999 +1000`
        // (no operator between `0` and `999`), then ArithmeticParseError
        // fired. Now both `%`s in `%%` collapse to one, leaving
        // `set /a numa=0 % 999 +1000` which set /a parses fine.
        let out = normalize_to_string(
            &lex("set /a numa=5 %% 3 +1"),
            &mut Environment::new(&Config::default()),
        );
        assert_eq!(out, "set /a numa=5 % 3 +1");
    }

    #[test]
    fn for_var_with_substitute_op_preserved() {
        // Real corpus form: `Call Set "GUID[%%i:*1=%%]=..."` where
        // `%%i:*1=%%` is the FOR-var i with a substring-substitute op
        // (after CMD's percent-doubling: `%i:*1=%`). Previously this
        // was tokenized as ForVar('i') followed by orphan text — the
        // `:*1=` part disappeared. Now the full `%%i:*1=%%` is emitted
        // as a literal Word so the analyst can read what the loop body
        // is doing.
        let out = normalize_to_string(
            &lex(r#"Call Set "GUID[%%i:*1=%%]=foo""#),
            &mut Environment::new(&Config::default()),
        );
        assert!(out.contains("%%i:*1=%%"), "got: {}", out);
    }

    #[test]
    fn for_var_tilde_modifier_preserved() {
        // `%%~zA` (file size of FOR var A's value), `%%~nB` (name part),
        // `%%~xB` (extension), `%%~$PATH:X` — these have tilde modifiers
        // that depend on runtime file metadata. We can't resolve them
        // statically, so the deob must echo the source form verbatim
        // instead of dropping the `%%` and leaving bare `~zA`. That would
        // turn `if %%~zA gtr 7 ...` into `if ~zA gtr 7 ...` and confuse
        // the if-folder.
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex("if %%~zA gtr 7 start foo.exe"), &mut env);
        assert!(out.contains("%%~zA"), "got: {}", out);
    }

    #[test]
    fn for_var_marker_preserved_when_body_unresolved() {
        // The lexer used to drop both `%`s of `%%X` as unclosed sigils,
        // leaving bare `X` in the deob — corrupting `if %%l==4 (...)` into
        // `if l==4 (...)`. Now `%%X` survives as a literal in unresolved
        // FOR-loop bodies.
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex("if %%l==4 echo hit"), &mut env);
        assert_eq!(out, "if %%l==4 echo hit");
    }

    #[test]
    fn adjacent_percent_refs_separated_by_space() {
        // Regression: my fix for `%CHAR:~%R%,1%` initially used a too-loose
        // "is this a nested var ref?" check that treated space as a valid
        // var-name char, merging `%A:~..% %B:~..%` into one giant ref and
        // dropping the second one. WinBugsFix.cmd has dozens of these.
        let mut env = Environment::new(&Config::default());
        env.set("X", "0123456789");
        let out = normalize_to_string(&lex("%X:~3,1% %X:~5,1%"), &mut env);
        assert_eq!(out, "3 5");
    }

    #[test]
    fn bang_substitute_with_percent_resolved_needle() {
        // The substitute form must also pre-expand its operands.
        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = true;
        env.set("S", "fooXYZbar");
        env.set("M", "XYZ");
        let out = normalize_to_string(&lex(r#"echo !S:%M%=!"#), &mut env);
        assert_eq!(out, "echo foobar");
    }

    #[test]
    fn bang_substitute_echoed_when_delayed_off() {
        // With delayed expansion OFF the `!`-form is preserved literally.
        // The operator MUST be preserved too, not silently dropped.
        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = false;
        env.set("VAR", "heXYZllo");
        let out = normalize_to_string(&lex(r#"echo !VAR:XYZ=!"#), &mut env);
        assert_eq!(out, "echo !VAR:XYZ=!");
    }
}
