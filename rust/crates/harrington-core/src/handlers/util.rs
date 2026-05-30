//! Shared helpers for command-handler implementations.

/// Split a whitespace-separated command line into tokens, keeping
/// double-quoted and single-quoted spans as single tokens. Quote
/// characters are retained in the output tokens (callers strip as needed).
///
/// **Known limitations** (acceptable for our current corpus, but worth
/// noting before publishing): does NOT understand the PowerShell backtick
/// escape (`-Command \`"hi\`"`), here-strings (`@"..."@` / `@'...'@`),
/// `@(...)` subexpression brackets, or `${var}` interpolation. CMD-side
/// callers expect raw arg tokens with quotes preserved, which this gives;
/// the PS handler then applies its own normalization. If a future corpus
/// shape lands that mangles PS args, replace this with a proper tokenizer
/// that emits `(text, quoted)` tuples and update `h_powershell` /
/// `collect_encoded_argument` to honor the `quoted` flag.
pub(crate) fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    for c in s.chars() {
        if c == '"' && !in_sq {
            in_dq = !in_dq;
            cur.push(c);
            continue;
        }
        if c == '\'' && !in_dq {
            in_sq = !in_sq;
            cur.push(c);
            continue;
        }
        if c.is_whitespace() && !in_dq && !in_sq {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
