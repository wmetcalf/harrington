//! Token types and variable-operator types. The lexer state machine that
//! produces these lives in the same file (Task 6 onward).

/// Characters that count as "inside an argument" for the comma-vs-whitespace
/// decision. We treat the comma in `host.dll,Entry` as literal because both
/// neighbors are arg-style chars; the comma in `,;,cmd.exe` is whitespace
/// because the neighbor is another separator. Parens are included so that
/// PowerShell code embedded in a batch script (e.g. `... -join '');$bnt=...`)
/// keeps its semicolons after the closing `)`.
fn is_arg_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '.' | '_'
                | '-'
                | '\\'
                | '/'
                | ':'
                | '$'
                | '@'
                | '#'
                | '+'
                | '~'
                | '*'
                | '?'
                | '['
                | ']'
                | '{'
                | '}'
                | '!'
                | '%'
                | '^'
                | '\''
                | '`'
                | '('
                | ')'
                | '='
        )
        || (!c.is_ascii() && c.is_alphanumeric())
}

fn is_var_name_char(c: char) -> bool {
    // CMD's var-name span ends at `%` / `:` / `!` (closer + substring op +
    // delayed-expansion sigil) plus shell-significant operators that
    // SEPARATE commands (`&` `|` `;`), redirect (`<` `>`), open string
    // contexts (`"`), or escape (`^`). Without this rule, `%FOO&BAR%`
    // lexes as a single VarPercent(name="FOO&BAR") and the `&` command
    // separator is silently lost — a regression that hides IOCs.
    !matches!(
        c,
        '%' | ':' | '!' | '\r' | '\n' | '&' | '|' | ';' | '<' | '>' | '"' | '^'
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(String),
    DoubleQuoted(String), // contents WITHOUT the surrounding quotes; quotes restored on render
    OpAnd,                // &
    OpAndAnd,             // &&
    OpOr,                 // |
    OpOrOr,               // ||
    OpRedirect {
        fd: u8,
        append: bool,
    }, // > 1> 2> >> 1>> 2>>
    OpInput,              // <
    OpenParen,
    CloseParen,
    Whitespace,
    VarPercent {
        name: String,
        op: Option<VarOp>,
    },
    VarBang {
        name: String,
        op: Option<VarOp>,
    },
    PositionalArg(u8), // %0..%9
    AllArgs,           // %*
    /// `%%X` — FOR-loop iteration variable. Emitted by the lexer when it
    /// sees a doubled percent followed by an ASCII letter. The FOR handler
    /// substitutes these at the RAW-text level before lex when the loop
    /// actually iterates; if a body emits without iteration, normalize
    /// echoes the marker back as `%%X` so the deob stays readable.
    ForVar(char),
    PercentTilde {
        flags: PercentTildeFlags,
        path_search: Option<String>,
        arg_index: u8,
    },
    /// Caret-before-sigil marker. CMD's order is: expand `%X%` first,
    /// THEN apply `^` escape to whatever followed. For `^%X%`:
    ///   - if X is non-empty, the `^` escapes X's first char (no-op for
    ///     normal chars) → result is X's value
    ///   - if X is empty, the `^` remains as a literal (XOR operator in
    ///     arith context, or just literal `^` elsewhere)
    ///
    /// Lex emits CaretBeforeSigil before the VarPercent so normalize can
    /// resolve based on the expansion. Handles xeno-class XOR arith
    /// `0x6b84^%empty%^%empty%031624` → `0x6b84^^031624` AND LC NO's
    /// `^%!4%` → `d` (escape no-op).
    CaretBeforeSigil,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarOp {
    Substr {
        index: i64,
        length: Option<i64>,
    },
    Substitute {
        needle: String,
        replacement: String,
        leading_wildcard: bool,
    },
    /// A var-op that the lexer could not parse — typically because it
    /// contains a nested `%X%` or `!X!` reference whose value is needed
    /// before the substring/substitute form is well-formed. The string
    /// is the raw op body (everything after the leading `:`). Normalize
    /// expands the inner refs, re-parses, then applies.
    Raw(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PercentTildeFlags {
    pub f: bool,
    pub d: bool,
    pub p: bool,
    pub n: bool,
    pub x: bool,
    pub s: bool,
    pub a: bool,
    pub t: bool,
    pub z: bool,
}

impl PercentTildeFlags {
    pub fn parse(flags_str: &str) -> Option<Self> {
        let mut f = Self::default();
        for c in flags_str.chars() {
            match c {
                'f' | 'F' => f.f = true,
                'd' | 'D' => f.d = true,
                'p' | 'P' => f.p = true,
                'n' | 'N' => f.n = true,
                'x' | 'X' => f.x = true,
                's' | 'S' => f.s = true,
                'a' | 'A' => f.a = true,
                't' | 'T' => f.t = true,
                'z' | 'Z' => f.z = true,
                _ => return None,
            }
        }
        Some(f)
    }
}

pub(crate) fn parse_substr(rest: &str) -> Option<VarOp> {
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('~')?;
    let rest = rest.trim_start();
    let (idx_str, after) = take_signed_int(rest);
    let index: i64 = idx_str.parse().ok()?;
    let after = after.trim_start();
    if let Some(after) = after.strip_prefix(',') {
        let after = after.trim_start();
        let (len_str, _) = take_signed_int(after);
        let length: Option<i64> = len_str.parse().ok();
        Some(VarOp::Substr { index, length })
    } else {
        Some(VarOp::Substr {
            index,
            length: None,
        })
    }
}

fn take_signed_int(s: &str) -> (String, &str) {
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    if let Some((_, c)) = chars.peek() {
        if *c == '+' || *c == '-' {
            out.push(*c);
            chars.next();
        }
    }
    let mut consumed_to = 0usize;
    for (idx, c) in chars {
        if c.is_ascii_digit() {
            out.push(c);
            consumed_to = idx + c.len_utf8();
        } else {
            return (out, &s[idx..]);
        }
    }
    (out, &s[consumed_to..])
}

pub(crate) fn parse_substitute(rest: &str) -> Option<VarOp> {
    let (leading_wildcard, rest) = match rest.strip_prefix('*') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let eq = rest.find('=')?;
    let needle = rest[..eq].to_string();
    let replacement = rest[eq + 1..].to_string();
    Some(VarOp::Substitute {
        needle,
        replacement,
        leading_wildcard,
    })
}

pub fn lex(input: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut word = String::new();

    fn flush_word(out: &mut Vec<Token>, word: &mut String) {
        if !word.is_empty() {
            out.push(Token::Word(std::mem::take(word)));
        }
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            '%' => {
                flush_word(&mut out, &mut word);
                // %% — doubled percent. In a FOR-loop body it's the source
                // form of an iteration variable (`%%X` or `%%~xX` with a
                // tilde modifier like `%%~zA` for the loop var's file
                // size). The FOR handler pre-substitutes these at the
                // RAW-text level when the loop iterates, so by the time
                // lex runs the substituted value is in place. If the
                // lexer still sees `%%X`/`%%~xX`, the loop didn't
                // iterate — preserve the source form so normalize doesn't
                // emit bare letters (`if ~zA gtr 7` was the corruption
                // before this).
                if chars.get(i + 1) == Some(&'%') {
                    // Four-percent escape: `%%%%X` (or `%%%%`) is the
                    // source form for a literal `%%` followed by `X`
                    // (CMD halves doubled-percent once at line read).
                    // If we naively let the alpha branch grab the
                    // second `%%` as a ForVar, the first `%%` collapses
                    // to one `%` and the second renders as `%%X`,
                    // giving `%%%X` (off-by-one). Detect and emit the
                    // literal `%%` here, advancing past both pairs only
                    // when there's no `:OP%%` form attached.
                    if chars.get(i + 2) == Some(&'%') && chars.get(i + 3) == Some(&'%') {
                        // Check the char after `%%%%`: if it's alphabetic
                        // AND there's a `:OP%%` form attached we want the
                        // outer code to handle the `%%X:OP%%` as a unit,
                        // so only short-circuit here when the inner
                        // `%%X` is plain (next-after-X != ':').
                        let after = chars.get(i + 4).copied();
                        let after_x = chars.get(i + 5).copied();
                        let is_plain_inner_forvar = matches!(after, Some(c) if c.is_ascii_alphabetic())
                            && after_x != Some(':');
                        if is_plain_inner_forvar
                            || !matches!(after, Some(c) if c.is_ascii_alphabetic())
                        {
                            // Emit `%%` as literal Word, advance 4.
                            word.push('%');
                            word.push('%');
                            i += 4;
                            continue;
                        }
                    }
                    let mut k = i + 2;
                    let mut had_tilde = false;
                    if chars.get(k) == Some(&'~') {
                        had_tilde = true;
                        k += 1;
                        // Skip standard %~ modifier flags. CMD's modifiers
                        // are lowercase; the next non-modifier char is the
                        // FOR var letter (which is matched
                        // case-insensitively against the loop's var).
                        while k < chars.len()
                            && matches!(
                                chars[k],
                                'f' | 'd' | 'p' | 'n' | 'x' | 's' | 'a' | 't' | 'z' | '$'
                            )
                        {
                            k += 1;
                        }
                        // Handle the `%~$PATH:X` form by skipping past
                        // the PATH-style env-ref segment.
                        if k > i + 3 && chars.get(k - 1) == Some(&'$') {
                            while k < chars.len() && chars[k] != ':' {
                                k += 1;
                            }
                            if chars.get(k) == Some(&':') {
                                k += 1;
                            }
                        }
                    }
                    if let Some(&c) = chars.get(k) {
                        if c.is_ascii_alphabetic() {
                            // CMD's `%%X` FOR-var is single-letter; if the
                            // next char is alphanumeric (`%%count`) then X
                            // is just the head of a longer identifier and
                            // the `%%` is the percent-escape, not a
                            // FOR-var. The set /a modulo form
                            // `set /a rd=%random%%%count` depends on this:
                            // it must lex as `%` (mod) + `count` (var),
                            // not as ForVar('c') + Word("ount").
                            let next_extends_name = chars
                                .get(k + 1)
                                .map(|c2| c2.is_ascii_alphanumeric() || *c2 == '_')
                                .unwrap_or(false);
                            if !had_tilde && next_extends_name {
                                // `%%` percent-escape, not a FOR-var.
                                // Fall through to the literal-percent
                                // branch below.
                            } else {
                                flush_word(&mut out, &mut word);
                                // Check for an attached substring/substitute op
                                // form: `%%X:OP%%`. CMD halves the doubled `%`
                                // at runtime and applies OP to the FOR-var
                                // value.
                                if !had_tilde && chars.get(k + 1) == Some(&':') {
                                    let mut m = k + 2;
                                    while m + 1 < chars.len() {
                                        if chars[m] == '%' && chars[m + 1] == '%' {
                                            break;
                                        }
                                        m += 1;
                                    }
                                    if m + 1 < chars.len() && chars[m] == '%' && chars[m + 1] == '%'
                                    {
                                        let raw: String = chars[i..m + 2].iter().collect();
                                        out.push(Token::Word(raw));
                                        i = m + 2;
                                        continue;
                                    }
                                }
                                if had_tilde {
                                    let raw: String = chars[i..=k].iter().collect();
                                    out.push(Token::Word(raw));
                                } else {
                                    out.push(Token::ForVar(c));
                                }
                                i = k + 1;
                                continue;
                            }
                        }
                    }
                    // `%%` NOT followed by a letter (and not a tilde-form
                    // FOR var) is the source for a literal `%`. CMD's
                    // variable-expansion phase collapses doubled percent
                    // to single. Classic case: `set /a "x = a %% b"`
                    // where `%%` is the modulo operator escaped for batch.
                    // Drop the second `%` and emit a single literal `%`.
                    if !had_tilde {
                        word.push('%');
                        i += 2;
                        continue;
                    }
                }
                // %* all-args
                if chars.get(i + 1) == Some(&'*') {
                    out.push(Token::AllArgs);
                    i += 2;
                    continue;
                }
                // %~[flags][$ENV:]<digit> percent-tilde
                if chars.get(i + 1) == Some(&'~') {
                    let mut j = i + 2;
                    let mut flag_str = String::new();
                    let mut path_search: Option<String> = None;
                    while j < chars.len() {
                        let cc = chars[j];
                        if cc.is_ascii_digit() || cc == '$' {
                            break;
                        }
                        if matches!(
                            cc,
                            'f' | 'd'
                                | 'p'
                                | 'n'
                                | 'x'
                                | 's'
                                | 'a'
                                | 't'
                                | 'z'
                                | 'F'
                                | 'D'
                                | 'P'
                                | 'N'
                                | 'X'
                                | 'S'
                                | 'A'
                                | 'T'
                                | 'Z'
                        ) {
                            flag_str.push(cc);
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    if chars.get(j) == Some(&'$') {
                        j += 1;
                        let env_start = j;
                        while j < chars.len() && chars[j] != ':' {
                            j += 1;
                        }
                        if j < chars.len() && j > env_start && chars[j] == ':' {
                            path_search = Some(chars[env_start..j].iter().collect());
                            j += 1;
                        }
                    }
                    if j < chars.len() && chars[j].is_ascii_digit() {
                        if let Some(flags) = PercentTildeFlags::parse(&flag_str) {
                            let arg_index = (chars[j] as u32).saturating_sub('0' as u32) as u8;
                            out.push(Token::PercentTilde {
                                flags,
                                path_search,
                                arg_index,
                            });
                            i = j + 1;
                            continue;
                        }
                    }
                    // Fall through: not a valid tilde form — let later code handle
                }
                // %0..%9 positional — `%4` followed by `%` or a non-name
                // character is the positional arg. When the digit is
                // followed by MORE name chars (`%45YZ...PIF%`), real CMD
                // still treats `%4` as positional + literal trailing, but
                // malware samples often deliberately name variables with
                // a leading digit and expect `%<digit><name>%` to look up
                // the full name. We prefer the variable-ref interpretation
                // so the named value resolves (analyst-useful) at the cost
                // of slight divergence from CMD on never-rendered
                // positional-with-trailing-garbage code paths.
                if let Some(&n) = chars.get(i + 1) {
                    if n.is_ascii_digit() {
                        let next2 = chars.get(i + 2).copied();
                        let next_extends_name = next2
                            .map(|c| c.is_ascii_alphanumeric() || c == '_')
                            .unwrap_or(false);
                        if !next_extends_name {
                            // `%4 ` / `%4&` / `%4%` / `%4` (EOL): positional.
                            let d = (n as u32).saturating_sub('0' as u32) as u8;
                            out.push(Token::PositionalArg(d));
                            i += 2;
                            continue;
                        }
                        // else fall through to general var-name scan
                    }
                }
                let mut j = i + 1;
                let mut name = String::new();
                // `SET !VAR=…` (delayed expansion OFF) lets a script name
                // a variable literally `!VAR`. Subsequent refs use `%!VAR%`
                // — `is_var_name_char` excludes `!` so without a special
                // case the lex would treat the `%` as unclosed and drop
                // both sigils, mangling the reference (LC NO-... family).
                // Allow `!` as the FIRST char of a percent-style var name
                // only — interior `!` is still the delayed-expansion sigil
                // and breaks the name as before.
                if j < chars.len() && chars[j] == '!' {
                    name.push('!');
                    j += 1;
                }
                while j < chars.len() {
                    let cc = chars[j];
                    if cc == '%' || cc == ':' {
                        break;
                    }
                    if !is_var_name_char(cc) {
                        break;
                    }
                    name.push(cc);
                    j += 1;
                }
                if name.is_empty() {
                    // Drop unclosed % sigil for Python parity.
                    i += 1;
                    continue;
                }
                // Note: name == "!" alone IS a valid (closed) ref to a var
                // literally named `!` — single-char-decorator obfuscators
                // (`pow%-%ers%!%h%+%e%+%ll%?%` family) rely on `%!%` empty-
                // expanding to "" so the surrounding source chars assemble
                // into `powershell`. We must NOT drop this case, only the
                // unclosed-`%` case where there's no following `%`/`:`.
                if j < chars.len() && chars[j] == ':' {
                    // Find closing `%` for the whole var-ref, skipping any
                    // nested `%X%` references inside the op string (e.g.
                    // `%CHAR:~%R%,1%` — the inner `%R%` must not be treated
                    // as a closer).
                    let mut k = j + 1;
                    let close_idx = loop {
                        while k < chars.len() && chars[k] != '%' {
                            k += 1;
                        }
                        if k >= chars.len() {
                            break None;
                        }
                        let op_candidate: String = chars[j + 1..k].iter().collect();
                        if op_candidate.trim_start().starts_with('~')
                            && parse_substr(&op_candidate).is_some()
                        {
                            break Some(k);
                        }
                        // Possible nested `%NAME%`? A real nested ref starts
                        // with an alpha/digit/underscore (the standard var
                        // name start), runs for at least one of those chars,
                        // then closes with `%`. We deliberately do NOT use
                        // `is_var_name_char` here because that helper accepts
                        // space/tab/punctuation for legacy reasons, which
                        // would mis-merge `%A:~..% %B:..%` into one ref.
                        let is_name_start = |c: char| c.is_ascii_alphanumeric() || c == '_';
                        let mut m = k + 1;
                        let mut saw_name = false;
                        while m < chars.len() && is_name_start(chars[m]) {
                            saw_name = true;
                            m += 1;
                        }
                        if saw_name && m < chars.len() && chars[m] == '%' {
                            k = m + 1;
                            continue;
                        }
                        break Some(k);
                    };
                    let Some(k) = close_idx else {
                        // Drop unclosed % sigil for Python parity
                        i += 1;
                        continue;
                    };
                    let op_str: String = chars[j + 1..k].iter().collect();
                    let parsed = if op_str.trim_start().starts_with('~') {
                        parse_substr(&op_str)
                    } else {
                        parse_substitute(&op_str)
                    };
                    // If the parse failed AND the op contains a nested
                    // var reference, defer to normalize via VarOp::Raw.
                    let op = parsed.or_else(|| {
                        if !op_str.is_empty() && (op_str.contains('%') || op_str.contains('!')) {
                            Some(VarOp::Raw(op_str))
                        } else {
                            None
                        }
                    });
                    out.push(Token::VarPercent { name, op });
                    i = k + 1;
                } else if j < chars.len() && chars[j] == '%' {
                    out.push(Token::VarPercent { name, op: None });
                    i = j + 1;
                } else {
                    // Drop unclosed % sigil for Python parity
                    i += 1;
                }
            }
            '!' => {
                flush_word(&mut out, &mut word);
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() {
                    let cc = chars[j];
                    if cc == '!' || cc == ':' {
                        break;
                    }
                    // AbObUs-family char-substitution packers build the
                    // delayed-expansion var NAME from a chain of `%X:~N,1%`
                    // substring refs (e.g. `!%A:~18,1%%PTBhumIOyCSiIO:~0,1%…!`
                    // → `!QFeKjKNuT!`). Include the whole `%…%` span in the
                    // collected name so normalize::expand_vars_in_string can
                    // pre-expand it before the env.get lookup.
                    if cc == '%' {
                        let mut k = j + 1;
                        while k < chars.len() && chars[k] != '%' && chars[k] != '\n' {
                            k += 1;
                        }
                        if k < chars.len() && chars[k] == '%' {
                            for c2 in &chars[j..=k] {
                                name.push(*c2);
                            }
                            j = k + 1;
                            continue;
                        }
                        // Unclosed `%` — drop the name attempt and let outer
                        // handling treat `!` as literal below.
                        break;
                    }
                    if !is_var_name_char(cc) {
                        break;
                    }
                    name.push(cc);
                    j += 1;
                }
                if name.is_empty() {
                    // Lone `!` with no var-name char following — keep as
                    // literal so escape patterns like `^!!^X^!` (FE
                    // DOSfuscation echo_pipe case) round-trip correctly.
                    // Real CMD treats a `!` with no closing `!` and no
                    // name as the literal character; dropping it silently
                    // collapsed valid `!fa!!gc!!tf!` runs into one fewer
                    // `!` and broke the inner var refs.
                    word.push('!');
                    i += 1;
                    continue;
                }
                if j < chars.len() && chars[j] == ':' {
                    let mut k = j + 1;
                    while k < chars.len() && chars[k] != '!' {
                        k += 1;
                    }
                    if k >= chars.len() {
                        // Drop unclosed ! sigil for Python parity
                        i += 1;
                        continue;
                    }
                    let op_str: String = chars[j + 1..k].iter().collect();
                    let parsed = if op_str.trim_start().starts_with('~') {
                        parse_substr(&op_str)
                    } else {
                        parse_substitute(&op_str)
                    };
                    let op = parsed.or_else(|| {
                        if !op_str.is_empty() && (op_str.contains('%') || op_str.contains('!')) {
                            Some(VarOp::Raw(op_str))
                        } else {
                            None
                        }
                    });
                    out.push(Token::VarBang { name, op });
                    i = k + 1;
                } else if j < chars.len() && chars[j] == '!' {
                    out.push(Token::VarBang { name, op: None });
                    i = j + 1;
                } else {
                    // Unclosed `!` followed by name chars (e.g.
                    // `SET !h=E` — `!h` is the literal var name, not a
                    // delayed-expansion ref). Emit `!` + the collected
                    // letters as a Word so the SET line round-trips
                    // and `%!h%` refs still resolve. The previous "drop
                    // for Python parity" behavior swallowed the `!` and
                    // mangled the LC NO-... family.
                    word.push('!');
                    word.push_str(&name);
                    i = j;
                }
            }
            '"' => {
                // Inside double quotes, CMD treats `^` as a LITERAL caret —
                // it's only an escape character OUTSIDE quotes. The XOR
                // operator inside `set /a "..."` (`(0xA ^ 0xFDE3)`) relies
                // on this: stripping `^` here would turn it into the
                // un-parseable `(0xA  0xFDE3)` (two values, no operator).
                flush_word(&mut out, &mut word);
                i += 1;
                let mut content = String::new();
                while i < chars.len() && chars[i] != '"' {
                    content.push(chars[i]);
                    i += 1;
                }
                let closed = i < chars.len();
                if closed {
                    i += 1; // consume closing quote
                    out.push(Token::DoubleQuoted(content));
                } else {
                    // Unmatched `"` at EOL: keep the literal `"` + raw
                    // contents as a Word so normalize doesn't synthesize
                    // a closing quote that wasn't in the source.
                    // `set X=abc"foo` previously rendered as
                    // `set X=abc"foo"` because DoubleQuoted always
                    // restores quotes on render, corrupting the value.
                    let mut literal = String::from('"');
                    literal.push_str(&content);
                    out.push(Token::Word(literal));
                }
            }
            '^' => {
                if let Some(&next) = chars.get(i + 1) {
                    // CMD's variable-expansion phase runs BEFORE caret
                    // processing, so `^%X%foo` expands `%X%` first, then
                    // `^` escapes the char that followed `%X%` (or
                    // nothing). For analysis, treat `^` as a no-op when
                    // it directly precedes a well-formed `%X%`/`!X!`
                    // sigil so the var ref still lexes. The carret-
                    // sandwich obfuscators (LC NO-... family) rely on
                    // this `^%X%^%Y%` form pervasively. We do this
                    // conservatively — only when a closing sigil exists
                    // — so plain `^%` (literal `%`) still escapes.
                    let opens_var_ref = match next {
                        '%' => {
                            // require `%` + at least one name char + closing `%` or `!`
                            let mut k = i + 2;
                            // tolerate a single leading `!` (matches our
                            // `%!X%` handling above)
                            if k < chars.len() && chars[k] == '!' {
                                k += 1;
                            }
                            let start = k;
                            while k < chars.len()
                                && is_var_name_char(chars[k])
                                && chars[k] != '%'
                                && chars[k] != '!'
                                && chars[k] != ':'
                            {
                                k += 1;
                            }
                            k > start && k < chars.len() && (chars[k] == '%' || chars[k] == ':')
                        }
                        '!' => {
                            let mut k = i + 2;
                            let start = k;
                            while k < chars.len()
                                && is_var_name_char(chars[k])
                                && chars[k] != '%'
                                && chars[k] != '!'
                                && chars[k] != ':'
                            {
                                k += 1;
                            }
                            k > start && k < chars.len() && (chars[k] == '!' || chars[k] == ':')
                        }
                        _ => false,
                    };
                    if opens_var_ref {
                        // Emit CaretBeforeSigil marker; normalize will
                        // resolve based on var expansion (drop caret if
                        // var non-empty / escape no-op; keep `^` literal
                        // if var empty / preserve XOR semantics).
                        flush_word(&mut out, &mut word);
                        out.push(Token::CaretBeforeSigil);
                        i += 1;
                        continue;
                    }
                    word.push(next);
                    i += 2;
                } else {
                    word.push('^');
                    i += 1;
                }
            }
            ' ' | '\t' => {
                flush_word(&mut out, &mut word);
                while i < chars.len() && matches!(chars[i], ' ' | '\t') {
                    i += 1;
                }
                out.push(Token::Whitespace);
            }
            ',' | ';' => {
                // CMD treats `,;` as token separators in some lexer
                // contexts (DOSfuscation `,;,cmd.exe /c echo,X`) but as
                // LITERAL characters inside arguments — both to external
                // programs (`rundll32 dll,Entry`) and inside PS function
                // calls embedded in batch (`[Path]::Combine($env:USERPROFILE,
                // 'file')`, `... -join '');$bnt=...`).
                //
                // Two-layer rule:
                //   (1) If we see a MIXED `,;` / `;,` adjacency, treat the
                //       whole run as token separator regardless of prev
                //       context. The FE DOSfuscation paper documents
                //       `,;,cmd.exe,;,/c,;,echo` exactly — three-char
                //       `,;,` between every argument. That mix never
                //       appears inside legit `rundll32 dll,Entry` (always
                //       a single `,`) or PS arg lists.
                //   (2) Otherwise fall back to context: if the previous
                //       token / word-buffer is arg-style, treat the `,` /
                //       `;` as literal; if it's start-of-line / whitespace
                //       / operator, treat as separator (DOSfuscation
                //       leading `,;,`).
                let is_mixed_run = {
                    // Look ahead: is the very next char the OTHER of
                    // {`,`,`;`}? Or is the immediately-preceding char in
                    // the word buffer / out stream the other one? Either
                    // direction qualifies as a `,;` / `;,` mix.
                    let next = chars.get(i + 1).copied();
                    let other = if c == ',' { ';' } else { ',' };
                    let prev_char = word.chars().last().or_else(|| {
                        out.last().and_then(|t| match t {
                            Token::Word(w) => w.chars().last(),
                            _ => None,
                        })
                    });
                    next == Some(other) || prev_char == Some(other)
                };
                let prev_word = if !word.is_empty() {
                    word.chars().last().map(is_arg_word_char).unwrap_or(false)
                } else {
                    matches!(
                        out.last(),
                        Some(Token::Word(_))
                            | Some(Token::DoubleQuoted(_))
                            | Some(Token::CloseParen)
                            | Some(Token::VarPercent { .. })
                            | Some(Token::VarBang { .. })
                            | Some(Token::PercentTilde { .. })
                            | Some(Token::PositionalArg(_))
                            | Some(Token::ForVar(_))
                    )
                };
                if prev_word && !is_mixed_run {
                    word.push(c);
                    i += 1;
                } else {
                    // Mixed-run case: previous char might be `,` / `;`
                    // that we just appended to the word buffer thinking it
                    // was literal. Trim those trailing separator chars off
                    // the buffer so the resulting Word doesn't keep them.
                    while word.ends_with(',') || word.ends_with(';') {
                        word.pop();
                    }
                    flush_word(&mut out, &mut word);
                    while i < chars.len() && matches!(chars[i], ' ' | '\t' | ',' | ';') {
                        i += 1;
                    }
                    out.push(Token::Whitespace);
                }
            }
            '&' => {
                flush_word(&mut out, &mut word);
                if chars.get(i + 1) == Some(&'&') {
                    out.push(Token::OpAndAnd);
                    i += 2;
                } else {
                    out.push(Token::OpAnd);
                    i += 1;
                }
            }
            '|' => {
                flush_word(&mut out, &mut word);
                if chars.get(i + 1) == Some(&'|') {
                    out.push(Token::OpOrOr);
                    i += 2;
                } else {
                    out.push(Token::OpOr);
                    i += 1;
                }
            }
            '<' => {
                flush_word(&mut out, &mut word);
                out.push(Token::OpInput);
                i += 1;
            }
            '>' => {
                // A preceding digit '1' or '2' is the fd number.
                let fd: u8 = match word.chars().last() {
                    Some('1') => {
                        word.pop();
                        1
                    }
                    Some('2') => {
                        word.pop();
                        2
                    }
                    _ => 1,
                };
                flush_word(&mut out, &mut word);
                let append = chars.get(i + 1) == Some(&'>');
                out.push(Token::OpRedirect { fd, append });
                i += if append { 2 } else { 1 };
            }
            '(' => {
                flush_word(&mut out, &mut word);
                out.push(Token::OpenParen);
                i += 1;
            }
            ')' => {
                flush_word(&mut out, &mut word);
                out.push(Token::CloseParen);
                i += 1;
            }
            _ => {
                word.push(c);
                i += 1;
            }
        }
    }
    flush_word(&mut out, &mut word);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(s: &str) -> Vec<Token> {
        super::lex(s)
    }

    #[test]
    fn pipeline_operator_inside_apparent_var_span_surfaces() {
        // Regression: is_var_name_char's denylist rewrite swallowed `&`/`|`/`;`/
        // `<`/`>`/`=`/`"` into the var-name span. Input `%FOO&BAR%` should
        // NOT lex as VarPercent(name="FOO&BAR") — the `&` is a shell-operator
        // that has to surface as Token::OpAnd so the second command splits.
        // The expected lex (Python parity): drop the unclosed `%`, emit
        // Word("FOO") + OpAnd + Word("BAR") + drop the trailing `%`.
        let toks = lex("%FOO&BAR%");
        assert!(
            toks.iter().any(|t| matches!(t, Token::OpAnd)),
            "expected Token::OpAnd from `%FOO&BAR%`; got: {:?}",
            toks
        );
        let bad_name = toks.iter().find_map(|t| match t {
            Token::VarPercent { name, .. } if name.contains('&') => Some(name.clone()),
            _ => None,
        });
        assert!(
            bad_name.is_none(),
            "var-name swallowed an operator: VarPercent(name={:?}); full tokens: {:?}",
            bad_name,
            toks
        );
    }

    #[test]
    fn redirect_operator_inside_apparent_var_span_surfaces() {
        let toks = lex("%FOO>out.txt%");
        assert!(
            toks.iter().any(|t| matches!(t, Token::OpRedirect { .. })),
            "expected Token::OpRedirect from `%FOO>out.txt%`; got: {:?}",
            toks
        );
        let bad_name = toks.iter().find_map(|t| match t {
            Token::VarPercent { name, .. } if name.contains('>') => Some(name.clone()),
            _ => None,
        });
        assert!(
            bad_name.is_none(),
            "var-name swallowed a redirect: VarPercent(name={:?}); full tokens: {:?}",
            bad_name,
            toks
        );
    }

    #[test]
    fn lex_single_word() {
        assert_eq!(lex("echo"), vec![Token::Word("echo".into())]);
    }

    #[test]
    fn lex_two_words_split_by_space() {
        assert_eq!(
            lex("echo hi"),
            vec![
                Token::Word("echo".into()),
                Token::Whitespace,
                Token::Word("hi".into()),
            ]
        );
    }

    #[test]
    fn lex_tabs_count_as_whitespace() {
        assert_eq!(
            lex("a\tb"),
            vec![
                Token::Word("a".into()),
                Token::Whitespace,
                Token::Word("b".into()),
            ]
        );
    }

    #[test]
    fn lex_comma_semicolon_at_token_boundary_is_whitespace() {
        // DOSfuscation form: separator-flanked `,;` between commands or
        // between argument tokens is whitespace.
        assert_eq!(
            lex(",;,cmd.exe"),
            vec![Token::Whitespace, Token::Word("cmd.exe".into())]
        );
        // Adjacent whitespace runs may produce multiple Whitespace tokens
        // (normalize collapses them); we just care no Words got mangled.
        let toks = lex("echo ,; X");
        assert!(toks.contains(&Token::Word("echo".into())), "{:?}", toks);
        assert!(toks.contains(&Token::Word("X".into())), "{:?}", toks);
        // No `,` or `;` survives as a Word.
        for t in &toks {
            if let Token::Word(w) = t {
                assert!(
                    !w.contains(',') && !w.contains(';'),
                    "comma/semi leaked into Word: {:?}",
                    toks
                );
            }
        }
    }

    #[test]
    fn lex_comma_inside_argument_is_literal() {
        // CMD passes `,;` to external programs as part of the argument
        // when both neighbors are arg-style word chars. `rundll32
        // host.dll,Entry` previously lost the comma, leaving rundll32
        // with two args instead of one. Same shape for hostnames with
        // embedded `;`-separated paths.
        assert_eq!(
            lex("rundll32 host.dll,EntryPoint"),
            vec![
                Token::Word("rundll32".into()),
                Token::Whitespace,
                Token::Word("host.dll,EntryPoint".into()),
            ]
        );
    }

    #[test]
    fn lex_percent_digit_followed_by_name_chars_is_varref() {
        // Real CMD parses `%4ABC%` as `%4` (positional) + `ABC%` literal,
        // but malware samples define variable names that begin with a
        // digit (`set "45YZ...=wer"`) and reference them as
        // `%45YZ...%`. Prefer the variable-ref interpretation so the
        // resolved value reaches the deob output.
        let toks = lex("%45YZ1%");
        assert_eq!(
            toks,
            vec![Token::VarPercent {
                name: "45YZ1".into(),
                op: None,
            }]
        );
        // `%4 ` (space) and `%4%` should still be PositionalArg(4).
        let toks2 = lex("%4 ");
        assert!(matches!(toks2.first(), Some(Token::PositionalArg(4))));
    }

    #[test]
    fn lex_unmatched_double_quote_is_literal_word() {
        // `set X=abc"foo` previously rendered as `set X=abc"foo"`
        // because lex emitted DoubleQuoted (which always restores
        // closing `"` on render). Now the unterminated string is
        // kept as a Word so normalize preserves the source byte.
        let toks = lex(r#"abc"foo"#);
        assert!(
            toks.iter()
                .any(|t| matches!(t, Token::Word(w) if w == r#"abc"#)),
            "Word `abc` missing: {:?}",
            toks
        );
        assert!(
            toks.iter()
                .any(|t| matches!(t, Token::Word(w) if w == r#""foo"#)),
            "Word `\"foo` missing: {:?}",
            toks
        );
    }

    #[test]
    fn lex_comma_then_space_in_ps_arg_kept() {
        // PowerShell embedded in batch uses `arg1, arg2` (space after
        // comma). Previously the comma was dropped because next-char
        // was space; this broke `[Path]::Combine($env:USERPROFILE,
        // 'file.exe')` and VBS `obj.Method "GET", url, False`.
        let toks = lex("Combine($env:USERPROFILE, 'qdll.exe')");
        let s: String = toks
            .iter()
            .map(|t| match t {
                Token::Word(w) => w.clone(),
                Token::Whitespace => " ".into(),
                Token::DoubleQuoted(q) => format!("\"{}\"", q),
                _ => String::new(),
            })
            .collect();
        assert!(
            s.contains("USERPROFILE,"),
            "comma after USERPROFILE got stripped: {}",
            s
        );
    }

    #[test]
    fn lex_semicolon_then_space_in_ps_kept() {
        // PS statement terminator: `$a = 1; $b = 2`. Without literal
        // preservation, the `;` between statements is lost.
        let toks = lex("$a = 1; $b = 2");
        let has_semi = toks
            .iter()
            .any(|t| matches!(t, Token::Word(w) if w.ends_with(';')));
        assert!(has_semi, "semicolon dropped from PS: {:?}", toks);
    }

    #[test]
    fn lex_ampersand_variants() {
        assert_eq!(
            lex("a&b&&c"),
            vec![
                Token::Word("a".into()),
                Token::OpAnd,
                Token::Word("b".into()),
                Token::OpAndAnd,
                Token::Word("c".into()),
            ]
        );
    }

    #[test]
    fn lex_pipe_variants() {
        assert_eq!(
            lex("a|b||c"),
            vec![
                Token::Word("a".into()),
                Token::OpOr,
                Token::Word("b".into()),
                Token::OpOrOr,
                Token::Word("c".into()),
            ]
        );
    }

    #[test]
    fn lex_redirects() {
        assert_eq!(
            lex("a>b 1>>c 2>d <e"),
            vec![
                Token::Word("a".into()),
                Token::OpRedirect {
                    fd: 1,
                    append: false
                },
                Token::Word("b".into()),
                Token::Whitespace,
                Token::OpRedirect {
                    fd: 1,
                    append: true
                },
                Token::Word("c".into()),
                Token::Whitespace,
                Token::OpRedirect {
                    fd: 2,
                    append: false
                },
                Token::Word("d".into()),
                Token::Whitespace,
                Token::OpInput,
                Token::Word("e".into()),
            ]
        );
    }

    #[test]
    fn lex_parens() {
        assert_eq!(
            lex("(a)"),
            vec![Token::OpenParen, Token::Word("a".into()), Token::CloseParen,]
        );
    }

    #[test]
    fn caret_escapes_next_char() {
        assert_eq!(lex("a^&b"), vec![Token::Word("a&b".into())]);
    }

    #[test]
    fn caret_escapes_operator() {
        assert_eq!(lex("a^|b"), vec![Token::Word("a|b".into())]);
    }

    #[test]
    fn many_carets_in_word() {
        assert_eq!(lex("s^e^t"), vec![Token::Word("set".into())]);
    }

    #[test]
    fn trailing_caret_kept_literally() {
        assert_eq!(lex("foo^"), vec![Token::Word("foo^".into())]);
    }

    #[test]
    fn double_quoted_string_is_single_token() {
        assert_eq!(
            lex(r#"echo "hello world""#),
            vec![
                Token::Word("echo".into()),
                Token::Whitespace,
                Token::DoubleQuoted("hello world".into()),
            ]
        );
    }

    #[test]
    fn operators_inside_quotes_are_literal() {
        assert_eq!(lex(r#""a|b&c""#), vec![Token::DoubleQuoted("a|b&c".into())]);
    }

    #[test]
    fn comma_inside_quotes_kept() {
        assert_eq!(lex(r#""a,b""#), vec![Token::DoubleQuoted("a,b".into())]);
    }

    #[test]
    fn percent_var_simple() {
        assert_eq!(
            lex("%FOO%"),
            vec![Token::VarPercent {
                name: "FOO".into(),
                op: None
            }]
        );
    }

    #[test]
    fn bang_var_simple() {
        assert_eq!(
            lex("!foo!"),
            vec![Token::VarBang {
                name: "foo".into(),
                op: None
            }]
        );
    }

    #[test]
    fn percent_var_among_words() {
        assert_eq!(
            lex("echo %X% rest"),
            vec![
                Token::Word("echo".into()),
                Token::Whitespace,
                Token::VarPercent {
                    name: "X".into(),
                    op: None
                },
                Token::Whitespace,
                Token::Word("rest".into()),
            ]
        );
    }

    #[test]
    fn percent_var_with_unicode_name() {
        // CJK characters in var names — corpus discovery (FX.cmd sample)
        let toks = lex("%せっん%");
        assert_eq!(
            toks,
            vec![Token::VarPercent {
                name: "せっん".into(),
                op: None
            }]
        );
    }

    #[test]
    fn unclosed_percent_drops_sigil() {
        // Python parity: unclosed %sigil is stripped, not kept literal.
        assert_eq!(lex("%abc"), vec![Token::Word("abc".into())]);
    }

    #[test]
    fn percent_positional_arg() {
        assert_eq!(lex("%1"), vec![Token::PositionalArg(1)]);
        assert_eq!(lex("%0"), vec![Token::PositionalArg(0)]);
        assert_eq!(lex("%*"), vec![Token::AllArgs]);
    }

    #[test]
    fn percent_var_substr_positive() {
        assert_eq!(
            lex("%X:~0,3%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substr {
                    index: 0,
                    length: Some(3)
                }),
            }]
        );
    }

    #[test]
    fn percent_var_substr_negative_no_length() {
        assert_eq!(
            lex("%X:~-7%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substr {
                    index: -7,
                    length: None
                }),
            }]
        );
    }

    #[test]
    fn percent_var_substr_whitespace_in_op() {
        assert_eq!(
            lex("%X:~   -7,    +3%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substr {
                    index: -7,
                    length: Some(3)
                }),
            }]
        );
    }

    #[test]
    fn percent_var_substitute_simple() {
        assert_eq!(
            lex("%X:abc=xyz%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substitute {
                    needle: "abc".into(),
                    replacement: "xyz".into(),
                    leading_wildcard: false,
                }),
            }]
        );
    }

    #[test]
    fn percent_var_substitute_wildcard() {
        assert_eq!(
            lex("%X:*abc=xyz%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substitute {
                    needle: "abc".into(),
                    replacement: "xyz".into(),
                    leading_wildcard: true,
                }),
            }]
        );
    }

    #[test]
    fn percent_tilde_simple() {
        let toks = lex("%~f0");
        assert_eq!(
            toks,
            vec![Token::PercentTilde {
                flags: PercentTildeFlags {
                    f: true,
                    ..Default::default()
                },
                path_search: None,
                arg_index: 0,
            }]
        );
    }

    #[test]
    fn percent_tilde_combined_flags() {
        let toks = lex("%~dpnx0");
        let expected_flags = PercentTildeFlags {
            d: true,
            p: true,
            n: true,
            x: true,
            ..Default::default()
        };
        assert_eq!(
            toks,
            vec![Token::PercentTilde {
                flags: expected_flags,
                path_search: None,
                arg_index: 0
            }]
        );
    }

    #[test]
    fn percent_tilde_combined_flags_mixed_case() {
        let toks = lex("%~DpNx0");
        let expected_flags = PercentTildeFlags {
            d: true,
            p: true,
            n: true,
            x: true,
            ..Default::default()
        };
        assert_eq!(
            toks,
            vec![Token::PercentTilde {
                flags: expected_flags,
                path_search: None,
                arg_index: 0
            }]
        );
    }

    #[test]
    fn percent_tilde_bare_with_arg() {
        let toks = lex("%~1");
        assert_eq!(
            toks,
            vec![Token::PercentTilde {
                flags: PercentTildeFlags::default(),
                path_search: None,
                arg_index: 1
            }]
        );
    }

    #[test]
    fn percent_tilde_path_search() {
        let toks = lex("%~$PATH:1");
        assert_eq!(
            toks,
            vec![Token::PercentTilde {
                flags: PercentTildeFlags::default(),
                path_search: Some("PATH".into()),
                arg_index: 1
            }]
        );
    }
}
