//! Split a logical line into individual commands at top-level
//! `& && | ||` operators, respecting double-quotes and caret-escapes.

/// Peel balanced surrounding parens off a single command. CMD's
/// parenthesised-block syntax is transparent — `((set x=1))` runs the
/// same as `set x=1`. The FE DOSfuscation paper's "Parentheses"
/// obfuscation section (and the heavily-wrapped FORcoding/Reversal
/// vectors) bury every command in extra `( … )` layers as a signature-
/// defeat measure; peel them so the inner SET / FOR / IF dispatches.
fn strip_balanced_parens(s: &str) -> String {
    let mut s = s.trim().to_string();
    loop {
        let bytes = s.as_bytes();
        if bytes.len() < 2 || bytes[0] != b'(' || bytes[bytes.len() - 1] != b')' {
            return s;
        }
        // Verify the leading `(` actually pairs with the trailing `)` (not
        // a stray inner pair like `(echo) | (find)`). Track depth across
        // the whole string ignoring `^`-escaped chars and double-quoted
        // sections. If depth drops to 0 BEFORE the final `)`, the outer
        // pair doesn't pair — leave the string alone.
        let chars: Vec<char> = s.chars().collect();
        let mut depth = 0i32;
        let mut in_dq = false;
        let mut paired = true;
        for (i, &c) in chars.iter().enumerate() {
            if c == '^' && i + 1 < chars.len() {
                // Skip the escaped char — but a depth update only fires
                // on the unescaped char anyway, so just continue.
                continue;
            }
            if c == '"' {
                in_dq = !in_dq;
                continue;
            }
            if in_dq {
                continue;
            }
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 && i + 1 < chars.len() {
                    paired = false;
                    break;
                }
            }
        }
        if !paired || depth != 0 {
            return s;
        }
        // Strip the outer pair and any internal whitespace, then loop in
        // case there's another layer (`(((set x=1)))`).
        s = s[1..s.len() - 1].trim().to_string();
        if s.is_empty() {
            return s;
        }
    }
}

pub fn split_commands(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if !line
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'&' | b'|' | b'(' | b')'))
    {
        return vec![trimmed.to_string()];
    }

    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_dq = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '^' && i + 1 < chars.len() {
            i += 2;
            continue;
        }
        if c == '"' {
            in_dq = !in_dq;
            i += 1;
            continue;
        }
        if in_dq {
            i += 1;
            continue;
        }

        // Skip operator-internal & after >
        if c == '&' && i > 0 && chars[i - 1] == '>' {
            i += 1;
            continue;
        }
        // `&` and `&&` are unconditional / conditional separators — split.
        // `||` is the failure-conditional separator — split.
        // Single `|` is a PIPELINE — keep both sides together as one
        // logical command so `type X | cmd` renders verbatim instead of
        // becoming two unrelated lines in the deob.
        if c == '&' {
            let seg = chars[start..i].iter().collect::<String>();
            let trimmed = seg.trim();
            if !trimmed.is_empty() {
                out.push(strip_balanced_parens(trimmed));
            }
            if chars.get(i + 1) == Some(&c) {
                i += 2;
            } else {
                i += 1;
            }
            start = i;
            continue;
        }
        if c == '|' && chars.get(i + 1) == Some(&'|') {
            let seg = chars[start..i].iter().collect::<String>();
            let trimmed = seg.trim();
            if !trimmed.is_empty() {
                out.push(strip_balanced_parens(trimmed));
            }
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    let seg: String = chars[start..].iter().collect();
    let trimmed = seg.trim();
    if !trimmed.is_empty() {
        out.push(strip_balanced_parens(trimmed));
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod strip_paren_tests {
    use super::strip_balanced_parens;

    #[test]
    fn strips_single_layer() {
        assert_eq!(strip_balanced_parens("(set x=1)"), "set x=1");
    }

    #[test]
    fn strips_nested_layers() {
        assert_eq!(strip_balanced_parens("((( set x=1 )))"), "set x=1");
    }

    #[test]
    fn leaves_unbalanced_parens_alone() {
        // The outer `(` pairs with the FIRST `)`, not the last — peeling
        // would split the command incorrectly. Keep verbatim.
        assert_eq!(
            strip_balanced_parens("(echo a) (echo b)"),
            "(echo a) (echo b)"
        );
    }

    #[test]
    fn leaves_command_with_internal_parens_alone() {
        // `echo (test)` — no outer parens to peel.
        assert_eq!(strip_balanced_parens("echo (test)"), "echo (test)");
    }

    #[test]
    fn split_commands_peels_each_segment() {
        // Realistic DOSfuscation wrapped FORcoding fragment: each `&&`-
        // separated command starts with extra parens. The dispatcher
        // only sees the inner command — `set unique=…`, `for %a in (…)
        // do …`, etc.
        let segs = super::split_commands("((set unique=nets /ao)) && ((set final=))");
        assert_eq!(segs, vec!["set unique=nets /ao", "set final="]);
    }
}
