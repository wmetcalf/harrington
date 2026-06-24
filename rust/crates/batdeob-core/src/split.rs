//! Split a logical line into individual commands at top-level
//! `& && | ||` operators, respecting double-quotes and caret-escapes.

pub fn split_commands(line: &str) -> Vec<String> {
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
                out.push(trimmed.to_string());
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
                out.push(trimmed.to_string());
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
        out.push(trimmed.to_string());
    }
    out
}
