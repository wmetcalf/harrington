//! wmic handler — extracts the inner command from `wmic process call create ...`.

use crate::env::Environment;
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_wmic(raw: &str, env: &mut Environment) {
    let Some(inner) = wmic_process_create_inner(raw) else {
        return;
    };
    if inner.is_empty() {
        return;
    }
    env.traits.push(Trait::WmicProcessCreate {
        inner_cmd: inner.clone(),
    });
    env.exec_cmd.push(inner);
    env.exec_cmd_delayed.push(false);
}

pub(crate) fn wmic_process_create_inner(raw: &str) -> Option<String> {
    let tokens = split_words(raw);
    let mut process_idx = None;
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        if strip_quotes(token).eq_ignore_ascii_case("process") {
            process_idx = Some(idx);
            break;
        }
    }

    let process_idx = process_idx?;
    if !tokens
        .get(process_idx + 1)
        .map(|token| strip_quotes(token).eq_ignore_ascii_case("call"))
        .unwrap_or(false)
    {
        return None;
    }
    if !tokens
        .get(process_idx + 2)
        .map(|token| strip_quotes(token).eq_ignore_ascii_case("create"))
        .unwrap_or(false)
    {
        return None;
    }

    let tail_start = tokens
        .get(process_idx + 3)
        .map(|token| raw.find(token))
        .unwrap_or(None)?;
    let inner = wmic_create_commandline_argument(raw[tail_start..].trim())?;
    if inner.is_empty() {
        None
    } else {
        Some(inner)
    }
}

fn wmic_create_commandline_argument(tail: &str) -> Option<String> {
    let tail = tail.trim();
    if let Some(value_start) = wmic_commandline_value_start(tail) {
        return wmic_create_commandline_argument(&tail[value_start..]);
    }
    let mut in_dq = false;
    let mut in_sq = false;
    let mut end = tail.len();
    for (idx, c) in tail.char_indices() {
        match c {
            '"' if !in_sq => in_dq = !in_dq,
            '\'' if !in_dq => in_sq = !in_sq,
            ',' if !in_dq && !in_sq => {
                end = idx;
                break;
            }
            _ => {}
        }
    }
    let inner = strip_quotes(tail[..end].trim()).trim().to_string();
    (!inner.is_empty()).then_some(inner)
}

fn wmic_commandline_value_start(tail: &str) -> Option<usize> {
    let bytes = tail.as_bytes();
    let mut i = 0usize;
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    let name = tail.get(i..i + "commandline".len())?;
    if !name.eq_ignore_ascii_case("commandline") {
        return None;
    }
    i += "commandline".len();
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    if bytes.get(i) != Some(&b'=') {
        return None;
    }
    i += 1;
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    (i < tail.len()).then_some(i)
}

fn strip_quotes(text: &str) -> &str {
    text.trim_matches(|c| c == '"' || c == '\'')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::wmic_create_commandline_argument;

    #[test]
    fn create_argument_extracts_named_commandline() {
        assert_eq!(
            wmic_create_commandline_argument(r#"CommandLine="cmd /c echo named""#).as_deref(),
            Some("cmd /c echo named")
        );
    }

    #[test]
    fn create_argument_extracts_named_commandline_with_spaces() {
        assert_eq!(
            wmic_create_commandline_argument(r#"CommandLine = "cmd /c echo named", "C:\Temp""#)
                .as_deref(),
            Some("cmd /c echo named")
        );
    }
}
