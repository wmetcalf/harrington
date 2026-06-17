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
    if let Some(target_host) = wmic_node_target(raw) {
        env.traits.push(Trait::LateralMovement {
            tool: "wmic".to_string(),
            target_host,
        });
    }
    let command = unescape_outer_caret_bangs(&inner);
    env.traits.push(Trait::WmicProcessCreate {
        inner_cmd: command.clone(),
    });
    let delayed = crate::handlers::cmd::has_v_on_raw(&command);
    env.exec_cmd.push(command);
    env.exec_cmd_delayed.push(delayed);
}

pub(crate) fn wmic_process_create_inner(raw: &str) -> Option<String> {
    let tokens = split_words(raw);
    let mut process_idx = None;
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        if is_process_create_selector(strip_quotes(token)) {
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

fn is_process_create_selector(token: &str) -> bool {
    token.eq_ignore_ascii_case("process") || token.eq_ignore_ascii_case("win32_process")
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

fn wmic_node_target(raw: &str) -> Option<String> {
    let tokens = split_words(raw);
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        let value = if lower == "/node" || lower == "-node" {
            tokens.get(i + 1).map(|next| strip_quotes(next))
        } else {
            attached_node_value(token)
        };
        if let Some(host) = value
            .map(normalize_node_target)
            .filter(|host| !host.is_empty())
        {
            return Some(host);
        }
        i += 1;
    }
    None
}

fn attached_node_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for prefix in ["/node:", "/node=", "-node:", "-node="] {
        if lower.starts_with(prefix) {
            return token.get(prefix.len()..);
        }
    }
    None
}

fn normalize_node_target(value: &str) -> String {
    strip_quotes(value)
        .trim()
        .trim_start_matches('\\')
        .to_string()
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

fn unescape_outer_caret_bangs(command: &str) -> String {
    command.replace("^!", "!")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{wmic_create_commandline_argument, wmic_node_target};

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

    #[test]
    fn node_target_accepts_attached_and_spaced_values() {
        assert_eq!(
            wmic_node_target(r#"wmic /node:"target.example" process call create "cmd""#).as_deref(),
            Some("target.example")
        );
        assert_eq!(
            wmic_node_target(r#"wmic -node \\target2 process call create "cmd""#).as_deref(),
            Some("target2")
        );
    }
}
