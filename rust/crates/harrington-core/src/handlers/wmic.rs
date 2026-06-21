//! wmic handler — extracts the inner command from `wmic process call create ...`.

use crate::env::Environment;
use crate::handlers::util::split_words;
use crate::handlers::util::strip_outer_quotes;
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

fn wmic_process_create_inner(raw: &str) -> Option<String> {
    let tokens = split_words(raw);
    let mut process_idx = None;
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        if strip_outer_quotes(token).eq_ignore_ascii_case("process") {
            process_idx = Some(idx);
            break;
        }
    }

    let process_idx = process_idx?;
    if !tokens
        .get(process_idx + 1)
        .map(|token| strip_outer_quotes(token).eq_ignore_ascii_case("call"))
        .unwrap_or(false)
    {
        return None;
    }
    if !tokens
        .get(process_idx + 2)
        .map(|token| strip_outer_quotes(token).eq_ignore_ascii_case("create"))
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
    let inner = strip_outer_quotes(tail[..end].trim()).trim().to_string();
    (!inner.is_empty()).then_some(inner)
}
