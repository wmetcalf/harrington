//! FOR-loop body interpreter. Re-uses lex/normalize/interp for each iteration.

use crate::env::Environment;

/// Execute the body once per value, substituting the loop variable each time.
/// Honors `env.limits.max_iterations` and emits `Trait::IterationCapped` when hit.
/// Returns the number of iterations actually performed.
pub fn run_body<F>(
    body: &str,
    var_name: char, // e.g. 'A' for %%A
    values: impl IntoIterator<Item = String>,
    env: &mut Environment,
    mut on_iter: F,
) -> u64
where
    F: FnMut(&mut Environment, &str),
{
    let mut count = 0u64;
    for v in values {
        if for_body_budget_exhausted(body, env) {
            break;
        }
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
        count += 1;
        // Substitute %%A or %A in the body with the current value.
        let substituted = substitute_loop_var(body, var_name, &v);
        on_iter(env, &substituted);
        if for_body_budget_exhausted(body, env) {
            break;
        }
    }
    count
}

pub(crate) fn for_body_budget_exhausted(body: &str, env: &mut Environment) -> bool {
    if let Some(deadline) = env.limits.deadline {
        if std::time::Instant::now() >= deadline {
            if !env
                .traits
                .iter()
                .any(|t| matches!(t, crate::traits::Trait::TimeoutHit))
            {
                env.traits.push(crate::traits::Trait::TimeoutHit);
            }
            return true;
        }
    }
    if env.limits.max_output_bytes > 0
        && (env.iter_output.len() as u64) >= env.limits.max_output_bytes
    {
        env.note_output_capped(env.iter_output.len() as u64);
        if !env
            .traits
            .iter()
            .any(|t| matches!(t, crate::traits::Trait::IterationCapped { .. }))
        {
            env.traits.push(crate::traits::Trait::IterationCapped {
                command: body.to_string(),
            });
        }
        return true;
    }
    false
}

/// Replace `%%X` (script form) and `%X` (interactive form) with `value`.
/// The match on the variable letter is case-insensitive.
pub fn substitute_loop_var(body: &str, var: char, value: &str) -> String {
    let mut out = String::with_capacity(body.len() + value.len());
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            // Try `%%~nxX` / `%%~X` script-form modifiers.
            if chars.get(i + 1) == Some(&'%') && chars.get(i + 2) == Some(&'~') {
                if let Some((replacement, consumed)) =
                    expand_tilde_loop_modifier(&chars, i + 3, var, value)
                {
                    out.push_str(&replacement);
                    i = consumed;
                    continue;
                }
            }
            // Try `%%X` first.
            if chars.get(i + 1) == Some(&'%')
                && chars
                    .get(i + 2)
                    .map(|c| c.eq_ignore_ascii_case(&var))
                    .unwrap_or(false)
            {
                out.push_str(value);
                i += 3;
                continue;
            }
            // Try `%~nxX` / `%~X` interactive-form modifiers.
            if chars.get(i + 1) == Some(&'~') {
                if let Some((replacement, consumed)) =
                    expand_tilde_loop_modifier(&chars, i + 2, var, value)
                {
                    out.push_str(&replacement);
                    i = consumed;
                    continue;
                }
            }
            // Try `%X`.
            if chars
                .get(i + 1)
                .map(|c| c.eq_ignore_ascii_case(&var))
                .unwrap_or(false)
            {
                out.push_str(value);
                i += 2;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn expand_tilde_loop_modifier(
    chars: &[char],
    modifier_start: usize,
    var: char,
    value: &str,
) -> Option<(String, usize)> {
    let mut modifiers = Vec::new();
    let mut j = modifier_start;
    while let Some(c) = chars.get(j) {
        if c.eq_ignore_ascii_case(&var) {
            return loop_var_modifier_value(value, &modifiers)
                .map(|replacement| (replacement, j + 1));
        }
        if !is_supported_loop_modifier(*c) || modifiers.len() >= 8 {
            return None;
        }
        modifiers.push(c.to_ascii_lowercase());
        j += 1;
    }
    None
}

fn is_supported_loop_modifier(c: char) -> bool {
    matches!(c.to_ascii_lowercase(), 'd' | 'p' | 'n' | 'x' | 'f' | 's')
}

fn loop_var_modifier_value(value: &str, modifiers: &[char]) -> Option<String> {
    if modifiers.is_empty()
        || modifiers.contains(&'f')
        || modifiers.iter().all(|modifier| *modifier == 's')
    {
        return Some(trim_loop_var_quotes(value).to_string());
    }

    let mut out = String::new();
    for modifier in modifiers {
        match modifier {
            'd' => out.push_str(loop_var_drive(value)),
            'p' => out.push_str(loop_var_path(value)),
            'n' => out.push_str(loop_var_name_stem(value)),
            'x' => out.push_str(loop_var_extension(value)),
            's' => {}
            _ => return None,
        }
    }
    Some(out)
}

fn trim_loop_var_quotes(value: &str) -> &str {
    value.trim_matches('"')
}

fn loop_var_drive(value: &str) -> &str {
    let value = trim_loop_var_quotes(value);
    if value.as_bytes().get(1) == Some(&b':') {
        &value[..2]
    } else {
        ""
    }
}

fn loop_var_path(value: &str) -> &str {
    let value = trim_loop_var_quotes(value);
    let without_drive = if value.as_bytes().get(1) == Some(&b':') {
        &value[2..]
    } else {
        value
    };
    match without_drive.rfind(['\\', '/']) {
        Some(idx) => &without_drive[..=idx],
        None => "",
    }
}

fn loop_var_name_stem(value: &str) -> &str {
    let filename = value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim_matches('"');
    filename.rsplit_once('.').map_or(filename, |(stem, _)| stem)
}

fn loop_var_extension(value: &str) -> &str {
    let filename = value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim_matches('"');
    filename
        .rfind('.')
        .map_or("", |idx| filename.get(idx..).unwrap_or(""))
}
