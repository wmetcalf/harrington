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
    }
    count
}

/// Replace `%%X` (script form) and `%X` (interactive form) with `value`.
/// The match on the variable letter is case-insensitive.
pub fn substitute_loop_var(body: &str, var: char, value: &str) -> String {
    let mut out = String::with_capacity(body.len() + value.len());
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            // Try `%%~nX` / `%%~X` script-form modifiers.
            if chars.get(i + 1) == Some(&'%') && chars.get(i + 2) == Some(&'~') {
                if chars
                    .get(i + 3)
                    .map(|c| c.eq_ignore_ascii_case(&var))
                    .unwrap_or(false)
                {
                    out.push_str(value);
                    i += 4;
                    continue;
                }
                if chars
                    .get(i + 3)
                    .is_some_and(|c| c.eq_ignore_ascii_case(&'n'))
                    && chars
                        .get(i + 4)
                        .map(|c| c.eq_ignore_ascii_case(&var))
                        .unwrap_or(false)
                {
                    out.push_str(loop_var_name_stem(value));
                    i += 5;
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
            // Try `%~nX` / `%~X` interactive-form modifiers.
            if chars.get(i + 1) == Some(&'~') {
                if chars
                    .get(i + 2)
                    .map(|c| c.eq_ignore_ascii_case(&var))
                    .unwrap_or(false)
                {
                    out.push_str(value);
                    i += 3;
                    continue;
                }
                if chars
                    .get(i + 2)
                    .is_some_and(|c| c.eq_ignore_ascii_case(&'n'))
                    && chars
                        .get(i + 3)
                        .map(|c| c.eq_ignore_ascii_case(&var))
                        .unwrap_or(false)
                {
                    out.push_str(loop_var_name_stem(value));
                    i += 4;
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

fn loop_var_name_stem(value: &str) -> &str {
    let filename = value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim_matches('"');
    filename.rsplit_once('.').map_or(filename, |(stem, _)| stem)
}
