//! setlocal / endlocal handlers.

use crate::env::Environment;
use crate::handlers::util::contains_ascii_case_insensitive;
use crate::traits::Trait;

pub fn h_setlocal(raw: &str, env: &mut Environment) {
    let enable_delayed = contains_ascii_case_insensitive(raw, "enabledelayedexpansion");
    env.push_setlocal(enable_delayed);
    env.traits.push(Trait::SetlocalScope {
        enabled_delayed: enable_delayed,
    });
}

pub fn h_endlocal(_raw: &str, env: &mut Environment) {
    env.pop_setlocal();
}
