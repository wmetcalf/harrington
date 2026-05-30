//! setlocal / endlocal handlers.

use crate::env::Environment;
use crate::traits::Trait;

pub fn h_setlocal(raw: &str, env: &mut Environment) {
    let lower = raw.to_ascii_lowercase();
    let enable_delayed = lower.contains("enabledelayedexpansion");
    env.push_setlocal(enable_delayed);
    env.traits.push(Trait::SetlocalScope {
        enabled_delayed: enable_delayed,
    });
}

pub fn h_endlocal(_raw: &str, env: &mut Environment) {
    env.pop_setlocal();
}
