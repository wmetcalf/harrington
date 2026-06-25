//! wmic handler — extracts the inner command from `wmic process call create ...`.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;

#[allow(clippy::expect_used)]
static WMIC_PROCESS_CREATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*wmic\s+process\s+call\s+create\s+(?:"(?P<dq>[^"]+)"|'(?P<sq>[^']+)'|(?P<bare>\S.*))\s*$"#,
    )
        .expect("wmic regex")
});

pub fn h_wmic(raw: &str, env: &mut Environment) {
    let Some(caps) = WMIC_PROCESS_CREATE_RE.captures(raw) else {
        return;
    };
    let inner = caps
        .name("dq")
        .or_else(|| caps.name("sq"))
        .or_else(|| caps.name("bare"))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    if inner.is_empty() {
        return;
    }
    env.traits.push(Trait::WmicProcessCreate {
        inner_cmd: inner.clone(),
    });
    env.exec_cmd.push(inner);
    env.exec_cmd_delayed.push(false);
}
