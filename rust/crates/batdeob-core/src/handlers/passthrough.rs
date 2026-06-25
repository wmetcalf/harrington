//! Pass-through admin commands — emits an AdminCommand trait so analysts
//! can filter on these without inspecting the deobfuscated text.

#![allow(clippy::expect_used)]

use crate::env::Environment;
use crate::handlers::util::contains_ascii_case_insensitive;
use crate::traits::Trait;

macro_rules! make_handler {
    ($fn_name:ident, $cmd_name:literal) => {
        pub fn $fn_name(raw: &str, env: &mut Environment) {
            env.traits.push(Trait::AdminCommand {
                name: $cmd_name.to_string(),
                cmd: raw.to_string(),
            });
        }
    };
}

make_handler!(h_del, "del");
make_handler!(h_cls, "cls");
make_handler!(h_timeout, "timeout");

/// `reg add` handler. Pushes the existing AdminCommand trait for backward
/// compat, and additionally emits a Persistence trait when the target key
/// is a well-known Windows autorun hive (Run / RunOnce / RunServices /
/// Userinit / Image File Execution Options). Recognised by a substring
/// match on the lowercased key path.
pub fn h_reg(raw: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    env.traits.push(Trait::AdminCommand {
        name: "reg".to_string(),
        cmd: raw.to_string(),
    });
    if !contains_ascii_case_insensitive(raw, "reg") || !contains_ascii_case_insensitive(raw, "add")
    {
        return;
    }
    // Match `reg add <key> /v <name> /d <data>` — `key` is quoted or
    // unquoted up to the next space/`/v`. `data` extends to end of line
    // (or `/f`/`/t`). Tolerate the optional `.exe` and any flag order.
    static REG_ADD_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)reg(?:\.exe)?\s+add\s+(?:"([^"]+)"|(\S+))"#).expect("reg add regex")
    });
    // Separate regexes for /v and /d so each can scan the rest of the
    // line independently (a single lazy regex would skip the /d match).
    static V_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/v\s+(?:"([^"]+)"|(\S+))"#).expect("/v regex"));
    static D_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/d\s+(?:"([^"]*)"|(\S+))"#).expect("/d regex"));
    let Some(caps) = REG_ADD_RE.captures(raw) else {
        return;
    };
    let key = caps
        .get(1)
        .or_else(|| caps.get(2))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    if key.is_empty() {
        return;
    }
    let value_name = V_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();
    let command = D_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();
    // Defender registry tampering — `reg add …\Windows Defender\… /v
    // Disable…` pattern. AV evasion IOC even when the key isn't a
    // persistence path. d5033dd..., eae19989..., 864eedb8..., 68ee8152...
    // families flip DisableBehaviorMonitoring / DisableAntiSpyware /
    // DisableEnhancedNotifications via this exact form.
    if let Some(suffix) = defender_regset_suffix(&key, &value_name) {
        env.traits.push(Trait::DefenderEvasion {
            action: format!("regset-{suffix}"),
            target: command.clone(),
        });
    }
    // Persistence keys — case-insensitive substring match on the key path.
    const PERSISTENCE_PATHS: &[&str] = &[
        r"\currentversion\run",
        r"\currentversion\runonce",
        r"\currentversion\runservices",
        r"\currentversion\runservicesonce",
        r"\currentversion\explorer\run",
        r"\currentversion\policies\explorer\run",
        r"\currentversion\shell\open\command",
        r"\winlogon\userinit",
        r"\winlogon\shell",
        r"\image file execution options\",
        r"\currentversion\app paths\",
        r"\currentversion\winlogon\shell",
    ];
    if !PERSISTENCE_PATHS
        .iter()
        .any(|p| contains_ascii_case_insensitive(&key, p))
    {
        return;
    }
    // Split hive from sub-key for clarity.
    let (hive, subkey) = if let Some(idx) = key.find('\\') {
        (key[..idx].to_string(), key[idx + 1..].to_string())
    } else {
        (key.clone(), String::new())
    };
    env.traits.push(Trait::Persistence {
        hive,
        key: subkey,
        value_name,
        command: command.clone(),
    });
    queue_registry_persisted_command(command, env);
}

fn defender_regset_suffix(key: &str, value_name: &str) -> Option<&'static str> {
    if !(contains_ascii_case_insensitive(key, "\\windows defender")
        || contains_ascii_case_insensitive(key, "/windows defender"))
        || !contains_ascii_case_insensitive(value_name, "disable")
    {
        return None;
    }
    crate::deob_scan::defender_evasion_action_suffix(value_name)
}

make_handler!(h_attrib, "attrib");
make_handler!(h_mkdir, "mkdir");
make_handler!(h_md, "md");
make_handler!(h_move, "move");
make_handler!(h_rmdir, "rmdir");
make_handler!(h_rd, "rd");
make_handler!(h_taskkill, "taskkill");
make_handler!(h_tasklist, "tasklist");
/// `schtasks` handler. Pushes AdminCommand; if the invocation creates a
/// scheduled task (`schtasks /create /tn X /tr Y`), also emits a
/// Persistence trait — scheduled tasks are a primary autorun mechanism.
pub fn h_schtasks(raw: &str, env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    env.traits.push(Trait::AdminCommand {
        name: "schtasks".to_string(),
        cmd: raw.to_string(),
    });
    if !contains_ascii_case_insensitive(raw, "/create") {
        return;
    }
    static TN_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/tn\s+(?:"([^"]+)"|(\S+))"#).expect("/tn regex"));
    static TR_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)/tr\s+(?:"([^"]+)"|(\S+))"#).expect("/tr regex"));
    let task_name = TN_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();
    let task_run = TR_RE
        .captures(raw)
        .and_then(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .unwrap_or_default();
    env.traits.push(Trait::Persistence {
        hive: "ScheduledTask".to_string(),
        key: task_name,
        value_name: String::new(),
        command: task_run.clone(),
    });
    queue_child_command(task_run, env);
}

fn queue_registry_persisted_command(command: String, env: &mut Environment) {
    if !persisted_command_looks_dispatchable(&command) {
        return;
    }
    queue_child_command(command, env);
}

fn queue_child_command(command: String, env: &mut Environment) {
    if command.is_empty() {
        return;
    }
    if let Some(inner) = super::cmd::extract_cmd_inner(&command) {
        env.exec_cmd.push(inner);
        env.exec_cmd_delayed
            .push(super::cmd::has_v_on_raw(&command));
    } else {
        env.exec_cmd.push(command);
        env.exec_cmd_delayed.push(false);
    }
}

fn persisted_command_looks_dispatchable(command: &str) -> bool {
    let trimmed = command.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.ends_with('\\') || trimmed.ends_with('/') {
        return false;
    }
    trimmed.bytes().any(|b| b.is_ascii_whitespace())
}

make_handler!(h_sc, "sc");
make_handler!(h_ping, "ping");
make_handler!(h_xcopy, "xcopy");
make_handler!(h_title, "title");
make_handler!(h_pause, "pause");
make_handler!(h_color, "color");
make_handler!(h_doskey, "doskey");
make_handler!(h_chcp, "chcp");
make_handler!(h_ver, "ver");
make_handler!(h_whoami, "whoami");

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn reg_run_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_reg(
            r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "cmd /c echo hidden" /f"#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "registry persistence command was not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn schtasks_tr_command_is_queued_for_recursive_analysis() {
        let mut env = Environment::new(&Config::default());

        h_schtasks(
            r#"schtasks /create /tn Updater /tr "cmd /c echo hidden""#,
            &mut env,
        );

        assert!(
            env.exec_cmd.iter().any(|cmd| cmd == "echo hidden"),
            "scheduled task command was not queued: {:?}",
            env.exec_cmd
        );
    }
}
