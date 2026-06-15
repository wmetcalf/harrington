//! bitsadmin handler — extracts /transfer URL + DST.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_bitsadmin(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();
    if let Some((job, command)) = bitsadmin_notify_command(&tokens) {
        push_lolbas(env, raw);
        push_notify_persistence(env, job, command.clone());
        if let Some((child, delayed)) =
            crate::handlers::passthrough::persisted_command_child(&command)
        {
            env.exec_cmd.push(child);
            env.exec_cmd_delayed.push(delayed);
        }
        return;
    }
    if !lower
        .iter()
        .any(|t| bitsadmin_flag_matches(t, "/transfer") || bitsadmin_flag_matches(t, "/addfile"))
    {
        return;
    }

    // Skip past /transfer and known flags to find URL + DST pairs.
    let mut downloads: Vec<(String, String)> = Vec::new();
    let mut pending_url: Option<String> = None;

    let mut i = 1; // skip "bitsadmin"
    while i < tokens.len() {
        let t = &tokens[i];
        let tl = t.to_ascii_lowercase();
        if bitsadmin_skip_flag(&tl) {
            if tl == "/priority" {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // Job name (first positional after /transfer) — skip if URL not yet seen
        // and current token doesn't look like a URL. Case-insensitive +
        // tolerate Windows-liberal slashes (`http:\\` / `http:/`) plus the
        // corpus-observed BITS shape `domain.tld/path` with no scheme.
        let maybe_url = normalize_bitsadmin_url_token(t);
        if maybe_url.is_none()
            && pending_url.is_none()
            && downloads.is_empty()
            && !t.starts_with('/')
        {
            // This is the job name; skip it.
            i += 1;
            continue;
        }
        if let Some(normalized) = maybe_url {
            if let Some(url) = pending_url.replace(normalized) {
                downloads.push((url, String::new()));
            }
            i += 1;
            continue;
        }
        if let Some(url) = pending_url.take() {
            if !t.starts_with('/') {
                downloads.push((url, strip_quotes(t).to_string()));
            } else {
                downloads.push((url, String::new()));
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    if let Some(url) = pending_url {
        downloads.push((url, String::new()));
    }

    if !downloads.is_empty() {
        push_lolbas(env, raw);
    }

    for (u, d) in downloads {
        env.traits.push(Trait::BitsadminDownload {
            url: u.clone(),
            dst: d.clone(),
        });
        if !d.is_empty() {
            env.modified_filesystem
                .insert(d.to_ascii_lowercase(), FsEntry::Download { src: u });
        }
    }
}

fn bitsadmin_skip_flag(token: &str) -> bool {
    ["/transfer", "/addfile", "/download", "/upload", "/priority"]
        .iter()
        .any(|flag| bitsadmin_flag_matches(token, flag))
}

fn bitsadmin_flag_matches(token: &str, flag: &str) -> bool {
    token == flag
        || token
            .strip_prefix(flag)
            .and_then(|rest| rest.as_bytes().first())
            .is_some_and(|byte| matches!(*byte, b':' | b'='))
}

fn bitsadmin_notify_command(tokens: &[String]) -> Option<(String, String)> {
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        let (job, program_idx) = if lower == "/setnotifycmdline" || lower == "-setnotifycmdline" {
            (strip_quotes(tokens.get(i + 1)?).to_string(), i + 2)
        } else if let Some(rest) = strip_notify_attached_value(token) {
            (strip_quotes(rest).to_string(), i + 1)
        } else {
            i += 1;
            continue;
        };
        let program = strip_quotes(tokens.get(program_idx)?).trim();
        if job.is_empty() || program.is_empty() || program.eq_ignore_ascii_case("none") {
            return None;
        }
        let params = tokens
            .get(program_idx + 1..)
            .unwrap_or_default()
            .iter()
            .map(|part| strip_quotes(part))
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let command = if params.is_empty() {
            program.to_string()
        } else {
            format!("{program} {params}")
        };
        return Some((job, command));
    }
    None
}

fn strip_notify_attached_value(token: &str) -> Option<&str> {
    let lower = token.to_ascii_lowercase();
    for prefix in [
        "/setnotifycmdline:",
        "/setnotifycmdline=",
        "-setnotifycmdline:",
        "-setnotifycmdline=",
    ] {
        if lower.starts_with(prefix) {
            return Some(&token[prefix.len()..]);
        }
    }
    None
}

fn push_notify_persistence(env: &mut Environment, job: String, command: String) {
    if env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Persistence {
                hive,
                key,
                value_name,
                command: existing,
            } if hive == "BITS"
                && key == &job
                && value_name == "SetNotifyCmdLine"
                && existing == &command
        )
    }) {
        return;
    }
    env.traits.push(Trait::Persistence {
        hive: "BITS".to_string(),
        key: job,
        value_name: "SetNotifyCmdLine".to_string(),
        command,
    });
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}

fn normalize_bitsadmin_url_token(token: &str) -> Option<String> {
    if let Some(url) = crate::deob_scan::normalize_liberal_url_token(token) {
        return Some(url);
    }
    crate::deob_scan::normalize_schemeless_domain_path_token(token)
}

fn push_lolbas(env: &mut Environment, raw: &str) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "bitsadmin" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "bitsadmin".to_string(),
            cmd: raw.to_string(),
        });
    }
}
