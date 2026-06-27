//! bitsadmin handler — extracts /transfer URL + DST.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{attached_flag_value, split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_bitsadmin(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if let Some((job, command)) = bitsadmin_notify_command(&tokens) {
        push_lolbas(raw, env);
        push_notify_persistence(env, job, command.clone());
        queue_notify_child(command, env);
        return;
    }

    if !tokens
        .iter()
        .any(|t| bitsadmin_flag_eq(t, "transfer") || bitsadmin_flag_eq(t, "addfile"))
    {
        return;
    }

    // Skip past job-control verbs and known flags to find URL + DST pairs.
    let mut downloads: Vec<(String, String)> = Vec::new();
    let mut pending_url: Option<String> = None;
    let skip_flags = [
        "transfer", "addfile", "create", "download", "upload", "priority",
    ];
    let skip_values = ["priority"]; // flags whose separate VALUE we also skip

    let mut i = 1; // skip "bitsadmin"
    while i < tokens.len() {
        let t = &tokens[i];
        if skip_flags.iter().any(|flag| bitsadmin_flag_eq(t, flag)) {
            if skip_values
                .iter()
                .any(|flag| bitsadmin_flag_is_bare(t, flag))
            {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // Job name (first positional after /transfer) — skip if URL not yet seen
        // and current token doesn't look like a URL. Case-insensitive +
        // tolerate Windows-liberal slashes (`http:\\` / `http:/`).
        if pending_url.is_none()
            && downloads.is_empty()
            && !is_bitsadmin_option(t)
            && crate::deob_scan::normalize_liberal_url_token(strip_outer_quotes(t)).is_none()
        {
            // This is the job name; skip it.
            i += 1;
            continue;
        }
        if let Some(normalized) =
            crate::deob_scan::normalize_liberal_url_token(strip_outer_quotes(t))
        {
            if let Some(url) = pending_url.replace(normalized) {
                downloads.push((url, String::new()));
            }
            i += 1;
            continue;
        }

        if let Some(url) = pending_url.take() {
            if !is_bitsadmin_option(t) {
                downloads.push((url, strip_outer_quotes(t).to_string()));
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
        push_lolbas(raw, env);
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

fn bitsadmin_flag_eq(token: &str, flag: &str) -> bool {
    token.strip_prefix(['/', '-']).is_some_and(|value| {
        value.eq_ignore_ascii_case(flag)
            || value
                .strip_prefix(flag)
                .is_some_and(|rest| matches!(rest.as_bytes().first(), Some(b':' | b'=')))
    })
}

fn bitsadmin_flag_is_bare(token: &str, flag: &str) -> bool {
    token
        .strip_prefix(['/', '-'])
        .is_some_and(|value| value.eq_ignore_ascii_case(flag))
}

fn is_bitsadmin_option(token: &str) -> bool {
    token.starts_with('/') || token.starts_with('-')
}

fn bitsadmin_notify_command(tokens: &[String]) -> Option<(String, String)> {
    let mut i = 1usize;
    while i < tokens.len() {
        let token = strip_outer_quotes(&tokens[i]);
        let (job, program_idx) = if token.eq_ignore_ascii_case("/setnotifycmdline")
            || token.eq_ignore_ascii_case("-setnotifycmdline")
        {
            (strip_outer_quotes(tokens.get(i + 1)?).to_string(), i + 2)
        } else if let Some(value) =
            attached_flag_value(token, &["/setnotifycmdline", "-setnotifycmdline"])
        {
            (strip_outer_quotes(value).to_string(), i + 1)
        } else {
            i += 1;
            continue;
        };

        let program = tokens
            .get(program_idx)
            .map(|value| strip_outer_quotes(value).trim())
            .filter(|value| !value.is_empty())?;
        if job.is_empty() || program.eq_ignore_ascii_case("none") {
            return None;
        }

        let params = tokens
            .get(program_idx + 1..)
            .unwrap_or_default()
            .iter()
            .map(|part| strip_outer_quotes(part).trim())
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

fn queue_notify_child(command: String, env: &mut Environment) {
    if let Some(inner) = super::cmd::extract_cmd_inner(&command) {
        env.exec_cmd.push(inner);
        env.exec_cmd_delayed
            .push(super::cmd::has_v_on_raw(&command));
    } else {
        env.exec_cmd.push(command);
        env.exec_cmd_delayed.push(false);
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
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
