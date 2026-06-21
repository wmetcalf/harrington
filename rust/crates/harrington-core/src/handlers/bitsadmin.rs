//! bitsadmin handler — extracts /transfer URL + DST.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_bitsadmin(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();
    if !lower.iter().any(|t| t == "/transfer" || t == "/addfile") {
        return;
    }

    // Skip past /transfer and known flags to find URL + DST pairs.
    let mut downloads: Vec<(String, String)> = Vec::new();
    let mut pending_url: Option<String> = None;
    let skip_flags = ["/transfer", "/addfile", "/download", "/upload", "/priority"];
    let skip_values = ["/priority"]; // flags whose VALUE we also skip

    let mut i = 1; // skip "bitsadmin"
    while i < tokens.len() {
        let t = &tokens[i];
        let tl = t.to_ascii_lowercase();
        if skip_flags.contains(&tl.as_str()) {
            if skip_values.contains(&tl.as_str()) {
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
