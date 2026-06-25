//! bitsadmin handler — extracts /transfer URL + DST.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_bitsadmin(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if !tokens
        .iter()
        .any(|t| t.eq_ignore_ascii_case("/transfer") || t.eq_ignore_ascii_case("/addfile"))
    {
        return;
    }

    // Skip past job-control verbs and known flags to find URL + DST.
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let skip_flags = [
        "/transfer",
        "/addfile",
        "/create",
        "/download",
        "/upload",
        "/priority",
    ];
    let skip_values = ["/priority"]; // flags whose VALUE we also skip

    let mut i = 1; // skip "bitsadmin"
    while i < tokens.len() {
        let t = &tokens[i];
        if skip_flags.iter().any(|flag| t.eq_ignore_ascii_case(flag)) {
            if skip_values.iter().any(|flag| t.eq_ignore_ascii_case(flag)) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        // Job name (first positional after /transfer) — skip if URL not yet seen
        // and current token doesn't look like a URL. Case-insensitive +
        // tolerate Windows-liberal slashes (`http:\\` / `http:/`).
        if url.is_none()
            && !t.starts_with('/')
            && crate::deob_scan::normalize_liberal_url_token(strip_outer_quotes(t)).is_none()
        {
            // This is the job name; skip it.
            i += 1;
            continue;
        }
        if url.is_none() {
            if let Some(normalized) =
                crate::deob_scan::normalize_liberal_url_token(strip_outer_quotes(t))
            {
                url = Some(normalized);
                i += 1;
                continue;
            }
        }
        if url.is_some() && dst.is_none() && !t.starts_with('/') {
            dst = Some(strip_outer_quotes(t).to_string());
            i += 1;
            continue;
        }
        i += 1;
    }

    if let Some(u) = url {
        let d = dst.unwrap_or_default();
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
