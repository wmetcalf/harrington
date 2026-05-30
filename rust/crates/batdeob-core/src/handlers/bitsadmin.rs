//! bitsadmin handler — extracts /transfer URL + DST.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_bitsadmin(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();
    if !lower.iter().any(|t| t == "/transfer") {
        return;
    }

    // Skip past /transfer and known flags to find URL + DST.
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let skip_flags = ["/transfer", "/download", "/upload", "/priority"];
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
        // tolerate Windows-liberal slashes (`http:\\` / `http:/`).
        let tl = t.to_ascii_lowercase();
        let is_url_like = |s: &str| -> bool {
            for scheme in &["http:", "https:", "ftp:"] {
                if let Some(rest) = s.strip_prefix(scheme) {
                    let c = rest.chars().next();
                    if matches!(c, Some('/') | Some('\\')) {
                        return true;
                    }
                }
            }
            false
        };
        if !tl.starts_with("http") && !tl.starts_with("ftp") && url.is_none() && !t.starts_with('/')
        {
            // This is the job name; skip it.
            i += 1;
            continue;
        }
        if is_url_like(&tl) && url.is_none() {
            url = Some(strip_quotes(t).to_string());
            i += 1;
            continue;
        }
        if url.is_some() && dst.is_none() && !t.starts_with('/') {
            dst = Some(strip_quotes(t).to_string());
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

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}
