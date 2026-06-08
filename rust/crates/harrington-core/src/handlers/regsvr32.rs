//! regsvr32 handler — surfaces remote scriptlet URLs and WebDAV/UNC targets.

use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_regsvr32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if regsvr32_remote_unc_target_after(&tokens, 1) {
        push_lolbas(raw, env);
    }
    if let Some(url) = regsvr32_scriptlet_url_after(&tokens, 1) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
    if let Some(url) = regsvr32_prior_download_url(&tokens, env) {
        push_url_argument(raw, url, env);
    }
}

fn regsvr32_scriptlet_url_after(tokens: &[String], start: usize) -> Option<String> {
    let limit = tokens.len().min(start.saturating_add(12));
    for i in start..limit {
        let token = strip_quotes(&tokens[i]);
        let lower = token.to_ascii_lowercase();
        let candidate = if lower.starts_with("/i:") || lower.starts_with("-i:") {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens.get(i + 1).map(|next| strip_quotes(next))
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = trim_url_suffix(candidate);
        if let Some(url) = crate::deob_scan::normalize_liberal_url_token(candidate)
            .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(candidate))
        {
            return Some(url);
        }
    }
    None
}

fn regsvr32_remote_unc_target_after(tokens: &[String], start: usize) -> bool {
    let limit = tokens.len().min(start.saturating_add(12));
    tokens[start..limit].iter().any(|token| {
        let token = strip_quotes(token);
        token.starts_with(r"\\")
            && token.to_ascii_lowercase().contains(r"\davwwwroot\")
            && regsvr32_loadable_target(token)
    })
}

fn regsvr32_loadable_target(token: &str) -> bool {
    let trimmed = trim_url_suffix(token).to_ascii_lowercase();
    [".dll", ".sct", ".ocx", ".cpl"]
        .iter()
        .any(|suffix| trimmed.ends_with(suffix))
}

fn regsvr32_prior_download_url(tokens: &[String], env: &Environment) -> Option<String> {
    let limit = tokens.len().min(13);
    for i in 1..limit {
        let token = strip_quotes(&tokens[i]).trim();
        let lower = token.to_ascii_lowercase();
        let candidate = if lower.starts_with("/i:") || lower.starts_with("-i:") {
            token.get(3..)
        } else if lower == "/i" || lower == "-i" {
            tokens.get(i + 1).map(|next| strip_quotes(next).trim())
        } else {
            None
        };
        let Some(candidate) = candidate else {
            continue;
        };
        let candidate = trim_url_suffix(candidate).trim();
        if candidate.is_empty() {
            continue;
        }
        let key = candidate.to_ascii_lowercase();
        if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
            return Some(src.clone());
        }
    }
    None
}

fn push_url_argument(raw: &str, url: String, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument { cmd, url: existing }
                if cmd == raw && existing == &url
        )
    }) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::Lolbas { name, cmd } if name == "regsvr32" && cmd == raw
        )
    }) {
        env.traits.push(Trait::Lolbas {
            name: "regsvr32".to_string(),
            cmd: raw.to_string(),
        });
    }
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}

fn trim_url_suffix(url: &str) -> &str {
    url.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
}
