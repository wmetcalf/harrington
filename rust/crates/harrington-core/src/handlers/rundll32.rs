use super::util::{split_words, windows_basename};
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    let parts = split_words(raw);
    if parts.len() < 2 {
        return;
    }
    let mut matched_lolbas = queue_inline_script_payload(raw, env);
    if let Some(url) = url_launch_export_argument(&parts) {
        env.traits.push(Trait::UrlLaunch {
            cmd: raw.to_string(),
            url,
        });
        matched_lolbas = true;
    }
    if let Some(url) = download_export_argument(&parts) {
        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: url,
            dst: None,
        });
        matched_lolbas = true;
    }
    if let Some(url) = download_export_prior_download_argument(&parts, env) {
        push_url_argument(raw, url, env);
        matched_lolbas = true;
    }
    let dll = strip_quotes(parts[1].split(',').next().unwrap_or(""));
    let url = downloaded_src_for_candidate(dll, env).or_else(|| webdav_url_for_candidate(dll));
    if url.is_some() {
        matched_lolbas = true;
    }
    env.traits.push(Trait::Rundll32 {
        cmd: raw.to_string(),
        url,
    });
    if matched_lolbas {
        push_lolbas(raw, env);
    }
}

fn queue_inline_script_payload(raw: &str, env: &mut Environment) -> bool {
    const MAX_INLINE_SCRIPT_BYTES: usize = 256 * 1024;
    let mut queued = false;

    if let Some(body) = inline_payload_after(raw, "vbscript:") {
        if body.len() <= MAX_INLINE_SCRIPT_BYTES {
            let payload = body.as_bytes().to_vec();
            if !env
                .all_extracted_vbs
                .iter()
                .any(|existing| existing == &payload)
            {
                env.all_extracted_vbs.push(payload);
            }
            queued = true;
        }
    }

    if let Some(body) =
        inline_payload_after(raw, "javascript:").or_else(|| inline_payload_after(raw, "jscript:"))
    {
        if body.len() <= MAX_INLINE_SCRIPT_BYTES {
            let payload = body.as_bytes().to_vec();
            if !env
                .all_extracted_jscript
                .iter()
                .any(|existing| existing == &payload)
            {
                env.all_extracted_jscript.push(payload);
            }
            queued = true;
        }
    }
    queued
}

fn inline_payload_after<'a>(raw: &'a str, marker: &str) -> Option<&'a str> {
    let start = find_ascii_case_insensitive(raw, marker)? + marker.len();
    let body = raw[start..].trim().trim_matches(['"', '\'']);
    (!body.is_empty()).then_some(body)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn url_launch_export_argument(parts: &[String]) -> Option<String> {
    let export_idx = parts
        .iter()
        .enumerate()
        .skip(1)
        .take(4)
        .find_map(|(idx, part)| {
            if rundll32_url_launch_export(strip_quotes(part)) {
                Some(idx)
            } else {
                None
            }
        })?;
    first_url_after(parts, export_idx + 1)
}

fn download_export_argument(parts: &[String]) -> Option<String> {
    let export_idx = parts
        .iter()
        .enumerate()
        .skip(1)
        .take(4)
        .find_map(|(idx, part)| {
            if rundll32_download_export(strip_quotes(part)) {
                Some(idx)
            } else {
                None
            }
        })?;
    first_url_after(parts, export_idx + 1)
}

fn download_export_prior_download_argument(parts: &[String], env: &Environment) -> Option<String> {
    let export_idx = parts
        .iter()
        .enumerate()
        .skip(1)
        .take(4)
        .find_map(|(idx, part)| {
            if rundll32_download_export(strip_quotes(part)) {
                Some(idx)
            } else {
                None
            }
        })?;
    for token in parts.iter().skip(export_idx + 1).take(4) {
        let candidate = trim_arg_suffix(strip_quotes(token)).trim();
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if let Some(src) = downloaded_src_for_candidate(candidate, env) {
            return Some(src);
        }
    }
    None
}

fn downloaded_src_for_candidate(candidate: &str, env: &Environment) -> Option<String> {
    let key = candidate.to_ascii_lowercase();
    if let Some(FsEntry::Download { src }) = env.modified_filesystem.get(&key) {
        return Some(src.clone());
    }
    if candidate.contains(['\\', '/']) {
        return None;
    }
    for (path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(candidate) {
            if let FsEntry::Download { src } = entry {
                return Some(src.clone());
            }
        }
    }
    None
}

fn webdav_url_for_candidate(candidate: &str) -> Option<String> {
    let candidate = trim_arg_suffix(strip_quotes(candidate)).trim();
    if !candidate.starts_with(r"\\") {
        return None;
    }
    let parts: Vec<&str> = candidate
        .split('\\')
        .filter(|part| !part.is_empty())
        .collect();
    let host_port = parts.first()?;
    if let Some((host, port)) = host_port.split_once('@') {
        if host.is_empty()
            || port.is_empty()
            || !contains_ascii_case_insensitive(candidate, r"\davwwwroot\")
        {
            return None;
        }
        return Some(crate::deob_scan::unc_webdav_to_http_url(
            host, port, candidate,
        ));
    }
    if parts.len() < 3 || !parts[1].eq_ignore_ascii_case("webdav") || parts[2].is_empty() {
        return None;
    }
    Some(crate::deob_scan::unc_webdav_to_http_url(
        host_port, "80", candidate,
    ))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn rundll32_url_launch_export(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("url.dll,fileprotocolhandler")
        || lower.contains("url.dll,openurl")
        || lower.contains("ieframe.dll,openurl")
        || lower.contains("shdocvw.dll,openurl")
        || lower.contains("photoviewer.dll,imageview_fullscreen")
        || lower.contains("shimgvw.dll,imageview_fullscreen")
}

fn rundll32_download_export(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("scrobj.dll,generatetypelib")
}

fn first_url_after(parts: &[String], start: usize) -> Option<String> {
    parts
        .iter()
        .skip(start)
        .map(|part| strip_quotes(part).trim_start_matches(['"', '\'']))
        .find_map(|part| {
            let end = part
                .find([')', '(', ';', ',', '"', '\'', '`'])
                .unwrap_or(part.len());
            crate::deob_scan::normalize_liberal_url_token(&part[..end])
                .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&part[..end]))
        })
}

fn trim_arg_suffix(value: &str) -> &str {
    value.trim_end_matches(['"', '\'', ')', ']', '}', ';', ','])
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

fn push_url_argument(raw: &str, url: String, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::UrlArgument { cmd, url: existing } if cmd == raw && existing == &url
        )
    }) {
        env.traits.push(Trait::UrlArgument {
            cmd: raw.to_string(),
            url,
        });
    }
}

fn push_lolbas(raw: &str, env: &mut Environment) {
    if !env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::Lolbas { name, cmd } if name == "rundll32" && cmd == raw))
    {
        env.traits.push(Trait::Lolbas {
            name: "rundll32".to_string(),
            cmd: raw.to_string(),
        });
    }
}
