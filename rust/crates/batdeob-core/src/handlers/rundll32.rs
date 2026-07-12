use crate::env::{Environment, FsEntry};
use crate::handlers::util::{
    filesystem_entry_for_path, split_words, strip_outer_quotes, windows_basename,
};
use crate::traits::Trait;
use crate::util::contains_ascii_case_insensitive;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    let parts = split_words(raw);
    if parts.len() < 2 {
        return;
    }
    let mut matched_lolbas = false;
    if let Some(url) = url_launch_export_argument(&parts) {
        env.traits.push(Trait::UrlLaunch {
            cmd: raw.to_string(),
            url,
        });
        matched_lolbas = true;
    } else if let Some(url) = url_launch_export_prior_download_argument(&parts, env) {
        push_url_argument(raw, url, env);
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
    let dll = strip_outer_quotes(parts[1].split(',').next().unwrap_or(""));
    let url = match filesystem_entry_for_path(env, dll) {
        Some(FsEntry::Download { src }) => Some(src.clone()),
        _ => webdav_url_for_candidate(dll),
    };
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

fn url_launch_export_argument(parts: &[String]) -> Option<String> {
    let export_idx = parts
        .iter()
        .enumerate()
        .skip(1)
        .take(4)
        .find_map(|(idx, part)| {
            if rundll32_url_launch_export(strip_outer_quotes(part)) {
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
            if rundll32_download_export(strip_outer_quotes(part)) {
                Some(idx)
            } else {
                None
            }
        })?;
    first_url_after(parts, export_idx + 1)
}

fn url_launch_export_prior_download_argument(
    parts: &[String],
    env: &Environment,
) -> Option<String> {
    let export_idx = parts
        .iter()
        .enumerate()
        .skip(1)
        .take(4)
        .find_map(|(idx, part)| {
            if rundll32_url_launch_export(strip_outer_quotes(part)) {
                Some(idx)
            } else {
                None
            }
        })?;
    prior_download_after_export(parts, export_idx, env)
}

fn prior_download_after_export(
    parts: &[String],
    export_idx: usize,
    env: &Environment,
) -> Option<String> {
    for token in parts.iter().skip(export_idx + 1).take(4) {
        let candidate = trim_arg_suffix(strip_outer_quotes(token)).trim();
        if candidate.is_empty() || candidate.starts_with(['/', '-']) {
            continue;
        }
        if let Some(url) = prior_download_url(candidate, env) {
            return Some(url);
        }
    }
    None
}

fn prior_download_url(path: &str, env: &Environment) -> Option<String> {
    if let Some(FsEntry::Download { src }) = filesystem_entry_for_path(env, path) {
        return Some(src.clone());
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return match filesystem_entry_for_path(env, stripped) {
                Some(FsEntry::Download { src }) => Some(src.clone()),
                _ => None,
            };
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return prior_download_url_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    prior_download_url_by_basename(path, env)
}

fn prior_download_url_by_basename(path: &str, env: &Environment) -> Option<String> {
    env.modified_filesystem
        .iter()
        .find_map(|(tracked_path, entry)| {
            windows_basename(tracked_path)
                .is_some_and(|name| name.eq_ignore_ascii_case(path))
                .then_some(entry)
        })
        .and_then(|entry| match entry {
            FsEntry::Download { src } => Some(src.clone()),
            _ => None,
        })
}

fn webdav_url_for_candidate(candidate: &str) -> Option<String> {
    let candidate = candidate.trim();
    if !candidate.starts_with(r"\\") || !rundll32_loadable_target(candidate) {
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

fn rundll32_loadable_target(token: &str) -> bool {
    windows_basename(token).is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        lower.ends_with(".dll") || lower.ends_with(".cpl")
    })
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn rundll32_url_launch_export(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("url.dll,fileprotocolhandler")
        || lower.contains("url.dll,openurl")
        || lower.contains("ieframe.dll,openurl")
        || lower.contains("shdocvw.dll,openurl")
        || lower.contains("shell32.dll,shellexec_rundll")
        || lower.contains("photoviewer.dll,imageview_fullscreen")
        || lower.contains("shimgvw.dll,imageview_fullscreen")
}

fn rundll32_download_export(token: &str) -> bool {
    token
        .to_ascii_lowercase()
        .contains("scrobj.dll,generatetypelib")
}

fn trim_arg_suffix(token: &str) -> &str {
    let end = token
        .find([')', '(', ';', ',', '"', '\'', '`'])
        .unwrap_or(token.len());
    &token[..end]
}

fn first_url_after(parts: &[String], start: usize) -> Option<String> {
    parts
        .iter()
        .skip(start)
        .map(|part| strip_outer_quotes(part).trim_start_matches(['"', '\'']))
        .find_map(|part| {
            let token = trim_arg_suffix(part);
            crate::deob_scan::normalize_liberal_url_token(token)
                .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(token))
        })
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
