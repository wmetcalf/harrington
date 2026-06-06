use super::util::split_words;
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    let parts = split_words(raw);
    if parts.len() < 2 {
        return;
    }
    if let Some(url) = url_launch_export_argument(&parts) {
        env.traits.push(Trait::UrlLaunch {
            cmd: raw.to_string(),
            url,
        });
    }
    if let Some(url) = download_export_argument(&parts) {
        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: url,
            dst: None,
        });
    }
    let dll = strip_quotes(parts[1].split(',').next().unwrap_or(""));
    let url = match env.modified_filesystem.get(&dll.to_ascii_lowercase()) {
        Some(FsEntry::Download { src }) => Some(src.clone()),
        _ => None,
    };
    env.traits.push(Trait::Rundll32 {
        cmd: raw.to_string(),
        url,
    });
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

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
        && s.len() >= 2
    {
        return &s[1..s.len() - 1];
    }
    s
}
