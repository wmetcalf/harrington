use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    let parts = split_words(raw);
    if parts.len() < 2 {
        return;
    }
    if let Some(url) = file_protocol_handler_url(&parts) {
        env.traits.push(Trait::UrlLaunch {
            cmd: raw.to_string(),
            url,
        });
    }
    let dll = strip_outer_quotes(parts[1].split(',').next().unwrap_or(""));
    let url = match env.modified_filesystem.get(&dll.to_ascii_lowercase()) {
        Some(FsEntry::Download { src }) => Some(src.clone()),
        _ => None,
    };
    env.traits.push(Trait::Rundll32 {
        cmd: raw.to_string(),
        url,
    });
}

fn file_protocol_handler_url(parts: &[String]) -> Option<String> {
    let handler_idx = parts
        .iter()
        .enumerate()
        .skip(1)
        .take(4)
        .find_map(|(idx, part)| {
            if strip_outer_quotes(part)
                .to_ascii_lowercase()
                .contains("fileprotocolhandler")
            {
                Some(idx)
            } else {
                None
            }
        })?;
    parts
        .iter()
        .skip(handler_idx + 1)
        .map(|part| strip_outer_quotes(part).trim_start_matches(['"', '\'']))
        .find_map(|part| {
            let end = part
                .find([')', '(', ';', ',', '"', '\'', '`'])
                .unwrap_or(part.len());
            crate::deob_scan::normalize_liberal_url_token(&part[..end])
                .or_else(|| crate::deob_scan::normalize_schemeless_domain_path_token(&part[..end]))
        })
}
