//! ftp.exe handler - scans tracked `-s:script` command files.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{
    filesystem_entry_for_path, filesystem_storage_key, join_windows_path_preserving_separator,
    split_words, strip_outer_quotes,
};
use crate::traits::Trait;

pub fn h_ftp(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let Some(script_path) = ftp_script_path(&tokens) else {
        return;
    };
    let Some(content) = tracked_script_content(&script_path, env) else {
        return;
    };
    let script = String::from_utf8_lossy(&content);
    let Some(parsed) = parse_ftp_script(&script) else {
        return;
    };

    push_remote_connect(raw, &parsed.host, parsed.port, env);
    for transfer in parsed.downloads {
        let src = ftp_url(&parsed.host, parsed.port, &transfer.remote);
        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: src.clone(),
            dst: Some(transfer.local.clone()),
        });
        env.modified_filesystem.insert(
            filesystem_storage_key(&transfer.local),
            FsEntry::Download { src },
        );
    }
}

struct FtpScript {
    host: String,
    port: u16,
    downloads: Vec<FtpDownload>,
}

struct FtpDownload {
    remote: String,
    local: String,
}

fn ftp_script_path(tokens: &[String]) -> Option<String> {
    for (idx, token) in tokens.iter().enumerate().skip(1) {
        let token = strip_outer_quotes(token);
        let lower = token.to_ascii_lowercase();
        if lower == "-s" || lower == "/s" {
            return tokens
                .get(idx + 1)
                .map(|value| strip_outer_quotes(value).to_string())
                .filter(|value| !value.is_empty());
        }
        for prefix in ["-s:", "/s:", "-s=", "/s="] {
            let Some(rest) = lower.strip_prefix(prefix) else {
                continue;
            };
            let value_start = token.len() - rest.len();
            let value = strip_outer_quotes(&token[value_start..]).trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn parse_ftp_script(script: &str) -> Option<FtpScript> {
    let mut host: Option<String> = None;
    let mut port: u16 = 21;
    let mut cwd = String::new();
    let mut lcd = String::new();
    let mut downloads = Vec::new();

    for line in script.lines() {
        let tokens = split_words(line);
        let Some(command) = tokens.first().map(|value| {
            strip_outer_quotes(value)
                .trim_start_matches('@')
                .to_ascii_lowercase()
        }) else {
            continue;
        };
        match command.as_str() {
            "open" => {
                if let Some(value) = tokens.get(1).map(|value| strip_outer_quotes(value).trim()) {
                    if !value.is_empty() {
                        host = Some(value.to_string());
                    }
                }
                if let Some(parsed_port) = tokens
                    .get(2)
                    .and_then(|value| strip_outer_quotes(value).parse::<u16>().ok())
                {
                    port = parsed_port;
                }
            }
            "cd" => {
                if let Some(value) = tokens.get(1).map(|value| strip_outer_quotes(value).trim()) {
                    cwd = normalize_remote_path(value);
                }
            }
            "lcd" => {
                if let Some(value) = tokens.get(1).map(|value| strip_outer_quotes(value).trim()) {
                    lcd = normalize_local_path(value);
                }
            }
            "get" | "recv" => {
                let Some(remote) = tokens.get(1).map(|value| strip_outer_quotes(value).trim())
                else {
                    continue;
                };
                if remote.is_empty() {
                    continue;
                }
                let remote = join_remote_path(&cwd, remote);
                let local = tokens
                    .get(2)
                    .map(|value| strip_outer_quotes(value).trim().to_string())
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| remote_basename(&remote).unwrap_or_else(|| remote.clone()));
                let local = join_local_path(&lcd, &local);
                downloads.push(FtpDownload { remote, local });
            }
            "mget" => {
                for token in tokens.iter().skip(1) {
                    let remote = strip_outer_quotes(token).trim();
                    if remote.is_empty() || remote.contains(['*', '?']) {
                        continue;
                    }
                    let remote = join_remote_path(&cwd, remote);
                    let local =
                        remote_basename(&remote).unwrap_or_else(|| normalize_remote_path(&remote));
                    let local = join_local_path(&lcd, &local);
                    downloads.push(FtpDownload { remote, local });
                }
            }
            _ => {}
        }
    }

    let host = host?;
    Some(FtpScript {
        host,
        port,
        downloads,
    })
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    if let Some(content) = content_from_entry(filesystem_entry_for_path(env, path)) {
        return Some(content);
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return content_from_entry(filesystem_entry_for_path(env, stripped));
        }
    }
    if let Some(name) = current_dir_basename(path) {
        return tracked_script_content_by_basename(name, env);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
    tracked_script_content_by_basename(path, env)
}

fn tracked_script_content_by_basename(path: &str, env: &Environment) -> Option<Vec<u8>> {
    for (tracked_path, entry) in &env.modified_filesystem {
        let Some(name) = windows_basename(tracked_path) else {
            continue;
        };
        if name.eq_ignore_ascii_case(path) {
            return content_from_entry(Some(entry));
        }
    }
    None
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn content_from_entry(entry: Option<&FsEntry>) -> Option<Vec<u8>> {
    match entry {
        Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
            Some(content.clone())
        }
        _ => None,
    }
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
}

fn normalize_remote_path(path: &str) -> String {
    path.trim_matches(['"', '\''])
        .trim_matches('/')
        .replace('\\', "/")
}

fn normalize_local_path(path: &str) -> String {
    path.trim_matches(['"', '\''])
        .trim_end_matches(['\\', '/'])
        .to_string()
}

fn join_local_path(lcd: &str, local: &str) -> String {
    let local = local.trim_matches(['"', '\'']);
    if lcd.is_empty() || is_windows_rooted_path(local) {
        local.to_string()
    } else {
        join_windows_path_preserving_separator(lcd, local)
    }
}

fn is_windows_rooted_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['\\', '/'])
        || bytes
            .get(0..2)
            .is_some_and(|head| head[0].is_ascii_alphabetic() && head[1] == b':')
}

fn join_remote_path(cwd: &str, remote: &str) -> String {
    let remote = normalize_remote_path(remote);
    if remote.starts_with('/') || cwd.is_empty() {
        remote
    } else {
        format!("{cwd}/{remote}")
    }
}

fn remote_basename(path: &str) -> Option<String> {
    path.rsplit('/')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn ftp_url(host: &str, port: u16, remote: &str) -> String {
    let remote = normalize_remote_path(remote);
    if port == 21 {
        format!("ftp://{host}/{remote}")
    } else {
        format!("ftp://{host}:{port}/{remote}")
    }
}

fn push_remote_connect(raw: &str, host: &str, port: u16, env: &mut Environment) {
    if !env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::RemoteConnect {
                cmd,
                host: existing_host,
                port: existing_port
            } if cmd == raw && existing_host == host && *existing_port == port
        )
    }) {
        env.traits.push(Trait::RemoteConnect {
            cmd: raw.to_string(),
            host: host.to_string(),
            port,
        });
    }
}
