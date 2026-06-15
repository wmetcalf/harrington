//! ftp.exe handler - scans tracked `-s:script` command files.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, strip_outer_quotes};
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
        env.traits.push(Trait::Download {
            cmd: raw.to_string(),
            src: ftp_url(&parsed.host, parsed.port, &transfer.remote),
            dst: Some(transfer.local),
        });
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
                downloads.push(FtpDownload { remote, local });
            }
            _ => {}
        }
    }

    let host = host?;
    (!downloads.is_empty()).then_some(FtpScript {
        host,
        port,
        downloads,
    })
}

fn tracked_script_content(path: &str, env: &Environment) -> Option<Vec<u8>> {
    let key = path.to_ascii_lowercase();
    if let Some(content) = content_from_entry(env.modified_filesystem.get(&key)) {
        return Some(content);
    }
    if path.contains(['\\', '/']) {
        return None;
    }
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
