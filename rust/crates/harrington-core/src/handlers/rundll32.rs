use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let dll = parts[1].split(',').next().unwrap_or("");
    let url = match env.modified_filesystem.get(&dll.to_ascii_lowercase()) {
        Some(FsEntry::Download { src }) => Some(src.clone()),
        _ => None,
    };
    env.traits.push(Trait::Rundll32 {
        cmd: raw.to_string(),
        url,
    });
}
