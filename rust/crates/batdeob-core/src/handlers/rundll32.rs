use crate::env::{Environment, FsEntry};
use crate::handlers::util::{split_words, strip_outer_quotes};
use crate::traits::Trait;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    let parts = split_words(raw);
    if parts.len() < 2 {
        return;
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
