//! Pre-pass over logical lines to build a label -> line-index map.
//! Lowercased keys; key has no leading colon.

use std::collections::HashMap;

pub fn build_label_index(lines: &[String]) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with(':') {
            continue;
        }
        let rest = &trimmed[1..];
        if let Some(c) = rest.chars().next() {
            // `::` is a comment (per cmd.exe). Any punctuation right after the
            // colon means "comment", not "label".
            if c == ':' || (c.is_ascii_punctuation() && c != '_') {
                continue;
            }
        } else {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if !name.is_empty() {
            out.entry(name).or_insert(i);
        }
    }
    out
}
