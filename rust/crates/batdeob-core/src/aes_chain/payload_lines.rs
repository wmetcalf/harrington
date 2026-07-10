//! Collect `:::N*` and `:: ` payload lines from the raw .bat input.
//!
//! Both formats co-occur in the same sample (`:::N` is the multi-stage
//! loader payload; `:: ` is the single-line AES ciphertext envelope).

const MAX_TOTAL: usize = 2 * 1024 * 1024;
const MAX_COLON_N_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadLines<'a> {
    /// Lines matching `:::<N><content>` keyed by N (sorted ascending).
    /// `content` is the byte slice after the `:::N` prefix.
    pub colon_n: Vec<(u32, &'a [u8])>,
    /// First line matching `:: <content>`. `content` is bytes after the
    /// three-character prefix.
    pub colon_space: Option<&'a [u8]>,
}

pub fn collect(raw: &[u8]) -> PayloadLines<'_> {
    let mut colon_n: Vec<(u32, &[u8])> = Vec::new();
    let mut colon_space: Option<&[u8]> = None;
    let mut total = 0usize;

    for line in raw.split(|&b| b == b'\n') {
        let line = strip_trailing_cr(line);
        if line.len() < 3 {
            continue;
        }
        if line[0] != b':' || line[1] != b':' {
            continue;
        }

        // Case A: `:: <content>` — first match wins.
        if line[2] == b' ' && colon_space.is_none() {
            let content = &line[3..];
            if total + content.len() > MAX_TOTAL {
                break;
            }
            total += content.len();
            colon_space = Some(content);
            continue;
        }

        // Case B: `:::<digits><content>`
        if line[2] == b':' && line.len() >= 4 && line[3].is_ascii_digit() {
            // Parse the run of digits after `:::`.
            let mut end = 3usize;
            while end < line.len() && line[end].is_ascii_digit() {
                end += 1;
                if end - 3 > 10 {
                    break;
                } // cap at u32 width
            }
            let digits = &line[3..end];
            if let Ok(s) = std::str::from_utf8(digits) {
                if let Ok(n) = s.parse::<u32>() {
                    let content = &line[end..];
                    if colon_n.len() >= MAX_COLON_N_ENTRIES {
                        break;
                    }
                    if total + content.len() > MAX_TOTAL {
                        break;
                    }
                    total += content.len();
                    colon_n.push((n, content));
                }
            }
        }
    }

    colon_n.sort_by_key(|&(n, _)| n);
    PayloadLines {
        colon_n,
        colon_space,
    }
}

fn strip_trailing_cr(line: &[u8]) -> &[u8] {
    if let Some((&b'\r', rest)) = line.split_last() {
        rest
    } else {
        line
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn collects_colon_n_lines_in_order() {
        let raw = b":::2second\r\n:::1first\r\n:::3third\r\n";
        let p = collect(raw);
        assert_eq!(p.colon_n.len(), 3);
        assert_eq!(p.colon_n[0].0, 1);
        assert_eq!(p.colon_n[0].1, b"first");
        assert_eq!(p.colon_n[1].0, 2);
        assert_eq!(p.colon_n[2].0, 3);
        assert!(p.colon_space.is_none());
    }

    #[test]
    fn collects_first_colon_space_line_only() {
        let raw = b":: first_payload\r\n:: should_be_ignored\r\n";
        let p = collect(raw);
        assert_eq!(p.colon_space, Some(b"first_payload".as_slice()));
    }

    #[test]
    fn distinguishes_colon_space_from_colon_n() {
        let raw = b":: aaa\r\n:::1 bbb\r\n";
        let p = collect(raw);
        assert_eq!(p.colon_space, Some(b"aaa".as_slice()));
        assert_eq!(p.colon_n.len(), 1);
        assert_eq!(p.colon_n[0].0, 1);
        assert_eq!(p.colon_n[0].1, b" bbb");
    }

    #[test]
    fn ignores_lines_not_starting_with_double_colon() {
        let raw = b"echo off\r\nset x=1\r\n@cls\r\n:: payload";
        let p = collect(raw);
        assert_eq!(p.colon_space, Some(b"payload".as_slice()));
    }

    #[test]
    fn caps_total_bytes() {
        let mut raw = Vec::new();
        for i in 0..200 {
            raw.extend_from_slice(format!(":::{i}").as_bytes());
            raw.extend(std::iter::repeat(b'A').take(20_000));
            raw.push(b'\n');
        }
        let p = collect(&raw);
        let total: usize = p.colon_n.iter().map(|(_, s)| s.len()).sum();
        assert!(total <= MAX_TOTAL, "total {} exceeds cap", total);
    }

    #[test]
    fn caps_empty_colon_n_entry_count() {
        let mut raw = Vec::new();
        for i in 0..10_000 {
            raw.extend_from_slice(format!(":::{i}\n").as_bytes());
        }

        let p = collect(&raw);

        assert_eq!(p.colon_n.len(), MAX_COLON_N_ENTRIES);
    }
}
