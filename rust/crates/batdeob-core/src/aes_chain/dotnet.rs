//! Walk PE -> CLI header -> metadata root -> `#US` heap and yield every
//! user-string literal. Used by Plan T-lite to surface the second-stage
//! AES Key/IV that the AES-CBC dropper family hides inside the loader
//! assembly.

use thiserror::Error;

const MAX_US_HEAP: usize = 4 * 1024 * 1024;
const MAX_STRINGS: usize = 256;
const MAX_STRING_BYTES: usize = 8 * 1024;
/// Realistic PE files have ~10 sections; benign images stay under 96.
/// A malicious header could advertise 65535 sections to force expensive
/// walking — cap defensively.
const MAX_SECTIONS: usize = 96;
const MAX_STREAMS: usize = 16;

#[derive(Debug, Error)]
pub enum DotnetError {
    #[error("not a PE")]
    NotPe,
    #[error("not a CLR assembly")]
    NotClr,
    #[error("bounds")]
    Bounds,
    #[error("heap too large: {0}")]
    HeapTooLarge(usize),
}

fn rd_u16(b: &[u8], off: usize) -> Result<u16, DotnetError> {
    let end = off.checked_add(2).ok_or(DotnetError::Bounds)?;
    b.get(off..end)
        .ok_or(DotnetError::Bounds)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd_u32(b: &[u8], off: usize) -> Result<u32, DotnetError> {
    let end = off.checked_add(4).ok_or(DotnetError::Bounds)?;
    b.get(off..end)
        .ok_or(DotnetError::Bounds)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn add_off(off: usize, delta: usize) -> Result<usize, DotnetError> {
    off.checked_add(delta).ok_or(DotnetError::Bounds)
}

struct Section {
    rva: u32,
    size: u32,
    raw_off: u32,
}

fn parse_sections(
    bytes: &[u8],
    pe_off: usize,
    num: usize,
    opt_hdr_size: usize,
) -> Result<Vec<Section>, DotnetError> {
    if num > MAX_SECTIONS {
        return Err(DotnetError::Bounds);
    }
    let table_off = pe_off
        .checked_add(24)
        .and_then(|x| x.checked_add(opt_hdr_size))
        .ok_or(DotnetError::Bounds)?;
    let mut out = Vec::with_capacity(num);
    for i in 0..num {
        let entry = table_off
            .checked_add(i.checked_mul(40).ok_or(DotnetError::Bounds)?)
            .ok_or(DotnetError::Bounds)?;
        let entry_end = entry.checked_add(40).ok_or(DotnetError::Bounds)?;
        if entry_end > bytes.len() {
            return Err(DotnetError::Bounds);
        }
        let virt_size = rd_u32(bytes, entry + 8)?;
        let rva = rd_u32(bytes, entry + 12)?;
        let raw_size = rd_u32(bytes, entry + 16)?;
        let raw_off = rd_u32(bytes, entry + 20)?;
        out.push(Section {
            rva,
            size: virt_size.max(raw_size),
            raw_off,
        });
    }
    Ok(out)
}

fn rva_to_offset(rva: u32, sections: &[Section]) -> Option<usize> {
    for s in sections {
        if s.rva <= rva && rva < s.rva.checked_add(s.size)? {
            let delta = (rva - s.rva) as usize;
            return (s.raw_off as usize).checked_add(delta);
        }
    }
    None
}

/// Compressed unsigned int (.NET metadata format). Returns (value, bytes_consumed).
fn read_compressed_uint(bytes: &[u8], pos: usize) -> Option<(u32, usize)> {
    let b0 = *bytes.get(pos)? as u32;
    if (b0 & 0x80) == 0 {
        Some((b0, 1))
    } else if (b0 & 0xc0) == 0x80 {
        let b1 = *bytes.get(pos.checked_add(1)?)? as u32;
        Some((((b0 & 0x3f) << 8) | b1, 2))
    } else if (b0 & 0xe0) == 0xc0 {
        let b1 = *bytes.get(pos.checked_add(1)?)? as u32;
        let b2 = *bytes.get(pos.checked_add(2)?)? as u32;
        let b3 = *bytes.get(pos.checked_add(3)?)? as u32;
        Some((((b0 & 0x1f) << 24) | (b1 << 16) | (b2 << 8) | b3, 4))
    } else {
        None
    }
}

/// Extract every user-string in the `#US` heap as a Rust `String`.
pub fn extract_us_strings(bytes: &[u8]) -> Result<Vec<String>, DotnetError> {
    // ---- PE header ----
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Err(DotnetError::NotPe);
    }
    let pe_off = rd_u32(bytes, 0x3c)? as usize;
    let pe_end = add_off(pe_off, 4)?;
    if bytes.get(pe_off..pe_end) != Some(b"PE\0\0") {
        return Err(DotnetError::NotPe);
    }
    let coff_off = pe_end;
    let num_sections = rd_u16(bytes, add_off(coff_off, 2)?)? as usize;
    let opt_hdr_size = rd_u16(bytes, add_off(coff_off, 16)?)? as usize;
    let opt_off = add_off(coff_off, 20)?;
    let magic = rd_u16(bytes, opt_off)?;
    let data_dir_off = match magic {
        0x10b => add_off(opt_off, 96)?,  // PE32
        0x20b => add_off(opt_off, 112)?, // PE32+
        _ => return Err(DotnetError::NotPe),
    };
    // CLI header = DataDir[14]
    let cli_dir_off = add_off(data_dir_off, 14 * 8)?;
    let cli_rva = rd_u32(bytes, cli_dir_off)?;
    let cli_size = rd_u32(bytes, add_off(cli_dir_off, 4)?)?;
    if cli_rva == 0 || cli_size == 0 {
        return Err(DotnetError::NotClr);
    }

    let sections = parse_sections(bytes, pe_off, num_sections, opt_hdr_size)?;
    let cli_off = rva_to_offset(cli_rva, &sections).ok_or(DotnetError::Bounds)?;

    // CLI header: cb (4) | major (2) | minor (2) | metadata_rva (4) | metadata_size (4) | ...
    let metadata_rva = rd_u32(bytes, add_off(cli_off, 8)?)?;
    let metadata_size = rd_u32(bytes, add_off(cli_off, 12)?)? as usize;
    let metadata_off = rva_to_offset(metadata_rva, &sections).ok_or(DotnetError::Bounds)?;
    let metadata_sig_end = add_off(metadata_off, 4)?;
    if bytes.get(metadata_off..metadata_sig_end) != Some(b"BSJB") {
        return Err(DotnetError::NotClr);
    }
    let metadata_end = metadata_off
        .checked_add(metadata_size)
        .ok_or(DotnetError::Bounds)?;
    if metadata_end > bytes.len() {
        return Err(DotnetError::Bounds);
    }

    // After BSJB(4) + major(2) + minor(2) + reserved(4) + version_len(4) + version_str (padded to 4)
    let version_len = rd_u32(bytes, add_off(metadata_off, 12)?)? as usize;
    let pad_aligned = version_len.checked_add(3).ok_or(DotnetError::Bounds)? & !3;
    let after_ver = metadata_off
        .checked_add(16)
        .and_then(|x| x.checked_add(pad_aligned))
        .ok_or(DotnetError::Bounds)?;
    let stream_headers_start = add_off(after_ver, 4)?;
    if stream_headers_start > bytes.len() {
        return Err(DotnetError::Bounds);
    }
    let streams_count = rd_u16(bytes, add_off(after_ver, 2)?)? as usize;
    if streams_count > MAX_STREAMS {
        return Err(DotnetError::Bounds);
    }
    let mut stream_hdr_off = stream_headers_start;

    let mut us_offset: Option<usize> = None;
    let mut us_size: usize = 0;
    for _ in 0..streams_count {
        let hdr_end = stream_hdr_off.checked_add(8).ok_or(DotnetError::Bounds)?;
        if hdr_end > bytes.len() {
            return Err(DotnetError::Bounds);
        }
        let off = rd_u32(bytes, stream_hdr_off)? as usize;
        let size = rd_u32(bytes, add_off(stream_hdr_off, 4)?)? as usize;
        // null-terminated name, padded to 4-byte boundary
        let name_start = hdr_end;
        let mut name_end = name_start;
        while name_end < metadata_end && bytes.get(name_end).copied() != Some(0) {
            name_end += 1;
        }
        if name_end >= metadata_end {
            return Err(DotnetError::Bounds);
        }
        let name = std::str::from_utf8(bytes.get(name_start..name_end).ok_or(DotnetError::Bounds)?)
            .map_err(|_| DotnetError::Bounds)?;
        if name == "#US" {
            us_offset = Some(metadata_off.checked_add(off).ok_or(DotnetError::Bounds)?);
            us_size = size;
        }
        let consumed = name_end
            .checked_add(1)
            .ok_or(DotnetError::Bounds)?
            .checked_sub(stream_hdr_off)
            .ok_or(DotnetError::Bounds)?;
        let aligned = consumed.checked_add(3).ok_or(DotnetError::Bounds)? & !3;
        stream_hdr_off = stream_hdr_off
            .checked_add(aligned)
            .ok_or(DotnetError::Bounds)?;
    }
    let us_offset = us_offset.ok_or(DotnetError::NotClr)?;
    if us_size > MAX_US_HEAP {
        return Err(DotnetError::HeapTooLarge(us_size));
    }
    let us_end = us_offset.checked_add(us_size).ok_or(DotnetError::Bounds)?;
    if us_end > bytes.len() {
        return Err(DotnetError::Bounds);
    }
    let us = bytes.get(us_offset..us_end).ok_or(DotnetError::Bounds)?;

    // ---- Walk the heap: each entry is compressed-uint len + len bytes
    //      (UTF-16LE + 1-byte ASCII flag at end). Entry 0 is empty. ----
    let mut out = Vec::new();
    let mut pos = 1usize; // skip the leading zero byte (entry 0 = empty)
    while pos < us.len() && out.len() < MAX_STRINGS {
        let (len, consumed) = match read_compressed_uint(us, pos) {
            Some(v) => v,
            None => break,
        };
        let len = len as usize;
        if len == 0 || consumed == 0 {
            break;
        }
        let body_start = match pos.checked_add(consumed) {
            Some(v) => v,
            None => break,
        };
        let entry_end = match body_start.checked_add(len) {
            Some(v) => v,
            None => break,
        };
        if entry_end > us.len() {
            break;
        }
        if (1..=MAX_STRING_BYTES).contains(&len) {
            // len includes the trailing flag byte
            let body_end = entry_end - 1;
            if let Some(body) = us.get(body_start..body_end) {
                // UTF-16LE
                let u16s: Vec<u16> = body
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&u16s);
                if !s.is_empty() {
                    out.push(s);
                }
            }
        }
        pos = entry_end;
    }
    Ok(out)
}

/// Find paired base64-encoded AES Key (32 chars body = 24 b64 chars... no
/// wait — 32 bytes = 44 base64 chars with padding) and IV (16 bytes = 24
/// base64 chars). Returns each (key_b64, iv_b64) pair in source order.
pub fn find_nested_aes_pairs(strings: &[String]) -> Vec<(String, String)> {
    use base64::Engine;
    let mut out = Vec::new();
    // First pass: classify each string as key32 | iv16 | neither.
    #[derive(Copy, Clone, Debug, PartialEq)]
    enum Tag {
        Key,
        Iv,
        Other,
    }
    let tags: Vec<(Tag, &String)> = strings
        .iter()
        .map(|s| {
            let bytes_opt = base64::engine::general_purpose::STANDARD.decode(s).ok();
            match bytes_opt {
                Some(b) if b.len() == 32 => (Tag::Key, s),
                Some(b) if b.len() == 16 => (Tag::Iv, s),
                _ => (Tag::Other, s),
            }
        })
        .collect();
    // Pair: look for Key immediately followed by Iv (with up to 3 Others between).
    let mut i = 0;
    while i < tags.len() {
        if tags[i].0 != Tag::Key {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let max_j = (i + 4).min(tags.len());
        while j < max_j {
            if tags[j].0 == Tag::Iv {
                out.push((tags[i].1.clone(), tags[j].1.clone()));
                i = j + 1;
                break;
            }
            j += 1;
        }
        if j >= max_j {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn not_pe_rejected() {
        let bytes = b"not a PE";
        assert!(matches!(extract_us_strings(bytes), Err(DotnetError::NotPe)));
    }

    #[test]
    fn empty_input_rejected() {
        assert!(matches!(extract_us_strings(&[]), Err(DotnetError::NotPe)));
    }

    #[test]
    fn truncated_mz_header_rejected_without_panic() {
        // Just `MZ` with no further bytes — early bounds check must trip.
        let bytes = b"MZ\x90\x00";
        let r = extract_us_strings(bytes);
        assert!(r.is_err(), "expected Err, got {:?}", r);
    }

    #[test]
    fn pe_with_oob_e_lfanew_returns_bounds() {
        // PE header at advertised offset 0xFFFFFFFF (way past file end).
        // Should return Bounds / NotPe, never panic.
        let mut bytes = vec![0u8; 0x80];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let r = extract_us_strings(&bytes);
        assert!(r.is_err(), "expected Err, got {:?}", r);
    }

    #[test]
    fn read_compressed_uint_truncated_returns_none() {
        // 0x80-flagged byte requires a follower; if it's missing, the
        // function must return None rather than panicking.
        assert_eq!(read_compressed_uint(&[0x80], 0), None);
        assert_eq!(read_compressed_uint(&[0xc0, 0x00], 0), None);
    }

    #[test]
    fn read_compressed_uint_one_byte() {
        assert_eq!(read_compressed_uint(&[0x42], 0), Some((0x42, 1)));
    }
    #[test]
    fn read_compressed_uint_two_byte() {
        assert_eq!(
            read_compressed_uint(&[0x80 | 0x12, 0x34], 0),
            Some((0x1234, 2))
        );
    }
    #[test]
    fn read_compressed_uint_four_byte() {
        assert_eq!(
            read_compressed_uint(&[0xc0 | 0x01, 0x23, 0x45, 0x67], 0),
            Some((0x01234567, 4))
        );
    }

    #[test]
    fn nested_aes_pairs_simple() {
        // Make a fake 32-byte key + 16-byte iv pair.
        let key_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let strings = vec![
            "junk".to_string(),
            key_b64.clone(),
            iv_b64.clone(),
            "more junk".to_string(),
        ];
        let pairs = find_nested_aes_pairs(&strings);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, key_b64);
        assert_eq!(pairs[0].1, iv_b64);
    }

    #[test]
    fn nested_aes_pairs_with_intervening_strings() {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode([2u8; 16]);
        let strings = vec![
            key_b64.clone(),
            "small".to_string(),
            "tiny".to_string(),
            iv_b64.clone(),
        ];
        let pairs = find_nested_aes_pairs(&strings);
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn nested_aes_pairs_too_far_apart_skipped() {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode([2u8; 16]);
        let strings = vec![
            key_b64,
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(), // 5 between
            iv_b64,
        ];
        let pairs = find_nested_aes_pairs(&strings);
        assert!(pairs.is_empty());
    }
}
