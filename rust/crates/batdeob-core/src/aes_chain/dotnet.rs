//! Walk PE -> CLI header -> metadata root -> `#US` heap and yield every
//! user-string literal. Used by Plan T-lite to surface the second-stage
//! AES Key/IV that the AES-CBC dropper family hides inside the loader
//! assembly.

use thiserror::Error;

const MAX_US_HEAP: usize = 4 * 1024 * 1024;
const MAX_STRINGS: usize = 256;
const MAX_STRING_BYTES: usize = 8 * 1024;
const MAX_STRIDE_RC4_FIELDS: usize = 64;
const MAX_STRIDE_RC4_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_STRIDE_RC4_ATTEMPTS: usize = 1024;
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
fn rd_u64(b: &[u8], off: usize) -> Result<u64, DotnetError> {
    let end = off.checked_add(8).ok_or(DotnetError::Bounds)?;
    b.get(off..end)
        .ok_or(DotnetError::Bounds)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

fn add_off(off: usize, delta: usize) -> Result<usize, DotnetError> {
    off.checked_add(delta).ok_or(DotnetError::Bounds)
}

struct Section {
    rva: u32,
    size: u32,
    raw_off: u32,
}

struct MetadataStream {
    name: String,
    offset: usize,
    size: usize,
}

impl MetadataStream {
    fn end(&self) -> usize {
        self.offset.saturating_add(self.size)
    }
}

struct DotnetLayout {
    sections: Vec<Section>,
    streams: Vec<MetadataStream>,
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

fn parse_dotnet_layout(bytes: &[u8]) -> Result<DotnetLayout, DotnetError> {
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
        0x10b => add_off(opt_off, 96)?,
        0x20b => add_off(opt_off, 112)?,
        _ => return Err(DotnetError::NotPe),
    };
    let cli_dir = add_off(data_dir_off, 14 * 8)?;
    let cli_rva = rd_u32(bytes, cli_dir)?;
    let cli_size = rd_u32(bytes, add_off(cli_dir, 4)?)?;
    if cli_rva == 0 || cli_size == 0 {
        return Err(DotnetError::NotClr);
    }

    let sections = parse_sections(bytes, pe_off, num_sections, opt_hdr_size)?;
    let cli_off = rva_to_offset(cli_rva, &sections).ok_or(DotnetError::Bounds)?;
    let metadata_rva = rd_u32(bytes, add_off(cli_off, 8)?)?;
    let metadata_size = rd_u32(bytes, add_off(cli_off, 12)?)? as usize;
    let metadata_off = rva_to_offset(metadata_rva, &sections).ok_or(DotnetError::Bounds)?;
    let metadata_end = metadata_off
        .checked_add(metadata_size)
        .ok_or(DotnetError::Bounds)?;
    if metadata_end > bytes.len()
        || bytes.get(metadata_off..add_off(metadata_off, 4)?) != Some(b"BSJB")
    {
        return Err(DotnetError::NotClr);
    }

    let version_len = rd_u32(bytes, add_off(metadata_off, 12)?)? as usize;
    let pad_aligned = version_len.checked_add(3).ok_or(DotnetError::Bounds)? & !3;
    let after_ver = metadata_off
        .checked_add(16)
        .and_then(|x| x.checked_add(pad_aligned))
        .ok_or(DotnetError::Bounds)?;
    if add_off(after_ver, 4)? > bytes.len() {
        return Err(DotnetError::Bounds);
    }
    let streams_count = rd_u16(bytes, add_off(after_ver, 2)?)? as usize;
    if streams_count > MAX_STREAMS {
        return Err(DotnetError::Bounds);
    }

    let mut streams = Vec::new();
    let mut stream_hdr_off = after_ver + 4;
    for _ in 0..streams_count {
        let hdr_end = add_off(stream_hdr_off, 8)?;
        if hdr_end > bytes.len() {
            return Err(DotnetError::Bounds);
        }
        let rel_off = rd_u32(bytes, stream_hdr_off)? as usize;
        let size = rd_u32(bytes, add_off(stream_hdr_off, 4)?)? as usize;
        let name_start = hdr_end;
        let mut name_end = name_start;
        while name_end < metadata_end && bytes.get(name_end).copied() != Some(0) {
            name_end += 1;
        }
        if name_end >= metadata_end {
            return Err(DotnetError::Bounds);
        }
        let name = std::str::from_utf8(bytes.get(name_start..name_end).ok_or(DotnetError::Bounds)?)
            .map_err(|_| DotnetError::Bounds)?
            .to_string();
        let offset = metadata_off
            .checked_add(rel_off)
            .ok_or(DotnetError::Bounds)?;
        let end = offset.checked_add(size).ok_or(DotnetError::Bounds)?;
        if end > metadata_end {
            return Err(DotnetError::Bounds);
        }
        streams.push(MetadataStream { name, offset, size });

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

    Ok(DotnetLayout { sections, streams })
}

fn table_index_size(rows: u32) -> usize {
    if rows < 0x10000 {
        2
    } else {
        4
    }
}

fn coded_index_size(row_counts: &[u32; 64], tag_bits: u8, tables: &[usize]) -> usize {
    let max_rows = tables
        .iter()
        .map(|table| row_counts.get(*table).copied().unwrap_or(0))
        .max()
        .unwrap_or(0);
    if max_rows < (1u32 << (16 - tag_bits)) {
        2
    } else {
        4
    }
}

fn table_row_size(
    table_id: usize,
    row_counts: &[u32; 64],
    heap_sizes: u8,
) -> Result<usize, DotnetError> {
    let string = if (heap_sizes & 0x01) != 0 { 4 } else { 2 };
    let guid = if (heap_sizes & 0x02) != 0 { 4 } else { 2 };
    let blob = if (heap_sizes & 0x04) != 0 { 4 } else { 2 };
    let field = table_index_size(row_counts[0x04]);
    let method = table_index_size(row_counts[0x06]);
    let param = table_index_size(row_counts[0x08]);
    let typedef = table_index_size(row_counts[0x02]);
    let event = table_index_size(row_counts[0x14]);
    let property = table_index_size(row_counts[0x17]);
    let moduleref = table_index_size(row_counts[0x1a]);
    let resolution_scope = coded_index_size(row_counts, 2, &[0x00, 0x1a, 0x23, 0x01]);
    let typedef_or_ref = coded_index_size(row_counts, 2, &[0x02, 0x01, 0x1b]);
    let has_constant = coded_index_size(row_counts, 2, &[0x04, 0x08, 0x17]);
    let has_custom_attribute = coded_index_size(
        row_counts,
        5,
        &[
            0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b,
            0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c,
        ],
    );
    let custom_attribute_type = coded_index_size(row_counts, 3, &[0x06, 0x0a]);
    let has_decl_security = coded_index_size(row_counts, 2, &[0x02, 0x06, 0x20]);
    let member_ref_parent = coded_index_size(row_counts, 3, &[0x02, 0x01, 0x1a, 0x06, 0x1b]);
    let has_semantics = coded_index_size(row_counts, 1, &[0x14, 0x17]);
    let member_forwarded = coded_index_size(row_counts, 1, &[0x04, 0x06]);

    let size = match table_id {
        0x00 => 2 + string + guid + guid + guid,
        0x01 => resolution_scope + string + string,
        0x02 => 4 + string + string + typedef_or_ref + field + method,
        0x04 => 2 + string + blob,
        0x06 => 4 + 2 + 2 + string + blob + param,
        0x08 => 2 + 2 + string,
        0x09 => typedef + typedef_or_ref,
        0x0a => member_ref_parent + string + blob,
        0x0b => 2 + has_constant + blob,
        0x0c => has_custom_attribute + custom_attribute_type + blob,
        0x0e => 2 + has_decl_security + blob,
        0x0f => 2 + 4 + typedef,
        0x11 => blob,
        0x12 => typedef + event,
        0x14 => 2 + string + typedef_or_ref,
        0x15 => typedef + property,
        0x17 => 2 + string + blob,
        0x18 => 2 + method + has_semantics,
        0x1a => string,
        0x1b => blob,
        0x1c => 2 + member_forwarded + string + moduleref,
        0x1d => 4 + field,
        id if row_counts[id] == 0 => 0,
        _ => return Err(DotnetError::Bounds),
    };
    Ok(size)
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn rc4_crypt(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return Vec::new();
    }
    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut j = 0u8;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    let mut i = 0u8;
    j = 0;
    let mut out = Vec::with_capacity(bytes.len());
    for byte in bytes {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
        out.push(byte ^ k);
    }
    out
}

fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || bytes.get(0..2) != Some(b"MZ") {
        return false;
    }
    let Some(pe_off_bytes) = bytes.get(0x3c..0x40) else {
        return false;
    };
    let pe_off = u32::from_le_bytes([
        pe_off_bytes[0],
        pe_off_bytes[1],
        pe_off_bytes[2],
        pe_off_bytes[3],
    ]) as usize;
    pe_off.checked_add(4).and_then(|end| bytes.get(pe_off..end)) == Some(b"PE\0\0".as_slice())
}

pub(crate) fn recover_stride_rc4_pes_until(
    bytes: &[u8],
    deadline: Option<std::time::Instant>,
) -> Result<Vec<Vec<u8>>, DotnetError> {
    let fields = extract_field_rva_blobs(bytes)?;
    Ok(recover_stride_rc4_pes_from_static_blobs_until(
        &fields, deadline,
    ))
}

#[cfg(test)]
fn recover_stride_rc4_pes_from_static_blobs(fields: &[Vec<u8>]) -> Vec<Vec<u8>> {
    recover_stride_rc4_pes_from_static_blobs_until(fields, None)
}

fn recover_stride_rc4_pes_from_static_blobs_until(
    fields: &[Vec<u8>],
    deadline: Option<std::time::Instant>,
) -> Vec<Vec<u8>> {
    let large_fields = fields
        .iter()
        .filter(|field| field.len() >= 32 * 1024 && field.len() <= MAX_STRIDE_RC4_OUTPUT * 8);
    let key_fields: Vec<&[u8]> = fields
        .iter()
        .filter(|field| field.len() >= 32)
        .map(|field| &field[..32])
        .collect();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut attempts = 0usize;

    for large in large_fields {
        let sampled: Vec<u8> = large.iter().step_by(5).copied().collect();
        if sampled.len() < 0x84 || sampled.len() > MAX_STRIDE_RC4_OUTPUT {
            continue;
        }
        for key_field in &key_fields {
            for mask in 0u8..=u8::MAX {
                if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                    return out;
                }
                if attempts >= MAX_STRIDE_RC4_ATTEMPTS {
                    return out;
                }
                attempts += 1;
                let key_material: Vec<u8> = key_field.iter().map(|b| b ^ mask).collect();
                let key = sha256(&key_material);
                let decrypted = rc4_crypt(&sampled, &key);
                if looks_like_pe(&decrypted) && !out.iter().any(|existing| existing == &decrypted) {
                    out.push(decrypted);
                }
            }
        }
    }

    out
}

fn extract_field_rva_blobs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, DotnetError> {
    let layout = parse_dotnet_layout(bytes)?;
    let tables_stream = layout
        .streams
        .iter()
        .find(|stream| stream.name == "#~" || stream.name == "#-")
        .ok_or(DotnetError::NotClr)?;
    let tables = bytes
        .get(tables_stream.offset..tables_stream.end())
        .ok_or(DotnetError::Bounds)?;
    if tables.len() < 24 {
        return Err(DotnetError::Bounds);
    }
    let heap_sizes = *tables.get(6).ok_or(DotnetError::Bounds)?;
    let valid = rd_u64(tables, 8)?;
    let mut row_counts = [0u32; 64];
    let mut pos = 24usize;
    for (table_id, count) in row_counts.iter_mut().enumerate() {
        if (valid & (1u64 << table_id)) != 0 {
            *count = rd_u32(tables, pos)?;
            pos = pos.checked_add(4).ok_or(DotnetError::Bounds)?;
        }
    }
    let rows_start = pos;
    let mut table_offsets = [None; 64];
    for table_id in 0..=0x1dusize {
        if row_counts[table_id] == 0 {
            continue;
        }
        table_offsets[table_id] = Some(pos);
        let row_size = table_row_size(table_id, &row_counts, heap_sizes)?;
        let table_size = row_size
            .checked_mul(row_counts[table_id] as usize)
            .ok_or(DotnetError::Bounds)?;
        pos = pos.checked_add(table_size).ok_or(DotnetError::Bounds)?;
    }
    if rows_start > tables.len() || pos > tables.len() {
        return Err(DotnetError::Bounds);
    }

    let Some(field_rva_off) = table_offsets[0x1d] else {
        return Ok(Vec::new());
    };
    let field_index_size = table_index_size(row_counts[0x04]);
    let row_size = 4usize
        .checked_add(field_index_size)
        .ok_or(DotnetError::Bounds)?;
    let mut offsets = Vec::new();
    for row in 0..(row_counts[0x1d] as usize).min(MAX_STRIDE_RC4_FIELDS) {
        let row_off = field_rva_off
            .checked_add(row.checked_mul(row_size).ok_or(DotnetError::Bounds)?)
            .ok_or(DotnetError::Bounds)?;
        let rva = rd_u32(tables, row_off)?;
        if let Some(file_off) = rva_to_offset(rva, &layout.sections) {
            if file_off < bytes.len() {
                offsets.push(file_off);
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();

    let mut fields = Vec::new();
    for (idx, off) in offsets.iter().copied().enumerate() {
        let end = offsets
            .get(idx + 1)
            .copied()
            .unwrap_or(bytes.len())
            .min(bytes.len());
        if off < end {
            fields.push(bytes[off..end].to_vec());
        }
    }
    Ok(fields)
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

    #[test]
    fn stride_rc4_static_blobs_recover_inner_pe() {
        let key_xor = 0x4au8;
        let key_plain = [0x33u8; 32];
        let key_blob: Vec<u8> = key_plain.iter().map(|b| b ^ key_xor).collect();
        let mut inner = vec![0u8; 0x90];
        inner[0..2].copy_from_slice(b"MZ");
        inner[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        inner[0x80..0x84].copy_from_slice(b"PE\0\0");
        inner.resize(0x9000, 0);
        inner.extend_from_slice(b"https://inner-static-rc4.example/payload");

        let key = sha256(&key_plain);
        let encrypted = rc4_crypt(&inner, &key);
        let mut large_blob = Vec::with_capacity(encrypted.len() * 5);
        for byte in encrypted {
            large_blob.extend_from_slice(&[byte, 0xaa, 0xbb, 0xcc, 0xdd]);
        }

        let fields = vec![key_blob, large_blob];
        let recovered = recover_stride_rc4_pes_from_static_blobs(&fields);

        assert_eq!(recovered, vec![inner]);
    }

    #[test]
    fn stride_rc4_static_blob_recovery_has_work_budget() {
        let key_xor = 0x4au8;
        let key_plain = [0x33u8; 32];
        let key_blob: Vec<u8> = key_plain.iter().map(|b| b ^ key_xor).collect();
        let mut inner = vec![0u8; 0x90];
        inner[0..2].copy_from_slice(b"MZ");
        inner[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        inner[0x80..0x84].copy_from_slice(b"PE\0\0");
        inner.resize(0x9000, 0);

        let key = sha256(&key_plain);
        let encrypted = rc4_crypt(&inner, &key);
        let mut large_blob = Vec::with_capacity(encrypted.len() * 5);
        for byte in encrypted {
            large_blob.extend_from_slice(&[byte, 0xaa, 0xbb, 0xcc, 0xdd]);
        }

        let mut fields = vec![large_blob];
        for marker in 0..4u8 {
            fields.push((0..32u8).map(|idx| marker.wrapping_add(idx)).collect());
        }
        fields.push(key_blob);

        let recovered = recover_stride_rc4_pes_from_static_blobs(&fields);

        assert!(recovered.is_empty());
    }

    #[test]
    fn stride_rc4_static_blob_recovery_honors_expired_deadline() {
        let fields = vec![vec![0x41; 32], vec![0x42; 32], vec![0x55; 256 * 1024]];
        let deadline = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));

        let recovered = recover_stride_rc4_pes_from_static_blobs_until(&fields, deadline);

        assert!(recovered.is_empty());
    }
}
