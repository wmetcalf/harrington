//! Glue for the AES dropper chain. Gated by the presence of a
//! `MultiStageEncryptedDropper` trait that the deob_scan detector
//! already emitted.

#![allow(clippy::expect_used)]

use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::env::Environment;
use crate::traits::Trait;

use super::crypto::{aes_cbc_decrypt, gunzip};
use super::payload_lines;
use super::ps_extract;
use super::scan;

const MAX_STAGE1_B64: usize = 1024 * 1024;
const MAX_STAGE1_DECODED: usize = 2 * 1024 * 1024;
const MAX_STAGE_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_URLS_PER_SAMPLE: usize = 16;

#[allow(clippy::expect_used)]
static STAGE1_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"'([^']{200,})'\s*\.\s*Replace\s*\(\s*'([^']{2,40})'\s*,\s*''\s*\)")
        .expect("stage1 re")
});

/// Top-level entry. Run after `scan_multistage_encrypted_dropper` so the
/// gate trait is in place. No-op when the gate trait is absent.
pub fn extract_from_chain(raw_input: &[u8], deob: &str, env: &mut Environment) {
    // dwm.bat / agent_debug / Account_Access_Alert family doesn't trigger
    // the STAGE1_RE gate (no `'X'.Replace('Y','')` form); instead the
    // PS body holds a literal AES key+IV and the bat has a single
    // `:: <b64>\<b64>` ciphertext line. Try the simpler path first.
    try_extract_simple_ps_aes(raw_input, deob, env);

    let has_gate = env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::MultiStageEncryptedDropper { .. }));
    if !has_gate {
        return;
    }

    // ---- Stage 1: find 'b64'.Replace('marker','') with long b64. ----
    let stage2_ps = match decode_stage1(deob) {
        Some(s) => s,
        None => return,
    };

    // ---- Stage 2: find marker list + inline gzipped b64 if present. ----
    let stage3_ps = match unwrap_stage2(&stage2_ps) {
        Some(s) => s,
        None => stage2_ps.clone(), // some variants skip the gunzip step
    };

    // ---- Source line: prefer `:: ` payload, fall back to assembled :::N. ----
    let lines = payload_lines::collect(raw_input);
    let ciphertext_envelopes: Vec<Vec<u8>> = if let Some(cs) = lines.colon_space {
        // Format: `<b64>\<b64>` — split on backslash, b64-decode each half.
        split_and_decode_envelope(cs)
    } else if !lines.colon_n.is_empty() {
        // Stage-2 already consumed these in earlier loaders; on samples
        // where there's no `:: ` line, the joined `:::N` payload IS the
        // ciphertext envelope. Apply the marker chain from stage-2.
        let marker_chain = ps_extract::find_replace_chain(&stage2_ps);
        let joined: Vec<u8> = lines
            .colon_n
            .iter()
            .flat_map(|(_, s)| s.iter().copied())
            .collect();
        let mut as_text = String::from_utf8_lossy(&joined).into_owned();
        for (needle, replacement) in &marker_chain {
            as_text = as_text.replace(needle.as_str(), replacement.as_str());
        }
        let cleaned: String = as_text
            .chars()
            .filter(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '='))
            .collect();
        match base64::engine::general_purpose::STANDARD.decode(&cleaned) {
            Ok(b) => vec![b],
            Err(_) => return,
        }
    } else {
        return;
    };

    // ---- Stage 3: extract AES key/IV. Try the literal-regex path first;
    // fall back to a cryptographically-validated pair search across every
    // base64 literal in the script if the regex misses (which it does on
    // samples that rename the `.Key`/`.IV` fields or nest them under
    // additional dotted properties). The validator needs a ciphertext
    // sample, so it has to run AFTER ciphertext_envelopes is built. ----
    let (key, iv) = match ps_extract::find_aes_key_iv(&stage3_ps) {
        Some(kv) => kv,
        None => match ciphertext_envelopes
            .first()
            .and_then(|ct| ps_extract::find_aes_pair_with_oracle(&stage3_ps, ct))
        {
            Some(kv) => kv,
            None => return,
        },
    };

    // ---- Decrypt + gunzip each envelope, scan for URLs. ----
    let mut all_urls: Vec<String> = Vec::new();
    let mut assemblies_recovered: u32 = 0;
    let mut nested_keys: Vec<crate::traits::NestedAesKey> = Vec::new();
    for envelope in ciphertext_envelopes {
        let pt = match aes_cbc_decrypt(&key, &iv, &envelope) {
            Ok(p) => p,
            Err(_) => continue,
        };
        // assemblies_recovered counts only successful gunzip outputs (those
        // are the .NET assemblies `dotnet::extract_us_strings` can walk).
        // Raw-fallback bytes are still URL-scanned but not counted as
        // recovered assemblies — naming the field that way was misleading.
        let decompressed = match gunzip(&pt, MAX_STAGE_OUTPUT) {
            Ok(d) => {
                assemblies_recovered += 1;
                d
            }
            Err(_) => pt.clone(),
        };
        // If the decrypted blob is a .NET assembly, walk its `#US` heap
        // and surface (a) any URLs the loader has inline, (b) nested
        // AES Key/IV pairs that decrypt embedded resources.
        if decompressed.starts_with(b"MZ") {
            // Persist the recovered PE so analysts can pull it out for
            // sandbox / static RE follow-up. `write_report_files`
            // sha-prefixes the output filename and picks an extension
            // based on the PE characteristics.
            if env.recovered_pe.len() < MAX_URLS_PER_SAMPLE {
                let label = format!("aes-chain-stage1-asm{}", env.recovered_pe.len());
                env.recovered_pe.push((label, decompressed.clone()));
            }
            if let Ok(us_strings) = super::dotnet::extract_us_strings(&decompressed) {
                for s in &us_strings {
                    // Scan each #US string for a URL.
                    for url in scan::scan_urls(s.as_bytes(), MAX_URLS_PER_SAMPLE) {
                        if !all_urls.contains(&url) && all_urls.len() < MAX_URLS_PER_SAMPLE {
                            all_urls.push(url);
                        }
                    }
                }
                for (k, iv2) in super::dotnet::find_nested_aes_pairs(&us_strings) {
                    nested_keys.push(crate::traits::NestedAesKey {
                        key_b64: k,
                        iv_b64: iv2,
                    });
                }
            }
        }
        // Fallback / belt-and-braces: also do a raw byte scan in case URLs
        // appear outside `#US` (e.g., in resource blobs or unmanaged data).
        for url in scan::scan_urls(&decompressed, MAX_URLS_PER_SAMPLE) {
            if all_urls.len() >= MAX_URLS_PER_SAMPLE {
                break;
            }
            if !all_urls.contains(&url) {
                all_urls.push(url);
            }
        }
        if all_urls.len() >= MAX_URLS_PER_SAMPLE {
            break;
        }
    }

    // ---- Annotate the gate trait with recovered crypto material so
    //      analysts get value even when URLs are hidden inside the .NET
    //      assembly's #US stream. ----
    if assemblies_recovered > 0 {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(&iv);
        for t in env.traits.iter_mut() {
            if let Trait::MultiStageEncryptedDropper {
                aes_key_b64,
                aes_iv_b64,
                assemblies_recovered: ar,
                nested_aes,
                ..
            } = t
            {
                *aes_key_b64 = Some(key_b64.clone());
                *aes_iv_b64 = Some(iv_b64.clone());
                *ar = Some(assemblies_recovered);
                *nested_aes = nested_keys.clone();
                break;
            }
        }
    }

    // ---- Emit DownloadInDeobText for each URL. ----
    let already_known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();
    for url in all_urls {
        if already_known.contains(&url) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "aes-chain".to_string(),
        });
    }
}

fn decode_stage1(deob: &str) -> Option<String> {
    for caps in STAGE1_RE.captures_iter(deob) {
        // `?` would abort the whole loop on a missing capture / failed
        // decode — turning a single benign-decoy match into a silent skip
        // of every subsequent real stage-1 blob. Use `continue` so each
        // match is independent.
        let Some(raw) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(marker) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if raw.len() < 1000 || raw.len() > MAX_STAGE1_B64 {
            continue;
        }
        let cleaned: String = raw
            .replace(marker, "")
            .chars()
            .filter(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '='))
            .collect();
        if cleaned.len() < 100 {
            continue;
        }
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&cleaned) else {
            continue;
        };
        if bytes.len() > MAX_STAGE1_DECODED {
            continue;
        }
        // Stage-1 output is UTF-16LE PowerShell.
        let utf16: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16_lossy(&utf16);
        // Heuristic: keep the match that looks like PS (contains $ and ;).
        if text.contains('$') && text.contains(';') {
            return Some(text);
        }
    }
    None
}

fn unwrap_stage2(stage2_ps: &str) -> Option<String> {
    let gz_b64 = ps_extract::find_inline_gzipped_b64(stage2_ps)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(gz_b64)
        .ok()?;
    let decompressed = gunzip(&bytes, MAX_STAGE_OUTPUT).ok()?;
    String::from_utf8(decompressed).ok()
}

/// Cap on the number of `\`-separated b64 chunks we attempt to decode in a
/// single envelope. A crafted `:: <b64>\<b64>\…` line could otherwise force
/// thousands of base64 decodes each up to MAX_CIPHERTEXT.
const MAX_ENVELOPE_CHUNKS: usize = 64;

fn split_and_decode_envelope(payload: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(payload);
    text.split('\\')
        .filter(|part| !part.is_empty())
        .take(MAX_ENVELOPE_CHUNKS)
        .filter_map(|part| {
            let cleaned: String = part
                .chars()
                .filter(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '='))
                .collect();
            if cleaned.len() < 16 {
                return None;
            }
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .ok()
        })
        .collect()
}

/// Simpler AES-decryption path for the dwm.bat / agent_debug /
/// Account_Access_Alert / d09f2f0f... family. Pattern:
///   - extracted PS body contains `Key=[…]'FromBase64String'('<KEY44>')`
///     and `IV=[…]'FromBase64String'('<IV24>')` literals
///   - bat has a single `:: <b64>\<b64>` line (or `:: <b64>` with no split)
///   - each chunk is AES-CBC-PKCS7 then gzip
///   - decompressed payload is a .NET PE
///
/// We pull KEY+IV from any extracted PS body, find the `:: ` line in raw
/// input, decrypt each chunk, gunzip, and scan the result for:
///   1. URLs (rare but possible)
///   2. AV-blocklist hosts (very common — surfaces as DefenderEvasion-host)
///   3. Persistence strings (Run keys, scheduled task names)
///   4. PE info (assembly name, file description)
///
/// Emits MultiStageEncryptedDropper with the recovered key/IV so the
/// main pipeline can see what was unlocked, plus DownloadInDeobText for
/// any URLs and AvBlocklistHost summary.
fn try_extract_simple_ps_aes(raw_input: &[u8], deob: &str, env: &mut Environment) {
    use base64::Engine as _;
    use once_cell::sync::Lazy;
    use regex::Regex;
    // Already-decrypted? Don't redo work.
    if env.traits.iter().any(|t| {
        matches!(
            t,
            Trait::MultiStageEncryptedDropper {
                aes_key_b64: Some(_),
                ..
            }
        )
    }) {
        return;
    }
    // Find the `:: <b64>` ciphertext line in the raw input. Also
    // tolerate `::<no-space>` (some dropper variants don't put a
    // space, e.g. 3eeecf195767... family — same AES+gzip+chunks
    // structure, just tighter prefix).
    static COLON_SPACE_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?m)^::\s?([A-Za-z0-9+/\\=]{200,})"#).expect("colon-space re"));
    let raw_text = String::from_utf8_lossy(raw_input);
    let Some(ct_line) = COLON_SPACE_RE.captures(&raw_text) else {
        return;
    };
    let payload = ct_line.get(1).map(|m| m.as_str()).unwrap_or("");
    if payload.len() < 200 || payload.len() > MAX_STAGE_OUTPUT {
        return;
    }
    // Find AES Key + IV in any extracted PS body. Match the form
    // `'<44-char-b64-ending-=>'` immediately preceded by `Key=` or after
    // `FromBase64String`. Allow various PS-string obfuscation forms.
    static KEY_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/]{43}=)['"]\s*\)"#).expect("aes key re"));
    static IV_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/]{22}==)['"]\s*\)"#).expect("aes iv re"));
    // Search across all extracted PS bodies (normalized form preferred),
    // then fall back to the raw input. The 1895041a55e8… family stashes
    // the PS body in a `set "EtnCTS=…"` value that never makes it into
    // `all_extracted_ps1` (it's invoked later via `%EtnCTS%` expansion),
    // so the Key/IV literals only exist in raw_text — without this fallback
    // we silently skip the entire family.
    fn harvest(
        text: &str,
        keys: &mut Vec<String>,
        ivs: &mut Vec<String>,
        key_re: &Regex,
        iv_re: &Regex,
    ) {
        for c in key_re.captures_iter(text).take(4) {
            if let Some(m) = c.get(1) {
                let s = m.as_str().to_string();
                if !keys.contains(&s) {
                    keys.push(s);
                }
            }
        }
        for c in iv_re.captures_iter(text).take(4) {
            if let Some(m) = c.get(1) {
                let s = m.as_str().to_string();
                if !ivs.contains(&s) {
                    ivs.push(s);
                }
            }
        }
    }
    let mut found_keys: Vec<String> = Vec::new();
    let mut found_ivs: Vec<String> = Vec::new();
    for body in env.all_extracted_ps1.iter() {
        harvest(
            &String::from_utf8_lossy(body),
            &mut found_keys,
            &mut found_ivs,
            &KEY_RE,
            &IV_RE,
        );
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        // Deob-output fallback. 1895041a55e8… stores the PS body inside
        // `set "EtnCTS=…"` with marker noise (`RSAqZJqVpt77…`) that only
        // resolves to a clean Key/IV after our normalize pipeline runs.
        // The clean form appears in `deob`, not raw_input or
        // `all_extracted_ps1`.
        harvest(deob, &mut found_keys, &mut found_ivs, &KEY_RE, &IV_RE);
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        // Last-resort raw-input scan (for variants we haven't characterised).
        harvest(&raw_text, &mut found_keys, &mut found_ivs, &KEY_RE, &IV_RE);
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        return;
    }
    // Try every (key, iv) combo. The first that AES+gunzip-decodes the
    // first chunk wins.
    let chunks: Vec<&str> = payload
        .split('\\')
        .filter(|s| !s.is_empty())
        .take(MAX_ENVELOPE_CHUNKS)
        .collect();
    let Some(first_chunk) = chunks.first() else {
        return;
    };
    let Ok(first_ct) = base64::engine::general_purpose::STANDARD.decode(first_chunk) else {
        return;
    };
    let mut winning: Option<(Vec<u8>, Vec<u8>)> = None;
    'outer: for k_b64 in &found_keys {
        let Ok(key) = base64::engine::general_purpose::STANDARD.decode(k_b64) else {
            continue;
        };
        if key.len() != 32 {
            continue;
        }
        for iv_b64 in &found_ivs {
            let Ok(iv) = base64::engine::general_purpose::STANDARD.decode(iv_b64) else {
                continue;
            };
            if iv.len() != 16 {
                continue;
            }
            let Ok(pt) = aes_cbc_decrypt(&key, &iv, &first_ct) else {
                continue;
            };
            // Unpad PKCS7
            let pt = pkcs7_unpad(&pt);
            if gunzip(&pt, MAX_STAGE_OUTPUT).is_ok() {
                winning = Some((key, iv));
                break 'outer;
            }
        }
    }
    let Some((key, iv)) = winning else {
        return;
    };
    // Decrypt + gunzip all chunks, concat for IOC scan.
    let mut combined: Vec<u8> = Vec::new();
    let mut assemblies_count: u32 = 0;
    for chunk in &chunks {
        let Ok(ct) = base64::engine::general_purpose::STANDARD.decode(chunk) else {
            continue;
        };
        let Ok(pt) = aes_cbc_decrypt(&key, &iv, &ct) else {
            continue;
        };
        let pt = pkcs7_unpad(&pt);
        let Ok(decompressed) = gunzip(&pt, MAX_STAGE_OUTPUT) else {
            continue;
        };
        // Recognise .NET PE blob. Persist alongside the count so
        // analysts can extract the bytes (CLI's `write_report_files`
        // dumps them as `<sha>.exe` / `<sha>.dll` in the out-dir).
        if decompressed.len() >= 64 && decompressed.starts_with(b"MZ") {
            assemblies_count += 1;
            if env.recovered_pe.len() < MAX_URLS_PER_SAMPLE {
                let label = format!("ps-aes-stage1-asm{}", env.recovered_pe.len());
                env.recovered_pe.push((label, decompressed.clone()));
            }
        }
        if combined.len() + decompressed.len() <= MAX_STAGE_OUTPUT {
            combined.extend_from_slice(&decompressed);
        }
    }
    // Record the dropper trait with the recovered crypto material.
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key);
    let iv_b64 = base64::engine::general_purpose::STANDARD.encode(&iv);
    env.traits.push(Trait::MultiStageEncryptedDropper {
        marker: "ps-aes-cbc-gzip".to_string(),
        b64_length: u32::try_from(payload.len()).unwrap_or(u32::MAX),
        has_aes_cbc: true,
        has_gzip_stage: true,
        reads_self_lines: true,
        aes_key_b64: Some(key_b64),
        aes_iv_b64: Some(iv_b64),
        assemblies_recovered: Some(assemblies_count),
        nested_aes: Vec::new(),
    });
    // Scan combined decrypted blob for IOCs. PEs store strings as both
    // ASCII and UTF-16LE — handle both.
    scan_decrypted_iocs(&combined, env);
}

fn pkcs7_unpad(pt: &[u8]) -> Vec<u8> {
    if pt.is_empty() {
        return Vec::new();
    }
    let pad = *pt.last().unwrap_or(&0) as usize;
    if pad == 0 || pad > 16 || pad > pt.len() {
        return pt.to_vec();
    }
    if pt[pt.len() - pad..].iter().all(|&b| b as usize == pad) {
        pt[..pt.len() - pad].to_vec()
    } else {
        pt.to_vec()
    }
}

/// Parse a .NET PE's #US (UserString) metadata stream. Each entry is
/// `<compressed-length-prefix><utf-16-le-bytes><terminator-byte>`. The
/// byte-pair UTF-16LE scan can miss URLs that start on odd offsets;
/// the metadata parser knows the exact string boundaries.
fn extract_dotnet_us_strings(blob: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if blob.len() < 0x80 || &blob[..2] != b"MZ" {
        return out;
    }
    let read_u32 = |off: usize| -> Option<u32> {
        if off + 4 > blob.len() {
            None
        } else {
            Some(u32::from_le_bytes([
                blob[off],
                blob[off + 1],
                blob[off + 2],
                blob[off + 3],
            ]))
        }
    };
    let read_u16 = |off: usize| -> Option<u16> {
        if off + 2 > blob.len() {
            None
        } else {
            Some(u16::from_le_bytes([blob[off], blob[off + 1]]))
        }
    };
    let Some(pe_off) = read_u32(0x3c).map(|v| v as usize) else {
        return out;
    };
    if pe_off + 24 > blob.len() || &blob[pe_off..pe_off + 4] != b"PE\0\0" {
        return out;
    }
    let Some(num_sect) = read_u16(pe_off + 6) else {
        return out;
    };
    let opt_hdr_off = pe_off + 24;
    let Some(opt_hdr_size) = read_u16(pe_off + 20) else {
        return out;
    };
    let sect_table_off = opt_hdr_off + opt_hdr_size as usize;
    let mut sections: Vec<(u32, u32, u32)> = Vec::new();
    for i in 0..num_sect as usize {
        let so = sect_table_off + i * 40;
        if so + 40 > blob.len() {
            return out;
        }
        let vsize = read_u32(so + 8).unwrap_or(0);
        let vaddr = read_u32(so + 12).unwrap_or(0);
        let roff = read_u32(so + 20).unwrap_or(0);
        sections.push((vaddr, vsize, roff));
    }
    let rva_to_off = |rva: u32| -> Option<usize> {
        for (va, vsz, ro) in &sections {
            if rva >= *va && rva < va.saturating_add(*vsz) {
                return Some(((rva - va) + ro) as usize);
            }
        }
        None
    };
    let Some(magic) = read_u16(opt_hdr_off) else {
        return out;
    };
    let dd_off = if magic == 0x10b {
        opt_hdr_off + 96
    } else {
        opt_hdr_off + 112
    };
    let Some(clr_rva) = read_u32(dd_off + 14 * 8) else {
        return out;
    };
    if clr_rva == 0 {
        return out;
    }
    let Some(clr_off) = rva_to_off(clr_rva) else {
        return out;
    };
    let Some(md_rva) = read_u32(clr_off + 8) else {
        return out;
    };
    let Some(md_off) = rva_to_off(md_rva) else {
        return out;
    };
    if md_off + 16 > blob.len() || &blob[md_off..md_off + 4] != b"BSJB" {
        return out;
    }
    let Some(ver_len) = read_u32(md_off + 12) else {
        return out;
    };
    let ver_padded = ((ver_len + 3) & !3) as usize;
    if md_off + 16 + ver_padded + 4 > blob.len() {
        return out;
    }
    let n_streams = read_u16(md_off + 16 + ver_padded + 2).unwrap_or(0);
    let streams_base = md_off + 16 + ver_padded + 4;
    let mut sp = streams_base;
    let mut us_off: Option<usize> = None;
    let mut us_size: usize = 0;
    for _ in 0..n_streams {
        if sp + 8 > blob.len() {
            return out;
        }
        let rel = read_u32(sp).unwrap_or(0) as usize;
        let sz = read_u32(sp + 4).unwrap_or(0) as usize;
        let name_start = sp + 8;
        let name_end = match blob[name_start..].iter().position(|&b| b == 0) {
            Some(i) => name_start + i,
            None => return out,
        };
        let name = std::str::from_utf8(&blob[name_start..name_end]).unwrap_or("");
        if name == "#US" {
            us_off = Some(md_off + rel);
            us_size = sz;
        }
        sp = name_end + 1;
        while (sp - streams_base) % 4 != 0 {
            sp += 1;
        }
    }
    let Some(us_start) = us_off else { return out };
    let us_end = (us_start + us_size).min(blob.len());
    let mut p = us_start + 1;
    while p < us_end {
        let b = blob[p];
        let (length, hdr_size) = if b == 0 {
            (0usize, 1usize)
        } else if b < 0x80 {
            (b as usize, 1)
        } else if b < 0xC0 {
            if p + 1 >= us_end {
                break;
            }
            ((((b & 0x3F) as usize) << 8) | blob[p + 1] as usize, 2)
        } else {
            if p + 3 >= us_end {
                break;
            }
            (
                (((b & 0x1F) as usize) << 24)
                    | ((blob[p + 1] as usize) << 16)
                    | ((blob[p + 2] as usize) << 8)
                    | (blob[p + 3] as usize),
                4,
            )
        };
        p += hdr_size;
        if length == 0 || p + length > us_end {
            p += length.min(us_end - p);
            continue;
        }
        let str_bytes = &blob[p..p + length.saturating_sub(1)];
        p += length;
        if str_bytes.len() >= 2 && str_bytes.len() % 2 == 0 {
            let units: Vec<u16> = str_bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            if let Ok(s) = String::from_utf16(&units) {
                if !s.trim().is_empty() {
                    out.push(s);
                }
            }
        }
        if out.len() > 4096 {
            break;
        }
    }
    out
}

fn scan_decrypted_iocs(blob: &[u8], env: &mut Environment) {
    use once_cell::sync::Lazy;
    use regex::Regex;
    static URL_BYTES_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)(?:https?|ftp|file):[\x2f\x5c]+[A-Za-z0-9.\-_/?=&%#@:+\\]{6,200}")
            .expect("blob url re")
    });
    // .NET PE #US (UserString) stream — accurately extracted from
    // metadata. Catches URLs that byte-level UTF-16LE scanning misses
    // due to alignment. For samples whose C2 is in the .NET string heap.
    let us_strings = extract_dotnet_us_strings(blob);
    let mut us_combined = String::new();
    for s in &us_strings {
        us_combined.push_str(s);
        us_combined.push('\n');
    }
    // Direct ASCII URLs.
    let blob_ascii = String::from_utf8_lossy(blob);
    let known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => {
                Some(src.clone())
            }
            _ => None,
        })
        .collect();
    let mut new_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
    for m in URL_BYTES_RE.find_iter(&blob_ascii).take(64) {
        new_urls.insert(m.as_str().to_string());
    }
    // UTF-16LE: convert every other byte (LE plain) and scan.
    if blob.len() >= 16 {
        let utf16: String = blob
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take(MAX_STAGE_OUTPUT)
            .map(|u| char::from_u32(u as u32).unwrap_or('?'))
            .collect();
        for m in URL_BYTES_RE.find_iter(&utf16).take(64) {
            new_urls.insert(m.as_str().to_string());
        }
    }
    // .NET PE #US strings — properly extracted from metadata.
    for m in URL_BYTES_RE.find_iter(&us_combined).take(64) {
        new_urls.insert(m.as_str().to_string());
    }
    for url in new_urls {
        if known.contains(&url) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "aes-pe-strings".to_string(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::env::Config;
    use crate::traits::Trait;

    #[test]
    fn no_op_without_gate_trait() {
        let mut env = Environment::new(&Config::default());
        let big_b64 = "A".repeat(2000);
        let deob = format!("'{big_b64}'.Replace('xxx','')");
        extract_from_chain(b"", &deob, &mut env);
        // No gate trait → nothing happens.
        assert!(env.traits.is_empty());
    }

    #[test]
    fn scan_decrypted_iocs_extracts_ftp_url() {
        let mut env = Environment::new(&Config::default());
        scan_decrypted_iocs(b"ftp://aes-chain.example/payload.dat", &mut env);
        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::DownloadInDeobText { src, .. } if src == "ftp://aes-chain.example/payload.dat"
            )),
            "ftp url was not surfaced: {:?}",
            env.traits
        );
    }

    #[test]
    fn scan_decrypted_iocs_extracts_file_url() {
        let mut env = Environment::new(&Config::default());
        scan_decrypted_iocs(b"file:///C:/aes-chain.example/payload.exe", &mut env);
        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::DownloadInDeobText { src, .. } if src == "file:///C:/aes-chain.example/payload.exe"
            )),
            "file url was not surfaced: {:?}",
            env.traits
        );
    }
}
