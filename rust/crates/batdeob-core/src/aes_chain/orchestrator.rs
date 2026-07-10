//! Glue for the AES dropper chain. Gated by the presence of a
//! `MultiStageEncryptedDropper` trait that the deob_scan detector
//! already emitted.

use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::env::Environment;
use crate::traits::Trait;
use crate::util::contains_ascii_case_insensitive;

use super::crypto::{aes_cbc_decrypt, gunzip};
use super::payload_lines;
use super::ps_extract;
use super::scan;

const MAX_STAGE1_B64: usize = 1024 * 1024;
const MAX_STAGE1_DECODED: usize = 2 * 1024 * 1024;
const MAX_STAGE_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_URLS_PER_SAMPLE: usize = 16;
const MAX_ENVELOPE_CHUNKS: usize = 64;

#[expect(clippy::expect_used, reason = "static regex construction")]
static STAGE1_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"'([^']{200,})'\s*\.\s*Replace\s*\(\s*'([^']{2,40})'\s*,\s*''\s*\)")
        .expect("stage1 re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_KEY_BYTES_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\.Key\s*=\s*(?:\[\s*byte\s*\[\s*\]\s*\]\s*@?\(\s*([^)]+)\)|\[\s*(by[0-9A-Za-z]{2}\s*,[^)]+)\))")
        .expect("ps key bytes re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_IV_BYTES_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\.IV\s*=\s*(?:\[\s*byte\s*\[\s*\]\s*\]\s*@?\(\s*([^)]+)\)|\[\s*(by[0-9A-Za-z]{2}\s*,[^)]+)\))")
        .expect("ps iv bytes re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_B64_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*\(?\s*['"]([A-Za-z0-9+/=]{80,})['"]\s*\)?"#)
        .expect("ps b64 assignment re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_DYNAMIC_AES_B64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\[[^\]]*Convert\]\s*::\s*(?:FromBase64String|\$[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\(?\s*((?:['"][A-Za-z0-9+/=]{16,}['"]\s*(?:\+\s*)?){1,96})\s*\)?\s*\)"#,
    )
    .expect("ps dynamic aes b64 re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_DYNAMIC_KEY_B64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\.Key\s*=\s*\[[^\]]*Convert\]\s*::\s*(?:FromBase64String|\$[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*['"]([A-Za-z0-9+/=]{16,})['"]\s*\)"#,
    )
    .expect("ps dynamic key b64 re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_DYNAMIC_IV_B64_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\.IV\s*=\s*\[[^\]]*Convert\]\s*::\s*(?:FromBase64String|\$[A-Za-z_][A-Za-z0-9_]*)\s*\(\s*['"]([A-Za-z0-9+/=]{16,})['"]\s*\)"#,
    )
    .expect("ps dynamic iv b64 re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_QUOTED_B64_FRAGMENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/=]{16,})['"]"#).expect("ps b64 fragment re"));

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_SELF_MARKER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)\.StartsWith\(\s*['"]([^'"]{2,80})['"]\s*\).*?\.Substring\(\s*(\d{1,3})\s*\)"#,
    )
    .expect("ps self marker re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_REPLACE_PAIR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\.Replace\(\s*['"]([^'"]{1,8})['"]\s*,\s*['"]([^'"]{0,8})['"]\s*\)"#)
        .expect("ps replace pair re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static PS_REVERSED_STRING_MEMBER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\(\s*['"]([^'"]{2,64})['"]\s*\[\s*-1\s*\.\.\s*-\d{1,3}\s*\]\s*-\s*join\s*['"]{2}\s*\)"#)
        .expect("ps reversed string member re")
});

#[expect(clippy::expect_used, reason = "static regex construction")]
static SIMPLE_AES_KEY_B64_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/]{43}=)['"]\s*\)"#).expect("simple aes key re"));

#[expect(clippy::expect_used, reason = "static regex construction")]
static SIMPLE_AES_IV_B64_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"['"]([A-Za-z0-9+/]{22}==)['"]\s*\)"#).expect("simple aes iv re"));

#[expect(clippy::expect_used, reason = "static regex construction")]
static CMD_VAR_MARKER_REMOVAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"%[A-Za-z_][A-Za-z0-9_]*:([^=%\s"]{2,32})=%"#)
        .expect("cmd variable marker removal regex")
});

/// Top-level entry. Run after `scan_multistage_encrypted_dropper` so the
/// gate trait is in place. No-op when the gate trait is absent.
pub fn extract_from_chain(raw_input: &[u8], deob: &str, env: &mut Environment) {
    if env.check_timeout() {
        return;
    }
    let recovered_before_self_marker = env.recovered_pe.len();
    try_extract_self_marker_ps_aes_gzip(raw_input, deob, env);
    if env.check_timeout() {
        return;
    }
    if env.recovered_pe.len() > recovered_before_self_marker {
        return;
    }
    try_extract_self_tail_split_reversed_ps_aes_gzip(raw_input, deob, env);
    if env.check_timeout() {
        return;
    }
    try_extract_simple_ps_aes(raw_input, deob, env);
    if env.check_timeout() {
        return;
    }
    try_extract_dynamic_ps_aes_gzip(deob, env);
    if env.check_timeout() {
        return;
    }

    let has_gate = env
        .traits
        .iter()
        .any(|t| matches!(t, Trait::MultiStageEncryptedDropper { .. }));
    if !has_gate {
        return;
    }

    try_extract_ps_base64_aes_gzip(deob, env);
    if env.check_timeout() {
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

    // ---- Stage 3: extract AES key/IV. ----
    let (key, iv) = match ps_extract::find_aes_key_iv(&stage3_ps) {
        Some(kv) => kv,
        None => return,
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

    // ---- Decrypt + gunzip each envelope, scan for URLs. ----
    let mut all_urls: Vec<String> = Vec::new();
    let mut assemblies_recovered: u32 = 0;
    let mut nested_keys: Vec<crate::traits::NestedAesKey> = Vec::new();
    for envelope in ciphertext_envelopes {
        if env.check_timeout() {
            return;
        }
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
        if env.check_timeout() {
            return;
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

fn try_extract_ps_base64_aes_gzip(deob: &str, env: &mut Environment) {
    if !has_ps_base64_aes_gzip_indicators(deob) {
        return;
    }

    let key = match PS_KEY_BYTES_RE.captures(deob).and_then(|caps| {
        caps.get(1)
            .or_else(|| caps.get(2))
            .and_then(|m| parse_ps_byte_array(m.as_str()))
    }) {
        Some(key) => key,
        None => return,
    };
    let iv = match PS_IV_BYTES_RE.captures(deob).and_then(|caps| {
        caps.get(1)
            .or_else(|| caps.get(2))
            .and_then(|m| parse_ps_byte_array(m.as_str()))
    }) {
        Some(iv) => iv,
        None => return,
    };

    for caps in PS_B64_ASSIGNMENT_RE.captures_iter(deob).take(16) {
        if env.check_timeout() {
            return;
        }
        let Some(encoded) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            continue;
        };
        if ciphertext.len() > super::crypto::MAX_CIPHERTEXT {
            continue;
        }
        let Ok(plaintext) = aes_cbc_decrypt(&key, &iv, &ciphertext) else {
            continue;
        };
        let Ok(decompressed) = gunzip(&plaintext, MAX_STAGE_OUTPUT) else {
            continue;
        };
        if !decompressed.starts_with(b"MZ") {
            continue;
        }
        if env
            .recovered_pe
            .iter()
            .any(|(_, existing)| existing == &decompressed)
        {
            scan_decrypted_iocs(&decompressed, env);
            continue;
        }
        let label = format!("ps-b64-aes-asm{}", env.recovered_pe.len() + 1);
        env.recovered_pe.push((label, decompressed.clone()));
        scan_decrypted_iocs(&decompressed, env);
        if env.check_timeout() {
            return;
        }
    }
}

fn try_extract_dynamic_ps_aes_gzip(deob: &str, env: &mut Environment) {
    if !contains_ascii_case_insensitive(deob, "aesmanaged")
        || !contains_ascii_case_insensitive(deob, "gzipstream")
        || !contains_ascii_case_insensitive(deob, "assembly]::load")
        || !contains_ascii_case_insensitive(deob, "transformfinalblock")
    {
        return;
    }

    let Some(key_b64) = PS_DYNAMIC_KEY_B64_RE
        .captures(deob)
        .and_then(|caps| caps.get(1).map(|m| m.as_str()))
    else {
        return;
    };
    let Some(iv_b64) = PS_DYNAMIC_IV_B64_RE
        .captures(deob)
        .and_then(|caps| caps.get(1).map(|m| m.as_str()))
    else {
        return;
    };
    let Ok(key) = base64::engine::general_purpose::STANDARD.decode(key_b64) else {
        return;
    };
    let Ok(iv) = base64::engine::general_purpose::STANDARD.decode(iv_b64) else {
        return;
    };
    if !matches!(key.len(), 16 | 24 | 32) || iv.len() != 16 {
        return;
    }

    let mut recovered = 0u32;
    for caps in PS_DYNAMIC_AES_B64_RE.captures_iter(deob).take(16) {
        if env.check_timeout() {
            return;
        }
        let Some(expr) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(encoded) = collect_quoted_base64_fragments(expr) else {
            continue;
        };
        if encoded.len() < 128 {
            continue;
        }
        let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            continue;
        };
        if ciphertext.len() > super::crypto::MAX_CIPHERTEXT {
            continue;
        }
        let Ok(plaintext) = aes_cbc_decrypt(&key, &iv, &ciphertext) else {
            continue;
        };
        let Ok(decompressed) = gunzip(&plaintext, MAX_STAGE_OUTPUT) else {
            continue;
        };
        if !decompressed.starts_with(b"MZ") {
            continue;
        }
        recovered = recovered.saturating_add(1);
        if env
            .recovered_pe
            .iter()
            .any(|(_, existing)| existing == &decompressed)
        {
            scan_decrypted_iocs(&decompressed, env);
            continue;
        }
        let label = format!("ps-dynamic-aes-asm{}", env.recovered_pe.len() + 1);
        env.recovered_pe.push((label, decompressed.clone()));
        scan_decrypted_iocs(&decompressed, env);
        if env.check_timeout() {
            return;
        }
    }

    if recovered > 0 {
        env.traits.push(Trait::MultiStageEncryptedDropper {
            marker: "ps-dynamic-aes-cbc-gzip".to_string(),
            b64_length: 0,
            has_aes_cbc: true,
            has_gzip_stage: true,
            reads_self_lines: false,
            aes_key_b64: Some(key_b64.to_string()),
            aes_iv_b64: Some(iv_b64.to_string()),
            assemblies_recovered: Some(recovered),
            nested_aes: Vec::new(),
        });
    }
}

fn try_extract_self_marker_ps_aes_gzip(raw_input: &[u8], deob: &str, env: &mut Environment) {
    let scan_text_storage;
    let scan_text = if self_marker_ps_aes_gzip_gate(deob) {
        deob
    } else {
        let mut candidate = if deob.contains('*') {
            deob.replace('*', "")
        } else {
            deob.to_string()
        };
        if !self_marker_ps_aes_gzip_gate(&candidate) {
            if let Some(normalized) = normalize_ps_reversed_string_members(&candidate) {
                candidate = normalized;
            }
        }
        scan_text_storage = candidate;
        if !self_marker_ps_aes_gzip_gate(&scan_text_storage) {
            return;
        }
        &scan_text_storage
    };

    let Some(key_b64) = PS_DYNAMIC_KEY_B64_RE
        .captures(scan_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str()))
    else {
        return;
    };
    let Some(iv_b64) = PS_DYNAMIC_IV_B64_RE
        .captures(scan_text)
        .and_then(|caps| caps.get(1).map(|m| m.as_str()))
    else {
        return;
    };
    let Ok(key) = base64::engine::general_purpose::STANDARD.decode(key_b64) else {
        return;
    };
    let Ok(iv) = base64::engine::general_purpose::STANDARD.decode(iv_b64) else {
        return;
    };
    if !matches!(key.len(), 16 | 24 | 32) || iv.len() != 16 {
        return;
    }

    let replacements = collect_replace_pairs(deob);
    let mut recovered_gzip = 0u32;
    let mut recovered_direct = 0u32;
    for caps in PS_SELF_MARKER_RE.captures_iter(scan_text).take(4) {
        if env.check_timeout() {
            return;
        }
        let Some(marker) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let offset = caps
            .get(2)
            .and_then(|m| m.as_str().parse::<usize>().ok())
            .unwrap_or(marker.len());
        if let Some(payload_line) = find_raw_line_starting_with(raw_input, marker.as_bytes()) {
            if payload_line.len() <= offset {
                continue;
            }
            if !recover_self_marker_payload_chunks(
                &payload_line[offset..],
                &replacements,
                &key,
                &iv,
                env,
                &mut recovered_gzip,
                &mut recovered_direct,
            ) {
                return;
            }
        } else if let Some(payload_line) = deob.lines().find(|line| line.starts_with(marker)) {
            let payload_line = payload_line.as_bytes();
            if payload_line.len() <= offset {
                continue;
            }
            if !recover_self_marker_payload_chunks(
                &payload_line[offset..],
                &replacements,
                &key,
                &iv,
                env,
                &mut recovered_gzip,
                &mut recovered_direct,
            ) {
                return;
            }
        }
    }

    let recovered = recovered_gzip.saturating_add(recovered_direct);
    if recovered > 0 {
        let has_gzip_stage = recovered_gzip > 0;
        env.traits.push(Trait::MultiStageEncryptedDropper {
            marker: if has_gzip_stage {
                "ps-self-marker-aes-cbc-gzip"
            } else {
                "ps-self-marker-aes-cbc"
            }
            .to_string(),
            b64_length: 0,
            has_aes_cbc: true,
            has_gzip_stage,
            reads_self_lines: true,
            aes_key_b64: Some(key_b64.to_string()),
            aes_iv_b64: Some(iv_b64.to_string()),
            assemblies_recovered: Some(recovered),
            nested_aes: Vec::new(),
        });
    }
}

fn recover_self_marker_payload_chunks(
    payload: &[u8],
    replacements: &[(String, String)],
    key: &[u8],
    iv: &[u8],
    env: &mut Environment,
    recovered_gzip: &mut u32,
    recovered_direct: &mut u32,
) -> bool {
    if payload.len() < 200 {
        return true;
    }

    for chunk in payload
        .split(|byte| *byte == b'\\')
        .take(MAX_ENVELOPE_CHUNKS)
    {
        if env.check_timeout() {
            return false;
        }
        let chunk = trim_ascii_bytes(chunk);
        if replacements.is_empty()
            && chunk.len() > max_base64_encoded_len(super::crypto::MAX_CIPHERTEXT)
        {
            continue;
        }

        let Ok(chunk_text) = std::str::from_utf8(chunk) else {
            continue;
        };
        let candidate_storage = self_marker_payload_decode_candidates(chunk_text, replacements);
        let mut recovered_chunk = false;
        for encoded in &candidate_storage {
            if encoded.len() > max_base64_encoded_len(super::crypto::MAX_CIPHERTEXT) {
                continue;
            }
            if encoded.len() < 128 {
                continue;
            }
            let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
                continue;
            };
            if ciphertext.len() > super::crypto::MAX_CIPHERTEXT {
                continue;
            }
            let Ok(plaintext) = aes_cbc_decrypt(key, iv, &ciphertext) else {
                continue;
            };
            let (decrypted, had_gzip) =
                if let Ok(decompressed) = gunzip(&plaintext, MAX_STAGE_OUTPUT) {
                    (decompressed, true)
                } else if plaintext.starts_with(b"MZ") {
                    (plaintext, false)
                } else {
                    continue;
                };
            if !decrypted.starts_with(b"MZ") {
                continue;
            }
            if had_gzip {
                *recovered_gzip = (*recovered_gzip).saturating_add(1);
            } else {
                *recovered_direct = (*recovered_direct).saturating_add(1);
            }
            if env
                .recovered_pe
                .iter()
                .any(|(_, existing)| existing == &decrypted)
            {
                scan_decrypted_iocs(&decrypted, env);
                recovered_chunk = true;
                break;
            }
            let label = format!("ps-self-marker-aes-asm{}", env.recovered_pe.len() + 1);
            env.recovered_pe.push((label, decrypted.clone()));
            scan_decrypted_iocs(&decrypted, env);
            recovered_chunk = true;
            if env.check_timeout() {
                return false;
            }
            break;
        }
        if recovered_chunk {
            continue;
        }
    }

    true
}

fn self_marker_payload_decode_candidates(
    chunk: &str,
    replacements: &[(String, String)],
) -> Vec<String> {
    let mut candidates = vec![chunk.to_string()];
    if replacements.is_empty() {
        return candidates;
    }

    let non_empty_replacements: Vec<(String, String)> = replacements
        .iter()
        .filter(|(_, replacement)| !replacement.is_empty())
        .cloned()
        .collect();
    if !non_empty_replacements.is_empty() {
        let normalized = apply_replace_pairs(chunk, &non_empty_replacements);
        if !candidates.contains(&normalized) {
            candidates.push(normalized);
        }
    }

    let legacy_normalized = apply_replace_pairs(chunk, replacements);
    if !candidates.contains(&legacy_normalized) {
        candidates.push(legacy_normalized);
    }

    candidates
}

fn trim_ascii_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|idx| idx + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn max_base64_encoded_len(decoded_len: usize) -> usize {
    decoded_len.div_ceil(3) * 4
}

fn self_marker_ps_aes_gzip_gate(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "readalltext")
        && contains_ascii_case_insensitive(text, "startswith")
        && contains_ascii_case_insensitive(text, "substring")
        && contains_ascii_case_insensitive(text, "assembly]::load")
        && contains_ascii_case_insensitive(text, "transformfinalblock")
}

fn normalize_ps_reversed_string_members(text: &str) -> Option<String> {
    let mut changed = false;
    let normalized =
        PS_REVERSED_STRING_MEMBER_RE.replace_all(text, |caps: &regex::Captures<'_>| {
            let Some(reversed) = caps.get(1).map(|m| m.as_str()) else {
                return caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string();
            };
            changed = true;
            reversed.chars().rev().collect::<String>()
        });
    changed.then(|| normalized.into_owned())
}

fn collect_replace_pairs(deob: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for caps in PS_REPLACE_PAIR_RE.captures_iter(deob).take(16) {
        let Some(needle) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(replacement) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let pair = (needle.to_string(), replacement.to_string());
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    }
    pairs
}

fn apply_replace_pairs(input: &str, replacements: &[(String, String)]) -> String {
    let mut out = input.to_string();
    for (needle, replacement) in replacements {
        out = out.replace(needle, replacement);
    }
    out
}

fn collect_quoted_base64_fragments(expr: &str) -> Option<String> {
    let mut out = String::new();
    for caps in PS_QUOTED_B64_FRAGMENT_RE.captures_iter(expr).take(128) {
        let Some(fragment) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        out.push_str(fragment);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn has_ps_base64_aes_gzip_indicators(deob: &str) -> bool {
    contains_ascii_case_insensitive(deob, "aesmanaged")
        && contains_ascii_case_insensitive(deob, "frombase64string")
        && contains_ascii_case_insensitive(deob, "transformfinalblock")
        && contains_ascii_case_insensitive(deob, "gzip")
}

fn try_extract_self_tail_split_reversed_ps_aes_gzip(
    raw_input: &[u8],
    deob: &str,
    env: &mut Environment,
) {
    if !looks_like_self_tail_split_reversed_ps_aes_gzip_loader(deob) {
        return;
    }
    let Some(payload) = last_nonempty_raw_line(raw_input) else {
        return;
    };
    let Ok(payload) = std::str::from_utf8(payload) else {
        return;
    };
    let payload = payload.trim();
    if payload.len() < 200 || payload.len() > MAX_STAGE_OUTPUT || !payload.contains('\\') {
        return;
    }
    if !payload.bytes().all(is_simple_aes_payload_byte) {
        return;
    }

    let chunks: Vec<&str> = payload
        .split('\\')
        .map(str::trim)
        .filter(|chunk| chunk.len() >= 128)
        .take(MAX_ENVELOPE_CHUNKS)
        .collect();
    if chunks.is_empty() {
        return;
    }

    let mut found_keys = Vec::new();
    let mut found_ivs = Vec::new();
    harvest_simple_aes_material(deob, &mut found_keys, &mut found_ivs);
    for body in &env.all_extracted_ps1 {
        harvest_simple_aes_material(
            &String::from_utf8_lossy(body),
            &mut found_keys,
            &mut found_ivs,
        );
    }
    for body in &env.all_extracted_cmd {
        harvest_simple_aes_material(body, &mut found_keys, &mut found_ivs);
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        let raw_text = String::from_utf8_lossy(raw_input);
        harvest_simple_aes_material(&raw_text, &mut found_keys, &mut found_ivs);
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        return;
    }

    let mut recovered = 0u32;
    for key_b64 in found_keys.iter().take(4) {
        let Ok(key) = base64::engine::general_purpose::STANDARD.decode(key_b64) else {
            continue;
        };
        if !matches!(key.len(), 16 | 24 | 32) {
            continue;
        }
        for iv_b64 in found_ivs.iter().take(4) {
            let Ok(iv) = base64::engine::general_purpose::STANDARD.decode(iv_b64) else {
                continue;
            };
            if iv.len() != 16 {
                continue;
            }
            let before = recovered;
            for chunk in &chunks {
                if env.check_timeout() {
                    return;
                }
                if recover_split_reversed_aes_gzip_chunk(chunk, &key, &iv, env) {
                    recovered = recovered.saturating_add(1);
                }
            }
            if recovered > before {
                env.traits.push(Trait::MultiStageEncryptedDropper {
                    marker: "ps-self-tail-split-reversed-aes-cbc-gzip".to_string(),
                    b64_length: u32::try_from(payload.len()).unwrap_or(u32::MAX),
                    has_aes_cbc: true,
                    has_gzip_stage: true,
                    reads_self_lines: true,
                    aes_key_b64: Some(key_b64.clone()),
                    aes_iv_b64: Some(iv_b64.clone()),
                    assemblies_recovered: Some(recovered),
                    nested_aes: Vec::new(),
                });
                return;
            }
        }
    }
}

fn looks_like_self_tail_split_reversed_ps_aes_gzip_loader(text: &str) -> bool {
    contains_ascii_case_insensitive(text, "readalllines")
        && contains_ascii_case_insensitive(text, ".split")
        && contains_ascii_case_insensitive(text, "tochararray")
        && contains_ascii_case_insensitive(text, "[array]::reverse")
        && contains_ascii_case_insensitive(text, "transformfinalblock")
        && contains_ascii_case_insensitive(text, "gzip")
        && contains_ascii_case_insensitive(text, "assembly")
}

fn last_nonempty_raw_line(input: &[u8]) -> Option<&[u8]> {
    input
        .split(|byte| *byte == b'\n')
        .rev()
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .map(trim_ascii_bytes)
        .find(|line| !line.is_empty())
}

fn recover_split_reversed_aes_gzip_chunk(
    chunk: &str,
    key: &[u8],
    iv: &[u8],
    env: &mut Environment,
) -> bool {
    let candidates = vec![chunk.to_string(), chunk.chars().rev().collect::<String>()];
    for encoded in candidates {
        if encoded.len() > max_base64_encoded_len(super::crypto::MAX_CIPHERTEXT) {
            continue;
        }
        let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            continue;
        };
        if ciphertext.len() > super::crypto::MAX_CIPHERTEXT {
            continue;
        }
        let Ok(plaintext) = aes_cbc_decrypt(key, iv, &ciphertext) else {
            continue;
        };
        let Ok(decompressed) = gunzip(&plaintext, MAX_STAGE_OUTPUT) else {
            continue;
        };
        if !decompressed.starts_with(b"MZ") {
            continue;
        }
        if env
            .recovered_pe
            .iter()
            .any(|(_, existing)| existing == &decompressed)
        {
            scan_decrypted_iocs(&decompressed, env);
            return false;
        }
        let label = format!(
            "ps-self-tail-split-reversed-aes-asm{}",
            env.recovered_pe.len() + 1
        );
        env.recovered_pe.push((label, decompressed.clone()));
        scan_decrypted_iocs(&decompressed, env);
        return true;
    }
    false
}

fn try_extract_simple_ps_aes(raw_input: &[u8], deob: &str, env: &mut Environment) {
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

    let payloads = find_simple_aes_colon_payloads(raw_input);
    if payloads.is_empty() {
        return;
    }
    let payload = payloads.join("\\");
    if payload.len() < 200 || payload.len() > MAX_STAGE_OUTPUT {
        return;
    }
    let payload = clean_simple_aes_payload(&payload);
    if payload.len() < 200 {
        return;
    }
    let chunks: Vec<&str> = payload
        .split(['\\', ':'])
        .filter(|s| !s.is_empty())
        .take(MAX_ENVELOPE_CHUNKS)
        .collect();
    let Some(first_chunk) = chunks.first() else {
        return;
    };

    let mut found_keys = Vec::new();
    let mut found_ivs = Vec::new();
    for body in &env.all_extracted_ps1 {
        harvest_simple_aes_material(
            &String::from_utf8_lossy(body),
            &mut found_keys,
            &mut found_ivs,
        );
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        for body in &env.all_extracted_cmd {
            harvest_simple_aes_material(body, &mut found_keys, &mut found_ivs);
            if !found_keys.is_empty() && !found_ivs.is_empty() {
                break;
            }
        }
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        for trait_ in &env.traits {
            let Trait::EchoRedirect { content, .. } = trait_ else {
                continue;
            };
            harvest_simple_aes_material(
                &String::from_utf8_lossy(content),
                &mut found_keys,
                &mut found_ivs,
            );
            if !found_keys.is_empty() && !found_ivs.is_empty() {
                break;
            }
        }
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        harvest_simple_aes_material(deob, &mut found_keys, &mut found_ivs);
    }
    if found_keys.is_empty() || found_ivs.is_empty() {
        let raw_text = String::from_utf8_lossy(raw_input);
        harvest_simple_aes_material(&raw_text, &mut found_keys, &mut found_ivs);
        harvest_simple_aes_material_from_marker_removal_variants(
            &raw_text,
            &mut found_keys,
            &mut found_ivs,
        );
    }
    harvest_simple_aes_material_from_payload_chunks(&chunks, &mut found_keys, &mut found_ivs);
    if found_keys.is_empty() || found_ivs.is_empty() {
        return;
    }

    let Ok(first_ct) = base64::engine::general_purpose::STANDARD.decode(first_chunk) else {
        return;
    };

    let mut winning: Option<(Vec<u8>, Vec<u8>)> = None;
    'outer: for key_b64 in &found_keys {
        let Ok(key) = base64::engine::general_purpose::STANDARD.decode(key_b64) else {
            continue;
        };
        if !matches!(key.len(), 16 | 24 | 32) {
            continue;
        }
        for iv_b64 in &found_ivs {
            let Ok(iv) = base64::engine::general_purpose::STANDARD.decode(iv_b64) else {
                continue;
            };
            if iv.len() != 16 {
                continue;
            }
            let Ok(plaintext) = aes_cbc_decrypt(&key, &iv, &first_ct) else {
                continue;
            };
            if gunzip(&plaintext, MAX_STAGE_OUTPUT).is_ok() {
                winning = Some((key, iv));
                break 'outer;
            }
        }
    }
    let Some((key, iv)) = winning else {
        return;
    };

    let mut combined = Vec::new();
    let mut assemblies_recovered = 0u32;
    for chunk in chunks {
        if env.check_timeout() {
            return;
        }
        let Ok(ciphertext) = base64::engine::general_purpose::STANDARD.decode(chunk) else {
            continue;
        };
        let Ok(plaintext) = aes_cbc_decrypt(&key, &iv, &ciphertext) else {
            continue;
        };
        let Ok(decompressed) = gunzip(&plaintext, MAX_STAGE_OUTPUT) else {
            continue;
        };
        if decompressed.len() >= 64 && decompressed.starts_with(b"MZ") {
            assemblies_recovered += 1;
            if env
                .recovered_pe
                .iter()
                .any(|(_, existing)| existing == &decompressed)
            {
                scan_decrypted_iocs(&decompressed, env);
            } else if env.recovered_pe.len() < MAX_URLS_PER_SAMPLE {
                let label = format!("ps-aes-stage1-asm{}", env.recovered_pe.len());
                env.recovered_pe.push((label, decompressed.clone()));
                scan_decrypted_iocs(&decompressed, env);
            }
        }
        if combined.len() + decompressed.len() <= MAX_STAGE_OUTPUT {
            combined.extend_from_slice(&decompressed);
        }
        if env.check_timeout() {
            return;
        }
    }

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
        assemblies_recovered: Some(assemblies_recovered),
        nested_aes: Vec::new(),
    });
    if assemblies_recovered == 0 {
        scan_decrypted_iocs(&combined, env);
    }
}

fn find_simple_aes_colon_payloads(raw_input: &[u8]) -> Vec<String> {
    let mut payloads = Vec::new();
    for raw_line in raw_input.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(rest) = line.strip_prefix(b"::") else {
            continue;
        };
        let rest = rest.strip_prefix(b" ").unwrap_or(rest);
        let rest = rest.strip_prefix(b"@").unwrap_or(rest);
        if rest.len() < 200 || !rest.iter().all(|byte| is_simple_aes_payload_byte(*byte)) {
            continue;
        }
        let Ok(payload) = std::str::from_utf8(rest) else {
            continue;
        };
        payloads.push(payload.to_string());
    }
    payloads
}

#[cfg(test)]
fn find_simple_aes_colon_payload(raw_input: &[u8]) -> Option<String> {
    find_simple_aes_colon_payloads(raw_input).into_iter().next()
}

fn is_simple_aes_payload_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'+'
            | b'/'
            | b'\\'
            | b':'
            | b'='
            | b'_'
            | b'-'
    )
}

fn find_raw_line_starting_with<'a>(raw_input: &'a [u8], marker: &[u8]) -> Option<&'a [u8]> {
    if marker.is_empty() {
        return None;
    }
    for raw_line in raw_input.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.starts_with(marker) {
            return Some(line);
        }
    }
    None
}

fn clean_simple_aes_payload(payload: &str) -> String {
    payload
        .trim_start_matches('@')
        .replace("_CASH_", "")
        .chars()
        .filter(|c| {
            matches!(
                c,
                'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '\\' | ':' | '='
            )
        })
        .collect()
}

fn harvest_simple_aes_material(text: &str, keys: &mut Vec<String>, ivs: &mut Vec<String>) {
    for caps in SIMPLE_AES_KEY_B64_RE.captures_iter(text).take(4) {
        if let Some(key) = caps.get(1).map(|m| m.as_str().to_string()) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    for caps in SIMPLE_AES_IV_B64_RE.captures_iter(text).take(4) {
        if let Some(iv) = caps.get(1).map(|m| m.as_str().to_string()) {
            if !ivs.contains(&iv) {
                ivs.push(iv);
            }
        }
    }
}

fn harvest_simple_aes_material_from_marker_removal_variants(
    text: &str,
    keys: &mut Vec<String>,
    ivs: &mut Vec<String>,
) {
    let mut seen = std::collections::HashSet::new();
    for caps in CMD_VAR_MARKER_REMOVAL_RE.captures_iter(text).take(8) {
        let Some(marker) = caps.get(1).map(|m| m.as_str()) else {
            continue;
        };
        if !seen.insert(marker.to_string()) {
            continue;
        }
        let cleaned = text.replace(marker, "");
        harvest_simple_aes_material(&cleaned, keys, ivs);
    }
}

fn harvest_simple_aes_material_from_payload_chunks(
    chunks: &[&str],
    keys: &mut Vec<String>,
    ivs: &mut Vec<String>,
) {
    for chunk in chunks.iter().rev().take(8) {
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(chunk) else {
            continue;
        };
        match decoded.len() {
            16 => {
                let iv = (*chunk).to_string();
                if !ivs.contains(&iv) {
                    ivs.push(iv);
                }
            }
            24 | 32 => {
                let key = (*chunk).to_string();
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            _ => {}
        }
    }
}

fn parse_ps_byte_array(nums: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut parts = nums.split(',');
    let first = parts.next()?.trim();
    if let Some((b0, b1)) = parse_damaged_byte_array_head(first) {
        out.push(b0);
        out.push(b1);
    } else {
        out.push(parse_ps_byte(first)?);
    }
    for part in parts {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        out.push(parse_ps_byte(token)?);
    }
    Some(out)
}

fn parse_ps_byte(token: &str) -> Option<u8> {
    let cleaned = token
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u8::from_str_radix(hex, 16).ok()
    } else {
        cleaned.parse::<u8>().ok()
    }
}

fn parse_damaged_byte_array_head(token: &str) -> Option<(u8, u8)> {
    let head = token.trim();
    let rest = head.strip_prefix("by")?;
    if rest.len() != 2 {
        return None;
    }
    let bytes = rest.as_bytes();
    Some((bytes[0], bytes[1]))
}

fn scan_decrypted_iocs(blob: &[u8], env: &mut Environment) {
    let already_known = env.known_extracted_urls();
    let mut seen = std::collections::HashSet::new();
    let mut scanned_dotnet_user_strings = false;

    if blob.starts_with(b"MZ") {
        if let Ok(us_strings) = super::dotnet::extract_us_strings(blob) {
            scanned_dotnet_user_strings = true;
            for s in &us_strings {
                for url in scan::scan_urls(s.as_bytes(), MAX_URLS_PER_SAMPLE) {
                    if already_known.contains(&url) || !seen.insert(url.clone()) {
                        continue;
                    }
                    env.traits.push(Trait::DownloadInDeobText {
                        src: url,
                        line_hint: "aes-chain".to_string(),
                    });
                    if seen.len() >= MAX_URLS_PER_SAMPLE {
                        return;
                    }
                }
            }
        }
    }

    let raw_urls = if scanned_dotnet_user_strings {
        scan::scan_ascii_urls(blob, MAX_URLS_PER_SAMPLE)
    } else {
        scan::scan_urls(blob, MAX_URLS_PER_SAMPLE)
    };
    for url in raw_urls {
        if already_known.contains(&url) || !seen.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "aes-chain".to_string(),
        });
        if seen.len() >= MAX_URLS_PER_SAMPLE {
            return;
        }
    }
}

fn decode_stage1(deob: &str) -> Option<String> {
    for caps in STAGE1_RE.captures_iter(deob) {
        let raw = caps.get(1)?.as_str();
        let marker = caps.get(2)?.as_str();
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
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .ok()?;
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

fn split_and_decode_envelope(payload: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(payload);
    text.split('\\')
        .filter(|part| !part.is_empty())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::env::Config;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use std::io::Write;

    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    fn fake_pe_with_url(url: &str) -> Vec<u8> {
        let mut pe = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe.extend_from_slice(url.as_bytes());
        pe
    }

    fn aes_gzip_b64(pe: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> String {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(pe).unwrap();
        let gzipped = gz.finish().unwrap();
        let mut enc_buf = gzipped.clone();
        enc_buf.resize(gzipped.len() + 16, 0);
        let cipher = Aes128CbcEnc::new_from_slices(key, iv).unwrap();
        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut enc_buf, gzipped.len())
            .unwrap()
            .to_vec();
        base64::engine::general_purpose::STANDARD.encode(ciphertext)
    }

    fn aes256_gzip_b64(pe: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> String {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(pe).unwrap();
        let gzipped = gz.finish().unwrap();
        let mut enc_buf = gzipped.clone();
        enc_buf.resize(gzipped.len() + 16, 0);
        let cipher = Aes256CbcEnc::new_from_slices(key, iv).unwrap();
        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut enc_buf, gzipped.len())
            .unwrap()
            .to_vec();
        base64::engine::general_purpose::STANDARD.encode(ciphertext)
    }

    fn aes256_plain_b64(pe: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> String {
        let mut enc_buf = pe.to_vec();
        enc_buf.resize(pe.len() + 16, 0);
        let cipher = Aes256CbcEnc::new_from_slices(key, iv).unwrap();
        let ciphertext = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut enc_buf, pe.len())
            .unwrap()
            .to_vec();
        base64::engine::general_purpose::STANDARD.encode(ciphertext)
    }

    fn byte_array(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn cash_marker_noise(s: &str) -> String {
        let mut out = String::new();
        for (idx, ch) in s.chars().enumerate() {
            if idx > 0 && idx % 11 == 0 {
                out.push_str("_CASH_");
            }
            out.push(ch);
        }
        out
    }

    fn gated_env(b64_len: usize) -> Environment {
        let mut env = Environment::new(&Config::default());
        env.traits.push(Trait::MultiStageEncryptedDropper {
            marker: String::new(),
            b64_length: b64_len as u32,
            has_aes_cbc: true,
            has_gzip_stage: true,
            reads_self_lines: false,
            aes_key_b64: None,
            aes_iv_b64: None,
            assemblies_recovered: None,
            nested_aes: Vec::new(),
        });
        env
    }

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
    fn extract_from_chain_marks_expired_deadline() {
        let mut env = Environment::new(&Config::default());
        env.limits.deadline = Some(std::time::Instant::now() - std::time::Duration::from_secs(1));

        extract_from_chain(b"", "not an aes chain", &mut env);

        assert!(
            env.traits
                .iter()
                .any(|trait_| matches!(trait_, Trait::TimeoutHit)),
            "expired AES-chain deadline was not surfaced: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps_base64_aes_gzip_payload_recovers_pe() {
        let key: [u8; 16] = [
            0x20, 0x7b, 0x91, 0x4a, 0xf5, 0x0d, 0x32, 0x6c, 0x9e, 0x41, 0x88, 0x03, 0xa7, 0xdd,
            0x14, 0x59,
        ];
        let iv: [u8; 16] = [
            0xa0, 0x31, 0x6c, 0x11, 0x8b, 0x45, 0x72, 0xde, 0x39, 0xff, 0x06, 0xc2, 0x4b, 0x80,
            0x17, 0xea,
        ];
        let url = "https://b64-aes.example/payload";
        let pe = fake_pe_with_url(url);
        let b64 = aes_gzip_b64(&pe, &key, &iv);
        let key_array = byte_array(&key);
        let iv_array = byte_array(&iv);
        let deob = format!(
            r#"
$ZbmpUg=('{b64}');
$LyzpcK=[Convert]::FromBase64String($ZbmpUg);
$aes=[type]('Activator')::CreateInstance([type]'System.Security.Cryptography.AesManaged');
$aes.Mode=1;$aes.Padding=2;
$aes.Key=[byte[]]@({key_array});
$aes.IV=[byte[]]@({iv_array});
$dec=$aes.CreateDecryptor();
$stage=$dec.TransformFinalBlock($LyzpcK,0,$LyzpcK.Length);
$gzip=New-Object System.IO.Compression.GZipStream($stage,[IO.Compression.CompressionMode]::Decompress);
[System.Reflection.Assembly]::Load($stage)
"#
        );
        let mut env = gated_env(b64.len());

        extract_from_chain(b"", &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-b64-aes-asm") && bytes == &pe),
            "recovered_pe: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "traits: {:?}",
            env.traits
        );
    }

    #[test]
    fn dynamic_method_concat_aes_gzip_payload_recovers_pe_without_gate() {
        let key: [u8; 16] = [
            0x20, 0x7b, 0x91, 0x4a, 0xf5, 0x0d, 0x32, 0x6c, 0x9e, 0x41, 0x88, 0x03, 0xa7, 0xdd,
            0x14, 0x59,
        ];
        let iv: [u8; 16] = [
            0xa0, 0x31, 0x6c, 0x11, 0x8b, 0x45, 0x72, 0xde, 0x39, 0xff, 0x06, 0xc2, 0x4b, 0x80,
            0x17, 0xea,
        ];
        let url = "https://dynamic-aes.example/payload";
        let pe = fake_pe_with_url(url);
        let b64 = aes_gzip_b64(&pe, &key, &iv);
        let split = b64.len() / 2;
        let (left, right) = b64.split_at(split);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let deob = format!(
            r#"
$method='gnirtS46esaBmorF'.ToCharArray();[array]::Reverse($method);$decode=-join $method;
$blob=[System.Convert]::$decode(('{}'+'{}'));
$aes=New-Object System.Security.Cryptography.AesManaged;
$aes.Key=[System.Convert]::$decode('{key_b64}');
$aes.IV=[System.Convert]::$decode('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
[System.Reflection.Assembly]::Load($plain)
"#,
            left, right
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(b"", &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-dynamic-aes-asm") && bytes == &pe),
            "recovered_pe: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "traits: {:?}",
            env.traits
        );
    }

    #[test]
    fn oversized_simple_colon_payload_is_skipped_before_timeout() {
        let raw = format!("::{}\r\n", "A".repeat(3 * 1024 * 1024));
        let deob = r#"
$x=[System.Security.Cryptography.Aes]::Create();
$x.Key=[System.Convert]::FromBase64String('tet9nbwKcJ4H6PSPZ0pG5xwbtojIGRT3Q4ePBrT3Xwk=');
$x.IV=[System.Convert]::FromBase64String('h2l7jJ1Xd8qRkIzzjzvfeg==');
$x.CreateDecryptor().TransformFinalBlock($bytes,0,$bytes.Length);
"#;
        let mut env = Environment::new(&Config {
            timeout_secs: 1,
            ..Config::default()
        });

        extract_from_chain(raw.as_bytes(), deob, &mut env);

        assert!(
            !env.traits.iter().any(|t| matches!(t, Trait::TimeoutHit)),
            "oversized simple :: payload should be skipped without timeout: {:?}",
            env.traits
        );
    }

    #[test]
    fn simple_colon_payload_scanner_ignores_large_non_payload_prefix() {
        let payload = format!("{}\\{}", "A".repeat(240), "B".repeat(240));
        let raw = format!(
            "{}\r\n:: {payload}\r\n",
            "set noise=value\r\n".repeat(16_384)
        );

        let found = find_simple_aes_colon_payload(raw.as_bytes());

        assert_eq!(found.as_deref(), Some(payload.as_str()));
    }

    #[test]
    fn simple_raw_ps_aes_gzip_harvests_key_iv_from_extracted_cmd_body() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url1 = "https://cmd-backed-simple-aes.example/first";
        let url2 = "https://cmd-backed-simple-aes.example/second";
        let mut pe1 = fake_pe_with_url(url1);
        pe1.resize(4096, 0x41);
        let mut pe2 = fake_pe_with_url(url2);
        pe2.resize(4096, 0x42);
        let b64_1 = aes256_gzip_b64(&pe1, &key, &iv);
        let b64_2 = aes256_gzip_b64(&pe2, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let raw = format!("@echo off\r\n:: {b64_1}\\{b64_2}\r\n");
        let mut env = Environment::new(&Config::default());
        env.all_extracted_cmd.push(format!(
            "echo $aes=[System.Security.Cryptography.Aes]::Create();\
             $aes.Key=[System.Convert]::FromBase64String('{key_b64}');\
             $aes.IV=[System.Convert]::FromBase64String('{iv_b64}');\
             $plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length); \
             | powershell.exe"
        ));

        extract_from_chain(raw.as_bytes(), "", &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe1),
            "first PE was not recovered from cmd-backed simple AES: {:?}",
            env.recovered_pe
        );
        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe2),
            "second PE was not recovered from cmd-backed simple AES: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    reads_self_lines: true,
                    assemblies_recovered: Some(2),
                    ..
                } if marker == "ps-aes-cbc-gzip"
            )),
            "cmd-backed simple AES trait was not emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_harvests_key_iv_from_echo_redirect_content() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url = "https://echo-redirect-simple-aes.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(4096, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(29).wrapping_add(7);
        }
        let b64 = aes256_gzip_b64(&pe, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let raw = format!("@echo off\r\n:: {b64}\r\n");
        let mut env = Environment::new(&Config::default());
        env.traits.push(Trait::EchoRedirect {
            content: format!(
                "$aes=[System.Security.Cryptography.Aes]::Create();\
                 $aes.Key=[System.Convert]::FromBase64String('{key_b64}');\
                 $aes.IV=[System.Convert]::FromBase64String('{iv_b64}');\
                 $plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);"
            )
            .into_bytes(),
            target: "nul".to_string(),
            append: false,
        });

        extract_from_chain(raw.as_bytes(), "", &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe),
            "PE was not recovered from echo-redirect simple AES: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    reads_self_lines: true,
                    assemblies_recovered: Some(1),
                    ..
                } if marker == "ps-aes-cbc-gzip"
            )),
            "echo-redirect simple AES trait was not emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_recovers_colon_delimited_payload_chunks() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url1 = "https://colon-simple-aes.example/first";
        let url2 = "https://colon-simple-aes.example/second";
        let mut pe1 = fake_pe_with_url(url1);
        let filler_start = pe1.len();
        pe1.resize(4096, 0);
        for (i, slot) in pe1[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(11);
        }
        let mut pe2 = fake_pe_with_url(url2);
        let filler_start = pe2.len();
        pe2.resize(4096, 0);
        for (i, slot) in pe2[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(13);
        }
        let b64_1 = aes256_gzip_b64(&pe1, &key, &iv);
        let b64_2 = aes256_gzip_b64(&pe2, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let raw = format!("@echo off\r\n::{b64_1}:{b64_2}\r\n");
        let deob = format!(
            "$aes=[System.Security.Cryptography.Aes]::Create();\
             $aes.Key=[System.Convert]::FromBase64String('{key_b64}');\
             $aes.IV=[System.Convert]::FromBase64String('{iv_b64}');\
             $parts=$line.Substring(2).Split(':');\
             $plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);"
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe1),
            "first colon-delimited PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe2),
            "second colon-delimited PE was not recovered: {:?}",
            env.recovered_pe
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_recovers_large_colon_delimited_payload_chunk() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url1 = "https://colon-simple-aes.example/large-first";
        let url2 = "https://colon-simple-aes.example/small-second";
        let mut pe1 = fake_pe_with_url(url1);
        let filler_start = pe1.len();
        pe1.resize(4 * 1024 * 1024 + 256 * 1024, 0);
        let mut state = 0x5eed_1234u32;
        for (idx, slot) in pe1[filler_start..].iter_mut().enumerate() {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *slot = (state as u8).wrapping_add((idx >> 16) as u8);
        }
        let mut pe2 = fake_pe_with_url(url2);
        pe2.resize(4096, 0x41);
        let b64_1 = aes256_gzip_b64(&pe1, &key, &iv);
        let b64_2 = aes256_gzip_b64(&pe2, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let raw = format!("@echo off\r\n::{b64_1}:{b64_2}\r\n");
        let deob = format!(
            "$aes=[System.Security.Cryptography.Aes]::Create();\
             $aes.Key=[System.Convert]::FromBase64String('{key_b64}');\
             $aes.IV=[System.Convert]::FromBase64String('{iv_b64}');\
             $parts=$line.Substring(2).Split(':');\
             $plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);"
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe1),
            "large colon-delimited PE was not recovered: {:?}",
            env.recovered_pe
                .iter()
                .map(|(label, bytes)| (label, bytes.len()))
                .collect::<Vec<_>>()
        );
        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe2),
            "small colon-delimited PE was not recovered after large chunk: {:?}",
            env.recovered_pe
                .iter()
                .map(|(label, bytes)| (label, bytes.len()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn raw_marker_line_lookup_avoids_full_raw_string_materialization() {
        let marker = "payload_marker_";
        let payload = "A".repeat(512);
        let raw = format!(
            "{}\r\n{marker}{payload}\r\n",
            "rem filler\r\n".repeat(16_384)
        );

        let found = find_raw_line_starting_with(raw.as_bytes(), marker.as_bytes());

        assert_eq!(
            found.and_then(|line| std::str::from_utf8(line).ok()),
            Some(format!("{marker}{payload}").as_str())
        );
    }

    #[test]
    fn self_marker_aes_gzip_payload_recovers_pe_without_gate() {
        let key: [u8; 16] = [
            0x20, 0x7b, 0x91, 0x4a, 0xf5, 0x0d, 0x32, 0x6c, 0x9e, 0x41, 0x88, 0x03, 0xa7, 0xdd,
            0x14, 0x59,
        ];
        let iv: [u8; 16] = [
            0xa0, 0x31, 0x6c, 0x11, 0x8b, 0x45, 0x72, 0xde, 0x39, 0xff, 0x06, 0xc2, 0x4b, 0x80,
            0x17, 0xea,
        ];
        let url = "https://self-marker-aes.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(2048, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        let original_b64 = aes_gzip_b64(&pe, &key, &iv);
        let b64 = original_b64.replace('/', "#").replace('A', "@");
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let marker = "nsiwjFslDvZfvwXwOXvp";
        let raw = format!("@echo off\r\n{marker}{b64}\\ignored\r\n");
        let deob = format!(
            r#"
$aes=New-Object System.Security.Cryptography.AesManaged;
$aes.Key=[System.Convert]::FromBase64String('{key_b64}');
$aes.IV=[System.Convert]::FromBase64String('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
$lines=[System.IO.File]::ReadAllText($wrlhT).Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith('{marker}')) {{ $payload=$line.Substring(20); break; }}
}}
$payloads=$payload.Split('\');
$payload1=decompress_function (decrypt_function ([Convert]::FromBase64String($payloads[0].Replace('#', '/').Replace('@', 'A'))));
[System.Reflection.Assembly]::Load([byte[]]$payload1)
"#
        );
        assert!(PS_DYNAMIC_KEY_B64_RE.captures(&deob).is_some());
        assert!(PS_DYNAMIC_IV_B64_RE.captures(&deob).is_some());
        assert!(PS_SELF_MARKER_RE.captures(&deob).is_some());
        assert!(contains_ascii_case_insensitive(&deob, "readalltext"));
        assert!(contains_ascii_case_insensitive(&deob, "startswith"));
        assert!(contains_ascii_case_insensitive(&deob, "substring"));
        assert!(contains_ascii_case_insensitive(&deob, "gzipstream"));
        assert!(contains_ascii_case_insensitive(&deob, "assembly]::load"));
        assert!(contains_ascii_case_insensitive(
            &deob,
            "transformfinalblock"
        ));
        let replacements = collect_replace_pairs(&deob);
        assert_eq!(apply_replace_pairs(&b64, &replacements), original_b64);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&original_b64)
            .unwrap();
        let plaintext = aes_cbc_decrypt(&key, &iv, &decoded).unwrap();
        assert_eq!(gunzip(&plaintext, MAX_STAGE_OUTPUT).unwrap(), pe);
        let payload_line = raw.lines().find(|line| line.starts_with(marker)).unwrap();
        let payload = &payload_line[20..];
        let first_chunk = payload.split('\\').next().unwrap();
        assert_eq!(
            apply_replace_pairs(first_chunk, &replacements),
            original_b64
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe),
            "self-marker AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    reads_self_lines: true,
                    assemblies_recovered: Some(1),
                    ..
                } if marker == "ps-self-marker-aes-cbc-gzip"
            )),
            "self-marker AES trait was not emitted: {:?}",
            env.traits
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "recovered PE URL was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn self_marker_aes_gzip_ignores_unrelated_delete_replace_pairs() {
        let key: [u8; 16] = *b"0123456789012345";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url = "https://self-marker-delete-noise.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(4096, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(43).wrapping_add(19);
        }
        let original_b64 = aes_gzip_b64(&pe, &key, &iv);
        let b64 = original_b64.replace('/', "#").replace('A', "@");
        let delete_noise = b64
            .as_bytes()
            .windows(2)
            .find_map(|window| {
                let s = std::str::from_utf8(window).ok()?;
                s.chars().all(|ch| ch.is_ascii_alphanumeric()).then_some(s)
            })
            .expect("base64 chunk contains alphanumeric pair");
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let marker = "ldvLy";
        let raw = format!("@echo off\r\n{marker}{b64}\\ignored\r\n");
        let deob = format!(
            r#"
Invoke-Expression '$junk=3x[System.Text.Encoding]3x::UTF8;'.Replace('{delete_noise}', '');
$aes=[System.Security.Cryptography.Aes]::Create();
$aes.Key=[System.Convert]::FromBase64String('{key_b64}');
$aes.IV=[System.Convert]::FromBase64String('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
$lines=[System.IO.File]::ReadAllText($self).Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith('{marker}')) {{ $payload=$line.Substring(5); break; }}
}}
$payloads=$payload.Split('\');
$payload1=decompress_function (decrypt_function ([Convert]::FromBase64String($payloads[0].Replace('#', '/').Replace('@', 'A'))));
[System.Reflection.Assembly]::Load([byte[]]$payload1)
"#
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe),
            "self-marker AES/GZip PE was not recovered when unrelated delete replacements were present: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "recovered PE URL was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn self_marker_aes_gzip_payload_recovers_pe_from_deobfuscated_marker_line() {
        let key: [u8; 16] = [
            0x20, 0x7b, 0x91, 0x4a, 0xf5, 0x0d, 0x32, 0x6c, 0x9e, 0x41, 0x88, 0x03, 0xa7, 0xdd,
            0x14, 0x59,
        ];
        let iv: [u8; 16] = [
            0xa0, 0x31, 0x6c, 0x11, 0x8b, 0x45, 0x72, 0xde, 0x39, 0xff, 0x06, 0xc2, 0x4b, 0x80,
            0x17, 0xea,
        ];
        let url = "https://self-marker-deob-only.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(2048, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(29).wrapping_add(7);
        }
        let original_b64 = aes_gzip_b64(&pe, &key, &iv);
        let b64 = original_b64.replace('/', "#").replace('A', "@");
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let marker = "nsiwjFslDvZfvwXwOXvp";
        let raw = "@echo off\r\nrem raw source has not exposed the marker payload line\r\n";
        let deob = format!(
            r#"{marker}{b64}\ignored
$aes=New-Object System.Security.Cryptography.AesManaged;
$aes.Key=[System.Convert]::FromBase64String('{key_b64}');
$aes.IV=[System.Convert]::FromBase64String('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
$lines=[System.IO.File]::ReadAllText($wrlhT).Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith('{marker}')) {{ $payload=$line.Substring(20); break; }}
}}
$payloads=$payload.Split('\');
$payload1=decompress_function (decrypt_function ([Convert]::FromBase64String($payloads[0].Replace('#', '/').Replace('@', 'A'))));
[System.Reflection.Assembly]::Load([byte[]]$payload1)
"#
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe),
            "self-marker AES/GZip PE was not recovered from deobfuscated marker line: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "recovered PE URL was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn self_marker_aes_gzip_accepts_star_replace_obfuscated_api_names() {
        let key: [u8; 16] = [
            0x20, 0x7b, 0x91, 0x4a, 0xf5, 0x0d, 0x32, 0x6c, 0x9e, 0x41, 0x88, 0x03, 0xa7, 0xdd,
            0x14, 0x59,
        ];
        let iv: [u8; 16] = [
            0xa0, 0x31, 0x6c, 0x11, 0x8b, 0x45, 0x72, 0xde, 0x39, 0xff, 0x06, 0xc2, 0x4b, 0x80,
            0x17, 0xea,
        ];
        let url = "https://self-marker-star-replace.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(2048, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(11);
        }
        let original_b64 = aes_gzip_b64(&pe, &key, &iv);
        let b64 = original_b64.replace('/', "#").replace('A', "@");
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let marker = "nsiwjFslDvZfvwXwOXvp";
        let raw = format!("@echo off\r\n{marker}{b64}\\ignored\r\n");
        let deob = format!(
            r#"
$aes=New-Object System.Security.Cryptography.AesManaged;
$aes.Key=[System.Convert]::FromBase64String('{key_b64}');
$aes.IV=[System.Convert]::FromBase64String('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
IEX '$gzip=New-Object System.IO.Compression.G*Z*ip*St*re*am($plain,[IO.Compression.CompressionMode]::Decompress);'.Replace('*', '');
$lines=[System.IO.File]::ReadAllText($wrlhT).Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith('{marker}')) {{ $payload=$line.Substring(20); break; }}
}}
$payloads=$payload.Split('\');
$payload1=decompress_function (decrypt_function ([Convert]::FromBase64String($payloads[0].Replace('#', '/').Replace('@', 'A'))));
IEX '[System.R*e*fl*ect*io*n.As*se*mb*l*y]::L*o*a*d([byte[]]$payload1)'.Replace('*', '');
"#
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe),
            "self-marker AES/GZip PE was not recovered through star-replace API gate: {:?}",
            env.recovered_pe
        );
    }

    #[test]
    fn self_marker_aes_gzip_accepts_reversed_string_member_names() {
        let key: [u8; 16] = *b"0123456789012345";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url = "https://self-marker-reversed-member.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(4096, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(13);
        }
        let b64 = aes_gzip_b64(&pe, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let marker = "SEROXEN";
        let raw = format!("@echo off\r\n{marker}{b64}\r\n");
        let deob = format!(
            r#"
$aes=[System.Security.Cryptography.Aes]::Create();
$aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;
$aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;
$aes.Key=[System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('{key_b64}');
$aes.IV=[System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
$lines=[System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')($self).Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith('{marker}')) {{ $payload=$line.Substring(7); break; }}
}}
$payloads=$payload.Split('\');
$payload1=RMuWl (AZiex ([Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($payloads[0])));
[System.Reflection.Assembly]::('daoL'[-1..-4] -join '')([byte[]]$payload1)
"#
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe),
            "self-marker AES/GZip PE was not recovered through reversed member names: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "recovered PE URL was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn self_marker_aes_gzip_accepts_colon_space_marker() {
        let key: [u8; 16] = *b"0123456789012345";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url = "https://self-marker-colon-space.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(4096, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(41).wrapping_add(17);
        }
        let b64 = aes_gzip_b64(&pe, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let raw = format!("@echo off\r\n:: {b64}\r\n");
        let deob = format!(
            r#"
$aes=[System.Security.Cryptography.Aes]::Create();
$aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;
$aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;
$aes.Key=[System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('{key_b64}');
$aes.IV=[System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('{iv_b64}');
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
$lines=[System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')($self).Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith(':: ')) {{ $payload=$line.Substring(3); break; }}
}}
$payloads=$payload.Split('\');
$payload1=RMuWl (AZiex ([Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($payloads[0])));
[System.Reflection.Assembly]::('daoL'[-1..-4] -join '')([byte[]]$payload1)
"#
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe),
            "self-marker AES/GZip PE was not recovered through :: marker: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "recovered PE URL was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn self_marker_aes_accepts_direct_pe_without_gzip() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url1 = "https://self-marker-direct-pe.example/first";
        let url2 = "https://self-marker-direct-pe.example/second";
        let mut pe1 = fake_pe_with_url(url1);
        pe1.push(0);
        pe1.resize(5120, 0x41);
        let mut pe2 = fake_pe_with_url(url2);
        pe2.push(0);
        pe2.resize(6144, 0x42);
        let b64_1 = aes256_plain_b64(&pe1, &key, &iv);
        let b64_2 = aes256_plain_b64(&pe2, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let raw = format!("@echo off\r\n:: {b64_1}\\{b64_2}\r\n");
        let deob = format!(
            r#"
$aes=[System.Security.Cryptography.Aes]::Create();
$aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;
$aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;
$aes.Key=[System.Convert]::FromBase64String('{key_b64}');
$aes.IV=[System.Convert]::FromBase64String('{iv_b64}');
function decrypt_function($param_var) {{
  $dec=$aes.CreateDecryptor();
  $dec.TransformFinalBlock($param_var,0,$param_var.Length);
}}
$self=[System.IO.File]::ReadAllText('%~f0');
$lines=$self.Split([Environment]::NewLine);
foreach ($line in $lines) {{
  if ($line.StartsWith(':: ')) {{ $payload=$line.Substring(3); break; }}
}}
$payloads=$payload.Split('\');
$payload1=decrypt_function ([Convert]::FromBase64String($payloads[0]));
$payload2=decrypt_function ([Convert]::FromBase64String($payloads[1]));
[System.Reflection.Assembly]::Load([byte[]]$payload1)
[System.Reflection.Assembly]::Load([byte[]]$payload2)
"#
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe1),
            "first direct PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-self-marker-aes-asm") && bytes == &pe2),
            "second direct PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url1 && line_hint == "aes-chain"
            )),
            "first recovered PE URL was not extracted: {:?}",
            env.traits
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    has_gzip_stage: false,
                    reads_self_lines: true,
                    assemblies_recovered: Some(2),
                    ..
                } if marker == "ps-self-marker-aes-cbc"
            )),
            "direct self-marker AES trait was not emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps_base64_aes_gzip_payload_accepts_damaged_byte_array_heads() {
        let key: [u8; 16] = [
            b'v', b'9', 0x91, 0x4a, 0xf5, 0x0d, 0x32, 0x6c, 0x9e, 0x41, 0x88, 0x03, 0xa7, 0xdd,
            0x14, 0x59,
        ];
        let iv: [u8; 16] = [
            b'A', b'z', 0x6c, 0x11, 0x8b, 0x45, 0x72, 0xde, 0x39, 0xff, 0x06, 0xc2, 0x4b, 0x80,
            0x17, 0xea,
        ];
        let pe = fake_pe_with_url("https://damaged-byte-head.example/payload");
        let b64 = aes_gzip_b64(&pe, &key, &iv);
        let key_tail = byte_array(&key[2..]);
        let iv_tail = byte_array(&iv[2..]);
        let deob = format!(
            r#"
$stageBytes=('{b64}');
$blob=[Convert]::FromBase64String($stageBytes);
$aes=New-Object System.Security.Cryptography.AesManaged;
$aes.Key=[byv9,{key_tail});
$aes.IV=[byAz,{iv_tail});
$plain=$aes.CreateDecryptor().TransformFinalBlock($blob,0,$blob.Length);
$gzip=New-Object System.IO.Compression.GZipStream($plain,[IO.Compression.CompressionMode]::Decompress);
"#
        );
        let mut env = gated_env(b64.len());

        extract_from_chain(b"", &deob, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-b64-aes-asm") && bytes == &pe),
            "recovered_pe: {:?}",
            env.recovered_pe
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_payload_recovers_pe_without_gate() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let url = "https://simple-aes.example/payload";
        let mut pe = fake_pe_with_url(url);
        let filler_start = pe.len();
        pe.resize(2048, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let b64 = aes256_gzip_b64(&pe, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let script = format!(
            "@echo off\r\n\
             set \"EtnCTS=$a.Key=[System.Convert]::FromBase64String('{key_b64}');\
             $a.IV=[System.Convert]::FromBase64String('{iv_b64}');\"\r\n\
             :: {b64}\r\n"
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(script.as_bytes(), &script, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-aes-stage1-asm") && bytes == &pe),
            "simple AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    aes_key_b64: Some(_),
                    aes_iv_b64: Some(_),
                    assemblies_recovered: Some(1),
                    ..
                } if marker == "ps-aes-cbc-gzip"
            )),
            "dropper trait was not annotated: {:?}",
            env.traits
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::DownloadInDeobText { src, line_hint }
                    if src == url && line_hint == "aes-chain"
            )),
            "recovered PE URL was not extracted: {:?}",
            env.traits
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_recovers_marker_stripped_key_and_multiple_lines() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let mut pe1 = fake_pe_with_url("https://simple-aes-lines.example/one");
        let mut pe2 = fake_pe_with_url("https://simple-aes-lines.example/two");
        let filler_start_1 = pe1.len();
        pe1.resize(2048, 0);
        for (i, slot) in pe1[filler_start_1..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(23).wrapping_add(17);
        }
        let filler_start_2 = pe2.len();
        pe2.resize(2048, 0);
        for (i, slot) in pe2[filler_start_2..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(19);
        }
        let b64_1 = aes256_gzip_b64(&pe1, &key, &iv);
        let b64_2 = aes256_gzip_b64(&pe2, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let ps = format!(
            "$a.Key=[System.Convert]::FromBase64String('{key_b64}');\
             $a.IV=[System.Convert]::FromBase64String('{iv_b64}');"
        );
        let mut noisy_ps = String::new();
        for ch in ps.chars() {
            noisy_ps.push(ch);
            noisy_ps.push_str("lxodr");
        }
        let script = format!(
            "@echo off\r\n\
             set \"EtnCTS={noisy_ps}\"\r\n\
             echo %EtnCTS:lxodr=% | powershell.exe\r\n\
             ::{b64_1}\r\n\
             ::{b64_2}\r\n"
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(script.as_bytes(), &script, &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe1),
            "first marker-stripped AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe2),
            "second marker-stripped AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    assemblies_recovered: Some(2),
                    ..
                } if marker == "ps-aes-cbc-gzip"
            )),
            "dropper trait did not record both assemblies: {:?}",
            env.traits
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_recovers_key_iv_from_payload_chunks() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let mut pe1 = fake_pe_with_url("https://simple-aes-trailing-key.example/one");
        let mut pe2 = fake_pe_with_url("https://simple-aes-trailing-key.example/two");
        let filler_start_1 = pe1.len();
        pe1.resize(2048, 0);
        for (i, slot) in pe1[filler_start_1..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(5);
        }
        let filler_start_2 = pe2.len();
        pe2.resize(2048, 0);
        for (i, slot) in pe2[filler_start_2..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(41).wrapping_add(9);
        }
        let b64_1 = aes256_gzip_b64(&pe1, &key, &iv);
        let b64_2 = aes256_gzip_b64(&pe2, &key, &iv);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let script = format!(
            "@echo off\r\n\
             powershell -c \"System.Security.Cryptography.Aes;GZipStream;Assembly]::Load\"\r\n\
             ::{b64_1}\\{b64_2}\\{key_b64}\\{iv_b64}\r\n"
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(script.as_bytes(), &script, &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe1),
            "first trailing-key AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe2),
            "second trailing-key AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    aes_key_b64: Some(found_key),
                    aes_iv_b64: Some(found_iv),
                    assemblies_recovered: Some(2),
                    ..
                } if found_key == &key_b64 && found_iv == &iv_b64
            )),
            "dropper trait did not record trailing key/IV: {:?}",
            env.traits
        );
    }

    #[test]
    fn self_tail_split_reversed_ps_aes_gzip_recovers_assemblies() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let mut pe1 = fake_pe_with_url("https://split-reversed-aes.example/one");
        let mut pe2 = fake_pe_with_url("https://split-reversed-aes.example/two");
        pe1.resize(2048, 0x41);
        pe2.resize(2048, 0x42);
        let b64_1: String = aes256_gzip_b64(&pe1, &key, &iv).chars().rev().collect();
        let b64_2: String = aes256_gzip_b64(&pe2, &key, &iv).chars().rev().collect();
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let deob = format!(
            "$aes=New-Object System.Security.Cryptography.AesManaged;\
             $aes.Key=[System.Convert]::FromBase64String('{key_b64}');\
             $aes.IV=[System.Convert]::FromBase64String('{iv_b64}');\
             $lines=[System.IO.File]::ReadAllLines($env:sample);\
             $last=$lines[$lines.Length-1];\
             $parts=[string[]]$last.Split('\\');\
             $left=$parts[0].ToCharArray();[Array]::Reverse($left);$parts[0]=-join $left;\
             $right=$parts[1].ToCharArray();[Array]::Reverse($right);$parts[1]=-join $right;\
             $plain=$aes.CreateDecryptor().TransformFinalBlock([Convert]::FromBase64String($parts[0]),0,$parts[0].Length);\
             New-Object System.IO.Compression.GZipStream;\
             [System.Reflection.Assembly]::Load($plain)"
        );
        let raw = format!("@echo off\r\npowershell -c \"{deob}\"\r\n{b64_1}\\{b64_2}\r\n");
        let mut env = Environment::new(&Config::default());

        extract_from_chain(raw.as_bytes(), &deob, &mut env);

        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe1),
            "first split-reversed AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.recovered_pe.iter().any(|(_, bytes)| bytes == &pe2),
            "second split-reversed AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
        assert!(
            env.traits.iter().any(|trait_| matches!(
                trait_,
                Trait::MultiStageEncryptedDropper {
                    marker,
                    reads_self_lines: true,
                    assemblies_recovered: Some(2),
                    ..
                } if marker == "ps-self-tail-split-reversed-aes-cbc-gzip"
            )),
            "split-reversed AES/GZip trait was not emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn simple_raw_ps_aes_gzip_payload_recovers_cash_marker_carrier() {
        let key: [u8; 32] = *b"01234567890123456789012345678901";
        let iv: [u8; 16] = *b"abcdefghijklmnop";
        let mut pe = fake_pe_with_url("https://cash-marker-aes.example/payload");
        let filler_start = pe.len();
        pe.resize(2048, 0);
        for (i, slot) in pe[filler_start..].iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(29).wrapping_add(11);
        }
        let b64 = aes256_gzip_b64(&pe, &key, &iv);
        let noisy_b64 = cash_marker_noise(&b64);
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);
        let script = format!(
            "@echo off\r\n\
             powershell -c \"$a.Key=[System.Convert]::'FromBase64String'('{key_b64}');\
             $a.IV=[System.Convert]::'FromBase64String'('{iv_b64}');\"\r\n\
             :: @{noisy_b64}\r\n"
        );
        let mut env = Environment::new(&Config::default());

        extract_from_chain(script.as_bytes(), &script, &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, bytes)| label.starts_with("ps-aes-stage1-asm") && bytes == &pe),
            "marker-polluted AES/GZip PE was not recovered: {:?}",
            env.recovered_pe
        );
    }
}
