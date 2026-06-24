//! Glue for the AES dropper chain. Gated by the presence of a
//! `MultiStageEncryptedDropper` trait that the deob_scan detector
//! already emitted.

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

    #[test]
    fn no_op_without_gate_trait() {
        let mut env = Environment::new(&Config::default());
        let big_b64 = "A".repeat(2000);
        let deob = format!("'{big_b64}'.Replace('xxx','')");
        extract_from_chain(b"", &deob, &mut env);
        // No gate trait → nothing happens.
        assert!(env.traits.is_empty());
    }
}
