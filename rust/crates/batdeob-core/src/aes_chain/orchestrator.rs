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

#[allow(clippy::expect_used)]
static STAGE1_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"'([^']{200,})'\s*\.\s*Replace\s*\(\s*'([^']{2,40})'\s*,\s*''\s*\)")
        .expect("stage1 re")
});

#[allow(clippy::expect_used)]
static PS_KEY_BYTES_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\.Key\s*=\s*(?:\[\s*byte\s*\[\s*\]\s*\]\s*@?\(\s*([^)]+)\)|\[\s*(by[0-9A-Za-z]{2}\s*,[^)]+)\))")
        .expect("ps key bytes re")
});

#[allow(clippy::expect_used)]
static PS_IV_BYTES_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)\.IV\s*=\s*(?:\[\s*byte\s*\[\s*\]\s*\]\s*@?\(\s*([^)]+)\)|\[\s*(by[0-9A-Za-z]{2}\s*,[^)]+)\))")
        .expect("ps iv bytes re")
});

#[allow(clippy::expect_used)]
static PS_B64_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*\(?\s*['"]([A-Za-z0-9+/=]{80,})['"]\s*\)?"#)
        .expect("ps b64 assignment re")
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

    try_extract_ps_base64_aes_gzip(deob, env);

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
    }
}

fn has_ps_base64_aes_gzip_indicators(deob: &str) -> bool {
    contains_ascii_case_insensitive(deob, "aesmanaged")
        && contains_ascii_case_insensitive(deob, "frombase64string")
        && contains_ascii_case_insensitive(deob, "transformfinalblock")
        && contains_ascii_case_insensitive(deob, "gzip")
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

    if blob.starts_with(b"MZ") {
        if let Ok(us_strings) = super::dotnet::extract_us_strings(blob) {
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

    for url in scan::scan_urls(blob, MAX_URLS_PER_SAMPLE) {
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

    fn byte_array(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(",")
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
}
