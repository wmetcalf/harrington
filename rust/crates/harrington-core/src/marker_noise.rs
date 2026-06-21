//! Repeated-substring noise stripper shared between the CMD-side normalizer
//! and the PowerShell payload pipeline.
//!
//! Obfuscators insert short marker runs between every source character
//! (`pow#XYZ#ershell` -> `powershell`). This pass enumerates 3-8 char alpha
//! ngrams, finds those with sandwich-pattern evidence (≥2 occurrences inside
//! a single alphabetic run), and strips them line-by-line. The sandwich
//! requirement prevents natural shared substrings (like `ell` in
//! `Hello` + `powershell`) from being stripped — that was a real regression
//! before [[strip-marker-noise-sandwich-bug]] was fixed.
//!
//! Two callers (`normalize::strip_marker_noise` for CMD output, and
//! `ps1_scan::strip_marker_noise` for PS payload bodies) wrap this with
//! their own per-context gate predicates but share the underlying algorithm
//! and the protected-keyword list. Keeping them in one place prevents
//! drift — both copies used to live inline in each module and were
//! starting to diverge.

use base64::Engine as _;
use std::collections::HashMap;

<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
pub(crate) const MAX_SCAN_BYTES: usize = 512 * 1024;
=======
const MAX_SCAN_BYTES: usize = 512 * 1024;
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
const MIN_MARKER_LEN: usize = 3;
const MAX_MARKER_LEN: usize = 8;
const MIN_MIXED_CASE_COUNT: usize = 5;
const MIN_ALL_CAPS_COUNT: usize = 20;
const MIN_B64_RUN: usize = 64;

<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MarkerCandidate {
    len: u8,
    bytes: [u8; MAX_MARKER_LEN],
}

impl MarkerCandidate {
    fn from_ascii(candidate: &[u8]) -> Option<Self> {
        if candidate.is_empty() || candidate.len() > MAX_MARKER_LEN || !candidate.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; MAX_MARKER_LEN];
        bytes[..candidate.len()].copy_from_slice(candidate);
        Some(Self {
            len: candidate.len() as u8,
            bytes,
        })
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

=======
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
/// Strip repeated-marker noise from a single line of (already-line-split)
/// text. Bounded by MAX_SCAN_BYTES per call and up to 4 inner passes.
pub fn strip_line(text: &str) -> String {
    if text.len() > MAX_SCAN_BYTES {
        return text.to_string();
    }
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
    if !has_repeated_sandwich_candidate_shape(text) {
        return text.to_string();
    }
=======
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
    let mut out = text.to_string();
    for _ in 0..4 {
        let bytes = out.as_bytes();
        let run_ids = enclosing_alpha_run_ids(bytes);
        let run_strings = collect_alpha_run_strings(bytes);
        type Counts = (usize, usize, usize, bool, HashMap<usize, usize>);
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
        let mut counts: HashMap<MarkerCandidate, Counts> = HashMap::new();
=======
        let mut counts: HashMap<String, Counts> = HashMap::new();
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs

        for start in 0..bytes.len() {
            for len in MIN_MARKER_LEN..=MAX_MARKER_LEN {
                let end = start + len;
                if end > bytes.len() {
                    break;
                }
                let candidate = &bytes[start..end];
                if !candidate.iter().all(|b| b.is_ascii_alphabetic()) {
                    continue;
                }
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
                if !candidate_has_multiple_distinct_bytes(candidate) {
                    continue;
                }
                let Some(candidate_key) = MarkerCandidate::from_ascii(candidate) else {
                    continue;
                };
                if is_protected_marker_candidate(candidate_key.as_str()) {
                    continue;
                }
                let is_mixed = candidate.iter().any(|b| b.is_ascii_lowercase())
                    && candidate.iter().any(|b| b.is_ascii_uppercase());
                let vowel_count = candidate
                    .iter()
                    .filter(|b| matches!(b.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u'))
                    .count();
                let embedded = (start > 0 && bytes[start - 1].is_ascii_alphabetic())
                    || (end < bytes.len() && bytes[end].is_ascii_alphabetic());
                let entry = counts.entry(candidate_key).or_insert((
=======
                let Ok(candidate) = std::str::from_utf8(candidate) else {
                    continue;
                };
                if is_protected_marker_candidate(candidate) {
                    continue;
                }
                if candidate
                    .chars()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    < 2
                {
                    continue;
                }
                let is_mixed = candidate.chars().any(|c| c.is_ascii_lowercase())
                    && candidate.chars().any(|c| c.is_ascii_uppercase());
                let vowel_count = candidate
                    .chars()
                    .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
                    .count();
                let embedded = (start > 0 && bytes[start - 1].is_ascii_alphabetic())
                    || (end < bytes.len() && bytes[end].is_ascii_alphabetic());
                let entry = counts.entry(candidate.to_string()).or_insert((
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
                    0,
                    0,
                    vowel_count,
                    is_mixed,
                    HashMap::new(),
                ));
                entry.0 += 1;
                if embedded {
                    entry.1 += 1;
                    if let Some(rid) = run_ids.get(start).copied().flatten() {
                        *entry.4.entry(rid).or_insert(0) += 1;
                    }
                }
                entry.2 = entry.2.min(vowel_count);
                entry.3 |= is_mixed;
            }
        }

        let mut markers: Vec<(String, usize, usize)> = counts
            .iter()
            .filter_map(
                |(candidate, (count, embedded_count, vowel_count, is_mixed, per_run))| {
                    // Sandwich noise interleaves a marker between source
                    // chars, so the marker appears multiple times INSIDE a
                    // single alphabetic run. Natural shared substrings like
                    // `ell` in `Hello` + `powershell` appear at most once
                    // per enclosing word.
                    //
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
                    // A candidate is useful only if it repeats inside at
                    // least one alphabetic run. That covers the single-run
                    // marker noise shape (`aXYZbXYZ...`) while still
                    // rejecting ordinary one-off substrings like `ell` in
                    // `powershell`.
                    let mut sandwich_run_contents: std::collections::HashSet<&str> =
                        std::collections::HashSet::new();
                    let mut qualifying_runs = 0usize;
=======
                    // Dedupe runs by CONTENT — a variable name reused N
                    // times in a script counts as one sandwich "host", not
                    // N. Without this, `$Oversigtsbilleders173` (one var
                    // containing `ers` twice, used N×) made `ers` qualify
                    // as noise and got stripped from `powershell` →
                    // `powhell`. (e5ebe4d8... Danish PS family.)
                    let mut sandwich_run_contents: std::collections::HashSet<&str> =
                        std::collections::HashSet::new();
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
                    for (rid, n) in per_run.iter() {
                        if *n < 2 {
                            continue;
                        }
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
                        qualifying_runs += 1;
=======
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
                        if let Some(s) = run_strings.get(*rid).map(|s| s.as_str()) {
                            sandwich_run_contents.insert(s);
                        }
                    }
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
                    let has_sandwich = qualifying_runs == 1 || sandwich_run_contents.len() >= 2;
                    let qualifies = if *is_mixed {
                        has_sandwich
                            && (*embedded_count >= MIN_MIXED_CASE_COUNT
                                || (*count >= MIN_MIXED_CASE_COUNT && *vowel_count <= 1))
                    } else {
                        has_sandwich
                            && ((*embedded_count >= MIN_MIXED_CASE_COUNT
                                && *count >= MIN_MIXED_CASE_COUNT
                                && *vowel_count <= 1)
                                || (*count >= MIN_ALL_CAPS_COUNT && *vowel_count <= 1))
                    };
                    if qualifies {
                        Some((candidate.as_str().to_string(), *count, *vowel_count))
=======
                    let has_sandwich = sandwich_run_contents.len() >= 2;
                    // Single-run obfuscators can keep the whole payload in
                    // one alpha run (`aXYZbXYZ...`). Require a heavier
                    // repetition floor here so we do not re-strip ordinary
                    // repeated trigrams embedded in one real token.
                    let has_single_run_sandwich = sandwich_run_contents.len() == 1
                        && per_run.values().copied().max().unwrap_or(0) >= 5;
                    let qualifies = if *is_mixed {
                        (has_sandwich
                            && (*embedded_count >= MIN_MIXED_CASE_COUNT
                                || (*count >= MIN_MIXED_CASE_COUNT && *vowel_count <= 1)))
                            || (has_single_run_sandwich && *vowel_count <= 1)
                    } else {
                        (has_sandwich
                            && ((*embedded_count >= MIN_MIXED_CASE_COUNT
                                && *count >= MIN_MIXED_CASE_COUNT
                                && *vowel_count <= 1)
                                || (*count >= MIN_ALL_CAPS_COUNT && *vowel_count <= 1)))
                            || (has_single_run_sandwich && *vowel_count <= 1)
                    };
                    if qualifies {
                        Some((candidate.clone(), *count, *vowel_count))
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
                    } else {
                        None
                    }
                },
            )
            .collect();
        if markers.is_empty() {
            break;
        }

        markers.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.0.len().cmp(&a.0.len()))
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| b.0.cmp(&a.0))
        });
        let mut changed = false;
        for (marker, _, _) in markers {
            if !out.contains(&marker) {
                continue;
            }
            out = out.replace(&marker, "");
            changed = true;
        }
        if !changed {
            break;
        }
        if !decodable_base64_spans(&out).is_empty() {
            break;
        }
    }
    out
}

<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
pub(crate) fn has_repeated_sandwich_candidate_shape(text: &str) -> bool {
    // The real stripper requires repeated 3-byte marker evidence inside a
    // single alphabetic run. We only need a cheap shape check here, so we
    // look for any repeated 3-byte alphabetic substring inside a run. That
    // catches single-run marker noise like `aXYZbXYZ...` without turning
    // normal long words into false positives.
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let run = &bytes[start..i];
        if run.len() < MIN_MARKER_LEN * 2 {
            continue;
        }
        let mut seen: std::collections::HashSet<[u8; MIN_MARKER_LEN]> =
            std::collections::HashSet::new();
        for window in run.windows(MIN_MARKER_LEN) {
            let mut key = [0u8; MIN_MARKER_LEN];
            key.copy_from_slice(window);
            if !seen.insert(key) {
                return true;
            }
        }
    }
    false
}

=======
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
/// Find byte spans within `text` that look like ASCII-alphanumeric base64
/// runs of at least 64 chars whose decoded bytes look textual or UTF-16LE.
/// Used to PRESERVE base64 literals when stripping marker noise around them.
pub fn decodable_base64_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (idx, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
            start.get_or_insert(idx);
        } else if let Some(s) = start.take() {
            if idx.saturating_sub(s) >= MIN_B64_RUN && decodes_as_base64(&text[s..idx]) {
                spans.push((s, idx));
            }
        }
    }
    if let Some(s) = start {
        if text.len().saturating_sub(s) >= MIN_B64_RUN && decodes_as_base64(&text[s..]) {
            spans.push((s, text.len()));
        }
    }
    spans
}

fn decodes_as_base64(s: &str) -> bool {
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) else {
        return false;
    };
    decoded_looks_textual(&decoded) || decoded_looks_utf16le(&decoded)
}

fn decoded_looks_textual(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
        .count();
    printable * 100 / bytes.len() >= 60
}

fn decoded_looks_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 8 || bytes.len() % 2 != 0 {
        return false;
    }
    let pairs = bytes.len() / 2;
    let nul_hi = bytes.chunks_exact(2).filter(|pair| pair[1] == 0).count();
    nul_hi * 100 / pairs >= 50
}

<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
=======
fn collect_alpha_run_strings(bytes: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        // Safe — bytes are all ASCII alphabetic in the slice.
        let s = std::str::from_utf8(&bytes[start..i])
            .unwrap_or("")
            .to_string();
        runs.push(s);
    }
    runs
}

>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
fn enclosing_alpha_run_ids(bytes: &[u8]) -> Vec<Option<usize>> {
    let mut ids = vec![None; bytes.len()];
    let mut next = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let id = next;
        next += 1;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            ids[i] = Some(id);
            i += 1;
        }
    }
    ids
}

<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
fn collect_alpha_run_strings(bytes: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        // Safe — bytes are all ASCII alphabetic in the slice.
        let s = std::str::from_utf8(&bytes[start..i])
            .unwrap_or("")
            .to_string();
        runs.push(s);
    }
    runs
}

fn is_protected_marker_candidate(candidate: &str) -> bool {
    [
        "system", "object", "string", "convert", "security", "crypto", "graphy", "length",
        "invoke", "request",
    ]
    .iter()
    .any(|protected| candidate.eq_ignore_ascii_case(protected))
}

fn candidate_has_multiple_distinct_bytes(candidate: &[u8]) -> bool {
    let Some(first) = candidate.first() else {
        return false;
    };
    candidate.iter().any(|byte| byte != first)
=======
fn is_protected_marker_candidate(candidate: &str) -> bool {
    matches!(
        candidate.to_ascii_lowercase().as_str(),
        "system"
            | "object"
            | "string"
            | "convert"
            | "security"
            | "crypto"
            | "graphy"
            | "length"
            | "invoke"
            | "request"
    )
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
}

#[cfg(test)]
mod tests {
<<<<<<< HEAD:rust/crates/harrington-core/src/marker_noise.rs
    use super::{
        candidate_has_multiple_distinct_bytes, has_repeated_sandwich_candidate_shape,
        is_protected_marker_candidate, strip_line, MarkerCandidate,
    };

    #[test]
    fn strip_line_keeps_plain_assignment_without_marker_shape() {
        let line = r#"set "Ynclwtharj=INIMIZ" & set "Gopsadtjgt=& star""#;
        assert_eq!(strip_line(line), line);
    }

    #[test]
    fn strip_line_removes_repeated_sandwich_marker_shape() {
        assert_eq!(strip_line("aXYZbXYZcXYZ dXYZeXYZ"), "abc de");
    }

    #[test]
    fn sandwich_shape_detects_single_valid_run() {
        assert!(has_repeated_sandwich_candidate_shape("aXYZbXYZ"));
        assert!(!has_repeated_sandwich_candidate_shape("aXYZb"));
    }

    #[test]
    fn candidate_distinct_check_matches_ascii_marker_semantics() {
        assert!(!candidate_has_multiple_distinct_bytes(b"AAA"));
        assert!(candidate_has_multiple_distinct_bytes(b"AaA"));
        assert!(candidate_has_multiple_distinct_bytes(b"ABC"));
    }

    #[test]
    fn protected_marker_check_is_ascii_case_insensitive() {
        assert!(is_protected_marker_candidate("SyStEm"));
        assert!(!is_protected_marker_candidate("SyStXm"));
    }

    #[test]
    fn marker_candidate_key_preserves_length_and_case() {
        let abc = MarkerCandidate::from_ascii(b"ABC");
        let abc_long = MarkerCandidate::from_ascii(b"ABCX");
        let lower = MarkerCandidate::from_ascii(b"abc");

        assert!(matches!(abc, Some(key) if key.as_str() == "ABC"));
        assert_ne!(abc, abc_long);
        assert_ne!(abc, lower);
=======
    use super::strip_line;

    #[test]
    fn single_run_repeated_marker_noise_is_stripped() {
        let noisy = "aXYZbXYZcXYZdXYZeXYZ";
        assert_eq!(strip_line(noisy), "abcde");
    }

    #[test]
    fn repeated_plain_token_is_not_stripped() {
        let noisy = "abcabcabcabc";
        assert_eq!(strip_line(noisy), noisy);
>>>>>>> 5afae56 (marker_noise: handle single-run marker strips):rust/crates/batdeob-core/src/marker_noise.rs
    }
}
