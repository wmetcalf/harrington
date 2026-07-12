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

const MAX_SCAN_BYTES: usize = 64 * 1024;
const MIN_MARKER_LEN: usize = 3;
const MAX_MARKER_LEN: usize = 8;
const MIN_MIXED_CASE_COUNT: usize = 5;
const MIN_ALL_CAPS_COUNT: usize = 20;
const MIN_B64_RUN: usize = 64;

/// Strip repeated-marker noise from a single line of (already-line-split)
/// text. Bounded by MAX_SCAN_BYTES per call and up to 4 inner passes.
pub fn strip_line(text: &str) -> String {
    if text.len() > MAX_SCAN_BYTES {
        return text.to_string();
    }
    let mut out = text.to_string();
    for _ in 0..4 {
        let bytes = out.as_bytes();
        let run_ids = enclosing_alpha_run_ids(bytes);
        let run_strings = collect_alpha_run_strings(bytes);
        type Counts = (usize, usize, usize, bool, HashMap<usize, usize>);
        let mut counts: HashMap<String, Counts> = HashMap::new();

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
                let Ok(candidate) = std::str::from_utf8(candidate) else {
                    continue;
                };
                if is_protected_marker_candidate(candidate) {
                    continue;
                }
                if !candidate_has_multiple_distinct_bytes(candidate.as_bytes()) {
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
                    // Dedupe runs by CONTENT — a variable name reused N
                    // times in a script counts as one sandwich "host", not
                    // N. Without this, `$Oversigtsbilleders173` (one var
                    // containing `ers` twice, used N×) made `ers` qualify
                    // as noise and got stripped from `powershell` →
                    // `powhell`. (e5ebe4d8... Danish PS family.)
                    let mut sandwich_run_contents: std::collections::HashSet<&str> =
                        std::collections::HashSet::new();
                    for (rid, n) in per_run.iter() {
                        if *n < 2 {
                            continue;
                        }
                        if let Some(s) = run_strings.get(*rid).map(|s| s.as_str()) {
                            sandwich_run_contents.insert(s);
                        }
                    }
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
    strip_unicode_marker_islands(&out)
}

pub fn strip_unicode_marker_islands(text: &str) -> String {
    if text.is_ascii() || text.len() > MAX_SCAN_BYTES {
        return text.to_string();
    }

    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].1.is_ascii_alphanumeric() {
            i += 1;
            continue;
        }

        let start_idx = i;
        let start = chars[start_idx].0;
        while i < chars.len() && !chars[i].1.is_ascii_alphanumeric() {
            i += 1;
        }
        let end = chars.get(i).map(|(idx, _)| *idx).unwrap_or(text.len());
        let prev = start_idx.checked_sub(1).and_then(|idx| chars.get(idx));
        let next = chars.get(i);
        let candidate = &text[start..end];
        for (marker_start, marker_end) in unicode_marker_subspans(candidate) {
            if marker_subspan_is_probable_assignment_name(candidate, marker_end) {
                continue;
            }
            let marker_abs_start = start + marker_start;
            let marker_abs_end = start + marker_end;

            if (prev.is_some_and(|(_, ch)| ch.is_ascii_alphanumeric())
                || next.is_some_and(|(_, ch)| ch.is_ascii_alphanumeric()))
                && is_unicode_marker_island(&text[marker_abs_start..marker_abs_end])
            {
                spans.push((marker_abs_start, marker_abs_end));
            }
        }
    }

    if spans.is_empty() {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end) in &spans {
        out.push_str(&text[cursor..*start]);
        cursor = *end;
    }
    out.push_str(&text[cursor..]);
    if spans.len() >= 2 || has_batch_command_signal_after_unicode_strip(&out) {
        out
    } else {
        text.to_string()
    }
}

fn unicode_marker_subspans(candidate: &str) -> Vec<(usize, usize)> {
    if candidate.starts_with('%') && candidate.ends_with('%') && candidate.len() >= 2 {
        return vec![(0, candidate.len())];
    }

    let mut spans = Vec::new();
    let mut segment_start: Option<usize> = None;
    let mut first_non_ascii: Option<usize> = None;
    let mut last_non_ascii: Option<usize> = None;

    for (idx, ch) in candidate.char_indices() {
        if ch.is_ascii_alphanumeric() || is_structural_ascii_separator(ch) {
            if let (Some(first), Some(last)) = (first_non_ascii, last_non_ascii) {
                spans.push((first, last));
            }
            segment_start = None;
            first_non_ascii = None;
            last_non_ascii = None;
            continue;
        }

        if segment_start.is_none() {
            segment_start = Some(idx);
        }
        if !ch.is_ascii() {
            first_non_ascii.get_or_insert(segment_start.unwrap_or(idx));
            last_non_ascii = Some(idx + ch.len_utf8());
        }
    }
    if let (Some(first), Some(last)) = (first_non_ascii, last_non_ascii) {
        spans.push((first, last));
    }
    spans
}

fn is_structural_ascii_separator(ch: char) -> bool {
    matches!(
        ch,
        '&' | '|' | '<' | '>' | '=' | '"' | '\'' | ',' | ';' | ':' | '[' | ']'
    )
}

fn marker_subspan_is_probable_assignment_name(candidate: &str, marker_end: usize) -> bool {
    candidate
        .get(marker_end..)
        .is_some_and(|tail| tail.trim_start().starts_with('='))
}

fn is_unicode_marker_island(candidate: &str) -> bool {
    if candidate.len() > 4096 {
        return false;
    }
    let mut non_ascii_bytes = 0usize;
    for ch in candidate.chars() {
        if ch.is_ascii_alphanumeric() {
            return false;
        }
        if matches!(ch, '&' | '|' | '<' | '>' | '=' | '"' | '\'') {
            return false;
        }
        if !ch.is_ascii() {
            non_ascii_bytes += ch.len_utf8();
        }
    }
    non_ascii_bytes >= 3
}

fn has_batch_command_signal_after_unicode_strip(text: &str) -> bool {
    let trimmed = text.trim_start_matches(|c: char| c == '@' || c == '(' || c.is_whitespace());
    let command = trimmed
        .split(|c: char| !c.is_ascii_alphabetic())
        .next()
        .unwrap_or("");
    matches_any_ascii_case_insensitive(
        command,
        &[
            "assoc",
            "attrib",
            "bitsadmin",
            "call",
            "cd",
            "certutil",
            "chcp",
            "cls",
            "cmd",
            "copy",
            "cscript",
            "curl",
            "del",
            "echo",
            "erase",
            "exit",
            "find",
            "for",
            "if",
            "mkdir",
            "move",
            "mshta",
            "pause",
            "powershell",
            "reg",
            "ren",
            "rmdir",
            "rundll32",
            "set",
            "start",
            "type",
            "wmic",
            "wscript",
        ],
    )
}

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

fn is_protected_marker_candidate(candidate: &str) -> bool {
    matches_any_ascii_case_insensitive(
        candidate,
        &[
            "system", "object", "string", "convert", "security", "crypto", "graphy", "length",
            "invoke", "request",
        ],
    )
}

fn matches_any_ascii_case_insensitive(text: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| text.eq_ignore_ascii_case(needle))
}

fn candidate_has_multiple_distinct_bytes(candidate: &[u8]) -> bool {
    let Some(first) = candidate.first() else {
        return false;
    };
    candidate.iter().any(|byte| byte != first)
}

#[cfg(test)]
mod tests {
    use super::{candidate_has_multiple_distinct_bytes, strip_line};

    #[test]
    fn single_run_repeated_marker_noise_is_stripped() {
        let noisy = "aXYZbXYZcXYZdXYZeXYZ";
        assert_eq!(strip_line(noisy), "abcde");
    }

    #[test]
    fn long_single_line_marker_noise_is_not_scanned() {
        let mut noisy = String::new();
        for i in 0..20_000 {
            noisy.push((b'a' + (i % 26) as u8) as char);
            noisy.push_str("XYZ");
        }

        assert_eq!(strip_line(&noisy), noisy);
    }

    #[test]
    fn repeated_plain_token_is_not_stripped() {
        let noisy = "abcabcabcabc";
        assert_eq!(strip_line(noisy), noisy);
    }

    #[test]
    fn protected_marker_candidate_is_not_stripped() {
        let noisy = "systemsystemsystem";
        assert_eq!(strip_line(noisy), noisy);
    }

    #[test]
    fn candidate_distinct_check_matches_ascii_marker_semantics() {
        assert!(!candidate_has_multiple_distinct_bytes(b"AAA"));
        assert!(candidate_has_multiple_distinct_bytes(b"AaA"));
        assert!(candidate_has_multiple_distinct_bytes(b"ABC"));
    }

    #[test]
    fn unicode_marker_islands_inside_ascii_tokens_are_stripped() {
        let noisy = "ec┌( ಠ_ಠ)┘ho ofヾ(⌐■_■)ノf & s已法製et X=1 & if noﮕ◯t def字神ined X exit";
        assert_eq!(
            strip_line(noisy),
            "echo off & set X=1 & if not defined X exit"
        );
    }

    #[test]
    fn unicode_marker_islands_at_command_token_boundaries_are_stripped() {
        let noisy = "set \"x=⟀ ⻉ ䷥ ⻮ ┋powershellExecutionPolicyBypassWindowStyle HiddenCommand⟀ ⻉ ䷥ ⻮ ┋\"";
        assert_eq!(
            strip_line(noisy),
            "set \"x=powershellExecutionPolicyBypassWindowStyle HiddenCommand\""
        );
    }

    #[test]
    fn standalone_unicode_variable_names_are_preserved() {
        let line = r#"set "豆饿色德=value""#;
        assert_eq!(strip_line(line), line);
    }

    #[test]
    fn percent_wrapped_unicode_marker_islands_inside_ascii_tokens_are_stripped() {
        let noisy = "e%┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ%cho of%◯س﷽تﯤس%f";
        assert_eq!(strip_line(noisy), "echo off");
    }

    #[test]
    fn long_percent_wrapped_unicode_marker_islands_are_stripped() {
        let marker = "%┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ(◕‿◕)(⊙ω⊙)%".repeat(12);
        let noisy = format!("e{marker}cho of{marker}f");
        assert_eq!(strip_line(&noisy), "echo off");
    }
}
