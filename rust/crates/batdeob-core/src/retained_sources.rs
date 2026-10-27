//! Optional source retention. This never supplies input to the analyzer.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;

pub const MAX_RETAINED_SOURCE_BYTES: usize = 8 * 1024 * 1024;
pub const RETAINED_SOURCE_MANIFEST_RESERVE: usize = 256 * 1024;
const MAX_SNAPSHOTS: usize = 32;
const MAX_EVENTS: usize = 64;
const MAX_RANGES: usize = 512;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RetainedSourceSnapshot {
    pub sha256: String,
    /// Exact UTF-8 bytes of the input to the selected summarizer, not raw input.
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetainedSourceRange {
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RetainedSourceEvent {
    pub stage: &'static str,
    pub family: &'static str,
    pub snapshot_sha256: String,
    pub ranges: Vec<RetainedSourceRange>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct Omissions {
    bytes: u64,
    snapshots: u64,
    events: u64,
    ranges: u64,
    deadline: u64,
    invalid_ranges: u64,
    unsupported_input: u64,
}

impl Omissions {
    fn total(&self) -> u64 {
        [
            self.bytes,
            self.snapshots,
            self.events,
            self.ranges,
            self.deadline,
            self.invalid_ranges,
            self.unsupported_input,
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }
}

/// Bounded, nonexhaustive snapshots of selected root summarizer inputs.
/// No executable-equivalence or complete-deobfuscation claim is made.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RetainedSources {
    full_input_sha256: Option<String>,
    snapshots: Vec<RetainedSourceSnapshot>,
    events: Vec<RetainedSourceEvent>,
    omissions: Omissions,
}

impl RetainedSources {
    /// None if the existing analysis deadline interrupted identity hashing.
    pub fn full_input_sha256(&self) -> Option<&str> {
        self.full_input_sha256.as_deref()
    }
    pub fn snapshots(&self) -> &[RetainedSourceSnapshot] {
        &self.snapshots
    }
    pub fn events(&self) -> &[RetainedSourceEvent] {
        &self.events
    }

    /// Metadata only. Snapshot bytes are deliberately excluded from JSON.
    /// The CLI changes availability_scope only after it verifies written files.
    pub fn manifest_json(&self) -> serde_json::Value {
        let snapshots: Vec<_> = self
            .snapshots
            .iter()
            .map(|snapshot| {
                serde_json::json!({
                    "sha256": snapshot.sha256,
                    "name": format!("source-{}.bin", snapshot.sha256),
                    "size": snapshot.bytes.len(),
                    "representation": "stage_utf8",
                    "available": true,
                })
            })
            .collect();
        let events: Vec<_> = self
            .events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "stage": event.stage, "family": event.family,
                    "depth": 0, "snapshot_sha256": event.snapshot_sha256,
                    "ranges": event.ranges, "original_input_span": null,
            "original_span_unavailable_reason": "stage_coordinates_only_original_artifact_not_supplied",
                })
            })
            .collect();
        serde_json::json!({
            "version": "harrington-retained-sources/1",
            "full_input_sha256": self.full_input_sha256,
            "input_identity_status": if self.full_input_sha256.is_some() { "complete" } else { "unavailable_deadline" },
            "classification": "retained_source_snapshots",
            "availability_scope": "report_memory",
            "coverage_complete": false,
            "capture_complete_for_selected_passes": self.omissions.total() == 0,
            "covered_families": ["long_double_colon", "colon_self_read_marker", "dense_long_set_scaffolding", "long_set_scaffolding_run", "dense_set_scaffolding"],
            "coverage_exclusions": ["other_summary_passes_not_captured", "descendant_sources_not_captured", "not_full_deobfuscation_or_executable_reconstruction"],
            "limits": {"aggregate_bytes": MAX_RETAINED_SOURCE_BYTES,
                "manifest_bytes": RETAINED_SOURCE_MANIFEST_RESERVE,
                "snapshots": MAX_SNAPSHOTS, "events": MAX_EVENTS,
                "ranges": MAX_RANGES, "depth": 0},
            "snapshots": snapshots, "events": events, "omissions": self.omissions,
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Rejection {
    Bytes,
    Snapshots,
    Events,
    Ranges,
    Deadline,
    InvalidRanges,
}

/// One transaction's bounded descriptors; a rejected event retains no prefix.
pub(crate) struct PendingEvent {
    ranges: Vec<RetainedSourceRange>,
    remaining_ranges: usize,
    rejection: Option<Rejection>,
    encountered: bool,
}

impl PendingEvent {
    pub(crate) fn push(&mut self, start_byte: usize, end_byte: usize) {
        self.encountered = true;
        if self.rejection.is_some() {
            return;
        }
        if self.ranges.len() >= self.remaining_ranges {
            self.rejection = Some(Rejection::Ranges);
            self.ranges.clear();
            return;
        }
        self.ranges.push(RetainedSourceRange {
            start_byte,
            end_byte,
        });
    }
}

/// Hash only complete original input; never publish a digest of a prefix.
fn bounded_input_identity(input: &[u8], deadline: Option<Instant>) -> Option<String> {
    let expired = || deadline.is_some_and(|at| Instant::now() >= at);
    if expired() {
        return None;
    }
    let mut hasher = Sha256::new();
    for chunk in input.chunks(64 * 1024) {
        if expired() {
            return None;
        }
        hasher.update(chunk);
    }
    if expired() {
        return None;
    }
    Some(hex::encode(hasher.finalize()))
}

pub(crate) struct Collector {
    retained: RetainedSources,
    snapshot_bytes: usize,
    range_count: usize,
    deadline: Option<Instant>,
}

impl Collector {
    pub(crate) fn new(input: &[u8], deadline: Option<Instant>) -> Self {
        let full_input_sha256 = bounded_input_identity(input, deadline);
        let mut omissions = Omissions::default();
        if full_input_sha256.is_none() {
            omissions.deadline = 1;
        }
        Self {
            retained: RetainedSources {
                full_input_sha256,
                snapshots: Vec::new(),
                events: Vec::new(),
                omissions,
            },
            snapshot_bytes: 0,
            range_count: 0,
            deadline,
        }
    }

    fn expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    fn existing_snapshot(&self, text: &str) -> Option<usize> {
        self.retained
            .snapshots
            .iter()
            .position(|snapshot| snapshot.bytes == text.as_bytes())
    }

    pub(crate) fn pending(&self, text: &str) -> PendingEvent {
        let rejection = if self.retained.full_input_sha256.is_none() || self.expired() {
            Some(Rejection::Deadline)
        } else if self.retained.events.len() >= MAX_EVENTS {
            Some(Rejection::Events)
        } else if text.len() > MAX_RETAINED_SOURCE_BYTES - RETAINED_SOURCE_MANIFEST_RESERVE {
            Some(Rejection::Bytes)
        } else if self.existing_snapshot(text).is_some() {
            None
        } else if self.retained.snapshots.len() >= MAX_SNAPSHOTS {
            Some(Rejection::Snapshots)
        } else if self
            .snapshot_bytes
            .checked_add(text.len())
            .and_then(|bytes| bytes.checked_add(RETAINED_SOURCE_MANIFEST_RESERVE))
            .map_or(true, |bytes| bytes > MAX_RETAINED_SOURCE_BYTES)
        {
            Some(Rejection::Bytes)
        } else {
            None
        };
        PendingEvent {
            ranges: Vec::new(),
            remaining_ranges: MAX_RANGES - self.range_count,
            rejection,
            encountered: false,
        }
    }

    pub(crate) fn record(
        &mut self,
        stage: &'static str,
        family: &'static str,
        text: &str,
        mut pending: PendingEvent,
    ) {
        if !pending.encountered {
            return;
        }
        // Other pending events may have committed since this one began.
        if pending.rejection.is_none() {
            pending.rejection = self.pending(text).rejection;
        }
        if pending.rejection.is_none()
            && self
                .range_count
                .checked_add(pending.ranges.len())
                .map_or(true, |count| count > MAX_RANGES)
        {
            pending.rejection = Some(Rejection::Ranges);
        }
        if pending.rejection.is_none() && self.expired() {
            pending.rejection = Some(Rejection::Deadline);
        }
        if pending.rejection.is_none()
            && pending.ranges.iter().any(|range| {
                range.start_byte >= range.end_byte
                    || range.end_byte > text.len()
                    || (range.start_byte != 0
                        && text.as_bytes().get(range.start_byte - 1) != Some(&b'\n'))
                    || (range.end_byte != text.len()
                        && text.as_bytes().get(range.end_byte - 1) != Some(&b'\n'))
            })
        {
            pending.rejection = Some(Rejection::InvalidRanges);
        }
        if let Some(reason) = pending.rejection {
            let counter = match reason {
                Rejection::Bytes => &mut self.retained.omissions.bytes,
                Rejection::Snapshots => &mut self.retained.omissions.snapshots,
                Rejection::Events => &mut self.retained.omissions.events,
                Rejection::Ranges => &mut self.retained.omissions.ranges,
                Rejection::Deadline => &mut self.retained.omissions.deadline,
                Rejection::InvalidRanges => &mut self.retained.omissions.invalid_ranges,
            };
            *counter = counter.saturating_add(1);
            return;
        }
        let index = match self.existing_snapshot(text) {
            Some(index) => index,
            None => {
                let sha256 = hex::encode(Sha256::digest(text.as_bytes()));
                if self.expired() {
                    self.retained.omissions.deadline =
                        self.retained.omissions.deadline.saturating_add(1);
                    return;
                }
                // Admission checked every bound before this allocation. Collector
                // is exclusively borrowed; no concurrent transaction can consume it.
                let bytes = text.as_bytes().to_vec();
                if self.expired() {
                    self.retained.omissions.deadline =
                        self.retained.omissions.deadline.saturating_add(1);
                    return;
                }
                self.snapshot_bytes += bytes.len();
                self.retained
                    .snapshots
                    .push(RetainedSourceSnapshot { sha256, bytes });
                self.retained.snapshots.len() - 1
            }
        };
        self.range_count += pending.ranges.len();
        self.retained.events.push(RetainedSourceEvent {
            stage,
            family,
            snapshot_sha256: self.retained.snapshots[index].sha256.clone(),
            ranges: pending.ranges,
        });
    }

    pub(crate) fn unsupported_input(&mut self) {
        self.retained.omissions.unsupported_input =
            self.retained.omissions.unsupported_input.saturating_add(1);
    }
    pub(crate) fn finish(mut self) -> RetainedSources {
        if self.expired() && self.retained.omissions.deadline == 0 {
            self.retained.omissions.deadline = 1;
        }
        self.retained
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn record(collector: &mut Collector, text: &str) {
        let mut event = collector.pending(text);
        event.push(0, text.len());
        collector.record("test", "test", text, event);
    }

    #[test]
    fn overlapping_pending_events_cannot_overrun_shared_byte_budget() {
        let mut collector = Collector::new(b"original", None);
        let first = "A".repeat(5 * 1024 * 1024);
        let second = "B".repeat(4 * 1024 * 1024);
        let mut a = collector.pending(&first);
        let mut b = collector.pending(&second);
        a.push(0, first.len());
        b.push(0, second.len());
        collector.record("test", "test", &first, a);
        collector.record("test", "test", &second, b);
        assert_eq!(collector.retained.snapshots.len(), 1);
        assert_eq!(collector.retained.omissions.bytes, 1);
    }

    #[test]
    fn overlapping_pending_events_cannot_overrun_event_or_range_limits() {
        let mut collector = Collector::new(b"original", None);
        for _ in 0..MAX_EVENTS - 1 {
            record(&mut collector, "x");
        }
        let mut a = collector.pending("x");
        let mut b = collector.pending("x");
        a.push(0, 1);
        b.push(0, 1);
        collector.record("test", "test", "x", a);
        collector.record("test", "test", "x", b);
        assert_eq!(collector.retained.events.len(), MAX_EVENTS);
        assert_eq!(collector.retained.omissions.events, 1);

        let mut collector = Collector::new(b"original", None);
        let text = "x\n".repeat(MAX_RANGES);
        let mut a = collector.pending(&text);
        let mut b = collector.pending(&text);
        for i in 0..500 {
            a.push(i * 2, i * 2 + 2);
        }
        for i in 500..520 {
            b.push(i * 2, i * 2 + 2);
        }
        collector.record("test", "test", &text, a);
        collector.record("test", "test", &text, b);
        assert_eq!(collector.range_count, 500);
        assert_eq!(collector.retained.omissions.ranges, 1);
    }

    #[test]
    fn range_overflow_is_atomic_and_metadata_remains_bounded() {
        let mut collector = Collector::new(b"original", None);
        let text = "x\n".repeat(MAX_RANGES + 1);
        let mut event = collector.pending(&text);
        for i in 0..MAX_RANGES + 1 {
            event.push(i * 2, i * 2 + 2);
        }
        collector.record("test", "test", &text, event);
        assert!(collector.retained.snapshots.is_empty());
        assert!(collector.retained.events.is_empty());
        assert_eq!(collector.retained.omissions.ranges, 1);
        assert!(
            serde_json::to_vec(&collector.retained.manifest_json())
                .unwrap()
                .len()
                < RETAINED_SOURCE_MANIFEST_RESERVE
        );
    }

    #[test]
    fn exact_budget_and_one_byte_over_are_whole_snapshot_decisions() {
        let size = MAX_RETAINED_SOURCE_BYTES - RETAINED_SOURCE_MANIFEST_RESERVE;
        let mut collector = Collector::new(b"original", None);
        record(&mut collector, &"x".repeat(size));
        assert_eq!(collector.snapshot_bytes, size);
        record(&mut collector, &"y".repeat(size + 1));
        assert_eq!(collector.retained.snapshots.len(), 1);
        assert_eq!(collector.retained.omissions.bytes, 1);
        let retained = collector.finish();
        assert!(
            retained
                .snapshots()
                .iter()
                .map(|s| s.bytes.len())
                .sum::<usize>()
                + serde_json::to_vec(&retained.manifest_json()).unwrap().len()
                <= MAX_RETAINED_SOURCE_BYTES
        );
    }

    #[test]
    fn equal_snapshots_reuse_bytes_but_preserve_events() {
        let mut collector = Collector::new(b"original", None);
        record(&mut collector, "x\n");
        record(&mut collector, "x\n");
        assert_eq!(collector.retained.snapshots.len(), 1);
        assert_eq!(collector.retained.events.len(), 2);
        assert_eq!(collector.snapshot_bytes, 2);
    }

    #[test]
    fn snapshot_count_and_deadline_are_not_renewed() {
        let mut collector = Collector::new(b"original", None);
        for i in 0..MAX_SNAPSHOTS + 1 {
            record(&mut collector, &format!("{i}\n"));
        }
        assert_eq!(collector.retained.snapshots.len(), MAX_SNAPSHOTS);
        assert_eq!(collector.retained.omissions.snapshots, 1);
        let deadline = Instant::now();
        let mut collector = Collector::new(b"original", Some(deadline));
        record(&mut collector, "x");
        assert_eq!(collector.deadline, Some(deadline));
        assert!(collector.retained.snapshots.is_empty());
        assert!(collector.retained.omissions.deadline > 0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod helper_tests {
    use super::*;
    use crate::{Config, Environment};

    #[test]
    fn dense_long_and_short_scaffolding_capture_only_omitted_physical_lines() {
        for long in [true, false] {
            let mut text = String::new();
            for i in 0..105 {
                let name = if long {
                    format!("NoiseCarrierScaffoldName{i:03}")
                } else {
                    format!("carrier_{i:03}")
                };
                text.push_str(&format!(
                    "set \"{name}=alphabeticalpayload{i:03}filler\"\r\n"
                ));
                if i % 4 == 0 {
                    text.push_str("echo kept\r\n");
                }
            }
            let mut baseline_env = Environment::new(&Config::default());
            let before =
                crate::summarize_unreferenced_long_set_scaffolding_runs(&text, &mut baseline_env);
            let mut env = Environment::new(&Config::default());
            let mut collector = Collector::new(text.as_bytes(), None);
            let after = crate::summarize_unreferenced_long_set_scaffolding_runs_captured(
                &text,
                &mut env,
                Some(&mut collector),
                "root_post_analysis_set",
            );
            assert_eq!(before, after);
            assert_eq!(
                serde_json::to_value(&baseline_env.traits).unwrap(),
                serde_json::to_value(&env.traits).unwrap()
            );
            let retained = collector.finish();
            assert_eq!(retained.events.len(), 1);
            let event = &retained.events[0];
            assert_eq!(event.ranges.len(), 105);
            let snapshot = &retained.snapshots[0];
            assert_eq!(snapshot.bytes, text.as_bytes());
            for range in &event.ranges {
                let bytes = &snapshot.bytes[range.start_byte..range.end_byte];
                assert!(bytes.starts_with(b"set "));
                assert!(bytes.ends_with(b"\r\n"));
                assert!(!bytes
                    .windows(b"echo kept".len())
                    .any(|window| window == b"echo kept"));
            }
        }
    }

    #[test]
    fn contiguous_scaffolding_and_missing_final_newline_ranges_round_trip() {
        // 64 short long-name assignments total <2048 body bytes but >=2048
        // physical bytes, exercising the contiguous branch rather than dense.
        let line = "set AAAAAAAAAAAAAAAAAAAA=x\r\n";
        let text = line.repeat(76);
        let mut out = String::new();
        let mut pending = text.clone();
        let mut count = 76;
        let mut collector = Collector::new(text.as_bytes(), None);
        let mut event = collector.pending(&text);
        let mut env = Environment::new(&Config::default());
        crate::flush_unreferenced_long_set_scaffolding_run(
            &mut out,
            &mut pending,
            &mut count,
            &mut env,
            Some(&mut event),
            0,
        );
        collector.record(
            "root_post_analysis_set",
            "long_set_scaffolding_run",
            &text,
            event,
        );
        let retained = collector.finish();
        assert_eq!(retained.events[0].ranges[0].end_byte, text.len());
        assert!(pending.is_empty());
        assert!(out.contains("rem omitted"));

        let text = format!("::{}", "A".repeat(1024));
        let mut collector = Collector::new(text.as_bytes(), None);
        crate::summarize_long_double_colon_payload_lines(&text, &mut env, Some(&mut collector));
        let retained = collector.finish();
        assert_eq!(retained.events[0].ranges[0].end_byte, text.len());
        assert_eq!(retained.snapshots[0].bytes, text.as_bytes());
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    #[test]
    fn finishing_after_deadline_marks_capture_interrupted_without_extending_it() {
        let mut collector = Collector::new(b"original", None);
        let expired = Instant::now();
        collector.deadline = Some(expired);
        let retained = collector.finish();
        assert_eq!(retained.omissions.deadline, 1);
    }
}

#[cfg(test)]
mod input_identity_tests {
    use super::*;
    #[test]
    fn expired_capture_does_not_hash_or_claim_complete_input_identity() {
        let input = vec![b'A'; 16 * 1024 * 1024];
        let collector = Collector::new(&input, Some(Instant::now()));
        let retained = collector.finish();
        let manifest = retained.manifest_json();
        assert!(manifest["full_input_sha256"].is_null());
        assert_eq!(manifest["input_identity_status"], "unavailable_deadline");
        assert_eq!(manifest["capture_complete_for_selected_passes"], false);
        assert!(retained.snapshots().is_empty());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod maximum_manifest_tests {
    use super::*;
    #[test]
    fn maximum_admitted_metadata_fits_reserved_space() {
        let mut collector = Collector::new(b"original", None);
        for index in 0..MAX_EVENTS {
            let text = format!("line{}\n", index % MAX_SNAPSHOTS).repeat(8);
            let mut pending = collector.pending(&text);
            let mut start = 0;
            for line in text.split_inclusive('\n') {
                pending.push(start, start + line.len());
                start += line.len();
            }
            collector.record(
                "root_post_analysis_set",
                "dense_long_set_scaffolding",
                &text,
                pending,
            );
        }
        assert_eq!(collector.retained.snapshots.len(), MAX_SNAPSHOTS);
        assert_eq!(collector.retained.events.len(), MAX_EVENTS);
        assert_eq!(collector.range_count, MAX_RANGES);
        let manifest = serde_json::to_vec_pretty(&collector.finish().manifest_json()).unwrap();
        assert!(manifest.len() <= RETAINED_SOURCE_MANIFEST_RESERVE);
    }
}
