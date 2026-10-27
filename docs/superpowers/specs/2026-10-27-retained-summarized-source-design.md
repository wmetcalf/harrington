# Bounded retention of sources summarized by Harrington

Status: IMPLEMENTED and independently reviewed; source-only, with inherited timing-test failures documented in ../validation/2026-10-27-retained-summarized-source.md. Core/CLI source and synthetic emulator tests are authorized; dependency changes, deployment, runtime changes, and external sample execution remain excluded. Source baseline is f077a8322cf848778fc117d525b867a5be9f1e38, independently cloned with --no-hardlinks into this repository.

## Outcome and limits of the claim

Export byte-identical snapshots of the input to two selected summarizer families, with a manifest identifying exactly which ranges those passes omitted. The current compact analysis, preview, diagnostics, extracted payloads, and self-read behavior remain unchanged. These files are **retained source snapshots**, not full deobfuscation, executable reconstruction, or proof that discarded material was harmless. The manifest always says coverage is partial.

A snapshot is the complete UTF-8 byte representation of the text entering the selected helper, before that helper changes it. It can already contain changes made by earlier passes. Keeping that complete snapshot avoids inventing offsets into the original file, and allows nonadjacent scaffolding lines to be represented as separate ranges in one actual file. No concatenation of disjoint lines is presented as a contiguous original span.

## Source locations and first capture scope

All locations below refer to rust/crates/batdeob-core/src/lib.rs at the pinned revision.

* summarize_long_double_colon_payload_lines, line20908, called before drive at10393: capture both the ordinary long :: branch and the successful marker-prefixed self-read branch reached through this helper. Preserve the entire physical line, including leading bytes and CR/LF, in its source span. The existing recognition, URL rescue, decoding, and trait emission remain untouched.
* summarize_unreferenced_long_set_scaffolding_runs, line16092, called after analysis at10796 and11072: cover its contiguous flush16177, dense-long16133, and dense-short16324 branches. Record every physical omitted line range, including its existing line ending. Dense branches can omit nonadjacent lines; retain separate ranges and never include surviving lines as omitted. Capture before the dense-long intermediate string and before dense-short input changes. Each branch therefore receives the snapshot of its own actual input.

Scope deliberately excludes all other summarizers, explicit output/line caps, child scripts, and container/wrapper recursion. Other callers of the marker helper at20397 are not automatically covered. Existing early transformations at10320 onward can precede the :: helper. No claim of recovering their discarded bytes is made. The manifest lists the covered family identifiers and `other_summary_passes_not_captured`, `descendant_sources_not_captured`. The GitHub HTML wrapper early-return path10251 reports `unsupported_container_input` and cannot relabel a nested blob as the original input.

## Byte identity, provenance, and offsets

`full_input_sha256` hashes every byte of the original top-level input in deadline-checked64KiB chunks, before decoding, NUL-tail removal, or any other transformation. If the existing deadline interrupts this optional hash, the captured report returns null with `input_identity_status:unavailable_deadline`, refuses snapshots, and marks capture incomplete. No prefix digest is published. The existing separate CLI top-level input_sha256 remains its complete input hash. Existing Loadout sourceRefs continue pointing to the retained original artifact. Core capture must not overwrite env.input_bytes; PS self-read currently uses the original Arc at ps1_scan.rs8393.

Every snapshot has a full SHA256, exact byte count, representation `stage_utf8`, and binary bytes outside JSON. Each capture event supplies its fixed stage identifier; the top-level descriptor supplies the shared root-input identity. Identical bytes can be reused across stage events. Identical snapshots may share a blob only after full hash, length, and byte equality; capture events and repeated occurrences remain distinct. A SHA collision never merges unequal bytes.

Each recorded source span is half-open `[start_byte,end_byte)`, zero based, relative ONLY to its referenced retained snapshot. Offsets are bytes, never character, UTF-16-unit, or original-file offsets. Before accepting an event, verify every range is in bounds and starts/ends on the actual selected physical-line boundaries. Whole-line byte ranges are obtained from split_inclusive('\n') cumulative byte lengths before mutation. A missing final newline and CRLF are preserved verbatim.

An optional `original_input_span` is permitted only after verifying that the entire relevant stage equals the original raw input, or after verifying a caller-supplied contiguous original slice with exact byte equality and its known start. Do not search for an arbitrary equal substring and guess its occurrence. Require an existing retained original source artifact before exposing that cross-artifact span in Loadout; otherwise serialize null. UTF-16 decoding, invalid UTF-8 replacement, earlier transformations, and ambiguous repeated substring matches yield `original_input_span:null` and an explicit reason. The snapshot and its local spans remain independently usable. A complete raw input SHA and existing sourceRefs remain independent of whether an original span exists; interrupted optional identity is explicitly unavailable.

In the CLI-only manifest, original input is an external source reference identified by full SHA, never a claim the CLI exported another original file. Until the caller supplies an existing retained original reference, optional original spans remain null. Consumers must not infer original offsets from stage coordinates.

## Shared resource bound

Library capture defaults to zero/disabled, with no source hashing, snapshot copies, or capture collector allocation. CLI current behavior also remains default. A new explicit CLI profile enables `--retain-summarized-sources --retained-source-budget-bytes 8388608`; the future worker adapter opts in explicitly. The only supported first profile is 8MiB; do not add arbitrary larger settings.

The per-top-level-analysis collector has one shared budget, not a fresh budget per pass, snapshot, event, recursive drive, or wrapper. Hard limits:

* aggregate retained snapshot bytes plus serialized manifest <=8388608 bytes;
* reserve262144 bytes up front for bounded manifest metadata, so snapshot payloads <=8126464 bytes;
* at most32 distinct snapshots,64 capture events,512 total omitted ranges;
* capture depth0: only the selected passes in a direct root batch analysis; no descendant capture;
* fixed small enum labels and full hex digests; no unbounded labels, input paths, arbitrary summary strings, or raw arrays in manifest JSON.

Check remaining byte/count/range limits with checked arithmetic BEFORE copying a snapshot, extending a vector, or incrementing success counters. Reuse one complete byte-identical snapshot where possible. A capture event is atomic: either its whole snapshot and all its ranges are admitted, or none of that event is recorded. Never export a prefix as a complete source snapshot. Overflow increments saturating counters by fixed reason (`bytes`, `snapshots`, `events`, `ranges`, `depth`, `deadline`) and marks selected capture incomplete. Metadata does not grow per rejected event. Budget failure does not change analyzer output, traits, or limits.

Do not extend the existing analyzer deadline. Before hashing/copying a snapshot, check remaining deadline. Large snapshots are rejected by size before hashing. Existing input-identity hashing is shared where possible. A collector callback may observe deadline without emitting additional semantic/limit traits; the manifest records capture interruption. Resource pressure during optional capture must not create a new unlimited writer.

## Report and CLI interface proposal

Add private module retained_sources.rs for collector/types, with public non_exhaustive `RetainedSources` and snapshot/event/limit descriptors. Add `Report.retained_sources: Option<RetainedSources>`; `None` when disabled, including every early-return report constructor. Snapshots own Arc<[u8]> or Vec<u8> but are not serialized as JSON numeric arrays. Extend non_exhaustive AnalysisOptions with an opt-in capture profile, and retain the current with_environment constructor semantics with default capture disabled. No Config/default/Rustymonkey dependency change is required.

The collector receives fixed stage IDs and borrowed actual helper input. Helper instrumentation records candidate byte ranges after the existing classifier decides to omit, immediately before existing output emission; recognition and original traits are unchanged. A report-level finalizer moves retained blobs/metadata out of the collector. Do not hold new borrows across existing mutable env calls. Root capture context is explicit, not inferred from temporarily replaced env.input_bytes or a copied Environment.

At CLI write_report_files1015, export each retained snapshot as `source-<fullsha256>.bin` with safe_join/safe_write, and one `retained-source-manifest.json`. Export raw bytes exactly. The manifest contains version `harrington-retained-sources/1`, full input SHA, partial coverage, producer limits/status, snapshot metadata, event family/stage IDs, and omitted byte ranges. It never embeds snapshot bodies. Existing deobfuscated.bat, traits.json, extracted PS1/normalized PS1, and recovered binaries remain unchanged and are linked separately through existing output_files. Producer-generated paths use full hashes and safe fixed names.

The manifest distinguishes `capture_complete_for_selected_passes` from `coverage_complete:false`; neither sets complete analysis true. Snapshot metadata is marked available only after that exact file was successfully written; an export error cannot leave a success manifest pointing at a nonexistent or short file. Write exact files first, verify size/hash, write manifest last atomically. On partial filesystem failure return explicit error; no success manifest. No new arbitrary path writer.

## Future adapter phase, separately scoped

The future trusted adapter passes the explicit bounded CLI profile. It declares `.bin` snapshots as retained source artifacts and declares the manifest as a report. It resolves existing input SHA to actual sourceRefs; source provenance remains original-root vs stage-derived. A byte-identical root snapshot can SHA-deduplicate to the existing original artifact; resolve the manifest to the canonical retained artifact and avoid self-referential sourceRefs cycles. Reserve space for the manifest before admitting optional snapshot artifacts. Existing extracted payloads retain priority. If global artifact count/size/total limits omit a produced source snapshot, record that exact hash as unavailable in the adapter-visible manifest and summary; do not expose a dangling available pointer or falsely report full coverage. Rewriting availability does not rewrite raw snapshot bytes or their digests. The original producer manifest can remain separately retained for inspection with its narrower filesystem-export meaning.

Current artifactizer walks files in lexical order at engines.py176–199 and only emits a generic omission problem. It therefore needs a bounded manifest-aware admission step; relying on its present arbitrary walk would not satisfy this design. No adapter/runtime/dependency update is part of the current design-only task.

## Executable specification and acceptance tests

A separate Python reference model exercises the byte/provenance/budget contract only. It does not implement or claim to test Harrington instrumentation. It is saved privately under evidence/harrington-fragment-design/reference_model_spec.py. Tests cover ASCII and CRLF, UTF-16 and invalid UTF-8 as derived snapshots with null original offsets, transformed-source mapping refusal, repeated identical carrier occurrences, exact full-input SHA, byte/count/depth admission, atomic rejection with no partial blob, and fixed metadata/manifest bounds.

Implementation must additionally add actual core tests beside the selected helpers:

1. ASCII long :: at1023/1024 threshold: identical compact output and ordered traits when capture off/on; retained span equals exact omitted physical line.
2. CRLF/no-final-newline: byte-for-byte snapshot/range round-trip, no newline normalization.
3. UTF-16LE and invalid UTF-8: original raw SHA exact; decoded-stage snapshot and null original span; no bogus offsets.
4. Two equal carriers in one input: distinct ranges; equal stage snapshots reuse one blob; no arbitrary first-substring mapping.
5. Dense interleaved105-line scaffolding: all exact omitted ranges retained; following real command is outside ranges; 512-range overflow atomically declines the event.
6. Byte budget exactly at boundary and one byte over; repeated passes share a single aggregate; count/depth limits; no collector allocation when disabled.
7. Original self-read marker payload: existing extracted PS1 bytes and semantic traits identical with capture enabled, env.input_bytes remains root Arc. Use harmless synthetic Write-Output content only.
8. Explicit max_output_line_bytes, real trait caps, deadline interruption: all original incomplete diagnostics survive; new export does not make analysis complete.
9. CLI manifest round-trip: every available SHA/byte-range resolves to the exact written .bin; raw arrays absent; safe path and partial-write failure tests; original output files unchanged.
10. Future adapter low artifact/byte budget: manifest declared, omitted snapshots explicitly unavailable, existing recovered PS1/PE preserved, sourceRefs/root SHA unchanged, complete false remains false.

Run cargo fmt --check, cargo test --workspace, cargo clippy --workspace --all-targets -- -D warnings before a core commit. No deployment or external sample execution follows from passing these checks.

## Implemented interface and deadline precision

AnalysisOptions::with_retained_sources() enables the fixed profile; Report.retained_sources defaults to None. RetainedSources exposes immutable snapshots(), events(), manifest_json(), and full_input_sha256()->Option<&str>. All original_input_span values remain null with a fixed stage-coordinates-only reason. CLI opt-in requires --out-dir and accepts only the8388608-byte profile. Snapshot hashing/copying share the existing deadline; near a wall-clock boundary optional work can make analysis time out earlier. Deterministic sufficient-budget parity is tested; no universal timing-edge parity is claimed and no existing cap or deadline is extended.

## Sanitized retained-input regression

The parent ran the trusted pinned Rust1.90 Bookworm emulator once with capture off and once on for a retained835385-byte batch input, under network-none/read-only/capability-drop/PID/memory/CPU constraints. No recovered command, script, or binary was executed. All9 legacy output files were byte-identical, including compact batch output, traits, extracted PowerShell, and recovered binaries.

The opt-in export contained2 complete source snapshots and2 events covering111 whole physical omission ranges, for861739 aggregate exported bytes. The longest range was704585 bytes. One snapshot equaled the entire raw original input byte-for-byte; full input SHA, range contents, and line endings were verified. Original spans remained null, overall coverage remained false, and capture was complete for the selected passes. This establishes exact retained-source behavior for that input; it does not establish full reconstruction, complete analysis, or a performance improvement. Sanitized proof is retained privately as evidence/harrington-emulator-regression/proof.json.
