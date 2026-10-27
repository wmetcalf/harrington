# Retained summarized source implementation plan

> Implementation is native/inline in this isolated clone. Parent supplies independent review before any commit. No deployment, runtime/dependency update, or external sample execution.

**Goal:** export bounded byte-identical source snapshots and exact omission ranges for the approved root-only summarizers.

**Architecture:** a private capture module owns a shared bounded collector outside Environment. Only selected root helper calls receive it. Report exposes immutable snapshot/manifest access; CLI explicitly enables the fixed8MiB profile and writes raw snapshots before atomically installing the final manifest.

**Spec:** ../specs/2026-10-27-retained-summarized-source-design.md

**Constraints:** library/CLI defaults disabled; selected root-only capture; aggregate8388608 including262144 manifest reserve; at most32snapshots/64events/512ranges; no trait/output/self-read/cap changes; every original span null in CLI; partial coverage explicit.

**Review focus:** UTF16/lossy source identity; nonadjacent/repeated ranges; atomic budget failure without partial blobs; wrapper/early-return capture scope; symlink/file-failure behavior and no dangling successful manifest.

## Task1: Core bounded capture and selected helper instrumentation

Files: new rust/crates/batdeob-core/src/retained_sources.rs; modify lib.rs only for public option/report fields and selected helper parameters/hooks; new core integration tests tests/retained_sources.rs.

- [x] RED: add actual analyze_with_options tests for ASCII/repeated CRLF carrier capture, default disabled, UTF16/invalidUTF8 provenance, postanalysis scaffolding, self-read payload parity, and existing caps. Add collector unit tests for budget/count/deadline all-or-nothing admission and no duplicate snapshot copies.
- [x] Observe actual failure for absent feature before implementation.
- [x] Implement immutable RetainedSources access, fixed capture profile default disabled, root shared collector and stage IDs; instrument both physical-line classifier branches and long/short scaffold branches. Capture actual pre-mutation snapshots and bounded whole-line ranges.
- [x] GREEN focused real core tests; run workspace tests before claiming task complete.

## Task2: CLI opt-in export and atomic manifest

Files: modify rust/crates/batdeob-cli/src/main.rs; add CLI integration tests tests/retained_sources.rs.

- [x] RED actual binary test: opt-in flags accepted only with out-dir and fixed8388608 profile; default no extra export; all available manifest ranges resolve to exact .bin bytes/SHA; no raw numeric arrays; preview/traits unchanged; force removes stale source exports only.
- [x] RED symlink and existing-file conflict: failure produces no success manifest; manifest writing atomic and last.
- [x] Implement profile wiring; safe snapshot writes/hash verification; bounded manifest JSON; atomic no-clobber publication (or replacement under force after cleanup), temporary files always cleaned; metadata reports partial coverage and null original spans.
- [x] GREEN focused CLI and core tests.

## Task3: Verification and review handoff

- [x] Update design status and usage note with implemented exact interface/coverage.
- [x] Run cargo fmt --all -- --check; cargo test --workspace --offline --locked; cargo clippy --workspace --all-targets --offline --locked -- -D warnings.
- [x] Confirm diff contains only scoped clone files, Cargo-managed source/runtime/dependencies unchanged.
- [x] Send parent exact commands/results and source diff for independent review. Hold commit until approval.

No intermediate commits: explicit parent instruction overrides skill default; final core+CLI commit only after independent approval.

Verification record:26 new tests/fmt/Clippy PASS. Pinned1.85 full debug retains3 independently reproduced baseline timing failures; pinned1.90 release completes2883pass/1 independently reproduced baseline CLI timing failure. Existing assertions/caps unchanged. See ../validation/2026-10-27-retained-summarized-source.md for exact commands, counts, separate-target proof, and real emulator regression. Parent independent review approved; final source hashes rechecked before commit.
