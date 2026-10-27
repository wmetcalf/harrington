# Retained summarized source validation

The core/CLI feature is implemented and independently approved. It is source-only: no dependency revision, adapter release, deployment, production worker, or Rustymonkey runtime was changed. A future manifest-aware adapter admission phase is required before worker opt-in; current CLI/library defaults remain disabled. These files are retained source snapshots with partial coverage, not full deobfuscation or executable reconstruction.

## Source and compiler provenance

Baseline: f077a8322cf848778fc117d525b867a5be9f1e38. The implementation uses an independent --no-hardlinks clone and leaves the Cargo-managed checkout's tracked files unchanged. The final source hashes checked before commit are:

* core lib.rs: d280b45e069d8cb7235198481cf98878aa88a8c1dbcb6b4fb813dbb969fcb25a
* core retained_sources.rs: 3d9604d90cf36a003474fcd56a19728bb740c76981a015608cfcf9979b27e01f
* CLI main.rs: 747b25e57361896f21d946534852b9c4e1ca2b258b47cdf3ad0aaeab3e27b9c6

The repository pins Rust1.85.0 in rust/rust-toolchain.toml. Documented checks ran from rust/ with that toolchain and a dedicated target directory. Additional production-representative release tests used cached official image rust@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f (Rust1.90.0, Bookworm), readonly source, network none, UID1000, dropped capabilities, and separate private Cargo/target mounts. The resulting release CLI SHA256 is e85996158ab8bd38d02dbef5d5fb3de88941469824691e9ea38c44c6369189c6.

## New feature and static checks

All26 new tests passed on the repository-pinned toolchain, independently repeated by reviewers:

* 11 collector/helper tests: shared aggregate admission, stale pending admission recheck, atomic range rejection, full metadata bounds, snapshot deduplication, deadline/identity interruption, and exact scaffolding ranges;
* 8 actual core integration tests: default disabled, repeated CRLF carriers, UTF16/invalid-UTF8 identity, unchanged self-read/extracted payloads, original line/trait caps, container scope, whole-snapshot budget refusal, and actual root post-analysis scaffolding;
* 7 CLI integration tests: opt-in/fixed budget, exact snapshots and manifest, default behavior, safe force cleanup, no success manifest on failure, symlink refusal, and nonblocking FIFO refusal.

Commands from rust/ (private target path omitted):

```sh
cargo +1.85.0 fmt --all -- --check
cargo +1.85.0 clippy --offline --locked --workspace --all-targets -- -D warnings
cargo +1.85.0 test --offline --locked --test retained_sources
cargo +1.85.0 test --offline --locked -p batdeob-core --lib retained_sources::
```

Formatting, all-target Clippy with warnings denied, and git diff --check passed. New snapshot writers use create_new/nofollow/nonblock even after force cleanup; they never inherit a truncating FIFO open. Manifest publication is atomic and last, after exact snapshot write/hash verification. No old test assertion, resource cap, or deadline was relaxed.

## Full-workspace results and inherited failures

There is **no universal-green claim**.

The pinned Rust1.85 debug command `cargo test --offline --locked --workspace -- --test-threads=4` passed8 CLI unit,55 existing CLI integration,7 new CLI integration, and2791 core unit tests, with3 existing core timing failures. Remaining core integration targets were run separately:1 corpus,11 parity,8 new core integration all passed. The three failures also reproduce individually against the exact original baseline, compiled into a different target directory (2783 original unit tests;2782 filtered in each exact run):

| Existing test | Unchanged budget | Baseline observed time/result |
| --- | --- | --- |
| line_cap_tests::bare_base64_carrier_line_is_summarized_before_timeout |2s |2.21s, unexpected TimeoutHit |
| trait_dedup_tests::combined_opaque_and_percent_noise_uses_fully_summarized_drive_input |1s |1.04s, unexpected TimeoutHit |
| trait_dedup_tests::self_tail_base64_xor_utf16_powershell_stage_is_extracted |3s |3.72s, unexpected TimeoutHit |

The Rust1.90 Bookworm release command `cargo test --offline --locked --release --workspace --no-fail-fast -- --test-threads=4` completed all targets: **2883 passed,1 inherited failure**. All2794 core unit tests,1 corpus test,11 parity tests,8 new core integrations,7 new CLI integrations,8 CLI unit tests, and54 existing CLI integrations passed. The only failure was `report_timeout_emits_partial_json`: its synthetic input finished before its expected timeout in optimized mode, so no TimeoutHit was emitted. The same exact test fails against the unchanged original baseline in the same official compiler image and a separate baseline target, in0.51s with54 other original CLI tests filtered. No source or assertion was changed to hide this timing dependency.

Earlier root-invoked Rust1.95 runs are not the repository's documented gate. An initial baseline comparison reused target artifacts and was explicitly invalidated; its logs are retained but are not baseline proof. All baseline claims above use independently compiled targets and verified original source.

## Retained-input emulator regression

A separate parent-run regression used one retained835385-byte batch input under the trusted emulator in a network-none/read-only/capability-drop/PID/memory/CPU constrained container. It never executed recovered commands, scripts, or binaries. All9 legacy output files were byte-identical off/on, including compact batch output, traits, PowerShell, and recovered binary artifacts.

The opt-in export contained2 complete snapshots and2 events with111 exact whole physical omission ranges,861739 aggregate exported bytes, and a longest range of704585 bytes. One snapshot was byte-identical to the entire original raw input. Full input SHA, snapshot hashes, range bytes, and line endings were verified. Original spans stayed null, overall coverage stayed false, and selected-pass capture was complete. This is case-specific correctness evidence, not a performance or complete-reconstruction claim.

## Evidence retained privately

The evidence bundle contains exact commands, separate-target provenance, and full logs:

* evidence/harrington-fragment-design/pinned185-results.json and pinned185-{fmt,workspace,clippy}.log
* evidence/harrington-fragment-design/isolated185-and-bookworm190-results.json
* evidence/harrington-fragment-design/isolated185-baseline-*.log
* evidence/harrington-fragment-design/bookworm190-followup-{commands,results}.json
* evidence/harrington-fragment-design/bookworm190-release-no-fail-fast.log
* evidence/harrington-fragment-design/bookworm190-baseline-cli-timeout.log
* evidence/harrington-fragment-design/final-validation-proof.json
* evidence/harrington-emulator-regression/proof.json

The old invalid shared-target baseline evidence is labeled INVALID-SHARED-TARGET-BASELINE.txt. The CLI timeout failure log can contain a large synthetic JSON body; use anchored test-result/error extraction instead of printing the body.
