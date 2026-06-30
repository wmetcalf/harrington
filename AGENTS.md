# Repository Guidelines

## Project Structure & Module Organization
This repository is a Rust workspace under `rust/`. The main CLI lives in `rust/crates/batdeob-cli/`, and the deobfuscation engine lives in `rust/crates/batdeob-core/`. Core modules are grouped by concern: `src/handlers/` for command-specific parsers, `ps1_scan.rs` / `js_scan.rs` / `vbs_scan.rs` for embedded script extraction, and `aes_chain/` for staged dropper recovery. Integration tests and examples sit alongside the crates.

The corpus regression workflow uses an external JSON dump of baseline reports. Point the `corpus_audit.py` / `corpus_iterate.py` scripts (under `rust/tools/`) at the dump directory you want as the baseline — the previous developer kept it at `/tmp/corpus_dump_v54/`, but the path is configurable per-invocation. Treat any such dump as read-only reference data.

## Build, Test, and Development Commands
Run commands from `rust/`:

```bash
cargo build -p batdeob-cli
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

`cargo run -p batdeob-cli -- analyze sample.bat` is the quickest way to inspect a sample locally.

## Coding Style & Naming Conventions
Use standard Rust formatting (`cargo fmt`) and keep changes consistent with existing modules. Prefer explicit helper functions over large regex-only patches when parsing can be made more robust. Test names use descriptive snake_case, usually ending in the behavior being exercised, e.g. `ps1_normalization_decodes_regex_replace_base64_variable`.

## Testing Guidelines
Add or update tests next to the code they cover, usually in `rust/crates/batdeob-core/src/lib.rs` or the relevant module. Prefer corpus-driven regressions: reproduce the exact obfuscation shape, then assert on the normalized output or emitted trait. Run the full workspace test suite plus Clippy before landing changes.

## Commit & Pull Request Guidelines
Recent commits use short, scoped prefixes and an imperative summary, such as `deob_scan: stop URL extraction at whitespace/quote/angle-bracket`. Keep commits focused on one behavioral change. Pull requests should explain the sample or corpus pattern being fixed, note any new tests, and mention whether the change affects CLI output, trait extraction, or limits.

## Agent Notes
When iterating on corpus findings, inspect both the original source and the deobfuscated output for each report. Prefer batching analysis in chunks and land only changes that improve readability, extraction, or robustness.
