# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-05-18

### Summary

Complete Rust rewrite of the batch deobfuscator. The original Python implementation
has been retired; the Rust port delivers full feature parity plus significant new
capabilities, a bounded-execution safety model, and a corpus regression suite
covering 1,416 in-the-wild malware samples.

### Core Engine

- **Lexer / tokenizer** (`batdeob-core::lexer`): full DOS batch tokenizer handling
  carets, percent-expansion, delayed-expansion (`!var!`), string literals, and
  operator tokens. Caret-continuation collapse, `@` prefix stripping, and
  comma/semicolon command splitting all occur at lex time.

- **Normalizer** (`batdeob-core::normalizer`): reduces `^`, `^^`, and mixed-case
  identifiers; strips redundant whitespace; collapses empty-var sandwiches
  (`%x%%y%%z%` → `%xz%` when `y` is unset).

- **Variable interpreter** (`batdeob-core::interpreter`): tracks SET assignments,
  resolves `%var%` and `!var!` references, handles substring extraction
  (`%var:~off,len%`) and search-and-replace (`%var:find=replace%`), applies
  `%~f0` / `%~dp0` / `%~nx0` path modifier expansions.

- **SET /A arithmetic**: evaluates integer expressions including `+`, `-`, `*`,
  `/`, `%`, `<<`, `>>`, `&`, `|`, `^`, and operator precedence. Expressions
  containing unresolved percent/bang sigils are silently skipped rather than
  crashing.

- **IF constant-folding**: resolves `IF /I EQU/NEQ/LSS/LEQ/GTR/GEQ` comparisons
  when both operands are known at analysis time; recurses into the true branch.
  `IF DEFINED` / `IF NOT DEFINED` handled analogously.

- **FOR interpreter**: `FOR /L` (counter loops), `FOR /F` (token splitting with
  `tokens=`, `delims=`, `skip=`, `usebackq`, and command/string/file sources),
  and plain `FOR` (file-glob iteration). Body is preserved on unresolved sources
  rather than discarded.

- **CALL / GOTO tracing**: follows intra-file `CALL :label` and `GOTO :label`
  jumps; detects `:eof` / `EXIT /B` and continues scanning for trailing IOCs
  rather than halting.

### Synthetic Environment Emulators

- **FINDSTR /R** (`synth::findstr`): executes anchored POSIX-ERE patterns against
  in-memory variable contents; used by many obfuscators for string extraction.
  Switched from hand-rolled matcher to `regex::Regex` for correctness on complex
  patterns.

- **CERTUTIL -decode / -decodehex** (`synth::certutil`): decodes Base64 and hex
  blobs embedded in batch variables; extracts decoded bytes as a child script.

- **REG QUERY** (`synth::reg`): emits a `RegQuery` trait recording the queried
  key/value path; returns a synthetic empty result so downstream variable
  assignments resolve cleanly instead of halting execution.

- **DIR** (`synth::dir`): emits a `DirListing` trait; returns a synthetic empty
  result allowing FOR /F loops over `dir` output to expand their bodies.

### Command Handlers

Pass-through handlers that record intent without blocking control flow:

`del`, `cls`, `reg add/delete`, `attrib`, `mkdir/md`, `taskkill`, `schtasks`,
`icacls`, `move`, `copy`, `xcopy`, `robocopy`, `sc`, `net`, `netsh`,
`wmic`, `timeout`, `ping`, `type`, `mshta`, `wscript`, `cscript`,
`extrac32` (CAB-polyglot self-extraction tracking).

### IOC / Trait Extraction

- **Download traits**: extracted from `curl`, `certutil -urlcache`, `bitsadmin`,
  `Invoke-WebRequest`, `Invoke-RestMethod`, `Net.WebClient.DownloadFile/String`,
  `Start-BitsTransfer`.

- **Execution traits**: `cmd /c`, `powershell`, `mshta`, `wscript`, `cscript`,
  `rundll32`, `regsvr32`, `msiexec`, `start`, and scheduled-task creation.

- **RegQuery / DirListing traits** (new in v0.1.0): emitted by the reg and dir
  synth emulators for analyst awareness of anti-sandbox recon patterns.

- **PowerShell payload scanning** (new in v0.1.0): after a PowerShell invocation
  is decoded / assembled from variable concatenation, the resulting ps1 payload
  is scanned for download URLs (`IWR`, `IRM`, `Net.WebClient`, `BITS`) and
  emitted as additional `Download` traits, making URLs visible even when the
  batch script wraps them inside an encoded ps1 blob.

- **Per-trait-kind cap** (`--max-traits-per-kind`, default 100): prevents trait
  explosion from looping downloaders; adds a `TraitsCapped` summary record when
  the cap fires.

### CLI (`batdeob-cli`)

Two subcommands:

- **`batdeob analyze <file>`** — full deobfuscation output as JSON including
  all traits, deobfuscated command lines, child scripts, and summary metadata.

- **`batdeob summarize <file>`** — focused IOC report: downloads, executed
  commands, files written, registry activity, and summary flags. Does **not**
  include raw deobfuscated text, suitable for high-volume triage pipelines.

Bounded-execution flags (all subcommands):

| Flag | Default |
|------|---------|
| `--timeout` | 5 s |
| `--max-iterations` | 65 536 |
| `--max-child-scripts` | 64 |
| `--max-depth` | 12 |
| `--max-output-bytes` | 4 MiB |
| `--max-output-line-bytes` | 64 KiB |

### Safety & Quality

- **Bounded execution**: every analysis run is capped on wall-clock time,
  loop iterations, recursion depth, output bytes, and per-line bytes.
  No sample can cause unbounded memory growth or infinite loops.

- **Corpus regression test** (`tests/corpus.rs`): 30+ representative ITW samples
  smoke-tested on every `cargo test` run; assertions cover trait kinds, download
  counts, and known-deobfuscated strings.

- **Fuzz target** (`fuzz/fuzz_targets/fuzz_analyze.rs`): cargo-fuzz target wraps
  `analyze()` with tight per-input limits; suitable for OSS-Fuzz integration.

- **CI** (`.github/workflows/ci.yml`): build, test, clippy, rustfmt, MSRV
  (1.75), and smoke-fuzz on every push and pull request.

- **Release workflow** (`.github/workflows/release.yml`): cross-compiled binaries
  for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-pc-windows-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`
  on tagged releases.

### Corpus Results (1,416 ITW samples)

| Run | Samples | Success | Rate |
|-----|---------|---------|------|
| v1 (Plan B baseline) | 1,416 | ~1,200 | ~85% |
| v2 (Plan C) | 1,416 | ~1,310 | ~93% |
| v3 (Plan D) | 1,416 | ~1,380 | ~97% |
| v4 (Plan E) | 1,416 | 1,416 | 100% |
| v5 (Plan F / v0.1.0) | 1,416 | 1,416 | 100% |

### Test Count

208 unit + integration tests (0 failures).

[0.1.0]: https://github.com/wmetcalf/batch_deobfuscator/releases/tag/v0.1.0
