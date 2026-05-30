# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed — robustness + IOC accuracy

- **`normalize.rs` + `ps1_scan.rs` strip-marker-noise sandwich check**: the
  3-8 char ngram stripper used to fire on any ngram appearing 5+ times in
  alpha context, which silently mangled identifiers when a variable name
  shared a substring with the surrounding text (`$Hello` + `powershell`
  both contain `ell` → both got `ell`-stripped, producing `$Ho` and
  `powersh`). Now requires sandwich-pattern evidence (the ngram appears
  ≥2 times inside a single alphabetic run) before treating it as marker
  noise. Recovers ~370 corpus samples that previously had their
  PowerShell variable names corrupted.
- **`handlers/powershell.rs::canonical_ps_flag`**: replaced the hand-listed
  `-e`/`-en`/`-enc` prefix matcher with a full PS-shorthand resolver that
  handles `-Ec`/`-Ex`/`-W`/`-NoP` / CamelCase initials / forward-slash
  variants, mirroring real `powershell.exe` parameter binding.
- **`lex.rs::is_var_name_char`**: tightened to reject shell-significant
  operators (`& | ; < > " ^`), preventing `%FOO&BAR%` from swallowing
  the `&` command separator.
- **`handlers/for_cmd.rs::parse_token_range`**: clamps `tokens=N-M` at 64
  so `tokens=1-2147483647` no longer allocates ~17 GB.
- **`lib.rs::decode_utf16le_script_blob`**: 16 MB input cap on the
  pseudo-UTF-16 detector.
- **`interp.rs::capture_synthetic_stdout_redirect` + `handlers/echo.rs`**:
  per-FsEntry cap so a `:loop\necho A>>z.txt\ngoto loop` pattern no
  longer grows `modified_filesystem` past the global output budget.
- **`aes_chain/orchestrator.rs::decode_stage1`**: a benign decoy stage-1
  match used to abort the entire AES chain via `?`; now `continue`s.
- **`aes_chain/orchestrator.rs::split_and_decode_envelope`**: caps the
  per-envelope chunk count at 64.
- **`aes_chain/crypto.rs::gunzip`**: pre-reserves the output capacity so
  the doubling allocator can't overshoot `max_out`.
- **`aes_chain/dotnet.rs::extract_us_strings`**: every PE-header offset
  add now goes through `checked_add` (no 32-bit wrap).
- **`aes_chain/ps_extract.rs::find_aes_pair_with_oracle`**: when the
  regex-driven `find_aes_key_iv` misses (renamed `.Key`/`.IV` fields,
  nested-property assignment, etc.), enumerates every base64 literal in
  the body and uses AES-CBC decrypt + gzip magic as a success oracle.
- **`js_scan.rs::parse_js_string_literal_at`**: full JS string-escape
  decoder (`\xNN`, `\uNNNN`, `\u{...}`, single-char escapes) plus
  `char`-not-`u8` quote-byte compare so non-ASCII chars don't terminate
  literals prematurely (`'ħttp://...'` no longer loses everything after
  the `ħ`).
- **`handlers/cmd.rs::has_v_on`**: respects CMD's LAST-`/v:*`-wins rule;
  `cmd /v:on /v:off` now correctly classified as delayed-expansion off.
- **`deob_scan.rs::scan_decimal_ip_urls`**: new scanner for the PS
  `Invoke-WebRequest 1297338337/x.jpg` decimal-IP form. Rejects
  11+-digit truncations and matches in prose comments.
- **`handlers/mod.rs::lookup`**: dispatch by exact basename (stripped of
  `.exe`) instead of `ends_with`, so `flashcmd.exe` no longer routes to
  the cmd handler.
- **`ps_alias.rs::looks_like_powershell`**: also accepts a bare network
  alias (`iex`, `iwr`, `irm`) at command position so alias-only payloads
  trigger alias expansion.
- **`cli/main.rs::safe_write_new`**: `O_CREATE | O_EXCL` plus
  `O_NOFOLLOW` on Unix when emitting extracted children, closing the
  TOCTOU window around `safe_join`.
- **`deob_scan.rs::is_noise_url`**: 200-line if-chain replaced with three
  const tables.

### Refactored

- New `crates/batdeob-core/src/marker_noise.rs` shared module — the
  strip-marker-noise algorithm and protected-keyword list used to be
  duplicated byte-for-byte in `normalize.rs` and `ps1_scan.rs`.
- New `Environment::known_extracted_urls()` helper — 12 URL scanners
  previously each re-derived the dedup set with their own `match` over
  `Trait` variants. Centralizing means a new URL-bearing trait kind is
  one edit, not 12.

### Added

- `tools/corpus_audit.py` + `tools/corpus_iterate.py` — driver scripts
  for the corpus regression workflow (audit CSV + next-batch TSV).

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

Five subcommands:

- **`batdeob deob <file> -o <dir>`** — writes the deobfuscated batch,
  extracted child scripts (`.bat` / `.ps1` / normalized `.ps1`), and
  `traits.json` into the given directory.

- **`batdeob analyze <file>`** — full deobfuscation output as JSON
  including all traits, deobfuscated command lines, child scripts, and
  summary metadata.

- **`batdeob summarize <file>`** — focused IOC report: downloads,
  executed commands, files written, registry activity, and summary
  flags. Does **not** include raw deobfuscated text — suitable for
  high-volume triage pipelines.

- **`batdeob report <file>`** — pretty-printed analyst-facing report.
  Optional `--include-source` / `--include-deob` re-inline the input
  and deobfuscated text.

- **`batdeob version`** — print the engine version.

Bounded-execution flags (all subcommands):

| Flag | Default |
|------|---------|
| `--timeout` | 10 s |
| `--max-iterations` | 65 536 |
| `--max-child-scripts` | 64 |
| `--max-depth` | 12 |
| `--max-output-bytes` | 10 MiB |
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
  (1.78), and smoke-fuzz on every push and pull request.

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

506 unit + integration + parity + corpus tests (0 failures).

[0.1.0]: https://github.com/wmetcalf/batch_deobfuscator/releases/tag/v0.1.0
