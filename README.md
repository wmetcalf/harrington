# Harrington — Windows batch deobfuscator

Static-analysis deobfuscator for Windows `.bat` / `.cmd` scripts. Never
invokes PowerShell or `cmd.exe`. Runs on Linux, macOS, and Windows.

Harrington is the public name for the tool. The Rust crates are
`harrington-core` and `harrington-cli`, and the CLI binary is
`harrington`.

Handles real-world obfuscation: caret-escape, comma/semicolon
substitution, `%VAR%` and `!VAR!` with substring + substitution
operators, DOSfuscation FOR-loop ciphers, `setlocal enabledelayedexpansion`,
percent-tilde, `set /a` arithmetic, IF constant-folding, `goto :label`,
`call :label`, the FOR-loop interpreter, and a synthetic emulator for
`set` / `findstr` / `find` / `type` / `assoc` / `ftype` / `reg query` /
`dir` / `whoami` / `chcp` / `query` / `tasklist` / `where`.

Tracks IOCs from `curl` / `bitsadmin` / `certutil` / `mshta` /
`rundll32` / `wmic` / `cscript` / `wscript` / `extrac32` / `net use` +
23 pass-through admin commands. Extracts and scans embedded
PowerShell / JScript / VBScript payloads. Replays the AES-CBC
multi-stage dropper chain (stage-1 base64+marker → UTF-16LE PS →
inline gzipped stage-2 → AES-decrypt → reflection-load .NET assembly)
and surfaces the recovered key material via the `MultiStageEncryptedDropper`
trait.

## Install

From crates.io (once published):

```bash
cargo install harrington-cli
```

From source (Rust 1.78+):

```bash
git clone https://github.com/wmetcalf/harrington
cd harrington/rust
cargo build --release -p harrington-cli
./target/release/harrington version
```

Add to PATH:

```bash
export PATH="$PWD/rust/target/release:$PATH"
```

## Usage

Five subcommands. Run `harrington <subcommand> --help` for full options.

### `summarize` — analyst's TL;DR

Compact JSON report: downloads, lolbas, admin commands, extracted script
counts, PowerShell samples, deob preview. No files written. **Use this first
for triage.**

```bash
harrington summarize sample.bat
```

Optional external LOLBAS enrichment can annotate recognized command lines
without bundling GPL-licensed LOLBAS data:

```bash
harrington summarize sample.bat --lolbas-json /path/to/lolbas.json
harrington analyze sample.bat --lolbas-json /path/to/lolbas.json
harrington report sample.bat --lolbas-json /path/to/lolbas.json
harrington deob sample.bat --json-only --lolbas-json /path/to/lolbas.json
```

When supplied, JSON output includes `lolbas_matches[]` entries with the
matched binary name, observed command line, LOLBAS URL, categories, and
MITRE IDs from that user-provided file. For `analyze --jsonl`, matches
are emitted as `{"kind":"lolbas_match", ...}` events.

### `analyze` — full structured JSON

Every trait, every URL, the full deobfuscated text.

```bash
harrington analyze sample.bat              # pretty JSON
harrington analyze --jsonl sample.bat      # one event per line (meta / trait / deob)
```

Pipe `--jsonl` output through `jq` for grep-like workflows.

### `report` — comprehensive JSON for archival

Everything `summarize` produces, plus the full typed trait list and a
SHA-256 of the input. Two opt-in flags inline the raw source and the
deobfuscated text as JSON strings.

```bash
harrington report sample.bat                                  # summary + traits + sha256
harrington report --include-source sample.bat                 # + JSON-escaped input bytes
harrington report --include-deob sample.bat                   # + JSON-escaped deob text
harrington report --include-source --include-deob sample.bat  # the whole picture in one blob
```

Use this when you want a single self-contained record per sample —
re-analysis without keeping the original `.bat` around, IR pipelines,
sample databases, etc.

### `deob` — write files to disk

```bash
harrington deob sample.bat -o ./out
```

Produces:

| File | Contents |
|------|----------|
| `deobfuscated.bat` | Human-readable cleaned script |
| `traits.json` | All IOCs as a JSON array |
| `<sha10>.bat` | Each extracted CMD child |
| `<sha10>.ps1` | Each extracted PowerShell payload |
| `<sha10>.normalized.ps1` | Normalized PowerShell payload when readability improves |
| `<sha10>.js` | Each extracted JScript payload |
| `<sha10>.vbs` | Each extracted VBScript payload |

### `version`

```bash
harrington version
```

## Stdin

Every subcommand accepts `-` as the file argument. Capped at 256 MB.

```bash
echo 'set X=ll & set Y=he & %Y%%X%o' | harrington analyze -
```

## Limits and tuning

The interpreter is bounded everywhere — a malicious sample cannot force
unbounded work. Defaults are conservative; raise or lower per workload:

| Flag | Default | What it caps |
|------|---------|--------------|
| `--timeout N` | 10s | wall-clock per sample |
| `--max-depth N` | 12 | recursive cmd-in-cmd nesting |
| `--max-iterations N` | 65536 | FOR-loop iterations |
| `--max-child-scripts N` | 64 | extracted children |
| `--max-output-bytes N` | 10 MiB | total deobfuscated output |
| `--max-output-line-bytes N` | 64 KiB | per line |
| `--max-traits-per-kind N` | 100 | IOC dedup ceiling |
| `--no-self-extract` | off | disable `%~f0` self-reference resolution |

Input is hard-capped at 256 MB (stdin or on-disk).

## Library usage

`harrington-core` is also usable as a Rust library. Runnable examples live
in `rust/crates/harrington-core/examples/`:

| Example | What it shows |
|---------|---------------|
| `basic` | Minimum-viable load + analyze + print URL traits |
| `custom_config` | Override every limit (timeout, recursion, output caps) |
| `filter_aes_dropper` | Detect the AES-CBC dropper family and dump recovered Key/IV |
| `batch_url_extract` | Stream paths from stdin, emit one CSV line per file |

```bash
cargo run --example basic              -p harrington-core -- sample.bat
cargo run --example custom_config      -p harrington-core -- sample.bat
cargo run --example filter_aes_dropper -p harrington-core -- sample.bat
find samples/ -name '*.bat' | cargo run --example batch_url_extract -p harrington-core
```

Core API surface:

```rust
use harrington_core::{analyze, Config, Report, Trait, WinVer};

let input = std::fs::read("sample.bat")?;
let report: Report = analyze(&input, &Config::default());

for trait_event in &report.traits {
    match trait_event {
        Trait::Download { src, dst, .. }        => { /* explicit handler hit */ }
        Trait::DownloadInDeobText { src, line_hint } => { /* text-sweep hit */ }
        Trait::UncWebDavC2 { http_url, .. }     => { /* webdav C2, resolved URL */ }
        Trait::MultiStageEncryptedDropper {
            aes_key_b64, aes_iv_b64, nested_aes, ..
        } => { /* outer + inner key material */ }
        _ => {}
    }
}

// Extracted children are in report.extracted_cmd, extracted_ps1,
// extracted_jscript, and extracted_vbs. PowerShell payloads also have
// report.extracted_ps1_normalized.
// The deobfuscated text is report.deobfuscated.
```

The public types are all in `harrington_core::{Config, Report, Trait,
WinVer}` and the module roots
`harrington_core::{deob_scan, ps1_scan, js_scan, vbs_scan, aes_chain}`.

## Trait kinds emitted

The `traits.json` output is a list of typed events; each has a
discriminator `"kind"` field. Most useful kinds:

- `Download` — explicit URL download from a handler
  (`curl`/`wget`/`bitsadmin`/etc.) with `cmd`, `src`, `dst`
- `CertutilDownload`, `BitsadminDownload` — same shape, command-specific
- `DownloadInDeobText` — URL recovered from a deobfuscated-text sweep;
  `line_hint` identifies which sweep
  (`certutil-decode-js`, `echo-unicode-js`, `delim-wrapped-mshta-hta`,
  `bare-ip-url`, `trunc-url-var`, `quoted-b64-string`,
  `FromBase64String inline`, `b64-url-prefix` (UTF-8 + UTF-16LE base64
  `aHR0c…`/`aAB0AHQAcAA…` anchored decode), `ps-char-concat`
  (`[char[]]@(N,N,…)-join''` chain recovery), `aes-chain`, etc.)
- `UncWebDavC2` — `\\host@port\davwwwroot\...` C2 reference, with the
  derived `http_url` (e.g. `https://host/file`)
- `MultiStageEncryptedDropper` — AES-CBC dropper detected; carries the
  outer `aes_key_b64` / `aes_iv_b64`, `assemblies_recovered` count, and
  `nested_aes` pairs harvested from the .NET assembly's `#US` heap.
  **Caveat for analysts:** the AES-CBC chain is decrypted without MAC
  validation (the malware's key/IV travels in plaintext alongside the
  ciphertext, so this is key-recovery, not crypto). A sample whose author
  knows it will hit harrington can craft ciphertext that decrypts to a
  misleading URL or PE header. Treat URLs surfaced via the `aes-chain`
  line-hint and `nested_aes` pairs as leads to verify, not signed truths.
- `Lolbas`, `Mshta`, `Rundll32`, `AdminCommand`, `WindowsUtilManip`,
  `NetUse`
- `SetlocalScope`, `DelayedExpansionUsed`, `EchoRedirect` — structural
- `LineTruncated`, `OutputCapped`, `TraitsCapped`, `IterationCapped`,
  `DepthCapped`, `ChildScriptsCapped`, `TimeoutHit` — limit signals

## Status

- 100% crash-free, 0 timeouts on a 1,416-sample real-world malware corpus
- 67.0% URL IOC recall on that corpus (949 / 1416)
- 506 unit + integration + parity + corpus tests passing
- Clippy clean with `-D warnings`
- `cargo-fuzz` validated — no panics or UB on random byte input
- MSRV 1.78 for the library crate

## Naming

Harrington is the tool name used in the CLI and docs. The underlying
crate names are unchanged so existing scripts and dependency references
continue to work.

### Deobfuscation coverage (selected)

CMD lexing edge cases that real samples hit:

- caret-escape `^X` (consumed) and line-continuation trailing `^`
- caret inside `"..."` preserved literally (`set /a` XOR support)
- `,;` between arg-words preserved (rundll32, PS argument lists); DOSfuscation
  `,;,cmd.exe /c X` still splits on token boundaries
- `%%X` / `%%~xX` / `%%X:op%%` preserved verbatim for unresolved FOR
- `%%%%X` (four-percent escape) renders as literal `%%X` — no off-by-one
- unmatched `"` at EOL kept as a literal Word (no synthesized closing quote)
- `%<digit><name>%` parses as a variable ref (malware vars with leading
  digit), not just as positional `%4`
- `set "X=val<EOL>` auto-closes the missing quote — keeps marker-strip
  chains (`%X:WJesB=%`) working in EBKG-style samples
- `(set k=value)` group strips the wrapping parens
- runtime-only `%errorlevel%` / `%cmdcmdline%` render as literal so
  conditional logic isn't constant-folded

Control-flow handling:

- `:label` lines echoed on first visit only (goto-loop dedup)
- multi-line `for ... do (\n…\n)` no longer doubles the open paren
- unresolved-source FOR doesn't duplicate its body in the deob output
- trivial / single-pipeline `cmd /c X` children don't duplicate-emit the
  wrapper text
- `cmd /V:ON /C "..." > NUL` outer-redirect tail stripped so the inner
  block's nested `"..."` quotes lex correctly

IOC recovery:

- base64-encoded URLs anchored on `aHR0c…` (UTF-8) and `aAB0AHQAcAA…`
  (UTF-16LE) prefixes, terminated at the first non-printable / quote /
  angle byte to keep dedup clean
- PowerShell `[char[]]@(N,N,…)-join'' + (...)` chains reassembled into
  whole URLs
- VNC / tightvnc `-connect IP:PORT` reverse-shell C2 surfaced as a
  synthesized `http://IP:PORT` Download trait
- polyglot `<script language="JScript|VBScript">…</script>` blocks
  embedded in `.bat` (mshta-driven) pre-extracted and walked through the
  same UNC / URL scanners as standalone payloads

## Project layout

```
harrington/
├── rust/                                  # workspace (primary)
│   ├── crates/harrington-core/              # library
│   ├── crates/harrington-cli/               # `harrington` binary
│   ├── fuzz/                             # cargo-fuzz target
│   └── tools/
│       ├── collect-windows-env.bat       # pure-cmd Windows env collector
│       └── extract-from-wim/             # WIM-based registry/env extractor
└── docs/                                  # user-facing docs
```

## Acknowledgments

The synthetic Windows environment snapshot
(`rust/crates/harrington-core/data/win11.json`) was extracted from a
Windows 11 25H2 Pro `install.wim` using the helper at
`rust/tools/extract-from-wim/`. No registry data ships from Microsoft
directly.

## License

Licensed under [MIT](LICENSE). The Rust port and extensions are
copyright (c) 2026 Will Metcalf; the underlying Python
`batch_deobfuscator` algorithm is copyright (c) 2018 Malwrologist.
