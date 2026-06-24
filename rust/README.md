# batdeob — Rust port of batch_deobfuscator

Static-analysis deobfuscator for Windows batch scripts. Library crate
(`batdeob-core`) plus a single-binary CLI (`batdeob`). Runs on Linux,
macOS, and Windows; never invokes PowerShell or cmd.exe.

See `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md` for
the full design.

## Build

```bash
cd rust
cargo build --workspace --release
./target/release/batdeob version
```

## Usage

```bash
# deobfuscate a script, writing deobfuscated.bat + extracted children
batdeob deob path/to/script.bat -o ./out

# JSON-only report to stdout
batdeob analyze path/to/script.bat

# stdin
echo 'set X=hi&&echo %X%' | batdeob deob -
```

## Status

| Plan | Status | Scope |
|---|---|---|
| A — Foundation | this plan | lex / normalize / split / interp dispatch, basic + Python-parity handlers (set, echo, cmd, powershell, curl, mshta, rundll32, copy, net), CLI |
| B — Control flow + DOSfuscation | follow-on | goto/call :label, for-loop interpreter, set /a evaluator, synthetic command emulator (assoc/ftype/findstr/find/type), self-extract `%~f0`, IF evaluation, percent-tilde |
| C — LOLBAS + corpus + CI | follow-on | certutil/bitsadmin/wmic/cscript/wscript, corpus regression tests, cargo-fuzz, GitHub Actions, release pipeline |
