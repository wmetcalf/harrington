# batdeob Plan C — LOLBAS + Corpus + CI + Bug Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address every corpus-discovered issue from the 1,416-sample run + ship the LOLBAS handlers the spec calls out + add corpus regression tests, fuzzing, CI, and a release pipeline. Order is driven by empirical priority from the corpus run.

**Architecture:** Builds on Plans A + B. Tasks 1-2 are critical bug fixes (currently 17.6% of corpus panics). Tasks 3-9 add the missing handlers and safety caps. Tasks 10-13 add CI, fuzz, corpus regression, and release.

**Tech Stack:** Same as Plans A/B. New tools added: `cargo-fuzz`, GitHub Actions, `cross` for multi-target release.

**Corpus baseline (before Plan C):**
- 1,416 samples processed in 16s (8-way parallel)
- 82.4% success (1167)
- 17.6% panic (249) — all caused by 2 Unicode-handling bugs
- Output size: median 1.2 KB, p99 30 MB, worst 560 MB (adversarial)
- Top unhandled commands: `certutil -decode` (62 samples), `extrac32` (23), `start-process` (12), `python.exe` (14)

**Spec:** `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md`

**Prereq:** Plans A + B + all fixups landed. 167 tests passing.

---

## Task 1: Fix char-vs-byte panic in `command_name()` (interp.rs:101)

**Impact:** 237 corpus samples currently panic with `byte index N is not a char boundary`. All caused by binary content (PE/MZ disguised as .bat) or multi-byte chars near redirection operators.

**Files:**
- Modify: `rust/crates/batdeob-core/src/interp.rs`

- [ ] **Step 1: Write failing test** in `lib.rs`:

```rust
#[cfg(test)]
mod char_boundary_tests {
    use crate::{analyze, Config};

    #[test]
    fn binary_content_does_not_panic() {
        // PE header at start, then a > to trigger redirection parsing.
        let mut script = vec![0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        script.extend_from_slice(b" > file.txt\r\n");
        let _ = analyze(&script, &Config::default());
        // If we get here without panic, we're good.
    }

    #[test]
    fn multibyte_char_at_redirect_boundary() {
        let script = "echo ₳ > out.txt\r\n".as_bytes();
        let _ = analyze(script, &Config::default());
    }
}
```

- [ ] **Step 2: Verify they panic**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core char_boundary 2>&1 | tail -10
```

- [ ] **Step 3: Fix `command_name()` in `interp.rs`**

Open `interp.rs`. Find the function that does redirection-aware command extraction (described in the bug report at `interp.rs:101`). The bug is `chars().enumerate()` producing char-indices used as byte-slice indices. Replace with `char_indices()`:

Read the function first:
```bash
grep -n "command_name\|chars().enumerate\|char_indices" /home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/src/interp.rs
```

The likely fix pattern: replace `for (i, c) in s.chars().enumerate()` with `for (i, c) in s.char_indices()`, then use `i` directly as a byte offset for slicing.

Read the actual file, identify the broken loop, and apply the fix.

- [ ] **Step 4: Verify both tests pass**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core char_boundary 2>&1 | tail -10
```

- [ ] **Step 5: Run corpus subset** as smoke test:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
# Re-run on one of the previously-panicking samples
/home/coz/Downloads/batch_deobfuscator/rust/target/release/batdeob analyze "/home/coz/cstorage/mbzdls/QUOTE 7254.bat" 2>&1 | head -5
```
Expected: no panic. Either a successful JSON output or a graceful exit.

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Fix char-vs-byte indexing panic in command_name()"
```

---

## Task 2: Fix `apply_substitute` byte-stride panic (normalize.rs:237)

**Impact:** 12 corpus samples panic on CJK Unicode padding. Affects the FX.cmd-style obfuscation family.

**Files:**
- Modify: `rust/crates/batdeob-core/src/normalize.rs`

- [ ] **Step 1: Write failing test** in `lib.rs`:

```rust
#[cfg(test)]
mod cjk_padding_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    #[test]
    fn cjk_padded_var_substitution_does_not_panic() {
        // A value with multi-byte chars, then a substitute that would advance
        // i by needle.len() bytes — must respect char boundaries.
        let mut env = Environment::new(&Config::default());
        env.set("X", "abc₳def₳ghi");  // multi-byte char inside
        let toks = lex("%X:def=zzz%");
        let _ = normalize_to_string(&toks, &mut env);
        // No panic = win.
    }

    #[test]
    fn long_cjk_padding_chain() {
        // Mimics the FX.cmd-style sample.
        let mut env = Environment::new(&Config::default());
        let huge: String = "京京京京京京京京京京".repeat(20);
        env.set("X", &huge);
        let toks = lex("%X:京=A%");
        let out = normalize_to_string(&toks, &mut env);
        assert_eq!(out, "A".repeat(200));
    }
}
```

- [ ] **Step 2: Verify they panic** (the first one will, the second one's outcome depends on the fix):

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core cjk_padding 2>&1 | tail -10
```

- [ ] **Step 3: Fix `apply_substitute` in `normalize.rs`**

Read the function:
```bash
grep -n "fn apply_substitute\|needle.len()" /home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/src/normalize.rs
```

The bug is at the case-insensitive match branch: when the needle matches at position `i`, the code advances `i += needle.len()` (bytes), which may land in the middle of a multi-byte UTF-8 char if `needle` happens to end at a multi-byte boundary or the haystack continues with a multi-byte char.

Fix: use a more cautious advance, e.g., advance by `needle.len()` ONLY when matched (since the match aligned bytewise on both sides), but BEFORE checking the next iteration, verify `s.is_char_boundary(i)` and if not, advance by `s[i..].chars().next().map_or(1, |c| c.len_utf8())` until aligned.

Actual likely fix — rewrite using a char-by-char advance that does case-insensitive match on segments:

```rust
fn apply_substitute(s: &str, needle: &str, repl: &str, wildcard: bool) -> String {
    if needle.is_empty() { return s.to_string(); }
    // ... wildcard branch unchanged ...

    let mut out = String::with_capacity(s.len());
    let needle_lower = needle.to_ascii_lowercase();
    let nlen = needle.len();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Try to match needle at this position — only valid if i + nlen is in bounds
        // AND s.is_char_boundary(i + nlen).
        if i + nlen <= bytes.len()
            && s.is_char_boundary(i + nlen)
            && s[i..i + nlen].eq_ignore_ascii_case(&needle_lower)
        {
            out.push_str(repl);
            i += nlen;
        } else {
            // Advance by ONE char (not one byte)
            let c = match s[i..].chars().next() {
                Some(c) => c,
                None => break,
            };
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}
```

Apply this. The key invariant: `i` is always on a char boundary.

- [ ] **Step 4: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core 2>&1 | tail -10
```
Both CJK tests must pass + all prior tests must still pass.

- [ ] **Step 5: Re-run on the previously-panicking corpus sample**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
/home/coz/Downloads/batch_deobfuscator/rust/target/release/batdeob analyze /home/coz/cstorage/mbzdls/105e06b9770ed2d002dce521b40e89455ae5d5bf08295af1f39faf3e1c4da474.bat 2>&1 | head -10
```
Expected: no panic.

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Fix multi-byte panic in apply_substitute char-boundary handling"
```

---

## Task 3: Output size cap

**Impact:** 16 corpus samples produced output >10 MB, worst 560 MB. The `--timeout 5` fires but only after the interpreter has buffered the entire output. Adversarial input can OOM the analyst.

**Files:**
- Modify: `rust/crates/batdeob-core/src/env.rs` (add `max_output_bytes` to Config + Limits)
- Modify: `rust/crates/batdeob-core/src/lib.rs` (`drive()` checks output size after each command)
- Modify: `rust/crates/batdeob-core/src/traits.rs` (add `OutputCapped` variant)
- Modify: `rust/crates/batdeob-cli/src/main.rs` (expose `--max-output-bytes`)

- [ ] **Step 1: Add trait variant** to `traits.rs`:

```rust
    OutputCapped { bytes_at_cap: u64 },
```

Add to BOTH the existing Plan A "placeholder" group and the trait enum proper.

- [ ] **Step 2: Add `max_output_bytes` to `Config`** (env.rs):

```rust
    pub max_output_bytes: u64,
```

Default to **4 MB** (`4 * 1024 * 1024`) — comfortably above p99 of corpus output (30 MB is p99 of successful runs, but those are pathological; 4 MB caps the cases that actually matter). Update `Config::default()`.

Add to `Limits`:
```rust
    pub max_output_bytes: u64,
    pub output_bytes: u64,
```

`Environment::new` populates from cfg.

- [ ] **Step 3: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod output_cap_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn output_cap_fires_on_pathological_loop() {
        // A script that would generate megabytes of output via repeat-set
        let mut script = String::new();
        for _ in 0..10000 {
            script.push_str("set X=hello_world_value_for_padding_purposes\r\n");
        }
        // Use a tiny cap to force the trip
        let cfg = Config { max_output_bytes: 1024, ..Config::default() };
        let report = analyze(script.as_bytes(), &cfg);
        let capped = report.traits.iter().any(|t| matches!(t, Trait::OutputCapped { .. }));
        assert!(capped, "expected OutputCapped trait. traits: {:?}", report.traits);
        assert!(
            report.deobfuscated.len() < 4096,
            "output should be bounded near cap, got {} bytes",
            report.deobfuscated.len()
        );
    }
}
```

- [ ] **Step 4: Implement the cap** in `drive()` (`lib.rs`):

After each `out.push_str(&normalized)` and after the iter_output drain, check:

```rust
            if (out.len() as u64) >= env.limits.max_output_bytes {
                if !env.traits.iter().any(|t| matches!(t, Trait::OutputCapped { .. })) {
                    env.traits.push(Trait::OutputCapped {
                        bytes_at_cap: out.len() as u64,
                    });
                }
                should_halt = true;
                break;
            }
```

- [ ] **Step 5: Wire CLI flag** in `main.rs`:

Add to both `Deob` and `Analyze` variants:
```rust
        #[arg(long, default_value_t = 4 * 1024 * 1024)]
        max_output_bytes: u64,
```

Pass through `make_config()`.

- [ ] **Step 6: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/ rust/crates/batdeob-cli/src/
git commit -m "Add --max-output-bytes cap (default 4 MB) to bound adversarial output"
```

---

## Task 4: `certutil` handler

**Impact:** 62 corpus samples use `certutil -decode` or `certutil -urlcache` and currently get no special handling. The spec describes this as a triple-decode chain pattern.

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/certutil.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (tests)

The trait variants `Trait::CertutilDecode` and `Trait::CertutilDownload` already exist (Plan A placeholders).

- [ ] **Step 1: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod certutil_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    fn b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    #[test]
    fn certutil_decode_emits_trait_and_writes_fs_entry() {
        let mut env = Environment::new(&Config::default());
        let payload = "hello world";
        env.modified_filesystem.insert(
            "src.b64".to_string(),
            FsEntry::Content { content: b64(payload).into_bytes(), append: false },
        );
        interpret_line("certutil -decode src.b64 dst.bin", &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::CertutilDecode { src, dst, .. } if src == "src.b64" && dst == "dst.bin"
        ));
        assert!(has, "no CertutilDecode trait: {:?}", env.traits);
        if let Some(FsEntry::Decoded { content, .. }) = env.modified_filesystem.get("dst.bin") {
            assert_eq!(&content[..], payload.as_bytes());
        } else {
            panic!("dst.bin not Decoded: {:?}", env.modified_filesystem.get("dst.bin"));
        }
    }

    #[test]
    fn certutil_urlcache_emits_download_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line("certutil -urlcache -split -f http://x/y.exe out.exe", &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::CertutilDownload { url, dst } if url == "http://x/y.exe" && dst == "out.exe"
        ));
        assert!(has, "no CertutilDownload trait: {:?}", env.traits);
    }

    #[test]
    fn certutil_decode_unresolved_src_still_emits_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line("certutil -decode missing.b64 dst.bin", &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::CertutilDecode { src_resolved: false, .. }
        ));
        assert!(has, "no CertutilDecode with src_resolved=false: {:?}", env.traits);
        // dst.bin should NOT have been created
        assert!(!env.modified_filesystem.contains_key("dst.bin"));
    }
}
```

- [ ] **Step 2: Verify they fail**

- [ ] **Step 3: Create `handlers/certutil.rs`**:

```rust
//! certutil handler — handles -decode, -decodehex, -urlcache for LOLBAS use.

use crate::env::{DecodeKind, Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;
use base64::Engine;

pub fn h_certutil(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();

    // -urlcache -split -f URL DST
    if lower.iter().any(|t| t == "-urlcache") {
        if let Some(url) = find_first_url(&tokens) {
            let dst = find_dst_after_url(&tokens, &url);
            env.traits.push(Trait::CertutilDownload {
                url: url.clone(),
                dst: dst.clone().unwrap_or_default(),
            });
            if let Some(d) = dst {
                env.modified_filesystem.insert(d.to_ascii_lowercase(), FsEntry::Download { src: url });
            }
        }
        return;
    }

    // -decode SRC DST  /  -decodehex SRC DST
    let (method, flag) = if let Some(p) = lower.iter().position(|t| t == "-decode") {
        (DecodeKind::Base64, p)
    } else if let Some(p) = lower.iter().position(|t| t == "-decodehex") {
        (DecodeKind::Hex, p)
    } else {
        return;
    };

    let src = match tokens.get(flag + 1) {
        Some(s) => strip_quotes(s).to_string(),
        None => return,
    };
    let dst = match tokens.get(flag + 2) {
        Some(s) => strip_quotes(s).to_string(),
        None => return,
    };

    let src_key = src.to_ascii_lowercase();
    let src_content = env.modified_filesystem.get(&src_key)
        .and_then(|e| match e {
            FsEntry::Content { content, .. } => Some(content.clone()),
            FsEntry::Decoded { content, .. } => Some(content.clone()),
            _ => None,
        });

    let src_resolved = src_content.is_some();
    env.traits.push(Trait::CertutilDecode {
        src: src.clone(),
        dst: dst.clone(),
        src_resolved,
    });

    if let Some(bytes) = src_content {
        let decoded: Option<Vec<u8>> = match method {
            DecodeKind::Base64 => {
                let s = std::str::from_utf8(&bytes).ok()?;
                base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()
            }
            DecodeKind::Hex => {
                let s = std::str::from_utf8(&bytes).ok()?;
                hex::decode(s.trim().replace(&[' ', '\n', '\r', '\t'][..], "")).ok()
            }
        };
        if let Some(d) = decoded {
            env.modified_filesystem.insert(
                dst.to_ascii_lowercase(),
                FsEntry::Decoded { content: d, src, method },
            );
        }
    }
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}

fn find_first_url(tokens: &[String]) -> Option<String> {
    tokens.iter()
        .find(|t| t.starts_with("http://") || t.starts_with("https://") || t.starts_with("ftp://"))
        .map(|s| strip_quotes(s).to_string())
}

fn find_dst_after_url(tokens: &[String], url: &str) -> Option<String> {
    let mut found_url = false;
    for t in tokens {
        if !found_url {
            if strip_quotes(t) == url { found_url = true; }
            continue;
        }
        if !t.starts_with('-') {
            return Some(strip_quotes(t).to_string());
        }
    }
    None
}
```

Note: the `?` operator inside `let decoded: Option<Vec<u8>> = ...` block requires the closure / function to return `Option`. Wrap in an inner `(|| -> Option<Vec<u8>> { ... })()` IIFE if you hit compile errors.

- [ ] **Step 4: Register** in `handlers/mod.rs`:

```rust
pub mod certutil;

// in lookup suffix-dispatch section:
    if lower.ends_with("certutil") || lower.ends_with("certutil.exe") {
        return Some(certutil::h_certutil);
    }
```

- [ ] **Step 5: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
```

- [ ] **Step 6: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add certutil handler: -decode, -decodehex, -urlcache -split -f"
```

---

## Task 5: `bitsadmin` handler

**Impact:** 10 corpus samples. Pattern: `bitsadmin /transfer name URL DST` — track as download.

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/bitsadmin.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (test)

- [ ] **Step 1: Add test**:

```rust
#[cfg(test)]
mod bitsadmin_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn bitsadmin_transfer_emits_download() {
        let mut env = Environment::new(&Config::default());
        interpret_line("bitsadmin /transfer myjob /Download /Priority FOREGROUND http://x/y.exe C:\\temp\\y.exe", &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::BitsadminDownload { url, dst } if url == "http://x/y.exe" && dst == "C:\\temp\\y.exe"
        ));
        assert!(has, "no BitsadminDownload: {:?}", env.traits);
    }
}
```

- [ ] **Step 2: Implement**:

```rust
//! bitsadmin handler — extracts /transfer URL + DST.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_bitsadmin(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let lower: Vec<String> = tokens.iter().map(|s| s.to_ascii_lowercase()).collect();
    if !lower.iter().any(|t| t == "/transfer") { return; }

    // Skip past /transfer and known flags to find URL + DST
    let mut url: Option<String> = None;
    let mut dst: Option<String> = None;
    let skip_flags = ["/transfer", "/download", "/upload", "/priority"];
    let skip_values = ["/priority"];  // flags whose VALUE we skip too

    let mut i = 1;  // skip "bitsadmin"
    while i < tokens.len() {
        let t = &tokens[i];
        let tl = t.to_ascii_lowercase();
        if skip_flags.contains(&tl.as_str()) {
            if skip_values.contains(&tl.as_str()) { i += 2; } else { i += 1; }
            continue;
        }
        // Job name (first positional after /transfer) — skip if URL not yet seen
        // and current token doesn't look like URL.
        if !t.starts_with("http") && !t.starts_with("ftp") && url.is_none() && !t.starts_with('/') {
            // This is the job name. Skip it.
            i += 1;
            continue;
        }
        if (t.starts_with("http://") || t.starts_with("https://") || t.starts_with("ftp://")) && url.is_none() {
            url = Some(strip_quotes(t).to_string());
            i += 1;
            continue;
        }
        if url.is_some() && dst.is_none() && !t.starts_with('/') {
            dst = Some(strip_quotes(t).to_string());
            i += 1;
            continue;
        }
        i += 1;
    }

    if let Some(u) = url {
        let d = dst.unwrap_or_default();
        env.traits.push(Trait::BitsadminDownload { url: u.clone(), dst: d.clone() });
        if !d.is_empty() {
            env.modified_filesystem.insert(d.to_ascii_lowercase(), FsEntry::Download { src: u });
        }
    }
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}
```

- [ ] **Step 3: Register, test, commit**:

```rust
pub mod bitsadmin;
// in lookup match arm:
        "bitsadmin" => Some(bitsadmin::h_bitsadmin),
```

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add bitsadmin handler for /transfer URL extraction"
```

---

## Task 6: `wmic` handler

**Impact:** 24 corpus samples. Pattern: `wmic process call create "cmd"` — extract inner cmd.

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/wmic.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (test)

- [ ] **Step 1: Add test**:

```rust
#[cfg(test)]
mod wmic_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn wmic_process_call_create_extracts_inner() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"wmic process call create "cmd /c echo hi""#, &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::WmicProcessCreate { inner_cmd } if inner_cmd.contains("echo hi")
        ));
        assert!(has, "no WmicProcessCreate: {:?}", env.traits);
        // Inner should also be queued for recursion via exec_cmd
        assert!(env.exec_cmd.iter().any(|c| c.contains("echo hi")), "no recursive cmd: {:?}", env.exec_cmd);
    }
}
```

- [ ] **Step 2: Implement**:

```rust
//! wmic handler — extracts the inner command from `wmic process call create "..."`.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;

// Regex is a compile-time constant.
#[allow(clippy::expect_used)]
static WMIC_PROCESS_CREATE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)^\s*wmic\s+process\s+call\s+create\s+["'](?P<cmd>.+)["']\s*$"#)
        .expect("wmic regex")
});

pub fn h_wmic(raw: &str, env: &mut Environment) {
    let Some(caps) = WMIC_PROCESS_CREATE_RE.captures(raw) else { return };
    let inner = caps.name("cmd").map(|m| m.as_str().to_string()).unwrap_or_default();
    if inner.is_empty() { return; }
    env.traits.push(Trait::WmicProcessCreate { inner_cmd: inner.clone() });
    env.exec_cmd.push(inner);
    env.exec_cmd_delayed.push(false);
}
```

- [ ] **Step 3: Register, test, commit**:

```rust
        "wmic" => Some(wmic::h_wmic),
```

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add wmic process call create handler with recursive inner extraction"
```

---

## Task 7: `cscript` / `wscript` handlers

**Impact:** Spec calls this out; corpus has scattered VBScript droppers (the `bitsadmin` sample from earlier exploration).

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/cscript.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (test)

- [ ] **Step 1: Add test**:

```rust
#[cfg(test)]
mod cscript_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn cscript_with_vbs_content_extracts_payload() {
        let mut env = Environment::new(&Config::default());
        let vbs_content = b"WScript.Echo \"hi\"\r\n".to_vec();
        env.modified_filesystem.insert(
            "dropper.vbs".to_string(),
            FsEntry::Content { content: vbs_content.clone(), append: false },
        );
        interpret_line("cscript //nologo dropper.vbs", &mut env);
        let has = env.traits.iter().any(|t| matches!(t, Trait::CscriptExec { src } if src == "dropper.vbs"));
        assert!(has, "no CscriptExec: {:?}", env.traits);
        assert!(env.exec_vbs.iter().any(|c| c == &vbs_content), "vbs not extracted");
    }

    #[test]
    fn wscript_with_js_content_extracts_payload() {
        let mut env = Environment::new(&Config::default());
        let js_content = b"WScript.Echo('hi')\r\n".to_vec();
        env.modified_filesystem.insert(
            "drop.js".to_string(),
            FsEntry::Content { content: js_content.clone(), append: false },
        );
        interpret_line("wscript drop.js", &mut env);
        assert!(env.exec_jscript.iter().any(|c| c == &js_content), "js not extracted");
    }
}
```

- [ ] **Step 2: Implement**:

```rust
//! cscript / wscript handlers — extract VBScript/JScript payloads.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_cscript(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let path = match find_script_arg(&tokens) {
        Some(p) => p,
        None => return,
    };
    extract_script(&path, env, Trait::CscriptExec { src: path.clone() });
}

pub fn h_wscript(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    let path = match find_script_arg(&tokens) {
        Some(p) => p,
        None => return,
    };
    extract_script(&path, env, Trait::WscriptExec { src: path.clone() });
}

fn find_script_arg(tokens: &[String]) -> Option<String> {
    for t in tokens.iter().skip(1) {
        let unq = t.trim_matches('"');
        if unq.starts_with("//") || unq.starts_with("/") { continue; }
        return Some(unq.to_string());
    }
    None
}

fn extract_script(path: &str, env: &mut Environment, trait_evt: Trait) {
    env.traits.push(trait_evt);
    let key = path.to_ascii_lowercase();
    if let Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) =
        env.modified_filesystem.get(&key)
    {
        let ext_lower = path.to_ascii_lowercase();
        if ext_lower.ends_with(".vbs") || ext_lower.ends_with(".vbe") {
            env.exec_vbs.push(content.clone());
        } else if ext_lower.ends_with(".js") || ext_lower.ends_with(".jse") {
            env.exec_jscript.push(content.clone());
        }
    }
}
```

The match pattern `Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. })` requires both arms to bind `content` with the same type — they do (`&Vec<u8>`). Rust may complain about the pattern shape; if so, expand to two `if let` arms.

- [ ] **Step 3: Register, test, commit**:

```rust
pub mod cscript;
// in lookup match arm:
        "cscript" => Some(cscript::h_cscript),
        "wscript" => Some(cscript::h_wscript),
```

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add cscript/wscript handlers with VBS/JS payload extraction"
```

---

## Task 8: `extrac32` handler (CAB polyglot)

**Impact:** ~23 corpus samples (7 plain + 16 CAB-polyglot). Pattern: `extrac32 /y "%~f0" out.bin` extracts a CAB archive embedded in the .bat itself.

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/extrac32.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (test)
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant)

- [ ] **Step 1: Add trait variant** to `traits.rs`:

```rust
    Extrac32 { src: String, dst: String, self_reference: bool },
```

- [ ] **Step 2: Add test**:

```rust
#[cfg(test)]
mod extrac32_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn extrac32_self_reference_records_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"extrac32 /y "C:\Users\al\Downloads\script.bat" "%temp%\dropped.exe""#, &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Extrac32 { self_reference: true, .. }
        ));
        assert!(has, "no Extrac32 self_reference: {:?}", env.traits);
    }
}
```

- [ ] **Step 3: Implement**:

```rust
//! extrac32 handler — CAB extraction LOLBAS. Tracks self-extraction patterns.

use crate::env::{Environment, FsEntry};
use crate::handlers::util::split_words;
use crate::traits::Trait;

pub fn h_extrac32(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    // Skip command name + flags like /y /e /a
    let positional: Vec<String> = tokens.iter().skip(1)
        .filter(|t| !t.starts_with('/'))
        .map(|t| t.trim_matches('"').to_string())
        .collect();
    if positional.len() < 2 { return; }
    let src = positional[0].clone();
    let dst = positional[1].clone();

    // Self-reference if the src path matches our synthetic input path
    let self_reference = src.contains("script.bat");
    env.traits.push(Trait::Extrac32 {
        src: src.clone(),
        dst: dst.clone(),
        self_reference,
    });
    env.modified_filesystem.insert(
        dst.to_ascii_lowercase(),
        FsEntry::Copy { src },  // Not actually a copy, but the closest existing variant
    );
}
```

- [ ] **Step 4: Register, test, commit**.

```rust
        "extrac32" => Some(extrac32::h_extrac32),
```

---

## Task 9: `echo.` tokenizer fix + misc tokenizer cleanups

**Impact:** 232 corpus occurrences of `echo.` (empty echo with dot). Currently the dispatcher sees `echo.` as the command name and finds no handler.

**Files:**
- Modify: `rust/crates/batdeob-core/src/interp.rs` (`command_name` strips trailing `.` from `echo`)

- [ ] **Step 1: Add test**:

```rust
#[cfg(test)]
mod tokenizer_misc_tests {
    use crate::interp::command_name;

    #[test]
    fn echo_dot_resolves_to_echo() {
        assert_eq!(command_name("echo.").as_deref(), Some("echo"));
        assert_eq!(command_name("echo. some text").as_deref(), Some("echo"));
    }
}
```

- [ ] **Step 2: Modify `command_name`** to strip trailing `.` IF the resulting name is `echo`:

```rust
    let name_cmd = name.trim_end_matches('.');
    if name_cmd.eq_ignore_ascii_case("echo") {
        return Some("echo".to_string());
    }
```

(Plus the existing return.)

- [ ] **Step 3: Verify + commit**.

---

## Task 10: Corpus regression test harness

**Impact:** Lock in the 82.4% → ~98% corpus pass rate. Future regressions caught immediately.

**Files:**
- Create: `rust/crates/batdeob-core/tests/corpus/` (committed seed samples)
- Create: `rust/crates/batdeob-core/tests/corpus_regression.rs`

- [ ] **Step 1: Curate a seed corpus** of ~30 samples covering each technique:

```bash
mkdir -p /home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/tests/corpus
# Select 30 representative samples
for f in \
  "run.bat" "installer.bat" "FX.cmd" \
  "3360300701166418019.bat" "Invoice 6238829.bat" \
  "?impactfulbrands.co.uk__________________________________________.html.bat" \
  "FW-APGKSDTPX4HOAUJJMBVDNXPOHZ.PDF.bat" \
  "QUOTE 7254.bat" "105e06b9770ed2d002dce521b40e89455ae5d5bf08295af1f39faf3e1c4da474.bat" \
  ; do
    cp "/home/coz/cstorage/mbzdls/$f" "/home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/tests/corpus/$(echo "$f" | tr ' ?' '__')" 2>/dev/null || true
done
# Add 20 more from the corpus, random-ish selection
find /home/coz/cstorage/mbzdls -maxdepth 5 -name '*.bat' -size -20k -type f | sort -R | head -20 | while read f; do
    cp "$f" "/home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/tests/corpus/$(basename "$f" | tr ' ?' '__')"
done
ls /home/coz/Downloads/batch_deobfuscator/rust/crates/batdeob-core/tests/corpus/ | wc -l
```

Target: 30-50 samples committed.

- [ ] **Step 2: Create `tests/corpus_regression.rs`**:

```rust
//! Corpus regression test: run every sample in tests/corpus/ through
//! analyze() with strict limits. Failures = any panic, any sample taking
//! >2 seconds wall-clock, or any sample producing >1 MB output.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use batdeob_core::{analyze, Config};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[test]
fn corpus_no_panics_no_hangs() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut total = 0;
    let mut slow: Vec<(String, f64)> = Vec::new();
    let mut huge: Vec<(String, usize)> = Vec::new();
    let cfg = Config { timeout_secs: 2, max_output_bytes: 4 * 1024 * 1024, ..Config::default() };

    for entry in fs::read_dir(&dir).expect("read corpus dir") {
        let path = entry.expect("entry").path();
        if !path.is_file() { continue; }
        let content = fs::read(&path).expect("read sample");
        let start = Instant::now();
        let report = analyze(&content, &cfg);
        let wall = start.elapsed().as_secs_f64();
        total += 1;
        let name = path.file_name().expect("name").to_string_lossy().to_string();
        if wall > 2.0 { slow.push((name.clone(), wall)); }
        if report.deobfuscated.len() > 1_000_000 { huge.push((name, report.deobfuscated.len())); }
    }
    assert!(total > 0, "no samples found");
    println!("Corpus: {} samples processed", total);
    if !slow.is_empty() {
        panic!("Samples > 2s wall: {:?}", slow);
    }
    if !huge.is_empty() {
        panic!("Samples > 1 MB output: {:?}", huge);
    }
}
```

- [ ] **Step 3: Run + commit**:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core --test corpus_regression 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/tests/
git commit -m "Add corpus regression test: 30+ representative ITW samples"
```

---

## Task 11: cargo-fuzz target

**Impact:** Catch memory-safety + panic bugs against random byte input.

**Files:**
- Create: `rust/fuzz/Cargo.toml`
- Create: `rust/fuzz/fuzz_targets/analyze.rs`

- [ ] **Step 1: Install cargo-fuzz**:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo install cargo-fuzz 2>&1 | tail -3
```

- [ ] **Step 2: Initialize**:

```bash
cd /home/coz/Downloads/batch_deobfuscator/rust
mkdir -p fuzz/fuzz_targets
```

Create `rust/fuzz/Cargo.toml`:

```toml
[package]
name = "batdeob-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
batdeob-core = { path = "../crates/batdeob-core" }

[[bin]]
name = "analyze"
path = "fuzz_targets/analyze.rs"
test = false
doc = false
```

Create `rust/fuzz/fuzz_targets/analyze.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use batdeob_core::{analyze, Config};

fuzz_target!(|data: &[u8]| {
    let cfg = Config {
        timeout_secs: 1,
        max_iterations: 1024,
        max_output_bytes: 1024 * 1024,
        max_depth: 4,
        max_child_scripts: 4,
        ..Config::default()
    };
    let _ = analyze(data, &cfg);
});
```

Add `fuzz/` to `rust/Cargo.toml` workspace exclude:

```toml
[workspace]
resolver = "2"
members = ["crates/batdeob-core", "crates/batdeob-cli"]
exclude = ["fuzz"]
```

- [ ] **Step 3: Smoke run** (10K iterations):

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust/fuzz
cargo +nightly fuzz run analyze -- -runs=10000 -max_total_time=60 2>&1 | tail -20
```

Note: cargo-fuzz requires nightly. If nightly isn't installed, install it:

```bash
rustup install nightly --component rust-src 2>&1 | tail -5
```

If any panic is found, the corpus is at `rust/fuzz/artifacts/analyze/`. Triage the crash, fix the bug, re-run.

- [ ] **Step 4: Document the fuzz target** in a `rust/fuzz/README.md`:

```markdown
# batdeob fuzz target

Run:
```bash
cd rust/fuzz
cargo +nightly fuzz run analyze
```

The target wraps `analyze(&[u8], &Config)` with tight per-invocation limits
(1s timeout, 1024 iterations, 1 MB output, depth 4, 4 child scripts). Run
indefinitely or for a fixed budget via `-runs=N` / `-max_total_time=S`.
```

- [ ] **Step 5: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/fuzz/ rust/Cargo.toml
git commit -m "Add cargo-fuzz target for analyze() with tight per-input limits"
```

---

## Task 12: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create `.github/workflows/ci.yml`**:

```yaml
name: CI

on:
  push:
    branches: [ master, main ]
  pull_request:
    branches: [ master, main ]

jobs:
  test:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: rust
    steps:
      - uses: actions/checkout@v4
      - name: Cache cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            rust/target
          key: ${{ runner.os }}-cargo-${{ hashFiles('rust/Cargo.lock') }}
      - name: Build
        run: cargo build --workspace --all-targets
      - name: Test
        run: cargo test --workspace
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Fmt
        run: cargo fmt --check

  msrv:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: rust
    steps:
      - uses: actions/checkout@v4
      - name: Install MSRV
        run: rustup install 1.78.0
      - name: MSRV check (lib only)
        run: cargo +1.78.0 check -p batdeob-core

  fuzz-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install nightly
        run: rustup install nightly --component rust-src
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz
      - name: Smoke fuzz
        working-directory: rust/fuzz
        run: cargo +nightly fuzz run analyze -- -runs=5000 -max_total_time=120
```

- [ ] **Step 2: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add .github/
git commit -m "Add GitHub Actions CI: build, test, clippy, fmt, MSRV, smoke-fuzz"
```

---

## Task 13: Multi-target release pipeline

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create the release workflow**:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        target:
          - x86_64-unknown-linux-musl
          - aarch64-unknown-linux-musl
          - x86_64-apple-darwin
          - aarch64-apple-darwin
          - x86_64-pc-windows-msvc
        include:
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
            use-cross: true
          - target: aarch64-unknown-linux-musl
            os: ubuntu-latest
            use-cross: true
          - target: x86_64-apple-darwin
            os: macos-latest
            use-cross: false
          - target: aarch64-apple-darwin
            os: macos-latest
            use-cross: false
          - target: x86_64-pc-windows-msvc
            os: windows-latest
            use-cross: false
    runs-on: ${{ matrix.os }}
    defaults:
      run:
        working-directory: rust
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust target
        run: rustup target add ${{ matrix.target }}
      - name: Install cross
        if: matrix.use-cross
        run: cargo install cross
      - name: Build (cross)
        if: matrix.use-cross
        run: cross build --release --target ${{ matrix.target }} -p batdeob-cli
      - name: Build (native)
        if: ${{ !matrix.use-cross }}
        run: cargo build --release --target ${{ matrix.target }} -p batdeob-cli
      - name: Package
        shell: bash
        run: |
          mkdir -p dist
          if [[ "${{ matrix.target }}" == *windows* ]]; then
            cp rust/target/${{ matrix.target }}/release/batdeob.exe dist/batdeob-${{ matrix.target }}.exe
          else
            cp rust/target/${{ matrix.target }}/release/batdeob dist/batdeob-${{ matrix.target }}
          fi
      - uses: actions/upload-artifact@v4
        with:
          name: batdeob-${{ matrix.target }}
          path: dist/*

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
        with:
          path: dist
      - name: Create release
        uses: softprops/action-gh-release@v2
        with:
          files: dist/*/*
```

- [ ] **Step 2: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add .github/
git commit -m "Add release workflow for 5 target triples"
```

---

## Task 14: Final corpus run + comparison report

After Tasks 1-9 land, re-run the corpus to measure improvement.

- [ ] **Step 1: Build release**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release --workspace 2>&1 | tail -3
```

- [ ] **Step 2: Run** the same corpus driver as before:

```bash
chmod +x /tmp/corpus_run.sh
mkdir -p /tmp/corpus_results_v2
sed -i 's|/tmp/corpus_results|/tmp/corpus_results_v2|g' /tmp/corpus_run.sh
timeout 1800 /tmp/corpus_run.sh > /tmp/corpus_run_v2.log 2>&1
```

- [ ] **Step 3: Compare**

```bash
python3 <<'PY'
import json
from pathlib import Path

def load(d):
    by_sha = {}
    for line in (Path(d) / "index.jsonl").read_text().splitlines():
        try:
            r = json.loads(line)
            by_sha[r["sha"]] = r
        except: pass
    return by_sha

before = load("/tmp/corpus_results")
after  = load("/tmp/corpus_results_v2")
print(f"Before: {len(before)} samples, {sum(1 for r in before.values() if r['rc']==0)} success ({100*sum(1 for r in before.values() if r['rc']==0)/len(before):.1f}%)")
print(f"After:  {len(after)} samples, {sum(1 for r in after.values() if r['rc']==0)} success ({100*sum(1 for r in after.values() if r['rc']==0)/len(after):.1f}%)")
# Crashes fixed
fixed = [sha for sha in before if before[sha]["rc"] != 0 and after.get(sha, {}).get("rc") == 0]
print(f"Newly successful: {len(fixed)}")
regressed = [sha for sha in before if before[sha]["rc"] == 0 and after.get(sha, {}).get("rc") != 0]
print(f"Newly failing:    {len(regressed)}")
PY
```

Target: <2% failure rate (from 17.6%). If higher, investigate which remaining samples panic.

- [ ] **Step 4: Document in a brief commit message**:

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "Plan C complete: corpus failure rate X% -> Y%"
```

---

## Self-review

- **Spec coverage**: certutil, bitsadmin, wmic, cscript/wscript covered (4-7); extrac32 added based on corpus (8); echo. fix from corpus (9). Corpus regression (10), fuzz (11), CI (12), release (13). Bugs from corpus (1-2). Output cap (3). ✓
- **Placeholders**: none.
- **Type consistency**: `Trait::Extrac32` is new — added to traits.rs in Task 8. `Trait::CertutilDecode` already exists from Plan A placeholders. ✓
- **Deferred**: Environment structural decomposition (still on backlog; field grouping was done in B-Fixup 5). Snapshot env-overlay (intentional, would break baseline DOSfuscation tests). Real `findstr /R` regex mode. Full `for /R` / `for /D` filesystem walks.

---

**Plan C complete.** Execute via `superpowers:subagent-driven-development`.
