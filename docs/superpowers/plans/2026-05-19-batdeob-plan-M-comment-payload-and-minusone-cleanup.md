# batdeob Plan M — `:::` comment-payload extraction + minusone cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Plan L's investigation identified ~31 samples that store a secondary base64 payload in `:::`-prefixed lines of the .bat file, then read it back via `findstr "^:::" "%~f0"`. batdeob filters `::` as a comment BEFORE findstr sees it. Fix that. Also remove the minusone integration: an empirical analysis showed it produces +1 URL and +1 regression on the corpus, with most of its activity being quote/whitespace normalization that has no detection impact. Cleanup cost is small.

**Prereq:** Plans A–L landed. 244 tests, v11 corpus has 743 samples (52.5%) with URL IOCs.

---

## Task 1: Remove minusone integration

**Rationale (from `/tmp/minusone_inspect/` analysis):**
- 50-sample inspection, 64 ps1 payloads scanned
- 25 unchanged (38%), 35 minor/moderate reformatting (no URL impact), 3 obliterated to `"-"` (regression), 1 genuine win (b64 decode → IEX chain)
- Net corpus contribution: +1 URL, +1 lost URL (dual-scan papers over the regression)
- The genuine win (`GetString(FromBase64String('...'))` chain → `$de = decoded; IEX $de`) requires our pipeline to add `IEX $var → substitute $var` — a small extension to `ps1_scan` we can do directly

**Files:**
- Modify: `rust/Cargo.toml` (remove `[patch.crates-io]` entry)
- Modify: `rust/crates/batdeob-core/Cargo.toml` (remove `minusone` dep)
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs` (remove `minusone_deobfuscate` + dual-scan)
- Modify: `rust/crates/batdeob-core/src/lib.rs` (remove `minusone_smoke_tests` module)
- Delete: `rust/vendor/minusone-patched/` (entire directory)
- Modify: `README.md` (drop the minusone acknowledgment, keep the WIM-extract note)

- [ ] **Step 1: Remove the code-level integration**

In `rust/crates/batdeob-core/src/ps1_scan.rs`, find `minusone_deobfuscate` function and the dual-scan call site in `scan_ps1_payloads`. The dual-scan structure is approximately:

```rust
let raw_text = ...;
let minusone_text = minusone_deobfuscate(&raw_text).unwrap_or_else(|| raw_text.clone());
let text_raw = expand_obfuscation(&raw_text);
let text_minusone = expand_obfuscation(&minusone_text);
// Scan both, dedup by (idx, url)
```

Collapse to single-scan:

```rust
let raw_text = ...;
let text = expand_obfuscation(&raw_text);
// Scan once
```

Delete the `minusone_deobfuscate` function entirely. Delete the module-doc-comment line about minusone.

- [ ] **Step 2: Remove the smoke tests**

Delete the `minusone_smoke_tests` module from `lib.rs` (the 2 tests `format_string_obfuscation_resolves_url` and `char_cast_concat_resolves_url`). 

Wait — `char_cast_concat_resolves_url` covers `[char]N+[char]M+...` which our `expand_char_concat` already handles. Test that this still works without minusone by running the test against the new pipeline:

```bash
# After removing minusone, see if expand_char_concat alone catches the URL
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core char_cast_concat 2>&1 | tail -10
```

If our existing `expand_char_concat` catches it, MOVE the test (rename it `char_concat_resolves_url`) to a different module like `ps_obfuscation_tests` to preserve coverage. If the test FAILS without minusone, that proves minusone IS doing genuine work for this case — pause and reconsider.

`format_string_obfuscation_resolves_url`: our pipeline doesn't currently expand `"{0}{1}" -f 'h','t'`. After removing minusone, this test will fail. Two options:
(a) Delete the test (we lose that coverage; FormatString is an Invoke-Obfuscation pattern, low corpus rate)
(b) Add a small `expand_format_string` to `ps1_scan` that handles `"{N}{M}..." -f 'a','b'`

For Plan M's scope, do option (a) — delete the test. If FormatString coverage becomes needed later, add it as a focused Plan N task.

- [ ] **Step 3: Remove Cargo plumbing**

In `rust/crates/batdeob-core/Cargo.toml`:
- Remove the `minusone = "..."` line from `[dependencies]`

In `rust/Cargo.toml` (workspace root):
- Remove the `[patch.crates-io]` entry for minusone

- [ ] **Step 4: Delete the vendored crate**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git rm -r rust/vendor/minusone-patched
# This removes the vendor dir + LICENSE.txt + PATCH.md + the entire patched copy
```

- [ ] **Step 5: Update README**

Edit `README.md`'s `## Acknowledgments` section. Remove the minusone-specific block. Keep the WIM-extract acknowledgment. The section becomes minimal:

```markdown
## Acknowledgments

The synthetic Windows environment snapshot
(`rust/crates/batdeob-core/data/win11.json`) was extracted from a
Windows 11 25H2 Pro `install.wim` using the helper at
`rust/tools/extract-from-wim/`. No registry data ships from
Microsoft directly.
```

- [ ] **Step 6: Verify clean build + tests**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --workspace 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: 244 - 2 (removed minusone tests) = 242 tests passing. If `cargo update` is needed to rebuild Cargo.lock without the patched entry, run it.

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/Cargo.toml rust/crates/batdeob-core/Cargo.toml rust/crates/batdeob-core/src/ rust/Cargo.lock README.md
# `git rm` from Step 4 already staged the deletions
git commit -m "Remove minusone integration: empirical +1 URL on corpus, not worth the vendored patch"
```

---

## Task 2: Preserve `:::` comments for self-extract findstr

**Pattern:**

```bat
for /f "tokens=*" %%a in ('findstr "^:::" "%~f0"') do (
    echo %%a | findstr "://" >> %temp%\urls.txt
)
goto :eof
:::base64-payload-line-1
:::base64-payload-line-2
:::http://evil.example/dropper.exe
```

The bat reads its OWN file for `:::`-prefixed lines and extracts URLs/payloads from them. Our synth `findstr` handler reads `env.input_bytes` when the file path matches `%~f0` (Plan B Task 11). But the deobfuscation output filter (`is_label_or_comment_line` in `lib.rs`) treats `:::` lines as comments and skips them, which is correct for the MAIN driver loop — they're not commands. The issue isn't that we lose them from the deob text (we do, but findstr reads the source bytes anyway). Let me verify the actual failure mode before fixing.

**Files:**
- Possibly modify: `rust/crates/batdeob-core/src/synth.rs`
- Possibly modify: `rust/crates/batdeob-core/src/handlers/for_cmd.rs`

- [ ] **Step 1: Smoke test the current behavior**

```bash
cd /tmp
mkdir -p plan_m_test
cat > plan_m_test/self_extract.bat <<'BAT'
@echo off
for /f "tokens=*" %%a in ('findstr "^:::" "%~f0"') do echo got: %%a
goto :eof
:::http://evil.example/dropper.exe
:::http://evil.example/loader.dll
BAT

export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
./target/release/batdeob analyze /tmp/plan_m_test/self_extract.bat 2>&1 | head -50
```

The expected output should contain the two URLs in the deobfuscated text AND emit them as Download traits (via the deob_scan URL sweep).

If the URLs DON'T appear, examine WHY:
- Does the `findstr "^:::" "%~f0"` synth call actually return the `:::` lines?
- Does `env.input_bytes` contain the `:::` lines?
- Is the for loop's body actually executing with `%%a` substituted to the matched lines?

- [ ] **Step 2: If the smoke test FAILS**

Likely the synth `findstr` reads `env.input_bytes` then filters via the substring pattern, but the `^:::` anchor might not be respected (findstr without `/R` is substring-only, so `^:::` matches lines literally containing `^:::`, which they don't). Verify by changing the test to `findstr ":::" "%~f0"` (no anchor) and re-running. If THAT works, document that the `/R` regex mode (Plan G Task 4) is required for the anchor.

The fix path depends on the failure mode:
- If `:::` lines never reach the synth: investigate the synth's `type_file` / `findstr` self-reference path
- If `^` anchor isn't respected: ensure the synth's `/R` regex path is used when the pattern starts with `^` (even if `/R` isn't explicitly passed — heuristic: if the pattern starts with `^` or `$`, treat as regex)

The latter is the most likely fix. In `synth.rs::filter_findstr`, add this auto-detection:

```rust
// Auto-enable regex mode for patterns that contain regex metacharacters
// (^, $, [, etc.) — many real-world scripts omit /R but use ^anchor patterns.
if !regex_mode {
    if patterns.iter().any(|p| p.starts_with('^') || p.ends_with('$') || p.contains('[')) {
        regex_mode = true;
    }
}
```

- [ ] **Step 3: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod self_extract_comment_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn findstr_caret_anchor_matches_comment_lines() {
        let script = b"@echo off\r\nfor /f \"tokens=*\" %%a in ('findstr \"^:::\" \"%~f0\"') do echo got: %%a\r\ngoto :eof\r\n:::http://evil.example/dropper.exe\r\n:::http://evil.example/loader.dll\r\n";
        let report = analyze(script, &Config::default());
        // Both URLs should surface (likely as DownloadInDeobText via the regex sweep)
        let urls: Vec<_> = report.traits.iter().filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
            _ => None,
        }).collect();
        assert!(urls.iter().any(|u| u.contains("dropper.exe")), "no dropper.exe: {:?}", urls);
        assert!(urls.iter().any(|u| u.contains("loader.dll")), "no loader.dll: {:?}", urls);
    }
}
```

- [ ] **Step 4: Apply the fix from Step 2** and verify

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "synth findstr: auto-enable regex mode for ^anchor patterns (catches :::comment self-extract)"
```

---

## Task 3: Corpus v12 + measurement

- [ ] **Step 1: Build + corpus run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
sed 's|corpus_results_v11|corpus_results_v12|g' /tmp/corpus_run_v11.sh > /tmp/corpus_run_v12.sh
chmod +x /tmp/corpus_run_v12.sh
mkdir -p /tmp/corpus_results_v12 && rm -rf /tmp/corpus_results_v12/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v12.sh > /tmp/corpus_run_v12.log 2>&1
ls /tmp/corpus_results_v12/*.json | wc -l
```

The release binary should be SMALLER (no tree-sitter dep). Note the size:

```bash
ls -la /home/coz/Downloads/batch_deobfuscator/rust/target/release/batdeob
```

- [ ] **Step 2: Compare v11 → v12**

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

v11 = stats("/tmp/corpus_results_v11")
v12 = stats("/tmp/corpus_results_v12")
common = set(v11) & set(v12)
print(f"v11={len(v11)}  v12={len(v12)}  common={len(common)}")

def counts(samples, keys):
    cnt = Counter()
    for k in keys:
        for t in samples[k].get("traits", []):
            cnt[t.get("kind","")] += 1
    return cnt

c11 = counts(v11, common)
c12 = counts(v12, common)
print(f"\nOn {len(common)} common samples:")
print(f"  {'Trait':32} {'v11':>8} {'v12':>8}  Δ")
for k in sorted(set(c11)|set(c12), key=lambda x: -max(c11[x], c12[x]))[:15]:
    delta = c12[k] - c11[k]
    sign = "+" if delta > 0 else ""
    print(f"    {k:30} {c11[k]:>8} {c12[k]:>8}  {sign}{delta}")

URL_KINDS = {"Download","DownloadInDeobText","CertutilDownload","BitsadminDownload","UncWebDavC2"}
v11_with = sum(1 for k in common if any(t.get("kind") in URL_KINDS for t in v11[k].get("traits",[])))
v12_with = sum(1 for k in common if any(t.get("kind") in URL_KINDS for t in v12[k].get("traits",[])))
print(f"\nSamples with URL IOC: v11={v11_with} v12={v12_with}  Δ={v12_with - v11_with}")
PY
```

Expected: v11 → v12 net deltas should be near-zero on Download (minusone was +1 URL — we lose that), and possibly a small POSITIVE on DownloadInDeobText (the `:::` comment fix might surface 5-30 new URLs).

- [ ] **Step 3: Commit completion**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "$(cat <<EOF
Plan M complete: v12 corpus after minusone removal + :::comment fix

[paste delta table]
EOF
)"
```

## Report

- Binary size delta (target: smaller without tree-sitter)
- v11 → v12 trait deltas
- Any unexpected losses
- Samples newly gaining IOC from the `:::` fix
- Test count (target: 244 - 2 minusone tests + 1 new = 243)
- 4 commit SHAs

---

## Self-review

- **Spec coverage**: minusone removal (the user's question) + `:::` comment fix (the user's "do the comment thing as well" ask).
- **Placeholders**: none.
- **Risk**: Task 2's diagnosis ("is it the `^` anchor or something else?") happens at execution time. If the failure mode is different from anticipated, the implementer should report findings before patching.

**Plan M complete.** Execute via `superpowers:subagent-driven-development`.
