# Plan S: AES-CBC Dropper Chain — URL Recovery for the Multi-Stage Family

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:subagent-driven-development` or `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Decrypt the multi-stage AES-CBC PowerShell dropper family that accounts for ~72 of the remaining 600 no-IOC corpus samples. Recover URLs from the final reflection-loaded .NET assembly bytes.

**Architecture:** New `aes_chain` module under `batdeob-core`. Drives off the `MultiStageEncryptedDropper` trait detector already shipped in Round 9. Re-runs the stage-1 b64+marker decode, parses stage-2 PS to find marker strings and source-file refs, replays the `:::N*` payload assembly off the raw `.bat` input, then walks stage-3 PS for AES Key/IV, decrypts both halves of the `:: ` line payload, gunzips, and scans the resulting .NET assembly bytes for URL string literals.

**Tech Stack:** Rust workspace; new deps `aes = "0.8"`, `cbc = "0.1"`, `flate2 = "1"` (workspace).

---

## Sample reference

This plan is derived from these observed corpus samples — keep at least three open in another window while implementing:

- `DHL_Delivery_Form_(03.10.2025)_PDF.bat`
- `factura_53030.bat`
- `OrbitalProtocol.bat`
- `Payment_Advice_pdf.bat`
- `wMecANa.bat`

The chain shape was traced end-to-end against `DHL_Delivery_Form_(03.10.2025)_PDF.bat` and is recorded in `docs/superpowers/notes/2026-05-19-aes-chain-trace.md` (create that file in Task 0 below from the inline trace at the end of this plan).

## Background — the chain shape

For each sample, four stages get us from the deob to the URL:

| Stage | Lives in | Operation | Yields |
|-------|----------|-----------|--------|
| 1 | deob text | `[Convert]::FromBase64String('<b64>'.Replace('<m1>',''))` | UTF-16LE PS source |
| 2 | stage-1 output | parse, find marker list, find inline gzipped b64 (`$orange='H4sIA...'`) | stage-3 PS source (after gunzip) |
| 3 | stage-2 inline | extract AES key/IV from stage-3 PS; find `:: ` line in raw .bat; split on `\`; b64-decode each half; AES-CBC decrypt; gunzip | two .NET assembly byte blobs |
| 4 | stage-3 outputs | binary string scan for URL literals | URLs |

Variants observed:

- `:::N*` vs `:: ` payload-line prefixes (both present in DHL family; only `:: ` in some others)
- Some samples have one assembly (only `$lenc`); some have two (`$hqedd` decoy + `$lenc` payload)
- Marker counts in stage-2: usually 2 (`-replace` chain like `-replace "limestrawberry","" -replace "ugiwuhkkfiquilr",""`); occasionally 3
- AES key/IV always plaintext base64 strings in stage-3 PS; never indirectly assembled

---

## File Structure

- Create: `rust/crates/batdeob-core/src/aes_chain.rs` — module entry, types, public `extract_from_chain()` function
- Create: `rust/crates/batdeob-core/src/aes_chain/ps_extract.rs` — string extraction from PS source (single-quoted literals, `-replace` chains, AES Key/IV regexes)
- Create: `rust/crates/batdeob-core/src/aes_chain/payload_lines.rs` — raw `:::N*` and `:: ` line collection from input bytes
- Create: `rust/crates/batdeob-core/src/aes_chain/crypto.rs` — AES-CBC decrypt wrapper, gzip decompress wrapper, both pure functions with limits
- Create: `rust/crates/batdeob-core/src/aes_chain/scan.rs` — URL scanner over decrypted+decompressed bytes (with the same noise filter as `deob_scan::is_noise_url`)
- Modify: `rust/crates/batdeob-core/Cargo.toml` — add `aes`, `cbc`, `flate2`
- Modify: `rust/Cargo.toml` (workspace) — add the same to `[workspace.dependencies]`
- Modify: `rust/crates/batdeob-core/src/lib.rs` — `pub mod aes_chain;` and call `aes_chain::extract_from_chain(&raw_input, &out, &mut env)` after `scan_multistage_encrypted_dropper`
- Modify: `rust/crates/batdeob-core/src/deob_scan.rs` — `scan_multistage_encrypted_dropper` already emits the gating trait; no further change
- Modify: `rust/crates/batdeob-core/src/traits.rs` — extend `MultiStageEncryptedDropper` with `urls_recovered: Vec<String>` field (default empty), so the trait records what we got out
- Test: `rust/crates/batdeob-core/src/aes_chain/tests.rs` — unit tests with synthetic chains
- Test: `rust/crates/batdeob-core/tests/aes_chain_corpus.rs` — black-box test that runs against the 5 reference samples and asserts a URL per sample

---

## Limits & safety

Every stage MUST have hard caps. The AES key gives the attacker no leverage over the analyzer if we keep these. Hard-code at module top:

- Max stage-1 b64 byte size: 1 MB (after marker strip)
- Max stage-1 decoded UTF-16LE size: 2 MB
- Max raw payload-line byte sum: 2 MB
- Max AES ciphertext per half: 4 MB
- Max gunzipped output per stage: 16 MB
- Max URLs returned per sample: 16

Anything exceeding a limit emits a `MultiStageEncryptedDropper { aes_chain_aborted_at: <stage> }` field and returns. The orchestrator MUST NOT panic on bad ciphertext, wrong key, or any decrypt/gunzip failure — log a single `AesChainFailed { reason }` trait and stop.

The AES key is in cleartext in the malware so we are not breaking crypto; we are replaying a known-key decryption against bytes we already control. No timing-side-channel concerns apply.

---

## Task 0: Capture the trace into the repo

**Files:**
- Create: `docs/superpowers/notes/2026-05-19-aes-chain-trace.md`

- [ ] **Step 1: Write the trace document**

Paste the entire stage-by-stage trace (the table above, the captured stage-2 head, the captured stage-3 head with the literal AES key `YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=` and IV `PcWh4S5zqexZ2ueefstJ6A==`, and the observed marker list `limestrawberry, ugiwuhkkfiquilr`) into the note. This is the ground truth all later tasks reference.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/notes/2026-05-19-aes-chain-trace.md
git commit -m "docs: capture AES dropper chain trace for plan S"
```

---

## Task 1: Add workspace deps

**Files:**
- Modify: `rust/Cargo.toml`
- Modify: `rust/crates/batdeob-core/Cargo.toml`

- [ ] **Step 1: Add to `[workspace.dependencies]`**

```toml
aes = "0.8"
cbc = { version = "0.1", features = ["std"] }
flate2 = "1"
```

- [ ] **Step 2: Reference in `batdeob-core/Cargo.toml` `[dependencies]`**

```toml
aes.workspace = true
cbc.workspace = true
flate2.workspace = true
```

- [ ] **Step 3: Verify build is clean**

```
cargo build -p batdeob-core
```
Expected: no errors. New deps compile.

- [ ] **Step 4: Commit**

---

## Task 2: `crypto.rs` — AES-CBC + GZip wrappers

**Files:**
- Create: `rust/crates/batdeob-core/src/aes_chain/crypto.rs`
- Test: same file, `#[cfg(test)]` module

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn aes_cbc_roundtrip_with_known_key() {
    // Key/IV/ciphertext captured from a corpus sample's stage-3 PS.
    // Round-trip-encrypt some plaintext with the same key/IV to verify.
    let key = base64::engine::general_purpose::STANDARD
        .decode("YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=").unwrap();
    let iv = base64::engine::general_purpose::STANDARD
        .decode("PcWh4S5zqexZ2ueefstJ6A==").unwrap();
    let pt = b"hello world this is the payload";
    let mut buf = pt.to_vec();
    // Pad to AES block then encrypt-decrypt
    let ct = aes_cbc_encrypt(&key, &iv, pt).unwrap();
    assert_eq!(aes_cbc_decrypt(&key, &iv, &ct).unwrap(), pt.to_vec());
}

#[test]
fn aes_cbc_rejects_oversize_ciphertext() {
    let key = vec![0u8; 32]; let iv = vec![0u8; 16];
    let too_big = vec![0u8; 5 * 1024 * 1024];
    assert!(aes_cbc_decrypt(&key, &iv, &too_big).is_err());
}

#[test]
fn gunzip_decompresses_known_blob() {
    let original = b"hello gzip";
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    e.write_all(original).unwrap();
    let gz = e.finish().unwrap();
    assert_eq!(gunzip(&gz, 1024).unwrap(), original.to_vec());
}

#[test]
fn gunzip_respects_size_limit() {
    // Compress 100 KB of zeros; allow only 1 KB.
    let big = vec![0u8; 100 * 1024];
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write; e.write_all(&big).unwrap();
    let gz = e.finish().unwrap();
    assert!(gunzip(&gz, 1024).is_err());
}
```

- [ ] **Step 2: Run, expect compile fail**

`cargo test -p batdeob-core aes_chain::crypto`

Expected: missing `aes_cbc_encrypt`, `aes_cbc_decrypt`, `gunzip`.

- [ ] **Step 3: Implement**

```rust
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use thiserror::Error;

type Aes128Cbc = cbc::Decryptor<aes::Aes128>;
type Aes192Cbc = cbc::Decryptor<aes::Aes192>;
type Aes256Cbc = cbc::Decryptor<aes::Aes256>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
// ...etc, see aes-rs docs for full constructors.

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ciphertext too large: {0} bytes")]
    TooLarge(usize),
    #[error("invalid key length: {0}")]
    BadKey(usize),
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("gunzip: {0}")]
    Gunzip(String),
}

pub const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ct.len() > MAX_CIPHERTEXT { return Err(CryptoError::TooLarge(ct.len())); }
    let mut buf = ct.to_vec();
    let out = match key.len() {
        16 => Aes128Cbc::new_from_slices(key, iv).map_err(|_| CryptoError::BadKey(key.len()))?
            .decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| CryptoError::DecryptFailed)?,
        24 => Aes192Cbc::new_from_slices(key, iv).map_err(|_| CryptoError::BadKey(key.len()))?
            .decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| CryptoError::DecryptFailed)?,
        32 => Aes256Cbc::new_from_slices(key, iv).map_err(|_| CryptoError::BadKey(key.len()))?
            .decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| CryptoError::DecryptFailed)?,
        n => return Err(CryptoError::BadKey(n)),
    };
    Ok(out.to_vec())
}

pub fn aes_cbc_encrypt(/* ... mirror with Encryptor types ... */) -> Result<Vec<u8>, CryptoError> { /* ... */ }

pub fn gunzip(input: &[u8], max_out: usize) -> Result<Vec<u8>, CryptoError> {
    use std::io::Read;
    let mut d = flate2::read::GzDecoder::new(input);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = d.read(&mut buf).map_err(|e| CryptoError::Gunzip(e.to_string()))?;
        if n == 0 { break; }
        if out.len() + n > max_out { return Err(CryptoError::Gunzip("size limit".into())); }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}
```

- [ ] **Step 4: Run tests, expect PASS** — `cargo test -p batdeob-core aes_chain::crypto`

- [ ] **Step 5: Commit**

---

## Task 3: `ps_extract.rs` — PS source parsing helpers

**Files:**
- Create: `rust/crates/batdeob-core/src/aes_chain/ps_extract.rs`

Implements:
- `find_single_quoted_long(text: &str) -> Vec<&str>` — single-quoted PS string literals ≥ N chars (handles PS's `''` quote-escape: a doubled single quote inside is one literal `'`).
- `find_replace_chain(text: &str) -> Vec<(String, String)>` — extracts `-replace 'a','b'` and `.Replace('a','b')` pairs as `(needle, replacement)`.
- `find_aes_key_iv(text: &str) -> Option<(Vec<u8>, Vec<u8>)>` — locates `Key = ... FromBase64String('<b64>') ... IV = ... FromBase64String('<b64>')` and returns decoded bytes. Tolerates whitespace, function-name variation, and ordering (key before IV vs IV before key).
- `find_payload_line_prefix(text: &str) -> Option<String>` — finds `:: ` or `:::N*` glob used by the loader (`-like ":::*"`, `.StartsWith(':: ')`, etc.).
- `find_inline_gzipped_b64(text: &str) -> Option<&str>` — single-quoted base64 starting with `H4sIA` (gzip magic in base64).

- [ ] **Step 1: Write failing tests** with fixtures lifted from the trace doc.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement each helper. Use `regex` crate (already a dep).** Keep regexes anchored on PS keywords (`Key`, `IV`, `-replace`, `FromBase64String`) to bound false positives. Sample regex for the key:
  ```
  Key\s*=\s*\[(?:System\.)?Convert\]::FromBase64String\(\s*'([A-Za-z0-9+/=]{16,})'\s*\)
  ```
- [ ] **Step 4: Re-run tests, expect PASS.**
- [ ] **Step 5: Commit.**

---

## Task 4: `payload_lines.rs` — raw line collection

**Files:**
- Create: `rust/crates/batdeob-core/src/aes_chain/payload_lines.rs`

- [ ] **Step 1: Write failing tests** with synthetic raw bat content containing `:::1`, `:::2`, ..., `:: ` lines.

- [ ] **Step 2-3: Implement**

```rust
pub struct PayloadLines<'a> {
    pub colon_n: Vec<(u32, &'a str)>,  // (N, content after :::N)
    pub colon_space: Option<&'a str>,  // content after ":: "
}

pub fn collect(raw: &[u8]) -> PayloadLines<'_> {
    // Iterate lines; collect ones starting with `:::<digit>` or `:: `.
    // No allocation beyond the returned slices.
}
```

Constraint: each returned slice MUST be a slice of `raw` (no copy). Cap total returned bytes at 2 MB combined.

- [ ] **Step 4: Tests PASS.**
- [ ] **Step 5: Commit.**

---

## Task 5: `scan.rs` — URL scanning of decrypted bytes

**Files:**
- Create: `rust/crates/batdeob-core/src/aes_chain/scan.rs`

The decrypted+decompressed output is usually a .NET PE assembly. URLs appear as UTF-8 or UTF-16LE string literals embedded in the `.text`, `.rsrc`, or `#US` (user strings) streams.

- [ ] **Step 1: Write failing tests** with a synthetic byte blob containing both UTF-8 and UTF-16LE URLs.

- [ ] **Step 2-3: Implement**

```rust
pub fn scan_urls(bytes: &[u8], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    // UTF-8 scan
    let utf8_re = once_cell::sync::Lazy::new(||
        regex::bytes::Regex::new(r"(?i)https?://[\x20-\x7e]{4,300}").unwrap());
    for m in utf8_re.find_iter(bytes) {
        if let Ok(s) = std::str::from_utf8(m.as_bytes()) {
            push_clean(&mut out, s);
            if out.len() >= limit { return out; }
        }
    }
    // UTF-16LE scan: build the encoded bytes for "http" and "https" and
    // look for those, then read ahead chars until a non-printable.
    out
}
```

Reuse `deob_scan::is_noise_url`. Dedup the returned `Vec`.

- [ ] **Step 4: Tests PASS.**
- [ ] **Step 5: Commit.**

---

## Task 6: `aes_chain.rs` orchestrator

**Files:**
- Create: `rust/crates/batdeob-core/src/aes_chain.rs` (top-level module re-export)
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write top-level integration test** using a real corpus sample. Place the sample at `rust/crates/batdeob-core/tests/data/dhl_delivery_form.bat` (copied from the corpus). Call:

```rust
#[test]
fn dhl_sample_yields_url() {
    let raw = std::fs::read("tests/data/dhl_delivery_form.bat").unwrap();
    let cfg = Config::default();
    let report = analyze(&raw, &cfg);
    let urls: Vec<&str> = report.traits.iter().filter_map(|t| match t {
        Trait::DownloadInDeobText { src, .. } => Some(src.as_str()),
        _ => None,
    }).collect();
    assert!(!urls.is_empty(), "expected at least one URL, got {:?}", report.traits);
}
```

Expected: FAIL (URLs are still empty until the chain wires up).

- [ ] **Step 2: Implement `extract_from_chain`**

Signature:

```rust
pub fn extract_from_chain(raw_input: &[u8], deob: &str, env: &mut Environment) {
    // 1. Only run if MultiStageEncryptedDropper trait already present.
    // 2. Re-find stage-1: 'b64'.Replace('marker','') in deob.
    // 3. Strip marker, b64-decode (limit), UTF-16LE decode → stage-2 PS.
    // 4. ps_extract::find_replace_chain(stage-2) → marker_list.
    //    ps_extract::find_inline_gzipped_b64(stage-2) → gz_b64.
    //    If gz_b64: b64-decode → gunzip → stage-3 PS.
    //    Else: stage-2 might already BE the loader; treat stage-2 as stage-3.
    // 5. payload_lines::collect(raw_input) → :::N lines, :: line.
    // 6. Concat :::N lines in order; apply marker_list; b64-decode.
    //    Some samples treat this as an embedded loader payload, others
    //    don't use it. If decryption keys aren't in stage-3, bail.
    // 7. ps_extract::find_aes_key_iv(stage-3) → (key, iv).
    // 8. If :: line present: split on '\\', b64-decode each half,
    //    aes_cbc_decrypt with (key, iv), gunzip each.
    // 9. scan::scan_urls(decrypted_blob_1, 16) ++ scan_urls(decrypted_blob_2, 16).
    // 10. For each URL, push Trait::DownloadInDeobText with
    //     line_hint = "aes-chain". Also extend the existing
    //     MultiStageEncryptedDropper trait's urls_recovered list.
    // Any failure → push Trait::AesChainFailed { stage: N, reason } and return.
}
```

Step-by-step within the function uses the four helper modules. No new logic here beyond glue and limit enforcement.

- [ ] **Step 3: Wire into `lib.rs`**

After `deob_scan::scan_multistage_encrypted_dropper(&out, &mut env);` add:

```rust
aes_chain::extract_from_chain(input, &out, &mut env);
```

- [ ] **Step 4: Run integration test, expect PASS.**

- [ ] **Step 5: Commit.**

---

## Task 7: Corpus regression test against the reference set

**Files:**
- Test: `rust/crates/batdeob-core/tests/aes_chain_corpus.rs`

- [ ] **Step 1: Add the 5 reference samples to `tests/data/`** (one-time copy from `/home/coz/cstorage/mbzdls`).

- [ ] **Step 2: Write a parametrized test** asserting each sample yields ≥ 1 URL.

```rust
#[test]
fn aes_chain_recovers_url_from_reference_samples() {
    for name in &[
        "dhl_delivery_form.bat",
        "factura_53030.bat",
        "OrbitalProtocol.bat",
        "Payment_Advice_pdf.bat",
        "wMecANa.bat",
    ] {
        let path = format!("tests/data/{name}");
        let raw = std::fs::read(&path).unwrap();
        let report = analyze(&raw, &Config::default());
        let url_count = report.traits.iter().filter(|t|
            matches!(t, Trait::DownloadInDeobText { .. })
        ).count();
        assert!(url_count >= 1, "{}: no URLs recovered, traits={:?}", name, report.traits);
    }
}
```

- [ ] **Step 3: Run test. If fewer than 5/5 pass, debug the failing sample.** Expected outcome: at least 4/5 (the chain has known variants; document the failing one and either fix or mark `#[ignore]` with a one-line note).

- [ ] **Step 4: Commit.**

---

## Task 8: Full corpus measurement

- [ ] **Step 1: `cargo build --release -p batdeob-cli`**

- [ ] **Step 2: Re-run the 1416-sample corpus runner**, count URL IOC delta vs Round 8 baseline (816/1416).

- [ ] **Step 3: Update `CHANGELOG.md`** with `v0.X.0 — AES dropper chain (+N samples)`.

- [ ] **Step 4: Commit + tag.**

Expected gain: **+30 to +50** samples. Anything under +20 means the variants we handle don't match the corpus's actual distribution; in that case, sample 5 of the unrecovered samples, inspect, and decide whether to add another variant or stop.

---

## Open variants to watch for

1. **Single-payload vs dual-payload `:: ` line.** DHL has dual (split-on-`\`). Some have single (no split). Handle by checking the split count and falling back to "treat the whole line as one ciphertext."
2. **Stage-2 with no inline gzipped b64.** Some samples skip the gunzip step and go straight to AES — stage-2 IS stage-3. Detect by absence of `H4sIA` and presence of `Aes` keywords in stage-2 itself.
3. **Source file path other than `aoc.bat`.** Some samples use `%TEMP%\<random>.bat`. Always read from the raw input we're analyzing, not the literal path in the PS — the PS path is what the malware would read AT RUNTIME, but we have the original.
4. **Multiple `MultiStageEncryptedDropper` traits per sample.** We currently emit at most one. If the chain needs more than one stage-1 match, the orchestrator can iterate but should still produce one final trait.
5. **Key length variants.** Most observed are AES-256 (32-byte key); the crypto module handles 128/192/256.

## Out of scope

- Full .NET assembly disassembly. We only string-scan the bytes; structural parsing is its own project.
- Non-AES dropper families (RC4, XOR rollups). Treat as future plans.
- Any attempt to *execute* the decoded PS. Static-only.

## Done criteria

- Plan S Task 6 integration test passes.
- ≥ 4/5 reference samples in Task 7 pass.
- Corpus measurement shows ≥ +20 samples vs v17 baseline.
- All new code clippy-clean; existing 258-test suite still green.
- `CHANGELOG.md` entry committed.
