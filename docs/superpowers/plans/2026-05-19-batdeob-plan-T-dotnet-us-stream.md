# Plan T: .NET `#US` Stream URL Extraction (continuation of Plan S)

**Status (2026-05-19, post-investigation): SHELVED — empirical finding makes the plan low-yield.**

A Python prototype walked the `#US` heaps of the assemblies recovered
from 10 Plan-S-decrypted samples. **0 of them contain a literal URL.**
The strings present in the loader assembly are:

- ETW unhook (`ntdll.dll`, `EtwEventWrite`)
- Process enumeration (`SELECT ProcessId, CommandLine FROM Win32_Process ...`)
- Defender exclusion (`MSFT_MpPreference`, `ExclusionPath`)
- A `Resource '...' not found` error template
- **A second base64-encoded AES Key/IV pair** (e.g. `fD3IHmORy...`,
  `+wCkJwhjMm...`) used to decrypt an embedded resource

The C2 URL lives in that embedded resource (a 4th-stage payload),
loaded via `Assembly.GetManifestResourceStream` and decrypted with the
inner Key/IV at runtime. Static recovery would require:

1. Parse .NET metadata tables (`ManifestResource`, `Blob` heap) — not just `#US`
2. Decrypt the inner resource with the second AES Key/IV
3. The result is another .NET assembly which itself likely uses
   stack-string construction, DGA, or remote config — so another
   1-2 layers beyond.

Effort to URL: estimated 1-2 weeks of careful .NET analysis work, with
a high risk of hitting runtime-only behaviour at the end. URL recall
gain vs the current 57.6% is **+10 at best** (only the 10 Plan-S
samples with recovered Key/IV; the rest don't even decrypt cleanly).

**Recommendation: do not pursue.** Instead, the Plan-S trait already
surfaces the recovered AES Key/IV and the inner Key/IV could be added
to that trait (Plan T-lite below) — analysts can then run downstream
.NET tooling (`dnSpy`, `de4dot`) themselves.

---

## Plan T-lite (1-2 hours): surface the inner AES Key/IV

Add a `nested_aes` field to `MultiStageEncryptedDropper`:

```rust
pub struct NestedAesKey { pub key_b64: String, pub iv_b64: String }
// ...
nested_aes: Vec<NestedAesKey>,
```

Implementation:

1. After `gunzip()` in `aes_chain::orchestrator`, when the bytes start
   with `MZ`, parse the .NET `#US` heap (use the prototype in
   `/tmp/batdeob-r6/dotnet_us_probe.py` as the algorithm reference).
2. Pair adjacent base64-looking strings (32 chars for key, 24 chars for
   IV) and decode-verify (32/16 byte lengths).
3. Each verified pair → push to `nested_aes`.

That makes the existing trait analyst-actionable: they get the outer
chain decrypted + the inner key material for manual continuation.

---

## Original plan (for reference / future)

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`.

**Goal:** Reach the URLs that Plan S's AES chain proved are NOT at the surface of the decrypted .NET assemblies. The AES chain successfully recovers 2 byte blobs per sample (commit `<plan-S-sha>`) — `Trait::MultiStageEncryptedDropper { assemblies_recovered: 2, ... }` — but a UTF-8/UTF-16LE bytes scan finds 0 URLs because the malware encodes strings in the .NET `#US` user-strings metadata stream.

**Architecture:** New `aes_chain::dotnet` submodule. Parses the .NET assembly's PE headers, locates the CLI header, walks the metadata table to find the `#US` heap, decodes each compressed-uint-prefixed UTF-16LE user-string entry, then re-runs the URL scanner. No execution; no IL interpretation; pure structural parse.

**Tech Stack:** Existing Rust workspace. Optional new dep `object = "0.36"` for PE parsing (we already use heavy crates so this is fine), or hand-rolled PE/COR20 parsing in ~200 lines.

---

## Background — what `#US` is

.NET stores user-defined string literals (anything created by `ldstr` in IL) in a heap called `#US`. The heap is referenced by RVA from the metadata root. Each entry is a compressed-unsigned-int length followed by UTF-16LE bytes; the final byte indicates whether the string contains non-ASCII (`0x00` = ASCII-only, `0x01` = has wide chars).

A URL string like `"http://evil.example.com/payload"` literally lives in `#US` as:
- compressed-uint = `len*2 + 1` (length tag)
- UTF-16LE bytes for the string
- terminator byte

ASCII byte scan misses it because nothing in the byte stream is contiguous ASCII (every other byte is `\x00`). Plain UTF-16LE scan in `aes_chain::scan` *should* catch some of these, but the actual `#US` entries are length-prefixed and the byte alignment can be off depending on what precedes them in the heap. A structured walk fixes that.

## File Structure

- Create: `rust/crates/batdeob-core/src/aes_chain/dotnet.rs` — PE → CLI header → metadata → `#US` walker
- Modify: `rust/crates/batdeob-core/src/aes_chain/orchestrator.rs` — when the gunzipped bytes start with `MZ`, route to `dotnet::extract_us_strings()` BEFORE falling back to the generic byte scan
- Modify: `rust/crates/batdeob-core/src/aes_chain.rs` — add `pub mod dotnet;`
- Test: `rust/crates/batdeob-core/src/aes_chain/dotnet.rs` `#[cfg(test)]` block with a minimal synthetic .NET assembly fixture (~1KB of crafted bytes)
- Test: integration test that decrypts a real corpus sample (e.g. `factura_53030.bat`), parses the `#US` stream, asserts at least one URL is recovered

Optionally if `object` crate is added:
- Modify: `rust/Cargo.toml` workspace deps
- Modify: `rust/crates/batdeob-core/Cargo.toml`

## Limits & safety

Mirror Plan S caps:
- Max `#US` heap size: 4 MB
- Max strings emitted per assembly: 256
- Max single string length: 8 KB
- All offsets bounds-checked; any out-of-range read returns `Err` and the orchestrator falls back to the generic byte scan

---

## Task 1: Confirm `#US` exists in the recovered assemblies

**Files:**
- Read-only: `/home/coz/cstorage/mbzdls/{factura_53030,RK,OrbitalProtocol}.bat`

- [ ] **Step 1:** Run `batdeob analyze --jsonl <path>` and capture the `MultiStageEncryptedDropper` trait's `aes_key_b64` and `aes_iv_b64` for the three samples.

- [ ] **Step 2:** Outside the project, decrypt the `:: ` line payload manually with the Plan-S algorithm (Python script in `/tmp/batdeob-r6/` or a quick Rust binary).

- [ ] **Step 3:** Run `monodis --userstrings` or open the bytes in `dotPeek` / `dnSpy` if available. Otherwise hand-walk the PE → CLI → `#US` and dump every user-string.

- [ ] **Step 4:** Document in `docs/superpowers/notes/2026-05-19-aes-chain-trace.md`:
  - Whether the URL appears in `#US` literally, in fragments, or further encoded (XOR / rot13 / b64).
  - The exact `#US` size and string count for each of the 3 samples.

If step 4 shows the URL is NOT in `#US` literally (e.g., the malware splits it into single chars in code), this plan needs to pivot to IL stack-string reconstruction — out of scope for this plan; close with a "needs IL analysis" finding.

## Task 2: `dotnet.rs` skeleton + PE header walk

Implements:

```rust
pub fn extract_us_strings(bytes: &[u8]) -> Result<Vec<String>, DotnetError>;

#[derive(Debug, thiserror::Error)]
pub enum DotnetError {
    #[error("not a PE")]            NotPe,
    #[error("not a CLR assembly")]  NotClr,
    #[error("bounds")]              Bounds,
    #[error("heap too large: {0}")] HeapTooLarge(usize),
}
```

Steps:
- Check `MZ` magic at offset 0
- Read `e_lfanew` (offset 0x3C) for PE header location
- Validate `PE\0\0` signature
- Read `NumberOfSections`, `SizeOfOptionalHeader`
- Read optional header `DataDirectory[14]` (`COM_DESCRIPTOR_DATA_DIRECTORY`) → RVA + size of CLI header
- Map RVA to file offset via section table

This is ~80-120 lines of careful bounds-checked code. See `object` crate or `ldr_data_table_entry` references.

- [ ] **TDD:** Tests with a hand-crafted minimal PE that has a CLI header.

## Task 3: CLI header → metadata root → `#US` heap

The CLI header gives an RVA to the metadata root. The root has a `BSJB` magic, then version length / version bytes / flags / streams count, then a list of stream-headers each pointing into the metadata blob. Walk them to find the stream named `#US`.

- [ ] **TDD:** Synthesize a minimal metadata blob with a single `#US` stream containing one known string. Test that `extract_us_strings` returns that string.

## Task 4: `#US` walker

Each entry in `#US`:
- compressed uint length tag (1/2/4 bytes — high bits indicate width):
  - 0xxxxxxx (1 byte)
  - 10xxxxxx xxxxxxxx (2 bytes)
  - 110xxxxx xxxxxxxx xxxxxxxx xxxxxxxx (4 bytes)
- `length` bytes follow: UTF-16LE chars + final byte flag

The first entry is always the empty string. Walk until offset reaches heap size or a length tag yields 0.

- [ ] **TDD:** Multiple-string fixture with various length tags, including 2-byte and 4-byte forms.

## Task 5: Integration into orchestrator

In `orchestrator::extract_from_chain`, after `let decompressed = gunzip(&pt, ...)`:

```rust
// First try .NET #US extraction; fall back to generic scan.
let nd_urls = if decompressed.starts_with(b"MZ") {
    match crate::aes_chain::dotnet::extract_us_strings(&decompressed) {
        Ok(strings) => {
            let mut acc = Vec::new();
            for s in &strings {
                // Run URL_RE on each #US string
                for url in scan::scan_text_for_url(s) { acc.push(url); }
            }
            acc
        }
        Err(_) => Vec::new(),
    }
} else {
    Vec::new()
};
let urls = if nd_urls.is_empty() {
    scan::scan_urls(&decompressed, MAX_URLS_PER_SAMPLE)
} else {
    nd_urls
};
```

Add `scan::scan_text_for_url(s: &str) -> Vec<String>` (re-using the URL regex against an already-decoded string).

## Task 6: Corpus measurement

- [ ] Re-run the 1416-sample corpus runner.
- [ ] Count delta vs Plan S baseline.
- [ ] Expected: +30 to +50 samples IF Task 1's investigation showed URLs are in `#US` literally. If Task 1 showed they're stack-built or further-encoded, gain is +0 and we report the variant for a future Plan U.

## Done criteria

- 5+ new unit tests for `dotnet.rs`, all passing
- Existing 283-test suite still green
- ≥ 4/5 reference samples in `tests/aes_chain_corpus.rs` recover at least one URL
- `CHANGELOG.md` entry committed
