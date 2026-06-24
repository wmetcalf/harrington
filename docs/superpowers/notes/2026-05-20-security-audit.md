# Security & Functionality Audit — 2026-05-20

Audit performed across four dimensions in parallel: memory/DoS safety,
crypto correctness, path/file I/O, and IOC accuracy. Each finding lists
severity, file:line, the issue, the fix, and the commit that lands it.

Auditors found a mix of real bugs and false positives. False positives
are recorded so the next round doesn't re-flag them.

## Confirmed findings — fixed

### Memory / DoS

| # | Severity | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| M1 | High | `aes_chain/dotnet.rs:36-46` | `parse_sections` allocates and walks `num` sections with `num` from a u16 header (max 65535). Real PE images have <96. | Cap `num` to 96; reject larger as `Bounds`. |
| M2 | High | `aes_chain/dotnet.rs:38,52,116,117,124,142,160,161,177` | Unchecked usize arithmetic on offsets / lengths read from attacker-controlled PE. Most are bounded by surrounding checks but defense-in-depth prefers `checked_add`. | Convert hot arithmetic to `checked_add` with `Bounds` on overflow. |
| M3 | High | `aes_chain/dotnet.rs:147,166` | Direct slice `&bytes[us_offset..us_offset+us_size]` after a bounds check on the line above. Safe but brittle. | Replace with `bytes.get(..).ok_or(Bounds)?`. |
| M4 | High | `aes_chain/orchestrator.rs:171` | `marker_chain` from stage-2 PS feeds an unbounded `for (n,r) in chain { as_text.replace(n,r) }`. A malicious stage-2 could define thousands of replace pairs. | Already partly mitigated by `find_replace_chain` size; tighten by capping `marker_chain` to 16. |
| M5 | Medium | `aes_chain/ps_extract.rs:55-63` | `find_replace_chain` collects every regex match unbounded. | Cap with `.take(32)`. |
| M6 | Medium | `aes_chain/orchestrator.rs:85-95` | `assemblies_recovered` increments even when gunzip *fails* (and we fall back to the raw plaintext). Misleads analyst. | Only count on gunzip success; track raw-fallback separately if useful. |

### Crypto

The aes_chain primitives are correct: `decrypt_padded_mut::<Pkcs7>`
returns `Result<&[u8], UnpadError>`, key length is dispatched by 16/24/32
into the right `Aes{128,192,256}Cbc::Decryptor`, IV is length-checked,
ciphertext is size-capped, gunzip is output-size-capped. No timing or
side-channel concerns — we're decrypting with the malware's own
plaintext-embedded key, not protecting a secret.

The findings here are all bounded-check / parser robustness, already
covered by M1-M3. No additional crypto fixes.

### Path / file I/O

| # | Severity | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| F1 | High | `batdeob-cli/src/main.rs` (`write_*` functions) | `fs::create_dir_all(out_dir)` followed by `out_dir.join(filename)` does not protect against `out_dir` being a symlink to a sensitive location, nor against generated filenames containing `..` or absolute paths. | Canonicalize `out_dir` after creation; for every write, canonicalize the target's parent and verify it starts with the canonical out_dir. |
| F2 | High | `batdeob-cli/src/main.rs` (stdin path) | `stdin().read_to_end(&mut buf)` is unbounded. Piping a multi-GB file causes OOM. | Use `stdin().take(MAX_INPUT_BYTES).read_to_end(...)`; reject when exhausted. |
| F3 | Medium | `batdeob-cli/src/main.rs` (report subcommand) | `--out <path>` accepts any path including absolute or `..`-traversing values. | Validate that `out` is a single non-traversing filename when not explicitly absolute. |
| F4 | Medium | `batdeob-cli/src/main.rs` (error formatters) | Some error messages use `{}` to print user-supplied paths, allowing terminal escape injection via filenames containing `\x1b[`. | Use `{:?}` debug format on all path interpolations in error paths. |

### IOC accuracy

| # | Severity | File:Line | Issue | Fix |
|---|----------|-----------|-------|-----|
| I1 | High | `deob_scan.rs::scan_bare_ip_urls` | Emits URLs without checking `is_noise_url`. A benign `curl 8.8.8.8/` mention or cert metadata IP would land as a false-positive C2 IOC. | Add `if is_noise_url(&url) { continue; }`. |
| I2 | High | `deob_scan.rs::scan_truncated_url_vars` | `known` set omits `CertutilDownload` and `BitsadminDownload` URLs, so an already-extracted URL re-fires through this sweep. | Include both kinds in the `known` filter. |

## False positives — agent claims that don't reproduce

- **"3 panics in non-test code (`lib.rs:381,2065,2772`)"** — All three are
  inside `#[cfg(test)]` modules with `#[allow(clippy::panic)]`. Verified
  by reading surrounding context. No fix needed.
- **"Trait-level dedup gaps across sweeps (DownloadInDeobText with
  different line_hint)"** — Every sweep filters its `known` set against
  *all* prior emitted Download / DownloadInDeobText / Certutil /
  Bitsadmin URLs, so cross-sweep dedup already works. The exception is
  `scan_truncated_url_vars`, which is fix I2.
- **"`looks_like_powershell` false-positive on `REM powershell`
  comments"** — The function is only called on extracted PS payloads
  (`env.all_extracted_ps1` and during PS scanning), never on raw CMD
  lines. The PS-extraction handlers gate this upstream, so a `REM` line
  in a .bat never reaches alias expansion.
- **"PE section count DoS via 65535 sections"** — Real, but the actual
  exploitable cost is a 2.6 MB `Vec` allocation. Still fixed by M1 as
  defense in depth.

## Notes (not fixed; would-be-nice)

- `aes_chain/orchestrator.rs:130-131` writes the recovered AES Key/IV to
  the trait JSON. Intentional and documented in Plan S; not a leak.
- `aes_chain/scan.rs:54-65` allocates `bytes.len() / 2` for the UTF-16LE
  ASCII projection. Capped upstream by `MAX_STAGE_OUTPUT = 16 MB`, so
  max alloc is 8 MB. Acceptable.
- `find_nested_aes_pairs` could pair coincidentally-sized base64 strings
  into spurious AES Key/IV. The 32+16 byte alignment is strong enough in
  practice; corpus measurement shows 10/17 samples surface the correct
  pair, 0 spurious pairs observed.
