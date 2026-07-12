//! AES-CBC dropper chain — recover URLs from the multi-stage encrypted
//! malware family detected by `deob_scan::scan_multistage_encrypted_dropper`.
//!
//! See `docs/superpowers/notes/2026-05-19-aes-chain-trace.md` for the
//! observed chain shape. This module re-runs the decryption against the
//! raw .bat bytes and emits the recovered URLs as `DownloadInDeobText`
//! traits with `line_hint = "aes-chain"`.

pub mod crypto;
pub mod dotnet;
pub mod orchestrator;
pub mod payload_lines;
pub mod ps_extract;
pub mod scan;

pub use orchestrator::extract_from_chain;
