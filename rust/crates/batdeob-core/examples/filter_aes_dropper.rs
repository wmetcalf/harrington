//! Recognize the AES-CBC multi-stage dropper family and print the
//! recovered key material. The trait carries both the outer Key/IV (used
//! to decrypt the `:: ` line ciphertext envelope) and any nested Key/IV
//! the loader assembly holds in its .NET `#US` heap.
//!
//!     cargo run --example filter_aes_dropper -p batdeob-core -- sample.bat

use batdeob_core::{analyze, Config, Trait};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: filter_aes_dropper <sample.bat>")?;
    let input = std::fs::read(&path)?;
    let report = analyze(&input, &Config::default());

    for t in &report.traits {
        if let Trait::MultiStageEncryptedDropper {
            marker,
            b64_length,
            has_aes_cbc,
            has_gzip_stage,
            reads_self_lines,
            aes_key_b64,
            aes_iv_b64,
            assemblies_recovered,
            nested_aes,
        } = t
        {
            println!("AES-CBC dropper detected in {path}");
            println!("  marker: {marker:?}  (stage-1 b64 length: {b64_length})");
            println!("  visible: aes_cbc={has_aes_cbc} gzip={has_gzip_stage} self_lines={reads_self_lines}");
            if let (Some(k), Some(v)) = (aes_key_b64, aes_iv_b64) {
                println!("  outer key:  {k}");
                println!("  outer iv:   {v}");
            }
            if let Some(n) = assemblies_recovered {
                println!("  assemblies_recovered: {n}");
            }
            for (i, nk) in nested_aes.iter().enumerate() {
                println!("  nested[{i}]:");
                println!("    key: {}", nk.key_b64);
                println!("    iv:  {}", nk.iv_b64);
            }
        }
    }
    Ok(())
}
