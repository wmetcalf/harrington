//! Run analyze with a customized Config: lower limits, no self-extract,
//! stricter trait-per-kind cap. Useful when you want bounded latency or
//! you're batch-analyzing many small samples in parallel.
//!
//!     cargo run --example custom_config -p batdeob-core -- path/to/sample.bat

use batdeob_core::{analyze, Config, WinVer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: custom_config <sample.bat>")?;
    let input = std::fs::read(&path)?;

    let cfg = Config {
        max_depth: 6,           // shallow recursion
        max_iterations: 10_000, // tight FOR-loop budget
        max_child_scripts: 16,  // few children
        timeout_secs: 3,        // short wall clock
        self_extract: false,    // skip %~f0 chain
        winver: WinVer::Win10,
        max_output_bytes: 1024 * 1024,    // 1 MiB output cap
        max_output_line_bytes: 16 * 1024, // 16 KiB line cap
        max_traits_per_kind: 20,          // aggressive dedup
    };

    let report = analyze(&input, &cfg);
    println!("traits: {}", report.traits.len());
    println!("deob size: {}", report.deobfuscated.len());
    println!(
        "extracted: {} cmd, {} ps1",
        report.extracted_cmd.len(),
        report.extracted_ps1.len()
    );
    Ok(())
}
