//! Minimum library example: analyze a `.bat` file and print every URL found.
//!
//! Run with:
//!
//!     cargo run --example basic -p harrington-core -- path/to/sample.bat

use harrington_core::{analyze, Config, Trait};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: basic <sample.bat>")?;
    let input = std::fs::read(&path)?;

    let report = analyze(&input, &Config::default());

    println!("input: {} ({} bytes)", path, input.len());
    println!(
        "deobfuscated: {} bytes, {} traits emitted",
        report.deobfuscated.len(),
        report.traits.len()
    );

    for t in &report.traits {
        match t {
            Trait::Download { src, dst, .. } => println!(
                "  Download           {src}{}",
                dst.as_deref()
                    .map(|d| format!(" -> {d}"))
                    .unwrap_or_default()
            ),
            Trait::CertutilDownload { url, dst } => println!("  CertutilDownload   {url} -> {dst}"),
            Trait::BitsadminDownload { url, dst } => {
                println!("  BitsadminDownload  {url} -> {dst}")
            }
            Trait::DownloadInDeobText { src, line_hint } => {
                println!("  Sweep hit          {src}  [{line_hint}]")
            }
            Trait::UncWebDavC2 {
                http_url,
                host,
                port,
                ..
            } => println!("  UNC WebDAV C2      {http_url}  (raw: \\\\{host}@{port})"),
            _ => {}
        }
    }
    Ok(())
}
