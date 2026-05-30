//! Process many samples in a loop and print a one-line CSV of URLs per
//! file. Designed for piping into other tools. Reads paths from stdin or
//! takes a single path on the command line.
//!
//!     find samples/ -name '*.bat' | cargo run --example batch_url_extract -p harrington-core
//!     cargo run --example batch_url_extract -p harrington-core -- single.bat

use harrington_core::{analyze, Config, Trait};
use std::io::BufRead;

fn urls_in(report: &harrington_core::Report) -> Vec<String> {
    let mut out = Vec::new();
    for t in &report.traits {
        match t {
            Trait::Download { src, .. }
            | Trait::CertutilDownload { url: src, .. }
            | Trait::BitsadminDownload { url: src, .. }
            | Trait::DownloadInDeobText { src, .. }
                if !out.contains(src) =>
            {
                out.push(src.clone());
            }
            Trait::UncWebDavC2 { http_url, .. }
                if !http_url.is_empty() && !out.contains(http_url) =>
            {
                out.push(http_url.clone());
            }
            _ => {}
        }
    }
    out
}

fn process(path: &str) {
    let input = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{path}: read: {e}");
            return;
        }
    };
    let report = analyze(&input, &Config::default());
    let urls = urls_in(&report);
    println!("{}\t{}\t{}", path, urls.len(), urls.join(","));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        for p in &args {
            process(p);
        }
        return;
    }
    // Read paths from stdin, one per line.
    let stdin = std::io::stdin();
    for line in stdin.lock().lines().map_while(Result::ok) {
        let p = line.trim();
        if !p.is_empty() {
            process(p);
        }
    }
}
