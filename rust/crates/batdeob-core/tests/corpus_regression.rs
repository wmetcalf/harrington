//! Corpus regression test: run every sample in tests/corpus/ through
//! analyze() with strict limits. Failures = any panic, any sample taking
//! >2 seconds wall-clock, or any sample producing >1 MB output.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use batdeob_core::{analyze, Config};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[test]
fn corpus_no_panics_no_hangs() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut total = 0;
    let mut slow: Vec<(String, f64)> = Vec::new();
    let mut huge: Vec<(String, usize)> = Vec::new();
    let cfg = Config {
        timeout_secs: 2,
        max_output_bytes: 4 * 1024 * 1024,
        ..Config::default()
    };

    for entry in fs::read_dir(&dir).expect("read corpus dir") {
        let path = entry.expect("entry").path();
        if !path.is_file() {
            continue;
        }
        let content = fs::read(&path).expect("read sample");
        let start = Instant::now();
        let report = analyze(&content, &cfg);
        let wall = start.elapsed().as_secs_f64();
        total += 1;
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .to_string();
        if wall > 2.0 {
            slow.push((name.clone(), wall));
        }
        if report.deobfuscated.len() > 1_000_000 {
            huge.push((name, report.deobfuscated.len()));
        }
    }
    assert!(total > 0, "no samples found in tests/corpus/");
    eprintln!("Corpus: {} samples processed", total);
    if !slow.is_empty() {
        panic!("Samples > 2s wall: {:?}", slow);
    }
    if !huge.is_empty() {
        panic!("Samples > 1 MB output: {:?}", huge);
    }
}
