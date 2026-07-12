#![no_main]
use libfuzzer_sys::fuzz_target;
use batdeob_core::{analyze, Config};

fuzz_target!(|data: &[u8]| {
    let cfg = Config {
        timeout_secs: 1,
        max_iterations: 1024,
        max_output_bytes: 1024 * 1024,
        max_depth: 4,
        max_child_scripts: 4,
        ..Config::default()
    };
    let _ = analyze(data, &cfg);
});
