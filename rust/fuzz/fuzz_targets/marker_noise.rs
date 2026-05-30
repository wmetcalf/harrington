#![no_main]
use batdeob_core::marker_noise;
use libfuzzer_sys::fuzz_target;

// Fuzz the strip-marker-noise loop directly. This was the algorithm that
// silently mangled `$Hello` to `$Ho` and `powershell` to `powersh` before
// the sandwich-pattern guard landed; pathological inputs (long alpha
// runs, contrived sandwich/non-sandwich mixes, MAX_SCAN_BYTES boundary)
// should never panic, never blow the per-line allocation budget, and
// always return a result.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = marker_noise::strip_line(s);
    let _ = marker_noise::decodable_base64_spans(s);
});
