#![no_main]
use batdeob_core::handlers::cmd::extract_cmd_inner;
use libfuzzer_sys::fuzz_target;

// Fuzz the `cmd /c "..."` body extractor. Quote-balance handling has been
// a recurring trouble spot (nested `SET "x=val"`, trailing redirects,
// unbalanced quotes from caret continuations). Should never panic on any
// byte sequence; should always either return None or a String.
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = extract_cmd_inner(s);
});
