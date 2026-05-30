#![no_main]
use harrington_core::deob_scan;
use harrington_core::env::Environment;
use harrington_core::Config;
use libfuzzer_sys::fuzz_target;

// Fuzz the decimal-IP URL scanner. The regex has a digit-boundary check
// to reject 11+ digit numbers and a path-stop on `;`. Targeting it
// directly with random text exercises the post-match validator (which
// runs OUTSIDE the regex engine for the digit-boundary check).
fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let mut env = Environment::new(&Config::default());
    deob_scan::scan_decimal_ip_urls(s, &mut env);
});
