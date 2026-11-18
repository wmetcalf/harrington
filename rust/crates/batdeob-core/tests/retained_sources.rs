#![allow(clippy::unwrap_used)]
use batdeob_core::{analyze, analyze_with_options, AnalysisOptions, Config};
use sha2::{Digest, Sha256};

fn options() -> AnalysisOptions {
    AnalysisOptions::default().with_retained_sources()
}

#[test]
fn capture_is_disabled_by_default() {
    let input = format!("@echo off\r\n::{}\r\necho kept\r\n", "A".repeat(1100));
    assert!(analyze(input.as_bytes(), &Config::default())
        .retained_sources
        .is_none());
}

#[test]
fn retained_sources_round_trip_crlf_repeated_carriers_without_analysis_changes() {
    let line = format!("::{}\r\n", "A".repeat(1100));
    let input = format!("@echo off\r\n{line}{line}echo kept\r\n");
    let cfg = Config::default();
    let before = analyze(input.as_bytes(), &cfg);
    let after = analyze_with_options(input.as_bytes(), &cfg, &options());
    assert_eq!(before.deobfuscated, after.deobfuscated);
    assert_eq!(
        serde_json::to_value(&before.traits).unwrap(),
        serde_json::to_value(&after.traits).unwrap()
    );
    assert_eq!(before.extracted_ps1, after.extracted_ps1);
    let retained = after.retained_sources.as_ref().unwrap();
    assert_eq!(
        retained.full_input_sha256().unwrap(),
        hex::encode(Sha256::digest(input.as_bytes()))
    );
    let event = retained
        .events()
        .iter()
        .find(|e| e.family == "long_double_colon")
        .unwrap();
    assert_eq!(event.ranges.len(), 2);
    assert_ne!(event.ranges[0].start_byte, event.ranges[1].start_byte);
    let snapshot = retained
        .snapshots()
        .iter()
        .find(|s| s.sha256 == event.snapshot_sha256)
        .unwrap();
    for range in &event.ranges {
        assert_eq!(
            &snapshot.bytes[range.start_byte..range.end_byte],
            line.as_bytes()
        );
    }
    assert_eq!(retained.manifest_json()["coverage_complete"], false);
    assert!(retained.manifest_json()["events"][0]["original_input_span"].is_null());
}

#[test]
fn retained_sources_preserve_raw_identity_for_utf16_and_invalid_utf8() {
    let text = format!("@echo off\r\n::{}\r\necho kept\r\n", "A".repeat(1100));
    let mut utf16 = vec![0xff, 0xfe];
    for unit in text.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let mut invalid = text.as_bytes().to_vec();
    invalid.splice(0..0, [b'r', b'e', b'm', b' ', 0xff, b'\n']);
    for input in [utf16, invalid] {
        let before = analyze(&input, &Config::default());
        let after = analyze_with_options(&input, &Config::default(), &options());
        assert_eq!(before.deobfuscated, after.deobfuscated);
        assert_eq!(
            serde_json::to_value(&before.traits).unwrap(),
            serde_json::to_value(&after.traits).unwrap()
        );
        let retained = after.retained_sources.as_ref().unwrap();
        assert_eq!(
            retained.full_input_sha256().unwrap(),
            hex::encode(Sha256::digest(&input))
        );
        assert!(!retained.events().is_empty());
        for snapshot in retained.snapshots() {
            assert!(std::str::from_utf8(&snapshot.bytes).is_ok());
        }
        for event in retained.manifest_json()["events"].as_array().unwrap() {
            assert!(event["original_input_span"].is_null());
        }
    }
}

#[test]
fn self_read_payload_and_all_existing_limits_remain_analysis_inputs() {
    use base64::Engine;
    use batdeob_core::Trait;
    let marker = "::SyntheticSourceMarker";
    let payload = format!(
        "$x='retained-self-read'; Write-Output $x; #{}",
        "A".repeat(2048)
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    let input = format!(
        r#"@echo off
powershell -NoP -C "$sweep = Get-Content '%~f0' -Raw; if ($sweep -match '{marker}([A-Za-z0-9+/=]+)') {{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])) | iex }}"
exit /b
{marker}{encoded}
"#
    );
    let cfg = Config::default();
    let before = analyze(input.as_bytes(), &cfg);
    let after = analyze_with_options(input.as_bytes(), &cfg, &options());
    assert_eq!(before.deobfuscated, after.deobfuscated);
    assert_eq!(before.extracted_ps1, after.extracted_ps1);
    assert_eq!(before.recovered_pe, after.recovered_pe);
    assert_eq!(
        serde_json::to_value(&before.traits).unwrap(),
        serde_json::to_value(&after.traits).unwrap()
    );
    assert!(after
        .extracted_ps1
        .iter()
        .any(|bytes| bytes == payload.as_bytes()));
    assert!(after
        .retained_sources
        .as_ref()
        .unwrap()
        .events()
        .iter()
        .any(|e| e.family == "colon_self_read_marker"));
    assert!(after
        .traits
        .iter()
        .any(|t| matches!(t, Trait::LineTruncated { .. })));
    let cfg = Config {
        max_output_line_bytes: 5,
        ..Config::default()
    };
    let before = analyze(b"echo short\r\n", &cfg);
    let after = analyze_with_options(b"echo short\r\n", &cfg, &options());
    assert_eq!(before.deobfuscated, after.deobfuscated);
    assert!(after
        .traits
        .iter()
        .any(|t| matches!(t, Trait::LineTruncated { .. })));
    assert_eq!(
        serde_json::to_value(before.traits).unwrap(),
        serde_json::to_value(after.traits).unwrap()
    );
}

#[test]
fn existing_trait_caps_are_not_cleared_by_capture() {
    use batdeob_core::Trait;
    let cfg = Config {
        max_traits_per_kind: 1,
        ..Config::default()
    };
    let input = b"curl https://first.example/a -o a\r\ncurl https://second.example/b -o b\r\n";
    let before = analyze(input, &cfg);
    let after = analyze_with_options(input, &cfg, &options());
    assert_eq!(before.deobfuscated, after.deobfuscated);
    assert_eq!(
        serde_json::to_value(before.traits).unwrap(),
        serde_json::to_value(&after.traits).unwrap()
    );
    assert!(after
        .traits
        .iter()
        .any(|t| matches!(t, Trait::TraitsCapped { .. })));
}

#[test]
fn root_only_capture_does_not_mislabel_html_wrappers_as_original_batch_source() {
    let payload = serde_json::json!({"payload":{"blob":{"rawLines":["@echo off",format!("::{}","A".repeat(1100)),"echo kept"],"path":"synthetic.bat"}}});
    let input = format!("<html><script type=\"application/json\" data-target=\"react-app.embeddedData\">{payload}</script></html>");
    let before = analyze(input.as_bytes(), &Config::default());
    let after = analyze_with_options(input.as_bytes(), &Config::default(), &options());
    assert!(before.deobfuscated.contains("GitHub HTML blob wrapper"));
    assert_eq!(before.deobfuscated, after.deobfuscated);
    let retained = after.retained_sources.as_ref().unwrap();
    assert_eq!(
        retained.full_input_sha256().unwrap(),
        hex::encode(Sha256::digest(input.as_bytes()))
    );
    assert!(retained.snapshots().is_empty());
    assert_eq!(
        retained.manifest_json()["omissions"]["unsupported_input"],
        1
    );
}

#[test]
fn oversized_capture_is_withheld_without_changing_compact_analysis_or_limits() {
    let input = format!("@echo off\n::{}\necho kept\n", "A".repeat(8 * 1024 * 1024));
    let cfg = Config {
        timeout_secs: 0,
        ..Config::default()
    };
    let before = analyze(input.as_bytes(), &cfg);
    let after = analyze_with_options(input.as_bytes(), &cfg, &options());
    assert_eq!(before.deobfuscated, after.deobfuscated);
    assert_eq!(
        serde_json::to_value(before.traits).unwrap(),
        serde_json::to_value(&after.traits).unwrap()
    );
    assert!(after.deobfuscated.contains("echo kept"));
    let retained = after.retained_sources.as_ref().unwrap();
    assert!(retained.snapshots().is_empty());
    assert!(retained.events().is_empty());
    assert_eq!(retained.manifest_json()["omissions"]["bytes"], 1);
    assert_eq!(
        retained.manifest_json()["capture_complete_for_selected_passes"],
        false
    );
}

#[test]
fn actual_root_postanalysis_pass_retains_all_scaffold_occurrences() {
    let mut input = String::from("@echo off\r\n");
    for i in 0..105 {
        input.push_str(&format!(
            "set \"NoiseCarrierScaffoldName{i:03}=alphabeticalpayload{i:03}filler\"\r\n"
        ));
        if i % 4 == 0 {
            input.push_str("echo kept\r\n");
        }
    }
    let cfg = Config {
        timeout_secs: 0,
        ..Config::default()
    };
    let before = analyze(input.as_bytes(), &cfg);
    let after = analyze_with_options(input.as_bytes(), &cfg, &options());
    assert_eq!(before.deobfuscated, after.deobfuscated);
    assert_eq!(
        serde_json::to_value(before.traits).unwrap(),
        serde_json::to_value(&after.traits).unwrap()
    );
    let retained = after.retained_sources.as_ref().unwrap();
    let event = retained
        .events()
        .iter()
        .find(|event| event.family == "dense_long_set_scaffolding")
        .unwrap();
    assert_eq!(event.stage, "root_post_analysis_set");
    assert_eq!(event.ranges.len(), 105);
    let snapshot = retained
        .snapshots()
        .iter()
        .find(|snapshot| snapshot.sha256 == event.snapshot_sha256)
        .unwrap();
    for range in &event.ranges {
        let line = std::str::from_utf8(&snapshot.bytes[range.start_byte..range.end_byte]).unwrap();
        assert!(line.contains("NoiseCarrierScaffoldName"));
        assert!(!line.contains("echo kept"));
    }
}

#[test]
fn contiguous_scaffolding_run_range_covers_only_the_omitted_set_lines() {
    // Exercises the real contiguous-run loop (pending_start/offset), not the
    // flush helper alone: the range must end before the surviving commands.
    let mut input = String::from("@echo off\r\n");
    for i in 0..64 {
        input.push_str(&format!("set ScaffoldCarrierNm{i:03}=vqxzw\r\n"));
    }
    for i in 0..70 {
        input.push_str(&format!("echo surviving-command-{i:07}\r\n"));
    }
    let report = analyze_with_options(input.as_bytes(), &Config::default(), &options());
    let retained = report.retained_sources.as_ref().unwrap();
    let event = retained
        .events()
        .iter()
        .find(|e| e.family == "long_set_scaffolding_run")
        .unwrap();
    let snapshot = retained
        .snapshots()
        .iter()
        .find(|s| s.sha256 == event.snapshot_sha256)
        .unwrap();
    for range in &event.ranges {
        let omitted =
            std::str::from_utf8(&snapshot.bytes[range.start_byte..range.end_byte]).unwrap();
        assert!(
            !omitted.contains("surviving-command"),
            "range {}..{} covers surviving commands",
            range.start_byte,
            range.end_byte
        );
        assert!(omitted.starts_with("set ScaffoldCarrierNm"), "{omitted:?}");
    }
    let covered: usize = event.ranges.iter().map(|r| r.end_byte - r.start_byte).sum();
    assert_eq!(covered, 64 * "set ScaffoldCarrierNm000=vqxzw\r\n".len());
}
