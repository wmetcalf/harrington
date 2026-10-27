#![allow(clippy::expect_used, clippy::unwrap_used)]
use assert_cmd::Command;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::TempDir;

fn input(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("synthetic.bat");
    fs::write(
        &path,
        format!("@echo off\r\n::{}\r\necho kept\r\n", "A".repeat(1100)),
    )
    .unwrap();
    path
}

#[test]
fn opt_in_writes_exact_snapshots_and_manifest_without_changing_existing_outputs() {
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    let before = dir.path().join("before");
    let after = dir.path().join("after");
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&before)
        .assert()
        .success();
    assert!(!before.join("retained-source-manifest.json").exists());
    let output = Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&after)
        .args([
            "--retain-summarized-sources",
            "--retained-source-budget-bytes",
            "8388608",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let manifest_bytes = fs::read(after.join("retained-source-manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["coverage_complete"], false);
    assert_eq!(
        manifest["full_input_sha256"],
        hex::encode(Sha256::digest(fs::read(&input).unwrap()))
    );
    assert!(manifest["events"][0]["original_input_span"].is_null());
    assert!(report["output_files"]["retained_sources"]["manifest"]["name"].is_string());
    for name in ["deobfuscated.bat", "traits.json"] {
        assert_eq!(
            fs::read(before.join(name)).unwrap(),
            fs::read(after.join(name)).unwrap()
        );
    }
    let mut retained_bytes = manifest_bytes.len();
    for snapshot in manifest["snapshots"].as_array().unwrap() {
        assert!(snapshot.get("bytes").is_none());
        assert_eq!(snapshot["available"], true);
        let data = fs::read(after.join(snapshot["name"].as_str().unwrap())).unwrap();
        retained_bytes += data.len();
        assert_eq!(hex::encode(Sha256::digest(&data)), snapshot["sha256"]);
        assert_eq!(data.len() as u64, snapshot["size"].as_u64().unwrap());
    }
    assert!(retained_bytes <= 8 * 1024 * 1024);
}

#[test]
fn capture_requires_outdir_and_rejects_a_larger_profile() {
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("--retain-summarized-sources")
        .assert()
        .failure()
        .stderr(predicates::str::contains("--out-dir"));
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(dir.path().join("out"))
        .args([
            "--retain-summarized-sources",
            "--retained-source-budget-bytes",
            "8388609",
        ])
        .assert()
        .failure();
}

#[test]
fn conflicting_snapshot_prevents_success_manifest() {
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    let sha = hex::encode(Sha256::digest(fs::read(&input).unwrap()));
    fs::write(out.join(format!("source-{sha}.bin")), b"do not overwrite").unwrap();
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .arg("--retain-summarized-sources")
        .assert()
        .failure();
    assert!(!out.join("retained-source-manifest.json").exists());
    assert_eq!(
        fs::read(out.join(format!("source-{sha}.bin"))).unwrap(),
        b"do not overwrite"
    );
}

#[cfg(unix)]
#[test]
fn symlink_manifest_target_is_never_followed() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    let protected = dir.path().join("protected");
    fs::write(&protected, b"unchanged").unwrap();
    symlink(&protected, out.join("retained-source-manifest.json")).unwrap();
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .arg("--retain-summarized-sources")
        .assert()
        .failure();
    assert_eq!(fs::read(&protected).unwrap(), b"unchanged");
    assert_eq!(
        fs::read_dir(&out)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with(".retained-source-"))
            .count(),
        0
    );
}

#[test]
fn force_export_failure_does_not_leave_an_old_success_manifest() {
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(
        out.join("retained-source-manifest.json"),
        b"previous-success",
    )
    .unwrap();
    fs::create_dir(out.join("0000000000.bat")).unwrap();
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["--retain-summarized-sources", "--force"])
        .assert()
        .failure();
    assert!(!out.join("retained-source-manifest.json").exists());
}

#[cfg(unix)]
#[test]
fn force_snapshot_fifo_collision_fails_without_blocking_or_manifest() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    let sha = hex::encode(Sha256::digest(fs::read(&input).unwrap()));
    let fifo = CString::new(out.join(format!("source-{sha}.bin")).as_os_str().as_bytes()).unwrap();
    // Only creates an inert FIFO inside this test's temporary output directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    Command::cargo_bin("batdeob")
        .unwrap()
        .timeout(std::time::Duration::from_secs(2))
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["--retain-summarized-sources", "--force"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("existing output path"));
    assert!(!out.join("retained-source-manifest.json").exists());
}

#[test]
fn force_replaces_old_snapshot_set_and_preserves_unrelated_files() {
    let dir = TempDir::new().unwrap();
    let input = input(&dir);
    let out = dir.path().join("out");
    let sha = hex::encode(Sha256::digest(fs::read(&input).unwrap()));
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .arg("--retain-summarized-sources")
        .assert()
        .success();
    fs::write(
        out.join("source-not-a-generated-digest.bin"),
        b"keep human file",
    )
    .unwrap();
    fs::write(
        &input,
        format!("@echo off\r\n::{}\r\necho kept\r\n", "B".repeat(1100)),
    )
    .unwrap();
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["--retain-summarized-sources", "--force"])
        .assert()
        .success();
    assert!(!out.join(format!("source-{sha}.bin")).exists());
    assert_eq!(
        fs::read(out.join("source-not-a-generated-digest.bin")).unwrap(),
        b"keep human file"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("retained-source-manifest.json")).unwrap())
            .unwrap();
    for snapshot in manifest["snapshots"].as_array().unwrap() {
        assert!(out.join(snapshot["name"].as_str().unwrap()).is_file());
    }
    Command::cargo_bin("batdeob")
        .unwrap()
        .arg("report")
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .arg("--force")
        .assert()
        .success();
    assert!(!out.join("retained-source-manifest.json").exists());
    assert_eq!(
        fs::read_dir(&out)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("source-"))
            .count(),
        1
    );
}
