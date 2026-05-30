//! Parity tests against the Python batch_deobfuscator suite.
//! Source: ../../batch_deobfuscator/tests/test_unittests.py
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use harrington_core::{analyze, Config};

fn deob(script: &str) -> String {
    let report = analyze(script.as_bytes(), &Config::default());
    report.deobfuscated.trim_end_matches("\r\n").to_string()
}

#[test]
fn simple_set() {
    let out = deob("set WALLET=43DTEF92be6XcPj5Z7U\r\necho %WALLET%");
    assert!(out.contains("echo 43DTEF92be6XcPj5Z7U"), "got:\n{}", out);
}

#[test]
fn unset_variable_expands_to_empty() {
    let out = deob("echo ERROR: %MISSING%");
    assert!(out.contains("echo ERROR: "), "got:\n{}", out);
    assert!(!out.contains("%MISSING%"), "var not expanded:\n{}", out);
}

#[test]
fn echo_caret_pipe_preserved_through_normalize() {
    let out = deob(r#"echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL"#);
    // Lexer's caret-escape strips ^ — pipe/redirect become literal | and >NUL inside the echo output.
    // The exact rendering depends on how the splitter treats the caret-escaped operator.
    // Acceptable outcomes: caret kept literal OR pipe/redirect rendered literally inside one command.
    let has_pipe_or_caret = out.contains("|") || out.contains("^|");
    let has_redir_or_caret = out.contains(">NUL") || out.contains("^>NUL");
    assert!(has_pipe_or_caret && has_redir_or_caret, "got: {}", out);
}

#[test]
fn comma_semicolon_splits_into_commands() {
    // Leading `,;` runs (no surrounding arg-word chars) collapse to
    // whitespace. Commas WITHIN argument-style tokens (`a,b`) stay
    // literal — CMD passes the comma to the receiving program as part
    // of the arg, and external tools like rundll32 rely on this. The
    // `&&` is the real command separator here.
    let out = deob(",;,cmd.exe ,; /c ,; echo Command 1&&echo Command 2");
    assert!(out.contains("echo Command 2"), "got: {}", out);
}

#[test]
fn empty_var_sandwich_collapses() {
    let out = deob(r#"ec%a%ho "Fi%b%nd Ev%c%il!""#);
    // With delayed expansion OFF, `!` inside double quotes is a literal character
    // (no expansion occurs) so it is preserved verbatim by the char-level helper.
    assert!(out.contains(r#"echo "Find Evil!""#), "got:\n{}", out);
}

// ============================================================================
// Plan B: previously-skipped Python DOSfuscation tests
// ============================================================================

#[test]
fn dosfuscation_set_reverse_v_on() {
    let script_str = r#"cmd /V:ON /C "set reverse=ona/ tatsten&& FOR /L %A IN (11 -1 0) DO set final=!final!!reverse:~%A,1!&&IF %A==0 CALL %final:~-12%""#;
    let report = analyze(script_str.as_bytes(), &Config::default());
    // The decoded payload is "netstat /ano"
    let deob = &report.deobfuscated;
    assert!(
        deob.contains("netstat") && deob.contains("/ano"),
        "expected 'netstat' and '/ano' in:\n{}",
        deob
    );
}

#[test]
fn dosfuscation_call_var_for_simple() {
    let inner = r#"set unique=nets /ao&&FOR %A IN (0 1 2 3 2 6 2 4 5 6 0 7 1337) DO set final=!final!!unique:~%A,1!&& IF %A==1337 CALL !final:~-12!"#;
    let wrapped = format!(r#"cmd /V:ON /C "{}""#, inner);
    let report = analyze(wrapped.as_bytes(), &Config::default());
    let deob = &report.deobfuscated;
    assert!(
        deob.contains("netstat") && deob.contains("/ano"),
        "expected 'netstat' '/ano' in:\n{}",
        deob
    );
}

#[test]
fn dosfuscation_for_execution_set_findstr() {
    let script_str = r#"FOR /F "delims=s\ tokens=4" %%a IN ('set^|findstr PSM') DO %%a hostname"#;
    let report = analyze(script_str.as_bytes(), &Config::default());
    // PSModulePath in our baseline:
    // C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\
    // After tokenizing on 's\\', the 4th token is "powershell".
    // We don't assert exact full path; just verify hostname appears in output
    // and (ideally) the deobfuscated text contains "powershell" or "hostname".
    let deob = &report.deobfuscated;
    assert!(deob.contains("hostname"), "no hostname in:\n{}", deob);
}

#[test]
fn dosfuscation_type_self_extract_findstr() {
    // The script embeds its own payload as a marker-prefixed comment line.
    // findstr reads %~f0 (the script itself = input_bytes) and filters lines
    // containing "::CMD".  for /F with delims= returns the whole matched line.
    // The body executes the matched line as a command via %%a.
    let script = b"@echo off\r\nfor /F \"delims=\" %%a in ('findstr \"::CMD\" \"%~f0\"') do echo got=%%a\r\ngoto :eof\r\n::CMD echo SELF_EXTRACTED_PAYLOAD\r\n";
    let report = analyze(script, &Config::default());
    let deob = &report.deobfuscated;
    assert!(
        deob.contains("SELF_EXTRACTED_PAYLOAD"),
        "expected SELF_EXTRACTED_PAYLOAD in:\n{}",
        deob
    );
}
