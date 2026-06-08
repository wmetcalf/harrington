//! Synthetic command-pipeline emulator. Models the output of selected
//! cmd.exe commands against the live Environment so `for /F ('…')` and
//! `findstr "%~f0"` style gadgets can resolve without an actual shell.

use crate::env::Environment;
use crate::handlers::util::split_words;

pub fn run_pipeline(pipeline: &str, env: &mut Environment) -> Vec<String> {
    if is_cmd_prompt_escape_probe(pipeline) {
        return vec!["[ESC]".to_string()];
    }
    // Split on top-level `|` (not inside quotes) and run each stage in order
    let stages = split_pipeline(pipeline);
    let mut buf: Vec<String> = Vec::new();
    for (i, stage) in stages.iter().enumerate() {
        let input = if i == 0 {
            Vec::new()
        } else {
            std::mem::take(&mut buf)
        };
        buf = run_stage(stage.trim(), input, env);
    }
    buf
}

fn is_cmd_prompt_escape_probe(pipeline: &str) -> bool {
    let stages = split_pipeline(pipeline);
    if stages.len() != 2 {
        return false;
    }
    let first = stages[0].trim();
    let second = stages[1].trim();
    first.eq_ignore_ascii_case("echo prompt $E") && second.eq_ignore_ascii_case("cmd")
}

pub fn can_run_pipeline(pipeline: &str) -> bool {
    if is_cmd_prompt_escape_probe(pipeline) {
        return true;
    }
    let stages = split_pipeline(pipeline);
    !stages.is_empty()
        && stages
            .iter()
            .all(|stage| stage_command(stage).is_some_and(|cmd| is_supported_command(&cmd)))
}

fn split_pipeline(p: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '^' && i + 1 < chars.len() {
            cur.push(chars[i + 1]);
            i += 2;
            continue;
        }
        if c == '"' {
            in_dq = !in_dq;
            cur.push(c);
            i += 1;
            continue;
        }
        if c == '|' && !in_dq {
            out.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        cur.push(c);
        i += 1;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn run_stage(stage: &str, input: Vec<String>, env: &mut Environment) -> Vec<String> {
    // First token is the command
    let stage = normalize_stage_prefix(stage);
    let Some((cmd_token, rest)) = split_stage_command(stage) else {
        return Vec::new();
    };
    let cmd = synth_command_key_with_env(cmd_token, env);
    let parts = split_words(rest);
    let rest_args: Vec<&str> = parts.iter().map(String::as_str).collect();
    match cmd.as_str() {
        "set" => {
            let prefix = rest_args
                .first()
                .copied()
                .unwrap_or("")
                .to_ascii_lowercase();
            let mut lines: Vec<(String, String)> = env
                .vars_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            lines.sort_by_key(|(k, _)| k.to_ascii_lowercase());
            lines
                .into_iter()
                .filter(|(k, _)| prefix.is_empty() || k.to_ascii_lowercase().starts_with(&prefix))
                // Real Windows CMD's `set` outputs each var with its
                // canonical Windows casing (`PSModulePath`, `COMSPEC`,
                // `ALLUSERSPROFILE`, …), not the lowercased storage key
                // we keep internally. The FE DOSfuscation FOR /F gadget
                // `set^|findstr PSM` is case-sensitive (`findstr` is) so
                // matching against `psmodulepath=…` misses. Re-case the
                // built-in vars before printing so the gadget resolves.
                .map(|(k, v)| format!("{}={}", canonical_env_name(&k), v))
                .collect()
        }
        "findstr" => {
            // If input is empty and the last arg is a file path (e.g. "%~f0" or a .bat path),
            // read that file as the input source before filtering.
            let mut effective_input = input;
            if effective_input.is_empty() {
                // Expand %~f0 → synthetic path, check if last arg is a file source.
                let expanded_args: Vec<String> = rest_args
                    .iter()
                    .map(|a| {
                        let trimmed = a.trim_matches('"');
                        if trimmed.eq_ignore_ascii_case("%~f0")
                            || trimmed.eq_ignore_ascii_case("%0")
                        {
                            "C:\\Users\\al\\Downloads\\script.bat".to_string()
                        } else {
                            (*a).to_string()
                        }
                    })
                    .collect();
                if let Some(last) = expanded_args.last() {
                    let candidate = last.trim_matches('"');
                    if candidate.contains(".bat")
                        || candidate.contains(".cmd")
                        || candidate.contains('\\')
                        || candidate.contains('/')
                    {
                        effective_input = type_file(candidate, env);
                    }
                }
                let expanded_refs: Vec<&str> = expanded_args.iter().map(String::as_str).collect();
                return filter_findstr(&expanded_refs, effective_input);
            }
            filter_findstr(&rest_args, effective_input)
        }
        "find" => filter_find(&rest_args, input),
        "type" => {
            // type FILE — pull from modified_filesystem or input_bytes
            let path = rest_args.first().copied().unwrap_or("");
            type_file(path, env)
        }
        "assoc" => synth_assoc(&rest_args, env),
        "ftype" => synth_ftype(&rest_args, env),
        "reg" => synth_reg(&rest_args, env),
        "dir" => synth_dir(&rest_args, env),
        "whoami" => synth_whoami(env),
        "chcp" => synth_chcp(&rest_args),
        "query" => synth_query(&rest_args),
        "vol" => synth_vol(&rest_args),
        "tzutil" => synth_tzutil(&rest_args),
        "sc" => synth_sc(&rest_args),
        "netsh" => synth_netsh(&rest_args),
        "net" => synth_net(&rest_args),
        "schtasks" => synth_schtasks(&rest_args),
        "wevtutil" => synth_wevtutil(&rest_args),
        "ver" => synth_ver(),
        "ipconfig" => synth_ipconfig(),
        "systeminfo" => synth_systeminfo(env),
        "getmac" => synth_getmac(),
        "fsutil" => synth_fsutil(&rest_args),
        "powershell" | "powershell.exe" => synth_powershell(&rest_args, env),
        "tasklist" => synth_tasklist(&rest_args),
        "where" => synth_where(&rest_args, env),
        "wmic" => synth_wmic(&rest_args),
        "ping" => synth_ping(&rest_args),
        "curl" | "curl.exe" => {
            let out = synth_curl(&rest_args);
            if out.is_empty() {
                env.traits.push(crate::traits::Trait::ForUnresolvedSource {
                    pipeline: stage.to_string(),
                });
            }
            out
        }
        _ => {
            env.traits.push(crate::traits::Trait::ForUnresolvedSource {
                pipeline: stage.to_string(),
            });
            Vec::new()
        }
    }
}

fn normalize_stage_prefix(stage: &str) -> &str {
    let mut s = stage.trim_start_matches(|c: char| {
        c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
    });
    loop {
        let Some(rest) = strip_leading_redirection(s) else {
            return s;
        };
        s = rest.trim_start_matches(|c: char| {
            c == '@' || c == '(' || c == ';' || c == ',' || c.is_whitespace()
        });
    }
}

fn strip_leading_redirection(s: &str) -> Option<&str> {
    let mut chars = s.char_indices().peekable();
    while matches!(chars.peek(), Some((_, c)) if c.is_ascii_digit()) {
        chars.next();
    }
    let op_start = chars.peek().map(|(idx, _)| *idx).unwrap_or(s.len());
    let op = s[op_start..].chars().next()?;
    if op != '>' && op != '<' {
        return None;
    }
    let mut after_op = op_start + op.len_utf8();
    if op == '>' && s[after_op..].starts_with('>') {
        after_op += 1;
    }
    let mut rest = s[after_op..].trim_start();
    if rest.starts_with('&') {
        rest = rest[1..].trim_start();
    }
    if let Some(quoted) = rest.strip_prefix('"') {
        for (idx, c) in quoted.char_indices() {
            if c == '"' {
                return Some(&rest[idx + 2..]);
            }
        }
        return Some("");
    }
    for (idx, c) in rest.char_indices() {
        if c.is_whitespace() || c == '<' || c == '>' || c == '&' || c == '|' {
            return Some(&rest[idx..]);
        }
    }
    Some("")
}

fn stage_command(stage: &str) -> Option<String> {
    split_stage_command(normalize_stage_prefix(stage)).map(|(part, _)| synth_command_key(part))
}

fn split_stage_command(stage: &str) -> Option<(&str, &str)> {
    let mut in_dq = false;
    let mut in_sq = false;
    let mut in_percent = false;
    for (idx, c) in stage.char_indices() {
        if c == '"' && !in_sq && !in_percent {
            in_dq = !in_dq;
            continue;
        }
        if c == '\'' && !in_dq && !in_percent {
            in_sq = !in_sq;
            continue;
        }
        if c == '%' && !in_dq && !in_sq {
            in_percent = !in_percent;
            continue;
        }
        if c.is_whitespace() && !in_dq && !in_sq && !in_percent {
            let cmd = &stage[..idx];
            let rest = stage[idx..].trim_start();
            return (!cmd.is_empty()).then_some((cmd, rest));
        }
    }
    (!stage.is_empty()).then_some((stage, ""))
}

fn synth_command_key(token: &str) -> String {
    synth_command_key_inner(token, None)
}

fn synth_command_key_with_env(token: &str, env: &Environment) -> String {
    synth_command_key_inner(token, Some(env))
}

fn synth_command_key_inner(token: &str, env: Option<&Environment>) -> String {
    let token = token.trim_matches('"');
    let key = token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .to_ascii_lowercase();
    if is_supported_command(&key) {
        return key;
    }
    if let Some(env) = env {
        if let Some(expanded) = expand_percent_vars_for_command_key(&key, env) {
            if is_supported_command(&expanded) {
                return expanded;
            }
        }
    }
    let skeleton: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();
    if !skeleton.is_empty() && is_supported_command(&skeleton) {
        return skeleton;
    }
    if is_type_with_one_missing_char(&skeleton) {
        return "type".to_string();
    }
    if !key.contains('%') && key.is_ascii() {
        return key;
    }
    key
}

fn is_type_with_one_missing_char(s: &str) -> bool {
    matches!(s, "typ" | "tye" | "tpe" | "ype" | "te")
}

fn expand_percent_vars_for_command_key(key: &str, env: &Environment) -> Option<String> {
    if !key.contains('%') {
        return None;
    }
    let chars: Vec<char> = key.chars().collect();
    let mut out = String::with_capacity(key.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '%' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let mut end = i + 1;
        while end < chars.len() && chars[end] != '%' {
            end += 1;
        }
        if end >= chars.len() || end == i + 1 {
            return None;
        }
        let name: String = chars[i + 1..end].iter().collect();
        if name.contains(['%', ':', '!', '^', '&', '|', '<', '>', '"', '\'']) {
            return None;
        }
        if let Some(value) = env.get(&name) {
            out.push_str(&value.to_ascii_lowercase());
        }
        i = end + 1;
    }
    (!out.is_empty()).then_some(out)
}

fn is_supported_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "set"
            | "findstr"
            | "find"
            | "type"
            | "assoc"
            | "ftype"
            | "reg"
            | "dir"
            | "whoami"
            | "chcp"
            | "query"
            | "vol"
            | "tzutil"
            | "sc"
            | "netsh"
            | "net"
            | "schtasks"
            | "wevtutil"
            | "ver"
            | "ipconfig"
            | "systeminfo"
            | "getmac"
            | "fsutil"
            | "powershell"
            | "powershell.exe"
            | "tasklist"
            | "where"
            | "wmic"
            | "ping"
            | "curl"
            | "curl.exe"
    )
}

/// Restore the canonical Windows casing of a well-known env var name so
/// the synthesized `set` output looks like real CMD's. Required for the
/// FE DOSfuscation `set^|findstr PSM` / `assoc^|findstr lMo` /
/// `ftype^|findstr lCo` FOR /F gadgets — `findstr` is case-sensitive and
/// each gadget's literal anchor is the canonical mixed-case substring.
/// Returns the input unchanged when no canonical form is known.
fn canonical_env_name(lower: &str) -> String {
    match lower {
        "allusersprofile" => "ALLUSERSPROFILE".into(),
        "appdata" => "APPDATA".into(),
        "commonprogramfiles" => "CommonProgramFiles".into(),
        "commonprogramfiles(x86)" => "CommonProgramFiles(x86)".into(),
        "commonprogramw6432" => "CommonProgramW6432".into(),
        "computername" => "COMPUTERNAME".into(),
        "comspec" => "ComSpec".into(),
        "driverdata" => "DriverData".into(),
        "homedrive" => "HOMEDRIVE".into(),
        "homepath" => "HOMEPATH".into(),
        "localappdata" => "LOCALAPPDATA".into(),
        "logonserver" => "LOGONSERVER".into(),
        "number_of_processors" => "NUMBER_OF_PROCESSORS".into(),
        "onedrive" => "OneDrive".into(),
        "os" => "OS".into(),
        "path" => "Path".into(),
        "pathext" => "PATHEXT".into(),
        "processor_architecture" => "PROCESSOR_ARCHITECTURE".into(),
        "processor_identifier" => "PROCESSOR_IDENTIFIER".into(),
        "processor_level" => "PROCESSOR_LEVEL".into(),
        "processor_revision" => "PROCESSOR_REVISION".into(),
        "programdata" => "ProgramData".into(),
        "programfiles" => "ProgramFiles".into(),
        "programfiles(x86)" => "ProgramFiles(x86)".into(),
        "programw6432" => "ProgramW6432".into(),
        "psmodulepath" => "PSModulePath".into(),
        "public" => "PUBLIC".into(),
        "systemdrive" => "SystemDrive".into(),
        "systemroot" => "SystemRoot".into(),
        "temp" => "TEMP".into(),
        "tmp" => "TMP".into(),
        "userdomain" => "USERDOMAIN".into(),
        "userdomain_roamingprofile" => "USERDOMAIN_ROAMINGPROFILE".into(),
        "username" => "USERNAME".into(),
        "userprofile" => "USERPROFILE".into(),
        "windir" => "windir".into(),
        _ => lower.to_string(),
    }
}

fn filter_findstr(args: &[&str], input: Vec<String>) -> Vec<String> {
    let mut patterns: Vec<String> = Vec::new();
    let mut case_insensitive = false;
    let mut invert = false;
    let mut regex_mode = false;
    let mut i = 0;
    // If the last arg looks like a file path (was consumed as the file source in run_stage),
    // exclude it from pattern/flag parsing.
    let skip_last = args
        .last()
        .map(|a| {
            let trimmed = a.trim_matches('"');
            let lc = trimmed.to_ascii_lowercase();
            trimmed.contains('\\')
                || trimmed.contains('/')
                || lc.ends_with(".bat")
                || lc.ends_with(".cmd")
        })
        .unwrap_or(false);
    let limit = if skip_last {
        args.len().saturating_sub(1)
    } else {
        args.len()
    };
    while i < limit {
        let a = args[i];
        if let Some(flags_and_maybe_literal) = a.strip_prefix('/') {
            // Handle /C:"literal" (flag and literal may be glued: /C:"lit")
            let flags_upper = flags_and_maybe_literal.to_ascii_uppercase();
            if flags_upper.starts_with('C') {
                let after_c = &flags_and_maybe_literal[1..];
                let literal = if let Some(after_colon) = after_c.strip_prefix(':') {
                    // /C:literal or /C:"literal"
                    after_colon.trim_matches('"').to_string()
                } else if after_c.is_empty() {
                    // /C as separate flag — next arg is the literal
                    if i + 1 < limit {
                        if let Some(next) = args.get(i + 1) {
                            i += 1;
                            next.trim_matches('"').to_string()
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    after_c.trim_matches('"').to_string()
                };
                if !literal.is_empty() {
                    patterns.push(literal);
                }
            } else {
                for f in flags_and_maybe_literal.chars() {
                    match f.to_ascii_lowercase() {
                        'i' => case_insensitive = true,
                        'v' => invert = true,
                        'r' => regex_mode = true,
                        _ => {}
                    }
                }
            }
        } else {
            patterns.push(a.trim_matches('"').to_string());
        }
        i += 1;
    }
    // Auto-enable regex mode for ^anchor / $end / [class] patterns even when
    // /R wasn't explicitly passed. Many real scripts omit /R but use anchors.
    if !regex_mode
        && patterns
            .iter()
            .any(|p| p.starts_with('^') || p.ends_with('$') || p.contains('['))
    {
        regex_mode = true;
    }
    if regex_mode {
        // Compile each pattern as a regex; prefix (?i) when case-insensitive.
        let compiled: Vec<regex::Regex> = patterns
            .iter()
            .filter_map(|p| {
                let pat = if case_insensitive {
                    format!("(?i){p}")
                } else {
                    p.clone()
                };
                regex::Regex::new(&pat).ok()
            })
            .collect();
        return input
            .into_iter()
            .filter(|line| {
                let hit = if compiled.is_empty() {
                    true
                } else {
                    compiled.iter().any(|re| re.is_match(line))
                };
                if invert {
                    !hit
                } else {
                    hit
                }
            })
            .collect();
    }
    input
        .into_iter()
        .filter(|line| {
            let l = if case_insensitive {
                line.to_ascii_lowercase()
            } else {
                line.clone()
            };
            let hit = if patterns.is_empty() {
                true
            } else {
                patterns.iter().any(|p| {
                    let pat = if case_insensitive {
                        p.to_ascii_lowercase()
                    } else {
                        p.clone()
                    };
                    l.contains(pat.as_str())
                })
            };
            if invert {
                !hit
            } else {
                hit
            }
        })
        .collect()
}

fn filter_find(args: &[&str], input: Vec<String>) -> Vec<String> {
    // find "literal"  — supports /i and /v
    let mut case_insensitive = false;
    let mut invert = false;
    let mut pattern = String::new();
    for a in args {
        if let Some(flags) = a.strip_prefix('/') {
            for f in flags.chars() {
                match f.to_ascii_lowercase() {
                    'i' => case_insensitive = true,
                    'v' => invert = true,
                    _ => {}
                }
            }
        } else {
            pattern = a.trim_matches('"').to_string();
        }
    }
    if pattern.is_empty() {
        return input;
    }
    let p = if case_insensitive {
        pattern.to_ascii_lowercase()
    } else {
        pattern
    };
    input
        .into_iter()
        .filter(|line| {
            let l = if case_insensitive {
                line.to_ascii_lowercase()
            } else {
                line.clone()
            };
            let hit = l.contains(&p);
            if invert {
                !hit
            } else {
                hit
            }
        })
        .collect()
}

fn type_file(path: &str, env: &mut Environment) -> Vec<String> {
    use crate::env::FsEntry;

    let path = path.trim_matches('"');

    // %~f0 / explicit input path → read input bytes
    let is_self = path.contains("script.bat")
        || env
            .file_path
            .as_deref()
            .map(|p| p.to_string_lossy() == path)
            .unwrap_or(false);

    if is_self {
        if let Some(bytes) = &env.input_bytes {
            let bytes = bytes.clone();
            let text = String::from_utf8_lossy(&bytes);
            env.traits.push(crate::traits::Trait::SelfExtract {
                method: "type".into(),
            });
            return text
                .split_inclusive('\n')
                .map(|l| l.trim_end_matches(['\r', '\n']).to_string())
                .collect();
        }
    }

    let key = path.to_ascii_lowercase();
    match env.modified_filesystem.get(&key) {
        Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
            let content = content.clone();
            String::from_utf8_lossy(&content)
                .split_inclusive('\n')
                .map(|l| l.trim_end_matches(['\r', '\n']).to_string())
                .collect()
        }
        Some(FsEntry::Download { src }) => synth_downloaded_file_lines(src),
        _ => Vec::new(),
    }
}

fn synth_downloaded_file_lines(src: &str) -> Vec<String> {
    let lower = src.to_ascii_lowercase();
    if lower.contains("ip-api.com/csv") {
        return vec![
            "success,Exampleland,EX,CA,ExampleState,Metropolis,00000,0,0,UTC,ExampleISP,ExampleOrg,AS64500,203.0.113.10"
                .to_string(),
        ];
    }
    Vec::new()
}

fn synth_assoc(args: &[&str], env: &Environment) -> Vec<String> {
    // Prefer the loaded snapshot for the configured winver.
    if let Some(snap) = crate::snapshot::get(env.winver) {
        let filter = args.first().copied().unwrap_or("");
        return snap
            .assoc
            .iter()
            .filter(|(ext, _)| filter.is_empty() || ext.eq_ignore_ascii_case(filter))
            .map(|(ext, progid)| format!("{}={}", ext, progid))
            .collect();
    }
    // Fallback: hardcoded table.
    let table: &[(&str, &str)] = &[
        (".bat", "batfile"),
        (".cmd", "cmdfile"),
        (".com", "comfile"),
        (".exe", "exefile"),
        (".dll", "dllfile"),
        (".vbs", "VBSFile"),
        (".vbe", "VBEFile"),
        (".js", "JSFile"),
        (".jse", "JSEFile"),
        (".wsf", "WSFFile"),
        (".wsh", "WSHFile"),
        (".ps1", "Microsoft.PowerShellScript.1"),
        (".reg", "regfile"),
        (".lnk", "lnkfile"),
        (".hta", "htafile"),
        (".inf", "inffile"),
        (".chm", "chm.file"),
        (".scr", "scrfile"),
        (".pif", "piffile"),
        (".msi", "Msi.Package"),
        (".msp", "Msi.Patch"),
        (".txt", "txtfilelegacy"),
        (".xml", "xmlfile"),
        (".zip", "CompressedFolder"),
    ];
    let filter = args.first().copied().unwrap_or("");
    table
        .iter()
        .filter(|(ext, _)| filter.is_empty() || ext.eq_ignore_ascii_case(filter))
        .map(|(ext, progid)| format!("{}={}", ext, progid))
        .collect()
}

fn synth_reg(args: &[&str], env: &mut Environment) -> Vec<String> {
    // Only handle `reg query`; all other subcommands fall through as empty.
    if args.first().map(|s| s.eq_ignore_ascii_case("query")) != Some(true) {
        return Vec::new();
    }
    let mut iter = args.iter().skip(1);
    let key = iter
        .next()
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_default();
    let mut value: Option<String> = None;
    let mut prev_was_v = false;
    for a in args.iter().skip(2) {
        if prev_was_v {
            value = Some(a.trim_matches('"').to_string());
            prev_was_v = false;
            continue;
        }
        if a.eq_ignore_ascii_case("/v") {
            prev_was_v = true;
        }
    }
    env.traits
        .push(crate::traits::Trait::RegQuery { key, value });
    Vec::new()
}

fn synth_dir(args: &[&str], env: &mut Environment) -> Vec<String> {
    let mut flags: Vec<String> = Vec::new();
    let mut path: String = String::new();
    for a in args {
        if a.starts_with('/') {
            flags.push(a.to_string());
        } else if path.is_empty() {
            path = a.trim_matches('"').to_string();
        }
    }
    env.traits
        .push(crate::traits::Trait::DirListing { path, flags });
    Vec::new()
}

fn synth_ftype(args: &[&str], env: &Environment) -> Vec<String> {
    // Prefer the loaded snapshot for the configured winver.
    if let Some(snap) = crate::snapshot::get(env.winver) {
        let filter = args.first().copied().unwrap_or("");
        return snap
            .ftype
            .iter()
            .filter(|(p, _)| filter.is_empty() || p.eq_ignore_ascii_case(filter))
            .map(|(p, t)| format!("{}={}", p, t))
            .collect();
    }
    // Fallback: hardcoded table.
    let table: &[(&str, &str)] = &[
        ("batfile", r#""%1" %*"#),
        ("cmdfile", r#""%1" %*"#),
        ("comfile", r#""%1" %*"#),
        ("exefile", r#""%1" %*"#),
        ("VBSFile", r#""C:\Windows\System32\WScript.exe" "%1" %*"#),
        ("VBEFile", r#""C:\Windows\System32\WScript.exe" "%1" %*"#),
        ("JSFile", r#""C:\Windows\System32\WScript.exe" "%1" %*"#),
        ("JSEFile", r#""C:\Windows\System32\WScript.exe" "%1" %*"#),
        ("WSFFile", r#""C:\Windows\System32\WScript.exe" "%1" %*"#),
        (
            "Microsoft.PowerShellScript.1",
            r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "%1""#,
        ),
        ("regfile", r#"regedit.exe "%1""#),
        ("htafile", r#"C:\Windows\SysWOW64\mshta.exe "%1" %*"#),
        (
            "Msi.Package",
            r#"%SystemRoot%\System32\msiexec.exe /i "%1" %*"#,
        ),
        (
            "Msi.Patch",
            r#"%SystemRoot%\System32\msiexec.exe /p "%1" %*"#,
        ),
        ("scrfile", r#""%1" /S"#),
        ("piffile", r#""%1" %*"#),
        ("lnkfile", r#""%1""#),
        ("chm.file", r#"%SystemRoot%\hh.exe "%1""#),
        (
            "inffile",
            r#"%SystemRoot%\System32\rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 %1"#,
        ),
        ("xmlfile", r#"C:\Windows\System32\mshta.exe "%1""#),
    ];
    let filter = args.first().copied().unwrap_or("");
    table
        .iter()
        .filter(|(p, _)| filter.is_empty() || p.eq_ignore_ascii_case(filter))
        .map(|(p, t)| format!("{}={}", p, t))
        .collect()
}

fn synth_whoami(env: &Environment) -> Vec<String> {
    let domain = env
        .get("userdomain")
        .unwrap_or_else(|| "miscreanttears".to_string());
    let user = env.get("username").unwrap_or_else(|| "puncher".to_string());
    vec![format!(
        "{}\\{}",
        domain.to_ascii_lowercase(),
        user.to_ascii_lowercase()
    )]
}

fn synth_chcp(args: &[&str]) -> Vec<String> {
    let page = args.first().copied().unwrap_or("437");
    vec![format!("Active code page: {}", page)]
}

fn synth_query(args: &[&str]) -> Vec<String> {
    let sub = args.first().copied().unwrap_or("").to_ascii_lowercase();
    match sub.as_str() {
        "session" => vec![
            " SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE"
                .to_string(),
            ">console           puncher                   1  Active".to_string(),
        ],
        "user" => vec![
            " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME"
                .to_string(),
            ">puncher               console             1  Active      none   1/1/2026 12:00 AM"
                .to_string(),
        ],
        _ => Vec::new(),
    }
}

fn non_redirect_args<'a>(args: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
    args.iter()
        .copied()
        .filter(|arg| !arg.contains('>') && !arg.contains('<'))
}

fn synth_vol(args: &[&str]) -> Vec<String> {
    let drive = non_redirect_args(args)
        .next()
        .unwrap_or("C:")
        .trim_matches('"');
    vec![
        format!(" Volume in drive {drive} is Windows"),
        " Volume Serial Number is 1234-ABCD".to_string(),
    ]
}

fn synth_tzutil(args: &[&str]) -> Vec<String> {
    if non_redirect_args(args).any(|arg| arg.eq_ignore_ascii_case("/g")) {
        return vec!["Central Standard Time".to_string()];
    }
    Vec::new()
}

fn synth_sc(args: &[&str]) -> Vec<String> {
    let mut iter = non_redirect_args(args);
    let Some(action) = iter.next() else {
        return Vec::new();
    };
    if !action.eq_ignore_ascii_case("query") {
        return Vec::new();
    }
    let service = iter.next().unwrap_or("WinDefend").trim_matches('"');
    vec![
        format!("SERVICE_NAME: {service}"),
        "        TYPE               : 10  WIN32_OWN_PROCESS".to_string(),
        "        STATE              : 4  RUNNING".to_string(),
    ]
}

fn synth_netsh(args: &[&str]) -> Vec<String> {
    let args: Vec<String> = non_redirect_args(args)
        .map(str::to_ascii_lowercase)
        .collect();
    if args.len() >= 4 && args[0] == "advfirewall" && args[1] == "show" && args[3] == "state" {
        return vec!["State                                 ON".to_string()];
    }
    Vec::new()
}

fn synth_net(args: &[&str]) -> Vec<String> {
    let args: Vec<&str> = non_redirect_args(args).collect();
    if args.len() >= 2 && args[0].eq_ignore_ascii_case("localgroup") {
        let group = args[1].trim_matches('"');
        return vec![
            format!("Alias name     {group}"),
            "Comment        Administrators have complete and unrestricted access".to_string(),
            String::new(),
            "Members".to_string(),
            "-------------------------------------------------------------------------------"
                .to_string(),
            "Administrator".to_string(),
            "The command completed successfully.".to_string(),
        ];
    }
    Vec::new()
}

fn synth_schtasks(args: &[&str]) -> Vec<String> {
    let args: Vec<&str> = non_redirect_args(args).collect();
    if !args.iter().any(|arg| arg.eq_ignore_ascii_case("/query")) {
        return Vec::new();
    }
    let mut task_name = "\\Updater".to_string();
    for pair in args.windows(2) {
        if pair[0].eq_ignore_ascii_case("/tn") {
            task_name = format!(r"\{}", pair[1].trim_matches('"').trim_start_matches('\\'));
            break;
        }
    }
    vec![
        format!("TaskName: {task_name}"),
        "Status: Ready".to_string(),
    ]
}

fn synth_wevtutil(args: &[&str]) -> Vec<String> {
    let mut iter = non_redirect_args(args);
    let Some(action) = iter.next() else {
        return Vec::new();
    };
    if !action.eq_ignore_ascii_case("qe") {
        return Vec::new();
    }
    let log = iter.next().unwrap_or("System").trim_matches('"');
    vec![
        "Event[0]:".to_string(),
        format!("  Log Name: {log}"),
        "  Level: Error".to_string(),
    ]
}

fn synth_ver() -> Vec<String> {
    vec!["Microsoft Windows [Version 10.0.19045.4046]".to_string()]
}

fn synth_ipconfig() -> Vec<String> {
    vec![
        String::new(),
        "Windows IP Configuration".to_string(),
        String::new(),
        "Ethernet adapter Ethernet:".to_string(),
        "   Connection-specific DNS Suffix  . : local".to_string(),
        "   IPv4 Address. . . . . . . . . . . : 192.0.2.10".to_string(),
        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0".to_string(),
        "   Default Gateway . . . . . . . . . : 192.0.2.1".to_string(),
    ]
}

fn synth_systeminfo(env: &Environment) -> Vec<String> {
    let username = env.get("USERNAME").unwrap_or_else(|| "User".to_string());
    let computername = env
        .get("COMPUTERNAME")
        .unwrap_or_else(|| "DESKTOP-EXAMPLE".to_string());
    vec![
        format!("Host Name:                 {computername}"),
        "OS Name:                   Microsoft Windows 10 Pro".to_string(),
        "OS Version:                10.0.19045 N/A Build 19045".to_string(),
        "System Manufacturer:       Example Manufacturer".to_string(),
        "System Model:              Virtual Machine".to_string(),
        format!("Registered Owner:          {username}"),
        "System Type:               x64-based PC".to_string(),
    ]
}

fn synth_getmac() -> Vec<String> {
    vec![
        "Physical Address    Transport Name".to_string(),
        "=================== =========================================================="
            .to_string(),
        "00-11-22-33-44-55   \\Device\\Tcpip_{00000000-0000-0000-0000-000000000000}".to_string(),
    ]
}

fn synth_powershell(args: &[&str], env: &Environment) -> Vec<String> {
    let command = args.join(" ");
    let lower = command.to_ascii_lowercase();
    if lower.contains("[system.net.dns]::gethostname()") {
        return vec![env
            .get("COMPUTERNAME")
            .unwrap_or_else(|| "DESKTOP-EXAMPLE".to_string())];
    }
    if lower.contains("get-date") && lower.contains("uformat") {
        return vec!["120000".to_string()];
    }
    if lower.contains("get-ciminstance")
        && lower.contains("securitycenter")
        && lower.contains("antivirusproduct")
        && lower.contains("displayname")
    {
        return vec!["Microsoft Defender Antivirus".to_string()];
    }
    Vec::new()
}

fn synth_fsutil(args: &[&str]) -> Vec<String> {
    if args.len() >= 3
        && args[0].eq_ignore_ascii_case("dirty")
        && args[1].eq_ignore_ascii_case("query")
    {
        let drive = args[2].trim_matches('"');
        return vec![format!("Volume - {drive} is NOT Dirty")];
    }
    Vec::new()
}

fn synth_tasklist(_args: &[&str]) -> Vec<String> {
    vec![
        "Image Name                     PID Session Name        Session#    Mem Usage".to_string(),
        "========================= ======== ================ =========== ============".to_string(),
        "System Idle Process              0 Services                   0          8 K".to_string(),
        "System                           4 Services                   0      1,234 K".to_string(),
        "explorer.exe                  1234 Console                    1     45,678 K".to_string(),
    ]
}

fn synth_where(args: &[&str], env: &Environment) -> Vec<String> {
    let bin = match args.first() {
        Some(b) => b.trim_matches('"').to_ascii_lowercase(),
        None => return Vec::new(),
    };
    if let Some(snap) = crate::snapshot::get(env.winver) {
        if let Some(path) = snap.r#where.get(&bin) {
            if !path.is_empty() {
                return vec![path.clone()];
            }
        }
    }
    Vec::new()
}

fn synth_wmic(args: &[&str]) -> Vec<String> {
    let filtered: Vec<String> = non_redirect_args(args)
        .map(|arg| arg.trim_matches('"').to_ascii_lowercase())
        .collect();
    let joined = filtered.join(" ");
    if filtered
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("logicaldisk"))
        && joined.contains("get size")
    {
        return vec!["Size".to_string(), "250954240000".to_string()];
    }
    if filtered
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("computersystem"))
        && joined.contains("manufacturer")
    {
        if joined.contains("/value") {
            return vec!["Manufacturer=Microsoft Corporation".to_string()];
        }
        return vec![
            "Manufacturer".to_string(),
            "Microsoft Corporation".to_string(),
        ];
    }
    if filtered
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("group"))
        && joined.contains("get name")
    {
        if joined.contains("/value") {
            return vec!["Name=Administrators".to_string()];
        }
        return vec!["Name".to_string(), "Administrators".to_string()];
    }
    Vec::new()
}

fn synth_ping(args: &[&str]) -> Vec<String> {
    let mut target = None;
    let mut skip_next = false;
    for arg in args {
        let arg = arg.trim_matches('"');
        if arg.is_empty() {
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with(['-', '/']) {
            let option = arg
                .trim_start_matches(['-', '/'])
                .chars()
                .next()
                .map(|c| c.to_ascii_lowercase());
            if matches!(
                option,
                Some('n' | 'l' | 'w' | 'i' | 'v' | 'r' | 's' | 'j' | 'k' | '4' | '6')
            ) {
                skip_next = !matches!(option, Some('4' | '6'));
            }
            continue;
        }
        target = Some(arg);
    }
    let Some(target) = target else {
        return Vec::new();
    };
    vec![format!(
        "Pinging {target} [{target}] with 32 bytes of data:"
    )]
}

fn synth_curl(args: &[&str]) -> Vec<String> {
    let Some(url) = args
        .iter()
        .rev()
        .map(|arg| arg.trim_matches(['"', '\'']))
        .find(|arg| arg.starts_with("http://") || arg.starts_with("https://"))
    else {
        return Vec::new();
    };
    let lower = url.to_ascii_lowercase();
    if lower == "https://api.ipify.org"
        || lower == "http://api.ipify.org"
        || lower.starts_with("https://api.ipify.org?")
        || lower.starts_with("http://api.ipify.org?")
    {
        return vec!["203.0.113.10".to_string()];
    }
    if lower == "http://www.geoplugin.net/php.gp?ip"
        || lower == "https://www.geoplugin.net/php.gp?ip"
    {
        return vec!["geoplugin_request:203.0.113.10".to_string()];
    }
    Vec::new()
}
