//! Synthetic command-pipeline emulator. Models the output of selected
//! cmd.exe commands against the live Environment so `for /F ('…')` and
//! `findstr "%~f0"` style gadgets can resolve without an actual shell.

use crate::env::Environment;
use crate::handlers::util::{
    normalize_filesystem_storage_path, normalize_wildcard_path, wildcard_match,
};
use crate::util::contains_ascii_case_insensitive;
use crate::util::starts_with_ascii_case_insensitive;

type SynthFileInput = (String, Vec<String>);

pub fn run_pipeline(pipeline: &str, env: &mut Environment) -> Vec<String> {
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

pub fn can_run_pipeline(pipeline: &str) -> bool {
    let stages = split_pipeline(pipeline);
    !stages.is_empty()
        && stages
            .iter()
            .all(|stage| stage_command(stage).is_some_and(is_supported_command))
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
    let (redir_cleaned, redirs) = crate::redirect::extract_redirections(stage);
    let input = if input.is_empty() {
        redirs
            .stdin
            .as_deref()
            .map(|path| type_file(path, env))
            .unwrap_or(input)
    } else {
        input
    };
    let stage = normalize_stage_prefix(&redir_cleaned);
    if let Some(lines) = synth_echo_stage(stage) {
        return lines;
    }
    let Some(cmd) = stage_command(stage) else {
        return Vec::new();
    };
    let mut parts = stage.split_whitespace();
    let _ = parts.next();
    let rest_args: Vec<&str> = parts.collect();
    match cmd.as_str() {
        "set" => {
            let prefix = rest_args.first().copied().unwrap_or("");
            let mut lines: Vec<(String, String)> = env
                .vars_iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            lines.sort_by_cached_key(|(k, _)| k.to_ascii_lowercase());
            lines
                .into_iter()
                .filter(|(k, _)| prefix.is_empty() || starts_with_ascii_case_insensitive(k, prefix))
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
        "cmd" | "cmd.exe" => synth_cmd(rest_after_command(stage), input, env),
        "findstr" => synth_findstr(&rest_args, input, env),
        "find" => synth_find(&rest_args, input, env),
        "more" => synth_more(stage, &rest_args, input, env),
        "sort" => synth_sort(stage, &rest_args, input, env),
        "type" => synth_type(&rest_args, input, env),
        "assoc" => synth_assoc(&rest_args, env),
        "ftype" => synth_ftype(&rest_args, env),
        "reg" => synth_reg(&rest_args, env),
        "dir" => synth_dir(&rest_args, env),
        "whoami" => synth_whoami(&rest_args, env),
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
        "date" => synth_date(&rest_args),
        "time" => synth_time(&rest_args),
        "ipconfig" => synth_ipconfig(),
        "hostname" => synth_hostname(env),
        "systeminfo" => synth_systeminfo(env),
        "getmac" => synth_getmac(),
        "fsutil" => synth_fsutil(&rest_args),
        "wmic" => synth_wmic(&rest_args),
        "ping" => synth_ping(&rest_args),
        "powershell" | "powershell.exe" => synth_powershell(&rest_args, env),
        "echo" => synth_echo_stage(stage).unwrap_or_default(),
        "tasklist" => synth_tasklist(&rest_args),
        "where" => synth_where(&rest_args, env),
        "curl" | "curl.exe" => {
            let out = synth_curl(&rest_args, env);
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
    stage.trim_start_matches(|c: char| c == '@' || c == ';' || c.is_whitespace())
}

fn rest_after_command(stage: &str) -> &str {
    let stage = normalize_stage_prefix(stage);
    stage
        .split_whitespace()
        .next()
        .map(|cmd| stage[cmd.len()..].trim_start())
        .unwrap_or("")
}

fn stage_command(stage: &str) -> Option<String> {
    let cleaned;
    let stage = if stage.contains('<') || stage.contains('>') {
        cleaned = crate::redirect::extract_redirections(stage).0;
        cleaned.as_str()
    } else {
        stage
    };
    normalize_stage_prefix(stage)
        .split_whitespace()
        .next()
        .map(normalize_command_token)
}

fn is_supported_command(cmd: String) -> bool {
    matches!(
        cmd.as_str(),
        "set"
            | "cmd"
            | "cmd.exe"
            | "findstr"
            | "find"
            | "more"
            | "sort"
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
            | "date"
            | "time"
            | "ipconfig"
            | "hostname"
            | "systeminfo"
            | "getmac"
            | "fsutil"
            | "wmic"
            | "ping"
            | "powershell"
            | "powershell.exe"
            | "echo"
            | "tasklist"
            | "where"
            | "curl"
            | "curl.exe"
    )
}

fn normalize_command_token(token: &str) -> String {
    let trimmed = token.trim_matches('"');
    let basename = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    if echo_payload_after_command(basename).is_some() {
        return "echo".to_string();
    }
    let key = basename.to_ascii_lowercase();
    let skeleton: String = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '.')
        .collect();
    if is_type_with_missing_noise(&skeleton) {
        return "type".to_string();
    }
    key
}

fn synth_echo_stage(stage: &str) -> Option<Vec<String>> {
    echo_payload_after_command(stage).map(|payload| vec![payload.to_string()])
}

fn echo_payload_after_command(command: &str) -> Option<&str> {
    let command = normalize_stage_prefix(command);
    let rest = command.get(4..)?;
    if !command[..4].eq_ignore_ascii_case("echo") {
        return None;
    }
    match rest.chars().next() {
        None => Some(""),
        Some(ch) if ch.is_whitespace() => Some(rest.trim_start()),
        Some('.') | Some(':') | Some('/') | Some('(') => Some(rest[1..].trim_start()),
        _ => None,
    }
}

fn is_type_with_missing_noise(token: &str) -> bool {
    matches!(token, "typ" | "tye" | "tpe" | "ype" | "te")
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
        "windir" => "WINDIR".into(),
        _ => lower.to_string(),
    }
}

fn filter_findstr(args: &[&str], input: Vec<String>) -> Vec<String> {
    let mut patterns: Vec<String> = Vec::new();
    let mut case_insensitive = false;
    let mut invert = false;
    let mut regex_mode = false;
    let mut literal_mode = false;
    let mut match_begin = false;
    let mut match_end = false;
    let mut match_exact = false;
    let mut line_numbers = false;
    let mut offsets = false;
    let mut i = 0;
    let limit = args.len();
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
                let flags_lower = flags_and_maybe_literal.to_ascii_lowercase();
                if !flags_lower.starts_with("off") {
                    for f in flags_lower.chars() {
                        match f {
                            'i' => case_insensitive = true,
                            'v' => invert = true,
                            'r' => {
                                regex_mode = true;
                                literal_mode = false;
                            }
                            'l' => literal_mode = true,
                            'b' => match_begin = true,
                            'e' => match_end = true,
                            'x' => match_exact = true,
                            'n' => line_numbers = true,
                            'o' => offsets = true,
                            _ => {}
                        }
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
        && !literal_mode
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
                let anchored = if match_exact {
                    format!("^(?:{p})$")
                } else if match_begin {
                    format!("^(?:{p})")
                } else if match_end {
                    format!("(?:{p})$")
                } else {
                    p.clone()
                };
                let pat = if case_insensitive {
                    format!("(?i){anchored}")
                } else {
                    anchored
                };
                regex::Regex::new(&pat).ok()
            })
            .collect();
        return input
            .into_iter()
            .enumerate()
            .filter(|line| {
                let line = &line.1;
                let hit = if compiled.is_empty() {
                    Some(0)
                } else {
                    compiled
                        .iter()
                        .find_map(|re| re.find(line).map(|match_| match_.start()))
                };
                if invert {
                    hit.is_none()
                } else {
                    hit.is_some()
                }
            })
            .map(|(idx, line)| {
                let offset = compiled
                    .iter()
                    .find_map(|re| re.find(&line).map(|match_| match_.start()));
                format_findstr_output_line(
                    line,
                    line_numbers.then_some(idx + 1),
                    offsets.then_some(offset.unwrap_or(0)),
                )
            })
            .collect();
    }
    input
        .into_iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let hit = if patterns.is_empty() {
                Some(0)
            } else {
                patterns.iter().find_map(|p| {
                    findstr_literal_match_offset(
                        &line,
                        p,
                        case_insensitive,
                        match_begin,
                        match_end,
                        match_exact,
                    )
                })
            };
            let include = if invert { hit.is_none() } else { hit.is_some() };
            include.then(|| {
                format_findstr_output_line(
                    line,
                    line_numbers.then_some(idx + 1),
                    offsets.then_some(hit.unwrap_or(0)),
                )
            })
        })
        .collect()
}

fn findstr_literal_match_offset(
    line: &str,
    pattern: &str,
    case_insensitive: bool,
    match_begin: bool,
    match_end: bool,
    match_exact: bool,
) -> Option<usize> {
    let line_cmp;
    let pattern_cmp;
    let (line, pattern) = if case_insensitive {
        line_cmp = line.to_ascii_lowercase();
        pattern_cmp = pattern.to_ascii_lowercase();
        (line_cmp.as_str(), pattern_cmp.as_str())
    } else {
        (line, pattern)
    };
    if match_exact {
        return (line == pattern).then_some(0);
    }
    if match_begin && match_end {
        return (line == pattern).then_some(0);
    }
    if match_begin {
        return line.starts_with(pattern).then_some(0);
    }
    if match_end {
        return line
            .ends_with(pattern)
            .then_some(line.len().saturating_sub(pattern.len()));
    }
    line.find(pattern)
}

fn format_findstr_output_line(
    line: String,
    line_number: Option<usize>,
    offset: Option<usize>,
) -> String {
    let mut out = String::new();
    if let Some(line_number) = line_number {
        out.push_str(&format!("{line_number}:"));
    }
    if let Some(offset) = offset {
        out.push_str(&format!("{offset}:"));
    }
    out.push_str(&line);
    out
}

fn format_find_output_line(line: String, line_number: Option<usize>) -> String {
    if let Some(line_number) = line_number {
        format!("[{line_number}]{line}")
    } else {
        line
    }
}

fn find_option_file_value(arg: &str, flag: char) -> Option<&str> {
    let flags = arg.strip_prefix('/')?;
    let mut chars = flags.chars();
    let first = chars.next()?;
    if !first.eq_ignore_ascii_case(&flag) {
        return None;
    }
    let rest = chars.as_str();
    if rest.is_empty() {
        None
    } else {
        rest.strip_prefix(':').or(Some(rest))
    }
}

fn expand_findstr_indirect_args(args: Vec<String>, env: &mut Environment) -> Vec<String> {
    let mut expanded = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].trim_matches('"');
        if arg.eq_ignore_ascii_case("/g") || arg.eq_ignore_ascii_case("/f") {
            if let Some(path) = args.get(i + 1) {
                let lines = type_file(path.trim_matches('"'), env);
                if lines.is_empty() {
                    expanded.push(args[i].clone());
                    expanded.push(path.clone());
                } else {
                    expanded.extend(lines);
                }
                i += 2;
                continue;
            }
        }
        if let Some(path) =
            find_option_file_value(arg, 'g').or_else(|| find_option_file_value(arg, 'f'))
        {
            let lines = type_file(path.trim_matches('"'), env);
            if lines.is_empty() {
                expanded.push(args[i].clone());
            } else {
                expanded.extend(lines);
            }
            i += 1;
            continue;
        }
        expanded.push(args[i].clone());
        i += 1;
    }
    expanded
}

fn filter_find(args: &[&str], input: Vec<String>) -> Vec<String> {
    // find "literal"  — supports /i, /v, and /n
    let mut case_insensitive = false;
    let mut invert = false;
    let mut line_numbers = false;
    let mut pattern = String::new();
    for a in args {
        if let Some(flags) = a.strip_prefix('/') {
            for f in flags.chars() {
                match f.to_ascii_lowercase() {
                    'i' => case_insensitive = true,
                    'v' => invert = true,
                    'n' => line_numbers = true,
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
    let p = pattern;
    input
        .into_iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            let hit = if case_insensitive {
                contains_ascii_case_insensitive(&line, &p)
            } else {
                line.contains(&p)
            };
            let include = if invert { !hit } else { hit };
            include.then(|| format_find_output_line(line, line_numbers.then_some(idx + 1)))
        })
        .collect()
}

fn synth_findstr(args: &[&str], input: Vec<String>, env: &mut Environment) -> Vec<String> {
    if !input.is_empty() {
        let expanded_args =
            expand_findstr_indirect_args(args.iter().map(|arg| (*arg).to_string()).collect(), env);
        let refs: Vec<&str> = expanded_args.iter().map(String::as_str).collect();
        return filter_findstr(&refs, input);
    }
    let expanded_args: Vec<String> = args
        .iter()
        .map(|arg| {
            let trimmed = arg.trim_matches('"');
            if trimmed.eq_ignore_ascii_case("%~f0") || trimmed.eq_ignore_ascii_case("%0") {
                "C:\\Users\\al\\Downloads\\script.bat".to_string()
            } else {
                (*arg).to_string()
            }
        })
        .collect();
    let expanded_args = expand_findstr_indirect_args(expanded_args, env);
    let Some((file_idxs, file_inputs)) = findstr_file_input_args(&expanded_args, env) else {
        let refs: Vec<&str> = expanded_args.iter().map(String::as_str).collect();
        return filter_findstr(&refs, Vec::new());
    };
    let filter_args: Vec<&str> = expanded_args
        .iter()
        .enumerate()
        .filter_map(|(idx, arg)| (!file_idxs.contains(&idx)).then_some(arg.as_str()))
        .collect();
    if findstr_outputs_matching_file_names(&expanded_args) {
        return file_inputs
            .into_iter()
            .filter_map(|(name, lines)| {
                (!filter_findstr(&filter_args, lines).is_empty()).then_some(name)
            })
            .collect();
    }
    let lines = file_inputs
        .into_iter()
        .flat_map(|(_, lines)| lines)
        .collect();
    filter_findstr(&filter_args, lines)
}

fn findstr_file_input_args(
    args: &[String],
    env: &mut Environment,
) -> Option<(Vec<usize>, Vec<SynthFileInput>)> {
    let mut file_idxs = Vec::new();
    let mut input = Vec::new();
    let recursive = findstr_searches_recursively(args);
    for (idx, arg) in args.iter().enumerate() {
        let candidate = arg.trim_matches('"');
        if candidate.is_empty() || candidate.starts_with('/') {
            continue;
        }
        let files = findstr_file_inputs_for_arg(candidate, env, recursive);
        if !files.is_empty() {
            file_idxs.push(idx);
            input.extend(files);
        }
    }
    (!file_idxs.is_empty()).then_some((file_idxs, input))
}

fn findstr_file_inputs_for_arg(
    candidate: &str,
    env: &mut Environment,
    recursive: bool,
) -> Vec<SynthFileInput> {
    if candidate.contains(['*', '?']) {
        let normalized_pattern =
            normalize_wildcard_path(&normalize_filesystem_storage_path(candidate));
        let tracked = env
            .modified_filesystem
            .keys()
            .filter(|path| {
                if recursive {
                    recursive_wildcard_matches(candidate, &normalized_pattern, path)
                } else {
                    dir_wildcard_matches(candidate, &normalized_pattern, path)
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        return tracked
            .into_iter()
            .filter_map(|path| {
                let lines = type_file(&path, env);
                (!lines.is_empty())
                    .then(|| (findstr_file_output_name(candidate, &path, recursive), lines))
            })
            .collect();
    }
    let lines = type_file(candidate, env);
    if lines.is_empty() {
        Vec::new()
    } else {
        vec![(candidate.to_string(), lines)]
    }
}

fn findstr_file_output_name(pattern: &str, tracked_path: &str, recursive: bool) -> String {
    if recursive || pattern.contains(['\\', '/', ':']) {
        tracked_path.to_string()
    } else {
        windows_basename(tracked_path)
            .unwrap_or(tracked_path)
            .to_string()
    }
}

fn recursive_wildcard_matches(pattern: &str, normalized_pattern: &str, tracked_path: &str) -> bool {
    let normalized_path = normalize_wildcard_path(tracked_path);
    if pattern.contains(['\\', '/', ':']) {
        let Some((pattern_dir, pattern_name)) = normalized_pattern.rsplit_once('\\') else {
            return wildcard_match(normalized_pattern, &normalized_path);
        };
        return path_is_under_root(&normalized_path, pattern_dir)
            && windows_basename(&normalized_path)
                .is_some_and(|name| wildcard_match(pattern_name, &normalize_wildcard_path(name)));
    }
    windows_basename(&normalized_path)
        .is_some_and(|name| wildcard_match(normalized_pattern, &normalize_wildcard_path(name)))
}

fn findstr_searches_recursively(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let flags = arg.strip_prefix('/').unwrap_or_default();
        !flags
            .chars()
            .next()
            .is_some_and(|c| c.eq_ignore_ascii_case(&'c'))
            && flags.chars().any(|c| c.eq_ignore_ascii_case(&'s'))
    })
}

fn findstr_outputs_matching_file_names(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let flags = arg.strip_prefix('/').unwrap_or_default();
        !flags
            .chars()
            .next()
            .is_some_and(|c| c.eq_ignore_ascii_case(&'c'))
            && flags.chars().any(|c| c.eq_ignore_ascii_case(&'m'))
    })
}

fn synth_find(args: &[&str], input: Vec<String>, env: &mut Environment) -> Vec<String> {
    if !input.is_empty() {
        return filter_find(args, input);
    }

    let non_flags = args
        .iter()
        .copied()
        .filter(|arg| !arg.starts_with('/'))
        .collect::<Vec<_>>();
    let Some(paths) = non_flags.get(1..) else {
        return filter_find(args, input);
    };
    let mut lines = Vec::new();
    for path in paths {
        lines.extend(find_file_input_lines(path, env));
    }
    if lines.is_empty() {
        return Vec::new();
    }
    let filter_args = args
        .iter()
        .copied()
        .filter(|arg| !paths.contains(arg))
        .collect::<Vec<_>>();
    filter_find(&filter_args, lines)
}

fn find_file_input_lines(path: &str, env: &mut Environment) -> Vec<String> {
    let path = path.trim_matches('"');
    if path.contains(['*', '?']) {
        let normalized_pattern = normalize_wildcard_path(&normalize_filesystem_storage_path(path));
        let tracked = env
            .modified_filesystem
            .keys()
            .filter(|tracked| dir_wildcard_matches(path, &normalized_pattern, tracked))
            .cloned()
            .collect::<Vec<_>>();
        return tracked
            .into_iter()
            .flat_map(|tracked| type_file(&tracked, env))
            .collect();
    }
    type_file(path, env)
}

fn synth_type(args: &[&str], input: Vec<String>, env: &mut Environment) -> Vec<String> {
    let mut out = Vec::new();
    for path in non_redirect_args(args) {
        out.extend(type_file(path, env));
    }
    if out.is_empty() && !input.is_empty() {
        return input;
    }
    out
}

fn synth_more(
    stage: &str,
    args: &[&str],
    input: Vec<String>,
    env: &mut Environment,
) -> Vec<String> {
    let skip = args
        .iter()
        .find_map(|arg| more_plus_start_line(arg))
        .map(|line| line.saturating_sub(1))
        .unwrap_or(0);
    let apply_skip = |lines: Vec<String>| lines.into_iter().skip(skip).collect();
    if !input.is_empty() {
        return apply_skip(input);
    }
    let (_, redirs) = crate::redirect::extract_redirections(stage);
    if let Some(path) = redirs.stdin {
        return apply_skip(type_file(&path, env));
    }
    let mut lines = Vec::new();
    for path in args.iter().copied().filter(|arg| !is_more_option(arg)) {
        lines.extend(type_file(path, env));
    }
    apply_skip(lines)
}

fn is_more_option(arg: &str) -> bool {
    arg.starts_with(['/', '-', '+']) || arg == "<"
}

fn more_plus_start_line(arg: &str) -> Option<usize> {
    arg.strip_prefix('+')?.parse::<usize>().ok()
}

fn synth_sort(
    stage: &str,
    args: &[&str],
    input: Vec<String>,
    env: &mut Environment,
) -> Vec<String> {
    let mut lines = if !input.is_empty() {
        input
    } else {
        let (_, redirs) = crate::redirect::extract_redirections(stage);
        if let Some(path) = redirs.stdin {
            type_file(&path, env)
        } else {
            args.iter()
                .copied()
                .find(|arg| !arg.starts_with(['/', '-']) && *arg != "<")
                .map(|path| type_file(path, env))
                .unwrap_or_default()
        }
    };
    lines.sort();
    lines
}

fn synth_cmd(rest: &str, input: Vec<String>, env: &mut Environment) -> Vec<String> {
    let Some(child) = cmd_child_after_switch(rest) else {
        return input;
    };
    run_pipeline(child, env)
}

fn cmd_child_after_switch(rest: &str) -> Option<&str> {
    for (start, end) in command_token_spans(rest) {
        let token = rest[start..end].trim_matches('"');
        let lower = token.to_ascii_lowercase();
        if matches!(lower.as_str(), "/c" | "/k" | "/r") {
            return Some(strip_wrapping_quotes(rest[end..].trim()));
        }
        if lower.starts_with("/c") || lower.starts_with("/k") || lower.starts_with("/r") {
            let child_start = start + 2;
            return Some(strip_wrapping_quotes(rest[child_start..].trim()));
        }
        if let Some(switch_idx) = cmd_exec_switch_index(&lower) {
            let child_start = start + switch_idx + 2;
            return Some(strip_wrapping_quotes(rest[child_start..].trim()));
        }
    }
    None
}

fn cmd_exec_switch_index(token: &str) -> Option<usize> {
    let bytes = token.as_bytes();
    bytes.windows(2).enumerate().find_map(|(idx, pair)| {
        (pair[0] == b'/' && matches!(pair[1], b'c' | b'k' | b'r')).then_some(idx)
    })
}

fn command_token_spans(s: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut token_start = None;
    let mut in_dq = false;
    for (idx, c) in s.char_indices() {
        if token_start.is_none() && !c.is_whitespace() {
            token_start = Some(idx);
        }
        if c == '"' {
            in_dq = !in_dq;
        }
        if c.is_whitespace() && !in_dq {
            if let Some(start) = token_start.take() {
                if start < idx {
                    spans.push((start, idx));
                }
            }
        }
    }
    if let Some(start) = token_start {
        if start < s.len() {
            spans.push((start, s.len()));
        }
    }
    spans
}

fn strip_wrapping_quotes(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(s)
}

fn non_redirect_args<'a>(args: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
    args.iter().copied().filter(|arg| {
        !arg.starts_with(['<', '>'])
            && *arg != "2>"
            && *arg != "1>"
            && !arg.starts_with("2>")
            && !arg.starts_with("1>")
    })
}

fn type_file(path: &str, env: &mut Environment) -> Vec<String> {
    let path = path.trim_matches('"');

    if path.contains(['*', '?']) {
        let normalized_pattern = normalize_wildcard_path(&normalize_filesystem_storage_path(path));
        let mut tracked = env
            .modified_filesystem
            .keys()
            .filter(|tracked| dir_wildcard_matches(path, &normalized_pattern, tracked))
            .cloned()
            .collect::<Vec<_>>();
        tracked.sort();
        return tracked
            .into_iter()
            .flat_map(|tracked| type_file(&tracked, env))
            .collect();
    }

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

    if let Some(lines) =
        type_lines_from_entry(crate::handlers::util::filesystem_entry_for_path(env, path))
    {
        return lines;
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        if stripped.contains(['\\', '/']) {
            return type_lines_from_entry(crate::handlers::util::filesystem_entry_for_path(
                env, stripped,
            ))
            .unwrap_or_default();
        }
    }
    if let Some(name) = current_dir_basename(path) {
        let key = name.to_ascii_lowercase();
        if let Some(lines) = type_lines_from_entry(env.modified_filesystem.get(&key)) {
            return lines;
        }
    }
    Vec::new()
}

fn type_lines_from_entry(entry: Option<&crate::env::FsEntry>) -> Option<Vec<String>> {
    use crate::env::FsEntry;

    match entry {
        Some(FsEntry::Content { content, .. }) | Some(FsEntry::Decoded { content, .. }) => {
            Some(bytes_to_type_lines(content))
        }
        Some(FsEntry::Download { src }) => Some(synth_downloaded_file_lines(src)),
        _ => None,
    }
}

fn bytes_to_type_lines(content: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(content)
        .split_inclusive('\n')
        .map(|l| l.trim_end_matches(['\r', '\n']).to_string())
        .collect()
}

fn current_dir_basename(path: &str) -> Option<&str> {
    strip_current_dir_prefix(path).and_then(windows_basename)
}

fn strip_current_dir_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r".\").or_else(|| path.strip_prefix("./"))
}

fn windows_basename(path: &str) -> Option<&str> {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
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

fn synth_curl(args: &[&str], env: &mut Environment) -> Vec<String> {
    let Some(url) = args
        .iter()
        .rev()
        .map(|arg| arg.trim_matches(['"', '\'']))
        .find(|arg| {
            starts_with_ascii_case_insensitive(arg, "file://")
                || starts_with_ascii_case_insensitive(arg, "http://")
                || starts_with_ascii_case_insensitive(arg, "https://")
        })
    else {
        return Vec::new();
    };

    if starts_with_ascii_case_insensitive(url, "file://") {
        return file_url_to_windows_path(url)
            .map(|path| type_file(&path, env))
            .unwrap_or_default();
    }
    if is_public_ip_endpoint(url) {
        return vec!["203.0.113.10".to_string()];
    }
    Vec::new()
}

fn is_public_ip_endpoint(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower == "https://api.ipify.org"
        || lower == "http://api.ipify.org"
        || lower.starts_with("https://api.ipify.org?")
        || lower.starts_with("http://api.ipify.org?")
        || lower == "https://ifconfig.me"
        || lower == "http://ifconfig.me"
        || lower == "https://ifconfig.me/ip"
        || lower == "http://ifconfig.me/ip"
        || lower == "https://icanhazip.com"
        || lower == "http://icanhazip.com"
        || lower == "https://ipv4.icanhazip.com"
        || lower == "http://ipv4.icanhazip.com"
        || lower == "https://checkip.amazonaws.com"
        || lower == "http://checkip.amazonaws.com"
        || lower == "https://ipinfo.io/ip"
        || lower == "http://ipinfo.io/ip"
        || lower.starts_with("https://www.geoplugin.net/php.gp")
        || lower.starts_with("http://www.geoplugin.net/php.gp")
}

fn file_url_to_windows_path(url: &str) -> Option<String> {
    let rest = crate::util::strip_ascii_case_insensitive_prefix(url, "file://")?;
    let rest = rest.trim_start_matches(['/', '\\']);
    if rest.is_empty() {
        return None;
    }
    if rest.as_bytes().get(1) == Some(&b':') {
        return Some(rest.replace('/', "\\"));
    }
    if let Some(local) = rest
        .strip_prefix("localhost/")
        .or_else(|| rest.strip_prefix("localhost\\"))
    {
        let local = local.trim_start_matches(['/', '\\']);
        if local.is_empty() {
            return None;
        }
        return Some(local.replace('/', "\\"));
    }
    if let Some((host, share)) = rest.split_once('/') {
        if !host.is_empty() && !share.is_empty() {
            return Some(format!(r"\\{}\{}", host, share.replace('/', "\\")));
        }
    }
    Some(rest.replace('/', "\\"))
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
    let out = if flags.iter().any(|flag| dir_has_switch(flag, 'b')) {
        let recursive = flags.iter().any(|flag| dir_has_switch(flag, 's'));
        dir_tracked_file_names(&path, env, recursive)
    } else {
        Vec::new()
    };
    env.traits
        .push(crate::traits::Trait::DirListing { path, flags });
    out
}

fn dir_has_switch(flag: &str, switch: char) -> bool {
    flag.trim_start_matches('/').split('/').any(|part| {
        part.chars()
            .next()
            .is_some_and(|c| c.eq_ignore_ascii_case(&switch))
    })
}

fn dir_tracked_file_names(path: &str, env: &Environment, recursive: bool) -> Vec<String> {
    let path = path.trim_matches('"');
    if path.is_empty() || is_current_dir_listing_path(path) {
        return dir_current_file_names(env, recursive);
    }
    if path.contains(['*', '?']) {
        let normalized_pattern = normalize_wildcard_path(&normalize_filesystem_storage_path(path));
        let mut names = env
            .modified_filesystem
            .keys()
            .filter(|tracked| {
                if recursive {
                    recursive_wildcard_matches(path, &normalized_pattern, tracked)
                } else {
                    dir_wildcard_matches(path, &normalized_pattern, tracked)
                }
            })
            .map(|tracked| dir_listing_name(tracked, recursive))
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        return names;
    }
    let key = path.to_ascii_lowercase();
    if env.modified_filesystem.contains_key(&key) {
        return vec![dir_listing_name(path, recursive)];
    }
    if let Some(stripped) = strip_current_dir_prefix(path) {
        let key = stripped.to_ascii_lowercase();
        if env.modified_filesystem.contains_key(&key) {
            return vec![dir_listing_name(stripped, recursive)];
        }
    }
    Vec::new()
}

fn is_current_dir_listing_path(path: &str) -> bool {
    matches!(path, "." | r".\" | "./")
}

fn dir_current_file_names(env: &Environment, recursive: bool) -> Vec<String> {
    let mut names = env
        .modified_filesystem
        .keys()
        .filter(|path| recursive || !path.contains(['\\', '/', ':']))
        .map(|path| dir_listing_name(path, recursive))
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    names
}

fn dir_listing_name(path: &str, recursive: bool) -> String {
    if recursive {
        path.to_string()
    } else {
        windows_basename(path).unwrap_or(path).to_string()
    }
}

fn dir_wildcard_matches(pattern: &str, normalized_pattern: &str, tracked_path: &str) -> bool {
    let normalized_path = normalize_wildcard_path(tracked_path);
    if pattern.contains(['\\', '/', ':']) {
        let Some((pattern_dir, pattern_name)) = normalized_pattern.rsplit_once('\\') else {
            return wildcard_match(normalized_pattern, &normalized_path);
        };
        let Some((tracked_dir, tracked_name)) = normalized_path.rsplit_once('\\') else {
            return false;
        };
        return pattern_dir == tracked_dir && wildcard_match(pattern_name, tracked_name);
    }
    windows_basename(tracked_path).is_some_and(|name| {
        !tracked_path.contains(['\\', '/', ':'])
            && wildcard_match(normalized_pattern, &normalize_wildcard_path(name))
    })
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

fn synth_whoami(args: &[&str], env: &Environment) -> Vec<String> {
    let domain = env
        .get("userdomain")
        .unwrap_or_else(|| "miscreanttears".to_string());
    let user = env.get("username").unwrap_or_else(|| "puncher".to_string());
    if args.iter().any(|arg| arg.eq_ignore_ascii_case("/user")) {
        return vec![
            "User Name SID".to_string(),
            format!(
                "{}\\{} S-1-5-21-1000-1000-1000-1001",
                domain.to_ascii_lowercase(),
                user.to_ascii_lowercase()
            ),
        ];
    }
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

fn synth_date(args: &[&str]) -> Vec<String> {
    if args.iter().any(|arg| arg.eq_ignore_ascii_case("/t")) {
        return vec!["Mon 06/15/2026".to_string()];
    }
    vec!["The current date is: Mon 06/15/2026".to_string()]
}

fn synth_time(args: &[&str]) -> Vec<String> {
    if args.iter().any(|arg| arg.eq_ignore_ascii_case("/t")) {
        return vec!["12:00 PM".to_string()];
    }
    vec!["The current time is: 12:00:00.00".to_string()]
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

fn synth_hostname(env: &Environment) -> Vec<String> {
    vec![env
        .get("COMPUTERNAME")
        .unwrap_or_else(|| "MISCREANTTEARS".to_string())]
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
                .map(|ch| ch.to_ascii_lowercase());
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

fn synth_powershell(args: &[&str], env: &Environment) -> Vec<String> {
    let command = args.join(" ");
    let lower = command.to_ascii_lowercase();
    if let Some(output) = powershell_write_output_literal(&command) {
        return vec![output];
    }
    if lower.contains("[system.net.dns]::gethostname()") {
        return vec![env
            .get("COMPUTERNAME")
            .unwrap_or_else(|| "DESKTOP-EXAMPLE".to_string())];
    }
    if lower.contains("get-ciminstance")
        && lower.contains("securitycenter")
        && lower.contains("antivirusproduct")
        && lower.contains("displayname")
    {
        return vec!["Microsoft Defender Antivirus".to_string()];
    }
    if lower.contains("get-process") && lower.contains("explorer") && lower.contains("processname")
    {
        return vec!["explorer".to_string()];
    }
    if lower.contains("get-date")
        && lower.contains("uformat")
        && (lower.contains("%h%m%s") || lower.contains("%%h%%m%%s"))
    {
        return vec!["120000".to_string()];
    }
    Vec::new()
}

fn powershell_write_output_literal(command: &str) -> Option<String> {
    let lower = command.to_ascii_lowercase();
    let idx = lower.find("write-output")?;
    let mut value = command[idx + "write-output".len()..].trim_start();
    if value.is_empty() {
        return None;
    }
    value = value
        .split_once(';')
        .map(|(head, _)| head)
        .unwrap_or(value)
        .trim();
    value = value.trim_matches(|ch| ch == '"' || ch == '\'').trim();
    (!value.is_empty()).then(|| value.to_string())
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
    if let Some((root, pattern)) = where_recursive_args(args) {
        let mut out = env
            .modified_filesystem
            .keys()
            .filter(|path| where_recursive_matches(&root, &pattern, path))
            .cloned()
            .collect::<Vec<_>>();
        out.sort();
        out.dedup();
        if !out.is_empty() {
            return out;
        }
    }
    let bin = match where_pattern_arg(args) {
        Some(b) => b.to_ascii_lowercase(),
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

fn where_recursive_args(args: &[&str]) -> Option<(String, String)> {
    let mut iter = non_redirect_args(args).map(|arg| arg.trim_matches('"'));
    while let Some(arg) = iter.next() {
        if arg.eq_ignore_ascii_case("/r") {
            let root = iter.next()?.to_string();
            let pattern = iter
                .find(|candidate| !candidate.is_empty() && !candidate.starts_with('/'))?
                .to_string();
            return Some((root, pattern));
        }
    }
    None
}

fn where_recursive_matches(root: &str, pattern: &str, tracked_path: &str) -> bool {
    let root = normalize_wildcard_path(&normalize_filesystem_storage_path(root));
    let root = root.trim_end_matches('\\');
    let path = normalize_wildcard_path(tracked_path);
    if !path_is_under_root(&path, root) {
        return false;
    }
    let suffix = &path[root.len()..];
    let rest = suffix.trim_start_matches('\\');
    !rest.is_empty()
        && windows_basename(&path).is_some_and(|name| {
            wildcard_match(
                &normalize_wildcard_path(pattern),
                &normalize_wildcard_path(name),
            )
        })
}

fn path_is_under_root(path: &str, root: &str) -> bool {
    path.starts_with(root) && path[root.len()..].starts_with('\\')
}

fn where_pattern_arg(args: &[&str]) -> Option<String> {
    let mut pattern = None;
    let mut skip_next = false;
    for arg in non_redirect_args(args) {
        if skip_next {
            skip_next = false;
            continue;
        }
        let arg = arg.trim_matches('"');
        if arg.eq_ignore_ascii_case("/r") {
            skip_next = true;
            continue;
        }
        if arg.starts_with('/') {
            continue;
        }
        pattern = Some(arg.to_string());
    }
    pattern
}

fn synth_wmic(args: &[&str]) -> Vec<String> {
    let filtered: Vec<String> = non_redirect_args(args)
        .map(|arg| arg.trim_matches('"').to_ascii_lowercase())
        .collect();
    let joined = filtered.join(" ");
    if filtered.first().is_some_and(|arg| arg == "os") && joined.contains("localdatetime") {
        if joined.contains("/value") {
            return vec!["LocalDateTime=20260615120000.000000-000".to_string()];
        }
        return vec![
            "LocalDateTime".to_string(),
            "20260615120000.000000-000".to_string(),
        ];
    }
    if filtered.first().is_some_and(|arg| arg == "logicaldisk")
        && joined.contains("250954240000")
        && joined.contains("size")
    {
        return vec!["Size".to_string(), "250954240000".to_string()];
    }
    if filtered.first().is_some_and(|arg| arg == "computersystem")
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
    if filtered.first().is_some_and(|arg| arg == "group")
        && joined.contains("s-1-5-32-544")
        && joined.contains("name")
    {
        if joined.contains("/value") {
            return vec!["Name=Administrators".to_string()];
        }
        return vec!["Name".to_string(), "Administrators".to_string()];
    }
    Vec::new()
}
