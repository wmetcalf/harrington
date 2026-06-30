use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(version, about = "Harrington — Windows batch deobfuscator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Deobfuscate a script. Writes deobfuscated.bat + extracted children to --out-dir.
    Deob {
        /// Input script (`-` for stdin).
        file: String,
        #[arg(short = 'o', long = "out-dir", default_value = "batdeob-out")]
        out_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        json_only: bool,
        /// Replace batdeob-generated files in an existing output directory.
        #[arg(long)]
        force: bool,
        /// Optional path to external LOLBAS JSON for JSON enrichment.
        #[arg(long = "lolbas-json")]
        lolbas_json: Option<PathBuf>,
        #[arg(long, default_value_t = 12)]
        max_depth: u32,
        #[arg(long, default_value_t = 65_536)]
        max_iterations: u64,
        #[arg(long, default_value_t = 64)]
        max_child_scripts: u32,
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        #[arg(long)]
        no_self_extract: bool,
        /// Seed an analysis environment variable (`NAME=VALUE`). Repeatable.
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        /// Read analysis environment variables from a `NAME=VALUE` file.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 0)]
        max_output_line_bytes: u64,
        #[arg(long, default_value_t = 100)]
        max_traits_per_kind: u32,
    },
    /// Like `deob --json-only`: JSON report to stdout, no files.
    Analyze {
        file: Vec<String>,
        #[arg(long = "file-list", value_name = "PATH")]
        file_list: Option<PathBuf>,
        #[arg(long, default_value_t = 12)]
        max_depth: u32,
        #[arg(long, default_value_t = 65_536)]
        max_iterations: u64,
        #[arg(long, default_value_t = 64)]
        max_child_scripts: u32,
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        #[arg(long)]
        no_self_extract: bool,
        /// Seed an analysis environment variable (`NAME=VALUE`). Repeatable.
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        /// Read analysis environment variables from a `NAME=VALUE` file.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 0)]
        max_output_line_bytes: u64,
        #[arg(long, default_value_t = 100)]
        max_traits_per_kind: u32,
        #[arg(long)]
        jsonl: bool,
        /// Optional path to external LOLBAS JSON for JSON enrichment.
        #[arg(long = "lolbas-json")]
        lolbas_json: Option<PathBuf>,
    },
    /// Emit a focused JSON IOC report without raw deobfuscated text.
    Summarize {
        /// Input script (`-` for stdin).
        file: String,
        /// Seed an analysis environment variable (`NAME=VALUE`). Repeatable.
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        /// Read analysis environment variables from a `NAME=VALUE` file.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,
        /// Optional path to external LOLBAS JSON for JSON enrichment.
        #[arg(long = "lolbas-json")]
        lolbas_json: Option<PathBuf>,
    },
    /// Emit a comprehensive JSON report: summary fields + full trait list,
    /// plus optionally the JSON-escaped source and deobfuscated text.
    Report {
        /// Input script (`-` for stdin).
        file: String,
        /// Embed the raw input bytes as a JSON string (lossy UTF-8).
        #[arg(long)]
        include_source: bool,
        /// Embed the deobfuscated text as a JSON string.
        #[arg(long)]
        include_deob: bool,
        #[arg(long, default_value_t = 12)]
        max_depth: u32,
        #[arg(long, default_value_t = 65_536)]
        max_iterations: u64,
        #[arg(long, default_value_t = 64)]
        max_child_scripts: u32,
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        #[arg(long)]
        no_self_extract: bool,
        /// Seed an analysis environment variable (`NAME=VALUE`). Repeatable.
        #[arg(long = "env", value_name = "NAME=VALUE")]
        env: Vec<String>,
        /// Read analysis environment variables from a `NAME=VALUE` file.
        #[arg(long = "env-file", value_name = "PATH")]
        env_file: Vec<PathBuf>,
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 0)]
        max_output_line_bytes: u64,
        #[arg(long, default_value_t = 100)]
        max_traits_per_kind: u32,
        /// Optional path to external LOLBAS JSON for JSON enrichment.
        #[arg(long = "lolbas-json")]
        lolbas_json: Option<PathBuf>,
    },
    /// Print version and exit.
    Version,
}

/// Maximum bytes we will read from stdin or a plain file. Defends against
/// OOM from a multi-gigabyte input. A real batch file is well under a few
/// MB; this is a generous safety ceiling.
const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENV_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILE_LIST_BYTES: u64 = 16 * 1024 * 1024;

fn read_input(path: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    if path == "-" {
        let mut buf = Vec::new();
        let mut limited = std::io::stdin().take(MAX_INPUT_BYTES);
        limited.read_to_end(&mut buf).context("read stdin")?;
        if buf.len() as u64 >= MAX_INPUT_BYTES {
            anyhow::bail!(
                "stdin input exceeds {} bytes; refusing to read more",
                MAX_INPUT_BYTES
            );
        }
        Ok(buf)
    } else {
        // Cap on-disk reads too — symlinks could point at /dev/zero etc.
        let meta = fs::metadata(path).with_context(|| format!("stat {:?}", path))?;
        if meta.len() > MAX_INPUT_BYTES {
            anyhow::bail!(
                "{:?}: {} bytes exceeds the {}-byte input cap",
                path,
                meta.len(),
                MAX_INPUT_BYTES
            );
        }
        fs::read(path).with_context(|| format!("read {:?}", path))
    }
}

fn read_file_list(path: &Path) -> Result<Vec<String>> {
    let meta = fs::metadata(path).with_context(|| format!("stat file list {:?}", path))?;
    if !meta.file_type().is_file() {
        anyhow::bail!("{:?}: file list is not a regular file", path);
    }
    if meta.len() > MAX_FILE_LIST_BYTES {
        anyhow::bail!(
            "file list {:?}: {} bytes exceeds the {}-byte cap",
            path,
            meta.len(),
            MAX_FILE_LIST_BYTES
        );
    }
    let contents =
        fs::read_to_string(path).with_context(|| format!("read file list {:?}", path))?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

fn parse_env_assignment(raw: &str, source: &str) -> Result<(String, String)> {
    let Some((name, value)) = raw.split_once('=') else {
        anyhow::bail!("{source}: expected NAME=VALUE");
    };
    let name = name.trim();
    validate_env_name(name, source)?;
    Ok((name.to_string(), value.to_string()))
}

fn parse_cli() -> Cli {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    if let Some(first) = args.get(1).and_then(|arg| arg.to_str()) {
        let known = matches!(
            first,
            "deob" | "analyze" | "summarize" | "report" | "version" | "help"
        ) || first.starts_with('-');
        if !known {
            args.insert(1, OsString::from("analyze"));
        }
    }
    Cli::parse_from(args)
}

fn read_env_file(path: &Path) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("stat env file {:?}", path))?;
    if !meta.file_type().is_file() {
        anyhow::bail!("{:?}: env file is not a regular file", path);
    }
    if meta.len() > MAX_ENV_FILE_BYTES {
        anyhow::bail!(
            "env file {:?}: {} bytes exceeds the {}-byte cap",
            path,
            meta.len(),
            MAX_ENV_FILE_BYTES
        );
    }
    fs::read_to_string(path).with_context(|| format!("read env file {:?}", path))
}

fn parse_env_file_assignments(contents: &str, path: &Path) -> Result<Vec<(String, String)>> {
    let mut environment = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((candidate_name, _)) = line.split_once('=') {
            let candidate_name = candidate_name.trim();
            if !candidate_name.is_empty()
                && validate_env_name(candidate_name, &format!("{:?}:{}", path, idx + 1)).is_ok()
            {
                environment.push(parse_env_assignment(
                    line,
                    &format!("{:?}:{}", path, idx + 1),
                )?);
                continue;
            }
        }
        if let Some((_, value)) = environment.last_mut() {
            value.push('\n');
            value.push_str(line);
            continue;
        }
        environment.push(parse_env_assignment(
            trimmed,
            &format!("{:?}:{}", path, idx + 1),
        )?);
    }
    Ok(environment)
}

fn validate_env_name(name: &str, source: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{source}: env variable name is empty");
    }
    if name.len() > 128 {
        anyhow::bail!("{source}: env variable name exceeds 128 bytes");
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        anyhow::bail!("{source}: unsupported env variable name {:?}", name);
    }
    Ok(())
}

fn make_analysis_options(
    env_args: &[String],
    env_files: &[PathBuf],
) -> Result<batdeob_core::AnalysisOptions> {
    let mut environment = Vec::new();
    for path in env_files {
        let contents = read_env_file(path)?;
        environment.extend(parse_env_file_assignments(&contents, path)?);
    }
    for raw in env_args {
        environment.push(parse_env_assignment(raw, "--env")?);
    }
    Ok(batdeob_core::AnalysisOptions::with_environment(environment))
}

#[allow(clippy::too_many_arguments)]
fn make_config(
    max_depth: u32,
    max_iterations: u64,
    max_child_scripts: u32,
    timeout: u64,
    self_extract: bool,
    max_output_bytes: u64,
    max_output_line_bytes: u64,
    max_traits_per_kind: u32,
) -> batdeob_core::Config {
    batdeob_core::Config {
        max_depth,
        max_iterations,
        max_child_scripts,
        timeout_secs: timeout,
        self_extract,
        winver: batdeob_core::WinVer::Win10,
        max_output_bytes,
        max_output_line_bytes,
        max_traits_per_kind,
    }
}

fn short_sha(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    hex::encode(digest)[..10].to_string()
}

#[derive(Debug, Clone)]
struct LolbasEntry {
    name: String,
    stem: String,
    url: Option<String>,
    categories: Vec<String>,
    mitre_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct LolbasIndex {
    entries: Vec<LolbasEntry>,
}

fn load_lolbas_index(path: &Path) -> Result<LolbasIndex> {
    const MAX_LOLBAS_JSON_BYTES: u64 = 64 * 1024 * 1024;

    let meta = fs::metadata(path).with_context(|| format!("stat {:?}", path))?;
    if !meta.file_type().is_file() {
        anyhow::bail!("{:?}: not a regular file", path);
    }
    if meta.len() > MAX_LOLBAS_JSON_BYTES {
        anyhow::bail!(
            "{:?}: {} bytes exceeds the {}-byte LOLBAS JSON cap",
            path,
            meta.len(),
            MAX_LOLBAS_JSON_BYTES
        );
    }
    let bytes = fs::read(path).with_context(|| format!("read {:?}", path))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {:?}", path))?;
    let Some(items) = value.as_array() else {
        anyhow::bail!("{:?}: expected top-level LOLBAS JSON array", path);
    };

    let mut entries = Vec::new();
    for item in items {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let Some(name) = obj.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let stem = program_stem(name);
        if stem.is_empty() {
            continue;
        }
        let url = obj
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let mut categories = Vec::new();
        let mut mitre_ids = Vec::new();
        if let Some(commands) = obj.get("Commands").and_then(|v| v.as_array()) {
            for command in commands {
                if let Some(category) = command.get("Category").and_then(|v| v.as_str()) {
                    push_unique(&mut categories, category);
                }
                if let Some(mitre_id) = command.get("MitreID").and_then(|v| v.as_str()) {
                    push_unique(&mut mitre_ids, mitre_id);
                }
            }
        }
        entries.push(LolbasEntry {
            name: name.to_string(),
            stem,
            url,
            categories,
            mitre_ids,
        });
    }

    Ok(LolbasIndex { entries })
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !values.iter().any(|v| v == value) {
        values.push(value.to_string());
    }
}

fn program_stem(name: &str) -> String {
    let basename = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .trim_matches(['"', '\'']);
    let lower = basename.to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .unwrap_or(lower.as_str())
        .to_string()
}

fn command_invokes_program(command: &str, wanted_stem: &str) -> bool {
    let tokens = lolbas_command_tokens(command);
    tokens.iter().enumerate().any(|(idx, token)| {
        if idx > 0 && lolbas_non_exec_value_option(tokens[idx - 1].text) {
            return false;
        }
        if idx > 0
            && lolbas_is_destination_separator(command, tokens[idx - 1].end, token.start)
            && is_url_like_program_token(tokens[idx - 1].text)
            && is_local_path_like_program_token(token.text)
        {
            return false;
        }
        if lolbas_is_certutil_file_operand(&tokens, idx) {
            return false;
        }
        if lolbas_is_split_msi_log_operand(&tokens, idx) {
            return false;
        }
        if lolbas_is_file_management_operand(&tokens, idx) {
            return false;
        }
        if lolbas_attached_non_exec_value_option(token.text) {
            return false;
        }
        if is_url_like_program_token(token.text) {
            return false;
        }
        let stem = program_stem(token.text);
        !stem.is_empty() && stem == wanted_stem
    })
}

struct LolbasCommandToken<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

fn lolbas_command_tokens(command: &str) -> Vec<LolbasCommandToken<'_>> {
    let mut tokens = Vec::new();
    let mut chars = command.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if matches!(ch, '"' | '\'') {
            let quote = ch;
            let token_start = idx;
            let mut token_end = idx + ch.len_utf8();
            for (quoted_idx, quoted_ch) in chars.by_ref() {
                token_end = quoted_idx + quoted_ch.len_utf8();
                if quoted_ch == quote {
                    break;
                }
            }
            tokens.push(LolbasCommandToken {
                text: &command[token_start..token_end],
                start: token_start,
                end: token_end,
            });
            continue;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '\\' | '/' | ':') {
            let token_start = idx;
            let mut token_end = idx + ch.len_utf8();
            while let Some(&(next_idx, next_ch)) = chars.peek() {
                if next_ch.is_ascii_alphanumeric()
                    || matches!(next_ch, '.' | '_' | '-' | '\\' | '/' | ':' | '"' | '\'')
                {
                    chars.next();
                    token_end = next_idx + next_ch.len_utf8();
                } else {
                    break;
                }
            }
            tokens.push(LolbasCommandToken {
                text: &command[token_start..token_end],
                start: token_start,
                end: token_end,
            });
        }
    }
    tokens
}

fn lolbas_is_destination_separator(command: &str, prev_end: usize, next_start: usize) -> bool {
    let between = &command[prev_end..next_start];
    !between.is_empty()
        && between
            .chars()
            .all(|ch| ch.is_whitespace() || matches!(ch, ','))
}

fn lolbas_is_certutil_file_operand(tokens: &[LolbasCommandToken<'_>], idx: usize) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    if program_stem(first.text) != "certutil" || !is_local_path_like_program_token(tokens[idx].text)
    {
        return false;
    }
    tokens
        .iter()
        .take(idx)
        .any(|token| certutil_file_transform_verb(token.text))
}

fn certutil_file_transform_verb(token: &str) -> bool {
    matches!(
        token
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
            .as_str(),
        "-encode"
            | "/encode"
            | "-encodehex"
            | "/encodehex"
            | "-decode"
            | "/decode"
            | "-decodehex"
            | "/decodehex"
    )
}

fn lolbas_non_exec_value_option(token: &str) -> bool {
    matches!(
        token
            .trim_matches(['"', '\''])
            .to_ascii_lowercase()
            .as_str(),
        "-o" | "/o"
            | "--output"
            | "--output-document"
            | "-output"
            | "/out"
            | "-out"
            | "-outfile"
            | "/outfile"
            | "-outf"
            | "/outf"
            | "-destination"
            | "/destination"
            | "-dest"
            | "/dest"
            | "-log"
            | "/log"
            | "--log"
    ) || lolbas_msi_log_option(token)
}

fn lolbas_attached_non_exec_value_option(token: &str) -> bool {
    let lower = token.trim_matches(['"', '\'']).to_ascii_lowercase();
    lower.starts_with("--output=")
        || lower.starts_with("--output-document=")
        || lower.starts_with("-output:")
        || lower.starts_with("-output=")
        || lower.starts_with("/out:")
        || lower.starts_with("/out=")
        || lower.starts_with("-outfile:")
        || lower.starts_with("-outfile=")
        || lower.starts_with("/outfile:")
        || lower.starts_with("/outfile=")
        || lower.starts_with("-outf:")
        || lower.starts_with("-outf=")
        || lower.starts_with("/outf:")
        || lower.starts_with("/outf=")
        || lower.starts_with("-destination:")
        || lower.starts_with("-destination=")
        || lower.starts_with("/destination:")
        || lower.starts_with("/destination=")
        || lower.starts_with("-dest:")
        || lower.starts_with("-dest=")
        || lower.starts_with("/dest:")
        || lower.starts_with("/dest=")
        || lower.starts_with("-log:")
        || lower.starts_with("-log=")
        || lower.starts_with("/log:")
        || lower.starts_with("/log=")
        || lower.starts_with("--log=")
        || (lower.len() > 2
            && (lower.starts_with("-o") || lower.starts_with("/o"))
            && lower[2..].contains(['\\', '/']))
        || lolbas_attached_msi_log_option(&lower)
}

fn lolbas_msi_log_option(token: &str) -> bool {
    let lower = token.trim_matches(['"', '\'']).to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix(['/', '-']) else {
        return false;
    };
    rest.starts_with('l') && rest.len() >= 2 && rest[1..].chars().all(is_msi_log_flag_char)
}

fn lolbas_attached_msi_log_option(lower: &str) -> bool {
    let Some(rest) = lower.strip_prefix(['/', '-']) else {
        return false;
    };
    let Some(path_start) = rest.find([':', '=']) else {
        return false;
    };
    path_start >= 2
        && rest.starts_with('l')
        && rest[1..path_start].chars().all(is_msi_log_flag_char)
}

fn lolbas_is_split_msi_log_operand(tokens: &[LolbasCommandToken<'_>], idx: usize) -> bool {
    if idx < 2 || !is_local_path_like_program_token(tokens[idx].text) {
        return false;
    }
    let log_prefix = tokens[idx - 2]
        .text
        .trim_matches(['"', '\''])
        .to_ascii_lowercase();
    if !matches!(log_prefix.as_str(), "/l" | "-l") {
        return false;
    }
    let flags = tokens[idx - 1]
        .text
        .trim_matches(['"', '\''])
        .to_ascii_lowercase();
    !flags.is_empty() && flags.chars().all(is_msi_log_flag_char)
}

fn is_msi_log_flag_char(ch: char) -> bool {
    matches!(
        ch,
        '*' | '!' | 'v' | 'o' | 'i' | 'w' | 'e' | 'a' | 'r' | 'u' | 'c' | 'm' | 'p' | 'x' | '+'
    )
}

fn lolbas_is_file_management_operand(tokens: &[LolbasCommandToken<'_>], idx: usize) -> bool {
    if idx == 0 || !is_local_path_like_program_token(tokens[idx].text) {
        return false;
    }
    matches!(
        tokens
            .first()
            .map(|token| program_stem(token.text))
            .as_deref(),
        Some(
            "del"
                | "erase"
                | "copy"
                | "xcopy"
                | "move"
                | "ren"
                | "rename"
                | "attrib"
                | "mkdir"
                | "md"
                | "rmdir"
                | "rd"
        )
    )
}

fn is_url_like_program_token(token: &str) -> bool {
    let token = token.trim_matches(['"', '\'']).to_ascii_lowercase();
    if token.contains("://")
        || ["http:", "https:", "hxxp:", "hxxps:", "ftp:", "file:"]
            .iter()
            .any(|prefix| token.starts_with(prefix))
    {
        return true;
    }
    let Some(slash) = token.find(['/', '\\']) else {
        return false;
    };
    let first_segment = &token[..slash];
    first_segment.contains('.') && !is_drive_path(&token)
}

fn is_local_path_like_program_token(token: &str) -> bool {
    let token = token.trim_matches(['"', '\'']);
    is_drive_path(token) || token.contains(['\\', '/'])
}

fn is_drive_path(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

/// Safely join `name` onto the canonical `out_dir`, refusing if the result
/// would escape that directory. All `name`s in this tool are either static
/// strings ("deobfuscated.bat", "traits.json") or `<sha10>.bat|ps1` — so a
/// successful escape would require a bug in the SHA encoder. Belt and
/// braces; the canonicalize step also catches the case where `out_dir`
/// itself is a symlink to a sensitive location.
fn safe_join(canonical_out: &Path, name: &str) -> Result<PathBuf> {
    // Refuse anything that looks like a path traversal upfront.
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        anyhow::bail!("refusing unsafe child filename: {:?}", name);
    }
    let target = canonical_out.join(name);
    Ok(target)
}

fn safe_write(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    match opts.open(path) {
        Ok(mut f) => {
            f.write_all(bytes)
                .with_context(|| format!("write {:?}", path))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "refusing to overwrite existing output path {:?}; rerun with --force to replace stale output",
                path
            )
        }
        Err(e) => Err(anyhow::Error::from(e).context(format!("open {:?}", path))),
    }
}

fn write_report_files(report: &batdeob_core::Report, out_dir: &Path, force: bool) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("mkdir {:?}", out_dir))?;
    let canonical_out =
        fs::canonicalize(out_dir).with_context(|| format!("canonicalize {:?}", out_dir))?;
    if force {
        remove_stale_generated_outputs(&canonical_out)?;
    }

    safe_write(
        &safe_join(&canonical_out, "deobfuscated.bat")?,
        report.deobfuscated.as_bytes(),
        force,
    )?;

    let mut seen = std::collections::HashSet::new();
    for child in &report.extracted_cmd {
        let bytes = child.as_bytes();
        let sha = short_sha(bytes);
        if !seen.insert(sha.clone()) {
            continue;
        }
        let name = format!("{sha}.bat");
        safe_write(&safe_join(&canonical_out, &name)?, bytes, force)?;
    }
    for (idx, child) in report.extracted_ps1.iter().enumerate() {
        let sha = short_sha(child);
        let name = format!("{sha}.ps1");
        if !seen.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, child, force)?;
        if let Some(normalized) = report.extracted_ps1_normalized.get(idx) {
            let raw_text = String::from_utf8_lossy(child);
            if normalized != raw_text.as_ref() {
                let name = format!("{sha}.normalized.ps1");
                if seen.insert(name.clone()) {
                    safe_write(
                        &safe_join(&canonical_out, &name)?,
                        normalized.as_bytes(),
                        force,
                    )?;
                }
            }
        }
    }
    for child in &report.extracted_jscript {
        let sha = short_sha(child);
        let name = format!("{sha}.js");
        if !seen.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, child, force)?;
    }
    for child in &report.extracted_vbs {
        let sha = short_sha(child);
        let name = format!("{sha}.vbs");
        if !seen.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, child, force)?;
    }
    for (label, blob) in &report.recovered_pe {
        let bytes = blob.as_slice();
        let sha = short_sha(bytes);
        let ext = detect_blob_extension(bytes);
        let name = format!("{sha}.{ext}");
        if !seen.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, bytes, force)?;

        let meta_name = format!("{sha}.meta");
        if seen.insert(meta_name.clone()) {
            let meta = format!(
                "origin: {label}\nsize: {}\nsha256-prefix: {sha}\n",
                bytes.len()
            );
            safe_write(
                &safe_join(&canonical_out, &meta_name)?,
                meta.as_bytes(),
                force,
            )?;
        }
    }

    let traits_json = serde_json::to_string_pretty(&report.traits)?;
    safe_write(
        &safe_join(&canonical_out, "traits.json")?,
        traits_json.as_bytes(),
        force,
    )?;

    Ok(())
}

fn detect_blob_extension(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"MZ") {
        return "exe";
    }
    if bytes.starts_with(b"MSCF") {
        return "cab";
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return "zip";
    }
    if bytes.starts_with(b"Rar!\x1A\x07") {
        return "rar";
    }
    if bytes.starts_with(b"7z\xBC\xAF\x27\x1C") {
        return "7z";
    }
    if bytes.starts_with(b"%PDF-") {
        return "pdf";
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
        return "png";
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "gif";
    }
    if bytes.starts_with(b"\xFF\xD8\xFF") {
        return "jpg";
    }
    "bin"
}

fn remove_stale_generated_outputs(canonical_out: &Path) -> Result<()> {
    for entry in fs::read_dir(canonical_out)
        .with_context(|| format!("read output dir {:?}", canonical_out))?
    {
        let entry = entry.with_context(|| format!("read output dir entry {:?}", canonical_out))?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if !is_generated_output_name(&name) {
            continue;
        }
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat output path {:?}", path))?;
        if file_type.is_file() || file_type.is_symlink() {
            fs::remove_file(&path).with_context(|| format!("remove stale output {:?}", path))?;
        } else if file_type.is_dir() {
            anyhow::bail!(
                "refusing to remove generated output directory {:?}; remove it manually",
                path
            );
        }
    }
    Ok(())
}

fn is_generated_output_name(name: &str) -> bool {
    if matches!(name, "deobfuscated.bat" | "traits.json") {
        return true;
    }
    let Some((prefix, ext)) = name.split_once('.') else {
        return false;
    };
    prefix.len() == 10
        && prefix.bytes().all(|b| b.is_ascii_hexdigit())
        && matches!(
            ext,
            "bat"
                | "ps1"
                | "normalized.ps1"
                | "js"
                | "vbs"
                | "exe"
                | "dll"
                | "cab"
                | "zip"
                | "rar"
                | "7z"
                | "lnk"
                | "pdf"
                | "png"
                | "gif"
                | "jpg"
                | "bin"
                | "meta"
        )
}

fn build_summary(
    input_path: &str,
    input: &[u8],
    report: &batdeob_core::Report,
    lolbas_index: Option<&LolbasIndex>,
) -> serde_json::Value {
    use batdeob_core::Trait;
    use std::collections::BTreeMap;

    let mut downloads = Vec::new();
    let mut lolbas: Vec<String> = Vec::new();
    let mut admin_commands: BTreeMap<String, u64> = BTreeMap::new();
    let mut ps_samples: Vec<String> = Vec::new();
    let mut windows_util: Vec<serde_json::Value> = Vec::new();
    let mut self_extract = false;
    let mut traits_capped: Vec<serde_json::Value> = Vec::new();

    for t in &report.traits {
        match t {
            Trait::Download { src, dst, .. } => {
                downloads.push(serde_json::json!({
                    "src": src,
                    "dst": dst,
                }));
            }
            Trait::CertutilDownload { url, dst } => {
                downloads.push(serde_json::json!({
                    "src": url,
                    "dst": dst,
                }));
            }
            Trait::BitsadminDownload { url, dst } => {
                downloads.push(serde_json::json!({
                    "src": url,
                    "dst": dst,
                }));
            }
            Trait::DownloadInDeobText { src, .. } => {
                downloads.push(serde_json::json!({
                    "src": src,
                    "dst": null,
                    "source": "deob-text-sweep",
                }));
            }
            Trait::UncWebDavC2 {
                host,
                port,
                share_path,
                http_url,
                ..
            } => {
                // `share_path` is already the full `\\host@port\share\...`
                // UNC string — using it verbatim. The MS-style http(s) URL
                // is the analyst-friendlier form.
                downloads.push(serde_json::json!({
                    "src": share_path,
                    "http_url": if http_url.is_empty() { None } else { Some(http_url) },
                    "dst": null,
                    "source": "unc-webdav-c2",
                    "host": host,
                    "port": port,
                }));
            }
            Trait::Lolbas { name, .. } => {
                if !lolbas.iter().any(|n| n == name) {
                    lolbas.push(name.clone());
                }
            }
            Trait::AdminCommand { name, .. } => {
                *admin_commands.entry(name.clone()).or_insert(0) += 1;
            }
            Trait::SelfExtract { .. } => {
                self_extract = true;
            }
            Trait::WindowsUtilManip { src, dst, .. } => {
                windows_util.push(serde_json::json!({"src": src, "dst": dst}));
            }
            Trait::TraitsCapped { .. }
            | Trait::LineTruncated { .. }
            | Trait::OutputCapped { .. }
            | Trait::DepthCapped { .. }
            | Trait::ChildScriptsCapped
            | Trait::TimeoutHit
            | Trait::IterationCapped { .. } => {
                traits_capped.push(serde_json::to_value(t).expect("trait serializes"));
            }
            _ => {}
        }
    }

    let ps_count = report.extracted_ps1.len();
    for s in report.extracted_ps1_normalized.iter().take(3) {
        ps_samples.push(s.chars().take(500).collect());
    }

    let preview: String = report.deobfuscated.chars().take(1000).collect();

    let mut summary = serde_json::json!({
        "input": input_path,
        "input_size": input.len(),
        "deobfuscated_size": report.deobfuscated.len(),
        "deobfuscated_preview": preview,
        "downloads": downloads,
        "extracted": {
            "cmd": report.extracted_cmd.len(),
            "powershell": ps_count,
            "powershell_samples": ps_samples,
        },
        "lolbas": lolbas,
        "admin_commands": admin_commands,
        "windows_util_manipulation": windows_util,
        "self_extract": self_extract,
        "traits_capped": traits_capped,
    });
    if let Some(index) = lolbas_index {
        if let serde_json::Value::Object(ref mut obj) = summary {
            obj.insert(
                "lolbas_matches".to_string(),
                serde_json::Value::Array(lolbas_matches(report, index)),
            );
        }
    }
    summary
}

fn extracted_counts(report: &batdeob_core::Report) -> serde_json::Value {
    serde_json::json!({
        "cmd": report.extracted_cmd.len(),
        "powershell": report.extracted_ps1.len(),
        "jscript": report.extracted_jscript.len(),
        "vbs": report.extracted_vbs.len(),
    })
}

fn recovered_counts(report: &batdeob_core::Report) -> serde_json::Value {
    serde_json::json!({
        "pe": report.recovered_pe.len(),
    })
}

fn lolbas_matches(report: &batdeob_core::Report, index: &LolbasIndex) -> Vec<serde_json::Value> {
    let mut matches = Vec::new();
    let commands = command_lines_for_lolbas(report);
    for command in commands {
        for entry in &index.entries {
            if !command_invokes_program(command, &entry.stem) {
                continue;
            }
            let duplicate = matches.iter().any(|item: &serde_json::Value| {
                item.get("name").and_then(|v| v.as_str()) == Some(entry.name.as_str())
                    && item.get("command").and_then(|v| v.as_str()) == Some(command)
            });
            if duplicate {
                continue;
            }
            matches.push(serde_json::json!({
                "name": entry.name,
                "command": command,
                "lolbas_url": entry.url,
                "categories": entry.categories,
                "mitre_ids": entry.mitre_ids,
            }));
        }
    }
    matches
}

fn optional_lolbas_matches(
    report: &batdeob_core::Report,
    lolbas_json: Option<&Path>,
) -> Result<Option<Vec<serde_json::Value>>> {
    let Some(path) = lolbas_json else {
        return Ok(None);
    };
    let index = load_lolbas_index(path)?;
    Ok(Some(lolbas_matches(report, &index)))
}

fn command_lines_for_lolbas(report: &batdeob_core::Report) -> Vec<&str> {
    use batdeob_core::Trait;

    let mut out = Vec::new();
    for t in &report.traits {
        let command = match t {
            Trait::Download { cmd, .. }
            | Trait::UrlLaunch { cmd, .. }
            | Trait::UrlArgument { cmd, .. }
            | Trait::UrlVariable { cmd, .. }
            | Trait::RegistryUrl { cmd, .. }
            | Trait::Lolbas { cmd, .. }
            | Trait::CommandGrouping { cmd, .. }
            | Trait::StartWithVar { cmd, .. }
            | Trait::VarUsed { cmd, .. }
            | Trait::Mshta { cmd }
            | Trait::Rundll32 { cmd, .. }
            | Trait::WindowsUtilManip { cmd, .. }
            | Trait::ManipulatedExec { cmd, .. }
            | Trait::AdminCommand { cmd, .. }
            | Trait::RemoteConnect { cmd, .. }
            | Trait::NetUse { cmd, .. }
            | Trait::SetpFileRedirect { cmd, .. }
            | Trait::UncWebDavC2 { command: cmd, .. }
            | Trait::Persistence { command: cmd, .. }
            | Trait::Enumeration { command: cmd, .. } => Some(cmd.as_str()),
            Trait::WmicProcessCreate { inner_cmd } => Some(inner_cmd.as_str()),
            Trait::CscriptExec { src } | Trait::WscriptExec { src } => Some(src.as_str()),
            Trait::SelfElevation { target, .. } => Some(target.as_str()),
            _ => None,
        };
        let Some(command) = command else {
            continue;
        };
        if !command.is_empty() && !out.contains(&command) {
            out.push(command);
        }
    }
    out
}

fn is_broken_pipe(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::BrokenPipe
}

fn write_line(out: &mut impl Write, line: &str) -> Result<bool> {
    match writeln!(out, "{line}") {
        Ok(()) => Ok(true),
        Err(err) if is_broken_pipe(&err) => Ok(false),
        Err(err) => Err(err).context("write stdout"),
    }
}

fn write_json_line(out: &mut impl Write, value: &serde_json::Value) -> Result<bool> {
    let line = serde_json::to_string(value)?;
    write_line(out, &line)
}

fn emit_analyze_profiles(file: &str, started: Instant) {
    if std::env::var_os("HARRINGTON_PROFILE_DRIVE").is_some() {
        eprintln!(
            "harrington_profile_drive input={} fast_expand_ms=0 total_ms={}",
            file,
            started.elapsed().as_millis()
        );
    }
    if std::env::var_os("HARRINGTON_PROFILE_FINAL").is_some() {
        eprintln!(
            "harrington_profile_final input={} total_ms={}",
            file,
            started.elapsed().as_millis()
        );
    }
}

fn analyze_one(
    out: &mut impl Write,
    file: &str,
    cfg: &batdeob_core::Config,
    options: &batdeob_core::AnalysisOptions,
    jsonl: bool,
    lolbas_json: Option<&Path>,
) -> Result<bool> {
    let started = Instant::now();
    let input = read_input(file)?;
    let report = batdeob_core::analyze_with_options(&input, cfg, options);
    emit_analyze_profiles(file, started);
    let lolbas_matches = optional_lolbas_matches(&report, lolbas_json)?;
    if jsonl {
        let meta = serde_json::json!({
            "kind": "meta",
            "input": file,
            "input_size": input.len(),
            "deobfuscated_size": report.deobfuscated.len(),
            "extracted": extracted_counts(&report),
            "recovered": recovered_counts(&report),
        });
        if !write_json_line(out, &meta)? {
            return Ok(false);
        }
        for t in &report.traits {
            let line = serde_json::json!({"kind": "trait", "trait": t});
            if !write_json_line(out, &line)? {
                return Ok(false);
            }
        }
        if let Some(matches) = lolbas_matches {
            for item in matches {
                let line = serde_json::json!({"kind": "lolbas_match", "match": item});
                if !write_json_line(out, &line)? {
                    return Ok(false);
                }
            }
        }
        let deob_line = serde_json::json!({"kind": "deob", "content": &report.deobfuscated});
        if !write_json_line(out, &deob_line)? {
            return Ok(false);
        }
    } else {
        let mut json = serde_json::json!({
            "deobfuscated": report.deobfuscated,
            "traits": report.traits,
            "extracted": extracted_counts(&report),
            "recovered": recovered_counts(&report),
        });
        if let Some(matches) = lolbas_matches {
            if let serde_json::Value::Object(ref mut obj) = json {
                obj.insert(
                    "lolbas_matches".to_string(),
                    serde_json::Value::Array(matches),
                );
            }
        }
        if !write_line(out, &serde_json::to_string_pretty(&json)?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn run() -> Result<()> {
    let cli = parse_cli();
    match cli.command {
        Command::Summarize {
            file,
            env,
            env_file,
            lolbas_json,
        } => {
            let input = read_input(&file)?;
            let cfg = batdeob_core::Config::default();
            let options = make_analysis_options(&env, &env_file)?;
            let report = batdeob_core::analyze_with_options(&input, &cfg, &options);
            let lolbas_index = lolbas_json.as_deref().map(load_lolbas_index).transpose()?;
            let summary = build_summary(&file, &input, &report, lolbas_index.as_ref());
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::Report {
            file,
            include_source,
            include_deob,
            max_depth,
            max_iterations,
            max_child_scripts,
            timeout,
            no_self_extract,
            env,
            env_file,
            max_output_bytes,
            max_output_line_bytes,
            max_traits_per_kind,
            lolbas_json,
        } => {
            let input = read_input(&file)?;
            let cfg = make_config(
                max_depth,
                max_iterations,
                max_child_scripts,
                timeout,
                !no_self_extract,
                max_output_bytes,
                max_output_line_bytes,
                max_traits_per_kind,
            );
            let options = make_analysis_options(&env, &env_file)?;
            let report = batdeob_core::analyze_with_options(&input, &cfg, &options);

            // Start from the analyst-friendly summary, then layer the full
            // typed trait list and any opt-in raw text on top.
            let lolbas_index = lolbas_json.as_deref().map(load_lolbas_index).transpose()?;
            let mut value = build_summary(&file, &input, &report, lolbas_index.as_ref());
            if let serde_json::Value::Object(ref mut obj) = value {
                let input_sha256 = {
                    let mut h = Sha256::new();
                    h.update(&input);
                    hex::encode(h.finalize())
                };
                obj.insert(
                    "input_sha256".to_string(),
                    serde_json::Value::String(input_sha256),
                );
                obj.insert("traits".to_string(), serde_json::to_value(&report.traits)?);
                if include_source {
                    obj.insert(
                        "source".to_string(),
                        serde_json::Value::String(String::from_utf8_lossy(&input).into_owned()),
                    );
                }
                if include_deob {
                    obj.insert(
                        "deobfuscated".to_string(),
                        serde_json::Value::String(report.deobfuscated.clone()),
                    );
                }
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Command::Version => {
            println!("batdeob {}", batdeob_core::version());
        }
        Command::Analyze {
            file,
            file_list,
            max_depth,
            max_iterations,
            max_child_scripts,
            timeout,
            no_self_extract,
            env,
            env_file,
            max_output_bytes,
            max_output_line_bytes,
            max_traits_per_kind,
            jsonl,
            lolbas_json,
        } => {
            let cfg = make_config(
                max_depth,
                max_iterations,
                max_child_scripts,
                timeout,
                !no_self_extract,
                max_output_bytes,
                max_output_line_bytes,
                max_traits_per_kind,
            );
            let options = make_analysis_options(&env, &env_file)?;
            let mut inputs = file;
            if let Some(path) = file_list {
                if !jsonl {
                    anyhow::bail!("analyze --file-list requires --jsonl");
                }
                inputs.extend(read_file_list(&path)?);
            }
            if inputs.is_empty() {
                anyhow::bail!("analyze requires at least one input");
            }
            if inputs.len() > 1 && !jsonl {
                anyhow::bail!("multiple analyze inputs require --jsonl");
            }
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for file in inputs {
                if !analyze_one(
                    &mut out,
                    &file,
                    &cfg,
                    &options,
                    jsonl,
                    lolbas_json.as_deref(),
                )? {
                    break;
                }
            }
        }
        Command::Deob {
            file,
            out_dir,
            json,
            json_only,
            force,
            lolbas_json,
            max_depth,
            max_iterations,
            max_child_scripts,
            timeout,
            no_self_extract,
            env,
            env_file,
            max_output_bytes,
            max_output_line_bytes,
            max_traits_per_kind,
        } => {
            let input = read_input(&file)?;
            let cfg = make_config(
                max_depth,
                max_iterations,
                max_child_scripts,
                timeout,
                !no_self_extract,
                max_output_bytes,
                max_output_line_bytes,
                max_traits_per_kind,
            );
            let options = make_analysis_options(&env, &env_file)?;
            let report = batdeob_core::analyze_with_options(&input, &cfg, &options);
            if !json_only {
                write_report_files(&report, &out_dir, force)?;
            }
            if json || json_only {
                let lolbas_matches = optional_lolbas_matches(&report, lolbas_json.as_deref())?;
                let mut val = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
                    "extracted": extracted_counts(&report),
                    "recovered": recovered_counts(&report),
                });
                if let Some(matches) = lolbas_matches {
                    if let serde_json::Value::Object(ref mut obj) = val {
                        obj.insert(
                            "lolbas_matches".to_string(),
                            serde_json::Value::Array(matches),
                        );
                    }
                }
                println!("{}", serde_json::to_string_pretty(&val)?);
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("batdeob: {:#}", e);
        std::process::exit(2);
    }
}
