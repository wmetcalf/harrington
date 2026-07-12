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
        /// Emit a human-readable TLDR instead of JSON.
        #[arg(long)]
        tldr: bool,
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
        /// Write deobfuscated output, extracted children, and recovered artifacts to this directory.
        #[arg(short = 'o', long = "out-dir")]
        out_dir: Option<PathBuf>,
        /// Replace batdeob-generated files in an existing output directory.
        #[arg(long)]
        force: bool,
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
        if !meta.file_type().is_file() {
            anyhow::bail!("{:?}: input is not a regular file", path);
        }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
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

fn basic_output_file(kind: &str, name: &str, path: &Path, size: usize) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "name": name,
        "path": path.display().to_string(),
        "size": size,
    })
}

fn extracted_output_file(
    kind: &str,
    name: &str,
    path: &Path,
    size: usize,
    sha256_prefix: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "name": name,
        "path": path.display().to_string(),
        "size": size,
        "sha256_prefix": sha256_prefix,
    })
}

struct RecoveredOutputFile<'a> {
    origin: &'a str,
    format: &'a str,
    name: &'a str,
    path: &'a Path,
    meta_name: &'a str,
    meta_path: &'a Path,
    size: usize,
    sha256_prefix: &'a str,
}

fn recovered_output_file(file: RecoveredOutputFile<'_>) -> serde_json::Value {
    serde_json::json!({
        "kind": recovered_artifact_kind(file.format, file.origin),
        "format": file.format,
        "origin": file.origin,
        "name": file.name,
        "path": file.path.display().to_string(),
        "meta_name": file.meta_name,
        "meta_path": file.meta_path.display().to_string(),
        "size": file.size,
        "sha256_prefix": file.sha256_prefix,
    })
}

fn recovered_artifact_kind(format: &str, origin: &str) -> &'static str {
    if origin.contains("shellcode") {
        return "shellcode";
    }
    match format {
        "exe" => "pe",
        "py" => "script",
        "cab" => "cab",
        "zip" | "rar" | "7z" => "archive",
        "pdf" => "pdf",
        "png" | "gif" | "jpg" => "image",
        _ => "blob",
    }
}

fn report_traits_json_value(report: &batdeob_core::Report) -> Result<serde_json::Value> {
    let bindings = deob_set_bindings(&report.deobfuscated);
    traits_json_value_with_bindings(&report.traits, &bindings)
}

fn traits_json_value_with_bindings(
    traits: &[batdeob_core::Trait],
    bindings: &std::collections::BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    traits
        .iter()
        .map(|trait_| trait_json_value_with_bindings(trait_, bindings))
        .collect::<Result<Vec<_>>>()
        .map(serde_json::Value::Array)
}

fn trait_json_value(trait_: &batdeob_core::Trait) -> Result<serde_json::Value> {
    trait_json_value_with_bindings(trait_, &std::collections::BTreeMap::new())
}

fn trait_json_value_with_bindings(
    trait_: &batdeob_core::Trait,
    bindings: &std::collections::BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(trait_)?;
    stringify_printable_byte_arrays(&mut value);
    render_known_trait_strings(&mut value, bindings);
    summarize_bulk_trait_content(&mut value);
    summarize_large_json_strings(&mut value);
    Ok(value)
}

fn render_known_trait_strings(
    value: &mut serde_json::Value,
    bindings: &std::collections::BTreeMap<String, String>,
) {
    if bindings.is_empty() {
        return;
    }
    match value {
        serde_json::Value::Object(obj) => {
            for (key, child) in obj {
                if matches!(
                    key.as_str(),
                    "src" | "dst" | "target" | "cmd" | "command" | "inner_cmd"
                ) {
                    if let Some(text) = child.as_str() {
                        *child = serde_json::Value::String(render_known_variables(text, bindings));
                        continue;
                    }
                }
                render_known_trait_strings(child, bindings);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                render_known_trait_strings(item, bindings);
            }
        }
        _ => {}
    }
}

fn summarize_bulk_trait_content(value: &mut serde_json::Value) {
    const MAX_INLINE_CONTENT_BYTES: usize = 1024;
    let serde_json::Value::Object(obj) = value else {
        return;
    };
    let Some(kind) = obj.get("kind").and_then(serde_json::Value::as_str) else {
        return;
    };
    if kind != "EchoRedirect" {
        return;
    }
    let Some(content) = obj.get_mut("content") else {
        return;
    };
    if let Some(text) = content.as_str() {
        if text.len() > MAX_INLINE_CONTENT_BYTES {
            let preview: String = text.chars().take(256).collect();
            *content = serde_json::json!({
                "omitted": true,
                "size": text.len(),
                "sha256_prefix": short_sha(text.as_bytes()),
                "preview": preview,
            });
        }
        return;
    }
    if let Some(bytes) = json_byte_array(content) {
        if bytes.len() > MAX_INLINE_CONTENT_BYTES {
            *content = serde_json::json!({
                "omitted": true,
                "size": bytes.len(),
                "sha256_prefix": short_sha(&bytes),
            });
        }
    }
}

fn summarize_large_json_strings(value: &mut serde_json::Value) {
    const MAX_INLINE_STRING_BYTES: usize = 8 * 1024;
    match value {
        serde_json::Value::String(text) if text.len() > MAX_INLINE_STRING_BYTES => {
            let preview: String = text.chars().take(256).collect();
            *value = serde_json::json!({
                "omitted": true,
                "size": text.len(),
                "sha256_prefix": short_sha(text.as_bytes()),
                "preview": preview,
            });
        }
        serde_json::Value::Object(obj) => {
            for child in obj.values_mut() {
                summarize_large_json_strings(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                summarize_large_json_strings(child);
            }
        }
        _ => {}
    }
}

fn stringify_printable_byte_arrays(value: &mut serde_json::Value) {
    if let Some(text) = printable_json_byte_array(value) {
        *value = serde_json::Value::String(text);
        return;
    }
    match value {
        serde_json::Value::Object(obj) => {
            for child in obj.values_mut() {
                stringify_printable_byte_arrays(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                stringify_printable_byte_arrays(child);
            }
        }
        _ => {}
    }
}

fn printable_json_byte_array(value: &serde_json::Value) -> Option<String> {
    let bytes = json_byte_array(value)?;
    if bytes.is_empty() {
        return None;
    }
    printable_text_bytes(&bytes)
}

fn json_byte_array(value: &serde_json::Value) -> Option<Vec<u8>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}

fn printable_text_bytes(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    if text
        .bytes()
        .all(|byte| matches!(byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
    {
        Some(text.to_string())
    } else {
        None
    }
}

fn write_report_files(
    report: &batdeob_core::Report,
    out_dir: &Path,
    force: bool,
) -> Result<serde_json::Value> {
    fs::create_dir_all(out_dir).with_context(|| format!("mkdir {:?}", out_dir))?;
    let canonical_out =
        fs::canonicalize(out_dir).with_context(|| format!("canonicalize {:?}", out_dir))?;
    if force {
        remove_stale_generated_outputs(&canonical_out)?;
    }

    let mut extracted_files = Vec::new();
    let mut recovered_files = Vec::new();

    let deob_name = "deobfuscated.bat";
    let deob_path = safe_join(&canonical_out, deob_name)?;
    safe_write(&deob_path, report.deobfuscated.as_bytes(), force)?;
    let deobfuscated_file = basic_output_file(
        "deobfuscated",
        deob_name,
        &deob_path,
        report.deobfuscated.len(),
    );

    let mut seen = std::collections::HashSet::new();
    for child in &report.extracted_cmd {
        let bytes = child.as_bytes();
        let sha = short_sha(bytes);
        if !seen.insert(sha.clone()) {
            continue;
        }
        let name = format!("{sha}.bat");
        let path = safe_join(&canonical_out, &name)?;
        safe_write(&path, bytes, force)?;
        extracted_files.push(extracted_output_file(
            "cmd",
            &name,
            &path,
            bytes.len(),
            &sha,
        ));
    }
    for (idx, child) in report.extracted_ps1.iter().enumerate() {
        let sha = short_sha(child);
        let name = format!("{sha}.ps1");
        if !seen.insert(name.clone()) {
            continue;
        }
        let path = safe_join(&canonical_out, &name)?;
        safe_write(&path, child, force)?;
        extracted_files.push(extracted_output_file(
            "powershell",
            &name,
            &path,
            child.len(),
            &sha,
        ));
        if let Some(normalized) = report.extracted_ps1_normalized.get(idx) {
            let raw_text = String::from_utf8_lossy(child);
            if normalized != raw_text.as_ref() {
                let name = format!("{sha}.normalized.ps1");
                if seen.insert(name.clone()) {
                    let path = safe_join(&canonical_out, &name)?;
                    safe_write(&path, normalized.as_bytes(), force)?;
                    extracted_files.push(extracted_output_file(
                        "powershell_normalized",
                        &name,
                        &path,
                        normalized.len(),
                        &sha,
                    ));
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
        let path = safe_join(&canonical_out, &name)?;
        safe_write(&path, child, force)?;
        extracted_files.push(extracted_output_file(
            "jscript",
            &name,
            &path,
            child.len(),
            &sha,
        ));
    }
    for child in &report.extracted_vbs {
        let sha = short_sha(child);
        let name = format!("{sha}.vbs");
        if !seen.insert(name.clone()) {
            continue;
        }
        let path = safe_join(&canonical_out, &name)?;
        safe_write(&path, child, force)?;
        extracted_files.push(extracted_output_file(
            "vbs",
            &name,
            &path,
            child.len(),
            &sha,
        ));
    }
    for (label, blob) in &report.recovered_pe {
        let bytes = blob.as_slice();
        let sha = short_sha(bytes);
        let ext = detect_blob_extension(bytes);
        let name = format!("{sha}.{ext}");
        if !seen.insert(name.clone()) {
            continue;
        }
        let path = safe_join(&canonical_out, &name)?;
        safe_write(&path, bytes, force)?;

        let meta_name = format!("{sha}.meta");
        if seen.insert(meta_name.clone()) {
            let meta_path = safe_join(&canonical_out, &meta_name)?;
            let meta = format!(
                "origin: {label}\nsize: {}\nsha256-prefix: {sha}\n",
                bytes.len()
            );
            safe_write(&meta_path, meta.as_bytes(), force)?;
            recovered_files.push(recovered_output_file(RecoveredOutputFile {
                origin: label,
                format: ext,
                name: &name,
                path: &path,
                meta_name: &meta_name,
                meta_path: &meta_path,
                size: bytes.len(),
                sha256_prefix: &sha,
            }));
        }
    }

    let traits_json = serde_json::to_string_pretty(&report_traits_json_value(report)?)?;
    let traits_name = "traits.json";
    let traits_path = safe_join(&canonical_out, traits_name)?;
    safe_write(&traits_path, traits_json.as_bytes(), force)?;
    let traits_file = basic_output_file("traits", traits_name, &traits_path, traits_json.len());

    Ok(serde_json::json!({
        "out_dir": canonical_out.display().to_string(),
        "deobfuscated": deobfuscated_file,
        "traits": traits_file,
        "extracted": extracted_files,
        "recovered": recovered_files,
    }))
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
    if looks_like_python_script_bytes(bytes) {
        return "py";
    }
    "bin"
}

fn looks_like_python_script_bytes(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    let has_python_import = lower.contains("import ")
        || lower.contains("__import__(")
        || lower.contains("from base64 import")
        || lower.contains("from urllib");
    let has_python_exec_or_decode = lower.contains("exec(")
        || lower.contains("marshal.loads")
        || lower.contains("zlib.decompress")
        || lower.contains("base64.b64decode")
        || lower.contains(".b85decode")
        || lower.contains("requests.")
        || lower.contains("urllib.request");
    has_python_import && has_python_exec_or_decode
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
            | Trait::ReExpansionDepthCapped { .. }
            | Trait::ChildScriptsCapped
            | Trait::TimeoutHit
            | Trait::IterationCapped { .. } => {
                traits_capped.push(serde_json::to_value(t).expect("trait serializes"));
            }
            _ => {}
        }
    }

    let ps_count = report.extracted_ps1.len();

    let mut summary = serde_json::json!({
        "input": input_path,
        "input_size": input.len(),
        "deobfuscated_size": report.deobfuscated.len(),
        "downloads": downloads,
        "extracted": {
            "cmd": report.extracted_cmd.len(),
            "powershell": ps_count,
            "jscript": report.extracted_jscript.len(),
            "vbs": report.extracted_vbs.len(),
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

fn lossy_payloads(payloads: &[Vec<u8>]) -> Vec<String> {
    dedup_strings(
        payloads
            .iter()
            .map(|payload| String::from_utf8_lossy(payload).into_owned()),
    )
}

fn dedup_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn ps_flag_value(text: &str, flag: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let flag_lower = flag.to_ascii_lowercase();
    let mut search = 0usize;
    while let Some(rel) = lower[search..].find(&flag_lower) {
        let start = search + rel;
        let end = start + flag_lower.len();
        let prev_ok = start == 0
            || lower.as_bytes()[start - 1].is_ascii_whitespace()
            || matches!(lower.as_bytes()[start - 1], b'{' | b';');
        let next_ok = lower
            .as_bytes()
            .get(end)
            .map_or(true, |byte| byte.is_ascii_whitespace());
        if !prev_ok || !next_ok {
            search = end;
            continue;
        }

        let mut value_start = end;
        while text
            .as_bytes()
            .get(value_start)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            value_start += 1;
        }
        let first = *text.as_bytes().get(value_start)?;
        if matches!(first, b'\'' | b'"') {
            let quote = first;
            let body_start = value_start + 1;
            let body_end = text.as_bytes()[body_start..]
                .iter()
                .position(|&byte| byte == quote)
                .map(|idx| body_start + idx)?;
            return Some(text[body_start..body_end].to_string());
        }
        let value_end = text.as_bytes()[value_start..]
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || matches!(*byte, b';' | b'}'))
            .map(|idx| value_start + idx)
            .unwrap_or(text.len());
        return Some(text[value_start..value_end].to_string());
    }
    None
}

fn filter_empty_powershell_file_arg_duplicates(payloads: Vec<String>) -> Vec<String> {
    let mut non_empty_download_uris = std::collections::HashSet::new();
    for payload in &payloads {
        let Some(uri) = ps_flag_value(payload, "-Uri") else {
            continue;
        };
        let Some(outfile) = ps_flag_value(payload, "-OutFile") else {
            continue;
        };
        if !uri.is_empty() && !outfile.is_empty() {
            non_empty_download_uris.insert(uri.to_ascii_lowercase());
        }
    }

    payloads
        .into_iter()
        .filter(|payload| {
            if is_empty_expand_archive_preview(payload) {
                return false;
            }
            if let (Some(uri), Some(outfile)) = (
                ps_flag_value(payload, "-Uri"),
                ps_flag_value(payload, "-OutFile"),
            ) {
                return !outfile.is_empty()
                    || !non_empty_download_uris.contains(&uri.to_ascii_lowercase());
            }
            true
        })
        .collect()
}

fn is_empty_expand_archive_preview(payload: &str) -> bool {
    let lower = payload.to_ascii_lowercase();
    if !lower.contains("expand-archive") {
        return false;
    }
    let path = ps_flag_value(payload, "-Path").unwrap_or_default();
    let destination = ps_flag_value(payload, "-DestinationPath").unwrap_or_default();
    if path.trim().is_empty() && destination.trim().is_empty() {
        return true;
    }
    path.to_ascii_lowercase().contains("-destinationpath")
        && destination.trim().is_empty()
        && !payload.contains('\\')
        && !payload.contains('/')
}

fn deob_set_bindings(deobfuscated: &str) -> std::collections::BTreeMap<String, String> {
    let baseline = batdeob_core::env::Environment::new(&batdeob_core::env::Config::default());
    let mut bindings = baseline
        .vars_iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    for line in deobfuscated.lines() {
        let line = line.trim().trim_start_matches('@').trim_start();
        let Some(rest) = line.get(3..) else {
            continue;
        };
        if !line[..3].eq_ignore_ascii_case("set")
            || rest
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        {
            continue;
        }
        let body = rest.trim_start();
        let body = body
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(body);
        let Some((name, value)) = body.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() {
            bindings.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }
    bindings
}

fn render_known_batch_variables(
    text: &str,
    bindings: &std::collections::BTreeMap<String, String>,
) -> String {
    if bindings.is_empty() || !text.contains('%') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        let Some(rel) = text[i..].find('%') else {
            out.push_str(&text[i..]);
            break;
        };
        let start = i + rel;
        out.push_str(&text[i..start]);
        let name_start = start + 1;
        let Some(end_rel) = text[name_start..].find('%') else {
            out.push_str(&text[start..]);
            break;
        };
        let end = name_start + end_rel;
        let name = &text[name_start..end];
        if !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'(' | b')'))
        {
            if let Some(value) = bindings.get(&name.to_ascii_lowercase()) {
                out.push_str(value);
            } else {
                out.push_str(&text[start..=end]);
            }
        } else {
            out.push_str(&text[start..=end]);
        }
        i = end + 1;
    }
    out
}

fn render_known_delayed_variables(
    text: &str,
    bindings: &std::collections::BTreeMap<String, String>,
) -> String {
    if bindings.is_empty() || !text.contains('!') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < text.len() {
        let Some(rel) = text[i..].find('!') else {
            out.push_str(&text[i..]);
            break;
        };
        let start = i + rel;
        out.push_str(&text[i..start]);
        let name_start = start + 1;
        let Some(end_rel) = text[name_start..].find('!') else {
            out.push_str(&text[start..]);
            break;
        };
        let end = name_start + end_rel;
        let name = &text[name_start..end];
        if !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'(' | b')'))
        {
            if let Some(value) = bindings.get(&name.to_ascii_lowercase()) {
                out.push_str(value);
            } else {
                out.push_str(&text[start..=end]);
            }
        } else {
            out.push_str(&text[start..=end]);
        }
        i = end + 1;
    }
    out
}

fn render_known_variables(
    text: &str,
    bindings: &std::collections::BTreeMap<String, String>,
) -> String {
    let rendered = render_known_batch_variables(text, bindings);
    render_known_delayed_variables(&rendered, bindings)
}

fn deob_cmd_targets(deobfuscated: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in deobfuscated.lines() {
        let trimmed = line.trim().trim_start_matches('@').trim_start();
        let lower = trimmed.to_ascii_lowercase();
        let target = if lower.starts_with("cmd.exe /c ") {
            trimmed[11..].trim().to_string()
        } else if lower.starts_with("cmd /c ") {
            trimmed[7..].trim().to_string()
        } else {
            continue;
        };
        if !target.is_empty() && seen.insert(target.to_ascii_lowercase()) {
            out.push(target);
        }
    }
    out
}

fn unresolved_adjacent_var_path_suffix(text: &str) -> Option<&str> {
    let text = text.trim();
    let mut i = usize::from(text.starts_with('"'));
    let mut consumed_var = false;
    while i < text.len() {
        let marker = text.as_bytes()[i];
        if marker != b'%' && marker != b'!' {
            break;
        }
        let end_rel = text[i + 1..].find(marker as char)?;
        let end = i + 1 + end_rel;
        let name = &text[i + 1..end];
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'(' | b')'))
        {
            return None;
        }
        consumed_var = true;
        i = end + 1;
    }
    let suffix = text.get(i..)?;
    if consumed_var
        && suffix.len() >= 4
        && suffix.bytes().any(|b| b == b'.' || b == b'\\' || b == b'/')
    {
        Some(suffix)
    } else {
        None
    }
}

fn render_cmd_payload(
    payload: String,
    bindings: &std::collections::BTreeMap<String, String>,
    deob_cmd_targets: &[String],
) -> String {
    let rendered = render_known_variables(&payload, bindings);
    if !rendered.contains('%') && !rendered.contains('!') {
        return rendered;
    }
    let Some(suffix) = unresolved_adjacent_var_path_suffix(&rendered) else {
        return rendered;
    };
    let suffix_lower = suffix.to_ascii_lowercase();
    let matches = deob_cmd_targets
        .iter()
        .filter(|target| target.to_ascii_lowercase().ends_with(&suffix_lower))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        matches[0].to_string()
    } else {
        rendered
    }
}

fn rendered_cmd_payloads(
    payloads: &[String],
    bindings: &std::collections::BTreeMap<String, String>,
    deob_cmd_targets: &[String],
) -> Vec<String> {
    dedup_strings(
        payloads
            .iter()
            .cloned()
            .map(|payload| render_cmd_payload(payload, bindings, deob_cmd_targets)),
    )
}

fn rendered_powershell_payloads(
    payloads: &[Vec<u8>],
    bindings: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    filter_empty_powershell_file_arg_duplicates(dedup_strings(
        payloads
            .iter()
            .map(|payload| render_known_variables(&String::from_utf8_lossy(payload), bindings)),
    ))
}

fn rendered_powershell_normalized(
    payloads: &[String],
    bindings: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    filter_empty_powershell_file_arg_duplicates(dedup_strings(
        payloads
            .iter()
            .map(|payload| render_known_variables(payload, bindings)),
    ))
}

fn extracted_payloads(report: &batdeob_core::Report) -> serde_json::Value {
    let bindings = deob_set_bindings(&report.deobfuscated);
    let deob_cmd_targets = deob_cmd_targets(&report.deobfuscated);
    serde_json::json!({
        "cmd": rendered_cmd_payloads(&report.extracted_cmd, &bindings, &deob_cmd_targets),
        "powershell": rendered_powershell_payloads(&report.extracted_ps1, &bindings),
        "powershell_normalized": rendered_powershell_normalized(&report.extracted_ps1_normalized, &bindings),
        "jscript": lossy_payloads(&report.extracted_jscript),
        "vbs": lossy_payloads(&report.extracted_vbs),
    })
}

fn recovered_counts(report: &batdeob_core::Report) -> serde_json::Value {
    let mut by_format = std::collections::BTreeMap::<&'static str, usize>::new();
    let mut by_kind = std::collections::BTreeMap::<&'static str, usize>::new();
    for (origin, blob) in &report.recovered_pe {
        let format = detect_blob_extension(blob);
        *by_format.entry(format).or_default() += 1;
        *by_kind
            .entry(recovered_artifact_kind(format, origin))
            .or_default() += 1;
    }
    serde_json::json!({
        "total": report.recovered_pe.len(),
        "pe": by_kind.get("pe").copied().unwrap_or(0),
        "by_format": by_format,
        "by_kind": by_kind,
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

fn build_tldr(file: &str, input: &[u8], report: &batdeob_core::Report) -> String {
    use batdeob_core::Trait;
    use std::collections::BTreeSet;

    let mut urls = BTreeSet::new();
    let mut unc = BTreeSet::new();
    let mut remote_connect = BTreeSet::new();
    let mut disguised = BTreeSet::new();
    let mut extrac32_self = BTreeSet::new();
    let mut persist = BTreeSet::new();
    let mut evasion = BTreeSet::new();
    let mut lateral = BTreeSet::new();
    let mut inmem = BTreeSet::new();
    let mut aes_findings = BTreeSet::new();
    let mut probes = BTreeSet::new();
    let mut enumeration = BTreeSet::new();
    let mut cred_access = BTreeSet::new();
    let mut injection = BTreeSet::new();
    let mut input_cap = BTreeSet::new();
    let mut remote_exec = BTreeSet::new();
    let mut shellcode = BTreeSet::new();
    let mut uac_bypass = BTreeSet::new();
    let mut svc_install = BTreeSet::new();
    let mut beacon_sleep = BTreeSet::new();
    let mut ransom_ext = BTreeSet::new();
    let mut anti_recov = BTreeSet::new();
    let mut self_elev = BTreeSet::new();
    let mut self_extract = false;

    for t in &report.traits {
        match t {
            Trait::Download { src, .. } | Trait::DownloadInDeobText { src, .. } => {
                urls.insert(src.clone());
            }
            Trait::CertutilDownload { url, .. }
            | Trait::BitsadminDownload { url, .. }
            | Trait::UrlLaunch { url, .. }
            | Trait::UrlArgument { url, .. }
            | Trait::UrlVariable { url, .. }
            | Trait::RegistryUrl { url, .. } => {
                urls.insert(url.clone());
            }
            Trait::UncWebDavC2 { share_path, .. } => {
                unc.insert(share_path.clone());
            }
            Trait::RemoteConnect { host, port, .. } => {
                remote_connect.insert(format!("{host}:{port}"));
            }
            Trait::DisguisedBinary { format, size } => {
                disguised.insert(format!("{format} ({size} bytes)"));
            }
            Trait::Extrac32 {
                src,
                dst,
                self_reference,
            } if *self_reference => {
                extrac32_self.insert(format!("{src} -> {dst}"));
            }
            Trait::Persistence {
                hive,
                key,
                value_name,
                command,
            } => {
                let value = if value_name.is_empty() {
                    String::new()
                } else {
                    format!(" /v {value_name}")
                };
                let command = if command.is_empty() {
                    "(no command)"
                } else {
                    command
                };
                persist.insert(format!("{hive}\\{key}{value} -> {command}"));
            }
            Trait::DefenderEvasion { action, target } => {
                if target.is_empty() {
                    evasion.insert(action.clone());
                } else {
                    evasion.insert(format!("{action} {target}"));
                }
            }
            Trait::LateralMovement { tool, target_host } => {
                lateral.insert(format!("{tool} -> {target_host}"));
            }
            Trait::InMemoryAssemblyLoad { variant } => {
                inmem.insert(variant.clone());
            }
            Trait::MultiStageEncryptedDropper {
                aes_key_b64,
                aes_iv_b64,
                assemblies_recovered,
                ..
            } => {
                if let (Some(key), Some(iv)) = (aes_key_b64, aes_iv_b64) {
                    let key_prefix: String = key.chars().take(16).collect();
                    let iv_prefix: String = iv.chars().take(16).collect();
                    aes_findings.insert(format!(
                        "key={key_prefix}... iv={iv_prefix}... asm={}",
                        assemblies_recovered.unwrap_or(0)
                    ));
                }
            }
            Trait::NetworkProbe { probe_kind, target } => {
                probes.insert(format!("{probe_kind}={target}"));
            }
            Trait::Enumeration { enum_kind, .. } => {
                enumeration.insert(enum_kind.clone());
            }
            Trait::CredentialAccess { technique, target } => {
                let target: String = target.chars().take(60).collect();
                cred_access.insert(format!("{technique}: {target}"));
            }
            Trait::ProcessInjection { api } => {
                injection.insert(api.clone());
            }
            Trait::InputCapture { capture_kind } => {
                input_cap.insert(capture_kind.clone());
            }
            Trait::RemoteExec { tool, target_host } => {
                remote_exec.insert(format!("{tool} -> {target_host}"));
            }
            Trait::ShellcodeMarker { evidence } => {
                shellcode.insert(evidence.clone());
            }
            Trait::UacBypass { technique } => {
                uac_bypass.insert(technique.clone());
            }
            Trait::ServiceInstall {
                service_name,
                bin_path,
            } => {
                if bin_path.is_empty() {
                    svc_install.insert(service_name.clone());
                } else {
                    svc_install.insert(format!("{service_name} -> {bin_path}"));
                }
            }
            Trait::BeaconSleep { seconds } => {
                beacon_sleep.insert(format!("{seconds}s"));
            }
            Trait::RansomFileExtension { extension } => {
                ransom_ext.insert(extension.clone());
            }
            Trait::AntiRecovery { action } => {
                anti_recov.insert(action.clone());
            }
            Trait::SelfElevation { target, .. } => {
                self_elev.insert(target.clone());
            }
            Trait::SelfExtract { .. } => {
                self_extract = true;
            }
            _ => {}
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "== {file} ({} bytes, {}) ==\n",
        input.len(),
        short_sha(input)
    ));

    fn emit_line(out: &mut String, label: &str, items: BTreeSet<String>) {
        if items.is_empty() {
            return;
        }
        let joined = items.into_iter().take(6).collect::<Vec<_>>().join("; ");
        out.push_str(&format!("  {label}: {joined}\n"));
    }

    emit_line(&mut out, "URLs", urls);
    emit_line(&mut out, "UNC", unc);
    emit_line(&mut out, "C2 connect", remote_connect);
    emit_line(&mut out, "Disguised binary", disguised);
    emit_line(&mut out, "Self-extract (extrac32 %~f0)", extrac32_self);
    if !report.recovered_pe.is_empty() {
        out.push_str(&format!(
            "  Recovered PE blobs: {} (run `deob -o <dir>` to dump)\n",
            report.recovered_pe.len()
        ));
    }
    emit_line(&mut out, "Persistence", persist);
    if self_extract {
        out.push_str("  Self-extract: yes\n");
    }
    emit_line(&mut out, "Self-elevation", self_elev);
    emit_line(&mut out, "AV evasion", evasion);
    emit_line(&mut out, "Lateral", lateral);
    emit_line(&mut out, "In-memory load", inmem);
    emit_line(&mut out, "AES dropper", aes_findings);
    emit_line(&mut out, "Network probe", probes);
    emit_line(&mut out, "Enumeration", enumeration);
    emit_line(&mut out, "Cred access", cred_access);
    emit_line(&mut out, "Process injection", injection);
    emit_line(&mut out, "Input capture", input_cap);
    emit_line(&mut out, "Remote exec", remote_exec);
    emit_line(&mut out, "Shellcode marker", shellcode);
    emit_line(&mut out, "UAC bypass", uac_bypass);
    emit_line(&mut out, "Service install", svc_install);
    emit_line(&mut out, "Beacon sleep", beacon_sleep);
    emit_line(&mut out, "Ransom file ext", ransom_ext);
    emit_line(&mut out, "Anti-recovery", anti_recov);

    if out.lines().count() <= 1 {
        out.push_str("  (no notable IOCs surfaced)\n");
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
    let report = analyze_cli_input(file, &input, cfg, options);
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
            let line = serde_json::json!({"kind": "trait", "trait": trait_json_value(t)?});
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
            "extracted": extracted_counts(&report),
            "recovered": recovered_counts(&report),
        });
        if let serde_json::Value::Object(ref mut obj) = json {
            obj.insert("traits".to_string(), report_traits_json_value(&report)?);
        }
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

fn analyze_cli_input(
    file: &str,
    input: &[u8],
    cfg: &batdeob_core::Config,
    options: &batdeob_core::AnalysisOptions,
) -> batdeob_core::Report {
    if file == "-" {
        batdeob_core::analyze_with_options(input, cfg, options)
    } else {
        batdeob_core::analyze_with_path_and_options(input, cfg, file, options)
    }
}

fn run() -> Result<()> {
    let cli = parse_cli();
    match cli.command {
        Command::Summarize {
            file,
            tldr,
            env,
            env_file,
            lolbas_json,
        } => {
            let input = read_input(&file)?;
            let cfg = batdeob_core::Config::default();
            let options = make_analysis_options(&env, &env_file)?;
            let report = analyze_cli_input(&file, &input, &cfg, &options);
            if tldr {
                print!("{}", build_tldr(&file, &input, &report));
            } else {
                let lolbas_index = lolbas_json.as_deref().map(load_lolbas_index).transpose()?;
                let summary = build_summary(&file, &input, &report, lolbas_index.as_ref());
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
        }
        Command::Report {
            file,
            out_dir,
            force,
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
            let report = analyze_cli_input(&file, &input, &cfg, &options);
            let output_files = out_dir
                .as_deref()
                .map(|out_dir| write_report_files(&report, out_dir, force))
                .transpose()?;

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
                obj.insert("recovered".to_string(), recovered_counts(&report));
                obj.insert("traits".to_string(), report_traits_json_value(&report)?);
                if let Some(output_files) = output_files {
                    obj.insert("output_files".to_string(), output_files);
                }
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
                    obj.insert(
                        "extracted_payloads".to_string(),
                        extracted_payloads(&report),
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
            let report = analyze_cli_input(&file, &input, &cfg, &options);
            let output_files = if json_only {
                None
            } else {
                Some(write_report_files(&report, &out_dir, force)?)
            };
            if json || json_only {
                let lolbas_matches = optional_lolbas_matches(&report, lolbas_json.as_deref())?;
                let mut val = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "extracted": extracted_counts(&report),
                    "recovered": recovered_counts(&report),
                });
                if let serde_json::Value::Object(ref mut obj) = val {
                    obj.insert("traits".to_string(), report_traits_json_value(&report)?);
                }
                if let Some(output_files) = output_files {
                    if let serde_json::Value::Object(ref mut obj) = val {
                        obj.insert("output_files".to_string(), output_files);
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::{
        deob_set_bindings, read_input, recovered_artifact_kind, safe_write,
        stringify_printable_byte_arrays, trait_json_value, trait_json_value_with_bindings,
    };

    #[cfg(unix)]
    #[test]
    fn read_input_rejects_non_regular_paths() {
        assert!(read_input("/dev/null").is_err());
    }

    #[test]
    fn printable_byte_array_rendering_is_field_name_agnostic() {
        let mut value = serde_json::json!({
            "payload": [65, 66, 67, 13, 10],
            "nested": {
                "bytes": [67, 77, 68]
            },
            "empty": [],
            "not_bytes": [300],
        });

        stringify_printable_byte_arrays(&mut value);

        assert_eq!(value["payload"].as_str(), Some("ABC\r\n"));
        assert_eq!(value["nested"]["bytes"].as_str(), Some("CMD"));
        assert!(value["empty"].as_array().is_some());
        assert!(value["not_bytes"].as_array().is_some());
    }

    #[test]
    fn recovered_bin_shellcode_origins_are_typed_as_shellcode() {
        assert_eq!(
            recovered_artifact_kind("bin", "ps1-aes-shellcode-1"),
            "shellcode"
        );
        assert_eq!(
            recovered_artifact_kind("bin", "ps1-xor-shellcode-1"),
            "shellcode"
        );
        assert_eq!(recovered_artifact_kind("bin", "opaque-data-1"), "blob");
    }

    #[test]
    fn trait_json_summarizes_large_string_fields() {
        let command = format!("net user {}", "A".repeat(10_000));
        let value = trait_json_value(&batdeob_core::Trait::Enumeration {
            enum_kind: "users".to_string(),
            command,
        })
        .expect("trait json");

        assert_eq!(
            value["command"]["omitted"].as_bool(),
            Some(true),
            "{value:#}"
        );
        assert_eq!(value["command"]["size"].as_u64(), Some(10_009), "{value:#}");
        assert_eq!(
            value["command"]["preview"].as_str().map(str::len),
            Some(256),
            "{value:#}"
        );
        assert!(
            value["command"]["sha256_prefix"].as_str().is_some(),
            "{value:#}"
        );
    }

    #[test]
    fn trait_json_renders_known_environment_paths_without_expanding_batch_meta() {
        let bindings = deob_set_bindings("");
        let value = trait_json_value_with_bindings(
            &batdeob_core::Trait::Extrac32 {
                src: "%~f0".to_string(),
                dst: "%tmp%\\x.exe".to_string(),
                self_reference: true,
            },
            &bindings,
        )
        .expect("trait json");

        assert_eq!(value["src"].as_str(), Some("%~f0"), "{value:#}");
        assert_eq!(
            value["dst"].as_str(),
            Some(r"C:\Users\puncher\AppData\Local\Temp\x.exe"),
            "{value:#}"
        );
    }

    #[test]
    fn trait_json_summarizes_payload_sized_echo_redirect_content() {
        let content = b"A".repeat(4096);
        let value = trait_json_value(&batdeob_core::Trait::EchoRedirect {
            content,
            target: "payload.tmp".to_string(),
            append: true,
        })
        .expect("trait json");

        assert_eq!(
            value["content"]["omitted"].as_bool(),
            Some(true),
            "{value:#}"
        );
        assert_eq!(value["content"]["size"].as_u64(), Some(4096), "{value:#}");
        assert_eq!(
            value["content"]["preview"].as_str().map(str::len),
            Some(256),
            "{value:#}"
        );
        assert!(
            value["content"]["sha256_prefix"].as_str().is_some(),
            "{value:#}"
        );
    }

    #[test]
    fn trait_json_keeps_small_printable_echo_redirect_content_inline() {
        let value = trait_json_value(&batdeob_core::Trait::EchoRedirect {
            content: b"CreateObject(WScript.Shell).Run calc.exe\r\n".to_vec(),
            target: "payload.vbs".to_string(),
            append: true,
        })
        .expect("trait json");

        assert_eq!(
            value["content"].as_str(),
            Some("CreateObject(WScript.Shell).Run calc.exe\r\n"),
            "{value:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_write_force_refuses_final_path_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().expect("tmp");
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "do not overwrite").expect("write outside");
        let link = dir.path().join("generated.txt");
        symlink(&outside, &link).expect("symlink");

        let err = safe_write(&link, b"replacement", true).expect_err("symlink should fail");
        let err_text = format!("{err:#}");
        assert!(
            err_text.contains("open") || err_text.contains("Too many levels"),
            "unexpected error: {err_text}"
        );
        let outside_contents = std::fs::read_to_string(&outside).expect("read outside");
        assert_eq!(outside_contents, "do not overwrite");
    }
}
