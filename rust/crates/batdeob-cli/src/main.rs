use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(version, about = "Windows batch deobfuscator")]
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
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 64 * 1024)]
        max_output_line_bytes: u64,
        #[arg(long, default_value_t = 100)]
        max_traits_per_kind: u32,
    },
    /// Like `deob --json-only`: JSON report to stdout, no files.
    Analyze {
        file: String,
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
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 64 * 1024)]
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
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 64 * 1024)]
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

fn write_report_files(report: &batdeob_core::Report, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("mkdir {:?}", out_dir))?;
    let canonical_out =
        fs::canonicalize(out_dir).with_context(|| format!("canonicalize {:?}", out_dir))?;

    fs::write(
        safe_join(&canonical_out, "deobfuscated.bat")?,
        &report.deobfuscated,
    )
    .context("write deobfuscated.bat")?;

    let mut seen = std::collections::HashSet::new();
    for child in &report.extracted_cmd {
        let bytes = child.as_bytes();
        let sha = short_sha(bytes);
        if !seen.insert(sha.clone()) {
            continue;
        }
        let name = format!("{sha}.bat");
        fs::write(safe_join(&canonical_out, &name)?, bytes)
            .with_context(|| format!("write {name}"))?;
    }
    for child in &report.extracted_ps1 {
        let sha = short_sha(child);
        if !seen.insert(sha.clone()) {
            continue;
        }
        let name = format!("{sha}.ps1");
        fs::write(safe_join(&canonical_out, &name)?, child)
            .with_context(|| format!("write {name}"))?;
    }

    let traits_json = serde_json::to_string_pretty(&report.traits)?;
    fs::write(safe_join(&canonical_out, "traits.json")?, traits_json)
        .context("write traits.json")?;

    Ok(())
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

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Summarize { file, lolbas_json } => {
            let input = read_input(&file)?;
            let cfg = batdeob_core::Config::default();
            let report = batdeob_core::analyze(&input, &cfg);
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
            let report = batdeob_core::analyze(&input, &cfg);

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
            max_depth,
            max_iterations,
            max_child_scripts,
            timeout,
            no_self_extract,
            max_output_bytes,
            max_output_line_bytes,
            max_traits_per_kind,
            jsonl,
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
            let report = batdeob_core::analyze(&input, &cfg);
            let lolbas_matches = optional_lolbas_matches(&report, lolbas_json.as_deref())?;
            if jsonl {
                let meta = serde_json::json!({
                    "kind": "meta",
                    "input": file,
                    "input_size": input.len(),
                    "deobfuscated_size": report.deobfuscated.len(),
                });
                println!("{}", serde_json::to_string(&meta)?);
                for t in &report.traits {
                    let line = serde_json::json!({"kind": "trait", "trait": t});
                    println!("{}", serde_json::to_string(&line)?);
                }
                if let Some(matches) = lolbas_matches {
                    for item in matches {
                        let line = serde_json::json!({"kind": "lolbas_match", "match": item});
                        println!("{}", serde_json::to_string(&line)?);
                    }
                }
                let deob_line =
                    serde_json::json!({"kind": "deob", "content": &report.deobfuscated});
                println!("{}", serde_json::to_string(&deob_line)?);
            } else {
                let mut json = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
                });
                if let Some(matches) = lolbas_matches {
                    if let serde_json::Value::Object(ref mut obj) = json {
                        obj.insert(
                            "lolbas_matches".to_string(),
                            serde_json::Value::Array(matches),
                        );
                    }
                }
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
        Command::Deob {
            file,
            out_dir,
            json,
            json_only,
            lolbas_json,
            max_depth,
            max_iterations,
            max_child_scripts,
            timeout,
            no_self_extract,
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
            let report = batdeob_core::analyze(&input, &cfg);
            if !json_only {
                write_report_files(&report, &out_dir)?;
            }
            if json || json_only {
                let lolbas_matches = optional_lolbas_matches(&report, lolbas_json.as_deref())?;
                let mut val = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
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
