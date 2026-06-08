use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

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
        #[arg(short = 'o', long = "out-dir", default_value = "harrington-out")]
        out_dir: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        json_only: bool,
        /// Replace Harrington-generated files in an existing output directory.
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
        #[arg(long, default_value_t = 10 * 1024 * 1024)]
        max_output_bytes: u64,
        #[arg(long, default_value_t = 64 * 1024)]
        max_output_line_bytes: u64,
        #[arg(long, default_value_t = 100)]
        max_traits_per_kind: u32,
    },
    /// Like `deob --json-only`: JSON report to stdout, no files.
    Analyze {
        #[arg(value_name = "FILE", num_args = 0..)]
        files: Vec<String>,
        /// Read additional input paths from a newline-delimited file.
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
        /// Emit a human-readable one-paragraph TLDR instead of JSON.
        /// Lists URLs, persistence, evasion, lateral movement, AV evasion,
        /// in-memory loaders, and enumeration in a few short lines suited
        /// for analyst triage / chat-paste.
        #[arg(long)]
        tldr: bool,
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
const MAX_FILE_LIST_BYTES: u64 = 16 * 1024 * 1024;

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        read_all_capped(std::io::stdin(), MAX_INPUT_BYTES, || {
            "stdin input".to_string()
        })
    } else {
        let file = fs::File::open(path).with_context(|| format!("open {:?}", path))?;
        let meta = file
            .metadata()
            .with_context(|| format!("stat {:?}", path))?;
        if !meta.file_type().is_file() {
            anyhow::bail!("{:?}: not a regular file", path);
        }
        if meta.len() > MAX_INPUT_BYTES {
            anyhow::bail!(
                "{:?}: {} bytes exceeds the {}-byte input cap",
                path,
                meta.len(),
                MAX_INPUT_BYTES
            );
        }
        read_all_capped(file, MAX_INPUT_BYTES, || format!("{:?}", path))
    }
}

fn read_all_capped<R, F>(reader: R, max_bytes: u64, read_context: F) -> Result<Vec<u8>>
where
    R: std::io::Read,
    F: Fn() -> String,
{
    let mut buf = Vec::new();
    let mut limited = reader.take(max_bytes.saturating_add(1));
    limited
        .read_to_end(&mut buf)
        .with_context(|| format!("read {}", read_context()))?;
    if buf.len() as u64 > max_bytes {
        anyhow::bail!(
            "{} exceeds {max_bytes} bytes; refusing to read more",
            read_context()
        );
    }
    Ok(buf)
}

fn read_file_list(path: &Path) -> Result<String> {
    let file = fs::File::open(path).with_context(|| format!("open file list {:?}", path))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat file list {:?}", path))?;
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
    let bytes = read_all_capped(file, MAX_FILE_LIST_BYTES, || {
        format!("file list {:?}", path)
    })?;
    String::from_utf8(bytes).with_context(|| format!("parse file list {:?} as UTF-8", path))
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
) -> harrington_core::Config {
    harrington_core::Config {
        max_depth,
        max_iterations,
        max_child_scripts,
        timeout_secs: timeout,
        self_extract,
        winver: harrington_core::WinVer::Win10,
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

fn analyze_for_file(
    file: &str,
    input: &[u8],
    cfg: &harrington_core::Config,
) -> harrington_core::Report {
    if file == "-" {
        harrington_core::analyze(input, cfg)
    } else {
        harrington_core::analyze_with_path(input, cfg, Path::new(file))
    }
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

    let file = fs::File::open(path).with_context(|| format!("open {:?}", path))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat {:?}", path))?;
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
    let bytes = read_all_capped(file, MAX_LOLBAS_JSON_BYTES, || format!("{:?}", path))?;
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
    )
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
        || (lower.len() > 2
            && (lower.starts_with("-o") || lower.starts_with("/o"))
            && lower[2..].contains(['\\', '/']))
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
/// strings ("deobfuscated.bat", "traits.json") or sha-prefixed artifact
/// filenames — so a successful escape would require a bug in the filename
/// generator. Belt and braces; the canonicalize step also catches the case
/// where `out_dir` itself is a symlink to a sensitive location.
fn safe_join(canonical_out: &Path, name: &str) -> Result<PathBuf> {
    // Refuse anything that looks like a path traversal upfront.
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        anyhow::bail!("refusing unsafe child filename: {:?}", name);
    }
    let target = canonical_out.join(name);
    Ok(target)
}

/// Write `bytes` to `path` without following a final-path symlink on Unix.
/// By default this uses O_CREATE+O_EXCL and refuses stale output. With
/// `force`, it truncates/replaces regular files but still refuses symlinks.
fn safe_write(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    use std::io::Write;
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
            // Pre-existing file at target path — refuse to overwrite. In
            // the analyst use case the output directory is supposed to be
            // fresh, so a collision is suspicious (race / replay).
            anyhow::bail!(
                "refusing to overwrite existing output path {:?}; rerun with --force to replace stale output",
                path
            )
        }
        Err(e) => Err(anyhow::Error::from(e).context(format!("open {:?}", path))),
    }
}

fn write_report_files(report: &harrington_core::Report, out_dir: &Path, force: bool) -> Result<()> {
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

    let mut seen_names = std::collections::HashSet::new();
    for child in &report.extracted_cmd {
        let bytes = child.as_bytes();
        let sha = short_sha(bytes);
        let name = format!("{sha}.bat");
        if !seen_names.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, bytes, force)?;
    }
    for (idx, child) in report.extracted_ps1.iter().enumerate() {
        let sha = short_sha(child);
        let name = format!("{sha}.ps1");
        if !seen_names.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, child, force)?;
        if let Some(normalized) = report.extracted_ps1_normalized.get(idx) {
            let raw_text = String::from_utf8_lossy(child);
            if normalized != raw_text.as_ref() {
                let name = format!("{sha}.normalized.ps1");
                if !seen_names.insert(name.clone()) {
                    continue;
                }
                safe_write(
                    &safe_join(&canonical_out, &name)?,
                    normalized.as_bytes(),
                    force,
                )?;
            }
        }
    }
    for child in &report.extracted_jscript {
        let sha = short_sha(child);
        let name = format!("{sha}.js");
        if !seen_names.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, child, force)?;
    }
    for child in &report.extracted_vbs {
        let sha = short_sha(child);
        let name = format!("{sha}.vbs");
        if !seen_names.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, child, force)?;
    }

    // Dump recovered binary blobs:
    //   * `.exe`/`.dll` payloads decrypted out of AES-chain droppers
    //     (dwm.bat / 1895041 / DHL families)
    //   * Whole-file disguised binaries — `.cab` / `.zip` / `.rar` /
    //     `.7z` / `.lnk` / `.pdf` / `.png` etc. delivered as `.bat`
    //     (15 CAB + 5 LNK + 223 PE in the corpus)
    // One file per blob, sha-prefixed so two runs against the same
    // input produce deterministic names. Extension picked by sniffing
    // the magic bytes (`detect_blob_extension`). Skipped silently if
    // there's nothing to write.
    for (label, blob) in &report.recovered_pe {
        let bytes = blob.as_slice();
        let sha = short_sha(bytes);
        let ext = detect_blob_extension(bytes);
        let name = format!("{sha}.{ext}");
        if !seen_names.insert(name.clone()) {
            continue;
        }
        safe_write(&safe_join(&canonical_out, &name)?, bytes, force)?;
        // Companion `.meta` text file documents what each blob is so an
        // analyst eyeballing the out-dir doesn't have to guess.
        let meta_name = format!("{sha}.meta");
        let meta = format!(
            "origin: {label}\nsize: {}\nsha256-prefix: {sha}\n",
            bytes.len()
        );
        if seen_names.insert(meta_name.clone()) {
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

/// Pick the right on-disk extension for a recovered blob by sniffing
/// its magic bytes. Order matters — PE check first (most common), then
/// archive formats, then LNK/PDF/images. Falls back to `.bin` for
/// truly unknown content.
fn detect_blob_extension(bytes: &[u8]) -> &'static str {
    if bytes.len() < 8 {
        return "bin";
    }
    if bytes.starts_with(b"MZ") {
        return pe_extension(bytes);
    }
    if bytes.starts_with(b"MSCF\x00\x00\x00\x00") {
        return "cab";
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        return "zip";
    }
    if bytes.starts_with(b"Rar!\x1a\x07\x00") || bytes.starts_with(b"Rar!\x1a\x07\x01\x00") {
        return "rar";
    }
    if bytes.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return "7z";
    }
    if bytes.starts_with(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00") {
        return "lnk";
    }
    if bytes.starts_with(b"%PDF-") {
        return "pdf";
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "png";
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "gif";
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return "jpg";
    }
    "bin"
}

/// Pick `.dll` vs `.exe` for a recovered PE based on its characteristics
/// flags. Falls back to `.exe` for malformed / non-PE blobs (those still
/// get written so analysts can inspect them).
fn pe_extension(bytes: &[u8]) -> &'static str {
    // PE header: bytes[0x3c..0x40] is the e_lfanew offset to the PE
    // signature. Then PE\0\0, then COFF File Header. Characteristics
    // is at offset 18 of the File Header. IMAGE_FILE_DLL = 0x2000.
    let Some(pe_off) = bytes
        .get(0x3c..0x40)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    else {
        return "exe";
    };
    let Some(sig) = bytes.get(pe_off..pe_off + 4) else {
        return "exe";
    };
    if sig != b"PE\0\0" {
        return "exe";
    }
    let chars_off = pe_off + 4 + 18; // COFF File Header is 20 bytes; chars is last 2
    let Some(chars) = bytes
        .get(chars_off..chars_off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
    else {
        return "exe";
    };
    if chars & 0x2000 != 0 {
        "dll"
    } else {
        "exe"
    }
}

fn build_summary(
    input_path: &str,
    input: &[u8],
    report: &harrington_core::Report,
    lolbas_index: Option<&LolbasIndex>,
) -> serde_json::Value {
    use harrington_core::Trait;
    use std::collections::BTreeMap;

    let mut downloads = Vec::new();
    // Dedupe across trait kinds. A URL extracted via both `Trait::Download`
    // and `Trait::DownloadInDeobText` used to appear twice. Logic:
    //   1. Same src + same dst → drop the second.
    //   2. Same src, one has None dst & other has a real dst → keep the
    //      one with a dst (the post-pass sweep's None-dst entry loses).
    //   3. Same src, different real dsts → keep both (rare but possible
    //      when the same URL is downloaded to two locations).
    // Normalize a dst path for dedup comparison: lowercase + collapse the
    // common `%APPDATA%`/`%TEMP%`/`%LOCALAPPDATA%` env vars and the standard
    // expanded forms into a canonical token, so handlers that emit `dst=
    // %APPDATA%/X.exe` vs `dst=C:\Users\puncher\AppData\Roaming/X.exe`
    // dedupe as the same target. Conservative — only the env vars we
    // actually substitute in the baseline env.
    fn norm_dst(s: Option<&str>) -> Option<String> {
        let s = s?;
        let mut t = s.to_ascii_lowercase().replace('\\', "/");
        for (var, expanded) in &[
            ("%appdata%", "c:/users/puncher/appdata/roaming"),
            ("%localappdata%", "c:/users/puncher/appdata/local"),
            ("%temp%", "c:/users/puncher/appdata/local/temp"),
            ("%tmp%", "c:/users/puncher/appdata/local/temp"),
            ("%userprofile%", "c:/users/puncher"),
            ("%systemroot%", "c:/windows"),
            ("%programdata%", "c:/programdata"),
        ] {
            t = t.replace(var, expanded);
        }
        Some(t)
    }
    let push_download = |downloads: &mut Vec<serde_json::Value>, val: serde_json::Value| {
        let src = val
            .get("src")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let dst_str = val.get("dst").and_then(|v| v.as_str()).map(String::from);
        let dst_norm = norm_dst(dst_str.as_deref());
        for (i, prev) in downloads.iter_mut().enumerate() {
            let prev_src = prev.get("src").and_then(|v| v.as_str()).unwrap_or("");
            if prev_src != src {
                continue;
            }
            let prev_dst = prev.get("dst").and_then(|v| v.as_str()).map(String::from);
            let prev_dst_norm = norm_dst(prev_dst.as_deref());
            // Identical (after norm) → drop new.
            if prev_dst_norm == dst_norm {
                return;
            }
            // New has a dst, prev doesn't → replace prev with new.
            if prev_dst.is_none() && dst_str.is_some() {
                downloads[i] = val;
                return;
            }
            // Prev has a dst, new doesn't → drop new.
            if prev_dst.is_some() && dst_str.is_none() {
                return;
            }
            // Both have different real dsts → fall through to push the new
            // one as a separate entry.
        }
        downloads.push(val);
    };
    let mut lolbas: Vec<String> = Vec::new();
    let mut admin_commands: BTreeMap<String, u64> = BTreeMap::new();
    let mut ps_samples: Vec<String> = Vec::new();
    let mut windows_util: Vec<serde_json::Value> = Vec::new();
    let mut self_extract = false;
    let mut traits_capped: Vec<serde_json::Value> = Vec::new();

    for t in &report.traits {
        match t {
            Trait::Download { src, dst, .. } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": src,
                        "dst": dst,
                    }),
                );
            }
            Trait::CertutilDownload { url, dst } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": url,
                        "dst": dst,
                    }),
                );
            }
            Trait::BitsadminDownload { url, dst } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": url,
                        "dst": dst,
                    }),
                );
            }
            Trait::DownloadInDeobText { src, .. } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": src,
                        "dst": null,
                        "source": "deob-text-sweep",
                    }),
                );
            }
            // PowerShell `$url = "https://..."` / `Start "" https://...` /
            // `cmd http://...` style URLs: surface in `downloads[]` so
            // analyst tooling sees them alongside cmd.exe-style downloads.
            // De-dup is handled by `push_download`.
            Trait::UrlVariable { url, .. } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": url,
                        "dst": null,
                        "source": "ps-url-variable",
                    }),
                );
            }
            Trait::UrlArgument { url, .. } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": url,
                        "dst": null,
                        "source": "process-url-arg",
                    }),
                );
            }
            Trait::UrlLaunch { url, .. } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": url,
                        "dst": null,
                        "source": "url-launch",
                    }),
                );
            }
            // `reg add … /d https://…` style C2 URL stashed in the registry —
            // sandbox tooling treats this the same as a direct download since
            // the resident component will later fetch it.
            Trait::RegistryUrl { url, .. } => {
                push_download(
                    &mut downloads,
                    serde_json::json!({
                        "src": url,
                        "dst": null,
                        "source": "registry-url",
                    }),
                );
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
            Trait::Lolbas { name, .. } if !lolbas.iter().any(|n| n == name) => {
                lolbas.push(name.clone());
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
            "jscript": report.extracted_jscript.len(),
            "vbs": report.extracted_vbs.len(),
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

fn extracted_counts_json(report: &harrington_core::Report) -> serde_json::Value {
    serde_json::json!({
        "cmd": report.extracted_cmd.len(),
        "powershell": report.extracted_ps1.len(),
        "jscript": report.extracted_jscript.len(),
        "vbs": report.extracted_vbs.len(),
    })
}

fn lolbas_matches(report: &harrington_core::Report, index: &LolbasIndex) -> Vec<serde_json::Value> {
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
    report: &harrington_core::Report,
    lolbas_json: Option<&Path>,
) -> Result<Option<Vec<serde_json::Value>>> {
    let Some(path) = lolbas_json else {
        return Ok(None);
    };
    let index = load_lolbas_index(path)?;
    Ok(Some(lolbas_matches(report, &index)))
}

fn command_lines_for_lolbas(report: &harrington_core::Report) -> Vec<&str> {
    use harrington_core::Trait;

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
            | Trait::AccountModification { command: cmd, .. }
            | Trait::FileConcealment { command: cmd, .. }
            | Trait::UncWebDavC2 { command: cmd, .. }
            | Trait::Persistence { command: cmd, .. }
            | Trait::EvidenceCleanup { command: cmd, .. }
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

/// Human-readable one-paragraph TLDR for analyst triage.
/// Groups: URLs, persistence, evasion, lateral movement, in-memory loaders,
/// network/enum probes. Each section is one line (or omitted if empty).
fn build_tldr(file: &str, input: &[u8], report: &harrington_core::Report) -> String {
    use harrington_core::Trait;
    use std::collections::BTreeSet;
    let mut urls: BTreeSet<String> = BTreeSet::new();
    let mut persist: Vec<String> = Vec::new();
    let mut evasion: Vec<String> = Vec::new();
    let mut lateral: Vec<String> = Vec::new();
    let mut inmem: BTreeSet<String> = BTreeSet::new();
    let mut probes: BTreeSet<String> = BTreeSet::new();
    let mut enumeration: BTreeSet<String> = BTreeSet::new();
    let mut self_elev: Vec<String> = Vec::new();
    let mut anti_recov: BTreeSet<String> = BTreeSet::new();
    let mut unc: BTreeSet<String> = BTreeSet::new();
    let mut self_extract = false;
    let mut aes_findings: Vec<String> = Vec::new();
    let mut cred_access: BTreeSet<String> = BTreeSet::new();
    let mut injection: BTreeSet<String> = BTreeSet::new();
    let mut input_cap: BTreeSet<String> = BTreeSet::new();
    let mut ransom_ext: BTreeSet<String> = BTreeSet::new();
    let mut remote_exec: BTreeSet<String> = BTreeSet::new();
    let mut shellcode: BTreeSet<String> = BTreeSet::new();
    let mut uac_bypass: BTreeSet<String> = BTreeSet::new();
    let mut svc_install: BTreeSet<String> = BTreeSet::new();
    let mut beacon_sleep: BTreeSet<String> = BTreeSet::new();
    let mut remote_connect: BTreeSet<String> = BTreeSet::new();
    let mut disguised: BTreeSet<String> = BTreeSet::new();
    let mut extrac32_self: BTreeSet<String> = BTreeSet::new();

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
                extrac32_self.insert(format!("{src} → {dst}"));
            }
            Trait::UncWebDavC2 { share_path, .. } => {
                unc.insert(share_path.clone());
            }
            Trait::Persistence {
                hive,
                key,
                value_name,
                command,
            } => {
                persist.push(format!(
                    "{hive}\\{key}{}{} → {}",
                    if value_name.is_empty() { "" } else { " /v " },
                    value_name,
                    if command.is_empty() {
                        "(no /d)"
                    } else {
                        command
                    }
                ));
            }
            Trait::DefenderEvasion { action, target } => {
                evasion.push(if target.is_empty() {
                    action.clone()
                } else {
                    format!("{action} {target}")
                });
            }
            Trait::LateralMovement { tool, target_host } => {
                lateral.push(format!("{tool} → {target_host}"));
            }
            Trait::InMemoryAssemblyLoad { variant } => {
                inmem.insert(variant.clone());
            }
            Trait::NetworkProbe { probe_kind, target } => {
                probes.insert(format!("{probe_kind}={target}"));
            }
            Trait::Enumeration { enum_kind, .. } => {
                enumeration.insert(enum_kind.clone());
            }
            Trait::SelfElevation { target, .. } => {
                self_elev.push(target.clone());
            }
            Trait::AntiRecovery { action } => {
                anti_recov.insert(action.clone());
            }
            Trait::SelfExtract { .. } => {
                self_extract = true;
            }
            Trait::CredentialAccess { technique, target } => {
                cred_access.insert(format!(
                    "{technique}: {}",
                    target.chars().take(60).collect::<String>()
                ));
            }
            Trait::ProcessInjection { api } => {
                injection.insert(api.clone());
            }
            Trait::InputCapture { capture_kind } => {
                input_cap.insert(capture_kind.clone());
            }
            Trait::RansomFileExtension { extension } => {
                ransom_ext.insert(extension.clone());
            }
            Trait::RemoteExec { tool, target_host } => {
                remote_exec.insert(format!("{tool} → {target_host}"));
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
                svc_install.insert(if bin_path.is_empty() {
                    service_name.clone()
                } else {
                    format!("{service_name} → {bin_path}")
                });
            }
            Trait::BeaconSleep { seconds } => {
                beacon_sleep.insert(format!("{seconds}s"));
            }
            Trait::MultiStageEncryptedDropper {
                aes_key_b64,
                aes_iv_b64,
                assemblies_recovered,
                ..
            } => {
                if let (Some(k), Some(iv)) = (aes_key_b64, aes_iv_b64) {
                    aes_findings.push(format!(
                        "Key={}… IV={}… asm={}",
                        &k.chars().take(16).collect::<String>(),
                        &iv.chars().take(16).collect::<String>(),
                        assemblies_recovered.unwrap_or(0)
                    ));
                }
            }
            _ => {}
        }
    }

    let mut out = String::new();
    let sha = short_sha(input);
    out.push_str(&format!("== {file} ({} bytes, {sha}) ==\n", input.len()));

    fn emit_line(out: &mut String, label: &str, items: Vec<String>) {
        if items.is_empty() {
            return;
        }
        let joined: Vec<String> = items.into_iter().take(6).collect();
        out.push_str(&format!("  {label}: {}\n", joined.join("; ")));
    }
    emit_line(&mut out, "URLs", urls.into_iter().collect());
    emit_line(&mut out, "UNC", unc.into_iter().collect());
    emit_line(
        &mut out,
        "C2 connect (host:port)",
        remote_connect.into_iter().collect(),
    );
    emit_line(
        &mut out,
        "Disguised binary",
        disguised.into_iter().collect(),
    );
    emit_line(
        &mut out,
        "Self-extract (extrac32 %~f0)",
        extrac32_self.into_iter().collect(),
    );
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
    emit_line(&mut out, "In-memory load", inmem.into_iter().collect());
    emit_line(&mut out, "AES dropper (DECRYPTED)", aes_findings);
    emit_line(&mut out, "Network probe", probes.into_iter().collect());
    emit_line(&mut out, "Enumeration", enumeration.into_iter().collect());
    emit_line(&mut out, "Cred access", cred_access.into_iter().collect());
    emit_line(
        &mut out,
        "Process injection (API)",
        injection.into_iter().collect(),
    );
    emit_line(&mut out, "Input capture", input_cap.into_iter().collect());
    emit_line(&mut out, "Remote exec", remote_exec.into_iter().collect());
    emit_line(
        &mut out,
        "Shellcode marker",
        shellcode.into_iter().collect(),
    );
    emit_line(&mut out, "UAC bypass", uac_bypass.into_iter().collect());
    emit_line(
        &mut out,
        "Service install (sc create)",
        svc_install.into_iter().collect(),
    );
    emit_line(&mut out, "Beacon sleep", beacon_sleep.into_iter().collect());
    emit_line(
        &mut out,
        "Ransom file ext",
        ransom_ext.into_iter().collect(),
    );
    // Anti-recovery is a strong ransomware indicator — call out separately.
    emit_line(
        &mut out,
        "Anti-recovery (RANSOMWARE)",
        anti_recov.into_iter().collect(),
    );

    if out.lines().count() <= 1 {
        out.push_str("  (no notable IOCs surfaced)\n");
    }
    out
}

fn write_all_or_pipe<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<bool> {
    match writer.write_all(bytes) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err).context("write stdout"),
    }
}

fn write_line_to<W: Write>(writer: &mut W, s: &str) -> Result<bool> {
    if !write_all_or_pipe(writer, s.as_bytes())? {
        return Ok(false);
    }
    write_all_or_pipe(writer, b"\n")
}

fn write_stdout(s: &str) -> Result<bool> {
    let mut stdout = io::stdout().lock();
    write_all_or_pipe(&mut stdout, s.as_bytes())
}

fn write_stdout_line(s: &str) -> Result<bool> {
    let mut stdout = io::stdout().lock();
    write_line_to(&mut stdout, s)
}

fn write_analyze_jsonl_report(
    writer: &mut impl Write,
    file: &str,
    input: &[u8],
    report: &harrington_core::Report,
    lolbas_matches: Option<Vec<serde_json::Value>>,
) -> Result<bool> {
    let meta = serde_json::json!({
        "kind": "meta",
        "input": file,
        "input_size": input.len(),
        "deobfuscated_size": report.deobfuscated.len(),
        "extracted": extracted_counts_json(report),
    });
    if !write_line_to(writer, &serde_json::to_string(&meta)?)? {
        return Ok(false);
    }
    for t in &report.traits {
        let line = serde_json::json!({"kind": "trait", "trait": t});
        if !write_line_to(writer, &serde_json::to_string(&line)?)? {
            return Ok(false);
        }
    }
    if let Some(matches) = lolbas_matches {
        for item in matches {
            let line = serde_json::json!({"kind": "lolbas_match", "match": item});
            if !write_line_to(writer, &serde_json::to_string(&line)?)? {
                return Ok(false);
            }
        }
    }
    let deob_line = serde_json::json!({"kind": "deob", "content": &report.deobfuscated});
    write_line_to(writer, &serde_json::to_string(&deob_line)?)
}

fn analyze_input_files(
    mut files: Vec<String>,
    file_list: Option<&Path>,
    jsonl: bool,
) -> Result<Vec<String>> {
    if file_list.is_some() && !jsonl {
        bail!("analyze --file-list requires --jsonl");
    }
    if let Some(path) = file_list {
        let list = read_file_list(path)?;
        files.extend(
            list.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string),
        );
    }
    if files.is_empty() {
        bail!("analyze requires at least one input file or --file-list");
    }
    if files.len() > 1 && !jsonl {
        bail!("multiple analyze inputs require --jsonl");
    }
    Ok(files)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Summarize {
            file,
            tldr,
            lolbas_json,
        } => {
            let input = read_input(&file)?;
            let cfg = harrington_core::Config::default();
            let report = analyze_for_file(&file, &input, &cfg);
            if tldr {
                if !write_stdout(&build_tldr(&file, &input, &report))? {
                    return Ok(());
                }
            } else {
                let lolbas_index = lolbas_json.as_deref().map(load_lolbas_index).transpose()?;
                let summary = build_summary(&file, &input, &report, lolbas_index.as_ref());
                if !write_stdout_line(&serde_json::to_string_pretty(&summary)?)? {
                    return Ok(());
                }
            }
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
            let report = analyze_for_file(&file, &input, &cfg);

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
            if !write_stdout_line(&serde_json::to_string_pretty(&value)?)? {
                return Ok(());
            }
        }
        Command::Version => {
            if !write_stdout_line(&format!("Harrington {}", harrington_core::version()))? {
                return Ok(());
            }
        }
        Command::Analyze {
            files,
            file_list,
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
            let files = analyze_input_files(files, file_list.as_deref(), jsonl)?;
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
            let lolbas_index = lolbas_json.as_deref().map(load_lolbas_index).transpose()?;
            if jsonl {
                let mut stdout = io::stdout().lock();
                for file in files {
                    let input = read_input(&file)?;
                    let report = analyze_for_file(&file, &input, &cfg);
                    let lolbas_matches = lolbas_index
                        .as_ref()
                        .map(|index| lolbas_matches(&report, index));
                    if !write_analyze_jsonl_report(
                        &mut stdout,
                        &file,
                        &input,
                        &report,
                        lolbas_matches,
                    )? {
                        return Ok(());
                    }
                }
            } else {
                let file = &files[0];
                let input = read_input(file)?;
                let report = analyze_for_file(file, &input, &cfg);
                let lolbas_matches = lolbas_index
                    .as_ref()
                    .map(|index| lolbas_matches(&report, index));
                let mut json = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
                    "extracted": extracted_counts_json(&report),
                });
                if let Some(matches) = lolbas_matches {
                    if let serde_json::Value::Object(ref mut obj) = json {
                        obj.insert(
                            "lolbas_matches".to_string(),
                            serde_json::Value::Array(matches),
                        );
                    }
                }
                if !write_stdout_line(&serde_json::to_string_pretty(&json)?)? {
                    return Ok(());
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
            let report = analyze_for_file(&file, &input, &cfg);
            if !json_only {
                write_report_files(&report, &out_dir, force)?;
            }
            if json || json_only {
                let lolbas_matches = optional_lolbas_matches(&report, lolbas_json.as_deref())?;
                let mut val = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
                    "extracted": extracted_counts_json(&report),
                });
                if let Some(matches) = lolbas_matches {
                    if let serde_json::Value::Object(ref mut obj) = val {
                        obj.insert(
                            "lolbas_matches".to_string(),
                            serde_json::Value::Array(matches),
                        );
                    }
                }
                if !write_stdout_line(&serde_json::to_string_pretty(&val)?)? {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("harrington: {:#}", e);
        std::process::exit(2);
    }
}
