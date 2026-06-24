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
    },
    /// Emit a focused JSON IOC report without raw deobfuscated text.
    Summarize {
        /// Input script (`-` for stdin).
        file: String,
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

    serde_json::json!({
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
    })
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Summarize { file } => {
            let input = read_input(&file)?;
            let cfg = batdeob_core::Config::default();
            let report = batdeob_core::analyze(&input, &cfg);
            let summary = build_summary(&file, &input, &report);
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
            let mut value = build_summary(&file, &input, &report);
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
                let deob_line =
                    serde_json::json!({"kind": "deob", "content": &report.deobfuscated});
                println!("{}", serde_json::to_string(&deob_line)?);
            } else {
                let json = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
        Command::Deob {
            file,
            out_dir,
            json,
            json_only,
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
                let val = serde_json::json!({
                    "deobfuscated": report.deobfuscated,
                    "traits": report.traits,
                });
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
