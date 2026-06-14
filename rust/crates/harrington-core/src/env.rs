//! Execution environment — variables, file-system tracking, limits, traits.

use crate::traits::Trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Control-flow signal returned (via `env.pending_action`) by command handlers.
/// Lives here (not in `interp.rs`) to avoid a circular import.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CursorAction {
    Next,
    GotoLine(usize),
    PopFrame,
    Halt,
}

/// Knobs for `analyze`. Constructed by callers — adding a field here is
/// a SemVer-significant change because it adds a required field to the
/// struct literal at every call site. For now we don't mark this
/// `#[non_exhaustive]` (which would require a builder) and accept that
/// new knobs ship in minor versions. Existing callers should use
/// `Config { my_knob: x, ..Config::default() }` to stay forward-compatible.
#[derive(Debug, Clone)]
pub struct Config {
    pub max_depth: u32,
    pub max_iterations: u64,
    pub max_child_scripts: u32,
    pub timeout_secs: u64,
    pub self_extract: bool,
    pub winver: WinVer,
    pub max_output_bytes: u64,
    pub max_output_line_bytes: u64,
    pub max_traits_per_kind: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_depth: 12,
            max_iterations: 65_536,
            max_child_scripts: 64,
            timeout_secs: 10,
            self_extract: true,
            winver: WinVer::Win10,
            max_output_bytes: 10 * 1024 * 1024,
            max_output_line_bytes: 64 * 1024,
            max_traits_per_kind: 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WinVer {
    Win7,
    Win10,
    Win11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsEntry {
    Content {
        content: Vec<u8>,
        append: bool,
    },
    Download {
        src: String,
    },
    Copy {
        src: String,
    },
    Decoded {
        content: Vec<u8>,
        src: String,
        method: DecodeKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeKind {
    Base64,
    Hex,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Limits {
    pub max_depth: u32,
    pub depth: u32,
    pub max_iterations: u64,
    pub iterations: u64,
    pub max_child_scripts: u32,
    pub child_scripts: u32,
    pub deadline: Option<Instant>,
    pub max_output_bytes: u64,
    pub output_bytes: u64,
    pub max_output_line_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub return_line: usize,
    pub args: Vec<String>,
    pub locals_snapshot: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct SetlocalSnapshot {
    pub vars: std::collections::HashMap<String, String>,
    pub delayed_expansion: bool,
}

#[derive(Debug, Clone)]
pub struct Environment {
    // ===== Variable + filesystem state =====
    /// Variable map (lowercase keys, case-insensitive lookup).
    pub(crate) vars: HashMap<String, String>,
    /// Files created, downloaded, decoded, or copied during execution.
    pub modified_filesystem: HashMap<String, FsEntry>,
    /// Stack of variable snapshots from nested `setlocal` calls.
    pub setlocal_stack: Vec<SetlocalSnapshot>,
    /// Whether `!VAR!` resolves to its value (true after `setlocal enabledelayedexpansion`).
    pub delayed_expansion: bool,
    /// Current CMD echo state, used for bare `echo` redirected into files.
    pub(crate) echo_enabled: bool,

    // ===== Static input / configuration =====
    /// Path to the input file, for `%~f0` self-extract resolution.
    pub file_path: Option<PathBuf>,
    /// Bytes of the input file, populated when `cfg.self_extract` is on.
    pub input_bytes: Option<Arc<[u8]>>,
    /// Which Windows version's synthetic env to use for assoc/ftype/where.
    pub winver: WinVer,
    /// Execution limits (depth, iterations, child scripts, wall-clock).
    pub limits: Limits,

    // ===== Per-command execution state =====
    /// Signal from a handler to drive() about how to advance the cursor.
    pub pending_action: Option<CursorAction>,
    /// Index of the currently-executing logical line.
    pub current_line: Option<usize>,
    /// Suppress further commands on the current logical line (set by `if` on false).
    pub suppress_until_eol: bool,
    /// Output accumulator for per-iteration command renders (FOR loops).
    pub iter_output: String,
    /// `:label` → line-index map, rebuilt on each `drive()` entry.
    pub label_index: HashMap<String, usize>,
    /// Stack of `call :label` frames (positional args + return cursor).
    pub call_stack: Vec<Frame>,

    // ===== Output accumulators =====
    /// IOC events emitted during deobfuscation.
    pub traits: Vec<Trait>,
    /// Queue of child cmd-scripts to recurse into (drained after each command).
    pub exec_cmd: Vec<String>,
    /// Parallel to `exec_cmd`: whether each child needs `delayed_expansion=true`.
    pub exec_cmd_delayed: Vec<bool>,
    /// Queue of extracted PowerShell payloads (drained after each command).
    pub exec_ps1: Vec<Vec<u8>>,
    /// Queue of extracted VBScript payloads.
    pub exec_vbs: Vec<Vec<u8>>,
    /// Queue of extracted JScript payloads.
    pub exec_jscript: Vec<Vec<u8>>,
    /// Cumulative list of all extracted cmd-scripts across the whole run.
    pub all_extracted_cmd: Vec<String>,
    /// Cumulative list of all extracted PowerShell payloads across the whole run.
    pub all_extracted_ps1: Vec<Vec<u8>>,
    /// Normalized PowerShell payload cache for payloads already scanned in this run.
    pub ps1_normalized_cache: HashMap<Vec<u8>, String>,
    /// Whether PS payload scanning should populate/use normalized report-cache text.
    pub ps1_scan_cache_normalized: bool,
    /// Cumulative list of all extracted VBScript payloads across the whole run.
    pub all_extracted_vbs: Vec<Vec<u8>>,
    /// Cumulative list of all extracted JScript payloads across the whole run.
    pub all_extracted_jscript: Vec<Vec<u8>>,
    /// Cumulative list of decrypted PE blobs (`.exe`/`.dll`) we've
    /// recovered from AES-chain droppers' `:: <b64>` payload lines.
    /// Each entry is `(label, bytes)` where the label is a short
    /// human-readable origin tag (e.g. `"aes-chain-asm0"`) so analyst
    /// tooling can prefix output filenames meaningfully. CLI's
    /// `write_report_files` dumps each to `<out_dir>/<sha>.<ext>` so
    /// the analyst can hand the bytes to a sandbox / RE pipeline.
    pub recovered_pe: Vec<(String, Vec<u8>)>,
    /// Counter used to produce a different `%random%` value on each lookup.
    /// CMD's `%random%` returns a pseudo-random 0..32767 each read; we use a
    /// deterministic counter so analysis is reproducible while still letting
    /// loops that index by `%random%` reach distinct values.
    pub(crate) random_counter: std::cell::Cell<u32>,
    /// Per-source-line visit count, used to detect goto-loop cycles. Lines
    /// that have been visited more than `GOTO_LOOP_ELIDE_AFTER` times have
    /// their output suppressed (handlers still run for IOC extraction).
    pub line_visit_count: HashMap<usize, u32>,
}

/// Number of times a single source line may emit to the deob output via a
/// goto cycle before further visits are elided. Tuned to be high enough
/// that legitimate `goto :label` flow always lands in the deob, but low
/// enough that pathological `:loop ... goto loop` watchdogs don't fill
/// the 4 MiB output cap with repeated copies.
pub const GOTO_LOOP_ELIDE_AFTER: u32 = 4;

/// Hard cap on how many times any single source line may be visited by
/// the main drive loop. Above this we force-exit the loop to stop
/// pathological `:watchdog ... goto watchdog` cycles from running for
/// the full iteration budget while producing no new output. Tuned to be
/// well above the elision threshold so analysts still see distinct goto
/// targets execute their handlers a reasonable number of times.
pub const GOTO_LOOP_HARD_CAP: u32 = 256;

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 12,
            depth: 0,
            max_iterations: 65_536,
            iterations: 0,
            max_child_scripts: 64,
            child_scripts: 0,
            deadline: None,
            max_output_bytes: 10 * 1024 * 1024,
            output_bytes: 0,
            max_output_line_bytes: 64 * 1024,
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self {
            vars: HashMap::new(),
            modified_filesystem: HashMap::new(),
            setlocal_stack: Vec::new(),
            delayed_expansion: false,
            echo_enabled: true,
            file_path: None,
            input_bytes: None,
            winver: WinVer::Win10,
            limits: Limits::default(),
            pending_action: None,
            current_line: None,
            suppress_until_eol: false,
            iter_output: String::new(),
            label_index: HashMap::new(),
            call_stack: Vec::new(),
            traits: Vec::new(),
            exec_cmd: Vec::new(),
            exec_cmd_delayed: Vec::new(),
            exec_ps1: Vec::new(),
            exec_vbs: Vec::new(),
            exec_jscript: Vec::new(),
            all_extracted_cmd: Vec::new(),
            all_extracted_ps1: Vec::new(),
            ps1_normalized_cache: HashMap::new(),
            ps1_scan_cache_normalized: true,
            all_extracted_vbs: Vec::new(),
            all_extracted_jscript: Vec::new(),
            recovered_pe: Vec::new(),
            random_counter: std::cell::Cell::new(0),
            line_visit_count: HashMap::new(),
        }
    }
}

impl Environment {
    pub fn new(cfg: &Config) -> Self {
        let mut e = Self {
            winver: cfg.winver,
            limits: Limits {
                max_depth: cfg.max_depth,
                depth: 0,
                max_iterations: cfg.max_iterations,
                iterations: 0,
                max_child_scripts: cfg.max_child_scripts,
                child_scripts: 0,
                deadline: if cfg.timeout_secs == 0 {
                    None
                } else {
                    Some(Instant::now() + std::time::Duration::from_secs(cfg.timeout_secs))
                },
                max_output_bytes: cfg.max_output_bytes,
                output_bytes: 0,
                max_output_line_bytes: cfg.max_output_line_bytes,
            },
            ..Default::default()
        };
        e.load_baseline();
        e
    }

    /// Return true when the analysis deadline has expired, recording a
    /// single TimeoutHit trait so callers can distinguish a bounded stop
    /// from a quiet no-op.
    pub(crate) fn check_deadline(&mut self) -> bool {
        let Some(deadline) = self.limits.deadline else {
            return false;
        };
        if Instant::now() < deadline {
            return false;
        }
        if !self.traits.iter().any(|t| matches!(t, Trait::TimeoutHit)) {
            self.traits.push(Trait::TimeoutHit);
        }
        true
    }

    /// Collect every URL-carrying string that's already been recorded as a
    /// trait. Used by URL scanners as a dedup baseline so the same URL
    /// surfaced by two different scanners doesn't double-emit. Centralizing
    /// the trait-variant fan-out here means a new URL-bearing trait kind
    /// only has to be added in one place — historically each `scan_*_urls`
    /// re-derived this set with its own `match`, and adding a new variant
    /// silently leaked URLs through any scanner whose match arm forgot
    /// the new variant.
    pub fn known_extracted_urls(&self) -> std::collections::HashSet<String> {
        let mut out = std::collections::HashSet::new();
        for t in &self.traits {
            match t {
                Trait::Download { src, .. } => {
                    out.insert(src.clone());
                }
                Trait::CertutilDownload { url, .. } => {
                    out.insert(url.clone());
                }
                Trait::BitsadminDownload { url, .. } => {
                    out.insert(url.clone());
                }
                Trait::DownloadInDeobText { src, .. } => {
                    out.insert(src.clone());
                }
                Trait::UrlLaunch { url, .. } => {
                    out.insert(url.clone());
                }
                Trait::UrlArgument { url, .. } => {
                    out.insert(url.clone());
                }
                Trait::UrlVariable { url, .. } => {
                    out.insert(url.clone());
                }
                Trait::RegistryUrl { url, .. } => {
                    out.insert(url.clone());
                }
                Trait::Rundll32 { url: Some(u), .. } => {
                    out.insert(u.clone());
                }
                Trait::RemoteConnect { host, port, .. } => {
                    out.insert(format!("http://{host}:{port}"));
                }
                Trait::UncWebDavC2 { http_url, .. } if !http_url.is_empty() => {
                    out.insert(http_url.clone());
                }
                _ => {}
            }
        }
        out
    }

    /// Look up a variable case-insensitively. Returns an owned String so the caller
    /// can hold the value across further `set` calls.
    pub fn get(&self, name: &str) -> Option<String> {
        let key = name.to_ascii_lowercase();
        // `%random%` is a magic built-in that yields a different 0..32767 each
        // read in real CMD. Counter-stepped per call so a loop like
        //   set RMZ=!CHAR:~%random%,1!%RMZ%
        // sees a distinct index on each iteration instead of a constant.
        if key == "random" {
            let n = self.random_counter.get();
            // Bit-mix into the 0..32767 space so the values look reasonably
            // spread instead of just 0,1,2,3,...
            self.random_counter.set(n.wrapping_add(1));
            let mixed = n.wrapping_mul(2654435761) ^ n;
            return Some((mixed & 0x7fff).to_string());
        }
        self.vars.get(&key).cloned()
    }

    /// Set or delete (when value is empty) a variable. Name is normalized to lowercase.
    pub fn set(&mut self, name: &str, value: &str) {
        let k = name.to_ascii_lowercase();
        if value.is_empty() {
            self.vars.remove(&k);
        } else {
            self.vars.insert(k, value.to_string());
        }
    }

    /// Seed a variable from analyst-supplied analysis context. Unlike CMD's
    /// `set NAME=`, an explicit empty value is preserved.
    pub fn seed(&mut self, name: &str, value: &str) {
        let key = name.to_ascii_lowercase();
        self.vars.insert(key, value.to_string());
    }

    pub fn contains_var(&self, name: &str) -> bool {
        self.vars.contains_key(&name.to_ascii_lowercase())
    }

    pub fn vars_iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.vars.iter()
    }

    pub fn push_setlocal(&mut self, enable_delayed: bool) {
        self.setlocal_stack.push(SetlocalSnapshot {
            vars: self.vars.clone(),
            delayed_expansion: self.delayed_expansion,
        });
        if enable_delayed {
            self.delayed_expansion = true;
        }
    }

    pub fn pop_setlocal(&mut self) {
        if let Some(snap) = self.setlocal_stack.pop() {
            self.vars = snap.vars;
            self.delayed_expansion = snap.delayed_expansion;
        }
    }

    /// Population matching Python batch_interpreter.py:122-172.
    fn load_baseline(&mut self) {
        let pairs: &[(&str, &str)] = &[
            ("allusersprofile", "C:\\ProgramData"),
            ("appdata", "C:\\Users\\puncher\\AppData\\Roaming"),
            ("commonprogramfiles", "C:\\Program Files\\Common Files"),
            ("commonprogramfiles(x86)", "C:\\Program Files (x86)\\Common Files"),
            ("commonprogramw6432", "C:\\Program Files\\Common Files"),
            ("computername", "MISCREANTTEARS"),
            ("comspec", "C:\\WINDOWS\\system32\\cmd.exe"),
            ("driverdata", "C:\\Windows\\System32\\Drivers\\DriverData"),
            // `%errorlevel%` is intentionally NOT defined: real CMD
            // updates it after every command, so a static value would
            // fold all conditional retry/branch logic into a constant.
            // `set errorlevel=0` at runtime would override this; if a
            // sample explicitly sets it we'll honor that.
            ("homedrive", "C:"),
            ("homepath", "\\Users\\puncher"),
            ("localappdata", "C:\\Users\\puncher\\AppData\\Local"),
            ("logonserver", "\\\\MISCREANTTEARS"),
            ("number_of_processors", "4"),
            ("onedrive", "C:\\Users\\puncher\\OneDrive"),
            ("os", "Windows_NT"),
            ("path", "C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\;C:\\Program Files\\dotnet\\;C:\\Users\\puncher\\AppData\\Local\\Microsoft\\WindowsApps;"),
            ("pathext", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"),
            ("processor_architecture", "AMD64"),
            ("processor_identifier", "Intel Core Ti-83 Family 6 Model 158 Stepping 10, GenuineIntel"),
            ("processor_level", "6"),
            ("processor_revision", "9e0a"),
            ("programdata", "C:\\ProgramData"),
            ("programfiles", "C:\\Program Files"),
            ("programfiles(x86)", "C:\\Program Files (x86)"),
            ("programw6432", "C:\\Program Files"),
            // PSModulePath — chosen so that the FE DOSfuscation FOR /F
            // gadget `('set^|findstr PSM') DO %%a` with `delims=s\
            // tokens=4` resolves to a token containing `PowerShell`.
            // Splitting `PSModulePath=C:\Program Files\WindowsPowerShell\Modules`
            // on `s`/`\` yields:
            //   t1=`PSModulePath=C:`  t2=`Program File`  t3=`Window`
            //   t4=`PowerShell`       t5=`Module`
            // Single-path value (the Windows default has 3 paths, but a
            // single canonical entry is what minimizes false positives in
            // downstream consumers that grep the literal value, and the
            // gadget's intent — extract `PowerShell` — survives).
            ("psmodulepath", "C:\\Program Files\\WindowsPowerShell\\Modules"),
            ("public", "C:\\Users\\Public"),
            ("random", "4"),
            // CMD dynamic built-ins. Static placeholders are fine for
            // analysis — `%TIME:~-2%` (last-2 chars of seconds field)
            // is a common obfuscation gating token; without a sensible
            // value our arithmetic emits ArithmeticParseError instead
            // of reaching the URL-bearing branch.
            ("time", "12:34:56.78"),
            ("date", "Mon 01/15/2024"),
            ("cd", "C:\\Users\\puncher\\Downloads"),
            ("sessionname", "Console"),
            ("systemdrive", "C:"),
            ("systemroot", "C:\\WINDOWS"),
            ("temp", "C:\\Users\\puncher\\AppData\\Local\\Temp"),
            ("tmp", "C:\\Users\\puncher\\AppData\\Local\\Temp"),
            ("userdomain", "MISCREANTTEARS"),
            ("userdomain_roamingprofile", "MISCREANTTEARS"),
            ("username", "puncher"),
            ("userprofile", "C:\\Users\\puncher"),
            ("windir", "C:\\WINDOWS"),
            ("__compat_layer", "DetectorsMessageBoxErrors"),
        ];
        for (k, v) in pairs {
            self.vars.insert((*k).to_string(), (*v).to_string());
        }
    }
}
