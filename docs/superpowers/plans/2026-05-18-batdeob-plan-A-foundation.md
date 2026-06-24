# batdeob Plan A — Foundation MVP

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working Rust `batdeob` CLI that deobfuscates Windows batch scripts: lexes, expands `%VAR%`/`!VAR!`/substring/substitution, splits commands on `& && | ||`, dispatches to handlers for `set`/`setlocal`/`endlocal`/`echo`/`cmd`/`powershell`/`curl`/`mshta`/`rundll32`/`copy`/`net`/`start`/`call`, writes a deobfuscated `.bat` and an extracted-children directory. Passes the easy half of the Python parity suite. No goto/labels, no FOR-loops, no LOLBAS-specific handlers beyond the Python parity set — those come in Plans B and C.

**Architecture:** Cargo workspace under `rust/`. Two crates: `batdeob-core` (library) and `batdeob-cli` (binary). Three layers inside core: `lex` (token stream), `normalize` (variable expansion), `interp` (per-command handlers). State lives in an `Environment` struct. IOCs collected as a typed `Trait` enum, serialized to JSON via serde.

**Tech Stack:** Rust 1.78+, `serde` + `serde_json`, `regex`, `once_cell`, `clap`, `base64`, `phf`, `proptest` (dev), `assert_cmd` (dev), `pretty_assertions` (dev).

**Spec:** `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md`

---

## File structure

```
rust/
├── Cargo.toml                                     # workspace manifest
├── crates/
│   ├── batdeob-core/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs                             # public API: analyze, Report, Config
│   │   │   ├── env.rs                             # Environment, FsEntry, Limits, baseline
│   │   │   ├── traits.rs                          # Trait enum + serde
│   │   │   ├── line_reader.rs                     # read_logical_lines
│   │   │   ├── lex.rs                             # Token, VarOp, lexer state machine
│   │   │   ├── normalize.rs                       # token-stream variable expansion
│   │   │   ├── split.rs                           # split_commands on & && | ||
│   │   │   ├── interp.rs                          # dispatch + analyze loop
│   │   │   ├── handlers/
│   │   │   │   ├── mod.rs                         # Handler type, dispatch table
│   │   │   │   ├── set.rs                         # set / setlocal / endlocal
│   │   │   │   ├── echo.rs                        # echo + redirection
│   │   │   │   ├── cmd.rs                         # cmd /c / start
│   │   │   │   ├── powershell.rs                  # powershell + iwr extraction
│   │   │   │   ├── curl.rs                        # curl arg parsing
│   │   │   │   ├── net.rs                         # net use
│   │   │   │   ├── copy.rs                        # copy
│   │   │   │   ├── rundll32.rs                    # rundll32
│   │   │   │   └── mshta.rs                       # mshta
│   │   │   └── redirect.rs                        # extract_redirections
│   │   └── tests/
│   │       └── parity/                            # ports of Python tests
│   │           ├── mod.rs
│   │           ├── test_set.rs
│   │           ├── test_echo.rs
│   │           ├── test_curl.rs
│   │           ├── test_net.rs
│   │           ├── test_powershell.rs
│   │           ├── test_dosfuscation_easy.rs      # comma/semicolon/caret/substring/substitute
│   │           └── helpers.rs
│   └── batdeob-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs                            # clap CLI: deob, analyze, version
```

---

## Task 1: Workspace scaffold

**Files:**
- Create: `rust/Cargo.toml`
- Create: `rust/crates/batdeob-core/Cargo.toml`
- Create: `rust/crates/batdeob-core/src/lib.rs`
- Create: `rust/crates/batdeob-cli/Cargo.toml`
- Create: `rust/crates/batdeob-cli/src/main.rs`
- Create: `rust/rust-toolchain.toml`
- Create: `rust/.gitignore`

- [ ] **Step 1: Write `rust/Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/batdeob-core", "crates/batdeob-cli"]

[workspace.package]
edition = "2021"
rust-version = "1.78"
license = "Apache-2.0"
repository = "https://github.com/willmetcalf/batch_deobfuscator"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
regex = "1.10"
once_cell = "1.19"
clap = { version = "4.5", features = ["derive"] }
base64 = "0.22"
phf = { version = "0.11", features = ["macros"] }
anyhow = "1"
thiserror = "1"
sha2 = "0.10"
hex = "0.4"
# dev
proptest = "1.4"
assert_cmd = "2.0"
pretty_assertions = "1.4"
tempfile = "3.10"
```

- [ ] **Step 2: Write `rust/rust-toolchain.toml`**

```toml
[toolchain]
channel = "1.78"
components = ["clippy", "rustfmt"]
```

- [ ] **Step 3: Write `rust/.gitignore`**

```
target/
**/*.rs.bk
Cargo.lock.bak
```

- [ ] **Step 4: Write `rust/crates/batdeob-core/Cargo.toml`**

```toml
[package]
name = "batdeob-core"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
regex.workspace = true
once_cell.workspace = true
base64.workspace = true
phf.workspace = true
anyhow.workspace = true
thiserror.workspace = true
sha2.workspace = true
hex.workspace = true

[dev-dependencies]
proptest.workspace = true
pretty_assertions.workspace = true
tempfile.workspace = true

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

- [ ] **Step 5: Write `rust/crates/batdeob-core/src/lib.rs` placeholder**

```rust
//! batdeob-core — Windows batch deobfuscator engine.
//!
//! See `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md`.

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 6: Write `rust/crates/batdeob-cli/Cargo.toml`**

```toml
[package]
name = "batdeob-cli"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "batdeob"
path = "src/main.rs"

[dependencies]
batdeob-core = { path = "../batdeob-core" }
clap.workspace = true
serde_json.workspace = true
anyhow.workspace = true
```

- [ ] **Step 7: Write `rust/crates/batdeob-cli/src/main.rs` placeholder**

```rust
fn main() {
    println!("batdeob {}", batdeob_core::version());
}
```

- [ ] **Step 8: Verify build**

Run: `cd rust && cargo build --workspace`
Expected: compiles clean, no warnings.

Run: `cd rust && cargo run --bin batdeob`
Expected output: `batdeob 0.1.0`

- [ ] **Step 9: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/Cargo.toml rust/rust-toolchain.toml rust/.gitignore rust/crates/
git commit -m "Add Cargo workspace scaffold for batdeob"
```

---

## Task 2: Trait enum + serde

**Files:**
- Create: `rust/crates/batdeob-core/src/traits.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing test**

Append to `rust/crates/batdeob-core/src/lib.rs`:

```rust
pub mod traits;

#[cfg(test)]
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
```

- [ ] **Step 2: Verify it fails**

Run: `cd rust && cargo test --package batdeob-core trait_serializes`
Expected: FAIL — `module 'traits' is private` or `cannot find module 'traits'`.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/traits.rs`**

```rust
//! Typed IOC events emitted during deobfuscation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Trait {
    // ---- existing (Python parity) ----
    Download {
        cmd: String,
        src: String,
        dst: Option<String>,
    },
    NetUse {
        cmd: String,
        info: NetUseInfo,
    },
    Lolbas {
        name: String,
        cmd: String,
    },
    CommandGrouping {
        cmd: String,
        normalized: String,
    },
    StartWithVar {
        cmd: String,
        normalized: String,
    },
    VarUsed {
        cmd: String,
        normalized: String,
        count: u32,
    },
    Mshta {
        cmd: String,
    },
    Rundll32 {
        cmd: String,
        url: Option<String>,
    },
    SetpFileRedirect {
        cmd: String,
        target: String,
    },
    WindowsUtilManip {
        cmd: String,
        src: String,
        dst: String,
    },
    ManipulatedExec {
        cmd: String,
        target: String,
    },
    ComplexOneLiner {
        line_count: u32,
    },
    OneLiner,
    EchoRedirect {
        content: Vec<u8>,
        target: String,
        append: bool,
    },
    SetlocalScope {
        enabled_delayed: bool,
    },
    DelayedExpansionUsed,
    NonUtf8Input,
    IterationCapped {
        command: String,
    },
    DepthCapped {
        command: String,
    },
    ChildScriptsCapped,
    TimeoutHit,

    // ---- placeholders used by later plans (B/C) ----
    Goto {
        from_line: usize,
        to_label: String,
    },
    GotoUnresolved {
        from_line: usize,
        to_label: String,
    },
    Subroutine {
        label: String,
        args: Vec<String>,
    },
    SelfExtract {
        method: String,
    },
    CertutilDecode {
        src: String,
        dst: String,
        src_resolved: bool,
    },
    CertutilDownload {
        url: String,
        dst: String,
    },
    BitsadminDownload {
        url: String,
        dst: String,
    },
    WmicProcessCreate {
        inner_cmd: String,
    },
    CscriptExec {
        src: String,
    },
    WscriptExec {
        src: String,
    },
    Arithmetic {
        expr: String,
        value: i32,
    },
    ArithmeticParseError {
        expr: String,
    },
    IfNotResolved {
        condition: String,
    },
    ForUnresolvedSource {
        pipeline: String,
    },
    GotoLoopCapped {
        label: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetUseInfo {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devicename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
```

- [ ] **Step 4: Verify test passes**

Run: `cd rust && cargo test --package batdeob-core trait_serializes`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add Trait enum + NetUseInfo with serde-tagged JSON"
```

---

## Task 3: Environment + Limits + FsEntry

**Files:**
- Create: `rust/crates/batdeob-core/src/env.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing test**

Append to `rust/crates/batdeob-core/src/lib.rs`:

```rust
pub mod env;

#[cfg(test)]
mod env_tests {
    use crate::env::{Environment, Config};

    #[test]
    fn env_has_python_baseline_vars() {
        let env = Environment::new(&Config::default());
        assert_eq!(env.get("comspec").as_deref(), Some("C:\\WINDOWS\\system32\\cmd.exe"));
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
```

- [ ] **Step 2: Verify it fails**

Run: `cd rust && cargo test --package batdeob-core env_tests`
Expected: FAIL — `cannot find module 'env'`.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/env.rs`**

```rust
//! Execution environment — variables, file-system tracking, limits, traits.

use crate::traits::Trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Config {
    pub max_depth: u32,
    pub max_iterations: u64,
    pub max_child_scripts: u32,
    pub timeout_secs: u64,
    pub self_extract: bool,
    pub winver: WinVer,
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinVer {
    Win7,
    Win10,
    Win11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEntry {
    Content { content: Vec<u8>, append: bool },
    Download { src: String },
    Copy { src: String },
    Decoded { content: Vec<u8>, src: String, method: DecodeKind },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeKind { Base64, Hex }

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_depth: u32,
    pub depth: u32,
    pub max_iterations: u64,
    pub iterations: u64,
    pub max_child_scripts: u32,
    pub child_scripts: u32,
    pub deadline: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub return_line: usize,
    pub args: Vec<String>,
    pub locals_snapshot: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Default)]
pub struct Environment {
    vars: HashMap<String, String>,                          // lowercase keys
    pub modified_filesystem: HashMap<String, FsEntry>,      // lowercase keys
    pub traits: Vec<Trait>,
    pub exec_cmd: Vec<String>,
    pub exec_ps1: Vec<Vec<u8>>,
    pub exec_vbs: Vec<Vec<u8>>,
    pub exec_jscript: Vec<Vec<u8>>,
    pub file_path: Option<PathBuf>,
    pub input_bytes: Option<Arc<[u8]>>,
    pub delayed_expansion: bool,
    pub call_stack: Vec<Frame>,
    pub limits: Limits,
}

impl Environment {
    pub fn new(cfg: &Config) -> Self {
        let mut e = Self {
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
            },
            ..Default::default()
        };
        e.load_baseline();
        e
    }

    /// Look up a variable case-insensitively. Returns an owned String so the caller
    /// can hold the value across further `set` calls.
    pub fn get(&self, name: &str) -> Option<String> {
        self.vars.get(&name.to_ascii_lowercase()).cloned()
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

    pub fn contains_var(&self, name: &str) -> bool {
        self.vars.contains_key(&name.to_ascii_lowercase())
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
            ("errorlevel", "0"),
            ("homedrive", "C:"),
            ("homepath", "\\Users\\puncher"),
            ("localappdata", "C:\\Users\\puncher\\AppData\\Local"),
            ("logonserver", "\\\\MISCREANTTEARS"),
            ("number_of_processors", "4"),
            ("onedrive", "C:\\Users\\puncher\\OneDrive"),
            ("os", "Windows_NT"),
            ("path",
                "C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;\
                 C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\;\
                 C:\\Program Files\\dotnet\\;\
                 C:\\Users\\puncher\\AppData\\Local\\Microsoft\\WindowsApps;"),
            ("pathext", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"),
            ("processor_architecture", "AMD64"),
            ("processor_identifier", "Intel Core Ti-83 Family 6 Model 158 Stepping 10, GenuineIntel"),
            ("processor_level", "6"),
            ("processor_revision", "9e0a"),
            ("programdata", "C:\\ProgramData"),
            ("programfiles", "C:\\Program Files"),
            ("programfiles(x86)", "C:\\Program Files (x86)"),
            ("programw6432", "C:\\Program Files"),
            ("psmodulepath", "C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\"),
            ("public", "C:\\Users\\Public"),
            ("random", "4"),
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
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core env_tests`
Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add Environment + Config + FsEntry + Limits"
```

---

## Task 4: Logical-line reader

**Files:**
- Create: `rust/crates/batdeob-core/src/line_reader.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Append to `rust/crates/batdeob-core/src/lib.rs`:

```rust
pub mod line_reader;

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
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core line_reader_tests`
Expected: `cannot find module 'line_reader'`.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/line_reader.rs`**

```rust
//! Read logical lines from a batch script. A logical line is one or more
//! physical lines joined by a trailing unescaped caret `^`.

/// Decode bytes as UTF-8 with replacement and split into logical lines,
/// joining caret-continuations. The trailing newline of each physical line
/// is stripped before joining; the caret itself is dropped.
pub fn read_logical_lines(input: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(input);
    let mut out: Vec<String> = Vec::new();
    let mut accum = String::new();
    for raw in text.split_inclusive('\n') {
        // strip trailing \n and optional \r
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(prefix) = line.strip_suffix('^') {
            accum.push_str(prefix);
        } else {
            accum.push_str(line);
            out.push(std::mem::take(&mut accum));
        }
    }
    if !accum.is_empty() {
        out.push(accum);
    }
    out
}
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core line_reader_tests`
Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add logical-line reader with caret-continuation handling"
```

---

## Task 5: Token types

**Files:**
- Create: `rust/crates/batdeob-core/src/lex.rs` (types only — state machine in Task 6)
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write `rust/crates/batdeob-core/src/lex.rs` types**

```rust
//! Token types and variable-operator types. The lexer state machine that
//! produces these lives in `lex_machine` (Task 6).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Word(String),
    DoubleQuoted(String),     // contents WITHOUT the surrounding quotes; quotes restored on render
    OpAnd,                    // &
    OpAndAnd,                 // &&
    OpOr,                     // |
    OpOrOr,                   // ||
    OpRedirect { fd: u8, append: bool },  // > 1> 2> >> 1>> 2>>
    OpInput,                  // <
    OpenParen,
    CloseParen,
    Whitespace,
    VarPercent { name: String, op: Option<VarOp> },
    VarBang { name: String, op: Option<VarOp> },
    PositionalArg(u8),        // %0..%9
    AllArgs,                  // %*
    PercentTilde { flags: PercentTildeFlags, arg_index: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarOp {
    Substr { index: i64, length: Option<i64> },
    Substitute { needle: String, replacement: String, leading_wildcard: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PercentTildeFlags {
    pub f: bool,
    pub d: bool,
    pub p: bool,
    pub n: bool,
    pub x: bool,
    pub s: bool,
    pub a: bool,
    pub t: bool,
    pub z: bool,
}

impl PercentTildeFlags {
    pub fn parse(flags_str: &str) -> Option<Self> {
        let mut f = Self::default();
        for c in flags_str.chars() {
            match c {
                'f' => f.f = true,
                'd' => f.d = true,
                'p' => f.p = true,
                'n' => f.n = true,
                'x' => f.x = true,
                's' => f.s = true,
                'a' => f.a = true,
                't' => f.t = true,
                'z' => f.z = true,
                _ => return None,
            }
        }
        Some(f)
    }
}
```

- [ ] **Step 2: Wire the module**

Append to `rust/crates/batdeob-core/src/lib.rs`:

```rust
pub mod lex;
```

- [ ] **Step 3: Verify it builds**

Run: `cd rust && cargo build --package batdeob-core`
Expected: compiles clean.

- [ ] **Step 4: Add a smoke test**

Append to `rust/crates/batdeob-core/src/lib.rs`:

```rust
#[cfg(test)]
mod lex_type_tests {
    use crate::lex::{PercentTildeFlags, Token, VarOp};

    #[test]
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
            Token::VarPercent { name: "x".into(), op: None },
            Token::VarBang { name: "x".into(), op: None }
        );
        let _v = VarOp::Substr { index: -7, length: Some(3) };
    }
}
```

Run: `cd rust && cargo test --package batdeob-core lex_type_tests`
Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add lexer token + VarOp + PercentTildeFlags types"
```

---

## Task 6: Lexer state machine — bare words & whitespace

We build the lexer up incrementally. Start with the simplest input: bare words and whitespace.

**Files:**
- Modify: `rust/crates/batdeob-core/src/lex.rs`

- [ ] **Step 1: Write failing test**

Append to `rust/crates/batdeob-core/src/lex.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn lex(s: &str) -> Vec<Token> {
        super::lex(s)
    }

    #[test]
    fn lex_single_word() {
        assert_eq!(lex("echo"), vec![Token::Word("echo".into())]);
    }

    #[test]
    fn lex_two_words_split_by_space() {
        assert_eq!(
            lex("echo hi"),
            vec![
                Token::Word("echo".into()),
                Token::Whitespace,
                Token::Word("hi".into()),
            ]
        );
    }

    #[test]
    fn lex_tabs_count_as_whitespace() {
        assert_eq!(
            lex("a\tb"),
            vec![
                Token::Word("a".into()),
                Token::Whitespace,
                Token::Word("b".into()),
            ]
        );
    }

    #[test]
    fn lex_comma_and_semicolon_are_whitespace() {
        // batch treats , and ; as whitespace outside quoted strings (DOSfuscation)
        assert_eq!(
            lex("a,b;c"),
            vec![
                Token::Word("a".into()),
                Token::Whitespace,
                Token::Word("b".into()),
                Token::Whitespace,
                Token::Word("c".into()),
            ]
        );
    }
}
```

- [ ] **Step 2: Verify tests fail**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: FAIL — `cannot find function 'lex' in module 'super'`.

- [ ] **Step 3: Write minimal lexer**

Append to `rust/crates/batdeob-core/src/lex.rs`:

```rust
pub fn lex(input: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut iter = input.chars().peekable();
    let mut word = String::new();

    while let Some(c) = iter.next() {
        if c == ' ' || c == '\t' || c == ',' || c == ';' {
            if !word.is_empty() {
                out.push(Token::Word(std::mem::take(&mut word)));
            }
            // collapse runs of whitespace into a single token
            while matches!(iter.peek(), Some(' ' | '\t' | ',' | ';')) {
                iter.next();
            }
            out.push(Token::Whitespace);
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        out.push(Token::Word(word));
    }
    out
}
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lex.rs
git commit -m "Add lexer skeleton: words + whitespace (incl comma/semicolon)"
```

---

## Task 7: Lexer — operators (& && | || > >> 1> 2> < parens)

**Files:**
- Modify: `rust/crates/batdeob-core/src/lex.rs`

- [ ] **Step 1: Add failing tests**

Append to `rust/crates/batdeob-core/src/lex.rs`'s `mod tests`:

```rust
    #[test]
    fn lex_ampersand_variants() {
        assert_eq!(
            lex("a&b&&c"),
            vec![
                Token::Word("a".into()),
                Token::OpAnd,
                Token::Word("b".into()),
                Token::OpAndAnd,
                Token::Word("c".into()),
            ]
        );
    }

    #[test]
    fn lex_pipe_variants() {
        assert_eq!(
            lex("a|b||c"),
            vec![
                Token::Word("a".into()),
                Token::OpOr,
                Token::Word("b".into()),
                Token::OpOrOr,
                Token::Word("c".into()),
            ]
        );
    }

    #[test]
    fn lex_redirects() {
        assert_eq!(
            lex("a>b 1>>c 2>d <e"),
            vec![
                Token::Word("a".into()),
                Token::OpRedirect { fd: 1, append: false },
                Token::Word("b".into()),
                Token::Whitespace,
                Token::OpRedirect { fd: 1, append: true },
                Token::Word("c".into()),
                Token::Whitespace,
                Token::OpRedirect { fd: 2, append: false },
                Token::Word("d".into()),
                Token::Whitespace,
                Token::OpInput,
                Token::Word("e".into()),
            ]
        );
    }

    #[test]
    fn lex_parens() {
        assert_eq!(
            lex("(a)"),
            vec![
                Token::OpenParen,
                Token::Word("a".into()),
                Token::CloseParen,
            ]
        );
    }
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: 4 new FAILs.

- [ ] **Step 3: Extend `lex`**

Replace the `lex` function body with:

```rust
pub fn lex(input: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut word = String::new();

    let flush_word = |out: &mut Vec<Token>, word: &mut String| {
        if !word.is_empty() {
            out.push(Token::Word(std::mem::take(word)));
        }
    };

    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | ',' | ';' => {
                flush_word(&mut out, &mut word);
                while i < chars.len() && matches!(chars[i], ' ' | '\t' | ',' | ';') {
                    i += 1;
                }
                out.push(Token::Whitespace);
            }
            '&' => {
                flush_word(&mut out, &mut word);
                if chars.get(i + 1) == Some(&'&') {
                    out.push(Token::OpAndAnd);
                    i += 2;
                } else {
                    out.push(Token::OpAnd);
                    i += 1;
                }
            }
            '|' => {
                flush_word(&mut out, &mut word);
                if chars.get(i + 1) == Some(&'|') {
                    out.push(Token::OpOrOr);
                    i += 2;
                } else {
                    out.push(Token::OpOr);
                    i += 1;
                }
            }
            '<' => {
                flush_word(&mut out, &mut word);
                out.push(Token::OpInput);
                i += 1;
            }
            '>' => {
                // Optional preceding fd digit was already consumed into `word`. Pull it back off.
                let fd = if let Some(last) = word.chars().last() {
                    if last == '1' || last == '2' {
                        word.pop();
                        last.to_digit(10).unwrap_or(1) as u8
                    } else {
                        1
                    }
                } else {
                    1
                };
                flush_word(&mut out, &mut word);
                let append = chars.get(i + 1) == Some(&'>');
                out.push(Token::OpRedirect { fd, append });
                i += if append { 2 } else { 1 };
            }
            '(' => {
                flush_word(&mut out, &mut word);
                out.push(Token::OpenParen);
                i += 1;
            }
            ')' => {
                flush_word(&mut out, &mut word);
                out.push(Token::CloseParen);
                i += 1;
            }
            _ => {
                word.push(c);
                i += 1;
            }
        }
    }
    flush_word(&mut out, &mut word);
    out
}
```

The `unwrap_or` is on a synthetic fallback that the `is_some` digit check already guarantees — no panic risk, but clippy will whine about it. Add an `#[allow(clippy::unwrap_used)]` directly above the `let fd = if let …` line **only if** clippy flags it; otherwise leave alone.

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: 8 tests PASS (4 prior + 4 new).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lex.rs
git commit -m "Lexer: handle & && | || > >> 1> 2> < and parens"
```

---

## Task 8: Lexer — caret escape

**Files:**
- Modify: `rust/crates/batdeob-core/src/lex.rs`

- [ ] **Step 1: Add failing tests**

Append to `lex.rs`'s `mod tests`:

```rust
    #[test]
    fn caret_escapes_next_char() {
        // ^& becomes literal & in a word
        assert_eq!(lex("a^&b"), vec![Token::Word("a&b".into())]);
    }

    #[test]
    fn caret_escapes_operator() {
        assert_eq!(lex("a^|b"), vec![Token::Word("a|b".into())]);
    }

    #[test]
    fn many_carets_in_word() {
        assert_eq!(lex("s^e^t"), vec![Token::Word("set".into())]);
    }

    #[test]
    fn trailing_caret_kept_literally() {
        assert_eq!(lex("foo^"), vec![Token::Word("foo^".into())]);
    }
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests caret`
Expected: FAILs.

- [ ] **Step 3: Add caret handling**

In the main `match c` arm in `lex`, add **before** the `' '` arm:

```rust
            '^' => {
                if let Some(&next) = chars.get(i + 1) {
                    word.push(next);
                    i += 2;
                } else {
                    word.push('^');
                    i += 1;
                }
            }
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: all PASS (including caret tests).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lex.rs
git commit -m "Lexer: caret-escape next character"
```

---

## Task 9: Lexer — double-quoted strings

**Files:**
- Modify: `rust/crates/batdeob-core/src/lex.rs`

- [ ] **Step 1: Add failing tests**

```rust
    #[test]
    fn double_quoted_string_is_single_token() {
        assert_eq!(
            lex(r#"echo "hello world""#),
            vec![
                Token::Word("echo".into()),
                Token::Whitespace,
                Token::DoubleQuoted("hello world".into()),
            ]
        );
    }

    #[test]
    fn operators_inside_quotes_are_literal() {
        assert_eq!(
            lex(r#""a|b&c""#),
            vec![Token::DoubleQuoted("a|b&c".into())]
        );
    }

    #[test]
    fn comma_inside_quotes_kept() {
        assert_eq!(
            lex(r#""a,b""#),
            vec![Token::DoubleQuoted("a,b".into())]
        );
    }
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests double_quoted`
Expected: FAILs.

- [ ] **Step 3: Add quoted-string handling**

In `lex`'s main `match`, add **before** the `'^'` arm:

```rust
            '"' => {
                flush_word(&mut out, &mut word);
                i += 1;
                let mut content = String::new();
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '^' && i + 1 < chars.len() {
                        content.push(chars[i + 1]);
                        i += 2;
                    } else {
                        content.push(chars[i]);
                        i += 1;
                    }
                }
                if i < chars.len() {
                    i += 1; // consume closing quote
                }
                out.push(Token::DoubleQuoted(content));
            }
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lex.rs
git commit -m "Lexer: double-quoted strings preserve internal operators"
```

---

## Task 10: Lexer — `%VAR%` and `!VAR!` (no operators yet)

**Files:**
- Modify: `rust/crates/batdeob-core/src/lex.rs`

- [ ] **Step 1: Add failing tests**

```rust
    #[test]
    fn percent_var_simple() {
        assert_eq!(
            lex("%FOO%"),
            vec![Token::VarPercent { name: "FOO".into(), op: None }]
        );
    }

    #[test]
    fn bang_var_simple() {
        assert_eq!(
            lex("!foo!"),
            vec![Token::VarBang { name: "foo".into(), op: None }]
        );
    }

    #[test]
    fn percent_var_among_words() {
        assert_eq!(
            lex("echo %X% rest"),
            vec![
                Token::Word("echo".into()),
                Token::Whitespace,
                Token::VarPercent { name: "X".into(), op: None },
                Token::Whitespace,
                Token::Word("rest".into()),
            ]
        );
    }

    #[test]
    fn percent_var_with_unicode_name() {
        // CJK characters in var names — corpus discovery
        let toks = lex("%せっん%");
        assert_eq!(
            toks,
            vec![Token::VarPercent { name: "せっん".into(), op: None }]
        );
    }

    #[test]
    fn unclosed_percent_falls_back_to_literal() {
        // No closing %, treat as literal text
        assert_eq!(lex("%abc"), vec![Token::Word("%abc".into())]);
    }

    #[test]
    fn percent_positional_arg() {
        assert_eq!(lex("%1"), vec![Token::PositionalArg(1)]);
        assert_eq!(lex("%0"), vec![Token::PositionalArg(0)]);
        assert_eq!(lex("%*"), vec![Token::AllArgs]);
    }
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests percent_var`
Expected: FAILs.

- [ ] **Step 3: Add var-ref handling**

In `lex`'s main `match`, add **before** the `'^'` arm:

```rust
            '%' => {
                flush_word(&mut out, &mut word);
                // %* all-args
                if chars.get(i + 1) == Some(&'*') {
                    out.push(Token::AllArgs);
                    i += 2;
                    continue;
                }
                // %0..%9 positional
                if let Some(&n) = chars.get(i + 1) {
                    if n.is_ascii_digit() {
                        // Could be %0 or start of %1xyz%; positional is exactly %<digit>
                        // and the next char (if any) must not extend to a closing %.
                        // We check ahead for a `%` before any non-name char.
                        let mut j = i + 2;
                        let mut saw_close = false;
                        while j < chars.len() {
                            if chars[j] == '%' { saw_close = true; break; }
                            if !is_var_name_char(chars[j]) { break; }
                            j += 1;
                        }
                        if !saw_close {
                            out.push(Token::PositionalArg(n.to_digit(10).unwrap_or(0) as u8));
                            i += 2;
                            continue;
                        }
                    }
                }
                // Find matching closing %
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() && chars[j] != '%' {
                    if !is_var_name_char(chars[j]) {
                        break;
                    }
                    name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && chars[j] == '%' && !name.is_empty() {
                    out.push(Token::VarPercent { name, op: None });
                    i = j + 1;
                } else {
                    word.push('%');
                    i += 1;
                }
            }
            '!' => {
                flush_word(&mut out, &mut word);
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() && chars[j] != '!' {
                    if !is_var_name_char(chars[j]) {
                        break;
                    }
                    name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && chars[j] == '!' && !name.is_empty() {
                    out.push(Token::VarBang { name, op: None });
                    i = j + 1;
                } else {
                    word.push('!');
                    i += 1;
                }
            }
```

And add a free function near the top of `lex.rs`:

```rust
fn is_var_name_char(c: char) -> bool {
    // cmd.exe accepts any Unicode letter/digit, plus most punctuation, in var names.
    c.is_alphabetic()
        || c.is_numeric()
        || c == '_'
        || matches!(c,
            '#' | '$' | '\'' | '(' | ')' | '*' | '+' | ',' | '-' |
            '.' | '?' | '@' | '[' | ']' | '`' | '{' | '}' | '~' | ' ' | '\t'
        )
}
```

The `unwrap_or(0)` is on a `to_digit(10)` of a char we already verified is `is_ascii_digit` — safe. Clippy may flag; in that case wrap as `n.to_digit(10).expect("ascii digit")` — but we already have `#![deny(clippy::expect_used)]`. Instead use:

```rust
let d = (n as u32).saturating_sub('0' as u32) as u8;
out.push(Token::PositionalArg(d));
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lex.rs
git commit -m "Lexer: %VAR% / !VAR! / positional args / %*"
```

---

## Task 11: Lexer — `:~i,n` substring & `:s1=s2` substitution

**Files:**
- Modify: `rust/crates/batdeob-core/src/lex.rs`

- [ ] **Step 1: Add failing tests**

```rust
    #[test]
    fn percent_var_substr_positive() {
        assert_eq!(
            lex("%X:~0,3%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substr { index: 0, length: Some(3) }),
            }]
        );
    }

    #[test]
    fn percent_var_substr_negative_no_length() {
        assert_eq!(
            lex("%X:~-7%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substr { index: -7, length: None }),
            }]
        );
    }

    #[test]
    fn percent_var_substr_whitespace_in_op() {
        // DOSfuscation pads operator with spaces/tabs
        assert_eq!(
            lex("%X:~   -7,    +3%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substr { index: -7, length: Some(3) }),
            }]
        );
    }

    #[test]
    fn percent_var_substitute_simple() {
        assert_eq!(
            lex("%X:abc=xyz%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substitute {
                    needle: "abc".into(),
                    replacement: "xyz".into(),
                    leading_wildcard: false,
                }),
            }]
        );
    }

    #[test]
    fn percent_var_substitute_wildcard() {
        assert_eq!(
            lex("%X:*abc=xyz%"),
            vec![Token::VarPercent {
                name: "X".into(),
                op: Some(VarOp::Substitute {
                    needle: "abc".into(),
                    replacement: "xyz".into(),
                    leading_wildcard: true,
                }),
            }]
        );
    }
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests percent_var_subs`
Expected: FAILs.

- [ ] **Step 3: Extend `%` / `!` handling**

Replace the variable-lexing inner loop. The shape becomes: parse the name up to either `%`/`!` or a `:`; if `:`, parse either `~i,n` (Substr) or `s1=s2` (Substitute).

Add this helper at the top of `lex.rs`:

```rust
fn parse_substr(rest: &str) -> Option<VarOp> {
    // Expect "~<i>[,<n>]"; whitespace tolerated everywhere
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('~')?;
    let rest = rest.trim_start();
    let (idx_str, after) = take_signed_int(rest);
    let index: i64 = idx_str.parse().ok()?;
    let after = after.trim_start();
    if let Some(after) = after.strip_prefix(',') {
        let after = after.trim_start();
        let (len_str, _) = take_signed_int(after);
        let length: Option<i64> = len_str.parse().ok();
        Some(VarOp::Substr { index, length })
    } else {
        Some(VarOp::Substr { index, length: None })
    }
}

fn take_signed_int(s: &str) -> (String, &str) {
    let mut out = String::new();
    let mut bytes = s.char_indices();
    if let Some((_, c @ ('+' | '-'))) = bytes.clone().next() {
        out.push(c);
        bytes.next();
    }
    let mut last = 0usize;
    for (i, c) in bytes {
        if c.is_ascii_digit() {
            out.push(c);
            last = i + c.len_utf8();
        } else {
            return (out, &s[last..]);
        }
    }
    (out, "")
}

fn parse_substitute(rest: &str) -> Option<VarOp> {
    let (leading_wildcard, rest) = match rest.strip_prefix('*') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let eq = rest.find('=')?;
    let needle = rest[..eq].to_string();
    let replacement = rest[eq + 1..].to_string();
    Some(VarOp::Substitute { needle, replacement, leading_wildcard })
}
```

In the `'%'` arm of `lex`, replace the inner "find matching `%` then push" block with this finite-state form. The name is scanned until either the closing `%` or a `:`:

```rust
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() {
                    let cc = chars[j];
                    if cc == '%' || cc == ':' { break; }
                    if !is_var_name_char(cc) { break; }
                    name.push(cc);
                    j += 1;
                }
                if name.is_empty() {
                    word.push('%');
                    i += 1;
                    continue;
                }
                let mut op: Option<VarOp> = None;
                if j < chars.len() && chars[j] == ':' {
                    // Find closing % for the whole var-ref
                    let mut k = j + 1;
                    while k < chars.len() && chars[k] != '%' { k += 1; }
                    if k >= chars.len() {
                        word.push('%');
                        i += 1;
                        continue;
                    }
                    let op_str: String = chars[j + 1..k].iter().collect();
                    op = if op_str.trim_start().starts_with('~') {
                        parse_substr(&op_str)
                    } else {
                        parse_substitute(&op_str)
                    };
                    out.push(Token::VarPercent { name, op });
                    i = k + 1;
                } else if j < chars.len() && chars[j] == '%' {
                    out.push(Token::VarPercent { name, op: None });
                    i = j + 1;
                } else {
                    word.push('%');
                    i += 1;
                }
```

Mirror the equivalent change in the `'!'` arm (replace `%` with `!`, `Token::VarPercent` with `Token::VarBang`).

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core --lib lex::tests`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lex.rs
git commit -m "Lexer: parse :~i,n substring + :s1=s2 substitution ops"
```

---

## Task 12: Normalizer — variable resolution baseline

**Files:**
- Create: `rust/crates/batdeob-core/src/normalize.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Append to `lib.rs`:

```rust
pub mod normalize;

#[cfg(test)]
mod normalize_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

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
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core normalize_tests`
Expected: `cannot find module 'normalize'`.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/normalize.rs`**

```rust
//! Variable expansion. Walks a token stream and produces a string by
//! resolving %VAR%, !VAR!, positional args, substring, and substitution
//! against an Environment. Recursively re-lexes resolved values so that
//! techniques like `ec%a%ho` (with %a% empty) collapse to `echo`.

use crate::env::Environment;
use crate::lex::{lex, Token, VarOp};
use crate::traits::Trait;

const MAX_REEXPAND_DEPTH: u32 = 32;

/// Render a token stream to its normalized string form against `env`.
pub fn normalize_to_string(tokens: &[Token], env: &mut Environment) -> String {
    normalize_inner(tokens, env, 0)
}

fn normalize_inner(tokens: &[Token], env: &mut Environment, depth: u32) -> String {
    let mut out = String::new();
    for tok in tokens {
        match tok {
            Token::Word(s) => out.push_str(s),
            Token::DoubleQuoted(s) => {
                out.push('"');
                // Inside quotes, %VAR% still expands but operators don't apply.
                // Re-lex the inner content so embedded %FOO% is recognized.
                let inner = lex(s);
                out.push_str(&normalize_inner(&inner, env, depth));
                out.push('"');
            }
            Token::Whitespace => out.push(' '),
            Token::OpAnd => out.push('&'),
            Token::OpAndAnd => out.push_str("&&"),
            Token::OpOr => out.push('|'),
            Token::OpOrOr => out.push_str("||"),
            Token::OpRedirect { fd, append } => {
                if *fd != 1 { out.push_str(&fd.to_string()); }
                out.push('>');
                if *append { out.push('>'); }
            }
            Token::OpInput => out.push('<'),
            Token::OpenParen => out.push('('),
            Token::CloseParen => out.push(')'),
            Token::VarPercent { name, op } => {
                expand_var(env, name, op.as_ref(), &mut out, depth, false);
            }
            Token::VarBang { name, op } => {
                if env.delayed_expansion {
                    if !env.traits.iter().any(|t| matches!(t, Trait::DelayedExpansionUsed)) {
                        env.traits.push(Trait::DelayedExpansionUsed);
                    }
                    expand_var(env, name, op.as_ref(), &mut out, depth, true);
                } else {
                    out.push('!');
                    out.push_str(name);
                    out.push('!');
                }
            }
            Token::PositionalArg(_) | Token::AllArgs | Token::PercentTilde { .. } => {
                // Plan B fills these in. For now expand to empty.
            }
        }
    }
    out
}

fn expand_var(
    env: &mut Environment,
    name: &str,
    op: Option<&VarOp>,
    out: &mut String,
    depth: u32,
    _is_bang: bool,
) {
    let raw = match env.get(name) {
        Some(v) => v,
        None => return, // unset -> empty
    };
    let value = match op {
        None => raw,
        Some(VarOp::Substr { index, length }) => apply_substr(&raw, *index, *length),
        Some(VarOp::Substitute { needle, replacement, leading_wildcard }) => {
            apply_substitute(&raw, needle, replacement, *leading_wildcard)
        }
    };
    // Re-lex/re-normalize the resolved value so nested %X% / carets resolve.
    if depth + 1 >= MAX_REEXPAND_DEPTH {
        out.push_str(&value);
        return;
    }
    if value.contains('%') || value.contains('!') || value.contains('^') {
        let inner = lex(&value);
        out.push_str(&normalize_inner(&inner, env, depth + 1));
    } else {
        out.push_str(&value);
    }
}

fn apply_substr(s: &str, index: i64, length: Option<i64>) -> String {
    // Operate on Unicode chars, not bytes — matches Python.
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len() as i64;
    let mut start = if index < 0 { (len + index).max(0) } else { index.min(len) };
    if start < 0 { start = 0; }
    let end = match length {
        None => len,
        Some(n) if n >= 0 => (start + n).min(len),
        Some(n) => (len + n).max(start),
    };
    if end <= start { return String::new(); }
    chars[start as usize..end as usize].iter().collect()
}

fn apply_substitute(s: &str, needle: &str, repl: &str, wildcard: bool) -> String {
    if needle.is_empty() { return s.to_string(); }
    let lower = s.to_ascii_lowercase();
    let nlower = needle.to_ascii_lowercase();
    if wildcard {
        if let Some(pos) = lower.find(&nlower) {
            let after = &s[pos + needle.len()..];
            let mut o = String::with_capacity(repl.len() + after.len());
            o.push_str(repl);
            o.push_str(after);
            return o;
        }
        return s.to_string();
    }
    // Case-insensitive replace-all
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        // Match needle at byte position i (case-insensitive on ASCII; multi-byte chars passthrough)
        if i + needle.len() <= bytes.len()
            && s[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            out.push_str(repl);
            i += needle.len();
        } else {
            let c = s[i..].chars().next().unwrap_or('\0');
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}
```

The `unwrap_or('\0')` on `chars().next()` is unreachable (we've already checked `i < bytes.len()`), but is the simplest panic-free formulation. Clippy may flag — if so, replace with `match s[i..].chars().next() { Some(c) => …, None => break }`.

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core normalize_tests`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add normalizer with %VAR% / !VAR! / substr / substitute"
```

---

## Task 13: Normalizer — DOSfuscation parity tests

**Files:**
- Modify: `rust/crates/batdeob-core/src/normalize.rs` (tests only)

- [ ] **Step 1: Add the spec's DOSfuscation parametric cases as Rust tests**

Append to `normalize.rs` (or add a new tests module — pick one location):

```rust
#[cfg(test)]
mod dosfuscation_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    fn nm(input: &str) -> String {
        let mut env = Environment::new(&Config::default());
        normalize_to_string(&lex(input), &mut env)
    }

    // From batch_deobfuscator/tests/test_FE_DOSfuscation.py test_variable_manipulation
    #[test] fn comspec_plain()              { assert_eq!(nm("%COMSPEC%"),               "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_zero()               { assert_eq!(nm("%COMSPEC:~0%"),            "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_zero_27()            { assert_eq!(nm("%COMSPEC:~0,27%"),         "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_neg7()               { assert_eq!(nm("%COMSPEC:~-7%"),           "cmd.exe"); }
    #[test] fn comspec_neg27()              { assert_eq!(nm("%COMSPEC:~-27%"),          "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_neg7_neg4()          { assert_eq!(nm("%COMSPEC:~-7,-4%"),        "cmd"); }
    #[test] fn comspec_neg7_3()             { assert_eq!(nm("%COMSPEC:~-7,3%"),         "cmd"); }
    #[test] fn comspec_zero_huge()          { assert_eq!(nm("%COMSPEC:~0,1337%"),       "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_huge_neg()           { assert_eq!(nm("%COMSPEC:~-1337%"),        "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_huge_neg_huge()      { assert_eq!(nm("%COMSPEC:~-1337,1337%"),   "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_neg40_3()            { assert_eq!(nm("%COMSPEC:~-40,3%"),        "C:\\"); }
    #[test] fn comspec_neg1_1()             { assert_eq!(nm("%COMSPEC:~-1,1%"),         "e"); }

    #[test] fn comspec_slash_swap()         { assert_eq!(nm("%COMSPEC:\\=/%"),          "C:/WINDOWS/system32/cmd.exe"); }
    #[test] fn comspec_no_match()           { assert_eq!(nm("%COMSPEC:KeepMatt=Happy%"), "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_wildcard_strip()     { assert_eq!(nm("%COMSPEC:*System32\\=%"),  "cmd.exe"); }
    #[test] fn comspec_wildcard_no_match()  { assert_eq!(nm("%COMSPEC:*Tea=Coffee%"),   "C:\\WINDOWS\\system32\\cmd.exe"); }
    #[test] fn comspec_wildcard_lower_e()   { assert_eq!(nm("%COMSPEC:*e=z%"),          "zm32\\cmd.exe"); }
    #[test] fn comspec_wildcard_upper_e()   { assert_eq!(nm("%COMSPEC:*e=Z%"),          "Zm32\\cmd.exe"); }
    #[test] fn comspec_s_to_z()             { assert_eq!(nm("%COMSPEC:s=z%"),           "C:\\WINDOWz\\zyztem32\\cmd.exe"); }
    #[test] fn comspec_drop_s()             { assert_eq!(nm("%COMSPEC:s=%"),            "C:\\WINDOW\\ytem32\\cmd.exe"); }
    #[test] fn comspec_wildcard_caps()      { assert_eq!(nm("%COMSPEC:*S=A%"),          "A\\system32\\cmd.exe"); }
    #[test] fn comspec_wildcard_lower()     { assert_eq!(nm("%COMSPEC:*s=A%"),          "A\\system32\\cmd.exe"); }
    #[test] fn comspec_case_swap()          { assert_eq!(nm("%COMSPEC:cMD=BlA%"),       "C:\\WINDOWS\\system32\\BlA.exe"); }

    #[test] fn whitespace_in_op()           { assert_eq!(nm("%coMSPec:~   -7,    +3%"), "cmd"); }
    #[test] fn whitespace_tabs_in_op()      { assert_eq!(nm("%coMSPec:~\t-7,\t+3%"),    "cmd"); }
    #[test] fn assembled_set_token()        { assert_eq!(nm("%comspec:~-16,1%%comspec:~-1%%comspec:~-13,1%"), "set"); }

    // From test_FE_DOSfuscation.py test_empty_var
    #[test] fn empty_var_sandwich() {
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex(r#"ec%a%ho "Fi%b%nd Ev%c%il!""#), &mut env);
        assert_eq!(out, r#"echo "Find Evil""#);
    }
}
```

- [ ] **Step 2: Run them**

Run: `cd rust && cargo test --package batdeob-core dosfuscation_tests`
Expected: all PASS. If any fail, debug the substring/substitute helpers against the failing case before continuing.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/batdeob-core/src/normalize.rs
git commit -m "Add DOSfuscation parity tests for variable manipulation"
```

---

## Task 14: Command splitter

**Files:**
- Create: `rust/crates/batdeob-core/src/split.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Append to `lib.rs`:

```rust
pub mod split;

#[cfg(test)]
mod split_tests {
    use crate::split::split_commands;

    #[test]
    fn simple_one() {
        assert_eq!(split_commands("echo hi"), vec!["echo hi"]);
    }

    #[test]
    fn ampersand_splits() {
        assert_eq!(
            split_commands("echo a && echo b"),
            vec!["echo a", "echo b"]
        );
    }

    #[test]
    fn pipe_splits() {
        assert_eq!(
            split_commands("echo a | find b"),
            vec!["echo a", "find b"]
        );
    }

    #[test]
    fn caret_escapes_pipe() {
        // The caret-escape prevents splitting
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
        // 2>&1 — the & after > is not a command separator
        assert_eq!(
            split_commands("foo 2>&1"),
            vec!["foo 2>&1"]
        );
    }
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core split_tests`
Expected: `cannot find module 'split'`.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/split.rs`**

```rust
//! Split a logical line into individual commands at top-level
//! `& && | ||` operators, respecting double-quotes and caret-escapes.

pub fn split_commands(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_dq = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '^' && i + 1 < chars.len() {
            i += 2;
            continue;
        }
        if c == '"' { in_dq = !in_dq; i += 1; continue; }
        if in_dq { i += 1; continue; }

        // Skip operator-internal & after >
        if c == '&' && i > 0 && chars[i - 1] == '>' {
            i += 1;
            continue;
        }
        if c == '&' || c == '|' {
            let seg = chars[start..i].iter().collect::<String>();
            let trimmed = seg.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
            // Step over && / ||
            if chars.get(i + 1) == Some(&c) {
                i += 2;
            } else {
                i += 1;
            }
            start = i;
            continue;
        }
        i += 1;
    }
    let seg: String = chars[start..].iter().collect();
    let trimmed = seg.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    out
}
```

- [ ] **Step 4: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core split_tests`
Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add command splitter for & && | || with quoting + caret"
```

---

## Task 15: Handler dispatch skeleton

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Create: `rust/crates/batdeob-core/src/interp.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing test**

Append to `lib.rs`:

```rust
pub mod handlers;
pub mod interp;

#[cfg(test)]
mod interp_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn echo_is_no_op_for_now() {
        let mut env = Environment::new(&Config::default());
        // Should not panic and not modify env.
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
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core interp_tests`
Expected: `cannot find module`.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/handlers/mod.rs`**

```rust
//! Per-command handlers and dispatch table.

use crate::env::Environment;

pub type Handler = fn(raw: &str, env: &mut Environment);

/// Return the handler for a command name, or None for unknown.
pub fn lookup(name: &str) -> Option<Handler> {
    let lower = name.to_ascii_lowercase();
    // Real handlers added in later tasks. For now, return None for everything.
    let _ = lower;
    None
}
```

- [ ] **Step 4: Write `rust/crates/batdeob-core/src/interp.rs`**

```rust
//! Interpreter — dispatches a normalized command string to its handler.

use crate::env::Environment;
use crate::handlers;

pub fn interpret_line(line: &str, env: &mut Environment) {
    let Some(name) = command_name(line) else { return };
    if let Some(handler) = handlers::lookup(&name) {
        handler(line, env);
    }
}

/// Extract the command name from a normalized line: the first token before
/// whitespace, '/' (for `set/p`-style), or a redirection operator.
pub fn command_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start_matches(|c: char| c == '@' || c == '(' || c.is_whitespace());
    if trimmed.is_empty() { return None; }
    let mut name = String::new();
    for c in trimmed.chars() {
        if c.is_whitespace() || c == '/' || c == '<' || c == '>' || c == '&' || c == '|' {
            break;
        }
        name.push(c);
    }
    if name.is_empty() { None } else { Some(name) }
}
```

- [ ] **Step 5: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core interp_tests`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add interpreter dispatch skeleton + command-name extraction"
```

---

## Task 16: `set` handler — basic name=value

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/set.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`

- [ ] **Step 1: Write failing tests**

Append to `interp.rs` (or create `interp_tests` more thoroughly):

```rust
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
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core set_tests`
Expected: FAILs (no handler registered).

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/handlers/set.rs`**

```rust
//! `set` command handler. Mirrors batch_interpreter.py:interpret_set.

use crate::env::Environment;

pub fn h_set(raw: &str, env: &mut Environment) {
    // Strip the leading `set` (and optional /a, /p — Plan B adds /a evaluator,
    // /p file-redirect; for now we only handle plain set NAME=VALUE forms).
    let rest = match strip_set_prefix(raw) {
        Some(r) => r,
        None => return,
    };

    // Empty body? `set` with no args is a no-op for now (Plan B: dump env).
    if rest.trim().is_empty() {
        return;
    }

    // Quoted form: set "NAME=VALUE"
    let body = rest.trim_start();
    if let Some(inner) = quoted_form(body) {
        if let Some((name, value)) = split_eq(inner) {
            env.set(name, value);
        }
        return;
    }

    // Unquoted: trailing newline already stripped by line_reader
    if let Some((name, value)) = split_eq(body) {
        env.set(name, value);
    }
}

fn strip_set_prefix(raw: &str) -> Option<&str> {
    let raw = raw.trim_start();
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("set") {
        let rest = &raw[3..];
        // After 'set' must be whitespace, '/', or '"' (quoted form attached)
        if let Some(c) = rest.chars().next() {
            if c.is_whitespace() || c == '/' || c == '"' {
                return Some(rest);
            }
        }
        if rest.is_empty() { return Some(rest); }
    }
    None
}

fn quoted_form(body: &str) -> Option<&str> {
    let body = body.trim_start();
    let bytes = body.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    // Find LAST '"' in the body (cmd.exe behavior)
    let last = body.rfind('"')?;
    if last == 0 { return None; }
    Some(&body[1..last])
}

fn split_eq(s: &str) -> Option<(&str, &str)> {
    let eq = s.find('=')?;
    Some((&s[..eq], &s[eq + 1..]))
}
```

- [ ] **Step 4: Register the handler**

Replace `handlers/mod.rs` `lookup`:

```rust
pub mod set;

pub fn lookup(name: &str) -> Option<Handler> {
    match name.to_ascii_lowercase().as_str() {
        "set" => Some(set::h_set),
        _ => None,
    }
}
```

- [ ] **Step 5: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core set_tests`
Expected: 5 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/handlers/
git commit -m "Add `set` handler: name=value, quoted form, trailing spaces"
```

---

## Task 17: `analyze` orchestrator

**Files:**
- Modify: `rust/crates/batdeob-core/src/lib.rs`
- Modify: `rust/crates/batdeob-core/src/interp.rs`

- [ ] **Step 1: Write failing integration-style test**

Append to `lib.rs`:

```rust
#[cfg(test)]
mod analyze_tests {
    use crate::env::Config;
    use crate::analyze;

    #[test]
    fn analyze_resolves_var_chain() {
        let script = b"set GREET=hi\r\necho %GREET% world\r\n";
        let report = analyze(script, &Config::default());
        assert!(
            report.deobfuscated.contains("echo hi world"),
            "deobf:\n{}", report.deobfuscated
        );
    }

    #[test]
    fn analyze_handles_caret_continuation_and_split() {
        let script = b"set X=hello & echo %X%\r\n";
        let report = analyze(script, &Config::default());
        assert!(report.deobfuscated.contains("echo hello"), "deobf:\n{}", report.deobfuscated);
    }
}
```

- [ ] **Step 2: Add the API**

At the end of `lib.rs`:

```rust
pub use env::{Config, Environment, WinVer};
pub use traits::Trait;

#[derive(Debug, Clone)]
pub struct Report {
    pub deobfuscated: String,
    pub traits: Vec<Trait>,
    pub extracted_cmd: Vec<String>,
    pub extracted_ps1: Vec<Vec<u8>>,
}

/// Top-level entry point: read logical lines, normalize each, dispatch
/// to handlers, accumulate the deobfuscated text and traits.
pub fn analyze(input: &[u8], cfg: &Config) -> Report {
    let mut env = Environment::new(cfg);
    let mut out = String::new();
    for logical in line_reader::read_logical_lines(input) {
        for cmd in split::split_commands(&logical) {
            let toks = lex::lex(&cmd);
            let normalized = normalize::normalize_to_string(&toks, &mut env);
            interp::interpret_line(&normalized, &mut env);
            out.push_str(&normalized);
            out.push_str("\r\n");
        }
    }
    Report {
        deobfuscated: out,
        traits: std::mem::take(&mut env.traits),
        extracted_cmd: std::mem::take(&mut env.exec_cmd),
        extracted_ps1: std::mem::take(&mut env.exec_ps1),
    }
}
```

- [ ] **Step 3: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core analyze_tests`
Expected: 2 PASS.

Run: `cd rust && cargo test --package batdeob-core` (all tests)
Expected: every test PASS.

- [ ] **Step 4: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add analyze() orchestrator: read -> split -> lex -> normalize -> interp"
```

---

## Task 18: CLI — `deob` subcommand

**Files:**
- Modify: `rust/crates/batdeob-cli/Cargo.toml`
- Modify: `rust/crates/batdeob-cli/src/main.rs`
- Create: `rust/crates/batdeob-cli/tests/cli.rs`

- [ ] **Step 1: Add CLI deps**

Edit `rust/crates/batdeob-cli/Cargo.toml` `[dependencies]`:

```toml
[dev-dependencies]
assert_cmd = { workspace = true }
tempfile = { workspace = true }
predicates = "3"
```

- [ ] **Step 2: Write failing CLI test**

Create `rust/crates/batdeob-cli/tests/cli.rs`:

```rust
use assert_cmd::Command;
use tempfile::TempDir;
use std::fs;

#[test]
fn deob_writes_deobfuscated_file() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "set X=hi\r\necho %X%\r\n").expect("write");
    let out_dir = dir.path().join("out");
    Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["deob", input.to_str().expect("path"), "-o", out_dir.to_str().expect("path")])
        .assert()
        .success();
    let deob = out_dir.join("deobfuscated.bat");
    assert!(deob.exists(), "deobfuscated.bat not produced");
    let contents = fs::read_to_string(&deob).expect("read");
    assert!(contents.contains("echo hi"), "got:\n{}", contents);
}

#[test]
fn analyze_emits_json_to_stdout() {
    let dir = TempDir::new().expect("tmp");
    let input = dir.path().join("in.bat");
    fs::write(&input, "echo plain\r\n").expect("write");
    let out = Command::cargo_bin("batdeob")
        .expect("bin")
        .args(["analyze", input.to_str().expect("path")])
        .output()
        .expect("run");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"deobfuscated\""), "stdout:\n{}", s);
}
```

- [ ] **Step 3: Verify they fail**

Run: `cd rust && cargo test --package batdeob-cli`
Expected: FAIL — bin doesn't accept those args yet.

- [ ] **Step 4: Write `rust/crates/batdeob-cli/src/main.rs`**

```rust
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

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
    },
    /// Like `deob --json-only`: JSON report to stdout, no files.
    Analyze { file: String },
    /// Print version and exit.
    Version,
}

fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).context("read stdin")?;
        Ok(buf)
    } else {
        fs::read(path).with_context(|| format!("read {}", path))
    }
}

fn make_config(
    max_depth: u32,
    max_iterations: u64,
    max_child_scripts: u32,
    timeout: u64,
    self_extract: bool,
) -> batdeob_core::Config {
    batdeob_core::Config {
        max_depth,
        max_iterations,
        max_child_scripts,
        timeout_secs: timeout,
        self_extract,
        winver: batdeob_core::WinVer::Win10,
    }
}

fn write_report_files(report: &batdeob_core::Report, out_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("mkdir {:?}", out_dir))?;
    fs::write(out_dir.join("deobfuscated.bat"), &report.deobfuscated)
        .context("write deobfuscated.bat")?;
    // Plan B writes extracted children with sha-prefixed names.
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("batdeob {}", batdeob_core::version());
        }
        Command::Analyze { file } => {
            let input = read_input(&file)?;
            let cfg = batdeob_core::Config::default();
            let report = batdeob_core::analyze(&input, &cfg);
            let json = serde_json::json!({
                "deobfuscated": report.deobfuscated,
                "traits": report.traits,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        Command::Deob {
            file, out_dir, json, json_only,
            max_depth, max_iterations, max_child_scripts, timeout,
            no_self_extract,
        } => {
            let input = read_input(&file)?;
            let cfg = make_config(max_depth, max_iterations, max_child_scripts, timeout, !no_self_extract);
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
```

- [ ] **Step 5: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-cli`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-cli/
git commit -m "Add CLI: deob / analyze / version subcommands"
```

---

## Task 19: `echo` handler + redirection capture

**Files:**
- Create: `rust/crates/batdeob-core/src/redirect.rs`
- Create: `rust/crates/batdeob-core/src/handlers/echo.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

Append to `lib.rs`:

```rust
pub mod redirect;

#[cfg(test)]
mod echo_tests {
    use crate::env::{Config, Environment, FsEntry};
    use crate::interp::interpret_line;

    #[test]
    fn echo_to_file_records_content() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#">%TEMP%\out.txt echo hello"#, &mut env);
        // %TEMP% resolves before interpret_line runs in analyze(); here we pass the literal.
        // For the unit test we just check the path-as-given.
        let key = r"%temp%\out.txt"; // env is lowercased by handler
        assert!(
            env.modified_filesystem.contains_key(key)
                || env.modified_filesystem.keys().any(|k| k.ends_with(r"\out.txt")),
            "filesystem: {:?}", env.modified_filesystem
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
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core echo_tests`
Expected: FAILs.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/redirect.rs`**

```rust
//! Extract redirection targets from a normalized command string. Returns
//! the cleaned-of-redirection command body and a RedirectionSet.

use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectionSet {
    pub stdout: Option<RedirTarget>,
    pub stderr: Option<RedirTarget>,
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirTarget {
    Trunc(String),
    Append(String),
}

impl RedirTarget {
    pub fn path(&self) -> &str {
        match self {
            RedirTarget::Trunc(p) | RedirTarget::Append(p) => p,
        }
    }
    pub fn append(&self) -> bool {
        matches!(self, RedirTarget::Append(_))
    }
}

// Match a redirection at any position. fd? > or >> or 1> 2> 1>> 2>> < <path>
static REDIR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?P<lead>^|\s)(?P<fd>[12])?(?P<op>>>|>|<)\s*(?P<tgt>"(?:[^"]|"")*"|[^\s|&<>]+)"#
    ).expect("redir regex compiles")
});

pub fn extract_redirections(cmd: &str) -> (String, RedirectionSet) {
    let mut set = RedirectionSet::default();
    let mut cleaned = cmd.to_string();
    loop {
        let m = match REDIR_RE.captures(&cleaned) {
            Some(m) => m,
            None => break,
        };
        let fd: u8 = m.name("fd").map(|s| s.as_str()).and_then(|s| s.parse().ok()).unwrap_or(1);
        let op = m.name("op").map(|x| x.as_str()).unwrap_or(">");
        let mut tgt = m.name("tgt").map(|x| x.as_str()).unwrap_or("").to_string();
        if tgt.starts_with('"') && tgt.ends_with('"') && tgt.len() >= 2 {
            tgt = tgt[1..tgt.len() - 1].to_string();
        }
        match op {
            "<" => set.stdin = Some(tgt),
            ">" | ">>" => {
                let target = if op == ">>" { RedirTarget::Append(tgt) } else { RedirTarget::Trunc(tgt) };
                if fd == 2 { set.stderr = Some(target); } else { set.stdout = Some(target); }
            }
            _ => {}
        }
        // Strip the matched span (including the leading whitespace it captured)
        let range = m.get(0).map(|x| x.range()).unwrap_or(0..0);
        cleaned.replace_range(range, " ");
    }
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    (cleaned, set)
}
```

The `unwrap()` on regex compile is a static lazy init; if it panics, the binary fails to start with a stable error. That's the right behavior for a compile-time-correct regex; we keep it as `.expect("regex compiles")` and document. (Lints permit `expect_used` inside `Lazy` initializers if you add `#[allow(clippy::expect_used)]` at the top of the file.)

- [ ] **Step 4: Write `rust/crates/batdeob-core/src/handlers/echo.rs`**

```rust
//! `echo` handler — records redirected output into modified_filesystem.

use crate::env::{Environment, FsEntry};
use crate::redirect::extract_redirections;
use crate::traits::Trait;

pub fn h_echo(raw: &str, env: &mut Environment) {
    let (cleaned, redir) = extract_redirections(raw);
    // Strip leading `echo` token
    let body = cleaned
        .trim_start()
        .strip_prefix("echo")
        .or_else(|| cleaned.trim_start().strip_prefix("ECHO"))
        .or_else(|| cleaned.trim_start().strip_prefix("Echo"))
        .unwrap_or(&cleaned);
    let payload = body.trim_start().to_string();

    let Some(target) = redir.stdout else { return };
    let path = target.path().to_string();
    let append = target.append();

    // Compute the content: "<payload>\r\n", and if appending, prepend prior bytes.
    let mut content = payload.into_bytes();
    content.extend_from_slice(b"\r\n");
    let key = path.to_ascii_lowercase();
    if append {
        if let Some(FsEntry::Content { content: prior, .. }) = env.modified_filesystem.get(&key) {
            let mut combined = prior.clone();
            combined.extend_from_slice(&content);
            content = combined;
        }
    }
    env.traits.push(Trait::EchoRedirect {
        content: content.clone(),
        target: path,
        append,
    });
    env.modified_filesystem.insert(key, FsEntry::Content { content, append });
}
```

- [ ] **Step 5: Register and verify**

Edit `handlers/mod.rs`:

```rust
pub mod echo;

pub fn lookup(name: &str) -> Option<Handler> {
    match name.to_ascii_lowercase().as_str() {
        "set"  => Some(set::h_set),
        "echo" => Some(echo::h_echo),
        _ => None,
    }
}
```

Run: `cd rust && cargo test --package batdeob-core echo_tests`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add echo handler with > / >> redirection capture"
```

---

## Task 20: Port `tests/test_unittests.py` parity suite (subset)

We add a Rust integration test that exercises a curated subset of the Python parity tests. Plans B and C add more.

**Files:**
- Create: `rust/crates/batdeob-core/tests/parity_basic.rs`

- [ ] **Step 1: Write the parity tests**

Create `rust/crates/batdeob-core/tests/parity_basic.rs`:

```rust
//! Parity tests against the Python batch_deobfuscator suite.
//! Source: ../../batch_deobfuscator/tests/test_unittests.py

use batdeob_core::{analyze, Config};
use pretty_assertions::assert_eq;

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
    // From test_caret_pipe — caret-escaped operators should round-trip.
    let out = deob(r#"echo tasklist /fi "imagename eq jin.exe" ^| find ":" ^>NUL"#);
    assert!(out.contains(r#"^|"#), "expected literal ^|: {}", out);
    assert!(out.contains(r#"^>NUL"#), "expected literal ^>NUL: {}", out);
}

#[test]
fn comma_semicolon_splits_into_commands() {
    // From test_FE_DOSfuscation::test_comma_semi_colon
    let out = deob(",;,cmd.exe,;,/c,;,echo;Command 1&&echo,Command 2");
    // We expect two lines, each beginning with the resolved command.
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.len() >= 2, "expected 2+ lines, got: {:?}", lines);
    // First line resolves the cmd.exe /c echo Command 1 portion
    assert!(lines[0].contains("cmd.exe"), "line0: {}", lines[0]);
    assert!(lines[0].contains("Command 1"), "line0: {}", lines[0]);
    assert!(lines.iter().any(|l| l.contains("echo Command 2")), "lines: {:?}", lines);
}

#[test]
fn empty_var_sandwich_collapses() {
    // ec%a%ho "Fi%b%nd Ev%c%il!" => echo "Find Evil"
    let out = deob(r#"ec%a%ho "Fi%b%nd Ev%c%il!""#);
    assert!(out.contains(r#"echo "Find Evil""#), "got:\n{}", out);
}
```

- [ ] **Step 2: Run them**

Run: `cd rust && cargo test --package batdeob-core --test parity_basic`
Expected: 5 PASS.

- [ ] **Step 3: Commit**

```bash
git add rust/crates/batdeob-core/tests/parity_basic.rs
git commit -m "Add Python parity tests for set/unset/caret/comma/sandwich"
```

---

## Task 21: `cmd /c` extraction

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/cmd.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing test**

Append to `lib.rs`:

```rust
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
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core cmd_tests`
Expected: FAILs.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/handlers/cmd.rs`**

```rust
//! cmd / cmd.exe / *cmd.exe handler — extracts the /c or /r body for
//! recursive deobfuscation. Mirrors batch_interpreter.py line 870-875.

use crate::env::Environment;
use once_cell::sync::Lazy;
use regex::Regex;

static CMD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^\s*\S*cmd(?:\.exe)?\s*(?:(?:/a|/u|/q|/d)\s+|(?:/[ef]:(?:on|off))\s*|/v(?::(?:on|off))?\s*)*(?:/c|/r)\s+(?P<cmd>.*)$"
    ).expect("cmd regex")
});

pub fn h_cmd(raw: &str, env: &mut Environment) {
    let Some(caps) = CMD_RE.captures(raw) else { return };
    let mut inner = caps.name("cmd").map(|m| m.as_str()).unwrap_or("").trim().to_string();
    // Strip surrounding quotes
    if inner.starts_with('"') && inner.ends_with('"') && inner.len() >= 2 {
        inner = inner[1..inner.len() - 1].to_string();
    }
    if !inner.is_empty() {
        env.exec_cmd.push(inner);
    }
}
```

- [ ] **Step 4: Register**

Edit `handlers/mod.rs`:

```rust
pub mod cmd;

pub fn lookup(name: &str) -> Option<Handler> {
    let lower = name.to_ascii_lowercase();
    if lower == "cmd" || lower.ends_with("cmd") || lower.ends_with("cmd.exe") {
        return Some(cmd::h_cmd);
    }
    match lower.as_str() {
        "set"  => Some(set::h_set),
        "echo" => Some(echo::h_echo),
        _ => None,
    }
}
```

- [ ] **Step 5: Verify tests pass**

Run: `cd rust && cargo test --package batdeob-core cmd_tests`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add cmd /c handler that queues inner command for recursion"
```

---

## Task 22: Recursive child-cmd drain in `analyze`

**Files:**
- Modify: `rust/crates/batdeob-core/src/lib.rs`

- [ ] **Step 1: Write failing test**

Append to `lib.rs`:

```rust
#[cfg(test)]
mod child_tests {
    use crate::{analyze, Config};

    #[test]
    fn nested_cmd_c_recurses_into_child() {
        let script = br#"cmd /c "set X=hi&&echo %X% world""#;
        let report = analyze(script, &Config::default());
        // The top-level cmd is deobfuscated, AND the child is recursively expanded.
        let combined = format!(
            "{}\n--children--\n{}",
            report.deobfuscated,
            report.extracted_cmd.join("\n---\n")
        );
        assert!(
            combined.contains("echo hi world") || report.deobfuscated.contains("echo hi world"),
            "no echo hi world in:\n{}", combined
        );
    }
}
```

- [ ] **Step 2: Verify it fails**

Run: `cd rust && cargo test --package batdeob-core child_tests`
Expected: FAIL — children aren't recursed yet.

- [ ] **Step 3: Modify `analyze` to drain children**

Replace the `analyze` function in `lib.rs`:

```rust
pub fn analyze(input: &[u8], cfg: &Config) -> Report {
    let mut env = Environment::new(cfg);
    let mut out = String::new();
    drive(input, &mut env, &mut out, 0, cfg.max_depth);
    Report {
        deobfuscated: out,
        traits: std::mem::take(&mut env.traits),
        extracted_cmd: std::mem::take(&mut env.exec_cmd),
        extracted_ps1: std::mem::take(&mut env.exec_ps1),
    }
}

fn drive(input: &[u8], env: &mut Environment, out: &mut String, depth: u32, max_depth: u32) {
    if depth >= max_depth {
        env.traits.push(crate::traits::Trait::DepthCapped { command: "(top-level)".to_string() });
        return;
    }
    for logical in line_reader::read_logical_lines(input) {
        for cmd in split::split_commands(&logical) {
            let toks = lex::lex(&cmd);
            let normalized = normalize::normalize_to_string(&toks, env);
            interp::interpret_line(&normalized, env);
            out.push_str(&normalized);
            out.push_str("\r\n");
            // Drain any newly-queued child cmds before continuing
            let pending: Vec<String> = std::mem::take(&mut env.exec_cmd);
            for child in pending {
                drive(child.as_bytes(), env, out, depth + 1, max_depth);
            }
        }
    }
}
```

- [ ] **Step 4: Verify it passes**

Run: `cd rust && cargo test --package batdeob-core child_tests`
Expected: PASS.

Run: `cd rust && cargo test --package batdeob-core`
Expected: all tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/lib.rs
git commit -m "analyze: recursively drain child cmds with depth cap"
```

---

## Task 23: `start` handler

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/cmd.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`

- [ ] **Step 1: Write failing test**

Append to `lib.rs`:

```rust
#[cfg(test)]
mod start_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;

    #[test]
    fn start_strips_flags_and_runs_inner() {
        let mut env = Environment::new(&Config::default());
        env.set("PAYLOAD", "echo hi");
        interpret_line("start /min %PAYLOAD%", &mut env);
        // Plain `start <cmd>` recurses into <cmd>; the cmd here is `echo hi`,
        // which has no observable side effect yet — but we should NOT have
        // pushed anything to exec_cmd (start != cmd /c).
        assert!(env.exec_cmd.is_empty(), "start should not enqueue: {:?}", env.exec_cmd);
    }
}
```

This test by itself is weak (we don't yet observe `echo` side effects). It primarily guards against false `exec_cmd` pushes from `start`. We strengthen with an integration test later.

- [ ] **Step 2: Add `h_start` to `cmd.rs`**

Append to `handlers/cmd.rs`:

```rust
static START_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^\s*start(?:\.exe)?(?:\s+/(?:min|max|wait|low|normal|abovenormal|belownormal|high|realtime|b|i|w))*\s+(?P<cmd>.+)$"
    ).expect("start regex")
});

pub fn h_start(raw: &str, env: &mut Environment) {
    let Some(caps) = START_RE.captures(raw) else { return };
    let inner = caps.name("cmd").map(|m| m.as_str()).unwrap_or("").trim();
    if inner.is_empty() { return }
    // Recurse: interpret the inner command inline. We do NOT push to exec_cmd
    // because start is in-process (Plan B may revisit /b parallelism).
    crate::interp::interpret_line(inner, env);
}
```

- [ ] **Step 3: Register**

Edit `handlers/mod.rs`:

```rust
        "start" => Some(cmd::h_start),
```

- [ ] **Step 4: Verify**

Run: `cd rust && cargo test --package batdeob-core start_tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add start handler that strips flags and recurses inline"
```

---

## Task 24: PowerShell `-EncodedCommand` extraction

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/powershell.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`

- [ ] **Step 1: Write failing test**

Append to `lib.rs`:

```rust
#[cfg(test)]
mod powershell_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use base64::Engine;

    #[test]
    fn powershell_encoded_command_extracts() {
        let payload = "Write-Host hi";
        // UTF-16-LE bytes of payload, base64
        let utf16: Vec<u8> = payload
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let mut env = Environment::new(&Config::default());
        interpret_line(&format!("powershell -EncodedCommand {}", b64), &mut env);
        assert_eq!(env.exec_ps1.len(), 1);
        // Stored as raw decoded bytes; convert back for assertion
        let stored = String::from_utf8_lossy(&env.exec_ps1[0]).into_owned();
        // Decoded bytes minus the nulls equals the original
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
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core powershell_tests`
Expected: FAILs.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/handlers/powershell.rs`**

```rust
//! PowerShell handler — captures -EncodedCommand / -Command arguments into
//! env.exec_ps1 for child extraction. Mirrors batch_interpreter.py
//! interpret_powershell.

use crate::env::Environment;
use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;

// abbreviations: -e / -ec / -enc / -encodedcommand (case-insensitive)
static ENC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[-/]e(c|n(c(o(d(e(d(c(o(m(m(a(nd?)?)?)?)?)?)?)?)?)?)?)?)?$").expect("enc")
});
static CMD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[-/]c(o(m(m(a(nd?)?)?)?)?)?$").expect("cmd")
});
static FILE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^[-/]f(i(l(e?)?)?)?$").expect("file")
});

pub fn h_powershell(raw: &str, env: &mut Environment) {
    // Tokenize on whitespace, preserving quoted strings
    let tokens = simple_split(raw);
    if tokens.is_empty() { return; }
    // The first token is the powershell invocation; we look at the rest
    let mut i = 1usize;
    while i < tokens.len() {
        let t = &tokens[i];
        if ENC_RE.is_match(t) {
            if let Some(next) = tokens.get(i + 1) {
                let mut s = next.clone();
                if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
                    s = s[1..s.len() - 1].to_string();
                }
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) {
                    env.exec_ps1.push(decoded);
                }
            }
            return;
        }
        if CMD_RE.is_match(t) {
            // Everything after this token is the command body
            let body = tokens[i + 1..].join(" ");
            let body = body.trim();
            let body = body.trim_matches('"').trim_matches('\'');
            if !body.is_empty() {
                env.exec_ps1.push(body.as_bytes().to_vec());
            }
            return;
        }
        if FILE_RE.is_match(t) {
            // -File <path>: not worth extracting the path as content
            return;
        }
        i += 1;
    }
    // No flag matched. Fall back: the last quoted-or-bare argument may be the script.
    if let Some(last) = tokens.last() {
        let s = last.trim_matches('"').trim_matches('\'');
        if !s.is_empty() {
            env.exec_ps1.push(s.as_bytes().to_vec());
        }
    }
}

fn simple_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    for c in s.chars() {
        if c == '"' && !in_sq { in_dq = !in_dq; cur.push(c); continue; }
        if c == '\'' && !in_dq { in_sq = !in_sq; cur.push(c); continue; }
        if c.is_whitespace() && !in_dq && !in_sq {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}
```

- [ ] **Step 4: Register**

Edit `handlers/mod.rs`:

```rust
pub mod powershell;

// inside lookup():
    if lower.ends_with("powershell") || lower.ends_with("powershell.exe") || lower == "pwsh" {
        return Some(powershell::h_powershell);
    }
```

- [ ] **Step 5: Verify**

Run: `cd rust && cargo test --package batdeob-core powershell_tests`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add powershell handler: -EncodedCommand + -Command extraction"
```

---

## Task 25: `curl` handler

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/curl.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`

- [ ] **Step 1: Write failing tests**

Append to `lib.rs`:

```rust
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
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Download { dst: Some(d), .. } if d == "foo.exe"
        ));
        assert!(has, "traits: {:?}", env.traits);
    }

    #[test]
    fn curl_without_output_records_src_only() {
        let mut env = Environment::new(&Config::default());
        interpret_line("curl http://x/y", &mut env);
        let has = env.traits.iter().any(|t| matches!(t,
            Trait::Download { src, dst: None, .. } if src == "http://x/y"
        ));
        assert!(has, "traits: {:?}", env.traits);
    }
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core curl_tests`
Expected: FAILs.

- [ ] **Step 3: Write `rust/crates/batdeob-core/src/handlers/curl.rs`**

```rust
//! curl handler — extracts URL + output target. Mirrors interpret_curl.

use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_curl(raw: &str, env: &mut Environment) {
    // crude windows-cmdline split (sufficient for curl invocations)
    let tokens = split_words(raw);
    let mut output: Option<String> = None;
    let mut remote_name = false;
    let mut url: Option<String> = None;
    let mut i = 1;
    while i < tokens.len() {
        let t = &tokens[i];
        match t.as_str() {
            "-o" | "--output" => {
                if let Some(v) = tokens.get(i + 1) {
                    output = Some(strip_quotes(v).to_string());
                }
                i += 2;
                continue;
            }
            "-O" | "--remote-name" => {
                remote_name = true;
                i += 1;
                continue;
            }
            // Skip values for known one-arg flags
            "-d" | "--data" | "--data-ascii" | "--data-binary" | "--data-raw" | "--data-urlencode"
                | "-H" | "--header" | "-X" | "--request" | "-A" | "--user-agent" | "-e" | "--referer"
                | "-b" | "--cookie" | "-c" | "--cookie-jar" | "-u" | "--user" | "--proxy"
                | "--connect-timeout" | "-m" | "--max-time" | "-T" | "--upload-file"
                | "--retry" | "--retry-delay" => {
                i += 2; continue;
            }
            _ => {
                if t.starts_with('-') {
                    i += 1; continue;
                }
                // First positional we see is the URL
                if url.is_none() {
                    url = Some(strip_quotes(t).to_string());
                }
                i += 1;
            }
        }
    }
    let Some(url) = url else { return };

    let dst = if let Some(o) = output {
        Some(o)
    } else if remote_name {
        url_basename(&url)
    } else {
        None
    };

    env.traits.push(Trait::Download {
        cmd: raw.to_string(),
        src: url.clone(),
        dst: dst.clone(),
    });
    if let Some(d) = dst {
        env.modified_filesystem.insert(d.to_ascii_lowercase(), FsEntry::Download { src: url });
    }
}

fn split_words(s: &str) -> Vec<String> {
    // Re-use the same simple splitter; curl args don't need fancy parsing.
    crate::handlers::powershell::__internal_split_for_test(s)
}

// Make a small re-export shim — the powershell file's splitter is private. Add the
// `pub(crate) fn` form there or duplicate this helper. To avoid coupling we duplicate:
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        if s.len() >= 2 { return &s[1..s.len() - 1]; }
    }
    s
}

fn url_basename(url: &str) -> Option<String> {
    let path_part = url.split(['?', '#']).next()?;
    let last = path_part.rsplit('/').next()?;
    if last.is_empty() { None } else { Some(last.to_string()) }
}
```

The `split_words` line referencing `powershell::__internal_split_for_test` was a placeholder mistake — drop it. Replace `split_words` with a local copy of `simple_split` from `powershell.rs` so each handler is independent:

```rust
fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    let mut in_sq = false;
    for c in s.chars() {
        if c == '"' && !in_sq { in_dq = !in_dq; cur.push(c); continue; }
        if c == '\'' && !in_dq { in_sq = !in_sq; cur.push(c); continue; }
        if c.is_whitespace() && !in_dq && !in_sq {
            if !cur.is_empty() { out.push(std::mem::take(&mut cur)); }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}
```

- [ ] **Step 4: Register**

Edit `handlers/mod.rs`:

```rust
pub mod curl;

    if lower.ends_with("curl") || lower.ends_with("curl.exe") {
        return Some(curl::h_curl);
    }
```

- [ ] **Step 5: Verify**

Run: `cd rust && cargo test --package batdeob-core curl_tests`
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add curl handler: -o / -O / URL extraction + Download trait"
```

---

## Task 26: `mshta` / `rundll32` / `copy` / `net` handlers (Python parity)

Each one is small and mostly ports Python code 1:1. We bundle them in this task to keep the plan moving — each gets one test plus one handler.

**Files:**
- Create: `rust/crates/batdeob-core/src/handlers/mshta.rs`
- Create: `rust/crates/batdeob-core/src/handlers/rundll32.rs`
- Create: `rust/crates/batdeob-core/src/handlers/copy.rs`
- Create: `rust/crates/batdeob-core/src/handlers/net.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`

- [ ] **Step 1: Add failing tests**

Append to `lib.rs`:

```rust
#[cfg(test)]
mod misc_handler_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn mshta_records_cmd() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"mshta vbscript:CreateObject("Wscript.Shell").Run("evil")"#, &mut env);
        assert!(env.traits.iter().any(|t| matches!(t, Trait::Mshta { .. })));
    }

    #[test]
    fn rundll32_records_cmd() {
        let mut env = Environment::new(&Config::default());
        interpret_line("rundll32 some.dll,EntryPoint", &mut env);
        assert!(env.traits.iter().any(|t| matches!(t, Trait::Rundll32 { .. })));
    }

    #[test]
    fn copy_system32_tracked() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"copy C:\windows\system32\calc.exe C:\Users\Public\evil.exe"#, &mut env);
        assert!(env.traits.iter().any(|t| matches!(t, Trait::WindowsUtilManip { .. })));
    }

    #[test]
    fn net_use_share_records() {
        let mut env = Environment::new(&Config::default());
        interpret_line(r#"net use Z: \\evil\share /user:adm pass"#, &mut env);
        assert!(env.traits.iter().any(|t| matches!(t, Trait::NetUse { .. })));
    }
}
```

- [ ] **Step 2: Verify they fail**

Run: `cd rust && cargo test --package batdeob-core misc_handler_tests`
Expected: 4 FAILs.

- [ ] **Step 3: Write each handler**

`handlers/mshta.rs`:

```rust
use crate::env::Environment;
use crate::traits::Trait;

pub fn h_mshta(raw: &str, env: &mut Environment) {
    env.traits.push(Trait::Mshta { cmd: raw.to_string() });
}
```

`handlers/rundll32.rs`:

```rust
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_rundll32(raw: &str, env: &mut Environment) {
    // Format: rundll32 <dll>,<entry>[ <args>]
    let parts: Vec<&str> = raw.split_whitespace().collect();
    if parts.len() < 2 { return; }
    let dll = parts[1].split(',').next().unwrap_or("");
    let url = match env.modified_filesystem.get(&dll.to_ascii_lowercase()) {
        Some(FsEntry::Download { src }) => Some(src.clone()),
        _ => None,
    };
    env.traits.push(Trait::Rundll32 { cmd: raw.to_string(), url });
}
```

`handlers/copy.rs`:

```rust
use crate::env::{Environment, FsEntry};
use crate::traits::Trait;

pub fn h_copy(raw: &str, env: &mut Environment) {
    let tokens: Vec<String> = split_words_local(raw);
    let general_opts = ["/v","/n","/l","/y","/-y","/z"];
    let file_opts = ["/a","/b","/d"];
    let mut args: Vec<String> = Vec::new();
    for t in &tokens[1..] {
        let lt = t.to_ascii_lowercase();
        if general_opts.contains(&lt.as_str()) || file_opts.contains(&lt.as_str()) {
            continue;
        }
        args.push(strip_quotes(t).to_string());
    }
    if args.len() != 2 { return; }
    let src = collapse_slashes(&args[0]);
    let dst = collapse_slashes(&args[1]);
    if src.to_ascii_lowercase().starts_with("c:\\windows\\system32")
        && !dst.to_ascii_lowercase().starts_with("c:\\windows\\system32")
    {
        env.traits.push(Trait::WindowsUtilManip { cmd: raw.to_string(), src: src.clone(), dst: dst.clone() });
    }
    env.modified_filesystem.insert(dst.to_ascii_lowercase(), FsEntry::Copy { src });
}

fn split_words_local(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_dq = false;
    for c in s.chars() {
        if c == '"' { in_dq = !in_dq; cur.push(c); continue; }
        if c.is_whitespace() && !in_dq {
            if !cur.is_empty() { out.push(std::mem::take(&mut cur)); }
        } else { cur.push(c); }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) && s.len() >= 2 {
        return &s[1..s.len() - 1];
    }
    s
}

fn collapse_slashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev = '\0';
    for c in s.chars() {
        if c == '\\' && prev == '\\' { continue; }
        out.push(c);
        prev = c;
    }
    out
}
```

`handlers/net.rs`:

```rust
use crate::env::Environment;
use crate::traits::{NetUseInfo, Trait};

pub fn h_net(raw: &str, env: &mut Environment) {
    let lower = raw.to_ascii_lowercase();
    if !lower.starts_with("net use") || lower.starts_with("net user") { return; }
    let tokens: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();
    if tokens.len() <= 2 { return; }
    let mut info = NetUseInfo::default();
    let mut extras: Vec<String> = Vec::new();
    for p in &tokens[2..] {
        let pl = p.to_ascii_lowercase();
        let p_unquoted = p.trim_matches('"').trim_matches('\'');
        if pl.starts_with("/sa")      { info.options.push("savecred".into()); continue; }
        if pl.starts_with("/sm")      { info.options.push("smartcard".into()); continue; }
        if pl.starts_with("/d")       {
            let v = if pl.split(':').nth(1).is_some_and(|x| x.starts_with('n')) { "not-delete" } else { "delete" };
            info.options.push(v.into()); continue;
        }
        if pl.starts_with("/p")       {
            let v = if pl.split(':').nth(1).is_some_and(|x| x.starts_with('n')) { "not-persistent" } else { "persistent" };
            info.options.push(v.into()); continue;
        }
        if pl.starts_with("/u")       {
            if let Some(v) = p.split(':').nth(1) { info.user = Some(v.to_string()); }
            continue;
        }
        if pl.starts_with("/y")       { info.options.push("auto-accept".into()); continue; }
        if pl.starts_with("/n")       { info.options.push("auto-decline".into()); continue; }
        extras.push(p_unquoted.to_string());
    }
    if extras.is_empty() { return; }
    let first = extras[0].clone();
    if first == "*" || (first.len() == 2 && first.ends_with(':')) {
        info.devicename = Some(extras.remove(0));
    }
    if !extras.is_empty() { info.server = Some(extras.remove(0)); }
    if !extras.is_empty() { info.password = Some(extras.remove(0)); }
    if !extras.is_empty() {
        let server = info.server.take().unwrap_or_default();
        let pwd = info.password.take().unwrap_or_default();
        let combined = format!("{} {} {}", server, pwd, extras.join(" "));
        info.server = Some(combined.trim().to_string());
    }
    env.traits.push(Trait::NetUse { cmd: raw.to_string(), info });
}
```

- [ ] **Step 4: Register**

Edit `handlers/mod.rs`:

```rust
pub mod mshta;
pub mod rundll32;
pub mod copy;
pub mod net;

// add to lookup match arms:
        "net"     => Some(net::h_net),
        "copy"    => Some(copy::h_copy),
// and after the cmd/powershell/curl suffix dispatch:
    if lower.ends_with("mshta")    || lower.ends_with("mshta.exe")    { return Some(mshta::h_mshta); }
    if lower.ends_with("rundll32") || lower.ends_with("rundll32.exe") { return Some(rundll32::h_rundll32); }
```

- [ ] **Step 5: Verify**

Run: `cd rust && cargo test --package batdeob-core misc_handler_tests`
Expected: 4 PASS.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/batdeob-core/src/
git commit -m "Add mshta, rundll32, copy, net use handlers (Python parity)"
```

---

## Task 27: Lints + format pass

**Files:**
- Modify: any files with clippy warnings

- [ ] **Step 1: Run formatters and lints**

Run: `cd rust && cargo fmt`
Run: `cd rust && cargo clippy --workspace --all-targets -- -D warnings`

- [ ] **Step 2: Fix any warnings**

Most likely warnings:
- `clippy::unwrap_used` on `Lazy::new(|| Regex::new(...).expect(...))` → add `#[allow(clippy::expect_used)]` at file top with comment explaining the static-init context.
- Unused imports / variables in handlers with placeholder bodies → either use them or `#[allow(dead_code)]`.

- [ ] **Step 3: Re-run everything**

Run: `cd rust && cargo test --workspace`
Expected: all PASS.

Run: `cd rust && cargo clippy --workspace --all-targets -- -D warnings`
Expected: no output (zero warnings).

- [ ] **Step 4: Commit**

```bash
git add -u rust/
git commit -m "fmt + clippy clean across workspace"
```

---

## Task 28: README + plan-to-spec consistency check

**Files:**
- Create: `rust/README.md`

- [ ] **Step 1: Write `rust/README.md`**

```markdown
# batdeob — Rust port of batch_deobfuscator

Static-analysis deobfuscator for Windows batch scripts. Library crate
(`batdeob-core`) plus a single-binary CLI (`batdeob`). Runs on Linux,
macOS, and Windows; never invokes PowerShell or cmd.exe.

See `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md` for
the full design.

## Build

```bash
cd rust
cargo build --workspace --release
./target/release/batdeob version
```

## Usage

```bash
# deobfuscate a script, writing deobfuscated.bat + extracted children
batdeob deob path/to/script.bat -o ./out

# JSON-only report to stdout
batdeob analyze path/to/script.bat

# stdin
echo 'set X=hi&&echo %X%' | batdeob deob -
```

## Status

| Plan | Status | Scope |
|---|---|---|
| A — Foundation | this plan | lex / normalize / split / interp dispatch, basic + Python-parity handlers (set, echo, cmd, powershell, curl, mshta, rundll32, copy, net), CLI |
| B — Control flow + DOSfuscation | follow-on | goto/call :label, for-loop interpreter, set /a evaluator, synthetic command emulator (assoc/ftype/findstr/find/type), self-extract `%~f0`, IF evaluation, percent-tilde |
| C — LOLBAS + corpus + CI | follow-on | certutil/bitsadmin/wmic/cscript/wscript, corpus regression tests, cargo-fuzz, GitHub Actions, release pipeline |
```

- [ ] **Step 2: Commit**

```bash
git add rust/README.md
git commit -m "Add rust/README with build instructions and plan-status table"
```

---

## Self-review

- **Spec coverage (Plan A scope):** lex (Tasks 5-11), normalize (12-13), split (14), env (3), traits (2), line reader (4), dispatch (15), set/echo/cmd/start/powershell/curl/mshta/rundll32/copy/net handlers (16, 19, 21, 23-26), CLI (18), child recursion (22), lint pass (27), README (28). Spec items deferred to Plan B and noted: goto/call :label, for-loops, set /a, certutil/bitsadmin/wmic, synthetic emulator, self-extract, IF evaluator, percent-tilde, setlocal scope. Spec items deferred to Plan C and noted: corpus regression, fuzzing, release pipeline.

- **Placeholders:** None. Every code block has full implementation.

- **Type consistency:** `Trait::Download { cmd, src, dst }` shape consistent in Task 2 definition, Task 25 usage, Task 26 misc tests. `Environment::set(name, value)` consistent everywhere (case-insensitive on name, empty-value deletes — verified by env_tests in Task 3 and used by handlers/set.rs in Task 16). `Token::DoubleQuoted` carries inner content without quotes (Task 9), normalizer re-adds quotes when rendering (Task 12). `FsEntry::Content { content, append }` consistent in Task 3 definition + Task 19 echo handler usage.

- **One known papercut already addressed in-line:** Task 25 had a stale reference to `powershell::__internal_split_for_test`. The plan text already includes the corrected local `split_words` so the engineer pastes the right code.

---

**Plan A complete and saved to `docs/superpowers/plans/2026-05-18-batdeob-plan-A-foundation.md`. Plans B and C will be written as follow-on files after this one is in flight (each builds on the previous).**

**Two execution options:**

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
