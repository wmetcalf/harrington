# batdeob — Rust port and extension of batch_deobfuscator

**Date:** 2026-05-18
**Status:** Draft for review
**Author:** Will Metcalf (william.metcalf@gmail.com)

## 1. Overview

Port the Python `batch_deobfuscator` (1257 LOC, ~750 LOC of tests) to a Rust workspace producing a single static `batdeob` binary and a reusable `batdeob-core` library crate. Extend the tool to handle the harder Invoke-DOSfuscation techniques the Python version currently skips, plus the in-the-wild techniques observed in a 1,416-sample real-world corpus that the Python tool does not cover at all (chiefly `goto`/`call :label`, `certutil`/`bitsadmin`/`wmic` LOLBAS handlers, generalized echo-to-file redirection, and Unicode variable names).

The tool runs on Linux, macOS, and Windows without invoking PowerShell or cmd.exe — all DOS semantics are emulated natively.

### 1.1 Goals

- Deobfuscate Windows batch scripts on any host OS, no shell calls.
- Strict parity with the Python tool's passing tests, plus enabling the four currently-skipped DOSfuscation tests (`test_FOR_execution`, `test_call_var_for`, `test_set_reverse`, the disabled `test_call_var` case).
- Handle the corpus-discovered techniques: `goto`/`call :label`, `certutil -decode`, `bitsadmin /transfer`, `wmic process call create`, `cscript`/`wscript` child extraction, echo-to-file redirection, `%~f0` self-extracting `findstr` gadgets, Unicode variable names.
- Bounded execution: cannot hang, panic, or write unbounded output on adversarial input.
- Structured JSON output: every IOC is a typed enum variant, serializable for downstream tooling.
- Single static binary for analysts; reusable library crate for embedding.

### 1.2 Non-goals

- Full cmd.exe grammar compliance. cmd.exe is context-sensitive and inconsistently documented; we model what malware actually uses.
- Multi-process semantics (`start /b`, background `&`). Side effects are collected in source order.
- Live execution of unknown LOLBAS (`reg query`, `schtasks`, etc.). Unknown pipelines produce a `Trait::Unresolved` rather than executing.
- A `set /a` evaluator that matches every edge case of cmd.exe's 32-bit signed arithmetic. We implement the documented operators with i32 wrapping arithmetic; obscure undocumented behaviors are out.

## 2. Repository layout

```
batch_deobfuscator/         # existing Python (untouched, parity oracle)
rust/
├── Cargo.toml              # workspace
├── crates/
│   ├── batdeob-core/       # library: lex, normalize, interp, env, traits
│   └── batdeob-cli/        # binary: thin wrapper around core
└── tests/
    ├── parity/             # ports of every Python test (asserted 1:1)
    └── corpus/             # diff-based regression suite over real samples
docs/superpowers/specs/     # this document
```

## 3. CLI

Fresh design (no compat with the Python CLI):

```
batdeob deob <FILE>             # deobfuscate; writes deobfuscated.bat + children
  -o, --out-dir <DIR>           # output directory (default: ./batdeob-out)
  --json                        # emit traits JSON to stdout in addition to files
  --json-only                   # JSON to stdout, no files
  --max-depth <N>               # default 12   (recursive cmd-in-cmd / start)
  --max-iterations <N>          # default 65536 (FOR-loop body executions)
  --max-child-scripts <N>       # default 64   (extracted .bat/.ps1/.vbs/.js)
  --timeout <SECS>              # default 10   (wall-clock per file)
  --no-self-extract             # disable %~f0 self-reference resolution (default: enabled)
  --winver <win7|win10|win11>   # which synthetic env table to load (default: win10)

batdeob analyze <FILE>          # JSON-only convenience: deob --json-only
batdeob version
batdeob deob -                  # stdin: single logical command
```

Exit codes: 0 success, 1 partial success with caps hit, 2 input error, 3 internal error.

### 3.1 Default-value rationale

Corpus-driven (1,416 samples, ~1 GB):

- `max-iterations=65536` — largest observed legitimate alphabet-concat scripts run ~1,500 expansions per logical line, far under cap. DOSfuscation `FORcode`/`Reverse` over a 16 KB base64 PowerShell payload is one iteration per byte, ~16,384. Cap absorbs realistic adversary cases.
- `max-depth=12` — `cmd /c` / `start` / `call :label` nesting in the corpus tops out around 5; cap gives headroom for chained launcher techniques.
- `max-child-scripts=64` — multi-stage droppers (e.g. certutil triple-decode + vbs builder + final exe) yield <10 children typically; 64 absorbs combinatorial cases without runaway.
- `timeout=10s` — with iteration capped, regex pathologies are the only remaining time risk; 10s is a wall-clock backstop.

## 4. Core data types

```rust
// crates/batdeob-core/src/env.rs

pub struct Environment {
    pub vars: HashMap<String, String>,            // lowercase var name -> value
    pub modified_filesystem: HashMap<String, FsEntry>, // lowercase path -> entry
    pub traits: Vec<Trait>,
    pub exec_cmd: Vec<String>,                    // queued child batch scripts
    pub exec_ps1: Vec<Vec<u8>>,                   // extracted PowerShell payloads
    pub exec_vbs: Vec<Vec<u8>>,                   // extracted VBScript payloads
    pub exec_jscript: Vec<Vec<u8>>,               // extracted JScript payloads
    pub file_path: Option<PathBuf>,
    pub input_bytes: Option<Arc<[u8]>>,           // for %~f0 self-extract
    pub delayed_expansion: bool,                  // setlocal enabledelayedexpansion
    pub call_stack: Vec<Frame>,                   // for call :label semantics
    limits: Limits,                                // depth, iter, child counters
}

pub struct Frame {
    pub return_line: usize,                       // logical-line index to resume at
    pub args: Vec<String>,                        // %1..%9, %*
    pub locals_snapshot: Option<HashMap<String, String>>, // for setlocal scoping
}

pub enum FsEntry {
    Content  { content: Vec<u8>, append: bool },                       // echo / set/p redirection
    Download { src: String },                                          // curl / iwr / certutil / bits
    Copy     { src: String },                                          // copy
    Decoded  { content: Vec<u8>, src: String, method: DecodeKind },    // certutil -decode chain (preserves bytes + provenance)
}

pub enum DecodeKind { Base64, Hex }

pub struct Limits {
    pub max_depth: u32,        pub depth: u32,
    pub max_iterations: u64,   pub iterations: u64,
    pub max_child_scripts: u32, pub child_scripts: u32,
    pub deadline: Option<Instant>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind")]
pub enum Trait {
    // Existing (Python parity)
    Download         { cmd: String, src: String, dst: Option<String> },
    NetUse           { cmd: String, info: NetUseInfo },
    Lolbas           { name: &'static str, cmd: String },
    CommandGrouping  { cmd: String, normalized: String },
    StartWithVar     { cmd: String, normalized: String },
    VarUsed          { cmd: String, normalized: String, count: u32 },
    Mshta            { cmd: String },
    Rundll32         { cmd: String, url: Option<String> },
    SetpFileRedirect { cmd: String, target: String },
    WindowsUtilManip { cmd: String, src: String, dst: String },
    ManipulatedExec  { cmd: String, target: String },
    ComplexOneLiner  { line_count: u32 },
    OneLiner,
    // New
    Goto             { from_line: usize, to_label: String },
    GotoUnresolved   { from_line: usize, to_label: String },
    Subroutine       { label: String, args: Vec<String> },
    SelfExtract      { method: &'static str },        // "findstr" | "for_f" | "type"
    CertutilDecode   { src: String, dst: String, method: DecodeKind },
    CertutilDownload { url: String, dst: String },
    BitsadminDownload{ url: String, dst: String },
    WmicProcessCreate{ inner_cmd: String },
    CscriptExec      { src: String },
    WscriptExec      { src: String },
    EchoRedirect     { content: Vec<u8>, target: String, append: bool },
    Arithmetic       { expr: String, value: i32 },
    ArithmeticParseError { expr: String },
    SetlocalScope    { enabled_delayed: bool },
    DelayedExpansionUsed,
    IfNotResolved    { condition: String },
    ForUnresolvedSource { pipeline: String },
    NonUtf8Input,
    IterationCapped  { command: String },
    DepthCapped      { command: String },
    ChildScriptsCapped,
    GotoLoopCapped   { label: String },
    TimeoutHit,
}
```

## 5. Lexer

State machine over codepoint stream. The lexer produces a `Token` stream; it does not expand variables or evaluate operators. State:

```rust
enum LexState {
    Init,
    InDoubleQuote,
    InPercentVar { name_start: usize },
    InBangVar    { name_start: usize },
    InVarOp      { name: String, sigil: Sigil, op_state: VarOpState },
    Escape(Box<LexState>),
}
```

```rust
pub enum Token<'a> {
    Word(Cow<'a, str>),
    OpAnd, OpAndAnd, OpOr, OpOrOr,
    OpRedirect { fd: u8, append: bool },          //   >  1>  2>  >>  1>>  2>>
    OpInput,                                       //   <
    OpenParen, CloseParen,
    Whitespace,
    Comma, Semicolon,                              // normalized to whitespace later
    VarPercent { name: String, op: Option<VarOp> },
    VarBang    { name: String, op: Option<VarOp> },
    PositionalArg(u8),                             // %0..%9
    AllArgs,                                       // %*
    PercentTilde { flags: PercentTildeFlags, arg_index: u8 },
}

pub enum VarOp {
    Substr { index: i64, length: Option<i64> },
    Substitute { needle: String, replacement: String, leading_wildcard: bool },
}
```

### 5.1 Variable-name character class

cmd.exe accepts any Unicode codepoint in a variable name. The lexer's var-name predicate is:

```rust
fn is_var_name_char(c: char) -> bool {
    c.is_alphabetic()
        || c.is_numeric()
        || matches!(c, '_' | '#' | '$' | '\'' | '(' | ')' | '*' | '+' | ',' | '-'
                       | '.' | '?' | '@' | '[' | ']' | '`' | '{' | '}' | '~')
        || c.is_whitespace() // tab/space inside %X% is allowed
}
```

Note: `is_alphabetic` is Unicode-aware (Japanese hiragana etc. pass). This is required for the corpus.

### 5.2 Caret escape rules

- `^` outside a quoted string escapes the next character (caret itself is dropped).
- `^` inside a quoted string is literal **except** when followed by a var-delimiter that would otherwise be active.
- `^` at end-of-line is logical-line continuation (handled by `read_logical_lines` before the lexer sees it).

### 5.3 Logical-line reader

```rust
pub fn read_logical_lines(input: &[u8]) -> Vec<String>
```

Concatenates physical lines that end with unescaped `^`. UTF-8 decoded with `from_utf8_lossy` (non-UTF-8 bytes become U+FFFD; `Trait::NonUtf8Input` emitted once).

## 6. Normalizer

`normalize(tokens, env) -> Vec<Token>` walks the token stream and resolves variable references against `env`.

### 6.1 Variable resolution

- `VarPercent { name, op }`: lookup `name.to_lowercase()` in `env.vars`. Apply `op` if present. If unset, expands to empty.
- `VarBang { name, op }`: same, but only resolves when `env.delayed_expansion == true`. Otherwise emits literal `!name!`. Emits `Trait::DelayedExpansionUsed` on first resolution.
- `PositionalArg(n)`: lookup in top of `env.call_stack`. `%0` returns synthetic script path. Unset → empty.
- `AllArgs`: all positional args from top frame joined by space.
- `PercentTilde`: synthesizes a file-stat-style string per Python's `percent_tilde` (matches Python exactly).

### 6.2 Substring operator (`:~index,length`)

Python-compatible: negative indices, clamped overflow, `None` length. Identical to `BatchDeobfuscator.get_value` semantics.

### 6.3 Substitution operator (`:s1=s2`, `:*s1=s2`)

Case-insensitive needle. `:*s1=s2` strips everything up to and including the first match and replaces with `s2`. Empty `s2` is deletion.

### 6.4 Recursive re-lex

If a resolved variable value contains `%`/`!`/`^`, the result is re-lexed and re-normalized recursively, with `env.limits.depth` decremented. This is what makes `ec%a%ho` → `echo` (`%a%` empty, then re-lex yields a `Word("echo")`). Cap on hit: emit `Trait::DepthCapped`, return the un-re-lexed value.

## 7. Splitting and label index

```rust
pub fn split_commands(logical_line: &str) -> Vec<String>
```

Walks the logical line splitting on unquoted, unescaped `&`/`&&`/`|`/`||`. Inside `if (…)`/`for (…)` body, the matching `)` is found via the existing Python state-machine logic (`find_closing_paren`) ported verbatim.

```rust
pub fn build_label_index(lines: &[String]) -> HashMap<String, usize>
```

Pre-pass over logical lines: any line whose first non-whitespace token is `:label` (and the second char of `label` is not punctuation, per cmd.exe `::` comment rule) is registered. Map key is lowercased label without leading `:`.

## 8. Interpreter

```rust
pub fn analyze(input: &[u8], cfg: &Config) -> Report

fn run(env: &mut Environment, lines: &[String], labels: &HashMap<String, usize>) {
    let mut cursor = 0usize;
    while cursor < lines.len() {
        let logical = &lines[cursor];
        let next = drive(env, logical, cursor, lines, labels);
        cursor = next;
    }
}
```

`drive` lexes, normalizes, splits commands, interprets each. The return value is the next line cursor — normally `cursor + 1`, but `goto`/`call :label`/`exit /b` rewrite it.

### 8.1 Dispatch table

```rust
static HANDLERS: phf::Map<&'static str, Handler> = phf_map! {
    "set"        => h_set,
    "setlocal"   => h_setlocal,
    "endlocal"   => h_endlocal,
    "if"         => h_if,
    "for"        => h_for,
    "goto"       => h_goto,
    "call"       => h_call,
    "exit"       => h_exit,
    "start"      => h_start,
    "cmd"        => h_cmd,         // also matches *cmd.exe via suffix dispatch
    "powershell" => h_powershell,  // also *powershell.exe, pwsh
    "curl"       => h_curl,
    "mshta"      => h_mshta,
    "rundll32"   => h_rundll32,
    "copy"       => h_copy,
    "net"        => h_net,
    "echo"       => h_echo,
    "certutil"   => h_certutil,
    "bitsadmin"  => h_bitsadmin,
    "wmic"       => h_wmic,
    "cscript"    => h_cscript,
    "wscript"    => h_wscript,
    "findstr"    => h_findstr,
    "find"       => h_find,
    "type"       => h_type,
    "assoc"      => h_assoc,       // synthetic table
    "ftype"      => h_ftype,       // synthetic table
    "forfiles"   => h_forfiles,
};
```

Suffix dispatch handles `*cmd.exe`, `*powershell.exe`, `*curl.exe`, etc. (matches Python). LOLBAS detection runs orthogonally over the resolved command name.

### 8.2 Redirection hoisting

Before dispatch, `extract_redirections(&mut tokens) -> RedirectionSet` peels `> file`, `>> file`, `1> file`, `2> file`, `< file` from the tail of the token stream. Result:

```rust
pub struct RedirectionSet {
    pub stdout: Option<RedirTarget>,    // Some(Append("a.vbs")) | Some(Trunc("a.vbs"))
    pub stderr: Option<RedirTarget>,
    pub stdin: Option<String>,
}
```

The handler receives both the cleaned token stream and the redirection set. `h_echo` and any command whose output is statically known (e.g., `assoc`, `ftype`, `set` with no args, `findstr` against a known input) writes to `modified_filesystem` and emits `Trait::EchoRedirect`. Commands whose output is dynamic (`powershell`, `wmic`) do not.

### 8.3 `set` handler

Ports `BatchDeobfuscator.interpret_set` verbatim including:
- `set /a expr` — now evaluated by §8.10 instead of wrapped in parens.
- `set /p X=prompt < file` and `set /p X=content > file` — redirection now comes from §8.2.
- Empty value → variable deletion.
- Quote-form preserves trailing spaces.
- Caret-escape pre-stripped by lexer.

### 8.4 `setlocal` / `endlocal`

`setlocal` pushes a snapshot of `env.vars` onto a stack inside `env`. `setlocal enabledelayedexpansion` additionally sets `env.delayed_expansion = true` and remembers prior state in the snapshot. `endlocal` restores. Emits `Trait::SetlocalScope`.

### 8.5 `if` handler

Forms recognized:

| Form | Evaluation |
|---|---|
| `if defined X` | `env.vars.contains_key(&x.to_lowercase())` |
| `if not defined X` | Negation |
| `if "a"=="b"` | String compare after normalization |
| `if /i "a"=="b"` | Case-insensitive |
| `if x EQU/NEQ/LSS/LEQ/GTR/GEQ y` | i32 compare, fall back to string |
| `if errorlevel N` | False (errorlevel synthetic 0) |
| `if cmdextversion N` | True |
| `if exist <path>` | `env.modified_filesystem.contains_key(path)` |

When the condition resolves, recurse into the matching branch only. When it does not (e.g. compares an unset var), recurse into **both** branches and emit `Trait::IfNotResolved`. This is the analyst-friendly choice for IOC extraction.

### 8.6 `for` handler

Implements:

- **Plain form**: `for %A in (a b c) do …` — iterate space/comma/semicolon-separated tokens.
- **`/L`**: `for /L %A in (start,step,end) do …` — numeric range, signed, step may be negative.
- **`/F`**:
  - `("literal")` — single-line input.
  - `('pipeline')` (or with `usebackq`) — run pipeline through synthetic-command emulator (§9), iterate over captured stdout lines.
  - `(file)` — open via `env.input_bytes` if path resolves to `file_path`; else `__input__` placeholder.
  - Options honored: `tokens=N`, `tokens=N,M`, `tokens=*`, `delims=`, `skip=N`, `usebackq`, `eol=`.
- **`/R`, `/D`** — emit `Trait::ForUnresolvedSource` for now; can be extended later.

Per-iteration: re-lex and re-normalize the body with loop variable bound and delayed expansion enabled. Decrement `env.limits.iterations`; on zero emit `Trait::IterationCapped` and break.

### 8.7 `goto` / `:label` / `call :label` / `exit /b`

- `h_goto`: resolves the label argument; if `:eof` → caller-style return; else look up in label index. Found → return new cursor. Missing → emit `Trait::GotoUnresolved`, return `cursor + 1`. Decrement an iteration counter so `goto :loop` bounded.
- `h_call`: if argument starts with `:`, treat as subroutine: push `Frame { return_line: cursor + 1, args, locals_snapshot: None }`, return label cursor. Otherwise re-feed argument through lex+normalize+interpret recursively (matches Python's `interpret_command(normalized_comm[5:])`).
- `h_exit`: `exit /b` → pop frame; `exit` (no `/b`) → set a `should_halt` flag.

Positional args (`%1`..`%9`, `%*`) resolve against `env.call_stack.last()`.

### 8.8 `cmd /c` / `start`

Match the Python's regex-based extraction: `cmd /c "inner"` queues `inner` into `env.exec_cmd` for post-line drain. `start [/flags] inner` recursively interprets `inner` (mirroring Python). New: `start /b` queues for parallel display purposes only (still executes inline).

### 8.9 `powershell` handler

Identical to Python's `interpret_powershell`:
- `-EncodedCommand` / `-enc` / abbreviations: base64-decode the next arg into `env.exec_ps1`.
- `-Command` / `-c`: capture next arg(s) as raw script.
- `-File`: silently skip (file path, not extractable).
- `Invoke-WebRequest` / `iwr` with `-Uri X -OutFile Y`: emit `Trait::Download`, register `Y` in `modified_filesystem`.

### 8.10 `set /a` evaluator

Pratt parser over the documented operator table (`! ~ -` unary, `* / % + -`, `<< >>`, `& ^ |`, `= *= /= %= += -= &= ^= |= <<= >>=`, `,` sequencing). Integer literals: decimal default, `0x` hex, leading `0` octal. Bare identifiers resolve against `env.vars` (case-insensitive); missing → 0. i32 wrapping arithmetic. Compound assignments mutate `env.vars` mid-expression. Comma sequencing returns the last expression's value.

Output: stores the resulting integer's decimal string into the target variable. Emits `Trait::Arithmetic { expr, value }`. Parse failures emit `Trait::ArithmeticParseError` and leave the variable unchanged.

### 8.11 `certutil` handler

| Form | Action |
|---|---|
| `certutil -decode SRC DST` | Look up `SRC` in `modified_filesystem`; if its content is known, base64-decode into `DST` as `FsEntry::Decoded { content, src, method: Base64 }`. Emit `Trait::CertutilDecode`. |
| `certutil -decodehex SRC DST` | Same with hex. |
| `certutil -urlcache -split -f URL DST` | Same shape as curl: emit `Trait::CertutilDownload`. |
| `certutil -encode SRC DST` | Mirror of decode; rarely seen in malware but supported. |

If `SRC` is the input file path (`%~f0`) and we have `env.input_bytes`, decode against those bytes. The `Trait::CertutilDecode` event is emitted unconditionally on a syntactically valid `certutil` invocation; if the source content is unknown, the `dst` `FsEntry` is not created and the JSON event records `src_resolved: false`.

### 8.12 `bitsadmin` handler

`bitsadmin /transfer NAME [/Download] [/Priority X] URL DST` → emit `Trait::BitsadminDownload { url, dst }`, register `DST` in `modified_filesystem` as `FsEntry::Download`.

### 8.13 `wmic` handler

Only `wmic process call create "cmd"` is parsed today. Extract the quoted inner command, recurse into the interpreter, emit `Trait::WmicProcessCreate { inner_cmd }`.

### 8.14 `cscript` / `wscript`

Argument resolves to a file path. If path is in `modified_filesystem` as `FsEntry::Content`, push the content into `env.exec_vbs` (if `.vbs`) or `env.exec_jscript` (if `.js`/`.jse`). Emit `Trait::CscriptExec` / `Trait::WscriptExec`. Files matching neither extension are skipped with a trait note.

### 8.15 `findstr` / `find` / `type`

Become real handlers, not synthetic-only. Input source can be:
- Prior pipe stage's stdout (already captured).
- `%~f0` (resolves to `env.input_bytes`).
- A path in `modified_filesystem` whose `FsEntry::Content` is known.

`findstr` supports `/i`, `/v`, `/n`, `/c:"literal"`, `/r` regex (via Rust `regex` crate — not a strict cmd.exe regex compat, but sufficient for known DOSfuscation gadgets). `find "literal" file` is a strict-substring filter.

When source is `%~f0`, emit `Trait::SelfExtract { method: "findstr" }`.

### 8.16 `assoc` / `ftype`

Synthetic outputs from a fixed table baked into the binary (drawn from a stock Windows 10 install). Only useful as a `for /F` source; we emit canned output and let the FOR loop tokenize it. This is what unlocks FIN-style decoders.

### 8.17 `echo`

Argument(s) are joined with single spaces, trailing `\r\n` appended. With redirection from §8.2, writes to `modified_filesystem` and emits `Trait::EchoRedirect`. Without redirection, no observable side effect (we don't model stdout).

Special: `echo off`, `echo on` — silently consumed.

## 9. Synthetic command emulator (FIN-style support)

For `for /F` and `cmd /c` pipelines, a small in-process executor models a handful of commands' stdout against the live `env`:

| Command | Modeled output |
|---|---|
| `set` (no args) | Iterate `env.vars` in case-insensitive sort order, format `NAME=VALUE\n` per line. |
| `set PREFIX` | Subset where name (case-insensitive) starts with `PREFIX`. |
| `assoc` | Canned table from §8.16. |
| `assoc .EXT` | Single-line lookup. |
| `ftype` | Canned table. |
| `findstr [/options] PATTERN` | Filter previous pipe stage's lines. |
| `find "LITERAL"` | Strict-substring filter. |
| `type FILE` | Content from `modified_filesystem` or `input_bytes`. |
| `where COMMAND` | Synthetic `C:\Windows\System32\<COMMAND>.exe` if `COMMAND` is in a small known-binary list. |

Unknown commands (`reg query`, `schtasks`, `tasklist`, `wmic`) cause the pipeline to resolve to an empty token set and emit `Trait::ForUnresolvedSource`.

## 10. Self-reference handling

When a token resolves to a path equal to (case-insensitive, normalized) the analyzer's input file path, the handler receiving that token may use `env.input_bytes` as the underlying content. This is what makes `findstr "::" "%~f0"` and `for /F "delims=" %%a in ('findstr ":: " "%~f0"') do …` actually decode.

`%~f0` / `%~dpnx0` / `%0` all map to the same synthetic path string and the same input bytes.

Disabled by `--no-self-extract` for sandbox safety.

## 11. Errors and safety

- All resource caps are typed `Halt` variants. None of them poison the run; they truncate the offending sub-tree and emit a `Trait::*Capped`.
- No `unwrap`/`expect` on input-derived data. CI enforces `clippy::unwrap_used` deny.
- All regexes are `regex::Regex` (RE2-class, linear time). Compiled once at module init via `once_cell`.
- File writes constrained to `--out-dir`; absolute paths in scripts (`C:\…`) are treated as opaque keys in `modified_filesystem` and never escape.
- Wall-clock deadline checked at each top-level command boundary.
- Non-UTF-8 input lossily decoded with single `Trait::NonUtf8Input`.

## 12. Testing

### 12.1 Python parity suite

Every test in `batch_deobfuscator/tests/*.py` ported as a Rust integration test under `rust/tests/parity/`. Same inputs, same assertions. Four currently-skipped DOSfuscation tests are **enabled** with the expected fully-decoded outputs.

### 12.2 Property tests (`proptest`)

- `set X=$value` then `echo %X%` round-trips, where `$value` is an arbitrary byte string with carets, percents, bangs scrubbed.
- Substring with random `(index, length)` over random strings — assert match against an oracle implementation of Python's slicing semantics.
- Substitution with random needles/replacements.

### 12.3 Corpus regression

A `tests/corpus/` directory of selected samples from `/home/coz/cstorage/mbzdls`. Expected JSON trait output is committed alongside each sample. CI diffs against fresh output; mismatches fail.

Seed corpus selection (representative across techniques):

| Sample | Technique |
|---|---|
| `run.bat` | Trivial launcher |
| `installer.bat` | curl-equivalent download |
| `3360300701166418019.bat` | `goto :label` over decoy English-word block |
| `Invoice 6238829.bat` | Alphabet-var concatenation (~200 vars) |
| `FX.cmd` | CJK Unicode var-name padding |
| `?impactfulbrands.co.uk__….bat` | Triple `certutil -decode` chain + `copy /b` |
| `FW-APGKSDTPX4HOAUJJMBVDNXPOHZ.PDF.bat` | `bitsadmin` + `call :UnZipFile` subroutine with `%1`/`%2` |
| Hand-picked DOSfuscation outputs | `FORcode`, `Reverse`, `FINcode` |

### 12.4 Fuzz

`cargo-fuzz` target wraps `analyze(&[u8])`. Success criterion: no panic, no UB, exits within iteration + wall-clock budget. Run in CI for 10M iterations per push.

## 13. Build, CI, release

- Workspace `Cargo.toml` pins MSRV 1.78.
- `cargo test`, `cargo clippy --deny warnings`, `cargo fmt --check` gate every PR.
- `cargo fuzz run analyze -- -runs=1000000` runs nightly.
- Release job builds for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`. Artifacts attached to GitHub Release.
- Python `batch_deobfuscator/` directory is **not** removed; it stays as the parity oracle and for users who can't migrate.

## 14. Out of scope (deferred)

- `for /R`, `for /D` filesystem walks beyond `Trait::ForUnresolvedSource`.
- `reg query`, `schtasks`, `tasklist`, full `wmic` query language.
- Real cmd.exe regex compatibility in `findstr /r` (we use Rust's `regex`, which is close enough for known gadgets but not bit-identical).
- An obfuscator (`obf` subcommand). Out per the brainstorm decision.
- Python bindings (`pyo3`). Could be added later without changing the core crate.

## 15. Synthetic Windows environment data

`batdeob` ships per-Windows-version JSON snapshots of the data it needs to emulate cmd.exe statically:

```
rust/crates/batdeob-core/data/
├── win7.json        # Windows 7 SP1
├── win10.json       # Windows 10 21H2 (default)
└── win11.json       # Windows 11 23H2
```

Each file contains:
- `identity` — `SystemRoot`, `ComSpec`, `ProgramFiles`, `PATHEXT`, etc.
- `assoc` — full `.ext` → `ProgID` table
- `ftype` — full `ProgID` → command-template table
- `env` — every environment variable (`set` output)
- `where` — `PATH` resolution for ~60 known LOLBAS and system binaries
- `ver` — Windows version banner

### 15.1 Source of the data

Two layers:

1. **Path table from the Python port.** `batch_deobfuscator.batch_interpreter.BatchDeobfuscator.__init__` already hardcodes a synthetic Windows env (lines 122–172): paths, `PATHEXT`, `NUMBER_OF_PROCESSORS`, `windir`, etc. This ports directly into the Rust core as a fallback baseline so the tool works with zero data files.

2. **Sandbox-harvested snapshots.** Two interchangeable producers, both emitting the same JSON schema:

   - **`rust/tools/collect-windows-env.bat`** — pure-cmd.exe collector. Runs inside a clean VM. Captures the live booted environment.
   - **`rust/tools/extract-from-wim/`** — Python tool. Pulls the same data from an offline Windows install ISO (no VM, no boot). Reads `sources/install.wim` from the ISO via `7z`, parses the offline `SOFTWARE`/`SYSTEM` registry hives with `regipy`, resolves `where` paths from the WIM's file listing. Tested against Windows 11 25H2 (build 26200): 228 `assoc` entries, 163 `ftype` entries, 15 env vars, 43/54 LOLBAS `where` paths resolved (11 misses are accurate — those binaries don't ship in the client SKU). See `rust/tools/extract-from-wim/README.md`.

   Output is checked into `data/<winver>.json`. The runtime picks the file matching `--winver` (default `win10`) and merges it onto the Python-derived baseline. The two producers are equivalent — pick `extract-from-wim` for CI reproducibility, `collect-windows-env` when you need live system state.

The Python tool's `percent_tilde` (line 910) ports verbatim into the Rust path-synthesizer.

## 16. Open questions

None blocking. Listed for tracking:

1. `set /a` overflow behavior — wrap (current spec) vs. saturate vs. emit a `Trait::ArithmeticOverflow`. Wrap matches cmd.exe; trait emission would be additionally informative.
2. Whether to commit collector output as one JSON per winver or one combined file with a top-level `versions` map. Per-file keeps diffs cleaner when refreshing a single VM.

## Decisions log

- **Self-extract default ON.** Static analysis already has the input bytes; resolving `%~f0` through `findstr`/`for /f` feeds known bytes back through a filter — no exfiltration, no remote fetch. RE2 regex bounds DoS risk.
- **No PowerShell / .NET in the collector.** Per the project's hard constraint; collector runs against fresh Windows installs (incl. Win 7 where PS versions vary) without external dependencies.
- **Two-layer env data.** Baseline ported from Python guarantees the tool works without data files; sandbox snapshots provide accuracy when present.
