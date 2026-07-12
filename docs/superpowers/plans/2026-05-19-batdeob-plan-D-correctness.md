# batdeob Plan D — Correctness fixes from corpus diff

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix correctness gaps surfaced by a 100-sample Python-vs-Rust diff. Plan C made the binary not crash; Plan D makes it produce the *right* output. Headline target: a sample that currently emits 137 bytes of output (silently truncated) should emit the same ~23 KB of decoded payload that the Python tool emits.

**Architecture:** No new modules. All fixes are in existing handlers (`goto.rs`, `if_cmd.rs`, `for_cmd.rs`, `set.rs`, `mod.rs`) and `lib.rs`'s `drive()`.

**Tech Stack:** Same as A/B/C.

**Spec:** `docs/superpowers/specs/2026-05-18-batdeob-rust-port-design.md`

**Prereq:** Plan A + B + C + all fixups landed. 167 unit + 9 parity + 5 CLI + 1 corpus-regression = 182 tests passing.

**Empirical findings from the analysis pass (`/tmp/pydiff_corpus/`):**

| Issue | Corpus impact | Sample evidence |
|---|---|---|
| Top-level `exit /b` halts whole drive() | 3 confirmed + likely many more | SKMBT28736292.bat: 23,101 chars Python → 137 chars Rust |
| Literal IF conditions unresolved (`0 neq 0`, `"AMD64" EQU "amd64"`) | 23+ files, 11,100+ IfNotResolved events | Easy constant-fold |
| Inline IF (`if 0 equ 900 exit`) miscoded | 23 files | `exit` parses into condition string |
| Semicolons stripped inside PS `-Command` quoted args | pay.bat + likely others | `Tls12; Invoke-WebRequest` → `Tls12 Invoke-WebRequest` |
| FOR /F `tokens=3,` trailing comma | LOGOFALL.bat + pattern | `tokens=3,` causes body to not execute |
| FOR /F body dropped on unresolved source | 17 files | LOGOFALL.bat's logoff loop entirely absent |
| Common pass-through commands not in handler table | 130+27+33+27 files | del/cls/attrib/mkdir args aren't being expanded |

---

## Task 1: Stop halting drive() on top-level `exit /b` / `goto :eof`

**Impact:** Restores deobfuscation of every script that gates its payload behind an `if (exit /b)` admin check. SKMBT28736292.bat: 137 chars → ~23 KB.

**Files:**
- Modify: `rust/crates/batdeob-core/src/lib.rs` (`drive()` `PopFrame` / `Halt` branches)
- Modify: `rust/crates/batdeob-core/src/lib.rs` (update `goto_tests::goto_eof_terminates` — see below)

The current `drive()` halts the cursor loop when `pending_action == PopFrame` and `call_stack.is_empty()`. That's correct for an executor; it's wrong for a static deobfuscator that wants to extract IOCs from every line. Fix: at top level, `PopFrame` and `Halt` become Continue (advance cursor one line).

The existing `goto_eof_terminates` test asserts `!report.deobfuscated.contains("NEVER")` — that's the broken-by-design behavior we're correcting. Update the test to verify control-flow trait emission instead.

- [ ] **Step 1: Add failing test** to `lib.rs`:

```rust
#[cfg(test)]
mod exit_continue_tests {
    use crate::{analyze, Config};

    #[test]
    fn top_level_exit_b_continues_for_ioc_extraction() {
        // Real-world pattern: admin-gate guards the payload
        let script = b"if not \"%1\"==\"am_admin\" ( echo GATED & exit /b )\r\necho REAL_PAYLOAD url=http://x/y.exe\r\n";
        let report = analyze(script, &Config::default());
        // Both branches should be visible in deob output
        assert!(report.deobfuscated.contains("echo REAL_PAYLOAD"),
            "missing payload after gate, got:\n{}", report.deobfuscated);
    }

    #[test]
    fn top_level_exit_bare_continues() {
        let script = b"exit\r\necho AFTER_EXIT\r\n";
        let report = analyze(script, &Config::default());
        assert!(report.deobfuscated.contains("echo AFTER_EXIT"),
            "exit halted top-level drive, got:\n{}", report.deobfuscated);
    }

    #[test]
    fn top_level_goto_eof_continues() {
        let script = b"goto :eof\r\necho AFTER_GOTOEOF\r\n";
        let report = analyze(script, &Config::default());
        assert!(report.deobfuscated.contains("echo AFTER_GOTOEOF"),
            "goto :eof halted top-level drive, got:\n{}", report.deobfuscated);
    }

    #[test]
    fn call_label_eof_still_returns_to_caller() {
        // Inside a call frame, eof should pop normally
        let script = b"call :sub\r\necho AFTER_CALL\r\ngoto :eof\r\n:sub\r\necho IN_SUB\r\ngoto :eof\r\n";
        let report = analyze(script, &Config::default());
        let lines: Vec<&str> = report.deobfuscated.lines().filter(|l| l.starts_with("echo ")).collect();
        // Expected order: IN_SUB then AFTER_CALL
        assert_eq!(lines, vec!["echo IN_SUB", "echo AFTER_CALL"], "got:\n{}", report.deobfuscated);
    }
}
```

- [ ] **Step 2: Verify they fail**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core exit_continue 2>&1 | tail -15
```

- [ ] **Step 3: Update the existing `goto_eof_terminates` test**

In `lib.rs`, find the test and replace it:

```rust
    #[test]
    fn goto_eof_emits_trait_at_top_level() {
        // At top level, goto :eof signals end-of-script but we continue
        // scanning for IOCs. Verify the deob output still reaches the next line.
        let script = b"goto :eof\r\necho AFTER\r\n";
        let report = analyze(script, &Config::default());
        assert!(report.deobfuscated.contains("echo AFTER"), "got:\n{}", report.deobfuscated);
    }
```

(Replaces the prior `goto_eof_terminates` test.)

- [ ] **Step 4: Modify `drive()` in `lib.rs`**

Find the `match env.pending_action.take()` block. Replace the `PopFrame` and `Halt` arms with:

```rust
                Some(crate::env::CursorAction::PopFrame) => {
                    if let Some(frame) = env.call_stack.pop() {
                        next_cursor = frame.return_line;
                    }
                    // No frame to pop — at top level, exit/b and goto :eof are
                    // no-ops for static deobfuscation. Continue to the next cursor
                    // so subsequent lines still get scanned for IOCs.
                }
                Some(crate::env::CursorAction::Halt) => {
                    // Bare `exit` at top level — same as PopFrame: continue scanning.
                    // (Inside a call frame this would propagate to the parent drive(),
                    // but Plan D defers that nuance — top-level only for now.)
                }
```

Remove `should_halt = true;` from those arms. Drop the `if should_halt { break; }` checks if they become unreachable — clippy will tell you.

- [ ] **Step 5: Run all tests**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -15
```

Other tests that may break:
- `goto_eof_terminates` (we already updated it)
- Possibly some Plan B `call_label_returns_after_eof` style tests — verify they still pass; if any rely on top-level halt semantics, update similarly.

- [ ] **Step 6: Smoke against the SKMBT sample**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3
./target/release/batdeob analyze "/home/coz/cstorage/mbzdls/SKMBT28736292.bat" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['deobfuscated']))"
```

Expected: output length >> 137 bytes. Target: >10000 bytes.

- [ ] **Step 7: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Don't halt drive() on top-level exit/b / goto :eof — keep scanning for IOCs"
```

---

## Task 2: Constant-fold literal IF conditions

**Impact:** 11,100+ `IfNotResolved` events across 23+ corpus files. Examples: `if 0 neq 0 (`, `if "AMD64" EQU "amd64" (`, `if 0 equ 900 exit`. All evaluable at parse time with zero ambiguity.

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/if_cmd.rs`

The current `evaluate()` in `if_cmd.rs` already handles `==`/`/i` string compares, `defined`, `exist`, `errorlevel`, `cmdextversion`. It's MISSING the relational operators (`EQU NEQ LSS LEQ GTR GEQ`) which the spec calls out and the corpus relies on.

- [ ] **Step 1: Add failing tests** to `lib.rs`:

```rust
#[cfg(test)]
mod if_constant_fold_tests {
    use crate::{analyze, Config};

    #[test]
    fn if_zero_neq_zero_is_constant_false() {
        let script = b"if 0 neq 0 echo SHOULD_NOT_FIRE\r\necho REAL\r\n";
        let report = analyze(script, &Config::default());
        // The if-line still renders (its text), but no `IfNotResolved` trait should fire,
        // and on the same logical line, the echo after the if should be suppressed.
        let has_unresolved = report.traits.iter().any(|t|
            matches!(t, crate::traits::Trait::IfNotResolved { .. })
        );
        assert!(!has_unresolved, "0 neq 0 should constant-fold to false");
    }

    #[test]
    fn if_zero_equ_zero_is_constant_true() {
        let script = b"if 0 equ 0 echo MATCH\r\n";
        let report = analyze(script, &Config::default());
        let has_unresolved = report.traits.iter().any(|t|
            matches!(t, crate::traits::Trait::IfNotResolved { .. })
        );
        assert!(!has_unresolved, "0 equ 0 should constant-fold to true");
    }

    #[test]
    fn if_string_equ_case_insensitive() {
        let script = b"if /i \"AMD64\" EQU \"amd64\" echo MATCH\r\n";
        let report = analyze(script, &Config::default());
        let has_unresolved = report.traits.iter().any(|t|
            matches!(t, crate::traits::Trait::IfNotResolved { .. })
        );
        assert!(!has_unresolved, "case-insensitive AMD64==amd64 should fold true");
    }

    #[test]
    fn if_gtr_lss_geq_leq() {
        for (op, expected_unresolved) in [("gtr 5", false), ("lss 5", false), ("geq 5", false), ("leq 5", false)] {
            let _ = op;
            let _ = expected_unresolved;
        }
        // Concrete checks:
        let script = b"if 10 gtr 5 echo A\r\nif 3 lss 5 echo B\r\nif 10 geq 10 echo C\r\nif 5 leq 5 echo D\r\n";
        let report = analyze(script, &Config::default());
        let unresolved_count = report.traits.iter().filter(|t|
            matches!(t, crate::traits::Trait::IfNotResolved { .. })
        ).count();
        assert_eq!(unresolved_count, 0, "all 4 relational ops should fold cleanly");
    }
}
```

- [ ] **Step 2: Extend `evaluate()` in `if_cmd.rs`** to handle `EQU NEQ LSS LEQ GTR GEQ`:

Find the existing `==` block:
```rust
    if let Some(eq_pos) = body.find("==") {
        ...
    }
```

After it, add a new block for relational ops. Match these tokens (case-insensitive): ` EQU `, ` NEQ `, ` LSS `, ` LEQ `, ` GTR `, ` GEQ ` (with surrounding spaces so we don't match inside a string):

```rust
    // Relational operators: EQU NEQ LSS LEQ GTR GEQ (case-insensitive, word-bounded)
    let upper = body.to_ascii_uppercase();
    for (op_str, op_kind) in [
        (" EQU ", "eq"), (" NEQ ", "ne"),
        (" LSS ", "lt"), (" LEQ ", "le"),
        (" GTR ", "gt"), (" GEQ ", "ge"),
    ] {
        if let Some(pos) = upper.find(op_str) {
            let lhs = body[..pos].trim().trim_matches('"');
            let rhs_start = pos + op_str.len();
            let rhs_full = body[rhs_start..].trim_start();
            let rhs_end = rhs_full.find(|c: char| c.is_whitespace() || c == ')').unwrap_or(rhs_full.len());
            let rhs = rhs_full[..rhs_end].trim().trim_matches('"');
            if lhs.contains('%') || lhs.contains('!') || rhs.contains('%') || rhs.contains('!') {
                return None;
            }
            // Try numeric first
            let l_n = lhs.parse::<i64>().ok();
            let r_n = rhs.parse::<i64>().ok();
            if let (Some(l), Some(r)) = (l_n, r_n) {
                return Some(match op_kind {
                    "eq" => l == r, "ne" => l != r,
                    "lt" => l < r,  "le" => l <= r,
                    "gt" => l > r,  "ge" => l >= r,
                    _ => return None,
                });
            }
            // Fall back to case-insensitive string compare for eq/ne
            if case_insensitive {
                let l_cmp = lhs.to_ascii_lowercase();
                let r_cmp = rhs.to_ascii_lowercase();
                return Some(match op_kind {
                    "eq" => l_cmp == r_cmp, "ne" => l_cmp != r_cmp,
                    _ => return None,
                });
            }
            return Some(match op_kind {
                "eq" => lhs == rhs, "ne" => lhs != rhs,
                _ => return None,
            });
        }
    }
```

Insert this before the function's final `None`.

- [ ] **Step 3: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
```

- [ ] **Step 4: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/handlers/if_cmd.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "Constant-fold IF EQU/NEQ/LSS/LEQ/GTR/GEQ comparisons"
```

---

## Task 3: Inline IF — recover the body when there's no `(`

**Impact:** 23 corpus files have malformed-looking IFs like `if 0 equ 900 exit` where `exit` is on the same line, no parens. Currently `exit` gets parsed into the condition string (RHS scan absorbs it).

This is actually a real cmd.exe form: `if COND CMD ARGS…` runs `CMD ARGS…` if true, same line, no parens. The current `evaluate()` extracts the RHS by scanning to the next whitespace, which mostly works, but the rest of the line (the "body") isn't being treated as an actual command-on-same-line.

The h_if handler delegates body suppression to `env.suppress_until_eol`. But the inline body in `if COND echo HI` is part of the SAME normalized line (single command in split_commands), not a subsequent split-command. So if we *don't* set suppress_until_eol, the `echo HI` portion never gets dispatched — it's already inside the if-line which the dispatcher handed to `h_if`.

**The fix is to recurse into the inline body when the condition resolves true.** When the if handler resolves to true, it should re-dispatch the body portion of the line.

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/if_cmd.rs`

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod inline_if_tests {
    use crate::{analyze, Config};

    #[test]
    fn inline_if_true_recurses_into_body() {
        let script = b"if 1 equ 1 set X=value\r\necho %X%\r\n";
        let report = analyze(script, &Config::default());
        assert!(report.deobfuscated.contains("echo value"), "got:\n{}", report.deobfuscated);
    }

    #[test]
    fn inline_if_false_does_not_run_body() {
        let script = b"if 1 equ 2 set X=value\r\necho %X%\r\n";
        let report = analyze(script, &Config::default());
        // X never set, so %X% expands to empty
        assert!(!report.deobfuscated.contains("echo value"), "got:\n{}", report.deobfuscated);
    }
}
```

- [ ] **Step 2: Update `h_if`** to recurse the inline body when the condition resolves true. After the `evaluate()` call:

```rust
pub fn h_if(raw: &str, env: &mut Environment) {
    let Some(caps) = IF_RE.captures(raw) else { return };
    let negate = caps.name("neg").is_some();
    let rest = caps.name("rest").map(|m| m.as_str()).unwrap_or("");
    let result = evaluate(rest, env);
    let final_result = match result {
        Some(b) => if negate { !b } else { b },
        None => {
            env.traits.push(crate::traits::Trait::IfNotResolved { condition: rest.to_string() });
            return;
        }
    };
    if !final_result {
        env.suppress_until_eol = true;
        return;
    }
    // Condition resolves true: if there's an inline body (the rest of the
    // condition string after the operator + RHS), re-dispatch it.
    if let Some(body) = extract_inline_body(rest) {
        let body = body.trim();
        if !body.is_empty() && !body.starts_with('(') {
            crate::interp::interpret_line(body, env);
        }
    }
}

/// Given the `rest` of an `if` statement (everything after `if [not]`),
/// return the inline body that follows the condition. Returns None when
/// the condition is followed by `(` (block form) or nothing.
fn extract_inline_body(rest: &str) -> Option<String> {
    // The body is "whatever follows the condition's RHS". We re-implement a
    // simplified condition-scanner that walks past defined-X, exist X, or
    // a relational compare with two operands, then returns the tail.
    let trimmed = rest.trim_start();

    // defined X / exist X — body is everything after X
    for kw in ["defined", "exist", "errorlevel", "cmdextversion"] {
        let lower = trimmed.to_ascii_lowercase();
        if let Some(after) = lower.strip_prefix(kw) {
            if after.starts_with(' ') || after.starts_with('\t') {
                let consumed = trimmed.len() - after.len();
                let rest_after_kw = &trimmed[consumed..].trim_start();
                let mut parts = rest_after_kw.splitn(2, |c: char| c.is_whitespace());
                let _operand = parts.next()?;
                return parts.next().map(|s| s.to_string());
            }
        }
    }

    // /i optional + "lhs" == "rhs" / EQU / NEQ / LSS / LEQ / GTR / GEQ
    // Body is everything after the rhs.
    let (rest2, _ci) = if let Some(after) = trimmed.to_ascii_lowercase().strip_prefix("/i") {
        if after.starts_with(' ') || after.starts_with('\t') {
            (trimmed[2..].trim_start(), true)
        } else {
            (trimmed, false)
        }
    } else {
        (trimmed, false)
    };

    if let Some(eq_pos) = rest2.find("==") {
        let after = &rest2[eq_pos + 2..].trim_start();
        // Skip the RHS (one whitespace-delimited token, possibly quoted)
        return Some(skip_one_token(after).to_string());
    }
    let upper = rest2.to_ascii_uppercase();
    for op in [" EQU ", " NEQ ", " LSS ", " LEQ ", " GTR ", " GEQ "] {
        if let Some(pos) = upper.find(op) {
            let after = rest2[pos + op.len()..].trim_start();
            return Some(skip_one_token(after).to_string());
        }
    }
    None
}

fn skip_one_token(s: &str) -> &str {
    let s = s.trim_start();
    if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            return s[end + 2..].trim_start();
        }
        return "";
    }
    match s.find(char::is_whitespace) {
        Some(p) => s[p..].trim_start(),
        None => "",
    }
}
```

- [ ] **Step 3: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/handlers/if_cmd.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "Recurse into inline IF body when condition resolves true"
```

---

## Task 4: Preserve `;` inside double-quoted args (PowerShell `-Command`)

**Impact:** `powershell -Command "$x=1; Get-Process"` currently strips the `;` because Plan A's lexer treats `;` as whitespace OUTSIDE quotes — but the issue is that within `Token::DoubleQuoted`, our re-lex on inner content during normalize STRIPS the `;` because the inner lex doesn't know it's inside a quote.

Check the actual behavior: in `normalize.rs`'s `Token::DoubleQuoted(s)` arm, we re-lex `s` and re-normalize. The re-lex hits the `;` and treats it as whitespace (Plan A behavior).

**The fix is to NOT re-lex DoubleQuoted content for variable expansion.** Instead, do a lightweight substitution pass that only handles `%VAR%` / `!VAR!` references, treating everything else as literal.

**Files:**
- Modify: `rust/crates/batdeob-core/src/normalize.rs`

- [ ] **Step 1: Add test** to `lib.rs`:

```rust
#[cfg(test)]
mod quoted_semicolon_tests {
    use crate::env::{Config, Environment};
    use crate::lex::lex;
    use crate::normalize::normalize_to_string;

    #[test]
    fn semicolon_inside_double_quotes_preserved() {
        let mut env = Environment::new(&Config::default());
        let out = normalize_to_string(&lex(r#"echo "a; b; c""#), &mut env);
        // The output should retain the semicolons
        assert!(out.contains("a; b; c"), "semicolons stripped: {:?}", out);
    }

    #[test]
    fn variable_in_quoted_string_still_expands() {
        let mut env = Environment::new(&Config::default());
        env.set("X", "value");
        let out = normalize_to_string(&lex(r#"echo "x=%X%; y=2""#), &mut env);
        assert!(out.contains("x=value; y=2"), "got: {:?}", out);
    }
}
```

- [ ] **Step 2: Fix `Token::DoubleQuoted` handling** in `normalize.rs`

Find the `Token::DoubleQuoted(s)` arm in `normalize_inner`. Replace the "lex+normalize the inner" approach with a direct character-level substitution:

```rust
            Token::DoubleQuoted(s) => {
                out.push('"');
                out.push_str(&expand_vars_in_string(s, env, depth));
                out.push('"');
            }
```

Add the helper near the top of `normalize.rs`:

```rust
/// Variable expansion that walks a string char-by-char, expanding %VAR% and
/// !VAR! (when delayed expansion is on) but preserving everything else
/// (including operators like `;`, `&`, `|` that the lexer would otherwise
/// collapse to whitespace). Used inside double-quoted strings.
fn expand_vars_in_string(s: &str, env: &mut crate::env::Environment, depth: u32) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '%' => {
                // Find matching %; if not found, drop the %
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() && chars[j] != '%' {
                    name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && !name.is_empty() {
                    // Got a closing %; resolve VAR (with possible :op)
                    let value = resolve_var_ref(&name, env, false, depth);
                    out.push_str(&value);
                    i = j + 1;
                } else {
                    // No closing % — drop the leading %, advance one char
                    i += 1;
                }
            }
            '!' if env.delayed_expansion => {
                let mut j = i + 1;
                let mut name = String::new();
                while j < chars.len() && chars[j] != '!' {
                    name.push(chars[j]);
                    j += 1;
                }
                if j < chars.len() && !name.is_empty() {
                    let value = resolve_var_ref(&name, env, true, depth);
                    out.push_str(&value);
                    i = j + 1;
                } else {
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Resolve a single var-ref body (the part between sigils). Handles bare
/// `NAME` plus `NAME:~i,n` substring and `NAME:s1=s2` substitution forms.
fn resolve_var_ref(body: &str, env: &mut crate::env::Environment, is_bang: bool, depth: u32) -> String {
    let _ = is_bang;
    let (name, op_str) = match body.find(':') {
        Some(p) => (&body[..p], Some(&body[p + 1..])),
        None => (body, None),
    };
    let raw = match env.get(name) {
        Some(v) => v,
        None => return String::new(),
    };
    let value = match op_str {
        None => raw,
        Some(op) => {
            // Apply substring or substitute
            if op.trim_start().starts_with('~') {
                // %X:~i,n%
                if let Some(crate::lex::VarOp::Substr { index, length }) = crate::lex::parse_substr_for_normalize(op) {
                    crate::normalize::apply_substr_pub(&raw, index, length)
                } else { raw }
            } else if let Some(crate::lex::VarOp::Substitute { needle, replacement, leading_wildcard }) = crate::lex::parse_substitute_for_normalize(op) {
                crate::normalize::apply_substitute_pub(&raw, &needle, &replacement, leading_wildcard)
            } else {
                raw
            }
        }
    };
    if depth + 1 >= 32 {
        return value;
    }
    // If the value contains nested %/!/^, recurse — but do so by re-lexing
    // the value (not the original string). This matches the existing
    // recursive-re-lex semantics.
    if value.contains('%') || value.contains('!') || value.contains('^') {
        let inner = crate::lex::lex(&value);
        crate::normalize::normalize_inner_pub(&inner, env, depth + 1)
    } else {
        value
    }
}
```

This sketch calls helpers like `crate::lex::parse_substr_for_normalize` and `crate::normalize::apply_substr_pub` that don't exist yet. The cleanest implementation is to **make the existing `parse_substr`/`parse_substitute` in `lex.rs` and `apply_substr`/`apply_substitute` in `normalize.rs` accessible via `pub(crate)` and call them directly**.

Specifically:
- In `lex.rs`: change `fn parse_substr` and `fn parse_substitute` from private to `pub(crate)`. Same for `take_signed_int` if needed.
- In `normalize.rs`: change `fn apply_substr` and `fn apply_substitute` to `pub(crate)`.
- Also make `normalize_inner` `pub(crate)` so the helper can recurse via the normal path.

Then in `expand_vars_in_string`, use them directly:

```rust
            if op.trim_start().starts_with('~') {
                if let Some(crate::lex::VarOp::Substr { index, length }) = crate::lex::parse_substr(op) {
                    crate::normalize::apply_substr(&raw, index, length)
                } else { raw }
            } else if let Some(crate::lex::VarOp::Substitute { needle, replacement, leading_wildcard }) = crate::lex::parse_substitute(op) {
                crate::normalize::apply_substitute(&raw, &needle, &replacement, leading_wildcard)
            } else { raw }
```

The two `_pub` aliases mentioned above don't need to exist if you make the originals `pub(crate)`. Cleaner.

- [ ] **Step 3: Verify**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -15
```

Pre-existing DOSfuscation tests may be sensitive to this change. Run them specifically:

```bash
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --package batdeob-core dosfuscation 2>&1 | tail -10
```

All 27 + 4 DOSfuscation tests must still pass.

- [ ] **Step 4: Commit**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Preserve operators inside double-quoted strings during var expansion"
```

---

## Task 5: FOR /F — `tokens=N,` trailing comma + body preservation on unresolved source

**Impact:** LOGOFALL.bat + 17 corpus files for the trailing comma; ForUnresolvedSource fires 506 times across 17 files for the body-dropped case.

**Files:**
- Modify: `rust/crates/batdeob-core/src/handlers/for_cmd.rs`

- [ ] **Step 1: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod for_f_misc_tests {
    use crate::{analyze, Config};

    #[test]
    fn for_f_tokens_trailing_comma() {
        // `tokens=3,` — trailing comma should not break body execution
        let script = br#"for /f "skip=0 tokens=3, delims= " %%a in ("a b c d") do echo got=%%a"#;
        let report = analyze(script, &Config::default());
        assert!(report.deobfuscated.contains("echo got=c"), "got:\n{}", report.deobfuscated);
    }

    #[test]
    fn for_f_unresolved_source_preserves_body() {
        // A pipeline we can't resolve (`reg query`). The body should still
        // appear in the deobfuscated output (with the loop variable left as %%a).
        let script = br#"for /f "tokens=*" %%a in ('reg query HKLM\Software') do echo got=%%a"#;
        let report = analyze(script, &Config::default());
        // We expect SOMETHING from the loop body to be visible — either with
        // %%a expanded to empty (running one iteration with no value), or
        // the body preserved verbatim. The minimum bar: "echo got=" appears.
        assert!(report.deobfuscated.contains("echo got="), "got:\n{}", report.deobfuscated);
    }
}
```

- [ ] **Step 2: Fix `parse_f_opts` trailing comma**

In `handlers/for_cmd.rs`, find `parse_f_opts` (or `parse_f_opts_full`). The bug: when parsing `tokens=3,`, the trailing comma causes an empty token to be parsed (or the parser to misroute). Fix the splitting on `,`:

```rust
                "tokens" => {
                    o.tokens.clear();
                    o.tokens_star = false;
                    for part in val.split(',') {
                        let part = part.trim();
                        if part.is_empty() { continue; }
                        if part == "*" {
                            o.tokens_star = true;
                        } else if let Ok(n) = part.parse::<usize>() {
                            o.tokens.push(n);
                        }
                    }
                    if o.tokens.is_empty() && !o.tokens_star { o.tokens.push(1); }
                }
```

The added `let part = part.trim(); if part.is_empty() { continue; }` skips empty splits caused by `tokens=3,`.

- [ ] **Step 3: Preserve loop body when source is unresolved**

In `handlers/for_cmd.rs`, find `run_for_from_raw` (or the `/F` branch). When `resolve_f_source` returns empty, currently the body doesn't run at all. Change to run the body ONCE with the loop variable substituted to empty:

```rust
        let values: Vec<String> = lines.into_iter()
            .skip(parsed.skip)
            .filter_map(|line| extract_token(&line, &parsed))
            .collect();

        if values.is_empty() {
            // Source was unresolvable. Still emit the body once with the loop
            // variable left as empty — preserves the body for IOC scanning.
            run_iter_body(&body, var, vec![String::new()], env);
        } else {
            run_iter_body(&body, var, values, env);
        }
        return true;
```

- [ ] **Step 4: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/handlers/for_cmd.rs rust/crates/batdeob-core/src/lib.rs
git commit -m "FOR /F: tolerate trailing comma in tokens=, preserve body on unresolved source"
```

---

## Task 6: Pass-through handlers for common admin commands

**Impact:** Corpus shows `cls` in 130 files, `del` in 80, `timeout` in 53, `reg` in 40, `attrib` in 33, `mkdir` in 27, `move` in 6, `rmdir`/`rd` in 5/2.

These commands currently fall through the dispatcher unhandled. That's mostly fine — arg variables already get normalized by the lexer/normalizer before dispatch. But some emit useful IOC traits.

Strategy: register them as known but with no-op handlers (just records the cmd via a new `Trait::AdminCommand { cmd, name }` for downstream filtering). Skip implementing per-command logic.

**Files:**
- Modify: `rust/crates/batdeob-core/src/traits.rs` (new variant)
- Create: `rust/crates/batdeob-core/src/handlers/passthrough.rs`
- Modify: `rust/crates/batdeob-core/src/handlers/mod.rs`

- [ ] **Step 1: Add trait variant** to `traits.rs`:

```rust
    AdminCommand { name: String, cmd: String },
```

- [ ] **Step 2: Add tests** to `lib.rs`:

```rust
#[cfg(test)]
mod passthrough_tests {
    use crate::env::{Config, Environment};
    use crate::interp::interpret_line;
    use crate::traits::Trait;

    #[test]
    fn del_emits_admin_command_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line("del /q /f C:\\temp\\evil.exe", &mut env);
        let has = env.traits.iter().any(|t|
            matches!(t, Trait::AdminCommand { name, .. } if name == "del")
        );
        assert!(has, "no AdminCommand: {:?}", env.traits);
    }

    #[test]
    fn reg_emits_admin_command_trait() {
        let mut env = Environment::new(&Config::default());
        interpret_line("reg add HKLM\\Software\\Run /v Evil /d C:\\evil.exe", &mut env);
        let has = env.traits.iter().any(|t|
            matches!(t, Trait::AdminCommand { name, .. } if name == "reg")
        );
        assert!(has, "no AdminCommand: {:?}", env.traits);
    }
}
```

- [ ] **Step 3: Create `handlers/passthrough.rs`**:

```rust
//! Pass-through admin commands — emits an AdminCommand trait so analysts
//! can filter on these without inspecting the deobfuscated text.

use crate::env::Environment;
use crate::traits::Trait;

macro_rules! make_handler {
    ($fn_name:ident, $cmd_name:literal) => {
        pub fn $fn_name(raw: &str, env: &mut Environment) {
            env.traits.push(Trait::AdminCommand {
                name: $cmd_name.to_string(),
                cmd: raw.to_string(),
            });
        }
    };
}

make_handler!(h_del, "del");
make_handler!(h_cls, "cls");
make_handler!(h_timeout, "timeout");
make_handler!(h_reg, "reg");
make_handler!(h_attrib, "attrib");
make_handler!(h_mkdir, "mkdir");
make_handler!(h_md, "md");
make_handler!(h_move, "move");
make_handler!(h_rmdir, "rmdir");
make_handler!(h_rd, "rd");
make_handler!(h_taskkill, "taskkill");
make_handler!(h_tasklist, "tasklist");
make_handler!(h_schtasks, "schtasks");
make_handler!(h_sc, "sc");
make_handler!(h_ping, "ping");
make_handler!(h_xcopy, "xcopy");
make_handler!(h_title, "title");
make_handler!(h_pause, "pause");
make_handler!(h_color, "color");
make_handler!(h_doskey, "doskey");
make_handler!(h_chcp, "chcp");
make_handler!(h_ver, "ver");
make_handler!(h_whoami, "whoami");
```

- [ ] **Step 4: Register** all of them in `handlers/mod.rs`:

```rust
pub mod passthrough;

// In lookup match block, add:
        "del"      => Some(passthrough::h_del),
        "cls"      => Some(passthrough::h_cls),
        "timeout"  => Some(passthrough::h_timeout),
        "reg"      => Some(passthrough::h_reg),
        "attrib"   => Some(passthrough::h_attrib),
        "mkdir"    => Some(passthrough::h_mkdir),
        "md"       => Some(passthrough::h_md),
        "move"     => Some(passthrough::h_move),
        "rmdir"    => Some(passthrough::h_rmdir),
        "rd"       => Some(passthrough::h_rd),
        "taskkill" => Some(passthrough::h_taskkill),
        "tasklist" => Some(passthrough::h_tasklist),
        "schtasks" => Some(passthrough::h_schtasks),
        "sc"       => Some(passthrough::h_sc),
        "ping"     => Some(passthrough::h_ping),
        "xcopy"    => Some(passthrough::h_xcopy),
        "title"    => Some(passthrough::h_title),
        "pause"    => Some(passthrough::h_pause),
        "color"    => Some(passthrough::h_color),
        "doskey"   => Some(passthrough::h_doskey),
        "chcp"     => Some(passthrough::h_chcp),
        "ver"      => Some(passthrough::h_ver),
        "whoami"   => Some(passthrough::h_whoami),
```

- [ ] **Step 5: Verify + commit**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -10
cd /home/coz/Downloads/batch_deobfuscator
git add rust/crates/batdeob-core/src/
git commit -m "Pass-through handlers for del/cls/reg/attrib/mkdir/taskkill/schtasks/etc"
```

---

## Task 7: Final lints + corpus re-run

After Tasks 1-6 land, re-run the corpus and the Python diff to measure improvement.

- [ ] **Step 1: Lints pass**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo fmt
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo test --workspace 2>&1 | tail -5
```

Commit any formatting changes:

```bash
cd /home/coz/Downloads/batch_deobfuscator
git add -u rust/
git diff --cached --quiet || git commit -m "Plan D: fmt + clippy clean"
```

- [ ] **Step 2: Re-run corpus** with the v3 binary:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/coz/Downloads/batch_deobfuscator/rust && cargo build --release 2>&1 | tail -3

# Reuse the existing driver, output to corpus_results_v3
sed 's|/tmp/corpus_results_v2|/tmp/corpus_results_v3|g' /tmp/corpus_run_v2.sh > /tmp/corpus_run_v3.sh
chmod +x /tmp/corpus_run_v3.sh
mkdir -p /tmp/corpus_results_v3
timeout 1800 /tmp/corpus_run_v3.sh > /tmp/corpus_run_v3.log 2>&1
wc -l /tmp/corpus_results_v3/index.jsonl
```

- [ ] **Step 3: Compare v2 vs v3**

```bash
python3 <<'PY'
import json
from pathlib import Path
from collections import Counter

def load(d):
    out = {}
    for line in (Path(d) / "index.jsonl").read_text().splitlines():
        try: r = json.loads(line); out[r["sha"]] = r
        except: pass
    return out

v2 = load("/tmp/corpus_results_v2")
v3 = load("/tmp/corpus_results_v3")

def summary(by_sha, name):
    n = len(by_sha)
    succ = sum(1 for r in by_sha.values() if r["rc"] == 0)
    avg_len = sum(r["out_size"] for r in by_sha.values() if r["rc"]==0) / max(1, succ)
    print(f"{name}: total={n} success={succ} ({100*succ/n:.1f}%) avg_out={avg_len:.0f}")
summary(v2, "v2 (post-Plan C)")
summary(v3, "v3 (post-Plan D)")

# Newly-resolved (output went UP for samples that were already successful)
larger = 0; smaller = 0
for sha, r_v3 in v3.items():
    if r_v3["rc"] != 0: continue
    r_v2 = v2.get(sha)
    if not r_v2 or r_v2["rc"] != 0: continue
    if r_v3["out_size"] > r_v2["out_size"] * 1.5: larger += 1
    elif r_v3["out_size"] < r_v2["out_size"] * 0.5: smaller += 1
print(f"Samples with much larger v3 output (likely gates lifted): {larger}")
print(f"Samples with much smaller v3 output (potential regression): {smaller}")

# Trait counts
trait_v2 = Counter(); trait_v3 = Counter()
for src, dst in ((v2, trait_v2), (v3, trait_v3)):
    for r in src.values():
        if r["rc"] != 0: continue
        p = Path(f"/tmp/corpus_results_{'v2' if src is v2 else 'v3'}") / f"{r['sha']}.json"
        if not p.exists(): continue
        try:
            for t in json.loads(p.read_text(errors='replace')).get("traits", []):
                dst[t.get("kind","")] += 1
        except: pass
print("\nTrait event counts (v2 vs v3):")
all_kinds = set(trait_v2) | set(trait_v3)
for k in sorted(all_kinds, key=lambda x: -max(trait_v2[x], trait_v3[x])):
    print(f"  {k:28} {trait_v2[k]:>8} -> {trait_v3[k]:>8}")
PY
```

Report the table. Target deltas:
- Success rate: still 100%
- `IfNotResolved`: 50,452 → < 5,000 (down 90%)
- `ForUnresolvedSource`: 506 → similar (we preserve bodies but unresolved sources still count)
- `AdminCommand` (new): non-zero

If success rate drops below 100% or "smaller" count is non-zero, INVESTIGATE — Plan D should be pure win.

- [ ] **Step 4: Commit the summary**

```bash
cd /home/coz/Downloads/batch_deobfuscator
git commit --allow-empty -m "$(cat <<EOF
Plan D complete: corpus v3 results

[paste the comparison table from Step 3]
EOF
)"
```

---

## Self-review

- **Spec coverage**: every Plan D task ties to a specific corpus-data finding from the analysis pass.
- **Placeholders**: none.
- **Type consistency**: `Trait::AdminCommand` added in Task 6; used in Task 6 only. `extract_inline_body` is a new private fn in `if_cmd.rs` (Task 3). The `pub(crate)` visibility changes in Task 4 affect existing functions — verify call sites still compile.
- **Risk**: Task 1 changes a semantic that prior tests asserted. The plan calls out the test rewrite explicitly. Task 4's lex/normalize visibility change could ripple — keep an eye on it.

**Plan D complete.** Execute via `superpowers:subagent-driven-development`.
