# Corpus diff audit — 2026-05-20 (second pass)

Following the `!VAR:OP!` fix (commit `5c5af54`), I diffed the deob against
the source on every corpus sample looking for the same kind of issue —
obfuscation residue surviving into the deob, or anomalous expansion.

1158 samples analyzed (258 PE-as-bat noise skipped). Findings, severity-ordered:

## Real bugs

### B1 (High): `!VAR:~%R%,N!` — bang-substring with `%`-resolved index returns whole string

Sample: `pp.cmd`. Source has the obfuscator loop

```bat
set CHAR=0123456789abc...
:LOOP
set /a R=%NZ%*%random%/32768
set RMZ=!CHAR:~%R%,1!%RMZ%
```

Repro:
```bat
@echo off
setlocal enabledelayedexpansion
set CHAR=ABCDEFGHIJ
set R=3
echo direct:  !CHAR:~3,1!     -> D            ✓
echo via_pct: !CHAR:~%R%,1!   -> ABCDEFGHIJ   ✗ (should be D)
```

Cause: `resolve_var_ref` splits the body on `:`, then `parse_substr("~%R%,1")`
fails because `%R%` isn't a parseable integer. The fallback returns the whole
`raw` value. The op string needs `%X%` pre-expansion before `parse_substr` /
`parse_substitute`.

### B2 (Medium): `%random%` always returns 4

Stub returns a constant. Breaks loops that build random strings (pp.cmd
folder-name generator). The deob shows the same value being appended every
iteration. Fix is to return a per-call deterministic-but-varying value
(e.g., hash of caller location + call index).

### B3 (Medium UX): Goto-loop unrolling fills the 4 MiB output cap

`curl.bat`: source has `:watchdog \n ... \n goto watchdog` at the end. Deob
shows the watchdog block 7,392 times before `OutputCapped` trait fires.
4 MB of repeated noise, hard for analysts to read.

Fix: detect repeated visits to the same goto target; after N (e.g. 4)
iterations, emit a `GotoLoopElided { target, iterations }` trait and stop
appending the body. The interpreter still tracks the iteration count for the
existing `max_iterations` cap; we just stop *appending the unrolled body*.

### B4 (Medium): FOR-loop variables stripped when the body emits unexecuted

`usbcreator.bat`: source has

```bat
for /f "skip=2 delims=" %%i in ('wmic logicaldisk ...') do (
  if %%l==4 (...)
)
```

When the FOR data source isn't statically resolvable, the body is emitted
in deob as-is. **But the FOR-var refs are partly stripped**:

```
for /f "skip=2 delims=" i in ('wmic ...') do (
  if l==4 (...)
)
```

`%%i` → `i`, `%%l` → `l`. The `if` test logic and the path-building
(`-o%%j` → `-oj`) is now wrong.

Fix: preserve `%%X` literal in any FOR body that didn't iterate (no
statically-resolvable data source).

### B5 (Low): Caret-escape in keyword survives in 4 samples

`caret_in_keyword: 4 samples` from the audit. Carets inside keywords
(`s^et`, `c^a^l^l`) usually normalize cleanly, but four samples have one
leftover `^` in deob. Probably an edge case in the lexer's caret-stripping
when a caret immediately precedes a `;` or some other operator.

Worth investigating but not high-impact.

## Not bugs (expected)

- **`!VAR!` survivors inside cmd /V/D/c literal echo (56 samples).** The
  deob's first-line literal echo of `start /MIN cmd /V/D/c "...!VAR!..."`
  preserves `!VAR!` un-expanded — that's the literal argument being passed
  to the child shell. The subsequent expanded sub-commands correctly
  resolve them. Confirmed on bad.bat, 536749_*.cmd, 950478_*.cmd.

- **`%~f0` / `%~dp0` / `%~nx0` survivors (289 samples).** Most are inside
  FOR-loop bodies or quoted strings that aren't fully resolved. Some are
  legitimate analyst signal (the script references its own path).

- **`goto :label` in deob (327 samples).** Control-flow statements are kept
  in the deob by design; we evaluate the goto for cursor movement but echo
  the line for human reading.

- **`%%X` in deob (134 samples).** Most are FOR-loop bodies that didn't
  iterate. Per B4, the `%%X` should be preserved when the loop body emits
  literally, but currently it's stripped — that's the bug.

## Audit findings JSON

Full per-pattern hit list at `/tmp/batdeob-audit2/findings.json`.
