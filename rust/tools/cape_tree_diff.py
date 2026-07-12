#!/usr/bin/env python3
"""For each reported task with cape_executed_count >= 2 (real batch run),
pull every command CAPE actually saw from report.json's behavior.processes
(or from /apiv2/tasks/get/iocs/'s executed_commands fallback), then ask:
  - Does batdeob's deob output produce a similar resolved command?
  - Or is there a CAPE-observed expansion that batdeob misses?

Output:
  /tmp/batdeob_cape_tree_diff.txt — per-task block with:
    [CAPE]:    one line per command CAPE ran (after %-var resolution etc.)
    [BATDEOB]: one line per cmd line found in batdeob's deobfuscated output
    [GAPS]:    CAPE lines that don't have a clear batdeob counterpart

Heuristic: a CAPE line "has a batdeob counterpart" if every alphanumeric
token (length >= 4) appears somewhere in the batdeob deob text.
"""
from __future__ import annotations
import csv, json, os, re, subprocess, sys, time
import urllib.request, urllib.error
from pathlib import Path

SUBMIT_CSV = Path("/tmp/batdeob_cape_submissions.csv")
SAMPLES_DIR = Path("/tmp/batdeob_cape_in")
OUT = Path("/tmp/batdeob_cape_tree_diff.txt")
BATDEOB = Path("/home/coz/Downloads/batdeob/rust/target/debug/batdeob")
CAPE = "http://172.18.101.17:8000"
TOKEN = os.environ.get("CAPE_TOKEN") or sys.exit("CAPE_TOKEN unset")
H = {"Authorization": f"Token {TOKEN}"}
TOKEN_RE = re.compile(r"[A-Za-z0-9_./:\\-]{4,}")
SKIP_TOKENS = {
    "cmd.exe", "powershell.exe", "wbem", "wmiprvse", "embedding",
    "csc.exe", "cvtres.exe", "powershell", "secured", "config", "noconfig",
    "fullpaths", "windowstyle", "hidden", "command", "noprofile",
}
# Whole-line patterns that are CAPE/sandbox runtime artifacts (not bat
# obfuscation we should mirror). Match against the lowercased line.
SANDBOX_NOISE_LINE_RE = re.compile(
    r"(?i)"
    r"cmd\.exe.*\bstart\s+/wait\s+\"\"\s+\"c:\\users\\jsmith\\appdata\\local\\temp"
    r"|csc\.exe.*\.cmdline"
    r"|cvtres\.exe"
    r"|splwow64\.exe"
    r"|wbem\\wmiprvse"
    r"|svchost\.exe\s+-k\s"  # any svchost service launch
    r"|werfault\.exe"  # Windows error reporting on crash
    r"|msedge\.exe"
    r"|identity_helper\.exe"
    r"|wordpad\.exe"
    r"|winword\.exe"
    r"|\\windowspowershell\\v1\.0\\powershell\.exe$"
)


def http_get(path: str, timeout: int = 60, retries: int = 6) -> dict:
    for i in range(retries):
        try:
            r = urllib.request.Request(f"{CAPE}{path}", headers=H)
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < retries - 1:
                time.sleep(20 + 10 * i)
                continue
            raise


def _walk_tree(node, depth: int, out: list[tuple[int, int, str, str]]):
    """Walk processtree, emitting (depth, pid, name, command_line) tuples."""
    if not isinstance(node, dict):
        return
    pid = node.get("pid") or node.get("process_id") or 0
    name = node.get("name") or node.get("process_name") or ""
    cl = (
        node.get("command_line")
        or node.get("commandLine")
        or (node.get("environ", {}) or {}).get("CommandLine", "")
        or ""
    )
    out.append((depth, pid, name, cl))
    children = node.get("spawned_processes") or node.get("children") or []
    for c in children:
        _walk_tree(c, depth + 1, out)


def fetch_cape_commands(tid: str) -> tuple[list[tuple[int, int, str, str]], str]:
    """Return ([(depth, pid, name, command_line), ...], package).
    Walks behavior.processtree so each command carries its depth in the spawn
    chain — depth 0 is the harness root, depth 1 the bat invocation, depth 2
    direct bat children (powershell, certutil, etc.), depth >= 3 is post-
    payload (loaded code spawning more processes — out of static scope)."""
    try:
        report = http_get(f"/apiv2/tasks/get/report/{tid}/json/", timeout=120)
    except Exception:
        report = None
    package = ""
    nodes: list[tuple[int, int, str, str]] = []
    if isinstance(report, dict) and not report.get("error"):
        info = (report.get("info") or {})
        package = info.get("package", "") or ""
        beh = report.get("behavior", {}) or {}
        tree = beh.get("processtree") or []
        if isinstance(tree, list):
            for root in tree:
                _walk_tree(root, 0, nodes)
        elif isinstance(tree, dict):
            _walk_tree(tree, 0, nodes)
        # If processtree didn't give command-lines, backfill from processes[]
        if nodes and not any(cl for _, _, _, cl in nodes):
            cl_by_pid = {
                p.get("process_id") or p.get("pid"):
                    (p.get("environ", {}) or {}).get("CommandLine", "")
                for p in beh.get("processes", []) or []
            }
            nodes = [(d, p, n, cl_by_pid.get(p, "")) for d, p, n, _ in nodes]
    if not nodes:
        try:
            ioc = http_get(f"/apiv2/tasks/get/iocs/{tid}/", timeout=30).get("data", {})
            cmds = list(ioc.get("executed_commands") or [])
            package = package or (ioc.get("info") or {}).get("package", "")
            # No tree info available — synthesize depth=2 for everything
            # (best-effort: assume direct children of the bat).
            nodes = [(2, 0, "", c) for c in cmds]
        except Exception:
            pass
    return nodes, package


def run_batdeob(sample: Path) -> str:
    try:
        r = subprocess.run(
            [str(BATDEOB), "report", str(sample), "--include-deob"],
            capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return ""
        rep = json.loads(r.stdout)
        # Combine deob text + any extracted ps/cmd samples (so we capture
        # commands that only surface inside the PS payload).
        parts = [rep.get("deobfuscated", "") or ""]
        ex = rep.get("extracted", {}) or {}
        parts.extend(ex.get("powershell_samples", []) or [])
        parts.extend(ex.get("cmd_samples", []) or [])
        return "\n".join(parts)
    except Exception:
        return ""


def is_sandbox_noise(cape_line: str) -> bool:
    """Filter out CAPE-only runtime artifacts that don't reflect bat
    obfuscation (sandbox launcher, .NET inline compile, browser opens, etc.)."""
    return bool(SANDBOX_NOISE_LINE_RE.search(cape_line))


_SANDBOX_TMP_RE = re.compile(r"(?i)c:\\users\\[^\\]+\\appdata\\local\\temp\\")
# Sample-hash tmp filename (e.g. CAPE renames the bat to `<sha-prefix>.bat`)
# — runtime artifact the static analyzer can't reproduce.
_SANDBOX_HASHNAME_RE = re.compile(r"\b[0-9a-f]{12,}(?:\.[a-z]{2,4})?\b", re.IGNORECASE)


def cape_line_covered(cape_line: str, batdeob_text: str) -> bool:
    """Heuristic: every interesting token of the CAPE line appears in
    batdeob's text (case-insensitive). Skip very generic launcher tokens and
    sandbox-injected tmp paths (those are runtime artifacts the static
    analyzer can never know — they're values of vars like `%liIlIiliiIl%`
    that resolve to `C:\\Users\\jsmith\\AppData\\Local\\Temp\\<hash>.bat`)."""
    if is_sandbox_noise(cape_line):
        return True
    # Strip sandbox-tmp tokens + sandbox-renamed-by-hash filenames from
    # the CAPE line before tokenizing so they don't count as missing.
    cape_clean = _SANDBOX_TMP_RE.sub("", cape_line)
    cape_clean = _SANDBOX_HASHNAME_RE.sub("", cape_clean)
    bd_lower = batdeob_text.lower()
    toks = [t.lower() for t in TOKEN_RE.findall(cape_clean)]
    interesting = [
        t for t in toks
        if t not in SKIP_TOKENS
        and not t.startswith("c:\\windows\\system32\\")
        and not t.startswith("c:\\users\\")
    ]
    if len(interesting) < 2:
        return True  # too generic to judge
    missing = [t for t in interesting if t not in bd_lower]
    # If >=70% covered, call it covered
    return len(missing) / max(1, len(interesting)) < 0.3


def main() -> int:
    rows = list(csv.DictReader(open(SUBMIT_CSV)))
    candidates = [
        r for r in rows
        if r.get("status") == "reported"
        and int(r.get("cape_executed_count", "0") or 0) >= 2
    ]
    print(f"diffing {len(candidates)} tasks (ec >= 2)...", file=sys.stderr)

    out_lines: list[str] = []
    gap_count = 0
    for r in candidates:
        tid = r["task_id"]
        sample = SAMPLES_DIR / f"{r['sha']}.bat"
        if not sample.exists():
            continue
        nodes, pkg = fetch_cape_commands(tid)
        if not nodes:
            continue
        # Hard filter: only consider tasks CAPE actually ran as batch.
        if not pkg or pkg.lower() != "batch":
            continue
        bd = run_batdeob(sample)
        # A gap is in-scope only if the process is reachable from the bat
        # itself: depth 0 = harness, depth 1 = the bat, depth 2 = its direct
        # children (powershell, certutil, regsvr32 launched by the bat).
        # Depth >= 3 means a second-stage payload that batdeob can't see
        # statically.
        in_scope = [(d, pid, n, cl) for d, pid, n, cl in nodes if d <= 2 and cl]
        gaps = [
            (d, pid, n, cl) for d, pid, n, cl in in_scope
            if not cape_line_covered(cl, bd) and not is_sandbox_noise(cl)
        ]
        out_lines.append("=" * 90)
        out_lines.append(
            f"task {tid}  bucket={r['bucket']}  pkg={pkg}  sha={r['sha'][:12]}  "
            f"filename={r['filename'][:50]}"
        )
        out_lines.append(
            f"  cape process tree ({len(nodes)} nodes, "
            f"{sum(1 for d,_,_,_ in nodes if d >= 3)} post-payload skipped):"
        )
        for d, pid, n, cl in nodes:
            if not cl:
                continue
            depth_marker = "  " * d
            if d >= 3:
                tag = "[stage2]"
            elif is_sandbox_noise(cl):
                tag = "[sbx]"
            elif cape_line_covered(cl, bd):
                tag = "[ok]"
            else:
                tag = "[GAP]"
            out_lines.append(f"  {depth_marker}d={d} pid={pid} {tag} {n}: {cl[:240]}")
        if gaps:
            gap_count += 1
            out_lines.append(f"  REAL GAPS (depth<=2, not sandbox-noise): {len(gaps)}")
            for d, pid, n, cl in gaps:
                out_lines.append(f"    >>> d={d} {n}: {cl[:240]}")
        out_lines.append("")
        time.sleep(3)  # polite rate to CAPE

    OUT.write_text("\n".join(out_lines))
    print(f"\nwrote {len(candidates)} task blocks to {OUT}", file=sys.stderr)
    print(f"tasks with potential gaps: {gap_count}/{len(candidates)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
