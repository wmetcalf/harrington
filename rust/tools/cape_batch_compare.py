#!/usr/bin/env python3
"""Aggregate the batched CAPE run (tools/cape_batch_run.py) into a verdict
table comparing batdeob's static extraction against CAPE's runtime IOCs and
process tree.

Reads /home/coz/cstorage/batdeob_caperun/state.csv + cmp/<sha>.json.
Runs incrementally — safe to call while the batch run is still going.

Per reported (package=batch) sample, emits a verdict:
  AGREE_URL    — batdeob & CAPE share a normalized URL
  AGREE_HOST   — share a host/domain (URI specifics differ)
  BATDEOB_ONLY — batdeob found URL(s), CAPE reached no net IOC
  CAPE_ONLY    — CAPE has net IOC(s), batdeob found none  (← candidate gaps)
  PARTIAL/NEITHER
Also flags process-tree GAPS: depth<=2 cmd lines CAPE ran that batdeob's deob
doesn't reflect (sandbox-noise + stage>=3 filtered), mirroring cape_tree_diff.
"""
from __future__ import annotations
import csv, json, os, re, sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

STATE = Path("/home/coz/cstorage/batdeob_caperun/state.csv")
CMP = Path("/home/coz/cstorage/batdeob_caperun/cmp")
OUT = Path(os.environ.get("CAPE_COMPARE_OUT", "/tmp/batdeob_cape_compare.tsv"))

SANDBOX_TMP = re.compile(r"(?i)c:\\users\\[^\\]+\\appdata\\local\\temp\\")
HASHNAME = re.compile(r"\b[0-9a-f]{12,}(?:\.[a-z]{2,4})?\b", re.I)
SANDBOX_NOISE = re.compile(
    r"(?i)cmd\.exe.*\bstart\s+/wait\s+\"\"\s+\"c:\\users\\[^\\]+\\appdata\\local\\temp"
    r"|cmd\.exe\s+/k\s+\"c:\\users\\[^\\]+\\appdata\\local\\temp"  # harness /K form
    r"|csc\.exe.*\.cmdline|cvtres\.exe|splwow64\.exe|wbem\\wmiprvse"
    r"|wmiadap\.exe|svchost\.exe\s+-k\s|werfault\.exe"
    r"|msedge\.exe|identity_helper\.exe|wordpad\.exe|winword\.exe|conhost\.exe"
    # Chrome's own multi-process internals — not malware behavior
    r"|chrome\.exe.*--type=(?:gpu-process|renderer|utility|crashpad-handler|broker|nacl-loader|ppapi)"
    r"|\\windowspowershell\\v1\.0\\powershell\.exe$")
TOK = re.compile(r"[A-Za-z0-9_./:\\-]{4,}")
SKIP = {"cmd.exe", "powershell.exe", "powershell", "command", "windowstyle",
        "hidden", "noprofile", "executionpolicy", "bypass"}


def host(u):
    if not u: return ""
    if "://" not in u: u = "http://" + u
    return (urlparse(u).hostname or "").lower()


def norm(u):
    u = (u or "").strip().rstrip("/")
    if u.startswith("http://") and ":443" in u:
        u = "https://" + u[7:].replace(":443", "", 1)
    if u.startswith("http://") and ":80" in u:
        u = "http://" + u[7:].replace(":80", "", 1)
    return u.lower()


def walk_tree(node, depth, out):
    if isinstance(node, dict):
        cl = (node.get("command_line") or node.get("commandLine")
              or (node.get("environ", {}) or {}).get("CommandLine", "") or "")
        out.append((depth, cl))
        for c in (node.get("spawned_processes") or node.get("children") or []):
            walk_tree(c, depth + 1, out)
    elif isinstance(node, list):
        for c in node:
            walk_tree(c, depth, out)


def covered(cl, deob_lc):
    if SANDBOX_NOISE.search(cl):
        return True
    cl = HASHNAME.sub("", SANDBOX_TMP.sub("", cl))
    toks = [t.lower() for t in TOK.findall(cl)
            if t.lower() not in SKIP and not t.lower().startswith(("c:\\windows", "c:\\users"))]
    if len(toks) < 2:
        return True
    miss = [t for t in toks if t not in deob_lc]
    return len(miss) / max(1, len(toks)) < 0.3


def main():
    if not STATE.exists():
        sys.exit("no state.csv yet")
    rows = [r for r in csv.DictReader(STATE.open(newline=""))
            if r["status"] == "reported" and r["cape_package"] == "batch"]
    verdicts = Counter()
    cape_only, gaps = [], []
    out = []
    for r in rows:
        bd = set(json.loads(r["bd_urls"] or "[]"))
        bd_hosts = {host(u) for u in bd if host(u)}
        c_urls = {u for u in (r["cape_urls"] or "").split(",") if u}
        c_hosts = {h for h in (r["cape_hosts"] or "").split(",") if h}
        c_doms = {d for d in (r["cape_domains"] or "").split(",") if d}
        c_net = c_hosts | c_doms
        bn, cn = {norm(u) for u in bd}, {norm(u) for u in c_urls}
        if bn & cn:
            v = "AGREE_URL"
        elif bd_hosts & (c_hosts | c_doms):
            v = "AGREE_HOST"
        elif bd and not (c_urls or c_net):
            v = "BATDEOB_ONLY"
        elif not bd and not bd_hosts and (c_urls or c_net):
            v = "CAPE_ONLY"; cape_only.append(r["sha"])
        elif bd or c_urls or c_net:
            v = "PARTIAL"
        else:
            v = "NEITHER"
        verdicts[v] += 1
        # process-tree gap check
        cf = CMP / f"{r['sha']}.json"
        ngap = 0
        if cf.exists():
            doc = json.loads(cf.read_text())
            deob_lc = (doc.get("batdeob_deob", "") or "").lower()
            nodes = []
            walk_tree(doc.get("cape_process_tree", []), 0, nodes)
            if not any(cl for _, cl in nodes):  # tree had no cmdlines; use executed_commands at depth 2
                nodes = [(2, c) for c in doc.get("cape_executed_commands", [])]
            for d, cl in nodes:
                if cl and d <= 2 and not covered(cl, deob_lc) and not SANDBOX_NOISE.search(cl):
                    ngap += 1
            if ngap:
                gaps.append((r["sha"], r["fname"], ngap))
        out.append({
            "sha": r["sha"][:12], "fname": r["fname"][:40], "verdict": v,
            "bd_urls": " | ".join(sorted(bd))[:300],
            "cape_urls": " | ".join(sorted(c_urls))[:300],
            "cape_hosts": " ".join(sorted(c_hosts)),
            "tree_gaps": ngap,
        })
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["sha", "fname", "verdict", "bd_urls",
                           "cape_urls", "cape_hosts", "tree_gaps"], delimiter="\t")
        w.writeheader()
        for o in out: w.writerow(o)
    print(f"reported batch-mode samples: {len(rows)}")
    print("verdicts:")
    for k, n in verdicts.most_common():
        print(f"  {k:14s} {n}")
    print(f"\nCAPE_ONLY (candidate gaps): {len(cape_only)}")
    for s in cape_only[:25]:
        print(f"  {s[:16]}")
    print(f"\nprocess-tree gaps (depth<=2): {len(gaps)} samples")
    for sha, fn, n in sorted(gaps, key=lambda x: -x[2])[:25]:
        print(f"  {n:2d}  {sha[:12]}  {fn}")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    raise SystemExit(main())
