#!/usr/bin/env python3
"""Find samples where CAPE saw a depth-2 child process (a direct child of the
bat invocation) whose binary / URL / UNC path / dropped-file name does NOT
appear ANYWHERE in batdeob's deobfuscated output. Those are concrete misses:
the bat spawned a real process that our static analysis didn't surface.

Skips sandbox-runtime noise (harness launcher, browser/win internals, AV
probes, etc.) and depth≥3 (post-payload, out of static scope).

Groups gaps by binary so a single systemic fix can target many samples.
"""
from __future__ import annotations
import json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

CMP = Path("/home/coz/cstorage/batdeob_caperun/cmp")

SANDBOX = re.compile(
    r"(?i)"
    r"^\s*\"?c:\\windows\\system32\\cmd\.exe\"?\s+/(?:c\s+start\s+/wait|k)\s+\"c:\\users\\[^\\]+\\appdata\\local\\temp"
    r"|csc\.exe.*\.cmdline|cvtres\.exe|splwow64\.exe|wbem\\wmiprvse"
    r"|wmiadap\.exe|svchost\.exe\s+-k\s|werfault\.exe|conhost\.exe"
    r"|msedge\.exe|identity_helper\.exe|wordpad\.exe|winword\.exe"
    r"|chrome\.exe.*--type=(?:gpu-process|renderer|utility|crashpad-handler|broker|nacl-loader|ppapi)"
)
# Probe / AV-evasion / informational commands — not real network IOCs
PROBE = re.compile(
    r"(?i)^\s*(?:tasklist|chcp|timeout|ping|whoami|wmic|systeminfo|hostname|net\s+(?:user|view|group)|"
    r"findstr|find|find\.exe|attrib|reg\s+(?:add|query|delete)|sc\s+(?:query|stop|start)|"
    r"netsh|ipconfig|getmac|nltest|fltmc|driverquery|setlocal|set\b)"
)
# Match a binary basename (lowercased) — the first token's last \…
BIN_RE = re.compile(r'^\s*"?([^\s"]+)')
URL_RE = re.compile(r'https?://[^\s"\'<>\\]+', re.I)
UNC_RE = re.compile(r'\\\\[A-Za-z0-9._@:-]+(?:\\[^\s"\']+)+')
# .exe / .dll / .scr / .ps1 etc dropped/used outside sandbox-tmp
INTRESTING_FILE = re.compile(r'[A-Za-z]:\\[^\s"\']+\.(?:exe|dll|scr|ps1|vbs|js|hta|jar|lnk|bat|cmd)', re.I)
SANDBOX_PATH = re.compile(r'(?i)c:\\users\\[^\\]+\\appdata\\local\\temp\\[0-9a-f]+\.bat')
HASH_BASENAME = re.compile(r'\b[0-9a-f]{12,}(?:\.[a-z]{2,5})?\b')


def walk(node, depth, out):
    if isinstance(node, dict):
        cl = (node.get("command_line") or node.get("commandLine")
              or (node.get("environ", {}) or {}).get("CommandLine", "") or "")
        nm = (node.get("name") or node.get("process_name") or "").lower()
        out.append((depth, nm, cl))
        for c in (node.get("spawned_processes") or node.get("children") or []):
            walk(c, depth + 1, out)
    elif isinstance(node, list):
        for c in node:
            walk(c, depth, out)


def binary_of(cl: str) -> str:
    m = BIN_RE.match(cl)
    if not m:
        return ""
    p = m.group(1).strip('"')
    return p.rsplit("\\", 1)[-1].lower()


def main():
    if not CMP.exists():
        sys.exit("no cmp dir yet")
    total = 0
    samples_with_gap = 0
    # bucket gaps by binary and by signal type
    by_bin = Counter()
    by_signal = Counter()
    # detailed list per binary for inspection
    by_bin_examples: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for f in sorted(CMP.glob("*.json")):
        total += 1
        d = json.loads(f.read_text())
        deob = (d.get("batdeob_deob") or "").lower()
        bd_urls = {u.lower() for u in d.get("batdeob_urls", [])}
        nodes = []
        # Prefer process_tree (has depth); fall back to executed_commands as depth=2
        walk(d.get("cape_process_tree", []), 0, nodes)
        if not any(cl for _, _, cl in nodes):
            nodes = [(2, "", str(c)) for c in d.get("cape_executed_commands", [])]
        sample_gap = False
        for depth, nm, cl in nodes:
            if depth != 2 or not cl:
                continue
            if SANDBOX.search(cl) or PROBE.match(cl):
                continue
            if cl.lower().startswith(("c:\\windows\\system32\\wbem", "c:\\windows\\system32\\svchost")):
                continue
            b = binary_of(cl) or nm
            # ignore harness-only spawns (just opens the bat)
            if b in ("cmd.exe", "cmd") and any(x in cl.lower() for x in ("/k \"c:\\users", "/c start /wait")):
                continue
            # actionable bits to search for in deob
            urls = [u for u in URL_RE.findall(cl) if u.lower() not in bd_urls]
            uncs = UNC_RE.findall(cl)
            files = [x for x in INTRESTING_FILE.findall(cl) if not SANDBOX_PATH.fullmatch(x.lower())]
            # gap signals
            sigs = []
            for u in urls:
                if u.lower() not in deob:
                    sigs.append(("url-miss", u))
            for u in uncs:
                if u.lower() not in deob:
                    sigs.append(("unc-miss", u))
            for fp in files:
                fl = fp.lower()
                base = fp.rsplit("\\", 1)[-1].lower()
                if HASH_BASENAME.fullmatch(base):
                    continue  # sandbox-renamed file, can't know statically
                # The launcher-resolved system32 binary path (e.g.
                # `C:\Windows\system32\net.exe`) is just CAPE recording the
                # full path of the spawned binary — the bat almost always
                # invokes it by basename, so the system32 prefix never
                # appears in our deob. That's not a real gap; require the
                # *basename* to be missing too.
                if fl.startswith(("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                                  "c:\\windows\\winsxs\\")):
                    continue
                if base not in deob and fl not in deob:
                    sigs.append(("file-miss", fp))
            # If no specific signal but the binary itself never appears in
            # deob AND batdeob didn't extract any URL from this command's args,
            # call it a binary-miss. (Requiring both filters out cases where the
            # parser correctly extracted URLs from the obfuscated invocation
            # even when the deob text — which we truncate to 6 KB for the cmp
            # file — doesn't visibly show the binary keyword.)
            if not sigs and b and b not in ("cmd.exe", "cmd"):
                bare = b[:-4] if b.endswith(".exe") else b
                hits = (b in deob) or bool(re.search(rf'\b{re.escape(bare)}\b', deob))
                if not hits:
                    # Check whether ALL urls from this cmd are already in bd_urls.
                    cmd_urls = [u.lower().rstrip(',.;') for u in URL_RE.findall(cl)]
                    if cmd_urls:
                        norm_bd = set()
                        for u in bd_urls:
                            uu = u.lower().rstrip('/')
                            if uu.startswith("http://") and ":443" in uu:
                                uu = "https://" + uu[7:].replace(":443", "", 1)
                            norm_bd.add(uu)
                        all_extracted = True
                        for u in cmd_urls:
                            uu = u.rstrip('/')
                            if uu.startswith("http://") and ":443" in uu:
                                uu = "https://" + uu[7:].replace(":443", "", 1)
                            if uu not in norm_bd:
                                all_extracted = False
                                break
                        if all_extracted:
                            continue  # parser worked; presentation-only miss
                    sigs.append(("binary-miss", b))
            for kind, val in sigs:
                by_signal[kind] += 1
                by_bin[b] += 1
                if len(by_bin_examples[b]) < 4:
                    by_bin_examples[b].append((d.get("fname", "")[:38], kind, val[:120]))
                sample_gap = True
        if sample_gap:
            samples_with_gap += 1
    print(f"reported cmp files scanned: {total}")
    print(f"samples with depth-2 child-process gaps: {samples_with_gap}")
    print(f"\ngap signal types:")
    for k, n in by_signal.most_common():
        print(f"  {k:14s} {n}")
    print(f"\ngaps by spawned binary (TOP — common patterns = best ROI):")
    for b, n in by_bin.most_common(20):
        print(f"\n  {n:4d}× {b}")
        for fn, kind, val in by_bin_examples[b][:3]:
            print(f"        [{kind}] {val[:100]}   ({fn})")


if __name__ == "__main__":
    raise SystemExit(main())
