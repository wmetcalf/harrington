#!/usr/bin/env python3
"""
extract.py — pull harrington's synthetic Windows env data from a Windows
install.wim, without running Windows. Output matches the schema of
rust/tools/collect-windows-env.bat (which captures the same fields
live from a sandbox VM).

Reads:
  - install.wim                 (extracted from the install ISO)
  - SOFTWARE, SYSTEM hives      (extracted from a chosen image index)

Writes:
  - <out>/windows-env.json

Usage:
  extract.py --wim path/to/install.wim --image 6 --out data/win11.json

The script does no network access. It uses 7z to extract files from the
WIM and regipy to parse offline registry hives.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Optional

try:
    from regipy.registry import RegistryHive
    from regipy.exceptions import RegistryKeyNotFoundException
except ImportError:
    sys.stderr.write("regipy not installed; run: pip install regipy\n")
    sys.exit(2)

# Known LOLBAS / system binaries we want resolved paths for. Kept in
# sync with the corresponding list in collect-windows-env.bat.
LOLBAS_BINARIES = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe", "ftp.exe", "tftp.exe",
    "wmic.exe", "schtasks.exe", "at.exe", "sc.exe", "net.exe", "net1.exe",
    "reg.exe", "regedit.exe", "taskkill.exe", "tasklist.exe", "whoami.exe",
    "forfiles.exe", "findstr.exe", "find.exe", "more.exe", "sort.exe", "type.com",
    "msbuild.exe", "regsvcs.exe", "regasm.exe", "installutil.exe", "ieexec.exe",
    "msxsl.exe", "odbcconf.exe", "sqldumper.exe", "pcalua.exe", "appvlp.exe",
    "runscripthelper.exe", "infdefaultinstall.exe", "diskshadow.exe", "msdt.exe",
    "hh.exe", "scriptrunner.exe", "syncappvpublishingserver.exe", "bash.exe",
    "msiexec.exe", "explorer.exe", "taskhost.exe", "svchost.exe", "conhost.exe",
]


def wim_xml_metadata(wim_path: Path) -> str:
    """Read the XML metadata block at the tail of a WIM."""
    with open(wim_path, "rb") as f:
        hdr = f.read(208)
        if hdr[:8] != b"MSWIM\0\0\0":
            raise SystemExit(f"{wim_path} is not a WIM file")
        size_flags = struct.unpack_from("<Q", hdr, 0x48)[0]
        offset = struct.unpack_from("<Q", hdr, 0x50)[0]
        size = size_flags & 0x00FFFFFFFFFFFFFF
        f.seek(offset)
        return f.read(size).decode("utf-16-le").lstrip("﻿")


def list_images(wim_path: Path) -> list[dict]:
    xml = wim_xml_metadata(wim_path)
    images: list[dict] = []
    # Split on IMAGE blocks first so non-greedy regexes can't bleed across them
    for block in re.findall(r'<IMAGE\s+INDEX="\d+".*?</IMAGE>', xml, re.DOTALL):
        idx = int(re.search(r'INDEX="(\d+)"', block).group(1))
        def first(pat):
            m = re.search(pat, block)
            return m.group(1) if m else ""
        images.append({
            "index": idx,
            "editionid": first(r"<EDITIONID>([^<]+)</EDITIONID>"),
            "name":      first(r"<NAME>([^<]+)</NAME>"),
            "build":     first(r"<BUILD>(\d+)</BUILD>"),
        })
    return images


def wim_build_for_image(wim_path: Path, index: int) -> Optional[str]:
    for img in list_images(wim_path):
        if img["index"] == index:
            return img["build"] or None
    return None


def extract_from_wim(wim_path: Path, archive_path: str, dest_dir: Path) -> Path:
    """Use 7z to extract a single path from a WIM. Returns dest_dir/<basename>."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["7z", "e", "-y", f"-o{dest_dir}", str(wim_path), archive_path],
        check=True,
        capture_output=True,
    )
    return dest_dir / Path(archive_path).name


def wim_file_listing(wim_path: Path, image: int) -> set[str]:
    """Lowercased set of all file paths in the given image."""
    out = subprocess.run(
        ["7z", "l", "-ba", str(wim_path)],
        check=True, capture_output=True, text=True,
    ).stdout
    prefix = f"{image}/"
    listing: set[str] = set()
    for line in out.splitlines():
        # 7z -ba lines: "<date> <time> <attr>  <size>  <compressed>  <name>"
        # We just want the trailing name. Lines may have spaces in names so we
        # split on the first whitespace block after attributes.
        m = re.match(r"\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.*)$", line)
        if not m:
            continue
        name = m.group(1).strip()
        if name.startswith(prefix):
            listing.add(name[len(prefix):].lower().replace("\\", "/"))
    return listing


def value_dict(key) -> dict:
    return {v.name: v.value for v in key.iter_values()}


def find_sub(key, name: str):
    """Case-insensitive subkey lookup. regipy's get_key() is case-sensitive,
    but real registry paths are not — work around that."""
    nl = name.lower()
    for s in key.iter_subkeys():
        if s.name.lower() == nl:
            return s
    return None


def chase(root, path: str):
    """Walk a backslash-separated path with case-insensitive matching."""
    cur = root
    for seg in path.split("\\"):
        if not seg:
            continue
        cur = find_sub(cur, seg)
        if cur is None:
            return None
    return cur


def safe_get_key(hive, path: str):
    """Case-insensitive get_key replacement."""
    return chase(hive.root, path)


# Win32 environment-block style expansion: %FOO% → env["FOO"]
ENV_REF = re.compile(r"%([^%]+)%")


def expand(value: str, env: dict[str, str], depth: int = 0) -> str:
    if depth > 8 or not isinstance(value, str):
        return value
    def repl(m):
        k = m.group(1).lower()
        for ek, ev in env.items():
            if ek.lower() == k:
                return expand(ev, env, depth + 1)
        return m.group(0)
    return ENV_REF.sub(repl, value)


def parse_assoc_ftype(software_hive: Path) -> tuple[dict, dict]:
    """Return (assoc, ftype) ordered dicts."""
    r = RegistryHive(str(software_hive))
    classes = chase(r.root, "Classes")
    if classes is None:
        return OrderedDict(), OrderedDict()

    assoc: dict[str, str] = OrderedDict()
    ftype: dict[str, str] = OrderedDict()
    # Snapshot subkeys once — iter_subkeys may not be safe to interleave with
    # further key chases on some regipy versions.
    progid_keys: list = []
    for sk in classes.iter_subkeys():
        if sk.name.startswith("."):
            vals = value_dict(sk)
            progid = vals.get("(default)") or vals.get("")
            if progid:
                assoc[sk.name.lower()] = progid
        else:
            progid_keys.append(sk)

    # For every ProgID subkey, walk shell\open\command\(default) directly
    for pk in progid_keys:
        shell = find_sub(pk, "shell")
        if shell is None:
            continue
        opn = find_sub(shell, "open")
        if opn is None:
            continue
        cmd_key = find_sub(opn, "command")
        if cmd_key is None:
            continue
        vals = value_dict(cmd_key)
        cmd = vals.get("(default)") or vals.get("")
        if cmd:
            # Strip the offline-mount drive letter (X:\Windows...) - the WIM
            # is mounted under a synthetic drive when these values were baked.
            cmd = re.sub(r"\b[A-Za-z]:\\Windows\\", r"C:\\Windows\\", cmd)
            ftype[pk.name] = cmd
    return assoc, ftype


def parse_system_env(system_hive: Path) -> tuple[dict, dict]:
    """Return (identity, env) — identity is a small subset, env is the full Session Manager Environment."""
    r = RegistryHive(str(system_hive))
    # The 'current' control set is selected by Select\Current (DWORD)
    # but in an unbooted WIM image, Select isn't always populated. Default to ControlSet001.
    cs = "ControlSet001"
    sel = safe_get_key(r, r"Select")
    if sel is not None:
        for v in sel.iter_values():
            if v.name == "Current":
                cs = f"ControlSet{v.value:03d}"
                break
    env_key = safe_get_key(r, fr"{cs}\Control\Session Manager\Environment")
    env: dict[str, str] = OrderedDict()
    if env_key is not None:
        for v in env_key.iter_values():
            if v.name and v.value is not None:
                env[v.name] = v.value if isinstance(v.value, str) else str(v.value)

    # ComputerName
    comp = safe_get_key(r, fr"{cs}\Control\ComputerName\ComputerName")
    if comp is not None:
        for v in comp.iter_values():
            if v.name == "ComputerName":
                env.setdefault("COMPUTERNAME", v.value)

    # ProductOptions: gives ProductType (WinNT for client, ServerNT for server)
    po = safe_get_key(r, fr"{cs}\Control\ProductOptions")
    if po is not None:
        for v in po.iter_values():
            if v.name == "ProductType":
                env.setdefault("PRODUCT_TYPE", v.value)

    # Resolve %SystemRoot% / %SystemDrive% etc. against itself
    env.setdefault("SystemDrive", "C:")
    env.setdefault("SystemRoot", env.get("SystemRoot", r"C:\Windows"))
    resolved: dict[str, str] = OrderedDict()
    for k, v in env.items():
        resolved[k] = expand(v, env) if isinstance(v, str) else v

    identity = OrderedDict()
    for k in ("SystemRoot", "SystemDrive", "ComSpec", "ProgramFiles",
              "ProgramFiles(x86)", "CommonProgramFiles", "windir",
              "PATHEXT", "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS"):
        if k in resolved:
            identity[k] = resolved[k]
    identity.setdefault("OS", "Windows_NT")
    identity.setdefault("PROCESSOR_ARCHITECTURE", "AMD64")
    identity.setdefault("NUMBER_OF_PROCESSORS", "4")
    identity.setdefault("ComSpec", r"%SystemRoot%\system32\cmd.exe")
    identity["ComSpec"] = expand(identity["ComSpec"], resolved)

    return identity, resolved


def resolve_where(listing: set[str], identity: dict, env: dict) -> dict[str, str]:
    """Compute a synthetic 'where' map for LOLBAS_BINARIES from the WIM listing.

    Strategy: real cmd's `where` searches directories in PATH; we approximate
    by finding any path ending in /<binary> anywhere under Windows/. We
    prefer matches under System32, then SysWOW64, then PATH dirs, then
    anywhere else, then shortest path as a tiebreaker."""
    sys_root = identity.get("SystemRoot", r"C:\Windows")

    def to_wim_rel(win_path: str) -> str:
        p = win_path.replace("\\", "/").lower()
        if len(p) >= 2 and p[1] == ":":
            p = p[2:]
        return p.lstrip("/")

    # Priority prefixes (lower index = higher priority)
    prio_prefixes = [
        to_wim_rel(f"{sys_root}\\System32"),
        to_wim_rel(f"{sys_root}\\SysWOW64"),
    ]
    path = env.get("Path") or env.get("PATH") or ""
    for p in path.split(";"):
        p = p.strip()
        if p:
            prio_prefixes.append(to_wim_rel(p))
    prio_prefixes.append("")  # last-resort: anywhere

    def priority(rel: str) -> int:
        for i, pref in enumerate(prio_prefixes):
            if rel.startswith(pref):
                return i
        return len(prio_prefixes)

    # Pre-index listing by basename for O(1) lookup
    by_basename: dict[str, list[str]] = {}
    for rel in listing:
        base = rel.rsplit("/", 1)[-1]
        by_basename.setdefault(base, []).append(rel)

    out: dict[str, str] = OrderedDict()
    for binary in LOLBAS_BINARIES:
        candidates = by_basename.get(binary.lower(), [])
        if not candidates:
            out[binary] = ""
            continue
        # Sort by (priority, path-length, path) for deterministic best pick
        best = sorted(candidates, key=lambda r: (priority(r), len(r), r))[0]
        # Render as Windows path on systemdrive
        drive = identity.get("SystemDrive", "C:")
        out[binary] = f"{drive}\\" + best.replace("/", "\\")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--wim", type=Path, required=True, help="path to install.wim")
    ap.add_argument("--image", type=int, default=6,
                    help="WIM image index (default 6 = Win11 Pro)")
    ap.add_argument("--out", type=Path, required=True, help="output JSON file path")
    ap.add_argument("--list-images", action="store_true",
                    help="just list image indices and exit")
    args = ap.parse_args()

    if args.list_images:
        for img in list_images(args.wim):
            print(f"  image {img['index']:>2}: {img['editionid']:<28} "
                  f"{img['name']:<40} build={img['build']}")
        return 0

    with tempfile.TemporaryDirectory(prefix="harrington-wim-") as td:
        td_path = Path(td)
        print(f"[+] Extracting hives from image {args.image}...", file=sys.stderr)
        sw = extract_from_wim(args.wim,
                              f"{args.image}/Windows/System32/config/SOFTWARE",
                              td_path)
        sy = extract_from_wim(args.wim,
                              f"{args.image}/Windows/System32/config/SYSTEM",
                              td_path)
        print(f"    SOFTWARE: {sw.stat().st_size:>10} bytes", file=sys.stderr)
        print(f"    SYSTEM:   {sy.stat().st_size:>10} bytes", file=sys.stderr)

        print("[+] Parsing assoc + ftype from SOFTWARE...", file=sys.stderr)
        assoc, ftype = parse_assoc_ftype(sw)
        print(f"    assoc entries: {len(assoc)}", file=sys.stderr)
        print(f"    ftype entries: {len(ftype)}", file=sys.stderr)

        print("[+] Parsing identity + env from SYSTEM...", file=sys.stderr)
        identity, env = parse_system_env(sy)
        print(f"    env vars:      {len(env)}", file=sys.stderr)

        print("[+] Listing WIM contents for 'where' resolution...", file=sys.stderr)
        listing = wim_file_listing(args.wim, args.image)
        where = resolve_where(listing, identity, env)
        resolved_count = sum(1 for v in where.values() if v)
        print(f"    where resolved: {resolved_count}/{len(where)}", file=sys.stderr)

        build = wim_build_for_image(args.wim, args.image)
        out = OrderedDict([
            ("schema", "harrington-windows-env/v1"),
            ("source", "extract-from-wim"),
            ("source_image_index", args.image),
            ("source_build", build),
            ("ver", f"Microsoft Windows [Version 10.0.{build or '?'}]"),
            ("identity", identity),
            ("assoc", assoc),
            ("ftype", ftype),
            ("env", env),
            ("where", where),
        ])

        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"[+] Wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
