#!/usr/bin/env python3
"""Audit batdeob output against a dumped corpus report directory.

Input is the JSON report dump directory containing summary.csv and
<sha256>.json files with source/deobfuscated/traits. Output is a CSV ledger
that can be re-run after each decoder improvement.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path


URL_FIELDS = ("src", "url", "http_url")
DEFAULT_BIN = Path(__file__).resolve().parents[1] / "target" / "debug" / "batdeob"


def normalize_url(url: str) -> str:
    return url.rstrip("\\")


def trait_urls(traits: list[object]) -> set[str]:
    urls: set[str] = set()
    for trait in traits:
        if not isinstance(trait, dict):
            continue
        if trait.get("kind") == "RemoteConnect":
            host = trait.get("host")
            port = trait.get("port")
            if isinstance(host, str) and isinstance(port, int):
                urls.add(f"http://{host}:{port}")
        for field in URL_FIELDS:
            value = trait.get(field)
            if isinstance(value, str) and value.startswith(("http://", "https://", "ftp://")):
                urls.add(normalize_url(value))
    return urls


def trait_kinds(traits: list[object]) -> set[str]:
    return {
        str(trait.get("kind"))
        for trait in traits
        if isinstance(trait, dict) and trait.get("kind")
    }


def unresolved_var_count(text: str) -> int:
    return len(re.findall(r"[%!][A-Za-z0-9_]{3,}[%!]", text))


def ps_signal_count(text: str) -> int:
    lower = text.lower()
    signals = (
        "powershell",
        "frombase64string",
        "downloadstring",
        "downloaddata",
        "invoke-webrequest",
        "new-object net.webclient",
        "start-process",
    )
    return sum(signal in lower for signal in signals)


def run_current(bin_path: Path, source: str, timeout: int) -> tuple[str, dict[str, object] | None]:
    try:
        proc = subprocess.run(
            [str(bin_path), "report", "-", "--include-deob"],
            input=source.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout", None
    if proc.returncode != 0:
        return "error", {"stderr": proc.stderr.decode(errors="replace")[:300]}
    try:
        return "ok", json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return "bad-json", {"stderr": str(exc)}


def classify(
    old_urls: set[str],
    new_urls: set[str],
    old_deob: str,
    new_deob: str,
    status: str,
) -> str:
    if status != "ok":
        return status
    gained, lost = diff_urls(old_urls, new_urls)
    unresolved = unresolved_var_count(new_deob)
    ps_signals = ps_signal_count(new_deob)
    if gained:
        return "url-gain"
    if lost:
        return "url-loss"
    if unresolved >= 100:
        return "high-unresolved"
    if len(new_deob) > max(4096, int(len(old_deob) * 1.5)) and ps_signals:
        return "expanded-ps-review"
    if ps_signals and not new_urls:
        return "ps-no-url-review"
    return "ok"


def diff_urls(old_urls: set[str], new_urls: set[str]) -> tuple[set[str], set[str]]:
    gained = set(new_urls - old_urls)
    lost = set(old_urls - new_urls)
    for old in list(lost):
        for new in new_urls:
            if (
                new.startswith(old + "&")
                or new.startswith(old + "?")
                or new.startswith(old + "/")
                or old.startswith(new + "&")
            ):
                lost.discard(old)
                gained.discard(new)
                break
    return gained, lost


def iter_rows(summary_path: Path, start: int, limit: int | None) -> list[tuple[int, dict[str, str]]]:
    with summary_path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    selected = [(idx, row) for idx, row in enumerate(rows, start=1) if idx >= start]
    if limit is not None:
        selected = selected[:limit]
    return selected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dump_dir", type=Path)
    parser.add_argument("--bin", type=Path, default=DEFAULT_BIN)
    parser.add_argument("--out", type=Path, default=Path("corpus_audit.csv"))
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-input-bytes", type=int, default=2_000_000)
    args = parser.parse_args()

    summary_path = args.dump_dir / "summary.csv"
    if not summary_path.exists():
        raise SystemExit(f"missing {summary_path}")

    fields = [
        "idx",
        "sha256",
        "filename",
        "input_size",
        "old_url_count",
        "new_url_count",
        "gained_urls",
        "lost_urls",
        "old_trait_kinds",
        "new_trait_kinds",
        "old_deob_size",
        "new_deob_size",
        "unresolved_vars",
        "ps_signals",
        "status",
        "bucket",
    ]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as out_fh:
        writer = csv.DictWriter(out_fh, fieldnames=fields)
        writer.writeheader()
        for idx, row in iter_rows(summary_path, args.start, args.limit):
            input_size = int(row["input_size"])
            report_path = args.dump_dir / f"{row['sha256']}.json"
            old_report = json.loads(report_path.read_text(errors="ignore"))
            old_traits = old_report.get("traits", [])
            old_urls = trait_urls(old_traits)
            old_deob = old_report.get("deobfuscated", "")

            if input_size > args.max_input_bytes:
                status = "skipped-large"
                current = None
            else:
                status, current = run_current(args.bin, old_report.get("source", ""), args.timeout)

            if status == "ok" and current is not None:
                new_traits = current.get("traits", [])
                new_deob = str(current.get("deobfuscated", ""))
                new_urls = trait_urls(new_traits if isinstance(new_traits, list) else [])
                new_kinds = trait_kinds(new_traits if isinstance(new_traits, list) else [])
            else:
                new_deob = ""
                new_urls = set()
                new_kinds = set()

            gained_urls, lost_urls = diff_urls(old_urls, new_urls)
            bucket = classify(old_urls, new_urls, old_deob, new_deob, status)
            writer.writerow(
                {
                    "idx": idx,
                    "sha256": row["sha256"],
                    "filename": row["filename"],
                    "input_size": input_size,
                    "old_url_count": len(old_urls),
                    "new_url_count": len(new_urls),
                    "gained_urls": " ".join(sorted(gained_urls)),
                    "lost_urls": " ".join(sorted(lost_urls)),
                    "old_trait_kinds": ";".join(sorted(trait_kinds(old_traits))),
                    "new_trait_kinds": ";".join(sorted(new_kinds)),
                    "old_deob_size": len(old_deob),
                    "new_deob_size": len(new_deob),
                    "unresolved_vars": unresolved_var_count(new_deob),
                    "ps_signals": ps_signal_count(new_deob),
                    "status": status,
                    "bucket": bucket,
                }
            )
            print(f"{idx}: {bucket} {row['filename']}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
