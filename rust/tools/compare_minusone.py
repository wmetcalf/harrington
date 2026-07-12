#!/usr/bin/env python3
"""Compare Harrington PowerShell output with MinusOne.

This is an optional differential-analysis helper. It does not add MinusOne as
runtime dependency of Harrington; instead it runs an external MinusOne CLI when
provided and reports cases where MinusOne exposes URLs or simpler PS text that
Harrington did not.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_TIMEOUT = 20
URL_RE = re.compile(
    r"(?i)\b((?:https?|ftp|file):[/\\]+[^\s\"'`;,<>(){}\[\]|^&]+)"
)
COMMAND_SIGNAL_RE = re.compile(
    r"(?i)\b(?:powershell|pwsh|cmd(?:\.exe)?|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|frombase64string|iex)\b"
)


def normalize_url(url: str) -> str:
    url = url.strip().rstrip(".,;:)]}'\"!?\\")
    match = re.match(r"(?i)^(https?|ftp|file):([/\\]+)(.*)$", url)
    if not match:
        return url
    scheme = match.group(1).lower()
    rest = match.group(3).replace("\\", "/")
    return f"{scheme}://{rest}"


def is_useful_url(url: str) -> bool:
    empty_match = re.match(r"(?i)^(https?|ftp|file)://$", url)
    if empty_match:
        return False
    match = re.match(r"(?i)^(https?|ftp|file)://(.+)$", url)
    if not match:
        return True
    if match.group(1).lower() == "file":
        return bool(match.group(2).strip("/\\"))
    host = match.group(2).split("/", 1)[0]
    if not host:
        return False
    return host.lower() == "localhost" or "." in host or ":" in host


def url_is_covered_by(url: str, other: str) -> bool:
    url_key = url.lower()
    other_key = other.lower()
    if url_key == other_key:
        return True
    return other_key.startswith(url_key) or url_key.startswith(other_key)


def subtract_covered_urls(urls: set[str], covered_by: set[str]) -> list[str]:
    return sorted(
        url
        for url in urls
        if not any(url_is_covered_by(url, other) for other in covered_by)
    )


def scan_urls(text: str) -> set[str]:
    urls: set[str] = set()
    for match in URL_RE.finditer(text):
        url = normalize_url(match.group(1))
        if is_useful_url(url):
            urls.add(url)
    return urls


def extract_observed_urls(value: Any) -> set[str]:
    urls: set[str] = set()
    if isinstance(value, str):
        urls.update(scan_urls(value))
    elif isinstance(value, dict):
        for child in value.values():
            urls.update(extract_observed_urls(child))
    elif isinstance(value, list):
        for child in value:
            urls.update(extract_observed_urls(child))
    return urls


def extract_observed_commands(value: Any) -> set[str]:
    commands: set[str] = set()
    if isinstance(value, str):
        command = value.strip()
        if is_interesting_observed_command(command):
            commands.add(command[:2000])
    elif isinstance(value, dict):
        for child in value.values():
            commands.update(extract_observed_commands(child))
    elif isinstance(value, list):
        for child in value:
            commands.update(extract_observed_commands(child))
    return commands


def is_interesting_observed_command(text: str) -> bool:
    if len(text) < 8:
        return False
    if not COMMAND_SIGNAL_RE.search(text):
        return False
    lower = text.lower()
    benign_processes = (
        "notepad.exe",
        "explorer.exe",
        "werfault.exe",
        "conhost.exe",
    )
    return not any(proc in lower for proc in benign_processes)


def looks_like_powershell(text: str) -> bool:
    lower = text.lower()
    signals = (
        "powershell",
        "frombase64string",
        "invoke-webrequest",
        "invoke-restmethod",
        "downloadstring",
        "downloadfile",
        "downloaddata",
        "new-object net.webclient",
        "start-bitstransfer",
        "[char]",
        "-join",
        "-replace",
        "iex",
        "iwr ",
        "irm ",
    )
    return any(signal in lower for signal in signals)


def unique_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = value.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def extract_banner_payloads(deobfuscated: str) -> list[str]:
    payloads: list[str] = []
    marker_re = re.compile(
        r"(?is)::==== batdeob: extracted PowerShell payload ====\s*(.*?)\s*::==== end extracted PowerShell payload ===="
    )
    for match in marker_re.finditer(deobfuscated):
        payloads.append(match.group(1))
    return payloads


def extract_ps_candidates(report: dict[str, Any]) -> list[str]:
    candidates: list[str] = []

    deobfuscated = report.get("deobfuscated")
    if isinstance(deobfuscated, str):
        banner_payloads = extract_banner_payloads(deobfuscated)
        candidates.extend(banner_payloads)
        if not banner_payloads and looks_like_powershell(deobfuscated):
            candidates.append(deobfuscated)

    extracted = report.get("extracted")
    if isinstance(extracted, dict):
        samples = extracted.get("powershell_samples")
        if isinstance(samples, list):
            candidates.extend(sample for sample in samples if isinstance(sample, str))

    traits = report.get("traits")
    if isinstance(traits, list):
        for trait in traits:
            if not isinstance(trait, dict):
                continue
            for key in ("script", "cmd", "command", "line_hint"):
                value = trait.get(key)
                if isinstance(value, str) and looks_like_powershell(value):
                    candidates.append(value)

    return unique_preserve_order(candidates)


def compact_text_for_compare(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def compare_texts(
    sample_id: str,
    source_name: str,
    harrington_text: str,
    minusone_text: str,
    harrington_compare_text: str | None = None,
    observed_urls: set[str] | None = None,
    observed_commands: set[str] | None = None,
) -> dict[str, Any]:
    harrington_urls = scan_urls(harrington_compare_text or harrington_text)
    minusone_urls = scan_urls(minusone_text)
    observed_urls = observed_urls or set()
    observed_commands = observed_commands or set()
    minusone_only = subtract_covered_urls(minusone_urls, harrington_urls)
    harrington_only = subtract_covered_urls(harrington_urls, minusone_urls)
    observed_only = subtract_covered_urls(observed_urls, harrington_urls | minusone_urls)

    h_compact = compact_text_for_compare(harrington_text)
    m_compact = compact_text_for_compare(minusone_text)
    readable_gain = (
        bool(m_compact)
        and len(m_compact) + 80 < len(h_compact)
        and ("download" in m_compact.lower() or "invoke-" in m_compact.lower())
    )
    combined_norm = normalize_observed_command(
        f"{harrington_compare_text or harrington_text}\n{minusone_text}"
    )
    observed_command_only = sorted(
        command
        for command in observed_commands
        if normalize_observed_command(command) not in combined_norm
    )

    if observed_only:
        bucket = "observed-url-gap"
    elif observed_command_only:
        bucket = "observed-command-gap"
    elif minusone_only:
        bucket = "minusone-url-gain"
    elif readable_gain:
        bucket = "minusone-readable"
    elif harrington_only:
        bucket = "harrington-url-only"
    else:
        bucket = "same"

    return {
        "sample_id": sample_id,
        "source_name": source_name,
        "harrington_url_count": len(harrington_urls),
        "minusone_url_count": len(minusone_urls),
        "minusone_only_urls": minusone_only,
        "harrington_only_urls": harrington_only,
        "observed_only_urls": observed_only,
        "observed_only_commands": observed_command_only,
        "observed_url_count": len(observed_urls),
        "observed_command_count": len(observed_commands),
        "harrington_size": len(harrington_text),
        "minusone_size": len(minusone_text),
        "bucket": bucket,
    }


def normalize_observed_command(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def minusone_binary(path_arg: str | None) -> str:
    candidate = path_arg or os.environ.get("MINUSONE_BIN") or "minusone"
    resolved = shutil.which(candidate)
    if resolved:
        return resolved
    if Path(candidate).exists():
        return candidate
    raise SystemExit(
        "MinusOne binary not found; set MINUSONE_BIN or pass --minusone-bin"
    )


def minusone_command(bin_path: str, script_path: str) -> list[str]:
    return [bin_path, "--lang", "powershell", "--path", script_path]


def run_minusone(bin_path: str, ps_text: str, timeout: int) -> tuple[str, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", encoding="utf-8") as fh:
        fh.write(ps_text)
        fh.flush()
        proc = subprocess.run(
            minusone_command(bin_path, fh.name),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    if proc.returncode != 0:
        return "", proc.stderr.strip()[:1000]
    return proc.stdout, ""


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} is not a JSON object")
    return data


def read_observed_signal_map(paths: list[Path]) -> dict[str, dict[str, set[str]]]:
    observed: dict[str, dict[str, set[str]]] = {}
    for path in paths:
        if path.is_dir():
            for child in sorted(path.glob("*.json")):
                observed[child.stem] = extract_observed_signals(read_json(child))
            for child in sorted(path.glob("*.jsonl")):
                observed[child.stem] = extract_observed_signals(read_jsonl_values(child))
            continue
        key = path.stem
        if path.suffix.lower() == ".json":
            observed[key] = extract_observed_signals(read_json(path))
        elif path.suffix.lower() == ".jsonl":
            observed[key] = extract_observed_signals(read_jsonl_values(path))
        else:
            text = path.read_text(errors="replace")
            observed[key] = {
                "urls": scan_urls(text),
                "commands": extract_observed_commands(text),
            }
    return observed


def extract_observed_signals(value: Any) -> dict[str, set[str]]:
    return {
        "urls": extract_observed_urls(value),
        "commands": extract_observed_commands(value),
    }


def read_jsonl_values(path: Path) -> list[Any]:
    values: list[Any] = []
    with path.open(errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                values.append(line)
    return values


def observed_urls_for(
    observed: dict[str, dict[str, set[str]]],
    sample_id: str,
    source_name: str,
    report_path: Path,
) -> set[str]:
    return observed_signals_for(observed, sample_id, source_name, report_path, "urls")


def observed_commands_for(
    observed: dict[str, dict[str, set[str]]],
    sample_id: str,
    source_name: str,
    report_path: Path,
) -> set[str]:
    return observed_signals_for(observed, sample_id, source_name, report_path, "commands")


def observed_signals_for(
    observed: dict[str, dict[str, set[str]]],
    sample_id: str,
    source_name: str,
    report_path: Path,
    signal: str,
) -> set[str]:
    keys = {
        sample_id,
        source_name,
        Path(source_name).name,
        Path(source_name).stem,
        report_path.stem,
    }
    values: set[str] = set()
    for key in keys:
        values.update(observed.get(key, {}).get(signal, set()))
    return values


def iter_report_paths(inputs: list[Path], start: int, limit: int | None) -> list[Path]:
    paths: list[Path] = []
    for input_path in inputs:
        if input_path.is_dir() and (input_path / "summary.csv").exists():
            with (input_path / "summary.csv").open(newline="") as fh:
                rows = list(csv.DictReader(fh))
            for idx, row in enumerate(rows, start=1):
                if idx < start:
                    continue
                sha = row.get("sha256")
                if sha:
                    paths.append(input_path / f"{sha}.json")
        elif input_path.is_dir():
            paths.extend(sorted(input_path.glob("*.json")))
        else:
            paths.append(input_path)
    if limit is not None:
        paths = paths[:limit]
    return paths


def compare_report(
    report_path: Path,
    bin_path: str,
    timeout: int,
    observed: dict[str, dict[str, set[str]]] | None = None,
) -> list[dict[str, Any]]:
    report = read_json(report_path)
    sample_id = str(report.get("input_sha256") or report_path.stem)
    source_name = str(report.get("input") or report.get("filename") or report_path.name)
    observed_urls = observed_urls_for(observed or {}, sample_id, source_name, report_path)
    observed_commands = observed_commands_for(observed or {}, sample_id, source_name, report_path)
    rows: list[dict[str, Any]] = []
    candidates = extract_ps_candidates(report)
    all_candidates_text = "\n".join(candidates)
    for idx, candidate in enumerate(candidates, start=1):
        minusone_text, error = run_minusone(bin_path, candidate, timeout)
        if error:
            rows.append(
                {
                    "sample_id": sample_id,
                    "source_name": source_name,
                    "candidate": idx,
                    "bucket": "minusone-error",
                    "error": error,
                    "minusone_only_urls": [],
                    "harrington_only_urls": sorted(scan_urls(candidate)),
                    "observed_only_urls": sorted(observed_urls - scan_urls(candidate)),
                    "observed_only_commands": sorted(
                        command
                        for command in observed_commands
                        if normalize_observed_command(command)
                        not in normalize_observed_command(candidate)
                    ),
                    "observed_url_count": len(observed_urls),
                    "observed_command_count": len(observed_commands),
                    "harrington_url_count": len(scan_urls(candidate)),
                    "minusone_url_count": 0,
                    "harrington_size": len(candidate),
                    "minusone_size": 0,
                }
            )
            continue
        row = compare_texts(
            sample_id,
            source_name,
            candidate,
            minusone_text,
            all_candidates_text,
            observed_urls,
            observed_commands,
        )
        row["candidate"] = idx
        row["error"] = ""
        rows.append(row)
    if not rows:
        rows.append(
            {
                "sample_id": sample_id,
                "source_name": source_name,
                "candidate": 0,
                "bucket": "no-ps-candidates",
                "error": "",
                "minusone_only_urls": [],
                "harrington_only_urls": [],
                "observed_only_urls": sorted(observed_urls),
                "observed_only_commands": sorted(observed_commands),
                "observed_url_count": len(observed_urls),
                "observed_command_count": len(observed_commands),
                "harrington_url_count": 0,
                "minusone_url_count": 0,
                "harrington_size": 0,
                "minusone_size": 0,
            }
        )
    return rows


def write_jsonl(rows: list[dict[str, Any]], out: Path | None) -> None:
    fh = out.open("w") if out else sys.stdout
    try:
        for row in rows:
            print(json.dumps(row, sort_keys=True), file=fh)
    finally:
        if out:
            fh.close()


def write_csv(rows: list[dict[str, Any]], out: Path | None) -> None:
    fields = [
        "sample_id",
        "source_name",
        "candidate",
        "bucket",
        "harrington_url_count",
        "minusone_url_count",
        "observed_url_count",
        "observed_command_count",
        "minusone_only_urls",
        "harrington_only_urls",
        "observed_only_urls",
        "observed_only_commands",
        "harrington_size",
        "minusone_size",
        "error",
    ]
    fh = out.open("w", newline="") if out else sys.stdout
    try:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            csv_row = dict(row)
            csv_row["minusone_only_urls"] = " ".join(row.get("minusone_only_urls", []))
            csv_row["harrington_only_urls"] = " ".join(row.get("harrington_only_urls", []))
            csv_row["observed_only_urls"] = " ".join(row.get("observed_only_urls", []))
            csv_row["observed_only_commands"] = " || ".join(
                row.get("observed_only_commands", [])
            )
            writer.writerow(csv_row)
    finally:
        if out:
            fh.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="report JSON files or corpus dump dirs")
    parser.add_argument("--minusone-bin", help="MinusOne CLI path; defaults to MINUSONE_BIN or minusone")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--observed",
        action="append",
        type=Path,
        default=[],
        help="Curtain/AMSI/sandbox JSON, JSONL, text file, or directory keyed by sample id/filename",
    )
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    parser.add_argument(
        "--interesting-only",
        action="store_true",
        help="omit rows where MinusOne and Harrington expose the same URLs",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    bin_path = minusone_binary(args.minusone_bin)
    observed = read_observed_signal_map(args.observed)
    rows: list[dict[str, Any]] = []
    for report_path in iter_report_paths(args.inputs, args.start, args.limit):
        if not report_path.exists():
            print(f"missing report: {report_path}", file=sys.stderr)
            continue
        rows.extend(compare_report(report_path, bin_path, args.timeout, observed))
        print(f"compared {report_path}", file=sys.stderr)
    if args.interesting_only:
        rows = [row for row in rows if row.get("bucket") != "same"]
    if args.format == "csv":
        write_csv(rows, args.out)
    else:
        write_jsonl(rows, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
