#!/usr/bin/env python3
"""Run batdeob over a raw .bat/.cmd corpus and keep artifact paths reviewable."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_BIN = Path(__file__).resolve().parents[1] / "target" / "debug" / "batdeob"
SCRIPT_EXTS = {".bat", ".cmd"}
CAP_TRAITS = {
    "ChildScriptsCapped",
    "DepthCapped",
    "IterationCapped",
    "LineTruncated",
    "OutputCapped",
    "ReExpansionDepthCapped",
    "TimeoutHit",
    "TraitsCapped",
}
SUMMARY_FIELDS = (
    "idx",
    "filename",
    "input_size",
    "elapsed_seconds",
    "status",
    "report_path",
    "artifact_dir",
    "caps",
    "recovered_total",
    "recovered_pe",
    "recovered_bin",
    "recovered_py",
    "recovered_shellcode",
)
FAILURE_FIELDS = ("idx", "filename", "input_size", "elapsed_seconds", "error_path")


def default_run_dir() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(f"/tmp/harrington-corpus-run-{stamp}")


def sample_id(idx: int, path: Path) -> str:
    return f"{idx:05d}-{path.name}"


def iter_samples(corpus_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in corpus_dir.iterdir()
        if path.is_file() and path.suffix.lower() in SCRIPT_EXTS
    )


def build_command(bin_path: Path, sample: Path, artifact_dir: Path, timeout: int) -> list[str]:
    return [
        str(bin_path),
        "report",
        str(sample),
        "--include-deob",
        "--out-dir",
        str(artifact_dir),
        "--force",
        "--timeout",
        str(timeout),
    ]


def trait_cap_kinds(report: dict[str, Any]) -> list[str]:
    traits = report.get("traits")
    if not isinstance(traits, list):
        return []
    caps: list[str] = []
    for trait in traits:
        if not isinstance(trait, dict):
            continue
        kind = trait.get("kind")
        if isinstance(kind, str) and kind in CAP_TRAITS and kind not in caps:
            caps.append(kind)
    return sorted(caps)


def recovered_counts(report: dict[str, Any]) -> dict[str, int]:
    recovered = report.get("recovered")
    if isinstance(recovered, dict):
        by_format = recovered.get("by_format")
        return {
            "total": int(recovered.get("total", 0))
            if isinstance(recovered.get("total"), int)
            else 0,
            "pe": int(recovered.get("pe", 0)) if isinstance(recovered.get("pe"), int) else 0,
            "bin": int(by_format.get("bin", 0))
            if isinstance(by_format, dict) and isinstance(by_format.get("bin"), int)
            else 0,
            "py": int(by_format.get("py", 0))
            if isinstance(by_format, dict) and isinstance(by_format.get("py"), int)
            else 0,
            "shellcode": int(recovered.get("by_kind", {}).get("shellcode", 0))
            if isinstance(recovered.get("by_kind"), dict)
            and isinstance(recovered.get("by_kind", {}).get("shellcode"), int)
            else 0,
        }
    output_files = report.get("output_files")
    if isinstance(output_files, dict) and isinstance(output_files.get("recovered"), list):
        recovered_len = len(output_files["recovered"])
        return {"total": recovered_len, "pe": recovered_len, "bin": 0, "py": 0, "shellcode": 0}
    return {"total": 0, "pe": 0, "bin": 0, "py": 0, "shellcode": 0}


def read_json_report(stdout: bytes) -> dict[str, Any]:
    parsed = json.loads(stdout)
    if not isinstance(parsed, dict):
        raise ValueError("batdeob emitted non-object JSON")
    return parsed


def run_one(
    *,
    bin_path: Path,
    sample: Path,
    idx: int,
    reports_dir: Path,
    artifacts_dir: Path,
    errors_dir: Path,
    timeout: int,
    watchdog: int,
) -> tuple[dict[str, str], dict[str, str] | None]:
    sid = sample_id(idx, sample)
    report_path = reports_dir / f"{sid}.json"
    artifact_dir = artifacts_dir / sid
    error_path = errors_dir / f"{sid}.txt"
    input_size = sample.stat().st_size
    start = time.monotonic()
    cmd = build_command(bin_path, sample, artifact_dir, timeout)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=watchdog,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        error_path.write_text(
            f"outer watchdog timeout after {watchdog}s\ncommand: {' '.join(cmd)}\n{exc}\n",
            errors="replace",
        )
        row = {
            "idx": str(idx),
            "filename": sample.name,
            "input_size": str(input_size),
            "elapsed_seconds": f"{elapsed:.3f}",
            "status": "outer-timeout",
            "report_path": "",
            "artifact_dir": str(artifact_dir),
            "caps": "",
            "recovered_total": "0",
            "recovered_pe": "0",
            "recovered_bin": "0",
            "recovered_py": "0",
            "recovered_shellcode": "0",
        }
        failure = {
            "idx": str(idx),
            "filename": sample.name,
            "input_size": str(input_size),
            "elapsed_seconds": f"{elapsed:.3f}",
            "error_path": str(error_path),
        }
        return row, failure

    elapsed = time.monotonic() - start
    if proc.returncode != 0:
        error_path.write_bytes(proc.stderr[:20000])
        row = {
            "idx": str(idx),
            "filename": sample.name,
            "input_size": str(input_size),
            "elapsed_seconds": f"{elapsed:.3f}",
            "status": "error",
            "report_path": "",
            "artifact_dir": str(artifact_dir),
            "caps": "",
            "recovered_total": "0",
            "recovered_pe": "0",
            "recovered_bin": "0",
            "recovered_py": "0",
            "recovered_shellcode": "0",
        }
        failure = {
            "idx": str(idx),
            "filename": sample.name,
            "input_size": str(input_size),
            "elapsed_seconds": f"{elapsed:.3f}",
            "error_path": str(error_path),
        }
        return row, failure

    try:
        report = read_json_report(proc.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        error_path.write_text(
            f"{exc}\n\nstdout:\n{proc.stdout[:20000].decode(errors='replace')}\n",
            errors="replace",
        )
        row = {
            "idx": str(idx),
            "filename": sample.name,
            "input_size": str(input_size),
            "elapsed_seconds": f"{elapsed:.3f}",
            "status": "bad-json",
            "report_path": "",
            "artifact_dir": str(artifact_dir),
            "caps": "",
            "recovered_total": "0",
            "recovered_pe": "0",
            "recovered_bin": "0",
            "recovered_py": "0",
            "recovered_shellcode": "0",
        }
        failure = {
            "idx": str(idx),
            "filename": sample.name,
            "input_size": str(input_size),
            "elapsed_seconds": f"{elapsed:.3f}",
            "error_path": str(error_path),
        }
        return row, failure

    input_bytes = sample.read_bytes()
    report.setdefault("input", str(sample))
    report.setdefault("input_size", input_size)
    report.setdefault("input_sha256", hashlib.sha256(input_bytes).hexdigest())
    report.setdefault("artifact_dir", str(artifact_dir))
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    caps = trait_cap_kinds(report)
    recovered = recovered_counts(report)
    row = {
        "idx": str(idx),
        "filename": sample.name,
        "input_size": str(input_size),
        "elapsed_seconds": f"{elapsed:.3f}",
        "status": "ok",
        "report_path": str(report_path),
        "artifact_dir": str(artifact_dir),
        "caps": ",".join(caps),
        "recovered_total": str(recovered["total"]),
        "recovered_pe": str(recovered["pe"]),
        "recovered_bin": str(recovered["bin"]),
        "recovered_py": str(recovered["py"]),
        "recovered_shellcode": str(recovered["shellcode"]),
    }
    return row, None


def write_tsv(path: Path, fields: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus_dir", type=Path)
    parser.add_argument("--bin", type=Path, default=DEFAULT_BIN)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--watchdog", type=int, default=30)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args(argv)

    run_dir = args.out_dir or default_run_dir()
    reports_dir = run_dir / "reports"
    artifacts_dir = run_dir / "artifacts"
    errors_dir = run_dir / "errors"
    for directory in (reports_dir, artifacts_dir, errors_dir):
        directory.mkdir(parents=True, exist_ok=True)

    samples = iter_samples(args.corpus_dir)
    indexed = [(idx, sample) for idx, sample in enumerate(samples, start=1) if idx >= args.start]
    if args.limit is not None:
        indexed = indexed[: args.limit]

    summary_rows: list[dict[str, str]] = []
    failure_rows: list[dict[str, str]] = []
    for idx, sample in indexed:
        row, failure = run_one(
            bin_path=args.bin,
            sample=sample,
            idx=idx,
            reports_dir=reports_dir,
            artifacts_dir=artifacts_dir,
            errors_dir=errors_dir,
            timeout=args.timeout,
            watchdog=args.watchdog,
        )
        summary_rows.append(row)
        if failure is not None:
            failure_rows.append(failure)
        print(
            f"{idx}\t{row['status']}\t{row['elapsed_seconds']}s\t"
            f"caps={row['caps'] or '-'}\t"
            f"recovered={row['recovered_total']}("
            f"pe={row['recovered_pe']},bin={row['recovered_bin']},"
            f"py={row['recovered_py']},shellcode={row['recovered_shellcode']})\t"
            f"{sample.name}",
            file=sys.stderr,
        )

    write_tsv(run_dir / "summary.tsv", SUMMARY_FIELDS, summary_rows)
    write_tsv(run_dir / "failures.tsv", FAILURE_FIELDS, failure_rows)
    timeout_rows = [
        row
        for row in summary_rows
        if row["status"] == "outer-timeout" or "TimeoutHit" in row["caps"].split(",")
    ]
    write_tsv(run_dir / "timeout_samples.tsv", SUMMARY_FIELDS, timeout_rows)

    print(f"run_dir\t{run_dir}")
    print(f"reports\t{reports_dir}")
    print(f"artifacts\t{artifacts_dir}")
    print(f"summary\t{run_dir / 'summary.tsv'}")
    print(f"failures\t{run_dir / 'failures.tsv'}")
    print(f"timeouts\t{run_dir / 'timeout_samples.tsv'}")
    print(f"ok\t{sum(1 for row in summary_rows if row['status'] == 'ok')}")
    print(f"failures_count\t{len(failure_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
