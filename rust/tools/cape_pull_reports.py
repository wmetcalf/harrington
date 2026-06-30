#!/usr/bin/env python3
"""Pull full CAPE JSON reports for saved batdeob corpus tasks.

The existing CAPE batch runner stores a reduced comparison record in
`/home/coz/cstorage/batdeob_caperun/cmp/<sha>.json`. This helper fills a
separate cache with full CAPE reports so downstream analysis can use richer
fields such as AMSI/Curtain output when the CAPE API token is available.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_CAPE = "http://172.18.101.17:8000"
DEFAULT_STATE = Path("/home/coz/cstorage/batdeob_caperun/state.csv")
DEFAULT_OUT = Path("/home/coz/cstorage/batdeob_caperun/full_reports")


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Token {token}"}


def http_json(
    base_url: str,
    path: str,
    token: str,
    timeout: int,
    retries: int,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=auth_headers(token))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            if not isinstance(data, dict):
                raise RuntimeError(f"{path} did not return a JSON object")
            return data
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"exhausted retries for {path}")


def task_ids_for_hash(
    base_url: str,
    sha256: str,
    token: str,
    timeout: int,
    retries: int,
) -> list[str]:
    data = http_json(
        base_url,
        f"/apiv2/tasks/search/sha256/{sha256}/",
        token,
        timeout,
        retries,
    )
    value = data.get("data", data)
    task_ids: list[str] = []
    if isinstance(value, dict):
        raw = value.get("task_ids") or value.get("tasks") or value.get("ids") or []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    task_id = item.get("id") or item.get("task_id")
                else:
                    task_id = item
                if task_id is not None:
                    task_ids.append(str(task_id))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                task_id = item.get("id") or item.get("task_id")
            else:
                task_id = item
            if task_id is not None:
                task_ids.append(str(task_id))
    return task_ids


def load_rows(state_path: Path) -> list[dict[str, str]]:
    with state_path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def selected_rows(
    rows: list[dict[str, str]],
    hashes: set[str],
    reported_only: bool,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for row in rows:
        sha = row.get("sha", "")
        if hashes and sha not in hashes and sha[:12] not in hashes:
            continue
        if reported_only and row.get("status") != "reported":
            continue
        out.append(row)
    return out


def pull_report(
    base_url: str,
    task_id: str,
    token: str,
    timeout: int,
    retries: int,
) -> dict[str, Any]:
    return http_json(
        base_url,
        f"/apiv2/tasks/get/report/{task_id}/",
        token,
        timeout,
        retries,
    )


def parse_hashes(values: list[str]) -> set[str]:
    hashes: set[str] = set()
    for value in values:
        path = Path(value)
        if path.exists():
            for line in path.read_text(errors="replace").splitlines():
                line = line.strip().split(",", 1)[0]
                if line:
                    hashes.add(line)
        else:
            hashes.add(value)
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cape", default=os.environ.get("CAPE_URL", DEFAULT_CAPE))
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--token", default=os.environ.get("CAPE_TOKEN"))
    parser.add_argument("--hash", action="append", default=[], dest="hashes")
    parser.add_argument("--all-statuses", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--retries", type=int, default=4)
    args = parser.parse_args()

    if not args.token:
        raise SystemExit("CAPE_TOKEN unset; export it or pass --token")
    if not args.state.exists():
        raise SystemExit(f"state file not found: {args.state}")

    rows = selected_rows(
        load_rows(args.state),
        parse_hashes(args.hashes),
        reported_only=not args.all_statuses,
    )
    if args.limit is not None:
        rows = rows[: args.limit]

    args.out.mkdir(parents=True, exist_ok=True)
    pulled = skipped = failed = 0
    for row in rows:
        sha = row.get("sha", "")
        if not sha:
            continue
        out_path = args.out / f"{sha}.json"
        if out_path.exists() and not args.force:
            skipped += 1
            continue
        task_id = row.get("task_id") or ""
        if not task_id:
            ids = task_ids_for_hash(args.cape, sha, args.token, args.timeout, args.retries)
            task_id = ids[-1] if ids else ""
        if not task_id:
            print(f"no task id for {sha}", file=sys.stderr)
            failed += 1
            continue
        try:
            report = pull_report(args.cape, task_id, args.token, args.timeout, args.retries)
            report["_batdeob_cape_state"] = {
                "sha": sha,
                "task_id": task_id,
                "fname": row.get("fname", ""),
                "status": row.get("status", ""),
                "cape_package": row.get("cape_package", ""),
            }
            out_path.write_text(json.dumps(report, indent=1, sort_keys=True))
            pulled += 1
            print(f"pulled {task_id} {sha[:12]}", file=sys.stderr)
        except Exception as exc:
            print(f"failed {task_id} {sha[:12]}: {exc}", file=sys.stderr)
            failed += 1

    print(f"pulled={pulled} skipped={skipped} failed={failed} out={args.out}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
