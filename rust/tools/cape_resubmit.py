#!/usr/bin/env python3
"""Re-submit the samples that hit HTTP 429 on the first pass, with a more
conservative 5s/submit cadence. Updates /tmp/batdeob_cape_submissions.csv in
place; only touches rows whose status is 'submit_failed' or empty task_id.
"""
from __future__ import annotations
import csv, json, os, random, sys, time
import urllib.request, urllib.error
import io
from pathlib import Path

CAPE = "http://172.18.101.17:8000"
SAMPLES_DIR = Path("/tmp/batdeob_cape_in")
SUBMIT_CSV = Path("/tmp/batdeob_cape_submissions.csv")
SUBMIT_DELAY_SEC = 5.0
TOKEN = os.environ.get("CAPE_TOKEN") or sys.exit("CAPE_TOKEN unset")

FIELDS = [
    "sha", "filename", "bucket", "batdeob_new_urls", "input_size", "task_id",
    "status", "cape_package", "cape_executed_count", "cape_executed_first",
    "cape_hosts", "cape_domains", "cape_urls", "cape_proc_count",
    "cape_signatures", "submitted_at", "reported_at", "error",
]


def http_submit(file_path: Path, *, timeout_sec: int = 120, route: str = "internet") -> int:
    boundary = f"----CAPE{int(time.time()*1000)}{random.randint(0, 1<<20):x}"
    crlf = b"\r\n"
    body = io.BytesIO()

    def field(name: str, value: str) -> None:
        body.write(f"--{boundary}\r\n".encode())
        body.write(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        )
        body.write(value.encode())
        body.write(crlf)

    field("timeout", str(timeout_sec))
    field("route", route)
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    body.write(file_path.read_bytes())
    body.write(crlf)
    body.write(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        f"{CAPE}/apiv2/tasks/create/file/",
        data=body.getvalue(),
        headers={
            "Authorization": f"Token {TOKEN}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        result = json.loads(r.read())
    if result.get("error"):
        raise RuntimeError(f"submit failed: {result.get('error_value')}")
    ids = result["data"].get("task_ids") or []
    if not ids:
        raise RuntimeError(f"no task_ids: {result}")
    return ids[0]


def main() -> int:
    rows = list(csv.DictReader(open(SUBMIT_CSV)))
    todo = [
        r for r in rows
        if (not r.get("task_id") or r.get("status") == "submit_failed")
        and r.get("sha")
    ]
    print(f"re-submitting {len(todo)} samples with {SUBMIT_DELAY_SEC}s/submit...", flush=True)

    submitted = 0
    for i, r in enumerate(todo):
        sample = SAMPLES_DIR / f"{r['sha']}.bat"
        if not sample.exists():
            print(f"  [{i+1}/{len(todo)}] missing {r['sha'][:12]}", flush=True)
            continue
        try:
            tid = http_submit(sample)
            r.update({
                "task_id": str(tid),
                "status": "submitted",
                "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "error": "",
            })
            submitted += 1
            print(f"  [{i+1}/{len(todo)}] task {tid:>6}  {r['bucket']:<22} {r['sha'][:12]}", flush=True)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # too fast: back off more
                wait = 30
                print(f"  [{i+1}/{len(todo)}] 429, sleeping {wait}s...", flush=True)
                time.sleep(wait)
                continue
            r["status"] = "submit_failed"
            r["error"] = f"HTTP {e.code}"[:200]
            print(f"  [{i+1}/{len(todo)}] FAIL {r['sha'][:12]}: {e}", flush=True)
        except Exception as e:
            r["status"] = "submit_failed"
            r["error"] = str(e)[:200]
            print(f"  [{i+1}/{len(todo)}] FAIL {r['sha'][:12]}: {e}", flush=True)

        # Checkpoint every 20 submits
        if submitted and submitted % 20 == 0:
            with SUBMIT_CSV.open("w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
                w.writeheader()
                [w.writerow(rr) for rr in rows]
            print(f"  [checkpoint] {submitted} new submits", flush=True)

        time.sleep(SUBMIT_DELAY_SEC)

    with SUBMIT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        [w.writerow(rr) for rr in rows]
    print(f"\ndone: {submitted} new submissions", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
