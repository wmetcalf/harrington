#!/usr/bin/env python3
"""Submit batdeob corpus samples to CAPE and track results.

Workflow:
  1. Pick candidates from /tmp/batdeob_audit_full_after_pass11.csv (or any
     audit CSV produced by corpus_audit.py).
  2. For each candidate, extract the original `source` from the matching
     /tmp/corpus_dump_v54/<sha>.json and submit to CAPE.
  3. Persist task IDs immediately so a resumed run picks up where it left off.
  4. Poll status; when a task is reported, pull IOCs and write a comparison
     row vs batdeob's extracted URLs.

Required env vars:
  CAPE_TOKEN  -- the API token (don't bake it into source).

Output:
  /tmp/batdeob_cape_submissions.csv  -- one row per sample:
    sha, filename, bucket, batdeob_new_urls, task_id, status,
    cape_hosts, cape_domains, cape_urls, cape_proc_count, executed_commands,
    submitted_at, reported_at
"""
from __future__ import annotations
import csv
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CAPE = "http://172.18.101.17:8000"
CORPUS_DIR = Path("/tmp/corpus_dump_v54")
AUDIT_CSV = Path("/tmp/batdeob_audit_full_after_pass11.csv")
SAMPLES_DIR = Path("/tmp/batdeob_cape_in")
SUBMIT_CSV = Path("/tmp/batdeob_cape_submissions.csv")
SUBMIT_DELAY_SEC = 1.0  # be polite to the API


def token() -> str:
    t = os.environ.get("CAPE_TOKEN")
    if not t:
        sys.exit("CAPE_TOKEN env var not set")
    return t


def http_get(path: str, timeout: int = 15) -> dict:
    req = urllib.request.Request(
        f"{CAPE}{path}",
        headers={"Authorization": f"Token {token()}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def http_submit(file_path: Path, *, timeout_sec: int = 120, route: str = "internet") -> int:
    """Multipart POST to /apiv2/tasks/create/file/. Returns task_id."""
    import io
    import mimetypes
    boundary = f"----CAPE{int(time.time()*1000)}{random.randint(0, 1<<20):x}"
    crlf = b"\r\n"

    body = io.BytesIO()

    def field(name: str, value: str) -> None:
        body.write(f"--{boundary}{chr(13)}{chr(10)}".encode())
        body.write(
            f'Content-Disposition: form-data; name="{name}"{chr(13)}{chr(10)}{chr(13)}{chr(10)}'.encode()
        )
        body.write(value.encode())
        body.write(crlf)

    field("timeout", str(timeout_sec))
    field("route", route)

    body.write(f"--{boundary}{chr(13)}{chr(10)}".encode())
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{file_path.name}"{chr(13)}{chr(10)}'
        f"Content-Type: application/octet-stream{chr(13)}{chr(10)}{chr(13)}{chr(10)}".encode()
    )
    body.write(file_path.read_bytes())
    body.write(crlf)
    body.write(f"--{boundary}--{chr(13)}{chr(10)}".encode())

    req = urllib.request.Request(
        f"{CAPE}/apiv2/tasks/create/file/",
        data=body.getvalue(),
        headers={
            "Authorization": f"Token {token()}",
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
        raise RuntimeError(f"no task_ids in response: {result}")
    return ids[0]


def pick_candidates(audit_csv: Path, want_total: int = 500) -> list[dict]:
    """Pick the candidate set per the v1 sandbox-comparison plan."""
    by_bucket: dict[str, list[dict]] = {}
    with audit_csv.open(newline="") as f:
        for row in csv.DictReader(f):
            by_bucket.setdefault(row["bucket"], []).append(row)

    out: list[dict] = []

    # All informative buckets in full.
    for b in ("url-loss", "url-gain", "high-unresolved", "error"):
        out.extend(by_bucket.get(b, []))

    # ps-no-url-review: size-biased (prefer smaller for faster sandbox runs).
    psnu = sorted(by_bucket.get("ps-no-url-review", []), key=lambda r: int(r["input_size"]))
    want_psnu = max(0, min(275, len(psnu)))
    out.extend(psnu[:want_psnu])

    # ok: random sample for control. Only small-to-medium so we don't blow
    # sandbox cycles on huge benign-looking matches.
    ok_small = [r for r in by_bucket.get("ok", []) if int(r["input_size"]) < 50_000]
    random.seed(20260527)  # deterministic
    random.shuffle(ok_small)
    fill = want_total - len(out)
    out.extend(ok_small[:max(0, fill)])

    return out[:want_total]


def extract_sample(sha: str, dst: Path) -> bool:
    """Write the .bat from the corpus JSON's `source` field to `dst`."""
    jp = CORPUS_DIR / f"{sha}.json"
    if not jp.is_file():
        return False
    src = json.loads(jp.read_text(errors="ignore")).get("source", "")
    if not isinstance(src, str) or not src:
        return False
    dst.write_text(src, encoding="utf-8", errors="ignore")
    return True


def load_submissions() -> dict[str, dict]:
    """Map sha → row of any prior submissions (for resume)."""
    if not SUBMIT_CSV.exists():
        return {}
    rows = {}
    with SUBMIT_CSV.open(newline="") as f:
        for r in csv.DictReader(f):
            rows[r["sha"]] = r
    return rows


SUBMIT_FIELDS = (
    "sha",
    "filename",
    "bucket",
    "batdeob_new_urls",
    "input_size",
    "task_id",
    "status",
    "cape_hosts",
    "cape_domains",
    "cape_urls",
    "cape_proc_count",
    "cape_signatures",
    "submitted_at",
    "reported_at",
    "error",
)


def write_submissions(rows: dict[str, dict]) -> None:
    SUBMIT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with SUBMIT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUBMIT_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows.values():
            w.writerow(r)


def submit_phase(candidates: list[dict], existing: dict[str, dict]) -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    new_or_failed = 0
    for c in candidates:
        sha = c["sha256"]
        if sha in existing and existing[sha].get("task_id"):
            continue
        sample_path = SAMPLES_DIR / f"{sha}.bat"
        if not sample_path.exists() and not extract_sample(sha, sample_path):
            print(f"  miss-source {sha}", flush=True)
            continue
        try:
            tid = http_submit(sample_path)
            existing[sha] = {
                "sha": sha,
                "filename": c["filename"],
                "bucket": c["bucket"],
                "batdeob_new_urls": c.get("gained_urls", ""),
                "input_size": c["input_size"],
                "task_id": tid,
                "status": "submitted",
                "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "cape_hosts": "",
                "cape_domains": "",
                "cape_urls": "",
                "cape_proc_count": "",
                "cape_signatures": "",
                "reported_at": "",
                "error": "",
            }
            new_or_failed += 1
            print(f"  submitted task {tid:>6}  {c['bucket']:<22} {sha[:12]} {c['filename'][:40]}", flush=True)
        except Exception as e:
            existing[sha] = {
                "sha": sha,
                "filename": c["filename"],
                "bucket": c["bucket"],
                "task_id": "",
                "status": "submit_failed",
                "error": str(e)[:200],
                "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            print(f"  FAIL {sha[:12]} {e}", flush=True)
        if new_or_failed % 10 == 0:
            write_submissions(existing)
        time.sleep(SUBMIT_DELAY_SEC)
    write_submissions(existing)


def poll_phase(existing: dict[str, dict]) -> None:
    pending = [r for r in existing.values() if r.get("task_id") and r.get("status") != "reported"]
    if not pending:
        return
    print(f"polling {len(pending)} pending tasks...", flush=True)
    for r in pending:
        tid = r["task_id"]
        try:
            view = http_get(f"/apiv2/tasks/view/{tid}/", timeout=10)
            st = view.get("data", {}).get("status", "unknown")
            r["status"] = st
            if st == "reported":
                try:
                    iocs = http_get(f"/apiv2/tasks/get/iocs/{tid}/", timeout=20).get("data", {})
                except Exception as e:
                    r["error"] = f"iocs fetch: {e}"
                    continue
                net = iocs.get("network", {})
                r["cape_hosts"] = ",".join(h.get("ip", "") for h in net.get("hosts", []) if h)[:500]
                r["cape_domains"] = ",".join(d.get("domain", d) if isinstance(d, dict) else str(d)
                                              for d in net.get("domains", []) if d)[:500]
                http_urls = [h.get("uri", "") for h in net.get("traffic", {}).get("http", []) if h.get("uri")]
                r["cape_urls"] = ",".join(http_urls)[:1000]
                pt = iocs.get("process_tree", {})
                r["cape_proc_count"] = str(count_procs(pt))
                sigs = iocs.get("signatures", []) or []
                r["cape_signatures"] = ",".join(s.get("name", "") for s in sigs if s)[:500]
                r["reported_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                print(f"  done {tid} {r['bucket']:<22} procs={r['cape_proc_count']} urls={len(http_urls)}", flush=True)
        except Exception as e:
            r["error"] = str(e)[:200]
    write_submissions(existing)


def count_procs(node) -> int:
    if not node:
        return 0
    n = 1 if isinstance(node, dict) and node.get("pid") else 0
    if isinstance(node, dict):
        for c in node.get("children", []) or []:
            n += count_procs(c)
    elif isinstance(node, list):
        for c in node:
            n += count_procs(c)
    return n


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "all"
    existing = load_submissions()
    if cmd in ("submit", "all"):
        candidates = pick_candidates(AUDIT_CSV)
        print(f"selected {len(candidates)} candidates", flush=True)
        from collections import Counter
        c = Counter(r["bucket"] for r in candidates)
        for b, n in c.most_common():
            print(f"  {b:25s} {n:>4}")
        submit_phase(candidates, existing)
    if cmd in ("poll", "all"):
        poll_phase(existing)
    if cmd == "summary":
        from collections import Counter
        st = Counter(r.get("status", "") for r in existing.values())
        for k, v in st.most_common():
            print(f"  {k:25s} {v:>4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
