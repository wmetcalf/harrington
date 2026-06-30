#!/usr/bin/env python3
"""Side-by-side comparison: batdeob extracted URLs/hosts vs CAPE IOCs.

Reads /tmp/batdeob_cape_submissions.csv and, for every reported task with
cape_executed_count >= 1 (i.e. CAPE actually ran it as batch, not as a
mis-detected exe), runs batdeob on the corresponding sample and emits one
row per task with:
  - cape_urls / cape_hosts / cape_domains
  - batdeob_urls (from downloads + traits)
  - batdeob_hosts / batdeob_domains (derived from urls)
  - verdict: AGREE | PARTIAL | BATDEOB_ONLY | CAPE_ONLY | NEITHER

Output: /tmp/batdeob_cape_compare.tsv (and prints a summary).
"""
from __future__ import annotations
import csv
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

SUBMIT_CSV = Path("/tmp/batdeob_cape_submissions.csv")
SAMPLES_DIR = Path("/tmp/batdeob_cape_in")
COMPARE_TSV = Path("/tmp/batdeob_cape_compare.tsv")
BATDEOB = Path("/home/coz/Downloads/batdeob/rust/target/debug/batdeob")


def host_of(url: str) -> str:
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    h = p.hostname or ""
    return h.lower()


def normalize_url(u: str) -> str:
    if not u:
        return ""
    u = u.strip().rstrip("/")
    # CAPE reports https traffic as http with :443; un-normalize for comparison
    if u.startswith("http://") and ":443" in u:
        u = "https://" + u[len("http://"):].replace(":443", "", 1)
    if u.startswith("http://") and ":80" in u:
        u = "http://" + u[len("http://"):].replace(":80", "", 1)
    return u.lower()


def run_batdeob(sample: Path) -> dict:
    try:
        r = subprocess.run(
            [str(BATDEOB), "report", str(sample)],
            capture_output=True,
            timeout=30,
        )
        if r.returncode != 0:
            return {"error": r.stderr.decode("utf-8", "replace")[:200]}
        return json.loads(r.stdout)
    except Exception as e:
        return {"error": str(e)[:200]}


def extract_batdeob_urls(report: dict) -> set[str]:
    """Collect every URL-like artifact. Prefer normalized `http_url` when the
    download entry has one (WebDAV UNC, decimal-IP, etc.), else fall back to
    raw `src`. Also pull `src` from traits with explicit `kind: Download*`."""
    urls = set()
    for d in report.get("downloads", []) or []:
        u = d.get("http_url") or d.get("src", "")
        if isinstance(u, str) and "://" in u:
            urls.add(u)
    for t in report.get("traits", []) or []:
        kind = t.get("kind", "")
        if not isinstance(kind, str) or "Download" not in kind:
            continue
        for k in ("src", "url"):
            v = t.get(k, "")
            if isinstance(v, str) and "://" in v:
                urls.add(v)
    return urls


def verdict(b_urls: set[str], c_urls: set[str], b_hosts: set[str], c_hosts: set[str]) -> str:
    b_n = {normalize_url(u) for u in b_urls}
    c_n = {normalize_url(u) for u in c_urls}
    url_agree = bool(b_n & c_n)
    host_agree = bool(b_hosts & c_hosts)
    if b_urls and not c_urls and not c_hosts:
        return "BATDEOB_ONLY"
    if not b_urls and not b_hosts and (c_urls or c_hosts):
        return "CAPE_ONLY"
    if url_agree:
        return "AGREE_URL"
    if host_agree:
        return "AGREE_HOST"
    if b_urls or c_urls or b_hosts or c_hosts:
        return "PARTIAL"
    return "NEITHER"


def main() -> int:
    rows = list(csv.DictReader(open(SUBMIT_CSV)))
    candidates = [
        r for r in rows
        if r.get("status") == "reported" and int(r.get("cape_executed_count", "0") or 0) >= 1
    ]
    print(f"comparing {len(candidates)} reported tasks with CAPE activity...", file=sys.stderr)

    out_rows = []
    for r in candidates:
        sample = SAMPLES_DIR / f"{r['sha']}.bat"
        if not sample.exists():
            continue
        report = run_batdeob(sample)
        b_urls = extract_batdeob_urls(report)
        b_hosts = {host_of(u) for u in b_urls if host_of(u)}
        c_urls = set([u for u in (r.get("cape_urls") or "").split(",") if u])
        c_hosts = set([h for h in (r.get("cape_hosts") or "").split(",") if h])
        c_domains = set([d for d in (r.get("cape_domains") or "").split(",") if d])
        v = verdict(b_urls, c_urls, b_hosts, c_hosts | c_domains)
        out_rows.append({
            "task_id": r["task_id"],
            "sha12": r["sha"][:12],
            "filename": r["filename"][:50],
            "bucket": r["bucket"],
            "cape_ec": r["cape_executed_count"],
            "verdict": v,
            "batdeob_urls": " | ".join(sorted(b_urls))[:500],
            "batdeob_hosts": " ".join(sorted(b_hosts)),
            "cape_urls": " | ".join(sorted(c_urls))[:500],
            "cape_hosts": " ".join(sorted(c_hosts)),
            "cape_domains": " ".join(sorted(c_domains)),
        })

    cols = ["task_id", "sha12", "filename", "bucket", "cape_ec", "verdict",
            "batdeob_urls", "batdeob_hosts", "cape_urls", "cape_hosts", "cape_domains"]
    with COMPARE_TSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, delimiter="\t")
        w.writeheader()
        for r in out_rows:
            w.writerow(r)

    print(f"\nwrote {len(out_rows)} rows to {COMPARE_TSV}\n", file=sys.stderr)

    # summary
    from collections import Counter
    c = Counter(r["verdict"] for r in out_rows)
    print("verdict summary:")
    for k, n in c.most_common():
        print(f"  {k:15s} {n:>3}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
