#!/usr/bin/env python3
"""Re-submit the batdeob corpus to CAPE in batches of N (default 24), waiting
for each batch to fully report before submitting the next, then record a
original / deob / process-tree comparison per sample.

- Excludes non-text samples per libmagic (PE wearing .bat/.cmd, CAB, empty).
- Pre-computes batdeob deob + extracted URLs locally (fast) up front.
- Resumable: state lives in a persistent dir (survives /tmp wipes / reboots).

Env: CAPE_TOKEN (required).
State dir: /home/coz/cstorage/batdeob_caperun/
  state.csv        — per-sample tracking
  cmp/<sha>.json   — per-sample comparison (original snippet / deob / cape tree)
"""
from __future__ import annotations
import csv, io, json, os, random, subprocess, sys, time
import urllib.request, urllib.error
from pathlib import Path

CAPE = "http://172.18.101.17:8000"
BIN = "/home/coz/Downloads/batdeob/rust/target/release/batdeob"
CORPUS = Path("/tmp/batdeob_corpus")
MIME_CSV = CORPUS / "mime.csv"
INDEX_CSV = CORPUS / "index.csv"
STATE_DIR = Path("/home/coz/cstorage/batdeob_caperun")
STATE_CSV = STATE_DIR / "state.csv"
CMP_DIR = STATE_DIR / "cmp"
BATCH = int(os.environ.get("CAPE_BATCH", "24"))
SUBMIT_DELAY = 1.5          # between submits within a batch
POLL_EVERY = 20             # seconds between batch status polls
BATCH_MAX_WAIT = 25 * 60    # give up waiting on a stuck batch after 25 min
TOKEN = os.environ.get("CAPE_TOKEN") or sys.exit("CAPE_TOKEN unset")
H = {"Authorization": f"Token {TOKEN}"}

FIELDS = [
    "sha", "fname", "localpath", "mime",
    "bd_urls", "bd_ps_count", "bd_cmd_count",
    "task_id", "status", "cape_package",
    "cape_proc_count", "cape_hosts", "cape_domains", "cape_urls",
    "cape_exec_count", "submitted_at", "reported_at", "error",
]


def http_get(path, t=30, retries=6):
    for i in range(retries):
        try:
            req = urllib.request.Request(f"{CAPE}{path}", headers=H)
            with urllib.request.urlopen(req, timeout=t) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < retries - 1:
                time.sleep(10 * (i + 1)); continue
            raise
    return None


def http_submit(path: Path, timeout_sec=120, route="internet"):
    boundary = f"----CAPE{int(time.time()*1000)}{random.randint(0,1<<20):x}"
    body = io.BytesIO()
    def field(n, v):
        body.write(f"--{boundary}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{n}"\r\n\r\n'.encode())
        body.write(v.encode()); body.write(b"\r\n")
    field("timeout", str(timeout_sec)); field("route", route)
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode())
    body.write(path.read_bytes()); body.write(b"\r\n")
    body.write(f"--{boundary}--\r\n".encode())
    req = urllib.request.Request(
        f"{CAPE}/apiv2/tasks/create/file/", data=body.getvalue(),
        headers={**H, "Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST")
    for i in range(6):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                res = json.loads(r.read())
            if res.get("error"):
                raise RuntimeError(res.get("error_value"))
            ids = res["data"].get("task_ids") or []
            if not ids:
                raise RuntimeError(f"no task_ids: {res}")
            return ids[0]
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < 5:
                time.sleep(15 * (i + 1)); continue
            raise


def run_batdeob(path: Path) -> dict:
    try:
        r = subprocess.run([BIN, "report", str(path), "--include-deob"],
                           capture_output=True, timeout=30)
        rep = json.loads(r.stdout)
        ex = rep.get("extracted", {}) or {}
        urls = []
        for d in rep.get("downloads", []) or []:
            u = d.get("http_url") or d.get("src", "")
            if u: urls.append(u)
        return {
            "deob": rep.get("deobfuscated", ""),
            "urls": sorted(set(urls)),
            "ps": ex.get("powershell", 0), "cmd": ex.get("cmd", 0),
        }
    except Exception as e:
        return {"deob": "", "urls": [], "ps": 0, "cmd": 0, "error": str(e)[:120]}


def load_state() -> dict:
    if not STATE_CSV.exists():
        return {}
    out = {}
    with STATE_CSV.open(newline="") as f:
        for r in csv.DictReader(f):
            out[r["sha"]] = r
    return out


def save_state(rows: dict):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = STATE_CSV.with_suffix(".tmp")
    with tmp.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows.values():
            w.writerow(r)
    tmp.replace(STATE_CSV)


def build_candidates() -> list[dict]:
    """text/* samples only, joined with sha index."""
    sha_by_path = {}
    with INDEX_CSV.open(newline="") as f:
        for r in csv.DictReader(f):
            sha_by_path[r["localpath"]] = (r["sha256"], r["fname"])
    cands = []
    with MIME_CSV.open(newline="") as f:
        for r in csv.DictReader(f):
            mime = r["mime"]
            if not mime.startswith("text/"):
                continue  # drop PE/exe, CAB, empty
            p = r["path"]
            sha, fname = sha_by_path.get(p, (Path(p).stem, Path(p).name))
            cands.append({"sha": sha, "fname": fname, "localpath": p, "mime": mime})
    return cands


def fetch_iocs(tid: str) -> dict:
    d = http_get(f"/apiv2/tasks/get/iocs/{tid}/", t=40) or {}
    ioc = d.get("data", {}) or {}
    net = ioc.get("network", {}) or {}
    pkg = (ioc.get("info") or {}).get("package", "") or ""
    ec = ioc.get("executed_commands") or []
    pt = ioc.get("process_tree") or []
    def cnt(n):
        if isinstance(n, dict):
            return 1 + sum(cnt(c) for c in (n.get("spawned_processes") or n.get("children") or []))
        if isinstance(n, list):
            return sum(cnt(c) for c in n)
        return 0
    http = [h.get("uri", "") for h in (net.get("traffic", {}).get("http") or []) if isinstance(h, dict) and h.get("uri")]
    return {
        "package": pkg,
        "proc_count": cnt(pt),
        "exec_count": len(ec),
        "executed_commands": ec,
        "process_tree": pt,
        "hosts": [h.get("ip", "") for h in net.get("hosts", []) if isinstance(h, dict)],
        "domains": [(x.get("domain", "") if isinstance(x, dict) else str(x)) for x in net.get("domains", [])],
        "urls": http,
        "signatures": [s.get("name", "") for s in (ioc.get("signatures") or []) if isinstance(s, dict)],
    }


def write_cmp(row, bd, iocs):
    CMP_DIR.mkdir(parents=True, exist_ok=True)
    orig = ""
    try:
        orig = Path(row["localpath"]).read_text("utf-8", "replace")
    except Exception:
        pass
    doc = {
        "sha": row["sha"], "fname": row["fname"], "mime": row["mime"],
        "task_id": row["task_id"], "cape_package": iocs.get("package", ""),
        "original_head": orig[:1500],
        "batdeob_deob": bd.get("deob", "")[:6000],
        "batdeob_urls": bd.get("urls", []),
        "cape_process_tree": iocs.get("process_tree", []),
        "cape_executed_commands": iocs.get("executed_commands", []),
        "cape_hosts": iocs.get("hosts", []),
        "cape_domains": iocs.get("domains", []),
        "cape_urls": iocs.get("urls", []),
        "cape_signatures": iocs.get("signatures", []),
    }
    (CMP_DIR / f"{row['sha']}.json").write_text(json.dumps(doc, indent=1))


def main():
    cands = build_candidates()
    state = load_state()
    # seed new candidates + precompute batdeob locally
    for c in cands:
        if c["sha"] not in state:
            bd = run_batdeob(Path(c["localpath"]))
            state[c["sha"]] = {
                **c, "bd_urls": json.dumps(bd["urls"]),
                "bd_ps_count": bd["ps"], "bd_cmd_count": bd["cmd"],
                "task_id": "", "status": "pending", "cape_package": "",
                "cape_proc_count": "", "cape_hosts": "", "cape_domains": "",
                "cape_urls": "", "cape_exec_count": "", "submitted_at": "",
                "reported_at": "", "error": "",
            }
    save_state(state)
    print(f"candidates: {len(cands)} text samples; state has {len(state)} rows", flush=True)

    pending = [s for s in state.values() if s["status"] in ("pending", "submit_failed")]
    print(f"to submit: {len(pending)} (batch size {BATCH})", flush=True)

    bnum = 0
    for i in range(0, len(pending), BATCH):
        bnum += 1
        batch = pending[i:i + BATCH]
        print(f"\n=== batch {bnum} ({len(batch)} samples) ===", flush=True)
        # submit
        for r in batch:
            try:
                tid = http_submit(Path(r["localpath"]))
                r["task_id"] = str(tid); r["status"] = "submitted"
                r["submitted_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                print(f"  submitted {tid} {r['sha'][:12]}", flush=True)
            except Exception as e:
                r["status"] = "submit_failed"; r["error"] = str(e)[:160]
                print(f"  FAIL {r['sha'][:12]}: {e}", flush=True)
            time.sleep(SUBMIT_DELAY)
        save_state(state)
        # wait for this batch to complete
        sub = [r for r in batch if r.get("task_id")]
        deadline = time.time() + BATCH_MAX_WAIT
        while time.time() < deadline:
            remaining = [r for r in sub if r["status"] not in ("reported", "failed_analysis", "failed_processing")]
            if not remaining:
                break
            time.sleep(POLL_EVERY)
            for r in remaining:
                try:
                    v = http_get(f"/apiv2/tasks/view/{r['task_id']}/", t=15) or {}
                    st = v.get("data", {}).get("status", "unknown")
                    r["status"] = st
                    if st == "reported":
                        iocs = fetch_iocs(r["task_id"])
                        r["cape_package"] = iocs["package"]
                        r["cape_proc_count"] = iocs["proc_count"]
                        r["cape_exec_count"] = iocs["exec_count"]
                        r["cape_hosts"] = ",".join(iocs["hosts"])[:400]
                        r["cape_domains"] = ",".join(iocs["domains"])[:400]
                        r["cape_urls"] = ",".join(iocs["urls"])[:800]
                        r["reported_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        bd = {"deob": "", "urls": json.loads(r["bd_urls"] or "[]")}
                        # reload deob for the cmp file
                        bd2 = run_batdeob(Path(r["localpath"]))
                        write_cmp(r, bd2, iocs)
                except Exception as e:
                    r["error"] = str(e)[:160]
            save_state(state)
            done = sum(1 for r in sub if r["status"] == "reported")
            print(f"  batch {bnum}: {done}/{len(sub)} reported", flush=True)
        save_state(state)
        print(f"  batch {bnum} done (reported {sum(1 for r in sub if r['status']=='reported')}/{len(sub)})", flush=True)

    print("\nALL BATCHES COMPLETE", flush=True)
    rep = sum(1 for r in state.values() if r["status"] == "reported")
    print(f"reported: {rep}/{len(state)}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
