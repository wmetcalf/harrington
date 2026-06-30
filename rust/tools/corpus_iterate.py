#!/usr/bin/env python3
"""Drive iterative corpus review from a batdeob audit CSV.

The audit CSV is produced by corpus_audit.py. This helper keeps the human and
agent review loop durable: select the next batch, append review decisions, and
summarize remaining work.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_REVIEW_LOG = Path("/tmp/batdeob_corpus_review.tsv")
DEFAULT_BATCH_OUT = Path("/tmp/batdeob_next_batch.tsv")
DEFAULT_BUCKET_ORDER = (
    "url-loss",
    "ps-no-url-review",
    "high-unresolved",
    "expanded-ps-review",
    "timeout",
    "error",
    "url-gain",
)
TERMINAL_STATUSES = {"reviewed", "fixed", "false-positive", "wont-fix", "skipped"}
REVIEW_FIELDS = ("timestamp", "idx", "sha256", "filename", "bucket", "status", "notes")
BATCH_FIELDS = (
    "idx",
    "sha256",
    "filename",
    "bucket",
    "input_size",
    "old_url_count",
    "new_url_count",
    "unresolved_vars",
    "ps_signals",
    "gained_urls",
    "lost_urls",
)


def read_audit(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        if "idx" not in row or "bucket" not in row:
            raise SystemExit(f"{path} is missing required audit columns")
    return rows


def read_review_log(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def terminal_reviewed_indexes(review_rows: list[dict[str, str]]) -> set[str]:
    return {
        row.get("idx", "")
        for row in review_rows
        if row.get("status", "").strip().lower() in TERMINAL_STATUSES
    }


def bucket_rank(bucket: str, order: tuple[str, ...]) -> int:
    try:
        return order.index(bucket)
    except ValueError:
        return len(order)


def select_next(
    audit_rows: list[dict[str, str]],
    review_rows: list[dict[str, str]],
    bucket_order: tuple[str, ...],
    batch_size: int,
    include_ok: bool,
) -> list[dict[str, str]]:
    reviewed = terminal_reviewed_indexes(review_rows)
    candidates = [
        row
        for row in audit_rows
        if row["idx"] not in reviewed and (include_ok or row.get("bucket") != "ok")
    ]
    candidates.sort(key=lambda row: (bucket_rank(row.get("bucket", ""), bucket_order), int(row["idx"])))
    return candidates[:batch_size]


def write_batch(rows: list[dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=BATCH_FIELDS, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def append_review(log_path: Path, row: dict[str, str], status: str, notes: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not log_path.exists() or log_path.stat().st_size == 0
    with log_path.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=REVIEW_FIELDS, delimiter="\t")
        if needs_header:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "idx": row["idx"],
                "sha256": row["sha256"],
                "filename": row["filename"],
                "bucket": row["bucket"],
                "status": status,
                "notes": notes,
            }
        )


def command_next(args: argparse.Namespace) -> int:
    audit_rows = read_audit(args.audit_csv)
    review_rows = read_review_log(args.review_log)
    bucket_order = tuple(args.bucket_order.split(",")) if args.bucket_order else DEFAULT_BUCKET_ORDER
    rows = select_next(audit_rows, review_rows, bucket_order, args.batch_size, args.include_ok)
    write_batch(rows, args.out)
    print(f"wrote\t{len(rows)}\t{args.out}")
    for row in rows[:10]:
        print(f"{row['idx']}\t{row['bucket']}\t{row['filename']}")
    if len(rows) > 10:
        print(f"...\t{len(rows) - 10}\tmore")
    return 0


def command_mark(args: argparse.Namespace) -> int:
    audit_rows = read_audit(args.audit_csv)
    matches = [row for row in audit_rows if row["idx"] == str(args.idx)]
    if not matches:
        raise SystemExit(f"idx {args.idx} not found in {args.audit_csv}")
    append_review(args.review_log, matches[0], args.status, args.notes)
    print(f"marked\t{args.idx}\t{args.status}\t{args.review_log}")
    return 0


def command_summary(args: argparse.Namespace) -> int:
    audit_rows = read_audit(args.audit_csv)
    review_rows = read_review_log(args.review_log)
    reviewed = terminal_reviewed_indexes(review_rows)
    bucket_counts = Counter(row.get("bucket", "") for row in audit_rows)
    pending_counts = Counter(
        row.get("bucket", "") for row in audit_rows if row.get("idx", "") not in reviewed
    )

    print(f"rows\t{len(audit_rows)}")
    print(f"terminal_reviewed\t{len(reviewed)}")
    print(f"pending\t{len(audit_rows) - len(reviewed)}")
    for bucket, count in bucket_counts.most_common():
        print(f"bucket\t{bucket}\t{count}\tpending\t{pending_counts[bucket]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    next_parser = subparsers.add_parser("next", help="write the next review batch TSV")
    next_parser.add_argument("audit_csv", type=Path)
    next_parser.add_argument("--review-log", type=Path, default=DEFAULT_REVIEW_LOG)
    next_parser.add_argument("--out", type=Path, default=DEFAULT_BATCH_OUT)
    next_parser.add_argument("--batch-size", type=int, default=50)
    next_parser.add_argument("--bucket-order", help="comma-separated bucket priority")
    next_parser.add_argument("--include-ok", action="store_true")
    next_parser.set_defaults(func=command_next)

    mark_parser = subparsers.add_parser("mark", help="append a review decision")
    mark_parser.add_argument("audit_csv", type=Path)
    mark_parser.add_argument("--review-log", type=Path, default=DEFAULT_REVIEW_LOG)
    mark_parser.add_argument("--idx", required=True)
    mark_parser.add_argument(
        "--status",
        required=True,
        choices=sorted(TERMINAL_STATUSES | {"selected", "needs-followup"}),
    )
    mark_parser.add_argument("--notes", default="")
    mark_parser.set_defaults(func=command_mark)

    summary_parser = subparsers.add_parser("summary", help="summarize audit and review status")
    summary_parser.add_argument("audit_csv", type=Path)
    summary_parser.add_argument("--review-log", type=Path, default=DEFAULT_REVIEW_LOG)
    summary_parser.set_defaults(func=command_summary)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
