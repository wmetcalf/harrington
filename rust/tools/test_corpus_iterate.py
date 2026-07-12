#!/usr/bin/env python3
"""Tests for corpus_iterate.py."""

from __future__ import annotations

import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("corpus_iterate.py")


class CorpusIterateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.audit = self.root / "audit.csv"
        with self.audit.open("w", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
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
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "idx": "1",
                    "sha256": "a" * 64,
                    "filename": "loss.bat",
                    "input_size": "10",
                    "old_url_count": "1",
                    "new_url_count": "0",
                    "gained_urls": "",
                    "lost_urls": "http://old.example",
                    "old_trait_kinds": "Download",
                    "new_trait_kinds": "",
                    "old_deob_size": "100",
                    "new_deob_size": "90",
                    "unresolved_vars": "0",
                    "ps_signals": "1",
                    "status": "ok",
                    "bucket": "url-loss",
                }
            )
            writer.writerow(
                {
                    "idx": "2",
                    "sha256": "b" * 64,
                    "filename": "ps.bat",
                    "input_size": "20",
                    "old_url_count": "0",
                    "new_url_count": "0",
                    "gained_urls": "",
                    "lost_urls": "",
                    "old_trait_kinds": "",
                    "new_trait_kinds": "",
                    "old_deob_size": "50",
                    "new_deob_size": "400",
                    "unresolved_vars": "4",
                    "ps_signals": "2",
                    "status": "ok",
                    "bucket": "ps-no-url-review",
                }
            )
            writer.writerow(
                {
                    "idx": "3",
                    "sha256": "c" * 64,
                    "filename": "gain.bat",
                    "input_size": "30",
                    "old_url_count": "0",
                    "new_url_count": "1",
                    "gained_urls": "https://new.example",
                    "lost_urls": "",
                    "old_trait_kinds": "",
                    "new_trait_kinds": "Download",
                    "old_deob_size": "50",
                    "new_deob_size": "60",
                    "unresolved_vars": "0",
                    "ps_signals": "1",
                    "status": "ok",
                    "bucket": "url-gain",
                }
            )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_next_prioritizes_review_buckets_and_writes_batch(self) -> None:
        out = self.root / "batch.tsv"
        proc = self.run_script("next", str(self.audit), "--batch-size", "2", "--out", str(out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with out.open(newline="") as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
        self.assertEqual([row["idx"] for row in rows], ["1", "2"])
        self.assertEqual([row["bucket"] for row in rows], ["url-loss", "ps-no-url-review"])

    def test_next_skips_terminal_review_log_entries(self) -> None:
        log = self.root / "review.tsv"
        log.write_text(
            "timestamp\tidx\tsha256\tfilename\tbucket\tstatus\tnotes\n"
            f"2026-05-25T00:00:00Z\t1\t{'a' * 64}\tloss.bat\turl-loss\treviewed\tfalse positive\n"
        )
        out = self.root / "batch.tsv"
        proc = self.run_script(
            "next",
            str(self.audit),
            "--batch-size",
            "2",
            "--review-log",
            str(log),
            "--out",
            str(out),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with out.open(newline="") as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
        self.assertEqual([row["idx"] for row in rows], ["2", "3"])

    def test_mark_appends_review_log_and_summary_counts_terminal_entries(self) -> None:
        log = self.root / "review.tsv"
        proc = self.run_script(
            "mark",
            str(self.audit),
            "--review-log",
            str(log),
            "--idx",
            "2",
            "--status",
            "fixed",
            "--notes",
            "added parser regression",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

        summary = self.run_script("summary", str(self.audit), "--review-log", str(log))
        self.assertEqual(summary.returncode, 0, summary.stderr)
        self.assertIn("rows\t3", summary.stdout)
        self.assertIn("terminal_reviewed\t1", summary.stdout)
        self.assertIn("pending\t2", summary.stdout)


if __name__ == "__main__":
    unittest.main()
