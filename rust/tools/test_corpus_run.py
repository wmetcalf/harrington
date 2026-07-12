#!/usr/bin/env python3
"""Tests for corpus_run.py."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("corpus_run.py")
SPEC = importlib.util.spec_from_file_location("corpus_run", SCRIPT)
assert SPEC is not None
corpus_run = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(corpus_run)


class CorpusRunTests(unittest.TestCase):
    def test_sample_id_preserves_index_and_filename(self) -> None:
        self.assertEqual(
            corpus_run.sample_id(1408, Path("Σύμβαση-pdf.bat")),
            "01408-Σύμβαση-pdf.bat",
        )

    def test_build_command_writes_artifacts_from_report_pass(self) -> None:
        cmd = corpus_run.build_command(
            Path("/tmp/batdeob"),
            Path("/samples/zap.cmd"),
            Path("/tmp/run/artifacts/01397-zap.cmd"),
            timeout=5,
        )
        self.assertEqual(
            cmd,
            [
                "/tmp/batdeob",
                "report",
                "/samples/zap.cmd",
                "--include-deob",
                "--out-dir",
                "/tmp/run/artifacts/01397-zap.cmd",
                "--force",
                "--timeout",
                "5",
            ],
        )

    def test_recovered_counts_reports_script_artifacts_separately(self) -> None:
        report = {
            "recovered": {
                "total": 4,
                "pe": 1,
                "by_format": {
                    "bin": 2,
                    "py": 1,
                },
                "by_kind": {
                    "shellcode": 1,
                },
            }
        }

        self.assertEqual(
            corpus_run.recovered_counts(report),
            {"total": 4, "pe": 1, "bin": 2, "py": 1, "shellcode": 1},
        )

    def test_recovered_counts_falls_back_to_legacy_recovered_list(self) -> None:
        report = {
            "output_files": {
                "recovered": [
                    {"name": "one.exe"},
                    {"name": "two.exe"},
                ]
            }
        }

        self.assertEqual(
            corpus_run.recovered_counts(report),
            {"total": 2, "pe": 2, "bin": 0, "py": 0, "shellcode": 0},
        )


if __name__ == "__main__":
    unittest.main()
