#!/usr/bin/env python3
"""Tests for corpus_audit.py."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("corpus_audit.py")
SPEC = importlib.util.spec_from_file_location("corpus_audit", SCRIPT)
assert SPEC is not None
corpus_audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(corpus_audit)


class CorpusAuditTests(unittest.TestCase):
    def test_diff_urls_treats_concrete_child_url_as_covering_base_variable_url(self) -> None:
        gained, lost = corpus_audit.diff_urls(
            {"http://%%B"},
            {"http://%%B/path/file.dat"},
        )
        self.assertEqual(gained, set())
        self.assertEqual(lost, set())


if __name__ == "__main__":
    unittest.main()
