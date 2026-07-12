#!/usr/bin/env python3
"""Tests for agent_gap_benchmark.py."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("agent_gap_benchmark.py")
SPEC = importlib.util.spec_from_file_location("agent_gap_benchmark", SCRIPT)
assert SPEC is not None
agent_gap_benchmark = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = agent_gap_benchmark
SPEC.loader.exec_module(agent_gap_benchmark)


class AgentGapBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.task = agent_gap_benchmark.Task(
            task_id="demo",
            title="Demo",
            problem="problem",
            source_files=(),
            expected_files=("src/handlers/goto.rs",),
            expected_terms=("line_visit_count", "GotoUnresolved"),
            counterexample="polling loop falls through",
            counterexample_terms=("polling",),
        )

    def test_build_command_uses_requested_model_and_plain_text_prompt(self) -> None:
        cmd = agent_gap_benchmark.build_command(
            "gemma4-dual/base", "diagnose this task"
        )
        self.assertEqual(
            cmd[:7],
            [
                "opencode",
                "run",
                "--pure",
                "--format",
                "default",
                "--model",
                "gemma4-dual/base",
            ],
        )
        self.assertEqual(cmd[-1], "diagnose this task")
        self.assertNotIn("--file", cmd)

    def test_last_json_object_uses_the_final_object(self) -> None:
        result = agent_gap_benchmark.last_json_object('noise {"first": 1} tail {"last": 2}')
        self.assertEqual(result, {"last": 2})

    def test_score_response_requires_files_terms_and_counterexample(self) -> None:
        score = agent_gap_benchmark.score_response(
            self.task,
            "src/handlers/goto.rs line_visit_count GotoUnresolved polling loop falls through",
        )
        self.assertEqual(score["score"], 1.0)
        self.assertTrue(score["counterexample_hit"])


if __name__ == "__main__":
    unittest.main()
