#!/usr/bin/env python3
"""Benchmark local OpenCode models on bounded Harrington gap diagnoses.

This runner is intentionally read-only. It gives each model the same compact
task packet, asks for a JSON diagnosis, and scores only the parts we can check
deterministically. A later patch loop can use the retained diagnoses, but this
tool never grants an agent edit or shell permissions.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MODELS = (
    "gemma4-dual/base",
    "qwen3-vllm/aeon-qwen36",
)
DEFAULT_TASKS = Path(__file__).with_name("agent_gap_benchmark_tasks.json")
MAX_SOURCE_CHARS = 12_000


@dataclass(frozen=True)
class SourceSpec:
    path: str
    ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class Task:
    task_id: str
    title: str
    problem: str
    source_files: tuple[SourceSpec, ...]
    expected_files: tuple[str, ...]
    expected_terms: tuple[str, ...]
    counterexample: str
    counterexample_terms: tuple[str, ...]


def load_tasks(path: Path) -> list[Task]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError("task manifest must be a JSON array")
    tasks: list[Task] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("task entry must be an object")
        required = ("id", "title", "problem", "source_files", "expected_files", "expected_terms", "counterexample", "counterexample_terms")
        if any(not isinstance(item.get(key), str) for key in ("id", "title", "problem", "counterexample")):
            raise ValueError(f"task has invalid scalar fields: {item!r}")
        if any(
            not isinstance(item.get(key), list)
            for key in ("source_files", "expected_files", "expected_terms", "counterexample_terms")
        ):
            raise ValueError(f"task has invalid list fields: {item!r}")
        sources: list[SourceSpec] = []
        for source in item["source_files"]:
            if not isinstance(source, dict) or not isinstance(source.get("path"), str):
                raise ValueError(f"task has invalid source entry: {item!r}")
            raw_ranges = source.get("ranges")
            if not isinstance(raw_ranges, list) or not raw_ranges:
                raise ValueError(f"task source has no ranges: {source!r}")
            ranges: list[tuple[int, int]] = []
            for line_range in raw_ranges:
                if (
                    not isinstance(line_range, list)
                    or len(line_range) != 2
                    or not all(isinstance(value, int) and value > 0 for value in line_range)
                    or line_range[0] > line_range[1]
                ):
                    raise ValueError(f"task source has invalid range: {source!r}")
                ranges.append((line_range[0], line_range[1]))
            sources.append(SourceSpec(path=source["path"], ranges=tuple(ranges)))
        tasks.append(
            Task(
                task_id=item["id"],
                title=item["title"],
                problem=item["problem"],
                source_files=tuple(sources),
                expected_files=tuple(str(value) for value in item["expected_files"]),
                expected_terms=tuple(str(value) for value in item["expected_terms"]),
                counterexample=item["counterexample"],
                counterexample_terms=tuple(str(value) for value in item["counterexample_terms"]),
            )
        )
    return tasks


def source_excerpt(repo: Path, source: SourceSpec) -> str:
    relative_path = source.path
    path = repo / relative_path
    lines = path.read_text(errors="replace").splitlines()
    excerpts: list[str] = []
    for start, end in source.ranges:
        selected = lines[start - 1 : end]
        numbered = "\n".join(
            f"{line_number:>6}: {line}"
            for line_number, line in enumerate(selected, start=start)
        )
        excerpts.append(f"// lines {start}-{end}\n{numbered}")
    text = "\n\n".join(excerpts)
    if len(text) > MAX_SOURCE_CHARS:
        return text[:MAX_SOURCE_CHARS] + "\n\n[excerpt truncated]\n"
    return text


def task_packet(repo: Path, task: Task) -> str:
    parts = [
        "# Harrington Gap Diagnosis",
        f"Task: {task.title}",
        "",
        "You are a read-only code reviewer. Do not propose edits outside the listed files.",
        "Return exactly one JSON object with these keys:",
        '"root_cause", "files", "failing_test", "safe_fix_shape", "polling_loop_risk", "confidence".',
        "",
        "## Observed behavior",
        task.problem,
        "",
        "## Required counterexample",
        task.counterexample,
    ]
    for source in task.source_files:
        parts.extend(
            [
                "",
                f"## Source: {source.path}",
                "```rust",
                source_excerpt(repo, source),
                "```",
            ]
        )
    return "\n".join(parts) + "\n"


def opencode_config() -> str:
    return json.dumps(
        {
            "$schema": "https://opencode.ai/config.json",
            "permission": {
                "edit": "deny",
                "bash": "deny",
                "external_directory": "deny",
                "webfetch": "deny",
                "websearch": "deny",
            },
        },
        indent=2,
    ) + "\n"


def build_command(model: str, prompt: str) -> list[str]:
    return [
        "opencode",
        "run",
        "--pure",
        "--format",
        "default",
        "--model",
        model,
        prompt,
    ]


def last_json_object(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    best: dict[str, Any] | None = None
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            best = parsed
    return best


def score_response(task: Task, response: str) -> dict[str, Any]:
    lower = response.lower()
    file_hits = [path for path in task.expected_files if path.lower() in lower]
    term_hits = [term for term in task.expected_terms if term.lower() in lower]
    counterexample_hit = all(term.lower() in lower for term in task.counterexample_terms)
    total = len(task.expected_files) + len(task.expected_terms) + 1
    matched = len(file_hits) + len(term_hits) + int(counterexample_hit)
    return {
        "score": round(matched / total, 3) if total else 0.0,
        "file_hits": file_hits,
        "term_hits": term_hits,
        "counterexample_hit": counterexample_hit,
    }


def run_model(repo: Path, task: Task, model: str, timeout: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="harrington-agent-benchmark-") as temp_dir:
        workspace = Path(temp_dir)
        packet = workspace / "task.md"
        prompt = task_packet(repo, task)
        packet.write_text(prompt)
        (workspace / "opencode.json").write_text(opencode_config())
        start = time.monotonic()
        try:
            proc = subprocess.run(
                build_command(model, prompt),
                cwd=workspace,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "task_id": task.task_id,
                "model": model,
                "status": "timeout",
                "elapsed_seconds": round(time.monotonic() - start, 3),
                "response": exc.stdout or "",
                "stderr": exc.stderr or "",
            }
    response = proc.stdout.strip()
    result = {
        "task_id": task.task_id,
        "model": model,
        "status": "ok" if proc.returncode == 0 else "error",
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "response": response,
        "stderr": proc.stderr.strip(),
        "result_json": last_json_object(response),
    }
    result.update(score_response(task, response))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Harrington repository root")
    parser.add_argument("--tasks", type=Path, default=DEFAULT_TASKS, help="task manifest JSON")
    parser.add_argument("--out", type=Path, required=True, help="output JSONL path")
    parser.add_argument("--model", action="append", dest="models", help="provider/model to benchmark")
    parser.add_argument("--timeout", type=int, default=180, help="per-model task timeout in seconds")
    parser.add_argument("--limit", type=int, default=0, help="only run the first N tasks")
    parser.add_argument("--dry-run", action="store_true", help="write packets but do not invoke OpenCode")
    args = parser.parse_args()

    repo = args.repo.resolve()
    if not (repo / "rust").is_dir():
        parser.error(f"not a Harrington repository: {repo}")
    tasks = load_tasks(args.tasks)
    if args.limit:
        tasks = tasks[: args.limit]
    models = tuple(args.models or DEFAULT_MODELS)
    args.out.parent.mkdir(parents=True, exist_ok=True)

    with args.out.open("w") as output:
        for task in tasks:
            for model in models:
                if args.dry_run:
                    result: dict[str, Any] = {
                        "task_id": task.task_id,
                        "model": model,
                        "status": "dry-run",
                        "packet": task_packet(repo, task),
                    }
                else:
                    result = run_model(repo, task, model, args.timeout)
                output.write(json.dumps(result, ensure_ascii=False) + "\n")
                output.flush()
                print(
                    f"{task.task_id}\t{model}\t{result['status']}\t{result.get('score', '-')}",
                    file=sys.stderr,
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
