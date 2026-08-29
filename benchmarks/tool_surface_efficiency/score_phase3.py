"""Phase 3 scoring: current 97-tool surface baseline trial results vs. corpus.

Reads the 4 raw trial batches under results/raw_trials/ (each line:
"<task_id>: <tool_name>[, <tool_name>, ...] | <reason>"), plus corpus.json,
and produces a scored per-task + aggregate report.

Scoring methodology (documented here because two tasks -- t39, t44 -- and
the four Batch-4 multi-tool diagnostic tasks (t53-t56) received reasonable
multi-tool answers against a corpus that records a single primary
`expected_tools` entry plus an `acceptable_tools` list; this must be an
explicit, honest judgment call, not glossed over):

  - `answer_set`  = the set of tool names the agent returned for a task.
  - `expected`    = set(task['expected_tools'])
  - `acceptable`  = set(task['acceptable_tools'])
  - `allowed`     = expected | acceptable  (anything not in `allowed` and
                     not "NONE" is an unnecessary/wrong call)

  first_choice_correct: for single-expected-tool tasks, True iff the FIRST
    tool named in the answer is in `expected` (or the answer is exactly
    "NONE -- unsupported" and the task is itself unsupported). For
    multi_tool tasks (corpus marks `multi_tool: true`), first_choice_correct
    is not a meaningful single-token concept -- scored as eventual only.

  eventually_correct: True iff `expected <= answer_set` (every expected
    tool was named somewhere in the answer) OR the entire answer_set is
    contained in `allowed` (expected | acceptable) -- i.e. an answer built
    entirely from the task's own defensible-alternative pool also counts
    as correct, not just an exact `expected` hit. OR (for unsupported
    tasks) the answer is "NONE" with unsupported reasoning.

  unnecessary_tools: answer_set - allowed. `allowed` is `expected |
    acceptable` for every task -- multi_tool tasks populate
    acceptable_tools too (e.g. t53/t55/t56), so it is never dropped based
    on the multi_tool flag.

  wrong_tool_task: eventually_correct is False and answer_set is non-empty
    and doesn't overlap `expected` at all.

This module has no import path from src/pfsense_mcp; it is benchmark-only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "results" / "raw_trials"
CORPUS_PATH = ROOT / "corpus.json"
OUT_PATH = ROOT / "results" / "phase3_scored.json"

_LINE_RE = re.compile(r"^(t\d+):\s*(.+?)\s*\|\s*(.+)$")

#: Trial answers were collected from fresh subagents whose live tool
#: namespace prefixes every pfSense tool with `mcp__pfsense__` (this
#: session's own MCP client naming), while corpus.json's expected/
#: acceptable tool lists use the bare wire-format names captured by
#: measure_schema_cost.py's real stdio handshake (`pfsense_get_...`).
#: Both refer to the identical 97 real tools -- normalize the prefix
#: away before comparing, never by editing either source list.
_MCP_PREFIX = "mcp__pfsense__"


def _normalize_tool_name(name: str) -> str:
    return name[len(_MCP_PREFIX) :] if name.startswith(_MCP_PREFIX) else name


def _parse_batch(path: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            raise ValueError(f"unparsable line in {path.name}: {line!r}")
        task_id, tools_part, reason = m.groups()
        if tools_part.upper().startswith("NONE"):
            answer_set: list[str] = []
            is_none = True
        else:
            answer_set = [_normalize_tool_name(t.strip()) for t in tools_part.split(",")]
            is_none = False
        out[task_id] = {"answer": answer_set, "is_none": is_none, "reason": reason}
    return out


def load_all_answers() -> dict[str, dict[str, Any]]:
    answers: dict[str, dict[str, Any]] = {}
    for name in ["batch1_current97.txt", "batch2_current97.txt", "batch3_current97.txt", "batch4_current97.txt"]:
        answers.update(_parse_batch(RAW_DIR / name))
    return answers


def score() -> dict[str, Any]:
    corpus = json.loads(CORPUS_PATH.read_text())
    answers = load_all_answers()

    per_task = []
    for task in corpus["tasks"]:
        tid = task["id"]
        if tid not in answers:
            raise ValueError(f"no trial answer recorded for {tid}")
        a = answers[tid]
        expected = set(task.get("expected_tools") or [])
        acceptable = set(task.get("acceptable_tools") or [])
        is_multi_tool = bool(task.get("multi_tool"))
        is_unsupported = bool(task.get("unsupported"))
        allowed = expected | acceptable

        answer_set = set(a["answer"])

        if is_unsupported:
            eventually_correct = a["is_none"]
            first_choice_correct = a["is_none"]
            unnecessary = set() if a["is_none"] else answer_set
            wrong_tool_task = not a["is_none"] and bool(answer_set)
        else:
            if expected:
                eventually_correct = expected.issubset(answer_set) or (
                    bool(answer_set) and answer_set.issubset(allowed)
                )
            else:
                eventually_correct = not a["is_none"]
            if is_multi_tool:
                first_choice_correct = None  # not a meaningful single-token concept
            else:
                first_tool = a["answer"][0] if a["answer"] else None
                first_choice_correct = first_tool in expected if first_tool else False
            unnecessary = answer_set - allowed
            wrong_tool_task = (not eventually_correct) and bool(answer_set) and not (answer_set & expected)

        per_task.append(
            {
                "id": tid,
                "topic": task["topic"],
                "types": task["types"],
                "multi_tool": is_multi_tool,
                "unsupported": is_unsupported,
                "expected_tools": sorted(expected),
                "acceptable_tools": sorted(acceptable),
                "answer": a["answer"],
                "reason": a["reason"],
                "first_choice_correct": first_choice_correct,
                "eventually_correct": eventually_correct,
                "unnecessary_tools": sorted(unnecessary),
                "wrong_tool_task": wrong_tool_task,
                "calls_in_answer": len(a["answer"]),
            }
        )

    n = len(per_task)
    single_tasks = [t for t in per_task if not t["multi_tool"]]
    n_single = len(single_tasks)
    first_choice_correct_n = sum(1 for t in single_tasks if t["first_choice_correct"])
    eventually_correct_n = sum(1 for t in per_task if t["eventually_correct"])
    wrong_tool_n = sum(1 for t in per_task if t["wrong_tool_task"])
    unnecessary_call_tasks_n = sum(1 for t in per_task if t["unnecessary_tools"])
    calls = [t["calls_in_answer"] for t in per_task]

    summary = {
        "task_count": n,
        "single_primary_tool_task_count": n_single,
        "multi_tool_task_count": n - n_single,
        "first_choice_accuracy_pct": round(100 * first_choice_correct_n / n_single, 1) if n_single else None,
        "eventual_accuracy_pct": round(100 * eventually_correct_n / n, 1),
        "wrong_tool_task_pct": round(100 * wrong_tool_n / n, 1),
        "tasks_with_unnecessary_calls_pct": round(100 * unnecessary_call_tasks_n / n, 1),
        "median_calls_per_task": sorted(calls)[len(calls) // 2],
        "mean_calls_per_task": round(sum(calls) / n, 2),
    }

    failures = [t for t in per_task if not t["eventually_correct"] or t["unnecessary_tools"]]

    report = {
        "methodology": __doc__,
        "summary": summary,
        "failures_or_notable": failures,
        "per_task": per_task,
    }
    return report


def main() -> None:
    report = score()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    s = report["summary"]
    print(
        f"tasks={s['task_count']} single_primary={s['single_primary_tool_task_count']} "
        f"multi_tool={s['multi_tool_task_count']}"
    )
    print(f"first_choice_accuracy_pct={s['first_choice_accuracy_pct']}")
    print(f"eventual_accuracy_pct={s['eventual_accuracy_pct']}")
    print(f"wrong_tool_task_pct={s['wrong_tool_task_pct']}")
    print(f"tasks_with_unnecessary_calls_pct={s['tasks_with_unnecessary_calls_pct']}")
    print(f"median_calls_per_task={s['median_calls_per_task']} mean_calls_per_task={s['mean_calls_per_task']}")
    print(f"failures_or_notable_count={len(report['failures_or_notable'])}")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
