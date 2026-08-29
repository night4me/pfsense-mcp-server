"""Phase 6 (part 2): score the category-selection agent trial against ground truth.

Ground truth per task = the set of categories its allowed_tools (expected |
acceptable) actually span, computed deterministically by
score_phase6_structural.py from the static TOOL_CATEGORY map (never guessed).

A category-selection answer is scored correct if it names at least one
category that intersects the task's ground-truth category set. For
unsupported tasks (no tool exists), there is no ground-truth category --
the agent's answer is recorded but not scored right/wrong, since "closest
plausible category" is inherently subjective for a request with no
matching tool.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STRUCTURAL_PATH = ROOT / "results" / "phase6_structural.json"
CORPUS_PATH = ROOT / "corpus.json"
RAW_DIR = ROOT / "results" / "raw_trials"
OUT_PATH = ROOT / "results" / "phase6_category_selection_scored.json"

_LINE_RE = re.compile(r"^(t\d+):\s*(.+?)\s*\|\s*(.+)$")


def _parse(path: Path) -> dict[str, dict]:
    out = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        m = _LINE_RE.match(line)
        if not m:
            raise ValueError(f"unparsable line in {path.name}: {line!r}")
        tid, cats_part, reason = m.groups()
        cats = [c.strip() for c in cats_part.split(",")]
        out[tid] = {"categories": cats, "reason": reason}
    return out


def main() -> None:
    structural = json.loads(STRUCTURAL_PATH.read_text())
    ground_truth = {t["id"]: set(t["categories_spanned"]) for t in structural["per_task"]}
    corpus = json.loads(CORPUS_PATH.read_text())
    unsupported_ids = {t["id"] for t in corpus["tasks"] if t.get("unsupported")}

    answers = {}
    answers.update(_parse(RAW_DIR / "phase6_category_batchA.txt"))
    answers.update(_parse(RAW_DIR / "phase6_category_batchB.txt"))

    per_task = []
    scored_correct = 0
    scored_total = 0
    for tid, a in sorted(answers.items()):
        is_unsupported = tid in unsupported_ids
        gt = ground_truth.get(tid, set())
        answer_cats = set(a["categories"])
        hit = bool(answer_cats & gt) if gt else None
        if not is_unsupported:
            scored_total += 1
            if hit:
                scored_correct += 1
        per_task.append(
            {
                "id": tid,
                "unsupported": is_unsupported,
                "ground_truth_categories": sorted(gt),
                "answer_categories": a["categories"],
                "correct": hit,
                "reason": a["reason"],
            }
        )

    report = {
        "methodology": __doc__,
        "summary": {
            "scored_task_count": scored_total,
            "correct_count": scored_correct,
            "accuracy_pct": round(100 * scored_correct / scored_total, 1) if scored_total else None,
        },
        "per_task": per_task,
    }
    OUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"scored_tasks={scored_total} correct={scored_correct} accuracy_pct={report['summary']['accuracy_pct']}")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
