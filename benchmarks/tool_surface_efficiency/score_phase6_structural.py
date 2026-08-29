"""Phase 6 (part 1): structural single-category-coverage check.

For every corpus task, determine which categories (from prototypes/categories.py's
static TOOL_CATEGORY map) its expected_tools + acceptable_tools fall into. If a task's
full allowed-tool set spans more than one category, a category-first funnel (static
grouping A, or progressive discovery B -- both rely on picking a category before
seeing tool names) cannot resolve it in a single category selection; the agent would
need to either guess right on the first try, browse multiple categories, or the corpus
task itself would need re-scoping under that architecture.

This is a deterministic, zero-cost, fully reproducible check -- no model calls
involved -- since discover_tools(category) is a fixed lookup, not a search.
"""

from __future__ import annotations

import json
from pathlib import Path

from prototypes.categories import TOOL_CATEGORY

ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"
OUT_PATH = ROOT / "results" / "phase6_structural.json"


def main() -> None:
    corpus = json.loads(CORPUS_PATH.read_text())
    per_task = []
    single_category_n = 0
    multi_category_n = 0
    unsupported_n = 0

    for task in corpus["tasks"]:
        if task.get("unsupported"):
            unsupported_n += 1
            continue
        allowed = set(task.get("expected_tools") or []) | set(task.get("acceptable_tools") or [])
        categories = sorted({TOOL_CATEGORY[t] for t in allowed if t in TOOL_CATEGORY})
        missing = sorted(t for t in allowed if t not in TOOL_CATEGORY)
        spans_multiple = len(categories) > 1
        if spans_multiple:
            multi_category_n += 1
        else:
            single_category_n += 1
        per_task.append(
            {
                "id": task["id"],
                "topic": task["topic"],
                "multi_tool": bool(task.get("multi_tool")),
                "allowed_tools": sorted(allowed),
                "categories_spanned": categories,
                "spans_multiple_categories": spans_multiple,
                "unmapped_tools": missing,
            }
        )

    supported_n = single_category_n + multi_category_n
    report = {
        "methodology": __doc__,
        "summary": {
            "supported_task_count": supported_n,
            "unsupported_task_count": unsupported_n,
            "single_category_task_count": single_category_n,
            "multi_category_task_count": multi_category_n,
            "single_category_pct": round(100 * single_category_n / supported_n, 1) if supported_n else None,
        },
        "multi_category_tasks": [t for t in per_task if t["spans_multiple_categories"]],
        "per_task": per_task,
    }
    OUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"supported_tasks={supported_n} single_category={single_category_n} multi_category={multi_category_n}")
    print(f"single_category_pct={report['summary']['single_category_pct']}")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
