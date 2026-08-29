"""Progressive-discovery prototype (Phase 4B).

Two inert, read-only lookup functions over the same fixed category map
`categories.py` already defines -- deliberately NOT a dispatcher:

  - `list_categories()` returns category names + one-line descriptions
    only (no tool names, no schemas, no way to reach an endpoint).
  - `discover_tools(category)` returns the fixed list of *existing*
    reviewed tool *names* for that category -- a lookup into the same
    static `TOOL_CATEGORY` map, never a constructed/computed/user-
    influenced path to any endpoint. The caller still has to invoke the
    real, already-registered MCP tool by its real name through the real
    MCP `tools/call` mechanism -- this module never calls, proxies, or
    forwards to pfSense itself, and never accepts a raw endpoint/method/
    resource argument of any kind.

This is benchmark-only. It is not registered as an MCP tool, not
imported by the production runtime, and exists only so the benchmark
harness can simulate what a two-stage "categories, then tools-in-
category" discovery flow would look like -- see
`benchmarks/tool_surface_efficiency/results/` for how it's exercised.
"""

from __future__ import annotations

from .categories import CATEGORY_DESCRIPTIONS, tools_in_category


def list_categories() -> list[dict[str, str]]:
    """Inert metadata only: category name + description. No tool names,
    no schemas -- this alone cannot be used to reach any endpoint."""

    return [{"category": name, "description": desc} for name, desc in sorted(CATEGORY_DESCRIPTIONS.items())]


def discover_tools(category: str) -> list[str]:
    """Returns the fixed list of existing, already-reviewed tool names
    for `category`. Raises for any value not in the fixed category set
    -- never falls back to a wildcard, a computed name, or an arbitrary
    string the caller supplied being used as-is to reach something new."""

    if category not in CATEGORY_DESCRIPTIONS:
        raise ValueError(f"Unknown category {category!r}. Valid categories: {sorted(CATEGORY_DESCRIPTIONS)}")
    return tools_in_category(category)


if __name__ == "__main__":
    for entry in list_categories():
        tools = discover_tools(entry["category"])
        print(f"{entry['category']} ({len(tools)} tools): {entry['description']}")
