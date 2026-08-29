# Phase 6 — benchmark alternatives A/B against the same corpus

## Methodology and its fidelity limitation

Alternatives A (static grouping) and B (progressive discovery) both funnel
through the identical mechanic for this benchmark's purposes: pick a category
from `CATEGORY_DESCRIPTIONS` (no tool names visible), then see only the
tools in `TOOL_CATEGORY` for that category. The only architectural
difference between A and B is *when* the category set is declared (A:
static, fixed at server start; B: could in principle be updated via
`notifications/tools/list_changed`, per Phase 5) -- that distinction is a
Phase 7 security-review question, not a Phase 6 selection-accuracy one.

**Fidelity limitation, stated explicitly per the mission's Phase 6
requirement**: this harness cannot dynamically reconfigure a live subagent's
actual MCP tool exposure mid-trial. Phase 6 therefore uses a text-simulated
two-stage funnel -- agents are given only category names/descriptions in the
prompt text (never real tool schemas for tools outside the guessed
category) -- rather than a true MCP-protocol-level filtered `tools/list`.
This measures the *selection-accuracy* question validly (can a model route
a natural-language request to the right category from a description alone)
but does not measure real wire-level latency/behavior of a live filtered
MCP session; Phase 5's protocol research is the source for that.

## Part 1 — structural single-category coverage (deterministic, zero-cost)

`score_phase6_structural.py` checked, for every supported corpus task,
whether its `expected_tools | acceptable_tools` fall within one category or
span more than one, using the static `TOOL_CATEGORY` map directly (no model
call needed -- `discover_tools()` is a fixed lookup, not a search).

- Supported tasks: 55 (5 unsupported tasks excluded -- no tool exists,
  category is moot)
- Single-category tasks: 50 (90.9%)
- Multi-category tasks: 5 (9.1%) -- t05 (networking+system, HA/CARP split
  across two categories), t53/t55/t56 (multi-tool diagnostics tasks,
  deliberately designed to span areas), t60 (system+guidance)

A category-first funnel resolves the large majority of realistic requests
in a single category hop; the minority that don't are concentrated almost
entirely in the corpus's own deliberately-cross-cutting
"multi_tool_diagnostics" task type plus HA/CARP's split across
system/networking.

## Part 2 — category-selection agent trial (real, cost-bounded)

30 of the 60 corpus tasks (every odd-numbered task ID, a representative
spread across all topics/types) were run through two parallel fresh
`general-purpose` subagents. Each agent saw **only** the 7 category
name+description pairs (no tool names, no schemas) and picked which
categor(ies) it would open first for each task -- selection-only, no tool
execution, mirroring the Phase 3 trial methodology.

Scored against the Part-1 ground-truth category set (28 of 30 tasks had a
defined ground truth; t57/t59 are unsupported-action tasks with no matching
tool, so "correct category" is undefined for them and they were excluded
from scoring, though the agent's answers were still recorded).

**Result: 28/28 scored tasks correct (100.0% category-selection accuracy).**
Notably, the model correctly flagged the multi-category tasks it saw (t05,
t53, t55) with two categories rather than guessing one, and for the two
unsupported-action tasks (t57 "block traffic", t59 "disable an interface")
it still named the closest plausible category (firewall, networking)
while implicitly treating the request as an action rather than a lookup --
consistent with its Phase 3 behavior of correctly recognizing unsupported
mutation requests once it can see real tool names.

## Part 3 — byte/token cost comparison

Using the exact Phase-1-measured per-tool byte counts
(`results/schema_cost_report.json`):

| Payload | Bytes | % of flat 97-tool payload |
|---|---|---|
| Flat 97-tool `tools/list` (current) | 50,287 | 100% |
| Stage 1: 7 category names + descriptions only | 1,225 | 2.4% |
| Stage 2: average single category's tool set | 7,168 | 14.3% |
| **Typical two-stage funnel total (stage 1 + one stage 2)** | **8,393** | **16.7%** |

Per-category stage-2 breakdown (tool count / bytes):

| Category | Tools | Bytes |
|---|---|---|
| vpn | 17 | 10,246 |
| system | 24 | 9,373 |
| networking | 16 | 8,541 |
| firewall | 15 | 7,710 |
| dns_dhcp | 15 | 6,013 |
| guidance | 3 | 5,033 |
| identity_certificates | 7 | 3,263 |

A category-first funnel's typical total payload for a single-category task
is roughly one-sixth of the current flat 97-tool payload.

## Headline Phase 6 findings

1. The category-first funnel mechanic (shared by both A and B) resolves
   90.9% of realistic tasks in a single category hop, with the remaining
   9.1% being genuinely cross-cutting requests the corpus deliberately
   included to test this.
2. Category-selection accuracy from bare descriptions alone was 100%
   (28/28 scored) in this trial -- no evidence found that reducing the
   decision to "which of 7 categories" introduces a new selection-accuracy
   bottleneck.
3. The funnel reduces typical payload to ~16.7% of the current flat
   97-tool cost -- but per Phase 5's evidence-based finding, this saving
   is against a baseline that is *already* mitigated by prompt-caching
   (steady-state turns pay cache-read price, not full price, for an
   unchanged tool set) and, for Claude Code specifically, an *already
   existing* client-side progressive-discovery mechanism
   (`ToolSearch`/tool search) that achieves a similar reduction without
   any server-side architecture change.
