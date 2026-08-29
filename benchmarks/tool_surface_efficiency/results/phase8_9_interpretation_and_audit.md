# Phase 8 — interpretation into a Case decision, and Phase 9 — description/schema quality audit

## Phase 8: decision-framework interpretation

Synthesizing every phase of this benchmark:

- **Phase 1 (real cost)**: the current flat 97-tool `tools/list` payload is
  50,287 bytes / ~12,572 estimated tokens (exact byte count; estimated
  tokens use the documented ~4-chars/token approximation, no exact
  tokenizer available in this environment). That is 6.3% of a 200K-token
  context window and 1.3% of a 1M-token window — around or below MCP's own
  documented "switch to progressive discovery" guidance threshold of
  1-5% of context window (Phase 5), not dramatically over it.
- **Phase 3 (does the current surface actually cause selection errors?)**:
  No. 92.9% first-choice accuracy, 98.3% eventual accuracy, 0% wrong-tool
  tasks, 6.7% tasks with a defensible-but-extra call, median 1 call/task,
  across a 60-task corpus spanning 19 topics and 7 task types including
  ambiguous and near-duplicate-tool cases. This is not evidence of a
  selection-accuracy problem the current architecture needs to solve.
- **Phase 5 (is the naive cost model even accurate?)**: No. Tool
  definitions are cacheable prefix content under Anthropic's prompt
  caching (steady-state turns pay cache-read price, not full price), and
  Claude Code — this project's most-verified client — already implements
  its own client-side progressive tool discovery (`ToolSearch`/tool
  search) independent of anything the MCP server does. The "97 tools = 97
  schemas paid every turn" framing this benchmark was chartered to test
  does not hold for the actual target clients.
- **Phase 6 (would A/B measurably help if built)**: The category-first
  funnel mechanic underlying both alternatives resolves 90.9% of tasks in
  a single category hop with 100% category-selection accuracy (28/28
  scored) — so it is technically workable. But its conversational-payload
  reduction (~16.7% of flat cost) does not translate into a real wire-level
  `tools/list` reduction unless implemented via genuine dynamic
  registration (Phase 7), and Phase 3 already shows there's no accuracy
  problem for it to fix.
- **Phase 7 (security cost)**: The safe, presentation-layer-only version of
  either alternative preserves every reviewed security property with no
  new engineering cost. The version that would actually reduce the real
  wire payload — dynamic FastMCP registration — introduces real,
  non-trivial new costs to auditability determinism and
  regression-testability that would need to be explicitly paid for, for a
  problem Phase 3/5 did not find to be real.

### Case selection

Adapting the mission's own decision framework (current-surface-verified /
static-grouping-justified / progressive-discovery-justified /
description-improvements-only / generic-router-rejected):

**The evidence supports "current surface verified, no architecture change"
(Case A of that framework).** The current 97-tool surface does not show a
measurable selection-accuracy problem (Phase 3), the token-cost concern
motivating this benchmark is substantially overstated for the actual
target clients once prompt caching and Claude Code's existing client-side
discovery are accounted for (Phase 5), and while both non-generic
alternatives are technically workable (Phase 6), building either into
production would mean paying real, avoidable security/auditability
engineering cost (Phase 7) to solve a problem that isn't currently
measurable. This is not a rejection of static grouping or progressive
discovery on their merits — both are legitimate, non-generic, reviewable
patterns fully consistent with this project's "explicit reviewed tools >
generic dispatch" default — it is a "not yet justified by evidence" call,
consistent with the mission's own instruction that Case E (generic router)
requires overwhelming evidence and any real architecture change requires
justification, not just theoretical workability.

**Generic dispatch (Case E) remains rejected outright** — nothing in any
phase of this benchmark constitutes evidence for it, and the mission
prohibited even considering it as a v1.1.0 candidate regardless of
findings.

## Phase 9: tool description/schema quality audit

Reviewed the Phase-1-measured largest-10 and smallest-10 tools, and
specifically investigated why `pfsense_get_api_guidance` (3,059 bytes,
description alone 2,263 bytes) is by far the largest tool in the surface
— nearly 2.5x the next-largest (`pfsense_get_official_guidance`, 1,223
bytes) and ~6.9x the median tool (445 bytes).

**Finding: the size is substantively justified, not verbosity.** Read the
full source (`src/pfsense_mcp/tools/read/api_guidance.py`). The tool has
four genuinely distinct query modes (`tool`/`endpoint`/`model`/`topic`),
each with a different required-parameter set, and the `topic` parameter is
typed as plain `str` at the function signature level (validated at
runtime against the `GuideTopic` enum, not declared as a `Literal` type) —
meaning its JSON Schema does **not** carry an `enum` constraint, so the
docstring's explicit listing of the six valid topic values is the *only*
place a caller can learn them. The docstring also carries the disambiguation
between this tool and `pfsense_get_official_guidance` (Netgate-official vs.
community pfREST-upstream documentation) — load-bearing content, not
padding: Phase 3's corpus deliberately included two tasks (t50, t52)
designed to test exactly this disambiguation, and the trial agents
resolved both correctly (t52 to `pfsense_get_api_guidance`, t50 to the
documented-acceptable `pfsense_get_official_guidance` alternative), which
is direct empirical evidence the current description length is doing real
work, not hurting selection accuracy.

**Checked for near-duplication/ambiguity more broadly**: Phase 3's own
empirical results are the strongest available evidence here — a 0%
wrong-tool-task rate and 98.3% eventual accuracy across 60 tasks
(including several deliberately near-duplicate-sounding pairs: the two
guidance tools, `pfsense_get_dns_resolver_host_overrides` vs.
`pfsense_get_dns_forwarder_host_overrides`, `pfsense_get_system_packages`
vs. `pfsense_get_system_package_available`, `pfsense_get_users` vs.
`pfsense_get_user_groups`) found no case where the model was misled by
similar names/descriptions into calling the wrong tool. This is direct,
current, empirical evidence against a description-quality problem existing
today, rather than a theoretical judgment.

**Conclusion**: No safe, evidence-backed description-only changes are
being made in this benchmark. Making cosmetic trims to
`pfsense_get_api_guidance`'s description without a concrete accuracy or
byte-cost problem to fix would risk removing the only source of its
`topic` enum values or its Netgate-vs-pfREST disambiguation — a real
regression risk for a benchmark that found no actual problem to justify
the change. This is a legitimate "no action needed" finding, not a
skipped step: the mission authorized changes only "if clearly
evidence-backed," and the evidence here supports leaving the descriptions
as-is.
