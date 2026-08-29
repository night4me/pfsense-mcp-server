# Phase 7 — security review of alternatives A (static grouping) and B (progressive discovery)

Reviewed against the actual prototype code (`prototypes/categories.py`,
`prototypes/progressive_discovery.py`), the actual production registry
(`src/pfsense_mcp/tools/registry.py`), and Phase 5's sourced findings on
FastMCP/MCP-protocol mechanics. This assesses what a *productionized*
version of either alternative would need to preserve, not just the inert
benchmark prototypes (which are not registered as MCP tools and are not
reachable from production today).

**Governing principle from the mission**: "The optimization is unacceptable
if it meaningfully weakens auditability." Every answer below is judged
against that bar, not against raw efficiency.

## The load-bearing design distinction found during this review

There are two structurally different ways either alternative could be
productionized, and they have very different security profiles:

- **Presentation-layer-only filtering** — the full 97-tool set stays
  statically registered in FastMCP exactly as today (unchanged
  authorization boundary, unchanged `list_tools()` behavior for any client
  that asks); "categories" and "discovery" are purely a client-facing UX
  layer (e.g. two additional meta-tools, or client-side grouping) that
  *recommends* which of the already-registered tools to look at, but every
  one of the 97 real tools remains technically callable exactly as it is
  today.
- **Genuinely dynamic registration** — the server actually calls FastMCP's
  `add_tool()`/`remove_tool()` (confirmed to exist but require explicit
  wiring in Phase 5) to shrink/grow what's registered per session state,
  paired with `send_tool_list_changed()` notifications.

This distinction answers most of the 10 questions below at once: the
presentation-layer approach preserves every one of the existing security
invariants by construction (it changes nothing about what's reachable, only
what's *suggested*); the dynamic-registration approach introduces real,
new auditability and determinism costs that would need to be paid for
explicitly. Both prototypes as designed (`discover_tools()` is a fixed,
side-effect-free lookup into the static `TOOL_CATEGORY` map) are compatible
with the presentation-layer approach and do not require dynamic
registration to work.

## 1. Unreviewed-endpoint reachability

Neither prototype can reach anything outside the 97 already-reviewed tool
names. `TOOL_CATEGORY` (categories.py:49-154) is a fixed `dict[str, str]`
built and cross-validated against the real captured tool list (zero drift,
verified in Phase 4); `discover_tools()` (progressive_discovery.py:36-44)
is a lookup into that same fixed map. There is no code path in either
module that constructs, computes, or accepts a tool/endpoint name from
outside that fixed set. **No new reachability risk for either A or B.**

## 2. Discovery-input-to-dispatch risk

`discover_tools(category)` takes a category string and raises `ValueError`
for anything not in `CATEGORY_DESCRIPTIONS` — it never uses the input to
construct a name, path, or dispatch target (progressive_discovery.py:42-44,
explicit docstring commitment: "never falls back to a wildcard, a computed
name, or an arbitrary string the caller supplied being used as-is to reach
something new"). The caller still must invoke the real MCP tool by its real
registered name through the real `tools/call` mechanism, which is unrelated
to and unaffected by this lookup. **No discovery-to-dispatch path exists in
either design as prototyped.**

## 3. Accidental WRITE exposure

Both A and B operate entirely on top of whatever tool set a session's
capability profile already has registered. The `TOOL_CATEGORY` map does
include entries for tools that may exist in a `write_protected` profile's
registry, but grouping never changes *which* tools are registered for a
given profile — that boundary is enforced today by the registry
(`src/pfsense_mcp/tools/registry.py`) at server-start, independent of any
client-facing grouping UX. Under the presentation-layer approach this is
unchanged. Under the dynamic-registration approach, WRITE exposure risk
would depend entirely on whether the dynamic add/remove logic is driven
by the same profile check the static registry uses today — this is a real
requirement to enforce explicitly if that path is ever taken, not an
automatic property. **No exposure under presentation-layer A/B as
prototyped; a explicit, testable requirement if dynamic registration is
ever chosen.**

## 4. Stale-client capability retention

Per Phase 5's Q6 finding: a client that caches a tool list and later calls
a tool the server has since unregistered gets a JSON-RPC protocol error
(fail-closed), not silent success. Critically, because grouping/discovery
never *adds* a tool beyond what a profile already has registered — it can
only ever surface a subset — a "stale" client under the presentation-layer
approach can see stale category groupings but every tool name it might
call was already authorized for that profile from session start. There is
no scenario where staleness lets a client retain access to something it
should no longer have, because nothing is ever granted beyond the static
profile registration in the first place. **No new stale-client
authorization risk under presentation-layer A/B.** Under dynamic
registration, staleness is still fail-closed per Phase 5, but the
window between an intended tool removal and a client's actual refresh
would need explicit handling if that path is chosen (e.g. Claude Code is
confirmed to auto-refresh on the notification; Codex CLI/Claude Desktop
behavior here is undetermined per Phase 5 and would need direct testing
before shipping a dynamic design against those clients).

## 5. Category-switching authorization broadening

Switching which category a session is "browsing" never changes the
underlying registered/authorized tool set for that profile — it only
changes which subset of already-authorized tools is being *discussed* in
the current turn. There is no mechanism in either prototype that grants
new authorization on a category switch. **No broadening risk in either
design as prototyped.**

## 6. Auditability determinism

This is the sharpest real difference between the two productionization
strategies. Under the presentation-layer approach, `list_tools()` continues
to return the full, deterministic 97-tool set for every session regardless
of category browsing state — existing audit logging and the existing
95/2/0/97 contract-verification tests are completely unaffected. Under
genuine dynamic registration, `list_tools()` would become
session-state-dependent, which would require (a) audit logs to also record
category-selection/discovery events to make "why was tool X visible in
this session" reconstructible, and (b) rework of any test that currently
asserts a fixed `list_tools()` response. **Presentation-layer A/B:
determinism fully preserved. Dynamic-registration A/B: determinism is
preservable but requires new, explicit engineering — not free.**

## 7. Guidance-triggers-invocation

`list_categories()` and `discover_tools()` are pure, side-effect-free
lookups — neither calls `session.call_tool()`, neither invokes any pfSense
or MCP operation, confirmed by direct code read (progressive_discovery.py
has no I/O of any kind). Browsing categories/guidance can never itself
trigger a live tool invocation. **No risk in either design.**

## 8. Fail-closed preservation

`discover_tools()` raises `ValueError` for any category not in the fixed
`CATEGORY_DESCRIPTIONS` set (progressive_discovery.py:42-43) — an unknown
or malformed category input fails closed (no tools returned, exception
raised) rather than falling open to some default/wildcard tool set.
**Fail-closed behavior verified in both prototypes.**

## 9. 0-default-WRITE invariant

Neither prototype touches capability-profile registration logic at all —
`TOOL_CATEGORY` is a read-only classification of tool *names*, built after
the fact from an already-captured `tools/list` response, and carries no
information about which profile registers which tool. The project's
0-default-WRITE property is enforced entirely by the existing registry
code this benchmark never modifies. **Invariant unaffected by either
alternative as prototyped**, and would need to remain the enforcement
point (not the grouping layer) under any future production
implementation.

## 10. Full enumerability / regression-testability

Presentation-layer A/B: `list_tools()` behavior is byte-identical to
today's, so the existing contract tests (the ones verifying 95 READ / 2
guidance / 0 default-WRITE / 97 total) continue to pass unmodified — this
was directly confirmed by this benchmark's own Phase 1 measurement script
capturing the real `tools/list` payload with zero code changes to
production. Dynamic-registration A/B: enumerability would require testing
every session-state permutation (which categories were discovered, in
what order) to have confidence the full 97-tool surface is still reachable
and correctly gated in every state — a materially larger regression-test
surface than exists today.

## Summary verdict for Phase 7

Both alternatives, **if implemented as a presentation-layer-only filter on
top of the existing static registry** (which is exactly how both
prototypes in this benchmark are shaped — `discover_tools()` never touches
FastMCP registration, never dispatches, never grants), preserve every one
of the 10 security properties reviewed above with no meaningful weakening
of auditability. The dynamic-registration variant of either alternative
(the one that would actually reduce the real MCP `tools/list` payload sent
to a client, as opposed to only reducing what's *presented* in conversation
text) is not free from a security-engineering standpoint: it introduces
real, explicit, payable costs to auditability determinism (#6) and
regression-testability (#10), and a requirement (#3) that WRITE-exposure
gating be re-verified against the dynamic path rather than assumed to
inherit from the static registry. Neither prototype as designed requires
choosing the dynamic-registration variant — the presentation-layer variant
achieves the Phase 6-measured selection-accuracy and (conversational,
not wire-level) verbosity benefits without touching the security boundary
at all.
