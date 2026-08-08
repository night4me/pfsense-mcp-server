# Tier 1 — Adapter restrictions and containment enforcement

Status: implementation-ready specification; implementation not authorized.
Activation gate: must exist before any `tier1/adapters/` package is
created (Milestone 9 groundwork).
Related: [sealed_executor.md](sealed_executor.md),
[capability_adapter_contract.md](capability_adapter_contract.md),
`tests/tier1/test_isolation.py` (existing pattern this spec extends).

## Purpose

`sealed_executor.md` and `capability_adapter_contract.md` describe what an
adapter *should* do. This document specifies how every restriction is
**mechanically enforced** — via the same AST-based static test approach
the architecture review independently verified already works for
`pfsense_mcp.tier1`'s isolation from production — so that "the adapter
shouldn't do X" is a CI-enforced fact, not a code-review hope.

## Security goals

- G1: Every forbidden adapter behavior listed in `sealed_executor.md`'s
  "Forbidden adapter behavior" section has a corresponding automated test
  that fails if violated.
- G2: A new adapter cannot be merged without these tests passing, the same
  way `tests/tier1/test_isolation.py` already gates the existing
  `tier1`/production boundary in `make validate`.

## Invariants

- I1: All adapter modules live under `src/pfsense_mcp/tier1/adapters/`
  (new package, does not exist yet) — a single, predictable location the
  AST scan can target exhaustively, mirroring how
  `test_isolation.py::test_tier1_domain_has_no_transport_or_tool_
  registration_dependency` already scans all of `tier1/*.py`.
- I2: The forbidden-import set for `tier1/adapters/*.py` is a strict
  superset of the forbidden-import set already enforced for
  `tier1/*.py` — it additionally forbids importing
  `pfsense_mcp.tier1.executor`, `pfsense_mcp.tier1.store`, and
  `pfsense_mcp.tier1.confirmation`/`reconciliation` (an adapter has no
  legitimate reason to touch contract storage, confirmation, or
  reconciliation directly — only the executor does).
- I3: The forbidden-call-name set for adapters is the existing
  `{"delete", "patch", "post", "put", "request", "tool"}` plus `"send"`
  and `"get"` — the existing set omits `get`/`send` because production
  READ code legitimately calls GET; adapters have no legitimate reason to
  call anything shaped like a transport verb at all, including GET (the
  executor performs all reads on the adapter's behalf).
- I4: Every adapter's public callable surface (the `CapabilityAdapter`
  Protocol methods) must be individually reachable and testable without
  constructing an executor, a store, or a transport — checked by a
  test-authoring convention (adapter tests import only the adapter
  module and plain data), not by AST, but stated here as a hard review
  requirement.

## Trust boundaries

Identical to `sealed_executor.md`. This document is entirely about
*enforcement mechanism*, not new boundaries.

## State ownership

`tests/tier1/test_adapter_isolation.py` (new, sibling to the existing
`test_isolation.py`) owns these checks. It does not replace
`test_isolation.py` — both run; `test_isolation.py` continues to guard
`tier1/*.py` (non-adapter modules), and the new file guards
`tier1/adapters/*.py` specifically, with the stricter rule set from I2/I3.

## Interfaces

```python
# tests/tier1/test_adapter_isolation.py (new; not created yet)

ADAPTER_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.tier1.executor",
    "pfsense_mcp.tier1.store",
    "pfsense_mcp.tier1.confirmation",
    "pfsense_mcp.tier1.reconciliation",
}
ADAPTER_FORBIDDEN_CALLS = {
    "delete",
    "patch",
    "post",
    "put",
    "request",
    "tool",
    "send",
    "get",
}


def test_no_adapter_imports_forbidden_modules(): ...
def test_no_adapter_calls_forbidden_names(): ...
def test_every_adapter_model_forbids_extra_fields(): ...
def test_every_adapter_method_is_static_or_free_function(): ...
```

The last two are new checks beyond what `test_isolation.py` currently
does for non-adapter `tier1` code, specific to the adapter contract's
extra guarantees (I1/I2 in `capability_adapter_contract.md`):

- `test_every_adapter_model_forbids_extra_fields`: AST-walk every
  `class` in `tier1/adapters/*.py` that subclasses a Pydantic base model
  and assert its `model_config` includes `extra="forbid"` (string match
  on the AST literal, same style as the existing checks — no need to
  actually import/instantiate Pydantic for this check).
- `test_every_adapter_method_is_static_or_free_function`: AST-walk every
  method defined on a class in `tier1/adapters/*.py` that matches one of
  the `CapabilityAdapter` Protocol method names and assert it is
  decorated `@staticmethod` (or is a module-level function, if adapters
  are implemented as plain modules rather than classes).

## Failure modes

| Failure | Detection | Resulting state | Automatic retry |
|---|---|---|---|
| Adapter imports a forbidden module | `test_no_adapter_imports_forbidden_modules` fails | CI/`make validate` fails; adapter cannot merge | N/A (build-time gate) |
| Adapter calls a forbidden name | `test_no_adapter_calls_forbidden_names` fails | Same | N/A |
| Adapter model omits `extra="forbid"` | `test_every_adapter_model_forbids_extra_fields` fails | Same | N/A |
| Adapter method reads `self` state (non-static) | `test_every_adapter_method_is_static_or_free_function` fails | Same | N/A |

## Recovery behavior

Not applicable — these are static/build-time checks, not runtime
recovery paths.

## Non-goals

- This spec does not attempt to catch every conceivable unsafe adapter
  pattern via AST alone — it catches the specific, enumerated forbidden
  behaviors. Human review (per `capability_adapter_contract.md`'s review
  checklist) remains required for semantic correctness (e.g., whether a
  fingerprint function is *complete*, which AST cannot verify).
- This spec does not sandbox adapter code at runtime (no
  `exec`-in-restricted-namespace, no separate process/container). The
  local trust model already assumes reviewed, first-party code; AST gates
  exist to catch mistakes and drift, not to defend against a malicious
  contributor with commit access — that threat is out of scope per
  `THREAT_MODEL.md`'s existing A5 boundary (supply-chain review, CI
  checks, pinned actions — not runtime sandboxing).

## Required tests

Listed under Interfaces above; all four must exist before the first
adapter module is created, run against an intentionally-violating
fixture adapter first (to prove the check actually fails when it should
— the same discipline the architecture review applied when verifying
`test_isolation.py` was real rather than trivially passing), then against
the real adapter once written.

## Activation requirements

- [ ] `test_adapter_isolation.py` created and proven against both a
      violating fixture and a compliant fixture before any real adapter
      exists.
- [ ] Wired into `make validate` alongside the existing
      `tests/tier1/` suite (no separate opt-in — it must run every time,
      same as `test_isolation.py` today).

## Implementation checklist

- [ ] Create `src/pfsense_mcp/tier1/adapters/__init__.py` (empty package,
      created only when the first adapter is authorized — do not
      pre-create an empty package speculatively; an empty, unreferenced
      package is exactly the kind of premature scaffolding the project's
      "no half-finished implementations" principle warns against).
- [ ] Create `tests/tier1/test_adapter_isolation.py` with all four checks.
- [ ] Add a deliberately-violating fixture module (test-only, not shipped)
      to prove each check fails when it should, then delete/neutralize it
      once the proof is captured in the test's own assertions (a
      "check the checker" test, same spirit as the fixture-safety
      self-tests already in this repo, e.g. `tests/test_fixture_safety.py`
      constructing deliberately-bad input to prove the checker catches
      it).

## Review checklist

- [ ] Confirm the forbidden-import/call sets here are kept in sync with
      `test_isolation.py`'s existing sets — if the base sets change,
      review whether the adapter-specific supersets need the same change.
- [ ] Confirm the "check the checker" fixture-violation tests actually
      ran and failed before the real checks were added (verify by
      temporarily reverting the check and confirming the fixture no
      longer fails, then restoring — a manual verification step for
      whoever implements this, not an automated one).

## Security checklist

- [ ] Confirm no adapter module can bypass these checks via dynamic
      imports (`importlib.import_module` with a computed string) — AST
      checks only see literal `import`/`from` statements; add a
      corresponding check that flags any use of `importlib` or
      `__import__` inside `tier1/adapters/*.py` as an additional
      forbidden call, since it would otherwise be an unmonitored escape
      hatch around the static import checks.

## Test checklist

- [ ] All four checks in Interfaces implemented and passing against a
      compliant fixture.
- [ ] All four checks proven to fail against a deliberately non-compliant
      fixture (checker self-test).
- [ ] `importlib`/`__import__` forbidden-call addition (Security
      checklist) implemented and tested.
