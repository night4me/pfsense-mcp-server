# ADR-024: Execution-authorization coordination boundary

- **Status:** Proposed — the architecture remains a proposal; this ADR
  is not "Accepted" in the `ADR-021`/`ADR-022`-style sense (no "I
  accept ADR-024 as written" statement has been given). **Slice E1
  only** (the freshness/precondition re-check primitive) has since been
  separately authorized under a fixed, narrow scope and implemented —
  see "Implementation status" below. The coordinator, Slice E2/E3, and
  every other item in "Implementation slices" remain unauthorized,
  unimplemented proposals.
- **Date:** 2026-08-11 (proposed); Slice E1 implemented same day.

## Implementation status

**Slice E1 — freshness/precondition re-check primitive — implemented
(2026-08-11), under a fixed owner scope.** New
`src/pfsense_mcp/security_plan_freshness.py`: one public function,
`plan_authorization_is_fresh(*, target_capability_posture,
target_anchor_assurance, expected_plan_digest, env=None) -> bool`, and
one public exception, `PlanFreshnessError`. Establishes exactly the
invariant this slice was authorized to establish: *a previously
authorized plan is fresh only when a newly discovered authoritative
posture, passed through the existing `generate_security_posture_plan()`
and `compute_plan_digest()`/`verify_plan_digest()` (via
`security_plan_digest.py`, unmodified), reproduces the exact authorized
`plan_digest`* — `evidence_fingerprint` is never read by this module at
all, closing off any possibility of it becoming the authoritative gate
by accident.

Composes two existing, unmodified primitives only — introduces zero new
hashing/canonicalization/comparison logic
(`test_module_defines_no_second_digest_or_canonicalization_function`
proves this by source inspection, not merely by claim). Zero
`pfsense_mcp.tier1` imports (no new isolation exemption needed).
Structurally cannot accept a caller-supplied "fresh" digest or a
caller-supplied plan object — no such parameter exists on the public
function (`inspect.signature`-based structural tests confirm this
directly). Malformed/wrong-type `expected_plan_digest` returns `False`;
an unexpected discovery/plan-generation/digest-generation failure raises
a sanitized `PlanFreshnessError` (never silently returns `True`, never
leaks the original exception's message).

Owner scope fixed for this slice, unchanged by implementation: no
coordinator, no `MutationExecutor`/state-machine modification, no
authorization consumption (this module never imports
`tier1.authorization_consumption_store`), no two-phase consumption, no
`DeprovisionAuthorization` work, no `target_identity_digest`/
appliance-identity mechanism of any kind (confirmed absent by direct
grep, not merely by omission). 36 new tests (27 regression/adversarial
+ 9 AST-based isolation). Full validation clean (2250 pytest passed, up
from 2214; `ruff`/`mypy`/`mkdocs build --strict`/`make quick`/`make
validate` all green). `MutationExecutor`, `tier1/state_machine.py`, and
`PlanAuthorization`'s schema confirmed byte-identical to the pre-slice
checkpoint via direct diff/sha256.

**Slice E2/E3 and the coordinator itself remain fully unimplemented,
unauthorized proposals** — see "Implementation slices" below, unchanged
by this status update.

## Naming note (read first)

The owner's request for this pass calls it "Phase E." `ADR-022`'s own
"Future implementation phases" list, however, splits this same
territory across three separate numbered phases: **Phase E** ("the
freshness/precondition engine" only), **Phase F** ("execution
coordinator for the `CONFIGURATION`-class mechanism only"), and
**Phase G** ("execution coordinator around existing `RecoveryContract`/
`MutationExecutor` machinery... this phase is where this ADR's design
and the pre-existing Tier 1 roadmap converge"). This document analyzes
the **combined territory** those three phases cover — freshness,
coordination, and bypass resistance are deeply interdependent and
cannot be soundly designed in isolation from one another — but its own
**"Implementation slices"** section (near the end) still recommends
they be *built* as separate, narrower, independently-authorized slices,
preserving `ADR-022`'s own phase-separation discipline rather than
proposing one combined implementation. Nothing in `ADR-022`'s own phase
numbering, sequencing, or scope is changed by this document.

## Context

`ADR-022` (Accepted) defined `Plan → Authorize → Execute → Verify`.
Phases B (`PlanDigest`), C (`PlanAuthorization`/`DeprovisionAuthorization`
data models + signing), and D (pure signature/expiry/scope verification
+ durable one-time consumption tracking) are implemented and pushed.
Current authoritative security checkpoint:
`ee7e7f45a489846f08e3199c60b4f2de1020c4a0`.

Phase D deliberately shipped four independent primitives and stopped:
`verify_plan_authorization_signature()`, `plan_authorization_is_current()`,
`plan_authorization_authorizes_step()`
(`src/pfsense_mcp/security_authorization_verifier.py`), and
`SqliteAuthorizationConsumptionStore.try_consume()`
(`src/pfsense_mcp/tier1/authorization_consumption_store.py`). None of
these are composed with each other, and none is wired to
`MutationExecutor`, `SqliteRecoveryContractStore`, or anything that
mutates pfSense. `MutationExecutor` (`src/pfsense_mcp/tier1/executor.py`)
remains, by construction, completely unaware that `PlanAuthorization`
exists at all — its own `execute()`/`rollback()` methods operate purely
on an already-`PREPARED`, already-`ConfirmationEvidence`-confirmed
`RecoveryContract` loaded by `contract_id`; nothing in its signature or
implementation references a Plan, a digest, or an authority.

This document is the requested architecture/decision pass for
composing those already-shipped primitives, plus the not-yet-built
freshness re-check and execution coordinator, into a coherent,
fail-closed path — **without building any of it**.

## Security goals

- G1. Signature validity, expiry/currentness, plan+step authorization,
  and one-time consumption remain **independently checked**, exactly as
  Phase D already established; the coordinator composes them, it does
  not merge them into one opaque check.
- G2. `MutationExecutor` and `tier1/state_machine.py` remain
  authorization-unaware; no policy migrates into either.
- G3. A `PlanAuthorization` can be consumed at most once, and a
  consumed authorization can never become usable again, under normal
  operation, concurrent operation, and crash/restart.
- G4. Freshness failure and signature/expiry/scope failure are
  distinguishable failure modes with distinguishable, already-accepted
  (`ADR-022`) classifications (`STALE` vs. security anomaly) — neither
  is silently collapsed into the other.
- G5. Every security-critical failure path fails closed: an
  indeterminate outcome (I/O error, ambiguous read, malformed stored
  state) is always treated as "not authorized to proceed," never as
  "proceed anyway."
- G6. No code path introduced or proposed by this document connects a
  verified/consumed authorization to an actual mutation without passing
  through the full, already-accepted `RecoveryContract`/
  `ConfirmationEvidence`/`MutationExecutor` chain unchanged.

## Non-goals (explicitly, for this document)

- Does not implement a coordinator, a freshness engine, or any code
  connecting authorization to execution.
- Does not modify `MutationExecutor`, `tier1/state_machine.py`,
  `RecoveryState`, `RecoveryContract`, `WriteApiClient`, or
  `WriteEndpoints`.
- Does not implement `target_identity_digest` construction for either
  `DeprovisionAuthorization` or a hypothetical appliance-identity
  binding — see "`target_identity_digest` design" below for why, and
  what is explicitly deferred.
- Does not implement `DeprovisionAuthorization` verification.
- Does not add, modify, or expose any MCP tool. Does not activate any
  WRITE milestone.
- Does not modify, reopen, or supersede any `ADR-021`/`ADR-022`/`ADR-023`
  decision. Where this document finds that closing a real gap would
  require amending an already-accepted schema (see
  `target_identity_digest` below), it says so explicitly and treats
  that as its own, separate, future owner decision — never something
  this document grants itself.

## Current trusted primitives (verified by reading the actual shipped code)

| Primitive | File | What it proves | What it does not prove |
|---|---|---|---|
| `compute_plan_digest()` | `security_plan_digest.py` | The plan a `PlanAuthorization` binds to, exactly, deterministically | Nothing about live/current state — a digest is an identity, not a freshness claim |
| `verify_plan_authorization_signature()` | `security_authorization_verifier.py` | A `proof` is a valid Ed25519 signature by a currently-active pinned authority, over `authz`'s own recomputed payload | Nothing about expiry, consumption, freshness, or target identity |
| `plan_authorization_is_current()` | `security_authorization_verifier.py` | `now < authz.expires_at` | Nothing about `issued_at`-side validity (deliberately not checked, per that module's own docstring) or freshness |
| `plan_authorization_authorizes_step()` | `security_authorization_verifier.py` | Exact `plan_digest` + `authorized_step_ids` membership | Nothing about whether the *live* target still matches that plan |
| `SqliteAuthorizationConsumptionStore.try_consume()` | `tier1/authorization_consumption_store.py` | At most one caller ever observes `True` for a given `authorization_id`, durably, across restarts | Nothing about *what* was consumed for — carries no `plan_digest`/step/target linkage by design (owner's own scope decision: minimal schema) |
| `RecoveryContract`/`SqliteRecoveryContractStore` | `tier1/contract.py`, `store.py` | Authenticated, compare-and-set, crash-recovering per-mutation state; `ConfirmationEvidence`-gated `PREPARED → EXECUTING`; target-fingerprint drift refusal at execute time | Nothing about plan-level authorization — has no concept of `PlanAuthorization` at all |
| `MutationExecutor` | `tier1/executor.py` | Exactly one non-GET send per successful `execute()`, authoritative re-read before and after, audit-complete on every path | Nothing about plan-level authorization — takes only `contract_id` + adapter + intent |

## Proposed component boundary

### E1 — Coordinator ownership and placement

**Recommendation: a single new, narrow, tier1-native class — working
name `ExecutionCoordinator` — living in `tier1/execution_coordinator.py`,
sibling to `executor.py`, never inside it.**

Reasoning:

- `MutationExecutor` must remain authorization-unaware (G2, and the
  task's own stated strong default). Adding `PlanAuthorization`
  parameters to `execute()`/`rollback()` would violate that default
  without a compelling invariant-based reason — none was found; the
  existing separation ("an agent asked for execution" vs. "an owner
  approved it," `sealed_executor.md`'s own "Authority boundaries"
  section) already gives the precedent for keeping a *third* authority
  (plan-level review) equally outside the executor.
- The coordinator's job is to sit **strictly upstream** of
  `RecoveryContract` creation: verify signature/expiry/scope, re-check
  freshness, consume the authorization, then — and only then — call
  `store.create()`, obtain `ConfirmationEvidence`-gated confirmation
  (unchanged, existing path), and call `executor.execute(contract_id, ...)`
  with nothing but the ID. This mirrors `sealed_executor.md`'s own
  "Authority boundaries" text almost exactly, one layer higher.
- Placement *inside* `tier1/` (not in the `security_` family
  `security_authorization.py`/`security_authorization_verifier.py`
  already occupy) is recommended because the coordinator's defining
  responsibility — per E7 below — is to be the **sole holder** of both
  the `AuthorizationConsumptionStore` and the `SqliteRecoveryContractStore`/
  `MutationExecutor` references. That encapsulation is most natural as
  a tier1-native class, sibling to `store.py`/`executor.py`, mirroring
  `sealed_executor.md`'s own "State ownership" pattern (constructor
  injection, never global state) rather than a `security_`-family
  module reaching *into* tier1 the way `security_authorization_verifier.py`
  already does for a narrower purpose.
- **A sixth, narrow, explicit `pfsense_mcp.tier1`-boundary exception
  would be needed in the *other* direction**: `tier1/execution_coordinator.py`
  would need to import `security_authorization_verifier`
  (non-tier1) and, for the freshness re-check, `security_plan`/
  `security_plan_digest` (also non-tier1) — the first time a `tier1/`
  module reaches into the `security_` family. This is **not**
  structurally forbidden by any existing isolation test (`executor.py`
  already reaches *outward* to `pfsense_mcp.capabilities`/
  `pfsense_client`/`write_api_client` when its job requires it — the
  existing isolation discipline blocks specific named roots
  — `rest_api_client`/`transport`/`tools`, plus `write_api_client`/
  `pfsense_client` for every module except `executor.py` — never a
  blanket "tier1 may only import tier1"), but it is a **new direction**
  worth naming explicitly rather than discovering by surprise during
  implementation, and `tests/tier1/test_isolation.py` would need a
  new, narrow, documented allowance for exactly this one file's exactly
  these two/three imports, matching this codebase's existing "narrow,
  explicit exception, not a relaxed rule" discipline throughout.

**Allowed imports** (proposed, for a future implementation): `security_authorization_verifier`
(verification primitives), `security_plan`/`security_plan_digest`
(freshness re-check), `authorization_consumption_store` (sibling,
same package), `store.SqliteRecoveryContractStore`, `executor.MutationExecutor`
(both already tier1-native).

**Forbidden imports** (proposed): `pfsense_mcp.rest_api_client`,
`pfsense_mcp.transport`, `pfsense_mcp.tools` (existing universal
tier1 prohibitions, unchanged), `pfsense_mcp.write_api_client`/
`pfsense_mcp.pfsense_client` directly (the coordinator reaches pfSense
only *through* `MutationExecutor`, never around it — mirroring
`executor_only_import_roots`'s existing precedent, extended to name the
coordinator as a second, sealed exception alongside `executor.py`
itself, never a general relaxation).

**Whether the coordinator may call `MutationExecutor`**: yes — this is
its entire purpose; it is the one new caller `MutationExecutor.execute()`
gains once built (`MutationExecutor` itself is unchanged, per G2).

**Whether `MutationExecutor` itself must remain authorization-unaware**:
yes, confirmed as a hard requirement, not merely a default — see
"Rejected designs" below for why moving policy into the executor was
considered and rejected.

**Whether the coordinator should be pure except for explicitly injected
side-effect boundaries**: yes. Proposed shape: the coordinator itself
performs no I/O directly — it composes (a) a fresh-evidence-obtaining
call (Phase E's freshness re-check, itself calling
`generate_security_posture_plan()`/`discover_security_posture()`), (b)
the four already-pure Phase D checks, (c) `try_consume()` (the one
state-changing call before contract creation), (d) `store.create()`/
`store.confirm()`/`executor.execute()` (all already-existing,
already-hardened calls). The coordinator's own added logic — the
*ordering* and *fail-closed branching* between these — should be
directly unit-testable against injected fakes for every dependency,
mirroring `MutationExecutor`'s own testing convention
(`tests/tier1/test_executor.py`'s synthetic adapter against
`MockTransport`).

### Responsibility matrix (E8)

| Component | MUST do | MUST NOT do | Side effects allowed | Trust assumption | Failure mode |
|---|---|---|---|---|---|
| **Plan builder** (`security_plan.py`) | Compute a deterministic `SecurityPosturePlan` from current evidence + a requested target | Authorize, execute, or persist anything | None (pure over its `discover_security_posture()` input) | Its own input (`SecurityPostureDiscovery`) is authoritative for "current state" | Returns a `BLOCKED_*` status; never raises for ordinary evidence |
| **Plan digest logic** (`security_plan_digest.py`) | Compute/verify a deterministic identity over a `SecurityPosturePlan` | Perform I/O, judge freshness, judge authorization | None | The `Plan` object passed in is what it claims to be (no re-discovery) | Never raises for well-formed input |
| **Authorization signer** (`security_authorization.py`, operator-side) | Build a payload from a `Plan` + explicit step set; sign with caller-supplied key material | Load/generate/persist a key; run inside the MCP server process | None (pure) | The private key holder is a human operator exercising real judgment (`ADR-012` precedent) | Raises `SecurityAuthorizationError` for malformed input, never signs malformed input |
| **Authorization verifier** (`security_authorization_verifier.py`) | Check signature/expiry/scope independently | Check consumption, freshness, or target identity; execute anything | None | The `PinnedAuthoritySet` it is given is the deployment's real, current trust configuration | Returns `False`/raises per each function's own documented contract; never fails open |
| **Authorization consumption store** (`tier1/authorization_consumption_store.py`) | Record one-time consumption of an `authorization_id`, atomically, durably | Know or care what was consumed *for*; verify anything; execute anything | Writes exactly one row per successful consumption to its own table only | The `authorization_id` string it receives has already been verified upstream (it does not re-verify) | Raises `AuthorizationConsumptionError` on any indeterminate state (malformed input, corrupted row, DB failure) — never silently treats an error as "not yet consumed" |
| **Freshness/precondition verifier** (not yet built) | Obtain a fresh `SecurityPosturePlan` (same target parameters) and recompute `plan_digest`; compare exactly against `authz.plan_digest` | Assume `evidence_fingerprint` comparison alone is sufficient (does not cover the step list — see "Freshness/precondition model" below); consume the authorization on failure | Re-runs `discover_security_posture()` (the one, already-existing, read-only I/O boundary) | The live pfSense/TPM/witness state it reads is what it currently, honestly is | A read/I/O failure is treated as "cannot confirm freshness" → refuse, never "assume fresh" |
| **Target identity verifier/builder** (not yet built; deferred, see below) | (deferred) | (deferred) | (deferred) | (deferred) | (deferred) |
| **Execution coordinator** (not yet built) | Compose, in the proposed order below, every above primitive; call `store.create()`/`store.confirm()`/`executor.execute()` only after every check passes | Duplicate any check another component already owns; execute a mutation itself; hold a reference reachable from outside its own construction site | Calls `try_consume()` (one state change) then the existing `store`/`executor` calls (already-hardened side effects) | Every composed primitive already does its own job correctly (the coordinator does not re-verify what a sub-primitive already proved) | Any sub-check failure halts the sequence at that point; no partial "proceed anyway" |
| **`MutationExecutor`** | Everything `sealed_executor.md` already specifies, unchanged | Gain any `PlanAuthorization`/signature/authority awareness | Exactly one non-GET send per `execute()` (unchanged) | A `contract_id` it is handed refers to an authoritative, already-`PREPARED`+confirmed contract (unchanged) | Unchanged — existing `FAILED`/`RECONCILIATION` classification |
| **Tier 1 state machine** (`state_machine.py`) | Enforce the closed transition table, unchanged | Gain any new state or transition for authorization purposes | None (pure) | Unchanged | Unchanged (`IllegalTransitionError`) |
| **`WriteApiClient`** | Send exactly one bounded request to an allow-listed endpoint, unchanged | Gain any authorization awareness | The one network call (unchanged) | Unchanged | Unchanged |
| **`WriteEndpoints`** | Remain the sole mutation allow-list, unchanged | Gain any per-authorization or per-plan variation | None (a class-level allow-list) | Unchanged | Unchanged (empty in this build) |
| **Future MCP WRITE exposure** (not yet built, Phase H) | Accept only a reference (`plan_digest` + `step_id`), never authorization contents wholesale, never a boolean (`ADR-022`'s own "MCP WRITE boundary" invariant, unchanged) | Accept caller-supplied `authorized=true` or equivalent; construct/hold `store`/`executor` directly — must go through the coordinator only | N/A — not built | N/A | N/A |

Note: this table deliberately does not duplicate security responsibility
— e.g. "is this signature valid" is checked exactly once (the
verifier), never re-checked by the coordinator in a different way; "is
this the right target" is checked exactly once at the `RecoveryContract`
layer (existing `target_fingerprint` drift detection at execute time),
never duplicated by a plan-level target check unless/until `target_identity_digest`
is separately, explicitly designed (see below).

## Exact proposed verification/execution ordering (E2)

1. Capability active (`ADR-004` profile check) — existing, unaffected.
2. Endpoint allow-listed (`WriteEndpoints`, `ADR-005`) — existing,
   unaffected.
3. `verify_plan_authorization_signature(authz, authorities)` — pure,
   cheap, no I/O. Refuse immediately on `False`.
4. `plan_authorization_is_current(authz, now=coordinator_clock())` —
   pure, cheap. Refuse immediately on `False`.
5. `plan_authorization_authorizes_step(authz, plan_digest=requested_plan_digest, step_id=requested_step_id)`
   — pure, cheap. Refuse immediately on `False`. (Steps 3–5 are
   deliberately ordered before any I/O: reject a badly-signed/expired/
   wrongly-scoped request without touching the network or the store.)
6. **Freshness re-check** (not yet built): re-run
   `discover_security_posture()` → `generate_security_posture_plan()`
   with the *same* target parameters the original plan used, compute
   `compute_plan_digest()` over the fresh result, and require exact
   equality with `authz.plan_digest`. On mismatch, classify per
   `ADR-022`'s existing `STALE`-vs-security-anomaly table (reused, not
   reinvented) — never proceed either way.
7. Anchor assurance appropriate for `authz.risk_class` (reuses
   `ADR-021`'s existing validity constraint; already structurally
   enforced by the fact that an invalid target combination never
   reaches `generate_security_posture_plan()`'s output at all) —
   existing, unaffected.
8. **Authorization consumption**: `try_consume(authz.authorization_id)`.
   The first state-changing call in the sequence. Refuse immediately
   (without creating anything) if `False`.
9. `store.create()` — existing, unaffected; produces a `PREPARING`
   `RecoveryContract`.
10. `store.confirm()` with a real `ConfirmationEvidence` — existing,
    unaffected; a **second, independent** signature, at the
    individual-mutation level (`ADR-022`'s own text: "Neither
    substitutes for the other").
11. `executor.execute(contract_id, adapter=..., intent=...)` —
    existing, unaffected.
12. Independent post-condition verification, audit write — existing,
    unaffected (already built into `store.transition()`/executor flow).

### Why this order, and not another

- **3–5 before 6**: cheap, pure, no-I/O checks first. A caller cannot
  force an expensive live re-discovery pass with a forged/expired/
  wrongly-scoped authorization.
- **6–7 before 8**: freshness and anchor-appropriateness are checks
  *about the live environment*, not about the authorization artifact's
  own validity. Consuming the authorization before these pass would
  burn a scarce, one-time artifact on a transient environmental
  condition unrelated to whether the authorization itself is good —
  see "Consumption semantics" below for the full reasoning.
- **8 before 9**: consumption must happen before `RecoveryContract`
  creation, not after, so that two concurrent callers who both pass
  checks 3–7 cannot both create a contract from the same authorization
  — `try_consume()`'s atomicity is what closes that race, and it can
  only close it if it gates entry to contract creation, not exit from
  it.
- **9–12 unchanged**: this is the entirety of `ADR-006`/`012`/`014`'s
  already-accepted, already-hardened machinery. This document adds
  nothing here and changes nothing here.

### TOCTOU analysis per transition

| Window | Exposure | Disposition |
|---|---|---|
| 3–5 → 6 | None — no live state read yet in 3–5 | N/A |
| 6 → 7 | Anchor state could change in this narrow window | Inherited, not new: `ADR-022`'s own three-point freshness model already exists specifically to bound this class of drift; a future implementation should keep 6 and 7 as close together as practical to minimize this window, but eliminating it entirely would require a single atomic "read everything relevant" primitive that does not exist and is not proposed here |
| 7 → 8 | Same class of narrow drift window | Same disposition |
| 8 → 9 | **Real, acknowledged gap** — see "Crash/retry semantics" below | Documented, not silently accepted |
| 9 → 12 | Fully covered by already-existing `RecoveryContract` crash-recovery (`reconcile_interrupted()`, expiry-driven `EXPIRED` transition, atomic `_replace()`) | No new exposure; this document adds nothing here |

## Consumption semantics (E3)

**Proposed semantic: "one attempt to create a `RecoveryContract` from
this authorization," not "one execution attempt" and not "one
successful execution."**

- **Not "one successful execution only"**: rejected outright. If
  consumption happened only *after* a successful `executor.execute()`,
  the authorization would remain valid and reusable for the entire
  window between "checks 3–7 passed" and "execution confirmed
  successful" — during which it could be used to create **multiple
  concurrent `RecoveryContract`s**, directly reopening the replay
  exposure Phase D exists to close. This is the one option this
  document actively rules out, not merely deprioritizes.
- **"One attempt" (proposed)**: consumption happens once, atomically,
  immediately before `store.create()` (step 8 above), gating entry to
  contract creation. This is precise and testable: `try_consume()`
  succeeding means "this authorization_id will never again gate a
  contract-creation attempt," full stop — regardless of what happens to
  that contract afterward (`VERIFIED`, `FAILED`, `RECONCILIATION`, or
  never created at all due to a crash — see below).

### Freshness failure does not consume

A freshness (`STALE`) failure at step 6 should **not** call
`try_consume()`. Reasoning: `ADR-022`'s own text already frames
ordinary staleness as recoverable ("re-planning produces a new,
authorizable `PlanDigest`") — and since re-planning produces a
*different* `plan_digest`, the *original* authorization could never be
reused against the re-planned version anyway (exact-match binding,
already enforced). The only case where non-consumption on freshness
failure has practical effect is a transient flicker (evidence briefly
diverged, then reverted) where the *same*, unchanged plan becomes fresh
again within the authorization's expiry window — letting the operator's
original authorization still be used once evidence stabilizes, rather
than forcing a brand-new signature for a transient blip. This is safe:
consuming nothing on a check that doesn't itself represent a security
violation (`STALE` is explicitly "not a security anomaly" per
`ADR-022`'s own table) costs nothing and avoids wasting a scarce
one-time artifact.

### Crash/retry semantics — the acknowledged gap

**If a crash occurs between step 8 (`try_consume()` succeeds) and step
9 (`store.create()` completes), the authorization is permanently
consumed with no corresponding `RecoveryContract` ever created.** This
is real, not hypothetical: `try_consume()` and `store.create()` are two
separate atomic operations against two separate, unrelated stores (per
the owner's own Phase D scope decision — no shared transaction is
possible or proposed). There is no way to make this window disappear
without either (a) a two-phase-commit-style protocol spanning both
stores (a materially larger, more complex primitive than anything
Phase D built or this document proposes building), or (b) extending the
consumption store with additional states beyond binary consumed/
unconsumed (the task's own suggested `claimed`/`in-progress`/
`committed`/`execution-bound-record` vocabulary) — explicitly **not**
implemented in this pass, per instruction.

**This document's assessment: the current one-shot `try_consume()`
primitive is *sufficient for safety* (no double-execution, no replay)
but *not ideal for operator ergonomics* under this specific crash
window — an acceptable, explicitly-documented v1 tradeoff, not a
silently-accepted gap.** Justification: `PlanAuthorization` is designed
to be short-lived, narrowly scoped, and cheaply replaceable — an
operator whose authorization was burned by a crash in this narrow
window can simply re-review and re-sign a new one for the same
still-valid plan (assuming it is still fresh); nothing about this
window causes an unsafe state, only an inconvenient one. This mirrors
`ADR-015`'s own "start restrictive, loosen later with real evidence"
philosophy rather than inventing a heavier mechanism against a window
with no operational evidence yet that it matters in practice.

**Recommended, explicitly deferred future enhancement** (not decided,
not implemented, named for future reference only): a `claim(authorization_id) -> ClaimToken`
/ `commit(claim_token)` two-phase extension to `AuthorizationConsumptionStore`,
narrowing the crash window from "spans two stores" to "spans one
store's own two-phase record" — this would need its own design pass,
its own adversarial review, and its own owner authorization if pursued;
this document only names it as a considered option, per instruction.

### Does one-shot consumption need anything beyond consumed/unconsumed?

**No, not for the "one attempt" semantic this document recommends.**
The current binary schema (`consumed_authorizations(authorization_id,
consumed_at, mac)`) is sufficient to prove "has this ID ever gated a
contract-creation attempt" — which is exactly what "one attempt"
requires. It would be **insufficient** for a "one *successful*
execution" semantic (already rejected above) or for a two-phase
claim/commit design (deferred above, not needed for the recommended
semantic).

## Freshness/precondition model (E4)

- **What must be re-read immediately before consumption/execution**:
  the same evidence `discover_security_posture()` already reads today
  (capability posture, anchor assurance, anchor evidence state,
  baseline, witness value, provisioned-at) — no new evidence source is
  proposed.
- **Two distinct freshness checks exist in the design, and they are not
  interchangeable — a finding this document surfaces explicitly, since
  `ADR-022`'s own text does not fully disambiguate them:**
  1. **`evidence_fingerprint` comparison** (the field already on
     `PlanAuthorization`): a *lighter*, target-parameter-free check —
     compare a freshly-discovered evidence snapshot's structural fields
     directly against `authz.evidence_fingerprint`'s stored copy.
  2. **Full `plan_digest` recomputation** (requires the coordinator to
     know the original target parameters — `target_capability_posture`/
     `target_anchor_assurance` — which a real caller would naturally
     supply alongside the authorization reference): re-run
     `generate_security_posture_plan()` with those parameters against
     fresh evidence, compute its digest, and require exact equality
     with `authz.plan_digest`.

  **`evidence_fingerprint` comparison alone is NOT sufficient as the
  authoritative freshness gate**, because it does not cover the `steps`
  list — `steps` participates in `plan_digest` (Phase B's own
  participates-list) but is **not** one of `evidence_fingerprint`'s six
  fields. If `security_plan.py`'s step-generation logic ever changed
  between authorization time and execution time (a code change, not a
  live-evidence change), `evidence_fingerprint` would show no
  difference even though `plan_digest` would. **Recommendation: the
  authoritative freshness gate (step 6 in the ordering above) must be
  full `plan_digest` recomputation; `evidence_fingerprint` comparison
  is at most a cheaper, secondary, non-authoritative signal (e.g. for a
  future read-only "is this authorization's evidence still current"
  status display) — never a substitute for the full recomputation.**
- **Where preconditions belong**: the freshness re-check is a **new**,
  narrow component (not yet built), living outside `tier1/` (it needs
  `security_plan.py`/`security_plan_digest.py`, which cannot be
  imported from inside `tier1/`) — most naturally as a sibling module
  to `security_authorization_verifier.py`, e.g. a
  `security_plan_freshness.py`-shaped module (naming left to a future
  implementation turn), imported by the tier1-native coordinator (E1)
  exactly the way it already imports `security_authorization_verifier`.
- **Purity**: the comparison logic (does this freshly-computed digest
  equal `authz.plan_digest`) should be pure; only "go obtain a fresh
  plan" is I/O-bearing — mirroring the same split already used
  throughout Phase B/C/D.
- **What constitutes stale state**: `ADR-022`'s own existing
  `STALE`-vs-anomaly table, reused verbatim, not reinvented.
- **Freshness failure does not consume**: see "Consumption semantics"
  above.
- **I/O failure must fail closed**: a freshness re-check that cannot
  complete (network error, store read failure, witness unreachable)
  must be treated as "cannot confirm freshness" and refuse — never as
  "no evidence of staleness found, assume fresh." This matches the
  established, codebase-wide fail-closed discipline
  (`read_only_anchor_provisioning_status()`'s `mode=ro` behavior,
  `Ed25519ConfirmationVerifier`'s unconfigured-authority refusal, etc.).
- **Canonical comparison**: all comparisons reuse `tier1.canonical.canonical_json()`/
  `digest_value()` exactly — never a parallel/ad hoc comparison scheme.

## `target_identity_digest` design (E5)

**Two genuinely different questions exist here, and conflating them
would be a real error — this document keeps them explicitly separate.**

### Question A: `DeprovisionAuthorization.target_identity_digest` (an already-accepted field)

This field already exists in the Accepted `ADR-022`/implemented Phase C
schema. Its deferral is **already decided, by `ADR-022` itself**
("Destructive operations": "no code path in this design ever
constructs a `DeprovisionAuthorization`, because no destructive
execution mechanism is designed at all yet... deliberately left as a
future, separate, explicitly-scoped ADR"). **This document changes
nothing here and does not reopen it** — see E9 below for confirmation
that Phase E-territory work should not touch `DeprovisionAuthorization`
at all.

### Question B: a hypothetical appliance-identity binding for ordinary `PlanAuthorization` (a new question, not an existing field)

**Critical finding: `PlanAuthorization`'s own, already-accepted (Phase
C) field table has no `target_identity_digest`-shaped field at all.**
Adding one would be a **schema change to an already-shipped, already-
pushed artifact type** (`e8dc037`/`f3cbcef`, on `origin/main`) — this is
explicitly outside what an architecture/planning pass should decide
unilaterally, and is named here as its own, separate, future owner
decision, not resolved by this document.

**Why the question is real, not manufactured**: per the substitution-
attack analysis below ("same plan sent to another appliance"), nothing
in the currently-accepted chain cryptographically distinguishes "this
plan, reviewed and authorized for Appliance A" from "an identical plan,
by coincidence, on Appliance B" — because this project's entire
architecture assumes exactly one pfSense appliance per deployment
(`PfSenseConfig`/`PFSENSE_API_URL` is a single, required, env-var-driven
target; there is no multi-appliance or multi-tenant concept anywhere in
`config.py`, the MCP transport, or the tool registry). Whether this
residual gap is *actually* exploitable depends entirely on whether this
project's deployment model is genuinely, permanently single-appliance
— which is a product/architecture question this document cannot answer
on its own.

**What repository evidence actually exists** (read-only investigation
performed for this document, no code changed): `src/pfsense_mcp/models/system.py`'s
`SystemStatus.netgate_id` and `src/pfsense_mcp/models/system_ha_sync.py`'s
`SystemHaSync.pfhostid` are both real, already-modeled, pfSense-native,
per-installation identifiers ("Identifying device metadata... same
class as netgate_id/serial," per that file's own docstring). **Both are
deliberately null by default** (`include_identifying_metadata=False`)
in every existing caller — this codebase already treats them as
privacy-sensitive, hidden-unless-explicitly-requested data, a
deliberate, existing convention this document did not invent.

**Why this document does not design the binding now, despite the
signal existing**:

1. Both fields are **nullable** — not every pfSense deployment exposes
   one (Netgate-branded hardware vs. generic pfSense CE installs). A
   safe design needs an explicit, reviewed answer for "no stable
   identifier available" that this document is not positioned to
   invent unilaterally (fail closed? treat as a distinct, named
   "unknown installation identity" state, itself requiring its own
   threat analysis?).
2. Using either field for this purpose means **overriding this
   codebase's own existing privacy-preserving default**
   (`include_identifying_metadata=False`) — a real, non-trivial
   trade-off between "close a replay gap" and "this project's own,
   already-deliberate stance that this data is sensitive by default" —
   requiring its own explicit owner review, not an AI-made call.
3. Neither field is cryptographically signed by pfSense itself — it is
   an ordinary HTTPS API response value, no stronger than the codebase's
   own existing TLS-endpoint trust root every other identity binding
   already relies on (`target_fingerprint`, `natural_identity`, etc.).
   Binding to it adds real defense-in-depth against
   operational/configuration mixups, not new cryptographic assurance
   beyond "this is still the same HTTPS endpoint the operator
   configured" — worth stating precisely so a future reviewer does not
   overestimate what this binding would actually prove.
4. **Where it would bind matters and is not obvious**: folding it into
   `plan_digest` itself would require a schema-version bump to an
   already-shipped, already-tested Phase B primitive
   (`security_plan_digest.py`) — this document recommends **against**
   that, in favor of a **new, separate, additive field/digest** at
   whatever future layer consumes it (the coordinator or a future
   `PlanAuthorization` schema v2), so Phase B's shipped behavior is
   never retroactively altered. This is itself a design fork requiring
   its own "options considered" treatment once (1)–(3) are resolved.

**Disposition: explicitly deferred.** Named prerequisites before this
can be safely designed, let alone implemented:

- (a) an explicit owner/product decision on whether this project's
  deployment model is intended to remain permanently single-appliance-
  per-process (if so, this residual gap may be judged acceptably low-
  value to close at all — closing it purely to satisfy a threat model
  this deployment shape does not actually present would be exactly the
  "solve around an unresolved security boundary" this task's own
  instructions warn against);
- (b) if closing it is judged worthwhile, an explicit owner decision on
  overriding the existing `include_identifying_metadata` privacy
  default for this one purpose;
- (c) a null-handling design for deployments with neither `netgate_id`
  nor `pfhostid`;
- (d) a schema-placement decision (new field/digest, never retroactive
  to Phase B's shipped `PlanDigest`).

This document does **not** treat this as a STOP condition for the rest
of this pass — the gap is real but narrow (bounded to a genuinely
multi-appliance threat model this project does not currently have), is
explicitly documented rather than silently accepted, and does not block
reasoning about the rest of the coordination boundary, which is
independently sound regardless of how this question is eventually
resolved.

## Binding-chain completeness and substitution-attack analysis (E6)

`authority → signed authorization → exact plan digest → exact
authorized step → exact target identity → current live preconditions →
one-time execution attempt → sealed executor/state transition`

| Link | Status | Closed by |
|---|---|---|
| authority → signed authorization | Closed | `PinnedAuthoritySet` (`ADR-012` precedent, reused unchanged) |
| signed authorization → exact plan digest | Closed | `plan_authorization_authorizes_step()` (Phase D) |
| → exact authorized step | Closed | Same function, same call |
| → exact target identity | **Open** — see `target_identity_digest` above | Deferred, named explicitly, not silently accepted |
| → current live preconditions | Open until Phase E's freshness re-check is built | This document specifies its exact design (above); not yet implemented |
| → one-time execution attempt | Closed in design, not yet wired | Phase D's `try_consume()` exists; this document specifies exactly where it must be called (step 8) |
| → sealed executor/state transition | Closed, unaffected | Existing, already-hardened `RecoveryContract`/`MutationExecutor` machinery |

Adversarial walk-through (mental, no code):

- **Same step ID in another plan**: closed — exact `plan_digest` match
  required, `step_id`s alone are never sufficient (Phase D, already
  tested).
- **Same plan sent to another appliance**: **open**, per
  `target_identity_digest` above — the one substitution class this
  document cannot currently close.
- **Stale plan**: closed once Phase E's freshness re-check (this
  document's design) is built; open until then, by design (not yet
  authorized for implementation).
- **Modified target**: closed at the `RecoveryContract` layer (existing
  `target_fingerprint` drift detection at `execute()` time) —
  a different layer than plan-level authorization, already hardened,
  unaffected by anything in this document.
- **Authorization replay**: closed by `try_consume()`, once wired at
  the proposed ordering position (step 8).
- **Authorization reordering**: not applicable — `authorized_step_ids`
  membership is already order-independent by design (Phase D, tested).
- **Alternate serialization**: not applicable — no serialization format
  exists (a deliberate Phase C decision); nothing to attack.
- **Plan reconstructed with semantically similar but non-identical
  values**: closed — `canonical_json()`'s exact byte-level hashing
  makes any value difference produce a different digest (Phase B,
  extensively tested).
- **Target restored from snapshot**: covered at the `RecoveryContract`
  layer (existing fingerprint drift detection), not a plan-level
  concern this document needs to re-solve.
- **Executor called directly / coordinator bypass**: see E7.
- **Consumption store rollback/copy**: an inherited, acknowledged
  limitation, not a new one — identical in kind to
  `SqliteRecoveryContractStore`'s own already-accepted threat model
  ("a same-effective-user attacker who already has file-level access
  this store's threat model does not attempt to defend against," per
  `rate_cooldowns`'s own existing comment). A restored/copied
  consumption-store file could resurrect an "unconsumed" state for an
  already-consumed ID — this is a file-system-level trust boundary this
  project has never claimed to defend against for *any* of its stores,
  not a gap introduced by this design specifically.
- **Crash after consumption**: analyzed fully in "Consumption
  semantics" above.
- **Concurrent execution attempts**: closed at both layers — the
  consumption store's own atomic insert-once (Phase D, tested with a
  real 8-thread race) and `RecoveryContract`'s own existing atomic
  target-reservation CAS (`test_same_target_cannot_be_acquired_concurrently`,
  already in the suite).

## Direct-executor bypass resistance (E7)

**Honest finding: bypass resistance here is a construction-site and
process/review-level guarantee, not a language-level or type-system
guarantee — exactly like every other Tier 1 boundary already is.**
Python has no access-control mechanism that prevents a caller holding a
reference to `MutationExecutor`/`SqliteRecoveryContractStore` from
calling their methods directly. The actual, already-proven-effective
mechanism this codebase relies on everywhere (not invented by this
document) is: **nothing constructs the sensitive object in the first
place, until an explicit, gated activation decision, and the object is
never exposed beyond its own construction site.**

Concretely, for this boundary:

- **Today**: `MutationExecutor` is unreachable — nothing in
  `Application`/`factory.py`/`server.py` constructs one. This alone is
  the primary defense right now, and it is unaffected by this document
  (no construction site is added).
- **Once Milestone 9 activation happens** (a separate, future,
  independent decision — unaffected by this document): the proposed
  `ExecutionCoordinator` (E1) must be the **only** object any future
  activation-time wiring constructs with direct references to both
  `SqliteRecoveryContractStore` and `MutationExecutor`. Neither should
  ever be exposed as a public attribute a future MCP WRITE tool (Phase
  H, not built) could reach independently — the tool must receive only
  a reference to the coordinator itself.
- **Enforcement mechanism, proposed for a future implementation**: a
  new, narrow AST isolation-test rule (not built in this pass),
  mirroring `test_isolation.py`'s existing `executor_only_import_roots`
  exception exactly — extended to name `ExecutionCoordinator` as a
  second, sealed exception authorized to import
  `write_api_client`/`pfsense_client`-adjacent machinery (via
  `MutationExecutor`), with every other `tier1/*.py` module (and any
  future `tier1/adapters/*.py`) still forbidden.
- **What this does *not* prevent**: a contributor with commit access
  writing new code that imports `MutationExecutor` directly. This is
  **explicitly outside this project's threat model** — `THREAT_MODEL.md`'s
  own local-stdio trust framing defends against a malicious/compromised
  MCP client or AI model interacting with an already-deployed,
  already-reviewed server, not against a malicious contributor
  modifying the server's own source. Stated explicitly here so the
  boundary's actual scope is never assumed broader than it is.

**This is a meaningful, enforceable boundary within its stated scope**
(review-time + AST-test-time, matching the codebase's own established
pattern), and its limitation (does not defend against a
source-modifying attacker) is stated plainly rather than left implicit,
per the task's own instruction.

## `DeprovisionAuthorization` decision (E9)

**Recommendation: continue deferring, unchanged.** No parallel
verifier, no shared machinery built now. Reasoning: (a) `ADR-022`
itself already, explicitly defers this ("a future, separate,
explicitly-scoped ADR"); (b) no destructive execution mechanism exists
to consume one even if verification existed; (c) `target_identity_digest`
construction for a *real* destructive target is at least as hard a
problem as Question B above, arguably harder (a wrong destructive-target
binding is catastrophic in a way a wrong ordinary-mutation binding is
not); (d) the task's own stated strong preference is to keep this pass
focused unless shared machinery is *proven* necessary now — it is not:
a future `verify_deprovision_authorization_signature()` would be a
near-identical, cheap-to-write mirror of the existing
`verify_plan_authorization_signature()` whenever it is actually needed,
not a piece of infrastructure that benefits from being built early.

## Public WRITE exposure (E10)

Unaffected by definition — this document adds zero production code.
42 READ / 0 WRITE, `WriteEndpoints` empty, 0/3 WRITE milestones active,
confirmed unchanged by validation (below).

## Trust boundaries (consolidated)

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Coordinator vs. MCP/AI request layer | Coordinator's own verification sequence | Any MCP-supplied reference/parameters | Coordinator never accepts authorization contents wholesale or a caller-supplied boolean (`ADR-022`'s existing "MCP WRITE boundary" invariant, unchanged, reused) |
| Coordinator vs. `MutationExecutor` | Coordinator (holds both store references) | Nothing — this is an internal, same-trust-level composition | Construction-site encapsulation + a future AST isolation-test exception (E7) |
| Coordinator vs. operator/signer | Operator's private key, entirely outside this process (`ADR-012` precedent, unchanged) | The coordinator itself — it never signs, never holds key material | `PlanAuthorization.proof` is the only channel; no code path here ever constructs one |
| Freshness re-check vs. live pfSense/TPM/witness state | The read-only `discover_security_posture()` path (existing, unchanged) | Nothing new — this document adds no new read path | Existing, already-reviewed discovery machinery |
| Consumption store vs. same-effective-user file access | N/A — explicitly out of scope, inherited from `store.py`'s own accepted threat model | A local attacker with file-level access to the consumption-store file | Not defended against, by design, consistent with every other Tier 1 store |

## Threat analysis (consolidated matrix)

| Threat | Disposition |
|---|---|
| Authorization forgery | Closed — `PinnedAuthoritySet`, reused unchanged |
| Replay | Closed once `try_consume()` is wired at the proposed ordering position |
| Expired authorization | Closed — `plan_authorization_is_current()`, independent check |
| Wrong signer | Closed — unknown/inactive authority fails closed in `PinnedAuthoritySet` |
| Signer-set downgrade | Closed — `algorithm` field checked before any signature attempt; no weaker algorithm accepted |
| Wrong plan | Closed — exact `plan_digest` match |
| Modified plan | Closed — any digest-participating field change produces a different digest (Phase B) |
| Wrong step | Closed — exact `authorized_step_ids` membership |
| Step-ID ambiguity | Closed — no wildcard/prefix/coercive matching exists structurally |
| Wrong target (appliance-level) | **Open** — see `target_identity_digest`, explicitly deferred |
| Target substitution (resource-level, within one appliance) | Closed — existing `RecoveryContract.target_fingerprint` drift detection |
| Stale target state | Closed once the freshness re-check (this document's design) is built |
| TOCTOU | Bounded per-transition (see table above); the 8→9 window is the one acknowledged, documented gap |
| Double execution | Closed — `try_consume()` (plan-level) + existing target-reservation CAS (mutation-level), two independent layers |
| Concurrent execution | Closed — same two layers |
| SQLite/store rollback (file restore) | Inherited, acknowledged, out of this project's stated threat model for any store |
| Copied consumption DB | Same disposition |
| Malformed consumption DB | Closed — fails closed (`AuthorizationConsumptionError`), tested |
| Storage failure | Closed — fails closed, tested |
| Crash windows | Mostly closed by existing `RecoveryContract` machinery; one acknowledged, documented gap at 8→9 |
| Process restart | Closed for everything except the 8→9 window (documented) |
| Network timeout (freshness read) | Must fail closed — a design requirement of the not-yet-built freshness component, stated explicitly here |
| API ambiguity | Existing `EffectKnowledge.AMBIGUOUS` → `RECONCILIATION` classification, unaffected |
| Direct executor bypass | Construction-site/process-level guarantee only — see E7 |
| State-machine bypass | Not possible — `state_machine.py`'s closed transition table is unaffected and unchanged |
| Recovery-path bypass | Not possible — unaffected, unchanged |
| Canonicalization disagreement | Closed — single shared `tier1.canonical` primitive reused everywhere |
| Digest domain confusion | Closed — `DigestPurpose` domain separation, reused unchanged |

## Alternatives considered

- **Fold authorization checks into `MutationExecutor` directly** (add
  `PlanAuthorization`/authorities parameters to `execute()`): rejected
  — violates G2 and the task's own strong default; would also
  conflate "an agent asked for execution" with "an owner approved the
  plan," exactly the merge `sealed_executor.md`'s own existing
  Authority-boundaries text already refuses to allow for confirmation.
- **A single, combined `verify_and_consume()` convenience function**:
  rejected — this is precisely what Phase D's own module docstring
  already warned against ("deliberately never composes them, so that
  composing them remains a decision made at the point real
  consumption/execution wiring is eventually, separately authorized").
  Composing them is exactly what the coordinator (E1) is for, and it
  should compose them with explicit, inspectable branching, not hide
  them behind one opaque call.
- **Place the coordinator in the `security_` family instead of
  `tier1/`**: considered; rejected as the primary recommendation
  because the coordinator's defining job (E7) is holding
  store/executor references exclusively, which is architecturally
  cleanest as a `tier1`-native, sealed class alongside `executor.py`
  itself — noted as a live alternative, not eliminated, since either
  placement is technically workable.
- **Extend `SqliteRecoveryContractStore`'s `contracts` table with an
  `authorization_id` column instead of a separate consumption store**:
  already rejected by the owner's own Phase D scope decision (`ADR-023`);
  not reopened here.
- **Bind appliance identity into `PlanDigest` itself now**: rejected —
  would retroactively alter an already-shipped, already-tested Phase B
  primitive; see `target_identity_digest` above.

## Rejected designs

- A "one successful execution" consumption semantic — rejected; reopens
  the exact replay window Phase D closed (see "Consumption semantics").
- A generic "authorization consumption" abstraction serving all three
  future mutation mechanisms (pfSense-API/config/hardware) at once —
  rejected for the same reason `ADR-022`'s own "Alternatives
  considered" rejected a universal `MutationExecutor`: the three
  classes have different durability answers (`ADR-022`'s own
  owner-review resolution), and a shared abstraction invented before
  the other two mechanisms have any real execution path risks being
  wrong for both.
- Implementing `target_identity_digest` now with a placeholder/best-
  guess design — explicitly rejected per the task's own instruction
  ("no placeholder design is acceptable here").

## Deferred work

- The freshness/precondition engine's core primitive (Slice E1) is
  **implemented** — see "Implementation status" above. Composing it
  with the other Phase D primitives and wiring it into an actual
  execution path (Slice E2/E3, the coordinator) remains fully
  deferred, not implemented.
- The execution coordinator itself (`ADR-022`'s own Phase F/G) —
  designed in detail above, not implemented.
- `target_identity_digest` for ordinary `PlanAuthorization` (Question B
  above) — fully deferred, prerequisites named.
- `DeprovisionAuthorization` verification and its own
  `target_identity_digest` (Question A above) — deferred by `ADR-022`
  itself, unchanged.
- The two-phase claim/commit consumption extension — named, not
  designed, not decided.
- Any MCP WRITE tool (Phase H) — untouched, gated on Milestone 9.

## Implementation slices for a future authorized coding phase

**Not authorized by this document. Listed for a future, separate
authorization to select from — prefer the earliest slices over later
ones; each should be independently reviewable and independently
mergeable.**

### Slice 1 — freshness re-check (pure comparison + I/O boundary split) — **implemented, see "Implementation status" above**

- **Files expected to change**: one new file (e.g.
  `security_plan_freshness.py`), sibling to
  `security_authorization_verifier.py`.
- **Files forbidden to change**: `security_plan.py`,
  `security_plan_digest.py`, `security_authorization.py`,
  `security_authorization_verifier.py`, anything in `tier1/`.
- **Public API additions**: a pure comparison function (fresh-plan
  digest vs. `authz.plan_digest`) plus a thin, separately-testable
  wrapper that performs the one I/O call
  (`generate_security_posture_plan()`).
- **Isolation rules**: no `pfsense_mcp.tier1` import at all (mirrors
  `security_plan.py`'s own existing invariant) — this module only needs
  `security_plan`/`security_plan_digest`.
- **Tests required**: fresh-matches-authorized (pass), fresh-differs
  (`STALE`), anomaly-detected (refuse, never `STALE`), I/O-failure
  (fail closed), no-mutation-of-inputs.
- **Adversarial tests**: stale plan with unchanged evidence,
  step-list-changed-but-evidence-fingerprint-unchanged (proves the
  "not sufficient alone" finding above), indeterminate current state.
- **Rollback/recovery considerations**: none — pure, no persistence.
- **Exact invariant established**: "a freshness check that passes means
  the live plan is byte-identical, right now, to the one
  `PlanAuthorization` was signed against."

### Slice 2 — `ExecutionCoordinator` skeleton, checks 3–8 only (no `store.create()`/`confirm()`/`execute()` calls yet)

- **Files expected to change**: one new file,
  `tier1/execution_coordinator.py`.
- **Files forbidden to change**: `tier1/executor.py`,
  `tier1/state_machine.py`, `tier1/store.py`, `tier1/contract.py`,
  `write_api_client.py`, `write_endpoints.py`.
- **Public API additions**: a class composing checks 3–8 (signature,
  expiry, scope, freshness, anchor, consumption) and returning an
  explicit, typed outcome (never a bare bool) — deliberately stopping
  *before* any `store.create()` call, so this slice cannot itself cause
  a `RecoveryContract` to exist.
- **Isolation rules**: the sixth narrow tier1-isolation exception (E1);
  a new, dedicated AST isolation test proving it imports nothing beyond
  the named allowed set and is imported by no production module.
- **Tests required**: full ordering test (each check gates the next);
  short-circuit tests (cheap checks fail before any I/O); consumption
  only reached after freshness+anchor pass.
- **Adversarial tests**: every row of this document's threat matrix
  that is "closed once wired" — re-verify each is actually closed by
  this slice's own composition, not merely asserted.
- **Rollback/recovery considerations**: none yet — no state-changing
  call beyond `try_consume()` exists in this slice.
- **Exact invariant established**: "reaching the end of this slice's
  own check sequence with a positive outcome means every Phase D check
  plus freshness plus anchor-appropriateness passed, and the
  authorization is now consumed — nothing about execution has happened
  yet."

### Slice 3 — wire `store.create()`/`confirm()`/`executor.execute()` behind the coordinator

- **Files expected to change**: `tier1/execution_coordinator.py`
  (extend, not `executor.py`/`store.py` themselves).
- **Files forbidden to change**: `tier1/executor.py`,
  `tier1/state_machine.py` (unchanged per G2 — this slice calls their
  existing public APIs, never modifies them).
- **Public API additions**: the coordinator's full, end-to-end call
  path — still never constructed by production (Milestone 9 gate
  unaffected).
- **Isolation rules**: the new AST exception from Slice 2 extended to
  cover `store`/`executor` imports too, mirroring
  `executor_only_import_roots`'s existing pattern for a second, named,
  sealed component.
- **Tests required**: full happy path against synthetic/mock stores and
  a synthetic adapter (mirroring `test_executor.py`'s own convention);
  crash-simulation between consumption and contract creation (proves
  the acknowledged gap's actual behavior, not just its written
  description).
- **Adversarial tests**: the full binding-chain walk-through (E6) run
  against real, constructed objects, not just reasoned about; a
  concurrency test proving two coordinator calls racing the same
  authorization yield exactly one `RecoveryContract`.
- **Rollback/recovery considerations**: none new — `rollback()` remains
  entirely `MutationExecutor`'s own, already-hardened responsibility,
  untouched by this slice.
- **Exact invariant established**: "the full authorization-to-execution
  chain is provably correct end-to-end against synthetic dependencies,
  still fully unreachable from any production entry point."

### Explicit stop conditions for each future slice

- Any slice that would require modifying `MutationExecutor`'s or
  `state_machine.py`'s existing public behavior — stop, report, do not
  widen.
- Any slice that would need to construct the coordinator from
  `Application`/`factory.py`/`ToolRegistry` before Milestone 9's own,
  separate activation decision — stop, that is Phase H's gate, not
  this one's.
- Any slice that discovers `target_identity_digest` is load-bearing for
  correctness (not merely defense-in-depth) — stop, that reopens
  Question B above and needs its own owner decision first.

## Validation before commit

`ruff format --check .`, `ruff check .`, `mypy` (repository's
established invocation: `mypy src/pfsense_mcp scripts lab witness_daemon`),
full pytest suite, `mkdocs build --strict`, and a diff/grep confirmation
that `MutationExecutor`, `tier1/state_machine.py`, and every existing
production `.py` file are byte-identical to the pre-pass checkpoint —
see the final report for actual results.

## References

- [`ADR-022`](ADR-022-execution-authorization-boundary.md) — the
  accepted design this document proposes detail for; authoritative for
  every decision not re-decided here.
- [`ADR-023`](ADR-023-authorization-verification-boundary.md) — Phase D's
  own design record and the owner's scope decisions this document
  builds directly on.
- [`ADR-021`](ADR-021-security-posture-provisioning.md) — the
  two-axis validity constraint the anchor-appropriateness check (step
  7) reuses unchanged.
- [`ADR-013`](ADR-013-reconciliation-authority.md),
  [`ADR-015`](ADR-015-rate-and-blast-radius-defaults.md),
  [`ADR-020`](ADR-020-milestone-0-first-write-capability-candidate.md) —
  read in full for this pass; none materially contradict the proposed
  boundary.
- [`sealed_executor.md`](../tier1/specs/sealed_executor.md) — the
  Authority-boundaries/Lifecycle precedent this document's coordinator
  design mirrors directly.
- `src/pfsense_mcp/tier1/store.py`, `state_machine.py`, `executor.py`,
  `write_api_client.py`, `write_endpoints.py`,
  `src/pfsense_mcp/security_authorization.py`,
  `security_authorization_verifier.py`,
  `tier1/authorization_consumption_store.py`,
  `src/pfsense_mcp/models/system.py`, `models/system_ha_sync.py` — read
  in full while preparing this document; no code changed.
