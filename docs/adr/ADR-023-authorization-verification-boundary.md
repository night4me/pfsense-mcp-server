# ADR-023: Authorization-verification boundary (`ADR-022` Phase D)

- **Status:** Proposed — architecture/planning only. No code, no
  storage schema, no MCP tool, no runtime authorization consumption.
  Does not authorize implementation of any kind.
- **Date:** 2026-08-11

## Context

`ADR-022` (Accepted) defined the `Plan → Authorize → Execute → Verify`
boundary and named its own recommended implementation sequence (Phase
A acceptance, B `PlanDigest`, C authorization data model/signing, D
authorization *verification*, E freshness engine, F/G execution
coordinators, H MCP WRITE exposure). Phases B and C are implemented and
pushed (`b5edc57`, then `e8dc037`/`f3cbcef` after a final adversarial
pre-push review found and fixed one real coercion-safety defect in
`PlanAuthorization.risk_class` validation — see `reports-ai/` for that
review's own record; not restated here since it changed nothing about
the accepted schema). Current authoritative security checkpoint:
`f3cbcef6b6fcced8678e7f613e4589432b87d9fb`.

This document is a **planning pass only**, requested to determine what
Phase D should contain, what trust boundaries and primitives are still
missing between a signed `PlanAuthorization`/`DeprovisionAuthorization`
and any future safe WRITE execution, and to propose the smallest
coherent next boundary — without implementing it, without activating
WRITE, and without foreclosing security models that remain genuinely
open. It is written in the same Proposed → Owner review → Accepted
shape `ADR-021`/`ADR-022` themselves used, because that is this
project's own established way of separating "what an AI has designed"
from "what an owner has authorized."

### What already exists (verified by reading the actual shipped code, not assumed)

- `security_plan.py` (`ADR-021`) — `SecurityPosturePlan`/`PlanStep`,
  read-only planning, never imports `pfsense_mcp.tier1`.
- `security_plan_digest.py` (`ADR-022` Phase B) — `compute_plan_digest()`/
  `verify_plan_digest()`, `evidence_fingerprint_payload()` (made public
  for Phase C's reuse). Pure, no I/O.
- `security_authorization.py` (`ADR-022` Phase C) — `PlanAuthorization`/
  `DeprovisionAuthorization` dataclasses, their canonical signing
  payloads (domain-separated via an explicit `"digest_purpose"` field
  and two new `DigestPurpose` members), `build_*_payload()`/`sign_*()`
  pure functions over caller-supplied `Ed25519PrivateKey` material. No
  verification, consumption, persistence, or CLI/MCP exposure exists in
  this module by design.
- `tier1/confirmation.py`/`confirmation_providers.py`/`ed25519_authority.py`
  (`ADR-012`) — the existing, Accepted, production-shaped precedent for
  exactly the kind of verifier Phase D needs: `Ed25519ConfirmationVerifier`
  checks a detached signature against a `PinnedAuthoritySet` (a
  validated, immutable `(authority_id, public_key, active)` tuple set),
  never raises for ordinary evidence, never distinguishes *why* a
  signature failed in its return value (`verify() -> bool` only).
- `tier1/reconciliation.py`/`reconciliation_providers.py` (`ADR-013`) —
  a second, independent instance of the same verification pattern,
  proving it generalizes (two artifact types, two `DigestPurpose`
  domains, one shared `PinnedAuthoritySet` mechanics module).
- `tier1/contract.py`/`state_machine.py`/`store.py`/`executor.py`
  (`ADR-006`/`014`) — the only mechanism in this repository that
  actually mutates pfSense today (still fully inert: `WriteEndpoints`
  empty, no capability active). `SqliteRecoveryContractStore` is an
  authenticated (per-row HMAC), compare-and-set, crash-recovering
  (`reconcile_interrupted()`) store — the concrete precedent this
  document reasons against for "does Phase D need a new store."
  `RecoveryContract.confirm()` already demonstrates the exact pattern
  Phase D's verification step should mirror: load → check expected
  version/expiry → `evidence.verify_bindings(contract)` → look up a
  configured verifier → `verifier.verify(evidence)` → only then produce
  a new, atomically compare-and-set state.
- `docs/adr/ADR-022-execution-authorization-boundary.md`'s "MCP WRITE
  boundary" section already names the exact 9-step ordering a future
  WRITE tool must enforce, and states explicitly that step 3
  ("Referenced `PlanAuthorization` exists, is unexpired, unrevoked, and
  its `plan_digest`/`authorized_step_ids` include the requested
  operation") and step 4 (the freshness re-check) are "new, this ADR."
  Phase D is step 3. Step 4 (freshness) is `ADR-022`'s own Phase E,
  explicitly a separate phase — this document treats that boundary as
  already decided and does not reopen it (see "Scope" below).

## Terminology (new for this document)

| Term | Meaning |
|---|---|
| **Verification** | Checking that a `PlanAuthorization`/`DeprovisionAuthorization`'s `proof` is a valid signature over its own canonical payload, by a currently-active pinned authority. Pure, stateless, no persistence required. |
| **Consumption** | Durably recording that a specific `authorization_id` has been used to gate one, and only one, `RecoveryContract` creation (or equivalent for the other two mechanism classes) — the replay-prevention half of Phase D, distinct from verification. |
| **AuthorizationRecord** | Working name (not committed to a schema by this document) for whatever durable row Phase D ends up needing, if it needs a new one — see "Consumption persistence: options" below. |

## Scope: what Phase D is, and, just as importantly, what it is not

Reusing `ADR-022`'s own Phase D description verbatim as the scope
anchor: **"authorization verification, no execution. Server-side
`verify_bindings()`-equivalent logic, storage/retrieval by
`authorization_id`, expiry/replay checks — provably correct against a
battery of the threat-model rows above, still connected to nothing
that mutates anything."**

Explicitly **not** Phase D (per `ADR-022`'s own phase list, unchanged
by this document):

- **Freshness re-check** (comparing a `PlanAuthorization`'s
  `evidence_fingerprint` against a *newly run* `discover`) is Phase E.
  Phase D's expiry check is a pure timestamp comparison
  (`now < expires_at`); it is not a re-derivation of current evidence.
- **Execution** of any kind (Phase F/G) — no `RecoveryContract` is
  created, no config file is edited, no TPM command is issued by
  anything this document proposes.
- **MCP WRITE exposure** (Phase H) — no MCP tool, no schema change.
- **`DeprovisionAuthorization` verification** — see "Deferred: `DeprovisionAuthorization`
  verification and target-identity construction" below. Genuinely
  separate from `PlanAuthorization` verification and not required to
  unblock the named Milestone 0 candidate (an ordinary, non-destructive
  `CONFIGURATION`-class step).

## Analysis: trust boundaries and missing primitives

### 1. Authorization consumption/verification boundary

**What's missing today**: nothing in this repository can currently
answer "is this `PlanAuthorization` a validly-signed artifact from an
authority this deployment trusts?" — `security_authorization.py`
deliberately has no verifier (module docstring: "there is no consumer,
verifier, or executor here at all"). This is the core Phase D gap.

**Proposed primitive**: a pure function, structurally identical to
`Ed25519ConfirmationVerifier.verify()`, checking `proof` against
`plan_authorization_signing_payload(payload)` (reconstructed from the
artifact's own fields — never trusting a caller-supplied payload, the
same "recompute, never trust" discipline `compute_plan_digest()` and
`verify_plan_digest()` already established in Phase B) using a pinned
`(authority_id, public_key, active)` set. This is signature
verification only — it says nothing about expiry or replay (see below)
and nothing about freshness (Phase E).

**Where it lives in the call graph, per `ADR-022`'s own step ordering**:
*before* `RecoveryContract` creation, *never* inside `MutationExecutor`
(`sealed_executor.md`'s "Executor responsibilities" list has no
`PlanAuthorization`-shaped step at all — by design, since the executor
operates purely on an already-`PREPARED`, already-confirmed
`RecoveryContract`; it has no concept of a Plan). This means Phase D's
verifier is a **new, small, independent component**, not an extension
of `MutationExecutor`, `SqliteRecoveryContractStore`, or any existing
class — it sits upstream of contract PREPARE, in whatever future
component actually handles a WRITE tool's `AuthorizationRequest`-shaped
input (itself still Phase H, not built).

### 2. Replay and one-time-use semantics

**What's missing**: `authorization_id` is a signed field
(`security_authorization.py`), but nothing tracks whether one has ever
been used. Signature validity alone is not single-use — the same valid
signature verifies every time it is checked, by design (that is what
makes it *verifiable*, not what makes it *non-replayable*).
Replay-prevention requires state, and state requires a decision about
where that state lives (see "Consumption persistence: options" below).

**Threat this closes**: `ADR-022`'s own threat-model row "Replay of a
consumed/expired authorization — Closed — Single-use `authorization_id`
+ `expires_at`, mirroring `RecoveryContract.with_confirmation()`'s
existing single-confirmation guarantee." Phase D is where that "Closed"
classification actually becomes true in code, not merely in design
intent.

### 3. Authorization expiry enforcement

**Simple and already fully specified**: `expires_at` is a UTC
`datetime`, already validated at construction (Phase C). Expiry
enforcement is `now >= artifact.expires_at` at the moment of
verification — no new primitive, no new invariant, just a comparison
using the same clock discipline `SqliteRecoveryContractStore._now()`
already uses (fail closed if the supplied clock is not UTC-aware).
**Not** freshness (Phase E) — expiry asks "has too much time passed
since this was signed," freshness asks "does current evidence still
match what was reviewed." Both are required; neither substitutes for
the other (`ADR-022`'s own "Freshness/TOCTOU model" section already
makes this distinction explicitly).

### 4. Plan/step binding at execution time

Already fully designed by Phase C and unchanged by this document:
`plan_digest` + `authorized_step_ids` are signed, exact-match fields.
Phase D's job is to check that a *specific requested step* (from
whatever future caller) is a member of `authorized_step_ids` **and**
that the plan digest supplied alongside the request matches the
artifact's own `plan_digest` exactly — never "the current plan," always
"this one." This is a pure comparison against already-signed,
already-verified fields; it requires no new cryptography.

### 5. Target identity binding — `target_identity_digest`

**Explicitly out of Phase D's scope**, and this document does not
attempt to resolve it, per the task's own instruction not to invent
target-identity construction here. `DeprovisionAuthorization.target_identity_digest`
remains, as `security_authorization.py`'s own docstring already states,
"an already-computed, caller-supplied 64-hex-character digest" with no
defined derivation from a real TPM NV index or store key anywhere in
this repository. Verifying a `DeprovisionAuthorization`'s *signature*
is mechanically identical to verifying a `PlanAuthorization`'s (same
pattern, different `DigestPurpose`/field set) and could be built
alongside Phase D's `PlanAuthorization` verifier at low incremental
cost — but doing so would create a working verification path for an
artifact type this repository still cannot construct *meaningfully*
(no real target to bind it to) and, per `ADR-022`'s own "Destructive
operations" section, no execution mechanism exists to consume it
regardless. **Recommendation: do not build `DeprovisionAuthorization`
verification in Phase D.** Building a verifier for an artifact type
with no real construction path and no consumer would be exactly the
"premature scaffolding" this project's own conventions warn against
(see `confirmation_providers.py`'s own precedent: `PinnedAuthority`
construction from real config was explicitly deferred "once something
actually constructs the executor that consumes it"). Left fully
deferred to a future, separate, explicitly-scoped ADR, exactly as
`ADR-022`'s "Destructive operations" section already anticipates.

### 6. Signer/public-key trust and authority resolution

**What exists**: `tier1/ed25519_authority.py`'s `PinnedAuthority`/
`PinnedAuthoritySet` already implement exactly this mechanism
(validated, immutable, `authority_id`-keyed, `active`-flag rotation) —
reused twice already (confirmation, reconciliation).

**Open question, not resolved by this document**: does a
`PlanAuthorization` verifier reuse the *same* pinned-authority table
`ConfirmationEvidence`/`ReconciliationEvidence` use, or does it need
its own, separate table? Arguments both ways exist and this is
precisely the kind of choice the task asked not to be made
unilaterally here:

- **Shared table**: simpler, fewer moving parts, matches "the operator"
  being one trust anchor across every artifact type in this design so
  far. `DigestPurpose` domain separation already prevents a
  confirmation signature from verifying as a plan-authorization
  signature even if the *same* key signs both, so sharing keys is not
  itself a security weakness the way sharing keys across genuinely
  different trust domains would be.
- **Separate table**: allows an operator to delegate "which plans get
  authorized" to a different key/person/process than "which individual
  mutations get confirmed" — a real separation-of-duties property
  `ADR-013`'s own "Future migration path" section already flags as a
  *possible* future need for reconciliation specifically ("multi-party
  approval... requiring two distinct `authority_id` signatures"). Given
  `PlanAuthorization` sits at a *higher* level of the trust hierarchy
  than an individual confirmation (`ADR-022`: "structurally mirrors
  `ConfirmationEvidence` one layer up"), a deployment might reasonably
  want a *stronger*, more restricted key for it, not the same one.

**Recommendation, not a decision**: `PinnedAuthoritySet`'s existing
mechanics (`ed25519_authority.py`) should be reused either way — the
open question is only "one pinned-authority *table*, configured once"
vs. "a second, `PlanAuthorization`-specific pinned-authority table,"
never a new cryptographic mechanism. This is an owner-level
configuration-shape decision, not an implementation blocker either way.

### 7. Persistence/state requirements — "Consumption persistence: options"

This is the single largest open architectural question this document
identifies, and it is deliberately left as **options**, not a decision.

`ADR-022`'s owner review (question 1) already resolved this for
config-class and hardware-class steps ("no new store" — durability
comes from git's own commit graph and the TPM/store's own "derive
state, don't trust a log" discipline, respectively). It explicitly did
**not** resolve it for the pfSense-API-mutation class, whose execution
mechanism (`RecoveryContract`/`MutationExecutor`) already has its own
durable, authenticated store. Three options exist for *that* class
specifically:

| Option | Mechanics | Strengths | Costs |
|---|---|---|---|
| **A. Extend `SqliteRecoveryContractStore`'s existing `contracts` table** with an `authorization_id` column, `UNIQUE`, populated at `create()` time (compare-and-set, same transaction as contract creation) | Reuses the exact authenticated, crash-recovering, compare-and-set machinery already proven for `idempotency_key`/`operation_id` uniqueness | No new schema/store/threat surface to review; "has this `authorization_id` been consumed" becomes "does a contract row already reference it," free from the store's own existing uniqueness enforcement | Couples `PlanAuthorization` consumption 1:1 to `RecoveryContract` creation — correct for the pfSense-API-mutation class specifically, but would need a *different* answer if a future capability ever authorizes multiple `RecoveryContract`s from one `PlanAuthorization` (not true today: `authorized_step_ids` already names a bounded, specific set, and nothing in `ADR-022` suggests one authorization should span multiple contracts) |
| **B. A new, small, dedicated table** (own file or a new table inside the existing store), recording only `authorization_id` + consumed-at, checked before contract creation, independent of contract state | Cleanly separates "was this authorization ever used" from "what did it get used for" — works even if a future authorization type doesn't map 1:1 to a `RecoveryContract` | A fourth SQLite table/mechanism to review, test, and reason about for crash-safety, mirroring the exact "new persistence primitive" cost `ADR-022`'s question-1 resolution avoided for the other two mechanism classes |
| **C. No new persistence at all** — rely on `plan_digest` exact-match plus a *short* `expires_at` (per `ADR-022`'s own "risk-dependent granularity" table: short lifetimes for every risk class) to bound the replay window, accepting that a replay within that short window before first use is not structurally prevented | Zero new schema, matches config/hardware-class steps' own "no new store" resolution | Weakens the explicit "Replay of a consumed/expired authorization — Closed" threat-model row from a structural guarantee to a time-bounded one — a real security regression relative to what `ADR-022`'s own text already claims. **Not recommended by this document**, listed for completeness only |

**This document's non-binding lean**: Option A is the narrowest,
lowest-new-surface choice that still keeps the "Closed" threat-model
classification structurally true (not merely time-bounded), and it
extends a store this project's own security review has already
scrutinized extensively rather than introducing a fourth table. But
this is exactly the kind of schema-shape choice with more than one
viable security model that should not be locked in inside a planning
pass — **flagged as an owner/architecture decision required before
Phase D implementation begins**, not resolved here.

### 8. Crash/restart behavior

Fully specified already by `ADR-022`'s own "Crash/restart semantics"
table and "Persisted authorization is never a bearer capability"
subsection (Accepted, unchanged, not reopened by this document): every
use of a `PlanAuthorization`, regardless of persistence or restart,
requires — unconditionally, at time of use — (1) exact `plan_digest`
match against a freshly recomputed plan, (2) unexpired, (3) unconsumed,
(4) passing freshness re-check (Phase E, not Phase D). Phase D
implements checks (2) and (3); check (1) is already implemented (Phase
B/C); check (4) is explicitly deferred to Phase E. If Option A above is
chosen, crash-safety comes for free from the existing store's own
`reconcile_interrupted()`/compare-and-set transaction discipline — no
new crash-recovery logic would need designing. If Option B is chosen,
Phase D would need to specify its own crash-safety story explicitly
(likely: an insert is atomic and durable the moment it commits, so
there is no partial-write state to reconcile — but this should be
stated, not assumed, whichever option is chosen).

### 9. Concurrency/race conditions

Two processes/sessions attempting to consume the same `authorization_id`
simultaneously must not both succeed. Option A gets this for free from
SQLite's own `BEGIN IMMEDIATE` + `UNIQUE` constraint (the exact pattern
`create()`'s `sqlite3.IntegrityError` → `ContractConflictError` handling
already uses for `idempotency_key`/`operation_id`). Option B would need
the identical transactional discipline applied to its own table. Either
way, this is **not a new concurrency model** — it is the same
atomic-compare-and-set discipline already proven correct for every
other uniqueness constraint in this store, applied to one more column
or one more table.

### 10. TOCTOU risks between authorization and mutation

`ADR-022`'s own "Freshness/TOCTOU model" already names three mandatory
re-check points (before `AUTHORIZED`, immediately before `EXECUTING`,
between steps of a multi-step authorization) — all three are Phase E's
job, not Phase D's. Phase D's own, narrower TOCTOU concern is smaller:
between "verify the signature and check consumption" and "actually
record consumption," could two concurrent callers both pass
verification and both believe they consumed it first? Answered by #9
above (atomic compare-and-set at the consumption-recording step, not
at the earlier signature-verification step, which is stateless and can
safely run concurrently any number of times).

### 11. Recovery Contract interaction

No change to `RecoveryContract`, `state_machine.py`, or
`MutationExecutor` is proposed by this document. Per #1 above, Phase
D's verifier is a precondition checked *before* `RecoveryContract`
creation (`store.create()`), never inside `MutationExecutor.execute()`
(which already correctly has no concept of a Plan). If Option A (extend
the `contracts` table) is eventually chosen, the only touch point on
existing code would be `RecoveryContract`'s own field list (adding
`authorization_id`) and `create()`'s existing validation — still no
change to the state machine, the executor, or any transition rule.

### 12. Witness/TPM interaction — required vs. optional

Already resolved by `ADR-021`'s existing validity constraint
(`write_protected` requires anchor assurance `≠ none`), which
`PlanDigest`/`plan_digest` already binds (Phase B: `target_validity`
participates in the digest). Phase D introduces **no new** TPM/witness
requirement: a `PlanAuthorization` for a `write_protected`-targeting
plan can only ever have been signed against a `plan_digest` that itself
encodes a valid (already anchor-appropriate) target — an invalid
combination never reaches `generate_security_posture_plan()`'s output
in the first place (`security_plan.py`'s own, already-tested
enforcement). TPM/witness therefore remains **optional at the Phase D
layer specifically** (Phase D's verifier never calls
`discover_security_posture()`, the TPM, or the witness daemon itself —
it is pure, like Phase B/C before it) while remaining **required at the
plan-generation layer**, exactly as today. Phase D must not weaken this
by, for example, allowing a `PlanAuthorization` to be verified without
reference to a `plan_digest` at all — the existing schema already
prevents this structurally (no such field-optional path exists).

### 13. Audit/evidence requirements

`TIER1_ROADMAP.md`'s Milestone 6 work item ("Audit event identity,
contract ID, capability, endpoint symbol, target digest, transition,
duration, and sanitized outcome only") already names the audit
discipline any future Phase D consumption-recording must follow if
Option A or B (above) is chosen: an audit event for "authorization
consumed" should record `authorization_id`, `plan_digest`, the
resulting `contract_id` (if Option A), and a timestamp — never the
`proof` bytes, never plaintext plan content, matching
`store.py`'s own existing `_insert_audit()` value-free discipline
exactly (event type + identifiers + state, never payload).

### 14. Fail-closed behavior

Mirrors `Ed25519ConfirmationVerifier`'s own already-Accepted pattern
exactly: an unconfigured verifier (no pinned authorities) must refuse
to construct, not silently accept everything (`store.confirm()`'s
existing `if verifier is None: raise ConfirmationError(...)` is the
precedent). A malformed, wrong-domain, or invalid-signature
`PlanAuthorization` must be refused generically (never distinguishing
*why* in a caller-visible way, matching Invariant I4's existing
"sanitized failure class" discipline) — never partially trusted, never
falling back to "treat as unauthorized but proceed read-only" (there is
no such graceful-degradation mode in this design; refusal is refusal).

### 15. Rollback/recovery implications

None. Phase D never reaches `MutationExecutor.rollback()` or anything
downstream of `EXECUTING` — it is a precondition check that runs, at
latest, once, before a `RecoveryContract` is even created. No new
rollback semantics are introduced or required.

### 16. Security invariants that must remain true for READ-only deployments

Every invariant already true today must remain true after Phase D,
verified explicitly (not assumed) as part of Phase D's own acceptance
criteria, mirroring `security_plan_digest.py`/`security_authorization.py`'s
own "no I/O" behavioral proofs:

- Phase D code must be **reachable and importable with zero behavioral
  effect** on a `read_only`-profile, WRITE-inactive build — a
  `read_only` deployment never calls a WRITE tool, so a Phase D
  verifier that is never invoked must not, by its mere existence,
  change any READ-path behavior, tool count, or schema.
- Constructing a Phase D verifier (if it requires configuration, e.g.
  a pinned-authority table) must **not** be a step any existing
  `Application`/`factory.py` construction path performs today — it
  must remain unwired, exactly like `Ed25519ConfirmationVerifier` and
  `MutationExecutor` are unwired today, until a future, separate
  activation decision (Milestone 9) wires it in alongside real WRITE
  activation.
- 42 READ / 0 WRITE tools, `WriteEndpoints` empty, WRITE 0/3 active
  must remain true after Phase D exists in the repository, exactly as
  it remained true after Phase B and Phase C (verified this document's
  own validation run, see below).

## Architectural dead ends or assumptions from Phases A–C, reviewed for Phase D difficulty

Searched deliberately for anything that would make safe execution
harder later, not merely re-confirmed the design is fine:

- **No dead end found in `PlanAuthorization`'s field shape.** Every
  field Phase D needs to check (`plan_digest`, `authorized_step_ids`,
  `expires_at`, `authorization_id`, `authority_id`, `algorithm`,
  `proof`) already exists, already signed, already validated. Nothing
  needs to be added to the schema for Phase D to function — this is a
  positive finding, not merely an absence of a negative one.
- **`security_authorization.py`'s deliberate exclusion of a
  `DigestPurpose`-based audit-binding property** (unlike
  `ConfirmationEvidence.evidence_digest`) means Phase D's own
  consumption-audit record, if any, will need to construct its own
  value-free binding (e.g., hash of `authorization_id` +
  `plan_digest` + outcome) rather than reusing an existing property —
  a small, expected addition, not a gap requiring rework.
- **`MutationExecutor` has zero awareness of `PlanAuthorization` by
  design** (confirmed by reading `executor.py` in full) — this is
  correct, not a dead end: it means Phase D's verifier is free-standing
  and does not require any change to already-reviewed executor code,
  which is exactly the "narrow, independently testable primitive"
  shape this document was asked to prefer.
- **One real ambiguity worth flagging, not a dead end**: `ADR-022`'s
  Decision item 4 field table lists `evidence_fingerprint` as letting
  "a verifier re-validate freshness without needing to still hold the
  original `Plan` object" — but freshness re-validation is Phase E, not
  Phase D. This means `evidence_fingerprint` is a field Phase D's
  verifier will *carry* and *return* (so a future Phase E can use it)
  but will **not itself check** against anything — worth stating
  explicitly in any future Phase D implementation's own scope section,
  so a reviewer does not mistake "Phase D reads this field" for "Phase
  D validates freshness."
- **No assumption found that would force a specific persistence choice
  later.** All three consumption-persistence options in #7 above
  remain fully compatible with the schema as shipped — Phase C did not
  quietly foreclose any of them (e.g., it did not embed a
  `RecoveryContract`-specific field into `PlanAuthorization` itself,
  which would have implicitly favored Option A). This is a second
  positive finding: the architecture through Phase C is genuinely
  neutral on this open question, not accidentally biased toward one
  answer.

## Proposed smallest coherent Phase D boundary

Preferring narrow, independently testable primitives over wiring a
complete path, per the task's own instruction:

1. **A pure `verify_plan_authorization_signature()`-equivalent**
   (naming left to a future implementation turn), mirroring
   `Ed25519ConfirmationVerifier.verify()` exactly: takes a
   `PlanAuthorization` and a `PinnedAuthoritySet` (reusing
   `ed25519_authority.py` unchanged), reconstructs
   `plan_authorization_signing_payload()` from the artifact's own
   fields, returns `bool`, never raises for ordinary malformed/invalid
   input, distinguishes nothing about *why* in its return value. No
   persistence, no I/O, fully testable offline exactly like Phase B/C's
   own test suites.
2. **A parallel pure expiry check** (`now >= expires_at`), independent
   of signature verification, composable but separately testable.
3. **A pure "does this authorized_step_ids set include this requested
   step, under this exact plan_digest" check** — a simple membership +
   equality check over already-verified fields, no new cryptography.
4. **A decision, made by the owner before implementation, among the
   three consumption-persistence options in #7** — this document
   explicitly does not choose one. Once chosen, the actual persistence
   change (if any) is the only piece of this boundary that touches
   existing storage code, and it should be its own, separately
   reviewable slice even within Phase D.
5. **No `DeprovisionAuthorization` verifier** (per #5 above — deferred).
6. **No new MCP tool, no CLI subcommand, no wiring into
   `Application`/`factory.py`** — mirrors Phase C's own "library code
   only" boundary exactly. A future signing/verification tool or the
   eventual Phase H WRITE tool are expected callers, neither built here.

This keeps Phase D's *cryptographic and comparison* core (items 1–3)
fully narrow, pure, and independently testable/mergeable even before
the one genuinely open architectural question (item 4) is settled —
consistent with "prefer narrow, independently testable primitives over
wiring the complete WRITE path."

## Adversarial/threat matrix for the proposed boundary

| # | Attack | Disposition against the proposed boundary |
|---|---|---|
| 1 | Verifier accepts a `PlanAuthorization` signed by an unpinned/retired key | Closed by `PinnedAuthoritySet.verify_signature()`'s existing, already-tested `active`-flag/unknown-authority refusal — reused, not reinvented |
| 2 | Verifier accepts a `DeprovisionAuthorization` payload mistaken for a `PlanAuthorization` (or vice versa) | Closed structurally by the existing `"digest_purpose"` domain separation (Phase C) — a Phase D verifier that reconstructs the signing payload from the artifact's own declared type can never cross-verify, proven already by Phase C's own adversarial test suite |
| 3 | A verified-but-expired artifact is accepted | Closed by item 2 of the proposed boundary (independent, mandatory expiry check) — must never be skippable even if signature verification alone passes |
| 4 | A verified, unexpired, but already-consumed `authorization_id` is accepted a second time | Open until the consumption-persistence decision (#7) is made and implemented — **this is exactly the gap Phase D exists to close**; not yet closed by anything in this repository |
| 5 | Two concurrent callers both attempt to consume the same `authorization_id` and both succeed | Closed by design *if* Option A or B (#7) uses the same atomic compare-and-set discipline the existing store already proves correct for `idempotency_key`/`operation_id` — must be a stated requirement of whichever option is chosen, not assumed |
| 6 | A caller supplies a `plan_digest`/`step_id` pair not actually covered by the artifact, hoping a loose check accepts a superset/prefix match | Closed by exact-match requirement (item 3 of the proposed boundary) — `ADR-022`'s own text already states "binding is exact-match, not prefix/subset-permissive in the caller's favor" |
| 7 | A verifier silently treats "no pinned authorities configured" as "allow everything" | Must be closed by explicit fail-closed construction-time refusal (mirrors `Ed25519ConfirmationVerifier`'s own precedent) — a stated requirement for Phase D implementation, not yet built |
| 8 | A future caller mistakes "Phase D verified this" for "this is fresh/current" and skips Phase E | **Documentation risk, not a code risk** — must be stated explicitly and loudly in any Phase D implementation's own docstrings/spec (mirroring this document's own repeated "not freshness" callouts), since nothing in the proposed boundary structurally prevents a careless future caller from conflating the two if the distinction isn't kept prominent |
| 9 | An attacker who can write to the consumption-persistence store directly (Option A or B) marks an unconsumed `authorization_id` as already-consumed, causing a denial of legitimate use | Same threat model `SqliteRecoveryContractStore` already accepts and documents (`rate_cooldowns`' own comment: "a same-effective-user attacker who could tamper with it already has file-level access this store's threat model does not attempt to defend against") — not a new risk Phase D introduces, inherited unchanged from the existing store's threat model |
| 10 | A `PlanAuthorization` is verified and consumed for a genuinely different, but still valid-looking, target than the operator believed they were authorizing (a "confused plan" attack, not a forged-signature attack) | Not closeable by Phase D alone — this is exactly why Phase E's freshness re-check and the human-facing rendering step (`ADR-012`'s G5 precedent, "the human confirming can see, in full, what they are approving") both remain mandatory, unremoved, future requirements; Phase D's own signature/expiry/replay checks are necessary but explicitly not sufficient on their own, and this document does not claim otherwise |

## What already exists / what Phase D should implement / what must remain deferred / what requires an explicit owner decision

**Already exists** (Phases A–C, Accepted/implemented, unchanged by this
document): `PlanDigest` computation, `PlanAuthorization`/
`DeprovisionAuthorization` data models and signing, `PinnedAuthoritySet`
mechanics (reused twice already), `SqliteRecoveryContractStore`'s
authenticated compare-and-set/crash-recovery pattern, the full
`ADR-022` "MCP WRITE boundary" 9-step ordering specification.

**Phase D should implement** (once the one open decision below is
made): pure signature verification, pure expiry check, pure
plan-digest/step-membership check, and — per whichever
consumption-persistence option is chosen — either an
`authorization_id` column extension to the existing store or a small
new dedicated table, with matching crash-safety/concurrency/audit
treatment as detailed in this document's analysis sections.

**Must remain deferred** (unchanged, this document does not attempt
any of these): Phase E's freshness/precondition engine; Phase F/G
execution coordinators; Phase H MCP WRITE exposure; any
`DeprovisionAuthorization` verifier or real `target_identity_digest`
construction; any change to `MutationExecutor`, `state_machine.py`, or
the sealed-executor boundary; any WRITE tool, WRITE allow-list entry,
or capability activation.

**Requires an explicit owner/security decision before Phase D
implementation begins**:

1. **Consumption-persistence option** (#7): extend the existing
   `contracts` table (Option A, this document's non-binding lean), a
   new dedicated table (Option B), or accept a weaker,
   short-expiry-only guarantee (Option C, not recommended).
2. **Pinned-authority table scope** (#6): reuse the existing
   confirmation/reconciliation pinned-authority configuration, or
   introduce a second, `PlanAuthorization`-specific one for
   separation-of-duties. Either is viable; this document does not
   recommend one over the other.
3. Whether Phase D is worth implementing on its own *before* Phase E,
   given that a `PlanAuthorization` that passes Phase D's checks but
   has no freshness re-check yet still cannot safely gate any real
   mutation — i.e., should Phase D and Phase E be authorized and built
   together as one slice, or is there value in landing Phase D's pure,
   narrow primitives first as this document's "smallest boundary"
   section recommends? Both are legitimate sequencing choices; this
   document recommends the narrower first slice but does not treat
   that as decided.

## Non-goals (explicitly, for this document)

- Does not implement any verification, persistence, or MCP-facing code.
- Does not choose between the consumption-persistence options in #7.
- Does not choose the pinned-authority table scope in #6.
- Does not design `DeprovisionAuthorization` verification or real
  `target_identity_digest` construction.
- Does not modify, reopen, or supersede any `ADR-021`/`ADR-022`
  decision — every reference to their accepted text above is a
  restatement for this document's own reasoning, not a proposed change.
- Does not activate WRITE, add an MCP tool, or change the public
  contract in any way.

## Alternatives considered

- **Skip Phase D and go straight to a combined D+E+F "minimal execution
  slice"**: rejected for this planning pass — the task explicitly asked
  for the smallest coherent boundary and for narrow, independently
  testable primitives; collapsing verification, freshness, and
  execution into one slice would make each harder to review and test in
  isolation, the same reasoning `ADR-022`'s own phase list already used
  to split B/C/D/E/F/G apart in the first place.
- **Design a generic "authorization consumption" abstraction usable by
  all three future mechanism classes (pfSense-API, config, hardware)
  at once**: considered and rejected, for the same reason `ADR-022`'s
  own "Alternatives considered" section already rejected a universal
  `MutationExecutor`: the three classes have genuinely different
  durability answers (question 1's resolution), and forcing one
  abstraction over them now, before the config/hardware classes have
  any real execution mechanism to integrate with, risks exactly the
  "wrong universal design" failure mode this project has repeatedly
  avoided by keeping mechanism-specific reasoning separate.

## Future implementation phases (unchanged sequence, restated for continuity)

Mirrors `ADR-022`'s own list exactly; this document proposes detail for
Phase D only and does not alter the sequence:

- Phase A (`ADR-022` acceptance) — done.
- Phase B (`PlanDigest`) — implemented, pushed.
- Phase C (authorization data model + signing) — implemented, pushed,
  one corrective fix applied and pushed.
- **Phase D (this document's subject) — authorization verification, no
  execution — proposed, not yet authorized for implementation.**
- Phase E — freshness/precondition engine.
- Phase F — execution coordinator, `CONFIGURATION`-class mechanism only.
- Phase G — execution coordinator around `RecoveryContract`/
  `MutationExecutor`.
- Phase H — MCP WRITE exposure, gated on Milestone 9's own, independent
  activation decision.

## References

- [`ADR-022`](ADR-022-execution-authorization-boundary.md) — the
  accepted design this document proposes detail for; authoritative for
  every decision this document does not itself re-decide.
- [`ADR-021`](ADR-021-security-posture-provisioning.md) — the planning
  layer `PlanDigest`/`PlanAuthorization` bind to.
- [`ADR-012`](ADR-012-confirmation-authority.md),
  [`ADR-013`](ADR-013-reconciliation-authority.md) — the two existing,
  Accepted precedents this document's proposed verifier mirrors.
- [`ADR-006`](ADR-006-recovery-contract-philosophy.md),
  [`ADR-014`](ADR-014-sealed-executor-interface.md) — the execution
  machinery Phase D sits upstream of, unchanged by this document.
- [`EXECUTION_AUTHORIZATION_BOUNDARY.md`](../EXECUTION_AUTHORIZATION_BOUNDARY.md) —
  `ADR-022`'s companion spec and running implementation-status record.
- [`sealed_executor.md`](../tier1/specs/sealed_executor.md),
  [`confirmation_authority.md`](../tier1/specs/confirmation_authority.md) —
  the concrete implementation specs this document's proposal reuses
  patterns from.
- `src/pfsense_mcp/tier1/store.py`, `contract.py`, `executor.py`,
  `ed25519_authority.py`, `confirmation_providers.py` — read in full
  while preparing this document; no code changed.
