# ADR-022: Execution-authorization boundary (Plan → Authorize → Execute → Verify)

- **Status:** **Accepted** (2026-08-11, owner) — the execution-authorization
  boundary architecture (the per-`PlanAuthorization` state machine,
  `PlanDigest`, the `PlanAuthorization`/`DeprovisionAuthorization` design,
  the three-point freshness/TOCTOU model, per-step authorization, the
  AI/MCP trust boundary, the MCP WRITE boundary ordering, the Recovery
  Contract/anchor relationship, the destructive-operation separation, the
  failure taxonomy, and the threat-model findings) is the accepted design
  for how a future operator authorizes one specific planned mutation
  without turning target selection, plan generation, a stale plan, or an
  AI/MCP request into reusable or implicit mutation authority.
  **Acceptance is architectural only.** It does not authorize
  implementing `PlanDigest` computation, authorization-artifact
  construction/verification, any execution coordinator, any WRITE tool,
  `WriteEndpoints` population, WRITE activation, or fail-closed
  enforcement — each remains its own separate, later, explicitly-scoped
  authorization, exactly as `ADR-021`'s own acceptance note already
  established for its own architecture. See "Acceptance note" below.
- **Date:** 2026-08-11 (proposed and accepted the same day, after an
  owner review resolved four of the five originally open questions — see
  "Owner review (2026-08-11)" and "Acceptance note" below)

## Acceptance note

Owner accepted this ADR's architecture as written on 2026-08-11, after
the owner-review pass (see "Owner review (2026-08-11)" below) resolved
four of the five originally open questions and made the fifth's
deferral concrete rather than vague. Accepted, in summary: `discover`/
`plan` remain mutation-free and unchanged; plan generation and target
selection are never authorization; a `PlanAuthorization` is bound to one
exact `PlanDigest` and an explicitly enumerated, non-wildcard set of
step IDs, never an implicit grant over future steps; `DeprovisionAuthorization`
is a structurally separate artifact type a routine `PlanAuthorization`
can never substitute for; pfSense API mutations use `RecoveryContract`/
`MutationExecutor`, config-class mutations and hardware-class mutations
each use their own, different, future execution mechanism, and no
universal executor is implied; ordinary staleness, security anomaly,
authorization expiry, and replay remain four distinct, never-conflated
conditions; hardware-class authorization never survives a process
restart; a persisted authorization is never a durable bearer capability
— every use, regardless of age or persistence, requires a fresh
`plan_digest` match, an unexpired/unconsumed artifact, and a passing
freshness re-check; expiry and replay-resistance are accepted as
mechanisms, with exact numeric expiry durations remaining explicitly
provisional pending implementation-phase lab evidence, mirroring
`ADR-015`'s own accepted-mechanism/provisional-numbers precedent; and
overlapping/chained authorization across a future second WRITE
capability remains an explicit, named future decision, bound to that
future capability actually existing, and is not a blocker to this
acceptance.

Nothing about the decisions themselves — the state machine, the digest/
artifact designs, the freshness model, the trust boundaries, the
threat-model findings, or the reasoning in "Alternatives considered" —
changed as part of acceptance; this note records that the owner reviewed
and approved the already-written (and, in the owner-review pass, further
strengthened) architecture, not a new revision of it. **Acceptance does
not authorize implementation.** Every non-goal listed below (no
`PlanDigest` code, no authorization-artifact code, no verification/
execution code, no WRITE tool, no `WriteEndpoints` population, no WRITE
activation, no fail-closed enforcement, no TPM/pfSense/Proxmox mutation,
no `ADR-021` change) remains in force exactly as written; building any
part of "Future implementation phases" below is its own separate,
future, explicitly-scoped authorization this note does not grant.

## Context

`ADR-021` (Accepted) established the two-axis security-posture model and
its `DISCOVERED → SELECTED → PREREQUISITES_VERIFIED → PROVISIONING →
ACTIVE` per-axis state machine. Two mutation-free slices now exist on
top of it: `pfsense-mcp-security discover`
(`security_discovery.py`) and `pfsense-mcp-security plan`
(`security_plan.py`), reaching exactly `DISCOVERED` and, as pure
analysis, describing what `SELECTED`/`PREREQUISITES_VERIFIED`/
`PROVISIONING` would require — **without performing any of it**. No
command in this codebase can turn a `SecurityPosturePlan` into a real
state change.

Separately, `ADR-006`/`ADR-012`/`ADR-013`/`ADR-014`/`ADR-015` already
define a complete, accepted, **inert** execution architecture for one
specific class of mutation — pfSense API WRITE calls — built around
`RecoveryContract`, `ConfirmationEvidence`/`ConfirmationVerifier`,
`ReconciliationEvidence`, `MutationExecutor`/`CapabilityAdapter`, and
`RatePolicy`. This machinery is real, tested, and already answers most
of "how is one specific, already-decided pfSense mutation safely
carried out" — it does **not** answer "how does an operator decide, in
an authenticated, non-repudiable, narrowly-scoped way, which specific
step(s) of a `security_plan.py` plan get to reach that machinery in the
first place." That gap — the boundary between planning (`ADR-021`) and
per-mutation execution (`ADR-006`/`012`/`013`/`014`/`015`) — is what
this ADR designs. It is a **design phase only**: no code implementing
any part of it is authorized by this ADR's acceptance, exactly as
`ADR-021`'s own acceptance note did not authorize implementation.

### Why this is not a Tier 1 subsystem, and not a revision of `ADR-021`

Like `ADR-017` and `ADR-021` (see `docs/adr/README.md`'s placement
note), this ADR sits **above** Tier 1, not inside it: it governs how an
operator's authority reaches Tier 1's existing machinery, and — as
"Scope: which mutation classes this covers" below establishes — also
governs mutation classes Tier 1's `RecoveryContract` was never designed
to cover at all (configuration-file changes, physical TPM provisioning).
It does not reopen or restate any `ADR-021` decision — the two-axis
model, the validity constraint, the per-axis state machine, the
DEACTIVATE/DEPROVISION split, and the declarative-vs-interactive scoping
are all reused as-is, unchanged, as inputs to this design.

## Terminology

| Term | Meaning | New in this ADR? |
|---|---|---|
| **Plan** | A `SecurityPosturePlan` (`security_plan.py`, already shipped) — an immutable, generated description of prospective steps. Never authorization. | No — reused exactly as shipped |
| **PlanDigest** | A canonical, deterministic digest binding a Plan's security-relevant fields, so an authorization can be shown to apply to *exactly* the plan reviewed | Yes |
| **AuthorizationRequest** | A named, bounded subset of one Plan's step IDs, presented for an operator decision. Not itself authorization. | Yes |
| **PlanAuthorization** | A signed, expiring, narrowly-scoped artifact binding an `authority_id` to an exact `PlanDigest` and an exact, explicit set of step IDs. The only thing that ever grants execution permission. | Yes |
| **DeprovisionAuthorization** | A structurally separate, even more narrowly-scoped artifact type for destructive operations (TPM NV deletion, store/key deletion). Never the same artifact type or code path as `PlanAuthorization`. | Yes |
| **Execution mechanism** | The mutation-class-specific machinery that actually carries out one authorized step. Three exist/are named; none is unified into one universal executor (see "Scope" below). | Partially — one of the three already exists (`MutationExecutor`) |
| **Freshness re-check** | Re-running `discover`/an equivalent evidence read immediately before a security-relevant transition, comparing it against the digest-bound expectation | Yes (as a named, mandatory step) |

## Trust boundaries

Four distinct trust domains, none collapsed into another:

1. **AI/MCP request boundary** — an MCP client (an AI model, via `pfsense-mcp-server`'s stdio transport) can invoke `discover`/`plan`-shaped read operations and, if ever built, an `AuthorizationRequest`-shaped call. It can never itself produce a valid `PlanAuthorization` or `DeprovisionAuthorization` — see "AI/MCP trust boundary" below.
2. **Operator boundary** — a human, physically present at a console or holding an offline signing key, is the only source of `PlanAuthorization`/`DeprovisionAuthorization` artifacts. Mirrors `ADR-012`'s "private key custody lives entirely outside the MCP server's host/process" exactly.
3. **Execution boundary** — `MutationExecutor` (pfSense-API-class steps), the TPM provisioning procedure (`anti_rollback_tpm_host_witness.md`, hardware-class steps), and ordinary source-controlled configuration change (config-class steps) — three separate, already-scoped mechanisms, each with its own pre-existing trust model. This ADR does not create a fourth generic executor.
4. **Verification boundary** — `discover_security_posture()`'s already-read-only machinery is the sole authority for "what changed"; no execution mechanism is ever trusted to self-report success without an independent post-condition re-check through this same boundary.

## Scope: which mutation classes this covers, and how they map to execution

`security_plan.py`'s `MutationClass` values map onto **three structurally
different future execution mechanisms** — this is a load-bearing finding
of this design, verified against the actual shipped code and existing
ADRs, not assumed:

| `MutationClass` | Example step | Future execution mechanism | Why |
|---|---|---|---|
| `CONFIGURATION` | `populate_write_endpoints`, `set_profile_engineer` | **Source-controlled code/config change** (edit `write_endpoints.py`/set an env var, reviewed, committed, deployed) — the same process already used for every real change in this repository, including this very ADR | `RecoveryContract.__post_init__` requires `capability.name.endswith("_WRITE")` and `http_method in {POST, PUT, PATCH, DELETE}` — it is typed to cover pfSense API calls only. `WriteEndpoints`/`PFSENSE_PROFILE` are not pfSense API resources; there is no HTTP request, target, or rollback plan to bind a `RecoveryContract` to |
| `DEACTIVATION` | `deactivate_write_protection`, `deactivate_anchor` | Same as `CONFIGURATION` (profile/allow-list revert) or a `systemctl stop`/`disable` command (daemon deactivation) — reversible, non-API | Same reasoning; `ADR-021`'s own DEACTIVATE definition is explicitly a service/config-state change, never an API mutation |
| `ANCHOR_PROVISIONING`, `SERVICE_DEPLOYMENT` | `provision_hardware_witness_anchor`, `deploy_witness_daemon` | **Interactive, human-run TPM/console procedure** (`anti_rollback_tpm_host_witness.md`'s already-specified provisioning state machine; `scripts/tier1_store_bootstrap.py`) | `ADR-021`'s own accepted "Declarative vs. interactive provisioning" table already states physical-TPM-touching steps are interactive-only, never declarative/automatable — this ADR does not reopen that; it inherits it |
| `ACTIVATION` | `milestone_9_activation` | Not executable at all today (`tools/write/` is empty) — once real WRITE tools exist, this becomes the entry point that makes `RecoveryContract`/`ConfirmationEvidence`/`MutationExecutor` reachable for the *first* time in production | This is the one class this ADR's `PlanAuthorization` design most directly gates the future MCP WRITE boundary for — see "MCP WRITE boundary" below |
| `DESTRUCTIVE_DEPROVISIONING` | *(never emitted by `security_plan.py` today)* | A wholly separate, future, `DeprovisionAuthorization`-gated procedure | `ADR-021` question 4: DEPROVISION is explicitly outside the routine per-axis lifecycle; this ADR keeps that separation structural, not advisory (see "Destructive operations" below) |

**Consequence**: this design does not propose one universal "executor"
that every `PlanStep` eventually flows through. `MutationExecutor`
(`ADR-014`) remains scoped exactly as accepted — the pfSense-API-mutation
engine — and this ADR's job is to define the authorization gate in front
of it (and, more narrowly, in front of the other two mechanisms) without
either weakening it or duplicating it.

## Decision

### 1. The authorization/execution lifecycle applies to a *bounded
   authorization*, not to the Plan itself

A `Plan` is, and remains, an immutable, static artifact once generated
— it never has its own "authorized" or "executing" state. What has a
lifecycle is a **`PlanAuthorization`**, scoped to an exact `PlanDigest`
and an exact, explicit, non-empty set of step IDs drawn from that plan.
Two different `PlanAuthorization`s can exist for two different (or
overlapping, non-conflicting) step subsets of the same Plan, and progress
independently — this is the direct mechanism for `ADR-021`'s "every
mutating step... requires its own explicit, distinct confirmation" and
this task's own "never authorize all future steps implicitly."

### 2. State machine (per `PlanAuthorization`, not per `Plan`)

```
DISCOVERED --(plan)--> PLANNED --(request)--> AUTHORIZATION_REQUESTED
                                                     |        |
                                    (operator grants)|        |(operator declines,
                                                      v        | or evidence changed)
                                                 AUTHORIZED     v
                                                  |    |    REJECTED / STALE
                          (operator revokes)------+    |(fresh evidence
                                     v                 | re-check fails
                                 REVOKED                | immediately before
                                                         | EXECUTING)
                                                         v
                                                     STALE
                                                 (from AUTHORIZED)
                                                         |
                                             (evidence still fresh)
                                                         v
                                                    EXECUTING
                                              /         |          \
                                     (mechanism      (ambiguous       (mechanism
                                      reports         outcome for a    reports clean
                                      clean failure    pfSense-API-    failure before
                                      before any       class step)     side effect)
                                      side effect)         |               |
                                         v                 v               v
                                      FAILED     NEEDS_RECONCILIATION   FAILED
                                                  (mirrors the wrapped
                                                   RecoveryContract's own
                                                   RECONCILIATION state --
                                                   resolved by ADR-013's
                                                   existing mechanism,
                                                   never a new one)
                                                         |
                                                (ADR-013 resolution)
                                                         v
                                               SUCCEEDED / FAILED
                                                         ^
                                                         |
                                                    VERIFYING
                                                         ^
                                                         |
                                                    EXECUTING
                                                    (clean path)
```

| State | Meaning | Terminal? | Requires fresh evidence to enter? | Requires operator action to enter? |
|---|---|---|---|---|
| `DISCOVERED` | Current posture evidence collected (`discover`, shipped) | No | N/A (it *is* the evidence) | No |
| `PLANNED` | An immutable `SecurityPosturePlan` + `PlanDigest` exists (`plan`, shipped) | No | N/A | No |
| `AUTHORIZATION_REQUESTED` | A named step-ID subset of one `PlanDigest` has been presented for a decision | No | Recommended, not required (a stale request is simply more likely to be rejected at the next check) | No — this is a *request*, which may originate from an AI/MCP caller (see below) |
| `AUTHORIZED` | A valid, unexpired, unrevoked `PlanAuthorization` exists | No | **Yes — mandatory**, at the moment of granting | **Yes — always**, and never via natural-language "the user said yes" (see "AI/MCP trust boundary") |
| `REVOKED` | Operator explicitly invalidated an `AUTHORIZED` artifact before execution | **Yes** | N/A | Yes |
| `REJECTED` | Operator explicitly declined an `AUTHORIZATION_REQUESTED` request | **Yes** | N/A | Yes |
| `STALE` | The evidence a `PLANNED`/`AUTHORIZATION_REQUESTED`/`AUTHORIZED` artifact was bound to no longer matches current reality | **Yes**, for that specific artifact instance (re-planning produces a new, distinct `PlanDigest`/authorization, not a resurrection of the stale one) | N/A | No — detected, not decided |
| `EXECUTING` | The mutation-class-appropriate mechanism is carrying out the authorized step(s) | No | **Yes — mandatory**, immediately before entry (see "Freshness/TOCTOU") | No (already authorized) |
| `VERIFYING` | Independent post-condition re-check via fresh `discover`/read-back is in progress | No | N/A (it *is* the fresh check) | No |
| `NEEDS_RECONCILIATION` | Only reachable for pfSense-API-class steps whose underlying `RecoveryContract` entered `RECONCILIATION` (`ADR-013`) | No (resolves via `ADR-013`'s existing signed-resolution mechanism) | N/A | Yes, via `ADR-013`'s already-accepted mechanism — not re-designed here |
| `SUCCEEDED` | Verified outcome matches intent | **Yes** | N/A | No |
| `FAILED` | Execution or verification concluded the intended change did not (cleanly) occur | **Yes** | N/A | No |

**Never a legal transition, by construction**: any transition directly
into `EXECUTING` that did not pass through `AUTHORIZED` first; any
transition out of `AUTHORIZATION_REQUESTED` into `AUTHORIZED` without a
fresh evidence re-check; any transition that widens the authorized
step-ID set after `AUTHORIZED` is reached (widening scope requires a new
`AuthorizationRequest`/`PlanAuthorization`, never an edit of an existing
one — artifacts are immutable, never patched).

### 3. `PlanDigest` — what participates in plan identity, and what does not

Reuses `pfsense_mcp.tier1.canonical.digest_value()`/`canonical_json()`
exactly as `RecoveryContract.idempotency_key` already does — a new
`DigestPurpose.PLAN` member, not a parallel hashing scheme.

**Participates** (security-relevant, must invalidate the digest if
changed):

- schema version (an explicit integer/string, so a future format change
  can never be silently reinterpreted as today's format)
- `target_capability_posture`, `target_anchor_assurance`
- `target_validity` (binding the *classification*, not only the target
  values, closes off a future bug where the same target is reachable
  through two differently-validated code paths)
- for each step, in order: `step_id`, `order`, `axis`, `mutation_class`,
  `authorization_required` — the fields that determine *what an
  authorization for this step would actually permit*
- a compact **evidence fingerprint** of the `current` state the plan was
  computed against: `capability_posture.value`,
  `anchor_assurance.{value, evidence_state, baseline, witness_value,
  provisioned_at}` — the same *structured* fields `security_plan.py`
  already treats as authoritative, not the prose `evidence` tuples
- `overall_status`, `safe_to_proceed` (binding the derived safety
  classification itself, not only its inputs, as defense in depth)

**Does not participate** (would cause unnecessary invalidation without
adding security value):

- `action`/`description`/`blocked_reason` free text — rewording a step's
  human-readable explanation must never silently invalidate every
  operator's already-reviewed authorization
- `notes` — fixed boilerplate, not plan-specific
- the raw `evidence` prose tuples — already summarized by the compact
  fingerprint above; including the prose verbatim would make the digest
  fragile to non-semantic wording changes in `security_discovery.py`

This directly closes the failure this task named: *AI generates harmless
Plan A → human approves Plan A → target/state/steps change → old
approval reused to execute modified Plan B* — because Plan B's
`PlanDigest` differs from Plan A's the instant any digest-participating
field differs, and `PlanAuthorization.verify_bindings()` (below) refuses
whenever the freshly-recomputed digest does not exactly match the one
the artifact was issued for.

### 4. `PlanAuthorization` — the authorization artifact

Structurally mirrors `ConfirmationEvidence` (`ADR-012`) one layer up —
same cryptographic mechanism (detached Ed25519 signature, pinned public
key set, `authority_id`-based rotation), new digest-purpose domain
separation so a `PlanAuthorization` signature can never be replayed as a
`ConfirmationEvidence`/`ReconciliationEvidence` signature or vice versa.

| Field | Purpose |
|---|---|
| `schema_version` | Same reasoning as `PlanDigest`'s |
| `authorization_id` | Unique per artifact — the binding target for revocation, analogous to `contract_id`'s role, never reused |
| `plan_digest` | Exact binding to one `PlanDigest` — never "the current plan," always this one |
| `authorized_step_ids` | Explicit, non-empty, ordered tuple — **never a wildcard, never "all remaining," never inferred** |
| `authority_id`, `algorithm`, `proof` | Reused from `ConfirmationEvidence` exactly |
| `issued_at`, `expires_at` | Short-lived — see "Freshness/TOCTOU" for concrete guidance by risk class |
| `risk_class` | The highest `SecurityImpact`/`AuthorizationLevel` among the authorized steps — bound into the signature so a lower-friction confirmation flow cannot be reused for a higher-risk step set |
| `evidence_fingerprint` | Copy of the compact fingerprint from the `PlanDigest` computation — lets a verifier re-validate freshness without needing to still hold the original `Plan` object |

**Security properties** (all directly requested by this task, verified
against this design, not assumed satisfied):

- **Narrow scope** — `authorized_step_ids` is explicit and closed; an
  artifact authorizing steps `{2, 3}` of a plan never authorizes step 4,
  even if step 4 has an identical `mutation_class`.
- **Short lifetime** — `expires_at` is mandatory and, for
  `INTERACTIVE_HARDWARE_CONFIRMATION`/`MILESTONE_9_ACTIVATION_DECISION`-class
  steps, should be scoped to the single interactive session that granted
  it (minutes, not hours), matching `ADR-021`'s existing interactive-only
  rule for TPM-touching steps.
- **Non-transferability** — `plan_digest` binding means an artifact
  issued for one plan is cryptographically meaningless for any other
  plan, even one that differs by a single byte. This matters more than
  it first appears: `step_id`s (e.g.
  `capability_posture.populate_write_endpoints`) are **stable,
  human-readable strings, deliberately reused across every plan that
  contains that step** (unlike `RecoveryContract.contract_id`, which is
  unique per contract) — a verifier that checked `authorized_step_ids`
  membership *without* also requiring exact `plan_digest` equality would
  let a `PlanAuthorization` issued against one plan silently satisfy a
  same-named step in an entirely different, later, differently-evidenced
  plan. Binding is always **both**, never `step_id` membership alone.
- **Replay resistance** — `authorization_id` is single-use exactly the
  way `RecoveryContract.with_confirmation()` already refuses a second
  confirmation; a consumed or expired `PlanAuthorization` can never be
  presented again to reach `EXECUTING`.
- **No wildcard authorization** — structurally impossible: there is no
  field shape that means "everything" — `authorized_step_ids` is always
  a concrete list.
- **No implicit inheritance** — `PlanAuthorization` never derives from
  `Plan.safe_to_proceed`, target selection, or plan generation; it is
  the *only* artifact that grants anything, and it is always
  operator-signed.
- **No authorization from MCP model output alone** — see "AI/MCP trust
  boundary."

### 5. Freshness / TOCTOU model

Three mandatory re-check points, not one:

1. **Before `AUTHORIZED`** — the operator's decision is made against a
   freshly re-run `discover`, and the resulting `PlanDigest` must
   exactly match the one in the `AuthorizationRequest`. If it does not,
   the request is `STALE`, not silently re-approved against the new
   state.
2. **Immediately before `EXECUTING`** — even a `PlanAuthorization` that
   was valid when issued must be re-validated against a *second* fresh
   `discover` immediately before use. This is the direct fix for
   `PLAN at T1 → environment changes → AUTHORIZE at T2 → environment
   changes → EXECUTE at T3`: T2's re-check catches drift between T1 and
   T2; this third check catches drift between T2 and T3.
3. **Between individual steps of a multi-step authorization**, where the
   later step's own prerequisites (e.g., `capability_posture`'s
   `milestone_9_activation` step's `prerequisite_satisfied` depending on
   the `anchor_assurance` axis) could have been invalidated by the
   *earlier* step's own real-world side effects turning out differently
   than the plan predicted.

**`STALE` vs. security anomaly — never conflated**:

| Condition | Classification | Why |
|---|---|---|
| Evidence value changed, but the new evidence is itself clean/valid (e.g., anchor now `provisioned_verified` where it was `configured_unprovisioned`) | `STALE` | Ordinary drift; re-planning produces a new, authorizable `PlanDigest` |
| Evidence configuration is now different in a way that changes `target_validity` (e.g., a target that was `VALID` is now `INVALID_COMBINATION` because something else changed capability posture concurrently) | `STALE` (blocks this authorization) **and** logged distinctly from ordinary drift | Re-planning is still the correct remedy, but the operator should see *why* |
| `AnchorEvidenceState.PROVISIONED_MISMATCH` detected at any re-check | **Security anomaly** — `REJECTED`/blocked outright, never silently treated as `STALE` | `security_plan.py` already established this distinction (`PlanOverallStatus.BLOCKED_ANOMALY_DETECTED`); this ADR extends it into the freshness re-checks, not around them |
| Current anchor-assurance value is indeterminate (`AnchorAssurance.UNKNOWN`) at any re-check | **Security anomaly** — same treatment as mismatch, per `security_plan.py`'s existing `BLOCKED_INDETERMINATE_CURRENT_STATE` handling, reused not reinvented | Unavailable evidence must never be treated as "just stale, try again" |

### 6. Per-step vs. plan-level authorization; risk-dependent granularity

One `AuthorizationRequest`/`PlanAuthorization` names an explicit,
non-empty subset of a plan's step IDs. The granularity an operator
*chooses* to grant at once is their decision (they may authorize one
step, or several, in one artifact) — but the artifact never expands
beyond exactly what was named, and different risk classes warrant
different default UX friction, not different mechanisms:

| Risk class (`MutationClass`/`AuthorizationLevel`) | Recommended default granularity | Recommended max lifetime |
|---|---|---|
| `CONFIGURATION`/`CONFIGURATION_CHANGE` (e.g. `WriteEndpoints` population, `PFSENSE_PROFILE`) | May be batched with adjacent config-class steps in one authorization | Short (this is still a source-controlled code change with its own review, not a runtime grant — see "Scope" table) |
| `DEACTIVATION`/`CONFIGURATION_CHANGE` | May be batched | Short |
| `ANCHOR_PROVISIONING`, `SERVICE_DEPLOYMENT`/`INTERACTIVE_HARDWARE_CONFIRMATION` | One step per authorization, interactive-session-scoped, never batched with a different mutation class | Minutes; never survives process restart (see "Crash/restart semantics") |
| `ACTIVATION`/`MILESTONE_9_ACTIVATION_DECISION` | Exactly one authorization, never batched with anything else, requires the Milestone-9-class decision as a separate precondition, not a replacement for it | Short, single-session |
| `DESTRUCTIVE_DEPROVISIONING`/*(future)* | Never via `PlanAuthorization` at all — see "Destructive operations" | N/A — different artifact type entirely |

## AI/MCP trust boundary

**The strongest single recommendation in this design**: the act of
*granting* a `PlanAuthorization` or `DeprovisionAuthorization` should
**never be reachable through the MCP/AI request path at all** — it
should remain, permanently, an out-of-band operator action (CLI/signing
tool run directly by a human), mirroring `ADR-012`'s own accepted
decision that "private key custody lives entirely outside the MCP
server's host/process." This is not a new principle invented for this
ADR; it is `ADR-012`'s decision applied one layer up, at the layer where
it is arguably even more important, since a Plan (unlike a single
`RecoveryContract`) can span multiple future steps and axes.

What the AI/MCP boundary **can** do, today and in any future phase:

- discover (shipped), plan (shipped), explain risk, reason about
  trade-offs;
- submit an `AuthorizationRequest` — i.e., *ask* an operator to consider
  authorizing a named step subset. This is not authorization; it is
  closer to a formatted question. It should carry no cryptographic
  weight and require independent operator judgment every time, even if
  the AI's proposed request is identical to a previous one.

What must **never** happen, with a concrete defense for each:

| Attack | Defense |
|---|---|
| Prompt injection causes the model to claim/request authorization | Identical to the existing Tier 1 threat-model row ("Prompt injection claims approval — Confirmation digest is a separate contract fact, not an MCP boolean"): a `PlanAuthorization` requires a real Ed25519 `proof`, produced by a human/tool the AI never controls; a model's textual claim has no cryptographic weight and is never accepted as one |
| Model fabricates "user approved" in its own output | Same defense — the server never reads authorization out of model-generated text; it reads a `proof` field and verifies it |
| An old, previously-issued approval is replayed | `authorization_id` single-use + `plan_digest` exact-match + `expires_at` (see `PlanAuthorization` properties above) |
| A plan is modified after approval | `plan_digest` binds to every security-relevant field; any modification changes the digest, invalidating the binding |
| A request asks for broader scope than what was actually discussed/reviewed | `authorized_step_ids` is explicit and never inferred; an operator reviewing a request sees exactly the named steps, nothing implicit |
| Individually-harmless approvals are chained into a dangerous sequence | Each `PlanAuthorization` binds to one specific `PlanDigest`'s specific steps; there is no mechanism by which two separate, narrowly-scoped authorizations combine into permission for a third, unauthorized action — the execution mechanisms themselves (config change review, TPM console procedure, `MutationExecutor`) have no "combine two prior grants" capability to design against in the first place |

## CLI / UX boundary (conceptual — no syntax committed)

Interactive only for any step whose `authorization_required` is
`INTERACTIVE_HARDWARE_CONFIRMATION` or `MILESTONE_9_ACTIVATION_DECISION`
— reusing `ADR-021`'s already-accepted interactive-vs-declarative
scoping exactly, not reopening it. `CONFIGURATION_CHANGE`-class requests
may reasonably support a declarative/itemized-authorization mode later,
matching `ADR-021`'s own text, but even then: **never** `--yes`,
`--force`, `--approve-all`, or any flag whose presence alone grants
anything — a declarative authorization input must itemize exact plan
digest + exact step IDs, the same granularity an interactive prompt
would require, delivered via a file/argument instead of a live prompt,
not a weaker substitute for it (mirrors `ADR-021`'s own "declarative
mode's consent model" text precisely).

A future `discover`/`plan`-shaped read command reporting authorization
state (if built) should show, per step: `authorization_required`,
whether an `AuthorizationRequest`/`PlanAuthorization` currently exists
for it, its state, and its expiry — read-only, exactly like `discover`/
`plan` today.

## MCP WRITE boundary

Explicit, permanent invariant this design imposes on any future WRITE
MCP tool: **a WRITE tool must never accept a caller-supplied
`authorized=true` (or any semantically equivalent) input.** A WRITE
tool's MCP-facing schema may accept, at most, a reference (e.g.
`plan_digest` + `step_id`) — never the authorization artifact's contents
wholesale, and never a boolean. Directly extends `ADR-007`'s
"security-first public schemas" principle (no caller-controlled
authoritative field) to this new artifact type.

Recommended ordering a future WRITE tool call must enforce, all
required, sequence matters:

1. Capability active (`ADR-004` profile check) — unaffected by this ADR.
2. Endpoint allow-listed (`WriteEndpoints`, `ADR-005`) — unaffected.
3. Referenced `PlanAuthorization` exists, is unexpired, unrevoked, and
   its `plan_digest`/`authorized_step_ids` include the requested
   operation — **new, this ADR**.
4. Freshness re-check (fresh `discover`, matches the artifact's
   `evidence_fingerprint`, or the call is refused as `STALE`/anomalous)
   — **new, this ADR**.
5. Appropriate anchor assurance for the risk class (reusing `ADR-021`'s
   validity constraint, e.g. no `write_protected` execution path is ever
   reachable with anchor assurance `none`) — unaffected, reused.
6. `RecoveryContract` creation from verified pre-state (`ADR-006`) —
   unaffected.
7. `ConfirmationEvidence` (`ADR-012`) — **this is a second, independent
   signature**, at the individual-mutation level, distinct in purpose
   from step 3's plan-level `PlanAuthorization`. Both are required, not
   either/or: `PlanAuthorization` answers "is an operator willing to see
   this class of change happen at all, for this plan"; `ConfirmationEvidence`
   answers "does an operator confirm *this exact* prepared mutation,
   with its own verified snapshot and rollback plan, right now." Neither
   substitutes for the other.
8. `MutationExecutor.execute()` (`ADR-014`) — unaffected.
9. Independent post-condition verification (already part of `ADR-006`'s
   philosophy) — unaffected.

**Bypass paths considered and closed**: a caller cannot skip step 3 by
supplying a self-asserted authorization, because the tool never accepts
one as input (only a reference, verified server-side against durably
stored, signature-verified state — the same integrity discipline
`SqliteRecoveryContractStore` already applies to `RecoveryContract`
rows). A caller cannot skip step 4 by reusing an old but technically
unexpired `PlanAuthorization` issued against now-stale evidence, because
step 4 is independent of, and in addition to, the artifact's own
`expires_at`. A caller cannot satisfy step 3 with a `PlanAuthorization`
scoped to a *different* step or plan, because binding is exact-match,
not prefix/subset-permissive in the caller's favor.

## Recovery Contract / Anchor relationship

Kept as four genuinely separate concepts, per the task's own suggested
separation, verified (not merely restated) against the actual code in
"Scope" above:

- **Plan** — what should change (`security_plan.py`, shipped, unchanged
  by this ADR).
- **Authorization** (`PlanAuthorization`/`DeprovisionAuthorization`,
  this ADR) — operator permission for exactly the named change(s).
  Exists **above** and **independent of** `RecoveryContract` — it is a
  precondition for *creating* a `RecoveryContract` for an
  `ACTIVATION`-class step, and the sole gate for the two non-`RecoveryContract`
  execution mechanisms (config-class, hardware-class).
- **Recovery Contract** (`ADR-006`/`012`/`013`/`014`/`015`, existing,
  unchanged) — how the system safely performs/reconciles *one pfSense
  API mutation specifically*, once a `PlanAuthorization` has already
  established that an operator is willing to see this class of change
  happen. Confirmation (`ADR-012`) remains its own, separate,
  per-mutation signature — see "MCP WRITE boundary" step 7.
- **Anchor** (`ADR-011`, existing, unchanged) — anti-rollback protection
  for the whole Recovery Contract store's durable security state,
  consulted (never mutated) by this design's freshness re-checks via
  `discover_security_posture()`'s existing anchor-assurance axis; this
  ADR introduces no new anchor interaction.

## Destructive operations

Kept structurally separate, not merely policy-separate, from routine
`PlanAuthorization`:

- **`DeprovisionAuthorization`** is a distinct artifact *type* (own
  schema, own `DigestPurpose`, own verification code path if ever
  implemented) — never a `destructive: bool` flag on the general
  artifact, specifically because a flag can be defaulted, forgotten, or
  set incorrectly by a careless future edit, while a wholly separate
  type cannot be reached by any code path that only knows how to
  construct the routine one.
- Selecting a lower security posture (routine `DEACTIVATION`-class
  steps) **never** produces, requires, or implies a
  `DeprovisionAuthorization` — this is the same guarantee
  `security_plan.py` already enforces at the planning layer
  (`MutationClass.DESTRUCTIVE_DEPROVISIONING` is declared but never
  emitted); this ADR extends that guarantee into the authorization layer
  so it cannot be reintroduced there instead.
- Retain-not-delete remains the default and the only currently
  designed behavior — no code path in this design ever constructs a
  `DeprovisionAuthorization`, because no destructive execution mechanism
  is designed at all yet. This is deliberately left as a **future,
  separate, explicitly-scoped ADR** if TPM NV deletion or store/key
  deletion is ever actually pursued — consistent with this project's
  standing practice of drafting exact authorization wording only when
  real and imminent (`ADR-021`'s own "Resolving open questions 3–6").

## Failure taxonomy (fail-closed conditions)

| Condition | Classification | Resulting state |
|---|---|---|
| `PlanDigest` mismatch at any check | Ordinary staleness (unless caused by an anomaly below) | `STALE` |
| `PlanAuthorization` expired | Ordinary — expected, not alarming | Refused; requires a new `AuthorizationRequest` |
| `PlanAuthorization` already consumed (replay attempt) | **Security-relevant** | Refused, logged distinctly from ordinary expiry |
| Step ID not in `authorized_step_ids` | **Security-relevant** (scope violation attempt) | Refused |
| Prerequisite changed since planning (e.g. anchor axis regressed) | Ordinary staleness | `STALE` |
| `target_validity` changed since planning | Ordinary staleness, logged distinctly (see freshness table) | `STALE` |
| Anchor unavailable where the target requires it | Reuses `ADR-021`'s existing validity constraint | Refused (same as today's `INVALID_COMBINATION`/`BLOCKED_NOT_IMPLEMENTED` handling) |
| Anchor mismatch (`PROVISIONED_MISMATCH`) | **Security anomaly** | Refused outright, never `STALE` |
| Indeterminate anchor state (`UNKNOWN`) | **Security anomaly** | Refused outright, never treated as success (reuses `security_plan.py`'s existing fix) |
| `RecoveryContract` conflict/rate-limit (`ADR-015`) | Existing, unaffected | Existing `RateLimitExceededError` handling |
| `WriteEndpoint` not allow-listed | Existing, unaffected | Existing refusal in `WriteApiClient` |
| Capability not active | Existing, unaffected | Existing refusal |
| Schema/version incompatibility (`schema_version` mismatch) | Fail closed | Refused — never guess an old artifact's meaning under a new schema |
| Partial/indeterminate execution outcome for a pfSense-API-class step | Existing, unaffected | `NEEDS_RECONCILIATION` (`ADR-013`) |

## Concurrency / replay

Multiple simultaneous MCP/CLI sessions are assumed, not special-cased
away:

- Two sessions may independently `plan` the same target concurrently —
  harmless, since planning is pure and read-only; they will compute
  identical `PlanDigest`s from identical evidence, or different digests
  if evidence genuinely differs between the two reads (itself meaningful
  information, not a bug).
- Two sessions may submit overlapping `AuthorizationRequest`s — the
  operator resolves this by choosing which to grant; granting one does
  not silently affect the other's future validity (they may target
  disjoint step subsets, or the same one, in which case the second
  grant, if attempted after the first, must itself fail the freshness
  re-check once the first authorization's later execution — or even
  its mere existence, depending on final design — changes the relevant
  evidence).
- `RecoveryContract`'s already-existing target-reservation/rate-policy
  machinery (`ADR-015`) remains the authority for "only one in-flight
  pfSense-API mutation against a given target at a time" — this ADR
  does not weaken or duplicate it.
- Concurrent `EXECUTING` for two *different*, non-conflicting
  authorizations is permitted in principle but still bounded by
  `RatePolicy`'s existing global-in-flight limit — no new concurrency
  ceiling is introduced by this design beyond what `ADR-015` already
  provides.

## Crash / restart semantics

| Crash point | Recommended behavior |
|---|---|
| After `PLANNED`, before any request | No effect — Plan was never persisted as a stateful object beyond its own digest computation; a resumed session simply re-plans |
| After `AUTHORIZATION_REQUESTED`, before grant | Request is lost; this is safe and acceptable — re-request is cheap and read-only up to this point |
| After `AUTHORIZED`, before `EXECUTING` | The artifact **may** survive restart if durably persisted (mirroring how `RecoveryContract` rows already survive restart) — but per "Freshness/TOCTOU," resuming toward `EXECUTING` always requires a fresh re-check regardless of how recently it was granted. For `INTERACTIVE_HARDWARE_CONFIRMATION`/`MILESTONE_9_ACTIVATION_DECISION`-class authorizations specifically: **recommend these never survive a restart at all**, consistent with `ADR-021`'s standing practice that TPM-facing actions are always run manually, in one sitting, never left pending across a restart |
| During `EXECUTING` for a pfSense-API-class step | Already-designed-for by `ADR-006`/`ADR-014`: durable-before-mutate transitions, restart moves interrupted records toward `RECONCILIATION`, never blind retry. This ADR adds nothing here — it is squarely `RecoveryContract`'s existing job |
| During `EXECUTING` for a config-class or hardware-class step | See "Durability for config-class and hardware-class execution" below — resolved without new persistence, for reasons specific to each class |
| After execution, before `VERIFYING` completes | Re-run verification on resume; never assume success merely because the process reached this point before crashing |

### Persisted authorization is never a bearer capability

Explicit, standalone guarantee (raised during owner review as a specific
consistency check): **an `AUTHORIZED` `PlanAuthorization` surviving
process restart never becomes a durable bearer capability** — a bearer
credential is dangerous specifically because presenting it alone is
sufficient to act. This design never has that property, restart or not:
every use of a `PlanAuthorization` — whether the artifact is a
minute-old, in-memory object or a day-old, durably persisted row —
requires, unconditionally, at the moment of use: (1) exact `plan_digest`
match against a **freshly recomputed** plan, never the stored plan; (2)
`expires_at` not yet reached; (3) not already consumed (see below); (4)
the mandatory pre-`EXECUTING` freshness re-check passing. Persistence
only ever affects *how long an artifact remains eligible to attempt
these four checks* — it never substitutes for any of them, and none of
the four is weakened, skipped, or cached across restarts. This is the
same property `RecoveryContract`'s own `confirmation_digest` already
has (surviving restart does not let a confirmation skip
`verify_bindings()` on resume) — this ADR extends it, not invents it.

### Durability for config-class and hardware-class execution (resolves unresolved question 1)

No new durable "authorization ledger" is required for either
non-`RecoveryContract` mechanism, for two different, each independently
sufficient reasons — resolved within existing accepted architecture,
not deferred:

- **Hardware-class** (`ANCHOR_PROVISIONING`/`SERVICE_DEPLOYMENT`): these
  authorizations are already recommended, above, to **never survive a
  restart at all** — there is no artifact left in existence after a
  crash for a replay attempt to present. Crash recovery for the
  *execution* itself (as opposed to the authorization) is already
  `anti_rollback_tpm_host_witness.md`'s own accepted "derive state, don't
  trust a log" discipline: a fresh `discover` after any interruption
  tells the truth about what the TPM/store actually contains, exactly
  as this project's existing hardware-provisioning recovery already
  works today, restart or not. No new log or ledger would add anything
  a fresh evidence read doesn't already provide.
- **Config-class** (`CONFIGURATION`/`DEACTIVATION`): the step's
  "execution" *is* a normal, reviewed, source-controlled commit — the
  commit itself is the durable, tamper-evident, single-execution record
  (git's own commit graph), not something this design needs to
  duplicate. The remaining question — could a `PlanAuthorization` that
  survives restart be *replayed* to attempt a second, duplicate commit —
  is already closed by the **mandatory pre-`EXECUTING` freshness
  re-check** (independent of persistence or expiry): if the target
  config state was already achieved by the first, already-committed
  change, the fresh re-check finds no remaining delta between current
  evidence and the plan's expected target, and the request degrades to
  `STALE`/already-satisfied rather than proceeding to a second,
  redundant commit. Replay against a config-class authorization is
  therefore bounded to, at worst, a harmless no-op rejection, not a
  duplicate or unauthorized action — without any new persistence
  primitive.

This removes new-store design from Phase C/D's scope entirely; both
phases now cover only the pfSense-API-mutation-class authorization path
plus artifact construction/verification logic for the other two
classes, never a new storage schema for them.

## Threat-model findings (adversarial review of this design)

| Attack | Credible against this design? | Defense / disposition |
|---|---|---|
| Stale-plan execution | Closed | Mandatory freshness re-check before `EXECUTING`, independent of `expires_at` |
| Plan substitution (Plan A approved, Plan B executed) | Closed | `PlanDigest` exact-match binding |
| Step substitution (approved step 2, step 3 executed) | Closed | `authorized_step_ids` explicit, closed set |
| Replay of a consumed/expired authorization | Closed | Single-use `authorization_id` + `expires_at`, mirroring `RecoveryContract.with_confirmation()`'s existing single-confirmation guarantee |
| Privilege escalation via risk-class confusion (low-risk grant reused for a high-risk step) | Closed | `risk_class` bound into the signed artifact; a `CONFIGURATION_CHANGE`-scoped grant cannot satisfy an `INTERACTIVE_HARDWARE_CONFIRMATION`-class step's binding check |
| Approval laundering (AI claims prior approval exists) | Closed | Same defense as the existing "prompt injection claims approval" threat-model row — no natural-language claim is ever accepted as a `proof` |
| Confused deputy (WRITE tool trusts a caller-supplied authorization blob) | Closed by design constraint | "MCP WRITE boundary" mandates reference-only input, never artifact contents |
| TOCTOU across plan → authorize → execute | Closed | Three-point freshness model (Freshness/TOCTOU section) |
| Concurrent sessions racing on the same target | Mitigated, not newly solved | Reuses `ADR-015`'s existing target-reservation/rate-policy machinery unchanged |
| Crash/restart losing or resurrecting authority incorrectly | Mitigated | Short-lived, class-appropriate persistence (Crash/restart table); TPM-class authorizations recommended never to survive restart at all |
| Downgrade abuse (using a downgrade request to smuggle a deprovision) | Closed | `DeprovisionAuthorization` is a structurally separate type unreachable from any `DEACTIVATION`-class code path |
| Destructive-operation smuggling via a batched `CONFIGURATION_CHANGE` authorization | Closed | Per "Per-step authorization" table, `DESTRUCTIVE_DEPROVISIONING`-class steps are never batchable and, more fundamentally, `security_plan.py` never emits them at all today |
| Capability/anchor axis confusion (hardware witness implying WRITE) | Closed, pre-existing | Directly verified unaffected — `security_plan.py`'s own tests already prove `hardware_witness` never implies `write_protected`; this ADR adds nothing that could reintroduce it, since `PlanAuthorization` only ever narrows what `security_plan.py` already computed |
| Model-generated fake consent | Closed | See "AI/MCP trust boundary" |
| Config-class/hardware-class replay or crash-safety gap | **Closed** (owner review, 2026-08-11) | See "Durability for config-class and hardware-class execution" — hardware-class authorizations never survive restart (nothing left to replay); config-class replay degrades to a harmless `STALE` no-op via the mandatory pre-`EXECUTING` freshness re-check, independent of persistence. No new ledger needed |
| **Left explicitly open**: whether two overlapping, independently-granted `PlanAuthorization`s for the same underlying resource, both still valid, can jointly produce an outcome neither alone would have — a generalized "chaining" risk beyond the specific cases already closed above | **Open, explicitly deferred to a named future process** (owner review, 2026-08-11) | Not a `PlanAuthorization`-design question — each artifact remains narrowly scoped and independently verified regardless. It is a *domain*-interaction-risk question, the same category `WRITE_ENDPOINT_RISK_MATRIX.md`'s per-endpoint review already addresses for single endpoints. No concrete capability pair exists yet to design a mechanism against (Milestone 0 has named exactly one candidate). **Resolution**: every future Milestone-0-successor candidate-naming decision (`ADR-020`'s own precedent) must, from this ADR onward, explicitly assess interaction with every previously-authorized capability as part of its own risk analysis — an addition to that future process, not a new mechanism designed speculatively here |

## `safe_to_proceed` clarification

Reviewed per this task's own request. Behavior (verified previously and
re-confirmed while writing this ADR) is exactly:
`safe_to_proceed = (target_validity is VALID) and not mismatch` —
meaning **only** "this target is a legitimate point in the model and
current evidence shows no detected anomaly," never authorization,
approval, execution-readiness, or step-level permission (individual
steps can be `blocked=True` — pending ordinary sequencing — while
`safe_to_proceed` is `True` for the plan as a whole).

**Recommendation**: documentation alone is likely sufficient, but
currently incomplete — the field has no inline docstring on
`SecurityPosturePlan` itself (unlike `PlanOverallStatus`, which has a
class-level docstring), and the CLI prints it as a bare boolean before
the disclaimer in `notes`. Suggested exact wording, for the owner's
review (not applied by this ADR):

- **Field-level docstring** (on `SecurityPosturePlan.safe_to_proceed`,
  if/when this file is next touched for an unrelated, separately-scoped
  reason — not a standalone edit this ADR authorizes): *"Whether this
  plan itself is safe to present/continue reasoning about — never
  whether any step is safe to execute, and never authorization. `True`
  only means the target is a valid point in the model and current
  evidence shows no detected anomaly; individual steps may still be
  `blocked` pending ordinary sequencing."*
- **CLI wording**: change the human-format line from
  `Safe to proceed:      {value}` to
  `Safe to present:      {value}  (not an execution/authorization signal -- see notes below)`,
  or move the `notes` disclaimer to print immediately after this line
  rather than only at the end of output.
- **JSON**: no schema change recommended (the field's *value* is
  correct); a `"safe_to_proceed_meaning"` companion string was
  considered and rejected as unnecessary schema growth — the existing
  `notes` array already carries this in machine-readable form.

This ADR does **not** rename the field or alter the published schema —
that remains the owner's decision, to be made (if at all) as its own
small, separately-authorized documentation change.

## Consequences

### Positive

- Closes a real, previously-undesigned gap between `ADR-021`'s planning
  layer and `ADR-006`/`012`/`013`/`014`/`015`'s execution layer, without
  weakening or duplicating either.
- Reuses every existing cryptographic/digest/state-machine primitive
  this codebase already built and reviewed (`digest_value`,
  `DigestPurpose`, the Ed25519 confirmation mechanism, `RatePolicy`,
  the closed `RecoveryState` machine) rather than inventing a parallel
  security system.
- Makes explicit, for the first time, that `RecoveryContract` covers
  only one of three future mutation-execution mechanisms — a finding
  that will materially shape how Phases C–G of `ADR-021`'s companion
  spec are eventually implemented.
- Gives the MCP WRITE boundary a concrete, bypass-resistant ordering
  before any WRITE tool is designed, rather than retrofitting
  authorization onto an already-shipped tool.

### Negative

- Two new artifact types (`PlanAuthorization`, `DeprovisionAuthorization`)
  and a new digest purpose add real future implementation and review
  surface, on top of the already-substantial Tier 1 machinery.
- The three-mechanism scope finding means a future implementer cannot
  build one generic "authorize and execute" module — three
  narrower, mechanism-specific integrations are required, which is more
  total work than a (incorrect) unified design would have appeared to
  require.
- One genuinely open question remains after owner review
  (overlapping-authorization chaining across a future second WRITE
  capability) — left open deliberately, bound to a concrete future
  trigger, rather than answered with unjustified confidence ahead of any
  real second capability to reason about.

## Alternatives considered

- **One universal `MutationExecutor`-style engine for every `MutationClass`**:
  rejected — `RecoveryContract`'s own type constraints
  (`capability.name.endswith("_WRITE")`, mutating HTTP method) prove it
  was never designed for config-file or physical-TPM changes; forcing
  those through it would mean either weakening its type guarantees or
  building a fake HTTP-shaped wrapper around a non-HTTP action, both
  worse than acknowledging three real mechanisms exist.
- **A single `authorized: bool` flag on `PlanStep`, settable via a
  future API call**: rejected outright — this is exactly the caller-controlled
  authoritative field `ADR-007` already forbids, and the specific
  "confused deputy" / "MCP fabricates approval" failure mode this whole
  design exists to prevent.
- **Letting a `PlanAuthorization` authorize an entire Plan at once (all
  steps)**: rejected — directly contradicts `ADR-021`'s "never one
  blanket approval for a whole preset" and this task's own "never
  authorize all future steps implicitly."
- **Allowing the AI/MCP boundary to both request and grant authorization,
  gated only by a stronger prompt/policy check**: rejected — a policy
  check implemented in the same trust domain as the thing it's supposed
  to constrain (the model's own request-handling path) is not a trust
  boundary; `ADR-012`'s "private key custody lives entirely outside the
  MCP server's host/process" precedent is adopted instead, structurally,
  not just procedurally.
- **A destructive-operation flag on the general authorization artifact**:
  rejected in favor of a wholly separate artifact type — see "Destructive
  operations" for the specific reasoning (a flag can be forgotten; a
  separate type cannot be reached by accident).

## Non-goals (explicitly, for this ADR)

- Does not implement `PlanDigest` computation, `PlanAuthorization`/
  `DeprovisionAuthorization` construction/verification, any new
  `DigestPurpose` member, any signing tool extension, or any storage
  schema for authorization artifacts.
- Does not build an `AuthorizationRequest`-shaped MCP tool or CLI
  subcommand.
- Does not implement the freshness re-check engine.
- Does not implement any execution coordinator for any of the three
  named mechanisms.
- Does not add, modify, or activate any WRITE MCP tool.
- Does not populate `WriteEndpoints` or activate any WRITE capability.
- Does not implement fail-closed runtime enforcement in `store.py`.
- Does not call `advance()` or perform any TPM/Tier1-store/pfSense/
  Proxmox/witness-daemon mutation.
- Does not change the public MCP contract.
- Does not modify, reopen, or supersede any `ADR-021` decision.

## Future implementation phases (recommended, not scheduled or authorized)

Mirrors `ADR-021`'s companion spec's own "each phase is its own future
authorization" discipline exactly:

- **Phase A — this ADR's acceptance.** Architectural only, as stated in
  its Status line.
- **Phase B — `PlanDigest` computation, no execution.** A new, narrowly
  scoped, read-only function computing a `PlanDigest` over an existing
  `SecurityPosturePlan` — no change to `security_plan.py`'s shipped
  behavior/schema. Independently testable (determinism, exact
  field-participation per "PlanDigest" above) before anything else
  exists.
- **Phase C — authorization data model, no execution.** `PlanAuthorization`/
  `DeprovisionAuthorization` dataclasses, canonicalization, and
  signature *construction* (the signing-tool side, entirely outside the
  MCP server's process, per `ADR-012`'s precedent) — still produces no
  runtime effect.
- **Phase D — authorization *verification*, no execution.** Server-side
  `verify_bindings()`-equivalent logic, storage/retrieval by
  `authorization_id`, expiry/replay checks — provably correct against a
  battery of the threat-model rows above, still connected to nothing
  that mutates anything.
- **Phase E — freshness/precondition engine.** The three-point
  re-check machinery, built and tested against synthetic drift/anomaly
  scenarios exactly as `security_plan.py`'s own adversarial-review
  fixes were.
- **Phase F — execution coordinator for the `CONFIGURATION`-class
  mechanism only** (the simplest of the three — no new durability
  primitive required, arguably). Deliberately the narrowest possible
  first real "execution" of anything.
- **Phase G — execution coordinator around existing `RecoveryContract`/
  `MutationExecutor` machinery**, wiring `PlanAuthorization` in front of
  the already-accepted Milestone 6 "prepare/dry-run/confirm sequence"
  (`TIER1_ROADMAP.md`) — this phase is where this ADR's design and the
  pre-existing Tier 1 roadmap converge.
- **Phase H — MCP WRITE exposure**, only after Phases B–G are each
  independently proven, and only alongside Milestone 9's own,
  independent activation decision (`TIER1_ROADMAP.md`) — this ADR does
  not shortcut, replace, or pre-approve that decision.

The first actual mutation, whenever separately authorized, should remain
`ADR-020`'s already-named candidate (firewall-alias description-only
`PATCH`) or whatever Milestone 0 process next names — deliberately
boring, reversible, and tightly bounded, unaffected by this ADR.

## Owner review (2026-08-11) — resolution of the original five questions

Performed prior to, and as the basis for, the owner's acceptance
decision recorded in "Acceptance note" above. Four of the five original
questions are resolved below, within already-accepted repository
architecture/precedent — no new architectural choice was required for
them. One remains genuinely open, now with a concrete, actionable
deferral rather than a vague one — explicitly not a blocker to
acceptance, per the owner's own acceptance decision.

### 1. Durable persistence for non-`RecoveryContract` execution mechanisms — **RESOLVED, no new store**

**Question, restated precisely**: for `CONFIGURATION`/`DEACTIVATION`-class
and `ANCHOR_PROVISIONING`/`SERVICE_DEPLOYMENT`-class steps — neither
`RecoveryContract`-shaped, so neither inherits its durable
compare-and-set/restart-recovery machinery — should a new, small,
`SqliteRecoveryContractStore`-style HMAC-authenticated ledger durably
record every `authorization_id` ever consumed, so replay can be detected
across a process restart the same way it already is for pfSense-API-class
steps?

**Why it matters**: without *some* durable answer to "has this
`authorization_id` already been used," the design's own claimed
replay-resistance property would be unenforced in practice for exactly
the two mechanism classes that don't inherit it for free from
`RecoveryContract`.

**Options considered**: (a) build a new HMAC-authenticated ledger,
mirroring `SqliteRecoveryContractStore`'s pattern; (b) rely on each
class's own already-existing durable source of truth — git's commit
graph for config-class, `anti_rollback_tpm_host_witness.md`'s
already-accepted "derive state, don't trust a log" discipline plus a
never-survives-restart authorization lifetime for hardware-class; (c) a
lighter single flat-file ledger as a middle ground.

**Recommendation and resolution**: (b), adopted, no new persistence
primitive. Detailed reasoning moved into "Durability for config-class
and hardware-class execution" (Crash/restart semantics, above) and the
matching Threat-model findings row, rather than restated here.

**Security tradeoff**: no single, unified "has this authorization been
consumed" answer exists across all three mechanism classes — but each
class already has its own trust-model-appropriate durable source of
truth (`RecoveryContract` rows; git commits; live TPM/store state via
fresh `discover`), and a fourth, parallel ledger would duplicate, not
strengthen, those guarantees, while adding a real risk of the ledger and
the underlying source of truth disagreeing.

**Implementation impact**: removes new-storage-schema design from
Phase C/D's scope entirely for these two classes; narrows both phases to
artifact construction/verification logic only.

**Can this be deferred beyond acceptance?** Already resolved now — not
deferred. This is a design decision (not an implementation), safely
made within already-accepted precedent (`anti_rollback_tpm_host_witness.md`'s
own discipline), so there is no reason to leave it open.

### 2. Overlapping/chained authorizations across distinct future capabilities — **remains genuinely open; concrete deferral, not resolution**

**Question, restated precisely**: once a second real WRITE capability
exists (beyond Milestone 0's single named candidate), could two
separately, validly, narrowly-authorized `PlanAuthorization`s — each
individually correct under this design — combine at the *pfSense
configuration* level to produce a security-relevant outcome neither
alone would have (e.g., two independently-reasonable firewall changes
that are jointly unsafe)? Should this design build a cross-capability
interaction-review mechanism now?

**Why it matters**: this is not a flaw in `PlanAuthorization`'s own
scoping (each artifact remains exact, narrow, and independently
verified regardless) — it is a question about whether *domain-level*
interaction risk between separately-authorized capabilities needs its
own review layer, a different concern from authorization-artifact
security.

**Options considered**: (a) design a cross-capability review mechanism
now, speculatively; (b) explicitly defer as a domain-risk-assessment
question, not an authorization-design question, with no forward-pointer;
(c) defer, but bind the deferral to a concrete future trigger.

**Recommendation**: (c). **This genuinely requires a future owner-level
decision and is not resolved by this review** — there is no second real
capability yet to reason about, so any mechanism designed now would be
speculative and likely wrong or incomplete. What *is* resolved now: the
deferral itself is made concrete rather than left as an unanchored
"someday" note — every future Milestone-0-successor candidate-naming
decision (`ADR-020`'s own precedent) must, from this ADR onward,
explicitly assess interaction with every previously-authorized
capability as part of its own risk analysis, extending
`WRITE_ENDPOINT_RISK_MATRIX.md`'s existing per-endpoint discipline
rather than inventing a parallel one.

**Security tradeoff**: leaving this open means this specific interaction
class remains structurally unaddressed until a second capability exists
— accepted, because a mechanism designed against zero real cases risks
being wrong, and this project's own repeated practice (`ADR-021`
question 6, `ADR-015`'s provisional numbers) is to defer exact
mechanisms until real and imminent, not to guess ahead of evidence.

**Implementation impact**: none on Phases A–H below; the trigger lives
in a future Milestone-0-successor ADR's own scope, not this one's.

**Can this be deferred beyond acceptance?** **Yes — this is the one item
that must remain open.** Exact decision required, when the time comes: a
future Milestone-0-successor ADR naming a second WRITE capability must
include an explicit "interaction with existing authorized capabilities"
section before that capability can be authorized — this is now a binding
requirement on that future process, not merely a suggestion, but the
mechanism itself is not designed until a real second capability exists.

### 3. Concrete authorization-expiry numeric values — **RESOLVED as mechanism-accepted/numbers-provisional, mirroring `ADR-015`**

**Question, restated precisely**: what are the exact `expires_at`
durations per risk class (e.g., minutes for hardware-class, hours for
config-class)?

**Why it matters**: too short creates operational pressure to work
around the mechanism (`ADR-015`'s own self-challenge reasoning); too
long weakens defense-in-depth. However: the mandatory pre-`EXECUTING`
freshness re-check is **independent of and in addition to** `expires_at`
— so the exact numeric value is a secondary control, not the primary
TOCTOU defense, which lowers the stakes of getting the number wrong.

**Options considered**: (a) commit to exact numbers now; (b) defer to
lab evidence, exactly as `ADR-015` already did for its own rate/blast-radius
defaults, marking the mechanism Accepted and the numbers explicitly
provisional; (c) provide a non-binding bounded range now.

**Recommendation and resolution**: (b), adopted directly as precedent,
not merely by analogy. `ADR-015`'s own Status line already reads
"Accepted (mechanism); numeric defaults remain provisional pending
disposable-lab evidence" — this ADR's authorization-lifetime numbers
should be accepted under the identical framing if/when this ADR itself
is accepted, rather than treated as a blocker to acceptance.

**Security tradeoff**: low — the primary TOCTOU defense (the mandatory
freshness re-check) does not depend on the exact expiry value, so
deferring the number carries materially less risk than deferring, say,
the freshness-recheck requirement itself would.

**Implementation impact**: Phase C (authorization data model) needs some
number to make the dataclass constructible/testable during development;
that default is explicitly test-only/provisional, exactly as
`RateLimits`'s actual field values already are in `rate_policy.py`.

**Can this be deferred beyond acceptance?** Yes, and this is now the
recommended, explicit framing (not a loose "figure it out later") —
identical in kind to how `ADR-015` was itself accepted.

### 4. Declarative/itemized authorization input format — **RESOLVED, not needed as a new mechanism given question 1's resolution**

**Question, restated precisely**: should a machine-parseable, file-based,
itemized authorization input format be designed now for
`CONFIGURATION_CHANGE`-class steps, per `ADR-021`'s own
declarative-vs-interactive scoping?

**Why it matters**: determines whether Phase C must also design a
serialization format for non-interactive authorization submission.

**Options considered**: (a) design the exact file format now; (b) defer
entirely until a concrete automation/CI use case is identified
(`ADR-021` question 6's precedent); (c) observe that, given question 1's
resolution above (config-class execution *is* a normal reviewed git
commit), no *new* format is actually needed for today's caller — this
project's own established operating pattern throughout every ADR-021/
ADR-022 session (an explicit, itemized, in-conversation owner
authorization statement, immediately followed by review and commit) is
already a working, informally-itemized authorization process for exactly
this mutation class.

**Recommendation and resolution**: (c) — a stronger resolution than a
plain deferral. No new format is designed or required by this ADR for a
human-operator caller; a machine-parseable format remains a genuine
*future* need only for a materially different caller this project has
not yet had (unattended CI/automation, not a human operator in
conversation) — deferred specifically to that trigger, not to a vague
"someday."

**Security tradeoff**: none introduced by this resolution — the existing
conversational-authorization-then-commit pattern already satisfies
itemized, non-blanket authorization for config-class changes, evidenced
by this project's own commit history.

**Implementation impact**: removes file-format design from Phase C's
scope entirely; a future declarative format (if ever needed) becomes its
own, separate, later phase gated on a real unattended-automation caller
existing.

**Can this be deferred beyond acceptance?** Resolved now, not merely
deferred — closed as "not needed for the caller this project actually
has today," with an explicit, narrow trigger for revisiting it.

### 5. `TIER1_ROADMAP.md` Milestone 6 cross-reference — **RESOLVED, applied**

**Question, restated precisely**: should Milestone 6's text (predates
`ADR-021`/`security_plan.py`, does not distinguish the three execution
mechanisms) be updated to point at `ADR-022`?

**Why it matters**: a future implementer reading only Milestone 6 could
design toward one universal executor, missing this ADR's three-mechanism
finding entirely.

**Options considered**: (a) rewrite Milestone 6; (b) leave it untouched;
(c) add one small, purely additive cross-reference sentence, no
restatement.

**Recommendation and resolution**: (c), applied as part of this review —
`TIER1_ROADMAP.md` is a living project document, not an ADR with its own
acceptance gate, and already cross-references ADRs routinely; a one-line
pointer is a safe, in-scope documentation edit, not a new decision. See
`TIER1_ROADMAP.md`'s Milestone 6 section for the applied cross-reference.

**Security tradeoff**: none — documentation clarity only.

**Implementation impact**: none on code; reduces future misreading risk.

**Can this be deferred beyond acceptance?** Not deferred — applied now,
since it costs nothing and closes a real gap identified during this
ADR's own reading phase.

### Summary: what remains genuinely open

Of the original five questions, **four are resolved** within already-accepted
architecture/precedent (1, 3, 4, 5) and require no further owner
decision to proceed to acceptance. **One item (2, overlapping/chained
authorizations) remains genuinely open** and is not resolved by this
review — it requires a real second WRITE capability to exist before any
concrete mechanism can be designed against it; the concrete, binding
deferral above (mandatory interaction-review section in any future
Milestone-0-successor ADR) is the actionable resolution available today.
This is not a blocker to accepting this ADR's own architecture — it is
explicitly scoped to a *future* ADR's own process, the same way
`ADR-021`'s own "software backend" and "read_only + software" questions
were accepted as open, named, future-triggered items rather than
blockers to that ADR's acceptance.

## Architectural consistency review (owner request, 2026-08-11)

Five specific consistency points, checked directly against the design
text above rather than re-asserted from memory:

**A. `PlanAuthorization` scope.** Confirmed, unchanged: "`PlanAuthorization`
— the authorization artifact" (`plan_digest` field: "Exact binding to
one `PlanDigest`"; `authorized_step_ids` field: "Explicit, non-empty,
ordered tuple — never a wildcard, never 'all remaining', never
inferred") and the state-machine table's "Never a legal transition, by
construction" paragraph (no transition ever widens
`authorized_step_ids` after `AUTHORIZED`; widening requires an entirely
new artifact). No wildcard field shape exists anywhere in the schema.
No change needed.

**B. Destructive operations.** Confirmed, unchanged: "Destructive
operations" states `DeprovisionAuthorization` is "a distinct artifact
*type*... never a `destructive: bool` flag," and "Alternatives
considered" records the flag-based design as explicitly rejected, with
the reasoning ("a flag can be forgotten... a separate type cannot be
reached by any code path that only knows how to construct the routine
one"). No code path in the design constructs a `DeprovisionAuthorization`
from any `PlanAuthorization`-handling logic — they share no
construction, verification, or storage path even conceptually. No
change needed.

**C. Execution classes.** Confirmed, unchanged: "Scope: which mutation
classes this covers" table states plainly that pfSense API mutations use
`RecoveryContract`/`MutationExecutor` (`ADR-006`/`014`), config-class
mutations use source-controlled code/config change, and hardware-class
mutations use the existing interactive TPM/console procedure — three
named mechanisms, with the explicit sentence "this design does not
propose one universal executor that every `PlanStep` eventually flows
through." No change needed.

**D. Freshness — four distinguished conditions.** Confirmed, and
strengthened by this review's resolution of question 1: the "Failure
taxonomy" table already carries four separate rows —
ordinary staleness (`PlanDigest`/prerequisite/`target_validity`
mismatch → `STALE`), security anomaly (mismatch/indeterminate state →
refused outright, never `STALE`), authorization expiry (ordinary,
expected), and replay (already-consumed, "**Security-relevant**,
logged distinctly from ordinary expiry"). These four were already
distinct in the original draft; this review's resolution of question 1
additionally clarifies *how* replay is detected/bounded for the two
mechanism classes that don't inherit it from `RecoveryContract` for
free (see "Durability for config-class and hardware-class execution"),
without collapsing any of the four categories into another. No further
change needed beyond that addition.

**E. Crash/restart — not a bearer capability.** Newly made explicit by
this review, not merely "confirmed" (the original draft's guarantee was
correct but implicit, scattered across the freshness and crash/restart
sections rather than stated once, plainly) — see the new "Persisted
authorization is never a bearer capability" subsection under
"Crash/restart semantics": every use of a `PlanAuthorization`,
regardless of how long it has existed or survived a restart, requires
all four checks (fresh `plan_digest` match, unexpired, unconsumed,
passing freshness re-check) unconditionally; persistence only affects
how long an artifact remains *eligible* to attempt those checks, never
substitutes for any of them.

## Amendment (2026-09-05): off-runtime anchor-assurance verification via `AnchorEvidenceExport`

Prompted by a real Round-1 Batch-1 authorization-signing failure: the
isolated Batch-1 signer's freshly re-derived `PlanDigest` did not match
an authorization preview's own copy. Forensic reconciliation proved the
cause was an environment-completeness gap in the signing instructions
given to the signer (missing `PFSENSE_TIER1_STORE_PATH`/`_KEY_FILE`/
`PFSENSE_TIER1_WITNESS_*` env vars), not a real security-state drift and
not a code regression — but it surfaced a genuine architectural gap: the
signer's *only* way to independently re-derive anchor assurance was
holding a periodically-stale copy of the runtime `RecoveryContract`
store plus its integrity key, which is broader trust than the signer's
actual job requires. This amendment records the narrow fix, reviewed
and approved by the owner ("OWNER DECISION — APPROVED WITH
TRUST-BOUNDARY CONSTRAINTS," 2026-09-05) as an amendment to this ADR
(and, for its discovery-model implications, `ADR-021`) rather than a new
ADR, per `ADR-022`'s own precedent of extending, not reopening, existing
execution-boundary decisions. See
[`docs/tier1/specs/anchor_evidence_export_trust_boundary.md`](../tier1/specs/anchor_evidence_export_trust_boundary.md)
for the full design record, including the candidate key-custody analysis.

This amendment makes the following 7 points explicit:

1. **Runtime discovery is unchanged.** `security_discovery.
   discover_anchor_assurance()`/`discover_security_posture()` (`ADR-021`
   Phase B) are not modified by this amendment — same store read, same
   witness client, same `AnchorAssuranceDiscovery` construction. The new
   `security_discovery_export.discover_anchor_assurance_from_export()`
   is an **additional**, off-runtime-only path for an isolated verifier,
   never a replacement for or a variant on the runtime path.
2. **The off-runtime verifier consumes an authenticated equivalent of
   the same evidence, never a lesser substitute.** A signed
   `AnchorEvidenceExport` (`tier1/anchor_evidence_export.py`) carries
   exactly `schema_version, store_id, handle, baseline, provisioned_at,
   issued_at, expires_at` — the precise fields `evidence_fingerprint_
   payload()` (below) actually consumes, no more. The signer still
   performs its own live TPM witness read and cross-checks it against
   the export's claimed baseline; it never trusts the export's baseline
   as sufficient on its own.
3. **Canonical `PlanDigest` semantics are unchanged.**
   `compute_plan_digest()`/`_plan_payload()`/`evidence_fingerprint_
   payload()` (`security_plan_digest.py`) are not modified. There is no
   second digest algorithm and no signer-specific plan or digest schema.
   `security_plan.generate_security_posture_plan_from_discovery()` is a
   new entry point that delegates to the exact same pure
   `_build_plan_from_discovery()` body `generate_security_posture_
   plan()` already used — proven, not merely asserted, to produce a
   byte-identical `compute_plan_digest()` result for digest-relevant-
   equivalent store-based and export-based evidence
   (`tests/test_security_plan_from_discovery.py`).
4. **Trusting a preview's own claimed `requested_plan_digest` remains
   forbidden.** This was true before this amendment
   (`sign_authorization_preview()` in `signing/write_batch1_signing.py`
   already independently recomputes the digest and refuses on
   mismatch — the exact mechanism that correctly failed closed in the
   Round-1 incident this amendment responds to) and remains true after
   it: an `AnchorEvidenceExport` changes *what evidence the signer's own
   independent recomputation is grounded in*, never *whether* the
   signer independently recomputes at all.
5. **Replicating the runtime `RecoveryContract` store, its encryption
   key, or its integrity key onto the signer remains forbidden.** This
   is the specific practice this amendment eliminates the *need* for,
   not merely a restated existing rule — `discover_anchor_assurance_
   from_export()` never imports `production_store.py` or `sqlite3`,
   proven by dedicated AST isolation tests
   (`tests/test_security_discovery_export_isolation.py`).
6. **A signer's witness-client identity must not be advance-authorized.**
   The signer performs only a read-only `GET /anchor/read` witness call,
   identical in shape to the runtime's own read-only witness use, and
   must never be present in the witness daemon's `WITNESS_ADVANCE_
   CLIENT_FINGERPRINTS` allow-list. This amendment does not itself
   verify the signer's live daemon configuration (that is an
   owner-only, Proxmox-host-side check — see the trust-boundary spec's
   own Non-goals) but records the requirement explicitly so it cannot be
   silently assumed satisfied.
7. **Provisioning a real posture-evidence signing authority is an owner
   gate, not an implementation detail.** No code in this amendment
   creates, copies, installs, or reads a real (non-test, non-ephemeral)
   private key for the posture-evidence authority.
   `sign_anchor_evidence_export()` exists and is exercised only by tests
   with synthetic, ephemeral keys. Where the real key should eventually
   live is recorded as an open decision, with a recommendation, in the
   trust-boundary spec above — this amendment implements the mechanism,
   not the key-custody decision.

No change to `PlanAuthorization`/`PlanAuthorizationV2`, the three-point
freshness/TOCTOU model, per-step authorization, the destructive-operation
separation, or any other already-accepted content in this ADR.

## References

- [`ADR-021`](ADR-021-security-posture-provisioning.md) — the planning
  layer this design sits above; no decision here reopens it
- [`SECURITY_POSTURE_PROVISIONING.md`](../SECURITY_POSTURE_PROVISIONING.md) —
  `ADR-021`'s companion spec, including the "Planning slice" section
  this ADR extends conceptually
- [`ADR-006`](ADR-006-recovery-contract-philosophy.md),
  [`ADR-012`](ADR-012-confirmation-authority.md),
  [`ADR-013`](ADR-013-reconciliation-authority.md),
  [`ADR-014`](ADR-014-sealed-executor-interface.md),
  [`ADR-015`](ADR-015-rate-and-blast-radius-defaults.md) — the existing
  execution architecture this design integrates with, not replaces
- [`ADR-004`](ADR-004-capability-profiles.md),
  [`ADR-005`](ADR-005-inert-tier-0-write-infrastructure.md),
  [`ADR-007`](ADR-007-security-first-public-schemas.md),
  [`ADR-008`](ADR-008-fail-closed-configuration.md),
  [`ADR-011`](ADR-011-whole-store-anti-rollback-anchor.md),
  [`ADR-019`](ADR-019-api-surface-capability-discovery-and-extension-architecture.md),
  [`ADR-020`](ADR-020-milestone-0-first-write-capability-candidate.md) —
  supporting principles reused throughout
- `src/pfsense_mcp/tier1/{contract,confirmation,reconciliation,executor,
  state_machine,rate_policy,canonical,audit}.py` — the existing,
  already-tested primitives this design's "reuse, don't reinvent"
  posture is grounded in
- `docs/tier1/specs/{confirmation_authority,reconciliation_authority,
  sealed_executor,capability_adapter_contract,rate_blast_radius_policy,
  anti_rollback_tpm_host_witness}.md`
- [`TIER1_ROADMAP.md`](../TIER1_ROADMAP.md) — Milestone 6 (audit,
  authorization, MCP surface design, now cross-referencing this ADR
  directly — see "Owner review," question 5) and Milestone 9 (activation
  decision), both unaffected but directly relevant
- [`WRITE_ENDPOINT_RISK_MATRIX.md`](../WRITE_ENDPOINT_RISK_MATRIX.md) —
  the per-endpoint risk taxonomy this design's per-step risk-class
  granularity table is grounded in, not duplicating
- [`THREAT_MODEL.md`](../THREAT_MODEL.md) — actor A6 and the Tier 1
  adversarial-paths table, both extended by this ADR's own threat-model
  findings rather than restated
- `src/pfsense_mcp/security_plan.py`, `security_discovery.py`,
  `security_cli.py` — the shipped, unmodified planning layer this ADR's
  `PlanDigest`/freshness design reads from
