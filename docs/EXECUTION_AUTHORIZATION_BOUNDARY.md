# Execution-authorization boundary — companion specification

Status: companion specification to
[`ADR-022`](adr/ADR-022-execution-authorization-boundary.md), **Accepted**
(2026-08-11, owner — see `ADR-022`'s "Acceptance note"). Read `ADR-022`
first; it is authoritative for every decision, the state machine,
`PlanDigest`/`PlanAuthorization` field lists, the freshness model, the
threat-model findings, and the future-phase list. **Acceptance was
architectural only and did not itself authorize implementation** —
`ADR-022`'s own Phase B (canonical `PlanDigest` computation, plan
identity only, still no authorization artifact, no verification, no
execution), Phase C (`PlanAuthorization`/`DeprovisionAuthorization`
data models, canonicalization, signature construction on the
signing/operator side only, still no verification, no execution), and
Phase D (pure signature/expiry/plan-step-scope verification plus
durable one-time consumption tracking, still no freshness re-check, no
execution, per the owner's `ADR-023`-recorded scope decisions) were
each separately authorized and implemented the same day; see
"Implementation status" below. Phase E onward (freshness/precondition
engine, execution coordinators, MCP WRITE exposure) remains
separate, future, explicitly-scoped authorizations neither `ADR-022`'s
acceptance nor Phase B/C/D's implementation grants. This document adds two
things the ADR does not carry: a scoping/affected-code inventory and a
running "implementation status" record, mirroring
[`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md)'s
own "Phase B/Planning slice — implemented" pattern.

**Owner review (2026-08-11)**: before acceptance, `ADR-022`'s five
originally-unresolved questions were reviewed. Four were resolved within
already-accepted architecture/precedent (no new durable authorization
ledger needed; authorization-lifetime numbers accepted as
mechanism-only/provisional, mirroring `ADR-015`; no new
declarative-authorization file format needed given the durability
resolution; the `TIER1_ROADMAP.md` Milestone 6 cross-reference applied,
see below). One (overlapping/chained authorizations across a future
second WRITE capability) remains genuinely open, with a concrete future
trigger rather than a vague deferral, and was accepted explicitly as a
non-blocking, deferred item — see `ADR-022`'s own "Owner review
(2026-08-11)" section for the full seven-point analysis of each, and its
"Acceptance note" for the owner's acceptance decision itself.

## Relationship to `ADR-021`'s phased plan

`ADR-021`'s companion spec already named Phases C–G (capability-posture
`read_only`, anchor-assurance `hardware_witness`, capability-posture
`write_protected`, downgrade paths, the `software` anchor backend).
`ADR-022` does not renumber or replace any of them — it defines the
authorization mechanism those phases will need the first time any of
them reaches an actual `PROVISIONING`/`ACTIVE` transition, rather than
each phase inventing its own ad hoc consent mechanism independently.
Concretely: Phase C (`read_only`, trivial by construction) may not need
`PlanAuthorization` at all, since it requires no mutation beyond
confirming the already-default state; Phases D (`hardware_witness`) and
E (`write_protected`) are exactly the cases this ADR's three-mechanism
scope finding (hardware-class vs. activation-class) was written for.

## Implementation status

**Phase D — pure `PlanAuthorization` verification (signature, expiry,
plan/step scope) plus durable one-time `authorization_id` consumption
tracking — implemented (2026-08-11), under the owner's explicit
scope decisions recorded in [`ADR-023`](adr/ADR-023-authorization-verification-boundary.md)'s
own "Owner decisions" section.** Still no runtime effect connected to
anything that mutates anything: no freshness re-check (`ADR-022`'s own
Phase E), no `RecoveryContract` creation, no execution coordinator, no
MCP tool, no wiring into `MutationExecutor`/`tier1/state_machine.py`/
`WriteApiClient`/`WriteEndpoints`/pfSense/Proxmox/TPM/witness state.
`ADR-021`/`ADR-022` remain unmodified. See `ADR-023`'s own
"Implementation status" section for the complete schema/API detail;
not restated here in full to avoid two documents drifting out of sync
-- summary only:

- `src/pfsense_mcp/security_authorization.py` (modified, additive) --
  new `plan_authorization_payload_of()`.
- `src/pfsense_mcp/security_authorization_verifier.py` (new) --
  `verify_plan_authorization_signature()`, `plan_authorization_is_current()`,
  `plan_authorization_authorizes_step()`. Fifth, narrow
  `pfsense_mcp.tier1` isolation exemption (only `ed25519_authority`).
- `src/pfsense_mcp/tier1/authorization_consumption_store.py` (new) --
  `AuthorizationConsumptionStore` Protocol + `SqliteAuthorizationConsumptionStore`,
  a wholly separate, minimal, HMAC-authenticated, atomic-insert-once
  store -- never extends `SqliteRecoveryContractStore`.
- `src/pfsense_mcp/tier1/errors.py` (modified, additive) -- new
  `AuthorizationConsumptionError`.
- 60 new tests (23 verifier + 9 verifier-isolation + 21 store + 4
  store-isolation + 3 cross-module independence).

**Phase C — `PlanAuthorization`/`DeprovisionAuthorization` data models,
canonicalization, and signature construction — implemented
(2026-08-11).** Produces no runtime effect: no verification, no
acceptance/consumption/replay tracking, no freshness enforcement, no
execution, no `RecoveryContract` creation, no MCP tool, no CLI
subcommand. `ADR-021`/`ADR-022` remain unmodified.

### What Phase C implements

- `src/pfsense_mcp/security_authorization.py` (new) — `PlanAuthorization`/
  `PlanAuthorizationPayload`/`AuthorizationEvidenceFingerprint` and
  `DeprovisionAuthorization`/`DeprovisionAuthorizationPayload`, plus
  `build_plan_authorization_payload()`/`sign_plan_authorization()` and
  `build_deprovision_authorization_payload()`/`sign_deprovision_authorization()`.
  Fourth, narrow, explicit exception to `pfsense_mcp.tier1` never being
  imported from outside its own package — imports only
  `canonical.DigestPurpose`/`canonical.canonical_json` (no store/witness/
  confirmation/contract access). Signing functions are pure over
  caller-supplied `Ed25519PrivateKey` material; this module is never
  imported by `security_cli.py`, any MCP tool, or any other
  request-handling code path (proved by
  `tests/test_security_authorization_isolation.py`). No CLI subcommand
  or MCP tool is added — see the module's own "CLI boundary" docstring
  section for why (unresolved key-management/UX questions this phase
  does not invent answers for).
- `src/pfsense_mcp/tier1/canonical.py` (modified, additive only) —
  `DigestPurpose` gained `PLAN_AUTHORIZATION`/`DEPROVISION_AUTHORIZATION`
  (now 10 members), each included as a literal `"digest_purpose"` field
  inside the respective signing payload for structural domain
  separation. No existing member's meaning changed.
- `src/pfsense_mcp/security_plan_digest.py` (modified) — `_evidence_fingerprint()`
  made public as `evidence_fingerprint_payload()` so `security_authorization.py`
  reuses the one definition of `PlanAuthorization.evidence_fingerprint`'s
  six sub-fields rather than re-deriving an equivalent structure a
  second, possibly-drifting way. No behavior change to `compute_plan_digest()`/
  `verify_plan_digest()`.

### `PlanAuthorization` schema (version 1)

`schema_version`, `authorization_id`, `plan_digest` (computed via
`compute_plan_digest()`, never caller-trusted), `authorized_step_ids`
(explicit, non-empty, duplicate-free tuple; signed sorted, not in
caller-supplied order), `authority_id`, `algorithm` (`"ed25519-v1"`
only), `proof` (64-byte Ed25519 signature, excluded from its own
payload), `issued_at`/`expires_at` (UTC, no built-in default duration),
`risk_class` (`AuthorizationLevel`, the highest friction level among the
authorized steps), `evidence_fingerprint` (6-field structured copy of
`PlanDigest`'s own fingerprint). A step whose `authorization_required`
is `SEPARATE_DEPROVISION_AUTHORIZATION`/`UNDETERMINED_NOT_IMPLEMENTED`
is refused at construction, defense-in-depth. Every field except `proof`
participates in the signature; there is no non-participating metadata
field on this artifact (see the module's own "Signed-payload fields vs.
metadata" docstring section).

### `DeprovisionAuthorization` schema (version 1)

A wholly separate artifact type (own schema-version namespace, own
`DigestPurpose.DEPROVISION_AUTHORIZATION` domain, own field set — no
`plan_digest`/`authorized_step_ids`/`risk_class`/`evidence_fingerprint`
field at all): `schema_version`, `authorization_id`,
`target_identity_digest` (already-computed, caller-supplied 64-hex
digest — this module defines no way to derive one from a real TPM NV
index or store key, per `ADR-022`'s own deliberate deferral),
`authority_id`, `algorithm`, `proof`, `issued_at`/`expires_at`. No
construction, verification, or storage path is shared with
`PlanAuthorization` even conceptually; no code path anywhere in this
repository computes a real `target_identity_digest`, so only tests,
using a synthetic one, ever construct one.

### No bearer capability

Neither dataclass exposes `.execute()`, `.apply()`, or
`.is_authorized_for_runtime()` (proved by
`test_never_defines_an_execute_or_apply_or_runtime_validity_method`).
`__post_init__` performs structural validation only — never a
runtime-authorization-validity judgment (expired/consumed/stale). There
is no verifier, consumer, or executor anywhere in this module.

### Tests

`tests/test_security_authorization.py` (regression + adversarial:
determinism; PlanDigest/step-set/added-step/removed-step participation;
step-set reordering does not change signed identity; duplicate/empty/
unknown/disallowed-level step IDs rejected; malformed PlanDigest/schema
version rejected; signer identity/authorization identity/issued-at/
expires-at participation; risk_class computed as the highest authorized
step's `AuthorizationLevel`, proved non-reusable for a higher-risk step
set; malformed/non-UTC timestamp rejection; no built-in default expiry
duration; proof excluded from its own payload; real Ed25519 signature
construction and verification via `cryptography`'s own primitive
directly; changing any signed field or widening the step set after
signing invalidates verification; `PlanAuthorization`/
`DeprovisionAuthorization` structural distinctness and cross-type
signature non-verification; raw-string/Enum/bool coercion safety;
unknown-keyword rejection; proof length/emptiness validation; no private
key material in either artifact or leaked during signing; no I/O of any
kind) and `tests/test_security_authorization_isolation.py` (9 AST-based
structural tests: only `canonical` imported from `pfsense_mcp.tier1`;
no mutating/IO-shaped calls; no `RecoveryContract`/`ConfirmationEvidence`-family
references; no `execute`/`apply`/`verify`/`consume`-named methods; exact
public surface; no production importer anywhere in the repository).
`tests/tier1/test_isolation.py`'s exemption list now names
`security_authorization.py` as the fourth, narrow exception.

**Phase D — implemented the same day** (pure `PlanAuthorization`
signature/expiry/plan-step-scope verification plus durable one-time
consumption tracking); see this document's own "Implementation status"
section above and
[`ADR-023`](adr/ADR-023-authorization-verification-boundary.md)'s
"Implementation status" section for the complete detail. Future phases
(see `ADR-022`'s own "Future implementation phases" for the recommended
sequence, starting at Phase E — the freshness/precondition engine,
still out of scope) should record their own "implemented" entry here
when and if separately authorized and built.
[`ADR-024`](adr/ADR-024-execution-authorization-coordination.md)
(Proposed, 2026-08-11) is an architecture/decision pass covering the
combined territory `ADR-022` numbers as Phases E/F/G — freshness
re-check design, the proposed execution-coordinator boundary,
consumption/crash semantics, and the `target_identity_digest` question.
Its own **Slice E1 (the freshness/precondition re-check primitive) has
since been separately authorized under a fixed, narrow scope and
implemented** — new `src/pfsense_mcp/security_plan_freshness.py`,
`plan_authorization_is_fresh()`, composing the existing
`generate_security_posture_plan()`/`compute_plan_digest()`/
`verify_plan_digest()` only, zero `pfsense_mcp.tier1` imports, no
authorization consumption, no coordinator, no `MutationExecutor`/
state-machine change. See `ADR-024`'s own "Implementation status"
section for the complete detail. The coordinator and every other item
in `ADR-024`'s "Implementation slices" remain unauthorized,
unimplemented proposals — this document and `ADR-024` should be
updated in place, not restated here, if and when any of that is
separately authorized and built.

**Phase B — canonical `PlanDigest` computation — implemented
(2026-08-11).** Plan identity only. No `PlanAuthorization`/
`DeprovisionAuthorization` construction or verification, no signing-tool
extension, no authorization-artifact storage schema, no MCP tool, no
execution/apply/provision command. `ADR-021` remains unmodified.

### What Phase B implements

- `src/pfsense_mcp/security_plan_digest.py` (new) — `compute_plan_digest(plan)`
  and `verify_plan_digest(plan, expected_digest)`, both pure, deterministic,
  and total over every `SecurityPosturePlan` `generate_security_posture_plan()`
  can produce. Third, narrow, explicit exception to `pfsense_mcp.tier1`
  never being imported from outside its own package — the only thing it
  imports from `pfsense_mcp.tier1` is `canonical` (pure, stateless
  canonicalization/hashing, zero I/O), never `store`/`contract`/
  `executor`/`confirmation`/`anti_rollback` or anything else the other
  two exemptions legitimately need. Reuses
  `tier1.canonical.digest_value()`/`canonical_json()` exactly, the same
  primitive `RecoveryContract.idempotency_key` already relies on — no
  parallel hashing/canonicalization system.
- `src/pfsense_mcp/tier1/canonical.py` (modified, additive only) — new
  `DigestPurpose.PLAN` member, domain-separating a `PlanDigest` from
  every other digest purpose (contract, confirmation, reconciliation,
  etc.) so one can never be replayed as another. No existing member's
  meaning changed.
- `src/pfsense_mcp/security_cli.py` (modified) — `plan`'s human output
  now shows `Plan digest (schema v1): <64-hex-char digest> (plan
  identity only -- not authorization)`; `--json` output gains
  `plan_digest`/`plan_digest_schema_version` top-level keys; the `--help`
  epilog gains one clarifying paragraph. `security_cli.py` deliberately
  imports only `PLAN_DIGEST_SCHEMA_VERSION`/`compute_plan_digest` from
  the new module, never `verify_plan_digest` — there is nothing in this
  build for it to verify against.

### `PlanDigest` schema (version 1)

Canonical JSON payload (hashed via `digest_value(DigestPurpose.PLAN, payload)`;
key order shown alphabetically for readability — `canonical_json()`
itself always sorts keys, so insertion order is never security-relevant):

```
{
  "schema_version": 1,
  "target_capability_posture": "read_only" | "write_protected",
  "target_anchor_assurance": "none" | "software" | "hardware_witness",
  "target_validity": "valid" | "invalid_combination" | "valid_not_implemented",
  "steps": [
    {
      "step_id": "<string>",
      "order": <int>,
      "axis": "capability_posture" | "anchor_assurance",
      "mutation_class": "<MutationClass value>",
      "authorization_required": "<AuthorizationLevel value>"
    },
    ...
  ],
  "evidence_fingerprint": {
    "capability_posture_value": "read_only" | "write_protected",
    "anchor_assurance_value": "none" | "software" | "hardware_witness" | "unknown",
    "anchor_evidence_state": "<AnchorEvidenceState value>",
    "anchor_baseline": <int> | null,
    "anchor_witness_value": <int> | null,
    "anchor_provisioned_at": "<ISO 8601 string>" | null
  },
  "overall_status": "<PlanOverallStatus value>",
  "safe_to_proceed": true | false
}
```

**Participates** (exactly ADR-022's own list, no more, no less):
`schema_version`; `target_capability_posture`/`target_anchor_assurance`/
`target_validity`; per step, in order: `step_id`/`order`/`axis`/
`mutation_class`/`authorization_required`; the six-field structured
evidence fingerprint above; `overall_status`/`safe_to_proceed`.

**Does not participate** (verified absent by dedicated regression
tests): step `action`/`description`/`blocked_reason`/`evidence`/
`reversible`/`implementation_available`/`security_impact`/
`prerequisite_satisfied`/`blocked`; plan `notes`/`validity_evidence`/
`blocking_findings`; `capability_posture_transition`/
`anchor_assurance_transition` (pure functions of already-participating
fields — including them would be redundant, not additionally safe); the
raw prose `evidence` tuples on `current.capability_posture`/
`current.anchor_assurance`.

Every optional value is represented as `null` when absent, never an
omitted key — `anchor_baseline: null` and "no `anchor_baseline` key at
all" are structurally impossible to confuse in this schema.

### Mutation-free evidence

`compute_plan_digest`/`verify_plan_digest` perform no I/O of any kind —
proven both structurally (AST inspection: the module's only
`pfsense_mcp.tier1` import is `canonical`; never calls a
mutating-shaped or `sqlite3`/`open`-shaped method) and behaviorally (a
test replacing `sqlite3.connect`/`builtins.open` with functions that
raise `AssertionError` if called, then computing digests for every
target combination). Computing or verifying a digest never mutates the
`SecurityPosturePlan` it operates on (frozen dataclass; also proven by a
dedicated equality-preserved test) and never touches `safe_to_proceed`
or any other field's value.

### Tests

`tests/test_security_plan_digest.py` (46 tests: determinism,
per-field participation in both directions, duplicate/reordered steps,
schema-version safety, verification semantics including rejection of a
caller-supplied digest issued for a different plan, enum/raw-string
coercion safety, payload leaf-type strictness, data-leak checks against
malformed-store and unreachable-witness scenarios, no-I/O behavioral
proof) and `tests/test_security_plan_digest_isolation.py` (8 AST-based
structural tests, including that `canonical` is the *only*
`pfsense_mcp.tier1` submodule ever imported here). `tests/test_security_cli.py`
gained 4 more covering human/JSON digest display and determinism.
`tests/tier1/test_isolation.py`'s exemption list now names
`security_plan_digest.py` as the third, narrow exception.

### Real production verification

`pfsense-mcp-security plan --capability-posture read_only
--anchor-assurance hardware_witness --json` against this project's own
production `PFSENSE_TIER1_*`/`WITNESS_*` environment: identical
`plan_digest` across repeated invocations; production Tier 1 store file
confirmed byte-identical before/after (SHA-256 unchanged).

## Affected code areas (identified for future scoping — none modified by this document)

| Area | Current state (verified by reading; Phase B/C/D changes noted explicitly) | Eventual relevance |
|---|---|---|
| `src/pfsense_mcp/security_plan.py` | Unmodified by Phase B/C/D — `SecurityPosturePlan`/`PlanStep` dataclasses, pure computation, no `pfsense_mcp.tier1` import | `security_plan_digest.py`/`security_authorization.py` (Phase B/C, implemented) are new, separate, read-only modules operating *on* this module's output — no change to this file's own shipped API/behavior |
| `src/pfsense_mcp/security_plan_digest.py` | **Phase B implemented (2026-08-11); modified for Phase C (2026-08-11)** — `compute_plan_digest()`/`verify_plan_digest()` unchanged; `_evidence_fingerprint()` made public as `evidence_fingerprint_payload()` so Phase C reuses it | Complete for Phase B's own scope; `security_authorization.py` (Phase C, implemented) calls `compute_plan_digest()`/`evidence_fingerprint_payload()`, never reimplements them |
| `src/pfsense_mcp/security_authorization.py` | **Phase C implemented (2026-08-11); modified for Phase D (2026-08-11)** — `PlanAuthorization`/`DeprovisionAuthorization` data models, canonical signing payloads, `sign_plan_authorization()`/`sign_deprovision_authorization()` unchanged; new `plan_authorization_payload_of()` added so Phase D's verifier reuses the exact payload reconstruction rather than re-deriving it | Complete for Phase C's own scope; `security_authorization_verifier.py` (Phase D, implemented) calls `plan_authorization_payload_of()`/`plan_authorization_signing_payload()`, never reimplements them |
| `src/pfsense_mcp/security_authorization_verifier.py` | **New, Phase D implemented (2026-08-11)** — `verify_plan_authorization_signature()`, `plan_authorization_is_current()`, `plan_authorization_authorizes_step()`, pure, three independent functions never composed. Fifth narrow `pfsense_mcp.tier1` isolation exemption (only imports `ed25519_authority`) | Complete for Phase D's own verification scope; a future Phase E freshness engine and any eventual WRITE-tool caller would call these directly, never reimplement signature/expiry/scope checking |
| `src/pfsense_mcp/tier1/authorization_consumption_store.py` | **New, Phase D implemented (2026-08-11)** — `AuthorizationConsumptionStore` Protocol + `SqliteAuthorizationConsumptionStore`, a wholly separate, minimal, HMAC-authenticated, atomic-insert-once store; never extends `SqliteRecoveryContractStore`, per the owner's explicit decision | Complete for Phase D's own consumption-tracking scope; a future WRITE-tool caller (Phase H) would call `try_consume()` directly as one of several required gates, never reimplement replay tracking |
| `src/pfsense_mcp/tier1/canonical.py` | **Modified, Phase B implemented; extended for Phase C** — `DigestPurpose` enum gained `PLAN` (Phase B), then `PLAN_AUTHORIZATION`/`DEPROVISION_AUTHORIZATION` (Phase C; now 10 members), additive only, no existing member's meaning changed; unmodified by Phase D | Phase D (verification, implemented) reuses these same purpose values via `plan_authorization_signing_payload()`; no new member needed |
| `src/pfsense_mcp/tier1/confirmation.py` | Unmodified — `ConfirmationEvidence`, `ConfirmationVerifier` Protocol, Ed25519 mechanism (`ADR-012`) | `PlanAuthorization` (Phase C, implemented) reuses this exact cryptographic mechanism (detached Ed25519, `authority_id`-based rotation) with its own digest-purpose domain separator — not a new cryptographic primitive; `confirmation.py` itself is not imported by `security_authorization.py`/`security_authorization_verifier.py` |
| `src/pfsense_mcp/tier1/ed25519_authority.py` | Unmodified — `PinnedAuthority`/`PinnedAuthoritySet` (`ADR-012`, reused twice already by confirmation/reconciliation) | `security_authorization_verifier.py` (Phase D, implemented) reuses this exact, already-reviewed mechanism as its sole `pfsense_mcp.tier1` dependency — no new cryptographic primitive |
| `src/pfsense_mcp/tier1/reconciliation.py` | `ReconciliationEvidence`, four-outcome enum (`ADR-013`) | `NEEDS_RECONCILIATION` (this design's state) is a pass-through to this existing, unmodified mechanism for pfSense-API-class steps only |
| `src/pfsense_mcp/tier1/store.py` | Unmodified — `SqliteRecoveryContractStore` (`ADR-006`), the precedent `authorization_consumption_store.py`'s atomicity/integrity/path-safety discipline mirrors but never extends or shares a schema with | Unaffected; remains the sole persistence for `RecoveryContract` rows |
| `src/pfsense_mcp/tier1/contract.py`, `state_machine.py`, `executor.py` | `RecoveryContract`, closed `RecoveryState` machine, `MutationExecutor` (`ADR-006`/`014`); unmodified by Phase D | Unaffected; `PlanAuthorization` becomes a precondition *for creating* a `RecoveryContract` for `ACTIVATION`-class steps only, per `ADR-022`'s "MCP WRITE boundary" ordering — that wiring remains unbuilt (Phase G) |
| `src/pfsense_mcp/tier1/errors.py` | **Modified, Phase D implemented (2026-08-11)** — new `AuthorizationConsumptionError(Tier1Error)`, additive only | Used only by `authorization_consumption_store.py`'s own fail-closed paths |
| `src/pfsense_mcp/tier1/rate_policy.py` | Store-backed counters, explicitly "not an authorization mechanism" (`ADR-015`) | Unaffected; remains a separate, later containment layer after authorization |
| `src/pfsense_mcp/write_endpoints.py`, `write_api_client.py` | `WriteEndpoints` (zero entries), `dry_run()`/`execute()` | Unaffected; allow-listing remains its own, separately-governed gate (`WRITE_ENDPOINT_RISK_MATRIX.md`, `ADR-020`), independent of plan-level authorization |
| `src/pfsense_mcp/tools/write/` | Empty, deliberately inert placeholder | The eventual home of any WRITE MCP tool that would enforce `ADR-022`'s "MCP WRITE boundary" ordering — nothing exists here yet |
| `scripts/tier1_store_bootstrap.py`, `witness_daemon/`, `docs/tier1/specs/anti_rollback_tpm_host_witness.md` | Existing hardware-class provisioning tooling/spec | The hardware-class execution mechanism `ADR-022`'s "Scope" table names — reused, not reimplemented, once a hardware-class `PlanAuthorization` is ever built |
| `tests/tier1/test_isolation.py` | **Modified, Phase B implemented; extended for Phase C and Phase D** — exemption list now names `security_plan_digest.py` (third), `security_authorization.py` (fourth), and `security_authorization_verifier.py` (fifth) | A future freshness-engine module (Phase E), if it needs to read (never construct) `RecoveryContract`/confirmation state, would need its own narrow, reviewed exemption — same discipline, not relaxed |
| `docs/TIER1_ROADMAP.md` | Milestone 6 ("audit, authorization, and MCP surface design") now carries a small, additive cross-reference note pointing to `ADR-022` (applied 2026-08-11, resolving `ADR-022`'s original question 5) | Text itself still predates the three-mechanism finding in detail; the note directs a future implementer to `ADR-022` before treating Milestone 6's authorization text as covering all mutation classes |

## References

- [`ADR-022`](adr/ADR-022-execution-authorization-boundary.md) —
  authoritative decision record
- [`ADR-021`](adr/ADR-021-security-posture-provisioning.md),
  [`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md) —
  the planning layer this design sits above
- [`TIER1_ROADMAP.md`](TIER1_ROADMAP.md) — Milestones 6 and 9
