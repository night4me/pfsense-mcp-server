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
execution) was separately authorized and implemented the same day; see
"Implementation status" below. Phases C onward (authorization data
model, verification, execution coordinators, MCP WRITE exposure) remain
separate, future, explicitly-scoped authorizations neither `ADR-022`'s
acceptance nor Phase B's implementation grants. This document adds two
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

Future phases (see `ADR-022`'s own "Future implementation phases" for
the recommended sequence and each phase's exact scope, starting at
Phase C — authorization data model, still no execution) should record
their own "implemented" entry here when and if separately authorized
and built.

## Affected code areas (identified for future scoping — none modified by this document)

| Area | Current state (verified by reading; Phase B changes noted explicitly) | Eventual relevance |
|---|---|---|
| `src/pfsense_mcp/security_plan.py` | Unmodified by Phase B — `SecurityPosturePlan`/`PlanStep` dataclasses, pure computation, no `pfsense_mcp.tier1` import | `security_plan_digest.py` (Phase B, implemented) is a new, separate, read-only module operating *on* this module's output — no change to this file's own shipped API/behavior |
| `src/pfsense_mcp/security_plan_digest.py` | **New, Phase B implemented (2026-08-11)** — `compute_plan_digest()`/`verify_plan_digest()`, pure, no I/O, third narrow `pfsense_mcp.tier1` isolation exemption (only imports `canonical`) | Complete for Phase B's own scope; a future `PlanAuthorization` (Phase C+) would call `compute_plan_digest()`, never reimplement it |
| `src/pfsense_mcp/tier1/canonical.py` | **Modified, Phase B implemented** — `DigestPurpose` enum gained `PLAN` (now 8 members), additive only, no existing member's meaning changed | A future `DigestPurpose.PLAN_AUTHORIZATION` member (Phase C) would extend this enum the same additive way |
| `src/pfsense_mcp/tier1/confirmation.py` | Unmodified — `ConfirmationEvidence`, `ConfirmationVerifier` Protocol, Ed25519 mechanism (`ADR-012`) | `PlanAuthorization` (Phase C) reuses this exact mechanism with a new digest-purpose domain separator — not a new cryptographic primitive |
| `src/pfsense_mcp/tier1/reconciliation.py` | `ReconciliationEvidence`, four-outcome enum (`ADR-013`) | `NEEDS_RECONCILIATION` (this design's state) is a pass-through to this existing, unmodified mechanism for pfSense-API-class steps only |
| `src/pfsense_mcp/tier1/contract.py`, `state_machine.py`, `executor.py` | `RecoveryContract`, closed `RecoveryState` machine, `MutationExecutor` (`ADR-006`/`014`) | Unaffected; `PlanAuthorization` becomes a precondition *for creating* a `RecoveryContract` for `ACTIVATION`-class steps only, per `ADR-022`'s "MCP WRITE boundary" ordering |
| `src/pfsense_mcp/tier1/rate_policy.py` | Store-backed counters, explicitly "not an authorization mechanism" (`ADR-015`) | Unaffected; remains a separate, later containment layer after authorization |
| `src/pfsense_mcp/write_endpoints.py`, `write_api_client.py` | `WriteEndpoints` (zero entries), `dry_run()`/`execute()` | Unaffected; allow-listing remains its own, separately-governed gate (`WRITE_ENDPOINT_RISK_MATRIX.md`, `ADR-020`), independent of plan-level authorization |
| `src/pfsense_mcp/tools/write/` | Empty, deliberately inert placeholder | The eventual home of any WRITE MCP tool that would enforce `ADR-022`'s "MCP WRITE boundary" ordering — nothing exists here yet |
| `scripts/tier1_store_bootstrap.py`, `witness_daemon/`, `docs/tier1/specs/anti_rollback_tpm_host_witness.md` | Existing hardware-class provisioning tooling/spec | The hardware-class execution mechanism `ADR-022`'s "Scope" table names — reused, not reimplemented, once a hardware-class `PlanAuthorization` is ever built |
| `tests/tier1/test_isolation.py` | **Modified, Phase B implemented** — exemption list now names `security_plan_digest.py` as the third, narrow exception (only imports `canonical`, unlike the other two) | A future authorization-verification module, if it needs to read (never construct) `RecoveryContract`/confirmation state, would need its own narrow, reviewed exemption — same discipline, not relaxed |
| `docs/TIER1_ROADMAP.md` | Milestone 6 ("audit, authorization, and MCP surface design") now carries a small, additive cross-reference note pointing to `ADR-022` (applied 2026-08-11, resolving `ADR-022`'s original question 5) | Text itself still predates the three-mechanism finding in detail; the note directs a future implementer to `ADR-022` before treating Milestone 6's authorization text as covering all mutation classes |

## References

- [`ADR-022`](adr/ADR-022-execution-authorization-boundary.md) —
  authoritative decision record
- [`ADR-021`](adr/ADR-021-security-posture-provisioning.md),
  [`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md) —
  the planning layer this design sits above
- [`TIER1_ROADMAP.md`](TIER1_ROADMAP.md) — Milestones 6 and 9
