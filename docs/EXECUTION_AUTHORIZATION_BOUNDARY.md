# Execution-authorization boundary — companion specification

Status: companion specification to
[`ADR-022`](adr/ADR-022-execution-authorization-boundary.md), **Accepted**
(2026-08-11, owner — see `ADR-022`'s "Acceptance note"). Read `ADR-022`
first; it is authoritative for every decision, the state machine,
`PlanDigest`/`PlanAuthorization` field lists, the freshness model, the
threat-model findings, and the future-phase list. **Acceptance is
architectural only — nothing here is implemented.** No `PlanDigest`
code, no authorization-artifact code, no verification/execution code,
no CLI entrypoint, no new environment variable, and no runtime behavior
exists yet. Building any of it is a separate, future, explicitly-scoped
authorization this document does not grant. This document adds two
things the ADR does not carry: a scoping/affected-code inventory (for
future implementers, none modified today) and a running "implementation
status" record, mirroring
[`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md)'s
own "Phase B/Planning slice — implemented" pattern, ready to be filled
in only if and when a future phase is separately authorized and built.

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

**Design phase only, as of 2026-08-11.** No `PlanDigest` computation, no
`PlanAuthorization`/`DeprovisionAuthorization` construction or
verification, no new `DigestPurpose` member, no signing-tool extension,
no storage schema, no CLI subcommand, no MCP tool. `security_plan.py`,
`security_discovery.py`, and `security_cli.py` are unmodified by this
design; `ADR-021` is unmodified.

Future phases (see `ADR-022`'s own "Future implementation phases" for
the recommended sequence and each phase's exact scope) should record
their own "implemented" entry here when and if separately authorized
and built — this section intentionally stays empty until then.

## Affected code areas (identified for future scoping — none modified by this document)

| Area | Current state (verified by reading, not modified) | Eventual relevance |
|---|---|---|
| `src/pfsense_mcp/security_plan.py` | `SecurityPosturePlan`/`PlanStep` dataclasses, pure computation, no `pfsense_mcp.tier1` import | `PlanDigest` computation (Phase B) would be a new, separate, read-only function operating *on* this module's output — no change to this file's own shipped API/behavior anticipated |
| `src/pfsense_mcp/tier1/canonical.py` | `DigestPurpose` enum (7 members), `digest_value()`/`canonical_json()` | A future `DigestPurpose.PLAN` (and possibly `PLAN_AUTHORIZATION`) member would extend this enum — additive only, no existing member's meaning changes |
| `src/pfsense_mcp/tier1/confirmation.py` | `ConfirmationEvidence`, `ConfirmationVerifier` Protocol, Ed25519 mechanism (`ADR-012`) | `PlanAuthorization` (Phase C) reuses this exact mechanism with a new digest-purpose domain separator — not a new cryptographic primitive |
| `src/pfsense_mcp/tier1/reconciliation.py` | `ReconciliationEvidence`, four-outcome enum (`ADR-013`) | `NEEDS_RECONCILIATION` (this design's state) is a pass-through to this existing, unmodified mechanism for pfSense-API-class steps only |
| `src/pfsense_mcp/tier1/contract.py`, `state_machine.py`, `executor.py` | `RecoveryContract`, closed `RecoveryState` machine, `MutationExecutor` (`ADR-006`/`014`) | Unaffected; `PlanAuthorization` becomes a precondition *for creating* a `RecoveryContract` for `ACTIVATION`-class steps only, per `ADR-022`'s "MCP WRITE boundary" ordering |
| `src/pfsense_mcp/tier1/rate_policy.py` | Store-backed counters, explicitly "not an authorization mechanism" (`ADR-015`) | Unaffected; remains a separate, later containment layer after authorization |
| `src/pfsense_mcp/write_endpoints.py`, `write_api_client.py` | `WriteEndpoints` (zero entries), `dry_run()`/`execute()` | Unaffected; allow-listing remains its own, separately-governed gate (`WRITE_ENDPOINT_RISK_MATRIX.md`, `ADR-020`), independent of plan-level authorization |
| `src/pfsense_mcp/tools/write/` | Empty, deliberately inert placeholder | The eventual home of any WRITE MCP tool that would enforce `ADR-022`'s "MCP WRITE boundary" ordering — nothing exists here yet |
| `scripts/tier1_store_bootstrap.py`, `witness_daemon/`, `docs/tier1/specs/anti_rollback_tpm_host_witness.md` | Existing hardware-class provisioning tooling/spec | The hardware-class execution mechanism `ADR-022`'s "Scope" table names — reused, not reimplemented, once a hardware-class `PlanAuthorization` is ever built |
| `tests/tier1/test_isolation.py` | Narrow, named exemptions only | A future authorization-verification module, if it needs to read (never construct) `RecoveryContract`/confirmation state, would need its own narrow, reviewed exemption — same discipline as `security_discovery.py`'s, not relaxed |
| `docs/TIER1_ROADMAP.md` | Milestone 6 ("audit, authorization, and MCP surface design") now carries a small, additive cross-reference note pointing to `ADR-022` (applied 2026-08-11, resolving `ADR-022`'s original question 5) | Text itself still predates the three-mechanism finding in detail; the note directs a future implementer to `ADR-022` before treating Milestone 6's authorization text as covering all mutation classes |

## References

- [`ADR-022`](adr/ADR-022-execution-authorization-boundary.md) —
  authoritative decision record
- [`ADR-021`](adr/ADR-021-security-posture-provisioning.md),
  [`SECURITY_POSTURE_PROVISIONING.md`](SECURITY_POSTURE_PROVISIONING.md) —
  the planning layer this design sits above
- [`TIER1_ROADMAP.md`](TIER1_ROADMAP.md) — Milestones 6 and 9
