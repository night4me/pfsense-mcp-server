# Tier 1 — Definitive implementation roadmap

Status: architecture blueprint; implementation not authorized to begin
until each phase's own gate is satisfied.

**2026-08-16 update**: this roadmap's phases have since been completed
for the one accepted `FIREWALL_ALIAS_DESCRIPTION` capability —
`WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION.verified=True`, following two
independently-verified live pfSense mutations against a disposable LAB
appliance (`ADR-026`). Table rows below describing "no endpoint/
capability/tool activation" or similar reflect the state at time of
writing this roadmap, not the current state — see
`docs/SECURITY_MODEL.md`'s "Recovery and WRITE status" for the current,
accurate description. This document is retained as the historical record
of how that work was planned and sequenced.
Supersedes, for sequencing purposes, `TIER1_ACTIVATION_DECISIONS.md`'s
"Design decisions still required" list (that document's analysis remains
valid background; this roadmap and the ADRs it names are the resolution).

This is the definitive sequence for the remainder of v0.3.0. Every item
below is either already fully specified (this document plus
`docs/tier1/specs/*.md` and `docs/adr/ADR-009` through `ADR-016`) or
explicitly named as the next thing that needs specifying. After the work
described here is complete through Phase 2, **all remaining work is
implementation, not architecture** — no future implementation agent
(Codex or Claude) should need to make a new security-relevant design
decision to build Phases 3–6; they should need only to follow the specs.

## How to use this document

Each phase names: what it produces, which specs/ADRs it depends on, its
entry gate (what must be true before starting), and its exit gate (what
must be true before the next phase starts). Phases are sequential — later
phases assume earlier ones are complete, not merely started.

## Phase 1 — Inert corrections

**Produces:** two small, reviewed diffs to already-existing inert code,
fixing the two findings from
`reports-ai/reviews/CLAUDE_TIER1_ARCHITECTURE_REVIEW_v0.3.0.md`'s "Required
corrections" section. Both are implementation work, not architecture —
the fix shape is already fully specified below; no further design
decision is required for either.

1. **MAC framing consistency**: `store.py::_mac()` and `_audit_mac()`
   currently delimit `store_id`/`"audit-event"` from their payload with a
   literal `b"\0"` byte, the same NUL-delimiter ambiguity class already
   fixed once in `canonical.py::digest_value()` via explicit four-byte
   length framing. Apply the identical length-prefixed framing to both
   `_mac()` and `_audit_mac()`, reusing (not reimplementing) the framing
   helper. This is not currently exploitable (every field feeding the MAC
   is regex-constrained against NUL) but leaves a latent hole for any
   future field with looser validation. Fix: apply length-prefix framing.
   Do not merely add a comment asserting the invariant — the fix is to
   remove the class of bug, not to document around it.
2. **`VERIFIED`-state reservation decision**: `store.py::_RESERVATION_
   STATES` excludes `VERIFIED`, meaning a target becomes claimable by an
   unrelated contract immediately after successful verification, before
   any rollback decision is made. This is not a correctness bug (a
   subsequent rollback attempt fails safely via `ContractConflictError`
   if the target was reclaimed) but is currently an undocumented,
   untested behavior rather than a stated decision. Resolve by adding an
   explicit sentence to `TIER1_ARCHITECTURE.md`'s Rollback section stating
   that fingerprint-drift detection on re-acquisition is the accepted
   safety net for this window (matching the existing design), plus a
   test in `tests/tier1/test_store.py` that specifically exercises and
   asserts this behavior (a target reclaimed between `VERIFIED` and a
   rollback attempt correctly produces `ContractConflictError`, not a
   silent success or corruption) — turning today's implicit behavior into
   a documented, tested one.

**Entry gate:** none — these are corrections to already-existing,
already-inert, already-tested code; they can begin immediately.

**Exit gate:** both fixes merged, `make quick`/`make validate` green,
`tests/tier1/` still 100% passing with the new/modified tests included,
and the architecture review's two "Required corrections" items marked
resolved in this roadmap (see Phase-completion tracking below).

## Phase 2 — Architecture implementation (subsystems)

**Produces:** the ten new modules specified in `docs/tier1/specs/`,
implemented, tested, and reviewed — but **still not wired to production
or to each other via an executor**. Each module remains independently
inert and independently testable, following exactly the isolation
discipline `tests/tier1/test_isolation.py` already enforces for the rest
of `pfsense_mcp.tier1`.

Recommended implementation order (dependency-driven, not arbitrary):

1. [`key_lifecycle.md`](specs/key_lifecycle.md) — depends on nothing new;
   the `O_NOFOLLOW`/`fstat()` helper extraction from `config.py` should
   land first since other work reuses it.
2. [`protected_artifact_encryption.md`](specs/protected_artifact_encryption.md)
   — depends on (1) for its `NonceCounter`.
3. [`whole_store_anti_rollback.md`](specs/whole_store_anti_rollback.md) —
   independent of (1)/(2); can proceed in parallel.
4. [`confirmation_authority.md`](specs/confirmation_authority.md) —
   independent; can proceed in parallel with (1)–(3).
5. [`reconciliation_authority.md`](specs/reconciliation_authority.md) —
   depends on (4)'s signing mechanism being in place first (shares the
   signing tool).
6. [`rate_blast_radius_policy.md`](specs/rate_blast_radius_policy.md) —
   independent; can proceed in parallel.
7. [`capability_adapter_contract.md`](specs/capability_adapter_contract.md)
   and [`adapter_restrictions.md`](specs/adapter_restrictions.md) — define
   the Protocol/enforcement together; no concrete adapter yet.

Each subsystem's own spec document is the authoritative source for its
implementation/review/security/test checklists — this roadmap does not
duplicate them, only sequences them.

**Entry gate:** Phase 1 complete. Corresponding ADR (009–013, 015)
accepted by the owner for each subsystem before that subsystem's
implementation begins — architecture work does not wait for owner
sign-off, but implementation does, per the original task's rules ("no
WRITE adapter... yet" applies to code, not design; these ADRs specifically
gate *code*, which Phase 2 is).

**Exit gate:** all seven items above implemented, each subsystem's own
"Required tests" passing, `make validate` green including the new tests,
and — critically — `tests/tier1/test_isolation.py` (extended per
`adapter_restrictions.md` for the adapters package once it exists)
confirming none of this new code is reachable from production. No
`Application`/`factory.py`/`ToolRegistry` change happens in this phase.

## Phase 3 — Sealed executor

**Produces:** `src/pfsense_mcp/tier1/executor.py` per
[`sealed_executor.md`](specs/sealed_executor.md), composing every Phase 2
subsystem into the one component capable of driving a real mutation —
still never constructed by production.

**Entry gate:** Phase 2 complete in full (the executor composes all seven
Phase 2 subsystems; partial completion is not sufficient). ADR-014
accepted.

**Exit gate:** `executor.py` implemented and tested per
`sealed_executor.md`'s full "Required tests" list, including forbidden-
adapter-behavior AST tests proven against a deliberately-violating
synthetic adapter fixture (not just a compliant one). `execute()`/
`rollback()` fully exercised against `MockTransport` with a synthetic
test-only adapter — never a real capability adapter, since none exists
yet. `test_isolation.py`-style checks confirm `executor.py` remains
unimported by production.

## First production WRITE convergence sequence

Owner-accepted ADR-025/ADR-026 supersede the former Phase 4-6 sequencing for
the first WRITE. Existing valid LAB and offline evidence is retained and
reused; exhaustive evidence outside the description-only semantic scope is
not a prerequisite. Every W slice requires separate authorization and stops
before the next.

### W1 — Bound semantic execution core

**Produces:** the production `set_firewall_alias_description_v1` typed request,
adapter and authoritative preparer; exact `PlanAuthorizationV2` intent/step/
digest verification; one-time consumption; appliance-specific authenticated
RecoveryContract provenance; confirmation/currentness/expiry binding; and one
MutationExecutor handoff. W1 includes focused offline adversarial tests and no
production construction or MCP reachability.

**Entry gate:** ADR-025 and ADR-026 Accepted; separate explicit W1 owner
authorization.

**Exit/STOP gate:** the complete tuple and appliance binding are derived from
one authoritative preparation; v1/legacy/caller substitution refuses; the
consume→create ordering is deterministic and fail closed; exactly one created
contract can reach the executor once. Stop if this needs a new security owner,
generic transaction framework, executor authorization awareness, or unchecked
caller fact. Stop after W1.

### W2 — Fixed production runtime

**Produces:** secure production bootstrap; authenticated store; pinned
authorization, confirmation and reconciliation verification authorities;
fixed alias adapter/policy and appliance-target binding; and restart/
reconciliation construction. No MCP WRITE exposure.

**Entry gate:** W1 complete and separately authorized W2.

**Exit/STOP gate:** disabled/default construction remains READ-only; enabled
construction has no private signing keys or caller-selected components;
missing/malformed authority, store, TLS, or stable appliance identity fails
closed; restart trusts only authenticated state and fresh authoritative reads.
Stop after W2.

### W3 — First product surface

**Produces:** exactly one `WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION` entry;
one explicit protected `ALIAS_WRITE` profile posture while the default remains
READ-only; and one `set_firewall_alias_description` MCP tool whose model-facing
inputs are only `alias_name` and `description`. W3 completes focused
acceptance, owner-selected remaining live evidence, operations/security docs,
and the owner enablement review.

**Entry gate:** W2 complete, every ADR-026 **MUST COMPLETE** acceptance row
closed, and separately authorized W3/live commands.

**Exit/STOP gate:** exactly one endpoint/capability/tool is reachable only in
the explicit protected posture; authorization, sealed execution, verification,
recovery and reconciliation remain intact; all validation passes. Stop for the
Owner Approval Gate before any release/tag/production enablement.

No W4 is planned before first WRITE.

### Deferred or cancelled before first WRITE

- Defer ADR-027 Slices 3-5, D6 standalone orchestration, complete D/E/G
  matrices, Stage 3F, broader alias mutation and a generic WRITE framework.
- Cancel ADR-027 Slice 6 / generic complete `ClosedStage3ExecutionPort` as a
  first-WRITE prerequisite.
- Retain useful existing evidence/code; do not promote LAB architecture into
  production merely because it exists.
- Add no ADR, abstraction, harness, service locator, generic framework or new
  security owner unless a concrete mandatory first-WRITE invariant cannot be
  enforced by existing architecture. Stop and obtain owner review before such
  an addition.

## Phase-completion tracking

| Phase | Depends on | Owner decisions required | Status |
|---|---|---|---|
| 1. Inert corrections | — | None (implementation-only) | **Complete** — MAC framing length-prefixed (`store.py::_mac`/`_audit_mac`, reusing `canonical.py::frame_str`/`frame_bytes`); `VERIFIED`-state reservation-release behavior documented in `TIER1_ARCHITECTURE.md` and tested (`test_verified_releases_target_and_later_rollback_refuses_on_conflict`). `make quick` 9/9, `make validate` 18/18. |
| 2. Architecture implementation | Phase 1 | ADR-009, 010, 011, 012, 013, 015 accepted | **Core subsystems complete** — key_lifecycle, protected_artifact_encryption, confirmation_authority, reconciliation_authority, rate_blast_radius_policy fully implemented and tested; whole_store_anti_rollback's protocol and store wiring implemented and tested, concrete backend intentionally not implemented (blocked on ADR-011's TPM-availability confirmation — a genuine owner/infrastructure decision, not an implementation gap). capability_adapter_contract/adapter_restrictions have no standalone Phase 2 code deliverable — the `CapabilityAdapter` Protocol they describe is defined in Phase 3's `executor.py`, and `adapter_restrictions.md`'s isolation tests need a `tier1/adapters/` package to scan, which does not exist until a capability is authorized (Phase 5). `make quick` 9/9, `make validate` 18/18 after every commit in this phase; 280 Tier1 tests (was 179 at Phase 1 exit). |
| 3. Sealed executor | Phase 2 | ADR-014 accepted | **Complete** — `src/pfsense_mcp/tier1/executor.py` implements `MutationExecutor`/`CapabilityAdapter` per `sealed_executor.md`, composing all Phase 2 subsystems plus a new, additive `WriteApiClient.send_for_tier1()` chokepoint and `Transport.request(body=...)` support (both existing-behavior-preserving; see `sealed_executor.md`'s Implementation notes for the three concrete design gaps the original pseudocode left open — `read_target(read_client, natural_identity)`, the `intent["raw_target_hint"]` dict shape, and 2xx/4xx/other response classification — each resolved, tested, and reconciled back into `capability_adapter_contract.md`/`adapter_restrictions.md`). `tests/tier1/test_executor.py` (19 tests) covers the full `execute()`/`rollback()` happy paths, policy/binding/fingerprint-drift refusals, every `EffectKnowledge` outcome, and audit-trail completeness, against `MockTransport` with a synthetic test-only adapter — never a real capability adapter. Not yet exercised: anchor refusal (no concrete `AntiRollbackAnchor` backend exists until ADR-011; ADR pending, as in Phase 2) and an executor-level concurrency test (the underlying `store.transition()` CAS race is already covered by `tests/tier1/test_store.py`'s threaded tests; the executor adds no new concurrency behavior on top of it). `test_isolation.py` extended with a single, narrow exception: `executor.py` alone may import `pfsense_mcp.write_api_client`/`pfsense_mcp.pfsense_client`; every other `tier1/*.py` module remains as restricted as before. `make quick` 9/9, `make validate` 18/18; 299 Tier1 tests (was 280 at Phase 2 exit). |
| 4. Semantic-scope evidence | Phase 3 | ADR-016 and ADR-026 accepted; live commands separately approved | **Partially complete and converged** — 25 clean A→B→A cycles, Stage 3A and Stage 3B evidence are accepted. ADR-026's matrix is authoritative for remaining first-WRITE evidence. Broader Stage 3F and exhaustive D/E/G matrices are deferred, not PASS. |
| W1. Bound semantic execution core | accepted ADR-025/026 | separate W1 authorization | **Complete (offline)** — exact two-field request, production-inert adapter/preparer, appliance-bound V2 authorization consumption, schema-v7 authenticated provenance, confirmation binding and one sealed executor handoff; no endpoint/capability/tool activation |
| W2. Fixed production runtime | W1 | separate W2 authorization | Not started |
| W3. First product surface | W2 plus completed ADR-026 mandatory matrix | separate W3/live authorization and Owner Approval Gate | Not started |

## What this roadmap deliberately does not resolve

- Exact production rate/blast-radius values remain a W2/W3 deployment-policy
  decision under ADR-015; no generic framework is introduced for them.
- Hardware availability (TPM) for the anti-rollback anchor
  (`ADR-011`) remains to be confirmed against the actual production host
  before Phase 2's anti-rollback work can select its concrete backend.
- Whether a systemd-managed deployment model changes the key-delivery
  recommendation (`ADR-009`/`ADR-010`) remains open if the actual
  production deployment differs from what this session observed.

These are intentionally left as owner decisions or lab-evidence-gated
items, not architectural gaps — the specs and ADRs already say precisely
what happens under either answer.

## Definition of done for this blueprint

This blueprint (the ten specs, eight ADRs, and this roadmap) is complete
when every subsystem an implementation agent would need to build Phases
1–3 has: purpose, security goals, invariants, trust boundaries, state
ownership, concrete interfaces, failure modes, recovery behavior,
non-goals, required tests, activation requirements, and four checklists
(implementation/review/security/test) — verified present in every file
under `docs/tier1/specs/`. It does **not** mean W1-W3 are risk-free or
automatic; each still requires separate authorization, ADR-026's remaining
mandatory evidence, and the existing Owner Approval Gate.
