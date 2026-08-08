# Tier 1 — Definitive implementation roadmap

Status: architecture blueprint; implementation not authorized to begin
until each phase's own gate is satisfied.
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

## Phase 4 — Disposable-lab validation

**Produces:** the harness specified in
[`disposable_lab_execution_model.md`](specs/disposable_lab_execution_model.md),
implemented and tested offline, **and then** — only under separate,
explicit command-level approval per `TIER1_ROADMAP.md` Milestone 8 — run
against a real disposable lab VM to produce evidence for the alias
candidate (or whichever candidate ADR-016 ultimately authorizes).

This phase has two distinct gates because implementing/testing the
harness offline is architecture-adjacent implementation work, while
running it against a live (even if disposable, non-production) appliance
is exactly the kind of action this project's approval boundaries treat as
requiring explicit, separate sign-off every time.

**Entry gate (harness implementation):** Phase 3 complete (the harness
constructs a real `MutationExecutor`). ADR-016 accepted (which candidate).

**Entry gate (live lab execution):** harness implementation's own exit
gate met, **plus** separate explicit command-level approval to actually
run it against the provisioned lab VM — this roadmap does not itself
grant that approval.

**Exit gate:** a complete `AcceptanceReport` covering every scenario in
`TIER1_LAB_PLAN.md`, informing final numeric values for `ADR-015`'s
rate/blast-radius defaults and confirming or disqualifying the candidate's
assumptions (partial-PATCH field scope, implicit reload behavior,
read-back/rollback semantics).

## Phase 5 — First adapter

**Produces:** exactly one concrete `CapabilityAdapter` implementation
(the alias-description adapter, or whichever candidate Phase 4 validated)
per [`capability_adapter_contract.md`](specs/capability_adapter_contract.md),
plus the one new `WriteEndpoints` entry, one new `*_WRITE` capability
addition, and the MCP tool registration wiring described in
`TIER1_ROADMAP.md` Milestones 6/9 — **this is the first phase in this
roadmap that touches production-adjacent code** (`WriteEndpoints`,
`capabilities.py`, `profiles.py`, `ToolRegistry`) and therefore the first
phase requiring the kind of milestone-by-milestone acceptance evidence
`TIER1_ROADMAP.md` already specifies in full (Milestones 6 and 7).

**Entry gate:** Phase 4's live lab evidence supports the candidate
(no disqualifying finding). Separate, explicit authorization naming the
exact capability/endpoint/method, per `TIER1_ROADMAP.md` Milestone 0's
existing requirement — this roadmap does not grant that authorization
either.

**Exit gate:** `TIER1_ROADMAP.md` Milestone 7's full offline acceptance
criteria met (all existing READ tests and security gates green, existing
41-tool contract unchanged, exactly the new WRITE tool registers only in
the approved profile, empty-allow-list checks replaced with precise
manifest checks per that milestone's existing acceptance criteria).

## Phase 6 — Production readiness review

**Produces:** the go/no-go decision described in `TIER1_ROADMAP.md`
Milestone 9 — explicit approval naming capability, endpoint, profile, and
release; accepted Recovery Contract/crash/rollback evidence; security and
compatibility review; updated public security/API/operations
documentation.

**Entry gate:** Phase 5 complete, including Milestone 8's private
test-appliance acceptance (a *second*, distinct disposable-appliance run
— this one exercising the real adapter end-to-end against a live but
non-production target, per `TIER1_ROADMAP.md`'s existing Milestone 8
sequence, distinct from Phase 4's earlier candidate-validation lab run).

**Exit gate:** the same commit/tag/push/release approval sequence already
governing every prior release in this project (`AGENTS.md`'s Owner
Approval Gate), applied to a WRITE-capable release for the first time.
Until this gate passes, `WriteEndpoints` remains empty, WRITE
capabilities remain inactive, and zero WRITE tools register — exactly as
today.

## Phase-completion tracking

| Phase | Depends on | Owner decisions required | Status |
|---|---|---|---|
| 1. Inert corrections | — | None (implementation-only) | **Complete** — MAC framing length-prefixed (`store.py::_mac`/`_audit_mac`, reusing `canonical.py::frame_str`/`frame_bytes`); `VERIFIED`-state reservation-release behavior documented in `TIER1_ARCHITECTURE.md` and tested (`test_verified_releases_target_and_later_rollback_refuses_on_conflict`). `make quick` 9/9, `make validate` 18/18. |
| 2. Architecture implementation | Phase 1 | ADR-009, 010, 011, 012, 013, 015 accepted | **Core subsystems complete** — key_lifecycle, protected_artifact_encryption, confirmation_authority, reconciliation_authority, rate_blast_radius_policy fully implemented and tested; whole_store_anti_rollback's protocol and store wiring implemented and tested, concrete backend intentionally not implemented (blocked on ADR-011's TPM-availability confirmation — a genuine owner/infrastructure decision, not an implementation gap). capability_adapter_contract/adapter_restrictions have no standalone Phase 2 code deliverable — the `CapabilityAdapter` Protocol they describe is defined in Phase 3's `executor.py`, and `adapter_restrictions.md`'s isolation tests need a `tier1/adapters/` package to scan, which does not exist until a capability is authorized (Phase 5). `make quick` 9/9, `make validate` 18/18 after every commit in this phase; 280 Tier1 tests (was 179 at Phase 1 exit). |
| 3. Sealed executor | Phase 2 | ADR-014 accepted | Not started |
| 4. Disposable-lab validation | Phase 3 | ADR-016 accepted; separate live-run approval | Not started |
| 5. First adapter | Phase 4 | Milestone 0 capability/endpoint authorization | Not started |
| 6. Production readiness review | Phase 5 | Milestone 9 activation decision; Owner Approval Gate | Not started |

## What this roadmap deliberately does not resolve

- The exact numeric rate/blast-radius values remain provisional until
  Phase 4 produces lab evidence (`ADR-015`).
- Whether the alias or system-tunable candidate ultimately proceeds
  remains conditional on Phase 4's findings (`ADR-016`).
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
under `docs/tier1/specs/`. It does **not** mean Phases 4–6 are
risk-free or automatic; those phases still require lab evidence, separate
authorization, and the existing Owner Approval Gate, exactly as
`TIER1_ROADMAP.md` already specified before this blueprint existed.
