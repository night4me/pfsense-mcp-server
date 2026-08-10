# Phase 5 / ADR-011 readiness review (2026-08-10)

Track 4 of an extended autonomous mission. Architecture/security analysis
only — **WRITE was not activated, no allow-list entry was added, no
capability adapter was built.** Grounded directly in the current shipped
code and accepted ADR/spec text, not memory; every claim below was
independently re-verified against the repository at commit `a2a9413`.

## 1. Dependency graph

```
ADR-011 (anti-rollback backend)  ─────────────┐
  owner/infra decision: TPM availability?      │
                                                ▼
Milestone 0 (capability/endpoint authorization) ──► Phase 5 (first adapter)
  owner decision: name the exact capability            │  produces:
  + endpoint + method (ADR-016 names a candidate,       │  CapabilityAdapter,
  does not authorize it)                                │  WriteEndpoints entry,
                                                          │  *_WRITE capability,
Phase 4 live lab run (Milestone 8)                       │  MCP tool registration
  owner decision: separate command-level approval,       │
  disposable/non-production target                       │
        ▲                                                 │
        └── depends on a real adapter existing ───────────┘
             (circular in practice: Milestone 0 must name
             the candidate before Phase 5 can build the
             adapter Milestone 8 needs to test against —
             this is why Phase 4's harness is offline-only
             so far, not a gap in the harness itself)
                                                          │
                                                          ▼
                                          Phase 6 (production readiness
                                          review — Milestone 9 go/no-go)
```

Two owner decisions gate everything else and are independent of each
other: **ADR-011's TPM-availability confirmation** (blocks finalizing the
anti-rollback backend) and **Milestone 0's exact capability/endpoint
naming** (blocks Phase 5 starting at all). Neither is a code gap.

## 2. What already exists (verified directly, not assumed)

| Subsystem | Status | Evidence |
|---|---|---|
| Recovery Contract model, closed state machine | **Implemented, tested** | `tier1/contract.py`, `tier1/state_machine.py` — 10 states (`PREPARING`→`PREPARED`→`EXECUTING`→`VERIFIED`/`FAILED`/`RECONCILIATION`/`ROLLING_BACK`→`ROLLED_BACK`/`ROLLBACK_FAILED`/`EXPIRED`) |
| Atomic SQLite store, audit chain | **Implemented, tested** | `tier1/store.py` |
| Encryption / key lifecycle | **Implemented, tested** | `tier1/crypto.py`, `tier1/key_lifecycle.py` — AES-256-GCM, domain-separated AAD |
| Confirmation authority | **Implemented, tested** | `tier1/confirmation.py`/`confirmation_providers.py` — `ConfirmationEvidence.evidence_digest`/`signing_payload()` (the signature-circularity bug found and fixed during Phase 2 is historical, not current) |
| Reconciliation authority | **Implemented, tested** | `tier1/reconciliation.py`/`reconciliation_providers.py` — triggered by `EffectKnowledge.AMBIGUOUS` (5xx/3xx/timeout outcomes; confirmed at `executor.py:179,190,267,277,338,342,354`) |
| Fingerprint binding / TOCTOU | **Implemented, tested** | `executor.py`'s `_fingerprint_digest()` (line 296) re-reads and compares the target fingerprint immediately before send (line 161) and before rollback (line 235) — drift fails closed to `FAILED`, never proceeds |
| Rate / blast-radius policy | **Implemented, tested (provisional numeric defaults)** | `tier1/rate_policy.py` |
| Whole-store anti-rollback protocol | **Protocol + store wiring implemented, tested; concrete backend NOT implemented** | `tier1/anti_rollback.py` — blocked on ADR-011 (below) |
| Sealed executor (`execute()`/`rollback()`) | **Implemented, tested** | `tier1/executor.py`, 354 lines, `MutationExecutor`/`CapabilityAdapter` Protocol |
| WRITE allow-list | **Implemented, deliberately empty** | `write_endpoints.py` — `WriteEndpoints.active_entries()` mechanically checked to return `[]` by `scripts/write_allow_list_check.py` |
| Capability model | **Three `*_WRITE` enum members exist, none active** | `capabilities.py` — `FIREWALL_WRITE`/`ALIAS_WRITE`/`SERVICE_WRITE`, none in `SUPPORTED_CAPABILITIES_THIS_BUILD` |
| Disposable-lab harness | **Implemented, tested offline; never run live** | `lab/harness.py`/`fault_proxy.py`/`config.py` — 44 offline tests against `MockTransport` and a synthetic test-only adapter |
| Tier 1 test suite | **304 tests, 21 files** | `tests/tier1/` |

**No production PREPARE-construction function exists anywhere in
`pfsense_mcp.tier1`** — confirmed by grep, not assumed: the executor only
ever *consumes* an already-`PREPARED` contract (`execute()`/`rollback()`);
nothing in `src/pfsense_mcp/tier1/*.py` constructs one from scratch.
`lab/harness.py::prepare_contract()` is the only implementation, and it is
explicitly lab-scoped (built against a synthetic test-only adapter, not a
real one). **This is the single largest concrete gap** — not because it's
hard, but because it is inherently capability-specific (it must call a
real `CapabilityAdapter.natural_identity()`/`.fingerprint()`), so it
cannot be built generically ahead of Milestone 0 naming which capability.

## 3. Unresolved owner decisions (not implementation gaps)

1. **ADR-011**: TPM2 NV counter availability on the actual production
   host, or authorization to stand up an independent remote witness as
   the mandatory fallback. Status: `Recommended — pending owner decision`.
2. **`TIER1_ROADMAP.md` Milestone 0**: name the exact first capability +
   pfSense endpoint + HTTP method. ADR-016 (Accepted, 2026-08-08)
   identifies firewall-alias description-only `PATCH` as the recommended
   candidate and authorized *disposable-lab research time* on it
   specifically — it explicitly does **not** authorize the endpoint,
   adapter, tool, or capability itself. This remains the single most
   concrete "ready to decide" item: the research recommendation already
   exists, only the activation decision doesn't.
3. **Milestone 8**: separate command-level approval for a live run
   against a disposable/non-production test appliance, once a real
   adapter exists to test.
4. **Deferred ADR-018 question #3**: whether a given capability's
   adapter contract opts into *requiring* guidance evidence for PREPARE —
   a Phase-5, per-capability decision, unchanged by this review.

## 4. Security invariants that must hold through Phase 5 (already-accepted, restated as a checklist for whoever builds it)

- [ ] `may_prepare = existing_authorization AND (guidance_not_required OR guidance_check_passes)` — guidance can only remove permission, never grant it (algebraically proven, ADR-018 acceptance review).
- [ ] Every PREPARE binds an immutable target fingerprint; `execute()`/`rollback()` re-read and compare it immediately before acting, failing closed on drift (already implemented — a future adapter must not bypass `executor.py`'s existing call sites).
- [ ] Confirmation evidence binds to the contract's own digest via `signing_payload()`, never `.proof` itself (the circularity bug already fixed — do not reintroduce it in a new evidence type).
- [ ] 4xx → `VERIFIED_FAILURE` (confidently no effect); 5xx/3xx/timeout → `AMBIGUOUS` → `RECONCILIATION` (already implemented, `executor.py`'s `_send()`) — a new adapter must not reclassify these.
- [ ] `WriteEndpoints` and `SUPPORTED_CAPABILITIES_THIS_BUILD` remain two independent chokepoints — a capability existing does not imply its endpoint is allow-listed, and vice versa (ADR-019 acceptance review's established split).
- [ ] No adapter constructs its own client (`capability_adapter_contract.md` I2) — the same rule `resolve_appliance_identity()`'s own docstring already restates for identity resolution.
- [ ] One MCP tool → one `Capability` → exactly one fixed underlying client method — no exceptions for WRITE.
- [ ] `AntiRollbackAnchor` stays `None`-permitted (current default) only until ADR-011 resolves — the store must not silently start assuming an anchor exists before one is actually wired.

## 5. Proposed implementation sequence (if/when Milestone 0 is decided)

1. Owner names the exact capability/endpoint/method (Milestone 0) —
   `firewall-alias description-only PATCH` is the evidence-backed
   recommendation already on record (ADR-016), not a new recommendation
   from this review.
2. Build the concrete `CapabilityAdapter` implementation for that one
   capability, per `capability_adapter_contract.md` — `natural_identity()`,
   `fingerprint()`, `read_target()`, the typed request/response models.
   This is also the point at which a real, capability-specific
   `prepare_contract()`-equivalent gets built in production
   (`pfsense_mcp.tier1`, not `lab/`), mirroring `lab/harness.py`'s shape
   but against the real adapter.
3. Add exactly one `WriteEndpoints` entry (verified=True, explicit
   `RollbackPlan`, `dry_run_supported=True` per the module's own
   documented bar) and activate the matching `*_WRITE` capability in
   `SUPPORTED_CAPABILITIES_THIS_BUILD`.
4. `tier1/adapters/` isolation tests (named but not yet buildable —
   `adapter_restrictions.md` needs this package to exist first) become
   possible for the first time.
5. Register the one new MCP tool, per `TIER1_ROADMAP.md` Milestones 6/9's
   already-specified acceptance criteria (existing 42-tool contract
   unchanged otherwise; new tool registers only in the approved profile).
6. Milestone 7's full offline acceptance suite, then Milestone 8's live
   disposable-appliance run (separate approval), then Milestone 9's
   production go/no-go (Phase 6).

## 6. Recovery Contract / PREPARE / EXECUTE / RECONCILE expectations for the first adapter

- PREPARE must compute and bind: target identity digest, target
  fingerprint digest, intent digest, snapshot digest, idempotency key —
  exactly the five `DigestPurpose` values `lab/harness.py::prepare_contract()`
  already demonstrates the shape of (not to be re-derived from scratch;
  the production version differs only in using a real adapter instead of
  a synthetic one).
- EXECUTE must re-verify the fingerprint immediately before sending
  (already implemented, `executor.py:161`) and classify the outcome via
  the existing 4xx/5xx boundary logic — a new adapter supplies the typed
  request/response models and the actual HTTP call target only, never its
  own classification logic.
- RECONCILE requires a human authority with independent, out-of-band
  evidence (`reconciliation_providers.py`) — the signing-side CLI tool
  this requires is still unbuilt project-wide (a standing, deliberately
  out-of-`pfsense_mcp` gap, unchanged by this review — see
  `NEXT_TASKS.md`).

## 7. Test plan for the first real adapter (beyond what already exists)

- Unit tests for the adapter's `natural_identity()`/`fingerprint()`/
  `read_target()` against `MockTransport`, mirroring `test_executor.py`'s
  existing synthetic-adapter coverage but for the real one.
- `tier1/adapters/` isolation test (per `adapter_restrictions.md`, not yet
  buildable until this package exists).
- The deferred executor-level anchor-refusal test (`sealed_executor.md`'s
  Required tests) — still blocked on ADR-011's backend, unchanged.
- A live disposable-lab acceptance run reusing `lab/harness.py`'s
  `run_full_acceptance()` against the real adapter (Milestone 8).

## 8. Adversarial test plan (what a red-team pass on the first adapter must specifically probe)

- Target drift between PREPARE and EXECUTE (an alias renamed/deleted
  between the two calls) — must fail closed via the existing fingerprint
  check, not silently proceed against a different target.
- Partial-update semantics: does a description-only `PATCH` ever silently
  rewrite unrelated fields? (ADR-016's own named disqualifying scenario —
  must be proven false by the lab run, not assumed.)
- Idempotent replay: does re-sending an already-applied PATCH produce a
  different `EffectKnowledge` the second time, and does that ever get
  misclassified as a new mutation rather than a no-op?
- Confirmation evidence replay/reuse across two different contracts.
- Rollback-after-partial-failure: does the rollback path's own fingerprint
  re-check (`executor.py:235`) actually block a rollback against a target
  that changed since the failed forward attempt?

## 9. Rollback / recovery expectations

Every `WriteEndpoints` entry needs an explicit `RollbackPlan` (the
dataclass already requires `reversible: bool` and implies a plan when
true) — for the alias-description candidate, this is restoring the prior
description value, itself a `PATCH`, subject to the exact same
fingerprint/confirmation discipline as the forward mutation, not a
privileged bypass path.

## 10. Documentation requirements once Phase 5 actually begins

- `docs/API.md`/public contract snapshot update (expected, mechanical —
  `make validate`'s contract-check already gates this).
- `docs/SECURITY_MODEL.md`/`docs/THREAT_MODEL.md` updates for the first
  real WRITE-adjacent trust boundary — precedented by how each Tier 1
  subsystem's introduction already updated these.
- A `docs/adr/ADR-0XX` recording the Milestone 0 decision itself once
  made (this review does not make that decision or pre-number that ADR).

## Result

No code implemented — every concrete next step is either owner-gated
(Milestone 0, ADR-011) or depends on something that is (a real adapter
requires knowing which capability first). What already exists is
substantially complete and well-tested (304 Tier 1 tests); the one
genuine implementation gap (production PREPARE construction) is
inherently incapable of being built generically ahead of Milestone 0.
This review changes no runtime behavior and activates nothing.
