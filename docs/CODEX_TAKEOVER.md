# Codex Project Takeover Guide

**Read this document completely before touching any code.** It is the
durable, repository-native handoff for continuing `pfsense-mcp-server`'s
ADR-022 execution-authorization work. It is written to be self-contained:
a fresh agent with no memory of the Claude Code session that produced it
should be able to read this file plus the repository files it points to
and arrive at an accurate, independently-verified understanding of the
architecture, its security invariants, and what is safe to do next.

This document separates **facts** (verifiable against the repository
right now), **decisions** (explicit owner choices that constrain future
work), **proposals** (architecture written down but not authorized to
build), and **future ideas** (named, not designed, not decided). Do not
blur these categories when extending this document.

---

## 1. Authoritative repository state

| Field | Value |
|---|---|
| **HANDOFF_SHA** (last implementation commit) | `48a93862f95981c7c97b47ae94cc8467196b92c5` |
| Branch | `main` |
| `origin/main == local HEAD` | Confirmed equal at `HANDOFF_SHA` |
| Working tree | Clean (confirmed via `git status --short`, empty output) |
| Full pytest | **2288 passed, 42 skipped**, 0 failed |
| ruff format --check | Clean (471 files formatted) |
| ruff check | Clean ("All checks passed!") |
| mypy (`mypy src/pfsense_mcp scripts lab witness_daemon`) | Clean — "Success: no issues found in 212 source files" |
| `mkdocs build --strict` | Clean — builds with only pre-existing, unrelated `nav`/relative-link INFO notices, no errors |
| `make quick` | **11/11 stages PASSED** |
| `make validate` | **20/20 stages PASSED** |
| Public MCP contract | **42 READ tools / 0 WRITE tools** (`public_contract: OK (42 tools)`) |
| WRITE milestone status | **0 of 3** `*_WRITE` capabilities active; `WriteEndpoints` has zero entries; `pfsense_mcp.tools.write` is never imported |
| Last completed Phase E slice | **Slice E2** — `ExecutionCoordinator` skeleton, through one-time authorization consumption only |
| First slice not started | **Slice E3** — wiring `store.create()`/`store.confirm()`/`executor.execute()` behind the coordinator |

This document itself, once committed, may add one more commit on top of
`HANDOFF_SHA` (documentation-only). If so, that later commit is the
**final takeover SHA**; `HANDOFF_SHA` above remains the authoritative
**last implementation** commit. Codex should verify both independently
via `git log --oneline -5` rather than trusting either SHA blindly — see
§16.

---

## 2. Project purpose and security posture

`pfsense-mcp-server` is a Model Context Protocol (MCP) server that lets
an AI client (Claude, or any MCP-speaking client) interact with a
pfSense firewall appliance. Its foundational, still-true architectural
decision (`ADR-001`, Accepted) is: **the publicly exposed MCP tool
surface is READ-only.** Every one of the 42 public tools performs a GET
against the pfSense REST API and nothing else — enforced structurally
(`ADR-003`'s GET-only transport chokepoint) and by repository-wide
tests, not merely by convention.

Underneath that public surface, a substantial amount of **inert**
WRITE-capable machinery exists — deliberately built ahead of activation,
under a strict "architecture and tests first, activation last, always
separately gated" discipline that spans more than twenty ADRs. This
machinery falls into four layers, from lowest to highest:

1. **Tier 1 mutation machinery** (`src/pfsense_mcp/tier1/`): the sealed
   executor (`executor.py`, `ADR-014`), a closed recovery state machine
   (`state_machine.py`), a crash-recovering `RecoveryContract` store
   (`store.py`, `contract.py`, `ADR-006`), owner **confirmation**
   authority (`ADR-012`) and **reconciliation** authority (`ADR-013`),
   rate/blast-radius limits (`ADR-015`), and canonicalization/digest
   primitives (`canonical.py`) everything else in the security stack
   reuses rather than reinventing.
2. **Authorization** (`src/pfsense_mcp/security_*.py`, `ADR-021`/`022`/
   `023`/`024`): a separate, higher-level layer answering "did a human
   operator actually review and sign off on this specific change,"
   independent of and upstream from Tier 1's own execution machinery.
   This is the layer this session's work (Slices E1 and E2) extended.
3. **Execution** (Tier 1's `MutationExecutor`): the *only* component
   authorized to make a non-GET network call, and only ever exactly one
   per `execute()`, against an allow-listed endpoint
   (`write_endpoints.py`), through `write_api_client.py`.
4. **Public exposure** (MCP tool registration): the layer that would let
   an AI client actually invoke any of the above. **This layer remains
   completely untouched by every ADR discussed in this document.** No
   WRITE tool has ever been registered. No milestone has been activated.

**The critical fact for Codex to internalize: the presence of extensive,
well-tested WRITE-capable code in this repository does not mean WRITE
is enabled, reachable, or one step away from being enabled.** Every
layer above is independently inert — `MutationExecutor` is never
constructed by production code; `WriteEndpoints` is an empty allow-list;
`EngineerProfile.capabilities` (the profile every runtime request
resolves against) is `frozenset()`; no MCP tool registration path leads
to any of it. Activation is gated behind "Milestone 9," a distinct,
separately-authorized, not-yet-made decision referenced throughout the
ADRs but not itself part of this document's scope.

---

## 3. Chronological architecture history (ADR map)

Full ADR index: `docs/adr/README.md`. Read the specific ADRs named below
in full — do not rely on this table alone for their content, only for
routing.

| ADR | Title | Status | What it decided | What remains open |
|---|---|---|---|---|
| 001–010 | READ-only architecture, typed boundaries, GET-only transport, capability profiles, inert Tier 0 WRITE, RecoveryContract philosophy, security-first schemas, fail-closed config, artifact encryption, key lifecycle | Accepted (006 "prerequisites incomplete") | Foundational Tier 0/1 architecture | 006's prerequisites — not this document's concern |
| 011 | Whole-store anti-rollback anchor | Backend decided (TPM-backed host witness), design-ready | The anchor mechanism itself | Not yet provisioned in any real deployment |
| 012 | Confirmation authority | Accepted | Owner-signed, per-mutation `ConfirmationEvidence`, `PREPARED → EXECUTING` gate | — |
| 013 | Reconciliation authority | Accepted | How an ambiguous/`AMBIGUOUS` mutation outcome gets manually resolved | — |
| 014 | Sealed executor interface | Accepted | `MutationExecutor`'s exact shape and authority boundaries — the precedent Slice E2's coordinator design reuses directly | — |
| 015 | Rate and blast-radius defaults | Accepted (mechanism); numeric defaults provisional | — | Exact numeric limits |
| 016 | Alias-candidate disposable-lab authorization | Accepted | — | — |
| 017 | Official guidance layer | Accepted, architecture + inert scaffolding only | — | No consumer wired |
| 018 | Version-aware Official Guidance resolution | Accepted, architecture/trust boundaries only | — | Nothing implemented |
| 019 | API Surface, Capability Discovery, and Extension Architecture | Accepted, vocabulary/evaluation only | — | Individual mechanisms separately gated |
| 020 | Milestone 0 — first WRITE capability candidate | Accepted, candidate naming only | Which capability would be *first* if ever activated | Implementation, lab run, allow-list population, activation all separately gated |
| 021 | Guided security-posture provisioning | Accepted, architecture/design only | The `CapabilityPosture` (`read_only`/`write_protected`) × `AnchorAssurance` (`none`/`hardware_witness`) two-axis model `SecurityPosturePlan` generation is built on | No wizard, no posture, no WRITE, no fail-closed enforcement authorized |
| 022 | Execution-authorization boundary | **Accepted**, architecture/design only | The `Plan → Authorize → Execute → Verify` model and its own internal phase lettering A–H (see §6) | No authorization/execution code, no WRITE tool, no schema change authorized *by this ADR itself* — later ADRs authorized specific slices under it |
| 023 | Authorization-verification boundary (`ADR-022` Phase D) | Proposed (architecture) — owner decisions made, **Phase D implemented** | `PlanAuthorization`/`DeprovisionAuthorization` data model, signing, three independent pure verifiers, durable one-time consumption store | Not a full ADR-021/022-style acceptance — still "Proposed" |
| 024 | Execution-authorization coordination boundary (`ADR-022` Phase E/F/G territory) | Proposed (architecture) — **Slice E1 and Slice E2 implemented** | Freshness re-check primitive (E1) + `ExecutionCoordinator` skeleton through one-time consumption (E2) | Slice E3 (wiring the coordinator to `RecoveryContract`/`MutationExecutor`) and everything past it — unauthorized |

**Do not confuse "Accepted" with "implemented."** `ADR-022` is Accepted
as an architecture but authorizes zero code by itself — every line of
authorization/execution code that exists was authorized by a *later*,
narrower, explicitly-scoped instruction referencing it (`ADR-023` for
Phase D, `ADR-024` for Phase E). `ADR-024` itself is still "Proposed,"
not "Accepted," even though two of its slices are implemented — its own
first line says so explicitly and this document does not change that.

---

## 4. Phase/slice status ledger

`ADR-022`'s own phase lettering (context in `ADR-022-execution-authorization-boundary.md`):
**A** (acceptance) → **B** (`PlanDigest`) → **C** (`PlanAuthorization`/
`DeprovisionAuthorization` data model + signing) → **D** (pure
verification + consumption tracking) → **E** (freshness/precondition
engine only) → **F** (execution coordinator for `CONFIGURATION`-class
mechanism only) → **G** (execution coordinator around existing
`RecoveryContract`/`MutationExecutor`) → **H** (MCP WRITE exposure,
gated on Milestone 9).

`ADR-024`'s own "Naming note" explains it analyzes the **combined**
E/F/G territory as one architecture document, but recommends —and this
session followed — building it as separate, narrower, independently
authorized **slices** (its own vocabulary, distinct from `ADR-022`'s
phase letters): Slice 1 = E1, Slice 2 = E2, Slice 3 = E3.

| Phase/Slice | Objective | Resulting invariant | Modules introduced | Key tests | Deliberately untouched |
|---|---|---|---|---|---|
| B | Deterministic plan identity | `compute_plan_digest()`/`verify_plan_digest()` produce an exact, canonical identity over a `SecurityPosturePlan` | `security_plan_digest.py` | `tests/test_security_plan_digest*.py` | Signing, verification, execution |
| C | Signed authorization artifacts | A `PlanAuthorization`/`DeprovisionAuthorization` is a frozen, fully self-validating dataclass; signing happens only on the operator side | `security_authorization.py` | `tests/test_security_authorization*.py` | Verification, consumption, execution |
| D | Independent pure verification + one-time consumption | Signature/expiry/scope are three *independent* checks; an `authorization_id` can be consumed at most once, durably, across restarts and concurrent races | `security_authorization_verifier.py`, `tier1/authorization_consumption_store.py` | `tests/test_security_authorization_verifier*.py`, `tests/tier1/test_authorization_consumption_store*.py` | Composition of the four primitives with each other; execution wiring |
| E1 | Freshness re-check | "A previously authorized plan is fresh only when a newly discovered posture, run through the same deterministic planner and `compute_plan_digest()`, reproduces the exact authorized `plan_digest`" — `evidence_fingerprint` alone is explicitly insufficient | `security_plan_freshness.py` | `tests/test_security_plan_freshness*.py` | Consumption, coordinator, execution |
| **E2 (current HEAD)** | Coordinator skeleton through consumption | "An execution attempt may reach the consumed state only after signature validity, expiry/currentness, exact plan-digest + authorized-step membership, and full freshness re-check all succeed, in that order" | `tier1/execution_coordinator.py` | `tests/tier1/test_execution_coordinator*.py` | `RecoveryContract` creation, `MutationExecutor`, `state_machine.py`, `store.create()`/`confirm()` |
| E3 (not started) | Wire `store.create()`/`confirm()`/`executor.execute()` behind the coordinator | (not yet established — this is exactly what E3 would establish) | Extends `execution_coordinator.py` only | Not written | `executor.py`/`state_machine.py`'s own public behavior; still no MCP construction site |
| F/G remainder, H | Full execution path; MCP WRITE exposure | — | — | — | Everything, until Milestone 9 |

---

## 5. Security invariants Codex MUST preserve

These are architectural guarantees enforced by tests today, not
aspirations. Treat a test that encodes one of these as **load-bearing**
— see §12 for the explicit warning about not "fixing" a failing security
test by weakening it.

- **Fail-closed, everywhere.** An indeterminate outcome (I/O error,
  ambiguous read, malformed stored state, unexpected exception) is
  always treated as "not authorized to proceed." Never "proceed
  anyway." This applies uniformly across discovery, planning, digesting,
  verification, freshness, and consumption.
- **Canonicalization has exactly one implementation.** `tier1/canonical.py`'s
  `canonical_json()`/`digest_value()`/`DigestPurpose` domain separation
  is the only hashing/canonicalization path in the entire security
  stack. No module — including the new coordinator — defines a second
  one; this is directly tested (`test_module_defines_no_second_digest_or_canonicalization_function`-style checks exist for the freshness module and should exist for any future module that touches digests).
- **`PlanDigest` has exactly one implementation.** `security_plan_digest.py`'s
  `compute_plan_digest()`/`verify_plan_digest()` are the sole authority
  for "does this plan match that digest." Nothing recomputes a digest a
  different way.
- **`PlanAuthorization` is a signed artifact, not a claim.** A
  `proof` is only meaningful once verified against a `PinnedAuthoritySet`
  (`ADR-012`'s precedent, reused). Signer identity is pinned, not
  inferred; an unknown or inactive `authority_id` fails closed.
- **Expiry is exact and independent.** `plan_authorization_is_current()`
  checks `now < expires_at`, exclusive boundary, and deliberately does
  **not** validate `issued_at`-side timing — this is documented,
  intentional behavior, not a gap to "fix."
- **Plan binding is exact, not fuzzy.** `plan_authorization_authorizes_step()`
  requires exact `plan_digest` equality (via `hmac.compare_digest`) *and*
  exact `step_id` membership. No wildcard, prefix, or partial matching
  exists anywhere, by design and by test.
- **Freshness is exact `plan_digest` recomputation, never a proxy.**
  `evidence_fingerprint` comparison is **not** sufficient — it excludes
  the `steps` list, which participates in `plan_digest` but not in
  `evidence_fingerprint`'s six fields. This was a genuine finding of
  this session's work (`ADR-024`'s "Freshness/precondition model," E4),
  now enforced by `security_plan_freshness.py` never even reading
  `evidence_fingerprint`.
- **Consumption is one-time, durable, and atomic.** `try_consume()`
  proves "at most one caller ever observes `True` for a given
  `authorization_id`," across restarts and concurrent races (tested with
  a real 8-thread barrier race in both the store's own tests and the
  new coordinator's tests). The accepted semantic is **"one attempt to
  create a `RecoveryContract`,"** not "one execution attempt" and
  explicitly not "one successful execution" (see §7).
- **`RecoveryContract`/`ConfirmationEvidence`/`MutationExecutor`
  boundary is untouched and must stay that way.** `MutationExecutor`
  remains completely authorization-unaware — it operates purely on an
  already-`PREPARED`, already-confirmed `RecoveryContract` loaded by
  `contract_id`; nothing in its signature references a Plan, digest, or
  authority. This is a hard requirement (`ADR-024`'s G2), not a
  convenience default — see `ADR-024`'s "Rejected designs" for why
  folding authorization into the executor was considered and refused.
- **`tier1/state_machine.py`'s closed transition table is unaffected.**
  No new state, no new transition, for any authorization purpose.
- **Isolation boundaries are architectural controls.** See §5 of this
  document's own philosophy note and §12 below — do not relax an
  isolation test to make an import "more convenient."
- **Public WRITE remains fully prohibited** until a separate, explicit
  Milestone 9 activation decision, itself gated behind its own future
  authorization, not part of anything in this document.
- **Target-identity status is an open, intentionally unresolved gap**
  — not a bug, not an oversight. See §9.

---

## 6. Component map

| Path | Responsibility | Allowed side effects | Major dependencies | Security significance | Codex should normally... |
|---|---|---|---|---|---|
| `src/pfsense_mcp/tier1/canonical.py` | Canonical JSON + purpose-separated digesting | None (pure) | stdlib only | Sole hashing/canonicalization authority | Never modify without extreme care and full re-review of every dependent module |
| `src/pfsense_mcp/security_discovery.py` | Read-only discovery of live capability posture + anchor assurance | One read-only I/O boundary (`discover_security_posture()`) | `httpx`, TPM witness client | Feeds planning; must fail closed on I/O error | Not modify without a separately authorized slice |
| `src/pfsense_mcp/security_plan.py` | Deterministic `SecurityPosturePlan` generation from discovery + a requested target | None (pure over its input) | `security_discovery` | Enforces `ADR-021`'s two-axis validity constraint | Not modify |
| `src/pfsense_mcp/security_plan_digest.py` | `compute_plan_digest()`/`verify_plan_digest()` | None (pure) | `tier1.canonical` | Sole `PlanDigest` authority | Not modify |
| `src/pfsense_mcp/security_authorization.py` | `PlanAuthorization`/`DeprovisionAuthorization` data model, payload construction, operator-side signing | None (pure) | `tier1.canonical` (digest only) | Signed-artifact schema | Not modify without a schema-change-level authorization |
| `src/pfsense_mcp/security_authorization_verifier.py` | Three independent pure verifiers (signature, expiry, scope) | None (pure) | `security_authorization`, `tier1.ed25519_authority` | Phase D's verification core | Not modify; compose, don't reimplement |
| `src/pfsense_mcp/security_plan_freshness.py` | Freshness re-check (`plan_authorization_is_fresh()`) | One read-only I/O boundary (delegates to `security_discovery`) | `security_discovery`, `security_plan`, `security_plan_digest` | Slice E1's core invariant | Not modify |
| `src/pfsense_mcp/tier1/authorization_consumption_store.py` | Durable one-time `authorization_id` consumption | Writes exactly one row per successful consumption | `tier1.canonical`, `tier1.errors`, SQLite | Replay-prevention authority | Not modify |
| **`src/pfsense_mcp/tier1/execution_coordinator.py`** (NEW, Slice E2) | Composes the five gates above in fixed order; the *only* component permitted to call `try_consume()` in the authorization flow | One state-changing call (`try_consume()`) | `security_authorization`, `security_authorization_verifier`, `security_discovery`, `security_plan_freshness`, `tier1.authorization_consumption_store`, `tier1.ed25519_authority` | This slice's entire deliverable | Extend only under an explicitly authorized future slice (E3); do not add `store`/`executor` calls without that authorization |
| `src/pfsense_mcp/tier1/store.py` | `SqliteRecoveryContractStore` — crash-recovering, compare-and-set `RecoveryContract` persistence | Writes/transitions contract rows | `tier1.canonical`, `tier1.contract`, `tier1.crypto` | `ADR-006`/`ADR-009`/`ADR-010` | Not modify without a separately authorized slice |
| `src/pfsense_mcp/tier1/contract.py` | `RecoveryContract`, `ProtectedArtifact` | None directly (data + verification methods) | `tier1.canonical` | Binding-chain target/intent verification | Not modify |
| `src/pfsense_mcp/tier1/state_machine.py` | Closed `RecoveryState` transition table | None (pure) | `tier1.errors` | Cannot be bypassed or extended informally | Not modify without a separately authorized slice |
| `src/pfsense_mcp/tier1/executor.py` | `MutationExecutor` — the sole component authorized to send a non-GET request | Exactly one non-GET send per `execute()` | `write_api_client`, `pfsense_client`, `tier1.store`, others | `ADR-014`'s sealed executor | Not modify without a separately authorized slice; must remain authorization-unaware (G2) |
| `src/pfsense_mcp/write_api_client.py` | `send_for_tier1()` — the one chokepoint for any non-GET call | The network call itself | HTTP transport | `ADR-003`'s GET-only enforcement boundary | Not modify |
| `src/pfsense_mcp/write_endpoints.py` | The sole mutation allow-list | None (class-level data) | — | Currently **empty** — 0 endpoints active | Not modify without an explicit, separately authorized allow-list-population decision |
| MCP registration/exposure layer (`src/pfsense_mcp/tools/`, `application.py`, `factory.py`) | Registers the 42 public READ tools | Tool registration only | — | No WRITE tool registered anywhere; `tools/write` never imported | Never register a WRITE tool without Milestone 9 authorization |

---

## 7. Isolation architecture

This project enforces dependency direction with **AST-based structural
tests**, not just code review. `tests/tier1/test_isolation.py` is the
central control:

- `test_tier1_is_not_imported_outside_its_inert_package` — proves no
  production module outside `tier1/` imports `pfsense_mcp.tier1`,
  **except** a small, explicit, individually-justified `exempt` set:
  `tier1_anchor_check.py`, `security_discovery.py`,
  `security_plan_digest.py`, `security_authorization.py`,
  `security_authorization_verifier.py`. Each entry has its own
  paragraph explaining *why* it is safe (what it imports from `tier1`,
  and what it structurally cannot do). This is the "outward-in"
  direction.
- `test_tier1_domain_has_no_transport_or_tool_registration_dependency`
  — proves every `tier1/*.py` module is forbidden from importing
  `rest_api_client`/`transport`/`tools` (universal), and forbidden from
  importing `write_api_client`/`pfsense_client` **except**
  `executor.py` (the one sealed exception, `ADR-014`'s Invariant I1).
  This is the "inward-out" direction, i.e. tier1 reaching toward
  pfSense.

**Slice E2 added a third direction**, which `ADR-024`'s own "E1 —
Coordinator ownership and placement" section names explicitly: a
`tier1/*.py` module (`execution_coordinator.py`) reaching *into* the
`security_` family (`security_authorization`,
`security_authorization_verifier`, `security_discovery`,
`security_plan_freshness`) — the first time this has happened in this
codebase. This was **not** structurally forbidden by either existing
test above (neither test's forbidden-root list names the `security_`
family at all), so no modification to the shared tests was needed.
Instead, a dedicated `tests/tier1/test_execution_coordinator_isolation.py`
locks down exactly this module's reviewed import set — mirroring the
established per-module isolation-test pattern already used for
`security_authorization_verifier.py`/`security_plan_freshness.py`
(`tests/test_security_authorization_verifier_isolation.py`,
`tests/test_security_plan_freshness_isolation.py`).

**Four pre-existing "no production module imports this yet" tests**
(one each in `security_authorization`, `security_authorization_verifier`,
`security_plan_freshness`, `authorization_consumption_store`'s own
isolation test files) were each narrowly extended, in this session, to
name `execution_coordinator.py` as their one reviewed consumer — the
same pattern already established when `security_authorization_verifier.py`
first became `security_authorization.py`'s own reviewed consumer. If a
future slice (E3) needs a new consumer of any of these primitives, or a
new outward-reaching import, follow this exact pattern: name the file
explicitly, explain why in a docstring/comment, never loosen the check
to a wildcard or a broad allowance.

**Expected dependency direction, current state**: `security_*` modules
depend on `tier1.canonical`/`tier1.ed25519_authority` only (never on
`tier1`'s stateful machinery). `tier1/execution_coordinator.py` depends
on the `security_*` family plus its own tier1 siblings
(`authorization_consumption_store`, `ed25519_authority`, `errors`) —
and, as of this handoff, **nothing else**: it does not yet import
`executor.py`, `store.py`, `contract.py`, or `state_machine.py`. That is
exactly what Slice E3 would add, under its own future authorization.

**Codex must treat every isolation test as an architectural control.**
See §12 for the explicit warning against "fixing" one by weakening it.

---

## 8. Authorization lifecycle — implemented vs. proposed

Source of truth: `ADR-024`'s "Exact proposed verification/execution
ordering (E2)" section, reproduced here with implementation status
annotated. (`ADR-024`'s own numbering is steps 1–12; this table uses the
same numbers.)

| # | Step | Status at `HANDOFF_SHA` |
|---|---|---|
| 1 | Capability active (`ADR-004` profile check) | Existing, unaffected by any authorization-boundary work |
| 2 | Endpoint allow-listed (`WriteEndpoints`, `ADR-005`) | Existing, unaffected; allow-list is empty |
| 3 | `verify_plan_authorization_signature()` | **Implemented** (Phase D) and **composed** by the coordinator (Slice E2) |
| 4 | `plan_authorization_is_current()` | **Implemented** (Phase D) and **composed** (Slice E2) |
| 5 | `plan_authorization_authorizes_step()` | **Implemented** (Phase D) and **composed** (Slice E2) |
| 6 | Freshness re-check | **Implemented** (Slice E1) and **composed** (Slice E2) |
| 7 | Anchor assurance appropriate for `authz.risk_class` | **Not separately implemented** — `ADR-024` itself documents this as structurally subsumed by step 6 (an invalid target combination never reaches a valid fresh plan; any anchor regression changes the fresh plan's own digest), and Slice E2's own docstring/ADR update records this reasoning explicitly rather than adding a redundant check |
| 8 | Authorization consumption (`try_consume()`) | **Implemented** (Phase D primitive) and **wired as the coordinator's last gate** (Slice E2) — this is where the current implementation boundary stops |
| 9 | `store.create()` | **Not implemented, not wired.** This is Slice E3's first task. |
| 10 | `store.confirm()` with `ConfirmationEvidence` | Existing (`ADR-012`), **not yet reachable** from the authorization path |
| 11 | `executor.execute(contract_id, ...)` | Existing (`ADR-014`), **not yet reachable** from the authorization path |
| 12 | Post-condition verification, audit write | Existing, **not yet reachable** from the authorization path |

**The implementation boundary is unmistakable: steps 1–8 are fully
implemented and composed by `ExecutionCoordinator.authorize_and_consume()`.
Steps 9–12 do not exist in the authorization path at all yet** —
`ExecutionCoordinator` does not import `store.py`, `contract.py`, or
`executor.py`. A successful `authorize_and_consume()` call today means
*only* "every pre-execution gate passed and the authorization is now
durably consumed" — nothing about a `RecoveryContract`, confirmation,
or an actual mutation has happened, and nothing in the current code
makes that happen.

---

## 9. Consumption semantics and crash behavior

**Owner-decided, fixed semantic: "one authorization permits one attempt
to create a `RecoveryContract`."** Not "one execution attempt." Not "one
successful execution."

- **"One successful execution only" was explicitly rejected**
  (`ADR-024`, "Consumption semantics," E3). If consumption happened
  only after a successful `executor.execute()`, the authorization would
  remain valid and reusable for the entire window between "checks
  passed" and "execution confirmed" — during which it could gate
  **multiple concurrent `RecoveryContract`s**, directly reopening the
  replay exposure Phase D exists to close.
- **"One attempt" is precise and testable**: `try_consume()` succeeding
  means "this `authorization_id` will never again gate a
  contract-creation attempt," full stop — regardless of what happens to
  that (not-yet-existing) contract afterward.
- **Freshness failure does not consume.** A `STALE` outcome at the
  freshness gate is explicitly *not* a security anomaly
  (`ADR-022`'s own `STALE`-vs-anomaly classification, reused unchanged)
  — re-planning after a transient staleness produces a *different*
  `plan_digest` anyway, so non-consumption costs nothing and preserves
  the original authorization for a transient-flicker case.
- **Acknowledged, documented gap: the 8→9 crash window.** If a crash
  occurs between successful `try_consume()` (step 8) and `store.create()`
  (step 9, not yet implemented), the authorization is permanently
  consumed with no corresponding `RecoveryContract` ever created. This
  is real, not hypothetical — `try_consume()` and a future
  `store.create()` are two separate atomic operations against two
  separate stores; no shared transaction exists or is proposed.
  **`ADR-024`'s own assessment: this is an accepted, explicitly-named
  v1 safety-over-availability tradeoff, not a silently-accepted gap.**
  An operator whose authorization is burned by a crash in this window
  can simply re-review and re-sign a new one for the same still-valid
  plan.
- **Two-phase claim/commit is named, not designed, not decided, and
  Codex must not invent it.** `ADR-024`'s "Recommended, explicitly
  deferred future enhancement" names a hypothetical
  `claim(authorization_id) -> ClaimToken` / `commit(claim_token)`
  extension purely for future reference — it would need its own design
  pass, its own adversarial review, and its own owner authorization. Do
  not build any part of it opportunistically while working on E3 or
  anything else.

---

## 10. Freshness (Slice E1) — precise recap

- **Fresh discovery source**: the same `discover_security_posture()`
  path already used for planning — no new evidence source.
- **Deterministic plan regeneration**: `generate_security_posture_plan()`
  is re-run with the *same* target parameters
  (`target_capability_posture`/`target_anchor_assurance`) the original
  plan used.
- **`compute_plan_digest()`/`verify_plan_digest()` ownership**: these
  remain `security_plan_digest.py`'s exclusive responsibility;
  `security_plan_freshness.py` calls them, never reimplements them
  (directly proven by
  `test_module_defines_no_second_digest_or_canonicalization_function`).
- **Exact equality, always**: freshness is `verify_plan_digest(fresh_plan, expected_plan_digest)`
  — full byte-level canonical equality, never an approximate or partial
  comparison.
- **Why `evidence_fingerprint` is insufficient**: it excludes the
  `steps` list. If `security_plan.py`'s step-generation logic ever
  changed between authorization time and execution time,
  `evidence_fingerprint` would show no difference even though
  `plan_digest` would — proven directly by
  `test_unchanged_evidence_fingerprint_but_added_step_is_stale` and
  siblings in `tests/test_security_plan_freshness.py`.
- **Failure behavior**: malformed/wrong-type `expected_plan_digest`
  returns `False` (not an exception); an unexpected discovery/plan-
  generation/digest-generation failure raises a sanitized
  `PlanFreshnessError` — never silently returns `True`.
- **No side effects**: `plan_authorization_is_fresh()` performs zero
  authorization-consumption, zero `MutationExecutor`, zero state-machine
  interaction — proven by `tests/test_security_plan_freshness_isolation.py`.

Reference tests: `tests/test_security_plan_freshness.py` (regression/
adversarial), `tests/test_security_plan_freshness_isolation.py` (AST-based).

---

## 11. Target identity gap — read carefully before any future slice touches it

**This is the single most important open architectural question in the
authorization boundary, and it is intentionally unresolved. Do not
close it unilaterally.**

Facts (verified against shipped code, `ADR-024`'s "`target_identity_digest`
design," E5):

- **Ordinary `PlanAuthorization` has no `target_identity_digest`-shaped
  field at all** in its already-shipped, already-pushed schema. Adding
  one would be a schema change to an already-shipped artifact type.
- **`DeprovisionAuthorization` has a related, already-accepted field**
  (`target_identity_digest`), but its deferral is *already decided by
  `ADR-022` itself* — no code path anywhere constructs a
  `DeprovisionAuthorization` at all, because no destructive execution
  mechanism exists yet. This is a *separate* question from the one
  below and must not be conflated with it.
- **`netgate_id`** (`src/pfsense_mcp/models/system.py`'s `SystemStatus`)
  and **`pfhostid`** (`src/pfsense_mcp/models/system_ha_sync.py`'s
  `SystemHaSync`) are real, already-modeled, pfSense-native,
  per-installation identifiers — genuine candidate signals for a future
  appliance-identity binding.
- **Both are deliberately null by default**
  (`include_identifying_metadata=False`) in every existing caller — this
  codebase already treats them as privacy-sensitive, hidden-unless-
  explicitly-requested data, a deliberate, pre-existing convention, not
  something this session invented.
- **No target-binding mechanism has been authorized.** Nothing in the
  currently-accepted authorization chain cryptographically distinguishes
  "this plan, reviewed and authorized for Appliance A" from "an
  identical plan, by coincidence, on Appliance B" — a real, narrow gap,
  bounded by the fact that this project's entire architecture currently
  assumes exactly one pfSense appliance per deployment
  (`PfSenseConfig`/`PFSENSE_API_URL` is a single, required, env-var-
  driven target; there is no multi-appliance or multi-tenant concept
  anywhere in `config.py`, the MCP transport, or the tool registry).
- **The desired architectural direction, per explicit owner instruction
  during this session, is that the architecture must remain correct for
  a future multi-appliance deployment without authorization becoming
  implicitly portable between appliances** — i.e., closing this gap
  correctly matters, but must not be done by inventing a placeholder.

**Unresolved prerequisites, named by `ADR-024`, not resolved by
anything in this repository yet:**

1. An explicit owner/product decision on whether this project's
   deployment model is intended to remain permanently single-appliance-
   per-process (if so, this gap may be judged acceptably low-value to
   close at all).
2. If closing it is judged worthwhile: an explicit owner decision on
   whether to override the existing `include_identifying_metadata`
   privacy default for this one purpose.
3. A null-handling design for deployments with neither `netgate_id` nor
   `pfhostid` available.
4. A schema-placement decision — `ADR-024` recommends *against* folding
   this into `plan_digest` itself (would require a schema-version bump
   to an already-shipped, already-tested Phase B primitive), in favor of
   a new, separate, additive field/digest at whatever future layer
   consumes it.
5. (Named by this document, not `ADR-024`, as a natural consequence of
   #2–#4): lifecycle behavior across backup/restore/clone/HA/migration
   scenarios, if and when a concrete design is proposed — pfSense
   appliances can be cloned or restored from backup, which interacts
   directly with any identity-binding scheme.

**Codex MUST STOP and report, rather than inventing a substitute, if any
future slice (including E3) turns out to require target-identity
binding for correctness.** `ADR-024`'s own "Explicit stop conditions for
each future slice" names this directly: "Any slice that discovers
`target_identity_digest` is load-bearing for correctness (not merely
defense-in-depth) — stop, that reopens Question B and needs its own
owner decision first."

---

## 12. Owner decisions (fixed, not proposals — do not re-litigate)

These were explicit choices made by the project owner during this
session's Phase E work, each narrowing an otherwise-open architecture
question. Distinguish these from `ADR-024`'s own *proposals* (§ sections
above) — a proposal is something `ADR-024` recommends; an owner decision
is something already chosen and binding.

1. The architecture must remain correct for a future multi-appliance
   deployment without authorization becoming implicitly portable between
   appliances (§11).
2. Do not override the identifying-metadata privacy default, and do not
   add `netgate_id`/`pfhostid` to `PlanAuthorization` or wire them into
   runtime authorization, without a separate, explicit future decision.
3. The coordinator's placement is `src/pfsense_mcp/tier1/execution_coordinator.py`
   — tier1-native, sibling to `executor.py` — a fixed placement decision,
   not merely `ADR-024`'s recommendation.
4. `MutationExecutor` remains authorization-unaware, permanently, not
   merely for the current slice — folding authorization into the
   executor was considered and rejected, not merely deferred.
5. Two-phase authorization consumption (claim/commit) is deferred; the
   v1 "one attempt to create a RecoveryContract" semantic, with its
   acknowledged 8→9 crash-window tradeoff, is accepted as-is for now.
6. `DeprovisionAuthorization` verification remains deferred — no
   parallel verifier, no shared machinery built ahead of an actual
   destructive-execution mechanism existing.
7. The appliance `target_identity_digest` gap (Question B in §11)
   remains explicitly deferred — no substitute, no placeholder, no
   weaker proxy field, ever, without a new owner decision resolving the
   prerequisites in §11.
8. Public MCP remains READ-only until a separate, explicit Milestone 9
   activation decision — nothing in the E1/E2 work changes this, and
   nothing in a hypothetical E3 would either, since E3's own scope (per
   `ADR-024`'s "Explicit stop conditions") excludes any MCP construction
   site.

---

## 13. Threat model / known attack classes

Full authoritative threat model: `docs/THREAT_MODEL.md` (read in full —
it frames this project's local-stdio trust model: defends against a
malicious/compromised MCP client or AI model interacting with an
already-deployed, already-reviewed server; explicitly does **not**
defend against a malicious contributor modifying the server's own
source). `ADR-024`'s own consolidated "Threat analysis (consolidated
matrix)" table is the authoritative disposition list for the
authorization-boundary-specific threats below — read it in full rather
than relying solely on this summary.

| Threat class | Disposition at `HANDOFF_SHA` |
|---|---|
| Authorization forgery | Closed — `PinnedAuthoritySet`, `ADR-012` precedent, reused unchanged |
| Wrong signer / signer downgrade | Closed — unknown/inactive authority fails closed; `algorithm` checked before any verification attempt |
| Replay | Closed — `try_consume()`'s atomic insert-once, now wired as the coordinator's last gate (Slice E2) |
| Expired authorization | Closed — `plan_authorization_is_current()`, independent check |
| Plan / step substitution | Closed — exact `plan_digest` match + exact `authorized_step_ids` membership, no wildcard matching |
| Target substitution (appliance-level) | **Open, intentionally** — see §11 |
| Target substitution (resource-level, within one appliance) | Closed at the `RecoveryContract` layer (existing `target_fingerprint` drift detection) — not yet reachable from the authorization path since E3 is not implemented |
| Stale target state | Closed — Slice E1's freshness re-check, now composed by the coordinator (Slice E2) |
| TOCTOU (time-of-check/time-of-use) | Bounded per-transition; the 8→9 crash window (§9) is the one acknowledged, documented gap |
| Double execution / concurrent execution | Closed at the consumption layer (proven via an 8-thread race in both the store's own tests and the coordinator's tests); the `RecoveryContract`-layer CAS defense is existing but not yet reachable from this path |
| Consumption DB tampering / rollback / copy | Closed for tampering (fails closed, tested); rollback/copy is an inherited, acknowledged limitation shared with every other Tier 1 store — not a gap introduced by this work |
| Direct executor bypass | Construction-site/process-review-level guarantee only, not language-level — explicitly documented as such in `ADR-024`'s E7 and in `execution_coordinator.py`'s own module docstring |
| State-machine bypass | Not possible — closed transition table unaffected |
| Canonicalization / digest-domain disagreement | Closed — single shared `tier1.canonical` primitive, `DigestPurpose` domain separation, reused everywhere |

---

## 14. Test map

- **Security-semantics tests** (encode the actual invariants, not just
  code coverage): `tests/test_security_authorization*.py`,
  `tests/test_security_plan_freshness.py`,
  `tests/tier1/test_authorization_consumption_store.py`,
  `tests/tier1/test_execution_coordinator.py`.
- **Isolation/AST tests** (structural, dependency-direction proofs, not
  ordinary unit tests): `tests/tier1/test_isolation.py` (the two shared,
  central tests), plus one dedicated file per security-boundary module —
  `tests/test_security_authorization_isolation.py`,
  `tests/test_security_authorization_verifier_isolation.py`,
  `tests/test_security_plan_freshness_isolation.py`,
  `tests/tier1/test_authorization_consumption_store_isolation.py`,
  `tests/tier1/test_execution_coordinator_isolation.py`.
- **Adversarial tests**: embedded throughout the regression files above
  (forged signatures, tampered fields, wrong scopes, malformed input,
  algorithm downgrade attempts, "same step ID in a different plan," etc.)
  — not a separate directory.
- **Concurrency tests**: `threading.Barrier`-based races proving
  exactly-one-success, in
  `tests/tier1/test_authorization_consumption_store.py`
  (`test_concurrent_double_consumption_yields_exactly_one_success`) and
  `tests/tier1/test_execution_coordinator.py`
  (`test_concurrent_attempts_yield_exactly_one_success`).
- **Persistence/tamper tests**: `tests/tier1/test_authorization_consumption_store.py`'s
  tampered-row/tampered-timestamp/malformed-schema/database-failure
  tests — the pattern any future persistence-adjacent test should
  follow.
- **Coordinator tests (Slice E2, new)**:
  `tests/tier1/test_execution_coordinator.py` (38 tests: happy path,
  each gate's independent denial + non-consumption proof, exact
  ordering proofs via monkeypatched "must not be called" spies,
  concurrency, cross-cutting invariants) and
  `tests/tier1/test_execution_coordinator_isolation.py` (10 AST-based
  structural tests).

**Explicit warning, repeated because it matters: a failing security or
isolation test is not authorization to weaken the test. Assume you
violated an invariant first, and re-read this document's §5 and the
relevant ADR before considering any change to a test's assertions.**

---

## 15. Validation commands (repository-standard, not invented)

Run from the repository root with `.venv` activated (`source .venv/bin/activate`).

```bash
# Targeted (fast, run first while iterating)
python -m pytest tests/tier1/test_execution_coordinator.py tests/tier1/test_execution_coordinator_isolation.py -q

# Full suite
python -m pytest -q

# Formatting / lint
ruff format --check .
ruff check .

# Types
mypy src/pfsense_mcp scripts lab witness_daemon

# Docs
mkdocs build --strict

# Repository-defined composite gates (see Makefile)
make quick      # 11-stage fast gate: format/lint/type/test + GET-only + write-inactivity checks
make validate   # 20-stage full gate: everything in quick + bandit + fixture/query-param safety +
                #                     public-contract snapshot + doc consistency + git report
```

`make validate`'s stage 18 ("Public MCP contract snapshot") is the
authoritative, automated check for "did I accidentally expose or grow
the WRITE surface" — it must always report `public_contract: OK (42 tools)`
with 0 WRITE. Treat any change to that number as a stop-and-report
event, not something to silently accept.

---

## 16. Current deferred-work register

| Item | Why deferred |
|---|---|
| Target-identity binding for ordinary `PlanAuthorization` | Requires an owner product decision (single- vs. multi-appliance), a privacy-default override decision, a null-handling design, and a schema-placement decision — none made yet (§11) |
| `DeprovisionAuthorization` verification | `ADR-022` itself defers it; no destructive execution mechanism exists yet to consume a verified one; building shared machinery now would be speculative |
| Slice E3 (coordinator → `RecoveryContract`/`MutationExecutor` wiring) | Not yet authorized — see §17 for what it would need |
| Two-phase claim/commit consumption | Named for future reference only, not designed, not decided — would need its own design pass and owner authorization |
| Public MCP WRITE exposure (Phase H) | Gated on Milestone 9, an entirely separate, not-yet-made activation decision |
| WRITE milestone activation generally | Same — 0 of 3 `*_WRITE` capabilities may become active without a dedicated future authorization |
| Guided security-posture provisioning wizard (`ADR-021`) | Accepted architecture only — no wizard, posture enforcement, or fail-closed runtime behavior authorized yet |
| Official/version-aware guidance layer consumption (`ADR-017`/`018`) | Accepted architecture + inert scaffolding only — no consumer wired |

---

## 17. Next recommended slice (planning only — NOT authorization to implement)

Per `HANDOFF_SHA`, the smallest safe next step is **`ADR-024`'s Slice
3**, exactly as that document specifies it (`docs/adr/ADR-024-execution-authorization-coordination.md`,
"Implementation slices for a future authorized coding phase" → "Slice 3
— wire `store.create()`/`confirm()`/`executor.execute()` behind the
coordinator"):

- **Objective**: extend `ExecutionCoordinator` so that a successful
  Slice E2 outcome (consumption) is followed by `store.create()`,
  `store.confirm()` with real `ConfirmationEvidence`, and
  `executor.execute(contract_id, ...)` — completing ordering steps 9–12
  from §8's table.
- **Invariant to establish**: "the full authorization-to-execution chain
  is provably correct end-to-end against synthetic dependencies, still
  fully unreachable from any production entry point."
- **Expected files**: `tier1/execution_coordinator.py` (extend only).
- **Forbidden files/behavior**: `tier1/executor.py`,
  `tier1/state_machine.py` (their existing public behavior must not
  change — this slice calls their existing public APIs, never modifies
  them); no MCP construction site; no target-identity mechanism unless
  it turns out to be load-bearing (§11), in which case STOP.
- **Major tests required**: full happy path against synthetic/mock
  stores and a synthetic adapter (mirroring `test_executor.py`'s own
  convention); a crash-simulation test between consumption and contract
  creation (proving the acknowledged 8→9 gap's actual behavior, not
  just its written description); a concurrency test proving two
  coordinator calls racing the same authorization yield exactly one
  `RecoveryContract`.
- **Major STOP conditions**: any requirement to modify
  `MutationExecutor`'s or `state_machine.py`'s existing public behavior;
  any requirement to construct the coordinator from
  `Application`/`factory.py`/the tool registry before Milestone 9's own
  separate activation decision; any discovery that `target_identity_digest`
  is load-bearing for correctness.

**This section is planning information only. Do not begin Slice E3
during bootstrap (§18) — a separate, explicit owner authorization,
matching the narrow, scoped style of every prior slice in this project,
is required first.**

---

## 18. Codex bootstrap protocol

On first takeover, Codex must, in order:

1. `git fetch origin`.
2. Verify the exact current `HEAD`/`origin/main` SHA — do not assume it
   still equals `HANDOFF_SHA` above; a documentation-only commit may
   have been added after it (see §1's note). Record whatever SHA is
   actually current.
3. Confirm the working tree is clean (`git status --short`, expect empty
   output).
4. Read `docs/CODEX_TAKEOVER.md` (this document) completely.
5. Read the files listed in §19's mandatory reading order, in that
   order.
6. **Independently verify important claims against repository code and
   tests** — do not take this document's assertions on faith where they
   are checkable (e.g., re-run `make validate`'s public-contract stage
   yourself; grep for `target_identity_digest`/`netgate_id`/`pfhostid`
   yourself; confirm `execution_coordinator.py` does not import
   `executor`/`store`/`contract`/`state_machine` yourself).
7. Run an appropriate baseline validation (§15) and record actual
   results.
8. Report understanding of: current architecture; security invariants
   (§5); current implementation boundary (§8); unresolved gaps
   (especially §11); next proposed slice (§17).
9. **STOP.** Do not modify code during this bootstrap. A separate owner
   authorization, in the same narrow, explicitly-scoped style used for
   every slice in this project's history, is required before any
   implementation begins — including Slice E3.

---

## 19. Mandatory reading order for Codex

Read each of these **completely**, not by snippet, in this order. This
list is curated to minimize context use while preserving architectural
understanding — do not read the entire repository.

1. `docs/CODEX_TAKEOVER.md` (this document)
2. `docs/adr/README.md` (ADR index)
3. `docs/adr/ADR-022-execution-authorization-boundary.md`
4. `docs/adr/ADR-023-authorization-verification-boundary.md`
5. `docs/adr/ADR-024-execution-authorization-coordination.md`
6. `docs/adr/ADR-021-security-posture-provisioning.md`
7. `docs/EXECUTION_AUTHORIZATION_BOUNDARY.md`
8. `docs/tier1/specs/sealed_executor.md`
9. `docs/THREAT_MODEL.md`
10. `src/pfsense_mcp/security_discovery.py`
11. `src/pfsense_mcp/security_plan.py`
12. `src/pfsense_mcp/security_plan_digest.py`
13. `src/pfsense_mcp/security_authorization.py`
14. `src/pfsense_mcp/security_authorization_verifier.py`
15. `src/pfsense_mcp/security_plan_freshness.py`
16. `src/pfsense_mcp/tier1/authorization_consumption_store.py`
17. `src/pfsense_mcp/tier1/execution_coordinator.py` (the newest module)
18. `src/pfsense_mcp/tier1/executor.py`
19. `src/pfsense_mcp/tier1/state_machine.py`
20. `tests/tier1/test_isolation.py`
21. `tests/tier1/test_execution_coordinator.py` and
    `tests/tier1/test_execution_coordinator_isolation.py`

Skim rather than fully read, only if time-constrained:
`src/pfsense_mcp/tier1/store.py`, `src/pfsense_mcp/tier1/contract.py`
(useful context for Slice E3 planning, not required for understanding
the current boundary).

---

## 20. Historical traps / non-obvious findings

Things a fresh agent could easily get wrong, learned the hard way during
this project's history:

- **The canonicalization module lives at `src/pfsense_mcp/tier1/canonical.py`**,
  not any path resembling `security_canonical.py` — an earlier task
  instruction in this project's history named a non-existent path and
  had to be corrected against the actual repository.
- **`evidence_fingerprint` does not bind the complete plan.** It
  excludes the `steps` list. Never treat it as a substitute for full
  `plan_digest` recomputation, for freshness or for anything else.
- **Ordinary `PlanAuthorization` has no target-identity field at all**
  — this is easy to assume exists (since `DeprovisionAuthorization`
  has a related one) and is not the same question. See §11.
- **The presence of internal WRITE-related code does not mean MCP WRITE
  is exposed.** This project deliberately builds inert machinery years
  ahead of activation. Always check the actual MCP tool registry and
  `make validate`'s public-contract stage, never infer exposure from
  the existence of `tier1/executor.py` or similar.
- **Python-level bypass resistance is a construction-site/AST-test-time
  guarantee, not a language-level one.** `ADR-024`'s E7 section states
  this explicitly and Codex should not claim stronger bypass resistance
  than actually exists in any future documentation or code comments.
- **Consumption semantics prioritize replay safety over retry
  ergonomics**, deliberately. The 8→9 crash window (§9) is a known,
  accepted tradeoff — do not "fix" it by weakening consumption
  atomicity or by silently building two-phase consumption without a
  fresh, explicit authorization for exactly that.
- **`plan_authorization_is_current()` deliberately does not check
  `issued_at`.** This is intentional, documented behavior in that
  module's own docstring — not a gap.
- **The coordinator's `requested_plan_digest`/`requested_step_id`
  parameters are deliberately separate from `authz.plan_digest`/the
  step being checked.** Passing `authz.plan_digest` back as its own
  comparison target would be a tautology; the real check is "does what
  the caller claims to be requesting match what `authz` actually
  authorizes" — a confused-deputy defense, not redundant plumbing. Any
  future slice that "simplifies" this by collapsing the two must not do
  so without re-deriving why they were separate in the first place.
- **`ruff format`/`ruff check --fix` may reformat files you just wrote**,
  including reordering imports — always re-run the full test suite after
  auto-fixes, don't assume formatting-only changes are risk-free to skip
  re-verifying.

---

## Change log for this document

- 2026-08-11 — Initial version, written at the conclusion of Slice E2
  (`HANDOFF_SHA` = `48a93862f95981c7c97b47ae94cc8467196b92c5`), per an
  explicit owner instruction to prepare a complete, lossless takeover
  package for a fresh implementation agent ahead of a usage-limit
  boundary.
