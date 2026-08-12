# ADR-027: Closed LAB-T1 Stage 3 execution-port composition

- **Status:** Accepted (2026-08-12, owner)
- **Date:** 2026-08-12
- **Scope:** Architecture only. This ADR does not authorize implementation,
  live LAB access, key provisioning, attestation creation, mutation, WRITE
  activation, Stage 3F, or B3b.

## Context

ADR-026's closed Stage 3D/E/G registry, selector, gate/lease validator,
reconciliation authority, and schema-v6 restart harness exist. The public
selector correctly fails closed because no fixed internal component composes
those pieces into a concrete execution path.

The missing component must not become another executor. `MutationExecutor`
already exclusively owns authoritative pre/post reads, semantic and locator
validation, request construction timing, forward and rollback sends, fault
classification, and automatic state transitions. `SqliteRecoveryContractStore`
owns authenticated persistence, compare-and-set transitions, interruption
reconciliation, audit, and signed reconciliation resolution. The execution port
must compose those owners without repeating their decisions.

Repository review found one sealed-interface gap and several lab-only
construction gaps. An ambiguous operation needs a fresh authoritative
fingerprint and locator to create applied-state reconciliation evidence.
`MutationExecutor` owns the canonical identity/fingerprint/locator checks, but
currently exposes them only inside `execute()` and `rollback()`. Letting the lab
port recompute them would create a second security owner. A narrow read-only
executor observation interface is therefore required.

## Decision proposed

The owner accepted this decision on 2026-08-12. Acceptance fixes the ownership
and interface boundaries below but does not authorize any implementation slice,
live LAB activity, key provisioning, WRITE activation, Stage 3F, or B3b.

`ClosedStage3ExecutionPort` is a **thin lab-only composition root with narrowly
typed per-stage orchestration methods**. It is not an execution engine. Its
implementation selects one immutable registry entry, constructs fixed runtime
objects, invokes existing owners, records their typed results, and verifies
declared counts/final policy.

The port receives only:

- the exact immutable `ScenarioDefinition` object from `SCENARIOS`;
- the absolute attestation deadline already validated by `ClosedLiveBinding`.

It must never receive an endpoint, method, payload, candidate, locator,
description, adapter, transport, fault enum, store path, reconciliation result,
or arbitrary callback from CLI/model input. All such values come from fixed
LAB-T1 configuration, the immutable registry, or authoritative protected state.

### Narrow sealed-executor addition

Add a read-only method conceptually shaped as:

```python
@dataclass(frozen=True)
class AuthoritativeReconciliationObservation:
    contract_id: str
    operation_id: str
    state_version: int
    uncertainty_origin: RecoveryState
    target_fingerprint: str
    lifecycle_locator: int

def observe_reconciliation_target(
    self,
    contract_id: str,
    *,
    adapter: CapabilityAdapter,
) -> AuthoritativeReconciliationObservation:
    ...
```

The exact repository-native name may differ. The method:

1. loads and authenticates the contract from the store;
2. requires `RECONCILIATION` and derives the immediately preceding
   `EXECUTING`/`ROLLING_BACK` origin from authenticated audit history;
3. decrypts only the protected semantic identity;
4. calls `adapter.read_target()` through the executor-held read client;
5. reuses the executor's existing identity digest, lifecycle-locator, and
   fingerprint digest logic;
6. returns the frozen minimum observation above;
7. performs no send, transition, outcome inference, pending-file write, or
   reconciliation resolution.

This keeps authoritative observation with the current owner. It does not add a
second reconciliation engine and does not decide APPLIED/NOT_APPLIED. The
signed owner outcome remains the only authority that resolves ambiguity.

### Lab-only construction additions

Add a fixed `LabStage3RuntimeFactory` (name illustrative) that constructs:

- secure LAB config and mandatory gate receipt;
- one authoritative `PfSenseClient`;
- the stateless `AliasDescriptionAdapter`;
- schema-v6 store from fixed secure bootstrap configuration;
- `WriteApiClient` over a scenario-selected `FaultProxy` whose mode comes only
  from the immutable registry;
- `MutationExecutor` with fixed alias-only policy;
- fixed reconciliation paths/verifier;
- a scoped lab-only endpoint installation guard for the already-proven alias
  endpoint, always removed on exit.

The factory accepts no arbitrary execution data. It is excluded from packaging
and production construction and remains unreachable from public MCP.

Add a closed `AliasDescriptionScenarioOrchestrator` whose methods correspond to
the registry's D actions. Replacement descriptions are constants keyed by
`ScenarioId`, not parameters. Every orchestration mutation is itself a fresh,
confirmed RecoveryContract executed by a separate `MutationExecutor` over a
clean proxy. Thus it cannot bypass the sealed send path. Its authoritative send
count is the clean proxy's attempt delta; its final restoration check is a fresh
adapter read and exact A fingerprint comparison.

### State ownership

Process-local only:

- config-derived clients/transports;
- stateless adapter;
- executors;
- fault proxies and per-install attempt counters;
- immutable registry definition;
- decrypted intent/snapshot within executor call frames;
- `ResolvedTransportTarget` within one executor send boundary;
- request/response and connection state.

Persisted only:

- schema-v6 encrypted/HMAC `RecoveryContract`, including A, B when established,
  lifecycle locator, state/version, and audit history;
- authenticated pending reconciliation evidence;
- externally supplied signed reconciliation evidence;
- secure bootstrap material by reference, never inside the contract.

Adapters, clients, requests, connections, fault-proxy state, and
`ResolvedTransportTarget` are never persisted.

## Exact ownership matrix

| Invariant | Sole authoritative owner | Port role | Gap/status |
|---|---|---|---|
| Semantic-unit restriction | immutable `SCENARIOS` registry | identity-check exact registry object | owned |
| Candidate restriction | `LabConfig` + registry fixed constant | compare gate receipt | owned |
| `ScenarioId` restriction | `ScenarioId`/`scenario_plan()` | dispatch only | owned |
| Endpoint restriction | `WriteEndpoints` + `WriteApiClient` | install fixed scoped lab entry | lab construction interface needed |
| HTTP method restriction | `MutationPolicy` + `WriteApiClient` | none | owned |
| Request construction | stateless `AliasDescriptionAdapter` after executor checks | none | owned |
| Transport locator resolution | `MutationExecutor` | none | owned |
| Locator lifecycle continuity | `MutationExecutor` + atomic store verified transitions | none | owned |
| Plan authorization | `ExecutionCoordinator`/authorization store | not used or reimplemented by LAB-T1 evidence harness | owned; LAB confirmation remains separate evidence authority |
| Attestation/gate lease | `lab.safety` + `ClosedLiveBinding` | recheck absolute deadline before actions | owned |
| Forward at-most-once | `MutationExecutor._send()` | invoke once | owned |
| Rollback at-most-once | `MutationExecutor._send()` | invoke once | owned |
| Authoritative B | `MutationExecutor` + `store.mark_execution_verified()` | observe result | owned |
| Exact A | adapter semantic snapshot + executor rollback verification; final independent read by port | require final digest equality | deliberately layered, not duplicate authority: executor owns transition, port owns evidence claim |
| Uncertainty classification | executor `faults.classify_fault()` for state; `classify_read_back()` for evidence labels | report only | owned |
| Retry suppression | executor has no retry loop; restart constructor reconciles before calls | do not reinvoke | owned |
| Reconciliation state | state machine + store | emit/stop only | owned |
| Signature verification | pinned `Ed25519ReconciliationVerifier` through store | consume fixed signed artifact | owned |
| Store integrity | `SqliteRecoveryContractStore` | construct/reopen only | owned |
| Restart reconstruction | store `reconcile_interrupted()` triggered by new `MutationExecutor` | discard/rebuild runtime | owned |
| Fault delivery classification | `FaultProxy.FAULT_DELIVERY` | select mode from registry only | owned |
| Orchestration mutation scope | new closed description orchestrator using adapter/executor | select fixed action | **no current owner; narrow lab interface required** |
| Send accounting | each `FaultProxy.send_attempts` counter | snapshot/delta and separate by proxy/phase | owned once runtime composition exists |
| Reconciliation observation | `MutationExecutor` | request frozen observation | **no public interface; narrow sealed interface required** |
| Pending evidence emission | `emit_pending_evidence()` | pass executor observation and fixed paths | owned after observation interface |
| Reconciliation resume | `resolve_signed_evidence()` + store | stop or invoke fixed resume path | owned |

No invariant is assigned to two decision owners. The final-A evidence layer does
not authorize `ROLLED_BACK`; only the executor/store do. It independently checks
whether the lab report may claim a safe resting state.

## Call graphs

Notation: `S:x→y` is persisted store state; `R` is an authoritative read; `W`
is one executor-owned send; `O` is a separately counted orchestration send.

### Ordinary closed scenario

`CLI(ScenarioId)` → `ClosedLiveBinding.execute` → `ClosedStage3Backend` →
`LabStage3ExecutionPort` → factory/gates → registry-derived scenario method →
`prepare_contract`/store confirm → `MutationExecutor.execute` (`S:PREPARED→EXECUTING`,
`R`, checks, `W`, `R`, `S:EXECUTING→VERIFIED`) → optional
`MutationExecutor.rollback` (`S:VERIFIED→ROLLING_BACK`, `R`, checks, `W`, `R`,
`S:ROLLING_BACK→ROLLED_BACK`) → independent final `R` → `BackendResult` →
binding validation/report. The port passes contract ID, adapter and the exact
prepared intent only; request/locator never cross into it.

### D1 stale before forward

Port prepares subject contract against A (`S:PREPARING→PREPARED`). Closed
orchestrator creates its own contract and invokes its own executor to change
A→C (`O=1`, authoritative verification). Subject executor executes:
`S:PREPARED→EXECUTING`, `R=C`, fingerprint mismatch,
`S:EXECUTING→FAILED`, `W=0`. Orchestrator uses a new sealed lifecycle C→A
(`O=2`) and verifies A by fresh `R`. Port reports counts; it never forces the
subject state or sends directly.

### D3 post-B rollback conflict

Subject executor performs A→B (`W-forward=1`, authoritative B sealed,
`S=VERIFIED`). Orchestrator performs B→C (`O=1`). Subject rollback transitions
to `ROLLING_BACK`, reads C, detects `fingerprint(C) != sealed B`, transitions to
`ROLLBACK_FAILED`, and sends zero rollback requests. Orchestrator restores C→A
through a separate sealed lifecycle (`O=2`) and final read proves A.

### E forward response loss / ambiguous

Factory wraps subject write transport in registry-selected `FaultProxy` and
resets its counter. Executor transitions to `EXECUTING`, performs pre-read and
one send. Proxy forwards once then drops/times out; executor classifies
ambiguous and transitions to `RECONCILIATION`. Port calls the proposed
executor observation method for a fresh read and validated fingerprint/locator,
then `emit_pending_evidence()` with fixed paths. Store remains reconciliation;
no resend or owner result is inferred. `send_attempts == 1` owns the evidence.

### E rollback response loss / ambiguous

After executor has sealed B, rollback transitions to `ROLLING_BACK`, validates
fresh B+locator, and sends once through the selected proxy. Response uncertainty
causes `RECONCILIATION`. The executor observation method performs a fresh read
and validates identity/locator. Pending evidence records rollback origin and
the observed locator (never a forward fingerprint). No second rollback occurs.

### G restart from EXECUTING

Persist real `EXECUTING`; discard executor, adapter, clients, transport and
proxy. Reopen schema-v6 store from fixed bootstrap. Constructing a new executor
calls `store.reconcile_interrupted()`, producing
`S:EXECUTING→RECONCILIATION`. No send occurs. Any later observation is fresh
through the new executor; no projection/request/client state is recovered.

### G restart after verified B

Persist `VERIFIED` with encrypted A, HMAC-bound B and locator. Discard runtime;
reopen store and construct new clients/adapter/executor. `VERIFIED` is not an
interrupted state, so no transition/send occurs. Explicit rollback performs a
fresh read, requires B+locator, sends once, fresh-reads A, and atomically marks
`ROLLED_BACK` only after exact verification.

### G restart from ROLLING_BACK

Persist `ROLLING_BACK`; discard runtime. New executor construction calls
`reconcile_interrupted()`, producing `ROLLING_BACK→RECONCILIATION`. No rollback
is automatically invoked and no proxy/request state survives. Observation and
owner reconciliation follow the rollback-origin path.

### Owner-signed reconciliation resume

Runner has stopped. Separate owner command loads authenticated pending evidence
and the current store, chooses one allowed typed outcome, and writes a signed
artifact. Explicit resume reconstructs store with pinned verifier, loads the
fixed signed artifact, validates origin/operation/version/fingerprint/locator/
signature, and calls `store.resolve_reconciliation()`. Applied-forward yields
`VERIFIED` with sealed B; applied-rollback yields `ROLLED_BACK`; non-applied
outcomes yield the defined failure state. Resume performs zero sends. Any later
rollback is a new explicit executor call with a fresh authoritative read.

## Description-only orchestration finding

`alias_evidence.run_description_cycle()` proves the basic shape but is not a
sufficient port API: it accepts a replacement string and dynamically installs
the endpoint, and its return value is campaign-oriented rather than a typed
orchestration result. It must not be exposed to the Stage 3 selector.

The needed interface is lab-only and closed by `ScenarioId`. It may reuse
`AliasDescriptionAdapter`, `prepare_contract()`, store confirmation, and
`MutationExecutor`; it must not call `WriteApiClient` directly. Scenario-owned
A/B/C constants are selected internally. Separate clean `FaultProxy` instances
make orchestration attempt counts independent from subject forward/rollback
attempts. Restoration is proven by an authoritative adapter read and exact A
fingerprint, not by a boolean returned from the mutation call.

## FaultProxy finding

`FaultProxy` is already the correct transport-boundary mechanism. It wraps the
transport injected into `WriteApiClient`; the executor remains unaware of fault
selection. `install()` resets both trigger and attempt count. The port maps the
immutable scenario's `fault_class` to one closed `FaultScenario` internally and
must verify `delivery_semantics == ScenarioDefinition.upstream_delivery` before
execution. Timing never determines delivery. On restart, proxy state is
discarded; persisted state, not the proxy, controls reconciliation/no-resend.

## Restart finding

The store and executor already implement the security behavior. A missing
lab-only factory must reopen the schema-v6 store using fixed secure bootstrap,
build fresh read/write clients, adapter, policy and executor, and let executor
construction reconcile `EXECUTING`/`ROLLING_BACK`. The fixed registry supplies
scenario identity. A fresh executor observation supplies any post-restart
authoritative evidence. Persisting or accepting a transport projection is
forbidden.

## Attestation and accounting

`lab.safety` owns attestation validation and read-only preflight.
`ClosedLiveBinding` owns the conservative whole-scenario lease calculation.
The port rechecks the absolute deadline before each gate, orchestration,
executor invocation, observation, evidence write, and final read. It does not
renew or reinterpret the lease.

`FaultProxy.send_attempts` is the sole transport-attempt counter. The runtime
uses separate proxies for orchestration and subject execution, and records
counter deltas around forward and rollback invocations. The port checks these
against the immutable plan; it does not infer counts from state alone.

## Hostile review

- **Second executor:** avoided; port never reads protected artifacts, resolves
  locators, constructs requests, sends, or transitions execution states.
- **Arbitrary request/transport:** avoided by fixed factory and registry-only
  selection. No dependency injection is exposed at CLI/runtime boundary.
- **Fresh-locator bypass:** avoided by executor-owned observation and ordinary
  execute/rollback paths.
- **Out-of-executor sends:** orchestration also uses a separate executor; only
  `WriteApiClient`/transport chokepoint sends.
- **Generic orchestration:** avoided by scenario-specific methods/constants;
  no description parameter crosses the selector boundary.
- **Caller-controlled fault:** avoided by registry mapping; proxy enum is not a
  CLI parameter.
- **Count divergence:** proxy counters own attempts; separate proxies and
  before/after deltas prevent orchestration/subject conflation.
- **Restart stale state:** factory reconstructs only from authenticated store
  and secure bootstrap; all transport objects are fresh.
- **Pending fabrication:** pending emitter consumes an executor-owned frozen
  observation plus authoritative store state and fixed paths.
- **Automatic reconciliation:** impossible; observation does not decide outcome
  and resume requires pinned owner signature.
- **Public reachability:** lab package remains excluded from production
  packaging/import roots; isolation tests must prohibit imports from public MCP.
- **Stage 3F expression:** impossible because adapter/orchestrator expose only
  description replacement and the registry has no sibling/create/delete cases.

## Classification

**MINOR INTERFACE ADR REQUIRED.**

No security ownership moves and no new lifecycle is required. One narrow
read-only executor observation method is necessary to avoid duplicating
identity/fingerprint/locator authority in the port. Lab-only factory and closed
description-orchestration interfaces are also required, but they compose
existing sealed owners rather than change them.

## Implementation slices

1. **Executor observation interface (offline only).** Expected files:
   `tier1/executor.py`, sealed-executor/capability specs, executor tests.
   Boundary: read-only reconciliation observation; no send/transition/outcome.
   Tests: state/origin, identity/locator/fingerprint, malformed/missing target,
   zero sends, no plaintext/projection persistence. STOP if observation requires
   moving reconciliation decisions into executor or exposing raw clients.
2. **Fixed LAB runtime factory (offline only).** Expected files: new lab factory,
   config/reconciliation helpers, tests. Boundary: construction only. Tests:
   fixed candidate/endpoint/policy/paths, scoped endpoint cleanup, no production
   import/reachability. STOP if caller-selected construction data is required.
3. **Closed description orchestrator (offline only).** Expected files: lab
   orchestrator/alias evidence and tests. Boundary: scenario-ID-only A/B/C
   mutations through separate executor. Tests: D1-D5, separate counts, exact A,
   sibling immutability. STOP if arbitrary description or direct PATCH is needed.
4. **E composition and pending emission (offline only).** Expected files:
   Stage 3 port/runtime and fault/reconciliation tests. Boundary: registry fault
   mapping, observation, authenticated pending stop. STOP on timing inference,
   retry, caller-selected outcome, or unsigned auto-resume.
5. **G reconstruction composition (offline only).** Expected files: runtime
   factory/restart tests. Boundary: authenticated store reconstruction. Tests:
   EXECUTING/ROLLING_BACK reconciliation, VERIFIED+B rollback, no resend,
   projection absence, tamper/legacy refusal. STOP if process-local state must be
   persisted.
6. **Closed CLI integration and hostile isolation (offline only).** Expected
   files: live runtime/CLI and isolation tests. Boundary: selector only. Run full
   validation. STOP if public MCP reachability, Stage 3F expression, generic
   payload/transport, or WRITE activation appears.

Each slice requires separate implementation authorization. Only after every
offline slice passes hostile review may owner key provisioning and a separately
authorized live D/E/G run be considered.

## Consequences

Positive: all mutation and recovery security decisions remain with existing
sealed owners; the port has minimal authority; ambiguous evidence is derived
from an executor-validated read; restart and counts are auditable.

Negative: one small executor interface and several closed lab construction
interfaces must be added before the port can be implemented. The live runner
remains fail closed until then.

## Alternatives rejected

- Port calls adapter/read client and computes digests itself: rejected as a
  second owner of identity, locator and fingerprint validation.
- Expose executor private helpers or clients: rejected as boundary leakage.
- Add a generic orchestration or transport interface: rejected because it
  broadens mutation/fault authority.
- Infer reconciliation from timing or HTTP result: rejected by ADR-013.
- Persist request/projection/proxy state: rejected as stale transport authority.
- Modify executor ordering to implement D6: rejected; D6 remains blocked.

## Owner decisions required

Acceptance of this Proposed ADR, especially the narrow executor observation
interface and closed lab-only orchestration/factory boundaries, is required
before implementation. No decision about semantic identity, locator policy,
A/B rollback, reconciliation authority, or WRITE activation is reopened.

## References

- [ADR-013](ADR-013-reconciliation-authority.md)
- [ADR-014](ADR-014-sealed-executor-interface.md)
- [ADR-022](ADR-022-execution-authorization-boundary.md)
- [ADR-024](ADR-024-execution-authorization-coordination.md)
- [ADR-025](ADR-025-authorization-recovery-contract-binding.md)
- [ADR-026](ADR-026-first-write-capability-adapter.md)
- [Sealed executor](../tier1/specs/sealed_executor.md)
- [Capability adapter contract](../tier1/specs/capability_adapter_contract.md)
- [Reconciliation authority](../tier1/specs/reconciliation_authority.md)
- [Recovery Contract specification](../RECOVERY_CONTRACT_SPEC.md)
