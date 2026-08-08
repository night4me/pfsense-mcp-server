# Tier 1 — Sealed executor (complete design, not implemented)

Status: implementation-ready specification; implementation not authorized.
Activation gate: Milestone 6/7 in [TIER1_ROADMAP.md](../../TIER1_ROADMAP.md);
requires [ADR-014](../../adr/ADR-014-sealed-executor-interface.md).
Related: all other `docs/tier1/specs/*.md` — the executor is the one
component that composes every other subsystem into an actual mutation
path, so this is the longest and most load-bearing spec in this set.

This document specifies the executor completely enough to implement
without further architectural decisions. **It must not be implemented as
part of this design phase** — the deliverable here is the design, reviewed
and frozen, not code.

## Purpose

There is currently no code anywhere in this repository that can send a
non-GET request based on a Recovery Contract. `WriteApiClient`
(Tier 0, `src/pfsense_mcp/write_api_client.py`) is the only chokepoint
capable of a non-GET call, and it is never constructed by production, has
an empty allow-list, and is not connected to `pfsense_mcp.tier1` in any
way. The sealed executor is the **one** future component authorized to
bridge Tier 1's authorization/state machinery to that chokepoint. Its
entire purpose is to make it structurally difficult for a correctly-
reviewed capability adapter to accidentally or maliciously perform an
unauthorized, unverified, or duplicate mutation — by owning every
security-relevant decision itself and giving the adapter no path around
it.

## Security goals

- G1: A capability adapter cannot cause a network call except through
  exactly one executor-owned send, gated by policy, contract state, and
  target re-verification that the adapter does not control.
- G2: A capability adapter cannot choose an HTTP method, path, or "raw"
  payload dict — only a typed request object the executor's policy layer
  has already matched against the allow-listed
  `(capability, endpoint_symbol, http_method)` tuple.
- G3: A capability adapter cannot claim verification — only the executor,
  after an authoritative read-back it performs itself, transitions a
  contract to `VERIFIED`.
- G4: A capability adapter cannot perform more than one mutating
  operation per `execute()` call — no adapter-driven loops, no bulk
  operations, structurally.
- G5: Every execution attempt — success, failure, or ambiguous — produces
  exactly the audit trail `store.py` already knows how to write,
  attributable to one `contract_id`, with no adapter-controlled bypass of
  audit writing.

## Invariants

- I1: `MutationExecutor` is the only class in `pfsense_mcp.tier1` (once
  this spec is implemented) that holds a reference to a `WriteApiClient`-
  shaped sender. No `CapabilityAdapter` implementation may hold, import,
  or construct one — enforced by extending `tests/tier1/test_isolation.py`
  to a new `tier1/adapters/` package (see `adapter_restrictions.md`).
- I2: The executor performs exactly the eight steps in
  `RECOVERY_CONTRACT_SPEC.md`'s "Execution algorithm" section, in that
  order, with no step skippable by adapter behavior.
- I3: The executor never accepts a caller-supplied `RecoveryContract`
  object — only a `contract_id` string, loaded authoritatively from the
  store, matching the existing "store, not an MCP-supplied contract
  object, is authoritative" principle already stated in
  `TIER1_ROADMAP.md`.
- I4: The executor performs the post-acquisition authoritative re-read
  (natural identity + fingerprint match) using the **existing**,
  already-accepted `PfSenseClient` GET path — the executor does not gain
  a second way to read pfSense.
- I5: Exactly one non-GET network call happens per successful `execute()`
  invocation, and zero on any refusal path — this must be true even under
  adapter misbehavior, not just adapter cooperation (see Forbidden adapter
  behavior).
- I6: The executor's rollback path (`rollback()`) has the same shape as
  `execute()` — one send, authoritative re-read, no adapter-controlled
  send count — and requires the same policy/contract-state checks,
  scoped to `VERIFIED -> ROLLING_BACK`.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Enforcement point |
|---|---|---|---|
| Executor vs. capability adapter | `MutationExecutor` (owns transport, policy, state, audit) | `CapabilityAdapter` implementation (pure projections only) | Adapter Protocol has no transport-capable method (see Adapter responsibilities); AST isolation test |
| Executor vs. MCP tool layer | `MutationExecutor.execute(contract_id, ...)` | MCP caller / agent-constructed arguments | `contract_id`-only interface (I3); typed intent input validated against the contract's `intent_digest` before any send |
| Executor vs. `WriteApiClient` | Executor's one internal client reference | Any other code that might try to reach `WriteApiClient` | `WriteApiClient` remains the sole non-GET chokepoint (Tier 0 invariant, unchanged); executor is the only Tier 1 caller once wired |

## State ownership

- `src/pfsense_mcp/tier1/executor.py` (new module) owns `MutationExecutor`
  and the `CapabilityAdapter` Protocol (the Protocol definition lives here
  because it is defined by what the executor requires, not by what any
  one adapter wants to provide — see `capability_adapter_contract.md` for
  the adapter-facing documentation of the same Protocol).
- The executor owns, by composition (constructor injection, not global
  state):
  - one `SqliteRecoveryContractStore`
  - one `WriteApiClient`-shaped sender (Tier 0's existing type, reused)
  - one `PfSenseClient` (existing, GET-only, reused for re-reads)
  - one `MutationPolicy` (existing `policy.py`, still built from a
    non-empty rule set only once a capability is activated)
  - one `AntiRollbackAnchor` (per `whole_store_anti_rollback.md`)
  - the encryption key and HMAC key (per `key_lifecycle.md`) — passed
    through to the store and to `crypto.py` calls the executor makes when
    it needs to decrypt a snapshot/intent for building a request
- The executor does **not** own confirmation/reconciliation verifiers
  directly — those are owned by the store (`store.confirm()`,
  `store.resolve_reconciliation()`), consistent with the existing
  `SqliteRecoveryContractStore.__init__(confirmation_verifier=...)`
  pattern.
- A `CapabilityAdapter` implementation owns **nothing stateful** — it is
  effectively a namespace of pure functions plus, at most, static
  configuration (e.g., the exact endpoint symbol it targets).

## Interfaces

```python
# src/pfsense_mcp/tier1/executor.py (new; not created yet)


class CapabilityAdapter(Protocol):
    """See capability_adapter_contract.md for the full contract this
    Protocol must satisfy. Summarized here for executor-flow context."""

    endpoint_symbol: str
    http_method: str
    capability: Capability

    def natural_identity(self, raw_target: object) -> CanonicalValue: ...
    def fingerprint(self, raw_target: object) -> CanonicalValue: ...
    def build_request(self, intent: object) -> TypedWriteRequest: ...
    def parse_response(self, raw_response: object) -> TypedWriteOutcome: ...
    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool: ...
    def build_rollback_request(self, pre: object) -> TypedWriteRequest: ...
    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool: ...


class MutationExecutor:
    def __init__(
        self,
        *,
        store: SqliteRecoveryContractStore,
        write_client: WriteApiClient,
        read_client: PfSenseClient,
        policy: MutationPolicy,
        anti_rollback_anchor: AntiRollbackAnchor,
        encryption_key: bytes,
    ) -> None: ...

    def execute(self, contract_id: str, *, adapter: CapabilityAdapter, intent: object) -> ExecutionResult:
        """The only method that can cause a mutating network call.
        See "Verification flow" below for the exact step sequence."""

    def rollback(self, contract_id: str, *, adapter: CapabilityAdapter) -> RollbackResult:
        """See "Rollback flow" below."""
```

`TypedWriteRequest`/`TypedWriteOutcome` are capability-specific Pydantic
(or equivalent) models defined by each adapter's own module, never a
generic `dict[str, Any]` — see `capability_adapter_contract.md`.

## Object ownership and dependency direction

```text
Application (production, future — only after activation)
    |
    v  constructs, at startup, only if the capability is activated
MutationExecutor
    |-- owns --> SqliteRecoveryContractStore
    |-- owns --> WriteApiClient          (Tier 0, existing, reused)
    |-- owns --> PfSenseClient           (existing, GET-only, reused)
    |-- owns --> MutationPolicy          (existing policy.py)
    |-- owns --> AntiRollbackAnchor
    |-- uses (per call) --> CapabilityAdapter   (stateless, swappable)
    |-- uses (per call) --> crypto.{encrypt,decrypt}_artifact

CapabilityAdapter
    (no outward edges to transport, store, or executor internals —
     pure function namespace only)
```

Dependency direction is strictly one-way: `MutationExecutor` depends on
`CapabilityAdapter` (via the Protocol), never the reverse. An adapter
module must not import `executor.py`, `store.py`, `write_api_client.py`,
or `transport/*` — see `adapter_restrictions.md` for the enforced list.

## Lifecycle

1. **Construction** (process/application startup, only once a capability
   is activated per Milestone 9): `Application`-equivalent code
   constructs one `MutationExecutor`, exactly as it constructs one
   `PfSenseClient` today. The executor is long-lived for the process
   lifetime, matching how `SqliteRecoveryContractStore` is already
   designed to be held across many operations.
2. **Per-call**: each MCP tool invocation that reaches a WRITE capability
   calls exactly one of `execute()`/`rollback()` on the single shared
   executor instance, passing a `contract_id` and the specific adapter
   instance for that capability (adapters are stateless and can be
   module-level singletons).
3. **Shutdown**: the executor holds no resources beyond what its
   composed objects already manage (`store`'s SQLite connection is opened
   per-operation already, per the existing `_connect()` pattern — the
   executor does not change this); shutdown is a no-op beyond what
   `Application.shutdown()` already does for the transport.
4. **Restart**: on process restart, `store.reconcile_interrupted()` (and,
   once `whole_store_anti_rollback.md` is implemented, the anchor check)
   run before the executor accepts any new `execute()`/`rollback()` call
   — the executor's constructor is the natural place to trigger this, so
   a newly-constructed executor never serves a call against an
   unreconciled store.

## Authority boundaries

- The executor is the **only** component authorized to hold a
  `WriteApiClient` reference once Tier 1 activates. This does not change
  Tier 0's existing invariant that `WriteApiClient` is never constructed
  by production — it changes *who* is allowed to construct it once a
  capability is separately activated (the executor, at the same
  activation-gated construction point, never earlier).
- The executor is the only component authorized to transition a contract
  to `EXECUTING`, `VERIFIED`, or (on the rollback side) `ROLLING_BACK`/
  `ROLLED_BACK` via the ordinary automatic-transition paths in
  `store.transition()`. It never calls
  `store.confirm()` or `store.resolve_reconciliation()` itself — those
  remain separately authorized entry points reachable only through the
  confirmation/reconciliation workflows, keeping "an agent asked for
  execution" and "an owner approved it" as distinct authorities that the
  executor cannot merge.
- A `CapabilityAdapter` has **no** authority beyond pure computation. It
  cannot authorize anything; it can only compute projections the executor
  chooses to trust for exactly one call.

## Adapter responsibilities

An adapter implementation (one per approved capability, e.g. a future
`tier1/adapters/firewall_alias_description.py`) is responsible only for:

1. Defining `natural_identity()`/`fingerprint()` as pure functions over a
   raw READ response (the shape `PfSenseClient` already returns) — no I/O.
2. Defining `build_request()` to produce a fully-typed, capability-
   specific request model from a typed intent object — never passing
   through an arbitrary dict, never accepting fields outside the approved
   projection (e.g., for the alias candidate: only `descr`).
3. Defining `parse_response()` to produce a typed outcome from the raw
   HTTP response body the executor hands it — the adapter does not fetch
   this itself.
4. Defining `is_semantically_verified()`/`is_rollback_verified()` as pure
   comparison functions over two already-fetched snapshots (`pre`/`post`)
   — never issuing a read itself.
5. Naming its own `endpoint_symbol`/`http_method`/`capability` as static
   attributes, matched against `WriteEndpoints`/policy by the executor,
   not self-asserted as authorization.

## Executor responsibilities

The executor performs every I/O operation and every security-relevant
decision:

1. Load the authoritative contract by ID (`store.load()`).
2. Require `PREPARED`, confirmed, unexpired, expected `state_version`
   (existing store semantics).
3. `policy.authorize(capability=adapter.capability,
   endpoint_symbol=adapter.endpoint_symbol, http_method=adapter.
   http_method)` — refuses before any further step if not allow-listed.
4. Recompute target/intent bindings from the typed `intent` argument using
   the adapter's pure functions, and call
   `contract.verify_bindings(...)` (existing) to confirm they match the
   contract exactly.
5. Consult the anti-rollback anchor (`whole_store_anti_rollback.md`)
   before allowing the `PREPARED -> EXECUTING` transition.
6. Atomically acquire `EXECUTING` via `store.transition()` (existing CAS
   semantics; this also acquires the target reservation).
7. Perform the authoritative re-read via `PfSenseClient` (existing GET
   path), require exactly one natural-identity match, compare the
   adapter's `fingerprint()` output to `contract.target_fingerprint` —
   refuse (transition to `FAILED`, zero sends) on any mismatch.
8. Decrypt the protected intent/snapshot via `crypto.decrypt_artifact()`
   using the executor's held key — the adapter never sees ciphertext or
   the key.
9. Build the request via `adapter.build_request(intent)`, send **exactly
   one** call through `WriteApiClient` to the exact allow-listed
   `(endpoint_symbol, http_method)` — the executor, not the adapter,
   invokes the client.
10. Classify the outcome via the existing `faults.classify_fault()` using
    `MutationBoundary`/`EffectKnowledge` derived from what actually
    happened (timeout, response received, connection reset, etc.) — the
    executor determines the boundary/knowledge pair; the adapter only
    tells it, via `parse_response()`, whether a *received* response looks
    like a semantic success, not whether the network step itself
    succeeded.
11. On any received response, re-read authoritatively and call
    `adapter.is_semantically_verified(pre, post, intent)` — only a `True`
    here, combined with a successfully classified `EffectKnowledge.
    VERIFIED_SUCCESS`, drives the transition to `VERIFIED`.
12. Write the audit event via the store's existing `_insert_audit` path
    (already wired into every `transition()`/`_replace()` call — no
    separate step needed, but the executor must ensure it always reaches
    a `store.transition()` call on every path, including refusals that
    have already reserved the target, so nothing is left un-audited).

## Forbidden adapter behavior

Enforced by the Protocol shape plus the AST isolation test extension in
`adapter_restrictions.md` — not by convention:

- An adapter must not import `httpx`, `pfsense_mcp.transport`,
  `pfsense_mcp.write_api_client`, `pfsense_mcp.rest_api_client`, or
  `pfsense_mcp.tier1.executor` (the last one prevents an adapter from
  reaching back into the executor to call its internals directly).
- An adapter must not define or call anything named `send`, `request`,
  `post`, `put`, `patch`, `delete`, or `get` as an HTTP-shaped operation
  (same forbidden-call-name discipline as `test_isolation.py` already
  applies to `tier1/*.py`, extended to `tier1/adapters/*.py`).
- An adapter must not accept a `dict[str, Any]` as its `build_request()`
  return type — the return type must be a concrete Pydantic/dataclass
  model with a closed field set, so an adapter cannot smuggle an
  unapproved field through as "just more dict keys."
- An adapter must not perform a loop over multiple targets inside any
  Protocol method — every method signature takes one target/one intent,
  structurally preventing bulk operations (G4).
- An adapter must not claim verification (there is no
  `mark_verified()`-shaped method on the Protocol at all — only
  comparison functions that the executor interprets).

## Verification flow

```text
execute(contract_id, adapter, intent):
  contract = store.load(contract_id)
  require contract.state == PREPARED, confirmed, not expired
  policy.authorize(adapter.capability, adapter.endpoint_symbol, adapter.http_method)
  target_identity = adapter.natural_identity(intent.raw_target_hint)
  target_fingerprint = adapter.fingerprint(intent.raw_target_hint)
  contract.verify_bindings(capability=..., endpoint_symbol=..., http_method=...,
                            target_identity=target_identity,
                            target_precondition=target_fingerprint,
                            normalized_intent=intent)
  anti_rollback_anchor.before_executing_transition(...)
  executing = store.transition(contract_id, PREPARED -> EXECUTING)   # atomic acquire
  pre = read_client.<capability-specific GET>(natural_identity)
  require exactly one match; require pre.fingerprint == executing.target_fingerprint
  plaintext_intent = crypto.decrypt_artifact(key, executing.protected_intent, ...)
  request = adapter.build_request(plaintext_intent)
  outcome = write_client.send(executing.endpoint_symbol, executing.http_method, request)  # the one send
  classify boundary/knowledge from what actually happened during send()
  if knowledge == AMBIGUOUS: store.transition(... -> RECONCILIATION); return
  post = read_client.<capability-specific GET>(natural_identity)
  if adapter.is_semantically_verified(pre, post, plaintext_intent) and knowledge == VERIFIED_SUCCESS:
      store.transition(... -> VERIFIED)
  elif knowledge in {PROVEN_NONE, VERIFIED_FAILURE}:
      store.transition(... -> FAILED)
  else:
      store.transition(... -> RECONCILIATION)
```

This is a direct, concrete realization of `RECOVERY_CONTRACT_SPEC.md`'s
existing "Execution algorithm" pseudocode — this spec adds the object
boundaries (who calls what) that the pseudocode left implicit.

## Rollback flow

```text
rollback(contract_id, adapter):
  contract = store.load(contract_id)
  require contract.state == VERIFIED
  rolling_back = store.transition(contract_id, VERIFIED -> ROLLING_BACK)  # re-acquires target reservation; may raise ContractConflictError if the target was claimed by unrelated work in the interim (see whole_store_anti_rollback.md / state-machine ADR for the accepted decision on this window)
  pre = read_client.<capability-specific GET>(natural_identity)
  require exactly one match; detect unrelated changes via adapter.fingerprint(pre) vs. contract.target_fingerprint at VERIFIED time — conflict is a refusal (ROLLBACK_FAILED), never a forced overwrite
  plaintext_snapshot = crypto.decrypt_artifact(key, contract.protected_snapshot, ...)
  rollback_request = adapter.build_rollback_request(plaintext_snapshot)
  outcome = write_client.send(...)   # the one rollback send
  classify boundary/knowledge (MutationBoundary.DURING_ROLLBACK)
  post = read_client.<capability-specific GET>(natural_identity)
  if adapter.is_rollback_verified(plaintext_snapshot, post) and knowledge == VERIFIED_SUCCESS:
      store.transition(... -> ROLLED_BACK)
  else:
      store.transition(... -> ROLLBACK_FAILED)  # or RECONCILIATION if ambiguous
```

## Audit flow

The executor does not write audit events directly — every state
transition it drives goes through `store.transition()`/`_replace()`,
which already writes an HMAC-chained audit row atomically with the state
change (existing behavior, unchanged). The executor's only audit-related
responsibility is to **guarantee it always reaches a transition call**,
including on refusal paths after a reservation has been acquired (step 7
of the verification flow refusing must still call
`store.transition(... -> FAILED)`, not just raise an exception and leave
the contract stuck in `EXECUTING` with no further audit trail explaining
why).

## Non-goals

- This spec does not implement generic "plugin" loading, dynamic adapter
  discovery, or a registry beyond a simple, explicit, reviewed mapping
  from `Capability` to one `CapabilityAdapter` instance, wired by hand at
  `Application` construction time (mirroring how `ToolRegistry` already
  dispatches on explicit `if Capability.X in capabilities` checks, not
  reflection).
- This spec does not implement concurrent multi-executor operation —
  exactly one `MutationExecutor` instance per process, matching the
  single-process, single-writer deployment model already assumed
  throughout `store.py`.
- This spec does not implement batching, queuing, or asynchronous
  execution — `execute()`/`rollback()` are synchronous, single-operation
  calls, matching the local-stdio, single-caller trust model in
  `THREAT_MODEL.md`.

## Required tests

- Full `execute()` happy path against `MockTransport` with a synthetic
  test-only adapter (never a real capability adapter in these tests,
  mirroring `test_write_integration_dry_run.py`'s existing convention of
  using a synthetic `MutationPlan`/`RollbackPlan` pair).
- Policy refusal: adapter/endpoint/method combination not in
  `MutationPolicy` → refused before any send (assert zero calls on the
  mock transport).
- Binding mismatch: `intent` that produces a different target/fingerprint
  than the contract → refused before any send.
- Anchor refusal: anti-rollback anchor unavailable/rollback-detected →
  refused before `EXECUTING` acquisition.
- Fingerprint drift: authoritative re-read after acquisition shows a
  different fingerprint than expected → `FAILED`, zero sends past that
  point.
- Ambiguous outcome (simulated timeout/reset during send) →
  `RECONCILIATION`, never a second send, never `VERIFIED`.
- Full `rollback()` happy path, conflict path (target claimed by other
  work), and ambiguous path.
- Forbidden-behavior tests: a deliberately misbehaving test-only adapter
  that tries to import forbidden modules or call forbidden names is
  caught by the AST isolation test, not merely by runtime behavior.
- Audit-completeness test: every refusal path after reservation
  acquisition still results in a queryable, chained audit event — no
  silent dead-end state.

## Activation requirements

- [ ] `ADR-014` accepted.
- [ ] `protected_artifact_encryption.md`, `key_lifecycle.md`,
      `whole_store_anti_rollback.md`, `confirmation_authority.md`,
      `reconciliation_authority.md` all implemented (the executor
      composes all of them).
- [ ] `executor.py` implemented and tested per "Required tests".
- [ ] `capability_adapter_contract.md` and `adapter_restrictions.md`
      accepted (the executor's Protocol is defined jointly with those
      documents — do not let `executor.py`'s Protocol drift from what
      those specs promise adapter authors).
- [ ] `executor.py` remains unimported by `Application`/`factory.py`/
      `ToolRegistry` until Milestone 9's explicit activation decision —
      verified by the same AST isolation test family used throughout
      Tier 1.

## Implementation checklist

- [ ] Create `src/pfsense_mcp/tier1/executor.py` with `MutationExecutor`
      and `CapabilityAdapter`.
- [ ] Implement `execute()` per the Verification flow exactly.
- [ ] Implement `rollback()` per the Rollback flow exactly.
- [ ] Wire construction-time `store.reconcile_interrupted()` +
      anchor-check into the executor's `__init__` (or an explicit
      `startup()` method called once before first use).
- [ ] Do not implement any concrete `CapabilityAdapter` in this module —
      that is Milestone-9-gated, separate work per
      `capability_adapter_contract.md`.

## Review checklist

- [ ] Confirm the executor is the only place `WriteApiClient.execute()`/
      `.dry_run()` is called anywhere in `pfsense_mcp.tier1`.
- [ ] Confirm every early-return/refusal path after target-reservation
      acquisition ends in a `store.transition()` call (audit
      completeness).
- [ ] Confirm `CapabilityAdapter` Protocol methods are all synchronous,
      pure (no `self.` state beyond static config), and individually
      unit-testable without a store or transport fixture.
- [ ] Confirm the executor never constructs a `WriteApiClient` itself
      inline — it must be injected, so tests can supply a
      `MockTransport`-backed one, matching every other Tier 0/Tier 1
      testing convention in this codebase.

## Security checklist

- [ ] Confirm G4 (no adapter-driven loops) by inspecting every Protocol
      method signature takes a single target/intent, not a collection.
- [ ] Confirm G2 (no raw dict payload) by inspecting `build_request()`'s
      return type is a concrete model in every adapter, enforced by mypy
      strict mode plus a runtime `isinstance` check in the executor
      before sending.
- [ ] Confirm the executor's decrypted plaintext (intent/snapshot) is
      never passed to anything outside the single `execute()`/
      `rollback()` call frame — no caching, no attribute storage on
      `self`.

## Test checklist

- [ ] Happy-path execute/rollback tests.
- [ ] Policy, binding, anchor, fingerprint-drift refusal tests.
- [ ] Ambiguous-outcome (`RECONCILIATION`) tests for both execute and
      rollback.
- [ ] Forbidden-adapter-behavior AST tests.
- [ ] Audit-completeness test across every refusal path.
- [ ] Concurrency test: two `execute()` calls for the same target cannot
      both acquire `EXECUTING` (relies on existing store CAS, but must be
      exercised through the executor's public interface, not just
      `store.py` directly).
