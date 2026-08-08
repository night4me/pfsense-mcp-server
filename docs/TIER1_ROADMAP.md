# Tier 1 Recovery Contract roadmap

Status: inert framework implemented; capability activation blocked
Current production state: 41 READ tools, 0 WRITE tools  
Activation authorized by this document: none

The implementation-independent field, canonicalization, transition, fault,
and reconciliation contract is specified in
[RECOVERY_CONTRACT_SPEC.md](RECOVERY_CONTRACT_SPEC.md). Neither document
authorizes a production capability, endpoint, executor, tool, or mutation.
The isolated `pfsense_mcp.tier1` package implements and tests only the domain
controls described here and is not imported by production bootstrap.

The concrete, implementation-ready specification for the milestones below —
subsystem interfaces, sealed executor design, capability adapter contract,
and the exact phase sequence with entry/exit gates — is
[`docs/tier1/IMPLEMENTATION_ROADMAP.md`](tier1/IMPLEMENTATION_ROADMAP.md)
and [`docs/tier1/specs/`](tier1/specs/). This document's milestones remain
the acceptance-criteria source of truth; the blueprint sequences how to
reach them.

## Objective

Tier 1 may introduce the first narrowly scoped mutating capability only after
the Recovery Contract becomes an authoritative, target-bound, transition-safe,
crash-resolved control. This roadmap describes the engineering and acceptance
sequence; it does not select a capability, add an endpoint, register a tool, or
authorize a live mutation.

The first capability must be named and approved separately after milestones 1
through 6 are accepted.

## Current implementation boundary

| Area | Inert framework status | Activation work still required |
|---|---|---|
| Contract and canonicalization | Implemented and unit-tested | Capability-specific typed target, intent, snapshot, and size policy |
| State and concurrency | Closed transitions, CAS, idempotency identities, and target reservations implemented | Cross-process load evidence, target-scoped rate policy, executor boundary |
| Persistence | Owner-only SQLite, durable transactions, record HMAC, restart reconciliation implemented | Encryption/key provider, whole-store anti-rollback anchor, retention/backup/deletion policy |
| Policy and audit | Exact immutable empty policy and value-free event model implemented | Owner-authenticated confirmation, durable audit export/integrity decision |
| Mutation outcome and rollback | Specification and fault classification only | All capability-specific transport, read-back, rollback, and reconciliation work |
| MCP and production wiring | Intentionally absent | Separate owner approval after lab acceptance |

The implementation is in `src/pfsense_mcp/tier1/` with offline tests under
`tests/tier1/`. Legacy Tier 0 modules are retained for compatibility and are
not silently upgraded into an executable path.

## Non-negotiable invariants

- `RestApiClient` remains permanently GET-only.
- `WriteApiClient` remains the only non-GET transport chokepoint.
- A WRITE endpoint requires an explicit `WriteEndpoints` entry and independent
  verification.
- A WRITE capability must be explicitly added to the build and selected
  profile; naming convention or reflection never activates it.
- Dry-run performs no mutating request.
- Execution requires a fresh authoritative Recovery Contract loaded by ID.
- Contract, endpoint, capability, target, method, and payload intent must match.
- Target identity is a capability-specific canonical natural identity; a
  numeric pfSense ID is only a transient locator hint.
- Execution atomically acquires its state, immediately re-reads the target
  authoritatively, and refuses drift before mutation.
- No payload, snapshot, credential, response body, or exception message enters
  logs or MCP errors.
- HTTP success and persisted contract state must be validated before reporting
  commitment.
- Rollback behavior and process-crash semantics must be accepted before any
  production mutation.

## Proposed contract identity

A contract needs immutable bindings beyond the current Tier 0 fields:

```text
contract_id
capability
endpoint_symbol
http_method
target_identity       canonical resource identifier, not a display label
target_fingerprint    digest of immutable identity and accepted pre-state fields
normalized_intent     capability-specific canonical operation, stored protected
intent_digest         digest of normalized intent and exact payload, not raw payload
snapshot_digest       integrity digest of protected pre-state
rollback_plan_version immutable capability-specific rollback semantics
created_at / expires_at
confirmed_at          explicit operator confirmation bound to this contract
status / state_version
```

The store, not an MCP-supplied contract object, is authoritative. Callers pass
only `contract_id` plus the matching mutation request. The implementation loads
the contract, verifies every binding, and performs a compare-and-transition.

Public cryptographic digests may be audited; raw snapshot/payload values may
not. Digest construction requires deterministic canonical serialization and a
documented domain separator to prevent cross-purpose reuse.

Target identity must be defined per capability from a unique natural key or
tuple. Numeric array indices may be retained only as transient locator hints.
Preparation fails on zero or multiple natural-identity matches. The immutable
fingerprint binds the prepared target to mutation and rollback without placing
raw identity or snapshot values in audit data.

## State machine

The legacy Tier 0 `OPEN`, `COMMITTED`, `ROLLED_BACK`, and `EXPIRED` states are
not sufficient to describe crashes around an external side effect. The inert
Tier 1 framework uses:

```text
PREPARING
    → PREPARED
PREPARED
    → EXECUTING
        → VERIFIED
        → FAILED
        → RECONCILIATION
VERIFIED
    → ROLLING_BACK
        → ROLLED_BACK
        → ROLLBACK_FAILED
        → RECONCILIATION
PREPARED → EXPIRED
```

Every transition is compare-and-set against `state_version`. Terminal states
cannot reopen. `PREPARING` cannot authorize execution. Expiry applies only
before execution begins and transitions `PREPARING` or `PREPARED` to `EXPIRED`.
`RECONCILIATION` requires an operator decision and cannot be retried blindly.
Only an explicit manual-reconciliation action may leave it. The complete
event/state table rejects every transition not declared in the specification.

## Milestone 0 — capability and threat-model selection

The roadmap does not choose the first capability. Owner approval must select it
using objective criteria: smallest blast radius, a reliable verified READ
dependency, stable natural target identity, deterministic rollback, no
network-lockout risk, no credential mutation, no service interruption, and
independently verified OpenAPI semantics. Candidate classes may be compared in
the decision record, but no specific capability is implied or preferred here.

### Deliverables

- Name one candidate capability and exact pfSense endpoint/method.
- Document target identity and smallest reversible mutation.
- Prove natural-identity uniqueness rules and document how unstable numeric IDs
  are refreshed without becoming authoritative.
- Confirm upstream API semantics, idempotency, response codes, concurrency
  behavior, and read-back endpoint.
- Define least-privilege upstream authorization and explicit operator role.
- Decide whether the mutation is safely reversible; “best effort” is not
  sufficient for the first capability.

### Estimated files

- New design under `docs/`.
- No source or allow-list change.

### Acceptance criteria

- Separate written authorization names the capability and test appliance.
- No ambiguity exists about target identity, pre-state capture, apply/read-back,
  and rollback operations.

## Milestone 1 — authoritative contract model

### Work

- Extend contract identity with method, canonical target, normalized intent,
  payload/intent digest, target fingerprint, snapshot digest, rollback-plan
  version, expiry, explicit confirmation, and state version.
- Replace free-form contract objects at execution boundaries with contract IDs.
- Define canonical serialization/digest rules and size limits.
- Bind rollback plans to the same capability/endpoint/target identity.
- Store numeric IDs, if needed, only as non-authoritative locator hints.

### Estimated files

- `src/pfsense_mcp/recovery.py`
- `src/pfsense_mcp/write_types.py`
- `src/pfsense_mcp/pfsense_write_client.py`
- `tests/test_recovery_contract.py`
- `tests/test_pfsense_write_client.py`
- security-model/spec documentation

### Acceptance criteria

- Swapping contract IDs, targets, endpoints, capabilities, methods, or payload
  intent always fails before transport.
- Missing targets, duplicate natural identities, target-fingerprint mismatch,
  or locator-ID mismatch always fail before transport.
- MCP callers cannot supply authoritative contract state.
- Digests reveal no source values in logs/errors.

## Milestone 2 — legal transitions and concurrency

### Work

- Implement the explicit state machine and compare-and-set transitions.
- Reject illegal, duplicate, stale-version, expired, and concurrent operations.
- Define clock source and injectable time for deterministic expiry tests.
- Use monotonic time for in-process deadlines and atomic store state for
  execution, rollback, rate, and concurrency decisions.
- Add operation IDs/idempotency keys where supported by the upstream API.
- Define capability/target-scoped rate and in-flight concurrency policy. Rate
  limiting is damage containment, never authorization or confirmation.

### Estimated files

- `src/pfsense_mcp/recovery.py`
- new private contract-state module if separation is warranted
- `src/pfsense_mcp/rollback.py`
- `tests/test_recovery_contract.py`
- `tests/test_rollback.py`
- property/state-machine tests

### Acceptance criteria

- Every state/event pair has an explicit allow/refuse result.
- Concurrent execution attempts cannot both acquire `EXECUTING`.
- Repeated rollback cannot produce a second mutation.
- Expiry cannot race an acquired execution into an incorrect state.
- Simultaneous operations for a conflicting canonical target cannot both
  acquire execution, regardless of process or worker concurrency.
- Dry-run, refusal, execution failure, and `RECONCILIATION` have explicit rate
  accounting and reservation-release behavior.

## Milestone 3 — persistence and crash contract

### Decision required

Choose one of two explicit models:

1. **Crash-safe persistent store:** encrypted/protected snapshot persistence,
   atomic durable transitions, restart recovery, retention, and secure deletion.
2. **No-crash-recovery model:** mutation is prohibited unless an external
   operator-owned recovery artifact/process guarantees restoration. This is
   unlikely to be acceptable for the first production capability.

In-memory-only state must not be presented as crash-safe recovery.

### Work for a persistent store

- Select a local transactional backend and filesystem protection contract.
- Define single-writer ownership or transactional multi-process semantics;
  filesystem locking alone is not assumed sufficient.
- Encrypt sensitive snapshots at rest with a key outside the database.
- Use atomic state transitions and durable-before-mutation ordering.
- Reconcile `EXECUTING`/`ROLLING_BACK` contracts after restart through safe
  read-back, never blind replay.
- Define TTL, retention, backup, secure deletion, and corruption handling.

### Estimated files

- `src/pfsense_mcp/recovery.py`
- new `src/pfsense_mcp/recovery_store.py`
- new migration/schema resources if needed
- `src/pfsense_mcp/config.py`
- `src/pfsense_mcp/application.py` (construction only after acceptance)
- unit, restart, corruption, permissions, and crash-injection tests
- deployment/security documentation

### Acceptance criteria

- Killing the process at every persistence/mutation boundary yields a defined,
  test-proven restart state.
- Store/snapshot permissions fail closed.
- Corrupt, missing, replayed, or foreign store records cannot authorize a
  mutation.
- Every `RECONCILIATION` path has a documented manual reconciliation action;
  no uncertain operation is retried automatically.
- Secrets/snapshots never enter reports, logs, exceptions, fixtures, or Git.

## Milestone 4 — payload transmission and HTTP outcomes

### Work

- Implement explicit JSON/body transmission in the write transport interface.
- Bound payload size and validate capability-specific request models.
- Define the exact accepted HTTP status and response shape for the selected
  endpoint; generic 2xx handling is prohibited.
- Reject redirects and unexpected content/status.
- Mark `VERIFIED` only after HTTP success plus required read-back validation.
- Move to `RECONCILIATION` when transport outcome cannot be determined.
- Immediately after atomically acquiring `EXECUTING`, authoritatively re-read
  the target and compare natural identity, fingerprint, and transient locator
  before sending the mutation.

### Estimated files

- `src/pfsense_mcp/transport/base.py`
- `src/pfsense_mcp/transport/http.py`
- `src/pfsense_mcp/transport/mock.py`
- `src/pfsense_mcp/write_api_client.py`
- selected capability request/response models
- `tests/test_transport_http.py`
- `tests/test_write_api_client.py`
- negative response/read-back tests

### Acceptance criteria

- Tests prove the exact approved payload reaches only the approved endpoint.
- Non-2xx, unexpected 2xx, malformed response, redirect, timeout, disconnect,
  and read-back mismatch never become `VERIFIED`.
- Missing targets, duplicate identity matches, external drift, or numeric-ID
  mismatch produce a safe refusal and zero mutating transport calls.
- Payload/request headers never appear in logs or errors.

## Milestone 5 — capability-specific snapshot and rollback

### Work

- Capture pre-state through one existing verified READ method.
- Define a typed, target-bound rollback plan.
- Bind rollback to the same canonical identity and target fingerprint used for
  preparation and mutation.
- Validate rollback HTTP outcome and read-back equivalence.
- Define behavior when external changes occur between snapshot and mutation or
  between mutation and rollback.
- Evaluate pfSense config-history metadata as an optional protected recovery
  artifact. Capture failure must block mutation; it may never be swallowed as
  best effort.
- Analyze whether restoring a config-history revision would overwrite unrelated
  changes made after capture. Refuse unsafe global restoration or require
  explicit manual reconciliation.

### Estimated files

- selected READ client/model files only if existing output is insufficient
- new capability-specific write model/client module
- `src/pfsense_mcp/rollback.py`
- `src/pfsense_mcp/pfsense_write_client.py`
- capability-specific unit/integration tests

### Acceptance criteria

- Snapshot target equals mutation target by canonical identity.
- Rollback refuses missing/duplicate targets, locator mismatch, fingerprint
  conflict, and unrelated-change risk.
- Rollback restores accepted semantic state, not merely an HTTP success code.
- Drift/conflict is detected and reported as a safe refusal or operator-
  reconciliation state.

## Milestone 6 — audit, authorization, and MCP surface design

### Work

- Define caller/operator authorization appropriate to the local stdio trust
  model and selected profile.
- Require a prepare/dry-run/confirm sequence without accepting raw contract
  objects from MCP.
- Bind explicit confirmation to the authoritative contract ID, normalized
  intent digest, target fingerprint, and unexpired state.
- Audit event identity, contract ID, capability, endpoint symbol, target digest,
  transition, duration, and sanitized outcome only.
- Enforce the accepted capability/target-scoped rate and concurrency policy and
  confirmation expiry with monotonic time and atomic state.

### Estimated files

- `src/pfsense_mcp/write_audit.py`
- `src/pfsense_mcp/tools/registry.py`
- new `src/pfsense_mcp/tools/write/<capability>.py`
- `src/pfsense_mcp/profiles.py` and `capabilities.py` only at final activation
- audit/registry/schema/security tests
- README, security model, API reference

### Acceptance criteria

- No WRITE tool registers under `auditor`.
- Tool schemas contain no secret/snapshot/payload leakage and no caller-
  controlled authoritative state.
- Every transition and failure produces one value-free audit record.
- BaseException and process termination semantics remain defined.

## Milestone 7 — offline acceptance

### Test strategy

- Model/unit tests for canonicalization, binding, expiry, and transitions.
- Table/property tests covering the complete state machine.
- MockTransport tests for exact method/path/body and zero-call refusals.
- Fault injection before/after every durable transition and transport boundary.
- Restart tests against a temporary store.
- Concurrency tests with simultaneous execute/rollback attempts.
- Target tests for shifted numeric IDs, duplicate natural identity, missing
  target, fingerprint drift, and rollback conflicts.
- Config-history tests for capture failure, stale revision, unrelated changes,
  and global-restore refusal.
- Compound-operation tests where the primary step, compensating action, or both
  fail; unresolved compensation enters `RECONCILIATION` and requires manual
  reconciliation.
- Negative schema/output/log/error/fixture scans using sentinel values.
- Package/entry-point and Python-version CI matrix.
- Existing complete READ regression suite and 41-tool enumeration.

### Acceptance criteria

- All existing READ tests and security gates remain green.
- Existing 41 READ tool schemas are unchanged unless separately approved.
- Exactly the separately authorized WRITE tools register only in the approved
  profile.
- Empty-allow-list/inactive-capability checks are replaced with precise
  manifest checks, never simply deleted.
- Recovery, crash, rollback, audit, and refusal evidence is reviewed externally
  before live testing.

## Milestone 8 — private test-appliance acceptance

Requires a separate command-level approval and a disposable/non-production
test target.

### Sequence

1. Metadata-only credential/configuration preflight.
2. Confirm upstream least privilege and read-only baseline before temporarily
   granting the exact test permission.
3. Capture sanitized structural evidence without values.
4. Dry-run and verify zero mutation.
5. Prepare one contract for one target.
6. Execute one reversible mutation.
7. Read back and validate commitment.
8. Roll back and validate semantic restoration.
9. Exercise approved fault/crash cases.
10. Revoke write permission and confirm READ-only baseline.

### Acceptance criteria

- No production appliance or production credential is used.
- Every side effect and restoration is independently observed.
- No sensitive value enters terminal output, reports, fixtures, or Git.
- Operator runbook and emergency reconciliation are complete.

## Milestone 9 — activation decision

Activation is a separate release decision, not an automatic consequence of
passing tests. It requires:

- explicit approval naming capability, endpoint, profile, and release;
- accepted Recovery Contract/crash/rollback evidence;
- security review and compatibility review;
- updated public security/API/operations documentation;
- commit, tag, push, and release approval under normal project policy.

Until that decision, `WriteEndpoints` remains empty, WRITE capabilities remain
inactive, and zero WRITE tools register.

## Principal risks

| Risk | Required mitigation |
|---|---|
| Contract substitution/replay | Store-loaded ID, immutable bindings, intent digest, expiry, state version |
| Wrong target | Canonical target identity shared by snapshot, mutation, and rollback |
| Unstable numeric ID | Transient locator only; authoritative natural identity and fingerprint re-read after atomic acquisition |
| Double execution | Atomic compare-and-set plus operation/idempotency identity |
| False commit | Exact status/shape policy and semantic read-back before `VERIFIED` |
| Timeout after side effect | `RECONCILIATION`, never blind retry |
| Compound compensation failure | `RECONCILIATION`, value-free audit, and explicit manual action |
| Process crash | Durable-before-mutate transitions and restart reconciliation |
| Rollback drift | Conflict detection and operator escalation |
| Config-history over-rollback | Capture must succeed; analyze and refuse restoration that could overwrite unrelated changes |
| Runaway/concurrent mutation | Atomic capability/target concurrency plus monotonic rate policy, independent of authorization |
| Snapshot disclosure | Protected store, value-free audit, secure retention/deletion |
| Overbroad upstream privilege | Capability-specific credential/role and post-test revocation |
| Accidental profile exposure | Explicit manifest tests and auditor-profile zero-WRITE assertion |

## Definition of done

Tier 1 is not done when a POST succeeds. It is done only when one approved
capability can be prepared, bound, executed, observed, rolled back, audited,
restarted/reconciled, and safely refused under every tested invalid state—while
all existing READ behavior and credential non-disclosure remain intact.
