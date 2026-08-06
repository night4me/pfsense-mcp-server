# Tier 1 Recovery Contract roadmap

Status: planning only  
Current production state: 41 READ tools, 0 WRITE tools  
Activation authorized by this document: none

## Objective

Tier 1 may introduce the first narrowly scoped mutating capability only after
the Recovery Contract becomes an authoritative, target-bound, transition-safe,
crash-resolved control. This roadmap describes the engineering and acceptance
sequence; it does not select a capability, add an endpoint, register a tool, or
authorize a live mutation.

The first capability must be named and approved separately after milestones 1
through 6 are accepted.

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
intent_digest         digest of canonical mutation intent, not raw payload
snapshot_digest       integrity digest of protected pre-state
created_at / expires_at
status / state_version
```

The store, not an MCP-supplied contract object, is authoritative. Callers pass
only `contract_id` plus the matching mutation request. The implementation loads
the contract, verifies every binding, and performs a compare-and-transition.

Public cryptographic digests may be audited; raw snapshot/payload values may
not. Digest construction requires deterministic canonical serialization and a
documented domain separator to prevent cross-purpose reuse.

## State machine

The current `OPEN`, `COMMITTED`, `ROLLED_BACK`, and `EXPIRED` states are not
sufficient to describe crashes around an external side effect. Proposed states:

```text
PREPARED
    → EXECUTING
        → COMMITTED
        → EXECUTION_FAILED
        → OUTCOME_UNKNOWN
COMMITTED
    → ROLLING_BACK
        → ROLLED_BACK
        → ROLLBACK_FAILED
        → OUTCOME_UNKNOWN
PREPARED → EXPIRED
```

Every transition is compare-and-set against `state_version`. Terminal states
cannot reopen. Expiry applies only before execution begins. `OUTCOME_UNKNOWN`
requires operator reconciliation and cannot be retried blindly.

## Milestone 0 — capability and threat-model selection

### Deliverables

- Name one candidate capability and exact pfSense endpoint/method.
- Document target identity and smallest reversible mutation.
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

- Extend contract identity with method, canonical target, intent digest,
  snapshot digest, and state version.
- Replace free-form contract objects at execution boundaries with contract IDs.
- Define canonical serialization/digest rules and size limits.
- Bind rollback plans to the same capability/endpoint/target identity.

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
- MCP callers cannot supply authoritative contract state.
- Digests reveal no source values in logs/errors.

## Milestone 2 — legal transitions and concurrency

### Work

- Implement the explicit state machine and compare-and-set transitions.
- Reject illegal, duplicate, stale-version, expired, and concurrent operations.
- Define clock source and injectable time for deterministic expiry tests.
- Add operation IDs/idempotency keys where supported by the upstream API.

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
- Secrets/snapshots never enter reports, logs, exceptions, fixtures, or Git.

## Milestone 4 — payload transmission and HTTP outcomes

### Work

- Implement explicit JSON/body transmission in the write transport interface.
- Bound payload size and validate capability-specific request models.
- Define accepted status codes and response shape for the selected endpoint.
- Reject redirects and unexpected content/status.
- Mark `COMMITTED` only after HTTP success plus required read-back validation.
- Move to `OUTCOME_UNKNOWN` when transport outcome cannot be determined.

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
  and read-back mismatch never become `COMMITTED`.
- Payload/request headers never appear in logs or errors.

## Milestone 5 — capability-specific snapshot and rollback

### Work

- Capture pre-state through one existing verified READ method.
- Define a typed, target-bound rollback plan.
- Validate rollback HTTP outcome and read-back equivalence.
- Define behavior when external changes occur between snapshot and mutation or
  between mutation and rollback.

### Estimated files

- selected READ client/model files only if existing output is insufficient
- new capability-specific write model/client module
- `src/pfsense_mcp/rollback.py`
- `src/pfsense_mcp/pfsense_write_client.py`
- capability-specific unit/integration tests

### Acceptance criteria

- Snapshot target equals mutation target by canonical identity.
- Rollback restores accepted semantic state, not merely an HTTP success code.
- Drift/conflict is detected and reported as a safe refusal or operator-
  reconciliation state.

## Milestone 6 — audit, authorization, and MCP surface design

### Work

- Define caller/operator authorization appropriate to the local stdio trust
  model and selected profile.
- Require a prepare/dry-run/confirm sequence without accepting raw contract
  objects from MCP.
- Audit event identity, contract ID, capability, endpoint symbol, target digest,
  transition, duration, and sanitized outcome only.
- Add rate/concurrency bounds and confirmation expiry.

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
| Double execution | Atomic compare-and-set plus operation/idempotency identity |
| False commit | Exact status/shape policy and semantic read-back before `COMMITTED` |
| Timeout after side effect | `OUTCOME_UNKNOWN` plus reconciliation, never blind retry |
| Process crash | Durable-before-mutate transitions and restart reconciliation |
| Rollback drift | Conflict detection and operator escalation |
| Snapshot disclosure | Protected store, value-free audit, secure retention/deletion |
| Overbroad upstream privilege | Capability-specific credential/role and post-test revocation |
| Accidental profile exposure | Explicit manifest tests and auditor-profile zero-WRITE assertion |

## Definition of done

Tier 1 is not done when a POST succeeds. It is done only when one approved
capability can be prepared, bound, executed, observed, rolled back, audited,
restarted/reconciled, and safely refused under every tested invalid state—while
all existing READ behavior and credential non-disclosure remain intact.
