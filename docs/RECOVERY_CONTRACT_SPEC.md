# Recovery Contract specification

Status: inert v0.3.0 framework; no mutation endpoint, tool, capability, or
production construction is authorized.

This is the normative contract/fault specification. The architectural layering
and remaining activation blockers are in
[TIER1_ARCHITECTURE.md](TIER1_ARCHITECTURE.md).

## Authoritative fields

| Field | Type | Source | Mutable | Sensitive | Digest-bound |
|---|---|---|---:|---:|---:|
| `contract_id` | opaque identifier | contract service | no | no | context |
| `operation_id` | opaque identifier | contract service | no | no | yes |
| `idempotency_key` | SHA-256 | canonical bindings | no | no | yes |
| `capability` | `*_WRITE` enum | accepted build policy | no | no | yes |
| `endpoint_symbol` | exact symbol | endpoint policy | no | no | yes |
| `http_method` | POST/PUT/PATCH/DELETE | endpoint policy | no | no | yes |
| protected target identity | ciphertext | authoritative READ | no | yes | yes |
| `target_identity_digest` | SHA-256 | canonical natural identity | no | no | yes |
| locator hint | optional protected upstream ID | authoritative READ | refreshable | yes | no |
| `target_fingerprint` | SHA-256 | capability target projection | no | no | yes |
| `verified_target_fingerprint` | optional SHA-256 | authoritative post-forward READ | once, with VERIFIED | no | HMAC record |
| protected normalized intent | ciphertext | typed caller request | no | yes | yes |
| `intent_digest` | SHA-256 | capability/endpoint/method/intent | no | no | yes |
| protected snapshot | ciphertext | authoritative READ | no | yes | yes |
| `snapshot_digest` | SHA-256 | snapshot projection | no | no | yes |
| `rollback_plan_version` | identifier | capability implementation | no | no | yes |
| `created_at` / `expires_at` | aware UTC instants | trusted clock | no | no | yes |
| confirmation digest/time | SHA-256 + UTC | owner confirmation authority | once | no | yes |
| `state` / `state_version` | enum + integer | authoritative store | yes | no | event-bound |

The caller supplies contract ID and matching typed request—not an authoritative
contract object. The service loads the record by ID and validates all bindings.

## Canonicalization and digests

- UTF-8 JSON, NFC Unicode, sorted object keys, compact separators, explicit
  null, stable array order.
- Floats are rejected unless a future typed capability defines an exact decimal
  representation.
- Non-string object keys, unsupported objects, and normalization collisions are
  rejected.
- Every digest uses `pfSense-MCP/Tier1/v1`, a purpose name, and exact contextual
  components framed by unsigned four-byte lengths. Length framing prevents
  delimiter injection and context-boundary ambiguity.
- Canonical inputs are bounded to 32 nested levels, 10,000 total nodes, 4,096
  members per collection, 64 KiB per string, and 1 MiB encoded form. Integers
  are signed 64-bit; booleans are not integers. Invalid Unicode scalars fail.
- Target identity, target fingerprint, intent, snapshot, confirmation, and
  idempotency use separate domains.

## Target contract

Each capability defines one natural identity and one fingerprint projection.
Preparation and execution require exactly one matching target. Numeric IDs are
transient locator hints. Immediately after PREPARED -> EXECUTING commits, the
target is re-read by natural identity and its refreshed ID and fingerprint must
match. Missing, duplicate, swapped, or drifted targets refuse before send.

`target_fingerprint` always remains the complete original pre-forward
precondition. After a successful mutation, the executor derives
`verified_target_fingerprint` from the authoritative post-forward READ and
persists it atomically with `EXECUTING -> VERIFIED`. Rollback compares its fresh
pre-rollback READ to that verified post-forward fingerprint, not to the
original fingerprint. This permits an authorized mutation to change a
fingerprinted field while still refusing any later unrelated change. The
protected snapshot and original fingerprint remain the recovery target.

## Confirmation contract

The owner confirmation authority authenticates an actor and binds authority,
algorithm, nonce, contract ID, operation ID, target digest and fingerprint,
intent digest, issue time, and expiry. The store accepts confirmation only
through a configured verifier; absence, refusal, or verifier failure is closed.
Raw proof bytes are not persisted. Confirmation is accepted once while PREPARED
and unexpired. Prompt text or an agent boolean is not owner authentication.

## State machine

| From | To | Meaning | Authority |
|---|---|---|---|
| PREPARING | PREPARED | protected snapshot/bindings persisted | automatic |
| PREPARING | FAILED / EXPIRED | preparation refused or expired | automatic |
| PREPARED | EXECUTING | confirmed atomic acquisition + target reservation | automatic |
| PREPARED | FAILED / EXPIRED | proven refusal or expiry before acquisition | automatic |
| EXECUTING | VERIFIED | exact response plus semantic read-back | automatic |
| EXECUTING | FAILED | no effect or failure is proven | automatic |
| EXECUTING | RECONCILIATION | outcome is not provable | automatic escalation |
| VERIFIED | ROLLING_BACK | rollback acquires same target | automatic after request |
| ROLLING_BACK | ROLLED_BACK | restoration read-back verified | automatic |
| ROLLING_BACK | ROLLBACK_FAILED | failure/conflict proven | automatic escalation |
| ROLLING_BACK | RECONCILIATION | rollback outcome ambiguous | automatic escalation |
| RECONCILIATION | VERIFIED / FAILED / ROLLING_BACK / ROLLED_BACK / ROLLBACK_FAILED | recorded operator conclusion | manual only |

Every other transition is illegal. FAILED, ROLLED_BACK, ROLLBACK_FAILED, and
EXPIRED do not reopen. State/version compare-and-set, idempotency uniqueness,
and canonical-target reservation are atomic with value-free transition audit.
The generic store refuses all manual-only edges; a separately reviewed resolver
must authenticate evidence and record the conclusion before using one.

## Persistence and integrity

- Persistent records contain protected artifacts, never plaintext target,
  intent, payload, snapshot, credential, or response.
- HMAC binds the complete canonical record to one store ID. The key is supplied
  externally, is at least 256 bits, and is never stored in the database.
- SQLite uses durable transactions and owner-only directory/file permissions.
- Duplicated operation/idempotency identities and conflicting target
  reservations fail closed.
- HMAC and denormalized index columns are cross-checked on every load/scan.
- Startup verifies exact column types/nullability, primary and unique keys, and
  cascading foreign keys; matching column names alone are insufficient.
- Every state event has an HMAC and contiguous state/version chain. This detects
  row-level deletion, insertion, modification, and reordering, but not rollback
  of the entire database to an older internally consistent copy.
- Startup scans all authenticated records; EXECUTING and ROLLING_BACK move to
  RECONCILIATION without resend.
- Whole-database rollback is not locally detectable; production activation
  requires an external monotonic anti-rollback anchor or equivalent evidence.
- Encryption/key rotation, retention, backup, secure deletion, and quarantine
  policy remain owner-approved activation prerequisites.

## Execution algorithm

```text
execute(contract_id, request):
  contract = authoritative_store.load_and_authenticate(contract_id)
  require PREPARED, confirmed, unexpired, expected state_version
  require exact policy(capability, endpoint, method)
  recompute target and intent bindings from typed request
  atomically reserve target and transition PREPARED -> EXECUTING
  authoritative_read_by_natural_identity()
  require exactly one target, refreshed locator, matching fingerprint
  require protected snapshot/rollback/config-history policy valid
  send exactly one bounded typed request; never retry
  require exact accepted status and response shape
  authoritative_read_after_write()
  if semantic intent verified:
      atomically seal authoritative post-forward fingerprint and transition EXECUTING -> VERIFIED
  elif no effect/failure proven: EXECUTING -> FAILED
  else: EXECUTING -> RECONCILIATION
```

No generic execute tool is permitted. Every request/response rule is
capability-specific.

A reconciliation authority declaring `CONFIRMED_APPLIED` must sign the exact
verified post-forward fingerprint. Other reconciliation outcomes must not
carry it. This prevents an ambiguous-send resolution from creating a VERIFIED
contract whose rollback precondition was never authenticated.

## Fault decisions

| Scenario | State | Automatic retry |
|---|---|---:|
| Refused before durable acquisition | remains PREPARED or FAILED | no |
| Crash before store commit | prior authenticated state | no |
| Crash after EXECUTING commit, before send | RECONCILIATION on restart unless no-send is independently proven | no |
| Partial transmission/reset/timeout after send | RECONCILIATION | never |
| Response lost after pfSense commit | RECONCILIATION | never |
| Verification interrupted or malformed | RECONCILIATION | never |
| Missing/duplicate/drifted target before send | FAILED, zero send | no |
| Concurrent duplicate invocation | CAS refusal, zero send | no |
| Rollback conflict | ROLLBACK_FAILED | never force |
| Partial/ambiguous rollback | RECONCILIATION | never |
| Corrupt/foreign/replayed record | refuse/quarantine | no |

Manual reconciliation re-reads by natural identity, compares snapshot, intent,
and current semantic state, records the operator conclusion, and never infers
success from HTTP status or numeric ID alone.

## Audit contract

Permitted: event/contract/operation IDs, capability, endpoint symbol, method,
target and intent digests, state/version, timing, outcome, sanitized failure and
exception class. Prohibited: arguments, raw identity, payload, intent, snapshot,
response, credentials, exception messages, rollback content, and result values.

## Required activation tests

- exhaustive legal/illegal transition matrix;
- canonicalization stability/domain separation/fuzz inputs;
- stale version, duplicate invocation/contract/operation/idempotency;
- concurrent same-target acquisition across store connections/processes;
- corruption of payload, MAC, indexes, metadata, store identity, and key;
- crash before/after every commit and send boundary;
- restart reconciliation with no blind resend;
- missing, duplicate, shifted-ID and fingerprint-drifted targets;
- timeout/lost response/partial send and malformed response;
- rollback conflicts and partial compound compensation;
- value-free schema/log/error/fixture/report scans;
- READ contract and WRITE-isolation regression.

Passing framework tests does not authorize a capability. Activation still
requires the separate gates in [TIER1_ROADMAP.md](TIER1_ROADMAP.md).
