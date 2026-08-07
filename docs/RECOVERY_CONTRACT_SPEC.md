# Recovery Contract specification (future Tier 1)

Status: design only; no mutation is authorized or activated.

This specification refines the [Tier 1 roadmap](TIER1_ROADMAP.md) into a
reviewable contract and fault model. It is intentionally independent of a
storage backend or first WRITE capability. Tier 0 types do not yet satisfy it.

## Contract fields

| Field | Type | Trust source | Mutable | Sensitive | Digest-bound | Validation |
|---|---|---|---:|---:|---:|---|
| `contract_id` | opaque random identifier | contract service | no | no | domain context | every lookup |
| `capability` | enum | accepted build registry | no | no | yes | prepare and execute |
| `endpoint_symbol` | enum/reference | WRITE endpoint registry | no | no | yes | prepare and execute |
| `http_method` | enum | endpoint registry | no | no | yes | prepare and execute |
| `target_identity` | capability-specific canonical value | authoritative READ | no | yes | yes | prepare, pre-send, rollback |
| `locator_hint` | optional upstream ID | authoritative READ | yes | yes | no | never authoritative |
| `target_fingerprint` | SHA-256 digest | canonical target projection | no | no | yes | pre-send and rollback |
| `normalized_intent` | typed canonical object | validated caller request | no | yes | yes | prepare and execute |
| `intent_digest` | SHA-256 digest | canonical intent/payload | no | no | yes | execute |
| `snapshot_digest` | SHA-256 digest | protected pre-state | no | no | yes | execute and rollback |
| `rollback_plan_version` | version identifier | capability implementation | no | no | yes | prepare and rollback |
| `created_at` / `expires_at` | UTC instants | trusted clock | no | no | yes | prepare and acquisition |
| `confirmed_at` | UTC instant or null | confirmation service | once | no | yes | execution acquisition |
| `status` | state enum | authoritative store | yes | no | event record | every transition |
| `state_version` | monotonic integer | authoritative store | yes | no | event record | compare-and-set |

Raw target identity, intent, payload, snapshot, credentials, and upstream
responses must not enter MCP errors, audit logs, or public reports. The
authoritative store may hold encrypted protected values needed for execution
and rollback; audit records use identifiers and digests only.

## Canonicalization

All digests use UTF-8 encoded deterministic JSON with sorted object keys, no
insignificant whitespace, explicit null handling, and capability-defined array
ordering. Floating-point values are prohibited unless a capability defines an
exact decimal representation. Unicode is normalized to NFC before uniqueness
comparison and serialization. Domain separators prevent cross-purpose reuse:

```text
pfSense-MCP/v1/target-fingerprint\0<capability>\0<canonical-target>
pfSense-MCP/v1/intent\0<capability>\0<endpoint>\0<method>\0<canonical-intent>
pfSense-MCP/v1/snapshot\0<capability>\0<canonical-snapshot>
```

Capability and endpoint are stable enum/symbol names from the accepted build.
Method is the uppercase endpoint-registry method. Target identity is a
capability-specific natural key or tuple; numeric pfSense IDs are locator hints
only. Payload and snapshot canonicalization are defined by versioned typed
models and reject unknown fields before hashing.

## Verification algorithm

```text
execute(contract_id, request):
  contract = authoritative_store.load(contract_id)
  require contract exists and state == PREPARED
  require trusted_now < expires_at and confirmed_at is present
  validate request capability, endpoint, method and normalized intent
  require request intent digest == stored intent digest
  atomically compare-and-set PREPARED -> EXECUTING using state_version
  reserve capability/target concurrency and rate budget atomically
  target_set = authoritative_read_by_natural_identity(target_identity)
  require exactly one target
  require refreshed locator matches any locator hint
  require fingerprint(target_set[0]) == stored target_fingerprint
  require protected snapshot digest and rollback plan remain valid
  require optional config-history capture succeeds when policy requires it
  durably record execution acquisition before transmission
  send exactly one approved mutation; never retry an ambiguous send
  validate exact status, response shape and authoritative read-after-write
  transition to COMMITTED only after verification
  otherwise transition to EXECUTION_FAILED or OUTCOME_UNKNOWN by fault class
```

Rollback repeats authoritative identity lookup, fingerprint/conflict checks,
atomic acquisition, exact endpoint verification, and read-back verification.
It must never restore a global appliance revision when unrelated changes could
be overwritten.

## State-transition contract

| From | Event | To | Automation allowed |
|---|---|---|---|
| `PREPARING` | durable preparation succeeds | `PREPARED` | yes |
| `PREPARING` | validation/capture fails | `PREPARATION_FAILED` | yes |
| `PREPARING` / `PREPARED` | unacquired contract expires | `EXPIRED` | yes |
| `PREPARED` | confirmed atomic acquisition | `EXECUTING` | yes |
| `EXECUTING` | exact success plus read-back | `COMMITTED` | yes |
| `EXECUTING` | proven no side effect | `EXECUTION_FAILED` | yes |
| `EXECUTING` | outcome cannot be proven | `OUTCOME_UNKNOWN` | reconciliation only |
| `COMMITTED` | rollback atomically acquired | `ROLLING_BACK` | yes |
| `ROLLING_BACK` | restoration verified | `ROLLED_BACK` | yes |
| `ROLLING_BACK` | proven rollback failure | `ROLLBACK_FAILED` | policy/manual |
| `ROLLING_BACK` | rollback outcome ambiguous | `OUTCOME_UNKNOWN` | reconciliation only |

Every unlisted transition is illegal. Terminal states do not reopen. A stale
`state_version`, duplicate invocation, or conflicting target reservation is a
refusal with no transport call.

## Fault model and reconciliation

| Fault | Required state/result | Automatic retry |
|---|---|---:|
| Rejected before transmission | `EXECUTION_FAILED` | no; new confirmation required |
| Partial transmission / connection reset | `OUTCOME_UNKNOWN` | never |
| Response lost after possible commit | `OUTCOME_UNKNOWN` | never |
| Crash before durable `EXECUTING` | remains/refuses `PREPARED` by atomic record | no blind execution |
| Crash after durable `EXECUTING` | startup reconciliation | never blind resend |
| Target drift before send | safe refusal, zero mutation | no |
| Missing or duplicate natural identity | safe refusal, zero mutation | no |
| Numeric locator now identifies another target | safe refusal, zero mutation | no |
| Concurrent operator change after mutation | conflict-aware reconciliation | no global restore |
| Rollback conflict | `ROLLBACK_FAILED` or reconciliation state | never force |
| Rollback response lost | `OUTCOME_UNKNOWN` | never |
| Config-history capture unavailable | preparation/execution blocked | no |
| Store corruption or foreign record | fail closed and quarantine | no |
| Duplicate MCP invocation | compare-and-set refusal | no |
| Compound compensation partly fails | `OUTCOME_UNKNOWN` | never |

Manual reconciliation must re-read by canonical identity, compare the intended,
snapshot, and current semantic states, record an operator decision, and never
infer success solely from an HTTP response or numeric ID.

## First-capability selection rubric

No candidate is authorized by this document. Owner review should score each
candidate class from 0 (unsafe/unknown) to 3 (strong) for stable natural
identity, narrow blast radius, deterministic rollback, reliable READ-back,
OpenAPI clarity, conflict detection, and config-history isolation. Lockout,
credential mutation, service interruption, global configuration impact, or an
ambiguous rollback is a veto rather than a score deduction. The first
capability requires an ADR with evidence and explicit approval.

## Required test model before implementation

- Table-driven coverage of every legal and illegal state/event pair.
- Two contenders cannot acquire the same contract or canonical target.
- Property tests for canonicalization stability and domain separation.
- Fault injection before and after every durable transition and network send.
- Restart reconciliation vectors for `EXECUTING`, `ROLLING_BACK`, and corrupt
  records.
- Missing, duplicate, drifted, and locator-swapped target tests with zero
  mutation calls.
- Ambiguous outcome and compound compensation failures with no automatic retry.
- Value-free audit, error, fixture, and report assertions.

These vectors remain documentation until a separately approved Tier 1 design
chooses storage, cryptography, and a first capability. They must not be wired
to production bootstrap in the current READ release.
