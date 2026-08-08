# Tier 1 safety architecture

Status: inert framework; no production mutation is reachable or authorized.

## Isolation and dependency direction

The active application graph remains:

```text
Application -> ToolRegistry -> READ tools -> PfSenseClient
            -> RestApiClient -> GET-only Transport
```

The new `pfsense_mcp.tier1` package is a disconnected safety-domain library.
`Application`, `factory`, `server`, `ToolRegistry`, `RestApiClient`, and
`PfSenseClient` do not import it. It contains no MCP tool, endpoint path,
credential loading, transport call, payload sender, or executor. Its production
policy constant contains zero rules.

## Recovery Contract

An authoritative record binds:

- random contract and operation identifiers;
- globally replay-resistant idempotency digest;
- exact WRITE capability, endpoint symbol, and uppercase HTTP method;
- protected canonical natural target identity and its public digest;
- target precondition fingerprint;
- protected normalized intent and deterministic intent digest;
- protected read-before-write snapshot and snapshot digest;
- rollback-plan version;
- creation, expiry, confirmation, state, and monotonic state version.

`ProtectedArtifact` is opaque ciphertext metadata. The framework deliberately
does not include a convenience plaintext codec. A future accepted encryption
provider must encrypt before persistence and keep its key outside the database.
HMAC authenticates the complete stored record and binds it to one store ID; it
does not replace encryption.

## Canonical target identity

Each capability must define one unique natural identity projection. Unicode is
normalized to NFC and serialized as sorted compact UTF-8 JSON. Floats and
unsupported dynamic values are rejected. Numeric upstream IDs are locator hints
only and are not authoritative.

Preparation requires exactly one natural-identity match. After atomic execution
acquisition, the future capability adapter must immediately re-read by natural
identity, require exactly one match, refresh any locator hint, and compare the
stored target fingerprint. Missing, duplicate, moved, or drifted targets fail
without sending.

## Confirmation and intent

Owner approval and the agent invocation are separate facts:

1. The owner confirmation authority binds its identity and algorithm, a nonce,
   contract/operation IDs, target digest/fingerprint, intent digest, issuance,
   and expiry into verified evidence and a confirmation digest.
2. The execution request supplies only contract ID plus typed intent/target
   inputs. Authoritative state is loaded from the store.
3. Capability, endpoint, method, target digest, and intent digest must match.

Confirmation is single-use and valid only while PREPARED and unexpired. The
store has no permissive fallback: without a configured verifier it refuses.
A future production provider must authenticate the owner outside prompt text;
an LLM assertion is not confirmation.

## State and atomic persistence

The closed state set is:

```text
PREPARING -> PREPARED -> EXECUTING -> VERIFIED
     |          |            |          |
     +-> FAILED +-> EXPIRED   +-> FAILED +-> ROLLING_BACK
                               \-> RECONCILIATION       |
                                      ^                 +-> ROLLED_BACK
                                      |                 +-> ROLLBACK_FAILED
                                      +-----------------+
```

Only declared transitions are legal. The generic store cannot exit
RECONCILIATION; a future authenticated resolution service must implement the
declared manual-only conclusions. SQLite transactions use `BEGIN IMMEDIATE`, compare state and
version, update the HMAC-bound record, reserve/release the target, and append a
value-free state event in one commit. Duplicate contract, operation, or
idempotency identities fail. A unique target reservation prevents concurrent
execution/rollback for the same canonical target.

On restart, every HMAC/index-verified EXECUTING or ROLLING_BACK record moves to
RECONCILIATION. It is never resent automatically. Whole-database rollback cannot
be detected solely from the database; production activation therefore requires
an owner-approved external anti-rollback anchor or equivalent durable monotonic
evidence.

## Mutation outcome contract

No mutation executor exists yet. A future capability-specific executor must:

1. acquire PREPARED -> EXECUTING durably;
2. re-read and verify target identity/fingerprint/config-history preconditions;
3. transmit exactly one typed, bounded request to one allow-listed path/method;
4. accept only capability-specific status and response shape;
5. perform authoritative semantic read-after-write;
6. enter VERIFIED only after read-back;
7. enter FAILED only when no effect or failure is proven;
8. enter RECONCILIATION for partial transmission, timeout after send, lost
   response, interrupted verification, or any ambiguous outcome;
9. never automatically retry a mutation.

## Rollback

Rollback is capability-specific and target-bound. VERIFIED -> ROLLING_BACK must
reserve the same target, re-read it, detect unrelated changes, and apply only a
deterministic inverse. Read-back must prove semantic restoration. Conflict or
partial compensation cannot force a global restore; it enters ROLLBACK_FAILED
or RECONCILIATION. Appliance configuration history may be captured as a
protected artifact, but capture failure blocks mutation and a global revision
must never overwrite unrelated changes automatically.

`VERIFIED` is not a reservation state: the canonical target reservation is
released the instant a contract reaches `VERIFIED`, so an unrelated contract
may acquire that same target before any rollback decision is made. This is a
deliberate, accepted design, not an oversight — fingerprint-drift detection on
the `VERIFIED -> ROLLING_BACK` re-acquisition is the safety net for this
window, not an extended reservation. Two consequences follow directly: (1) if
the target is unclaimed, `ROLLING_BACK` re-reserves it and proceeds normally;
(2) if another contract has since claimed the same target, re-acquisition
fails closed with a conflict refusal — never a corrupted or forced rollback —
and the original contract's rollback must wait or escalate to reconciliation.
A production capability with tight rollback-window requirements may need its
own target-scoped cooldown (see the rate/blast-radius policy) to reduce how
often this conflict is hit in practice; the underlying safety property does
not depend on that cooldown existing.

## Policy and audit

Policy is an immutable set of exact `(Capability, endpoint symbol, method)`
rules. No prefix, wildcard, tool-name inference, or profile implication is
accepted. The checked-in production policy is empty.

Audit records may contain identifiers, capability, endpoint symbol, method,
digests, states, sanitized failure/exception class, timestamps, and outcome.
They never contain raw target identity, payload, intent, snapshot, response,
credentials, exception messages, or tool arguments/results. State-transition
metadata is committed atomically with contract state and is HMAC-authenticated
as a contiguous state/version chain.

## Future adapter containment

A capability adapter must never receive a general REST client or raw transport.
One future central executor must own policy authorization, durable acquisition,
the authoritative re-read, one exact send, outcome classification, verification,
and state/audit persistence. An adapter may provide only typed projections and
pure comparisons for one approved rule. It cannot choose a path or method at
runtime, send directly, widen the field projection, perform bulk operations, or
claim verification. Until that sealed boundary exists and is reviewed, adapter
implementation remains blocked.

## Remaining activation blockers

- capability-specific protected-artifact codec and key lifecycle;
- external anti-rollback/backup policy and secure retention/deletion;
- exact typed mutation and response models;
- exact endpoint/method/status/read-back semantics from disposable-lab OpenAPI;
- owner-authenticated confirmation service;
- target-scoped monotonic rate policy;
- capability-specific rollback and reconciliation runbook;
- production wiring, tool registration, profile activation, and live acceptance,
  each requiring explicit approval.

The decision options and candidate-specific abuse review are maintained in
[TIER1_ACTIVATION_DECISIONS.md](TIER1_ACTIVATION_DECISIONS.md).
