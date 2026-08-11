# ADR-025: Authorization-to-RecoveryContract binding

- **Status:** Proposed
- **Date:** 2026-08-11
- **Scope:** Architecture only. This ADR authorizes no schema, code, test,
  production-construction, MCP, capability, or WRITE change.

## Implementation status

**Slice B1 — prepared execution-intent model and canonical digest — implemented
(2026-08-11), under a fixed owner scope.** New inert module
`src/pfsense_mcp/tier1/prepared_execution_intent.py` defines the frozen,
explicitly versioned `PreparedExecutionIntentV1`, its sole canonical payload
function, and `compute_execution_intent_digest()`. The existing canonical
owner gained only `DigestPurpose.EXECUTION_INTENT`; no second JSON/hash path was
introduced.

The B1 semantic fields are schema version, WRITE capability, endpoint symbol,
mutating HTTP method, adapter-semantics version, resource-level natural target,
exact target precondition, full normalized mutation intent, exact rollback
snapshot, and rollback-plan version. The four canonical values are deeply
frozen after validation and exposed only as defensive copies. Adapter version
plus normalized intent owns request/post-condition interpretation, so a second
expected-post-condition description would be duplicative. Generated IDs,
lifecycle state, expiry, authorization/plan/step provenance, digests of fields,
confirmation, and appliance identity are deliberately absent.

The digest domain is the existing framed Tier 1 v1 prefix plus the new
`execution-intent` purpose and fixed `PreparedExecutionIntentV1` context. The
schema version also participates in the payload. Unsupported versions fail
closed; there is no V0/legacy inference.

B1 remains synthetic and production-unreachable. It does not implement B2's
PlanAuthorization v2 binding, B3's preparer, B4's RecoveryContract provenance,
B5's freshness composition, or B6/E3. ADR-025 remains Proposed; public MCP
remains 42 READ / 0 WRITE and WRITE remains 0/3 active.

**Slice B2 — PlanAuthorization v2 signed per-step binding — implemented
(2026-08-11), under a fixed owner scope.** `PlanAuthorizationV2` is a separate
concrete artifact with schema version 2. It replaces v1's independent
`authorized_step_ids` with one authoritative, non-empty tuple of typed
`PlanAuthorizationStepBinding(step_id, execution_intent_digest)` values.
Duplicate step IDs, malformed safe-token step IDs, and non-64-lowercase-hex
digest values fail construction. Binding order has no semantic meaning; the
signed payload sorts exact `(step_id, digest)` pairs deterministically.

V2 signs the existing plan digest, the exact binding set, authority/algorithm,
timestamps, risk class, and evidence fingerprint under the distinct
`plan-authorization-v2` purpose plus signed schema version 2. V1 remains its
unchanged concrete type/domain/schema and cannot verify as v2 (or vice versa).
Expiry remains the same exclusive `now < expires_at` check and the same pinned
Ed25519 authority mechanism is reused.

B2 validates and signs only the B1 digest's stable 64-hex output shape. It does
not import a prepared intent, prepare or recompute an execution-intent digest,
claim freshness/consumption, or create a RecoveryContract. A same-shaped digest
from another domain cannot be distinguished structurally at B2; B3/B5 must
authoritatively recompute the B1 domain and compare it. B3–B6/E3 remain
unimplemented and unauthorized. ADR-025 remains Proposed; public MCP remains
42 READ / 0 WRITE and WRITE remains 0/3 active.

## Context

ADR-022 defines `Plan → Authorize → Execute → Verify`. ADR-024 Slice E1
implemented regenerated-plan freshness, and Slice E2 implemented ordered
authorization verification through durable one-time consumption. Slice E3 was
stopped before implementation because the authorization domain and Tier 1
execution domain have no proof-carrying common binding.

`PlanAuthorization` signs an exact plan digest and a set of step IDs. The v1
plan digest describes security-posture policy and ordering. A
`RecoveryContract` instead binds the concrete Tier 1 operation that the sealed
executor may send. Neither an ID copied between the objects nor a caller's
assertion proves that these meanings correspond.

This ADR designs the smallest safe bridge. Appliance-level authorization
target identity remains a separate unresolved concern.

## Problem statement

The current objects prove two disconnected statements:

1. an authority approved a current plan and named step; and
2. confirmation approved the exact target and intent in a RecoveryContract.

They do not prove that the contract represents the approved step. A caller
could present authorization for plan A/step A and select the capability,
endpoint, method, target, or mutation body for contract B. Consuming the
authorization first limits replay but does not remove this substitution.

The exact missing relation is:

```text
signed (plan digest, step ID)
            ?
concrete (capability, endpoint, method, target, precondition,
          normalized intent, recovery inputs)
```

## Existing domains and missing binding

### PlanAuthorization

The signed v1 payload contains `schema_version`, `authorization_id`,
`plan_digest`, ordered `authorized_step_ids`, `authority_id`, `algorithm`,
`issued_at`, `expires_at`, `risk_class`, and `evidence_fingerprint`. `proof`
authenticates that payload but is not itself inside it. Signature, currentness,
scope, freshness, and one-time consumption are already separate fail-closed
gates.

### SecurityPosturePlan and PlanStep

The plan describes desired capability posture, anchor assurance, validity,
axis transitions, findings, and ordered provisioning/activation steps. Its
steps are not resource-mutation requests. The v1 digest includes each step's
ID, order, axis, mutation class, and authorization level. It intentionally
does not include the Tier 1 capability, endpoint symbol, method, target,
precondition, normalized mutation intent, snapshot, or rollback policy.

### RecoveryContract

The contract binds `capability`, `endpoint_symbol`, `http_method`, target
identity digest, target fingerprint, intent digest, snapshot digest, rollback
plan version, protected target/intent/snapshot values, lifecycle data, and
derived idempotency identity. It contains no source plan digest, step ID,
authorization ID, or signed execution-intent digest.

### ConfirmationEvidence and MutationExecutor

Confirmation evidence binds the exact contract ID, operation ID, target
identity digest, target fingerprint, intent digest, and expiry. It does not
bind plan or authorization provenance. `MutationExecutor.execute()` accepts a
contract ID, capability adapter, and intent, loads the authoritative contract,
rechecks its bindings and state, performs one mutation, verifies the
post-condition, and records sealed transitions/audit. It must remain
authorization-unaware.

## Security invariant

For a coordinator-created RecoveryContract to be accepted for execution, a
pinned authority must have signed one unique association between an exact
fresh plan digest, one exact authorized step ID, and one domain-separated
digest of the complete execution intent. The coordinator must independently
recompute that digest from one trusted, typed prepared intent, consume the
authorization, construct exactly one contract from the same prepared intent,
and prove the persisted contract carries the same execution tuple and
provenance. No caller may supply or replace a preconstructed contract or any
parallel execution-critical value after that check.

Confirmation then binds the exact contract, and the existing executor consumes
only that contract's sealed execution facts. This is a transitive binding; it
does not make the authorization appliance-specific.

## Field-by-field binding matrix

Legend: **S** signed, **P** v1 plan-digest-bound, **R** RecoveryContract-bound,
**C** confirmation-bound, **X** executor-consumed, **D** derived, **V**
persisted. An omitted marker means “no.” “Caller” means selectable at the
current API boundary. Security-critical fields are marked **SC**; a row that
is not marked SC is descriptive/policy metadata only. Each row's final column
identifies whether an unclosed substitution surface exists.

### PlanAuthorization

| Field | Existing binding/use | Caller / derived / persisted | Security and substitution assessment |
|---|---|---|---|
| `schema_version` | S, V | signer-selected under verifier policy | SC; must fail closed by version |
| `authorization_id` | S, V; consumption key | signer-generated | SC replay identity; copying it into a contract would prove only provenance |
| `plan_digest` | S, V | computed from plan, then signed | SC; authenticates v1 plan semantics, not execution tuple |
| `authorized_step_ids` | S, V | signer-selected, canonical ordering/uniqueness enforced | SC; names policy steps only |
| `authority_id` | S, V | pinned authority | SC authentication/routing, not execution intent |
| `algorithm` | S, V | verifier-supported | SC algorithm selection |
| `issued_at`, `expires_at` | S, V | signer-selected within policy | SC currentness window; neither binds contract expiry |
| `risk_class` | S, V | signer-selected | SC authorization policy, not a mutation description |
| `evidence_fingerprint` | S, V; also P through plan | derived from posture evidence | SC freshness context, not Tier 1 target or intent |
| `proof` | authenticates signed payload | authority-generated, V | SC; excluded from its own payload by design |
| proposed per-step execution binding | absent in v1 | signer approves a preparer-derived digest | SC; required v2 association |

### SecurityPosturePlan

| Field/class | Existing binding/use | Caller / derived / persisted | Security and substitution assessment |
|---|---|---|---|
| plan schema/version | P | planner-owned | SC for canonical meaning; v1 cannot imply future execution semantics |
| current discovery/evidence | summarized by P fingerprint | live discovery, planner-derived | SC freshness input; not a Tier 1 target snapshot |
| target capability posture | P | caller requests; planner validates | SC policy goal, insufficient to select mutation tuple |
| target anchor assurance | P | caller requests; planner validates | SC policy goal, insufficient to select mutation tuple |
| target validity/axis transitions | P | planner-derived | policy-level; descriptive of posture transition |
| overall status / `safe_to_proceed` | P | planner-derived | SC gate; not execution mapping |
| findings/notes | not all P | planner-derived | descriptive/audit; must not become hidden execution authority |
| ordered steps | selected fields P | planner-derived | SC scope/order, but current steps are provisioning policy actions |
| appliance target identity | absent | unavailable by privacy-default design | separate unresolved authorization portability gap |

### PlanStep

| Field | In v1 plan digest? | Can derive Tier 1 execution? | Meaning and substitution assessment |
|---|---:|---:|---|
| `step_id` | yes | no | stable policy-step name; same name does not define a resource mutation |
| `order` | yes | no | sequencing only |
| `axis` | yes | no | posture axis only |
| `action` | no | no | policy action label, not canonical Tier 1 input |
| `description` | no | no | human-readable and never authoritative |
| `mutation_class` | yes | no | broad class; many capabilities/endpoints/intents share it |
| `authorization_required` | yes | no | authorization level, not operation data |
| `implementation_available` | no | no | rollout status only |
| `reversible` | no | no | policy characterization; does not define rollback artifact |
| `security_impact` | no | no | descriptive risk text |
| `prerequisite_satisfied` | no | no | planner status |
| `blocked`, `blocked_reason` | no | no | planner status/explanation |
| `evidence` | no | no | descriptive supporting evidence, not a target precondition |

No current PlanStep field is sufficient to derive a capability, endpoint,
method, resource target, canonical body, snapshot, or rollback plan.

### RecoveryContract

| Field | Existing binding/use | Caller / derived / persisted | Security and substitution assessment |
|---|---|---|---|
| `contract_id` | R, C, X, V | construction input today; proposed coordinator-generated | SC object identity; must not be caller-substitutable |
| `operation_id` | R, C, V | construction input today; proposed coordinator-generated | SC operation/audit identity |
| `idempotency_key` | R, X, D, V | derived by existing contract machinery | SC replay guard, not authorization proof |
| `capability` | R, X, V | currently construction input | SC; unbound to plan authorization |
| `endpoint_symbol` | R, X, V | currently construction input | SC; unbound to plan authorization |
| `http_method` | R, X, V | currently construction input | SC; unbound to plan authorization |
| `target_identity_digest` | R, C, X, D, V | derived from resource identity | SC resource binding; not appliance authorization identity |
| `target_fingerprint` | R, C, X, D, V | derived from precondition | SC stale-target check |
| `intent_digest` | R, C, X, D, V | derived from normalized intent | SC mutation-body binding |
| `snapshot_digest` | R, X, D, V | derived from rollback snapshot | SC recovery binding; not confirmation-bound today |
| `rollback_plan_version` | R, X, V | construction input | SC recovery policy/version |
| protected target/intent/snapshot | R, X, V | encryption of exact prepared values | SC; randomized ciphertext is not suitable signed canonical input |
| `created_at`, `expires_at` | R, X, V | coordinator/policy-derived | SC lifecycle bounds; not operator mutation choice |
| `state`, `state_version` | R, X, V | state machine/store-owned | SC; never caller-mutated directly |
| confirmation digest/time | R, X, D, V | store confirmation transition | SC evidence/audit state |
| source plan/step/auth/digest | absent | proposed coordinator-derived | SC durable provenance; alone would not prove tuple correspondence |

### ConfirmationEvidence

| Field | Bound today | Not bound today |
|---|---|---|
| authority/algorithm/nonce/proof | authenticates one confirmation payload | plan/step/authorization provenance |
| contract and operation IDs | exact RecoveryContract identity | why that contract was authorized |
| target identity/fingerprint | exact contract target/precondition | appliance-level authorization target |
| intent digest | exact contract mutation intent | plan semantics independently |
| issued/expiry times | evidence/currentness window | authorization lifetime |

### MutationExecutor invocation

| Input/value | Origin and validation | Substitution surface |
|---|---|---|
| `contract_id` | caller today; authoritative contract loaded from store | coordinator must pass only ID returned by its own successful create |
| adapter | caller today; executor verifies adapter capability/endpoint/method against contract | future coordinator must select from a sealed registry using the bound tuple, not accept an arbitrary parallel choice |
| `intent` | caller today; normalized and compared with contract digest | future coordinator must reuse the exact prepared intent, not accept a post-consumption replacement |
| target and precondition | adapter reads; executor compares digests | protected by existing contract/executor checks |
| request and result | adapter/executor-owned | sealed executor/state machine own send, verification, recovery, and audit |

## Deterministic derivation today

It is **not possible** to derive an exact RecoveryContract execution tuple from
the current authorized plan and step without caller-supplied security-critical
choices.

Missing semantic data includes capability, endpoint symbol, method, resource
target selector/identity, expected target precondition, normalized mutation
parameters/body, rollback snapshot input, and rollback-plan version. Missing
cross-reference data includes source plan digest, step ID, authorization ID,
and an execution-intent digest. Adding only the cross-references cannot supply
or authenticate the missing semantics.

## Trust boundaries and source-of-truth ownership

The proposed design gives each fact one semantic owner:

| Fact | Authoritative owner |
|---|---|
| posture plan, policy step, ordering | security-posture planner |
| plan digest | plan-digest module |
| approval, scope, lifetime, risk | pinned signing authority / PlanAuthorization |
| capability, endpoint, method, typed mutation parameters | capability-specific execution-intent preparer selected from a sealed registry |
| target selector/identity and precondition | preparer using authoritative adapter read |
| normalized intent | existing capability adapter normalization |
| rollback snapshot and rollback-plan version | preparer plus capability recovery policy |
| execution-intent digest | canonical module's dedicated domain over prepared intent |
| source plan/step/authorization association | PlanAuthorization v2 signed per-step binding |
| IDs, timestamps, encryption, contract construction | coordinator plus existing RecoveryContract machinery |
| contract persistence and lifecycle | RecoveryContract store/state machine |
| confirmation validity | existing confirmation verifier/store |
| send, post-condition, recovery, audit | existing MutationExecutor/state machine/store |

The coordinator composes these authorities. It does not become a second
planner, canonicalizer, adapter, confirmation verifier, or state machine.

## Alternatives considered

### Alternative A — extend PlanStep with the entire execution intent

This could make the plan digest directly cover all operation facts, but it
would turn a general security-posture plan into a Tier 1 resource-mutation
schema. The current planner does not possess authoritative target snapshots or
typed mutation parameters, and some plan steps concern configuration files,
physical TPM work, or capability activation outside RecoveryContract's
resource model. Mirroring adapter and recovery semantics in PlanStep would
create two sources of truth and force broad plan/digest version churn.

**Rejected as the primary design.** A plan may display an opaque execution
binding for review, but must not duplicate the execution schema.

### Alternative B — add only an execution-intent digest to PlanStep

A digest is strong only if an authoritative component can independently
construct the preimage. Putting an unexplained digest in PlanStep would let a
caller choose both the digest and the later contract. If the preparer and
signer workflow are specified, this can work, but the digest belongs to a
separate execution-intent domain rather than the PlanStep model itself.

**Retained as part of the recommended design, but not as a bare field.** The
signed authorization associates the digest with the exact plan and step.

### Alternative C — add plan/step provenance fields to RecoveryContract

`source_plan_digest`, `source_step_id`, and `source_authorization_id` improve
auditability. They do not prove that capability, endpoint, method, target, or
intent correspond to that source. A malicious constructor can copy valid IDs
onto an unrelated contract.

**Rejected alone; retained only as durable provenance plus the verified
execution-intent digest.**

### Alternative D — sign per-step execution-intent digests directly

PlanAuthorization v2 can sign an ordered, duplicate-free association of step
ID to execution-intent digest. The plan digest remains the identity of the
fresh policy plan; the new digest identifies concrete execution. The signer
approves both without making the verifier or executor understand adapter
internals.

This creates a clear version boundary and requires the operator/signing
workflow to receive a reviewable prepared intent. It couples authorization to
the existence of an execution-intent digest, but not to RecoveryContract's
state or executor implementation.

**Accepted as the cryptographic association in the recommended design.**

### Alternative E — fixed mapping registry from current step metadata

Current `axis` and `mutation_class` values are not one-to-one with Tier 1
operations. A registry would hide unsigned policy outside the plan digest,
become vulnerable to code-version skew, and still could not derive target,
parameters, snapshot, or recovery policy.

**Rejected.** A sealed registry may select a capability-specific preparer only
after the signed execution binding exists; it may not invent the binding from
current PlanStep metadata.

### Alternative F — signed prepared-execution binding with contract provenance

Create a frozen, typed `PreparedExecutionIntentV1` before authorization. A
capability-specific preparer derives all execution-critical plaintext facts
from typed request data, authoritative target read, existing adapter
normalization, and recovery policy. The sole canonical module computes a new
domain-separated digest. PlanAuthorization v2 signs the exact
`(step_id, execution_intent_digest)` association alongside `plan_digest`.

After verifying and recomputing everything and before creating a contract, the
coordinator consumes the authorization. It constructs the contract itself
from that same immutable prepared value. The contract persists source plan,
step, authorization, and execution-intent digest as authenticated provenance.
The coordinator verifies the created contract's existing digests and tuple
against the prepared value before persistence/transition. It never accepts a
preconstructed contract.

**Recommended.** This combines D's signed association, B's compact binding,
and C's durable provenance while assigning semantic derivation to one
capability-specific preparer.

## Alternative ranking

Scores are relative: 5 is strongest/best. “F” is the recommended composite.

| Criterion | A | B alone | C alone | D alone | E | F |
|---|---:|---:|---:|---:|---:|---:|
| substitution resistance | 4 | 2 | 1 | 4 | 2 | 5 |
| cryptographic/structural completeness | 4 | 2 | 1 | 4 | 1 | 5 |
| single source of truth | 2 | 2 | 3 | 4 | 2 | 5 |
| deterministic reproducibility | 2 | 2 | 1 | 4 | 2 | 5 |
| minimal schema churn | 1 | 4 | 3 | 3 | 5 | 2 |
| minimal coupling | 1 | 4 | 4 | 3 | 2 | 4 |
| auditability | 4 | 2 | 4 | 3 | 2 | 5 |
| fail-closed behavior | 3 | 2 | 1 | 5 | 2 | 5 |
| migration clarity | 2 | 3 | 2 | 5 | 2 | 5 |
| testability | 3 | 2 | 2 | 4 | 2 | 5 |
| E1 freshness compatibility | 2 | 3 | 5 | 5 | 2 | 5 |
| E2 consumption compatibility | 4 | 3 | 3 | 5 | 3 | 5 |
| RecoveryContract/state-machine compatibility | 2 | 3 | 2 | 4 | 3 | 4 |
| executor remains authorization-unaware | 5 | 5 | 5 | 5 | 5 | 5 |

## Recommended design

### 1. PreparedExecutionIntentV1

Define one frozen internal model whose semantic fields are:

- Tier 1 capability;
- endpoint symbol;
- mutating HTTP method;
- canonical resource target identity;
- canonical expected target precondition;
- normalized mutation intent;
- canonical rollback snapshot;
- rollback-plan version.

The exact types must reuse existing canonical-value, capability, endpoint,
method, and adapter types. Randomized ciphertext, generated contract and
operation IDs, timestamps, lifecycle state, state version, confirmation, and
idempotency key are excluded: they are contract mechanics rather than choices
about what operation is authorized.

The snapshot and rollback-plan version are included because recovery behavior
is security critical. The preparer must obtain target identity, precondition,
and snapshot before signing; an implementation that cannot do this
deterministically must stop rather than ask the coordinator caller to fill the
gap.

### 2. Execution-intent digest

Add exactly one `DigestPurpose.EXECUTION_INTENT` to the existing canonical
module. Its owner is the prepared-execution binding subsystem. It hashes the
canonical plaintext model above, not encrypted artifacts and not an existing
RecoveryContract serialization.

The digest intentionally excludes plan digest and step ID. PlanAuthorization
v2 is the outer signed object that associates all three domains. This keeps
the execution digest reusable for independent recomputation and prevents a
recursive or duplicated source of truth.

### 3. PlanAuthorization v2

Add an ordered, duplicate-free `authorized_executions` collection. Each entry
contains exactly `step_id` and `execution_intent_digest`. Every executable
authorized step must have exactly one entry; no extra entry may exist. The
collection is signed with the existing plan digest and other authorization
fields.

PlanAuthorization v1 remains valid for existing non-execution verification and
historical audit, but is categorically ineligible to create a RecoveryContract.
No verifier may synthesize a digest for v1.

### 4. Durable RecoveryContract provenance

A new contract schema version persists:

- `source_plan_digest`;
- `source_step_id`;
- `source_authorization_id`;
- `source_execution_intent_digest`.

These fields must be covered by the contract's authenticated persistence/HMAC
payload and immutable after creation. They are not sufficient by themselves;
creation must also recompute the execution digest from the prepared plaintext
and verify that the contract's capability, endpoint, method, target identity
digest, target fingerprint, intent digest, snapshot digest, and rollback-plan
version all represent that same value.

Legacy RecoveryContracts may retain their existing recovery lifecycle, but
they are ineligible for coordinator-originated execution. No legacy row is
upgraded by filling provenance from an assertion.

### 5. Coordinator API shape

The eventual coordinator caller may provide only:

- the signed PlanAuthorization v2;
- the exact plan digest and step ID being requested;
- posture targets and environment needed by existing freshness;
- one immutable prepared-execution intent or an authoritative persisted
  reference to it;
- real ConfirmationEvidence after the contract exists;
- time.

The caller must not provide a RecoveryContract, contract ID for execution,
capability, endpoint, method, target, precondition, snapshot, rollback version,
or intent as parallel replaceable arguments. The coordinator selects the
adapter/preparer through a sealed registry keyed by the already-bound
capability and passes only the ID of the contract it created to confirmation
and execution. Any conflict is a uniform pre-consumption denial.

Generated IDs, timestamps, contract expiry, encryption, and idempotency are
derived internally under existing policy. Contract expiry must not outlive an
applicable authorization/confirmation policy bound; the exact policy is an
owner decision before implementation.

## Canonicalization and digest design

The canonical representation is a versioned object with fixed field names and
the existing canonical value rules: NFC UTF-8 strings, sorted object keys,
order-preserving lists, explicit booleans/integers/null, no floats, bounded
depth/size, and enum values encoded by their stable wire strings. Optional
fields must be represented according to one schema rule—prefer explicit null
when absence has semantics—and may not oscillate between omitted and null.

The domain must be distinct from PLAN, PLAN_AUTHORIZATION, INTENT, TARGET,
SNAPSHOT, CONFIRMATION, IDEMPOTENCY, and RecoveryContract persistence domains.
A suitable semantic label is:

```text
pfSense-MCP/Tier1/execution-intent/v1
```

Implementation should express this through the existing canonical module's
purpose mechanism, not a new hash helper. The exact byte prefix must be fixed
by tests before use. `execution_intent_digest` is a digest of the whole
prepared operation; the existing `intent_digest` remains the narrower digest
of mutation parameters. Target identity, precondition, snapshot, and intent
retain their existing digest domains inside RecoveryContract. No digest is
substitutable for another.

Canonical tests must cover reordered object keys, list order, Unicode
normalization, enum encoding, null/omission, malformed/oversized values,
version mismatch, and domain-confusion attempts.

## Freshness consequences

The recommended design does not change PlanDigest v1 or ask the posture
planner to generate Tier 1 mutation details. E1 continues to prove that the
authorized policy plan is fresh by deterministic rediscovery and replanning.

Execution freshness becomes an additional, separate pre-consumption check:
the capability-specific preparer must rediscover/re-read the target and
reproduce the exact prepared execution digest, or the attempt fails. The
existing `plan_authorization_is_fresh()` API remains correct for plan
freshness; it must not be renamed or weakened to imply execution-target
freshness.

If implementation instead chooses to embed execution facts in PlanStep, both
PlanDigest and deterministic replanning would require a new version and the
planner would need all authoritative Tier 1 inputs. That is not recommended.

Code-version skew is fail closed: a preparer/canonical schema version that
cannot reproduce the signed v1 execution digest cannot execute. The signing
workflow should record the preparer schema/version for operator review.

## Consumption consequences

All of the following occur before consumption:

1. existing E2 gates;
2. PlanAuthorization v2 eligibility and one-to-one step binding;
3. authoritative prepared-intent reconstruction;
4. exact execution-intent digest verification;
5. adapter/preparer selection and contract-construction feasibility checks
   that do not persist a contract.

Consumption remains one authorization permits one attempt to create a
RecoveryContract. After successful consumption, the coordinator derives IDs,
constructs and persists exactly one contract. A crash or `store.create()`
failure burns the authorization and creates no retry entitlement. Provenance
does not create a claim/commit state and does not close that accepted window.

## Confirmation consequences

No ConfirmationEvidence schema change is recommended. Existing evidence binds
the exact created contract's identity, operation, target, precondition, intent,
and expiry. Once contract creation proves and persists the signed execution
binding, confirmation transitively approves the authorized execution.

The coordinator must use real evidence and exact contract ID. Confirmation for
contract A cannot confirm B under the existing verifier/store. Snapshot and
rollback policy remain protected by the contract and executor/recovery
machinery, not independently added to confirmation in this ADR.

## Executor and state-machine consequences

`MutationExecutor` remains authorization-unaware. It receives the exact
coordinator-created contract ID, a registry-selected matching adapter, and the
same normalized intent. Its existing contract-binding, one-send,
post-condition, recovery, transition, and audit behavior remains authoritative.

The state machine remains unchanged. The coordinator must use the legal
`PREPARING → PREPARED` transition after creation and before confirmation; it
must not mutate state directly or duplicate transitions. Direct executor
invocation remains controlled by production construction/isolation review,
not by a language-level authorization check inside the executor.

## Target-identity separation

Structural plan-to-contract binding does not require appliance identity. It
does require the existing operation/resource target identity and fingerprint
because they are part of the exact execution tuple.

Even after this ADR is implemented, ordinary PlanAuthorization remains
portable across appliances if the same signed plan and prepared resource
execution digest can be reproduced there. The design therefore does not prove
“this authority approved appliance X.” It must not substitute endpoint URLs,
`netgate_id`, `pfhostid`, or identifying-metadata privacy overrides for a
future appliance identity decision.

## Caller influence analysis

| Caller-provided value | Can alter execution? | Required treatment |
|---|---:|---|
| PlanAuthorization v2 | yes | pinned signature, expiry, scope, freshness, one-time consumption |
| requested plan digest / step ID | selects approved scope | exact match to signed fields; never used to populate unrelated contract fields |
| posture targets/environment | affects plan freshness | authoritative rediscovery/replanning; caller cannot provide fresh plan/digest |
| typed mutation request used by preparer | yes | normalized and authoritatively prepared before signing; full digest recomputed |
| prepared-intent reference | yes | load immutable authoritative record; reject caller-mutated copy |
| ConfirmationEvidence | permits transition | existing exact-contract verification only |
| time | affects currentness | injected trusted clock in production; bounded deterministic clock in tests |

The API must not accept a preconstructed contract or replacement adapter,
intent, target, method, endpoint, snapshot, or rollback policy. If a prepared
value is transported by the caller, the signed digest and authoritative live
reconstruction make it an untrusted carrier, not an authority.

## Threat analysis

| Threat | Result under recommended design |
|---|---|
| plan A/step A → contract B | prevented: signed step-to-execution digest plus contract tuple verification |
| same step ID in another plan | prevented: outer authorization binds exact plan digest and mapping |
| same mutation class, different parameters | prevented: normalized parameters are in execution digest |
| same endpoint, different method | prevented: method is in execution digest and contract |
| same capability, different endpoint | prevented: both are in execution digest and contract |
| same endpoint/method, different body | prevented: normalized intent is in execution digest and existing intent digest |
| parameter reordering/Unicode ambiguity | detected by sole canonicalizer and adapter normalization |
| stale planner version | detected by existing plan freshness/version boundary |
| prepared under one code version, executed under another | fail closed unless same versioned digest is reproduced |
| contract mutation after creation | detected by immutable model, authenticated store, state version, and existing bindings |
| caller-supplied preconstructed contract | prohibited by coordinator API and isolation tests |
| replay with another contract | prevented by atomic consumption and exact signed binding |
| copied authorization/plan IDs on unrelated contract | detected: provenance alone is insufficient; execution digest/tuple must match |
| digest-domain confusion | detected by distinct purpose/domain and negative tests |
| semantically similar but byte-different plan | rejected by exact plan digest/freshness |
| concurrent coordinator calls | at most one reaches creation through existing atomic consumption |
| confirmation for A applied to B | prevented by existing evidence contract/operation bindings |
| response lost after execution | existing durable contract state is authoritative; no automatic replay |
| direct executor invocation bypass | not solved cryptographically; production isolation/construction remains the boundary |
| authorization reused on another appliance | not solved; separate appliance-identity decision |

## Versioning and migration

The recommended design requires explicit fail-closed versions:

- `PreparedExecutionIntent` schema v1 and EXECUTION_INTENT digest domain v1;
- `PlanAuthorization` schema v2 with signed per-step execution bindings;
- no PlanStep or PlanDigest version change under the recommended design;
- a RecoveryContract schema/provenance version and store schema migration
  (expected next store version, determined at implementation pre-flight);
- no ConfirmationEvidence schema change;
- no MutationExecutor authorization input.

PlanAuthorization v1 may continue to verify for its historical/read-only
purpose but must be rejected for RecoveryContract creation. Existing contracts
may continue their existing sealed recovery lifecycle; they must not be
retroactively marked coordinator-authorized. Migration may add nullable
storage columns only for legacy reading, while new coordinator contracts
require non-null v2 provenance. No transition period may infer bindings.

Rollback of partially deployed schema support must preserve fail-closed
ineligibility: older code must not execute v2 authorizations or misread new
contracts. Exact database forward/backward compatibility needs an owner-approved
migration plan before implementation.

## Rejected designs

- Trusting a human-readable PlanStep action or description.
- Inferring a contract from `axis` plus `mutation_class`.
- Copying plan/step/authorization IDs into a contract without tuple proof.
- Letting the coordinator caller supply a contract beside authorization.
- Reusing `intent_digest`, `plan_digest`, target digest, or contract HMAC as a
  generic execution digest.
- Signing randomized encrypted artifacts instead of canonical plaintext
  semantics.
- Making MutationExecutor verify PlanAuthorization.
- Treating appliance identity as equivalent to execution-intent binding.
- Allowing v1 authorization to execute by compatibility inference.

## Deferred work

- Appliance-level target identity and its privacy/lifecycle policy.
- DeprovisionAuthorization verification and destructive-target binding.
- Two-phase authorization consumption.
- Concrete capability adapter/preparer implementation. ADR-026 now specifies
  the Proposed, lab-gated firewall-alias description-only semantic unit; its
  empirical evidence and owner decisions remain prerequisites to B3b.
- Numeric authorization/contract expiry policy.
- Production construction, MCP WRITE registration, allow-list population, and
  all three WRITE activation milestones.

Public MCP remains 42 READ / 0 WRITE; WRITE remains 0/3 active.

## Proposed implementation slices

Every slice below requires separate authorization. None is started by this ADR.

### B1 — execution-intent model and canonical digest

- **Invariant:** one frozen, versioned prepared intent has one independently
  reproducible, domain-separated digest.
- **Expected files:** new internal binding model/module, existing canonical
  purpose enum, focused canonical/adversarial tests, minimum spec docs.
- **Forbidden:** coordinator, executor, state machine, MCP, production factory.
- **Versions:** PreparedExecutionIntent v1; EXECUTION_INTENT domain v1.
- **Tests:** all fields load-bearing; normalization/domain/version confusion;
  malformed, reordered, null, list, Unicode, and size cases.
- **Migration:** none; inert model only.
- **Rollback:** remove inert model before any signed artifact exists.
- **STOP:** any field cannot be singularly owned or canonically represented.

### B2 — PlanAuthorization v2 per-step binding

- **Invariant:** a signature approves one exact plan digest and a duplicate-free
  step-to-execution-digest association.
- **Expected files:** authorization model/payload/verifier and tests; ADR/spec
  status notes only.
- **Forbidden:** RecoveryContract, executor, state machine, MCP.
- **Versions:** PlanAuthorization v2; v1 explicitly execution-ineligible.
- **Tests:** missing/extra/duplicate mappings, reordered encodings, cross-plan
  same-step IDs, wrong digest/domain, downgrade attempts.
- **Migration:** no auto-upgrade or synthesized binding.
- **Rollback:** v2 remains unused/inert until later slices.
- **STOP:** v1 could reach execution or signer cannot review the prepared
  intent represented by each digest.

### B3 — authoritative capability-specific preparer

- **Invariant:** the first candidate's exact tuple is derived without
  caller-selected parallel execution facts and reproduces B1's digest.
- **Expected files:** isolated capability-specific preparer/registry and tests.
- **Forbidden:** MCP registration, WriteEndpoints population, coordinator
  production construction, executor/state-machine changes.
- **Versions:** explicit preparer schema/version pinned to B1.
- **Tests:** target/precondition/snapshot reads, intent normalization, mapping
  ambiguity, version skew, mutation parameter substitution, fake adapters.
- **Migration:** none; synthetic/test-only.
- **Rollback:** remove inert preparer.
- **STOP:** authoritative target/snapshot inputs cannot be obtained before
  signing, mapping is not one-to-one, or nondeterminism changes the digest.

### B4 — RecoveryContract v2 provenance and tuple verification

- **Invariant:** a new contract durably records authenticated source provenance
  and proves its entire execution tuple matches the prepared-intent digest.
- **Expected files:** RecoveryContract/store schema and migration, contract
  builder/binding verifier, focused store/HMAC/migration tests.
- **Forbidden:** confirmation schema, executor authorization inputs, state
  transitions, MCP.
- **Versions:** RecoveryContract provenance version; store schema bump.
- **Tests:** copied IDs, altered capability/endpoint/method/target/intent/
  snapshot/rollback version, tampered provenance, legacy row behavior.
- **Migration:** legacy rows readable for existing recovery only and never
  coordinator-authorized; new rows require complete provenance.
- **Rollback:** migration must not make v2 rows executable by older code.
- **STOP:** provenance cannot be covered atomically/authentically or migration
  would infer missing facts.

### B5 — freshness and pre-consumption binding composition

- **Invariant:** all E2 gates plus authoritative execution-intent
  reconstruction and exact v2 binding succeed before consumption.
- **Expected files:** coordinator-side binding verifier/composition and focused
  isolation/adversarial tests.
- **Forbidden:** contract creation, confirmation, executor invocation, MCP.
- **Versions:** only v2 authorization eligible.
- **Tests:** every mismatch leaves authorization unconsumed; stale target/
  preparer version, wrong plan/step/digest, caller substitution.
- **Migration:** v1 fail-closed denial.
- **Rollback:** E2-only coordinator remains safe.
- **STOP:** binding verification requires caller assertion or changes E1/E2
  ordering/semantics.

### B6 — ADR-024 E3 retry with bound creation

- **Invariant:** only after all gates and atomic consumption, exactly one
  coordinator-built matching contract can be created, prepared, confirmed,
  and passed once to the sealed executor.
- **Expected files:** execution coordinator, behavioral/isolation tests, minimum
  ADR-024 implementation status.
- **Forbidden:** executor/state-machine behavioral changes, confirmation
  weakening, production construction, MCP WRITE, target-identity substitute.
- **Versions:** consumes only v2 authorization and v2 contract binding.
- **Tests:** original E3 matrix plus consume→create crash window, concurrency,
  response loss, exact contract/confirmation/executor identity.
- **Migration:** no legacy authorization/contract path.
- **Rollback:** path remains production-unreachable; consumed authorizations
  are never restored.
- **STOP:** any need for executor authorization awareness, state-machine
  bypass, retry invention, or appliance identity claim.

## STOP conditions

Implementation must stop if:

- the prepared tuple cannot be derived from one authoritative component;
- any execution-critical value remains an unchecked caller choice;
- canonical ownership or digest domain is duplicated or ambiguous;
- a v1 authorization or legacy contract could become executable by inference;
- execution freshness cannot deterministically reproduce the signed digest;
- contract provenance/tuple cannot be persisted atomically and authenticated;
- target identity must be treated as solved;
- MutationExecutor must inspect authorization;
- state-machine semantics must be bypassed;
- production construction or MCP WRITE exposure is required.

## Owner decisions required

| Decision | Recommended option | Alternatives | Consequences | Blocks implementation? |
|---|---|---|---|---:|
| Binding architecture | Alternative F: prepared intent + signed per-step digest + contract provenance | A, bare B/C/D, E | strongest substitution resistance with singular derivation; more explicit schema work | yes |
| Authorization versioning | PlanAuthorization v2; v1 never execution-eligible | mutate v1 or infer binding | fail-closed migration versus unsafe ambiguity | yes |
| Plan integration | keep PlanDigest/PlanStep v1; bind execution in authorization v2 | embed intent in plan/digest v2 | avoids planner/Tier 1 coupling; preserves E1 semantics | yes |
| Contract persistence | authenticated v2 provenance fields and store migration | separate binding record or no persistence | durable audit/transitive proof versus atomicity/duplication risk | yes |
| Prepared snapshot scope | include snapshot and rollback-plan version in execution digest | bind only mutation tuple | stronger recovery-policy authorization; requires preparation before signing | yes |
| Legacy contracts | existing recovery only; never coordinator-authorized | migrate by assertion | fail-closed, no invented provenance | yes |
| Adapter selection | sealed registry from bound capability/endpoint/method | caller-provided adapter | removes post-authorization substitution | yes |
| Expiry relationship | generated contract lifetime bounded by authorization and confirmation policy | independent contract expiry | reduces authority extension; exact rule needs specification | yes |
| Appliance identity | remain separate and unresolved | solve in later ADR | structural binding closes substitution but not cross-appliance portability | no for inert B1/B2; required before production WRITE if owner so decides |

No implementation slice may begin until the owner accepts or revises the
blocking decisions for that slice. Acceptance of this Proposed ADR alone is
not production WRITE authorization.

## Consequences

The design adds deliberate schema/version work before E3, but creates a
reviewable cryptographic chain without moving authorization into the executor
or duplicating state-machine behavior. It preserves E1 plan freshness, E2
one-time consumption, existing confirmation, and sealed execution. It makes
legacy ineligibility explicit and keeps the appliance-identity gap visible.

## References

- [ADR-022: Execution-authorization boundary](ADR-022-execution-authorization-boundary.md)
- [ADR-023: Authorization-verification boundary](ADR-023-authorization-verification-boundary.md)
- [ADR-024: Execution-authorization coordination](ADR-024-execution-authorization-coordination.md)
- [Execution Authorization Boundary](../EXECUTION_AUTHORIZATION_BOUNDARY.md)
- [Tier 1 Architecture](../TIER1_ARCHITECTURE.md)
- [Codex Takeover](../CODEX_TAKEOVER.md)
- [ADR-026: First WRITE capability adapter semantic unit](ADR-026-first-write-capability-adapter.md)
