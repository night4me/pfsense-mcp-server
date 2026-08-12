# ADR-026: First WRITE capability adapter semantic unit

- **Status:** Accepted (2026-08-12, owner)
- **Date:** 2026-08-11
- **Scope:** Architecture and disposable-lab evidence design only. This ADR
  does not authorize an adapter, preparer, endpoint allow-list entry, live
  mutation, WRITE activation, MCP tool, or production construction.

## Owner convergence decision

The owner accepted this description-only semantic unit and its
semantic-scope-specific acceptance policy on 2026-08-12. Acceptance authorizes
no implementation, capability/endpoint activation, MCP tool, production
construction, or live execution. W1 remains separately authorization-gated.

Evidence is mandatory before first WRITE only when it protects behavior the
exact semantic unit can exercise. Broader alias mutations, generic scenario
machinery, and exhaustive permutations are not promoted into product
prerequisites merely because they appear in the evidence catalogue below.
Existing valid evidence is reused and unperformed deferred evidence is never
reported as PASS.

### First-WRITE acceptance matrix

Status meanings: **ESTABLISHED** is accepted existing evidence;
**MUST COMPLETE** remains a W1/W2/W3 acceptance gate; **DEFERRED** is outside
the first-WRITE semantic scope and is not PASS.

| First-WRITE invariant | Status at acceptance | Accepted evidence / remaining requirement |
|---|---|---|
| exact target identity and singular resolution | ESTABLISHED | clean campaign and Stage 3A authoritative exact-name reads; production adapter retains zero/multiple refusal |
| complete authoritative pre-mutation READ | ESTABLISHED | name/type/description/ordered address/ordered detail captured authoritatively |
| complete protected fingerprint | ESTABLISHED | the exact five-field semantic fingerprint and ordering were exercised; production tests must preserve it unchanged |
| fresh lifecycle locator and continuity | ESTABLISHED | locator `0` remained stable in 25 clean cycles and all completed description cases; executor refusal on drift is already tested |
| omitted-field/protected-sibling preservation | ESTABLISHED | protected fields and ordering remained unchanged throughout clean and description evidence |
| explicit apply/reload suppression contract | MUST COMPLETE | explicit `apply=false` and omitted/default behavior are characterized; W3 must close any operationally material reload/service uncertainty without inferring absence from HTTP success |
| deterministic authoritative postcondition | ESTABLISHED | 25/25 verified B reads plus exact normalization/boundary evidence |
| description-field concurrent-change/conflict refusal | MUST COMPLETE | executor fingerprint refusal is established offline; production-bound D1-D5-equivalent focused tests and any owner-selected live evidence must prove the exact adapter path |
| stale expected-state refusal | MUST COMPLETE | existing executor behavior is reusable; prove it through the production-bound adapter/coordinator path |
| conflict-safe rollback from verified/reconciled B | MUST COMPLETE | sealed rollback and reconciliation architecture are established; prove post-B description drift refusal through the production-bound path |
| exact authoritative A restoration | ESTABLISHED | 25/25 clean restorations and every accepted Stage 3A/3B case restored exact A |
| at-most-one-send | ESTABLISHED | clean live send accounting plus MutationExecutor/FaultProxy offline tests exercise the same send owner; production wiring must not add a send path |
| no blind retry after uncertainty | MUST COMPLETE | executor/offline fault and reconciliation tests establish the security owner; confirm W1/W2 composition adds no retry; additional live permutations only if production introduces materially different behavior |
| authoritative uncertainty classification | MUST COMPLETE | ADR-027 observation and closed offline classifiers exist; integrate and test applied/not-applied/ambiguous in fixed production composition |
| fail-closed reconciliation | MUST COMPLETE | signed reconciliation architecture is established offline; fixed production verifier/resume construction and refusal tests remain |
| authenticated recovery across restart | MUST COMPLETE | schema-v6 encrypted/HMAC restart evidence is established offline; W2 must prove fixed production reconstruction and no resend |
| least privilege for exact endpoint/capability | MUST COMPLETE | prove the enabled production/test identity needs only the one alias-description endpoint/capability and no broader permission |
| sufficient authoritative side-effect evidence | MUST COMPLETE | deterministic config read-back and apply behavior are known; any unknown reload/service/config-history effect capable of invalidating verification or recovery remains blocking |

### Concurrency boundary

Description or protected-fingerprint change between preparation and the
forward/rollback precondition must fail closed. Unrelated-resource concurrency
does not require exhaustive empirical orchestration: the executor authorizes
from the selected alias's complete fingerprint and lifecycle locator, never a
global config revision, and the adapter builds a request only for the freshly
resolved exact alias locator. An unrelated change therefore cannot satisfy a
stale target fingerprint, change the resolved locator without refusal, or
redirect the request. If W1 review discovers shared appliance behavior that
breaks this separation, that concrete case becomes mandatory again.

### Response-loss and timeout boundary

The mandatory property is one send maximum, no blind retry, fresh
authoritative observation, the closed `DEFINITELY_APPLIED` /
`DEFINITELY_NOT_APPLIED` / `AMBIGUOUS` classification, and fail-closed signed
reconciliation where needed. Existing tests are acceptable where they execute
the same `MutationExecutor`, store, observation, and reconciliation owners.
Every live transport-fault permutation is not independently mandatory. New
live evidence is required only for material behavior introduced by the fixed
production composition.

### Side-effect boundary

HTTP success alone never proves absence of side effects. First-WRITE evidence
must establish deterministic authoritative configuration read-back, required
apply suppression, and that correctness/recovery needs no broader state
transition. Exhaustive filter/service/API/webConfigurator/config-history
instrumentation is not automatically required when existing authoritative
evidence and pinned endpoint behavior establish that contract. A genuinely
unknown effect that could invalidate deterministic verification, recovery, or
the description-only blast radius remains a blocker.

### Deferred / outside first-WRITE semantic scope

The following are retained as useful future evidence but do not block the
description-only first WRITE unless implementation review shows that they
affect a mandatory invariant above:

- address/member or detail mutation;
- alias create, delete, recreate, duplicate-name creation, or byte-identical
  recreation;
- forced numeric-locator manipulation outside normal description execution;
- full Stage 3F;
- D6 as a standalone empirical race;
- complete D/E/G permutation matrices and repeated cosmetic fault variants;
- generic ScenarioId orchestration or complete Stage3 execution-port work;
- exhaustive broader-resource mutation evidence.

## Context

ADR-025 B1 introduced the inert `PreparedExecutionIntentV1`; B2 introduced
signed plan/step-to-execution-digest associations. B3 then stopped because no
concrete capability adapter/preparer supplied authoritative values for the B1
execution/recovery tuple.

The repository already contains two narrower owner decisions. ADR-016 permits
disposable-lab research on firewall-alias description-only mutation, and
ADR-020 names that operation as the Milestone 0 first candidate. Neither
decision proves appliance behavior or authorizes implementation. This ADR
turns the named candidate into one reviewable semantic specification and
defines the evidence required before separately authorized W1 implementation.

The API is the community-maintained pfSense REST API package, not a
Netgate-supported interface. Source review is useful design evidence, but the
exact disposable appliance's generated OpenAPI document and observed behavior
remain authoritative for acceptance.

### LAB-T1 prerequisite status

The read-only LAB-T1 harness uses a separately owner-approved, lab-only manual
attestation gate for dependency surfaces that current APIs cannot enumerate
completely. It still automatically checks available firewall-rule and NAT
references, and positive, failed, malformed, or incomplete automatic evidence
cannot be overridden by an attestation. Attestations bind the exact sanitized
lab identity and normalized synthetic alias for at most ten minutes.

This does not establish global absence of alias dependencies and is explicitly
unacceptable as a production authorization, dependency, or target-identity
mechanism. Completing LAB-T1 does not authorize or begin this ADR's mutation
evidence matrix; a successful sanitized read-only preflight must return for
owner review first.

## B3 blocker

Current `SecurityPosturePlan` steps are policy/provisioning actions. They do not
carry a typed alias target or desired description. `WriteEndpoints` is empty,
and no real adapter exists. Consequently B3 cannot derive capability, endpoint,
method, adapter version, resource target, precondition, normalized mutation,
snapshot, or rollback version without a separately approved semantic unit.

This ADR specifies that unit. It does not remove the empirical lab gate and it
does not solve the typed planner-input prerequisite described below.

## Candidate selection criteria

The first semantic unit should minimize blast radius while exercising all
important prepared-intent properties: stable resource selection, complete
precondition, one closed mutation projection, authoritative read-back, exact
rollback, and ambiguous-outcome handling. It must avoid management addressing,
routing, authentication, key material, broad service configuration, bulk
replacement, create/delete, and apply/reload operations.

Evaluation priorities, in order, are reversibility, blast radius,
deterministic effect, exact identity, unique READ, complete fingerprint,
closed typing, authoritative post-condition, exact rollback, API stability,
least privilege, low appliance-wide coupling, lockout avoidance, absence of
broad disruption, and disposable-lab testability.

## Candidate comparison

The 240-endpoint risk inventory found only two credible early candidates. A
third representative object-level candidate is shown to make the rejection
boundary explicit; it is not considered credible enough to enter the final
ranking.

| Rank | Semantic unit | READ / WRITE | Identity | Mutation and rollback | Risk / decision |
|---:|---|---|---|---|---|
| 1 | firewall alias: replace `descr` only | `GET /api/v2/firewall/aliases`; `PATCH /api/v2/firewall/alias` | exact normalized unique alias `name`; numeric `id` is a fresh transport locator and protected lifecycle-continuity guard | one bounded string; restore old string after full conflict check | High* because aliases influence policy, but narrowest evidenced candidate; **selected, lab-gated** |
| 2 | system tunable: replace `descr` only | existing tunables READ; `PATCH /api/v2/system/tunable` | exact tunable name; numeric ID locator | one string; restore old string | High* and system-wide; description/value coupling and runtime effects are less favorable; fallback only |
| 3 | DNS resolver host-override metadata | `GET /api/v2/services/dns_resolver/host_overrides`; singular PATCH endpoint in upstream inventory | compound host/domain key is mutable and duplicate/normalization behavior is unproven | likely service-config write and resolver reload; exact rollback depends on full object | High/service-wide; rejected for first adapter because identity, reload, and rollback are materially more complex |

Interfaces, DHCP mappings, certificates/ACME, firewall rules/NAT, routing,
users/authentication, and bulk endpoints are rejected categorically for the
first adapter due to lockout, credential, ordering, service, or replacement
risk. No third candidate in the repository currently matches the top two's
combination of READ coverage, non-numeric natural key, and narrow reversible
field projection.

## Selected candidate

**Recommended first capability semantic unit: replace only the description of
one existing ordinary firewall alias identified by its exact normalized alias
name, using `PATCH /api/v2/firewall/alias`, while preserving name, type,
members, member details, placement, and all apply controls.**

This is an update-only operation. It cannot create, delete, rename, reorder,
retag, change members, change member details, submit bulk data, request apply,
or invoke `/api/v2/firewall/apply`.

### Capability semantics

- Capability: existing inactive `Capability.ALIAS_WRITE`.
- Conceptual operation: `set_firewall_alias_description_v1`.
- Risk class: High* at endpoint level; `CONFIGURATION_CHANGE` authorization.
  The narrow projection lowers blast radius but does not relabel the broad
  upstream endpoint as low-risk.
- Endpoint symbol proposed for later implementation:
  `FIREWALL_ALIAS_DESCRIPTION`.
- HTTP method: `PATCH`.
- Endpoint: singular/item update endpoint `/api/v2/firewall/alias`.
- Collection replacement (`PUT /firewall/aliases`) is forbidden.
- Partial-PATCH semantics are source-documented but must be proven against the
  pinned lab package. Whole-object replacement is unacceptable.
- `apply`, `async`, `placement`, `append`, and `remove` controls are forbidden
  as caller inputs. The request must explicitly keep `apply=false`; W1 must
  stop if the lab schema cannot express that without an implicit reload.

The upstream model at the reviewed commit declares alias `name` unique and
non-editable, accepts an empty description, and supports singular PATCH. Its
apply hook can reload the firewall filter. Whether description-only PATCH
without apply performs any runtime reload or unrelated normalization is an
empirical acceptance gate, not assumed here.

## Resource natural identity

The natural identity is:

```json
{"alias_name": "<NFC-normalized exact alias name>"}
```

Alias name is chosen because the reviewed upstream model declares it unique
and non-editable. Matching is exact and case-sensitive after NFC normalization;
no prefix, wildcard, case-folding, or numeric-ID identity is allowed. The lab
must confirm the API and pfSense configuration enforce those properties.

The numeric `id` returned by READ is a transport locator, not semantic identity.
The current pfSense API exposes no independent stable generation/incarnation
marker. Therefore the ID observed at lifecycle protection time is also sealed
as an incarnation-continuity guard. Every execute and rollback read resolves
the exact natural name to exactly one row, requires the current ID to equal that
guard, and only then projects the freshly read ID into request construction.

Any ID change during the protected lifecycle fails closed. This does not prove
that the alias was deleted and recreated; it means non-recreation cannot be
proved. A benign renumbering is consequently an accepted false-positive that
requires re-prepare/operator retry. Automatic continuation across a locator
change is forbidden. The ID remains outside `resource_target` and semantic
identity, cannot be caller supplied, and is never cached by the stateless
adapter.

Rename is outside this capability. Deletion/recreation under the same name is
treated as a replacement unless the complete precondition remains identical;
the later execution gate must fail on any mismatch. Backup/restore and reboot
stability of names and ID reassignment require lab characterization. Appliance
identity remains separate and unresolved.

System/built-in aliases, URL-table aliases, and other alias types not accepted
by the pinned ordinary-alias model must fail closed. The initial lab resource
must be a synthetic, ordinary `host`, `network`, or `port` alias with no role in
management access or production-equivalent policy.

## Authoritative READ

The authoritative read operation is the existing verified
`GET /api/v2/firewall/aliases`, requested with identifying metadata enabled and
pagination sufficient to inspect the complete ordinary-alias collection.

The future adapter must:

1. normalize and validate the requested natural name;
2. enumerate all pages, not rely on a default/partial limit;
3. filter by exact normalized `name`;
4. reject zero or more than one match;
5. reject malformed or incomplete objects;
6. return `id`, `name`, `type`, `descr`, ordered `address`, and ordered
   `detail` from the same authoritative response.

The current public READ model privacy-defaults `address` and `detail` to
redacted. A future internal preparer read may request those identifying fields
only for contract preparation and must not expose them through MCP output,
logs, errors, or reports. This narrow internal use does not change the public
privacy default.

If the lab's singular `GET /api/v2/firewall/alias?id=...` is proven to return
the same complete object, it may be used only after natural-name resolution;
the plural exact-name scan remains the authority for uniqueness.

## Fingerprint and precondition

The canonical target precondition is the full semantic ordinary-alias object,
excluding only the transient numeric locator:

```json
{
  "name": "<exact normalized name>",
  "type": "host|network|port",
  "descr": "<current normalized description>",
  "address": ["<ordered member>", "..."],
  "detail": ["<ordered member detail>", "..."]
}
```

Every field is load-bearing:

- `name` proves the natural target;
- `type` prevents mutation after semantic retagging;
- `descr` provides the expected pre-state and detects concurrent description
  edits;
- `address` protects policy-affecting members;
- `detail` protects member-to-detail correspondence and detects server-side
  regeneration or concurrent edits.

List order is preserved because address/detail positions correspond. NFC string
normalization follows B1 canonical rules; no sorting or case folding is added.
Numeric ID, API envelope, pagination data, response timestamps, config-history
revision numbers, runtime alias-table counters, and apply-status timing are
excluded because they are locators/volatile metadata rather than object
semantics. Config-history evidence may be retained as lab/audit evidence but is
not the resource fingerprint or an automatic global rollback source.

Any missing/redacted field, inconsistent address/detail cardinality, duplicate
name, unsupported type, or noncanonical value fails preparation.

## Typed mutation projection

The future typed planning input is conceptually:

```text
AliasDescriptionChangeV1
  alias_name: constrained alias-name string
  description: NFC-normalized string, 0..1024 evidenced units
```

The evidenced boundary accepts 1024 and rejects 1025. Embedded NUL, rejected
control characters (including U+0001), malformed/non-string values, and invalid
Unicode scalar values are refused. The established whitespace, tab, newline,
Unicode and NFD-to-NFC behavior is preserved by the typed boundary rather than
reinterpreted during implementation.

Unknown fields are forbidden. Empty description is an explicit value, not
missing/null. A requested description equal to the authoritative current value
is a no-op and must not create an executable prepared intent. Arbitrary JSON,
raw body, numeric ID, type, addresses, details, apply flags, placement, or
endpoint/method cannot be supplied.

The normalized B1 mutation intent is:

```json
{
  "operation": "set_firewall_alias_description_v1",
  "raw_target_hint": {"alias_name": "<normalized name>"},
  "new_description": "<normalized description>"
}
```

The operation discriminator prevents reinterpretation. There are no omitted
optional keys and no alternate equivalent input form.

## Request mapping

The later adapter must build exactly one closed request from the resolved live
locator and normalized intent:

- method: `PATCH`;
- path: `/api/v2/firewall/alias`;
- body: exact lab-verified selector plus `descr` and explicit `apply=false`;
- no query parameters;
- no `placement`, `append`, `remove`, `async`, `dry_run`, name, type, address,
  detail, or additional field;
- content type: the repository's existing canonical JSON request mechanism.

The expected source-backed selector is numeric `id`; the provisional body is
therefore `{id: resolved_id, descr: new_description, apply: false}`. This is a
**lab acceptance hypothesis**, not implementation authority. The exact pinned
OpenAPI document must confirm field location, types, and whether explicit
`apply=false` is accepted. If ID is a query parameter, if unrelated fields are
required, if omitted fields reset, or if apply/reload cannot be suppressed,
this candidate fails and W3 must not enable the capability.

No unrelated field is round-tripped into the PATCH. The reason for selecting
PATCH is precisely to avoid whole-object replacement. If the lab disproves
partial preservation, the operation is rejected rather than changed into a
full-object request.

## Post-condition

HTTP success is not sufficient. After a successful or ambiguous response, the
adapter re-enumerates aliases through the authoritative READ and resolves the
exact natural name again.

Verified success requires exactly one match, `descr == new_description`, and
`name`, `type`, ordered `address`, and ordered `detail` equal the pre-state.
The numeric ID is not semantic identity, but the API exposes no independent
incarnation marker. The ID captured when the lifecycle is protected is
therefore a continuity guard: every authoritative read before or after a send
must resolve the same ID. Any change means continuity is unproven and fails
closed; the operation never infers safe renumbering or recreation.

Zero/multiple matches, malformed data, a different description, or any
forbidden-field difference fails semantic verification. Timeout or lost
response never causes automatic replay; authoritative read-back determines
verified success versus reconciliation.

First-WRITE acceptance must establish the side-effect boundary in the matrix
above. Any apply/reload or policy effect that broadens the operational contract
or invalidates deterministic verification/recovery is disqualifying; absence
is never inferred solely from HTTP success.

## Rollback snapshot

The rollback snapshot is the same complete canonical semantic object used for
the precondition: `name`, `type`, old `descr`, ordered `address`, and ordered
`detail`. It is a full semantic snapshot, not a serialized API envelope and not
a global pfSense configuration revision. Numeric ID is intentionally excluded
from this semantic snapshot, but is separately integrity-bound as the
lifecycle-continuity guard and freshly resolved at every send boundary.

The rollback mutation itself changes only `descr` back to the captured value.
The full snapshot exists to prevent rollback from overwriting unrelated edits,
not to send those fields back to the API.

Delete/recreate, rename, duplicate name, type/member/detail change, or missing
target stops automatic rollback and enters the existing failure/reconciliation
path. Global config-history restore and resource recreation are forbidden.

## Rollback policy and version

Proposed rollback policy identifier:

```text
firewall-alias-description-rollback/v1
```

Rollback is allowed only when the current exact-name read returns one object
whose name/type/address/detail equal the snapshot, whose description equals the
successfully written new description, and whose target reservation/state permits
rollback. It resolves a fresh numeric ID, requires exact equality with the
protected lifecycle guard, PATCHes only the original description with
`apply=false`, and performs the full authoritative read-back plus continuity
check again.

Rollback succeeds only when all semantic fields equal the snapshot. Any
concurrent change, ambiguous send, missing/multiple resource, reload effect, or
verification failure stops automatic compensation. There is no generic retry,
create-on-missing behavior, or global config restore.

The full pre-forward fingerprint remains unchanged and includes the original
description. On successful authoritative forward read-back, the executor must
derive and integrity-seal a distinct expected post-forward fingerprint covering
the same complete tuple, including the new description, atomically with the
`VERIFIED` transition. The immediate pre-rollback READ must match that sealed
post-forward fingerprint exactly. Rollback then restores and verifies the
original snapshot/fingerprint. This corrects the pre-evidence finding that a
comparison against the original fingerprint would reject every successful
description mutation. It does not weaken any fingerprint field.

## Architecture-remediation implementation status

The inert Tier 1 contract/store/executor path now implements the distinct,
durable expected-post-forward fingerprint boundary and focused synthetic
regression coverage. Confirmed-applied reconciliation evidence also signs this
fingerprint before it can produce a rollback-eligible VERIFIED contract. This
is architecture validation only: no alias adapter, public endpoint, capability
activation, production construction, or lab PATCH is introduced. ADR-026 is
Accepted; the matrix above records which first-WRITE evidence remains.

First-WRITE acceptance must prove exact description rollback and preservation
of members, details, type, and ordering. Runtime/unrelated effects are governed
by the explicit side-effect and concurrency boundaries above rather than by an
exhaustive broader-mutation campaign.

## Adapter and preparer version

Proposed adapter/preparer identifier:

```text
firewall-alias-description/v1
```

A version bump is required for any change to endpoint or method, selector
location/type, request fields, description normalization/bounds, resource
identity, fingerprint fields or ordering, mutation-intent shape, read-back or
post-condition semantics, apply behavior, snapshot, rollback policy, or
supported upstream pfSense/API package compatibility range.

The pinned upstream package commit/version and generated OpenAPI fingerprint
are compatibility evidence, not replacements for `adapter_version`. New
software that cannot reproduce the exact B1 intent/digest fails closed.

## Complete B1 field mapping

| B1 field | Exact source and representation | Live/caller influence | Remaining prerequisite |
|---|---|---|---|
| `capability` | immutable registry entry `Capability.ALIAS_WRITE` | no caller choice | W1 adds the inert binding; W3 activates it |
| `endpoint_symbol` | immutable registry value `FIREWALL_ALIAS_DESCRIPTION` | no caller choice | exact symbol/allow-list remains unimplemented |
| `http_method` | immutable `PATCH` | no caller choice | pinned lab OpenAPI confirms |
| `adapter_version` | immutable `firewall-alias-description/v1` | no caller choice | accepted; W1 pins evidenced compatibility |
| `resource_target` | `{"alias_name": normalized exact typed input}` | caller requests name; signed V2 binding and live READ prove exact unique match | W1 typed request/binding |
| `target_precondition` | full live semantic object: name/type/descr/address/detail | authoritative live READ; caller cannot replace | established evidence; W1 production type |
| `normalized_mutation_intent` | fixed operation + bound target + normalized description | typed input only; no raw JSON | W1 exact intent binding |
| `rollback_snapshot` | same full live semantic object | authoritative live READ | established evidence; W1 production type |
| `rollback_plan_version` | immutable `firewall-alias-description-rollback/v1` | no caller choice | accepted |

All fields are deterministic given the exact typed plan input, one complete
authoritative read, and fixed registry/version. Live state is intentionally
load-bearing; later B5 must re-read/reprepare before consumption.

## Planner relationship

Current PlanStep prose does not select this semantic unit and must never be
parsed as authority. PlanDigest/PlanStep v1 remains unchanged. The typed
`AliasDescriptionChangeV1(alias_name, description)` is authoritatively
prepared, and `PlanAuthorizationV2` signs its exact execution-intent digest
beside the exact authorized step ID and plan digest. This is the accepted
cryptographic association; W1 must not create a second planning schema or
infer mutation facts from action/description text.

This is not a second policy engine: the planner decides that the typed request
belongs in the reviewed plan; the adapter only translates the closed request
and authoritative state into the fixed execution tuple.

## B2 relationship

The future B3 preparer remains authorization-independent. It selects the
approved registry entry from the typed semantic-unit discriminator, performs
the authoritative read, builds `PreparedExecutionIntentV1`, and invokes only
`compute_execution_intent_digest()`.

The signing workflow then places that recomputed digest beside the exact step
ID in `PlanAuthorizationV2`. B3 does not verify signatures. Future B5 must
reprepare from authoritative inputs and compare the exact B1 digest with B2's
signed pair before consumption.

## Threat analysis

| Threat | Classification and treatment |
|---|---|
| wrong or changed numeric ID | prevented: every fresh exact-name READ must match the integrity-bound lifecycle guard; mismatch fails closed and is never caller-overridable |
| duplicate/mutable name | lab must prove uniqueness/non-editability; zero/multiple fail closed; otherwise unacceptable |
| stale precondition / change between read and send | detected by executor re-read/fingerprint; fail closed before send |
| omitted field resets or hidden default | lab acceptance gate; any unrelated change rejects candidate |
| body parameter injection | prevented by closed typed request and `extra=forbid` |
| endpoint/method substitution | prevented by immutable registry and B1 digest/contract binding |
| delete/recreate | changed locator fails closed even when name and full fingerprint are byte-identical; the API cannot prove incarnation continuity |
| rollback overwrites legitimate edit | prevented by full pre-rollback conflict check; conflict enters reconciliation |
| partial success / timeout after server success | detected by read-back; no automatic replay; ambiguous state enters reconciliation |
| duplicate request/retry | prevented by sealed one-send semantics; direct out-of-band API use remains outside coordinator |
| filter reload/service effect | lab acceptance gate; unexpected reload is unacceptable for first adapter |
| post-condition ambiguity | detected/fail-closed by exact full read-back |
| rollback failure | existing rollback-failed/reconciliation state; no repeated blind rollback |
| privilege mismatch | least-privilege lab identity must prove exact operation; denial fails before effect |
| direct API use outside coordinator | deferred operational threat; production construction/isolation remains separate |
| malformed canonical values | prevented by typed model and B1 canonical validation |
| planner/adapter version mismatch | detected by semantic discriminator, adapter version, and digest mismatch |
| appliance substitution | prevented by ADR-025's accepted configured-target/TLS plus stable installation-identifier binding; unavailable or changed identity fails closed |

No threat marked as an empirical acceptance gate may be treated as prevented
until the lab evidence exists.

## Disposable-lab evidence plan

No production firewall, identity, address, certificate, credential, or packet
capture may be used. The existing disposable-lab containment/reset plan is
authoritative. The package version must be pinned, its generated OpenAPI
retained by non-sensitive hash/version, and the synthetic alias must not be
referenced by management or production-equivalent rules.

### Baseline

1. Create one synthetic ordinary alias and a second control alias.
2. Record full plural and singular READ responses without retaining secrets.
3. prove exact name uniqueness and non-editability; test duplicate creation and
   case/Unicode variants;
4. reboot and restore to characterize name stability and numeric ID behavior;
5. capture canonical semantic snapshot/fingerprint and config/runtime hashes
   that exclude credentials and identifying data.

### Mutation

1. Compare the generated OpenAPI schema with the pinned upstream source.
2. Exercise dry-run if supported and prove no config/apply effect.
3. PATCH only ID, description, and explicit `apply=false` as confirmed by the
   schema; record method/path/status/timing, never credentials.
4. Re-read and prove description equality plus byte-semantic equality of every
   forbidden field and the control alias.
5. Inspect config history, dirty/apply status, filter reload evidence, runtime
   alias table, and service/process state for side effects.

### Rollback

1. Resolve the target again by exact name and verify the forward-state
   precondition.
2. PATCH only the old description with apply disabled.
3. Re-read and prove exact canonical snapshot restoration and unchanged control
   resource/runtime state.
4. Repeat after process and appliance restarts where safe.

### Concurrency and ambiguity

- Change description externally between prepare/read and send; expect refusal.
- Change name/type/member/detail externally; expect refusal.
- Change a separate alias; measure whether execution can safely proceed without
  confusing global config revisions.
- Delete/recreate and reorder aliases; prove natural-name resolution and that
  any lifecycle ID change refuses conservatively because incarnation continuity
  cannot otherwise be proven.
- Drop connection during upload, drop response after commit, and timeout during
  read-back; prove no automatic second PATCH and deterministic reconciliation.
- Conflict after forward verification but before rollback; prove rollback stops.

### API behavior and repeatability

Test unknown/extra fields, omitted fields, null/empty description, over-limit
and invalid Unicode/control values, wrong ID, stale ID, duplicate names,
malformed bodies, wrong method, insufficient privilege, authentication failure,
dry-run, apply controls, async behavior, response schemas, config locking,
config-history failure, restart, and external/manual edits.

The completed 25 clean cycles and completed representative repetitions are not
repeated merely to increase counts. Additional repetitions apply only to a
remaining mandatory case where they add independent evidence. Any
nondeterministic semantic result or operationally material unexplained side
effect rejects the candidate.

## Evidence acceptance criteria

The first-WRITE acceptance matrix at the top of this ADR is authoritative.
Every **MUST COMPLETE** row must be established before W3 owner enablement;
**DEFERRED** evidence is not PASS and is not a description-only prerequisite.
All B1 fields must remain derivable without caller-trusted parallel facts, and
logs/results must contain no credentials, stable appliance identifiers, or
unnecessary identifying data.

Failure of identity uniqueness, omitted-field preservation, apply suppression,
exact rollback, deterministic read-back, least privilege, retry suppression,
or operationally material side-effect containment rejects the candidate rather
than weakening the design.

## Rejected candidates

- **System-tunable description-only PATCH:** the only credible fallback, but a
  tunable is system/kernel configuration and value/description coupling or
  runtime effects could be more severe. Consider only if alias evidence fails
  for an alias-specific reason that does not also invalidate tunables.
- **DNS resolver host-override metadata:** compound mutable identity,
  service-reload coupling, full-object preservation, and rollback ambiguity.
- **DHCP static-mapping metadata:** DHCP service/config coupling and compound
  MAC/address identity make rollback and side effects higher risk.
- **Interface description:** interface endpoint is critical and can affect
  management/network configuration or apply semantics; unacceptable first
  blast radius.
- **Certificate/ACME metadata:** key/certificate lifecycle and external ACME
  side effects; rollback and privilege impact are not local metadata concerns.
- **Alias members or create/delete:** directly changes firewall policy inputs,
  expands mutation shape, and complicates rollback/references.
- **Bulk endpoints:** omission means replacement/deletion; unacceptable.

## Resolved owner decisions

The owner accepts:

1. `Capability.ALIAS_WRITE` for description only;
2. singular `PATCH /api/v2/firewall/alias` and endpoint symbol
   `FIREWALL_ALIAS_DESCRIPTION`;
3. normalized exact alias name as natural identity and numeric ID only as a
   fresh protected lifecycle locator;
4. the complete name/type/description/ordered-address/ordered-detail
   fingerprint;
5. model-facing `AliasDescriptionChangeV1` inputs `alias_name` and
   `description`, with existing evidence-derived normalization and bounds:
   NFC intent, maximum 1024 accepted units, 1025 rejected, malformed/non-string
   and U+0001 control input rejected, and empirically accepted whitespace/
   Unicode behavior retained exactly rather than re-guessed;
6. the full semantic rollback snapshot;
7. rollback policy `firewall-alias-description-rollback/v1`;
8. adapter/preparer version `firewall-alias-description/v1`, pinned to the
   evidenced upstream compatibility range;
9. the semantic-scope-specific evidence matrix above;
10. PlanDigest/PlanStep v1 unchanged, with the exact step-to-intent association
    signed by `PlanAuthorizationV2` as accepted in ADR-025.

## W1 implementation boundary

A separately authorized W1 may add the production capability-specific typed
request, adapter and authoritative preparer, then compose the accepted ADR-025
PlanAuthorizationV2-to-provenance-bound-RecoveryContract chain through one
MutationExecutor handoff. W1 must remain production-unreachable from MCP and
must not populate `WriteEndpoints`, activate `ALIAS_WRITE`, register a tool, or
perform live mutation. W2 owns fixed production construction; W3 alone owns
the endpoint/capability/tool surface and selected live acceptance.

## STOP conditions

Stop W1/W2/W3 at the applicable boundary if a **MUST COMPLETE** matrix row
cannot be established, if exact request semantics or B1 sources diverge from
the accepted evidence, if caller-selected raw JSON is required, or if the
PlanAuthorizationV2/appliance-target binding cannot be carried through the
authenticated contract. W3 must not enable WRITE with an unresolved
operationally material side effect or candidate uncertainty.

Public MCP remains 42 READ / 0 WRITE. `WriteEndpoints` remains empty and WRITE
capabilities remain 0/3 active.

## References

- [ADR-016: Alias-candidate disposable-lab authorization](ADR-016-alias-candidate-lab-authorization.md)
- [ADR-020: First WRITE capability candidate](ADR-020-milestone-0-first-write-capability-candidate.md)
- [ADR-025: Authorization-to-RecoveryContract binding](ADR-025-authorization-recovery-contract-binding.md)
- [Writable endpoint risk matrix](../WRITE_ENDPOINT_RISK_MATRIX.md)
- [Tier 1 activation decisions](../TIER1_ACTIVATION_DECISIONS.md)
- [Disposable lab execution model](../tier1/specs/disposable_lab_execution_model.md)
- [Capability adapter contract](../tier1/specs/capability_adapter_contract.md)
- [pfrest endpoint-type documentation](https://pfrest.org/ENDPOINT_TYPES/)
- [pfrest common control parameters](https://pfrest.org/COMMON_CONTROL_PARAMETERS/)
- [Netgate alias documentation](https://docs.netgate.com/pfsense/en/latest/firewall/aliases.html)
