# ADR-026: First WRITE capability adapter semantic unit

- **Status:** Proposed
- **Date:** 2026-08-11
- **Scope:** Architecture and disposable-lab evidence design only. This ADR
  does not authorize an adapter, preparer, endpoint allow-list entry, live
  mutation, WRITE activation, MCP tool, or production construction.

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
defines the evidence required before a later B3b implementation decision.

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
| 1 | firewall alias: replace `descr` only | `GET /api/v2/firewall/aliases`; `PATCH /api/v2/firewall/alias` | exact normalized unique alias `name`; numeric `id` is a refreshed locator | one bounded string; restore old string after full conflict check | High* because aliases influence policy, but narrowest evidenced candidate; **selected, lab-gated** |
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
  as caller inputs. The request must explicitly keep `apply=false`; B3b must
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

The numeric `id` returned by READ is a transient request locator. Every prepare,
execute, and rollback read resolves the exact natural name to exactly one row
and uses that row's current ID only for the immediate API call. ID is not in
`resource_target`, is not authorization identity, and cannot be caller supplied.

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
  new_description: NFC-normalized string, 0..N UTF-8 bytes
```

`N` must equal the maximum in the pinned lab-generated OpenAPI schema. If that
schema has no finite safe limit, owner approval must choose a smaller explicit
bound before B3b. Embedded NUL/control characters and invalid Unicode scalar
values are rejected. Exact acceptance of newline/tab requires lab schema
evidence and an owner decision; the conservative default is to reject them.

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
this candidate fails and B3b must not proceed.

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
Numeric ID may change only if lab evidence establishes benign ID reassignment;
without that evidence, ID change is treated as ambiguity/reconciliation even
though it is not in the semantic fingerprint.

Zero/multiple matches, malformed data, a different description, or any
forbidden-field difference fails semantic verification. Timeout or lost
response never causes automatic replay; authoritative read-back determines
verified success versus reconciliation.

The lab must also prove whether a config write marks aliases dirty, triggers a
filter reload, or changes runtime tables. Any unexpected apply/reload or policy
effect is disqualifying for this first semantic unit.

## Rollback snapshot

The rollback snapshot is the same complete canonical semantic object used for
the precondition: `name`, `type`, old `descr`, ordered `address`, and ordered
`detail`. It is a full semantic snapshot, not a serialized API envelope and not
a global pfSense configuration revision. Numeric ID is intentionally excluded
and refreshed by exact-name READ.

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
rollback. It resolves a fresh numeric ID, PATCHes only the original description
with `apply=false`, and performs the full authoritative read-back again.

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
activation, production construction, or lab PATCH is introduced. ADR-026
remains Proposed and its disposable-lab evidence gates remain outstanding.

The lab must prove that description rollback is exact and that neither forward
nor rollback PATCH changes members, details, type, ordering, runtime tables, or
unrelated configuration.

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
| `capability` | immutable registry entry `Capability.ALIAS_WRITE` | no caller choice | owner approves B3b registry entry |
| `endpoint_symbol` | immutable registry value `FIREWALL_ALIAS_DESCRIPTION` | no caller choice | exact symbol/allow-list remains unimplemented |
| `http_method` | immutable `PATCH` | no caller choice | pinned lab OpenAPI confirms |
| `adapter_version` | immutable `firewall-alias-description/v1` | no caller choice | owner approves compatibility/version policy |
| `resource_target` | `{"alias_name": normalized exact typed plan input}` | caller originally requests name, but plan binds it; live READ proves unique match | typed planner input and lab uniqueness proof |
| `target_precondition` | full live semantic object: name/type/descr/address/detail | authoritative live READ; caller cannot replace | internal identifying READ and lab completeness proof |
| `normalized_mutation_intent` | fixed operation + bound target + normalized new description | typed plan input only; no raw JSON | typed planner extension and exact description bound |
| `rollback_snapshot` | same full live semantic object | authoritative live READ | lab proves sufficient/exact restoration |
| `rollback_plan_version` | immutable `firewall-alias-description-rollback/v1` | no caller choice | owner approves policy and lab proves it |

All fields are deterministic given the exact typed plan input, one complete
authoritative read, and fixed registry/version. Live state is intentionally
load-bearing; later B5 must re-read/reprepare before consumption.

## Planner relationship

Current PlanStep cannot select this semantic unit or its parameters. No current
posture step means “change alias description,” and action/description text must
never be parsed.

B3b therefore has a typed-plan prerequisite. The recommended option is an
explicit versioned execution-request association owned by the planner domain:

```text
PlanExecutionRequestV1
  step_id
  semantic_unit = "firewall-alias-description/v1"
  request = AliasDescriptionChangeV1(alias_name, new_description)
```

The association must be part of a new plan/planning-input version and its
canonical plan identity, or otherwise be cryptographically bound before the
signer reviews the prepared digest. It must have one exact entry for the chosen
step and no prose inference. The exact PlanStep/PlanDigest versioning design is
an owner decision and a prerequisite to B3b; this ADR does not implement or
silently choose it.

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
| wrong numeric ID | prevented: ID is refreshed from exact-name READ and never caller supplied |
| duplicate/mutable name | lab must prove uniqueness/non-editability; zero/multiple fail closed; otherwise unacceptable |
| stale precondition / change between read and send | detected by executor re-read/fingerprint; fail closed before send |
| omitted field resets or hidden default | lab acceptance gate; any unrelated change rejects candidate |
| body parameter injection | prevented by closed typed request and `extra=forbid` |
| endpoint/method substitution | prevented by immutable registry and B1 digest/contract binding |
| delete/recreate | detected when semantic precondition changes; same-semantics recreation remains a locator ambiguity to characterize in lab |
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
| appliance substitution | deferred; appliance-level target identity remains unresolved |

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
- Delete/recreate and reorder aliases; prove natural-name resolution and ID
  refresh behavior.
- Drop connection during upload, drop response after commit, and timeout during
  read-back; prove no automatic second PATCH and deterministic reconciliation.
- Conflict after forward verification but before rollback; prove rollback stops.

### API behavior and repeatability

Test unknown/extra fields, omitted fields, null/empty description, over-limit
and invalid Unicode/control values, wrong ID, stale ID, duplicate names,
malformed bodies, wrong method, insufficient privilege, authentication failure,
dry-run, apply controls, async behavior, response schemas, config locking,
config-history failure, restart, and external/manual edits.

Run at least 25 clean forward/rollback cycles across fresh VM clones, plus each
fault case at least three times. Any nondeterministic semantic result or
unexplained side effect rejects the candidate.

## Evidence acceptance criteria

B3b implementation may be proposed only after an owner-reviewed evidence
package proves all of the following on the pinned disposable appliance:

- generated OpenAPI exact selector/body/control semantics;
- stable unique exact-name identity and safe numeric-ID refresh;
- complete authoritative READ including name/type/descr/address/detail;
- partial PATCH preserves every omitted field and ordering;
- explicit apply suppression produces no filter reload or service-wide effect;
- closed request rejects unknown fields and invalid values;
- authoritative post-condition distinguishes success/failure/ambiguity;
- snapshot is sufficient and rollback restores exact semantic equality;
- precondition catches every target-field concurrent change;
- unrelated-resource concurrency behavior is characterized;
- timeout/response-loss causes no automatic replay;
- least-privilege permission is sufficient and no broader permission is used;
- all B1 fields in this ADR are derivable without caller-trusted parallel facts;
- logs/results contain no credentials or unnecessary appliance-identifying data.

Failure of identity uniqueness, omitted-field preservation, apply suppression,
exact rollback, deterministic read-back, or side-effect containment rejects the
candidate rather than weakening the design.

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

## Required owner decisions

Before B3b, the owner must explicitly approve or revise:

1. `Capability.ALIAS_WRITE` description-only semantic unit;
2. singular `PATCH /api/v2/firewall/alias` and proposed endpoint symbol;
3. exact normalized alias-name natural identity and transient ID policy;
4. full name/type/descr/address/detail fingerprint;
5. `AliasDescriptionChangeV1` fields, normalization, and exact length/control
   bounds from lab OpenAPI;
6. full semantic rollback snapshot;
7. `firewall-alias-description-rollback/v1` policy;
8. `firewall-alias-description/v1` adapter/preparer version and pinned upstream
   compatibility range;
9. the lab plan and acceptance thresholds above, after reviewing actual results;
10. the required typed plan/planner association and PlanStep/PlanDigest version
    boundary.

Approval of this Proposed ADR alone is not approval of any item above.

## Future B3b implementation boundary

After lab evidence and all owner decisions, a separately authorized B3b may add
one inert, capability-specific preparer/adapter plus typed models and tests. It
may read the synthetic/authoritative alias state and compute B1 intent/digest.

B3b must not populate `WriteEndpoints`, activate `ALIAS_WRITE`, register an MCP
tool, mutate an appliance, accept PlanAuthorization, consume authorization,
create a RecoveryContract, or wire coordinator/executor/state-machine paths.
B4/B5/B6/E3 remain separate authorizations.

## STOP conditions

Stop before B3b if lab evidence does not prove exact request semantics,
identity uniqueness, complete READ, omitted-field preservation, apply/reload
suppression, deterministic post-condition, conflict-safe exact rollback, and
all B1 field sources. Also stop if typed planner binding remains unresolved,
caller-selected raw JSON is required, appliance identity becomes load-bearing,
or implementation would require WRITE reachability.

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
