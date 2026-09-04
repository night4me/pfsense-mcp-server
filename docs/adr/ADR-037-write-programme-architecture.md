# ADR-037: WRITE Programme Architecture — Capability Families, Existence-Transition Executor, and Risk Scaling

- **Status:** **Accepted (2026-09-04, owner)** — architecture-only. This
  ADR authorizes no new WRITE capability, no executor code, and no
  adapter; it freezes the programme's architecture (capability-family
  model, execution-shape classification, existence-transition executor
  design, risk tagging) for future, separately-gated implementation
  work. See "Acceptance record" below for the clean review that led to
  this status change.
- **Date:** 2026-09-04 (drafted, then amended twice, same day: once per
  an owner architecture re-review, once per a follow-up narrow
  amendment pass correcting that review's own findings, then accepted
  following a clean acceptance review — see "Amendment record" and
  "Acceptance record" below.)

## Context

ADR-036 closed a specific, historically-scoped body of work: four
architecture gaps in the machinery the one already-shipped WRITE
capability (`set_firewall_alias_description_v1`) depends on, plus (this
session) a runtime-wide pfREST Read Only gate. Its own text is explicit
that it does not authorize a second capability, and does not decide
whether WRITE scope should expand at all — "an explicit, separate
product decision this design mission does not make."

The owner has since stated a programme-level destination: eventually
account for, and where safe implement, the complete pfREST mutation
surface — not as one mission, not by bypassing ADR-036, preserving the
existing discipline (explicit authorization, narrow named capabilities,
independent review, exhaustive tests, LAB qualification where
appropriate). This ADR is the architecture layer that destination
requires before any second capability is built. The full supporting
analysis (re-derived 451-operation inventory, classification, capability
families, risk tags, postcondition/recovery feasibility) lives in the
companion report, `reports-ai/WRITE_PROGRAMME_ARCHITECTURE_2026-09-04.md`
(gitignored, external, mirroring how ADR-036 references its own
companion threat-model report).

Two findings from that analysis drive this ADR's decisions:

1. **Privilege atomicity.** `security_privileges.py`'s existing,
   already-accepted `resolve_privilege()` resolves 450 of the 451
   mutating operations to their own distinct, narrow pfSense privilege
   string. Grouping operations into project-level "capability families"
   is therefore a pure policy layer this project fully controls — it
   never has to fight or widen what pfSense itself would enforce.
2. **The existence-transition gap.** `MutationExecutor.execute()`/
   `rollback()`'s verification flow requires the pre-mutation
   authoritative read to find exactly one existing match — a hard
   requirement for the shape `firewall/alias.descr` has (mutate a field
   on a persistently-existing object). There is no way for the current
   `CapabilityAdapter` contract to represent "confirmed absent" as a
   legitimate observation rather than a refusal. The owner's architecture
   review (below) replaced the original rough "POST/DELETE ≈ 299 ops"
   estimate with an exact, method-independent classification, corrected
   a second time in a follow-up amendment pass after six individual
   operations were found misclassified by their HTTP method/path shape
   alone (verified against each operation's actual OpenAPI description
   text): **148 operations (73 create-shaped + 75 delete-shaped)
   genuinely need this new primitive; the remainder of what looked like
   create/delete by HTTP method alone turned out to be secret-lifecycle,
   runtime-action, non-mutating, or bulk-shaped and does not belong in
   this gap at all** — see "Execution-shape classification" below.

## Decision

### D1 — Successor ADR, not an ADR-036 amendment

This ADR stands alone rather than amending ADR-036, to keep ADR-036 as
the closed, auditable W0 record it already is. See the companion
report's Step 3 for full rationale.

### D2 — A second sealed executor for existence-transition operations, never a modification to the shared `MutationExecutor`

Per ADR-014's own "Future migration path": *"If a future capability
genuinely cannot fit the single-executor model... that is a signal to
design a second, equally sealed executor variant with its own ADR — not
to weaken this executor's guarantees to accommodate an exception."*
Create/delete-shaped operations are exactly that signal. This ADR
authorizes, as a **future, separately-designed** artifact — not
implemented here — a new spec, `docs/tier1/specs/sealed_existence_executor.md`,
following `sealed_executor.md`'s own "designed, reviewed, frozen, then
implemented" discipline, before any create/delete-shaped capability
(including the DNS resolver host override candidate this programme
originally considered) is built. The existing `MutationExecutor` and its
one live capability are **not** touched by this decision, and Shape A
(existing-target update) continues to be served by `MutationExecutor`
exactly as it is today — this ADR does not propose migrating it.

**D2.1 — Refined executor shape (owner architecture review, 2026-09-04).**
The review explicitly required treating CREATE and DELETE as
independent questions rather than assuming they share one executor
merely because both fall outside today's implementation. Finding: they
are not independent in the way that matters most — **each shape's
rollback is a live instance of the other shape's forward operation**
(rolling back a create means deleting what was created; rolling back a
delete means re-creating what was removed, from the preserved
pre-deletion snapshot). Two fully separate, independently-implemented
executor classes would therefore either duplicate the "perform a
create-shaped send and verify it" logic inside `DeleteExecutor.rollback()`
and the mirror inside `CreateExecutor.rollback()` — exactly the
"multiplies the amount of security-critical code that must be kept
consistent across N copies" risk ADR-014 itself used to reject
per-capability executors — or import from each other, which is worse.

**Recommendation: one class, `ExistenceTransitionExecutor`, exposing two
distinctly-named, distinctly-typed public entry points, `create()` and
`delete()`** — structurally the same pattern `MutationExecutor` already
uses for its own two related-but-different operations, `execute()` and
`rollback()`. `create()` accepts only a `CreationAdapter`-shaped Protocol
(whose `read_target()` may return a typed `ConfirmedAbsent` sentinel);
`delete()` accepts only a `DeletionAdapter`-shaped Protocol (whose
`read_target()`'s *post*-mutation call may return that same sentinel).
Each method's own rollback path reuses the class's own other primitive
internally — never duplicated, never adapter-visible, never a second
place either primitive is implemented. This is deliberately **not** a
single `execute(direction=...)` method with a runtime discriminator flag
(rejected: a mismatched flag/adapter-shape pairing would be a real,
avoidable bug class; two distinctly-named/-typed methods make the shape
structural rather than a value a caller could get wrong).

**Precondition/postcondition/binding algebra per shape** (all three
share the existing store, state machine, `WriteApiClient`, crypto, and
canonical-digest infrastructure unchanged; `contract.verify_bindings()`
itself needs zero changes for any shape — it already just digests and
compares whatever canonical `target_precondition` value the adapter
computes, and shape B's "confirmed absent" marker is just another
canonical value to digest, the same mechanism, not a new one):

| | **A — UPDATE** (live, `MutationExecutor`) | **B — CREATE** (`ExistenceTransitionExecutor.create()`) | **C — DELETE** (`ExistenceTransitionExecutor.delete()`) |
|---|---|---|---|
| Canonical precondition | Fresh fingerprint of the existing object | Fresh, TOCTOU-safe proof of **absence** at the natural identity (canonical marker, not a real snapshot) | Fresh fingerprint of the existing object (identical to A) |
| Canonical postcondition | Fresh fingerprint shows exactly the intended field(s) changed, nothing else | Fresh read finds exactly one match whose fields equal the intended create payload; server-assigned locator bound only now | Fresh read finds **zero** matches (same `ConfirmedAbsent` sentinel as B's precondition, used at the opposite point in the flow) |
| Plan/authorization binding | Existing `PlanAuthorizationV2`/`verify_bindings()`, unchanged | Same, unchanged — the digest just covers a different canonical value | Same, unchanged |
| Confirmation binding | Existing `ConfirmationEvidence`, unchanged | Same, unchanged | Same, unchanged |
| Fresh pre-send verification | Re-read, compare fingerprint to contract | Re-read, re-confirm absence (TOCTOU: another admin could have created it since PREPARE) | Re-read, compare fingerprint to contract (identical to A) |
| pfREST Read Only gate placement | Immediately before `EXECUTING`, after binding verification (Mission III) — but **only inside `execute()`**; verified directly against source that `MutationExecutor.rollback()` does **not** call `_require_pfrest_writable()` at all today. This is presently harmless only because `rollback()` has zero production call sites (nothing wires it to any live MCP tool) | Must independently call the gate before *every* mutating send this class can issue, including the internal reuse of `create()`'s primitive inside `delete()`'s rollback path and vice versa. **Not** "inherited automatically" — the pattern being mirrored (`MutationExecutor`) does not itself demonstrate correct rollback-path gate coverage, so nothing about it can be assumed true by imitation. Because this design makes rollback genuinely reachable for the first time (unlike today's dead `rollback()`), `sealed_existence_executor.md` must explicitly specify and test gate placement on every entry point as its own reviewed requirement, not infer it from `MutationExecutor`'s existing shape | Same explicit, independently-specified requirement as CREATE's column — every entry point, including inverse-transition reuse, crosses the gate before send |
| `EXECUTING` transition placement | After the gate, before the one send | Identical | Identical |
| Sole mutating transport boundary | One `WriteApiClient.send_for_tier1()` call | One call, same client, same chokepoint | One call, same client, same chokepoint |
| Semantic verification | `is_semantically_verified(pre, post, intent)` | Same signature; `pre` is the `ConfirmedAbsent` sentinel, `post` is the newly-read real object | Same signature; `pre` is the real pre-state, `post` is the `ConfirmedAbsent` sentinel |
| Mutation-result-unknown handling | → `RECONCILIATION`, never blind retry | → `RECONCILIATION`; **discover before retry** — never blindly replay the POST (POST is not naturally idempotent; a replay could create a second object). Reconciliation resolution re-reads by natural identity (reusing the existing `observe_reconciliation_target()` pattern, which already re-reads by identity, not locator) — zero matches means the create did not happen; exactly one match means it did (bind its locator now); more than one is genuine ambiguity requiring manual resolution, never auto-picked | → `RECONCILIATION`. Reread first: absence proves the delete succeeded (safe to mark verified even after a transport-ambiguous send); continued existence permits only the explicitly-defined recovery path, never a blind retry; a *read failure* (as opposed to a clean zero-match read) must never be interpreted as absence — it raises and routes to `RECONCILIATION` exactly like today's read-failure handling, never conflated with `ConfirmedAbsent` |
| Recovery classification | `FAILED` (proven zero effect) / `RECONCILIATION` (ambiguous) — unchanged terminal states | Same two terminals, same meanings | Same two terminals, same meanings |
| Replay rules | Never retried automatically (existing) | Never retried automatically; additionally never assumed idempotent (POST) | Never retried automatically; DELETE against an already-absent target is naturally idempotent at the transport level (typically 4xx/zero-effect), which is *why* C's ambiguous-handling can safely treat a clean zero-match reread as proof of success rather than needing discovery machinery |
| Idempotency assumptions | Existing `derive_idempotency_key()` + store uniqueness constraint, unchanged | An in-flight or unresolved create contract for the same natural identity must be discoverable by a *fresh* PREPARE-time precondition check for a second contract attempt — no new mechanism, a direct consequence of "PREPARE only ever binds to a fresh read" | Unchanged from A's existing idempotency posture |
| Audit/journal semantics | `store.transition()`/`_insert_audit()`, unchanged | Same mechanism — `RecoveryState` is already generic over contract lifecycle, not update-specific; no new schema | Same mechanism |

**Rollback/gate invariants (owner amendment pass, 2026-09-04), stated
explicitly rather than left implicit:**

- Every independently callable mutation entry point on
  `ExistenceTransitionExecutor` — `create()`, `delete()`, and each's
  internal reuse of the other's primitive for its own rollback — must
  cross the pfREST writable gate before any network mutation. No entry
  point is exempt by virtue of being "internal" or "rollback."
- Internal reuse of create/delete logic for rollback must not bypass
  that gate, or any other gate below. Rollback is **not** an alternate
  authorization path — it is the same sealed send chokepoint, reached a
  second time under the same rules, not a side door.
- Authorization (plan binding), confirmation binding, replay protection,
  risk-class binding, endpoint binding, and privilege binding remain
  independently required on every path, exactly as they already are for
  `MutationExecutor.execute()` — none of these are satisfied "once" and
  then assumed to hold for a later internal reuse.
- `sealed_existence_executor.md`, when written, must specify gate
  placement explicitly and include a direct test proving every entry
  point (including the rollback-reuse paths) fails closed when
  `read_only=true` — inheriting the placement by assumption from
  `MutationExecutor`'s shape is exactly the mistake this amendment
  corrects, since that shape does not itself prove full coverage (see
  the gate-placement table row above).

This reduces the design surface from "a wholesale new architecture" to
"one new class following an already-proven two-method pattern, one new
adapter Protocol pair, and one new sentinel type (`ConfirmedAbsent`)" —
still real, still security-critical, still not implemented here.

### D2.2 — Execution-shape classification (owner architecture review, re-derived, not assumed from HTTP method)

Per the review's explicit instruction not to assume `POST == CREATE`,
`DELETE == simple deletion`, or `PATCH/PUT == ordinary update`: every one
of the 451 operations was re-classified by inspecting its actual path
semantics (secret/credential involvement and runtime-action framing
checked *before* falling through to a method-informed shape), independently
of the companion report's original cluster-level pass.

**Corrected in a follow-up amendment pass (2026-09-04)** after the first
classification pass's own numbers were themselves found to contain six
misclassified operations — caught only by reading each operation's
actual OpenAPI description text, not by the script's path/method
heuristics alone:

- `DELETE /diagnostics/arp_table` (bare) and `DELETE /system/restapi/access_list`:
  both take only `limit`/`offset`/`query` params, no `id` — genuinely
  bulk/filtered deletes ("Deletes multiple existing ARP Table Entries
  using a query"), moved from Shape C into the bulk bucket. The
  classifier's original plural-path-suffix heuristic missed both since
  neither path segment is plural-spelled; corrected to key on parameter
  shape (presence of an `id`) instead, which is the semantically
  correct signal and was verified against every Shape C row.
- `DELETE /diagnostics/table`: has an `id` param but its description
  reads "Flushes all entries in a specified table. Please note this
  does not delete the table itself, only its entries" — a runtime
  action on live/volatile contents, not a delete of the config resource
  itself; confirms the original classification, now on real evidence
  rather than a path-keyword guess.
- `DELETE /firewall/state` (bare, singular): description explicitly
  states "the firewall state table changes very quickly which may
  result in the state's `id` suddenly changing... use caution" and
  recommends the bulk/query endpoint instead — targets live
  connection-tracking state whose identity can change independent of
  any API action, which structurally breaks Shape C's TOCTOU
  precondition-rebinding model for this specific resource. Moved to
  runtime/action shape.
- `POST /status/service`: description reads "Triggers a start, stop or
  restart action for an existing Service" — a runtime action despite
  the POST method. Moved from Shape B to runtime/action.
- `POST /system/enum`: description reads "Enumerate all possible
  choices for a given model field" — not a mutation at all despite
  appearing in the mutating-methods inventory; a read-like introspection
  query the schema happens to expose via POST. Moved out of Shape B into
  a new, explicit "does not fit" sub-reason (non-mutating anomaly, not
  bulk-shaped) rather than force-classified into any A/B/C/runtime/secret
  bucket.
- `POST /vpn/openvpn/client_export` (bare): description reads "Export
  an OpenVPN Client configuration" — distinct from its sibling
  `/client_export/config` (a stored export-preferences object, ordinary
  CRUD); this bare endpoint is the action that actually emits the
  client bundle, which for OpenVPN client export includes the client's
  private key and certificate. Moved from Shape B to credential/secret-lifecycle.

Full corrected dataset: `mutation_universe_execution_shapes.json`
(scratchpad), produced by the corrected classification script with each
override individually justified in code comments, not merely asserted.

| Execution shape | Count | Notes |
|---|---:|---|
| **A — existing-target update** | 100 | `PATCH`, plus non-bulk single-object `PUT` — unaffected by the correction pass |
| **B — create/absent-to-existing** | 73 | `POST` that is genuinely a create, secret/runtime/non-mutating exclusions removed (net −3 from the correction pass: `status/service`, `system/enum`, `vpn/openvpn/client_export` bare) |
| **C — delete/existing-to-absent** | 75 | `DELETE` on a single, identified object, verified to have a genuine `id`-shaped parameter for every row (net −3: two moved to bulk, one moved to runtime/action) |
| **Runtime/action shape** | 25 | `apply` triggers (8), `halt_system`/`reboot`/`package*`/`update` (5), `ping`/`wake_on_lan` (2), the one `restapi/settings/sync` HA-sync trigger (1), OpenVPN kill-connection/CARP-maintenance-mode/config-history-revert (3), `diagnostics/table` flush (1), `firewall/state` kill (1, corrected), `status/service` start/stop/restart (1, corrected) — net +2 |
| **Credential/secret-lifecycle shape** | 69 | `certificate*`/`certificate_authority*`/`crl*` (22), `user*`/`auth_server*` (14), `auth/key`/`jwt` (4), FreeRADIUS `user` accounts (5), HAProxy frontend `certificate` bindings (4), ACME `certificate*` actions (13) and `account_key*` (6), OpenVPN client-export action (1, corrected) — net +1 |
| **Does not safely fit any currently proposed executor** | 107 | Bulk-delete-all (73, net +2: `arp_table` bare + `restapi/access_list` bare corrected in) + bulk-collection-replace `PUT` (33) + non-mutating schema anomaly (1, `system/enum`, corrected in) — structurally excluded by ADR-014/`sealed_executor.md`'s own G4 invariant ("no adapter-driven loops... every method signature takes one target/one intent") for the bulk subset, and simply out of scope for the non-mutating anomaly; a bulk-operation architecture is out of scope for both `MutationExecutor` and the proposed `ExistenceTransitionExecutor` |
| **Rejected/redundant/source-unsupported** | 2 | `graphql` (`REJECT_GENERIC_DISPATCH`), `diagnostics/command_prompt` (`REJECT_COMMAND_EXECUTION`); no `SOURCE_UNSUPPORTED` operations found this pass (all 451 resolved cleanly against the cached schema); no `REDUNDANT` operations positively identified at this pass's granularity (recorded as an incompleteness, not assumed empty) |
| **Total** | **451** | Every operation accounted for exactly once at this layer; risk/family tags (D3/D5 below) remain orthogonal, layered on top, never double-counted here |

This supersedes both the original companion report's rougher "POST+DELETE
≈ 299 operations, ~66%" estimate and the first (uncorrected)
classification pass's 154-operation figure: the verified count of
operations that actually need the new existence-transition primitive is
**148** (73 + 75, **32.8%** of the inventory) — update+create+delete
together account for **248 operations (55.0%)** of the full 451. A
materially smaller, more precisely scoped gap than the original rough
estimate, because a large share of what looked like create/delete by
HTTP method alone is actually secret-lifecycle, runtime-action,
non-mutating, or bulk-shaped and was never going to fit a two-shape
executor regardless of how CREATE/DELETE themselves were designed.

**The 450/451 privilege-resolution exception, independently re-verified:**
`POST /system/restapi/settings/sync` is the sole operation with no
narrow pfSense privilege (requires `page-all` only). It classifies as
**runtime/action shape**, not create-shaped, confirming it was never a
candidate for `ExistenceTransitionExecutor.create()` in the first place —
this operation remains excluded at the `Capability` enum level (D4)
regardless of which executor architecture is eventually built.

### D3 — Capability families replace "`write_protected` == every implemented WRITE privilege"

`write_protected` must never default to granting every implemented WRITE
family. An installation grants an explicit, named subset of families
(see the companion report's Step 5 table). No pfSense-side privilege
constraint is weakened or widened by this grouping (the privilege-
atomicity finding, Context above). `Capability`/`MutationPolicy`/`MutationRule` require no new
mechanism — only new rule population per family as each family's
adapters are actually built. **A family is a policy/least-privilege
grouping only, never itself an authorization mechanism**: membership in
a granted family determines whether `MutationPolicy.authorize()` has a
matching rule at all, but every other gate downstream of that — sealed
plan/confirmation binding, the fresh precondition re-read, the pfREST
Read Only gate, semantic postcondition verification — still runs in
full for every single call, exactly as it does today for `alias_write`;
no family, however broadly granted, skips or weakens any of these.

**Secret-lifecycle and structural exclusions cannot be overridden by a
broad package/cluster name (owner amendment pass, 2026-09-04).** A
family such as `service_settings_write` may legitimately span an entire
top-level product/package cluster (e.g. FreeRADIUS, HAProxy, ACME) for
its ordinary settings operations, but **operation-level exclusion always
wins over cluster-level family membership**: `services/freeradius/user*`,
`services/haproxy/*/certificate*`, `services/acme/certificate*`, and
`services/acme/*account_key*` remain permanently excluded from
`service_settings_write` (or any family) even though `freeradius`,
`haproxy`, and `acme` are otherwise legitimate family members — see D4's
now-explicit enumeration. Bulk operations (D2.2's "does not fit" bucket)
remain outside the family architecture entirely regardless of which
cluster they belong to, for the same reason they're outside the
executor architecture (ADR-014/`sealed_executor.md` G4). Runtime/action
operations are independently classified from both update/create/delete
shapes and from families — a family granting, say, `dns_write` does not
imply anything about the `services/dns_resolver/apply` runtime-action
trigger, which is a distinct classification requiring its own separate
authorization decision if ever built.

### D4 — Permanent exclusions are never assignable to any family

`system/certificate*`/`certificate_authority*`/`crl*`, `user/*`,
`auth/*`, `diagnostics/command_prompt`, `graphql`,
`system/package*`/`update`/`restapi/access_list`/`restapi/settings/sync`,
`diagnostics/halt_system`/`reboot` remain excluded at the `Capability`
enum level entirely — never merely left out of a default grant. This
matches the existing `WriteEndpoints`-exact-catalogue enforcement
pattern (`scripts/write_allow_list_check.py`) and ADR-036's own
non-negotiable invariant list.

**Extended (owner amendment pass, 2026-09-04)** to close a gap the
earlier list left open: it named only the `system/`, `user/`, `auth/`
prefixed secret-lifecycle operations, but D2.2's own classification
includes 28 further secret-lifecycle operations sharing a top-level
cluster name with an otherwise-legitimate family. Explicitly also
excluded, regardless of `service_settings_write` or any other family's
otherwise-legitimate claim to the same top-level cluster:
`services/freeradius/user`/`users` (5 operations — RADIUS account
credentials); `services/haproxy/frontend/certificate`/`certificates`
(4 operations — TLS certificate bindings); `services/acme/certificate`/
`certificate/action`/`certificate/domain`/`certificate/issue`/
`certificate/renew`/`certificates` (13 operations); `services/acme/
account_key`/`account_key/register`/`account_keys` (6 operations — the
ACME account's own private key). `vpn/openvpn/client_export` (bare, the
credential-emitting export action specifically, not its sibling
`/client_export/config` preferences-object CRUD) is likewise excluded.

### D5 — Risk classification gets a second, explicit dimension

`AuthorizationLevel` (confirmation friction) remains unchanged and
correct as-is. A new, per-*family* (not per-operation) failure-mode tag
set is added for architecture/sequencing decisions: Lockout, Routing
loss, DNS/DHCP outage, Firewall exposure, Credential compromise, VPN
disruption, Cert/key destruction, Service interruption (see companion
report's Step 6 table). No family's ceremony may be weaker than
`alias_write`'s already-live one. Families tagged Lockout or Routing
loss require a documented recovery path that does not itself depend on
the management channel the operation could sever, before
implementation — not designed by this ADR, recorded as a prerequisite.

## Non-negotiable invariants preserved by this decision

**Overlapping with, and extending, ADR-036's own list — not literally
identical (corrected, owner amendment pass, 2026-09-04).** The prior
draft of this section claimed identity with ADR-036's list; that
overclaimed precision. ADR-036's list additionally names two items this
list does not restate verbatim: `read_only` default posture and managed
`read_only` least privilege (both are properties of the default READ-only
profile, orthogonal to this WRITE-programme ADR, and remain untouched by
it) and **"optional stronger TPM/witness assurance"** — this one *is*
directly WRITE-relevant (ADR-036 W0 Gap 1 ties `risk_class` enforcement
to required anchor assurance) and is not restated here by omission, not
by design: this ADR does not alter, weaken, or remove TPM/witness
assurance in any way. It remains exactly as ADR-036 left it — an existing,
optional, `AnchorAssurance`-graded mechanism, constructor-injected into
whichever executor(s) are built (`MutationExecutor` today,
`ExistenceTransitionExecutor` in the future, per its own
`anti_rollback_anchor` parameter, unchanged) — and D5's risk-tagged
families (particularly Lockout/Routing-loss-tagged ones) are exactly the
kind of family where a future, separately-authorized decision to require
`hardware_witness` assurance would be the natural extension of ADR-036's
own W0 Gap 1 pattern. This ADR does not make that decision; it does not
need to, and does not foreclose it either.

Zero
default-reachable WRITE; no generic HTTP/path dispatcher (`graphql`
permanently `REJECT_GENERIC_DISPATCH`); no arbitrary shell/command
capability (`diagnostics/command_prompt` permanently
`REJECT_COMMAND_EXECUTION`); explicit, reviewed `Capability`/
`WriteEndpoints` catalogue only; canonical endpoint/method derivation;
canonical risk-class derivation (D5); canonical privilege derivation
(`resolve_privilege()`, the privilege-atomicity finding); sealed
authorization; confirmation binding; **no MCP caller/agent can select
which endpoint, HTTP method, privilege, risk class, or executor
(`MutationExecutor` vs. `ExistenceTransitionExecutor.create()`/
`.delete()`) a given call reaches** — each registered MCP tool is wired,
at project registration time, to exactly one specific adapter and
exactly one specific executor entry point, identically to how
`alias_write`'s one tool is wired today; nothing about a caller's
arguments ever chooses that binding; the pfREST Read Only owner gate (this session's Mission III,
inherited automatically by every future capability since it lives in
the shared executor(s), not per-adapter); precondition/fingerprint
verification; semantic postcondition verification; bounded recovery;
fail-closed transport-ambiguity handling; least privilege. None of these
are weakened, extended, or reinterpreted by this ADR.

## Consequences

### Positive

- A concrete, falsifiable classification exists for all 451 currently-known
  mutating operations — zero left unclassified — replacing "chase WRITE
  coverage" with a reviewable, bounded programme.
- The existence-transition gap is identified and named before any code
  is written against it, rather than discovered mid-implementation of a
  real capability.
- Capability families give installations genuine least-privilege choice
  once many WRITE capabilities exist, rather than an all-or-nothing
  `write_protected` toggle.

### Negative

- This ADR authorizes no new capability itself — real WRITE surface
  growth still requires, per family/operation, the same one-capability-
  at-a-time rigor `firewall/alias.descr` received (own mission, own LAB
  qualification, own adversarial test matrix).
- The existence-transition executor is real, non-trivial, security-critical
  design work not yet done — 148 operations (32.8% of the inventory, see
  D2.2) remain blocked on it, not on risk classification alone.

## Alternatives considered

- **Extend `MutationExecutor.execute()` in place with a `target_lifecycle`
  branch for create/delete:** rejected — directly contradicts ADR-014's
  own explicit guidance not to weaken the shared executor's guarantees
  to accommodate a shape it wasn't designed for, and would touch the
  live capability's own code path for no benefit to that capability.
- **Amend ADR-036 instead of a successor ADR:** rejected — would blur
  ADR-036's own closed, historically-scoped W0 record (see companion
  report Step 3).
- **`write_protected` grants everything implemented:** rejected —
  becomes unsafe and unreviewable once dozens of families exist; no
  privilege-atomicity reason requires it.
- **Two fully independent executor classes, `CreateMutationExecutor` and
  `DeleteMutationExecutor`, sharing no code:** rejected — each shape's
  rollback is a live instance of the other shape's forward operation, so
  full independence would force either duplicated create/delete-send
  logic (a real, avoidable security-critical duplication risk) or one
  class importing the other, which is worse. See D2.1.
- **One executor with a runtime `direction: CREATE | DELETE` discriminator
  instead of two named methods:** rejected — a mismatched discriminator
  and adapter shape is an avoidable bug class; `create()`/`delete()` as
  distinctly-named, distinctly-typed methods make the shape structural,
  mirroring `MutationExecutor`'s own existing `execute()`/`rollback()`
  pattern rather than inventing a new one. See D2.1.

## Amendment record

Amended 2026-09-04, same day as the initial draft, following an owner
architecture review of this Proposed ADR. Status remains **Proposed** —
the review explicitly declined to accept it. Changes made:

1. D2 refined from a provisionally-named, unspecified "second sealed
   executor" into a concretely-designed `ExistenceTransitionExecutor`
   with named `create()`/`delete()` methods, full precondition/
   postcondition/binding algebra per shape (D2.1), and explicit
   ambiguous-result/replay/idempotency rules distinguishing CREATE
   (discover-before-retry, not idempotent) from DELETE (reread-first,
   naturally idempotent, read-failure ≠ absence).
2. D2.2 added: exact execution-shape classification (not HTTP-method-based)
   replacing the original ~66%/299-operation estimate with a precise
   154-operation (34%) figure for what genuinely needs the new
   executor, and separating out runtime-action (23), secret-lifecycle
   (68), and bulk-shaped-and-out-of-scope (104) operations that had been
   folded into the rougher estimate.
3. Two additional rejected alternatives recorded (two independent
   executor classes; a runtime direction-discriminator flag).
4. Context section's gap-size claim corrected to match D2.2.

No change to D1, D3, D4, D5, or the non-negotiable invariants list in
this first pass — the owner re-review that followed this amendment
found concrete, fixable issues in exactly those sections, addressed in
the second amendment pass below.

### Second amendment pass (2026-09-04, narrow, following the owner acceptance re-review)

The re-review's decision was REVISE, not ACCEPT, with a minimum required
amendment set. All five items were addressed:

1. **D2.1 pfREST gate-inheritance claim corrected.** Verified directly
   against `executor.py` source that `MutationExecutor.rollback()` does
   not call `_require_pfrest_writable()` (only `execute()` does) —
   presently harmless only because `rollback()` has zero production call
   sites. The prior "identical placement, inherited automatically"
   wording is replaced with an explicit statement that this must be
   independently specified and tested for every `ExistenceTransitionExecutor`
   entry point, not assumed from `MutationExecutor`'s own shape. Five
   explicit rollback/gate invariants added.
2. **D4 secret-lifecycle exclusions extended** to name all 28 previously-
   unlisted operations (`services/freeradius/user*`,
   `services/haproxy/*/certificate*`, `services/acme/certificate*`/
   `*account_key*`) and D3 gained explicit wording that operation-level
   exclusion always wins over cluster-level family membership, even for
   families spanning an entire product/package (FreeRADIUS/HAProxy/ACME).
3. **Stale "~2/3"/"roughly two-thirds" figures corrected** in Context,
   Consequences > Negative, and (separately) `docs/adr/README.md`'s
   index row, to match D2.2's verified 148-operation/32.8% figure.
4. **"Identical to ADR-036's own list" corrected** to acknowledge
   overlap-not-identity, and TPM/witness assurance explicitly addressed
   (unchanged, out of scope for this ADR, remains available for a future
   risk-tagged-family decision per ADR-036's own W0 Gap 1 pattern).
5. **Classification defects corrected at the data level**, not merely
   caveated: re-inspecting each flagged operation's actual OpenAPI
   description text (not just path/method shape) found and fixed six
   misclassified operations (`diagnostics/arp_table` bare,
   `system/restapi/access_list` bare, `firewall/state` bare,
   `status/service`, `system/enum`, `vpn/openvpn/client_export` bare).
   The classifier's DELETE bulk-detection rule was corrected from a
   plural-path-suffix heuristic to the semantically correct signal
   (presence of an `id`-shaped parameter), verified against every Shape
   C row (zero remaining rows lack an `id`). D2.2's full table, the
   148-operation gap figure, and every dependent count/percentage were
   re-derived from the corrected dataset, not patched by hand.

No further amendment required to D1 or D5 — the re-review found no fault
with either.

## Acceptance record

**2026-09-04, owner.** A clean acceptance review (not another exploratory
pass) independently re-read this ADR in full, ADR-036's relevant
invariants, ADR-014's sealed-executor-evolution language, current
`MutationExecutor.execute()`/`rollback()`, the `AnchorAssurance`/
`anti_rollback_anchor` interfaces, and the corrected classification
evidence — verifying every claim against source rather than trusting the
prior amendment passes' own summaries. One editorial-only issue found and
fixed (a stray "diagnostics/" prefix on two `firewall/state` references
in D2.2/Amendment record — not a normative claim, corrected narrowly).
All 26 stated acceptance criteria passed on independent verification,
including: the 451-operation total, the 100/73/75/25/69/107/2
execution-shape counts, the 148-operation/32.8% CREATE+DELETE gap, the
248-operation/55.0% update+create+delete total, correct bulk/runtime
classification of `/diagnostics/arp_table` and `/diagnostics/table`,
secret-lifecycle exclusion completeness and its precedence over
cluster-level family membership, the pfREST Read Only gate invariant's
explicitness for every future `ExistenceTransitionExecutor` entry point
(including rollback-reuse), rollback's status as the same sealed
chokepoint rather than an alternate authorization path, preserved
TPM/hardware-witness assurance (independently confirmed against
`security_discovery.py`'s real `AnchorAssurance.HARDWARE_WITNESS`), and
ADR-036's historical W0 scope remaining fully intact and untouched. No
genuinely blocking contradiction was found. Status changed from Proposed
to **Accepted** on this basis — architecture only, per the Status line
above; every deferred item (`sealed_existence_executor.md`, per-cluster
schema qualification, bulk-operation architecture, lockout-safe recovery
design, and any real capability's own LAB qualification) remains exactly
as deferred as it was before acceptance, each requiring its own separate
authorization before implementation.

## References

- [ADR-014](ADR-014-sealed-executor-interface.md)
- [ADR-033](ADR-033-pfsense-least-privilege-bootstrap-architecture.md)
- [ADR-036](ADR-036-tier1-write-safety-contract.md)
- `reports-ai/WRITE_PROGRAMME_ARCHITECTURE_2026-09-04.md` (gitignored,
  external — the full inventory/classification/family/risk analysis
  this ADR summarizes)
- `reports-ai/POST_READ_CLOSURE_WRITE_ARCHITECTURE_THREAT_MODEL.md`
  (gitignored, external — ADR-036's own companion report, re-verified
  and extended by this ADR's companion report)
