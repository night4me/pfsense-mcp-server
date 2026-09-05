# Tier 1 — Shape-A batch-manifest ceremony

Status: mechanism implemented for **both** authorization and confirmation
signing — `ShapeABatchManifest`/`ShapeABatchOwnerApproval`/
`sign_authorization_batch_command()`/`sign-authorization-batch`, and
`ShapeAConfirmationBatchManifest`/`ShapeAConfirmationBatchOwnerApproval`/
`sign_confirmation_batch_command()`/`sign-confirmation-batch`. Restoration
batching is **not implemented** — see "Restoration semantics". No real
signing has occurred under this mechanism against production evidence;
everything below is proven with synthetic keys/evidence in tests only.

Related: `ADR-037` (Batch-1 write capabilities), `ADR-022` (execution
authorization boundary), [anchor_evidence_export_trust_boundary.md](anchor_evidence_export_trust_boundary.md)
(the discovery mechanism this ceremony reuses unmodified),
`src/pfsense_mcp/tier1/shape_a_batch_manifest.py`,
`src/pfsense_mcp/tier1/shape_a_confirmation_batch_manifest.py` (both pure
schema/canonicalization, no signing-crypto imports, so both stay under
`src/pfsense_mcp/tier1/`), `signing/shape_a_batch_owner_approval.py`,
`signing/shape_a_confirmation_batch_owner_approval.py` (both need
`security_authorization`/`security_authorization_verifier`, so both live
under `signing/` instead — see §2b's "Why this lives in signing/" note),
`signing/write_batch1_signing.py`.

## Background — the incident this responds to

2026-09-05: Round-1 Batch-1 authorization signing required five separate,
literal, interactively-typed `yes` responses — one full review-and-approve
ceremony per capability, even though all five previews shared one
`requested_plan_digest`/`requested_step_id` (one security-posture check
governs the whole batch by construction — see `sign_authorization_preview()`'s
own re-derivation-and-cross-check logic, unchanged). The owner's own explicit
direction: future homogeneous batches are expected to contain 20–50 WRITE
capabilities, and repeating that ceremony once per capability does not scale.
The instruction was explicit that human authorization must not be removed —
only its *granularity* changes, from capability-by-capability approval to
exact-batch approval.

A first implementation (commit `068a25a`) built `ShapeABatchManifest` with a
"digest for display/audit only" and no cryptographic link from an individual
signed `PlanAuthorizationV2` back to the batch it was approved as part of. A
second owner review of that commit identified this as a real gap — see
"Independent review of 068a25a" below — which §2b closes.

## 1. TTL / authorization-lifecycle findings (owner's seven questions)

These were established by direct reading of
`src/pfsense_mcp/tier1/write_execution_core.py`,
`src/pfsense_mcp/security_plan_freshness.py`, and
`src/pfsense_mcp/security_authorization_verifier.py` — not assumed.

1. **Where is `PlanAuthorizationV2` expiry checked?** Exactly once, inside
   `authorize_and_create()`: `authorization.issued_at <= now < authorization.expires_at`.
   No other function in `write_execution_core.py` re-derives this check
   against the live `PlanAuthorizationV2` object.
2. **Does `authorize_and_create()` accept a still-valid authorization into a
   persistent PREPARED contract?** Yes. On success it copies
   `authorization.issued_at`/`authorization.expires_at` verbatim into the new
   `RecoveryContract`'s `AuthorizationProvenance` (fields
   `authorization_issued_at`/`authorization_expires_at`), and separately caps
   the contract's own `expires_at = min(now + self._contract_validity,
   authorization.expires_at)`.
3. **Does later expiry of the original authorization matter once admitted to
   PREPARED?** The raw `PlanAuthorizationV2` object is not reinspected after
   admission — but its *copied* timestamps are: both `confirm_and_handoff()`
   and `resume_prepared()` re-check `now` against the same
   `authorization_issued_at`/`authorization_expires_at` window stored in
   `AuthorizationProvenance`. **PREPARED admission does not reset or extend
   the deadline.** Confirmation must still land before the *original*
   authorization's `expires_at`.
4. **Must confirmation occur before authorization expiry, or only admission
   into PREPARED?** Both, transitively — admission requires the check in (1),
   and confirmation independently re-checks the same window copied in (2).
   There is no path that admits after expiry, and no path that confirms after
   the copied `expires_at` even if admission happened earlier.
5. **What must be replaced/archived/consumed before retrying expired
   authorizations?** Nothing needs archiving — an authorization that was
   never passed to `authorize_and_create()` leaves no trace in any persistent
   store; it simply becomes unusable JSON on disk. A fresh
   `PlanAuthorizationV2` (new `authorization_id`, fresh `issued_at`/
   `expires_at`) can be signed against the same untouched preview at any time,
   provided the freshly re-derived plan digest still matches. See §8 for the
   full retry-semantics writeup this finding grounds.
6. **Can the five untouched previews safely receive fresh authorizations
   with new IDs/timestamps if bindings/posture remain valid?** Yes — nothing
   in `sign_authorization_preview()` or `authorize_and_create()` binds a
   preview to a specific prior `authorization_id`; the preview is immutable
   input, re-verified fresh (integrity MAC, plan-digest cross-check) on every
   signing attempt.
7. **Is the current 5-minute TTL appropriate if admission is immediate?**
   No single universal number is — the constant exists to substitute for a
   freshness recheck that `confirm_and_handoff()` does **not** perform (only
   `authorize_and_create()` calls `_plan_is_fresh()`); a wider TTL trades a
   longer window of "posture might have silently changed since signing" for
   the ability to complete a large batch during one realistic human ceremony.
   This directly motivates §4's separate constant for the batch path only —
   the existing single-capability path is unaffected.

**Conclusion driving the design below:** none of `MutationExecutor`,
`write_execution_core.py`, or `executor.py` need to change. The batch problem
is entirely a signer/ceremony-layer UX problem — the per-capability
`PlanAuthorizationV2` verification, binding, and freshness semantics are
untouched and individually re-verifiable exactly as before.

## 2. Batch-manifest schema and canonicalization

`ShapeABatchManifest` (`shape_a_batch_manifest.py`) is a **derived, read-only,
non-cryptographically-signed** view over N already-integrity-verified
`ShapeAAuthorizationPreview` objects. It is never a new source of truth and
never itself authorizes anything — approving it only triggers the *existing*
per-capability signing path (`sign_authorization_preview()`), once per
capability, exactly as it already worked. (`ShapeAConfirmationBatchManifest`
is its confirmation-side mirror — see §6.)

Fields: `schema_version` (`SHAPE_A_BATCH_MANIFEST_SCHEMA_VERSION = 1`),
`batch_id` (caller-supplied, random per invocation —
`batch-{secrets.token_hex(16)}`), `capability_symbols` (canonical sorted
order), `entries` (one `ShapeABatchManifestEntry` per capability:
`capability_symbol`, `execution_intent_digest`, `semantic_fields`),
`requested_plan_digest`, `requested_step_id`, `target_capability_posture`,
`target_anchor_assurance` — the last four values are hoisted once, since
homogeneity is a **construction invariant**, not merely a display fact:

- **Non-empty, explicit input only.** No `--all-registered` equivalent
  anywhere in the batch construction or CLI path. `capabilities` must be a
  finite, caller-supplied list.
- **No duplicates.** Refused before any other check.
- **Homogeneity required.** Every preview must share the exact same
  `requested_plan_digest`, `requested_step_id`, `target_capability_posture`,
  and `target_anchor_assurance`, or the whole manifest construction is
  refused. This is deliberate, not a limitation to lift later — it is what
  makes "one posture check governs the whole batch" true rather than merely
  displayed.
- **Canonical ordering.** Always sorted by `capability_symbol`, computed by
  the manifest builder, regardless of input order — so re-ordering the input
  list can never change what is reviewed, signed, or digested.
- **Bounded size.** `_MAX_BATCH_SIZE = 200` — comfortably above the owner's
  stated 20–50 capability range, refused beyond that as a sanity bound, not a
  tuned production limit.
- **Deterministic digest.** `compute_shape_a_batch_manifest_digest()` is a
  domain-separated SHA-256 over the canonical JSON payload
  (`_MANIFEST_DIGEST_DOMAIN = b"pfsense-mcp-shape-a-batch-manifest-v1\0"`),
  which now feeds directly into `ShapeABatchOwnerApproval`'s own signed
  payload (§2b) — no longer display/audit only.

## 2b. Cryptographic batch-owner-approval binding

**Independent review of `068a25a` — primary finding.** That commit's own
report described the manifest digest as "for display/audit only." Direct
inspection confirmed this was a real gap: `PlanAuthorizationV2`'s signed
payload (`build_plan_authorization_v2_payload()`) contains no `batch_id`,
`manifest_digest`, or any other field naming which batch (if any) the owner
approved before this specific artifact was signed. The only link was
procedural — "the signer loop produced this after the prompt" — which a
verifier examining artifacts after the fact, without having watched the
signer run, cannot check at all. The rest of `068a25a`'s design (homogeneity,
canonical ordering, fail-closed missing/already-signed handling,
`expected_execution_intent_digest` defense in depth) had no defects found on
review; only this one property was missing.

**Fix: `ShapeABatchOwnerApproval`** (`shape_a_batch_owner_approval.py`). The
binding mechanism uses a field `PlanAuthorizationV2` already has —
`authorization_id` — rather than evolving that shared, already-shipped
schema:

1. Before the owner is shown the manifest review, the signer pre-generates
   one `authorization_id` per capability (`authz-{secrets.token_hex(16)}`) —
   these are never shown to the owner (they are meaningless random tokens,
   not reviewable content) and never regenerated afterward.
2. On the owner's single `yes`, `build_shape_a_batch_owner_approval_payload()`
   builds a payload committing, under one signature, to the exact
   `(capability_symbol, execution_intent_digest, authorization_id)` triple for
   every capability, plus `manifest_digest` — **independently recomputed from
   the manifest itself**, never accepted as a caller-supplied value, so a
   caller cannot forge approval for content that was never actually built via
   `build_shape_a_batch_manifest()`.
3. The payload is signed with the same authorization authority/private key
   used for the individual `PlanAuthorizationV2` artifacts — one trust root
   for the whole ceremony — producing a `ShapeABatchOwnerApproval`, written to
   `<artifact_base_directory>/_batches/<batch_id>/batch-owner-approval.json`.
4. Each capability's `PlanAuthorizationV2` is then signed using the
   **pre-committed** `authorization_id` (via `_one_authorization()`'s new
   `authorization_id` parameter), never a freshly regenerated one.

**The resulting proof.** `verify_plan_authorization_v2_batch_membership(authz,
approval, capability_symbol=..., authorities=...)` returns `True` only if:
`approval`'s own signature verifies; `authz`'s own signature verifies
(`verify_plan_authorization_v2_signature()`, unchanged); `approval` has
exactly one entry for `capability_symbol`; that entry's `authorization_id`
equals `authz.authorization_id` (itself one of `authz`'s own signed-payload
fields); and `approval.requested_plan_digest == authz.plan_digest`. Because
both signatures come from the same authority key, an attacker cannot forge
either half independently, and a genuinely-signed authorization from one
batch's approval can never satisfy membership against a *different* batch's
approval — that approval's own signature simply does not cover this
authorization's `authorization_id` at all (proven by
`test_authorization_from_one_batch_does_not_satisfy_a_different_batchs_approval`
and the unit-level
`test_batch_membership_false_for_cross_batch_authorization_insertion`).

**What this still is not.** Not a new source of authorization — a verifier
still independently re-checks each `PlanAuthorizationV2`'s own signature,
freshness, plan-digest match, and risk-class binding exactly as before; batch
membership is one additional fact a verifier *can* check, never a substitute
for any existing one. Not consumed by `authorize_and_create()`/
`confirm_and_handoff()` at all — `write_execution_core.py` remains completely
unaware this artifact type exists.

## 3. Owner-review semantics (authorization batch)

`sign_authorization_batch_command(capabilities)`:

1. Validates the capability list (non-empty, no duplicates, each registered)
   — fails closed before touching any file.
2. Loads every named preview, refusing the **whole batch** if any preview is
   missing or if any capability already has a signed
   `authorization-inbox.json` — there is no partial-batch admission.
3. Builds the manifest (`build_shape_a_batch_manifest()`), which independently
   re-derives and enforces canonical order and homogeneity.
4. Shows `render_shape_a_batch_manifest_review()` — every capability, its
   `execution_intent_digest`, its semantic fields, the manifest digest, and
   the shared plan digest/step id/posture/assurance targets — and asks for
   **exactly one** literal `yes` (`_prompt_operator_approval()`, unchanged
   function, unchanged literal-string requirement — no
   `--yes`/`--force`/unattended flag exists or may be added).
5. On refusal, returns without signing anything.
6. On approval: pre-generates the N `authorization_id`s, builds and signs the
   `ShapeABatchOwnerApproval` (§2b) and writes it to disk, then builds the
   export-based `SecurityPostureDiscovery` **once** (not once per capability —
   see §5, threat 8) and signs each capability's `PlanAuthorizationV2` via the
   unchanged `_one_authorization()` body, now called with
   `require_approval=False` (no second prompt),
   `validity=_BATCH_AUTHORIZATION_VALIDITY` (§4), the shared `discovery`, the
   pre-committed `authorization_id`, and `expected_execution_intent_digest`
   bound to what the owner actually saw in the manifest (§5, threat 4).

The ordinary single-capability `sign-authorization` path
(`sign_authorization_command()` → `_one_authorization()` with all new
parameters at their defaults) is **unmodified**: default
`require_approval=True`, default `validity=_AUTHORIZATION_VALIDITY` (5
minutes, shared with `alias_description_signing.py`), no expected-digest
check, no pre-committed `authorization_id` (a fresh random one is generated,
exactly as before). `test_ordinary_single_capability_path_is_unaffected`
proves this.

## 4. The batch TTL constant

`_BATCH_AUTHORIZATION_VALIDITY = timedelta(minutes=30)` — a separate constant
from `_AUTHORIZATION_VALIDITY = timedelta(minutes=5)`, used **only** by the
two batch commands. **Re-derived** from the original `timedelta(hours=1)`
after confirmation batching (§6) was implemented:

The 1-hour value was originally chosen under the assumption that confirming a
50-capability batch might still require up to 50 separate manual confirmation
ceremonies — the exact bottleneck this whole redesign exists to remove.  Now
that `sign_confirmation_batch_command()` exists, confirming the whole batch is
itself one owner review, not N. The realistic end-to-end window between a
batch authorization's `yes` and the corresponding batch confirmation's `yes`
is: one batch-authorization review (seconds) + N individually scriptable
`authorize_and_create()` admission calls (non-ceremonial — no human review
point, since that already happened at signing time, so an operator can loop
them) + one batch-confirmation review (a few minutes to read, comparable in
order of magnitude to reading one preview). 30 minutes is a deliberately
narrower, still-generous value for that reduced scope — not a value derived
from a formal timing model (no more than the original 5-minute single-capability
constant was), but a considered reduction now that the N-manual-ceremonies
case it originally hedged against no longer exists. The existing 5-minute
single-capability path is completely untouched by this change.

## 5. Threat / failure analysis

Each item states the attack/failure and the mechanism that fails it closed,
with the proving test named where one exists.

1. **Substitution of one capability after approval.** Not reachable —
   `manifest.capability_symbols` is fixed at manifest-construction time
   (before the prompt); the signing loop iterates exactly that tuple. There
   is no code path that re-reads the CLI's `capabilities` argument after the
   prompt. `ShapeABatchOwnerApproval`'s own signature additionally makes this
   cryptographically checkable after the fact (§2b).
2. **Removal/addition/reordering attacks.** Reordering the input list cannot
   change canonical order (§2, `test_canonical_ordering_is_independent_of_input_order`).
   Adding a capability requires a brand new `sign_authorization_batch_command()`
   invocation — a new manifest, a new review, a new `yes`. Both manifest and
   approval dataclasses are frozen (`test_manifest_is_frozen`).
3. **Projection substitution** (the *content*, i.e. `semantic_fields`, of what
   a capability would do changes between manifest build and signing). The
   manifest digest — now cryptographically bound via `ShapeABatchOwnerApproval`
   — covers `semantic_fields` (`test_digest_changes_when_a_capability_projection_changes`);
   `execution_intent_digest` is the field actually enforced at signing time
   via `expected_execution_intent_digest`/`hmac.compare_digest()` inside
   `_one_authorization()` (see (4)).
4. **execution_intent_digest substitution.**
   `test_one_authorization_rejects_a_substituted_execution_intent_digest`
   proves a mismatch raises `SigningError` and signs nothing for that
   capability.
5. **Batch digest changed.** Any change to `manifest_digest`, `batch_id`, or
   any entry's `authorization_id`/`execution_intent_digest` breaks
   `ShapeABatchOwnerApproval`'s own signature
   (`test_verify_fails_when_a_signed_field_is_tampered`,
   `test_verify_fails_when_an_entry_authorization_id_is_tampered`).
6. **Authorization from Batch A inserted into Batch B.**
   `test_authorization_from_one_batch_does_not_satisfy_a_different_batchs_approval`
   proves a genuinely-signed authorization from batch A's approval fails
   `verify_plan_authorization_v2_batch_membership()` against batch B's
   approval — the different approval's own signature does not cover that
   `authorization_id` at all.
7. **Confirmation from Batch A inserted into Batch B.**
   `test_evidence_from_one_batch_does_not_satisfy_a_different_batchs_approval`
   proves the confirmation-side mirror of (6).
8. **Replay of an old batch approval.** Each `sign_authorization_batch_command()`
   call builds a fresh manifest with a fresh random `batch_id` and prompts a
   fresh literal `input()` call — there is no code path anywhere that accepts
   a previously-produced `ShapeABatchOwnerApproval` file as authorization to
   skip the prompt or to sign additional/different capabilities; the CLI only
   ever *writes* this artifact, never reads one back in as an input.
9. **Expired authorization replaced with fresh authorization without a fresh
   `yes`.** `test_expired_authorization_cannot_be_replaced_without_a_fresh_yes`
   proves that even a caller attempting `require_approval=False` directly
   cannot overwrite an existing `authorization-inbox.json` — the file's mere
   presence refuses the write (`write_secure_new()`'s `O_EXCL` discipline),
   regardless of whether the existing artifact has since expired.
10. **Signer crash midway through N artifacts / retry after partial output.**
    Each `_one_authorization()` call is independently atomic; a retry with the
    *original full* list is refused (`already exists`); the documented safe
    retry is a fresh, smaller batch of only the still-pending capabilities —
    `test_partial_retry_is_safe_with_only_the_remaining_capabilities` proves
    both halves. See §8 for the full retry-semantics writeup.
11. **One output tampered after batch signing.**
    `test_tampering_a_signed_authorization_after_batch_signing_breaks_its_signature`
    proves a post-signing edit to any signed field breaks
    `verify_plan_authorization_v2_signature()`.
12. **Stale posture evidence during a batch.**
    `test_stale_posture_during_batch_fails_the_whole_batch_before_any_signature`
    proves a stale/tampered preview fails the whole batch closed (via the
    preview's own integrity-MAC or plan-digest cross-check, either of which
    refuses before any signature is produced), not partway through.
13. **Witness changes during a batch.** The shared `discovery` is built
    exactly once per batch invocation
    (`test_shared_discovery_is_built_exactly_once_per_batch`), before the
    signing loop begins — every capability in one approved batch sees the
    identical posture snapshot, so a witness value that changed mid-batch
    cannot produce inconsistent postures within one approval.
14. **Mixed risk classes / mixed `requested_plan_digest` / mixed target
    posture/anchor assurance.** Impossible by construction —
    `build_shape_a_batch_manifest()` refuses any batch whose previews do not
    share one `requested_plan_digest`/`requested_step_id`/
    `target_capability_posture`/`target_anchor_assurance`
    (`test_refuses_heterogeneous_batch`, parametrized over all four fields);
    `risk_class` is itself derived from `plan.steps`, so one shared
    `requested_step_id` implies one shared risk class.
15. **Duplicate capability entries.** Refused explicitly before any preview is
    even loaded (`test_refuses_duplicate_capability_symbol`,
    `test_batch_refuses_duplicate_capability_in_the_list`).
16. **Partial admission into PREPARED state.** Out of scope for this ceremony
    — `authorize_and_create()` is a separate, later, per-capability step this
    module never calls. Nothing here creates or touches a `RecoveryContract`.

## 6. Confirmation batch semantics — implemented

`ShapeAConfirmationBatchManifest`/`ShapeAConfirmationBatchOwnerApproval`
(`shape_a_confirmation_batch_manifest.py`/
`shape_a_confirmation_batch_owner_approval.py`) mirror §2/§2b exactly, with
one deliberate difference in homogeneity predicate and binding mechanism:

**Homogeneity is `expected_authority_id`/`expected_algorithm` only** — never a
shared digest. Unlike authorization previews, pending confirmation requests
have no equivalent shared fact: each is intrinsically bound to its own
already-created `RecoveryContract` (own `contract_id`/`operation_id`/
`intent_digest`), and these are never expected to match across capabilities
even within one homogeneous batch.

**Binding uses pre-existing identifiers, not a pre-generated one.** Unlike
`PlanAuthorizationV2.authorization_id` (signer-generated, so it can be
pre-committed before the prompt), `ConfirmationEvidence.contract_id`/
`operation_id` are never chosen by the signer — they already exist on the
already-created `RecoveryContract`, read unchanged from the pending request on
disk. `ShapeAConfirmationBatchOwnerApproval`'s signed payload therefore
commits directly to the exact `(capability_symbol, contract_id, operation_id,
intent_digest)` tuple for every capability, rather than to a pre-generated ID.
`verify_confirmation_evidence_batch_membership()` is the exact mirror of
`verify_plan_authorization_v2_batch_membership()` (§2b), proven by
`test_every_produced_evidence_satisfies_batch_membership_against_its_own_approval`
and `test_evidence_from_one_batch_does_not_satisfy_a_different_batchs_approval`.

`sign_confirmation_batch_command(capabilities)` mirrors §3 exactly: refuses
the whole batch on any missing/already-signed pending request, builds and
reviews the manifest, requires exactly one `yes`, signs and writes the batch
owner approval, then loops `_one_confirmation()` with
`require_approval=False` and the three `expected_contract_id`/
`expected_operation_id`/`expected_intent_digest` defense-in-depth checks
(mirroring `_one_authorization()`'s `expected_execution_intent_digest`). The
ordinary single-capability `sign-confirmation` path
(`sign_confirmation_command()`) is unmodified —
`test_ordinary_single_capability_confirmation_path_is_unaffected` proves this.

This closes the gap the owner explicitly flagged in the prior pass ("do not
merely move the 20–50 manual-approval bottleneck from authorization to
confirmation") — confirming a 50-capability batch is now also exactly one
owner review.

## 7. Restoration semantics — deferred

Restoration remains, unconditionally, a separate owner decision derived from
fresh, observed post-mutation state — this ceremony does not, and must not,
pre-authorize unknown restoration intents as part of a mutation batch. A
future restoration batch may reuse this same one-review/one-`yes` pattern
once its exact, fresh intents are known and reviewable, following the same
manifest/digest/homogeneity/cryptographic-binding discipline documented above
— but building that manifest type is out of scope until a real restoration
scenario defines what its homogeneity predicate should be.

## 8. Retry semantics for expired/partial batch artifacts — explicit answers

Answering the owner's five specific sub-questions directly, grounded in §1's
findings and the fail-closed design of both batch commands:

1. **Are expired artifacts archived, atomically replaced, or consumed?**
   None of the three. An authorization/confirmation that was never passed to
   `authorize_and_create()`/consumed downstream leaves no trace in any
   persistent store — it simply becomes inert JSON on disk. Nothing in this
   codebase automates moving, renaming, or deleting it (deliberately — "do
   not simply delete security artifacts ad hoc"); §414's stale-vs-fresh
   messaging (`_describe_existing_authorization()`/
   `_describe_existing_confirmation()`) tells an operator which case they are
   looking at without ever mutating the file.
2. **How is accidental overwrite of a still-valid authorization prevented?**
   `write_secure_new()`'s `O_EXCL` — a create-only open that fails if the
   target already exists — makes overwrite structurally impossible, expired
   or not; `test_expired_authorization_cannot_be_replaced_without_a_fresh_yes`
   proves this holds even against a caller that supplies
   `require_approval=False` directly.
3. **How can stale and fresh artifacts never be confused?** Every artifact
   carries its own `issued_at`/`expires_at`; a verifier must always
   independently recompute freshness (mirroring `authorize_and_create()`'s own
   `_plan_is_fresh()`/expiry check) rather than trust file presence alone. The
   stale-vs-fresh messaging (item 1) surfaces this at the CLI layer too.
4. **How is partial prior batch output detected?** The precondition check in
   both `sign_authorization_batch_command()` and
   `sign_confirmation_batch_command()` refuses the **whole** batch if *any*
   named capability already has a signed artifact — there is no partial
   admission, so a retry with the original full list always surfaces partial
   completion immediately as a refusal rather than silently re-approving the
   already-done subset.
5. **How does a retry receive a new batch/review identity, and how can
   retries never replay an old owner approval?** Every invocation of either
   batch command generates a fresh random `batch_id`
   (`secrets.token_hex(_BATCH_ID_BYTES)`) and requires a fresh literal
   `input()` call — there is no persisted approval token, session, or flag
   that could be replayed across invocations; the owner's `yes` exists only
   as one function call inside one process's lifetime.

The five real Round-1 `authorization-inbox.json` artifacts (`fb48b55`-era,
signed under the pre-batch single-capability ceremony) were never passed to
`authorize_and_create()` and have since passed their original 5-minute
`expires_at`; per (1) above, nothing in this pass touched, archived, or
replaced them — they remain exactly as the owner's prior "allow them to
expire naturally" instruction left them.
