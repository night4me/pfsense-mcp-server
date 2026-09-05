# Tier 1 — Shape-A batch-manifest ceremony

Status: mechanism implemented for authorization signing only
(`ShapeABatchManifest`, `sign_authorization_batch_command()`,
`sign-authorization-batch` CLI subcommand). Confirmation-side batching is
**design-only** in this document — not implemented, see "Confirmation batch
semantics" below for why it is deferred. Restoration batching is likewise
**not implemented** — see "Restoration semantics".

Related: `ADR-037` (Batch-1 write capabilities), `ADR-022` (execution
authorization boundary), [anchor_evidence_export_trust_boundary.md](anchor_evidence_export_trust_boundary.md)
(the discovery mechanism this ceremony reuses unmodified),
`src/pfsense_mcp/tier1/shape_a_batch_manifest.py`,
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
   provided the freshly re-derived plan digest still matches.
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
   This directly motivates §3's separate, wider constant for the batch path
   only — the existing single-capability path is unaffected.

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
capability, exactly as it already worked.

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
  used only for audit/display (shown in the owner review text) — it is never
  an HMAC/signature pre-image for any other artifact type, so a plain
  domain-separated hash is sufficient (mirrors `anchor_evidence_export.py`'s
  own literal-domain-string precedent rather than extending the shared
  `tier1.canonical.DigestPurpose` enum for one narrow, non-cryptographic use).

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
6. On approval, builds the export-based `SecurityPostureDiscovery` **once**
   (not once per capability — see §5, threat 8) and signs each capability's
   `PlanAuthorizationV2` via the unchanged `_one_authorization()` body, now
   called with `require_approval=False` (no second prompt),
   `validity=_BATCH_AUTHORIZATION_VALIDITY` (§4), the shared `discovery`, and
   `expected_execution_intent_digest` bound to what the owner actually saw in
   the manifest (§5, threat 4).

The ordinary single-capability `sign-authorization` path
(`sign_authorization_command()` → `_one_authorization()` with all new
parameters at their defaults) is **unmodified**: default
`require_approval=True`, default `validity=_AUTHORIZATION_VALIDITY` (5
minutes, shared with `alias_description_signing.py`), no expected-digest
check. `test_ordinary_single_capability_path_is_unaffected` proves this.

## 4. The batch TTL constant

`_BATCH_AUTHORIZATION_VALIDITY = timedelta(hours=1)` — a separate constant
from `_AUTHORIZATION_VALIDITY = timedelta(minutes=5)`, used **only** by
`sign_authorization_batch_command()`. Rationale, tied to §1's findings: the
window must cover (a) the manifest review itself (seconds, even for a
50-capability batch) and (b) a realistic human-paced interval for each
resulting `PlanAuthorizationV2` to reach `authorize_and_create()` and, from
there, `confirm_and_handoff()` — both of which re-check the **same**
`issued_at`/`expires_at` this signing step assigns, never extended later. One
hour is a deliberately generous, conservative choice for a first
implementation, not a value derived from a formal model — the existing
5-minute single-capability path is completely untouched, so this choice
carries no risk to it.

## 5. Threat / failure analysis

Each item states the attack/failure and the mechanism that fails it closed.

1. **Substitution of one capability after approval.** Not reachable —
   `manifest.capability_symbols` is fixed at manifest-construction time
   (before the prompt); the signing loop iterates exactly that tuple. There
   is no code path that re-reads the CLI's `capabilities` argument after the
   prompt.
2. **Removal/addition/reordering attacks.** Reordering the input list cannot
   change canonical order (§2). Adding a capability requires a brand new
   `sign_authorization_batch_command()` invocation — a new manifest, a new
   review, a new `yes`. Removing one from an in-progress batch is not
   possible mid-invocation (no interactive per-capability skip exists in the
   batch path).
3. **Projection substitution** (the *content* of what a capability would do
   changes between manifest build and signing). Guarded by
   `expected_execution_intent_digest`: each capability's own
   `execution_intent_digest`, captured in the manifest at approval time, is
   compared via `hmac.compare_digest()` against the freshly reloaded preview
   file's own digest inside `_one_authorization()`. A mismatch raises
   `SigningError` and signs nothing for that capability —
   `test_one_authorization_rejects_a_substituted_execution_intent_digest`
   proves this.
4. **execution_intent_digest substitution** — same mechanism as (3); this is
   the field the check binds against directly.
5. **Replay of an old batch approval.** Each `sign_authorization_batch_command()`
   call builds a fresh manifest with a fresh random `batch_id`; the manifest
   itself is never persisted or reusable across process invocations — there
   is no "replay this approval" code path, since the approval only exists as
   one `input()` call inside one process lifetime.
6. **Partial signing after owner approval** (some capabilities sign, then the
   process dies). Each capability's own `write_secure_new()` is
   exclusive-create-only — a half-completed batch leaves only the
   capabilities that actually finished signed. See (12) for retry safety.
7. **Signer crash midway through N artifacts.** Same as (6) — no shared
   transaction spans the loop; each `_one_authorization()` call is
   independently atomic (`write_secure_new()` either fully creates the file
   or fails and creates nothing, per its own O_EXCL discipline).
8. **Expired evidence/authorization during batch generation.** The shared
   `discovery` is built once, before the loop, from one read of the
   `AnchorEvidenceExport`/witness — same posture is used for every capability
   in the batch, so no capability can slip through with a *different*,
   possibly staler discovery result than its siblings. If the export itself
   is expired or the plan digest is stale, `sign_authorization_preview()`'s
   existing re-derivation-and-cross-check (unchanged) fails the **first**
   capability closed, before any signature in the batch is produced (the
   loop signs in canonical order; an early failure surfaces immediately and
   the caller sees a non-zero `worst` return).
9. **Duplicate capability entries.** Refused explicitly before any preview is
   even loaded (`len(set(capabilities)) != len(capabilities)`).
10. **Mixed risk classes / mixed posture targets.** Impossible by
    construction — `build_shape_a_batch_manifest()` refuses any batch whose
    previews do not share one `requested_plan_digest`/`requested_step_id`/
    `target_capability_posture`/`target_anchor_assurance` (and `risk_class` is
    itself derived from `plan.steps`, so one shared `requested_step_id`
    implies one shared risk class — see `build_plan_authorization_v2_payload()`).
11. **Partial admission into PREPARED state.** Out of scope for this
    ceremony — `authorize_and_create()` is a separate, later, per-capability
    step this module never calls. Nothing here creates or touches a
    `RecoveryContract`.
12. **Safe retry semantics after partial completion.** A retry with the
    *original full* capability list is refused outright (`already exists`,
    §3 step 2) — there is no ambiguous "resume where it left off" behavior.
    The documented safe retry is: invoke `sign-authorization-batch` again
    with only the still-pending capabilities, which builds and reviews a
    fresh, smaller manifest of its own (a second, separate owner approval).
    `test_partial_retry_is_safe_with_only_the_remaining_capabilities` proves
    both halves of this.

## 6. Confirmation batch semantics — design only, not implemented

The confirmation ceremony (`sign_pending_confirmation()` /
`sign_confirmation_command()` / `_one_confirmation()`) has an analogous
per-capability `yes` bottleneck. The same manifest-then-one-approval pattern
applies in principle: collect N `ShapeAPendingConfirmationRequest` artifacts,
require them to share a common binding fact (each already carries its own
`contract_id`/`operation_id`/`intent_digest` — there is no single shared
"posture digest" equivalent to unify them the way `requested_plan_digest`
does for authorization previews, since each confirmation is intrinsically
bound to one already-created `RecoveryContract`), render one combined review,
and require one `yes` before looping through N individual
`sign_pending_confirmation()` calls exactly as today.

This is deliberately **not implemented in this pass** for two reasons stated
directly by the owner's own scope: (a) the owner authorized analysis of the
confirmation path, not new signing/confirmation code, and (b) unlike
authorization previews (produced ahead of any execution, freely re-signable),
confirmations are consumed once a `RecoveryContract` is already PREPARED —
introducing a new batch code path here without equally careful,
separately-reviewed adversarial testing of confirmation-specific replay/
binding edge cases (e.g., a `RecoveryContract` moving out of PREPARED between
manifest build and the loop) would be exactly the "move the bottleneck instead
of removing it safely" outcome the owner explicitly warned against. A future
pass implementing this should reuse `ShapeABatchManifest`'s canonicalization
approach but define its own homogeneity predicate appropriate to pending
confirmations (likely: same `expected_authority_id`/`expected_algorithm`,
never a shared digest).

## 7. Restoration semantics — deferred

Restoration remains, unconditionally, a separate owner decision derived from
fresh, observed post-mutation state — this ceremony does not, and must not,
pre-authorize unknown restoration intents as part of a mutation batch. A
future restoration batch may reuse this same one-review/one-`yes` pattern
once its exact, fresh intents are known and reviewable, following the same
manifest/digest/homogeneity discipline documented above — but building that
manifest type is out of scope until a real restoration scenario defines what
its homogeneity predicate should be.
