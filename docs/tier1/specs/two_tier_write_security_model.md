# Tier 1 — Two-Tier WRITE security model (STANDARD_SEALED_WRITE / HIGH_ASSURANCE_TIER1)

Status: Phase 1 (classification, migration, no-witness execution policy)
and Phase 2 (STANDARD approval enforcement) implemented; owner-authorized,
not pushed at time of writing. Related: [sealed_executor.md](sealed_executor.md),
[anchor_evidence_export_trust_boundary.md](anchor_evidence_export_trust_boundary.md).

## The two tiers

**`HIGH_ASSURANCE_TIER1`** — every WRITE capability except
`NTP_TIME_SERVER_PREFER` (`ALIAS_WRITE`, `NTP_SETTINGS_OBSERVABILITY_WRITE`,
`LOG_DISPLAY_PREFERENCES_WRITE`, `LOG_RETENTION_SETTINGS_WRITE`,
`SYSTEM_TIMEZONE_WRITE`):

- existing off-host `PlanAuthorizationV2` + `ConfirmationEvidence`
  ceremony (unchanged, unaffected by either phase of this model)
- hardware TPM witness ordering (`HighWaterMark`/`AntiRollbackAnchor`)
  at every `EXECUTING` transition
- the same sealed-execution algorithm every capability has always used

**`STANDARD_SEALED_WRITE`** — `NTP_TIME_SERVER_PREFER` only, the sole
capability the owner has positively reviewed and accepted for this tier
(`shape_a_registry.py` enforces the closed set at import time):

- the same off-host `PlanAuthorizationV2` + `ConfirmationEvidence`
  ceremony as HIGH (Phase 1/2 did not remove or narrow it)
- **plus** a human-gated `SealedWriteApproval` — a dedicated Ed25519
  authority (`standard-sealed-write-approval-authority-v1`), distinct
  from every HIGH_ASSURANCE authority, binding `contract_id`,
  `state_version`, `security_class`, `execution_intent_digest`, and
  `target_identity_digest` — verified inside `MutationExecutor.execute()`
  immediately after the registry/persisted-`security_class` consistency
  check, before `MutationPolicy.authorize()`, before
  `_require_pfrest_writable()`, before any adapter/transport call
- **no** per-mutation TPM witness/anchor contact (`StandardSealedExecutionPolicy.
  participates_in_witness() -> False`)
- the same sealed-execution algorithm otherwise: universal pfREST
  Read-Only gate, authoritative target read/fingerprint verification,
  exactly-one bounded send, authoritative reread, semantic verification

Classification is authoritative only from the static capability/adapter
registry (`shape_a_registry.WRITE_CAPABILITY_SECURITY_CLASS`) — never
caller-, request-, CLI-, environment-, or contract-selectable. A
contract's own persisted `security_class` is a durable audit/cross-check
value only; a mismatch against the registry fails the contract closed
(`PREPARED -> FAILED`, `event_type="security_class_mismatch"`) before any
network or witness activity. A missing or invalid STANDARD approval fails
identically (`event_type="sealed_write_approval_rejected"`). Neither path
ever reaches `EXECUTING` or `RECONCILIATION`.

A valid `SealedWriteApproval` is never consulted, and never relevant, for
a HIGH_ASSURANCE_TIER1 contract — the registry alone decides both whether
an approval is required and which execution policy applies.

## Approval delivery (Phase 2)

`MutationExecutor` accepts two additional, optional constructor
parameters: `standard_sealed_write_approval_authorities` (a
`PinnedAuthoritySet` scoped to the one STANDARD authority) and
`standard_sealed_write_approval_source` (a
`StandardSealedWriteApprovalSource`, one method: `load(contract_id) ->
SealedWriteApproval | None`). Both default to `None` — the safe,
fail-closed state: without both supplied, every STANDARD execution
attempt refuses. The runtime never signs, never generates an approval,
and never contacts a signer process; it only ever reads and verifies
evidence a trusted, non-caller-controlled source already holds. No
production runtime factory (`write_batch1_production_runtime.py`,
`production_runtime.py`) supplies these yet — wiring a concrete evidence
source (e.g. a fixed-inbox file, mirroring the existing
`PlanAuthorizationV2`/`ConfirmationEvidence` inbox convention) and a real
pinned STANDARD authority file is a separate, later, explicitly
owner-authorized phase.

## Signing (local, operator-only, off-runtime)

`signing/standard_sealed_write_signing.py` is a local CLI mirroring
`anchor_evidence_export_signing.py`'s discipline exactly: mandatory
interactive `"yes"` approval, no unattended/`--force` path, no network
capability, no import path to any pfSense-reaching or witness-reaching
module (proven by `signing/tests/test_signing_transport_isolation.py`),
never overwrites an existing artifact, never logs or re-serializes the
private key. It signs for exactly one authority and only ever produces a
`STANDARD_SEALED_WRITE` approval.

## Not yet safe for live use

`STANDARD_SEALED_WRITE` execution — even for `NTP_TIME_SERVER_PREFER`
alone — must not be attempted against a live appliance until all of the
following are true:

1. A real, separated STANDARD signer OS identity and private key have
   been provisioned (a distinct, later, explicitly owner-gated phase —
   neither Phase 1 nor Phase 2 provisions one; no such key exists today).
2. The live Tier 1/Batch 1 store has been migrated to schema v9
   (owner-approved, on the actual production/LAB store — only isolated
   test stores have been migrated so far).
3. The LAB `GET /api/v2/system/restapi/settings -> 403` least-privilege
   issue is resolved (unrelated to this model, but the universal pfREST
   Read-Only gate cannot pass while it stands, for either tier).

This model does not, and will not without a separate owner decision,
broaden the `STANDARD_SEALED_WRITE` eligible set beyond
`NTP_TIME_SERVER_PREFER`.
