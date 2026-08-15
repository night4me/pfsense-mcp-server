# ADR-028: First-WRITE product surface and delivery architecture

- **Status:** Proposed
- **Date:** 2026-08-15
- **Scope:** Architecture only. This ADR authorizes no code, test,
  capability, endpoint, tool, or live change. It records three decisions the
  owner already accepted during the W3 preflight/decision-pass sessions
  (2026-08-14/15) — the authorization/confirmation delivery seam (W3-D1), the
  capability/profile activation model (W3-D2), and the signing-side CLI trust
  boundary — as a durable, Git-tracked, reviewable record. Its own
  Proposed → Accepted transition is a separate owner action from the
  acceptance of the decisions it records; W3 Slice 0 (this document) does not
  itself authorize any implementation slice.

## Context

W1 (Bound Semantic Execution Core) and W2 (Fixed Production Runtime) are
complete and published, implementing the full offline authorization →
contract → execution chain for the description-only alias-write semantic
unit (ADR-025/ADR-026), but exposing no MCP surface at all. A read-only W3
preflight found two structural gaps preventing W3 from having a coherent
product surface, neither of which ADR-025 or ADR-026 resolves:

- **Delivery.** `AliasDescriptionExecutionCoreV1` is intentionally two-phase
  (`authorize_and_create()` generates a `contract_id`; `confirm_and_handoff()`
  requires a `ConfirmationEvidence` bound to that exact, not-yet-existing
  `contract_id`). A `ConfirmationEvidence` therefore cannot be pre-signed, so
  a single synchronous MCP call cannot complete the operation. ADR-025
  deliberately ships no serialization or delivery mechanism for signed
  artifacts; ADR-026 and the roadmap's W3 entry are silent on how a signed
  `PlanAuthorizationV2` or `ConfirmationEvidence` reaches the server process.
- **Activation.** `AuditorProfile.capabilities` aliases
  `SUPPORTED_CAPABILITIES_THIS_BUILD` directly today. Adding `ALIAS_WRITE` to
  that set — the otherwise-natural place, since it is what
  `write_capability_check.py` inspects — would grant WRITE to the *default*
  posture.

This document designs nothing new. Every mechanism it fixes as authoritative
already exists and is already accepted elsewhere: the pending/signed
secure-file artifact exchange is already implemented for LAB-T1
reconciliation in `lab/reconciliation_authority.py`; the off-host signing
requirement is already stated in `docs/tier1/specs/confirmation_authority.md`
(G3) and `docs/tier1/specs/reconciliation_authority.md` (G1); the
`write_protected` posture name is already established by ADR-021. This ADR's
role is narrow: fix which already-accepted mechanism is authoritative for the
first production WRITE path, and state the resulting invariants precisely
enough that Slices 1–5 can be implemented and reviewed against a fixed
record rather than conversational decisions.

## Decision W3-D1 — authorization/confirmation delivery seam

**Mechanism.** Both authorization and confirmation delivery reuse the exact
secure-file pending/signed artifact-exchange pattern already implemented and
accepted for LAB-T1 reconciliation in `lab/reconciliation_authority.py`,
generalized to two artifact kinds: a signed `PlanAuthorizationV2`
(authorization) and a signed `ConfirmationEvidence` (confirmation). No new
transport, daemon, queue, or service is introduced.

**Ownership and configuration.** The production runtime owns the
inbox/outbox configuration. Every inbox/outbox path, and every security
component involved in consuming an artifact from it, is fixed at runtime
construction and environment-derived, matching W2's existing all-or-nothing,
fail-closed configuration convention exactly. No path, and no security
component, may ever be caller-selectable.

**Authority.** Artifact discovery/selection is a pure filesystem lookup and
grants no authority by itself. The existing pinned verifiers and canonical
binding checks (signature verification, currentness, exact plan/step/intent
binding, freshness, contract provenance) remain the sole authority and must
independently and fully re-validate every artifact discovered this way.
Discovery is a pre-filter, never a substitute for verification, and never a
second security owner.

**Fail-closed behavior.** No matching signed authorization artifact means the
operation state is `REQUESTED`; nothing is consumed and no contract is
created — a no-match is not itself an error, but it must never be treated as
grounds to consume an authorization. A malformed, stale (expired), mismatched
(wrong contract/digest binding), duplicate, unsafe-path, wrong-owner,
wrong-permission, or wrong-authority (signed by an unpinned or inactive
authority) artifact must fail closed in every case — never silently treated
as absent, and never treated as valid.

**Artifact lifecycle and cleanup.** Stale or leftover artifacts are never
automatically deleted or overwritten merely to make forward progress; the
existing exclusive-creation discipline (refuse a second write rather than
discard the first) is itself the fail-closed behavior here, not an
inconvenience to be engineered around. Cleanup of a stale or leftover
artifact is an explicit, separately documented operator action. It can never
restore an already-consumed authorization and can never manufacture a retry
entitlement beyond what the existing one-time-consumption semantic already
grants.

**Durable state and deduplication.** The contract's own durable, authenticated
state (specifically: an existing contract already in `PREPARED` for the same
prepared intent) is the sole basis for "awaiting confirmation"/deduplication
decisions on re-invocation. No weaker or parallel notion of "same intent" may
be introduced merely for deduplication convenience, and no new persistent
store is introduced for this purpose. This must not weaken any existing
freshness, binding, consumption, contract, lifecycle-locator, or recovery
invariant already established by ADR-022/023/024/025 or Tier 1's existing
state machine.

**Product state model.** The resulting product-visible operation is
explicitly asynchronous, with states `REQUESTED`, `AWAITING_CONFIRMATION`,
`VERIFIED`, `RECONCILIATION_REQUIRED`, and a uniform `REFUSED` for any
fail-closed denial that never reveals which specific gate refused.
`RECONCILIATION_REQUIRED` — an uncertain outcome — must never be projected to
the caller as success. Pre-authorization (a signed authorization already
present in the inbox before the first request for that intent) is accepted
only as a special case of this same mechanism, never as a separate path.

## Decision W3-D2 — capability/profile activation model

**Capability semantics split.** `READ_CAPABILITIES` is introduced as an
explicit set naming exactly the capabilities already active today (the
current READ capability set) — separated out so it can be referenced without
implying a grant. `SUPPORTED_CAPABILITIES_THIS_BUILD` continues to mean
"implemented by this build" only; it must never again be treated as a grant
by direct aliasing or otherwise.

**Profile grants.** `AuditorProfile` grants `READ_CAPABILITIES` only.
`EngineerProfile` remains unchanged (empty). A new, explicit `write_protected`
profile grants `READ_CAPABILITIES | {ALIAS_WRITE}` — reusing the
`write_protected` posture name ADR-021 already established, not inventing a
new posture vocabulary.

**`PFSENSE_ALLOWED_TOOLS`.** May narrow the set of registered tools within
whatever the active profile already grants. Must never grant a capability the
active profile does not already grant.

**WRITE tool registration gate.** Registration of the WRITE MCP tool requires
all three of the following, independently:

1. the selected profile explicitly grants `ALIAS_WRITE`;
2. the corresponding endpoint is explicitly present in `WriteEndpoints`;
3. the production runtime successfully constructs the complete, fail-closed
   W2 runtime.

Any single condition failing means the tool is simply absent — never
degraded, never partially available.

**Default invariant.** Default or unconfigured operation (default profile, no
W2 environment configured) remains exactly 42 public READ tools / 0 WRITE
tools.

**Terminology.** "Implemented" (`SUPPORTED_CAPABILITIES_THIS_BUILD`),
"granted" (by the active profile), and "runtime-enabled" (by a successfully
constructed W2 runtime) are three separate concepts that must remain
independently checkable, never conflated into one axis.

## Signing-side CLI trust boundary

A required deliverable before first-WRITE activation is considered complete —
not optional, not deferrable past W3. It is the signing tool
`docs/tier1/specs/confirmation_authority.md`'s own "Non-goals" section names
but explicitly does not build.

- Remains off-host and off-runtime in security ownership: it must never run
  on the same host or in the same process as the MCP server, matching
  `confirmation_authority.md` G3 and `reconciliation_authority.md` G1
  exactly.
- Authenticates and validates the pending artifact (the same fail-closed
  matrix Decision W3-D1 establishes) before presenting it for approval — a
  corrupted or tampered pending request must not reach human review as if
  genuine.
- Renders the required human-readable review of exactly the accepted,
  security-relevant facts before signing — the operator-facing rendering step
  `confirmation_authority.md` requires and explicitly defers to this
  deliverable.
- Requires explicit operator approval before signing; signing is never
  automatic.
- Signs only the exact accepted canonical artifact — no free-form payload, no
  alternate encoding.
- Writes the resulting signed artifact using the same secure-file discipline
  already established elsewhere in this codebase (exclusive, non-overwriting,
  atomic creation).
- Contains zero pfSense mutation capability: no import of, or path to, any
  pfSense-reaching transport; never contacts pfSense and never invokes any
  MCP WRITE path, directly or indirectly.
- Preserves the existing pinned-authority/private-key separation unchanged:
  it uses the operator's own private key material, whose public counterpart
  is the one already pinned in production's verifiers — no new authority
  mechanism, no new key format.
- The production MCP/pfSense host never requires, loads, or has access to the
  private signing key at any point; its role there remains exclusively
  verification against the pinned public key.

## Architecture vs. implementation detail

This ADR fixes the security-relevant invariants above. It deliberately does
**not** fix, and a future implementation slice remains free to choose:

- exact module, file, function, or type names;
- exact internal call shapes or helper decomposition;
- exact artifact-file field ordering or key naming, beyond the accepted
  semantic content (authorization binding, confirmation binding, expiry);
- exact test file organization or naming;
- where the signing-side CLI's source lives, as long as it is not importable
  by, and never runs in the same process as, `pfsense_mcp`.

## Non-goals

- Does not implement any of the planned W3 slices.
- Does not modify ADR-025, ADR-026, or ADR-027 — all three remain accurate as
  written and are not reopened.
- Does not activate any capability, populate `WriteEndpoints`, register any
  MCP tool, or perform any live pfSense activity.
- Does not resolve ADR-026's remaining live-evidence rows (apply/reload
  suppression, least privilege, sufficient side-effect evidence) — those
  remain separately gated live-acceptance work, unaffected by this ADR.
- Does not revisit or reintroduce ADR-027 Slice 3 onward, Stage 3F, D6, or any
  generic WRITE framework.

## Consequences

W3 can proceed as a sequence of independently authorized slices against a
fixed, Git-tracked architectural record, rather than against conversational
decisions that could be lost or re-litigated. The production process gains,
for the first time, an explicit consumer of signed security artifacts
arriving via the filesystem rather than constructed in-process — a stated
design constraint (the artifact loader is never a security decision-maker),
not merely an implementation preference. The existing default-safety
invariant (42 READ / 0 WRITE) becomes independently checkable across three
separate axes ("implemented", "granted", "runtime-enabled") instead of one
conflated axis.

## References

- [ADR-021: Guided security-posture provisioning](ADR-021-security-posture-provisioning.md) —
  origin of the `write_protected` posture vocabulary reused here.
- [ADR-022: Execution-authorization boundary](ADR-022-execution-authorization-boundary.md)
- [ADR-023: Authorization-verification boundary](ADR-023-authorization-verification-boundary.md) —
  the one-time consumption semantics referenced above.
- [ADR-025: Authorization-to-RecoveryContract binding](ADR-025-authorization-recovery-contract-binding.md) —
  the crypto binding this ADR's delivery seam carries unchanged.
- [ADR-026: First WRITE capability adapter semantic unit](ADR-026-first-write-capability-adapter.md) —
  the semantic unit and evidence matrix this ADR's product surface exposes.
- `docs/tier1/specs/confirmation_authority.md` — G3 (signing key off-host) and
  the operator-facing rendering step, both reused unchanged.
- `docs/tier1/specs/reconciliation_authority.md` — G1 (signing key off-host)
  and the pending/signed artifact pattern this ADR promotes into production.
- `lab/reconciliation_authority.py` — the existing, accepted implementation
  of the artifact-exchange pattern this ADR generalizes.
- `docs/tier1/IMPLEMENTATION_ROADMAP.md` — the W1/W2/W3 sequencing this ADR's
  decisions unblock.
