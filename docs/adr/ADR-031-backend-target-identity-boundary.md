# ADR-031: Backend/target identity security boundary (Nexus Phase B)

- **Status:** Architecture/invariant only. Owner-authorized 2026-08-17
  ("OWNER DECISION — CONTINUE NETGATE NEXUS TRACK," decision 7/8) as a
  prerequisite that must exist and be reviewed *before* any future Nexus
  WRITE work — not as authorization for that work itself.
- **Scope:** States the invariant. Authorizes no change to any existing
  Tier1 signed schema, canonical digest format, `RecoveryContract` field,
  or any other backwards-incompatible change. Read-only backend selection
  (a second, independently-verified READ backend) may proceed
  independently of this ADR's own implementation, per owner decision 8.

## The invariant

**A mutation authorized for backend A / appliance X must never be
executable through backend B / appliance Y merely because the normalized
requested operation appears equivalent.**

This is not a hypothetical concern invented for this ADR. ADR-030's own
security review (Phase A) and Nexus Phase B's confirmed device-routing
mechanism (see `docs/NEXUS_COMPATIBILITY_MATRIX.md`'s Phase B section)
both point at the same underlying fact: this project now has, or will
have, more than one way to reach a pfSense-shaped API surface, and the
existing Tier1 signing/authorization chain (`tier1/contract.py`,
`tier1/alias_description.py`'s `target_precondition`/`rollback_snapshot`,
`tier1/transport_target.py::ResolvedTransportTarget`) was designed and
proven against exactly one backend, one appliance, one identifier scheme.
Nothing in the signed material today says *which* backend, or *which*
managed device behind a Controller, a given authorization is for — because
until now there was only ever one answer.

## Threats analyzed

- **`community_restapi` ↔ `netgate_nexus` substitution.** If a future
  execution path could choose either backend for an already-signed
  operation, an attacker able to influence that choice after signing could
  redirect a mutation intended for the directly-reached community backend
  toward a Controller-mediated Nexus path (or vice versa), where the
  security properties (privilege model, error semantics, controller
  compromise blast radius — all documented in ADR-030) differ.
- **Nexus Controller targeting the wrong managed device.** Confirmed this
  phase: Nexus device targeting is a URL path-prefix
  (`{controller}/api/device/pfsense/{device_id}/api/...`), reused against
  the *same* Controller-level JWT session for every device
  (`helper_funcs.py::RequestClient.createDeviceApiChild()`,
  Netgate's own official example source). A signed authorization that does
  not itself bind `device_id` says nothing about which device the
  signature was actually meant for — the binding exists only in
  whatever code happens to construct the URL at execution time.
- **Two pfSense devices containing the same logical resource name.** A
  gateway or alias named `"WAN_GW"` on two different managed devices are
  different resources. Nothing in a normalized, backend-neutral READ
  result (were one ever produced) distinguishes them without device
  identity attached.
- **Normalized target collision.** Generalizing this: any future
  normalization layer that maps two backends' differently-shaped
  identifiers (community integer index vs. Nexus string `device_id`/
  `gateway` name — see ADR-030's identifier-shape finding, reconfirmed by
  Phase B's `GatewayStatus` diff, which found **no integer identifier
  anywhere in the Nexus gateway schema**) into one common shape risks
  silently discarding the very information that would prevent a collision.
- **Controller re-registration / device-ID reuse.** The Controller's
  device registry (`/mim/devices*`) supports adding and presumably
  removing devices; nothing examined this phase establishes whether a
  `device_id` can be reused after a device is removed and a different
  physical appliance re-registered. Until confirmed otherwise, a signed
  authorization referencing only a `device_id` (and not, say, the device's
  `device_cert` fingerprint) should be assumed replayable against a
  different physical appliance under that scenario.
- **Backend configuration drift after signing.** If `PFSENSE_BACKEND` (or
  equivalent, per Phase B's config-model discussion) could change between
  when an authorization is signed and when it is executed, the signature
  says nothing about which backend it was signed against.
- **Replay of authorization across backends / across appliances.** Direct
  consequence of the above: without backend identity in the signed
  material, a valid authorization for one backend/appliance pair is, from
  the signature's own perspective, indistinguishable from one for another.
- **Confused-deputy behavior.** The executor (`tier1/executor.py`) is
  "authorization-unaware" by design (ADR-025) — it trusts the contract it
  is handed. If backend/target selection happened below that trust
  boundary rather than above it, the executor could be made to act as a
  confused deputy, executing a real, validly-signed mutation against a
  target the signer never saw.
- **Redirect/proxy ambiguity.** Because Nexus is Controller-mediated, a
  response nominally "from the target device" is, in fact, relayed through
  the Controller. Nothing establishes today whether that relay is
  cryptographically bound end-to-end (device cert/key pinned per Phase A)
  in a way this project's own read-back/reconciliation logic could verify,
  versus merely TLS-terminated at the Controller.
- **Stale controller inventory.** The device `state` field
  (`active/error/offline/rebooting/pending`, confirmed in Phase A) means
  the Controller's own view of a device can be wrong or stale at the
  moment of a request. A future reconciliation design assuming a
  directly-reachable, single appliance does not automatically generalize
  to "ask the Controller, trust its answer."

## What must be bound, in a future implementation

Not implemented here — stated as the requirement a later, explicitly
authorized WRITE-track ADR must satisfy:

- **Backend family** (`community_restapi` vs `netgate_nexus`, or
  whatever the eventual enum is) as an explicit, signed field.
- **Controller identity** (for Nexus: which Controller, verifiable
  independent of network location — e.g. its own certificate/key, not
  just a URL) where the backend is Controller-mediated.
- **Appliance/device identity** — for Nexus, the `device_id` *and*
  ideally something less reassignable than that string alone (the
  device's own `device_cert`/`device_key`, already present in the
  Controller's registry per ADR-030's `ControlledDevice` schema
  findings) — not just a name, which two devices could share.
- **Target resource identity** — already handled correctly for the one
  existing WRITE capability (`tier1/alias_description.py` binds the exact
  live-read alias state), but any future capability must do the same
  regardless of backend.
- **Backend API semantic/version identity where security-relevant** —
  e.g. binding that a signed plan assumed the community backend's
  status-code-based error model, not Nexus's body-encoded one, if that
  distinction is ever load-bearing for a security decision (it is, for
  instance, for auth-failure detection).

## Explicit non-implementation

This ADR makes **no change** to `tier1/contract.py`'s digest computation,
`PlanAuthorizationV2`'s signed payload shape, `PreparedExecutionIntentV1`,
`ResolvedTransportTarget`, or any other existing signed/canonical
structure. Doing so is explicitly out of scope for this run (no
backwards-incompatible change authorized) and, more importantly, would be
premature: there is currently exactly one backend and one appliance in
production, so there is nothing today for these fields to disambiguate.
Adding unused fields to a security-critical signed schema ahead of an
actual second backend risks the opposite failure mode this project has
consistently avoided — complexity and attack surface added before the
architecture that needs it is designed, reviewed, and authorized.

## Consequence for Phase C and beyond

**Nexus WRITE work of any kind cannot progress to acceptance until this
invariant has an implemented, reviewed cryptographic binding.** This is a
hard gate, not a recommendation. It does not block READ-only backend
selection (Phase B's gateway-status work, stopped this phase for an
unrelated reason — see `docs/NEXUS_COMPATIBILITY_MATRIX.md` — was never
blocked by this ADR; a future READ-only Nexus adapter for a capability
that *does* pass its semantic diff may proceed without this binding,
since READ operations carry no signed authorization to substitute).
