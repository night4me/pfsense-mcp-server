# ADR-030: Dual pfSense API backend architecture (Nexus Phase A)

**Status: research/architecture only. Nothing in this ADR is implemented,
wired, or reachable. No production behavior changed.**

**Update (Phase B, 2026-08-17):** this document is preserved unmodified as
the historical Phase A record. Two of its findings were superseded, not
retracted here — see `docs/NEXUS_COMPATIBILITY_MATRIX.md`'s "Phase B
update" section for the full detail: (1) the device-routing question this
ADR left UNKNOWN is now **CONFIRMED**, directly from Netgate's own example
source code; (2) `pfsense_get_gateway_status`, listed below as one of the
three ports this ADR's skeleton targeted, was field-by-field diffed in
Phase B and downgraded from ADAPTABLE to PARTIAL — a faithful
implementation was found not achievable, and no concrete adapter was
built. `docs/adr/ADR-031-backend-target-identity-boundary.md` was added in
Phase B, independent of that outcome.

## Motivation

The existing backend talks exclusively to the community `pfSense-pkg-RESTAPI`
package running on a single appliance. Netgate maintains its own, separate
official API — publicly described as "Nexus," backed by the
`Netgate/pfsense-api` repository and OpenAPI schema
(`pfapi_openapi.yml`, Apache-2.0) — aimed at pfSense Plus multi-instance
management. This ADR records what Phase A ("Nexus Phase A") established
about whether that official API can become a second, optional backend for
this project's 42 default-profile READ tools, and separately, what it would
take (not what is done) for the existing WRITE architecture to eventually
support it too.

## Official Netgate API discovery (FACT / INFERENCE / UNKNOWN)

- **FACT.** Nexus is "a GUI configuration interface and API for pfSense Plus
  software with multi-instance management (MIM) capabilities," available in
  "pfSense Plus software versions 25.07 and later" (docs.netgate.com/pfsense/en/latest/nexus/index.html).
  No Community Edition (CE) support is documented.
- **FACT.** The `Netgate/pfsense-api` repository's README describes itself
  as providing "a RESTful interface provided by the pfSense Multi-instance
  Management Controller." The OpenAPI schema's own `info.description` field
  reads "# Nexus Multi-instance Management APIs" — directly confirming this
  schema *is* the Nexus API, not a separate or older thing.
- **FACT.** The schema is OpenAPI 3.0.3, `info.version: "1.0"`, 486 paths /
  755 operations, Apache-2.0 licensed, no `servers:` entry (base URL is
  deployment-specific, not documented in the schema).
- **FACT.** Authentication is JWT-based: `POST /login` with base64-encoded
  `username`/`password` (+ optional `secondfactor`) returns an access token
  plus a refresh-token cookie, refreshed via `POST /login/refresh`. This is
  a Controller-account credential, not a per-pfSense-user API key.
- **FACT.** The Controller maintains a device registry (`/mim/devices*`)
  where each managed device has its own `address`/`address6`, a
  `device_cert`/`device_key` (public-key-based device identity), and a
  `state` field explicitly enumerated as `active, error, offline,
  rebooting, pending (pending auth)`.
- **INFERENCE.** The Controller is architecturally a centralized service
  distinct from any individual pfSense appliance, mediating requests to
  registered devices — supported by the device-registry model above, but
  the exact request-routing mechanism for ordinary (non-`/mim/*`) data-plane
  paths (how a call to, say, `/aliases` is scoped to one specific managed
  device) is not established from the schema alone.
- **UNKNOWN.** Exactly how a single data-plane operation (e.g. `GET
  /aliases`) is routed to one specific managed device when multiple devices
  are registered. No device-selector header, path segment, or query
  parameter was found on the endpoints inspected. This is the single most
  important open question before any live integration could be attempted.
- **UNKNOWN.** Whether GET endpoints are guaranteed side-effect-free by
  Netgate. Several GET-named diagnostic endpoints (`/diag/ping`,
  `/diag/traceroute`, `/diag/smart/test`) appear from their names to trigger
  live network probes or hardware tests even though modeled as `GET` —
  consistent with this project's own standing rule that "GET does not
  automatically mean safe." None of these were called, and none are
  candidates for any future READ adapter.
- **FACT.** Error handling uses exactly two HTTP status codes across all
  755 operations: `200` and `400`. Error detail (`errcode`/`errlevel`/
  `errmsg`) lives in the JSON body's `Error` schema, not in HTTP status —
  a genuinely different error model than the current `RestApiClient`'s
  401/403-by-status-code mapping.
- **FACT.** No pagination parameters were found on any of three
  representative large-collection endpoints checked (`/services/dhcp/leases`,
  `/system/users`, `/firewall/rules/interface/{interface}`).
- **FACT.** A system-wide "dirty subsystems" concept exists
  (`GET /system/config/dirty`, `DirtySubsystems` schema) — broader in scope
  than the current `FIREWALL_APPLY_STATUS` endpoint, which is
  firewall-subsystem-specific.
- **UNKNOWN.** HA/CARP behavior beyond `GET /services/carp/status` existing
  — its response schema and any HA-sync-configuration equivalent to the
  current `SYSTEM_HASYNC` endpoint were not found (positive search;
  see the compatibility matrix).

## Why the community backend remains

It is the only backend with any live evidence at all. The scoped
least-privilege identity, the two independently-verified live WRITE
executions, and the entire ADR-026 evidence chain are all evaluated against
`pfSense-pkg-RESTAPI` specifically. None of that evidence transfers to
Nexus by resemblance, similarity of endpoint names, or shared underlying
pfSense codebase — see "WRITE evidence isolation" below.

## Compatibility results

See `docs/NEXUS_COMPATIBILITY_MATRIX.md` for the full 42-row table.
Summary: **0 DIRECT, 32 ADAPTABLE, 3 PARTIAL, 5 UNSUPPORTED, 1 UNKNOWN, 1
LOCAL.** No tool was classified DIRECT — every plausible candidate endpoint
inspected deeply enough had at least one confirmed semantic gap (a required
current-side model field with no confirmed Nexus source field, an
identifier-shape mismatch, or a genuine structural difference such as
per-interface aggregation).

Five tools have no Nexus equivalent found by positive search:
`pfsense_get_auth_keys` (fundamentally different auth model — JWT sessions,
not per-user API keys), `pfsense_get_cron_jobs`, `pfsense_get_firewall_states_size`,
`pfsense_get_system_hasync`, and `pfsense_get_system_restapi_settings`
(this one is inherently community-package-specific and can never have a
Nexus equivalent by definition).

## Backend abstraction decision

**Decision: capability-specific ports/adapters (option C in the target
architecture), not a domain-service-level facade and never a
transport-level generic `request()` surface.**

Rejected alternatives:
- **(A) Transport-level abstraction** (swap the `Transport` implementation
  under the existing `RestApiClient`) — rejected because Nexus's path
  shapes, auth model (JWT + refresh, not a static bearer/API key), and
  error model (body-encoded, not status-code-encoded) are different enough
  that `RestApiClient`'s GET-only path-construction logic
  (`/api/{version}{path_suffix}`) does not generalize; forcing it to would
  either weaken its contract or require backend-specific branches inside a
  module whose entire value is being the single reviewed chokepoint.
- **(B) Domain-service-level facade** (one `PfSenseClient`-shaped interface
  both backends implement) — rejected for the same reason ADAPTABLE
  dominates the matrix: the domain models' required fields (e.g.
  `GatewayStatus.id: int`, `SystemStatus.disk_usage: int`) cannot always be
  populated from Nexus data without inventing values. A facade that must
  either fabricate fields or make them silently optional would weaken the
  existing fail-closed, no-guessing posture this project has held
  throughout every prior ADR.
- **(D) Hybrid** — considered, but a hybrid that keeps (A) for the parts
  that overlap cleanly still inherits (A)'s and (B)'s problems for the
  parts that don't, without a clean seam. Not adopted.

**(C)** means: small, typed Protocol interfaces, one per capability
(mirroring this project's own existing per-tool-per-model structure), each
returning the *existing* domain model unchanged. A capability whose fields
cannot be honestly populated from Nexus data (e.g. `SystemStatusReader`, per
the matrix's PARTIAL finding) simply does not get a Nexus implementation
yet — the Protocol can exist without every backend implementing every
member being wired anywhere. This keeps the abstraction genuinely optional
and additive: zero existing files change, capability adapters can be added
one at a time only when a real, non-fabricated mapping exists, and nothing
about tool registration, capability policy, or the Tier1 boundary needs to
know a second backend exists until one is actually wired in — which this
Phase does not do.

## Security architecture review (Phase 4)

Challenging the target diagram from the task brief rather than assuming it:

- **Backend substitution attack.** If a future backend-selection mechanism
  lived *below* the capability/policy/authorization layers (as the target
  diagram shows), an attacker who could influence backend selection after
  authorization was granted could potentially redirect a signed mutation
  intended for the community backend's specific appliance toward a
  different target reachable only through Nexus. **This is why backend
  identity must become part of signed/canonical state before any Nexus
  WRITE work is ever authorized** — stating this requirement explicitly, not
  changing any code to satisfy it. Today, backend identity is implicit
  (there is only one backend), so no code change is needed *yet*, but any
  future ADR introducing a second live backend for WRITE must bind backend
  identity into the plan/execution-intent digest, analogous to how
  `tier1/alias_description.py`'s `target_precondition`/`rollback_snapshot`
  already bind live pfSense *state*.
- **Differing target identity.** Confirmed by the matrix: Nexus identifiers
  are strings (device IDs, gateway names, certificate `refid`s), not the
  integers `ResolvedTransportTarget.numeric_locator` and several domain
  models (`GatewayConfig.id`, `GatewayStatus.id`) assume. A Nexus adapter
  cannot honestly satisfy those fields without inventing a mapping. This is
  a real blocker for WRITE, not just a READ inconvenience.
- **Differing apply/dirty semantics.** Nexus's dirty-state check is
  system-wide; the community backend's is firewall-subsystem-scoped. A
  reconciliation check written against one would not mean the same thing
  against the other.
- **Differing failure ambiguity / error model.** The community backend
  distinguishes auth failure from other errors by HTTP status
  (401/403 → `PfSenseAuthError`). Nexus encodes everything as `200`/`400`
  with an in-body error code. A reconciliation or read-back check that
  currently branches on HTTP status would silently misclassify Nexus
  failures if backends were ever unified without addressing this.
- **Controller compromise implications.** Because Nexus is Controller-
  mediated (device credentials/certs held centrally per the `/mim/devices*`
  registry), a compromised Controller is a categorically different threat
  than a compromised single-appliance API key — it is a blast-radius
  multiplier across every device it manages. This alone is a strong reason
  the existing scoped, single-appliance Tier1 identity should never be
  treated as equivalent evidence for a Controller-mediated backend.
- **Multi-node confusion.** The device `state` field
  (`active/error/offline/rebooting/pending`) confirms devices are not
  always reachable/consistent from the Controller's point of view — a
  reconciliation design assuming one directly-reachable appliance does not
  automatically generalize.
- **Normalization hiding security-relevant information.** Any future
  normalization layer that silently drops or defaults a field the current
  domain model requires (rather than failing closed) would be exactly the
  kind of behavior this project's fail-closed posture forbids. This is why
  Phase 6 of this run implemented *no* concrete Nexus reader for any
  capability — every one inspected deeply enough had at least one required
  field with no honest source, and fabricating a default would violate that
  posture.
- **Loss of deterministic read-back.** Not evaluated this pass beyond the
  general dirty/apply-scope finding above; requires its own future
  investigation once (if) a specific WRITE-candidate endpoint on Nexus is
  chosen.

**No authorization semantics were changed to accommodate any of the above.**
This section documents requirements for a later ADR, per the task's own
explicit instruction to prefer that over premature security-critical
changes.

## WRITE evidence isolation

The community backend's `FIREWALL_ALIAS_DESCRIPTION` endpoint remains
`verified=True`, unchanged by this ADR. **Any future Nexus equivalent must
be treated as `UNVERIFIED` until it independently earns its own acceptance
process**, mirroring exactly the evidentiary bar ADR-026 required for the
community backend (live execution, independent re-verification,
least-privilege identity, TPM witness advancement, authoritative read-back)
— not inherited, not assumed, not transferred by code or endpoint
similarity.

## Nexus WRITE readiness

**NOT DESIGNED.** Phase 3's tracing (MCP exposure → capability/profile gate
→ preparation → plan digest → authorization → RecoveryContract →
confirmation → executor → REST mutation → read-back → apply/dirty →
witness) was not attempted for a specific Nexus endpoint this pass, because
Phase 2/4 already surfaced blocking prerequisites (identifier-shape
mismatch, backend-identity-not-yet-bound-to-signed-state) that would make
any such design premature and likely to be discarded once resolved.

## Migration strategy (if a future ADR proceeds)

1. Resolve the device-routing UNKNOWN (Phase 1) — likely requires either a
   live Nexus/Controller instance to observe request routing directly, or
   direct outreach to Netgate.
2. Pick the single highest-confidence ADAPTABLE tool (e.g.
   `pfsense_get_gateway_status`, Medium-High confidence) as the first real
   Nexus `CapabilityAdapter` implementation, including a full field-by-field
   schema diff (not yet done for any tool in this pass) before writing any
   normalization code.
3. Add a `PFSENSE_BACKEND` (or similar) config value gating backend
   selection, defaulting to the existing community backend unconditionally.
4. Only after multiple READ capabilities are proven should a Nexus WRITE
   design even begin, and only as its own ADR with its own acceptance
   process — never by extending `verified=True` across backends.

## Rejected alternatives

Covered inline above (transport-level and domain-service-level
abstractions, and the hybrid). No alternative to "capability-specific
ports" was found that avoided either fabricating field values or
re-introducing backend-specific branching into a currently-clean chokepoint.

## Future acceptance requirements

Unchanged from ADR-026's own bar, applied fresh to Nexus: independent live
execution against a disposable target, least-privilege credential proof,
authoritative read-back, and (if hardware-witness parity is desired) its
own anti-rollback evidence — none of which this ADR performed or claims.
