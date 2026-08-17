# Netgate Nexus / official API — READ-tool compatibility matrix

**Status: research artifact, through Phase D. `pfsense_get_carp_status`
now has a concrete, tested, but NOT runtime-wired Nexus adapter — see
"Phase D update" below for exactly what that does and does not mean.
Nothing else in this document is wired into the running server; no
public MCP behavior changed.**

## Phase D update (2026-08-17) — first passing slice

`pfsense_get_carp_status` was the owner-chosen candidate after Phase C's
`firewall_aliases` result, specifically because `CarpStatus` is this
project's simplest domain model with **no `id: int` field** — the pattern
that blocked both prior slices.

Traced end-to-end: `tools/read/carp_status.py` →
`PfSenseClient.get_carp_status()` → `RestApiClient.get(Endpoints.STATUS_CARP)`
(`GET /api/v2/status/carp`) → `_parse_object_response()` (requires a
top-level `"data"` object key) → `CarpStatus.from_api()`, which reads
`data["enable"]` and `data["maintenance_mode"]` — two required boolean
dict keys, no defaults.

Compared against Nexus `GET /services/carp/status`
(`operationId` not set; response schema `CARPStatus`) — and, critically,
against **Netgate's own official generated Python client**
(`py/pfapi/models/carp_status.py` in `Netgate/pfsense-api`), fetched and
read directly rather than relying on the OpenAPI YAML alone, because the
YAML's bare `type: boolean` with no `required[]` entry doesn't by itself
say whether a field is reliably present:

```python
enabled: bool | Unset = UNSET
maintenancemode_enabled: bool | Unset = UNSET
```

This is decisive, from source: Nexus's own client explicitly models both
fields as possibly **absent entirely** (`Unset`), not merely nullable —
confirming the same ambiguity the owner asked to check for
("behavior when CARP is disabled, unavailable, partially configured, or
absent").

| community field | required? | Nexus field | Nexus type | Nexus required? | semantic equivalence | transformation | confidence |
|---|---|---|---|---|---|---|---|
| `enable: bool` | required key, no default | `enabled` | `bool \| Unset` | optional/possibly-absent | High — both represent "is the CARP service itself turned on for this appliance"; `/services/carp/enabled` (POST) is literally "Enable/Disable the CARP service," the same concept the GET status field reflects | direct rename, **when present** | High |
| `maintenance_mode: bool` | required key, no default | `maintenancemode_enabled` | `bool \| Unset` | optional/possibly-absent | High — both represent the standard pfSense/CARP-protocol "persistent maintenance mode" concept (forces this node's VIPs to BACKUP); `/services/carp/maintenancemode` (POST) names the same concept | direct rename, **when present** | High |

**Why this passes where gateway status/firewall aliases did not:** those
two had required community fields with **zero possible source under any
circumstance** (no `id` concept exists anywhere in their Nexus schemas).
Here, both fields exist, are named unambiguously, and match the community
concept with high confidence — domain knowledge (CARP enable/maintenance
mode are standard, specific pfSense/CARP-protocol terms, not generic
words like "status" that could mean several things) plus the paired
POST-toggle-endpoint names (`/services/carp/enabled`,
`/services/carp/maintenancemode`) corroborating the GET field semantics
independently. The only open question is *reliability of presence*, which
is a **fail-closed problem, not a fabrication problem**: unlike a field
with no source at all, "sometimes absent" can be handled correctly by
refusing to guess when it's missing, exactly as the community backend's
own `_parse_object_response()` already refuses on any missing required
key. That is what was implemented — see below.

**One additional, pre-existing nuance found and left as-is, not a new
gap:** `CarpStatus`'s plain Pydantic `bool` fields already perform lax
coercion (`"true"`/`"false"` strings, `1`/`0`, etc. are accepted) — this
is existing, shared behavior of the community backend's own model, not
something this adapter adds or could avoid without diverging from how
the community backend itself already behaves. Adversarial tests exercise
genuinely non-coercible malformed values instead (a list, a nested
object) to confirm real fail-closed behavior without asserting something
false about the shared model's own pre-existing leniency.

**Routing/device semantics:** consistent with Phase B's confirmed
mechanism — same base-path-prefix scheme, no CARP-specific routing
behavior found or expected.

### What was implemented

The **smallest isolated READ-only adapter**, per explicit owner scope:

- `CarpStatusReader` added to `src/pfsense_mcp/backends/ports.py`.
- `src/pfsense_mcp/backends/nexus/carp_status.py`: a pure
  `normalize_carp_status(raw: dict) -> CarpStatus` function (fail-closed:
  raises `PfSenseResponseShapeError` — the exact same exception type the
  community backend's own `_parse_object_response()` raises — on any
  missing key, `None`, or non-coercible type) plus
  `NexusCarpStatusReader`, a thin class taking an **injected**
  `fetch_raw: Callable[[], dict]` and calling
  `normalize_carp_status(self._fetch_raw())`.

**What was deliberately NOT built, and why:** any actual Nexus HTTP
transport — login/JWT session handling, refresh-token lifecycle, or the
`{controller}/api/device/pfsense/{device_id}/api/services/carp/status`
base-path construction Phase B confirmed. That is separate, materially
larger infrastructure work applicable to *every* future Nexus capability,
not specific to CARP status — building it now would be exactly the
"unrelated refactoring" the owner's Phase D authorization explicitly
excluded. `NexusCarpStatusReader` takes a raw dict via injection
precisely so this remains true: the reader is fully testable and
review-complete today, and plugging in a real fetch function later is a
separate, explicit, future decision — not a change to this code.

**Not wired anywhere.** `factory.py`, `tools/registry.py`, and
`application.py` are unaffected — `pfsense_mcp.backends` (including
`nexus/`) remains structurally unreachable from any of them, enforced by
`tests/backends/test_isolation.py`, generalized this phase to scan every
file under `backends/`, not just `ports.py`.

### Testing

26 tests in `tests/backends/` (16 new this phase, in
`tests/backends/nexus/test_carp_status.py`): both-true, both-false,
mixed, extra Nexus-only fields ignored, missing `enabled`, missing
`maintenancemode_enabled`, both missing, empty body, non-coercible wrong
type for each field, explicit JSON `null` for each field, reader calls
the injected fetch function and normalizes correctly, reader propagates
the fail-closed error from a malformed fetch, reader satisfies
`CarpStatusReader` structurally, and construction alone must not
eagerly invoke `fetch_raw`.

**No live validation performed.** No Nexus Controller/device/credential
is available in this environment — same as every prior phase.

## Phase C update (2026-08-17)

`pfsense_get_firewall_aliases` was the owner-chosen replacement first-slice
candidate after Phase B's gateway-status result. Traced end-to-end
(`tools/read/firewall_aliases.py` → `PfSenseClient.get_firewall_aliases()`
→ `RestApiClient.get(Endpoints.FIREWALL_ALIASES)`, `GET /api/v2/firewall/aliases?limit=N`
→ `_parse_list_response()` → `FirewallAlias.from_api()`, which reads
`data["descr"]`, `data["id"]`, `data["name"]`, `data["type"]`,
`data["address"]`, `data["detail"]` — all six as required dict keys, no
`.get()` defaults, identical fail-closed discipline to `GatewayStatus`).

Compared field-by-field against Nexus `GET /aliases` (`operationId:
FirewallGetAliases`, response schema `FWAliases` → `aliases:
list[FWAlias]` + a **second, separately-shaped** `system_aliases:
list[FWSystemAlias]` collection) and `GET /aliases/{id}` (single-alias
lookup, `{id}` is `type: string` in the path — confirmed almost certainly
the alias's own `name` used as an identifier, not a distinct numeric ID,
consistent with `example-set-alias.py`'s own logic which checks aliases by
`.name`, never by any numeric field).

**Result: does not pass the owner's compatibility bar ("complete,
deterministic, lossless enough for the existing contract, and
fail-closed"). Classified PARTIAL. No adapter implemented**, per explicit
owner instruction not to invent/default required fields to force a fit.

| community field | required? | Nexus field (`FWAlias`) | Nexus type | Nexus required? | equivalence | transformation needed | confidence | known difference |
|---|---|---|---|---|---|---|---|---|
| `id: int` | required key, no default | *(none)* | — | — | **NONE** | impossible without fabrication | — | No integer identifier anywhere in `FWAlias` or `FWSystemAlias`. The `/aliases/{id}` path parameter is a string and is almost certainly `name`, not a numeric ID — third independent confirmation (after gateways in Phase B, packages checked this phase) that this project's domain models' `id: int` convention has no Nexus counterpart anywhere checked so far. |
| `name: str` | required, no default | `name` | string | **required** | Direct | passthrough | High | Clean match — the one field that maps cleanly. |
| `descr: str` | required, no default | `descr` | string | optional | Partial | passthrough if present | Medium | Community requires this key to exist; Nexus may omit it entirely (e.g. plausibly for `urltable`-type aliases with no free-text description). A real omission would `KeyError`. |
| `type: str` | required, no default (community only ever produces `host`/`network`/`port` in practice, per `tier1/alias_description.py::_ALIAS_TYPES`) | `type` | string, documented enum `host, network, url, urltable, urltable_ports, port, or url_ports` | optional | Partial | passthrough if present | Medium | Nexus's enum is a **superset** with 4 values (`url`, `urltable`, `urltable_ports`, `url_ports`) this project's Tier1 WRITE side does not recognize at all (READ-side `type` itself is an unconstrained `str`, so it would not fail to parse — but a caller expecting only the 3 known types could be surprised). Also optional in Nexus vs. required in community. |
| `address: list[str] \| None` | required key | `address` | **string** ("space separated list of addresses") | optional | Partial | split on whitespace | Low-Medium | Type mismatch: community wants an already-split list; Nexus provides one space-separated string requiring parsing, with unspecified behavior for multiple/leading/trailing spaces or an alias with zero members. Also optional — could be entirely absent. |
| `detail: list[str] \| None` | required key | `detail` | **string** (singular, not a list) | optional | **Ambiguous** | unclear | Low | Structural mismatch, not just a type mismatch: community expects a list of per-member annotations parallel to `address`; Nexus's plain `detail` is one string. A better semantic match may be `targets: list[FWTarget]` (each with its own `name`+`descr`) — a *different field entirely*, requiring a genuine design decision (which source is authoritative?) rather than a mechanical rename, and the schema gives no guidance on whether `address`/`detail` and `targets` are populated consistently with each other. |
| *(none)* | — | `system_aliases: list[FWSystemAlias]` | — | — | — | — | — | Structural difference: Nexus separates system-defined aliases from user aliases into two differently-shaped collections (`FWSystemAlias` has `url`/`table`/`if_ident`/`if_assigned_name` instead of `targets`). Whether the current community endpoint's flat list includes system aliases at all was not confirmed either way — a genuine ambiguity, not just an extra field to ignore. |

**Routing/device semantics:** consistent with Phase B's confirmed finding
— the same `{controller}/api/device/pfsense/{device_id}/api/aliases`
base-path-prefix mechanism applies uniformly; no alias-specific routing
behavior was found or expected.

**Conclusion:** 1 required field (`id`) has zero source at all — the same
severity as gateway_status's worst gap. 2 more (`descr`, `type`) are
optional-in-Nexus vs. required-in-community, a real (if less severe) fail-
closed risk. 2 more (`address`, `detail`) require non-trivial, genuinely
ambiguous transformation rather than a mechanical rename. Only `name` is a
confident, clean match. This does not meet the owner's explicit bar for
implementation. See
`tests/backends/test_nexus_firewall_alias_infeasibility.py` for the
permanent regression guard encoding this finding.

**Recommended next candidate (Phase D):** *(acted on — see the "Phase D
update" section above the Phase C section for the result: this
recommendation passed.)* `pfsense_get_carp_status`
(`CarpStatus`) — checked this phase specifically because the `id: int`
pattern has now blocked two consecutive slices (gateways, aliases) and a
third model (`SystemPackage`) was spot-checked and found to have the same
required `id: int` with no Nexus source. `CarpStatus` is the simplest
domain model in the entire 42-tool surface with **no `id` field at all** —
exactly two required booleans (`enable`, `maintenance_mode`) — and Nexus
has a plausibly-matching `GET /services/carp/status` endpoint (found in
Phase A, not yet schema-diffed). This is a genuine structural reason to
expect a better outcome, not just an untested guess.

## Phase B update (2026-08-17)

Two things changed since Phase A; everything else in this document is
Phase A's original, unmodified research.

1. **Device routing: CONFIRMED.** Phase A's biggest open question — how a
   request through Nexus authoritatively targets one specific managed
   pfSense appliance — is resolved, directly from Netgate's own official
   example source code in the `Netgate/pfsense-api` repository
   (`helper_funcs.py`, `example.py`), not inferred from the OpenAPI schema
   (which does not capture this at all — see why, below).

   **Mechanism:** device targeting is a URL **base-path prefix**, not a
   path parameter, header, or JWT claim:

   ```
   {CONTROLLER_URL}/api/device/{device_type}/{device_id}/api{operation_path}
   ```

   e.g. `{CONTROLLER_URL}/api/device/pfsense/{device_id}/api/system/status`.
   `device_type` is literally the string `"pfsense"` in every example.
   `device_id` is the string identifier from `ControlledDevice.device_id`
   (confirming the string-not-integer identifier finding from ADR-030).
   The same Controller-level JWT bearer token and refresh-token cookie
   jar obtained from `POST /login` is reused unchanged across every
   per-device client — `helper_funcs.py::RequestClient.createDeviceApiChild(device_id)`
   constructs a new `AuthenticatedClient` with only the `base_url` changed,
   not a new login. Every example explicitly checks `device.state ==
   "online"` before issuing a per-device call and skips otherwise.

   This also explains why Phase A's schema-only search found nothing: the
   *same* `paths:` templates (e.g. `/system/status`) are used against
   *two* different base URLs (the bare Controller base for `/mim/*`
   operations, or a per-device base for everything else) — which base URL
   is in play is a client-construction-time decision entirely outside
   what the OpenAPI document's `paths`/`parameters` sections can express,
   consistent with the schema's own `servers: null`.

2. **`pfsense_get_gateway_status`: downgraded from ADAPTABLE to PARTIAL**
   after a genuine field-by-field diff (Phase A only checked property
   *names*, not `required[]` or exact types). See the dedicated section
   below. The Phase 4 concrete adapter was **stopped, not implemented** —
   a faithful, non-fabricating implementation is not achievable with the
   current model. `docs/adr/ADR-031-backend-target-identity-boundary.md`
   was added, independent of this outcome.

No other row's classification changed this pass — the rest of Phase A's
findings below were not re-verified this pass and should not be assumed
current beyond what's stated.

This matrix compares every one of the current 42 default-profile MCP READ
tools against the *official* Netgate API schema (`Netgate/pfsense-api`,
`pfapi_openapi.yml`, OpenAPI 3.0.3, `info.version: "1.0"`, description:
"Nexus Multi-instance Management APIs"), fetched directly from
`https://raw.githubusercontent.com/Netgate/pfsense-api/main/pfapi_openapi.yml`
and parsed programmatically (486 paths, 755 operations). This is **not** the
same product as the community `pfSense-pkg-RESTAPI` package this project's
existing backend already uses — it is Netgate's own, Plus-only,
Controller-mediated multi-instance API.

## Methodology and honesty notes

- Every current-side fact (tool names, `Endpoints.path_suffix` values,
  domain model required fields) was re-derived directly from `src/` on
  commit `0ce37ab0c7d4d99421146e4d45085fe8ed6cb467`, not recalled from prior conversation or reports-ai.
- Every Nexus-side fact was extracted by loading the actual schema YAML with
  `pyyaml` and inspecting `paths`/`components.schemas` programmatically —
  not inferred from path names alone.
- **No entry is classified DIRECT.** For every tool where a plausible Nexus
  endpoint exists, deep-enough inspection found at least one genuine
  semantic gap (a required field on the current Pydantic model with no
  confirmed source field in the Nexus schema, an identifier-shape mismatch,
  or a structural difference such as per-interface vs. flat collections).
  Where that inspection was not completed to the same depth, the entry is
  marked ADAPTABLE with confidence noted, not DIRECT.
- UNKNOWN means genuinely insufficient evidence was gathered this pass, not
  "probably unsupported." UNSUPPORTED means a positive search was made and
  no candidate was found.

## Summary

Updated in Phase B: `pfsense_get_gateway_status` moved ADAPTABLE → PARTIAL.

| Classification | Count (Phase A) | Count (Phase B) | Count (Phase C) | Count (Phase D) |
|---|---|---|---|---|
| DIRECT | 0 | 0 | 0 | 0 |
| ADAPTABLE | 32 | 31 | 30 | 30 |
| PARTIAL | 3 | 4 | 5 | 5 |
| UNSUPPORTED | 5 | 5 | 5 | 5 |
| UNKNOWN | 1 | 1 | 1 | 1 |
| LOCAL | 1 | 1 | 1 | 1 |
| **Total** | **42** | **42** | **42** | **42** |

Phase D's totals are unchanged from Phase C: `carp_status` was already
ADAPTABLE and stays ADAPTABLE — the DIRECT/ADAPTABLE/PARTIAL/etc. axis
tracks *schema compatibility*, not *implementation status*, which is a
separate fact recorded per-row and in the SCHEMA-MAPPED/OFFLINE-TESTED/
LIVE-READ-VERIFIED legend below. `carp_status` is the only row that has
reached OFFLINE-TESTED so far.

(`system_status`, `firewall_rules`, `dhcp_static_mappings` are PARTIAL from
Phase A; `gateway_status` is PARTIAL as of Phase B; `firewall_aliases` is
PARTIAL as of Phase C — see each row and the dedicated diff sections
below for why.)

## Full matrix

| MCP tool | Current endpoint (`Endpoints.*`) | Current method | Candidate Nexus path(s) | Nexus method(s) | Classification | Confidence | Key semantic differences |
|---|---|---|---|---|---|---|---|
| `pfsense_get_system_status` | `SYSTEM_STATUS` (`/status/system`) | GET | `/system/status` | GET | **PARTIAL** | High | Nexus `SystemStatus` schema has no field corresponding to the current model's required `disk_usage: int`, and no `temp_c`/`temp_f` equivalent at all. `ram`/`fram`/`swap`/`fswap` are untyped-unit integers (no documented unit), `cpu` is a string (likely a model name, not a usage percentage) — the current model's `cpu_usage: float` has no confirmed source. `up` is a string of undocumented format. Full reproduction is not possible from this schema as published. |
| `pfsense_get_interface_configs` | `INTERFACES` (`/interfaces`) | GET | `/interfaces` | GET | ADAPTABLE | Medium | `InterfaceSimple` has `ipaddr`/`ipaddrv6`/`mac`/`descr`/`enable` — reasonable config-field overlap. Not schema-diffed field-by-field against the current `InterfaceConfig` model. |
| `pfsense_get_interfaces` | `STATUS_INTERFACES` (`/status/interfaces`) | GET | none confirmed | — | **UNKNOWN** | — | This tool returns live link/status data (`InterfaceStatus`). The `/interfaces` schema found is configuration-shaped (no link/media/up-down field observed); `/system/status/ifstats` was found but not inspected. Insufficient evidence to classify. |
| `pfsense_get_gateways` | `ROUTING_GATEWAYS` (`/routing/gateways`) | GET | `/system/gateways` | GET | ADAPTABLE | Medium | `Gateways.gateways` structure not diffed field-by-field against `GatewayConfig`'s ~20 required fields. |
| `pfsense_get_gateway_status` | `STATUS_GATEWAYS` (`/status/gateways`) | GET | `/system/gateways/status` (`operationId: GetGatewaysStatus`) | GET | **PARTIAL** (downgraded from ADAPTABLE in Phase B) | High | See the dedicated field-by-field diff below. 4 of 9 required community fields have zero source in Nexus; the 3 that exist conceptually are type-mismatched strings, not floats. Phase 4's concrete adapter was stopped rather than fabricate values. |
| `pfsense_get_firewall_rules` | `FIREWALL_RULES` (`/firewall/rules`) | GET | `/firewall/rules/interface`, `/firewall/rules/interface/{interface}` | GET | **PARTIAL** | High | Structural mismatch: current tool returns one flat rule list; Nexus requires enumerating interfaces first, then one call per interface, then aggregating — a real multi-call transformation, not just field renaming. |
| `pfsense_get_firewall_states` | `FIREWALL_STATES` (`/firewall/states`) | GET | `/diag/states` | GET (also DELETE — do not use) | ADAPTABLE | Low-Medium | Endpoint exists; response schema not inspected this pass. |
| `pfsense_get_firewall_states_size` | `FIREWALL_STATES_SIZE` (`/firewall/states/size`) | GET | none found | — | UNSUPPORTED | High (positive search) | No state-table size/count endpoint found anywhere in the 486-path schema. |
| `pfsense_get_firewall_apply_status` | `FIREWALL_APPLY_STATUS` (`/firewall/apply`) | GET | `/system/config/dirty` | GET | ADAPTABLE | Medium | Real scope difference: Nexus's dirty-state check is system-wide across all "subsystems," not scoped to the firewall subsystem the way the current endpoint is. |
| `pfsense_get_firewall_aliases` | `FIREWALL_ALIASES` (`/firewall/aliases`) | GET | `/aliases` (`operationId: FirewallGetAliases`) | GET | **PARTIAL** (downgraded from ADAPTABLE in Phase C) | High | See the dedicated field-by-field diff below. `id` has zero source (same pattern as gateway_status); `descr`/`type` optional-in-Nexus vs. required-in-community; `address`/`detail` have real type/structural mismatches. No adapter implemented. |
| `pfsense_get_service_status` | `STATUS_SERVICES` (`/status/services`) | GET | `/services/status` | GET | ADAPTABLE | Low-Medium | Endpoint exists; response schema not inspected this pass. |
| `pfsense_get_system_version` | `SYSTEM_VERSION` (`/system/version`) | GET | embedded in `/system/status` (`SystemStatus.rev`, `.osver`) | GET | ADAPTABLE | Medium | No standalone version endpoint; version-like fields exist but are untyped strings nested in the broader status object, requiring extraction. |
| `pfsense_get_firewall_nat_port_forwards` | `FIREWALL_NAT_PORT_FORWARDS` | GET | `/firewall/nat/port-forward` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_firewall_nat_outbound_mode` | `FIREWALL_NAT_OUTBOUND_MODE` | GET | `/firewall/nat/outbound` | GET (note: `/firewall/nat/outbound/mode` is **POST-only** in Nexus — a write/apply action, not a mode-read) | ADAPTABLE | Low | The current tool reads a mode value; whether Nexus's GET on `/firewall/nat/outbound` includes a `mode` field was not confirmed. |
| `pfsense_get_users` | `USERS` (`/users`) | GET | `/system/users` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_system_certificates` | `SYSTEM_CERTIFICATES` | GET | `/system/certificates` | GET | ADAPTABLE | Medium | Nexus has a notably richer certificate surface (export-cert/export-key/export-p12/renew as separate operations); base collection endpoint exists. |
| `pfsense_get_user_groups` | `USER_GROUPS` (`/user/groups`) | GET | `/system/users/group` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_dhcp_leases` | `STATUS_DHCP_LEASES` | GET | `/services/dhcp/leases` | GET | ADAPTABLE | Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_dhcp_static_mappings` | `DHCP_SERVER_STATIC_MAPPINGS` | GET | `/services/dhcp-server/{version}/static-mappings/{iface}` | GET | **PARTIAL** | High | Structural mismatch: requires iterating `{version}` (v4/v6) × `{iface}` and aggregating, vs. the current single flat list. |
| `pfsense_get_dhcp_servers` | `DHCP_SERVERS` | GET | `/services/dhcp-server`, `/services/dhcp-server/{version}/interface` | GET | ADAPTABLE | Low-Medium | Endpoint exists; shape not diffed. |
| `pfsense_get_interface_bridges` | `INTERFACE_BRIDGES` | GET | `/interfaces/bridge` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_carp_status` | `STATUS_CARP` (`/status/carp`) | GET | `/services/carp/status` (response schema `CARPStatus`) | GET | **ADAPTABLE — PASSED, adapter implemented** (Phase D) | High | Both required fields (`enable`/`maintenance_mode`) map cleanly to Nexus's `enabled`/`maintenancemode_enabled` with high-confidence semantic equivalence, confirmed against Netgate's own generated client. Not runtime-wired — see the dedicated Phase D section above. |
| `pfsense_get_system_restapi_settings` | `SYSTEM_RESTAPI_SETTINGS` | GET | none | — | UNSUPPORTED | High | This tool exposes settings for the community `pfSense-pkg-RESTAPI` package specifically. That package/concept does not exist under Nexus's own, separate auth/API model. |
| `pfsense_get_system_hasync` | `SYSTEM_HASYNC` | GET | none found | — | UNSUPPORTED | High (positive search) | Searched for `pfsync`/`hasync`/`sync peer`/`failover` — no match. CARP *status* exists (`/services/carp/status`, `/services/carp/enabled`) but the HA-sync *configuration* (sync interface, sync peer IP) this tool exposes was not found. This is also the exact endpoint whose privilege (`api-v2-system-hasync-get`) is one of the 4 privileges the existing Tier1 scoped credential holds — see the security note below. |
| `pfsense_get_dns_resolver_host_overrides` | `DNS_RESOLVER_HOST_OVERRIDES` | GET | `/services/dnsresolver` (likely a sub-field) | GET | ADAPTABLE | Low | No standalone host-overrides endpoint found; likely nested inside the general resolver-settings object — not confirmed. |
| `pfsense_get_dns_resolver_settings` | `DNS_RESOLVER_SETTINGS` | GET | `/services/dnsresolver` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_arp_table` | `DIAGNOSTICS_ARP_TABLE` | GET | `/diag/arp` | GET (also DELETE — do not use) | ADAPTABLE | Medium | Clear name/purpose match; not schema-diffed. |
| `pfsense_get_firewall_traffic_shaper_limiters` | `FIREWALL_TRAFFIC_SHAPER_LIMITERS` | GET | `/firewall/traffic-shaper/limiter` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_firewall_advanced_settings` | `FIREWALL_ADVANCED_SETTINGS` | GET | `/system/advanced/firewall` | GET | ADAPTABLE | Low-Medium | Endpoint exists; not schema-diffed. |
| `pfsense_get_system_packages` | `SYSTEM_PACKAGES` | GET | `/system/package/installed` | GET | ADAPTABLE | Medium-High | `Package` schema (`name`, `version`, `installed_version`, `available_version`, `update_available`, `dependencies`) overlaps well conceptually with the current `SystemPackage` model; not diffed field-by-field. |
| `pfsense_get_system_tunables` | `SYSTEM_TUNABLES` | GET | `/system/advanced/sysctl` | GET | ADAPTABLE | Medium | Good name/purpose match (pfSense "tunables" are sysctl values); not schema-diffed. |
| `pfsense_get_email_notification_settings` | `SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS` | GET | `/system/advanced/notifications` | GET | ADAPTABLE | Medium | `AdvNotifications.notifications` contains `smtp*` fields but is a combined object also covering Pushover/Slack/Telegram/cert-expiry notification — requires extracting the SMTP-only subset. |
| `pfsense_get_bind_settings` | `BIND_SETTINGS` | GET | none confirmed | — | **UNKNOWN** | — | The current model's fields (`bind_dnssec_validation`, `bind_forwarder`, `bind_forwarder_ips`, `bind_custom_options`) suggest literal BIND-DNS-server configuration. Nexus has `/services/dnsmasq` and `/services/coredns` (pfSense's actual built-in resolver/forwarder options) but no confirmed BIND-specific endpoint, and the dnsmasq/coredns schemas were not inspected to check for overlap. Not classified UNSUPPORTED because the search was not exhaustive enough to be a confident negative. |
| `pfsense_get_ntp_settings` | `NTP_SETTINGS` | GET | `/services/ntp` | GET | ADAPTABLE | Medium | `ServicesNtpConfig.settings` has a clear overlapping field set (`enable`, `servers`, `ntpmaxpeers`, etc.). |
| `pfsense_get_ntp_time_servers` | `NTP_TIME_SERVERS` | GET | embedded in `/services/ntp` (`settings.servers`) | GET | ADAPTABLE | Medium | No standalone endpoint; time servers are a field within the general NTP settings object, requiring extraction. |
| `pfsense_get_ssh_settings` | `SERVICES_SSH` | GET | embedded in `/system/advanced/admin` (`SystemAdvAdmin`: `enablesshd`, `sshport`, `sshdkeyonly`, `sshdagentforwarding`) | GET | ADAPTABLE | Medium | No standalone SSH endpoint; SSH config is a subset of the broader "admin access" settings object. |
| `pfsense_get_cron_jobs` | `CRON_JOBS` | GET | none found | — | UNSUPPORTED | High (positive search) | No cron/scheduled-task endpoint found anywhere in the schema. |
| `pfsense_get_acme_settings` | `ACME_SETTINGS` | GET | `/services/acme` | GET | ADAPTABLE | Medium | Endpoint exists (also has richer per-account-key/per-cert sub-resources); base object not schema-diffed. |
| `pfsense_get_freeradius_eap` | `FREERADIUS_EAP` | GET | `/ports/freeradius/eap` | GET | ADAPTABLE | Low-Medium | Endpoint exists under the `/ports/` namespace (suggesting a package/plugin-dependent feature in Nexus too); not schema-diffed. |
| `pfsense_get_diagnostics_tables` | `DIAGNOSTICS_TABLES` | GET | `/diag/tables`, `/diag/tables/{table_name}` | GET | ADAPTABLE | Medium | Clear name/purpose match; not schema-diffed. |
| `pfsense_get_auth_keys` | `AUTH_KEYS` | GET | none | — | UNSUPPORTED | High | Fundamentally different auth model: Nexus authenticates via `POST /login` → JWT access + refresh token (username/password + optional 2FA), not per-user long-lived API keys. There is no concept in this schema equivalent to "list a user's API keys." |
| `pfsense_mcp_info` | n/a (local process introspection) | n/a | n/a | n/a | **LOCAL** | — | No upstream call of any kind; unaffected by backend choice. |

## Notable cross-cutting findings (apply to many rows above)

1. **Identifier-shape mismatch.** The current domain models and the Tier1
   execution-target layer (`tier1/transport_target.py::ResolvedTransportTarget.numeric_locator: int`)
   assume pfSense-REST-API-style integer indices. Every Nexus identifier
   inspected this pass is either a string name (`GatewayStatus` has no
   `id`, only `name`/`gateway`), a `device_id` string (MIM device registry),
   or a `refid` string (certificates) — no confirmed integer-index
   identifier scheme anywhere in the Nexus schema. This is a real
   architectural incompatibility for the WRITE side, not just a READ
   nuance — see Phase 4/ADR.
2. **No pagination.** Three representative large-collection endpoints
   (`/services/dhcp/leases`, `/system/users`, `/firewall/rules/interface/{interface}`)
   have zero pagination parameters. Collections appear to be returned in
   full.
3. **Two-value HTTP status model.** All 755 operations in the schema use
   only `200` and `400` as documented response codes — no distinct
   401/403/404/500. Error classification (auth failure vs. not-found vs.
   validation) would have to come from the JSON body's `Error.errcode`/
   `errlevel` fields, not the HTTP status code the current `RestApiClient`
   relies on (`errors.py` maps 401/403 → `PfSenseAuthError` by status code
   today).
4. **JWT/session auth, not a static API key.** `POST /login` with
   base64-encoded username/password (+ optional `secondfactor`) returns a
   JWT access token plus a refresh-token cookie, refreshable via
   `POST /login/refresh`. This does not map onto the current
   `PFSENSE_API_KEY_FILE` / static-credential model at all — a Nexus
   backend would need its own credential lifecycle (login + periodic
   refresh), not a drop-in swap of the API key file.

## Phase B: `pfsense_get_gateway_status` field-by-field diff

Current implementation traced end-to-end: `tools/read/gateway_status.py`
→ `PfSenseClient.get_gateway_status()` → `RestApiClient.get(Endpoints.STATUS_GATEWAYS)`
(`GET /api/v2/status/gateways`) → `_parse_list_response()` (requires a
top-level `"data"` list key; any missing/malformed entry raises
`PfSenseResponseShapeError`, fail-closed) → `GatewayStatus.from_api()`,
which reads `data["id"]`, `data["name"]`, `data["delay"]`, `data["stddev"]`,
`data["loss"]`, `data["status"]`, `data["substatus"]`, `data["srcip"]`,
`data["monitorip"]` — **all nine as required dict keys, no `.get()`
defaults** (`srcip`/`monitorip` are read unconditionally even when
`include_identifying_metadata=False`; they're just nulled out afterward,
not skipped). Any missing key raises `KeyError`, wrapped into
`PfSenseResponseShapeError` by `_parse_list_response()`'s `except` clause.

Nexus side: `GET /system/gateways/status` (`operationId: GetGatewaysStatus`)
→ `GatewaysStatus.gateways: list[GatewayStatus]`. The Nexus `GatewayStatus`
schema's own `required: [name, gateway]` — **only two of ten properties are
required; everything else, including `delay`/`stddev`/`loss`/`status`, is
optional.**

| community field | required? | Nexus field | Nexus type | Nexus required? | equivalence | transformation needed | confidence | known difference |
|---|---|---|---|---|---|---|---|---|
| `id: int` | required key, no default | *(none)* | — | — | **NONE** | impossible without fabrication | — | No integer identifier anywhere in `GatewayStatus`, `GatewaysStatus`, or the adjacent `GroupStatus` schema (also checked — gateway *groups*/tiers, not per-gateway IDs). |
| `name: str \| None` | required key (nullable value) | `name` | string | **required** | Direct | passthrough | High | Clean match. |
| `delay: float` | required key, no default | `delay` | **string** | optional | Partial | strip units/parse; format undocumented | Low | Type mismatch (string vs. required float); unclear what a down/unmonitored gateway reports (may be absent entirely, since the field is optional). |
| `stddev: float` | required key, no default | `stddev` | **string** | optional | Partial | same as `delay` | Low | Same issue. |
| `loss: float` | required key, no default | `loss` | **string** | optional | Partial | same as `delay`, likely `"N%"`-formatted | Low | Same issue. |
| `status: str \| None` | required key (nullable value) | `status` | string | optional | Partial | passthrough if present | Medium | Optional in Nexus vs. a required (if nullable) key in the community model; no enum values documented on either side to confirm value-set compatibility. |
| `substatus: str \| None` | required key (nullable value) | *(none)* | — | — | **NONE** | impossible without fabrication | — | No `substatus` concept anywhere in the schema. |
| `srcip: str \| None` (identifying) | required key even when unused | *(none confirmed)* | — | — | **NONE** | impossible without fabrication | — | No field observed corresponding to "the source IP used for monitoring." |
| `monitorip: str \| None` (identifying) | required key even when unused | `monitor`? | string | optional | Unconfirmed | passthrough *if* `monitor` is confirmed to be the monitored target IP | Low | `monitor` exists and is plausibly the same concept, but this was not confirmed against a real response — could equally be a monitor *method* or *interface* name. |
| *(none)* | — | `gateway` | string | required | — | — | — | Nexus-only field, likely the gateway's own IP/interface identifier — a better identity candidate than the missing `id`, but not what the current model expects. |
| *(none)* | — | `defaultgw` | boolean | optional | — | — | — | Nexus-only; no direct community `GatewayStatus` counterpart (default-gateway-ness lives elsewhere in the community model). |
| *(none)* | — | `descr`, `display` | string | optional | — | — | — | Nexus-only, no community counterpart needed. |

**Conclusion: 4 of 9 required community fields (`id`, `substatus`,
`srcip`, `monitorip`) have zero confirmed source in the Nexus response,
full stop — not "different format," not present at all.** The 3 fields
that do exist conceptually (`delay`/`stddev`/`loss`) require undocumented
string parsing and are themselves optional on the Nexus side, unlike the
community model's required floats. Only `name` is a clean, confident
match. **A faithful, non-fabricating implementation of the current
`GatewayStatus` model against this Nexus endpoint is not achievable as
written.** `pfsense_get_gateway_status` is downgraded PARTIAL, and the
Phase 4 concrete adapter was stopped rather than invent values for the
missing fields — see `tests/backends/test_nexus_gateway_status_infeasibility.py`,
which encodes this finding as a permanent regression guard.

## Classification legend used from Phase B onward

- **SCHEMA-MAPPED** — a candidate Nexus endpoint/schema was identified and
  compared field-by-field against the current domain model.
- **OFFLINE-TESTED** — a concrete adapter exists and has offline
  fixture/adversarial test coverage, but has never made a real network
  call.
- **LIVE-READ-VERIFIED** — a concrete adapter's output was compared
  against a real Nexus Controller/device. *(Not attempted for any row —
  no Nexus Controller/device/credential available in any phase so far;
  the relevant live-validation phase was skipped each time per its own
  stated conditions.)*

`pfsense_get_gateway_status` and `pfsense_get_firewall_aliases` both
reached **SCHEMA-MAPPED** only (no adapter implemented — see their
respective diff sections for why).

`pfsense_get_carp_status` reached **OFFLINE-TESTED** (Phase D, deepened
Phase F): `NexusCarpStatusReader` exists with 16 adversarial tests
(Phase D), and as of Phase F a real `NexusSession`/`NexusTransport`
also exist (`docs/adr/ADR-032-nexus-read-transport-architecture.md`'s
"Phase F implementation notes"), with 97 further tests (session,
transport, routing, and a 5-test CARP integration seam proving the
full login → device-scoped GET → normalization chain) — all offline,
`respx`-mocked, zero real network calls. **Still not LIVE-READ-VERIFIED**:
no live Nexus Controller/device/credential is available in this
environment (unchanged since Phase A), and this code is still not
wired into `factory.py`/`tools/registry.py`/`application.py` in any
way — that remains a deliberate, unauthorized-this-phase step for a
future Phase G.
