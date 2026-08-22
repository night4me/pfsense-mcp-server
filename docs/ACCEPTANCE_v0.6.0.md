# Acceptance — v0.6.0

**Status: release-candidate — prepared, not yet tagged or published.**
The `v0.6.0` git tag, GitHub Release, and PyPI upload do not yet exist as
of this document. This document records the release-preparation state
as of the exact commit it ships with; tag/Release/PyPI publication
remain separate, explicit owner actions taken only after this document
and that commit SHA have been reviewed.

## Release scope

v0.6.0 is a **READ-capability expansion release**. Public MCP contract:
**84 → 95 READ tools, 0 default WRITE tools** — confirmed by a new
`tests/contracts/mcp_public_contract_v0.6.0.json` snapshot. Useful READ
coverage against this project's own capability-audit denominator:
80.0% (84/105) → 90.5% (95/105); the denominator itself is unchanged —
every candidate added this release was already counted in the original
105-capability universe identified by that audit, none legitimately
expands it.

Full detail is in `CHANGELOG.md`'s `[0.6.0]` entry — this document
summarizes the independently verified evidence a reviewer needs to
accept the release.

## Independently verified release evidence

### Public contract change

- `KNOWN_READ_TOOL_NAMES`: **95**, re-derived from source. 11 new tools
  since `v0.5.1`:
  - `pfsense_get_diagnostics_config_history_revisions`
  - `pfsense_get_status_logs_settings`
  - `pfsense_get_firewall_virtual_ip_apply_status`
  - `pfsense_get_interface_apply_status`
  - `pfsense_get_routing_apply_status`
  - `pfsense_get_dhcp_server_apply_status`
  - `pfsense_get_dns_forwarder_apply_status`
  - `pfsense_get_dns_resolver_apply_status`
  - `pfsense_get_ipsec_apply_status`
  - `pfsense_get_wireguard_apply_status`
  - `pfsense_get_vpn_wireguard_tunnel_addresses`
- `KNOWN_WRITE_TOOL_NAMES`: 1 (`set_firewall_alias_description_v1`),
  unreachable under the default `auditor` profile — unchanged from
  `v0.5.1`. Independently confirmed live: even under the
  `write_protected` profile's *capability* grant, the tool is not
  constructed unless `can_construct_write_runtime()` independently
  returns true (a real Tier 1/TPM/security-bootstrap condition) —
  verified by direct construction during this release's own audit, not
  assumed from a prior report.
- Distinct READ privileges: **94** (was 84). Write-protected combined:
  **95** (was 85) — 94 READ + the one `api-v2-firewall-alias-patch`.
  Independently re-derived from source (`security_privileges.py`
  against the pinned schema fixture), not from the LAB account's own
  granted-privilege state, and confirmed to match it.

### Verification tier per new tool

Every new tool was exercised against this project's disposable LAB
appliance (pfSense CE 2.9.0) before public registration:

| Tool | Tier | Note |
|---|---|---|
| `pfsense_get_diagnostics_config_history_revisions` | `ENDPOINT_VERIFIED` | Rests on a genuine, pre-existing 2026-08-16 LAB record (ADR-026 row 18 evidence-gathering); field-safety argument independently strengthened by direct inspection of the upstream `ConfigHistoryRevision.inc` PHP source, not just the OpenAPI schema. |
| `pfsense_get_status_logs_settings` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 34-key match. 18 fields widened from the schema's declared `nullable: false` to `Optional` after two live-verification passes found this LAB genuinely returns `null` for every unconfigured log category. |
| `pfsense_get_firewall_virtual_ip_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_interface_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 2-key match. |
| `pfsense_get_routing_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_dhcp_server_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_dns_forwarder_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_dns_resolver_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_ipsec_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_wireguard_apply_status` | `FIELD_MODEL_LIVE_VERIFIED` | Exact 1-key match. |
| `pfsense_get_vpn_wireguard_tunnel_addresses` | `ENDPOINT_VERIFIED` | 200, `{"data": []}` — no WireGuard tunnel addresses configured on this LAB; item shape not exercised live. Field-safety rests on independent schema/security review (`address`/`mask` redacted by default; confirmed not redundant with the already-shipped `WireGuardTunnelStatus`). |

None have been exercised against production. The existing Plus 26.07
`PRODUCTION VERIFIED` evidence in `README.md` predates this release's
11 additions and explicitly says so.

### Security findings and fixes from this release's own process

1. **`LogSettings` nullability defect, found and fixed via live
   verification, not assumed correct.** A second live-verification pass
   (after an initial partial fix covering 17 fields) caught that
   `sourceip` also needed widening to `Optional` — the fix was not
   accepted until a live call actually parsed cleanly.
2. **Schema field-drift regression protection, new this release**
   (`scripts/lib/schema_drift.py`): a general mechanism, independently
   designed, that asserts a pinned upstream schema component's fields
   are all either modeled or explicitly, reviewedly excluded — closing
   the gap where a future pfREST release could add a field to an
   already-shipped response model with nothing in this project's test
   suite noticing (Pydantic silently ignores unknown keys by default).
   13 models registered, all passing, including synthetic proof the
   mechanism fires on ordinary/secret-like/nested drift and correctly
   ignores type-only schema evolution.
3. **LAB privilege-provisioning drift, found and reconciled with
   evidence, not assumed.** The LAB's read-only service account
   (`pfsense-mcp`) had not been re-synced since its original 2026-08-19
   provisioning (41 READ + 1 WRITE), even as the READ contract grew to
   84 tools since. Reconciled against `AI_CONTEXT.md`'s own provisioning
   checkpoint before any privilege change was made; the account's
   pre-existing `api-v2-firewall-alias-patch` privilege was confirmed
   legitimate (it is this project's `write_protected`-profile service
   account) and preserved. This is LAB-only account state, not a
   repository or public-contract change.
4. **Trimmed schema fixture gap, found and fixed.** Registering the new
   tools initially broke ~70 tests in
   `test_security_bootstrap_engine.py`/`test_security_admin_composition.py`/
   `test_security_bootstrap_recovery.py` — traced to one root cause (9
   of the 10 new paths missing from
   `tests/fixtures/pfsense_openapi_schema_trimmed.json`, which those
   tests resolve privileges from), not ~70 independent regressions.

## What this release does NOT do

- Does not install any pfSense package. The one package-conditional
  addition (`pfsense_get_vpn_wireguard_tunnel_addresses`) uses
  `pfSense-pkg-WireGuard`, already installed on the LAB from prior,
  separately authorized work.
- Does not change WRITE reachability in any way — the one WRITE tool
  remains exactly as unreachable under the default profile as in
  `v0.5.1`.
- Does not touch Nexus/Tier 1/security-bootstrap/protected-WRITE
  production semantics. The one bootstrap-adjacent fix this release
  made (the trimmed schema fixture) touched a test fixture only.
- Does not touch production pfSense. All verification targeted the
  disposable LAB only.
- Does not expand BIND/HAProxy/FreeRADIUS package coverage or any
  capability beyond the 11 tools listed above — this release is
  feature-frozen at exactly this scope, per explicit instruction.

## Acceptance boundary

This document accepts the v0.6.0 **release-candidate** state at its
preparation commit, once that commit passes the required local and
remote gates (CI, CodeQL, `make release-check`). It does **not**
authorize a tag, push of a tag, GitHub Release, TestPyPI/PyPI upload, or
any further pfSense/witness/credential action. Each of those remains a
separate, explicit owner decision, taken only after this document and
the exact commit SHA it corresponds to have been reviewed.
