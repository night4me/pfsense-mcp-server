# Compatibility

- **Python:** 3.11, 3.12, or 3.13.
- **pfSense REST API package (`pfrest`/`pfSense-pkg-RESTAPI`):** required,
  API v2. This project pins its models against the **v2.10** schema.

## pfSense edition/version compatibility

Evidence tiers used below — deliberately mutually exclusive, so no two
rows can plausibly satisfy the same tier:

| Tier | Meaning |
|---|---|
| **PRODUCTION VERIFIED** | Exercised against a real **production** pfSense appliance, under an explicit, narrowly-scoped, owner-authorized READ-only verification pass. |
| **LAB VERIFIED** | Exercised against this project's controlled, disposable **LAB** appliance — never production. |
| **SUPPORTED / COMPATIBLE** | Not directly exercised on that exact release, but compatibility is established by *this project's own* stronger adjacent evidence (e.g. a schema fetch or tool invocation against a release one step away with proven zero drift) — more than a plausible expectation, short of a direct test. |
| **EXPECTED COMPATIBLE / UNVERIFIED** | A reasonable expectation from public vendor documentation, FreeBSD-generation similarity, or cross-release package-version behavior — but nothing this project directly exercised against that release. Do not read this as "supported." |

| Platform | Version | Status | Evidence |
|---|---|---|---|
| pfSense CE | 2.9.0 (FreeBSD 16.0-CURRENT, pfREST 2.10) | **LAB VERIFIED** | Current LAB baseline; full 95-tool public contract exercised against a disposable, isolated appliance, including all 11 tools added in `v0.6.0` (config-history revisions, log settings, the 8 apply-status endpoints, and WireGuard tunnel addresses). |
| pfSense CE | 2.8.1 (pfREST 2.10) | **LAB VERIFIED** | Prior LAB baseline; this project's READ-expansion audit's initial 7-tool backlog was verified here before the LAB's platform upgrade to CE 2.9.0. |
| pfSense Plus | 26.07-RELEASE | **PRODUCTION VERIFIED** | Owner-authorized, READ-only production compatibility pass, performed against the `v0.5.x` 84-tool contract: 82 of 84 public tools invoked successfully with real data (30 valid-empty results); the remaining 2 (WireGuard status) correctly and automatically classified as package-absent, not a compatibility failure. The REST API package's own self-reported version (`pfsense_get_system_restapi_version`'s `current_version` field) was directly confirmed as **v2.10** — identical to both CE LAB baselines below. Schema-level: the live OpenAPI schema matched the pinned v2.10 reference exactly — 267/267 paths, 186/186 components; the only differences found across every field in every component were 5 instance-specific runtime default values, never a type or nullability change. Zero secret-bearing fields present in any exercised response. **The 11 tools added in `v0.6.0` have not yet been exercised against production — they are LAB VERIFIED only; this row's evidence predates them and must not be read as covering them.** |
| pfSense Plus | 25.11 | **EXPECTED COMPATIBLE / UNVERIFIED** | No live or LAB access to a 25.11 instance was available — nothing in this project has directly exercised a schema fetch, tool call, or package inspection against this specific release. The evidence available is entirely adjacent: the same pfREST v2.10 package this project directly confirmed (via `pfsense_get_system_restapi_version`, not inferred) on CE 2.8.1, CE 2.9.0, and Plus 26.07 already spans three different platform release numbers across both editions without incident; and Netgate's own published 25.11 release notes state its base OS was updated to FreeBSD 16-CURRENT, matching the CE 2.9.0 LAB baseline's directly-observed FreeBSD generation. That is a reasonable expectation, not this project's own stronger evidence — hence `EXPECTED COMPATIBLE / UNVERIFIED`, not `SUPPORTED / COMPATIBLE`. |

pfSense platform version, edition, FreeBSD generation, and REST API
package variant/version are five independent facts, not proxies for one
another:

- **Platform version** (e.g. `26.07-RELEASE`) and **edition** (CE vs.
  Plus) are read directly from `pfsense_get_system_version`/
  `pfsense_get_system_status`.
- **REST API package version**: self-reported (`pfsense_get_system_restapi_version`'s
  `current_version` field) and directly, independently confirmed as
  **v2.10** on three separate live systems — the CE 2.8.1 LAB, the CE
  2.9.0 LAB, and, via this release's owner-authorized production pass,
  pfSense Plus 26.07. That identical version string held across three
  different platform release numbers and both editions, so REST API
  package versioning is **not** required to numerically match the
  pfSense platform version.
- **REST API package variant**: on every platform this project has
  directly tested — the CE 2.9.0 LAB (which lists only the one other
  package actually installed there) and the Plus 26.07 production
  appliance (which lists 9 other installed packages) — the REST API
  package does **not** appear as a discrete named entry in
  `pfsense_get_system_packages`, the REST API's own general
  installed-package listing endpoint. **This omission is a property of
  that one pfREST endpoint, confirmed identical on both CE and Plus —
  it says nothing about, and must not be confused with, the appliance's
  underlying FreeBSD/pfSense package database.** The REST API package
  itself is unambiguously real and versioned: the dedicated
  version-check endpoint above directly confirms `v2.10` on every
  platform tested.
- **Schema/API compatibility**: verified independently of the above, by
  direct structural comparison (267/267 paths, 186/186 components) —
  see the Plus 26.07 row above.

## Package-conditional tools

Every one of the 95 registered tools' underlying endpoints was checked
against the pfREST schema's own declared package requirements, not
assumed. Two tools (`pfsense_get_status_wireguard_tunnels`,
`pfsense_get_status_wireguard_peers`) require `pfSense-pkg-WireGuard`
**in practice**: they return an automatically-classified package-absent
result (HTTP 404, `MODEL_MISSING_REQUIRED_PACKAGE`) — never an error —
when the package isn't installed, confirmed directly on both the LAB
and production systems used for this project's testing.

Four further tools' endpoints declare a required package in the
schema's own metadata but do **not** gate on it in practice, confirmed
by direct invocation against systems that genuinely lack the declared
package: `pfsense_get_acme_settings` (schema declares
`pfSense-pkg-acme`), `pfsense_get_bind_settings` (`pfSense-pkg-bind`),
`pfsense_get_cron_jobs` (`pfSense-pkg-Cron`), and
`pfsense_get_freeradius_eap` (`pfSense-pkg-freeradius3`) all returned a
successful, real response on the CE 2.9.0 LAB (which has none of these
four packages installed) and on the Plus 26.07 production appliance
(which has none of the first three, though `pfSense-pkg-Cron` happens
to be installed there). These read as stored configuration/default
settings structures rather than genuinely package-gated runtime state,
unlike the WireGuard status pair, which report live package-dependent
state and do 404 when absent. Do not assume a schema-declared package
requirement reflects actual runtime gating without direct verification
— this project checked, rather than guessed.

## Related

- [Installation](INSTALLATION.md)
- [Tool/guidance reference](TOOL_AND_GUIDANCE_REFERENCE.md)
- [MCP tool reference](API.md)
