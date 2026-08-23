# pfsense-mcp-server

[![CI](https://github.com/night4me/pfsense-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/night4me/pfsense-mcp-server/actions/workflows/ci.yml)
[![CodeQL](https://github.com/night4me/pfsense-mcp-server/actions/workflows/codeql.yml/badge.svg)](https://github.com/night4me/pfsense-mcp-server/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/pfsense-mcp-server.svg)](https://pypi.org/project/pfsense-mcp-server/)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/night4me/pfsense-mcp-server/blob/main/LICENSE)

**Safe, least-privilege pfSense access for AI assistants.** [MCP](https://modelcontextprotocol.io/)
server that gives an AI assistant strongly typed, read-only visibility into
one pfSense appliance — system, network, firewall, DHCP, DNS, VPN,
certificates, and diagnostics — without raw shell access, an unaudited
scripting surface, or any way to change the appliance by accident.

## Key facts

- **95 public READ tools, plus 1 documentation guidance tool. 0 public WRITE tools by default.**
- Covers roughly **90% of the useful READ capability surface** identified
  by this project's own capability audit (267 OpenAPI paths / 243 GET
  operations reviewed, every one given an explicit disposition).
- Every one of the 95 tools has been **exercised at least once against a
  real pfSense instance** (LAB or production) before public registration
  and confirmed to return a response matching this project's typed
  model — never assumed from schema alone. Depth varies by tool: some
  were confirmed against real, populated data; others have so far only
  been observed returning a valid empty/default envelope on every
  system tested (noted per capability where relevant) — see
  [Compatibility](#requirements--compatibility).
- **Explicit capability → privilege mapping** for every tool: least-privilege
  pfSense identities are documented and derivable from source, not
  guessed — see [`docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md`](https://night4me.github.io/pfsense-mcp-server/PFSENSE_LEAST_PRIVILEGE_MATRIX/).
- **Strongly typed response models** (Pydantic) for every tool — no
  untyped JSON passthrough.
- **Secret-bearing fields are excluded from the model layer by
  construction** wherever confirmed present (CA/certificate private keys,
  CARP shared secrets, WireGuard keys, OpenVPN client credentials) — never
  relied on upstream API redaction as the only safeguard.

## What you can do

Ask your MCP client things like:

- *"List my VLANs and show which physical interface each one rides on."*
- *"What static routes are configured, and where do they point?"*
- *"Is my WAN gateway up, and what's the current latency and packet loss?"*
- *"What firewall rules apply to the WAN interface?"*
- *"Show me every active DHCP lease and static mapping on the LAN."*
- *"What DNS resolver host overrides and access lists are configured?"*
- *"Are any IPsec tunnels established right now, and what are their child SAs?"*
- *"List my OpenVPN servers and their configured ciphers."*
- *"Which of my certificate authorities and certificates expire soon?"*
- *"What pfSense and REST API package version is this appliance running?"*

Each maps to one typed, capability-gated tool actually present in the
public registry — see [Capability overview](#capability-overview) for the
full breakdown and [`docs/API.md`](https://night4me.github.io/pfsense-mcp-server/API/)
for the complete reference. Nothing above requires WRITE access.

## Why this server

I built this project because I wanted AI assistance for pfSense without
giving an LLM the ability to accidentally disconnect my own network.

A firewall is not just another application. It is the foundation
everything else depends on. Any software capable of changing firewall
rules, routing, interfaces, DNS, VPN configuration, or other
network-critical settings also has the ability to make that network
unreachable — and "the model probably won't make a bad change" is not a
safety mechanism, it's a hope. I believe those operations deserve a
higher safety standard than simply exposing WRITE tools to an AI model.

**This project deliberately started, and remains, READ-only by default.**
Not because WRITE is impossible — a fully authorized, recoverable WRITE
path exists and is described in [Security model](#security-model) — but
because I believe WRITE should be earned through architecture rather than
enabled by implementation.

**What makes the engineering different, not just the policy:**

- **Explicit tool registration, never generic API dispatch.** Every tool
  is one statically checked, named function calling one client method —
  there is no `call_endpoint(path, method)` escape hatch an AI (or a bug)
  could use to reach an unregistered endpoint.
- **95 READ / 0 default-WRITE public contract**, enforced by an automated
  snapshot test — a change to the public surface that isn't reflected in
  the approved contract fails CI.
- **Capability-based least privilege.** Each tool is gated behind a named
  `Capability`; profiles grant capability sets, not raw endpoint access.
- **Deterministic public-contract validation** — the registered tool set,
  its privilege mapping, and its documentation are all re-derived from
  source and checked for drift on every run, not maintained by hand.
- **Secret-bearing fields omitted from models where confirmed present**,
  instead of trusting the upstream API's own redaction behavior.
- **Verification before promotion** — every tool is exercised against a
  real pfSense instance (LAB or production) and confirmed to return the
  expected shape before it is ever added to the public registry.
- **Fail-closed handling** of ambiguous or sensitive capabilities:
  unclear schema behavior is treated as unsafe until proven otherwise,
  not implemented optimistically.
- **CI, CodeQL, and a dedicated release-validation pipeline** gate every
  change — see [Security model](#security-model) for what's actually
  enforced, not just designed.

**The READ trust path, in one diagram:**

<!-- Rendered from assets/diagrams/read-trust-path.mmd -- see that file to
     edit the diagram source, then regenerate this image. README.md
     intentionally never uses a live Mermaid fenced code block: GitHub
     renders one, but PyPI's long_description renderer does not, and
     previously showed the raw Mermaid source as a plain code block
     instead -- see docs/adr/ADR-034-mermaid-pypi-compatibility.md. -->

![READ trust path: AI/MCP client through stdio, an explicitly registered MCP tool, capability/profile gate, least-privilege mapping, one fixed typed client method, a GET-only pfREST call, the pfSense appliance, a typed model boundary excluding secret fields, to a safe MCP result](https://raw.githubusercontent.com/night4me/pfsense-mcp-server/main/assets/diagrams/read-trust-path.svg)

Every one of the 95 tools takes this same path — no exceptions, no
alternate route. The yellow boxes are hard gates (fail closed, not
merely checked); the green box is where confirmed secret-bearing fields
are structurally excluded, not filtered. See
[the full architecture diagrams page](https://night4me.github.io/pfsense-mcp-server/ARCHITECTURE_DIAGRAMS/) for
the detailed sequence diagram this summarizes.

I don't mind if an AI answers a question incorrectly. I do mind if an AI
accidentally disconnects my house from the Internet. That single design
principle explains almost every architectural decision in this
repository. See [the security model](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/) for the complete
picture, including the fully-built (but not default-reachable) WRITE
path.

## Quick start

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --upgrade pfsense-mcp-server
install -m 600 /dev/null /absolute/private/path/pfsense-api.key
# put the API key on the first line of that file, then:
```

```json
{
  "command": "/absolute/path/to/.venv/bin/pfsense-mcp-server",
  "env": {
    "PFSENSE_API_URL": "https://pfsense.example.invalid",
    "PFSENSE_IDENTITY": "api-mcp-admin",
    "PFSENSE_API_KEY_FILE": "/absolute/private/path/pfsense-api.key",
    "PFSENSE_TLS_MODE": "strict"
  }
}
```

Point your MCP client at that command — see [MCP client setup](#mcp-client-setup)
below for client-specific guides — confirm it shows 95 READ tools, 1
guidance tool, and no WRITE tools, then try one of the [example prompts](#what-you-can-do)
above. Full configuration reference, troubleshooting, and every
environment variable: [`docs/CONFIGURATION.md`](https://night4me.github.io/pfsense-mcp-server/CONFIGURATION/).

`pfsense-mcp-server` is published on
[PyPI](https://pypi.org/project/pfsense-mcp-server/) with
[PEP 740](https://peps.python.org/pep-0740/) digital attestations verifiable
back to this repository and the exact release commit — no long-lived upload
token exists.

## Requirements / Compatibility

- **Python:** 3.11, 3.12, or 3.13.
- **pfSense REST API package (`pfrest`/`pfSense-pkg-RESTAPI`):** required,
  API v2. This project pins its models against the **v2.10** schema.

### pfSense edition/version compatibility

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
  platform tested. An earlier draft of this document incorrectly
  concluded from this same endpoint's output that the REST API "ships
  as a built-in platform component" on Plus specifically — that was
  wrong on both counts (Plus does run a real, versioned REST API
  package, and the omission is not a CE-vs-Plus difference); see
  `CHANGELOG.md` for the correction record.
- **Schema/API compatibility**: verified independently of the above, by
  direct structural comparison (267/267 paths, 186/186 components) —
  see the Plus 26.07 row above.

**Package-conditional tools.** Every one of the 95 registered tools'
underlying endpoints was checked against the pfREST schema's own
declared package requirements, not assumed. Two tools
(`pfsense_get_status_wireguard_tunnels`, `pfsense_get_status_wireguard_peers`)
require `pfSense-pkg-WireGuard` **in practice**: they return an
automatically-classified package-absent result (HTTP 404,
`MODEL_MISSING_REQUIRED_PACKAGE`) — never an error — when the package
isn't installed, confirmed directly on both the LAB and production
systems used for this project's testing.

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

## MCP client setup

Guides exist for Claude Desktop, Claude Code, Codex CLI, ChatGPT desktop
(via the Codex host), Cursor, VS Code, and Continue — see
[`examples/README.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)
for the complete, copy-pasteable set. Every guide configures the same
local-stdio launch shown in [Quick start](#quick-start) above; only the
client-specific config file location and key differ.

## Capability overview

| Category | Tools | Examples |
|---|---:|---|
| System | 26 | hostname, timezone, DNS, console, version, packages, REST API settings, cron, ACME, diagnostics, config-history revisions, log settings |
| VPN | 17 | IPsec (Phase 2, encryption options, live SA/child-SA status, pending-apply status), OpenVPN (server config, client-specific overrides, live status), WireGuard (status, tunnel addresses, pending-apply status), CARP |
| Firewall | 15 | rules, aliases, states, NAT (outbound / 1:1 / port forward), schedules, virtual IPs (incl. pending-apply status), traffic shapers |
| DNS | 7 | resolver settings, host/domain overrides, access lists, forwarder overrides, forwarder/resolver pending-apply status |
| Interfaces | 9 | interface status, VLANs, groups, bridges, GRE, LAGG, available interfaces, pending-apply status |
| DHCP | 7 | servers, static mappings, leases, relay, address pools, custom options, pending-apply status |
| Routing / Gateways | 6 | gateways, gateway status, gateway groups, default gateway, static routes, pending-apply status |
| Certificates / PKI | 3 | certificates, certificate authorities, CRLs |
| Users / API identities | 3 | local users, user groups, API keys |
| Services / Monitoring | 2 | service status, FreeRADIUS EAP |

95 pfSense READ tools total (plus the separately-counted official
guidance tool described below — never blended into this figure). Full
per-tool reference, parameters, and security notes:
[`docs/API.md`](https://night4me.github.io/pfsense-mcp-server/API/).

## Official documentation guidance layer

A subsystem (`src/pfsense_mcp/guidance/`,
[ADR-017](https://night4me.github.io/pfsense-mcp-server/adr/ADR-017-official-guidance-layer/) /
[ADR-018](https://night4me.github.io/pfsense-mcp-server/adr/ADR-018-version-aware-guidance-resolution/))
providing a deterministic, capability-keyed lookup over a small, curated
registry of **project-authored summaries** of official Netgate/pfSense
documentation (`docs.netgate.com` only) — meant to give a human or AI
client *context* about what a capability is, never *authority* to act on
it. As of 2026-08-22 this is reachable through exactly one MCP tool,
`pfsense_get_official_guidance` (Candidate A from
`reports-ai/GUIDANCE_MCP_EXPOSURE_QUALIFICATION_2026-08-22.md`,
owner-authorized).

- **What it is**: a Git-tracked, PR-reviewed registry mapping a
  capability (e.g. "firewall NAT") to one or more entries, each an
  independently-written summary (never a quotation) plus its canonical
  source URL, edition (CE/Plus) applicability, and an applicability state
  — never a full-page mirror, and never redistributed Netgate prose. The
  only verbatim text kept anywhere is a short (≤300 char) maintainer-only
  verification anchor, used solely to detect if a source page has
  drifted; it is never returned to any consumer, including this tool.
- **The tool**: `pfsense_get_official_guidance(capability)` takes exactly
  one input — a pfsense-mcp-server capability name (e.g.
  `"FIREWALL_NAT_READ"`) — and returns the registered guidance for it,
  structurally distinguished from live appliance state: every result
  carries a fixed `disclaimer` field stating it is documentation
  guidance, not observed state, and not an authorization. It is **not** a
  pfSense appliance READ capability (no new `Capability` enum member was
  added for it, and it is not gated by the capability/privilege/profile
  system), **not** a WRITE capability, **not** an arbitrary documentation
  search tool, URL fetcher, or web browser.
- **Appliance identity is tool-resolved, never model-supplied**: the tool
  itself calls the same already-authenticated pfSense client every other
  READ tool uses (the existing `pfsense_get_system_version`-equivalent
  call) to determine CE/Plus edition and version for applicability
  resolution — the caller never supplies this. If that call fails for any
  reason, the tool fails closed to "edition/version unknown" rather than
  trusting an unverified guess.
- **What it is not**: it does not read this server's own live pfSense
  configuration state, does not know anything else about *your*
  appliance, and cannot grant, expand, or imply any capability or WRITE
  authorization — its output type has no field a capability, endpoint,
  HTTP method, or confirmation token could be read from (enforced by
  AST-scanned isolation tests, not only by convention).
- **Network behavior**: zero runtime documentation network calls. The
  registry is a bundled snapshot, loaded once from source at import
  time; the tool's only network call is the one appliance-identity
  lookup described above. A separate, maintainer-invoked script
  (`make guidance-corpus-audit`) periodically re-fetches each cited URL
  to confirm the short verification anchor is still present verbatim — a
  dev-time check, never something a running server or an MCP tool call
  triggers.
- **Current coverage**: 28 of 86 total READ capabilities (32.6% raw,
  43.1% effective excluding capabilities with no independent
  documentation concept). Honest, not padded — see
  `reports-ai/GUIDANCE_COVERAGE_MAPPING_2026-08-22.md` for the full,
  source-derived breakdown including category-level gaps.

## Security model

- Credential fields (API keys, passwords, private keys) never appear in a
  public model, MCP schema, log line, or exception message — by
  construction, not filtering.
- Fail-closed configuration and strict TLS by default.
- Explicit capability gates: an MCP tool is reachable only if its capability
  is in the selected profile's accepted set.
- The supported transport is local stdio; the process controlling that
  channel is the trust boundary — see
  [the threat model](https://night4me.github.io/pfsense-mcp-server/THREAT_MODEL/) for exactly what that does and
  does not cover.

Every claim above is backed by a specific test class, listed with the tests
that enforce it in [`SECURITY.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md#security-guarantees). Report
vulnerabilities privately through [`SECURITY.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md) — never in a
public issue.

### Protected WRITE architecture (built, not default-reachable)

pfSense MCP Server ships a fully built, twice live-verified WRITE
architecture that remains unreachable unless an operator explicitly opts
in. State-changing operations are protected by a transaction-oriented
security architecture designed for AI-initiated infrastructure changes —
not simply an API credential placed behind an MCP tool.

- Zero WRITE capabilities exposed by default — reaching the one accepted
  WRITE tool requires an operator to explicitly select
  `PFSENSE_PROFILE=write_protected`.
- Least-privilege pfSense credentials, scoped to exactly the REST
  endpoints the WRITE path needs — never a broad/administrative account.
- Deterministic plan and execution-intent binding — the exact target
  state is bound cryptographically before anything is authorized.
- Ed25519-signed authorization, produced off-host by a human operator,
  short-lived and single-use.
- Fresh-state revalidation before execution, with stale-state and
  concurrent-change refusal.
- A `RecoveryContract` state machine governing every mutation's full
  lifecycle, durable and auditable, with independently signed
  confirmation from a separate confirmation authority.
- Deterministic execution with authoritative read-back verification and
  fail-closed reconciliation on any ambiguous outcome — never a blind
  retry.
- Integrity-protected, MAC-authenticated audit trail and state.
- Hardware-backed TPM monotonic witness for anti-rollback protection —
  the only anchor-assurance backend implemented today (a software-only
  posture is modeled but has no backend yet) and required for a plan to
  be considered safe to proceed in production.

**The authorization path, in one diagram:**

<!-- Rendered from assets/diagrams/write-authorization-path.mmd -- see
     that file to edit the diagram source, then regenerate this image.
     Same PyPI-compatibility reason as the READ-path diagram above --
     see docs/adr/ADR-034-mermaid-pypi-compatibility.md. -->

![Authorization path: the default profile has 0 WRITE tools and is not reachable; an explicit operator opt-in provisions the write_protected profile plus full Tier 1 material; that requires off-host signed authorization and confirmation from separate identities, six fail-closed gates, a sealed MutationExecutor that is the only path that ever sends, and an authoritative read-back whose outcome is either VERIFIED or, if ambiguous, RECONCILIATION -- never a blind retry](https://raw.githubusercontent.com/night4me/pfsense-mcp-server/main/assets/diagrams/write-authorization-path.svg)

**Implemented, verified, and default-reachable are three different
things — do not conflate them.** This path is *implemented* (real code,
shown above) and *verified* (twice, end-to-end, against a real
disposable LAB appliance) for exactly one operation. It is **not**
default-reachable: an operator must explicitly opt out of the default
profile, and even then an AI cannot single-handedly produce a valid
authorization — that requires an off-host Ed25519 signature the running
server never holds the key for. See
[the full authorization-path diagram](https://night4me.github.io/pfsense-mcp-server/ARCHITECTURE_DIAGRAMS/) for
the gate-by-gate detail and
[the defense-in-depth diagram](https://night4me.github.io/pfsense-mcp-server/ARCHITECTURE_DIAGRAMS/) for how this
fits alongside the READ path.

**`verified=True` does not mean WRITE is enabled by default.**
Verification, profile/posture selection, authorization, confirmation,
freshness, target state, and execution are separate, independently
enforced gates — every one of them must hold for a given mutation, every
time. The protected WRITE path has been exercised end-to-end **twice**,
each time independently verified, against a real disposable LAB pfSense
appliance — never production/home pfSense — including least-privilege
execution through a dedicated 4-privilege pfSense identity, authoritative
read-back, full `RecoveryContract` lifecycle, and TPM hardware witness
advancement confirmed against the physical device both times. See
[`docs/adr/ADR-026-first-write-capability-adapter.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/docs/adr/ADR-026-first-write-capability-adapter.md)
for the complete evidence chain, and
[the Tier 1 architecture](https://night4me.github.io/pfsense-mcp-server/TIER1_ARCHITECTURE/) for the full design.

## Troubleshooting

| Symptom | Likely cause | Diagnostic action |
|---|---|---|
| MCP client shows 0 tools / fails to start | Wrong command path, or the venv's `pfsense-mcp-server` entry point isn't executable | Run the command directly from a shell with the same `env` block; read the stderr output verbatim |
| `configuration error` on startup | A required environment variable is missing or malformed | Compare against [`docs/CONFIGURATION.md`](https://night4me.github.io/pfsense-mcp-server/CONFIGURATION/) — the process fails closed rather than guessing a default |
| `401`/authentication failures | Wrong API key, wrong `PFSENSE_IDENTITY`, or the key file has the wrong permissions/first-line format | Re-verify the key file's first line matches the key shown in pfSense's REST API user settings; confirm the identity string matches the pfSense user the key belongs to |
| `403`/insufficient-privilege failures on specific tools | The pfSense identity lacks the narrow privilege that tool needs | Cross-check the required privilege in [`docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md`](https://night4me.github.io/pfsense-mcp-server/PFSENSE_LEAST_PRIVILEGE_MATRIX/) against the identity's assigned privileges in pfSense |
| TLS/certificate verification errors | `PFSENSE_TLS_MODE=strict` against a self-signed or internal-CA certificate | Either install a trusted certificate on pfSense, or set `PFSENSE_TLS_MODE=auto` with `PFSENSE_TLS_CA_FILE` pointed at your internal CA — never disable verification entirely |
| A specific tool always returns an empty/package-absent result | The underlying pfSense feature or package (e.g. WireGuard) isn't installed/configured on that appliance | Confirm via pfSense's own package manager or configuration UI; this is expected behavior, not a bug — see [Compatibility](#requirements--compatibility) |
| REST API unreachable / connection refused | The `pfrest`/`pfSense-pkg-RESTAPI` package is disabled or not installed on the appliance | Confirm the package is installed and enabled in pfSense's package manager; confirm `PFSENSE_API_URL` and network reachability |
| Works on one pfSense version, not another | A genuine platform/schema incompatibility | Check [Compatibility](#requirements--compatibility) for your exact platform/version combination before filing an issue |
| Timeouts under load | Default HTTP timeouts, or the pfSense appliance is under heavy load | Confirm the appliance itself is responsive via its own web UI; this project does not currently expose a configurable timeout — see [`docs/CONFIGURATION.md`](https://night4me.github.io/pfsense-mcp-server/CONFIGURATION/) for current limits |

None of the above are resolved by weakening TLS verification, broadening
credentials, or selecting `write_protected` — if a READ tool fails, the
fix is almost always a narrower privilege grant or a configuration
correction, not a broader one.

## Documentation

A browsable version of the full documentation set below is published at
[night4me.github.io/pfsense-mcp-server](https://night4me.github.io/pfsense-mcp-server/)
(built with `make docs-serve` for a local preview); see
[`docs/index.md`](https://night4me.github.io/pfsense-mcp-server/) for the same map.

- [MCP tool reference](https://night4me.github.io/pfsense-mcp-server/API/)
- [Configuration reference](https://night4me.github.io/pfsense-mcp-server/CONFIGURATION/)
- [Client setup examples](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)
- [Least-privilege matrix](https://night4me.github.io/pfsense-mcp-server/PFSENSE_LEAST_PRIVILEGE_MATRIX/)
- [Security model](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/) · [Threat model](https://night4me.github.io/pfsense-mcp-server/THREAT_MODEL/)
- [Architecture diagrams](https://night4me.github.io/pfsense-mcp-server/ARCHITECTURE_DIAGRAMS/) · [Architecture decisions](https://night4me.github.io/pfsense-mcp-server/adr/)
- [Tier 1 safety architecture](https://night4me.github.io/pfsense-mcp-server/TIER1_ARCHITECTURE/) · [Public roadmap](https://night4me.github.io/pfsense-mcp-server/ROADMAP/)
- [Contributing](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md) · [Support](https://github.com/night4me/pfsense-mcp-server/blob/main/SUPPORT.md) · [Security policy](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md)

## Release status

**v0.7.1 is the immutable production baseline, published on PyPI —
95 pfSense READ tools + 1 official-guidance tool, 0 WRITE tools.** A
documentation/packaging presentation correction over `v0.7.0` — no MCP
capability change, no runtime security-semantic change, public contract
byte-identical to `v0.7.0`. It corrects a stale Quick start install
command `v0.7.0` shipped with (`pip install
'pfsense-mcp-server==0.5.1'`, unnoticed across two releases and
permanently baked into `v0.7.0`'s own published PyPI project page,
since PyPI cannot re-render an already-published artifact's
description) and a handful of stale current-state documentation
references found during the same sweep. See `CHANGELOG.md`'s `[0.7.1]`
entry and `docs/ACCEPTANCE_v0.7.1.md` for the complete, independently
verified evidence.

`v0.7.0` itself was the first release to add
`pfsense_get_official_guidance` — a separate, structurally distinct MCP
tool that returns project-authored summaries of official
Netgate/pfSense documentation, from a deterministic, Git-tracked,
bundled registry with no runtime documentation retrieval, each entry
carrying structural provenance (canonical Netgate source URL, evidence
level, and an applicability state resolved from the appliance's own
observed edition/version). It is **not** a 96th pfSense READ capability:
it is not gated by the `Capability`/privilege/profile system, and the
pfSense appliance READ surface itself was unchanged from `v0.6.0` —
still exactly 95 tools, 94 distinct privileges, 0 default-reachable
WRITE. `v0.6.0` itself was a READ-capability expansion release over
`v0.5.1` — public READ tool count grew from 84 to 95 (config-history
revisions, log settings, 8 apply-status endpoints, and WireGuard tunnel
addresses), useful READ coverage against this project's own
capability-audit denominator grew from roughly 80% to roughly 90%. No
WRITE capability, capability semantic, or default reachability changed
across any of these releases. Every new tool was exercised against this
project's disposable LAB appliance before public registration; none
have yet been exercised against production — see
[Compatibility](#requirements--compatibility) for the precise,
per-release evidence-tier distinction. `v0.5.1` was a documentation-
accuracy and security-communication patch over `v0.5.0` — no MCP
capability change, no runtime security-semantic change, public contract
byte-identical to `v0.5.0`. `v0.5.0` itself was a major READ-capability
expansion over the prior `v0.4.2` baseline — exactly a 100% increase in
public READ tool count (42 → 84) — driven by a comprehensive capability
discovery audit that found the prior 42-tool contract covered only ~40%
of the useful READ capability universe. All four prior releases' own
tags, GitHub Releases, and PyPI artifacts remain unmoved as an accurate
historical record — see `CHANGELOG.md`'s `[0.7.0]`, `[0.6.0]`,
`[0.5.1]`, and `[0.5.0]` entries for their complete, tool-by-tool lists
and every security-relevant finding along the way.

The one WRITE capability this repository has ever added
(`set_firewall_alias_description_v1`) is `verified=True` following
independently-verified live evidence (`ADR-026`), but remains
unreachable under the default profile, requires an operator to
explicitly opt into `write_protected`, and still requires a real,
owner-driven signing ceremony for every individual mutation — see
[the security model](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/)'s "Recovery and WRITE status"
section for the precise, current description. The Tier 1 safety
framework described above remains implemented, tested, structurally
isolated code, unchanged by this release.

`v0.4.2` was a documentation/packaging-presentation patch over `v0.4.1`
— no functional or security-relevant change — and remains a valid,
installable historical release, as does `v0.4.1` itself. `v0.4.0` was
tagged and its GitHub Release published, but its PyPI publication
failed outright before any upload was attempted — see `CHANGELOG.md`'s
`[0.4.1]` entry for the full root cause; per this project's release
policy, `v0.4.0`'s tag/Release are preserved unmoved as an accurate
historical record. See
[`docs/ROADMAP.md`](https://night4me.github.io/pfsense-mcp-server/ROADMAP/) for what's next.

## Contributing

Contributions are welcome within the documented security and approval
boundaries. Read [CONTRIBUTING.md](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md) before opening a change.

## License

Licensed under the [MIT License](https://github.com/night4me/pfsense-mcp-server/blob/main/LICENSE).
