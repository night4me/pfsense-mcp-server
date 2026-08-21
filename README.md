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

- **84 public READ tools. 0 public WRITE tools by default.**
- Covers roughly **80% of the useful READ capability surface** identified
  by this project's own capability audit (267 OpenAPI paths / 243 GET
  operations reviewed, every one given an explicit disposition).
- Every tool is **verified against a real pfSense instance** before public
  registration — LAB or production, never assumed from schema alone — see
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
- **84 READ / 0 default-WRITE public contract**, enforced by an automated
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
.venv/bin/python -m pip install 'pfsense-mcp-server==0.5.0'
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
below for client-specific guides — confirm it shows 84 READ tools and no
WRITE tools, then try one of the [example prompts](#what-you-can-do)
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

Evidence tiers used below:

| Tier | Meaning |
|---|---|
| **LIVE VERIFIED** | Exercised against a real, live pfSense installation (LAB or production) with this project's own registered tools. |
| **LAB VERIFIED** | Exercised against the project's controlled, disposable LAB appliance. |
| **SUPPORTED / COMPATIBLE** | Not directly exercised, but sufficiently established by matching API/schema/platform evidence from a verified adjacent version. |
| **EXPECTED COMPATIBLE / UNVERIFIED** | Reasonable expectation from public documentation only; insufficient evidence for a stronger claim. |

| Platform | Version | Status | Evidence |
|---|---|---|---|
| pfSense CE | 2.9.0 (FreeBSD 16.0-CURRENT, pfREST 2.10) | **LAB VERIFIED** | Current LAB baseline; full public contract exercised against a disposable, isolated appliance. |
| pfSense CE | 2.8.1 (pfREST 2.10) | **LAB VERIFIED** | Prior LAB baseline; this project's READ-expansion audit's initial 7-tool backlog was verified here before the LAB's platform upgrade to CE 2.9.0. |
| pfSense Plus | 26.07-RELEASE | **LIVE VERIFIED** | Owner-authorized, READ-only production compatibility pass: 82 of 84 public tools invoked successfully with real data (30 valid-empty results); the remaining 2 (WireGuard status) correctly and automatically classified as package-absent, not a compatibility failure. Schema-level: the live OpenAPI schema matched the pinned v2.10 reference exactly — 267/267 paths, 186/186 components; the only differences found across every field in every component were 5 instance-specific runtime default values, never a type or nullability change. Zero secret-bearing fields present in any exercised response. |
| pfSense Plus | 25.11 | **SUPPORTED / COMPATIBLE** (not live-verified) | No live or LAB access was available for this version. Classified as supported based on converging evidence: it shares the same FreeBSD 16-CURRENT base OS as both the CE 2.9.0 LAB baseline and the live-verified Plus 26.07 instance; it is one platform-version step from a build already proven to have zero schema drift from the pinned v2.10 reference; and the same pfREST v2.10 package this project pins against already spans CE 2.8.1, CE 2.9.0, and Plus 26.07 without incident in this project's own testing. This is an inference from strong adjacent evidence, not a test result — treat accordingly. |

pfSense REST API package versioning is **not** required to numerically
match the pfSense platform version — a single pfREST release (v2.10 here)
has been directly confirmed compatible across three different
platform/edition combinations above. On pfSense Plus, the REST API ships
as a built-in platform component rather than a separately versioned
add-on package, so its exact internal version is not independently
discoverable the way `pfSense-pkg-RESTAPI`'s package version is on CE;
schema-level comparison (above) is used instead.

**Package-conditional tools.** Two tools
(`pfsense_get_status_wireguard_tunnels`, `pfsense_get_status_wireguard_peers`)
require `pfSense-pkg-WireGuard` to be installed; they return a
package-absent result (not an error) when it isn't. No other tool in the
public contract has an external package dependency.

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
| System | 24 | hostname, timezone, DNS, console, version, packages, REST API settings, cron, ACME, diagnostics |
| Firewall | 14 | rules, aliases, states, NAT (outbound / 1:1 / port forward), schedules, virtual IPs, traffic shapers |
| VPN | 14 | IPsec (Phase 2, encryption options, live SA/child-SA status), OpenVPN (server config, client-specific overrides, live status), WireGuard status, CARP |
| DHCP | 6 | servers, static mappings, leases, relay, address pools, custom options |
| Interfaces | 8 | interface status, VLANs, groups, bridges, GRE, LAGG, available interfaces |
| DNS | 5 | resolver settings, host/domain overrides, access lists, forwarder overrides |
| Routing / Gateways | 5 | gateways, gateway status, gateway groups, default gateway, static routes |
| Certificates / PKI | 3 | certificates, certificate authorities, CRLs |
| Users / API identities | 3 | local users, user groups, API keys |
| Services / Monitoring | 2 | service status, FreeRADIUS EAP |

84 tools total. Full per-tool reference, parameters, and security notes:
[`docs/API.md`](https://night4me.github.io/pfsense-mcp-server/API/).

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
- Optional hardware-backed TPM monotonic witness for anti-rollback
  protection.

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

**v0.5.0 is the immutable production baseline, published on PyPI —
84 READ tools, 0 WRITE tools.** A major READ-capability expansion over
the prior `v0.4.2` baseline — exactly a 100% increase in public READ
tool count (42 → 84) — driven by a comprehensive capability discovery
audit that found the prior 42-tool contract covered only ~40% of the
useful READ capability universe; v0.5.0 covers roughly 80%. See
`CHANGELOG.md`'s `[0.5.0]` entry for the complete, tool-by-tool list,
the pfSense CE/Plus compatibility verification performed for this
release, and every security-relevant finding along the way.

The one WRITE capability this repository has ever added
(`set_firewall_alias_description_v1`) is `verified=True` following
independently-verified live evidence (`ADR-026`), but remains
unreachable under the default profile, requires an operator to
explicitly opt into `write_protected`, and still requires a real,
owner-driven signing ceremony for every individual mutation — see
[the security model](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/)'s "Recovery and WRITE status"
section for the precise, current description. The Tier 1 safety
framework described above remains implemented, tested, structurally
isolated code, unchanged by this READ expansion.

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
