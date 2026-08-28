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

## What it does

- **95 public READ tools + 1 documentation guidance tool.** Covers
  roughly 90% of pfSense's useful REST API READ surface. Every tool is
  strongly typed (Pydantic) — no untyped JSON passthrough.
- **0 WRITE tools by default.** A fully built, twice live-verified
  protected-WRITE path exists but requires an explicit operator opt-in
  — see [Safety by default](#safety-by-default).
- **Ask it things like**: *"List my VLANs and which interface each one
  rides on,"* *"Is my WAN gateway up right now?"*, *"Which certificates
  expire soon?"*, *"What DHCP leases are active on the LAN?"* — every
  question maps to one typed, capability-gated tool.

## Safety by default

- **READ-oriented public MCP surface, 0 default-reachable WRITE.**
  Enforced by an automated snapshot test, not just documented — a
  change to the public tool contract that isn't reflected in the
  approved snapshot fails CI.
- **Explicit tool registration, never generic API dispatch.** There is
  no `call_endpoint(path, method)` escape hatch an AI (or a bug) could
  use to reach an unregistered endpoint.
- **Capability-based least privilege**, with secret-bearing fields
  excluded from the response model by construction wherever confirmed
  present — never relying on the upstream API's own redaction alone.
- **Guidance is data, never authority.** The one documentation-guidance
  tool structurally cannot influence, select, or authorize any action —
  see [Tool & guidance reference](https://night4me.github.io/pfsense-mcp-server/TOOL_AND_GUIDANCE_REFERENCE/).

I built this because I wanted AI assistance for pfSense without giving
an LLM the ability to accidentally disconnect my own network — a
firewall deserves a higher safety standard than "the model probably
won't make a bad change." See
[Why this project exists](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/#why-this-project-exists)
for the full reasoning.

<!-- Rendered from assets/diagrams/read-trust-path.mmd -- see that file to
     edit the diagram source, then regenerate this image. README.md
     intentionally never uses a live Mermaid fenced code block: GitHub
     renders one, but PyPI's long_description renderer does not -- see
     docs/adr/ADR-034-mermaid-pypi-compatibility.md. -->

![READ trust path: AI/MCP client through stdio, an explicitly registered MCP tool, capability/profile gate, least-privilege mapping, one fixed typed client method, a GET-only pfREST call, the pfSense appliance, a typed model boundary excluding secret fields, to a safe MCP result](https://raw.githubusercontent.com/night4me/pfsense-mcp-server/main/assets/diagrams/read-trust-path.svg)

Every one of the 95 READ tools takes this same path — no exceptions.

### The protected-WRITE path (built, not default-reachable)

A fully built, twice live-verified WRITE architecture exists for exactly
one operation (a firewall alias's description field) but stays
unreachable unless an operator explicitly opts in: `write_protected`
must be selected, an off-host Ed25519 signature the running server never
holds the key for must authorize it, and a separate confirmation
authority must confirm it — see
[the security setup wizard](https://night4me.github.io/pfsense-mcp-server/SECURITY_SETUP_WIZARD/)
and [the security model](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/)
for exactly what it requires and does not do by default.

<!-- Rendered from assets/diagrams/write-authorization-path.mmd -- see
     that file to edit the diagram source, then regenerate this image.
     Same PyPI-compatibility reason as the READ-path diagram above. -->

![Authorization path: the default profile has 0 WRITE tools and is not reachable; an explicit operator opt-in provisions the write_protected profile plus full Tier 1 material; that requires off-host signed authorization and confirmation from separate identities, six fail-closed gates, a sealed MutationExecutor that is the only path that ever sends, and an authoritative read-back whose outcome is either VERIFIED or, if ambiguous, RECONCILIATION -- never a blind retry](https://raw.githubusercontent.com/night4me/pfsense-mcp-server/main/assets/diagrams/write-authorization-path.svg)

See [the full architecture diagrams page](https://night4me.github.io/pfsense-mcp-server/ARCHITECTURE_DIAGRAMS/)
for the gate-by-gate detail behind both diagrams above.

## Requirements

- **Python** 3.11, 3.12, or 3.13.
- **pfSense** with the REST API package (`pfrest`/`pfSense-pkg-RESTAPI`,
  API v2) installed and enabled.

See [Compatibility](https://night4me.github.io/pfsense-mcp-server/COMPATIBILITY/)
for exactly which pfSense editions/releases are directly verified vs.
merely expected to work.

## Quick start

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --upgrade pfsense-mcp-server
install -m 600 /dev/null /absolute/private/path/pfsense-api.key
# paste your pfSense API key as the file's first line, then:
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

Point your MCP client at that command (see
[Connect your MCP client](#connect-your-mcp-client) below), confirm it
shows 97 tools (95 READ + 2 guidance, 0 WRITE), then try one of the
prompts from [What it does](#what-it-does) above. Full walkthrough,
credential handling, and verification steps:
[Installation](https://night4me.github.io/pfsense-mcp-server/INSTALLATION/).

## First setup

Prefer a dedicated, least-privilege pfSense identity over reusing an
existing credential? The bundled operator CLI can provision and verify
one for you:

```console
pfsense-mcp-security setup
```

This is a guided, **non-mutating** wizard — it only plans; nothing is
provisioned until a separate, explicit `setup apply` step with a
confirmation token you've reviewed. Full walkthrough, including the
optional protected-WRITE opt-in:
[Security setup wizard](https://night4me.github.io/pfsense-mcp-server/SECURITY_SETUP_WIZARD/).

## Connect your MCP client

Once your server configuration works, generate the exact client config
block automatically:

```console
pfsense-mcp-security setup write-client-config \
  --client claude-desktop --config-path /absolute/path/to/claude_desktop_config.json \
  --capability-posture read_only --anchor-assurance none
```

Or copy one of the ready-made per-client guides — Claude Desktop,
Claude Code, Codex CLI, ChatGPT desktop, Cursor, VS Code, Continue — from
[`examples/README.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md).
Full detail on both paths:
[Connect your MCP client](https://night4me.github.io/pfsense-mcp-server/MCP_CLIENT_CONFIGURATION/).

## What you get

| Category | Tools | Examples |
|---|---:|---|
| System | 26 | hostname, DNS, version, packages, REST API settings, diagnostics |
| VPN | 17 | IPsec, OpenVPN, WireGuard status/config, CARP |
| Firewall | 15 | rules, aliases, states, NAT, schedules, virtual IPs, traffic shapers |
| DNS | 7 | resolver settings, overrides, access lists |
| Interfaces | 9 | status, VLANs, groups, bridges, LAGG |
| DHCP | 7 | servers, static mappings, leases, relay |
| Routing / Gateways | 6 | gateways, gateway status, static routes |
| Certificates / PKI | 3 | certificates, certificate authorities, CRLs |
| Users / API identities | 3 | local users, user groups, API keys |
| Services / Monitoring | 2 | service status, FreeRADIUS EAP |

Full per-tool reference, parameters, and provenance:
[MCP tool reference](https://night4me.github.io/pfsense-mcp-server/API/) ·
[Tool & guidance reference](https://night4me.github.io/pfsense-mcp-server/TOOL_AND_GUIDANCE_REFERENCE/).

## Documentation

- [Installation](https://night4me.github.io/pfsense-mcp-server/INSTALLATION/) ·
  [Compatibility](https://night4me.github.io/pfsense-mcp-server/COMPATIBILITY/)
- [Security setup wizard](https://night4me.github.io/pfsense-mcp-server/SECURITY_SETUP_WIZARD/) ·
  [Connect your MCP client](https://night4me.github.io/pfsense-mcp-server/MCP_CLIENT_CONFIGURATION/)
- [Configuration reference](https://night4me.github.io/pfsense-mcp-server/CONFIGURATION/) (env vars, troubleshooting)
- [MCP tool reference](https://night4me.github.io/pfsense-mcp-server/API/) ·
  [Tool & guidance reference](https://night4me.github.io/pfsense-mcp-server/TOOL_AND_GUIDANCE_REFERENCE/)
- [Security model](https://night4me.github.io/pfsense-mcp-server/SECURITY_MODEL/) ·
  [Threat model](https://night4me.github.io/pfsense-mcp-server/THREAT_MODEL/)
- [Architecture diagrams](https://night4me.github.io/pfsense-mcp-server/ARCHITECTURE_DIAGRAMS/) ·
  [Architecture decisions](https://night4me.github.io/pfsense-mcp-server/adr/)
- [Tier 1 safety architecture](https://night4me.github.io/pfsense-mcp-server/TIER1_ARCHITECTURE/) ·
  [Public roadmap](https://night4me.github.io/pfsense-mcp-server/ROADMAP/)
- [Contributing](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md) ·
  [Support](https://github.com/night4me/pfsense-mcp-server/blob/main/SUPPORT.md) ·
  [Security policy](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md)

## Release status

**v0.9.0 is the immutable production baseline, published on PyPI —
95 pfSense READ tools + 2 documentation guidance tools, 0 WRITE
tools.** Adds `pfsense_get_api_guidance`, a second, structurally
distinct guidance tool covering the community-maintained pfREST
package (`pfSense-pkg-RESTAPI`, documented at pfrest.org) — never
blended with `pfsense_get_official_guidance` (Netgate product
documentation). Evidence is explicitly labeled by provenance
(`PROJECT_AUTHORED` / `PFREST_UPSTREAM` / `LIVE_APPLIANCE_SCHEMA` /
`OFFICIAL_NETGATE`); documentation is data, never authority. See
`CHANGELOG.md`'s `[0.9.0]` entry and `docs/ACCEPTANCE_v0.9.0.md` for
the complete, independently verified evidence, and `CHANGELOG.md` in
full for every prior release's own complete history — every past
release's tag, GitHub Release, and PyPI artifact remains unmoved as an
accurate historical record.

## Contributing

Contributions are welcome within the documented security and approval
boundaries. Read [CONTRIBUTING.md](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md) before opening a change.

## License

Licensed under the [MIT License](https://github.com/night4me/pfsense-mcp-server/blob/main/LICENSE).
