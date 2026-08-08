# pfsense-mcp-server

[![CI](https://github.com/night4me/pfsense-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/night4me/pfsense-mcp-server/actions/workflows/ci.yml)
[![CodeQL](https://github.com/night4me/pfsense-mcp-server/actions/workflows/codeql.yml/badge.svg)](https://github.com/night4me/pfsense-mcp-server/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/pfsense-mcp-server.svg)](https://pypi.org/project/pfsense-mcp-server/)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A security-first [MCP](https://modelcontextprotocol.io/) server for pfSense.**

MCP (Model Context Protocol) is the open standard AI assistants use to call
tools. This server implements it for pfSense: point an MCP client (Claude,
Codex, Cursor, and others) at it, and it gets strongly typed, read-only
visibility into one pfSense appliance — system, network, firewall, services,
users, certificates, and diagnostics — without exposing raw shell access, an
unaudited scripting surface, or a way to mutate the appliance by accident.

**Current production contract: 41 READ tools. 0 WRITE tools.**

That split is deliberate, not incomplete. See
[Why this project exists](#why-this-project-exists) below.

## Quick start

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install 'pfsense-mcp-server==0.2.2'
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

Point your MCP client at that command (the exact configuration key varies by
client — see [verified client examples](examples/README.md)), confirm it
shows 41 READ tools and no WRITE tools, then try one of the
[example prompts](#example-prompts) below. Full configuration reference,
troubleshooting, and every environment variable:
[`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

`pfsense-mcp-server` is published on
[PyPI](https://pypi.org/project/pfsense-mcp-server/) with
[PEP 740](https://peps.python.org/pep-0740/) digital attestations verifiable
back to this repository and the exact release commit — no long-lived upload
token exists. To build from source instead, see
[`CONTRIBUTING.md`](CONTRIBUTING.md#local-setup).

## Example prompts

Ask your MCP client things like:

- *"Is my WAN gateway up, and what's the current latency and packet loss?"*
- *"Show me every active DHCP lease on the LAN."*
- *"What's the link status of each interface right now?"*
- *"What firewall rules apply to the WAN interface?"*
- *"Are all the services I've configured actually running?"*
- *"Which of my certificates expire in the next 30 days?"*
- *"Is CARP failover healthy across my HA pair?"*
- *"What DNS resolver overrides are configured, and do any look wrong?"*

Each maps to one typed, capability-gated tool — see the
[full tool reference](docs/API.md) for the complete 41-tool catalog.

## Why this project exists

Most pfSense automation options are one of two things: hand-rolled scripts
against the REST/XML-RPC/SSH surface with no safety net, or an assistant
integration that treats "add a mutation endpoint" and "safely activate a
mutation endpoint" as the same problem. They aren't. A firewall is exactly
the kind of system where a plausible-looking automated change can silently
take a network offline — and where "the AI meant well" is not a recovery
plan.

This project's answer is to treat mutation as a safety-engineering problem,
not a feature flag:

- **The current production surface is READ-only by construction**, not by
  convention — enforced by a static check over the transport layer, verified
  on every CI run, not a runtime setting someone could accidentally flip.
- **Writing the code for a future capability does not activate it.** The
  v0.3.0 development tree already contains a substantial WRITE-safety
  framework — and every part of it remains structurally unreachable from
  the running server until a separate, explicit authorization is granted.
- **When a first mutation capability is eventually activated**, it will
  only be reachable through a pipeline designed so no single mistake — a
  bad prompt, a race, a network timeout, a crash mid-request — can leave
  the appliance in an unknown or unrecoverable state:

```mermaid
flowchart LR
    subgraph today["Active today"]
        direction LR
        A1[MCP client] -->|stdio| A2[41 capability-gated<br/>READ tools]
        A2 --> A3[GET-only client]
        A3 -->|HTTPS GET| A4[(pfSense)]
    end

    subgraph future["Designed, tested, still inert — requires separate owner authorization to ever activate"]
        direction LR
        B1[Authorized intent] --> B2[Recovery Contract]
        B2 --> B3[Authenticated<br/>owner confirmation]
        B3 --> B4[Sealed executor]
        B4 --> B5[Semantic verification<br/>/ reconciliation]
        B5 --> B6[Disposable-lab<br/>evidence]
    end
```

Every box in the "designed, tested, still inert" half already exists as
real, tested code — a canonical Recovery Contract bound to the exact target
and intent; a closed state machine with crash-safe, atomic persistence;
Ed25519-authenticated owner confirmation and reconciliation; a sealed
executor that is the *only* component ever allowed to send one bounded
mutating request and classify what actually happened, rather than assume
success; and an offline-tested fault-injection harness for disposable-lab
validation before any of it ever touches a real appliance. None of it is
reachable today. See
[the Tier 1 architecture](docs/TIER1_ARCHITECTURE.md) and the
[public roadmap](docs/ROADMAP.md) for the complete picture, and
[the security model](docs/SECURITY_MODEL.md) for what's actually enforced,
not just designed.

### A note from the maintainer

pfSense is critical infrastructure in my own network, and this project
started because I wanted an AI assistant to be able to *look* at it, not
because I was ready to let one *change* it. I'm not comfortable giving an
AI agent unrestricted mutation access to the firewall a network depends
on — and "the model probably won't make a bad change" isn't a safety
mechanism to me, it's a hope.

A mistaken tool invocation, a misunderstood request, an implementation
defect, or a weak authorization boundary can alter firewall rules,
routing, DNS, interface configuration, VPN state, or other
connectivity-critical settings. Other MCP servers for pfSense expose
mutation more directly, and that can be a perfectly reasonable choice for
a different threat model and different priorities than mine — I'm not
claiming they're unsafe, only that my own risk tolerance for this
specific piece of infrastructure is lower. I'd rather ship a smaller,
READ-only surface first and treat WRITE activation as a genuine
engineering and safety problem — a recovery contract, an authenticated
confirmation step, a sealed executor, disposable-lab evidence, all behind
an explicit activation decision I make myself — than add mutating tools
and hope nothing goes wrong.

An AI assistant should not be able to take down the network simply
because it misunderstood a request. That's the specific failure this
project exists to prevent.

## Security

- Credential fields (API keys, passwords, private keys) never appear in a
  public model, MCP schema, log line, or exception message — by
  construction, not filtering.
- Fail-closed configuration and strict TLS by default.
- Explicit capability gates: an MCP tool is reachable only if its capability
  is in the selected profile's accepted set.
- The supported transport is local stdio; the process controlling that
  channel is the trust boundary — see
  [the threat model](docs/THREAT_MODEL.md) for exactly what that does and
  does not cover.

Every claim above is backed by a specific test class, listed with the tests
that enforce it in [`SECURITY.md`](SECURITY.md#security-guarantees). Report
vulnerabilities privately through [`SECURITY.md`](SECURITY.md) — never in a
public issue.

## Documentation

A browsable version of the full documentation set below is built (not yet
publicly deployed) via `make docs-serve`; see
[`docs/index.md`](docs/index.md) for the same map.

- [MCP tool reference](docs/API.md)
- [Configuration reference](docs/CONFIGURATION.md)
- [Client setup examples](examples/README.md)
- [Security model](docs/SECURITY_MODEL.md) · [Threat model](docs/THREAT_MODEL.md)
- [Architecture diagrams](docs/ARCHITECTURE_DIAGRAMS.md) · [Architecture decisions](docs/adr/README.md)
- [Tier 1 safety architecture](docs/TIER1_ARCHITECTURE.md) · [Public roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md) · [Security policy](SECURITY.md)

## Status

v0.2.2 is the immutable production baseline, published on PyPI. v0.3.0 is
active development of the Tier 1 safety framework described above — no
mutating capability, endpoint, transport path, or MCP tool is active as
part of it. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for what's next.

## Contributing

Contributions are welcome within the documented security and approval
boundaries. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change.

## License

Licensed under the [MIT License](LICENSE).
