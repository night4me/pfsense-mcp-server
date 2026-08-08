# pfsense-mcp-server

[![CI](https://github.com/night4me/pfsense-mcp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/night4me/pfsense-mcp-server/actions/workflows/ci.yml)
[![CodeQL](https://github.com/night4me/pfsense-mcp-server/actions/workflows/codeql.yml/badge.svg)](https://github.com/night4me/pfsense-mcp-server/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/pfsense-mcp-server.svg)](https://pypi.org/project/pfsense-mcp-server/)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A security-focused local MCP server exposing 41 strongly typed pfSense REST
API tools. It gives an MCP client operational visibility into one managed
pfSense Plus appliance while keeping the production path GET-only.

Key properties:

- explicit capability gates and typed Pydantic responses;
- credential fields excluded from models, schemas, logs, errors, and fixtures;
- optional sensitive metadata omitted by default;
- fail-closed configuration and TLS verification by default;
- 41 READ tools, zero WRITE tools, and an empty WRITE endpoint allow-list.

## Status

v0.2.2 is the immutable production baseline and is published on PyPI. It
completes project, packaging, documentation, and defense-in-depth hardening
while preserving the 41-tool READ API. v0.3.0 is the active development
milestone. Its Tier 1 safety framework remains inert: no mutating capability,
endpoint, transport path, or MCP tool is active.

## Scope (current phase)

- REST API only — SSH is out of scope.
- The production server is read-only. Accepted Tier 0 WRITE infrastructure
  exists as dormant library code, but it is not constructed by production
  bootstrap, has no allow-listed endpoint, and registers no MCP tool.
- 34 capabilities, 41 tools, spanning system, interfaces, gateways,
  firewall, users, certificates, DHCP, DNS, NTP, SSH, cron, ACME,
  FreeRADIUS, HA/CARP, and diagnostics. See `src/pfsense_mcp/capabilities.py`
  for the authoritative list.

## Architecture

    Transport            (swappable: HttpTransport / MockTransport)
        ↓
    RestApiClient         GET-only enforcement, API-version resolution,
        ↓                 JSON parsing, error mapping, duration logging
    PfSenseClient         semantic methods, raw JSON → typed models
        ↓
    ToolRegistry / MCP Tools   thin, capability-gated

`Application` (application.py) owns startup, dependency construction,
and lifecycle — via `factory.py` for client construction and
`profiles.py` for capability-set selection. `server.py`'s only job is
`Application().run()`.

`diagnostics.py` reports local server health (configuration validity,
TLS mode, active API version, registered capabilities, transport
type) without ever contacting pfSense.

The authoritative capability profile gates registration before a tool can
be exposed. The default auditor profile contains the accepted READ set;
the engineer placeholder contains no capabilities. Endpoint registries
independently enforce GET-only access and an empty WRITE allow-list.
An optional exact-name restriction can further reduce the tools authorized by
the selected profile; it can never add a tool or capability.

The v0.3.0 source tree also contains an isolated `tier1` domain package for
Recovery Contract, state-machine, persistence, policy, and audit design. It is
not imported by `Application`, has an empty mutation policy, and has no
production executor or transport. Its presence does not change the v0.2.2 MCP
contract or authorize WRITE.

## Credentials

This project never stores, logs, or contains an API key. The key is
loaded at runtime from a local file outside this repository — only
its **first line** is read — path supplied via `PFSENSE_API_KEY_FILE`.
The server fails closed if the key cannot be loaded.

## Configuration (missing/invalid values fail closed)

| Variable | Required | Example |
|---|---|---|
| `PFSENSE_API_URL` | yes | `https://pfsense.example.invalid` |
| `PFSENSE_IDENTITY` | yes | `api-mcp-admin` |
| `PFSENSE_API_KEY_FILE` | yes | `/path/outside/repository/pfsense-api.key` |
| `PFSENSE_TLS_MODE` | no (default `strict`) | `strict` / `auto` / `insecure` |
| `PFSENSE_TLS_CA_FILE` | required if `PFSENSE_TLS_MODE=auto` | path to a CA bundle |
| `PFSENSE_API_VERSION` | no (default `v2`) | `v2` |
| `PFSENSE_PROFILE` | no (default `auditor`) | `auditor` / `engineer` |
| `PFSENSE_ALLOWED_TOOLS` | no | comma-separated exact MCP tool names |
| `PFSENSE_LOG_MAX_BYTES` | no (default `5000000`) | log-file rotation size |
| `PFSENSE_LOG_BACKUP_COUNT` | no (default `5`) | rotated log files kept |

`PFSENSE_TLS_MODE=insecure` disables certificate verification and must
be set explicitly. Switching to `auto` later (once a CA file exists)
requires no code change — only this configuration.

`PFSENSE_PROFILE=engineer` currently grants no capabilities — write
tools are not registered or reachable. It is a named placeholder for
a separate, explicitly authorized future phase.

`PFSENSE_ALLOWED_TOOLS` is an optional restriction applied after the selected
profile. If absent, the auditor profile keeps all 41 tools. If present, only
the comma-separated exact names in both the profile and restriction register.
Whitespace around names is ignored and duplicate names are normalized. An
explicitly empty value registers zero tools. Unknown names, empty list entries,
wildcards, and prefix patterns fail closed at startup. The setting can only
remove tools; it cannot grant a capability, activate WRITE, or override an
endpoint check.

## Security policy

Credential material is never part of a public model or MCP schema and
is ignored if pfSense includes it in a READ response. Optional
`include_identifying_metadata` arguments disclose sensitive operational
metadata only; they never disclose passwords, pre-shared keys, private
keys, or API-key plaintext. See the [security model](docs/SECURITY_MODEL.md)
and [vulnerability reporting policy](SECURITY.md).

The supported MCP transport is local stdio. The process launching and
controlling that channel is the caller-authentication boundary; this is
not a multi-tenant network service. Public CI has no production
configuration and never contacts a pfSense appliance.

Every current tool advertises MCP `readOnlyHint=true` and
`openWorldHint=true`: it does not mutate pfSense, but it reads dynamic data
from an external appliance. These annotations are untrusted client hints for
presentation and tool selection, not authorization. They do not relax
capability profiles, the optional exact-name restriction, GET-only or endpoint
enforcement, credential handling, auditing, or WRITE inactivity.

## Installation

Linux is the supported production platform because secure credential loading
depends on descriptor-bound Unix file semantics. Python 3.11 or newer is
required.

`pfsense-mcp-server` is published on
[PyPI](https://pypi.org/project/pfsense-mcp-server/) via a GitHub Actions
Trusted Publisher, with [PEP 740](https://peps.python.org/pep-0740/) digital
attestations verifiable back to this repository and the exact release commit
— no long-lived upload token exists. Install the released version into an
isolated environment:

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install 'pfsense-mcp-server==0.2.2'
```

Verify the package you installed against the project page before trusting it
in any sensitive environment — do not use a similarly named package from a
package index. See the [release procedure](docs/PYPI_RELEASE.md) for exactly
how each release's provenance is produced and verified before publication.

### Installing from source

To build from a specific commit rather than the released tag, or for local
development:

```console
git clone https://github.com/night4me/pfsense-mcp-server.git
cd pfsense-mcp-server
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .
```

## Quick start

Create the API-key file outside the repository and restrict it to the account
that runs the MCP server:

```console
install -m 600 /dev/null /absolute/private/path/pfsense-api.key
```

Place the key on the first line without printing it in shell history or logs.
Then configure your MCP client to launch the console entry point with these
environment variables:

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

The exact outer MCP-client configuration key varies by client. Use one of the
[verified client examples](examples/README.md), then confirm that the client
shows 41 READ tools and no WRITE tools. A first safe call is
`pfsense_get_system_status`. The server communicates over stdio and produces
no web interface or screenshotable UI.

For development, install the project with its test and analysis tools:

```console
.venv/bin/python -m pip install -e ".[dev]"
make quick
make validate
```

Additional release checks are documented in the
[release checklist](docs/RELEASE_CHECKLIST.md). Live private-infrastructure
acceptance is separate, opt-in, and never part of public CI.

## Direct launch

Direct launch is useful for confirming configuration and MCP startup. The
process waits for MCP messages on stdin when configuration is valid.

```console
PFSENSE_API_URL=https://pfsense.example.invalid \
PFSENSE_IDENTITY=api-mcp-admin \
PFSENSE_API_KEY_FILE=/absolute/private/path/pfsense-api.key \
PFSENSE_TLS_MODE=strict \
pfsense-mcp-server
```

## Troubleshooting

### The server exits with a configuration error

Configuration fails closed. Confirm every required variable is present, the
API URL is an HTTPS origin without a path, and the identity contains no control
characters. Error messages identify the invalid setting but never print the
key value.

### The API-key file is rejected

The file must be a regular non-symlink file owned by the process user, with no
group or other permission bits, and its first line must be non-empty and
bounded. Parent directories should normally be mode 0700.

### TLS verification fails

Prefer `strict` with the system trust store. For an internal CA, set
`PFSENSE_TLS_MODE=auto` and point `PFSENSE_TLS_CA_FILE` to a readable CA
bundle. `insecure` disables certificate verification and should be limited to
short, explicitly accepted diagnostics.

### No tools appear

Use `PFSENSE_PROFILE=auditor`, the default accepted READ profile. The
`engineer` placeholder intentionally grants no capabilities in this build.
Also check `PFSENSE_ALLOWED_TOOLS`: an explicitly empty value intentionally
registers zero tools, and a configured subset hides every unlisted tool.

### Can this server manage more than one appliance?

No. One process has one configured upstream identity and appliance. Launch a
separate process with separate configuration for another appliance.

## Documentation

- [MCP tool reference](docs/API.md)
- [Future-major API review](docs/API_REVIEW.md)
- [Client setup examples](examples/README.md)
- [Architecture diagrams](docs/ARCHITECTURE_DIAGRAMS.md)
- [Architecture decisions](docs/adr/README.md)
- [Offline benchmark methodology](docs/BENCHMARKS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security abuse-case catalog](docs/SECURITY_TEST_CATALOG.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Vulnerability reporting](SECURITY.md)
- [Support and getting help](SUPPORT.md)
- [Public roadmap](docs/ROADMAP.md)
- [v0.3.0 milestone](docs/V0.3.0_MILESTONE.md)
- [Tier 1 safety architecture](docs/TIER1_ARCHITECTURE.md)
- [Recovery Contract specification](docs/RECOVERY_CONTRACT_SPEC.md)
- [Writable endpoint risk study](docs/WRITE_ENDPOINT_RISK_MATRIX.md)
- [Disposable Tier 1 lab plan](docs/TIER1_LAB_PLAN.md)
- [Contribution guide](CONTRIBUTING.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [PyPI release procedure](docs/PYPI_RELEASE.md)
- [Dependency policy](docs/DEPENDENCY_POLICY.md)
- [v0.2.2 acceptance](docs/ACCEPTANCE_v0.2.2.md)
- [v0.2.1 acceptance](docs/ACCEPTANCE_v0.2.1.md)

## Contributing

Contributions are welcome within the documented security and approval
boundaries. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a change.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE). The copyright notice uses the
project contributor identity and does not assert ownership by an invented
person or organization.
