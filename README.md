# pfsense-mcp-server

A local MCP server exposing strongly-typed, read-only tools for the
pfSense REST API at a single managed pfSense Plus instance.

## Status

v0.2.1 release candidate — security hardening of the accepted v0.2.0
inert WRITE-infrastructure release. No mutating capability is active.

## Scope (current phase)

- REST API only — SSH is out of scope.
- Read-only. No mutating tool exists in this build; `tools/write/` is
  reserved and unpopulated, and is never imported by the server.
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
| `PFSENSE_LOG_MAX_BYTES` | no (default `5000000`) | log-file rotation size |
| `PFSENSE_LOG_BACKUP_COUNT` | no (default `5`) | rotated log files kept |

`PFSENSE_TLS_MODE=insecure` disables certificate verification and must
be set explicitly. Switching to `auto` later (once a CA file exists)
requires no code change — only this configuration.

`PFSENSE_PROFILE=engineer` currently grants no capabilities — write
tools are not registered or reachable. It is a named placeholder for
a separate, explicitly authorized future phase.

## Security policy

Credential material is never part of a public model or MCP schema and
is ignored if pfSense includes it in a READ response. Optional
`include_identifying_metadata` arguments disclose sensitive operational
metadata only; they never disclose passwords, pre-shared keys, private
keys, or API-key plaintext. See `docs/SECURITY_MODEL.md`.

## Running

    PFSENSE_API_URL=https://pfsense.example.invalid \
    PFSENSE_IDENTITY=api-mcp-admin \
    PFSENSE_API_KEY_FILE=/path/outside/repository/pfsense-api.key \
    PFSENSE_TLS_MODE=insecure \
    pfsense-mcp-server
