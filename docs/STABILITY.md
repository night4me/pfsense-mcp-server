# Stability & compatibility contract (v1.0.0)

`v1.0.0` is this project's first release to treat its public interfaces as a
stable contract rather than an evolving prototype. This page states,
source-derived, exactly what "stable" covers and what it deliberately does
not — so a 0.9.x user upgrading, or anyone scripting/automating against this
project, knows what they can rely on.

Semantic versioning applies to everything listed as **Stable** below: a
breaking change to any of it is a major-version bump, never a patch or minor
release. Everything listed as **Internal** may change in any release,
including a patch release, without notice.

## MCP surface

| Surface | Status | Notes |
|---|---|---|
| Public tool names (`KNOWN_READ_TOOL_NAMES`, `KNOWN_GUIDANCE_TOOL_NAMES`) | **Stable** | 95 READ + 2 guidance tools, [API.md](API.md). A tool is never silently renamed; renames are additive (new name registered, old name deprecated first). |
| Tool input schemas | **Stable** | New optional fields may be added; existing fields are never removed or repurposed within a major version. |
| Tool output/result shapes | **Stable** | Pydantic response models are additive-only across `1.x`. |
| `pfsense_mcp_info`'s own fields (`server_version`, `registered_tool_count`, etc.) | **Stable** | The one tool whose entire purpose is exposing this contract to a client at runtime. |
| Server name (`serverInfo.name`) | **Stable** | Always `pfsense-mcp-server`. |
| Server version (`serverInfo.version`) | **Stable meaning, not a stable value** | Always the installed `pfsense-mcp-server` package version (`importlib.metadata`) as of `v1.0.0` — never the `mcp` SDK's own version. See the serverInfo.version fix in this same audit for why this needed stating explicitly. |
| MCP protocol behavior (stdio transport, initialize/list_tools/call_tool semantics) | **Stable, but owned upstream** | Governed by the `mcp` Python SDK (`mcp>=1.21.1,<2.0.0`), not this project. |
| Default-reachable WRITE tool count | **Stable at zero** | 0 by design for `v1.x`; any future default-reachable WRITE tool is itself a major-version, security-reviewed decision, never a minor/patch addition. |

## CLI surface

| Surface | Status | Notes |
|---|---|---|
| `pfsense-mcp-server` (`--help`, `--version`) | **Stable** | |
| `pfsense-mcp-security discover`/`plan`/`doctor` | **Stable** | Read-only diagnostics; flags are additive. |
| `pfsense-mcp-security setup` (bare, `--non-interactive`) | **Stable** | Plan-only; never provisions. |
| `pfsense-mcp-security setup apply` | **Stable** | Confirmation-gated; `--plan-digest`/`--confirm` contract unchanged. |
| `pfsense-mcp-security setup init-confirm-key` | **Stable** | |
| `pfsense-mcp-security setup write-client-config` | **Stable** | `--client {claude-desktop,codex}` values are stable; new client types are additive. |
| `pfsense-mcp-security bootstrap`/`recover` | **Stable** | ADR-033/recovery-contract commands. |
| Exit codes | **Stable per subcommand** | Documented in each subcommand's own `--help` epilog; a given outcome keeps its exit code across `1.x`. |
| `--json` output shapes | **Stable** | Field names are additive-only. |

## Configuration surface

| Surface | Status | Notes |
|---|---|---|
| `PFSENSE_API_URL`, `PFSENSE_IDENTITY`, `PFSENSE_API_KEY_FILE`, `PFSENSE_TLS_MODE`, `PFSENSE_TLS_CA_FILE` | **Stable** | [CONFIGURATION.md](CONFIGURATION.md). |
| `PFSENSE_SETUP_CONFIRM_KEY_FILE` | **Stable** | |
| Credential-file semantics (owner-only permissions, path-only in client config, value never serialized) | **Stable** | A security invariant, not just a convention — see `SECURITY_MODEL.md`. |
| Generated Claude Desktop JSON / Codex TOML shapes | **Stable** | [MCP_CLIENT_CONFIGURATION.md](MCP_CLIENT_CONFIGURATION.md); merge-only, never a whole-file replacement. |

## Persisted state (what a 0.9.x user's on-disk state means for 1.0)

| Artifact | Status | Notes |
|---|---|---|
| `PFSENSE_SETUP_CONFIRM_KEY_FILE` contents | **Compatible** | Opaque local secret; a 0.9.x-created key continues to work unchanged. |
| Generated `~/.codex/config.toml` / Claude Desktop config | **Compatible** | Existing entries are preserved (merge-only) by every `write-client-config` run, past or future. |
| Tier 1 store / bootstrap journal / witness baseline | **Internal** | Tier 1 is inert (no default-reachable WRITE capability ships in `v1.0.0`); its on-disk formats are pre-release, unversioned, and may change without notice until a Tier 1 capability is actually shipped and its own stability is declared separately. |

## Explicitly internal (no stability promise)

- Every `pfsense_mcp.*` Python module, class, and function not reached
  through the MCP tool surface or the two CLI entry points above. This
  project does not support being imported as a Python library — only as an
  MCP server (`pfsense-mcp-server`) and a CLI (`pfsense-mcp-security`).
- Log file formats/locations, internal audit-event schemas, and CI/release
  tooling under `scripts/`.
- `docs/adr/*` design-only ADRs describing not-yet-implemented capabilities
  (Nexus, Tier 1 WRITE execution, hardware witness backends) — these are
  research/design artifacts, not a compatibility promise for anything they
  describe.

## Related

- [Compatibility](COMPATIBILITY.md) — pfSense-appliance-side edition/version/schema compatibility (a different concern from this page).
- [Security model](SECURITY_MODEL.md)
- [MCP tool reference](API.md)
