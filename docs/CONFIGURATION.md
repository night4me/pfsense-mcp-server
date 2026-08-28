# Configuration reference

This is the complete configuration and troubleshooting reference. For a
one-minute path to a running server, see the
[README's quick start](https://github.com/night4me/pfsense-mcp-server#quick-start).

## Environment variables

Every value is validated at startup. A missing or invalid value fails
closed — the server refuses to start rather than falling back to an
insecure default.

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

### Credentials

This project never stores, logs, or contains an API key. The key is loaded
at runtime from a local file outside the repository — only its **first
line** is read — path supplied via `PFSENSE_API_KEY_FILE`. The file must be
a regular, non-symlink file owned by the process user with no group/other
permission bits; the server fails closed otherwise. See the
[security model](SECURITY_MODEL.md) for the full credential-handling design.

### TLS

`PFSENSE_TLS_MODE=insecure` disables certificate verification and must be
set explicitly — it is never a default. Switching to `auto` later, once a
CA file exists, requires no code change, only this configuration.

### Profiles and tool restriction

`PFSENSE_PROFILE=engineer` currently grants no capabilities — WRITE tools
are not registered or reachable under it. It is a named placeholder for a
separate, explicitly authorized future phase (see
[the public roadmap](ROADMAP.md)), not a way to unlock anything today.

`PFSENSE_ALLOWED_TOOLS` is an optional restriction applied after the
selected profile. If absent, the auditor profile keeps all 95 READ tools
plus the 2 documentation guidance tools (`pfsense_get_official_guidance`,
`pfsense_get_api_guidance`, 97 total). If present, only the comma-separated exact names in both the
profile and the restriction register — this applies uniformly to READ and
guidance tool names alike. Whitespace around names is ignored and duplicate
names are normalized. An explicitly empty value registers zero tools.
Unknown names, empty list entries, wildcards, and prefix patterns fail
closed at startup. The setting can only remove tools; it cannot grant a
capability, activate WRITE, or override an endpoint check.

```text
PFSENSE_ALLOWED_TOOLS=pfsense_get_system_status,pfsense_get_interfaces
```

## Direct launch

Direct launch is useful for confirming configuration and MCP startup
outside a client. The process waits for MCP messages on stdin once
configuration is valid.

```console
PFSENSE_API_URL=https://pfsense.example.invalid \
PFSENSE_IDENTITY=api-mcp-admin \
PFSENSE_API_KEY_FILE=/absolute/private/path/pfsense-api.key \
PFSENSE_TLS_MODE=strict \
pfsense-mcp-server
```

## Troubleshooting

### The MCP client shows 0 tools, or fails to start the server

Usually a wrong command path, or the venv's `pfsense-mcp-server` entry
point isn't executable from where the client launches it. Run the exact
command from your client's own `env`/`command` configuration directly
in a shell and read stderr verbatim — a client UI often swallows the
real error.

### The server exits with a configuration error

Configuration fails closed. Confirm every required variable is present, the
API URL is an HTTPS origin without a path, and the identity contains no
control characters. Error messages identify the invalid setting but never
print the key value.

### The API-key file is rejected

The file must be a regular non-symlink file owned by the process user, with
no group or other permission bits, and its first line must be non-empty and
bounded. Parent directories should normally be mode `0700`.

### `401` authentication failures

Wrong API key, wrong `PFSENSE_IDENTITY`, or the key file has the wrong
permissions/first-line format. Re-verify the key file's first line
matches the key shown in pfSense's REST API user settings, and that
`PFSENSE_IDENTITY` matches the pfSense user the key actually belongs
to.

### `403` insufficient-privilege failures on specific tools

The pfSense identity lacks the narrow privilege that specific tool
needs. Cross-check the required privilege in
[`docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md`](PFSENSE_LEAST_PRIVILEGE_MATRIX.md)
against the identity's assigned privileges in pfSense — or use
[the setup wizard](SECURITY_SETUP_WIZARD.md) to provision a fresh
identity with exactly the right privilege set from the start.

### TLS verification fails

Prefer `strict` with the system trust store. For an internal CA, set
`PFSENSE_TLS_MODE=auto` and point `PFSENSE_TLS_CA_FILE` to a readable CA
bundle. `insecure` disables certificate verification and should be limited
to short, explicitly accepted diagnostics.

### A specific tool always returns an empty or package-absent result

The underlying pfSense feature or package (e.g. WireGuard) likely isn't
installed/configured on that appliance. Confirm via pfSense's own
package manager or configuration UI — this is expected behavior, not a
bug. See [Compatibility](COMPATIBILITY.md) for exactly which tools are
known to gate on a package this way.

### REST API unreachable / connection refused

The `pfrest`/`pfSense-pkg-RESTAPI` package is disabled or not installed
on the appliance. Confirm the package is installed and enabled in
pfSense's package manager, and confirm `PFSENSE_API_URL` and network
reachability.

### Works on one pfSense version, not another

Check [Compatibility](COMPATIBILITY.md) for your exact platform/version
combination before filing an issue — this may be a genuine platform/
schema incompatibility rather than a configuration problem.

### Timeouts under load

Confirm the appliance itself is responsive via its own web UI first —
default HTTP timeouts assume a normally-loaded appliance; this project
does not currently expose a configurable timeout.

### No tools appear

Use `PFSENSE_PROFILE=auditor`, the default accepted READ profile. The
`engineer` placeholder intentionally grants no capabilities in this build.
Also check `PFSENSE_ALLOWED_TOOLS`: an explicitly empty value intentionally
registers zero tools, and a configured subset hides every unlisted tool.

### Can this server manage more than one appliance?

No. One process has one configured upstream identity and appliance. Launch
a separate process with separate configuration for another appliance.

## Related

- [Client setup examples](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)
- [Security model](SECURITY_MODEL.md)
- [MCP tool reference](API.md)
