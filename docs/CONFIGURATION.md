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
selected profile. If absent, the auditor profile keeps all 41 tools. If
present, only the comma-separated exact names in both the profile and the
restriction register. Whitespace around names is ignored and duplicate
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

### The server exits with a configuration error

Configuration fails closed. Confirm every required variable is present, the
API URL is an HTTPS origin without a path, and the identity contains no
control characters. Error messages identify the invalid setting but never
print the key value.

### The API-key file is rejected

The file must be a regular non-symlink file owned by the process user, with
no group or other permission bits, and its first line must be non-empty and
bounded. Parent directories should normally be mode `0700`.

### TLS verification fails

Prefer `strict` with the system trust store. For an internal CA, set
`PFSENSE_TLS_MODE=auto` and point `PFSENSE_TLS_CA_FILE` to a readable CA
bundle. `insecure` disables certificate verification and should be limited
to short, explicitly accepted diagnostics.

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
