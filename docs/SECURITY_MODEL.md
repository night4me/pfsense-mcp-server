# Security model

## Trust boundary

This server is intended for local stdio MCP use. The process that launches
and controls the MCP channel is the caller-authentication boundary. The
server is not a multi-tenant network service and does not authenticate
individual MCP messages.

The configured `PFSENSE_IDENTITY` identifies the shared upstream pfSense
API credential. It does not identify an MCP caller. Audit records call this
field `upstream_identity` for that reason.

## Data classes

### Credentials and secrets

Passwords, pre-shared keys, private keys, API-key plaintext, stored
credential hashes, and symmetric authentication keys must never appear in
public models, MCP schemas, serialized tool output, logs, errors, or
approved fixtures. Upstream values in these fields are ignored
unconditionally.

### Optional sensitive metadata

IP/MAC addresses, internal hostnames, persistent device identifiers,
firewall endpoints, account attribution, internal service-account names,
email addresses, and public SSH authorized keys are omitted by default.
Tools may expose them through `include_identifying_metadata=True`. Audit
records capture only whether this disclosure was requested, never values.

### Public cryptographic material

Public certificates and certificate signing requests may be returned by
their explicit inventory tool. Private keys and passphrases are never
returned. Public SSH keys are treated as optional sensitive metadata
because they identify accounts and hosts.

### Ordinary operational data

Service state, resource counters, versions, non-secret policy flags,
timeouts, and similar operational information are returned normally under
the active READ capability profile.

## Authorization

The default `auditor` profile exposes the accepted READ capability set.
The `engineer` profile has zero capabilities. No WRITE endpoint is
allow-listed, no WRITE tool is registered, and the production bootstrap
does not construct a write client.

`PFSENSE_ALLOWED_TOOLS` is an optional exact-name restriction applied as an
intersection after profile authorization. An absent value preserves the
profile; an explicitly empty value registers nothing. Unknown names and
wildcard forms fail closed. It can remove exposure but cannot grant a
capability, bypass endpoint verification, or activate WRITE.

All current tools publish MCP `readOnlyHint=true` and `openWorldHint=true`.
These values help clients describe the tool and recognize that its data comes
from a dynamic external appliance. MCP ToolAnnotations are untrusted hints,
not security decisions. Server-side capability profiles, exact-name
restriction, GET-only enforcement, endpoint verification, credential policy,
audit logging, and independent WRITE-inactivity checks remain authoritative.

## Credentials and transport

The pfSense API key is loaded from a configured local file and sent only in
the `X-API-Key` header. HTTPS is mandatory. Strict system trust is the
default; an explicit CA file can be used for an internal CA. TLS
verification can be disabled only by explicit startup configuration.

Linux is the supported production platform for credential loading. The key
file is opened read-only with `O_NOFOLLOW`, then its type, effective-user
ownership, permissions, and size are validated with `fstat()` before a bounded
first line is read from that same descriptor. The descriptor is closed on
every path. This binds validation and reading to one inode and prevents path
replacement from substituting a different file. Platforms without the
required safe-open primitive are rejected with a clear configuration error;
they do not silently use weaker path-based validation.

## Audit data

Tool audit records contain the tool name, upstream identity, duration,
outcome, whether optional sensitive metadata is supported/requested, and a
sanitized exception class on failure. They never contain arguments,
responses, exception messages, credential values, or raw pfSense bodies.

## Recovery and WRITE status

Tier 0 WRITE infrastructure is inert. It must not be activated until
Recovery Contracts are bound to capability/endpoint/target, authoritative
store state and legal transitions are enforced, payload transmission and
HTTP outcome validation are implemented, and crash-safe persistence is
resolved and accepted separately.
