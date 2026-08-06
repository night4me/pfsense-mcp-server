# Security policy

## Supported versions

Security fixes are provided for the current `0.2.x` release line.
Versions `0.1.x` and older are unsupported. Version `0.2.0` is
superseded by the credential-disclosure hardening in `0.2.1`.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/night4me/pfsense-mcp-server/security/advisories/new).
If that facility is unavailable, contact the repository owner through
their published GitHub contact channel. Do not open a public issue for
an unremediated vulnerability.

Never include credentials or identifying appliance data in a report.
This includes API keys, passwords, private keys, IPsec pre-shared keys,
real IP or MAC addresses, hostnames, account names, certificate identity
details, raw appliance responses, or unsanitized logs. Use synthetic
placeholders and describe how the maintainer can reproduce the issue.

Response targets are:

- acknowledgement within three business days;
- initial triage within seven business days;
- a status update at least every fourteen days until resolution.

These are communication targets, not guaranteed remediation deadlines.
Disclosure timing will be coordinated after impact and a safe fix are
understood.

## Trust boundary

The supported deployment is a local stdio MCP server. The process that
launches and controls the stdio channel is the caller-authentication
boundary. The server is not a multi-tenant network service and does not
authenticate individual MCP messages. Anyone who can control that MCP
channel can invoke every capability in the selected local profile.

See [the security model](docs/SECURITY_MODEL.md) for data classification,
credential handling, upstream authorization, audit behavior, and the
inert WRITE-infrastructure boundary.
