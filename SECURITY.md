# Security policy

## Supported versions

Security fixes are provided for the current `0.2.x` release line.
Versions `0.1.x` and older are unsupported. Version `0.2.0` is
superseded by the credential-disclosure hardening in `0.2.1`.

v0.3.0 is under active development and adds no reachable capability beyond
what `0.2.x` already exposes — its entire Tier 1 WRITE-safety framework
remains structurally unreachable from production (see "Non-goals" below).
It is not a supported release until published; report issues against it
the same way as `0.2.x`, noting the commit SHA you tested.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/night4me/pfsense-mcp-server/security/advisories/new).
If that facility is unavailable, contact the repository owner through
their published GitHub contact channel. Do not open a public issue for
an unremediated vulnerability, and do not discuss it in a public pull
request, discussion, or chat channel before a fix is available.

Never include credentials or identifying appliance data in a report.
This includes API keys, passwords, private keys, IPsec pre-shared keys,
real IP or MAC addresses, hostnames, account names, certificate identity
details, raw appliance responses, or unsanitized logs. Use synthetic
placeholders (this repository's own convention is `.invalid` hostnames and
RFC 5737 documentation addresses) and describe how the maintainer can
reproduce the issue using `MockTransport` or an isolated, disposable test
appliance you control — never a production pfSense instance, yours or
anyone else's.

A good report includes: the affected version or commit SHA, the component
(MCP tool, transport, configuration loading, Tier 1 framework, packaging,
CI/supply chain), the security property that's violated (see "Security
guarantees" below), a minimal reproduction, and the potential impact.

Response targets are:

- acknowledgement within three business days;
- initial triage within seven business days;
- a status update at least every fourteen days until resolution.

These are communication targets, not guaranteed remediation deadlines.
Disclosure timing will be coordinated after impact and a safe fix are
understood — we ask that you give us reasonable time to investigate and
release a fix before any public disclosure, and we will keep you informed
of progress in return. This project does not currently offer a paid bug
bounty; credit in the eventual security advisory is offered by default
unless you ask to remain anonymous.

## Scope

**In scope:**

- The `pfsense_mcp` package as published on PyPI and in this repository's
  `main` branch: configuration loading, credential handling, the MCP tool
  surface, transport/TLS behavior, and the (currently inert) Tier 1
  WRITE-safety framework.
- The packaging and release pipeline: `pyproject.toml`, the GitHub Actions
  workflows under `.github/workflows/`, and the artifacts they produce.
- The disposable-lab tooling under `lab/` (not packaged, but still
  first-party source subject to the same review).

**Out of scope** (report to the appropriate upstream instead):

- Vulnerabilities in `pfSense` itself, the pfSense REST API package, or any
  other upstream dependency not maintained in this repository — report
  those to their respective maintainers. A dependency vulnerability that
  is specifically *reachable through* this project's use of it is in
  scope here; report both.
- Findings that require a compromised launching operating-system account,
  a compromised pfSense appliance, or physical access to either — the
  [threat model](docs/THREAT_MODEL.md) explicitly does not claim either
  can be made trustworthy by this project (see "Non-goals" below). We are
  still interested in defense-in-depth suggestions for these cases, but
  they are feature requests, not vulnerability reports.
- Social engineering, physical security, or denial-of-service reports
  against GitHub, PyPI, or other third-party infrastructure this project
  uses but does not operate.

## Security guarantees

These hold for the current production (READ-only) surface, and are backed
by tests, not just documentation — see the
[threat model](docs/THREAT_MODEL.md)'s "Existing mitigations" section for
the complete, current list:

- **Credential non-disclosure.** The pfSense API key, and any other
  credential-shaped value, never appears in a public model, MCP schema,
  tool output, log line, or exception message — by construction (the
  fields don't exist on the typed models), not by best-effort filtering.
- **GET-only production transport.** The production request path cannot
  issue a mutating (non-GET) HTTP request. This is enforced structurally
  (a static check over the source, not just a runtime flag) and verified
  on every CI run.
- **Explicit capability gating.** An MCP tool is reachable only if its
  capability is present in the selected profile's accepted set; there is
  no reflection-based or implicit tool registration.
- **Fail-closed configuration.** Missing or invalid configuration (a bad
  URL, an unreadable or unsafe key file, an invalid TLS setting) refuses
  to start rather than falling back to an insecure default.
- **WRITE inactivity.** Every WRITE-shaped capability, endpoint, and MCP
  tool is currently empty/absent — asserted by tests that fail if that
  ever silently changes, not merely documented as a design intent.

## Non-goals

Reporting one of these as a "finding" is welcome as a design discussion
(open an issue), but it is not treated as a vulnerability, since it
describes an explicitly accepted boundary, not an accidental gap:

- **Not a multi-tenant service.** The server does not authenticate
  individual MCP messages or distinguish between callers sharing the same
  stdio channel. Anyone who can control that channel can invoke every tool
  in the selected profile. This is the documented trust boundary (TB1 in
  the threat model), not an oversight.
- **Trusts the launching operating-system account.** A compromised
  launching account has full access to configuration, credentials, stdio,
  and local logs by design of the local-process deployment model. Defense
  in depth reduces *accidental* exposure from this actor but cannot
  preserve credential secrecy from it.
- **Does not attempt to make a compromised pfSense appliance trustworthy.**
  Upstream responses are treated as untrusted input (shape-validated,
  never blindly trusted for security decisions), but a fully compromised
  appliance can still return misleading operational data within the
  read-only surface this project exposes.
- **No built-in per-caller rate limiting or denial-of-service protection**
  beyond basic bounded limits and timeouts. The local stdio deployment
  model assumes a single trusted caller process, not an adversarial one
  sharing the channel.
- **No production WRITE capability exists to report a bypass of.** The
  v0.3.0 Tier 1 framework is inert by construction — no executor, no
  registered WRITE tool, no allow-listed endpoint. A report that assumes
  WRITE is reachable is testing against a capability that doesn't exist
  yet in any published version.

## Trust boundary

The supported deployment is a local stdio MCP server. The process that
launches and controls the stdio channel is the caller-authentication
boundary. The server is not a multi-tenant network service and does not
authenticate individual MCP messages. Anyone who can control that MCP
channel can invoke every capability in the selected local profile.

See [the security model](docs/SECURITY_MODEL.md) for data classification,
credential handling, upstream authorization, audit behavior, and the
inert WRITE-infrastructure boundary, and [the threat model](docs/THREAT_MODEL.md)
for the full attacker-model and mitigation analysis this policy summarizes.
