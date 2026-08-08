# pfsense-mcp-server

**A security-first MCP server for pfSense.** It gives an MCP client
strongly typed, read-only visibility into one pfSense appliance — without
exposing raw shell access or a way to mutate the appliance by accident.

**Current production contract: 41 READ tools. 0 WRITE tools.** That split
is deliberate: this project treats mutation as a safety-engineering
problem, not a feature flag. See
[the Tier 1 overview](TIER1_ARCHITECTURE.md) below for what that means in
practice, and the repository README's "Why this project exists" section
for the short version.

This site is a browsable, organized view of the technical documentation
under `docs/`. It does not repeat the project's practical
getting-started material — that stays authoritative in the repository
itself:

- [README — install, quick start, example prompts](https://github.com/night4me/pfsense-mcp-server#readme)
- [Client setup examples](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)
- [CONTRIBUTING — development workflow](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md)
- [SECURITY — how to report a vulnerability](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md)

## Find your way in

| If you want to... | Go to |
|---|---|
| Install and run the server | [Getting Started](CONFIGURATION.md) |
| Know exactly what security properties are enforced (and which aren't) | [Security](SECURITY_MODEL.md) |
| See every MCP tool this server registers | [API reference](API.md) |
| Understand how the current READ path is built | [Architecture](ARCHITECTURE_DIAGRAMS.md) |
| Understand the future WRITE-safety framework — and why it isn't active yet | [Tier 1](TIER1_ARCHITECTURE.md) |
| Build, review, or release a change | [Release and contributing](RELEASE_CHECKLIST.md) |

## What is on this site

- **Getting Started** — the full configuration reference and
  troubleshooting guide; installation itself lives in the README (linked
  above), since that's what a new visitor sees first on GitHub or PyPI.
- **Security** — the threat model, security model, abuse-case catalog, and
  the risk study behind every writable pfSense endpoint class this project
  has inventoried and *not yet* authorized. Start here if you're deciding
  whether to trust this project with appliance credentials.
- **API reference** — the full MCP tool catalog this server currently
  registers (41 READ tools, zero WRITE tools).
- **Architecture (current production)** — how the active READ path is
  built: transport, typed response mapping, capability gating, tool
  registration.
- **Tier 1 — future WRITE safety framework (inert)** — everything about
  the WRITE-safety design that does *not* run in production yet: the
  Recovery Contract model, the phase-gated implementation roadmap, every
  Architecture Decision Record that gates a piece of it, and the
  implementation-ready specification for each subsystem (encryption, key
  lifecycle, anti-rollback, confirmation, reconciliation, rate-limiting,
  sealed executor, disposable-lab validation). Every page in this section
  describes code that exists and is tested — none of it is reachable from
  the running server.
- **Release and contributing** — how a release actually gets built,
  checked, and published; this project's dependency/supply-chain policy;
  and where to go to propose a change.
- **Acceptance records** — the point-in-time verification evidence
  recorded at each past release.

## Project status

The production server is READ-only: 41 tools, zero WRITE tools, an empty
WRITE endpoint allow-list. v0.2.2 is the current immutable, published
release. v0.3.0 development continues the Tier 1 safety framework — every
new module remains structurally unreachable from production until an
explicit, separately authorized activation decision is made. See the
[public roadmap](ROADMAP.md) and [v0.3.0 milestone](V0.3.0_MILESTONE.md)
for what "done" looks like for this phase.
