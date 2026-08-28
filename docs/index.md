# pfsense-mcp-server

**A security-first MCP server for pfSense.** It gives an MCP client
strongly typed, read-only visibility into one pfSense appliance — without
exposing raw shell access or a way to mutate the appliance by accident.

**Current `main`-branch contract: 95 pfSense READ tools + 2 documentation
guidance tools. 0 WRITE tools.** (The currently published PyPI release,
`v0.8.0`, has 1 guidance tool — 96 total — until the `v0.9.0` candidate
described here is actually published; see `CHANGELOG.md` and
`docs/ROADMAP.md`'s "Current baseline" section for the exact,
up-to-date status.) That split is deliberate: this project treats
mutation as a safety-engineering problem, not a feature flag — the
maintainer's own reasoning is in
[the security model's "Why this project exists"](SECURITY_MODEL.md#why-this-project-exists).
See [the Tier 1 overview](TIER1_ARCHITECTURE.md) below for the
engineering detail behind it.

This site is a browsable, organized view of the technical documentation
under `docs/`, including a complete getting-started path
([Installation](INSTALLATION.md) → [Security setup wizard](SECURITY_SETUP_WIZARD.md) →
[Connect your MCP client](MCP_CLIENT_CONFIGURATION.md)). A few things
stay authoritative in the repository itself instead:

- [README — quick overview and copy/paste quick-start](https://github.com/night4me/pfsense-mcp-server#readme)
- [Per-client config examples](https://github.com/night4me/pfsense-mcp-server/blob/main/examples/README.md)
- [CONTRIBUTING — development workflow](https://github.com/night4me/pfsense-mcp-server/blob/main/CONTRIBUTING.md)
- [SECURITY — how to report a vulnerability](https://github.com/night4me/pfsense-mcp-server/blob/main/SECURITY.md)

## Find your way in

| If you want to... | Go to |
|---|---|
| Install and run the server | [Installation](INSTALLATION.md) |
| Set up the operator CLI, or opt into protected WRITE | [Security setup wizard](SECURITY_SETUP_WIZARD.md) |
| Connect an MCP client | [Connect your MCP client](MCP_CLIENT_CONFIGURATION.md) |
| Know exactly what security properties are enforced (and which aren't) | [Security](SECURITY_MODEL.md) |
| See every MCP tool this server registers, and where guidance content comes from | [API reference](API.md) · [Tool & guidance reference](TOOL_AND_GUIDANCE_REFERENCE.md) |
| Understand how the current READ path is built | [Architecture](ARCHITECTURE_DIAGRAMS.md) |
| Understand the future WRITE-safety framework — and why it isn't active yet | [Tier 1](TIER1_ARCHITECTURE.md) |
| Build, review, or release a change | [Release and contributing](RELEASE_CHECKLIST.md) |

## What is on this site

- **Getting Started** — installation, the operator security CLI, MCP
  client configuration, the full environment-variable/configuration
  reference, and compatibility evidence.
- **Security** — the threat model, security model, abuse-case catalog, and
  the risk study behind every writable pfSense endpoint class this project
  has inventoried and *not yet* authorized. Start here if you're deciding
  whether to trust this project with appliance credentials.
- **API reference** — the full MCP tool catalog this server currently
  registers (95 pfSense READ tools, 2 documentation guidance tools, zero
  WRITE tools).
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

The production server is READ-only: 95 tools, zero WRITE tools, an empty
WRITE endpoint allow-list. **v0.8.0 is the current immutable, published
release** — see the [README's Release status](https://github.com/night4me/pfsense-mcp-server#release-status)
section for the exact delta from each prior release. It ships the Tier 1
safety framework — every new module remains structurally unreachable
from production until an explicit, separately authorized activation
decision is made. See the [public roadmap](ROADMAP.md) for what "done"
looks like for this phase.
