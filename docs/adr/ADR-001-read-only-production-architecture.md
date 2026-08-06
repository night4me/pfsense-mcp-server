# ADR-001: READ-only production architecture

- **Status:** Accepted
- **Date:** 2026-08-06

## Context

pfSense configuration and operational data is valuable to MCP-assisted audits,
but arbitrary mutation can cause lockout, outage, policy bypass, or loss of
recovery state. The initial server needed a useful surface with a small,
auditable blast radius. Future mutation was foreseeable, so “READ-only” could
not mean that every future design was forbidden; it needed to describe the
current production profile and bootstrap path precisely.

## Decision

The production server exposes only approved READ capabilities. It registers 41
READ tools and zero WRITE tools. The current upstream request path is GET-only.

Future WRITE capability requires a separately accepted architecture, endpoint,
profile, recovery, audit, test, and release decision. Dormant Tier 0 code does
not alter the current production decision.

## Consequences

### Positive

- MCP callers cannot mutate pfSense through the current registered surface.
- Review can focus on disclosure, availability, and upstream GET behavior.
- Live-safe acceptance can use a least-privilege `read_only=true` API identity.
- New READ tools follow consistent capability and model patterns.

### Negative

- Operational remediation still requires another controlled interface.
- Some pfSense “apply/status” endpoints need careful classification even when
  accessed with GET.
- Future WRITE work must preserve compatibility with a mature READ surface.

## Alternatives considered

- **Expose generic REST calls:** rejected because it bypasses typing,
  capability ownership, endpoint verification, and GET-only enforcement.
- **Ship READ and WRITE together behind prompts:** rejected because a prompt is
  not an authorization or recovery control.
- **Declare the project permanently READ-only:** rejected because it would make
  accepted Tier 0 planning incoherent and prevent separately governed future
  work.

## References

- [Security model](../SECURITY_MODEL.md)
- [Tier 1 roadmap](../TIER1_ROADMAP.md)
- [ADR-005](ADR-005-inert-tier-0-write-infrastructure.md)
