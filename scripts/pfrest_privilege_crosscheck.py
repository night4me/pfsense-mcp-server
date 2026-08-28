#!/usr/bin/env python3
"""Advisory, READ-only cross-check between what PFREST_UPSTREAM and
LIVE_APPLIANCE_SCHEMA each declare as a pfSense READ tool's required
privilege, plus a supplementary check against this project's own
ADR-033 pinned-source algorithm (owner direction, pfREST_LIVE_GUIDANCE_ARC,
2026-08-28).

Pipeline, per tool:

    MCP READ tool
      -> mapped GET endpoint (security_privileges.read_profile_requirements())
      -> OpenAPI "Allowed privileges" list, from BOTH:
           PFREST_UPSTREAM       (https://pfrest.org/api-docs/openapi.json, live)
           LIVE_APPLIANCE_SCHEMA (a connected appliance's own
                                   /api/v2/schema/openapi, live, optional)
      -> MATCH / EXPLAINED_DIFFERENCE / DRIFT
      -> (supplementary) does the narrow privilege also agree with
         security_privileges.compute_privilege_from_url() -- ADR-033's
         own pinned reimplementation of pfSense-pkg-RESTAPI's
         Core/Endpoint.inc::get_method_priv_name(), verified byte-identical
         v2.7.7-v2.10.0?

**Compares the two sources directly to each other**, not only each
independently against the pinned-source algorithm: an earlier draft of
this script routed both sides through
`security_privileges.resolve_privilege()`'s own fail-closed gate (which
requires a source's privilege to already equal the pinned-source value
before it is considered `ok` at all) -- that gate makes genuine
cross-source disagreement structurally unreachable as "DRIFT", because
two sources that are BOTH `ok` are, by that gate's own construction,
both already equal to the same third value and therefore trivially
equal to each other; a real disagreement always surfaced as
`EXPLAINED_DIFFERENCE` instead, which under-reports exactly the
class of finding this check exists to catch. Found via this script's
own test suite, not assumed. This version compares
`security_privileges.lookup_schema_privileges()`'s raw, unfiltered
privilege lists between the two sources directly; `compute_privilege_from_url()`
is still reused, but only as supplementary context in the report text,
never as a gate that can swallow a real disagreement.

Reuses `security_privileges.py`'s already-reviewed, already-tested pure
functions verbatim -- this script does not reimplement privilege
parsing or the pinned-source algorithm. `security_privileges.py` itself
performs no I/O; this script is the one place that fetches the two raw
schema dicts (via `pfsense_mcp.pfrest_docs.fetch.fetch()` for the public
document, and an optional live `PfSenseClient.get_system_schema_openapi()`
call for the appliance) and hands them to it.

**This mechanism is strictly advisory evidence, never authorization**:
it never grants a privilege, never modifies a service account, never
modifies ADR-033's own mapping, never authorizes an endpoint, never
expands the MCP tool surface, and never turns an upstream privilege
claim into trusted configuration. It only classifies and reports.

Two modes:

- No appliance configured (`PFSENSE_API_URL` unset): reports
  PFREST_UPSTREAM's own privilege list plus whether it agrees with the
  pinned-source algorithm -- useful even without a live appliance, since
  it still catches upstream privilege-naming drift against this
  project's own expectation.
- Appliance configured: additionally fetches LIVE_APPLIANCE_SCHEMA and
  compares its raw privilege list against PFREST_UPSTREAM's for the
  same tool set, reporting DRIFT on any real disagreement.

Exit code 0: no DRIFT found (EXPLAINED_DIFFERENCE entries, e.g. "schema
doesn't declare this endpoint at all," are not failures). Exit code 1:
at least one DRIFT finding. Suitable for CI/an offline validation
command, per the owner's own instruction.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pfsense_mcp.pfrest_docs.fetch import FetchError, fetch
from pfsense_mcp.security_privileges import (
    SchemaPrivilegeLookup,
    ToolPrivilegeRequirement,
    compute_privilege_from_url,
    lookup_schema_privileges,
    read_profile_requirements,
)

OPENAPI_URL = "https://pfrest.org/api-docs/openapi.json"
_PAGE_ALL_PRIVILEGE = "page-all"


class CrossCheckVerdict(str, Enum):
    MATCH = "match"
    EXPLAINED_DIFFERENCE = "explained_difference"
    DRIFT = "drift"


@dataclass(frozen=True)
class CrossCheckResult:
    tool_name: str
    url: str
    method: str
    verdict: CrossCheckVerdict
    detail: str


def _narrow(lookup: SchemaPrivilegeLookup) -> frozenset[str] | None:
    if not lookup.ok or lookup.privileges is None:
        return None
    return frozenset(p for p in lookup.privileges if p != _PAGE_ALL_PRIVILEGE)


def _pinned_agreement_note(url: str, method: str, narrow: frozenset[str]) -> str:
    expected = compute_privilege_from_url(url, method)
    if narrow == {expected}:
        return f"agrees with pinned-source algorithm ({expected!r})"
    return f"does NOT match pinned-source algorithm (expected {expected!r}, got {sorted(narrow)})"


def classify(
    requirement: ToolPrivilegeRequirement,
    upstream: SchemaPrivilegeLookup | None,
    appliance: SchemaPrivilegeLookup | None,
) -> CrossCheckResult:
    """Pure classification -- no I/O. `upstream`/`appliance` are `None`
    when that source's lookup was never attempted this run (e.g. no
    appliance configured); a populated `SchemaPrivilegeLookup` with
    `ok=False` means the source *was* consulted but the endpoint/method/
    description could not be resolved to a privilege list at all
    (already explained by its own `.error`)."""

    if requirement.url is None or requirement.method is None:
        raise ValueError(f"classify() requires a requirement with a real endpoint: {requirement.tool_name!r}")
    url, method = requirement.url, requirement.method

    if upstream is None:
        return CrossCheckResult(
            requirement.tool_name,
            url,
            method,
            CrossCheckVerdict.EXPLAINED_DIFFERENCE,
            "PFREST_UPSTREAM lookup unavailable this run",
        )
    if not upstream.ok:
        return CrossCheckResult(
            requirement.tool_name,
            url,
            method,
            CrossCheckVerdict.EXPLAINED_DIFFERENCE,
            f"PFREST_UPSTREAM: {upstream.error}",
        )

    upstream_narrow = _narrow(upstream)
    if upstream_narrow is None:
        # Unreachable given `upstream.ok` above, but checked explicitly
        # rather than with `assert` -- assertions are stripped under
        # Python's -O flag, which would silently defeat this fail-closed
        # guarantee (same discipline security_privileges.py's own
        # resolve_privilege() already applies).
        raise ValueError("internal error: upstream.ok was True but _narrow() returned None")

    if appliance is None:
        note = (
            _pinned_agreement_note(url, method, upstream_narrow)
            if len(upstream_narrow) == 1
            else (f"ambiguous: {sorted(upstream_narrow)}")
        )
        return CrossCheckResult(
            requirement.tool_name,
            url,
            method,
            CrossCheckVerdict.MATCH,
            f"PFREST_UPSTREAM privileges={sorted(upstream_narrow)}, {note} "
            "(no appliance configured to cross-check against)",
        )
    if not appliance.ok:
        return CrossCheckResult(
            requirement.tool_name,
            url,
            method,
            CrossCheckVerdict.EXPLAINED_DIFFERENCE,
            f"LIVE_APPLIANCE_SCHEMA: {appliance.error}",
        )

    appliance_narrow = _narrow(appliance)
    if appliance_narrow is None:
        raise ValueError("internal error: appliance.ok was True but _narrow() returned None")

    if upstream_narrow == appliance_narrow:
        return CrossCheckResult(
            requirement.tool_name,
            url,
            method,
            CrossCheckVerdict.MATCH,
            f"privileges {sorted(upstream_narrow)} agree across PFREST_UPSTREAM and LIVE_APPLIANCE_SCHEMA",
        )
    return CrossCheckResult(
        requirement.tool_name,
        url,
        method,
        CrossCheckVerdict.DRIFT,
        f"PFREST_UPSTREAM={sorted(upstream_narrow)} but LIVE_APPLIANCE_SCHEMA={sorted(appliance_narrow)}",
    )


def _fetch_upstream_schema() -> dict[str, Any] | None:
    try:
        result = fetch(OPENAPI_URL, accept="application/json")
    except FetchError as exc:
        print(f"pfrest_privilege_crosscheck: PFREST_UPSTREAM fetch failed: {exc}", file=sys.stderr)
        return None
    try:
        document = json.loads(result.body)
    except ValueError as exc:
        print(f"pfrest_privilege_crosscheck: PFREST_UPSTREAM document was not valid JSON: {exc}", file=sys.stderr)
        return None
    if not isinstance(document, dict):
        print("pfrest_privilege_crosscheck: PFREST_UPSTREAM document was not a JSON object", file=sys.stderr)
        return None
    return document


def _fetch_appliance_schema() -> dict[str, Any] | None:
    """Only attempted if the standard runtime PFSENSE_* environment
    variables are configured -- this script never invents a target."""

    import os

    if not os.environ.get("PFSENSE_API_URL"):
        return None

    from pfsense_mcp.config import load_api_key, load_config
    from pfsense_mcp.factory import build_pfsense_client

    try:
        config = load_config()
        api_key = load_api_key(config)
        transport, client = build_pfsense_client(config, api_key)
    except Exception as exc:
        print(f"pfrest_privilege_crosscheck: appliance configuration unavailable: {exc}", file=sys.stderr)
        return None

    try:
        document = client.get_system_schema_openapi()
    except Exception as exc:
        print(f"pfrest_privilege_crosscheck: appliance schema fetch failed: {exc}", file=sys.stderr)
        return None
    finally:
        transport.close()

    if not isinstance(document, dict):
        print("pfrest_privilege_crosscheck: appliance schema response was not a JSON object", file=sys.stderr)
        return None
    return document


def run_crosscheck(
    upstream_schema: dict[str, Any] | None, appliance_schema: dict[str, Any] | None
) -> tuple[CrossCheckResult, ...]:
    requirements = [r for r in read_profile_requirements() if r.url is not None and r.method is not None]

    results = []
    for requirement in requirements:
        if requirement.url is None or requirement.method is None:
            raise ValueError(
                f"internal error: filtered requirements list still had no endpoint: {requirement.tool_name!r}"
            )
        upstream_lookup = (
            lookup_schema_privileges(upstream_schema, requirement.url, requirement.method)
            if upstream_schema is not None
            else None
        )
        appliance_lookup = (
            lookup_schema_privileges(appliance_schema, requirement.url, requirement.method)
            if appliance_schema is not None
            else None
        )
        results.append(classify(requirement, upstream_lookup, appliance_lookup))
    return tuple(results)


def main(argv: list[str] | None = None) -> int:
    upstream = _fetch_upstream_schema()
    appliance = _fetch_appliance_schema()

    if upstream is None:
        print("pfrest_privilege_crosscheck: FAILED (could not fetch PFREST_UPSTREAM)")
        return 1

    results = run_crosscheck(upstream, appliance)
    drift = [r for r in results if r.verdict == CrossCheckVerdict.DRIFT]
    explained = [r for r in results if r.verdict == CrossCheckVerdict.EXPLAINED_DIFFERENCE]
    matched = [r for r in results if r.verdict == CrossCheckVerdict.MATCH]

    for result in drift:
        print(f"DRIFT: {result.tool_name} ({result.method} {result.url}): {result.detail}")
    for result in explained:
        print(f"EXPLAINED_DIFFERENCE: {result.tool_name} ({result.method} {result.url}): {result.detail}")

    mode = (
        "with LIVE_APPLIANCE_SCHEMA cross-check" if appliance is not None else "PFREST_UPSTREAM self-consistency only"
    )
    print(
        f"pfrest_privilege_crosscheck: {len(matched)} match, {len(explained)} explained difference, "
        f"{len(drift)} drift ({mode})"
    )
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
