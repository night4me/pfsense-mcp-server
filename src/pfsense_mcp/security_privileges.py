"""pfSense REST API least-privilege derivation and drift detection
(`ADR-033`, implementation Phase B). Pure, deterministic, READ-only
evidence-gathering only -- no pfSense contact of any kind lives in this
module, and it never mutates anything.

Three evidence classes, matching `ADR-033`'s own requirement that
future `bootstrap`/`doctor` output must never imply stronger evidence
than it actually has:

- `SCHEMA_DERIVED` -- a privilege value read from an already-fetched
  OpenAPI schema's own embedded "Allowed privileges" text
  (`pfSense-pkg-RESTAPI`'s `Schemas/OpenAPISchema.inc`), with no
  pinned-source corroboration available for that specific lookup.
- `SOURCE_CROSS_CHECKED` -- the schema's value independently agreed
  with `compute_privilege_from_url()`'s pure reimplementation of
  `Core/Endpoint.inc::get_method_priv_name()` (confirmed byte-identical
  across `pfSense-pkg-RESTAPI` `v2.7.7`-`v2.10.0`, `ADR-033` §2). The
  strongest evidence class this module can produce.
- `ACCOUNT_OBSERVED` -- not produced by this module directly; the
  evidence class a caller should attach to a privilege read off a real
  pfSense account's own `priv` list (`compute_account_drift()`'s
  `observed` parameter), kept here only as the third, complete member
  of the enum so callers share one vocabulary.

**Fail-closed, never guesses**: schema/source disagreement, missing
evidence, malformed evidence, and ambiguous evidence (more than one
non-`page-all` privilege offered) all resolve to `privilege=None` plus
a populated `error` -- this module never silently picks one candidate
over another or falls back to a weaker guess without saying so.

No network access anywhere in this module. `resolve_privilege()` takes
an already-fetched schema dict; it never fetches one itself. No
`pfsense_mcp.tier1` import, matching the established isolation
discipline for this `security_*` module family
(`security_discovery.py`, `security_plan.py`, `security_doctor.py`) --
pfSense RBAC evidence and Tier 1's cryptographic authorization chain
are independent defense layers (`ADR-033` §7); this module produces
evidence for the former only and has no relationship to the latter.

Does not create, modify, or delete a pfSense user, privilege, or API
key. Does not implement `bootstrap`/`setup`. See
`security_bootstrap_transaction.py` for the separate (also
provisioning-free) transaction-state model this Phase B also defines.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .api_version import ApiVersion
from .endpoints import EndpointInfo, Endpoints
from .write_endpoints import WriteEndpointInfo, WriteEndpoints

_TOOLS_READ_DIR = Path(__file__).parent / "tools" / "read"
_CLIENT_MODULE_PATH = Path(__file__).parent / "pfsense_client.py"

_ALLOWED_PRIVILEGES_PATTERN = re.compile(r"Allowed privileges\*\*:\s*\[\s*([^\]]*)\]")
_PAGE_ALL_PRIVILEGE = "page-all"

#: Confirmed range: `Core/Endpoint.inc::get_method_priv_name()` is
#: byte-identical across every `pfrest/pfSense-pkg-RESTAPI` tag from
#: `v2.7.7` through `v2.10.0` (the latest tag as of this research,
#: 2026-08-17) -- `ADR-033` §2. A version outside this range is not
#: known-bad, only unverified; see `check_package_version_support()`.
VERIFIED_PACKAGE_VERSION_MIN = (2, 7, 7)
VERIFIED_PACKAGE_VERSION_MAX = (2, 10, 0)


class EvidenceClass(str, Enum):
    SCHEMA_DERIVED = "schema_derived"
    SOURCE_CROSS_CHECKED = "source_cross_checked"
    ACCOUNT_OBSERVED = "account_observed"


def compute_privilege_from_url(url: str, method: str) -> str:
    """Pure reimplementation of `pfSense-pkg-RESTAPI`'s
    `Core/Endpoint.inc::get_method_priv_name()`:

        $priv_name_prefix = str_replace('/', '-', $this->url) . '-';
        $priv_name_prefix = str_replace('_', '-', $priv_name_prefix);
        # strip a leading '-' (present because the URL starts with '/')
        return $priv_name_prefix . strtolower($method);

    Raises `ValueError` on a malformed `url`/`method` rather than
    silently producing a nonsensical privilege string."""

    if not url or not url.startswith("/"):
        raise ValueError(f"url must be a non-empty path starting with '/': {url!r}")
    if not method or not method.isalpha():
        raise ValueError(f"method must be a non-empty alphabetic HTTP verb: {method!r}")

    slug = url.replace("/", "-").replace("_", "-")
    if slug.startswith("-"):
        slug = slug[1:]
    return f"{slug}-{method.lower()}"


@dataclass(frozen=True)
class SchemaPrivilegeLookup:
    """Result of extracting one endpoint+method's full "Allowed
    privileges" list from an already-parsed OpenAPI schema dict.
    `privileges` is `None` iff `error` is populated."""

    privileges: tuple[str, ...] | None
    error: str | None

    @property
    def ok(self) -> bool:
        return self.error is None


def lookup_schema_privileges(schema: dict[str, Any], url: str, method: str) -> SchemaPrivilegeLookup:
    """Pure -- performs no I/O. `schema` must already be a parsed
    OpenAPI document (e.g. from a previously-fetched live schema).
    Extracts the exact `"**Allowed privileges**: [ ... ]"` text
    `pfSense-pkg-RESTAPI`'s own `Schemas/OpenAPISchema.inc` embeds in
    every operation's `description` field (confirmed source, `ADR-033`
    §2), returning the full list (including `page-all`) unfiltered --
    callers needing the narrow privilege alone should use
    `resolve_privilege()`."""

    method_lower = method.lower()
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return SchemaPrivilegeLookup(None, "schema has no 'paths' object")

    operation_path = paths.get(url)
    if not isinstance(operation_path, dict):
        return SchemaPrivilegeLookup(None, f"endpoint not present in schema: {url!r}")

    method_obj = operation_path.get(method_lower)
    if not isinstance(method_obj, dict):
        return SchemaPrivilegeLookup(None, f"method {method!r} not present for endpoint {url!r}")

    description = method_obj.get("description")
    if not isinstance(description, str):
        return SchemaPrivilegeLookup(None, f"no 'description' field for {method!r} {url!r}")

    match = _ALLOWED_PRIVILEGES_PATTERN.search(description)
    if match is None:
        return SchemaPrivilegeLookup(None, f"no 'Allowed privileges' text found for {method!r} {url!r}")

    raw = match.group(1).strip()
    if not raw:
        return SchemaPrivilegeLookup(None, f"'Allowed privileges' list is empty for {method!r} {url!r}")

    # Normalize: split on comma, strip whitespace, dedupe order-preserving.
    # A duplicate entry in the schema's own list is noise, not ambiguity.
    ordered: dict[str, None] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            return SchemaPrivilegeLookup(None, f"malformed privilege list (empty entry) for {method!r} {url!r}")
        ordered.setdefault(item, None)

    return SchemaPrivilegeLookup(tuple(ordered.keys()), None)


@dataclass(frozen=True)
class ResolvedPrivilege:
    """The one, fail-closed combination of schema evidence and
    pinned-source cross-check (`ADR-033` §3, this phase's requirement
    3). `ok` is `True` iff `privilege` is populated and `error` is not
    -- callers must check `ok` before trusting `privilege`."""

    url: str
    method: str
    privilege: str | None
    evidence_class: EvidenceClass | None
    error: str | None

    @property
    def ok(self) -> bool:
        return self.privilege is not None and self.error is None


def resolve_privilege(schema: dict[str, Any] | None, url: str, method: str) -> ResolvedPrivilege:
    """The live OpenAPI schema is primary (`ADR-033` §3). If `schema`
    is `None`, resolves via the pinned-source algorithm alone --
    `evidence_class=None` (not `SCHEMA_DERIVED`/`SOURCE_CROSS_CHECKED`:
    honestly reflects that no live corroboration was available for this
    specific call, never overstates confidence). If `schema` is
    provided but the endpoint/method is missing, malformed, or offers
    more than one non-`page-all` privilege, fails closed --
    `privilege=None`, `error` populated -- rather than silently falling
    back to source alone. If schema and source disagree, fails closed
    the same way; never silently picks one."""

    source_privilege = compute_privilege_from_url(url, method)

    if schema is None:
        return ResolvedPrivilege(url, method, source_privilege, None, None)

    lookup = lookup_schema_privileges(schema, url, method)
    if not lookup.ok:
        return ResolvedPrivilege(url, method, None, None, lookup.error)

    if lookup.privileges is None:
        # Unreachable given `lookup.ok` above, but checked explicitly
        # rather than with `assert` -- assertions are stripped under
        # Python's -O flag, which would silently defeat this fail-closed
        # guarantee (same fix applied to security_doctor.py).
        return ResolvedPrivilege(url, method, None, None, "internal error: ok lookup with no privileges")
    narrow = [p for p in lookup.privileges if p != _PAGE_ALL_PRIVILEGE]
    if len(narrow) == 0:
        return ResolvedPrivilege(
            url,
            method,
            None,
            None,
            f"endpoint requires {_PAGE_ALL_PRIVILEGE!r} only, no narrow privilege exists: {method!r} {url!r}",
        )
    if len(narrow) > 1:
        return ResolvedPrivilege(
            url,
            method,
            None,
            None,
            f"ambiguous: more than one non-page-all privilege offered for {method!r} {url!r}: {sorted(narrow)}",
        )

    schema_privilege = narrow[0]
    if schema_privilege != source_privilege:
        return ResolvedPrivilege(
            url,
            method,
            None,
            None,
            f"schema/source disagreement for {method!r} {url!r}: "
            f"schema={schema_privilege!r} source={source_privilege!r}",
        )

    return ResolvedPrivilege(url, method, schema_privilege, EvidenceClass.SOURCE_CROSS_CHECKED, None)


@dataclass(frozen=True)
class ToolPrivilegeRequirement:
    """One registered READ tool's (or the one accepted WRITE
    capability's) privilege requirement. `client_method`/`endpoint_symbol`/
    `url`/`method` are all `None` for a local-only tool (no pfSense call
    at all, e.g. `mcp_info`)."""

    tool_name: str
    client_method: str | None
    endpoint_symbol: str | None
    url: str | None
    method: str | None


def _client_method_for_tool_source(source: str, *, tool_name: str) -> str | None:
    """AST-based extraction of the one `client.<method>()` call a READ
    tool's source makes -- mirrors `scripts/public_contract.py`'s own
    already-reviewed technique exactly. Reads source text only; never
    imports or executes the tool module."""

    tree = ast.parse(source)
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "client"
    }
    if not calls:
        return None
    if len(calls) > 1:
        raise ValueError(f"tool {tool_name!r} makes more than one client call: {sorted(calls)}")
    return next(iter(calls))


def full_api_path(path_suffix: str, api_version: ApiVersion) -> str:
    """Builds the full `/api/<version><path_suffix>` URL exactly as
    `RestApiClient.get()` does (`rest_api_client.py`:
    `f"/api/{self._api_version.value}{endpoint.path_suffix}"`) --
    reused here rather than reimplemented, so this module's URLs always
    match what a real request actually targets, including the schema's
    own `paths` keys and `Core/Endpoint.inc`'s `$this->url`."""

    return f"/api/{api_version.value}{path_suffix}"


def _endpoint_symbol_for_client_method(client_source: str, method_name: str) -> str | None:
    """AST-based extraction of the one `Endpoints.<SYMBOL>` reference
    inside `PfSenseClient.<method_name>()`'s body. Reads source text
    only."""

    tree = ast.parse(client_source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == method_name:
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Attribute)
                    and isinstance(inner.value, ast.Name)
                    and inner.value.id == "Endpoints"
                ):
                    return inner.attr
    return None


def registered_read_tool_requirements() -> tuple[ToolPrivilegeRequirement, ...]:
    """The authoritative current READ-tool -> endpoint mapping, derived
    mechanically from this package's own shipped `tools/read/*.py`
    source files -- never a hand-maintained list, so this stays correct
    as tools are added or removed without needing to update this
    function (`ADR-033` implementation Phase B requirement 2: "do not
    duplicate the tool/endpoint catalogue manually"). Returns however
    many entries the current `tools/read/` directory actually contains
    -- no hard-coded count."""

    client_source = _CLIENT_MODULE_PATH.read_text(encoding="utf-8")
    results: list[ToolPrivilegeRequirement] = []
    for path in sorted(_TOOLS_READ_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        tool_source = path.read_text(encoding="utf-8")
        method = _client_method_for_tool_source(tool_source, tool_name=path.stem)
        if method is None:
            results.append(ToolPrivilegeRequirement(path.stem, None, None, None, None))
            continue

        endpoint_symbol = _endpoint_symbol_for_client_method(client_source, method)
        if endpoint_symbol is None:
            raise ValueError(f"could not resolve an Endpoints symbol for client method {method!r} ({path.stem!r})")

        endpoint_info = getattr(Endpoints, endpoint_symbol, None)
        if not isinstance(endpoint_info, EndpointInfo):
            raise ValueError(f"Endpoints.{endpoint_symbol} does not exist or is not an EndpointInfo")

        results.append(
            ToolPrivilegeRequirement(
                path.stem,
                method,
                endpoint_symbol,
                full_api_path(endpoint_info.path_suffix, endpoint_info.min_api_version),
                "GET",
            )
        )
    return tuple(results)


def write_protected_tool_requirements() -> tuple[ToolPrivilegeRequirement, ...]:
    """The currently accepted WRITE capability's own privilege
    requirement(s), derived from `WriteEndpoints.active_entries()` --
    generic over however many entries exist (currently exactly one,
    `FIREWALL_ALIAS_DESCRIPTION`), not hard-coded to that one name, so
    a future, separately-authorized second WRITE capability is picked
    up automatically."""

    results: list[ToolPrivilegeRequirement] = []
    for name in WriteEndpoints.active_entries():
        info = getattr(WriteEndpoints, name)
        if not isinstance(info, WriteEndpointInfo):
            raise ValueError(f"WriteEndpoints.{name} is not a WriteEndpointInfo")
        results.append(
            ToolPrivilegeRequirement(
                f"WRITE:{name}",
                None,
                name,
                full_api_path(info.path_suffix, info.min_api_version),
                info.http_method,
            )
        )
    return tuple(results)


def read_profile_requirements() -> tuple[ToolPrivilegeRequirement, ...]:
    """Current READ-only profile's tool requirements (local-only tools
    included, with `url=None`/`method=None`)."""

    return registered_read_tool_requirements()


def write_protected_profile_requirements() -> tuple[ToolPrivilegeRequirement, ...]:
    """Current `write_protected` profile's tool requirements: every
    READ-profile requirement plus the accepted WRITE capability's own."""

    return registered_read_tool_requirements() + write_protected_tool_requirements()


def resolve_profile_privileges(
    schema: dict[str, Any] | None, requirements: tuple[ToolPrivilegeRequirement, ...]
) -> tuple[ResolvedPrivilege, ...]:
    """Resolves every requirement with a real endpoint (`url`/`method`
    populated) against `resolve_privilege()`; local-only tools
    contribute nothing (no `ResolvedPrivilege` produced for them).
    Deterministic ordering: same order as `requirements`."""

    resolved: list[ResolvedPrivilege] = []
    for requirement in requirements:
        if requirement.url is None or requirement.method is None:
            continue
        resolved.append(resolve_privilege(schema, requirement.url, requirement.method))
    return tuple(resolved)


def distinct_ok_privileges(resolved: tuple[ResolvedPrivilege, ...]) -> frozenset[str]:
    """The set of distinct privilege strings among only the
    successfully resolved (`ok`) entries. Callers must separately check
    for any non-`ok` entry (a real derivation failure) before trusting
    that this set is complete -- this helper deliberately does not
    raise, so a caller can report partial results alongside errors."""

    return frozenset(r.privilege for r in resolved if r.ok and r.privilege is not None)


class DriftFindingKind(str, Enum):
    PRIVILEGE_PRESENT_AS_EXPECTED = "privilege_present_as_expected"
    PRIVILEGE_MISSING = "privilege_missing"
    UNEXPECTED_ADDITIONAL_PRIVILEGE = "unexpected_additional_privilege"
    SCHEMA_SOURCE_DISAGREEMENT = "schema_source_disagreement"
    UNVERIFIED_PACKAGE_VERSION = "unverified_package_version"
    MALFORMED_EVIDENCE = "malformed_evidence"


@dataclass(frozen=True)
class DriftFinding:
    kind: DriftFindingKind
    detail: str
    privilege: str | None = None


@dataclass(frozen=True)
class DriftReport:
    """`clean` is `True` iff there are zero findings that mean "this
    account does not currently match its expected privilege set" --
    i.e. no `PRIVILEGE_MISSING`/`UNEXPECTED_ADDITIONAL_PRIVILEGE`/
    `SCHEMA_SOURCE_DISAGREEMENT`/`MALFORMED_EVIDENCE` findings.
    `UNVERIFIED_PACKAGE_VERSION` alone does not make a report unclean --
    it is an explicit "re-confirm before relying on this" flag, not
    proof of an actual mismatch (`ADR-033` §3)."""

    findings: tuple[DriftFinding, ...]

    @property
    def clean(self) -> bool:
        unclean_kinds = {
            DriftFindingKind.PRIVILEGE_MISSING,
            DriftFindingKind.UNEXPECTED_ADDITIONAL_PRIVILEGE,
            DriftFindingKind.SCHEMA_SOURCE_DISAGREEMENT,
            DriftFindingKind.MALFORMED_EVIDENCE,
        }
        return not any(f.kind in unclean_kinds for f in self.findings)


def compute_account_drift(
    expected: frozenset[str],
    observed: frozenset[str],
    *,
    resolution_errors: tuple[str, ...] = (),
) -> DriftReport:
    """Pure set comparison between `expected` (this project's own
    derived requirement, e.g. from `distinct_ok_privileges()`) and
    `observed` (a real account's actual `priv` list -- `ACCOUNT_OBSERVED`
    evidence, supplied by the caller; this function never fetches it).
    `resolution_errors` carries forward any `ResolvedPrivilege.error`
    strings from deriving `expected` itself, surfaced as
    `MALFORMED_EVIDENCE` findings so a caller can never mistake
    "expected set could not be fully derived" for "account matches."

    Never mutates anything -- pure function, no I/O. Deterministic
    ordering: missing (sorted) before unexpected (sorted) before
    malformed-evidence findings."""

    missing = sorted(expected - observed)
    unexpected = sorted(observed - expected)

    findings: list[DriftFinding] = [
        DriftFinding(DriftFindingKind.PRIVILEGE_MISSING, f"expected privilege not present on account: {p!r}", p)
        for p in missing
    ]
    findings.extend(
        DriftFinding(
            DriftFindingKind.UNEXPECTED_ADDITIONAL_PRIVILEGE,
            f"account holds a privilege not in the expected set: {p!r}",
            p,
        )
        for p in unexpected
    )
    findings.extend(DriftFinding(DriftFindingKind.MALFORMED_EVIDENCE, error) for error in resolution_errors)
    if not missing and not unexpected and not resolution_errors:
        matched = sorted(expected & observed)
        findings.extend(
            DriftFinding(DriftFindingKind.PRIVILEGE_PRESENT_AS_EXPECTED, f"privilege matches expectation: {p!r}", p)
            for p in matched
        )

    return DriftReport(tuple(findings))


def check_package_version_support(version: tuple[int, int, int]) -> DriftFinding | None:
    """Returns a `DriftFindingKind.UNVERIFIED_PACKAGE_VERSION` finding
    if `version` falls outside the range this module's derivation
    algorithm has actually been verified against
    (`VERIFIED_PACKAGE_VERSION_MIN`/`MAX`, `ADR-033` §2/§3), else
    `None`. Pure -- does not fetch the installed version itself; a
    caller supplies it (e.g. from an already-fetched live schema or
    `pfsense_get_system_packages`)."""

    if VERIFIED_PACKAGE_VERSION_MIN <= version <= VERIFIED_PACKAGE_VERSION_MAX:
        return None
    return DriftFinding(
        DriftFindingKind.UNVERIFIED_PACKAGE_VERSION,
        f"pfSense-pkg-RESTAPI version {'.'.join(map(str, version))} is outside the verified range "
        f"{'.'.join(map(str, VERIFIED_PACKAGE_VERSION_MIN))}-{'.'.join(map(str, VERIFIED_PACKAGE_VERSION_MAX))} "
        "-- re-confirm the derivation algorithm still matches before relying on it.",
    )
