"""Mutation allow-list — the single source of truth for which
(path, HTTP method) pairs this server is ever permitted to write to.

Through W3 Slice 3, empty in this build. W3 Slice 4 (ADR-028) added the
single accepted first-WRITE entry, `FIREWALL_ALIAS_DESCRIPTION` — the
description-only firewall-alias PATCH ADR-026 selected and ADR-028's
three-condition activation gate governs. ADR-037 Batch 1 (2026-09-04,
owner) added five further entries — `NTP_TIME_SERVER_PREFER`,
`NTP_SETTINGS_OBSERVABILITY_TOGGLES`, `LOG_DISPLAY_PREFERENCES`,
`LOG_RETENTION_SETTINGS`, `SYSTEM_TIMEZONE` — each `verified=False`
pending its own future LAB qualification, each governed by its own
capability module under `tier1/` (see each module's own docstring for its
exact field projection). WriteApiClient.execute()/send_for_tier1() refuse
any MutationPlan/Tier-1 send whose endpoint_symbol is not an attribute of
WriteEndpoints here, before any network call is made.
scripts/write_allow_list_check.py mechanically enforces that this class has
*exactly* these six entries and no more — any further WriteEndpoints entry
requires a new, separate, explicit owner decision, exactly as this batch
itself was.

`FIREWALL_ALIAS_DESCRIPTION.verified` is `True`, set 2026-08-16 after
ADR-026's acceptance matrix rows 6, 17, and 18 (previously the
outstanding live-evidence gap) were each independently satisfied by live
evidence: the first real pfSense WRITE (rows 6/18), and a second real
WRITE performed entirely through a dedicated, independently-verified
least-privilege pfSense identity holding only the four minimum
privileges the production path needs (row 17). Every other row in the
acceptance matrix carries production-bound offline evidence exercising
the real Tier1 composition (adapter, executor, `build_production_
runtime()`) with only the external pfSense transport substituted — see
ADR-026's evidence sections for the full row-by-row citation and the
strict, owner-confirmed standard this reclassification was checked
against. `WriteApiClient` still refuses any send/execute against an
endpoint whose `verified` is not `True` — that refusal now no longer
applies to this entry, but the check itself, and the full W3 Slice 4
three-condition activation gate (profile grant + `WriteEndpoints` entry
+ a constructed production runtime), remain fully in force and unchanged
for every other purpose. Setting `verified=True` does not itself expose
this WRITE tool under the default profile: `AuditorProfile` (the
default) still grants zero WRITE capabilities, so the tool is still
unreachable unless an operator explicitly selects
`PFSENSE_PROFILE=write_protected`.

Every entry requires: independent live verification before `verified` is
set `True` (the same bar `Endpoints.verified` already sets), an explicit
RollbackPlan if `reversible=True` (this entry's rollback is the existing
alias-description execution core's own snapshot/restore mechanism, not a
new one), and `dry_run_supported=True`.
"""

from __future__ import annotations

from dataclasses import dataclass

from .api_version import ApiVersion


@dataclass(frozen=True)
class WriteEndpointInfo:
    path_suffix: str  # e.g. "/firewall/alias" — no "/api/vN" prefix
    http_method: str  # "POST" | "PUT" | "PATCH" | "DELETE"
    verified: bool
    min_api_version: ApiVersion
    reversible: bool
    dry_run_supported: bool
    #: ADR-029: a distinct, independently-gated property from `verified`.
    #: `True` only permits use through `WriteApiClient.send_for_tier1_
    #: acceptance()` (tier1/acceptance.py) -- a separate, structurally
    #: isolated, LAB-only path for gathering the live evidence that
    #: justifies promoting `verified` to `True`. Never consulted by
    #: `dry_run()`/`execute()`/`send_for_tier1()`, which remain gated on
    #: `verified` alone, unchanged. Default `False` -- every entry must
    #: opt in explicitly.
    acceptance_eligible: bool = False


class WriteEndpoints:
    """Exactly six entries in this build. See module docstring."""

    #: ADR-026's selected, narrowest evidenced first-WRITE candidate:
    #: `PATCH /api/v2/firewall/alias`, description field only. `verified`
    #: is `True` -- see module docstring for the exact live-evidence
    #: chain that justified it (2026-08-16).
    FIREWALL_ALIAS_DESCRIPTION = WriteEndpointInfo(
        path_suffix="/firewall/alias",
        http_method="PATCH",
        verified=True,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        # ADR-029: this entry gathered its own promotion evidence via the
        # acceptance-only path prior to 2026-08-16. Left `True` even now
        # that `verified=True` -- harmless, since `tier1/acceptance.py`'s
        # own one-time gate already refuses `issue_acceptance_context()`
        # permanently for any endpoint once `verified=True` holds, so this
        # flag has no further effect. Not a second WRITE capability --
        # normal exposure still requires verified=True, unchanged.
        acceptance_eligible=True,
    )

    #: ADR-037 Batch 1 (2026-09-04, owner) -- five new entries, each
    #: `verified=False` (no LAB evidence yet; each entry's own capability
    #: module documents its exact narrow field projection). Raised from
    #: one active entry to exactly six by an explicit, narrow owner
    #: authorization -- not a general opening of the allow-list to future
    #: entries. `scripts/write_allow_list_check.py` still asserts this
    #: exact six-name set, exact-match, fail-closed.
    #:
    #: `acceptance_eligible=True` (2026-09-04, owner, post-implementation
    #: security review): each entry opts into the ADR-029 first-live-
    #: acceptance path (`tier1/acceptance.py`) -- the same, reviewed
    #: mechanism `FIREWALL_ALIAS_DESCRIPTION` already used, never a
    #: shortcut around it. This flag alone grants no reachability of any
    #: kind: `issue_acceptance_context()` only ever accepts the one
    #: pinned LAB target, and `tier1/write_batch1_production_runtime.py`
    #: (the production wiring these five capabilities would actually be
    #: exercised through) cannot itself be constructed in any environment
    #: that lacks a reachable TPM-witness anchor and real pinned Ed25519
    #: authority files -- neither exists in this repository's own CI/dev
    #: environment. Setting `verified=True` still requires the same full,
    #: independently-verified live-evidence chain
    #: `FIREWALL_ALIAS_DESCRIPTION`'s own docstring above describes.
    NTP_TIME_SERVER_PREFER = WriteEndpointInfo(
        path_suffix="/services/ntp/time_server",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        acceptance_eligible=True,
    )
    NTP_SETTINGS_OBSERVABILITY_TOGGLES = WriteEndpointInfo(
        path_suffix="/services/ntp/settings",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        acceptance_eligible=True,
    )
    LOG_DISPLAY_PREFERENCES = WriteEndpointInfo(
        path_suffix="/status/logs/settings",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        acceptance_eligible=True,
    )
    LOG_RETENTION_SETTINGS = WriteEndpointInfo(
        path_suffix="/status/logs/settings",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        acceptance_eligible=True,
    )
    SYSTEM_TIMEZONE = WriteEndpointInfo(
        path_suffix="/system/timezone",
        http_method="PATCH",
        verified=False,
        min_api_version=ApiVersion.V2,
        reversible=True,
        dry_run_supported=True,
        acceptance_eligible=True,
    )

    @classmethod
    def active_entries(cls) -> list[str]:
        """Names of all WriteEndpointInfo entries currently declared here.

        The single source of truth for "how many write endpoints are
        allow-listed" — scripts/write_allow_list_check.py and any
        runtime introspection both call this instead of each keeping
        their own copy of the same vars()-scan.
        """
        return [name for name, value in vars(cls).items() if isinstance(value, WriteEndpointInfo)]
