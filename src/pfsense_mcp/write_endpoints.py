"""Mutation allow-list — the single source of truth for which
(path, HTTP method) pairs this server is ever permitted to write to.

Empty in this build. WriteApiClient.execute() refuses any MutationPlan
whose endpoint_symbol is not an attribute of WriteEndpoints here, before
any network call is made. scripts/write_allow_list_check.py mechanically
enforces that this class has zero WriteEndpointInfo entries until a
future, separately authorized tier adds the first one.

Every future entry requires: independent live verification (verified=True,
the same bar Endpoints.verified already sets), an explicit RollbackPlan if
reversible=True, and dry_run_supported=True.
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


class WriteEndpoints:
    """Deliberately empty in this build. See module docstring."""

    @classmethod
    def active_entries(cls) -> list[str]:
        """Names of all WriteEndpointInfo entries currently declared here.

        The single source of truth for "how many write endpoints are
        allow-listed" — scripts/write_allow_list_check.py and any
        runtime introspection both call this instead of each keeping
        their own copy of the same vars()-scan.
        """
        return [name for name, value in vars(cls).items() if isinstance(value, WriteEndpointInfo)]
