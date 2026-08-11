"""Read-only disposable-lab provenance and candidate safety gates.

This module is intentionally lab-only. Its human attestation is not a
production authorization, appliance identity, or complete dependency proof.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from pfsense_mcp.models.firewall import FirewallRule
from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.firewall_nat_port_forward import FirewallNatPortForward
from pfsense_mcp.secure_file import open_nofollow, validate_descriptor

from .config import LabConfig, LabConfigError, normalize_lab_candidate

ATTESTATION_SCHEMA_VERSION = 1
ATTESTATION_MAX_AGE = timedelta(minutes=10)
ATTESTATION_FUTURE_TOLERANCE = timedelta(seconds=30)
_ATTESTATION_MAX_BYTES = 16 * 1024
_REQUIRED_SURFACES = frozenset(
    {"routing", "vpn", "services", "firewall_policy", "nat", "other_operational_configuration"}
)
_ALIAS_TOKEN_EDGE = re.compile(r"[A-Za-z0-9_]")


class LabSafetyError(Exception):
    """A lab safety gate failed; no mutation may proceed."""


@dataclass(frozen=True)
class LabAttestation:
    schema_version: int
    lab_identity: str
    candidate: str
    issued_at: datetime
    expires_at: datetime
    target_is_disposable_lab: bool
    candidate_is_synthetic_test_only: bool
    verified_no_operational_references: bool
    operator_checked_surfaces: frozenset[str]


@dataclass(frozen=True)
class DependencyCheck:
    surface: str
    complete: bool
    references_found: bool


@dataclass(frozen=True)
class CandidateSummary:
    name: str
    numeric_locator: int
    alias_type: str
    description: str
    member_count: int
    detail_count: int


@dataclass(frozen=True)
class LabPreflightReport:
    lab_identity: str
    candidate: CandidateSummary
    dependency_checks: tuple[DependencyCheck, ...]
    uncovered_surfaces: tuple[str, ...]
    attestation_expires_at: datetime
    passed: bool = True

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "lab_provenance": "PASS",
            "credential_availability": "PASS",
            "candidate_resolution": "PASS",
            "lab_identity": self.lab_identity,
            "candidate": {
                "name": self.candidate.name,
                "numeric_locator": self.candidate.numeric_locator,
                "type": self.candidate.alias_type,
                "description": self.candidate.description,
                "member_count": self.candidate.member_count,
                "detail_count": self.candidate.detail_count,
            },
            "automatic_dependency_checks": [
                {
                    "surface": item.surface,
                    "complete": item.complete,
                    "references_found": item.references_found,
                }
                for item in self.dependency_checks
            ],
            "uncovered_dependency_surfaces": list(self.uncovered_surfaces),
            "operator_attestation": "VALID",
            "attestation_expires_at": self.attestation_expires_at.isoformat().replace("+00:00", "Z"),
            "combined_disposable_lab_safety_gate": "PASS",
            "global_dependency_proof": False,
        }


class LabReadClient(Protocol):
    def get_firewall_aliases(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallAlias]: ...

    def get_firewall_rules(self, *, include_identifying_metadata: bool = False) -> list[FirewallRule]: ...

    def get_firewall_nat_port_forwards(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatPortForward]: ...


def _parse_utc_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LabSafetyError(f"Lab attestation {field} must be an explicit UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise LabSafetyError(f"Lab attestation {field} is malformed") from None
    if parsed.tzinfo != timezone.utc:
        raise LabSafetyError(f"Lab attestation {field} must be UTC")
    return parsed


def _read_secure_json(path: Path) -> dict[str, Any]:
    descriptor = open_nofollow(path, on_error=LabSafetyError)
    try:
        validate_descriptor(path, descriptor, max_bytes=_ATTESTATION_MAX_BYTES, on_error=LabSafetyError)
        try:
            raw = os.read(descriptor, _ATTESTATION_MAX_BYTES + 1)
        except OSError:
            raise LabSafetyError("Lab attestation could not be read") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise LabSafetyError("Lab attestation descriptor could not be closed") from None
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LabSafetyError("Lab attestation is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise LabSafetyError("Lab attestation must be a JSON object")
    return value


def load_lab_attestation(
    config: LabConfig, *, now: datetime | None = None, reader: Callable[[Path], dict[str, Any]] = _read_secure_json
) -> LabAttestation:
    """Load and validate a short-lived, exact-target-bound operator statement."""

    raw = reader(config.attestation_file)
    expected_keys = {
        "schema_version",
        "lab_identity",
        "candidate",
        "issued_at",
        "expires_at",
        "target_is_disposable_lab",
        "candidate_is_synthetic_test_only",
        "verified_no_operational_references",
        "operator_checked_surfaces",
    }
    if set(raw) != expected_keys:
        raise LabSafetyError("Lab attestation fields do not exactly match schema v1")
    if raw["schema_version"] != ATTESTATION_SCHEMA_VERSION or isinstance(raw["schema_version"], bool):
        raise LabSafetyError("Unsupported lab attestation schema version")
    if raw["lab_identity"] != config.identity:
        raise LabSafetyError("Lab attestation identity does not match configured lab identity")
    if not isinstance(raw["candidate"], str):
        raise LabSafetyError("Lab attestation candidate must be a string")
    try:
        attested_candidate = normalize_lab_candidate(raw["candidate"])
    except LabConfigError:
        raise LabSafetyError("Lab attestation candidate is malformed") from None
    if attested_candidate != config.candidate:
        raise LabSafetyError("Lab attestation candidate does not exactly match configured candidate")

    statements = (
        "target_is_disposable_lab",
        "candidate_is_synthetic_test_only",
        "verified_no_operational_references",
    )
    if any(raw[field] is not True for field in statements):
        raise LabSafetyError("Lab attestation requires every operator safety statement to be explicitly true")
    surfaces = raw["operator_checked_surfaces"]
    if not isinstance(surfaces, list) or any(not isinstance(item, str) for item in surfaces):
        raise LabSafetyError("Lab attestation checked surfaces must be a string list")
    if len(surfaces) != len(set(surfaces)) or frozenset(surfaces) != _REQUIRED_SURFACES:
        raise LabSafetyError("Lab attestation must acknowledge exactly every required dependency surface")

    issued_at = _parse_utc_timestamp(raw["issued_at"], "issued_at")
    expires_at = _parse_utc_timestamp(raw["expires_at"], "expires_at")
    current = now or datetime.now(timezone.utc)
    if issued_at > current + ATTESTATION_FUTURE_TOLERANCE:
        raise LabSafetyError("Lab attestation was issued too far in the future")
    if expires_at <= current:
        raise LabSafetyError("Lab attestation has expired")
    if expires_at <= issued_at or expires_at - issued_at > ATTESTATION_MAX_AGE:
        raise LabSafetyError("Lab attestation validity must be positive and no longer than 10 minutes")

    return LabAttestation(
        schema_version=ATTESTATION_SCHEMA_VERSION,
        lab_identity=config.identity,
        candidate=config.candidate,
        issued_at=issued_at,
        expires_at=expires_at,
        target_is_disposable_lab=True,
        candidate_is_synthetic_test_only=True,
        verified_no_operational_references=True,
        operator_checked_surfaces=frozenset(surfaces),
    )


def _contains_alias_reference(value: str | None, candidate: str) -> bool:
    if value is None:
        return False
    start = 0
    while True:
        index = value.find(candidate, start)
        if index < 0:
            return False
        left_ok = index == 0 or _ALIAS_TOKEN_EDGE.fullmatch(value[index - 1]) is None
        end = index + len(candidate)
        right_ok = end == len(value) or _ALIAS_TOKEN_EDGE.fullmatch(value[end]) is None
        if left_ok and right_ok:
            return True
        start = index + 1


def _resolve_candidate(aliases: list[FirewallAlias], candidate: str) -> FirewallAlias:
    if len(aliases) >= 500:
        raise LabSafetyError("Alias enumeration reached its maximum bound and may be incomplete")
    if any(not isinstance(alias, FirewallAlias) for alias in aliases):
        raise LabSafetyError("Alias query returned malformed candidate evidence")
    matches = [alias for alias in aliases if alias.name == candidate]
    if len(matches) != 1:
        raise LabSafetyError("Configured candidate must resolve to exactly one alias")
    alias = matches[0]
    if alias.address is None or alias.detail is None:
        raise LabSafetyError("Candidate alias state is incomplete or privacy-redacted")
    if alias.type not in {"host", "network", "port"}:
        raise LabSafetyError("Candidate alias type is unsupported for ADR-026")
    if len(alias.address) != len(alias.detail):
        raise LabSafetyError("Candidate alias members and details have inconsistent cardinality")
    return alias


def _check_dependencies(client: LabReadClient, candidate: str) -> tuple[DependencyCheck, ...]:
    try:
        rules = client.get_firewall_rules(include_identifying_metadata=True)
        nat = client.get_firewall_nat_port_forwards(include_identifying_metadata=True, limit=500)
    except Exception:
        raise LabSafetyError("Automatic dependency query failed") from None
    if len(nat) >= 500:
        raise LabSafetyError("NAT dependency enumeration reached its maximum bound and may be incomplete")
    if any(not isinstance(item, FirewallRule) for item in rules) or any(
        not isinstance(item, FirewallNatPortForward) for item in nat
    ):
        raise LabSafetyError("Automatic dependency query returned malformed evidence")

    rule_reference = any(
        _contains_alias_reference(value, candidate) for rule in rules for value in (rule.source, rule.destination)
    )
    nat_reference = any(
        _contains_alias_reference(value, candidate)
        for item in nat
        for value in (item.source, item.destination, item.target)
    )
    checks = (
        DependencyCheck("firewall_rules", complete=True, references_found=rule_reference),
        DependencyCheck("nat_port_forwards", complete=True, references_found=nat_reference),
    )
    if any(check.references_found for check in checks):
        raise LabSafetyError("Automatic dependency check found a candidate reference")
    return checks


def run_read_only_preflight(
    config: LabConfig,
    *,
    client: LabReadClient,
    attestation: LabAttestation,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> LabPreflightReport:
    """Run only authoritative GET operations; never constructs a WRITE client."""

    if attestation.lab_identity != config.identity or attestation.candidate != config.candidate:
        raise LabSafetyError("Attestation no longer matches the configured lab target")
    if attestation.expires_at <= now():
        raise LabSafetyError("Lab attestation expired before automatic checks began")
    try:
        aliases = client.get_firewall_aliases(include_identifying_metadata=True, limit=500)
    except Exception:
        raise LabSafetyError("Candidate alias query failed") from None
    alias = _resolve_candidate(aliases, config.candidate)
    checks = _check_dependencies(client, config.candidate)
    if attestation.expires_at <= now():
        raise LabSafetyError("Lab attestation expired during automatic checks")
    summary = CandidateSummary(
        name=alias.name,
        numeric_locator=alias.id,
        alias_type=alias.type,
        description=alias.descr,
        member_count=len(alias.address or ()),
        detail_count=len(alias.detail or ()),
    )
    return LabPreflightReport(
        lab_identity=config.identity,
        candidate=summary,
        dependency_checks=checks,
        uncovered_surfaces=tuple(sorted(_REQUIRED_SURFACES - {"firewall_policy", "nat"})),
        attestation_expires_at=attestation.expires_at,
    )


def render_evidence(event: str, report: LabPreflightReport) -> str:
    """Return deterministic, value-minimized JSON suitable for evidence capture."""

    return json.dumps({"event": event, **report.sanitized_dict()}, sort_keys=True, separators=(",", ":"))


def render_dry_run(report: LabPreflightReport, *, test_case_id: str = "not-specified") -> str:
    value = report.sanitized_dict()
    value["operation"] = {
        "mode": "READ_ONLY_DRY_RUN",
        "semantic_unit": "set_firewall_alias_description_v1",
        "method": "PATCH",
        "endpoint_symbol": "FIREWALL_ALIAS_DESCRIPTION",
        "test_case_id": test_case_id,
        "sent": False,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
