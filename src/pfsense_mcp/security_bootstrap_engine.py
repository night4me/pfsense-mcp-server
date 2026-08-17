"""BootstrapEngine — `ADR-033` implementation Phase C. The orchestration
layer that composes Phase B's pure primitives
(`security_privileges.py`'s derivation, `security_bootstrap_transaction.py`'s
state machine) with Phase C's own narrow HTTP surface
(`security_bootstrap_client.py`) into a single, deterministic,
read-before-write provisioning sequence for one dedicated pfSense
service account.

**Authorized for production provisioning code. Not authorized, and not
capable, of live provisioning in this build** -- nothing in this
module is imported by `security_cli.py`, `security_doctor.py`, or
`application.py` (`tests/test_security_bootstrap_engine_isolation.py`
proves this mechanically), so the only way to invoke
`provision_service_account()` is to import this module directly and
supply real `Transport` instances -- something only a test, or a
future, separately-authorized CLI phase, does.

## What this module will never do

- Take an arbitrary existing administrator/operator account and
  rewrite its privileges. `provision_service_account()`'s `username`
  names the *one* dedicated account being provisioned; every other
  account `list_users()` observes is inspected only to confirm it is
  not the one being touched.
- Grant a broader privilege set than `security_privileges.py` itself
  derives. `target_profile` selects which derived set
  (`read_profile_requirements()`/`write_protected_profile_requirements()`)
  to grant -- never a hard-coded list, never `page-all`.
- Remove any privilege from an existing account except the one named,
  transaction-tracked case (`BOOTSTRAP_ONLY_PRIVILEGE`, revoked by the
  same run that granted it). A "sync" against an existing
  under-provisioned account only ever *adds* the missing privileges;
  any additional, unrelated privilege already present is left alone.
- Attempt an automatic compensating mutation after a failure (e.g.
  auto-revoking the bootstrap privilege if key generation fails). Per
  `ADR-033` §"Rollback/recovery", failure always leaves the partial
  state in place and reports it precisely via the returned
  `BootstrapTransaction.failure_detail` -- a future operator-driven
  remediation path is a separate, later decision.
- Persist, log, or embed the generated account password or API key in
  any `ProvisioningResult` field, log line, or exception message. The
  password lives only in a local variable for the duration of one call
  and is explicitly `del`eted afterward; the API key is returned only
  as a `ProvisionedApiKey` (`security_bootstrap_client.py`), whose raw
  value is reachable only via its explicit `reveal()` method.

## Stricter-than-`doctor` derivation gate

`security_privileges.py`'s `DriftReport.clean` treats
`UNVERIFIED_PACKAGE_VERSION` as advisory (a "re-confirm before relying
on this" flag, not proof of mismatch) -- correct for a read-only
`doctor` report. This module deliberately applies a **stricter** gate
before any mutation: an unresolved package-version check, a missing
schema, or any per-privilege resolution that is not `SOURCE_CROSS_
CHECKED` fails the whole provisioning attempt closed
(`ProvisioningOutcome.DERIVATION_FAILED`) before any HTTP call is made.
A mutating operation earns a higher evidence bar than an advisory
report; this is an intentional divergence from `doctor`'s posture, not
an inconsistency with it.

## Self-service authentication is caller-supplied

`POST /api/v2/auth/key` must be called authenticated as the *new*
account itself (HTTP Basic Auth, `security_bootstrap_client.py`'s own
docstring). This codebase does not yet have a Basic-Auth-capable
`Transport` implementation (`transport/http.py`'s `HttpTransport` is
`X-API-Key`-only) -- building one is out of this phase's scope (no
live provisioning is authorized here at all). `provision_service_
account()` therefore takes a caller-supplied
`self_service_transport_factory(username, password) -> Transport`
rather than constructing one itself; every test in this repository
supplies a factory that returns a `MockTransport`. A future,
separately-authorized live-validation phase must supply a real
implementation of this factory.

No `pfsense_mcp.tier1` import in any form -- pfSense privilege
provisioning and Tier 1's cryptographic mutation-authorization chain
remain independent layers (`ADR-033` §7).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .api_version import ApiVersion
from .errors import BootstrapProvisioningError
from .security_bootstrap_client import (
    BootstrapProvisioningClient,
    ObservedUser,
    ProvisionedApiKey,
)
from .security_bootstrap_transaction import (
    BOOTSTRAP_ONLY_PRIVILEGE,
    BootstrapState,
    BootstrapTransaction,
    InvariantViolation,
)
from .security_privileges import (
    VERIFIED_PACKAGE_VERSION_MAX,
    VERIFIED_PACKAGE_VERSION_MIN,
    DriftFindingKind,
    DriftReport,
    EvidenceClass,
    ToolPrivilegeRequirement,
    check_package_version_support,
    compute_account_drift,
    distinct_ok_privileges,
    read_profile_requirements,
    resolve_profile_privileges,
    write_protected_profile_requirements,
)
from .transport.base import Transport

_DEFAULT_KEY_DESCR = "pfsense-mcp-server provisioned key"
_DEFAULT_USER_DESCR = "pfsense-mcp-server dedicated least-privilege service account"
_PASSWORD_ENTROPY_BYTES = 32


class TargetProfile(str, Enum):
    READ_ONLY = "read_only"
    WRITE_PROTECTED = "write_protected"


class ProvisioningOutcome(str, Enum):
    #: Existing account's privileges already equal the derived target
    #: set exactly -- no mutation performed.
    ALREADY_SATISFIED = "already_satisfied"
    #: Existing account holds every required privilege plus at least
    #: one unrelated extra -- functionally satisfied; the extra is
    #: reported, never auto-removed, and no mutation is performed.
    ALREADY_SATISFIED_WITH_EXTRA_PRIVILEGES = "already_satisfied_with_extra_privileges"
    #: Existing account was missing one or more required privileges;
    #: exactly the missing ones were added, unrelated ones preserved.
    PRIVILEGES_SYNCED = "privileges_synced"
    #: A brand-new account was created and the full bootstrap
    #: transaction reached BootstrapState.VERIFIED.
    COMPLETED = "completed"
    #: An existing account already holds BOOTSTRAP_ONLY_PRIVILEGE --
    #: evidence of an interrupted prior run. No mutation performed;
    #: requires human review before any future attempt.
    BLOCKED_EXISTING_PARTIAL = "blocked_existing_partial"
    #: The privilege derivation gate itself failed (missing schema,
    #: schema/source disagreement, ambiguous evidence, or an
    #: unsupported package version) -- refused before any HTTP call.
    DERIVATION_FAILED = "derivation_failed"
    #: A step in the transaction sequence failed. See `transaction.
    #: failure_detail` for exactly which step and why.
    FAILED = "failed"


@dataclass(frozen=True)
class ProvisioningResult:
    outcome: ProvisioningOutcome
    detail: str
    #: Populated only for the BootstrapState-tracked create path
    #: (COMPLETED or a FAILED that occurred inside that path).
    transaction: BootstrapTransaction | None = None
    #: Populated only when outcome is COMPLETED.
    api_key: ProvisionedApiKey | None = None
    #: Populated whenever an existing account was observed.
    drift_before: DriftReport | None = None
    #: Populated only for the PRIVILEGES_SYNCED path's post-sync re-read.
    drift_after: DriftReport | None = None


def _expected_requirements(target_profile: TargetProfile) -> tuple[ToolPrivilegeRequirement, ...]:
    if target_profile is TargetProfile.READ_ONLY:
        return read_profile_requirements()
    return write_protected_profile_requirements()


def _derive_expected_privileges(
    schema: dict[str, Any] | None, target_profile: TargetProfile
) -> tuple[frozenset[str] | None, str | None]:
    """Returns `(expected, None)` on success or `(None, error)` on any
    derivation failure. Requires every resolved privilege to be
    `SOURCE_CROSS_CHECKED` -- stricter than `DriftReport.clean` (see
    module docstring)."""

    if schema is None:
        return None, "no live OpenAPI schema supplied; provisioning requires source-cross-checked evidence"

    requirements = _expected_requirements(target_profile)
    resolved = resolve_profile_privileges(schema, requirements)

    if not resolved:
        return None, "privilege derivation produced zero resolvable requirements"

    problems = [
        (r.url, r.method, r.error)
        for r in resolved
        if not r.ok or r.evidence_class is not EvidenceClass.SOURCE_CROSS_CHECKED
    ]
    if problems:
        details = "; ".join(
            f"{method} {url}: {error or 'missing source-cross-checked evidence'}" for url, method, error in problems
        )
        return None, f"privilege derivation lacks source-cross-checked confidence for every requirement: {details}"

    expected = distinct_ok_privileges(resolved)
    if not expected:
        return None, "privilege derivation resolved to an empty privilege set"

    return expected, None


def _check_package_version(installed_package_version: tuple[int, int, int] | None) -> str | None:
    """Returns an error string if `installed_package_version` is known
    and outside the verified range -- `None` if it is within range or
    not supplied. Unlike `DriftReport.clean`, an out-of-range version
    here refuses provisioning outright (module docstring)."""

    if installed_package_version is None:
        return None
    finding = check_package_version_support(installed_package_version)
    if finding is None:
        return None
    return (
        f"installed pfSense-pkg-RESTAPI version {'.'.join(map(str, installed_package_version))} is outside "
        f"the verified range {'.'.join(map(str, VERIFIED_PACKAGE_VERSION_MIN))}-"
        f"{'.'.join(map(str, VERIFIED_PACKAGE_VERSION_MAX))}; refusing to provision"
    )


def _find_user(users: tuple[ObservedUser, ...], username: str) -> ObservedUser | None:
    for user in users:
        if user.name == username:
            return user
    return None


def _sanitize_client_error(exc: BootstrapProvisioningError) -> str:
    """`BootstrapProvisioningError`'s own message is already sanitized
    (`security_bootstrap_client.py`'s `_check_response()`/parse helpers
    never embed a payload or response body) -- this exists as a single,
    explicit place a future change to that guarantee would have to
    also update, rather than trusting the invariant silently."""

    return str(exc)


def _failed_result(transaction: BootstrapTransaction) -> ProvisioningResult:
    """Every failed-transaction step returns through this one helper --
    keeps the (outcome, detail, transaction) triple consistent across
    every checkpoint in `_provision_new_account()` rather than
    repeating it at each of the ten call sites."""

    return ProvisioningResult(ProvisioningOutcome.FAILED, transaction.failure_detail or "", transaction=transaction)


def provision_service_account(
    *,
    admin_transport: Transport,
    self_service_transport_factory: Callable[[str, str], Transport],
    api_version: ApiVersion,
    username: str,
    target_profile: TargetProfile,
    schema: dict[str, Any] | None,
    installed_package_version: tuple[int, int, int] | None = None,
    user_descr: str = _DEFAULT_USER_DESCR,
    key_descr: str = _DEFAULT_KEY_DESCR,
    password_factory: Callable[[], str] | None = None,
) -> ProvisioningResult:
    """Provisions (or verifies/repairs) exactly one dedicated pfSense
    service account named `username`, granting exactly `target_profile`'s
    derived privilege set. Deterministic, read-before-write throughout;
    see the module docstring for what this function will never do."""

    version_error = _check_package_version(installed_package_version)
    if version_error is not None:
        return ProvisioningResult(ProvisioningOutcome.DERIVATION_FAILED, version_error)

    expected, derivation_error = _derive_expected_privileges(schema, target_profile)
    if expected is None:
        return ProvisioningResult(
            ProvisioningOutcome.DERIVATION_FAILED, derivation_error or "privilege derivation failed"
        )

    admin_client = BootstrapProvisioningClient(admin_transport, api_version=api_version)

    try:
        existing_users = admin_client.list_users()
    except BootstrapProvisioningError as exc:
        return ProvisioningResult(
            ProvisioningOutcome.FAILED, f"pre-flight observation failed: {_sanitize_client_error(exc)}"
        )

    existing = _find_user(existing_users, username)

    if existing is not None:
        return _provision_against_existing_account(admin_client, existing, expected)

    return _provision_new_account(
        admin_client,
        self_service_transport_factory,
        api_version=api_version,
        username=username,
        expected=expected,
        user_descr=user_descr,
        key_descr=key_descr,
        password_factory=password_factory or (lambda: secrets.token_urlsafe(_PASSWORD_ENTROPY_BYTES)),
    )


def _provision_against_existing_account(
    admin_client: BootstrapProvisioningClient, existing: ObservedUser, expected: frozenset[str]
) -> ProvisioningResult:
    if BOOTSTRAP_ONLY_PRIVILEGE in existing.priv:
        return ProvisioningResult(
            ProvisioningOutcome.BLOCKED_EXISTING_PARTIAL,
            f"existing account {existing.name!r} already holds the temporary bootstrap privilege "
            f"{BOOTSTRAP_ONLY_PRIVILEGE!r} -- a prior bootstrap run may have been interrupted; "
            "human review is required before any further provisioning attempt. No mutation performed.",
        )

    drift_before = compute_account_drift(expected, existing.priv)
    if drift_before.clean:
        return ProvisioningResult(
            ProvisioningOutcome.ALREADY_SATISFIED,
            f"existing account {existing.name!r} already holds exactly the expected privilege set. "
            "No mutation performed.",
            drift_before=drift_before,
        )

    missing = {
        f.privilege for f in drift_before.findings if f.kind is DriftFindingKind.PRIVILEGE_MISSING and f.privilege
    }

    if not missing:
        return ProvisioningResult(
            ProvisioningOutcome.ALREADY_SATISFIED_WITH_EXTRA_PRIVILEGES,
            f"existing account {existing.name!r} already holds every expected privilege, plus at least one "
            "unrelated additional privilege. The additional privilege is preserved, never auto-removed. "
            "No mutation performed.",
            drift_before=drift_before,
        )

    new_priv = existing.priv | missing
    try:
        admin_client.update_user_privileges(user_id=existing.id, priv=new_priv)
    except BootstrapProvisioningError as exc:
        return ProvisioningResult(
            ProvisioningOutcome.FAILED,
            f"privilege sync for existing account {existing.name!r} failed: {_sanitize_client_error(exc)}",
            drift_before=drift_before,
        )

    try:
        refreshed_users = admin_client.list_users()
    except BootstrapProvisioningError as exc:
        return ProvisioningResult(
            ProvisioningOutcome.FAILED,
            f"post-sync verification read for {existing.name!r} failed: {_sanitize_client_error(exc)}",
            drift_before=drift_before,
        )

    refreshed = _find_user(refreshed_users, existing.name)
    if refreshed is None:
        return ProvisioningResult(
            ProvisioningOutcome.FAILED,
            f"post-sync verification failed: account {existing.name!r} no longer found",
            drift_before=drift_before,
        )

    drift_after = compute_account_drift(expected, refreshed.priv)
    still_missing = any(f.kind is DriftFindingKind.PRIVILEGE_MISSING for f in drift_after.findings)
    if still_missing:
        return ProvisioningResult(
            ProvisioningOutcome.FAILED,
            f"post-sync verification failed: account {existing.name!r} is still missing one or more "
            "expected privileges after the PATCH",
            drift_before=drift_before,
            drift_after=drift_after,
        )

    return ProvisioningResult(
        ProvisioningOutcome.PRIVILEGES_SYNCED,
        f"missing privileges added to existing account {existing.name!r}; unrelated privileges preserved.",
        drift_before=drift_before,
        drift_after=drift_after,
    )


def _provision_new_account(
    admin_client: BootstrapProvisioningClient,
    self_service_transport_factory: Callable[[str, str], Transport],
    *,
    api_version: ApiVersion,
    username: str,
    expected: frozenset[str],
    user_descr: str,
    key_descr: str,
    password_factory: Callable[[], str],
) -> ProvisioningResult:
    transaction = BootstrapTransaction(state=BootstrapState.NOT_STARTED, privileges=frozenset())
    password = password_factory()

    try:
        try:
            created = admin_client.create_user(name=username, password=password, descr=user_descr, priv=expected)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(f"account creation failed: {_sanitize_client_error(exc)}")
            return _failed_result(transaction)

        verified = _reread_and_check(admin_client, username, expected)
        if verified is None:
            transaction = transaction.fail(
                "post-creation verification failed: created account's privileges do not match the requested set"
            )
            return _failed_result(transaction)

        try:
            transaction = transaction.transition(BootstrapState.USER_CREATED, privileges=expected)
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after account creation: {exc}")
            return _failed_result(transaction)

        granted_priv = expected | {BOOTSTRAP_ONLY_PRIVILEGE}
        try:
            admin_client.update_user_privileges(user_id=created.id, priv=granted_priv)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(f"bootstrap-privilege grant failed: {_sanitize_client_error(exc)}")
            return _failed_result(transaction)

        verified = _reread_and_check(admin_client, username, granted_priv)
        if verified is None:
            transaction = transaction.fail(
                "post-grant verification failed: account does not hold exactly the expected privileges plus the "
                "temporary bootstrap privilege"
            )
            return _failed_result(transaction)

        try:
            transaction = transaction.transition(BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=granted_priv)
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after bootstrap-privilege grant: {exc}")
            return _failed_result(transaction)

        try:
            self_transport = self_service_transport_factory(username, password)
            self_client = BootstrapProvisioningClient(self_transport, api_version=api_version)
            api_key = self_client.create_auth_key(descr=key_descr)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(
                f"API-key creation failed: {_sanitize_client_error(exc)}. The account currently holds the "
                f"temporary bootstrap privilege {BOOTSTRAP_ONLY_PRIVILEGE!r} -- this was NOT automatically "
                "revoked and requires manual/operator-reviewed remediation."
            )
            return _failed_result(transaction)

        try:
            transaction = transaction.transition(BootstrapState.KEY_GENERATED, privileges=granted_priv)
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after key generation: {exc}")
            return _failed_result(transaction)

        try:
            admin_client.update_user_privileges(user_id=created.id, priv=expected)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(
                f"bootstrap-privilege revocation failed: {_sanitize_client_error(exc)}. The account currently "
                f"holds the temporary bootstrap privilege {BOOTSTRAP_ONLY_PRIVILEGE!r} -- this requires "
                "manual/operator-reviewed remediation. A usable API key was already generated for this account."
            )
            return _failed_result(transaction)

        verified = _reread_and_check(admin_client, username, expected)
        if verified is None:
            transaction = transaction.fail(
                "post-revocation verification failed: cannot confirm the temporary bootstrap privilege was "
                "actually removed -- treat as still present until manually confirmed"
            )
            return _failed_result(transaction)

        try:
            transaction = transaction.transition(BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED, privileges=expected)
            transaction = transaction.transition(BootstrapState.VERIFIED, privileges=expected)
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after revocation verification: {exc}")
            return _failed_result(transaction)

        return ProvisioningResult(
            ProvisioningOutcome.COMPLETED,
            f"account {username!r} provisioned successfully with the {len(expected)}-privilege target set.",
            transaction=transaction,
            api_key=api_key,
        )
    finally:
        del password


def _reread_and_check(
    admin_client: BootstrapProvisioningClient, username: str, expected_priv: frozenset[str]
) -> ObservedUser | None:
    """Independent re-read + exact-match check -- never trusts a
    mutating call's own response echo alone (`ADR-033`'s own stated
    discipline). Returns the re-read `ObservedUser` on an exact match,
    `None` otherwise (including on a read failure)."""

    try:
        users = admin_client.list_users()
    except BootstrapProvisioningError:
        return None
    user = _find_user(users, username)
    if user is None or user.priv != expected_priv:
        return None
    return user
