"""ADR-022 Phase C: `PlanAuthorization`/`DeprovisionAuthorization` data
models, canonical signing payloads, and signature *construction* only.

**This module produces no runtime effect.** It does NOT verify a
signature, accept/consume/replay-track an authorization, enforce
freshness, execute anything, provision anything, create a
`RecoveryContract`, populate `WriteEndpoints`, or activate any WRITE
capability -- none of those exist anywhere in this repository yet, and
this module does not build any of them. See `docs/adr/
ADR-022-execution-authorization-boundary.md`'s Decision item 4
("`PlanAuthorization` -- the authorization artifact") and "Destructive
operations" sections for the accepted design this module implements, and
`docs/adr/ADR-022-execution-authorization-boundary.md`'s "Future
implementation phases" for Phase C's exact, deliberately narrow scope
("`PlanAuthorization`/`DeprovisionAuthorization` dataclasses,
canonicalization, and signature construction ... still produces no
runtime effect").

**Signing happens only on the signing/operator side.** Every function
here that touches an `Ed25519PrivateKey` (`sign_plan_authorization()`,
`sign_deprovision_authorization()`) is a pure function over caller-
supplied key material -- it never loads a key from disk, environment, or
any other source, and this module is never imported by
`security_cli.py`, any MCP tool, or any other MCP-server request-handling
code path (proved by `tests/test_security_authorization_isolation.py`).
Mirrors `ADR-012`'s "private key custody lives entirely outside the MCP
server's host/process" precedent exactly: this repository has never
implemented a signing key custody/loading workflow (see
`confirmation_providers.py`/`docs/tier1/specs/confirmation_authority.md`,
whose own signing-side tool remains "a genuinely unbuilt, separate
deliverable" per `ADR-012`'s Acceptance note) and this module does not
change that -- it gives a future, separate signing tool a precise,
reviewed function to call, nothing more. No CLI subcommand is added by
this module; see "CLI boundary" below for why.

**A `PlanAuthorization`/`DeprovisionAuthorization` is a signed data
artifact, never a bearer capability.** Persisting or possessing one
proves nothing about whether it is still fresh, unexpired, or unconsumed
-- ADR-022's "Persisted authorization is never a bearer capability"
subsection requires every future *use* to independently re-check all
four of: exact `plan_digest` match against a freshly recomputed digest,
non-expiry, non-replay, and a freshness re-check against current
evidence. None of those four checks exist in this module, on purpose --
there is no consumer, verifier, or executor here at all, and neither
dataclass exposes any method resembling `.execute()`, `.apply()`, or
`.is_authorized_for_runtime()`. Structural validation (are the fields
well-formed) is the only thing either dataclass's `__post_init__` ever
checks; it is never a runtime-authorization-validity judgment.

## Signed-payload fields vs. metadata (self-review categories A/B/C)

(A) **Signed-payload fields** -- every `PlanAuthorization` field except
`proof` participates in `plan_authorization_signing_payload()`, and every
`DeprovisionAuthorization` field except `proof` participates in
`deprovision_authorization_signing_payload()`. There is no field on
either artifact that is excluded from its own signature -- unlike
`security_plan_digest.py`'s `PlanDigest` (which deliberately excludes
several `SecurityPosturePlan`/`PlanStep` fields as non-security-relevant
prose), every field an operator sets on an authorization artifact is
itself part of what they are attesting to, so none is excluded here.
(B) **Non-participating metadata** -- none exists on either dataclass;
see (A).
(C) **Derived/display-only info** -- none exists on either dataclass;
no `__str__`/property is added that could be mistaken for authorization
status. (`risk_class` is *derived* from the authorized `PlanStep`s at
*construction* time by `build_plan_authorization_payload()`, but once
constructed it is a first-class signed field like any other, not a
display-only convenience -- see "risk_class" below.)

## `PlanAuthorization` -- exact schema (version 1)

| Field | Type | Participates in signature |
|---|---|---|
| `schema_version` | `int` | yes |
| `authorization_id` | `str` (safe token) | yes |
| `plan_digest` | `str` (64 lowercase hex) | yes |
| `authorized_step_ids` | `tuple[str, ...]`, non-empty, no dupes | yes (sorted -- see "Step-set canonicalization") |
| `authority_id` | `str` (safe token) | yes |
| `algorithm` | `str`, must equal `AUTHORIZATION_SIGNING_ALGORITHM` | yes |
| `proof` | `bytes`, exactly 64 bytes (Ed25519 signature) | **no** -- see "Signature never signs itself" |
| `issued_at` | `datetime`, UTC | yes (ISO 8601) |
| `expires_at` | `datetime`, UTC, strictly after `issued_at` | yes (ISO 8601) |
| `risk_class` | `security_plan.AuthorizationLevel` | yes |
| `evidence_fingerprint` | `AuthorizationEvidenceFingerprint` (6 sub-fields) | yes (nested payload) |

`risk_class` is typed `AuthorizationLevel`, not `SecurityImpact`, even
though ADR-022's own field-table prose names both
("the highest `SecurityImpact`/`AuthorizationLevel` among the authorized
steps"): `AuthorizationLevel` is the field the ADR's own
"risk-dependent granularity" table keys its recommended default
granularity/lifetime on, and is the field whose values this design's
threat-model row ("Privilege escalation via risk-class confusion") names
directly ("a `CONFIGURATION_CHANGE`-scoped grant cannot satisfy an
`INTERACTIVE_HARDWARE_CONFIRMATION`-class step's binding check").
`SecurityImpact` (`INCREASES_ASSURANCE`/`DECREASES_ASSURANCE`/
`ENABLES_MUTATION_CAPABILITY`/`DISABLES_MUTATION_CAPABILITY`) has no
total ordering to take a "highest" of -- it names four different *kinds*
of effect, not four degrees of one. `AuthorizationLevel` is the only one
of the two with a defensible linear friction ordering.

## `authorized_step_ids` -- never a wildcard, never inferred

`build_plan_authorization_payload()` requires an explicit, non-empty,
duplicate-free sequence of step IDs and looks each one up in the
supplied `SecurityPosturePlan.steps` -- an unknown step ID is refused at
construction (there is no later point where this module still has plan
context to check it), never silently dropped or ignored. A step whose
`authorization_required` is `AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION`
or `UNDETERMINED_NOT_IMPLEMENTED` is refused too, defense-in-depth,
even though `security_plan.py` never emits either today (ADR-022's
"Destructive-operation smuggling via a batched `CONFIGURATION_CHANGE`
authorization" threat-model row).

### Step-set canonicalization (reordering does not change identity)

`plan_authorization_signing_payload()` signs `sorted(authorized_step_ids)`,
not the caller-supplied order. ADR-022 never assigns independent
security meaning to the *order* an operator happens to list step IDs in
when authorizing several at once -- ordering *within a plan* is already
fully captured by each `PlanStep.order`, which is itself bound into
`plan_digest` (`security_plan_digest.py`). Two authorizations naming the
same step-id set in a different presentation order are therefore
identical artifacts, not two different ones; the dataclass field itself
retains the caller-supplied order for display/audit purposes, since that
does not affect the signed identity either way.

## `DeprovisionAuthorization` -- exact schema (version 1)

Deliberately a **wholly separate artifact type** (own schema version,
own `DigestPurpose.DEPROVISION_AUTHORIZATION` domain, own field set) --
never `PlanAuthorization(destructive=True)` or any boolean-flag
equivalent, per ADR-022's "Destructive operations" section, which
rejects a flag-based design explicitly ("a flag can be forgotten... a
separate type cannot be reached by any code path that only knows how to
construct the routine one").

| Field | Type | Participates in signature |
|---|---|---|
| `schema_version` | `int` | yes |
| `authorization_id` | `str` (safe token) | yes |
| `target_identity_digest` | `str` (64 lowercase hex) | yes |
| `authority_id` | `str` (safe token) | yes |
| `algorithm` | `str`, must equal `AUTHORIZATION_SIGNING_ALGORITHM` | yes |
| `proof` | `bytes`, exactly 64 bytes | **no** |
| `issued_at` | `datetime`, UTC | yes |
| `expires_at` | `datetime`, UTC, strictly after `issued_at` | yes |

Has no `plan_digest`, `authorized_step_ids`, `risk_class`, or
`evidence_fingerprint` field at all -- those are `SecurityPosturePlan`
concepts, and `DESTRUCTIVE_DEPROVISIONING` is explicitly outside the
routine per-axis plan lifecycle (ADR-021 question 4; ADR-022's "Scope"
table). `target_identity_digest` is accepted as an already-computed,
caller-supplied 64-hex-character digest -- this module does not define
*how* to compute one for a real TPM NV index or store key, because
ADR-022 explicitly defers that design ("this is deliberately left as a
future, separate, explicitly-scoped ADR ... consistent with this
project's standing practice of drafting exact authorization wording only
when real and imminent"). Consequently **no code path anywhere in this
repository computes a real `target_identity_digest` for an actual
destructive target** -- only tests, using a synthetic one, ever
construct a `DeprovisionAuthorization` -- exactly ADR-022's own
"no code path in this design ever constructs a `DeprovisionAuthorization`,
because no destructive execution mechanism is designed at all yet."

## Domain separation

Both signing payloads include an explicit `"digest_purpose"` field
(`DigestPurpose.PLAN_AUTHORIZATION.value` /
`DigestPurpose.DEPROVISION_AUTHORIZATION.value`, `tier1/canonical.py`,
Phase C additions) as a literal, signed part of the canonical payload --
not merely an accidental field-shape difference between the two payload
shapes. A signature produced over a `PlanAuthorization` payload can
therefore never verify against a `DeprovisionAuthorization` payload, a
`ConfirmationEvidence`/`ReconciliationEvidence` payload (`DigestPurpose.
CONFIRMATION`/`RECONCILIATION`, distinct values, `tier1/confirmation.py`/
`reconciliation.py`, unmodified), or vice versa, even under a
hypothetical future field-shape collision. `PLAN_AUTHORIZATION` is
additionally distinct from `PLAN` (`security_plan_digest.py`'s own
`DigestPurpose`) even though `PlanAuthorization.plan_digest` embeds a
`PLAN`-purpose digest value as one of its own fields -- the outer
signature's domain is always `PLAN_AUTHORIZATION`, never `PLAN`.

## Signature never signs itself

Neither dataclass's `proof` field is ever included in the payload that
produces it: `sign_plan_authorization()`/`sign_deprovision_authorization()`
build the signing payload from a `*Payload` value that has no `proof`
field at all (it does not exist yet -- signing is what produces it), then
construct the final dataclass afterward. There is no code path where
`proof` could accidentally participate in its own pre-image.

## Expiry -- mechanism only, no invented numbers

ADR-022's owner review (2026-08-11, question 3) accepted the expiry
*mechanism* while leaving concrete numeric durations explicitly
provisional, mirroring `ADR-015`'s own "Accepted (mechanism); numeric
defaults remain provisional pending disposable-lab evidence" framing.
Neither `build_plan_authorization_payload()` nor
`build_deprovision_authorization_payload()` supplies a default duration
or a default `expires_at` -- both are mandatory, explicit, caller-
supplied UTC datetimes, exactly like `RecoveryContract.expires_at`/
`ConfirmationEvidence.expires_at` already are. This module invents no
production timeout value; test fixtures that pick a duration are test-
only, never read by this module as a default.

## CLI boundary -- deliberately no CLI subcommand

`pfsense-mcp-security` gains no new subcommand from this module. A
signing CLI would need to resolve real key-management/UX questions this
phase's own instructions explicitly forbid inventing (how the operator's
private key is stored/loaded, how a plan JSON is supplied, how the
resulting artifact is delivered back) -- none of which ADR-022 or
existing project precedent resolves today (`docs/tier1/specs/
confirmation_authority.md`'s own "separate, reviewed signing-side
workflow/tool" remains an explicit, un-built, future activation
requirement, not something this phase should improvise). This module is
therefore library/data-model code only: a future, separately-scoped
signing tool (inside or outside this repository, per that future
decision) is expected to import and call `build_plan_authorization_payload()`/
`sign_plan_authorization()` (or their `deprovision_*` equivalents)
directly, exactly the way `confirmation_providers.signing_payload()`
already gives a well-defined target for a signing workflow without this
repository including the workflow itself. No MCP tool is added either --
`AuthorizationRequest`-shaped MCP exposure is explicitly out of Phase C's
scope (ADR-022 "Future implementation phases", Phase C's own description).

## Isolation

Fourth, narrow, explicit exception (alongside `tier1_anchor_check.py`,
`security_discovery.py`, `security_plan_digest.py`) to `pfsense_mcp.tier1`
never being imported from outside its own package. The only two names
imported from `pfsense_mcp.tier1` here are `canonical.DigestPurpose` and
`canonical.canonical_json` -- pure, stateless canonicalization with zero
I/O, zero SQLite, zero TPM/store access. `tests/tier1/test_isolation.py`'s
exemption list and `tests/test_security_authorization_isolation.py`
(AST-based, mirroring `test_security_plan_digest_isolation.py`) both
prove this.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .security_plan import AuthorizationLevel, SecurityPosturePlan
from .security_plan_digest import compute_plan_digest, evidence_fingerprint_payload
from .tier1.canonical import CanonicalValue, DigestPurpose, canonical_json

__all__ = [
    "AUTHORIZATION_SIGNING_ALGORITHM",
    "DEPROVISION_AUTHORIZATION_SCHEMA_VERSION",
    "PLAN_AUTHORIZATION_SCHEMA_VERSION",
    "AuthorizationEvidenceFingerprint",
    "DeprovisionAuthorization",
    "DeprovisionAuthorizationPayload",
    "PlanAuthorization",
    "PlanAuthorizationPayload",
    "SecurityAuthorizationError",
    "build_deprovision_authorization_payload",
    "build_plan_authorization_payload",
    "deprovision_authorization_signing_payload",
    "plan_authorization_signing_payload",
    "sign_deprovision_authorization",
    "sign_plan_authorization",
]

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_ED25519_SIGNATURE_BYTES = 64

#: Bumped whenever a signed field is added, removed, or reinterpreted for
#: `PlanAuthorization` -- independent of `DEPROVISION_AUTHORIZATION_SCHEMA_VERSION`
#: below, since the two are separate artifact types with separate schemas.
PLAN_AUTHORIZATION_SCHEMA_VERSION = 1

#: Independent schema-version namespace for `DeprovisionAuthorization` --
#: never incremented merely because `PlanAuthorization`'s schema changes,
#: and vice versa; the two artifact types evolve independently.
DEPROVISION_AUTHORIZATION_SCHEMA_VERSION = 1

#: The only signing algorithm identifier either artifact type accepts.
#: Matches `confirmation_providers.ACCEPTED_ALGORITHM`'s value exactly
#: (same underlying primitive, Ed25519) -- domain separation between
#: confirmation/reconciliation/plan-authorization/deprovision-authorization
#: signatures comes from the `"digest_purpose"` field inside each signing
#: payload (see module docstring "Domain separation"), not from using a
#: different algorithm string per domain.
AUTHORIZATION_SIGNING_ALGORITHM = "ed25519-v1"

#: `AuthorizationLevel` values a `PlanAuthorization` can legally cover,
#: ranked low-to-high friction, exactly ADR-022's "risk-dependent
#: granularity" table ordering. `SEPARATE_DEPROVISION_AUTHORIZATION` and
#: `UNDETERMINED_NOT_IMPLEMENTED` are deliberately absent -- see
#: `_NEVER_PLAN_AUTHORIZATION_LEVELS`.
_AUTHORIZATION_LEVEL_RANK: dict[AuthorizationLevel, int] = {
    AuthorizationLevel.NONE_REQUIRED: 0,
    AuthorizationLevel.CONFIGURATION_CHANGE: 1,
    AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION: 2,
    AuthorizationLevel.MILESTONE_9_ACTIVATION_DECISION: 3,
}

#: A step requiring either of these can never be covered by a
#: `PlanAuthorization`: `SEPARATE_DEPROVISION_AUTHORIZATION` names the
#: wholly separate `DeprovisionAuthorization` path; `UNDETERMINED_NOT_IMPLEMENTED`
#: has no defined friction level to rank at all. `security_plan.py` never
#: emits either today, but `build_plan_authorization_payload()` refuses
#: them anyway, defense-in-depth (ADR-022's "Destructive-operation
#: smuggling" threat-model row).
_NEVER_PLAN_AUTHORIZATION_LEVELS = frozenset(
    {AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION, AuthorizationLevel.UNDETERMINED_NOT_IMPLEMENTED}
)


class SecurityAuthorizationError(Exception):
    """A `PlanAuthorization`/`DeprovisionAuthorization` value, or an
    attempt to build one, is structurally invalid. Never raised for a
    runtime-authorization-validity judgment (expired, consumed, stale) --
    no such judgment is made anywhere in this module."""


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)


@dataclass(frozen=True)
class AuthorizationEvidenceFingerprint:
    """Immutable copy of `security_plan_digest.evidence_fingerprint_payload()`'s
    six fields (ADR-022 Decision item 4, `PlanAuthorization.evidence_fingerprint`:
    "lets a verifier re-validate freshness without needing to still hold
    the original `Plan` object"). Constructed only via `from_plan()`,
    which is the sole place these six values are read from a
    `SecurityPosturePlan` -- never re-derived a second way elsewhere in
    this module."""

    capability_posture_value: str
    anchor_assurance_value: str
    anchor_evidence_state: str
    anchor_baseline: int | None
    anchor_witness_value: int | None
    anchor_provisioned_at: str | None

    def __post_init__(self) -> None:
        required = (self.capability_posture_value, self.anchor_assurance_value, self.anchor_evidence_state)
        if not all(isinstance(value, str) and value for value in required):
            raise SecurityAuthorizationError("Authorization evidence fingerprint is invalid.")
        for value in (self.anchor_baseline, self.anchor_witness_value):
            if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                raise SecurityAuthorizationError("Authorization evidence fingerprint is invalid.")
        if self.anchor_provisioned_at is not None and not isinstance(self.anchor_provisioned_at, str):
            raise SecurityAuthorizationError("Authorization evidence fingerprint is invalid.")

    def to_payload(self) -> dict[str, CanonicalValue]:
        return {
            "capability_posture_value": self.capability_posture_value,
            "anchor_assurance_value": self.anchor_assurance_value,
            "anchor_evidence_state": self.anchor_evidence_state,
            "anchor_baseline": self.anchor_baseline,
            "anchor_witness_value": self.anchor_witness_value,
            "anchor_provisioned_at": self.anchor_provisioned_at,
        }

    @classmethod
    def from_plan(cls, plan: SecurityPosturePlan) -> "AuthorizationEvidenceFingerprint":
        payload = evidence_fingerprint_payload(plan)
        return cls(
            capability_posture_value=payload["capability_posture_value"],  # type: ignore[arg-type]
            anchor_assurance_value=payload["anchor_assurance_value"],  # type: ignore[arg-type]
            anchor_evidence_state=payload["anchor_evidence_state"],  # type: ignore[arg-type]
            anchor_baseline=payload["anchor_baseline"],  # type: ignore[arg-type]
            anchor_witness_value=payload["anchor_witness_value"],  # type: ignore[arg-type]
            anchor_provisioned_at=payload["anchor_provisioned_at"],  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------
# PlanAuthorization
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanAuthorizationPayload:
    """Every `PlanAuthorization` field except `proof` -- the exact,
    already-validated content an operator's signature must cover.
    Constructed only by `build_plan_authorization_payload()`, the sole
    place `authorized_step_ids` membership, `risk_class`, and
    `evidence_fingerprint` are derived from a `SecurityPosturePlan` --
    never re-derived a second, possibly-inconsistent way by
    `sign_plan_authorization()`."""

    schema_version: int
    authorization_id: str
    plan_digest: str
    authorized_step_ids: tuple[str, ...]
    authority_id: str
    algorithm: str
    issued_at: datetime
    expires_at: datetime
    risk_class: AuthorizationLevel
    evidence_fingerprint: AuthorizationEvidenceFingerprint


def build_plan_authorization_payload(
    plan: SecurityPosturePlan,
    authorized_step_ids: Sequence[str],
    *,
    authorization_id: str,
    authority_id: str,
    issued_at: datetime,
    expires_at: datetime,
    algorithm: str = AUTHORIZATION_SIGNING_ALGORITHM,
    schema_version: int = PLAN_AUTHORIZATION_SCHEMA_VERSION,
) -> PlanAuthorizationPayload:
    """Build (never sign) the exact payload an operator's signature will
    cover. Requires an already-generated `SecurityPosturePlan` -- never
    calls `discover_security_posture()`/`generate_security_posture_plan()`
    itself, exactly like `compute_plan_digest()`. `plan_digest` is always
    computed here via `compute_plan_digest(plan)`; a caller can never
    supply its own and have it trusted.

    Raises `SecurityAuthorizationError` for: an empty or duplicate-
    containing `authorized_step_ids`; any step ID not present in
    `plan.steps`; any selected step whose `authorization_required` is
    `SEPARATE_DEPROVISION_AUTHORIZATION`/`UNDETERMINED_NOT_IMPLEMENTED`;
    non-UTC or malformed `issued_at`/`expires_at`; `expires_at` not
    strictly after `issued_at`; an invalid `authorization_id`/
    `authority_id`; an unsupported `algorithm`/`schema_version`."""

    if not isinstance(authorized_step_ids, (tuple, list)) or not authorized_step_ids:
        raise SecurityAuthorizationError("authorized_step_ids must be a non-empty, explicit sequence.")
    step_ids = tuple(authorized_step_ids)
    if not all(isinstance(step_id, str) and step_id for step_id in step_ids):
        raise SecurityAuthorizationError("authorized_step_ids must contain only non-empty strings.")
    if len(set(step_ids)) != len(step_ids):
        raise SecurityAuthorizationError("authorized_step_ids must not contain duplicates.")

    steps_by_id = {step.step_id: step for step in plan.steps}
    selected_levels = []
    for step_id in step_ids:
        step = steps_by_id.get(step_id)
        if step is None:
            raise SecurityAuthorizationError(f"Step {step_id!r} is not part of the supplied plan.")
        if step.authorization_required in _NEVER_PLAN_AUTHORIZATION_LEVELS:
            raise SecurityAuthorizationError(
                f"Step {step_id!r} requires {step.authorization_required.value!r}, "
                "which a PlanAuthorization can never cover."
            )
        selected_levels.append(step.authorization_required)

    if not isinstance(authorization_id, str) or not _SAFE_TOKEN.fullmatch(authorization_id):
        raise SecurityAuthorizationError("authorization_id is invalid.")
    if not isinstance(authority_id, str) or not _SAFE_TOKEN.fullmatch(authority_id):
        raise SecurityAuthorizationError("authority_id is invalid.")
    if algorithm != AUTHORIZATION_SIGNING_ALGORITHM:
        raise SecurityAuthorizationError("Unsupported authorization signing algorithm.")
    if schema_version != PLAN_AUTHORIZATION_SCHEMA_VERSION:
        raise SecurityAuthorizationError("Unsupported PlanAuthorization schema version.")
    if not isinstance(issued_at, datetime) or not isinstance(expires_at, datetime):
        raise SecurityAuthorizationError("issued_at/expires_at must be UTC datetimes.")
    if not _is_utc(issued_at) or not _is_utc(expires_at):
        raise SecurityAuthorizationError("issued_at/expires_at must be timezone-aware UTC datetimes.")
    if expires_at <= issued_at:
        raise SecurityAuthorizationError("expires_at must be strictly after issued_at.")

    risk_class = max(selected_levels, key=lambda level: _AUTHORIZATION_LEVEL_RANK[level])

    return PlanAuthorizationPayload(
        schema_version=schema_version,
        authorization_id=authorization_id,
        plan_digest=compute_plan_digest(plan),
        authorized_step_ids=step_ids,
        authority_id=authority_id,
        algorithm=algorithm,
        issued_at=issued_at,
        expires_at=expires_at,
        risk_class=risk_class,
        evidence_fingerprint=AuthorizationEvidenceFingerprint.from_plan(plan),
    )


def plan_authorization_signing_payload(payload: PlanAuthorizationPayload) -> bytes:
    """The exact canonical bytes a `PlanAuthorization`'s signature must
    cover -- every `PlanAuthorizationPayload` field, plus an explicit
    `"digest_purpose"` domain-separation tag (see module docstring
    "Domain separation"). `authorized_step_ids` is signed sorted, not in
    caller-supplied order (see "Step-set canonicalization")."""

    # list() instead of the comprehension would keep mypy's invariant
    # list[str] typing, which mypy then refuses to assign to
    # list[CanonicalValue] below (see mypy's "list is invariant" note) --
    # the comprehension is a list *display*, checked element-by-element
    # against the annotation instead.
    sorted_step_ids: list[CanonicalValue] = [step_id for step_id in sorted(payload.authorized_step_ids)]  # noqa: C416
    body: dict[str, CanonicalValue] = {
        "digest_purpose": DigestPurpose.PLAN_AUTHORIZATION.value,
        "schema_version": payload.schema_version,
        "authorization_id": payload.authorization_id,
        "plan_digest": payload.plan_digest,
        "authorized_step_ids": sorted_step_ids,
        "authority_id": payload.authority_id,
        "algorithm": payload.algorithm,
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
        "risk_class": payload.risk_class.value,
        "evidence_fingerprint": payload.evidence_fingerprint.to_payload(),
    }
    return canonical_json(body)


@dataclass(frozen=True)
class PlanAuthorization:
    """A signed, expiring, narrowly-scoped artifact binding an
    `authority_id` to an exact `PlanDigest` and an exact, explicit set of
    step IDs (ADR-022 Decision item 4). **Never itself execution,
    verification, or a bearer capability** -- see module docstring.
    Structural validation only; construct via `sign_plan_authorization()`,
    never by hand-assembling a `proof`."""

    schema_version: int
    authorization_id: str
    plan_digest: str
    authorized_step_ids: tuple[str, ...]
    authority_id: str
    algorithm: str
    proof: bytes
    issued_at: datetime
    expires_at: datetime
    risk_class: AuthorizationLevel
    evidence_fingerprint: AuthorizationEvidenceFingerprint

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != PLAN_AUTHORIZATION_SCHEMA_VERSION:
            raise SecurityAuthorizationError("PlanAuthorization schema_version is unsupported.")
        tokens = (self.authorization_id, self.authority_id, self.algorithm)
        if not all(isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) for value in tokens):
            raise SecurityAuthorizationError("PlanAuthorization metadata is invalid.")
        if self.algorithm != AUTHORIZATION_SIGNING_ALGORITHM:
            raise SecurityAuthorizationError("PlanAuthorization algorithm is unsupported.")
        if not isinstance(self.plan_digest, str) or not _HEX_64.fullmatch(self.plan_digest):
            raise SecurityAuthorizationError("PlanAuthorization plan_digest is invalid.")
        if (
            not isinstance(self.authorized_step_ids, tuple)
            or not self.authorized_step_ids
            or not all(isinstance(step_id, str) and step_id for step_id in self.authorized_step_ids)
            or len(set(self.authorized_step_ids)) != len(self.authorized_step_ids)
        ):
            raise SecurityAuthorizationError("PlanAuthorization authorized_step_ids is invalid.")
        if not isinstance(self.proof, bytes) or len(self.proof) != _ED25519_SIGNATURE_BYTES:
            raise SecurityAuthorizationError("PlanAuthorization proof must be a 64-byte Ed25519 signature.")
        if not isinstance(self.issued_at, datetime) or not isinstance(self.expires_at, datetime):
            raise SecurityAuthorizationError("PlanAuthorization timestamps must be UTC datetimes.")
        if not _is_utc(self.issued_at) or not _is_utc(self.expires_at) or self.expires_at <= self.issued_at:
            raise SecurityAuthorizationError("PlanAuthorization validity window is invalid.")
        # AuthorizationLevel is a (str, Enum) hybrid, so a raw string equal
        # to a member's value (e.g. "configuration_change") also hashes
        # and compares equal to that member -- `not in _AUTHORIZATION_LEVEL_RANK`
        # alone would silently accept it. isinstance() is required first,
        # matching this codebase's own established precedent for
        # (str, Enum)-typed fields (ReconciliationEvidence.outcome,
        # RecoveryContract.state).
        if not isinstance(self.risk_class, AuthorizationLevel) or self.risk_class not in _AUTHORIZATION_LEVEL_RANK:
            raise SecurityAuthorizationError("PlanAuthorization risk_class is invalid.")
        if not isinstance(self.evidence_fingerprint, AuthorizationEvidenceFingerprint):
            raise SecurityAuthorizationError("PlanAuthorization evidence_fingerprint is invalid.")


def sign_plan_authorization(payload: PlanAuthorizationPayload, private_key: Ed25519PrivateKey) -> PlanAuthorization:
    """Signing-side only: never called from any MCP-server request-
    handling path in this repository (proved by
    `tests/test_security_authorization_isolation.py`). `private_key` is
    caller-supplied, already-loaded key material -- this function never
    loads, generates, or persists a key. Pure: no I/O, no mutation of
    `payload`."""

    proof = private_key.sign(plan_authorization_signing_payload(payload))
    return PlanAuthorization(
        schema_version=payload.schema_version,
        authorization_id=payload.authorization_id,
        plan_digest=payload.plan_digest,
        authorized_step_ids=payload.authorized_step_ids,
        authority_id=payload.authority_id,
        algorithm=payload.algorithm,
        proof=proof,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        risk_class=payload.risk_class,
        evidence_fingerprint=payload.evidence_fingerprint,
    )


# --------------------------------------------------------------------------
# DeprovisionAuthorization
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DeprovisionAuthorizationPayload:
    """Every `DeprovisionAuthorization` field except `proof`. See module
    docstring "`DeprovisionAuthorization` -- exact schema"."""

    schema_version: int
    authorization_id: str
    target_identity_digest: str
    authority_id: str
    algorithm: str
    issued_at: datetime
    expires_at: datetime


def build_deprovision_authorization_payload(
    *,
    target_identity_digest: str,
    authorization_id: str,
    authority_id: str,
    issued_at: datetime,
    expires_at: datetime,
    algorithm: str = AUTHORIZATION_SIGNING_ALGORITHM,
    schema_version: int = DEPROVISION_AUTHORIZATION_SCHEMA_VERSION,
) -> DeprovisionAuthorizationPayload:
    """Build (never sign) a `DeprovisionAuthorization` payload.
    `target_identity_digest` must already be a 64-lowercase-hex-character
    digest -- this function does not compute one; see module docstring
    for why no such computation exists anywhere in this repository yet.
    Raises `SecurityAuthorizationError` for the same categories of
    malformed input as `build_plan_authorization_payload()`."""

    if not isinstance(target_identity_digest, str) or not _HEX_64.fullmatch(target_identity_digest):
        raise SecurityAuthorizationError("target_identity_digest is invalid.")
    if not isinstance(authorization_id, str) or not _SAFE_TOKEN.fullmatch(authorization_id):
        raise SecurityAuthorizationError("authorization_id is invalid.")
    if not isinstance(authority_id, str) or not _SAFE_TOKEN.fullmatch(authority_id):
        raise SecurityAuthorizationError("authority_id is invalid.")
    if algorithm != AUTHORIZATION_SIGNING_ALGORITHM:
        raise SecurityAuthorizationError("Unsupported authorization signing algorithm.")
    if schema_version != DEPROVISION_AUTHORIZATION_SCHEMA_VERSION:
        raise SecurityAuthorizationError("Unsupported DeprovisionAuthorization schema version.")
    if not isinstance(issued_at, datetime) or not isinstance(expires_at, datetime):
        raise SecurityAuthorizationError("issued_at/expires_at must be UTC datetimes.")
    if not _is_utc(issued_at) or not _is_utc(expires_at):
        raise SecurityAuthorizationError("issued_at/expires_at must be timezone-aware UTC datetimes.")
    if expires_at <= issued_at:
        raise SecurityAuthorizationError("expires_at must be strictly after issued_at.")

    return DeprovisionAuthorizationPayload(
        schema_version=schema_version,
        authorization_id=authorization_id,
        target_identity_digest=target_identity_digest,
        authority_id=authority_id,
        algorithm=algorithm,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def deprovision_authorization_signing_payload(payload: DeprovisionAuthorizationPayload) -> bytes:
    """The exact canonical bytes a `DeprovisionAuthorization`'s signature
    must cover -- domain-separated from `plan_authorization_signing_payload()`
    via `"digest_purpose": DigestPurpose.DEPROVISION_AUTHORIZATION.value`
    and a structurally different field set (see module docstring "Domain
    separation")."""

    body: dict[str, CanonicalValue] = {
        "digest_purpose": DigestPurpose.DEPROVISION_AUTHORIZATION.value,
        "schema_version": payload.schema_version,
        "authorization_id": payload.authorization_id,
        "target_identity_digest": payload.target_identity_digest,
        "authority_id": payload.authority_id,
        "algorithm": payload.algorithm,
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
    }
    return canonical_json(body)


@dataclass(frozen=True)
class DeprovisionAuthorization:
    """A structurally separate, even more narrowly-scoped artifact type
    for destructive operations (ADR-022 "Destructive operations"). No
    field, method, or shared base type connects this to `PlanAuthorization`
    -- there is no coercion path between the two (see
    `tests/test_security_authorization.py`'s adversarial coverage). No
    code path in this repository constructs one from a real target; see
    module docstring."""

    schema_version: int
    authorization_id: str
    target_identity_digest: str
    authority_id: str
    algorithm: str
    proof: bytes
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != DEPROVISION_AUTHORIZATION_SCHEMA_VERSION:
            raise SecurityAuthorizationError("DeprovisionAuthorization schema_version is unsupported.")
        tokens = (self.authorization_id, self.authority_id, self.algorithm)
        if not all(isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) for value in tokens):
            raise SecurityAuthorizationError("DeprovisionAuthorization metadata is invalid.")
        if self.algorithm != AUTHORIZATION_SIGNING_ALGORITHM:
            raise SecurityAuthorizationError("DeprovisionAuthorization algorithm is unsupported.")
        if not isinstance(self.target_identity_digest, str) or not _HEX_64.fullmatch(self.target_identity_digest):
            raise SecurityAuthorizationError("DeprovisionAuthorization target_identity_digest is invalid.")
        if not isinstance(self.proof, bytes) or len(self.proof) != _ED25519_SIGNATURE_BYTES:
            raise SecurityAuthorizationError("DeprovisionAuthorization proof must be a 64-byte Ed25519 signature.")
        if not isinstance(self.issued_at, datetime) or not isinstance(self.expires_at, datetime):
            raise SecurityAuthorizationError("DeprovisionAuthorization timestamps must be UTC datetimes.")
        if not _is_utc(self.issued_at) or not _is_utc(self.expires_at) or self.expires_at <= self.issued_at:
            raise SecurityAuthorizationError("DeprovisionAuthorization validity window is invalid.")


def sign_deprovision_authorization(
    payload: DeprovisionAuthorizationPayload, private_key: Ed25519PrivateKey
) -> DeprovisionAuthorization:
    """Signing-side only -- see `sign_plan_authorization()`'s docstring;
    identical contract, distinct artifact type."""

    proof = private_key.sign(deprovision_authorization_signing_payload(payload))
    return DeprovisionAuthorization(
        schema_version=payload.schema_version,
        authorization_id=payload.authorization_id,
        target_identity_digest=payload.target_identity_digest,
        authority_id=payload.authority_id,
        algorithm=payload.algorithm,
        proof=proof,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
    )
