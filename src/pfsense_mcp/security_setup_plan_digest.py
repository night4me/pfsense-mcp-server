"""`pfsense-mcp-security setup` Slice 1: canonical, deterministic
`SetupPlan` digest computation.

Mirrors `security_plan_digest.py`'s own design exactly (ADR-022 Phase
B's `PlanDigest` for `SecurityPosturePlan`), for the same reason: gives
every `SetupPlan` a deterministic, immutable identity a *future*
authorization artifact could bind to. **This module computes plan
identity only.** It does NOT create authorization artifacts, grant
authorization, validate operator approval, execute anything, provision
anything, or enable WRITE.

**Mechanism-agnostic by construction (`pfsense-mcp-security setup`
OWNER DECISION 5):** the payload this module hashes never names HMAC, a
signing key, a signature, Ed25519, or any other specific future
authorization mechanism -- it is a plain, keyless SHA-256 digest over a
canonical payload, exactly like `security_plan_digest.py`'s own
`compute_plan_digest()`. A future, separately-authorized authorization
mechanism (whether the simpler incident/plan-bound HMAC model or a full
ADR-022/023 signature) would wrap *this* digest, or bind to it, without
this module or `SetupPlan` itself ever needing to change -- "the
canonical plan representation and digest must be MECHANISM-AGNOSTIC so
a future accepted ADR-022/023 authorization/signature mechanism could
authorize the same semantic plan without changing plan meaning or
digest semantics" (verbatim owner requirement). This module does not
wire ADR-022/023 into `setup`, and does not change ADR-023's status.

Like `security_plan_digest.py`, this is a narrow, explicit exception to
`pfsense_mcp.tier1` never being imported from outside its own package:
the only thing imported from `pfsense_mcp.tier1` here is `canonical.py`
-- pure, stateless canonicalization and hashing with zero I/O, zero
SQLite, zero TPM/store access, and zero mutation capability of any
kind. `tests/tier1/test_isolation.py`'s exemption list names this file
explicitly, and `tests/test_security_setup_plan_digest_isolation.py`
proves, by direct AST inspection, that `canonical` is the only
`pfsense_mcp.tier1` submodule imported here."""

from __future__ import annotations

import hmac

from .security_plan_digest import compute_plan_digest
from .security_setup_plan import SetupPlan
from .tier1.canonical import CanonicalValue, DigestPurpose, digest_value

#: Bumped whenever a digest-participating field is added, removed, or
#: reinterpreted -- see `security_plan_digest.py`'s own
#: `PLAN_DIGEST_SCHEMA_VERSION` docstring for the identical reasoning
#: (the version itself is hashed as part of the payload, so a version
#: change alone already changes every future digest).
SETUP_PLAN_DIGEST_SCHEMA_VERSION = 1


def _setup_plan_payload(plan: SetupPlan) -> dict[str, CanonicalValue]:
    """The complete canonical payload `SetupPlanDigest` hashes.

    Deliberately structured, never prose: free-text fields
    (`provisioning_note`, `version_note`, the human-readable
    `unsupported_steps`/`planned_pfsense_actions`/`planned_local_artifacts`
    strings, `notes`) never participate directly -- only their
    structured, semantically load-bearing facts do, exactly mirroring
    `security_plan_digest.py::_plan_payload()`'s own exclusion of raw
    `evidence` prose. `unsupported_step_count` (a count, not the text
    itself) still detects a structural change -- a new unsupported
    category appearing or disappearing -- without binding the digest to
    exact wording that might be refined later with no semantic change.

    The nested `posture_plan` is bound via its own existing
    `compute_plan_digest()` rather than re-deriving an equivalent
    structured payload a second time -- reuse, not reinvention, and the
    two digests stay independently verifiable against their own inputs."""

    privilege = plan.privilege_plan
    version = plan.version_evidence
    return {
        "schema_version": SETUP_PLAN_DIGEST_SCHEMA_VERSION,
        "target_origin": plan.target.origin,
        "target_identity": plan.target.identity,
        "target_tls_mode": plan.target.tls_mode,
        "target_reachability_verified": plan.target.reachability_verified,
        "posture_plan_digest": compute_plan_digest(plan.posture_plan),
        "intended_capability_posture": privilege.intended_capability_posture.value,
        "intended_account_identity": privilege.intended_account_identity,
        "dedicated_account_provisioning_implemented": privilege.dedicated_account_provisioning_implemented,
        "privilege_schema_provided": privilege.schema_provided,
        "required_privileges": (
            list(privilege.required_privileges) if privilege.required_privileges is not None else None
        ),
        "unresolved_requirement_tool_names": list(privilege.unresolved_requirement_tool_names),
        "version_schema_provided": version.schema_provided,
        "declared_package_version": version.declared_package_version,
        "package_version_supported": version.package_version_supported,
        "unsupported_step_count": len(plan.unsupported_steps),
    }


def compute_setup_plan_digest(plan: SetupPlan) -> str:
    """Pure, deterministic, and total over every `SetupPlan`
    `generate_setup_plan()` can produce. No I/O of any kind; never
    mutates `plan` or anything else. Computing this digest is not
    authorization, does not require authorization, and grants nothing."""

    return digest_value(DigestPurpose.SETUP_PLAN, _setup_plan_payload(plan))


def verify_setup_plan_digest(plan: SetupPlan, expected_digest: str) -> bool:
    """Pure. Always independently recomputes the digest from `plan`
    alone via `compute_setup_plan_digest()`, then compares in constant
    time (`hmac.compare_digest()`) -- mirrors
    `security_plan_digest.py::verify_plan_digest()`'s own discipline
    exactly, including that a malformed, empty, or non-hex
    `expected_digest` is never treated as a match and never raises."""

    return hmac.compare_digest(compute_setup_plan_digest(plan), expected_digest)
