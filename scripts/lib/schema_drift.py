"""General mechanism for detecting upstream OpenAPI schema fields our
Pydantic response models don't account for.

Complements the endpoint-level discovery in `lib/openapi.py` (which
detects new *endpoints* appearing in a re-pinned schema) with
field-level drift detection on response objects this project has
*already* reviewed and shipped a typed model for: a pfREST release can
add a field to an already-modeled response object, and nothing else in
this project's test suite would notice, because a Pydantic model is a
positive allowlist by construction -- an unknown upstream key is simply
never read, not rejected. That silence is the gap this module closes.

This is deliberately independent of, and does not import, the
comparison project (`gensecaihq/pfsense-mcp-server`) investigated during
the v0.6.0 competitive audit. That project validates outgoing WRITE
request payloads against a vendored contract; this checks incoming READ
response shapes against a vendored schema excerpt -- same "vendor a
pinned contract, assert against it" idea, independently designed for
the opposite side of the traffic, because that is the side this
project's own risk actually lives on (a single, heavily-gated WRITE
tool vs. 84+ typed READ response models).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

# A newly-added upstream field's name is unpredictable, so this is a
# deliberately broader *substring* heuristic than the exact-name lists
# used elsewhere in this project (tests/test_credential_non_disclosure.py's
# PROHIBITED_FIELDS, scripts/lib/security_policy.py's
# PROHIBITED_CREDENTIAL_FIELDS) -- consistent in spirit with
# scripts/lib/sanitizer.py's _HARD_SUSPICIOUS_NAME_SUBSTRINGS, kept as
# its own definition here rather than importing that module's private
# name across a layering boundary.
_SECRET_LIKE_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "psk",
    "privatekey",
    "private_key",
    "presharedkey",
    "preshared_key",
    "apikey",
    "api_key",
    "prv",
    "auth_pass",
    "proxy_passwd",
    "ipsecpsk",
)


def _looks_secret_like(field_name: str) -> bool:
    lname = field_name.lower()
    return any(substring in lname for substring in _SECRET_LIKE_SUBSTRINGS)


class SchemaDriftError(AssertionError):
    """Raised when a pinned upstream schema declares a field this
    project's response model neither models nor explicitly excludes."""


def assert_model_accounts_for_schema_fields(
    *,
    model: type[BaseModel],
    schema_properties: dict[str, Any],
    intentional_exclusions: frozenset[str] = frozenset(),
    label: str | None = None,
) -> None:
    """Assert every field key the pinned schema declares for this
    response object is either:

      (a) a field `model` declares, or
      (b) present in `intentional_exclusions` -- an explicit, reviewed
          allowlist of fields this project has deliberately chosen
          never to model (e.g. a confirmed secret field).

    Any other schema field is drift: something no review has ever
    looked at. This fails closed on *any* unaccounted field, whether or
    not its name looks secret-like -- a plain-looking name is not
    evidence of safety, only the failure message's guidance differs.

    Deliberately name-based, not type/nullability-based: a field
    changing shape (e.g. gaining `nullable: true`) without a name
    change is not drift by this mechanism's definition -- that class of
    change is caught, if it breaks anything, by the model's own
    `from_api()` parsing at LAB-verification or live-call time. This
    mechanism targets specifically the "upstream added a field and nothing
    ever looked at it" gap, not general schema-shape validation.
    """
    name = label or model.__name__
    model_fields = set(model.model_fields.keys())
    schema_fields = set(schema_properties.keys())

    stale_exclusions = intentional_exclusions - schema_fields
    if stale_exclusions:
        raise SchemaDriftError(
            f"{name}: intentional_exclusions {sorted(stale_exclusions)} no longer "
            "appear in the pinned schema at all. The exclusion is stale -- remove "
            "it, or re-verify the field still exists upstream before keeping it."
        )

    drift = schema_fields - model_fields - intentional_exclusions
    if not drift:
        return

    secretish = sorted(f for f in drift if _looks_secret_like(f))
    ordinary = sorted(f for f in drift if f not in secretish)
    parts = [f"{name}: the pinned schema has field(s) this model does not account for."]
    if secretish:
        parts.append(
            f"SECURITY: {secretish} match a secret-like naming pattern and MUST be "
            "reviewed before being modeled or excluded -- never add blindly."
        )
    if ordinary:
        parts.append(
            f"{ordinary} are new/unreviewed field(s) -- add to the model if safe to "
            "expose, or to intentional_exclusions with a documented reason if not."
        )
    raise SchemaDriftError(" ".join(parts))
