"""Explicit, human-maintained capture-policy registry.

`EndpointInfo.verified=True` (pfsense_mcp.endpoints.Endpoints) means an
endpoint has been independently verified via an authenticated GET — it
does NOT mean the endpoint is safe to auto-capture into a fixture.
capture_fixture.py additionally requires an entry in CAPTURE_POLICIES
below before it will ever issue a request for that endpoint. An
endpoint with no policy is refused before any network call, even if
it is fully verified — this is a deliberate second gate, separate
from endpoint verification, requiring its own explicit human review.

Each policy mirrors what the corresponding pfsense_mcp.pfsense_client
method actually supports today (e.g. only get_firewall_states exposes
a bounded `limit` parameter) — it does not grant the capture tool any
query-parameter capability the reviewed, committed client layer
doesn't already have.

Field-name lists here deliberately overlap with each model's own
_IDENTIFYING_FIELDS-style tuple in src/pfsense_mcp/models/*.py. The
overlap is intentional and accepted for now (see design decision
"keep in the automation layer rather than modifying src/ this phase")
— if a model's identifying-fields list changes, the corresponding
policy below must be updated to match.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pfsense_mcp.endpoints import Endpoints


@dataclass(frozen=True)
class BoundedInt:
    minimum: int
    maximum: int

    def __post_init__(self) -> None:
        if self.minimum > self.maximum:
            raise ValueError(f"minimum ({self.minimum}) must be <= maximum ({self.maximum})")

    def validate(self, value: int) -> bool:
        return self.minimum <= value <= self.maximum


@dataclass(frozen=True)
class CapturePolicy:
    endpoint_attr: str
    result_shape: str  # "list" | "object"
    identifying_fields: frozenset[str] = field(default_factory=frozenset)
    hard_refusal_fields: frozenset[str] = field(default_factory=frozenset)
    allowed_params: dict[str, BoundedInt] = field(default_factory=dict)
    default_max_items: int = 5
    # Narrow escape hatch for a specific field otherwise caught by the
    # generic high-entropy-value-in-a-sensitive-looking-name heuristic
    # (e.g. a long opaque-but-non-secret identifier). Empty by default;
    # a general entropy bypass is deliberately not provided — only
    # exact field names may be listed here, one at a time, on review.
    benign_fields: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if self.result_shape not in ("list", "object"):
            raise ValueError(f"result_shape must be 'list' or 'object' (got {self.result_shape!r})")
        if not hasattr(Endpoints, self.endpoint_attr):
            raise ValueError(f"Endpoints has no attribute {self.endpoint_attr!r}")


CAPTURE_POLICIES: dict[str, CapturePolicy] = {
    "SYSTEM_STATUS": CapturePolicy(
        endpoint_attr="SYSTEM_STATUS",
        result_shape="object",
        identifying_fields=frozenset({"netgate_id"}),
        default_max_items=1,
    ),
    "STATUS_INTERFACES": CapturePolicy(
        endpoint_attr="STATUS_INTERFACES",
        result_shape="list",
        identifying_fields=frozenset(
            {"macaddr", "ipaddr", "subnet", "linklocal", "ipaddrv6", "subnetv6", "gateway", "gatewayv6"}
        ),
        default_max_items=5,
    ),
    "ROUTING_GATEWAYS": CapturePolicy(
        endpoint_attr="ROUTING_GATEWAYS",
        result_shape="list",
        identifying_fields=frozenset({"gateway", "monitor"}),
        default_max_items=5,
    ),
    "STATUS_GATEWAYS": CapturePolicy(
        endpoint_attr="STATUS_GATEWAYS",
        result_shape="list",
        identifying_fields=frozenset({"srcip", "monitorip"}),
        default_max_items=5,
    ),
    "FIREWALL_RULES": CapturePolicy(
        endpoint_attr="FIREWALL_RULES",
        result_shape="list",
        identifying_fields=frozenset({"source", "destination", "created_by", "updated_by"}),
        default_max_items=5,
    ),
    "FIREWALL_STATES": CapturePolicy(
        endpoint_attr="FIREWALL_STATES",
        result_shape="list",
        identifying_fields=frozenset({"source", "destination"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=500)},
        default_max_items=5,
    ),
    "FIREWALL_STATES_SIZE": CapturePolicy(
        endpoint_attr="FIREWALL_STATES_SIZE",
        result_shape="object",
        default_max_items=1,
    ),
    "FIREWALL_APPLY_STATUS": CapturePolicy(
        endpoint_attr="FIREWALL_APPLY_STATUS",
        result_shape="object",
        default_max_items=1,
    ),
    "FIREWALL_ALIASES": CapturePolicy(
        endpoint_attr="FIREWALL_ALIASES",
        result_shape="list",
        identifying_fields=frozenset({"address", "detail"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=500)},
        default_max_items=5,
    ),
    "STATUS_SERVICES": CapturePolicy(
        endpoint_attr="STATUS_SERVICES",
        result_shape="list",
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "SYSTEM_VERSION": CapturePolicy(
        endpoint_attr="SYSTEM_VERSION",
        result_shape="object",
        default_max_items=1,
    ),
    "INTERFACES": CapturePolicy(
        endpoint_attr="INTERFACES",
        result_shape="list",
        identifying_fields=frozenset(
            {
                "ipaddr",
                "ipaddrv6",
                "gateway",
                "gatewayv6",
                "subnet",
                "subnetv6",
                "spoofmac",
                "alias_address",
                "dhcphostname",
            }
        ),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "FIREWALL_NAT_PORT_FORWARDS": CapturePolicy(
        endpoint_attr="FIREWALL_NAT_PORT_FORWARDS",
        result_shape="list",
        identifying_fields=frozenset({"source", "destination", "target", "created_by", "updated_by"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=500)},
        default_max_items=5,
    ),
    "FIREWALL_NAT_OUTBOUND_MODE": CapturePolicy(
        endpoint_attr="FIREWALL_NAT_OUTBOUND_MODE",
        result_shape="object",
        default_max_items=1,
    ),
    "USERS": CapturePolicy(
        endpoint_attr="USERS",
        result_shape="list",
        # Administrative-usefulness policy: only authorizedkeys/ipsecpsk
        # are genuine secrets at runtime — descr/uid/priv/cert are
        # ordinary object metadata and stay visible in both the model
        # and the committed fixture. `name` is intentionally stricter
        # here than at the model layer: it stays visible at runtime
        # (the model's own identifying_fields tuple does not include
        # it — see models/pf_sense_user.py), but this committed test
        # fixture uses synthesized names, not this project's real
        # account list.
        identifying_fields=frozenset({"name", "authorizedkeys", "ipsecpsk"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
        # authorizedkeys/ipsecpsk are already declared identifying
        # above (redacted whenever non-empty via the identifying-field
        # path); they are empty strings for every account on this
        # instance, so the sanitizer's post-check otherwise flags them
        # as "sensitive-looking but not redacted" (empty values are
        # never substituted). Reviewed: this does not bypass the
        # identifying-field redaction itself, only the pre-redaction
        # hard-refusal gate for a field already covered another way.
        benign_fields=frozenset({"authorizedkeys", "ipsecpsk"}),
    ),
}


def get_policy(name: str) -> CapturePolicy | None:
    return CAPTURE_POLICIES.get(name)
