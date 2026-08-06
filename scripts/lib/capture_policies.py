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
    "SYSTEM_CERTIFICATES": CapturePolicy(
        endpoint_attr="SYSTEM_CERTIFICATES",
        result_shape="list",
        # Administrative-usefulness policy: crt/csr are public PKI
        # artifacts (certificate/CSR, never the private key — pfSense's
        # own GET response never includes "prv"), and type/validity
        # fields are operational; the model has no identifying_fields
        # so all of this stays visible at runtime. descr/refid/caref
        # are stricter here than at the model layer: this install's
        # real certificate names and reference IDs are
        # installation-specific, so the committed test fixture
        # synthesizes them (fixture policy may be stricter than
        # runtime redaction — see models/system_certificate.py).
        identifying_fields=frozenset({"descr", "refid", "caref"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "USER_GROUPS": CapturePolicy(
        endpoint_attr="USER_GROUPS",
        result_shape="list",
        # name/description/gid/priv/scope are ordinary object metadata
        # (group name, role assignment), visible at both layers. member
        # is stricter here than at the model layer: it's an array of
        # real account usernames, which are installation-specific, so
        # the committed test fixture synthesizes them — runtime keeps
        # them visible (group membership is core administrative value
        # for this capability, matching USER_READ's username policy).
        identifying_fields=frozenset({"member"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "STATUS_DHCP_LEASES": CapturePolicy(
        endpoint_attr="STATUS_DHCP_LEASES",
        result_shape="list",
        # ip/mac/hostname are the whole point of a DHCP lease
        # inventory capability and stay visible per explicit policy;
        # the sanitizer's generic IP/MAC/hostname substitution already
        # applies to them regardless of identifying_fields, so the
        # committed fixture is safe without declaring them here. descr
        # is stricter here than at the model layer: it holds this
        # install's real per-device labels (installation-specific),
        # so only the fixture synthesizes it — runtime keeps it
        # visible.
        identifying_fields=frozenset({"descr"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "DHCP_SERVER_STATIC_MAPPINGS": CapturePolicy(
        endpoint_attr="DHCP_SERVER_STATIC_MAPPINGS",
        result_shape="list",
        # Same DHCP-inventory exception as STATUS_DHCP_LEASES:
        # mac/ipaddr/hostname stay visible (core purpose of a static
        # mapping inventory), auto-sanitized generically in the
        # fixture regardless of identifying_fields. descr is stricter
        # here than at the model layer for the same reason as leases.
        identifying_fields=frozenset({"descr"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "DHCP_SERVERS": CapturePolicy(
        endpoint_attr="DHCP_SERVERS",
        result_shape="list",
        # DHCP server (scope) configuration per interface: range,
        # gateway, DNS/NTP/WINS servers, and embedded static mappings.
        # Same DHCP-inventory exception as STATUS_DHCP_LEASES/
        # DHCP_SERVER_STATIC_MAPPINGS: ip/mac/domain fields stay
        # visible (core purpose of this capability), auto-sanitized
        # generically regardless of identifying_fields. descr only
        # appears nested inside each server's embedded `staticmap`
        # entries; it is stricter here than at the model layer for the
        # same reason as the dedicated static-mapping capability.
        identifying_fields=frozenset({"descr"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "INTERFACE_BRIDGES": CapturePolicy(
        endpoint_attr="INTERFACE_BRIDGES",
        result_shape="list",
        # bridgeif/members are ordinary interface identifiers (core
        # purpose of a bridge-interface inventory capability) and stay
        # visible at both layers. descr is stricter here than at the
        # model layer: it holds this install's real custom label for
        # the bridge, which is installation-specific, so only the
        # fixture synthesizes it — runtime keeps it visible.
        identifying_fields=frozenset({"descr"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "STATUS_CARP": CapturePolicy(
        endpoint_attr="STATUS_CARP",
        result_shape="object",
        default_max_items=1,
    ),
    "SYSTEM_RESTAPI_SETTINGS": CapturePolicy(
        endpoint_attr="SYSTEM_RESTAPI_SETTINGS",
        result_shape="object",
        # ha_sync_username is a credential paired 1:1 with the (never
        # returned by pfSense's own API) ha_sync_password field for
        # HA-peer sync authentication -- a genuine auth credential,
        # not a general account username, so it is identifying at
        # both the model and fixture layers. Everything else here is
        # ordinary REST API service configuration (enabled state,
        # auth methods, JWT expiry, logging level, allowed
        # interfaces) and stays visible.
        identifying_fields=frozenset({"ha_sync_username"}),
        default_max_items=1,
    ),
    "SYSTEM_HASYNC": CapturePolicy(
        endpoint_attr="SYSTEM_HASYNC",
        result_shape="object",
        # username pairs with the (never returned by pfSense's own
        # API) password field for HA-peer sync authentication -- a
        # genuine auth credential, not a general account username.
        # pfhostid is a persistent per-installation host identifier,
        # same class as netgate_id/serial. Both are identifying at the
        # model layer. pfsyncpeerip/synchronizetoip are ordinary peer
        # network addresses (core purpose of an HA-sync status
        # capability) and stay visible, auto-sanitized generically in
        # the fixture regardless of identifying_fields. Every
        # synchronize* field is a plain config toggle.
        identifying_fields=frozenset({"username", "pfhostid"}),
        default_max_items=1,
    ),
    "DNS_RESOLVER_HOST_OVERRIDES": CapturePolicy(
        endpoint_attr="DNS_RESOLVER_HOST_OVERRIDES",
        result_shape="list",
        # host/domain/ip are the whole point of a DNS host-override
        # inventory capability and stay visible per explicit policy,
        # same exception as the DHCP inventory capabilities; ip and
        # domain are auto-sanitized generically in the fixture
        # regardless (domain via the hostname field-name check; ip via
        # the IP regex). host is NOT auto-caught: a bare single-label
        # value like "pfsense" has no dot, so it doesn't match the
        # generic hostname-shape check, and "host" isn't in the
        # hostname field-name set either -- it must be declared here
        # explicitly or a real configured override name leaks into
        # the fixture. descr/host are both stricter here than at the
        # model layer: they hold this install's real per-entry values.
        identifying_fields=frozenset({"descr", "host"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "DNS_RESOLVER_SETTINGS": CapturePolicy(
        endpoint_attr="DNS_RESOLVER_SETTINGS",
        result_shape="object",
        # sslcertref is a certificate reference ID, same treatment as
        # SYSTEM_CERTIFICATES' refid/caref: installation-specific, so
        # only the fixture synthesizes it. Everything else is ordinary
        # DNS resolver service configuration and stays visible.
        identifying_fields=frozenset({"sslcertref"}),
        default_max_items=1,
    ),
    "DIAGNOSTICS_ARP_TABLE": CapturePolicy(
        endpoint_attr="DIAGNOSTICS_ARP_TABLE",
        result_shape="list",
        # Same policy as the DHCP inventory capabilities: ip_address/
        # mac_address/hostname stay visible at runtime (that's the
        # whole point of an ARP-table capability) and are fixture-only
        # here. hostname is auto-caught by the sanitizer's generic
        # hostname field-name check; dnsresolve is a second, separate
        # resolved-name field not covered by that set and must be
        # declared explicitly or a real device name leaks into the
        # fixture.
        identifying_fields=frozenset({"hostname", "dnsresolve"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "FIREWALL_TRAFFIC_SHAPER_LIMITERS": CapturePolicy(
        endpoint_attr="FIREWALL_TRAFFIC_SHAPER_LIMITERS",
        result_shape="list",
        # name/description are user-authored limiter labels
        # (fixture-only, same asymmetric pattern). Nested queue[]
        # reuses the same field names.
        identifying_fields=frozenset({"name", "description"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "FIREWALL_ADVANCED_SETTINGS": CapturePolicy(
        endpoint_attr="FIREWALL_ADVANCED_SETTINGS",
        result_shape="object",
        # Two plain boolean/integer tuning fields; nothing identifying
        # or secret.
        default_max_items=1,
    ),
    "SYSTEM_PACKAGES": CapturePolicy(
        endpoint_attr="SYSTEM_PACKAGES",
        result_shape="list",
        # Package names/descriptions/versions are public catalog
        # metadata, not installation-specific secrets. No identifying
        # fields.
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=20,
    ),
    "SYSTEM_TUNABLES": CapturePolicy(
        endpoint_attr="SYSTEM_TUNABLES",
        result_shape="list",
        # FreeBSD sysctl tunables (name/description/value). Ordinary
        # kernel tuning parameters, not secrets or identifying data.
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=20,
    ),
    "SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS": CapturePolicy(
        endpoint_attr="SYSTEM_NOTIFICATIONS_EMAIL_SETTINGS",
        result_shape="object",
        # password is the SMTP auth password -- a genuine secret,
        # hard-refused. username/fromaddress/notifyemailaddress/
        # ipaddress are real personal contact info / SMTP account
        # identity, not ordinary administrative object names -- unlike
        # most other capabilities today, these are redacted by default
        # at the model layer too (matching the manifest's
        # identifying_fields), not just fixture-only.
        hard_refusal_fields=frozenset({"password"}),
        identifying_fields=frozenset({"username", "fromaddress", "notifyemailaddress", "ipaddress", "password"}),
        default_max_items=1,
    ),
    "BIND_SETTINGS": CapturePolicy(
        endpoint_attr="BIND_SETTINGS",
        result_shape="object",
        default_max_items=1,
    ),
    "NTP_SETTINGS": CapturePolicy(
        endpoint_attr="NTP_SETTINGS",
        result_shape="object",
        # serverauthkey is an NTP symmetric authentication key -- a
        # genuine secret, hard-refused and redacted-by-default at the
        # model layer, same treatment as SYSTEM_NOTIFICATIONS'
        # password.
        hard_refusal_fields=frozenset({"serverauthkey"}),
        identifying_fields=frozenset({"serverauthkey"}),
        default_max_items=1,
    ),
    "NTP_TIME_SERVERS": CapturePolicy(
        endpoint_attr="NTP_TIME_SERVERS",
        result_shape="list",
        # timeserver is a public NTP pool/server hostname (e.g. a
        # pfsense.pool.ntp.org entry) -- ordinary, non-sensitive
        # configuration, not installation-specific.
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "SERVICES_SSH": CapturePolicy(
        endpoint_attr="SERVICES_SSH",
        result_shape="object",
        default_max_items=1,
    ),
    "CRON_JOBS": CapturePolicy(
        endpoint_attr="CRON_JOBS",
        result_shape="list",
        # command/who are the whole point of a cron-job inventory
        # capability -- ordinary administrative configuration, not
        # secrets. No identifying fields.
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "ACME_SETTINGS": CapturePolicy(
        endpoint_attr="ACME_SETTINGS",
        result_shape="object",
        default_max_items=1,
    ),
    "FREERADIUS_EAP": CapturePolicy(
        endpoint_attr="FREERADIUS_EAP",
        result_shape="object",
        default_max_items=1,
    ),
    "DIAGNOSTICS_TABLES": CapturePolicy(
        endpoint_attr="DIAGNOSTICS_TABLES",
        result_shape="list",
        # entries[] are pf table IP/CIDR members -- auto-sanitized
        # generically by the IP regex. name is the pf table name
        # (e.g. "bogons", "sshlockout"), not sensitive.
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
    "AUTH_KEYS": CapturePolicy(
        endpoint_attr="AUTH_KEYS",
        result_shape="list",
        # key is the plaintext API key material (when present -- the
        # API typically only returns it once at creation, null on
        # subsequent reads); hash is the stored key hash used for
        # verification. Both are genuine credential material,
        # hard-refused. username/descr are account-identifying.
        hard_refusal_fields=frozenset({"key", "hash"}),
        identifying_fields=frozenset({"key", "hash", "username", "descr"}),
        allowed_params={"limit": BoundedInt(minimum=1, maximum=100)},
        default_max_items=10,
    ),
}


def get_policy(name: str) -> CapturePolicy | None:
    return CAPTURE_POLICIES.get(name)
