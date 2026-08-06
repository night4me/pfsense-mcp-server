#!/usr/bin/env python3
"""bounded_params_check.py — confirms every known bounded query
parameter still has an enforced MIN/MAX pair referenced ahead of the
actual pfSense request, so a capability can never issue an unbounded
request against a resource that can hold unbounded data (e.g. a
firewall's live state table).

This is an explicit, human-maintained registry (BOUNDED_PARAMETERS
below), matching this project's existing philosophy of explicit lists
(Endpoints, SUPPORTED_CAPABILITIES_THIS_BUILD) rather than generic
inference. Extend the registry whenever a future capability adds a
new bounded parameter.

Read-only. Exits 0 (every registered parameter is still bounded) or 1.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

CLIENT_FILE = Path(__file__).resolve().parent.parent / "src" / "pfsense_mcp" / "pfsense_client.py"


@dataclass(frozen=True)
class BoundedParameter:
    method_name: str
    param_name: str
    min_constant: str
    max_constant: str


BOUNDED_PARAMETERS = (
    BoundedParameter(
        method_name="get_firewall_states",
        param_name="limit",
        min_constant="FIREWALL_STATES_MIN_LIMIT",
        max_constant="FIREWALL_STATES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_firewall_aliases",
        param_name="limit",
        min_constant="FIREWALL_ALIASES_MIN_LIMIT",
        max_constant="FIREWALL_ALIASES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_service_status",
        param_name="limit",
        min_constant="SERVICE_STATUS_MIN_LIMIT",
        max_constant="SERVICE_STATUS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_interface_configs",
        param_name="limit",
        min_constant="INTERFACE_CONFIGS_MIN_LIMIT",
        max_constant="INTERFACE_CONFIGS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_firewall_nat_port_forwards",
        param_name="limit",
        min_constant="FIREWALL_NAT_PORT_FORWARDS_MIN_LIMIT",
        max_constant="FIREWALL_NAT_PORT_FORWARDS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_users",
        param_name="limit",
        min_constant="USERS_MIN_LIMIT",
        max_constant="USERS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_system_certificates",
        param_name="limit",
        min_constant="SYSTEM_CERTIFICATES_MIN_LIMIT",
        max_constant="SYSTEM_CERTIFICATES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_user_groups",
        param_name="limit",
        min_constant="USER_GROUPS_MIN_LIMIT",
        max_constant="USER_GROUPS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_dhcp_leases",
        param_name="limit",
        min_constant="DHCP_LEASES_MIN_LIMIT",
        max_constant="DHCP_LEASES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_dhcp_static_mappings",
        param_name="limit",
        min_constant="DHCP_STATIC_MAPPINGS_MIN_LIMIT",
        max_constant="DHCP_STATIC_MAPPINGS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_dhcp_servers",
        param_name="limit",
        min_constant="DHCP_SERVERS_MIN_LIMIT",
        max_constant="DHCP_SERVERS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_interface_bridges",
        param_name="limit",
        min_constant="INTERFACE_BRIDGES_MIN_LIMIT",
        max_constant="INTERFACE_BRIDGES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_dns_resolver_host_overrides",
        param_name="limit",
        min_constant="DNS_RESOLVER_HOST_OVERRIDES_MIN_LIMIT",
        max_constant="DNS_RESOLVER_HOST_OVERRIDES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_arp_table",
        param_name="limit",
        min_constant="ARP_TABLE_MIN_LIMIT",
        max_constant="ARP_TABLE_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_firewall_traffic_shaper_limiters",
        param_name="limit",
        min_constant="FIREWALL_TRAFFIC_SHAPER_LIMITERS_MIN_LIMIT",
        max_constant="FIREWALL_TRAFFIC_SHAPER_LIMITERS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_system_packages",
        param_name="limit",
        min_constant="SYSTEM_PACKAGES_MIN_LIMIT",
        max_constant="SYSTEM_PACKAGES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_system_tunables",
        param_name="limit",
        min_constant="SYSTEM_TUNABLES_MIN_LIMIT",
        max_constant="SYSTEM_TUNABLES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_ntp_time_servers",
        param_name="limit",
        min_constant="NTP_TIME_SERVERS_MIN_LIMIT",
        max_constant="NTP_TIME_SERVERS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_cron_jobs",
        param_name="limit",
        min_constant="CRON_JOBS_MIN_LIMIT",
        max_constant="CRON_JOBS_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_diagnostics_tables",
        param_name="limit",
        min_constant="DIAGNOSTICS_TABLES_MIN_LIMIT",
        max_constant="DIAGNOSTICS_TABLES_MAX_LIMIT",
    ),
    BoundedParameter(
        method_name="get_auth_keys",
        param_name="limit",
        min_constant="AUTH_KEYS_MIN_LIMIT",
        max_constant="AUTH_KEYS_MAX_LIMIT",
    ),
)


def _method_source(text: str, method_name: str) -> str | None:
    marker = f"def {method_name}("
    start = text.find(marker)
    if start == -1:
        return None
    # A method body runs until the next top-level "def " at the same
    # (4-space) indentation, or end of file.
    next_def = text.find("\n    def ", start + len(marker))
    return text[start:] if next_def == -1 else text[start:next_def]


def check_bounded_parameter(text: str, param: BoundedParameter) -> list[str]:
    failures = []

    if f"{param.min_constant} = " not in text:
        failures.append(f"{param.min_constant} is not defined as a module constant")
    if f"{param.max_constant} = " not in text:
        failures.append(f"{param.max_constant} is not defined as a module constant")

    body = _method_source(text, param.method_name)
    if body is None:
        failures.append(f"method {param.method_name} not found")
        return failures

    if param.min_constant not in body or param.max_constant not in body:
        failures.append(f"{param.method_name} does not reference both {param.min_constant} and {param.max_constant}")
    if "raise" not in body:
        failures.append(f"{param.method_name} has no validation raise guarding '{param.param_name}'")

    return failures


def main() -> int:
    text = CLIENT_FILE.read_text(encoding="utf-8")
    all_failures: list[str] = []
    for param in BOUNDED_PARAMETERS:
        failures = check_bounded_parameter(text, param)
        all_failures.extend(f"{param.method_name}({param.param_name}): {f}" for f in failures)

    if all_failures:
        print("bounded_params_check: FAILED", file=sys.stderr)
        for f in all_failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    print(f"bounded_params_check: OK ({len(BOUNDED_PARAMETERS)} registered parameter(s) verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
