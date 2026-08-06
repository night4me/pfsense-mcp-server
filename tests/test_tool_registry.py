import json

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport


class FakeMCP:
    def __init__(self) -> None:
        self.registered = []

    def tool(self):
        def decorator(fn):
            self.registered.append(fn)
            return fn

        return decorator


_INTERFACES_BODY = {
    "data": [
        {
            "id": 0,
            "name": "wan",
            "descr": "WAN",
            "hwif": "igb0",
            "macaddr": "02:00:00:aa:bb:cc",
            "mtu": "1500",
            "enable": True,
            "status": "up",
            "ipaddr": "198.51.100.10",
            "subnet": "255.255.255.0",
            "linklocal": None,
            "ipaddrv6": None,
            "subnetv6": None,
            "inerrs": 0,
            "outerrs": 0,
            "collisions": 0,
            "inbytes": 1000,
            "inbytespass": 1000,
            "outbytes": 2000,
            "outbytespass": 2000,
            "inpkts": 10,
            "inpktspass": 10,
            "outpkts": 20,
            "outpktspass": 20,
            "dhcplink": "up",
            "media": "1000baseT <full-duplex>",
            "gateway": "198.51.100.1",
            "gatewayv6": None,
        }
    ]
}

_GATEWAYS_BODY = {
    "data": [
        {
            "id": 0,
            "name": "WAN_DHCP",
            "descr": "Interface WAN Gateway",
            "disabled": False,
            "ipprotocol": "inet",
            "interface": "wan",
            "gateway": "198.51.100.1",
            "monitor_disable": False,
            "monitor": "198.51.100.1",
            "action_disable": False,
            "force_down": False,
            "dpinger_dont_add_static_route": False,
            "gw_down_kill_states": "",
            "nonlocalgateway": False,
            "weight": 1,
            "data_payload": 1,
            "latencylow": 200,
            "latencyhigh": 500,
            "losslow": 10,
            "losshigh": 20,
            "interval": 500,
            "loss_interval": 2000,
            "time_period": 60000,
            "alert_interval": 1000,
        }
    ]
}

_GATEWAY_STATUS_BODY = {
    "data": [
        {
            "id": 0,
            "name": "WAN_DHCP",
            "srcip": "198.51.100.10",
            "monitorip": "198.51.100.1",
            "delay": 12.345,
            "stddev": 1.2,
            "loss": 0.0,
            "status": "none",
            "substatus": "none",
        }
    ]
}

_FIREWALL_RULES_BODY = {
    "data": [
        {
            "id": 0,
            "type": "pass",
            "interface": ["wan"],
            "ipprotocol": "inet",
            "protocol": "tcp",
            "icmptype": None,
            "source": "198.51.100.10",
            "source_port": None,
            "destination": "203.0.113.5",
            "destination_port": "443",
            "descr": "Allow HTTPS",
            "disabled": False,
            "log": True,
            "dscp": None,
            "tag": "",
            "statetype": "keep state",
            "tcp_flags_any": False,
            "tcp_flags_out_of": None,
            "tcp_flags_set": None,
            "gateway": None,
            "sched": None,
            "dnpipe": None,
            "pdnpipe": None,
            "defaultqueue": None,
            "ackqueue": None,
            "floating": False,
            "quick": None,
            "direction": None,
            "tracker": 1700000000,
            "associated_rule_id": None,
            "created_time": 1700000000,
            "created_by": "admin@198.51.100.20",
            "updated_time": 1700000100,
            "updated_by": "admin@198.51.100.20",
        }
    ]
}

_FIREWALL_STATES_BODY = {
    "data": [
        {
            "id": 0,
            "interface": "wan",
            "protocol": "tcp",
            "direction": "out",
            "source": "198.51.100.10:51234",
            "destination": "203.0.113.5:443",
            "state": "ESTABLISHED:ESTABLISHED",
            "age": "00:05:12",
            "expires_in": "23:59:48",
            "packets_total": 120,
            "packets_in": 60,
            "packets_out": 60,
            "bytes_total": 45000,
            "bytes_in": 20000,
            "bytes_out": 25000,
        }
    ]
}

_FIREWALL_STATES_SIZE_BODY = {
    "data": {
        "maximumstates": 500000,
        "defaultmaximumstates": 500000,
        "currentstates": 42,
    }
}

_FIREWALL_APPLY_BODY = {"data": {"applied": True, "pending_subsystems": []}}

_FIREWALL_ALIASES_BODY = {
    "data": [
        {
            "id": 0,
            "name": "IPTV",
            "descr": "TWE",
            "type": "network",
            "address": ["198.51.100.10/20"],
            "detail": ["REDACTED-detail"],
        }
    ]
}


_SERVICE_STATUS_BODY = {
    "data": [
        {
            "id": 0,
            "name": "unbound",
            "description": "DNS Resolver",
            "enabled": True,
            "status": True,
        }
    ]
}


_SYSTEM_VERSION_BODY = {
    "data": {
        "base": "26.03.1",
        "buildtime": "20260731-1801",
        "patch": "0",
        "version": "26.03.1-RELEASE",
    }
}


_INTERFACE_CONFIGS_BODY = {
    "data": [
        {
            "adv_dhcp_config_advanced": False,
            "adv_dhcp_config_file_override": False,
            "adv_dhcp_config_file_override_path": "",
            "adv_dhcp_option_modifiers": "",
            "adv_dhcp_pt_backoff_cutoff": None,
            "adv_dhcp_pt_initial_interval": None,
            "adv_dhcp_pt_reboot": None,
            "adv_dhcp_pt_retry": None,
            "adv_dhcp_pt_select_timeout": None,
            "adv_dhcp_pt_timeout": None,
            "adv_dhcp_pt_values": "SavedCfg",
            "adv_dhcp_request_options": "",
            "adv_dhcp_required_options": "",
            "adv_dhcp_send_options": "",
            "alias_address": "",
            "alias_subnet": 32,
            "blockbogons": True,
            "blockpriv": True,
            "descr": "WAN",
            "dhcphostname": "REDACTED-hostname",
            "dhcprejectfrom": [],
            "enable": True,
            "gateway": None,
            "gateway_6rd": "",
            "gatewayv6": None,
            "id": "wan",
            "if": "igb0",
            "ipaddr": "198.51.100.10",
            "ipaddrv6": None,
            "ipv6usev4iface": None,
            "media": None,
            "mediaopt": None,
            "mss": None,
            "mtu": None,
            "prefix_6rd": None,
            "prefix_6rd_v4plen": None,
            "slaacusev4iface": None,
            "spoofmac": "",
            "subnet": None,
            "subnetv6": None,
            "track6_interface": None,
            "track6_prefix_id_hex": None,
            "typev4": "dhcp",
            "typev6": "none",
        }
    ]
}


_FIREWALL_NAT_PORT_FORWARDS_BODY = {
    "data": [
        {
            "id": 0,
            "interface": "wan",
            "ipprotocol": "inet",
            "protocol": "tcp",
            "source": "any",
            "source_port": None,
            "destination": "wan:ip",
            "destination_port": "58846",
            "target": "198.51.100.10",
            "local_port": "58846",
            "disabled": False,
            "nordr": False,
            "nosync": False,
            "descr": "DelugeTorrent",
            "natreflection": None,
            "associated_rule_id": None,
            "created_time": 1761601391,
            "created_by": "admin@198.51.100.11 (Local Database)",
            "updated_time": 1761601391,
            "updated_by": "admin@198.51.100.11 (Local Database)",
        }
    ]
}


_USERS_BODY = {
    "data": [
        {
            "authorizedkeys": "",
            "cert": None,
            "descr": "Test Account",
            "disabled": False,
            "expires": "",
            "id": 0,
            "ipsecpsk": "",
            "name": "testuser",
            "priv": ["test-priv"],
            "scope": "system",
            "uid": 0,
        }
    ]
}


_SYSTEM_CERTIFICATES_BODY = {
    "data": [
        {
            "caref": None,
            "crt": "-----BEGIN CERTIFICATE-----\nMIIEezCCA2Og==",
            "csr": None,
            "descr": "Test Certificate",
            "id": 0,
            "refid": "test-refid",
            "type": "server",
            "valid_days_left": 100,
            "valid_from": "2025-01-01 00:00:00",
            "valid_until": "2026-01-01 00:00:00",
        }
    ]
}


_USER_GROUPS_BODY = {
    "data": [
        {
            "description": "Test Group",
            "gid": 1999,
            "id": 0,
            "member": ["testuser"],
            "name": "testgroup",
            "priv": ["page-all"],
            "scope": "system",
        }
    ]
}


_DHCP_LEASES_BODY = {
    "data": [
        {
            "active_status": "static",
            "descr": "Test Device",
            "ends": "",
            "hostname": "testhost",
            "id": 0,
            "if": "lan",
            "ip": "198.51.100.10",
            "mac": "02:00:00:00:00:01",
            "online_status": "active/online",
            "starts": "",
        }
    ]
}


_DHCP_STATIC_MAPPINGS_BODY = {
    "data": [
        {
            "arp_table_static_entry": False,
            "cid": "",
            "defaultleasetime": None,
            "descr": "Test Mapping",
            "dnsserver": None,
            "domain": "",
            "domainsearchlist": [],
            "gateway": "",
            "hostname": "testhost",
            "id": 0,
            "ipaddr": "198.51.100.10",
            "mac": "02:00:00:00:00:01",
            "maxleasetime": None,
            "ntpserver": None,
            "parent_id": "lan",
            "winsserver": None,
        }
    ]
}


_DHCP_SERVERS_BODY = {
    "data": [
        {
            "defaultleasetime": None,
            "denyunknown": None,
            "dhcpleaseinlocaltime": False,
            "disablepingcheck": False,
            "dnsserver": None,
            "domain": "",
            "domainsearchlist": [],
            "enable": True,
            "failover_peerip": "",
            "gateway": "",
            "id": "lan",
            "ignorebootp": False,
            "ignoreclientuids": False,
            "interface": "lan",
            "mac_allow": [],
            "mac_deny": [],
            "maxleasetime": None,
            "nonak": False,
            "ntpserver": None,
            "numberoptions": None,
            "pool": [],
            "range_from": "198.51.100.10",
            "range_to": "198.51.100.11",
            "staticarp": False,
            "staticmap": [],
            "statsgraph": False,
            "winsserver": None,
        }
    ]
}


_INTERFACE_BRIDGES_BODY = {
    "data": [
        {
            "bridgeif": "bridge0",
            "descr": "Test Bridge",
            "id": 0,
            "members": ["opt1", "opt2"],
        }
    ]
}


_STATUS_CARP_BODY = {"data": {"enable": False, "maintenance_mode": False}}


_DNS_RESOLVER_HOST_OVERRIDES_BODY = {
    "data": [
        {
            "aliases": None,
            "descr": "Test override",
            "domain": "example.invalid",
            "host": "test-host",
            "id": 0,
            "ip": ["198.51.100.10"],
        }
    ]
}


_DNS_RESOLVER_SETTINGS_BODY = {
    "data": {
        "active_interface": ["lan"],
        "custom_options": "",
        "dnssec": True,
        "enable": True,
        "enablessl": False,
        "forwarding": False,
        "outgoing_interface": ["wan"],
        "port": "",
        "python": False,
        "python_order": None,
        "python_script": None,
        "regdhcp": False,
        "regdhcpstatic": False,
        "regovpnclients": True,
        "sslcertref": "test-sslcertref",
        "strictout": False,
        "system_domain_local_zone_type": "transparent",
        "tlsport": "",
    }
}


_ARP_TABLE_BODY = {
    "data": [
        {
            "dnsresolve": "",
            "expires": "Expires in 1197 seconds",
            "hostname": "test-host",
            "id": 0,
            "interface": "LAN",
            "ip_address": "198.51.100.10",
            "mac_address": "02:00:00:00:00:01",
            "permanent": False,
            "type": "bridge",
        }
    ]
}


_TRAFFIC_SHAPER_LIMITERS_BODY = {
    "data": [
        {
            "aqm": "droptail",
            "bandwidth": [{"bw": 470, "bwscale": "Mb", "bwsched": "none", "id": 0, "parent_id": 0}],
            "buckets": None,
            "delay": 0,
            "description": "",
            "ecn": None,
            "enabled": True,
            "id": 0,
            "mask": "dstaddress",
            "maskbits": 32,
            "maskbitsv6": 128,
            "name": "test-limiter",
            "number": 1,
            "param_codel_interval": 0,
            "param_codel_target": 0,
            "param_fq_codel_flows": 1024,
            "param_fq_codel_interval": 100,
            "param_fq_codel_limit": 10240,
            "param_fq_codel_quantum": 1514,
            "param_fq_codel_target": 5,
            "param_fq_pie_alpha": None,
            "param_fq_pie_beta": None,
            "param_fq_pie_flows": None,
            "param_fq_pie_limit": None,
            "param_fq_pie_max_burst": None,
            "param_fq_pie_max_ecnth": None,
            "param_fq_pie_quantum": None,
            "param_fq_pie_target": None,
            "param_fq_pie_tupdate": None,
            "param_gred_max_p": None,
            "param_gred_max_th": None,
            "param_gred_min_th": None,
            "param_gred_w_q": None,
            "param_pie_alpha": None,
            "param_pie_beta": None,
            "param_pie_max_burst": None,
            "param_pie_max_ecnth": None,
            "param_pie_target": None,
            "param_pie_tupdate": None,
            "param_red_max_p": None,
            "param_red_max_th": None,
            "param_red_min_th": None,
            "param_red_w_q": None,
            "pie_capdrop": None,
            "pie_onoff": None,
            "pie_pderand": None,
            "pie_qdelay": None,
            "plr": None,
            "qlimit": None,
            "queue": [],
            "sched": "fq_codel",
        }
    ]
}


_FIREWALL_ADVANCED_SETTINGS_BODY = {"data": {"aliasesresolveinterval": 300, "checkaliasesurlcert": True}}


_SYSTEM_PACKAGES_BODY = {
    "data": [
        {
            "descr": "Test package.",
            "id": 0,
            "installed_version": "1.0.0",
            "latest_version": "1.0.0",
            "name": "pfSense-pkg-Test",
            "shortname": "Test",
            "update_available": False,
        }
    ]
}


_SYSTEM_TUNABLES_BODY = {
    "data": [
        {
            "descr": "Test tunable.",
            "id": 0,
            "tunable": "net.inet.tcp.test",
            "value": "1",
        }
    ]
}


_EMAIL_NOTIFICATION_SETTINGS_BODY = {
    "data": {
        "authentication_mechanism": "PLAIN",
        "disable": False,
        "fromaddress": "test-from@example.invalid",
        "ipaddress": "198.51.100.30",
        "notifyemailaddress": "test-notify@example.invalid",
        "password": "test-password",
        "port": "587",
        "ssl": True,
        "sslvalidate": True,
        "timeout": 20,
        "username": "test-smtp-user",
    }
}


_BIND_SETTINGS_BODY = {
    "data": {
        "bind_custom_options": None,
        "bind_dnssec_validation": "auto",
        "bind_forwarder": False,
        "bind_forwarder_ips": None,
        "bind_global_settings": None,
        "bind_hide_version": False,
        "bind_ip_version": None,
        "bind_logging": False,
        "bind_notify": False,
        "bind_ram_limit": "256M",
        "controlport": "953",
        "enable_bind": False,
        "listenon": ["All"],
        "listenport": "53",
        "log_only": False,
        "log_options": ["default"],
        "log_severity": "critical",
        "rate_enabled": False,
        "rate_limit": None,
    }
}


_NTP_SETTINGS_BODY = {
    "data": {
        "clockstats": False,
        "dnsresolv": "auto",
        "enable": True,
        "interface": None,
        "leapsec": None,
        "logpeer": False,
        "logsys": False,
        "loopstats": False,
        "ntpmaxpeers": 5,
        "ntpmaxpoll": None,
        "ntpminpoll": None,
        "orphan": 12,
        "peerstats": False,
        "serverauth": False,
        "serverauthalgo": "md5",
        "statsgraph": False,
    }
}


_NTP_TIME_SERVERS_BODY = {
    "data": [
        {
            "id": 0,
            "noselect": False,
            "prefer": False,
            "timeserver": "test.pool.ntp.example.invalid",
            "type": "server",
        }
    ]
}


_SSH_SETTINGS_BODY = {
    "data": {
        "enable": True,
        "port": "22",
        "sshdagentforwarding": False,
        "sshdkeyonly": None,
    }
}


_CRON_JOBS_BODY = {
    "data": [
        {
            "command": "/usr/sbin/newsyslog",
            "hour": "*",
            "id": 0,
            "mday": "*",
            "minute": "*/1",
            "month": "*",
            "wday": "*",
            "who": "root",
        }
    ]
}


_ACME_SETTINGS_BODY = {"data": {"enable": False, "writecerts": False}}


_SYSTEM_RESTAPI_SETTINGS_BODY = {
    "data": {
        "allow_development_packages": False,
        "allow_pre_releases": False,
        "allowed_interfaces": ["lan"],
        "auth_methods": ["BasicAuth", "KeyAuth"],
        "enabled": True,
        "expose_sensitive_fields": False,
        "ha_sync": False,
        "ha_sync_hosts": [],
        "ha_sync_username": "",
        "ha_sync_validate_certs": False,
        "hateoas": False,
        "jwt_exp": 3600,
        "keep_backup": True,
        "log_level": "LOG_WARNING",
        "log_successful_auth": True,
        "login_protection": True,
        "override_sensitive_fields": [],
        "read_only": True,
        "represent_interfaces_as": "id",
    }
}


_SYSTEM_HASYNC_BODY = {
    "data": {
        "adminsync": False,
        "pfhostid": None,
        "pfsyncenabled": False,
        "pfsyncinterface": "lo0",
        "pfsyncpeerip": None,
        "synchronizealiases": False,
        "synchronizeauthservers": False,
        "synchronizecaptiveportal": False,
        "synchronizecerts": False,
        "synchronizedhcpd": False,
        "synchronizedhcpdv6": False,
        "synchronizedhcrelay": False,
        "synchronizedhcrelay6": False,
        "synchronizednsforwarder": False,
        "synchronizeipsec": False,
        "synchronizekea6": False,
        "synchronizenat": False,
        "synchronizeopenvpn": False,
        "synchronizerules": False,
        "synchronizeschedules": False,
        "synchronizestaticroutes": False,
        "synchronizetoip": None,
        "synchronizetrafficshaper": False,
        "synchronizetrafficshaperlimiter": False,
        "synchronizeusers": False,
        "synchronizevirtualip": False,
        "synchronizewol": False,
        "username": None,
    }
}


def _client(
    *,
    with_interfaces: bool = False,
    with_gateways: bool = False,
    with_firewall: bool = False,
    with_alias: bool = False,
    with_service: bool = False,
    with_system_version: bool = False,
    with_interface_configs: bool = False,
    with_nat_port_forwards: bool = False,
    with_nat_outbound_mode: bool = False,
    with_users: bool = False,
    with_system_certificates: bool = False,
    with_user_groups: bool = False,
    with_dhcp_leases: bool = False,
    with_dhcp_static_mappings: bool = False,
    with_dhcp_servers: bool = False,
    with_interface_bridges: bool = False,
    with_carp_status: bool = False,
    with_system_restapi_settings: bool = False,
    with_system_hasync: bool = False,
    with_dns_resolver_host_overrides: bool = False,
    with_dns_resolver_settings: bool = False,
    with_arp_table: bool = False,
    with_traffic_shaper_limiters: bool = False,
    with_firewall_advanced_settings: bool = False,
    with_system_packages: bool = False,
    with_system_tunables: bool = False,
    with_email_notification_settings: bool = False,
    with_bind_settings: bool = False,
    with_ntp_settings: bool = False,
    with_ntp_time_servers: bool = False,
    with_ssh_settings: bool = False,
    with_cron_jobs: bool = False,
    with_acme_settings: bool = False,
) -> PfSenseClient:
    transport = MockTransport()
    body = {
        "data": {
            "platform": "Netgate pfSense Plus",
            "uptime": "1 Hour",
            "cpu_model": "x",
            "cpu_count": 1,
            "cpu_usage": 1.0,
            "mem_usage": 1,
            "swap_usage": 0,
            "disk_usage": 1,
        }
    }
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    if with_interfaces:
        transport.register("GET", "/api/v2/status/interfaces", status_code=200, text=json.dumps(_INTERFACES_BODY))
    if with_gateways:
        transport.register("GET", "/api/v2/routing/gateways", status_code=200, text=json.dumps(_GATEWAYS_BODY))
        transport.register("GET", "/api/v2/status/gateways", status_code=200, text=json.dumps(_GATEWAY_STATUS_BODY))
    if with_firewall:
        transport.register("GET", "/api/v2/firewall/rules", status_code=200, text=json.dumps(_FIREWALL_RULES_BODY))
        transport.register(
            "GET", "/api/v2/firewall/states?limit=100", status_code=200, text=json.dumps(_FIREWALL_STATES_BODY)
        )
        transport.register(
            "GET", "/api/v2/firewall/states/size", status_code=200, text=json.dumps(_FIREWALL_STATES_SIZE_BODY)
        )
        transport.register("GET", "/api/v2/firewall/apply", status_code=200, text=json.dumps(_FIREWALL_APPLY_BODY))
    if with_alias:
        transport.register(
            "GET", "/api/v2/firewall/aliases?limit=100", status_code=200, text=json.dumps(_FIREWALL_ALIASES_BODY)
        )
    if with_service:
        transport.register(
            "GET", "/api/v2/status/services?limit=100", status_code=200, text=json.dumps(_SERVICE_STATUS_BODY)
        )
    if with_system_version:
        transport.register("GET", "/api/v2/system/version", status_code=200, text=json.dumps(_SYSTEM_VERSION_BODY))
    if with_interface_configs:
        transport.register(
            "GET", "/api/v2/interfaces?limit=100", status_code=200, text=json.dumps(_INTERFACE_CONFIGS_BODY)
        )
    if with_nat_port_forwards:
        transport.register(
            "GET",
            "/api/v2/firewall/nat/port_forwards?limit=100",
            status_code=200,
            text=json.dumps(_FIREWALL_NAT_PORT_FORWARDS_BODY),
        )
    if with_nat_outbound_mode:
        transport.register(
            "GET", "/api/v2/firewall/nat/outbound/mode", status_code=200, text=json.dumps({"data": {"mode": "hybrid"}})
        )
    if with_users:
        transport.register("GET", "/api/v2/users?limit=100", status_code=200, text=json.dumps(_USERS_BODY))
    if with_system_certificates:
        transport.register(
            "GET",
            "/api/v2/system/certificates?limit=100",
            status_code=200,
            text=json.dumps(_SYSTEM_CERTIFICATES_BODY),
        )
    if with_user_groups:
        transport.register("GET", "/api/v2/user/groups?limit=100", status_code=200, text=json.dumps(_USER_GROUPS_BODY))
    if with_dhcp_leases:
        transport.register(
            "GET", "/api/v2/status/dhcp_server/leases?limit=100", status_code=200, text=json.dumps(_DHCP_LEASES_BODY)
        )
    if with_dhcp_static_mappings:
        transport.register(
            "GET",
            "/api/v2/services/dhcp_server/static_mappings?limit=100",
            status_code=200,
            text=json.dumps(_DHCP_STATIC_MAPPINGS_BODY),
        )
    if with_dhcp_servers:
        transport.register(
            "GET", "/api/v2/services/dhcp_servers?limit=100", status_code=200, text=json.dumps(_DHCP_SERVERS_BODY)
        )
    if with_interface_bridges:
        transport.register(
            "GET", "/api/v2/interface/bridges?limit=100", status_code=200, text=json.dumps(_INTERFACE_BRIDGES_BODY)
        )
    if with_carp_status:
        transport.register("GET", "/api/v2/status/carp", status_code=200, text=json.dumps(_STATUS_CARP_BODY))
    if with_system_restapi_settings:
        transport.register(
            "GET",
            "/api/v2/system/restapi/settings",
            status_code=200,
            text=json.dumps(_SYSTEM_RESTAPI_SETTINGS_BODY),
        )
    if with_system_hasync:
        transport.register("GET", "/api/v2/system/hasync", status_code=200, text=json.dumps(_SYSTEM_HASYNC_BODY))
    if with_dns_resolver_host_overrides:
        transport.register(
            "GET",
            "/api/v2/services/dns_resolver/host_overrides?limit=100",
            status_code=200,
            text=json.dumps(_DNS_RESOLVER_HOST_OVERRIDES_BODY),
        )
    if with_dns_resolver_settings:
        transport.register(
            "GET",
            "/api/v2/services/dns_resolver/settings",
            status_code=200,
            text=json.dumps(_DNS_RESOLVER_SETTINGS_BODY),
        )
    if with_arp_table:
        transport.register(
            "GET", "/api/v2/diagnostics/arp_table?limit=100", status_code=200, text=json.dumps(_ARP_TABLE_BODY)
        )
    if with_traffic_shaper_limiters:
        transport.register(
            "GET",
            "/api/v2/firewall/traffic_shaper/limiters?limit=100",
            status_code=200,
            text=json.dumps(_TRAFFIC_SHAPER_LIMITERS_BODY),
        )
    if with_firewall_advanced_settings:
        transport.register(
            "GET",
            "/api/v2/firewall/advanced_settings",
            status_code=200,
            text=json.dumps(_FIREWALL_ADVANCED_SETTINGS_BODY),
        )
    if with_system_packages:
        transport.register(
            "GET", "/api/v2/system/packages?limit=100", status_code=200, text=json.dumps(_SYSTEM_PACKAGES_BODY)
        )
    if with_system_tunables:
        transport.register(
            "GET", "/api/v2/system/tunables?limit=100", status_code=200, text=json.dumps(_SYSTEM_TUNABLES_BODY)
        )
    if with_email_notification_settings:
        transport.register(
            "GET",
            "/api/v2/system/notifications/email_settings",
            status_code=200,
            text=json.dumps(_EMAIL_NOTIFICATION_SETTINGS_BODY),
        )
    if with_bind_settings:
        transport.register(
            "GET", "/api/v2/services/bind/settings", status_code=200, text=json.dumps(_BIND_SETTINGS_BODY)
        )
    if with_ntp_settings:
        transport.register("GET", "/api/v2/services/ntp/settings", status_code=200, text=json.dumps(_NTP_SETTINGS_BODY))
    if with_ntp_time_servers:
        transport.register(
            "GET",
            "/api/v2/services/ntp/time_servers?limit=100",
            status_code=200,
            text=json.dumps(_NTP_TIME_SERVERS_BODY),
        )
    if with_ssh_settings:
        transport.register("GET", "/api/v2/services/ssh", status_code=200, text=json.dumps(_SSH_SETTINGS_BODY))
    if with_cron_jobs:
        transport.register(
            "GET", "/api/v2/services/cron/jobs?limit=100", status_code=200, text=json.dumps(_CRON_JOBS_BODY)
        )
    if with_acme_settings:
        transport.register(
            "GET", "/api/v2/services/acme/settings", status_code=200, text=json.dumps(_ACME_SETTINGS_BODY)
        )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client)


def test_registry_registers_system_status_tool_when_capability_present():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_status"


def test_registry_registers_nothing_when_no_capabilities():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset())
    registry.register_all()
    assert mcp.registered == []


def test_registered_tool_invokes_client_and_returns_status():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    tool_fn = mcp.registered[0]
    status = tool_fn()
    assert status.platform == "Netgate pfSense Plus"
    assert status.netgate_id is None


def test_registry_registers_interfaces_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_interfaces"


def test_registry_does_not_register_interfaces_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_interfaces" not in names


def test_registry_registers_both_tools_when_both_capabilities_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True)
    registry = ToolRegistry(
        mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_READ, Capability.INTERFACE_READ})
    )
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {"pfsense_get_system_status", "pfsense_get_interfaces"}


def test_registered_interfaces_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_interfaces=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_READ}))
    registry.register_all()
    tool_fn = mcp.registered[0]
    interfaces = tool_fn()
    assert len(interfaces) == 1
    assert interfaces[0].name == "wan"
    assert interfaces[0].macaddr is None
    assert interfaces[0].ipaddr is None
    assert interfaces[0].gateway is None


def test_registry_registers_both_gateway_tools_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_gateways=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.GATEWAY_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {"pfsense_get_gateways", "pfsense_get_gateway_status"}


def test_registry_does_not_register_gateway_tools_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_gateways" not in names
    assert "pfsense_get_gateway_status" not in names


def test_registered_gateways_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_gateways=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.GATEWAY_READ}))
    registry.register_all()
    gateways_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_gateways")
    gateways = gateways_fn()
    assert len(gateways) == 1
    assert gateways[0].name == "WAN_DHCP"
    assert gateways[0].gateway is None
    assert gateways[0].monitor is None


def test_registered_gateway_status_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_gateways=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.GATEWAY_READ}))
    registry.register_all()
    status_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_gateway_status")
    statuses = status_fn()
    assert len(statuses) == 1
    assert statuses[0].name == "WAN_DHCP"
    assert statuses[0].srcip is None
    assert statuses[0].monitorip is None


def test_registry_registers_all_firewall_tools_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {
        "pfsense_get_firewall_rules",
        "pfsense_get_firewall_states",
        "pfsense_get_firewall_states_size",
        "pfsense_get_firewall_apply_status",
    }


def test_registry_does_not_register_firewall_tools_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_rules" not in names
    assert "pfsense_get_firewall_states" not in names
    assert "pfsense_get_firewall_states_size" not in names
    assert "pfsense_get_firewall_apply_status" not in names


def test_registered_firewall_rules_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    rules_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_rules")
    rules = rules_fn()
    assert len(rules) == 1
    assert rules[0].descr == "Allow HTTPS"
    assert rules[0].source is None
    assert rules[0].destination is None
    assert rules[0].created_by is None
    assert rules[0].updated_by is None


def test_registered_firewall_states_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    states_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_states")
    states = states_fn()
    assert len(states) == 1
    assert states[0].interface == "wan"
    assert states[0].source is None
    assert states[0].destination is None


def test_registered_firewall_states_size_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    size_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_states_size")
    size = size_fn()
    assert size.currentstates == 42


def test_registered_firewall_apply_status_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    apply_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_apply_status")
    status = apply_fn()
    assert status.applied is True
    assert status.pending_subsystems == []


def test_registry_registers_firewall_aliases_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_alias=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.ALIAS_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_firewall_aliases"


def test_registry_does_not_register_firewall_aliases_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_aliases" not in names


def test_registered_firewall_aliases_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_alias=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.ALIAS_READ}))
    registry.register_all()
    aliases_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_aliases")
    aliases = aliases_fn()
    assert len(aliases) == 1
    assert aliases[0].name == "IPTV"
    assert aliases[0].descr == "TWE"
    assert aliases[0].address is None
    assert aliases[0].detail is None


def test_registry_registers_service_status_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_service=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_service_status"


def test_registry_does_not_register_service_status_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_service_status" not in names


def test_registered_service_status_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_service=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICE_READ}))
    registry.register_all()
    service_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_service_status")
    services = service_fn()
    assert len(services) == 1
    assert services[0].name == "unbound"
    assert services[0].description == "DNS Resolver"
    assert services[0].enabled is True
    assert services[0].status is True


def test_registry_registers_system_version_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_system_version=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_INFO_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_version"


def test_registry_does_not_register_system_version_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_system_version" not in names


def test_registered_system_version_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_system_version=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_INFO_READ}))
    registry.register_all()
    version_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_system_version")
    result = version_fn()
    assert result.base == "26.03.1"
    assert result.buildtime == "20260731-1801"
    assert result.patch == "0"
    assert result.version == "26.03.1-RELEASE"


def test_registry_registers_interface_configs_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_interface_configs=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_CONFIG_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_interface_configs"


def test_registry_does_not_register_interface_configs_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_interface_configs" not in names


def test_registered_interface_configs_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_interface_configs=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_CONFIG_READ}))
    registry.register_all()
    configs_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_interface_configs")
    configs = configs_fn()
    assert len(configs) == 1
    assert configs[0].id == "wan"
    assert configs[0].if_ == "igb0"
    assert configs[0].descr == "WAN"
    assert configs[0].ipaddr is None
    assert configs[0].dhcphostname is None


def test_registry_registers_nat_port_forwards_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_nat_port_forwards=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_NAT_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert "pfsense_get_firewall_nat_port_forwards" in names


def test_registry_does_not_register_nat_port_forwards_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_nat_port_forwards" not in names


def test_registered_nat_port_forwards_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_nat_port_forwards=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_NAT_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_nat_port_forwards")
    rules = fn()
    assert len(rules) == 1
    assert rules[0].descr == "DelugeTorrent"
    assert rules[0].target is None
    assert rules[0].created_by is None


def test_registry_registers_nat_outbound_mode_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_nat_outbound_mode=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_NAT_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert "pfsense_get_firewall_nat_outbound_mode" in names


def test_registry_does_not_register_nat_outbound_mode_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_nat_outbound_mode" not in names


def test_registered_nat_outbound_mode_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_nat_outbound_mode=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_NAT_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_nat_outbound_mode")
    result = fn()
    assert result.mode == "hybrid"


def test_registry_registers_users_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_users=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.USER_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_users"


def test_registry_does_not_register_users_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_users" not in names


def test_registered_users_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_users=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.USER_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_users")
    users = fn()
    assert len(users) == 1
    assert users[0].id == 0
    assert users[0].scope == "system"
    assert users[0].name == "testuser"
    assert users[0].descr == "Test Account"
    assert users[0].uid == 0
    assert users[0].priv == ["test-priv"]
    assert users[0].authorizedkeys is None
    assert users[0].ipsecpsk is None
    assert users[0].cert is None


def test_registry_registers_system_certificates_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_system_certificates=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_CERTIFICATE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_certificates"


def test_registry_does_not_register_system_certificates_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_system_certificates" not in names


def test_registered_system_certificates_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_system_certificates=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_CERTIFICATE_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_system_certificates")
    certs = fn()
    assert len(certs) == 1
    assert certs[0].descr == "Test Certificate"
    assert certs[0].type == "server"
    assert certs[0].crt.startswith("-----BEGIN CERTIFICATE-----")


def test_registry_registers_user_groups_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_user_groups=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.USER_GROUP_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_user_groups"


def test_registry_does_not_register_user_groups_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_user_groups" not in names


def test_registered_user_groups_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_user_groups=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.USER_GROUP_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_user_groups")
    groups = fn()
    assert len(groups) == 1
    assert groups[0].name == "testgroup"
    assert groups[0].member == ["testuser"]
    assert groups[0].priv == ["page-all"]


def test_registry_registers_dhcp_leases_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_dhcp_leases=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DHCP_LEASE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_dhcp_leases"


def test_registry_does_not_register_dhcp_leases_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_dhcp_leases" not in names


def test_registered_dhcp_leases_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_dhcp_leases=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DHCP_LEASE_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_dhcp_leases")
    leases = fn()
    assert len(leases) == 1
    assert leases[0].ip == "198.51.100.10"
    assert leases[0].mac == "02:00:00:00:00:01"
    assert leases[0].hostname == "testhost"


def test_registry_registers_dhcp_static_mappings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_dhcp_static_mappings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DHCP_STATIC_MAPPING_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_dhcp_static_mappings"


def test_registry_does_not_register_dhcp_static_mappings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_dhcp_static_mappings" not in names


def test_registered_dhcp_static_mappings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_dhcp_static_mappings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DHCP_STATIC_MAPPING_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_dhcp_static_mappings")
    mappings = fn()
    assert len(mappings) == 1
    assert mappings[0].mac == "02:00:00:00:00:01"
    assert mappings[0].ipaddr == "198.51.100.10"
    assert mappings[0].hostname == "testhost"


def test_registry_registers_dhcp_servers_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_dhcp_servers=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DHCP_SERVER_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_dhcp_servers"


def test_registry_does_not_register_dhcp_servers_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_dhcp_servers" not in names


def test_registered_dhcp_servers_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_dhcp_servers=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DHCP_SERVER_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_dhcp_servers")
    servers = fn()
    assert len(servers) == 1
    assert servers[0].id == "lan"
    assert servers[0].range_from == "198.51.100.10"
    assert servers[0].range_to == "198.51.100.11"


def test_registry_registers_interface_bridges_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_interface_bridges=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_VIRTUAL_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_interface_bridges"


def test_registry_does_not_register_interface_bridges_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_interface_bridges" not in names


def test_registered_interface_bridges_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_interface_bridges=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_VIRTUAL_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_interface_bridges")
    bridges = fn()
    assert len(bridges) == 1
    assert bridges[0].bridgeif == "bridge0"
    assert bridges[0].members == ["opt1", "opt2"]


def test_registry_registers_carp_status_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_carp_status=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.STATUS_CARP_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_carp_status"


def test_registry_does_not_register_carp_status_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_carp_status" not in names


def test_registered_carp_status_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_carp_status=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.STATUS_CARP_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_carp_status")
    status = fn()
    assert status.enable is False
    assert status.maintenance_mode is False


def test_registry_registers_system_restapi_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_system_restapi_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_RESTAPI_SETTINGS_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_restapi_settings"


def test_registry_does_not_register_system_restapi_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_system_restapi_settings" not in names


def test_registered_system_restapi_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_system_restapi_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_RESTAPI_SETTINGS_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_system_restapi_settings")
    settings = fn()
    assert settings.enabled is True
    assert settings.ha_sync_username is None


def test_registry_registers_system_hasync_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_system_hasync=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_HA_SYNC_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_hasync"


def test_registry_does_not_register_system_hasync_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_system_hasync" not in names


def test_registered_system_hasync_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_system_hasync=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_HA_SYNC_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_system_hasync")
    hasync = fn()
    assert hasync.pfsyncinterface == "lo0"
    assert hasync.username is None


def test_registry_registers_all_tools_when_all_capabilities_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True, with_gateways=True, with_firewall=True)
    registry = ToolRegistry(
        mcp,
        client,
        "api-mcp-admin",
        frozenset(
            {
                Capability.SYSTEM_READ,
                Capability.INTERFACE_READ,
                Capability.GATEWAY_READ,
                Capability.FIREWALL_READ,
            }
        ),
    )
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {
        "pfsense_get_system_status",
        "pfsense_get_interfaces",
        "pfsense_get_gateways",
        "pfsense_get_gateway_status",
        "pfsense_get_firewall_rules",
        "pfsense_get_firewall_states",
        "pfsense_get_firewall_states_size",
        "pfsense_get_firewall_apply_status",
    }


def test_registry_registers_dns_resolver_host_overrides_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_dns_resolver_host_overrides=True, with_dns_resolver_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_DNS_RESOLVER_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert "pfsense_get_dns_resolver_host_overrides" in names


def test_registry_does_not_register_dns_resolver_host_overrides_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_dns_resolver_host_overrides" not in names


def test_registered_dns_resolver_host_overrides_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_dns_resolver_host_overrides=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_DNS_RESOLVER_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_dns_resolver_host_overrides")
    overrides = fn()
    assert len(overrides) == 1
    assert overrides[0].host == "test-host"
    assert overrides[0].domain == "example.invalid"


def test_registry_registers_dns_resolver_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_dns_resolver_host_overrides=True, with_dns_resolver_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_DNS_RESOLVER_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert "pfsense_get_dns_resolver_settings" in names


def test_registry_does_not_register_dns_resolver_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_dns_resolver_settings" not in names


def test_registered_dns_resolver_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_dns_resolver_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_DNS_RESOLVER_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_dns_resolver_settings")
    settings = fn()
    assert settings.enable is True
    assert settings.dnssec is True
    assert settings.sslcertref == "test-sslcertref"


def test_registry_registers_arp_table_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_arp_table=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DIAGNOSTICS_ARP_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_arp_table"


def test_registry_does_not_register_arp_table_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_arp_table" not in names


def test_registered_arp_table_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_arp_table=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.DIAGNOSTICS_ARP_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_arp_table")
    entries = fn()
    assert len(entries) == 1
    assert entries[0].hostname == "test-host"
    assert entries[0].ip_address == "198.51.100.10"


def test_registry_registers_firewall_traffic_shaper_limiters_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_traffic_shaper_limiters=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_TRAFFIC_SHAPER_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_firewall_traffic_shaper_limiters"


def test_registry_does_not_register_firewall_traffic_shaper_limiters_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_traffic_shaper_limiters" not in names


def test_registered_firewall_traffic_shaper_limiters_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_traffic_shaper_limiters=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_TRAFFIC_SHAPER_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_traffic_shaper_limiters")
    limiters = fn()
    assert len(limiters) == 1
    assert limiters[0].name == "test-limiter"
    assert limiters[0].sched == "fq_codel"


def test_registry_registers_firewall_advanced_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_firewall_advanced_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_ADVANCED_SETTINGS_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_firewall_advanced_settings"


def test_registry_does_not_register_firewall_advanced_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_advanced_settings" not in names


def test_registered_firewall_advanced_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_firewall_advanced_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_ADVANCED_SETTINGS_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_advanced_settings")
    settings = fn()
    assert settings.aliasesresolveinterval == 300
    assert settings.checkaliasesurlcert is True


def test_registry_registers_system_packages_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_system_packages=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_PACKAGE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_packages"


def test_registry_does_not_register_system_packages_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_system_packages" not in names


def test_registered_system_packages_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_system_packages=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_PACKAGE_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_system_packages")
    packages = fn()
    assert len(packages) == 1
    assert packages[0].name == "pfSense-pkg-Test"
    assert packages[0].installed_version == "1.0.0"


def test_registry_registers_system_tunables_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_system_tunables=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_TUNABLE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_tunables"


def test_registry_does_not_register_system_tunables_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_system_tunables" not in names


def test_registered_system_tunables_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_system_tunables=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_TUNABLE_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_system_tunables")
    tunables = fn()
    assert len(tunables) == 1
    assert tunables[0].tunable == "net.inet.tcp.test"
    assert tunables[0].value == "1"


def test_registry_registers_email_notification_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_email_notification_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_NOTIFICATIONS_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_email_notification_settings"


def test_registry_does_not_register_email_notification_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_email_notification_settings" not in names


def test_registered_email_notification_settings_tool_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_email_notification_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_NOTIFICATIONS_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_email_notification_settings")
    settings = fn()
    assert settings.disable is False
    assert settings.port == "587"
    assert settings.username is None
    assert settings.password is None
    assert settings.fromaddress is None
    assert settings.notifyemailaddress is None
    assert settings.ipaddress is None


def test_registered_email_notification_settings_tool_reveals_identifying_metadata_when_requested():
    mcp = FakeMCP()
    client = _client(with_email_notification_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_NOTIFICATIONS_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_email_notification_settings")
    settings = fn(include_identifying_metadata=True)
    assert settings.username == "test-smtp-user"
    assert settings.password == "test-password"
    assert settings.fromaddress == "test-from@example.invalid"


def test_registry_registers_bind_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_bind_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_BIND_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_bind_settings"


def test_registry_does_not_register_bind_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_bind_settings" not in names


def test_registered_bind_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_bind_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_BIND_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_bind_settings")
    settings = fn()
    assert settings.enable_bind is False
    assert settings.listenport == "53"


def test_registry_registers_ntp_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_ntp_settings=True, with_ntp_time_servers=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_NTP_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert "pfsense_get_ntp_settings" in names


def test_registry_does_not_register_ntp_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_ntp_settings" not in names
    assert "pfsense_get_ntp_time_servers" not in names


def test_registered_ntp_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_ntp_settings=True, with_ntp_time_servers=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_NTP_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_ntp_settings")
    settings = fn()
    assert settings.enable is True
    assert settings.ntpmaxpeers == 5


def test_registry_registers_ntp_time_servers_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_ntp_settings=True, with_ntp_time_servers=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_NTP_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert "pfsense_get_ntp_time_servers" in names


def test_registered_ntp_time_servers_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_ntp_settings=True, with_ntp_time_servers=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_NTP_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_ntp_time_servers")
    servers = fn()
    assert len(servers) == 1
    assert servers[0].timeserver == "test.pool.ntp.example.invalid"


def test_registry_registers_ssh_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_ssh_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_SSH_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_ssh_settings"


def test_registry_does_not_register_ssh_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_ssh_settings" not in names


def test_registered_ssh_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_ssh_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_SSH_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_ssh_settings")
    settings = fn()
    assert settings.enable is True
    assert settings.port == "22"


def test_registry_registers_cron_jobs_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_cron_jobs=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_CRON_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_cron_jobs"


def test_registry_does_not_register_cron_jobs_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_cron_jobs" not in names


def test_registered_cron_jobs_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_cron_jobs=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_CRON_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_cron_jobs")
    jobs = fn()
    assert len(jobs) == 1
    assert jobs[0].command == "/usr/sbin/newsyslog"
    assert jobs[0].who == "root"


def test_registry_registers_acme_settings_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_acme_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_ACME_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_acme_settings"


def test_registry_does_not_register_acme_settings_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_acme_settings" not in names


def test_registered_acme_settings_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_acme_settings=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.SERVICES_ACME_READ}))
    registry.register_all()
    fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_acme_settings")
    settings = fn()
    assert settings.enable is False
    assert settings.writecerts is False
