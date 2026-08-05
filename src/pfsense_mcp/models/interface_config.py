"""Model for the InterfaceConfig capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_INTERFACE_CONFIG_IDENTIFYING_FIELDS = (
    "alias_address",
    "dhcphostname",
    "gateway",
    "gatewayv6",
    "ipaddr",
    "ipaddrv6",
    "spoofmac",
    "subnet",
    "subnetv6",
)


class InterfaceConfig(BaseModel):
    adv_dhcp_config_advanced: bool | None
    adv_dhcp_config_file_override: bool | None
    adv_dhcp_config_file_override_path: str | None
    adv_dhcp_option_modifiers: str | None
    adv_dhcp_pt_backoff_cutoff: int | None
    adv_dhcp_pt_initial_interval: int | None
    adv_dhcp_pt_reboot: int | None
    adv_dhcp_pt_retry: int | None
    adv_dhcp_pt_select_timeout: int | None
    adv_dhcp_pt_timeout: int | None
    adv_dhcp_pt_values: str | None
    adv_dhcp_request_options: str | None
    adv_dhcp_required_options: str | None
    adv_dhcp_send_options: str | None
    alias_subnet: int | None
    blockbogons: bool
    blockpriv: bool
    descr: str
    dhcprejectfrom: list[str] | None
    enable: bool
    gateway_6rd: str | None
    id: str
    if_: str
    ipv6usev4iface: bool | None
    media: str | None
    mediaopt: str | None
    mss: int | None
    mtu: int | None
    prefix_6rd: str | None
    prefix_6rd_v4plen: int | None
    slaacusev4iface: bool | None
    track6_interface: str | None
    track6_prefix_id_hex: str | None
    typev4: str
    typev6: str | None
    alias_address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    dhcphostname: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    gateway: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    gatewayv6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    ipaddr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    ipaddrv6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    spoofmac: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    subnet: int | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    subnetv6: int | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "InterfaceConfig":
        identifying = {field: data[field] for field in _INTERFACE_CONFIG_IDENTIFYING_FIELDS}
        return cls(
            adv_dhcp_config_advanced=data["adv_dhcp_config_advanced"],
            adv_dhcp_config_file_override=data["adv_dhcp_config_file_override"],
            adv_dhcp_config_file_override_path=data["adv_dhcp_config_file_override_path"],
            adv_dhcp_option_modifiers=data["adv_dhcp_option_modifiers"],
            adv_dhcp_pt_backoff_cutoff=data["adv_dhcp_pt_backoff_cutoff"],
            adv_dhcp_pt_initial_interval=data["adv_dhcp_pt_initial_interval"],
            adv_dhcp_pt_reboot=data["adv_dhcp_pt_reboot"],
            adv_dhcp_pt_retry=data["adv_dhcp_pt_retry"],
            adv_dhcp_pt_select_timeout=data["adv_dhcp_pt_select_timeout"],
            adv_dhcp_pt_timeout=data["adv_dhcp_pt_timeout"],
            adv_dhcp_pt_values=data["adv_dhcp_pt_values"],
            adv_dhcp_request_options=data["adv_dhcp_request_options"],
            adv_dhcp_required_options=data["adv_dhcp_required_options"],
            adv_dhcp_send_options=data["adv_dhcp_send_options"],
            alias_subnet=data["alias_subnet"],
            blockbogons=data["blockbogons"],
            blockpriv=data["blockpriv"],
            descr=data["descr"],
            dhcprejectfrom=data["dhcprejectfrom"],
            enable=data["enable"],
            gateway_6rd=data["gateway_6rd"],
            id=data["id"],
            if_=data["if"],
            ipv6usev4iface=data["ipv6usev4iface"],
            media=data["media"],
            mediaopt=data["mediaopt"],
            mss=data["mss"],
            mtu=data["mtu"],
            prefix_6rd=data["prefix_6rd"],
            prefix_6rd_v4plen=data["prefix_6rd_v4plen"],
            slaacusev4iface=data["slaacusev4iface"],
            track6_interface=data["track6_interface"],
            track6_prefix_id_hex=data["track6_prefix_id_hex"],
            typev4=data["typev4"],
            typev6=data["typev6"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
