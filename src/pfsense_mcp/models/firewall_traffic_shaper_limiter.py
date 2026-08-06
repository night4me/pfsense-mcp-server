"""Model for the FirewallTrafficShaperLimiter capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class FirewallTrafficShaperLimiter(BaseModel):
    aqm: str
    bandwidth: list[Any]
    buckets: int | None
    delay: int | None
    description: str
    ecn: bool | None
    enabled: bool
    id: int
    mask: str
    maskbits: int
    maskbitsv6: int
    name: str
    number: int | None
    param_codel_interval: int
    param_codel_target: int
    param_fq_codel_flows: int | None
    param_fq_codel_interval: int
    param_fq_codel_limit: int | None
    param_fq_codel_quantum: int | None
    param_fq_codel_target: int
    param_fq_pie_alpha: int | None
    param_fq_pie_beta: int | None
    param_fq_pie_flows: int | None
    param_fq_pie_limit: int | None
    param_fq_pie_max_burst: int | None
    param_fq_pie_max_ecnth: int | None
    param_fq_pie_quantum: int | None
    param_fq_pie_target: int | None
    param_fq_pie_tupdate: int | None
    param_gred_max_p: int | None
    param_gred_max_th: int | None
    param_gred_min_th: int | None
    param_gred_w_q: int | None
    param_pie_alpha: int | None
    param_pie_beta: int | None
    param_pie_max_burst: int | None
    param_pie_max_ecnth: int | None
    param_pie_target: int | None
    param_pie_tupdate: int | None
    param_red_max_p: int | None
    param_red_max_th: int | None
    param_red_min_th: int | None
    param_red_w_q: int | None
    pie_capdrop: bool | None
    pie_onoff: bool | None
    pie_pderand: bool | None
    pie_qdelay: bool | None
    plr: float | None
    qlimit: int | None
    queue: list[Any]
    sched: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FirewallTrafficShaperLimiter":
        return cls(
            aqm=data["aqm"],
            bandwidth=data["bandwidth"],
            buckets=data["buckets"],
            delay=data["delay"],
            description=data["description"],
            ecn=data["ecn"],
            enabled=data["enabled"],
            id=data["id"],
            mask=data["mask"],
            maskbits=data["maskbits"],
            maskbitsv6=data["maskbitsv6"],
            name=data["name"],
            number=data["number"],
            param_codel_interval=data["param_codel_interval"],
            param_codel_target=data["param_codel_target"],
            param_fq_codel_flows=data["param_fq_codel_flows"],
            param_fq_codel_interval=data["param_fq_codel_interval"],
            param_fq_codel_limit=data["param_fq_codel_limit"],
            param_fq_codel_quantum=data["param_fq_codel_quantum"],
            param_fq_codel_target=data["param_fq_codel_target"],
            param_fq_pie_alpha=data["param_fq_pie_alpha"],
            param_fq_pie_beta=data["param_fq_pie_beta"],
            param_fq_pie_flows=data["param_fq_pie_flows"],
            param_fq_pie_limit=data["param_fq_pie_limit"],
            param_fq_pie_max_burst=data["param_fq_pie_max_burst"],
            param_fq_pie_max_ecnth=data["param_fq_pie_max_ecnth"],
            param_fq_pie_quantum=data["param_fq_pie_quantum"],
            param_fq_pie_target=data["param_fq_pie_target"],
            param_fq_pie_tupdate=data["param_fq_pie_tupdate"],
            param_gred_max_p=data["param_gred_max_p"],
            param_gred_max_th=data["param_gred_max_th"],
            param_gred_min_th=data["param_gred_min_th"],
            param_gred_w_q=data["param_gred_w_q"],
            param_pie_alpha=data["param_pie_alpha"],
            param_pie_beta=data["param_pie_beta"],
            param_pie_max_burst=data["param_pie_max_burst"],
            param_pie_max_ecnth=data["param_pie_max_ecnth"],
            param_pie_target=data["param_pie_target"],
            param_pie_tupdate=data["param_pie_tupdate"],
            param_red_max_p=data["param_red_max_p"],
            param_red_max_th=data["param_red_max_th"],
            param_red_min_th=data["param_red_min_th"],
            param_red_w_q=data["param_red_w_q"],
            pie_capdrop=data["pie_capdrop"],
            pie_onoff=data["pie_onoff"],
            pie_pderand=data["pie_pderand"],
            pie_qdelay=data["pie_qdelay"],
            plr=data["plr"],
            qlimit=data["qlimit"],
            queue=data["queue"],
            sched=data["sched"],
        )
