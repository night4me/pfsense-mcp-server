"""Local server health diagnostics.

Reports configuration validity, TLS mode, active API version,
registered capabilities, and transport type — using only state
already resolved during startup. Never contacts pfSense.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import PfSenseConfig


@dataclass(frozen=True)
class DiagnosticsReport:
    identity: str
    profile_name: str
    capabilities: tuple[str, ...]
    tls_mode: str
    api_version: str
    transport_type: str
    log_max_bytes: int
    log_backup_count: int


def build_diagnostics_report(config: PfSenseConfig, transport_type: str) -> DiagnosticsReport:
    return DiagnosticsReport(
        identity=config.identity,
        profile_name=config.profile.name,
        capabilities=tuple(sorted(c.name for c in config.profile.capabilities)),
        tls_mode=config.tls_mode.value,
        api_version=config.api_version.value,
        transport_type=transport_type,
        log_max_bytes=config.log_max_bytes,
        log_backup_count=config.log_backup_count,
    )
