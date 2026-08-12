"""Live, lab-only ADR-026 alias-description evidence runner.

This module is deliberately outside the production package and is never
imported by MCP startup. It exposes one closed semantic unit and one exact
configured candidate. Every cycle reruns LAB-T1's read-only safety gate before
constructing a throwaway RecoveryContract and MutationExecutor.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tier1.canonical import CanonicalValue, DigestPurpose, digest_value
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.contract import RecoveryContract
from pfsense_mcp.tier1.executor import MutationExecutor, ResolvedTransportTarget
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.transport.http import HttpTransport
from pfsense_mcp.write_api_client import WriteApiClient
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

from .config import LabConfig, load_lab_config, load_lab_key_material
from .harness import ScenarioSetup, evidence_from_confirmation, prepare_contract
from .safety import LabPreflightReport, load_lab_attestation, run_read_only_preflight

SEMANTIC_UNIT = "set_firewall_alias_description_v1"
ENDPOINT_SYMBOL = "FIREWALL_ALIAS_DESCRIPTION"
HTTP_METHOD = "PATCH"
ROLLBACK_VERSION = "firewall-alias-description-rollback-v1"
_LAB_PROOF = b"lab-b3a-owner-authorized-proof"


class AliasDescriptionRequest(BaseModel):
    """The complete allowed PATCH body; arbitrary sibling fields are impossible."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: StrictInt
    descr: StrictStr
    apply: StrictBool = False


@dataclass(frozen=True)
class AliasState:
    name: str
    numeric_locator: int
    alias_type: str
    descr: str
    address: tuple[str, ...]
    detail: tuple[str, ...]

    @classmethod
    def from_model(cls, alias: FirewallAlias) -> "AliasState":
        if alias.address is None or alias.detail is None or len(alias.address) != len(alias.detail):
            raise RuntimeError("authoritative alias state is incomplete")
        return cls(alias.name, alias.id, alias.type, alias.descr, tuple(alias.address), tuple(alias.detail))

    def identity(self) -> dict[str, CanonicalValue]:
        return {"alias_name": self.name}

    def fingerprint(self) -> dict[str, CanonicalValue]:
        return {
            "name": self.name,
            "type": self.alias_type,
            "descr": self.descr,
            "address": list(self.address),
            "detail": list(self.detail),
        }

    def sanitized(self) -> dict[str, object]:
        return {
            "name": self.name,
            "numeric_locator": self.numeric_locator,
            "type": self.alias_type,
            "description": self.descr,
            "member_count": len(self.address),
            "detail_count": len(self.detail),
            "fingerprint_digest": digest_value(DigestPurpose.TARGET_FINGERPRINT, self.fingerprint()),
        }


class AliasDescriptionAdapter:
    capability = Capability.ALIAS_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(self, read_client: PfSenseClient, natural_identity: CanonicalValue) -> AliasState:
        if not isinstance(natural_identity, dict) or set(natural_identity) != {"alias_name"}:
            raise RuntimeError("semantic alias identity is malformed")
        name = natural_identity["alias_name"]
        if not isinstance(name, str):
            raise RuntimeError("semantic alias identity is malformed")
        aliases = read_client.get_firewall_aliases(include_identifying_metadata=True, limit=500)
        matches = [AliasState.from_model(alias) for alias in aliases if alias.name == name]
        if len(matches) != 1:
            raise RuntimeError("semantic alias target did not resolve exactly once")
        return matches[0]

    def natural_identity(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).identity()

    def fingerprint(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).fingerprint()

    def transport_locator(self, raw_target: object) -> int:
        return self._state(raw_target).numeric_locator

    def build_request(self, intent: object, target: ResolvedTransportTarget) -> BaseModel:
        if not isinstance(intent, dict) or set(intent) != {"descr"} or not isinstance(intent["descr"], str):
            raise RuntimeError("protected alias-description intent is malformed")
        return AliasDescriptionRequest(id=target.numeric_locator, descr=intent["descr"], apply=False)

    def parse_response(self, raw_response: object) -> object:
        status = getattr(raw_response, "status_code", None)
        return {"accepted_status": status}

    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool:
        before, after = self._state(pre), self._state(post)
        if not isinstance(intent, dict) or not isinstance(intent.get("descr"), str):
            return False
        return (
            after.descr == intent["descr"]
            and before.name == after.name
            and before.alias_type == after.alias_type
            and before.address == after.address
            and before.detail == after.detail
        )

    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel:
        if not isinstance(pre, dict) or set(pre) != {"name", "type", "descr", "address", "detail"}:
            raise RuntimeError("protected alias rollback snapshot is malformed")
        description = pre["descr"]
        if not isinstance(description, str):
            raise RuntimeError("protected alias rollback description is malformed")
        return AliasDescriptionRequest(id=target.numeric_locator, descr=description, apply=False)

    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool:
        return isinstance(pre, dict) and pre == self._state(post_rollback).fingerprint()

    @staticmethod
    def _state(raw_target: object) -> AliasState:
        if isinstance(raw_target, AliasState):
            return raw_target
        if not isinstance(raw_target, dict):
            raise RuntimeError("alias target is malformed")
        required = {"name", "id", "type", "descr", "address", "detail"}
        if set(raw_target) != required:
            raise RuntimeError("alias target is malformed")
        address, detail = raw_target["address"], raw_target["detail"]
        if not isinstance(address, list) or not isinstance(detail, list):
            raise RuntimeError("alias target is malformed")
        return AliasState(
            name=raw_target["name"],
            numeric_locator=raw_target["id"],
            alias_type=raw_target["type"],
            descr=raw_target["descr"],
            address=tuple(address),
            detail=tuple(detail),
        )


class _LabVerifier:
    def verify(self, evidence: ConfirmationEvidence) -> bool:
        return evidence.algorithm == "lab-b3a-owner-authorization-v1" and evidence.proof == _LAB_PROOF


def _confirm(store: SqliteRecoveryContractStore, contract: RecoveryContract) -> RecoveryContract:
    prepared = store.transition(
        contract.contract_id,
        expected_state=RecoveryState.PREPARING,
        expected_version=contract.state_version,
        target_state=RecoveryState.PREPARED,
    )
    evidence = evidence_from_confirmation(
        contract=prepared,
        authority_id="lab-b3a-owner",
        algorithm="lab-b3a-owner-authorization-v1",
        nonce=f"nonce-{prepared.contract_id}",
        proof=_LAB_PROOF,
    )
    return store.confirm(prepared.contract_id, evidence=evidence, expected_version=prepared.state_version)


def _preflight() -> tuple[LabConfig, str, HttpTransport, PfSenseClient, LabPreflightReport]:
    config = load_lab_config()
    key = load_lab_key_material(config.key_file)
    attestation = load_lab_attestation(config)
    transport = HttpTransport(config.base_url, key, verify=True)
    rest = RestApiClient(transport, identity=config.identity, api_version=ApiVersion.V2)
    client = PfSenseClient(rest)
    try:
        report = run_read_only_preflight(config, client=client, attestation=attestation)
    except Exception:
        transport.close()
        raise
    return config, key, transport, client, report


def run_clean_cycle(cycle: int) -> dict[str, object]:
    config, _key, transport, read_client, gate = _preflight()
    adapter = AliasDescriptionAdapter()
    original = adapter.read_target(read_client, {"alias_name": config.candidate})
    if original.numeric_locator != gate.candidate.numeric_locator:
        transport.close()
        raise RuntimeError("candidate locator changed after safety gate")
    replacement = f"ADR026 B3a clean cycle {cycle:02d}"
    setup = ScenarioSetup(
        raw_target_hint={
            "name": original.name,
            "id": original.numeric_locator,
            "type": original.alias_type,
            "descr": original.descr,
            "address": list(original.address),
            "detail": list(original.detail),
        },
        intent_payload={"descr": replacement},
        snapshot_payload=original.fingerprint(),
        rollback_plan_version=ROLLBACK_VERSION,
    )
    with tempfile.TemporaryDirectory(prefix="pfsense-b3a-") as directory:
        store = SqliteRecoveryContractStore(
            Path(directory) / "contracts.sqlite3",
            integrity_key=os.urandom(32),
            store_id=f"lab-b3a-{cycle:02d}",
            confirmation_verifier=_LabVerifier(),
        )
        encryption_key = os.urandom(32)
        contract, intent = prepare_contract(
            adapter=adapter,
            setup=setup,
            encryption_key=encryption_key,
            contract_id=f"b3a-cycle-{cycle:02d}",
            operation_id=f"b3a-operation-{cycle:02d}",
        )
        store.create(contract)
        _confirm(store, contract)
        endpoint = WriteEndpointInfo(
            path_suffix="/firewall/alias",
            http_method=HTTP_METHOD,
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        )
        if hasattr(WriteEndpoints, ENDPOINT_SYMBOL):
            transport.close()
            raise RuntimeError("lab endpoint symbol unexpectedly already exists")
        setattr(WriteEndpoints, ENDPOINT_SYMBOL, endpoint)
        try:
            executor = MutationExecutor(
                store=store,
                write_client=WriteApiClient(transport, identity=config.identity, api_version=ApiVersion.V2),
                read_client=read_client,
                policy=MutationPolicy(frozenset({MutationRule(Capability.ALIAS_WRITE, ENDPOINT_SYMBOL, HTTP_METHOD)})),
                anti_rollback_anchor=None,
                encryption_key=encryption_key,
            )
            forward = executor.execute(contract.contract_id, adapter=adapter, intent=intent)
            if forward.state is not RecoveryState.VERIFIED:
                raise RuntimeError(f"forward did not verify: {forward.state.value}")
            verified_b = adapter.read_target(read_client, original.identity())
            expected_b = AliasState(
                original.name,
                original.numeric_locator,
                original.alias_type,
                replacement,
                original.address,
                original.detail,
            )
            if verified_b != expected_b:
                raise RuntimeError("authoritative post-forward state did not equal expected B")
            rollback = executor.rollback(contract.contract_id, adapter=adapter)
            if rollback.state is not RecoveryState.ROLLED_BACK:
                raise RuntimeError(f"rollback did not verify: {rollback.state.value}")
            restored = adapter.read_target(read_client, original.identity())
            if restored != original:
                raise RuntimeError("authoritative post-rollback state did not equal original A")
            return {
                "cycle": cycle,
                "gate": "PASS",
                "forward": "VERIFIED",
                "rollback": "VERIFIED",
                "restored": True,
                "a": original.sanitized(),
                "b": verified_b.sanitized(),
            }
        finally:
            delattr(WriteEndpoints, ENDPOINT_SYMBOL)
            transport.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ADR-026 lab-only evidence runner")
    parser.add_argument("command", choices=("stage-one", "clean-cycles"))
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args(argv)
    if args.command == "stage-one" and (args.start != 1 or args.count != 1):
        parser.error("stage-one is exactly cycle 1")
    if args.start < 1 or args.count < 1 or args.start + args.count - 1 > 25:
        parser.error("clean-cycle range must stay within 1..25")
    reports = [run_clean_cycle(cycle) for cycle in range(args.start, args.start + args.count)]
    print(json.dumps({"semantic_unit": SEMANTIC_UNIT, "cycles": reports}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
