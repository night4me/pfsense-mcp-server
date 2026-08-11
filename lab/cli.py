"""Read-only LAB-T1 command line entry point: ``python -m lab.cli``."""

from __future__ import annotations

import argparse
import json
import os
import sys

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.http import HttpTransport

from .config import LabConfigError, load_lab_config, load_lab_key_material
from .safety import LabSafetyError, load_lab_attestation, render_dry_run, render_evidence, run_read_only_preflight


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Strict read-only disposable-lab preflight")
    parser.add_argument("command", choices=("evidence-env", "preflight", "dry-run"))
    parser.add_argument("--test-case-id", default="not-specified")
    return parser


def _environment_status() -> dict[str, object]:
    names = (
        "PFSENSE_LAB_API_URL",
        "PFSENSE_LAB_IDENTITY",
        "PFSENSE_LAB_API_KEY_FILE",
        "PFSENSE_LAB_CANDIDATE",
        "PFSENSE_LAB_ATTESTATION_FILE",
    )
    configured = {name: bool(os.environ.get(name)) for name in names}
    config_valid = False
    credential_available = False
    attestation_valid = False
    try:
        config = load_lab_config()
        config_valid = True
        load_lab_key_material(config.key_file)
        credential_available = True
        load_lab_attestation(config)
        attestation_valid = True
    except (LabConfigError, LabSafetyError):
        pass
    return {
        "configured": configured,
        "lab_configuration_valid": config_valid,
        "credential_available": credential_available,
        "attestation_valid": attestation_valid,
        "preflight_ready": config_valid and credential_available and attestation_valid,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "evidence-env":
        print(json.dumps(_environment_status(), sort_keys=True))
        return 0

    transport: HttpTransport | None = None
    status: dict[str, object] = {
        "lab_provenance": "FAIL",
        "credential_availability": "NOT_CHECKED",
        "candidate_resolution": "NOT_CHECKED",
        "automatic_dependency_checks": "NOT_CHECKED",
        "references_found": "UNKNOWN",
        "operator_attestation": "NOT_CHECKED",
        "combined_disposable_lab_safety_gate": "FAIL",
    }
    try:
        # Every local provenance/secret/attestation gate precedes construction
        # of the first network-capable object.
        config = load_lab_config()
        status["lab_provenance"] = "PASS"
        key = load_lab_key_material(config.key_file)
        status["credential_availability"] = "PASS"
        status["operator_attestation"] = "INVALID"
        attestation = load_lab_attestation(config)
        status["operator_attestation"] = "VALID"
        transport = HttpTransport(config.base_url, key, verify=True)
        rest = RestApiClient(transport, identity=config.identity, api_version=ApiVersion.V2)
        report = run_read_only_preflight(config, client=PfSenseClient(rest), attestation=attestation)
        if args.command == "dry-run":
            print(render_dry_run(report, test_case_id=args.test_case_id))
        else:
            print(render_evidence("lab-t1-preflight", report))
        return 0
    except (LabConfigError, LabSafetyError) as exc:
        status["failure"] = str(exc)
        print(json.dumps(status, sort_keys=True), file=sys.stderr)
        return 2
    finally:
        if transport is not None:
            transport.close()


if __name__ == "__main__":
    raise SystemExit(main())
