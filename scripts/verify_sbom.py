#!/usr/bin/env python3
"""Fail closed when a generated CycloneDX SBOM contains unsafe content.

Pure inspection of an already-generated SBOM JSON file — this script does
not invoke any SBOM generator itself (that stays a separate, explicit,
network-requiring step; see `make sbom` and docs/DEPENDENCY_POLICY.md).
Offline-testable by construction: every check operates on a JSON document
already in hand, the same discipline `verify_distribution.py` applies to
an already-built archive.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

#: Same markers `verify_distribution.py` rejects in a distribution
#: archive -- an SBOM built from a developer's local environment (rather
#: than a clean, isolated one) can leak the same class of machine-specific
#: path, e.g. via an editable-install "file://" reference.
_LOCAL_HOME_MARKERS = (b"/home/", b"/Users/")
_LOCAL_INSTALL_MARKERS = (b"file://", b" -e ", b"editable")


class SbomVerificationError(ValueError):
    """A generated SBOM violates the release-artifact safety policy."""


def _load_document(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SbomVerificationError(f"cannot read SBOM file: {exc}") from exc
    if any(marker in raw for marker in _LOCAL_HOME_MARKERS):
        raise SbomVerificationError(f"local home path present in SBOM: {path}")
    if any(marker in raw for marker in _LOCAL_INSTALL_MARKERS):
        raise SbomVerificationError(f"local/editable install reference present in SBOM: {path}")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SbomVerificationError(f"SBOM is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SbomVerificationError("SBOM top level must be a JSON object")
    return document


def verify_sbom(path: Path, *, expected_name: str) -> dict[str, Any]:
    document = _load_document(path)

    if document.get("bomFormat") != "CycloneDX":
        raise SbomVerificationError(f"unexpected bomFormat: {document.get('bomFormat')!r}")
    if not document.get("specVersion"):
        raise SbomVerificationError("missing specVersion")

    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise SbomVerificationError("missing metadata section")
    component = metadata.get("component")
    if not isinstance(component, dict):
        raise SbomVerificationError("missing metadata.component section")
    actual_name = str(component.get("name", ""))
    if actual_name.lower().replace("_", "-") != expected_name.lower().replace("_", "-"):
        raise SbomVerificationError(
            f"metadata.component.name {actual_name!r} does not match expected {expected_name!r}"
        )

    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise SbomVerificationError(
            "components list is missing or empty -- SBOM does not describe a real dependency set"
        )

    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom_path", type=Path, help="path to a generated CycloneDX JSON SBOM")
    parser.add_argument("--expected-name", default="pfsense-mcp-server", help="expected metadata.component.name")
    args = parser.parse_args(argv)
    try:
        document = verify_sbom(args.sbom_path, expected_name=args.expected_name)
    except SbomVerificationError as exc:
        parser.exit(1, f"verify_sbom: ERROR {exc}\n")
    print(f"verify_sbom: OK ({len(document['components'])} component(s), specVersion {document['specVersion']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
