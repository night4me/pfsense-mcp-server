"""Pure, offline load/save helpers for the committed `EndpointCatalogue`
artifact (ADR-019 Part 1). No network access; no dependency on
`pfsense_mcp.endpoints`/`pfsense_mcp.capabilities`/
`pfsense_mcp.tools.registry`. The catalogue file itself lives outside
`src/pfsense_mcp` entirely (`catalogue/endpoint_catalogue.json`, repo
root) -- non-executable data, never packaged into the wheel/sdist
(`pyproject.toml`'s wheel target only packages `src/pfsense_mcp`; the
sdist include-list does not name `/catalogue`), never imported as
Python.
"""

from __future__ import annotations

import json
from pathlib import Path

from .catalogue import EndpointCatalogue

#: Repo-root-relative default location. Callers in tests/scripts pass an
#: explicit path; this constant exists only so the real, canonical
#: location is defined exactly once.
DEFAULT_CATALOGUE_PATH = Path(__file__).resolve().parents[3] / "catalogue" / "endpoint_catalogue.json"


def load_catalogue(path: Path = DEFAULT_CATALOGUE_PATH) -> EndpointCatalogue:
    """Load and validate the committed catalogue file. Raises if the
    file is missing or fails validation -- no silent empty-catalogue
    fallback, since a missing file at this path is a real configuration
    error, not an empty-but-valid state (an intentionally empty
    catalogue is represented by a file with `entries: []`, not by
    absence)."""
    with path.open("r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return EndpointCatalogue.model_validate(raw)


def save_catalogue(catalogue: EndpointCatalogue, path: Path = DEFAULT_CATALOGUE_PATH) -> None:
    """Write the catalogue as canonical, deterministically ordered JSON.
    Callers (the builder script) are solely responsible for ensuring a
    human reviews the resulting diff before it is committed -- this
    function only ever writes to the local working tree, exactly like
    `scripts/public_contract.py --update`; it never stages, commits, or
    pushes anything."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = catalogue.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
