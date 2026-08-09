#!/usr/bin/env python3
"""build_endpoint_catalogue.py -- regenerate the ADR-019 Endpoint
Catalogue artifact (`catalogue/endpoint_catalogue.json`) from a pfSense
OpenAPI schema.

Read-only against the schema; **dry-run by default** against the
catalogue file -- prints what would change and writes nothing unless
`--update` is passed. Even with `--update`, this script only ever writes
to the local working tree: it never stages, commits, or pushes anything,
and it is never invoked by CI. Committing a regenerated catalogue is an
ordinary, human-reviewed pull request like any other change -- see
`catalogue/README.md`. This is a structural requirement of ADR-019
(`docs/API_SURFACE_ARCHITECTURE.md` Part 1's "Catalogue regeneration
must not bypass human review either"), not a convention this script may
be extended to skip.

This script must never:
  - classify an endpoint as `EndpointInfo.verified` (that word belongs
    solely to `pfsense_mcp.endpoints`, set only after independent,
    human-performed verification against a real instance),
  - modify production source files, fixtures, or `endpoints.py`,
  - generate source code,
  - assign or infer `TYPED`/`IMPLEMENTED`/`CAPABILITY_MAPPED`/
    `AUTHORIZED`/`MCP_EXPOSED` for any entry -- `CatalogueEntry` has no
    field for any of those; this script cannot violate that even by
    mistake,
  - overwrite an existing entry's human-set `intended_use`.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.openapi import iter_get_operations, load_schema

from pfsense_mcp.api_surface.catalogue import CatalogueEntry, EndpointCatalogue
from pfsense_mcp.api_surface.store import DEFAULT_CATALOGUE_PATH, load_catalogue, save_catalogue
from pfsense_mcp.config import load_api_key, load_config
from pfsense_mcp.errors import PfSenseMCPError

SCHEMA_VERSION = 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_endpoint_catalogue.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--schema-file",
        type=Path,
        default=None,
        help="Load the OpenAPI schema from a local JSON file instead of the live instance.",
    )
    parser.add_argument(
        "--catalogue-file",
        type=Path,
        default=DEFAULT_CATALOGUE_PATH,
        help="Path to the catalogue artifact (default: catalogue/endpoint_catalogue.json).",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Write the merged catalogue to --catalogue-file. Without this flag, report only.",
    )
    return parser


def _load_existing_catalogue(path: Path) -> EndpointCatalogue:
    if not path.exists():
        return EndpointCatalogue(schema_version=SCHEMA_VERSION, entries=())
    return load_catalogue(path)


def _discover_entries(schema_doc: dict[str, object]) -> dict[tuple[str, str], CatalogueEntry]:
    discovered: dict[tuple[str, str], CatalogueEntry] = {}
    for path, get_op, sibling in iter_get_operations(schema_doc):
        entry = CatalogueEntry(
            path=path,
            method="get",
            tags=tuple(get_op.get("tags") or []),
            summary=get_op.get("summary"),
            description=get_op.get("description"),
            mutating_methods_exist=any(m != "get" for m in sibling),
        )
        discovered[(path, "get")] = entry
    return discovered


def _merge(
    existing: EndpointCatalogue, discovered: dict[tuple[str, str], CatalogueEntry]
) -> tuple[EndpointCatalogue, list[str], list[str], list[str]]:
    """Merge discovered entries into the existing catalogue.

    Never overwrites `intended_use`; never removes an existing entry.
    Returns (merged, added_paths, updated_paths, stale_paths) for the
    human-readable report.
    """
    existing_by_key = {(e.path, e.method): e for e in existing.entries}
    merged: dict[tuple[str, str], CatalogueEntry] = {}
    added: list[str] = []
    updated: list[str] = []

    for key, new_entry in discovered.items():
        current = existing_by_key.get(key)
        if current is None:
            merged[key] = new_entry
            added.append(f"GET {key[0]}")
            continue
        refreshed = new_entry.model_copy(update={"intended_use": current.intended_use})
        if refreshed.model_dump() != current.model_dump():
            updated.append(f"GET {key[0]}")
        merged[key] = refreshed

    stale: list[str] = []
    for key, current in existing_by_key.items():
        if key not in discovered:
            merged[key] = current
            stale.append(f"GET {key[0]} (no longer present in the fetched schema -- kept, review manually)")

    ordered_entries = tuple(merged[key] for key in sorted(merged.keys()))
    result = EndpointCatalogue(
        schema_version=SCHEMA_VERSION,
        generated_at=datetime.now(timezone.utc).isoformat(),
        entries=ordered_entries,
    )
    return result, sorted(added), sorted(updated), sorted(stale)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.schema_file is not None:
            schema_doc = load_schema(schema_file=args.schema_file)
        else:
            config = load_config()
            api_key = load_api_key(config)
            schema_doc = load_schema(config=config, api_key=api_key)
    except PfSenseMCPError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error reading schema file: {exc}", file=sys.stderr)
        return 2

    existing = _load_existing_catalogue(args.catalogue_file)
    discovered = _discover_entries(schema_doc)
    merged, added, updated, stale = _merge(existing, discovered)

    print(f"build_endpoint_catalogue: {len(discovered)} GET operation(s) discovered in the fetched schema")
    print(f"  {len(added)} new entr{'y' if len(added) == 1 else 'ies'} would be added:")
    for line in added:
        print(f"    + {line}")
    print(f"  {len(updated)} existing entr{'y' if len(updated) == 1 else 'ies'} would be refreshed:")
    for line in updated:
        print(f"    ~ {line}")
    print(f"  {len(stale)} existing entr{'y' if len(stale) == 1 else 'ies'} no longer discovered (kept as-is):")
    for line in stale:
        print(f"    ? {line}")

    if not args.update:
        print("\nDry run -- no file written. Pass --update to write the merged catalogue.")
        return 0

    save_catalogue(merged, args.catalogue_file)
    print(
        f"\nWrote {args.catalogue_file}. This is a working-tree change only -- "
        "review the diff and commit it through an ordinary pull request."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
