#!/usr/bin/env python3
"""Offline entry point for `pfsense_mcp.pfrest_docs.schema_diff` (owner
direction, pfREST_LIVE_GUIDANCE_ARC continuation, 2026-08-28).

Compares two OpenAPI documents, semantically and dimension-by-dimension
(paths/methods, operationIds, parameters, schemas/models, fields, enums,
field default values, required_packages, auth metadata,
allowed_privileges, applies_immediately, `x-` extensions, and top-level
version/build metadata) -- never a raw JSON/byte diff.

Each side is selected independently with `--a`/`--b`:

    upstream    fetch PFREST_UPSTREAM live (https://pfrest.org/api-docs/openapi.json)
    appliance   fetch LIVE_APPLIANCE_SCHEMA live, via the standard PFSENSE_*
                runtime environment variables and the existing authenticated
                PfSenseClient transport (same call as
                scripts/pfrest_privilege_crosscheck.py's appliance mode)
    file        load a previously saved OpenAPI JSON document from disk
                (--a-file/--b-file) -- no network call for that side

Default: `--a upstream --b appliance` -- today's real, currently-
authorized comparison (the same pfREST *version* on public
infrastructure vs. one specific connected appliance).

`file` mode exists specifically so a *future*, *separately authorized*
comparison between two different appliances (for example: does pfREST
2.10.2 expose an identical contract on pfSense CE 2.9.0 vs. pfSense
Plus 26.07?) can be performed *offline*, from two independently
captured snapshots, without ever configuring this process to talk to
two appliances at once and without this script initiating a second
live appliance connection on its own. Capture a snapshot with:

    python scripts/pfrest_schema_diff.py --a appliance --b appliance --dump-a snapshot.json

(the redundant --b is required by the CLI's shape but its output is
discarded when only --dump-a is used).

**Strictly advisory, read-only, GET-only.** Never grants a privilege,
never authorizes an endpoint, never modifies any configuration. Not
part of the public MCP tool surface (see
docs/adr/ADR-035-pfrest-live-guidance-layer.md) -- run manually or wire
into your own tooling.

**Never claims a cause.** A found difference is reported with its
dimension and both raw values only; this script does not attribute a
difference to pfSense edition, release, installed packages, runtime
environment, configuration, pfREST build, or schema-generation
behavior. See `schema_diff.py`'s own module docstring.

Exit code 0: comparison completed (regardless of findings -- unlike
`pfrest_privilege_crosscheck.py`, a schema difference is not itself a
failure; it may be entirely expected, e.g. across pfSense editions).
Exit code 1: either source could not be fetched/parsed.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from pfsense_mcp.pfrest_docs.fetch import FetchError, fetch
from pfsense_mcp.pfrest_docs.schema_diff import ChangeKind, SchemaDiffReport, diff_schemas

UPSTREAM_OPENAPI_URL = "https://pfrest.org/api-docs/openapi.json"
UPSTREAM_LABEL = "PFREST_UPSTREAM"
APPLIANCE_LABEL = "LIVE_APPLIANCE_SCHEMA"


def _fetch_upstream() -> dict[str, Any] | None:
    try:
        result = fetch(UPSTREAM_OPENAPI_URL, accept="application/json")
    except FetchError as exc:
        print(f"pfrest_schema_diff: PFREST_UPSTREAM fetch failed: {exc}", file=sys.stderr)
        return None
    try:
        document = json.loads(result.body)
    except ValueError as exc:
        print(f"pfrest_schema_diff: PFREST_UPSTREAM document was not valid JSON: {exc}", file=sys.stderr)
        return None
    if not isinstance(document, dict):
        print("pfrest_schema_diff: PFREST_UPSTREAM document was not a JSON object", file=sys.stderr)
        return None
    return document


def _fetch_appliance() -> dict[str, Any] | None:
    """Only ever contacts the appliance configured via the standard
    PFSENSE_* runtime environment variables -- this script never
    invents a target and never accepts an appliance URL as a CLI
    argument, matching pfrest_privilege_crosscheck.py's own
    convention."""

    import os

    if not os.environ.get("PFSENSE_API_URL"):
        print("pfrest_schema_diff: appliance mode requires PFSENSE_API_URL and friends to be set", file=sys.stderr)
        return None

    from pfsense_mcp.config import load_api_key, load_config
    from pfsense_mcp.factory import build_pfsense_client

    try:
        config = load_config()
        api_key = load_api_key(config)
        transport, client = build_pfsense_client(config, api_key)
    except Exception as exc:
        print(f"pfrest_schema_diff: appliance configuration unavailable: {exc}", file=sys.stderr)
        return None

    try:
        document = client.get_system_schema_openapi()
    except Exception as exc:
        print(f"pfrest_schema_diff: appliance schema fetch failed: {exc}", file=sys.stderr)
        return None
    finally:
        transport.close()

    if not isinstance(document, dict):
        print("pfrest_schema_diff: appliance schema response was not a JSON object", file=sys.stderr)
        return None
    return document


def _load_file(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        print(f"pfrest_schema_diff: could not read {path!r}: {exc}", file=sys.stderr)
        return None
    except ValueError as exc:
        print(f"pfrest_schema_diff: {path!r} was not valid JSON: {exc}", file=sys.stderr)
        return None
    if not isinstance(document, dict):
        print(f"pfrest_schema_diff: {path!r} did not contain a JSON object", file=sys.stderr)
        return None
    return document


def _resolve_source(source: str, file_path: str | None) -> tuple[dict[str, Any] | None, str]:
    if source == "upstream":
        return _fetch_upstream(), UPSTREAM_LABEL
    if source == "appliance":
        return _fetch_appliance(), APPLIANCE_LABEL
    if source == "file":
        if file_path is None:
            print("pfrest_schema_diff: --a-file/--b-file is required when source is 'file'", file=sys.stderr)
            return None, "file"
        return _load_file(file_path), f"file:{file_path}"
    raise ValueError(f"unknown source: {source!r}")


def _print_report(report: SchemaDiffReport) -> None:
    print(f"pfrest_schema_diff: comparing A={report.label_a} vs B={report.label_b}")
    print()
    for dimension, total in report.dimension_totals:
        marker = "identical" if dimension in report.identical_dimensions else f"{total} difference(s)"
        truncated_note = " (truncated in listing below)" if dimension in report.truncated_dimensions else ""
        print(f"  {dimension}: {marker}{truncated_note}")
    print()

    if not report.entries:
        print("No differences found in any compared dimension.")
    else:
        for entry in report.entries:
            symbol = {
                ChangeKind.ADDED_IN_B: "+",
                ChangeKind.REMOVED_IN_B: "-",
                ChangeKind.CHANGED: "~",
            }[entry.change]
            print(f"  [{symbol}] {entry.dimension}: {entry.key} -- {entry.detail}")

    print()
    print(report.disclaimer)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--a", choices=("upstream", "appliance", "file"), default="upstream", help="source A (default: upstream)"
    )
    parser.add_argument(
        "--b", choices=("upstream", "appliance", "file"), default="appliance", help="source B (default: appliance)"
    )
    parser.add_argument("--a-file", default=None, help="path to a saved OpenAPI JSON document, required when --a=file")
    parser.add_argument("--b-file", default=None, help="path to a saved OpenAPI JSON document, required when --b=file")
    parser.add_argument(
        "--dump-a", default=None, help="also write source A's raw document to this path (for later --a/--b file use)"
    )
    parser.add_argument(
        "--dump-b", default=None, help="also write source B's raw document to this path (for later --a/--b file use)"
    )
    args = parser.parse_args(argv)

    document_a, label_a = _resolve_source(args.a, args.a_file)
    document_b, label_b = _resolve_source(args.b, args.b_file)

    if document_a is None or document_b is None:
        print("pfrest_schema_diff: FAILED (could not obtain both sources)")
        return 1

    if args.dump_a is not None:
        with open(args.dump_a, "w", encoding="utf-8") as handle:
            json.dump(document_a, handle)
        print(f"pfrest_schema_diff: wrote source A to {args.dump_a}", file=sys.stderr)
    if args.dump_b is not None:
        with open(args.dump_b, "w", encoding="utf-8") as handle:
            json.dump(document_b, handle)
        print(f"pfrest_schema_diff: wrote source B to {args.dump_b}", file=sys.stderr)

    report = diff_schemas(document_a, document_b, label_a=label_a, label_b=label_b)
    _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
