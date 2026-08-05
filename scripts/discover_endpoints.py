#!/usr/bin/env python3
"""discover_endpoints.py — inspect the pfSense REST API OpenAPI schema
for GET endpoints.

Read-only, inspection-only. This tool must never:
  - classify an endpoint as "verified" (that only happens after an
    independent, human-performed GET check via the existing
    authenticated wrapper script, recorded in pfsense_mcp.endpoints),
  - modify production source files, fixtures, or endpoints.py,
  - generate source code.

Its only responsibility is producing a structured, deterministic
description of the available GET API surface, to speed up the
discovery step of adding a new read-only capability. Everything after
discovery (endpoint verification, sensitivity classification, design
approval, implementation) remains a separate, manual step.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.openapi import EndpointMatch, find_endpoints, load_schema  # noqa: E402

from pfsense_mcp.config import load_api_key, load_config  # noqa: E402
from pfsense_mcp.errors import PfSenseMCPError  # noqa: E402

SCHEMA_VERSION = 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discover_endpoints.py",
        description="Inspect the pfSense OpenAPI schema for GET endpoints (read-only, inspection-only).",
    )
    parser.add_argument(
        "query", nargs="?", default=None, help="Search term matched against path, tags, summary, and description."
    )
    parser.add_argument("--area", default=None, help="Filter to a resource area / OpenAPI tag (ANDed with query).")
    parser.add_argument(
        "--schema-file",
        type=Path,
        default=None,
        help="Load the schema from a local JSON file instead of the live instance.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the structured, versioned JSON report.")
    parser.add_argument(
        "--show-all-methods",
        action="store_true",
        help="Expand the mutating-methods summary into the actual verb list.",
    )
    return parser


def _render_human(endpoints: list[EndpointMatch], show_all_methods: bool) -> str:
    if not endpoints:
        return "No matching GET endpoints found."

    lines: list[str] = []
    for ep in endpoints:
        lines.append(f"GET {ep.path}")
        if ep.tags:
            lines.append(f"  Tag/area: {', '.join(ep.tags)}")
        if ep.summary:
            lines.append(f"  Summary: {ep.summary}")
        if ep.description:
            lines.append(f"  Description: {ep.description}")

        if ep.query_parameters:
            lines.append("  Query parameters:")
            for p in ep.query_parameters:
                req_s = "required" if p.required else "optional"
                default_s = f" default={p.default!r}" if p.default is not None else ""
                enum_s = f" enum: {list(p.enum)}" if p.enum else ""
                lines.append(f"    {p.name:<15} {p.type or 'unknown':<10} {req_s}{default_s}{enum_s}")
        else:
            lines.append("  Query parameters: (none)")

        if ep.response_fields:
            lines.append("  Response fields:")
            for f in ep.response_fields:
                flags = []
                if f.required:
                    flags.append("required")
                if f.nullable:
                    flags.append("nullable")
                if f.format:
                    flags.append(f"format={f.format}")
                if f.enum:
                    flags.append(f"enum: {list(f.enum)}")
                flag_s = f"  {' '.join(flags)}" if flags else ""
                lines.append(f"    {f.name:<15} {f.type or 'unknown':<10}{flag_s}")
        else:
            lines.append("  Response fields: (none)")

        mutating = [m for m in ep.sibling_methods if m != "get"]
        if show_all_methods:
            verb_s = ", ".join(m.upper() for m in mutating) if mutating else "none"
            lines.append(f"  Mutating methods on this path: {verb_s}")
        else:
            lines.append(f"  Mutating methods on this path: {'yes' if mutating else 'no'}")

        lines.append("")

    return "\n".join(lines).rstrip()


def _render_json(endpoints: list[EndpointMatch]) -> str:
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "endpoints": [
            {
                "path": ep.path,
                "method": ep.method,
                "tags": list(ep.tags),
                "summary": ep.summary,
                "description": ep.description,
                "sibling_methods": list(ep.sibling_methods),
                "mutating_methods_exist": any(m != "get" for m in ep.sibling_methods),
                "query_parameters": [
                    {
                        "name": p.name,
                        "type": p.type,
                        "required": p.required,
                        "default": p.default,
                        "enum": list(p.enum) if p.enum else None,
                    }
                    for p in ep.query_parameters
                ],
                "response_fields": [
                    {
                        "name": f.name,
                        "type": f.type,
                        "nullable": f.nullable,
                        "enum": list(f.enum) if f.enum else None,
                        "format": f.format,
                        "required": f.required,
                    }
                    for f in ep.response_fields
                ],
            }
            for ep in endpoints
        ],
    }
    return json.dumps(report, indent=2)


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
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error reading schema file: {exc}", file=sys.stderr)
        return 2

    endpoints = find_endpoints(schema_doc, query=args.query, area=args.area)

    if args.json:
        print(_render_json(endpoints))
    else:
        print(_render_human(endpoints, args.show_all_methods))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
