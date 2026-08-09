#!/usr/bin/env python3
"""capture_fixture.py — safe, GET-only fixture-capture workflow.

Produces a sanitized *proposal* under .fixture_proposals/ — never
writes directly into tests/fixtures/. A separate, explicit audit step
(audit_fixture.py / `make audit-fixture` / `make approve-fixture`) is
required before a proposal may become a real, committed fixture.

Safety gates, in order, all before any file is written:
  1. The endpoint must be a registered Endpoints attribute with
     verified=True (necessary, not sufficient).
  2. The endpoint must ALSO have an explicit entry in CAPTURE_POLICIES
     (scripts/lib/capture_policies.py) — a verified-but-un-policied
     endpoint is refused. This is a deliberate second gate, requiring
     its own human review, independent of endpoint verification.
  3. Only query parameters declared by that endpoint's policy are
     accepted, type- and bounds-checked, before ever reaching
     RestApiClient.get(..., params=...) — the only place a query
     string is ever constructed (via urllib.parse.urlencode).
  4. The raw response is size/shape-checked before any sanitization.
  5. The sanitizer (scripts/lib/sanitizer.py) recursively transforms
     the raw dict in memory; any credential/token/key-shaped value
     causes a hard refusal, never a "safe-looking" substitution.

Never prints, logs, or persists: the API key, the credential path, raw
request headers, or the unsanitized response. On any refusal, only the
field path / category / reason is reported — never the triggering
value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.capture_policies import CAPTURE_POLICIES, CapturePolicy
from lib.sanitizer import SanitizationRefusal, Sanitizer

from pfsense_mcp.config import PfSenseConfig, load_api_key, load_config
from pfsense_mcp.endpoints import EndpointInfo, Endpoints
from pfsense_mcp.errors import PfSenseMCPError
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tls import resolve_verify
from pfsense_mcp.transport.http import HttpTransport

MANIFEST_SCHEMA_VERSION = 1
PROPOSALS_DIR = Path(__file__).resolve().parent.parent / ".fixture_proposals"
DEFAULT_MAX_BYTES = 200_000


class CaptureRefusal(Exception):
    def __init__(self, category: str, reason: str) -> None:
        self.category = category
        self.reason = reason
        super().__init__(f"[{category}] {reason}")


def resolve_endpoint_and_policy(name: str) -> tuple[EndpointInfo, CapturePolicy]:
    endpoint = getattr(Endpoints, name, None)
    if not isinstance(endpoint, EndpointInfo):
        raise CaptureRefusal("unknown-endpoint", f"{name!r} is not a registered Endpoints attribute")
    if not endpoint.verified:
        raise CaptureRefusal("endpoint-not-verified", f"Endpoints.{name} is not verified=True")
    policy = CAPTURE_POLICIES.get(name)
    if policy is None:
        raise CaptureRefusal("no-capture-policy", f"Endpoints.{name} has no entry in CAPTURE_POLICIES")
    return endpoint, policy


def _parse_param(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise CaptureRefusal("invalid-parameter-syntax", f"--param must be KEY=VALUE (got {raw!r})")
    key, _, value = raw.partition("=")
    return key, value


def validate_params(policy: CapturePolicy, raw_params: list[str]) -> dict[str, str | int]:
    seen: set[str] = set()
    result: dict[str, str | int] = {}
    for raw in raw_params:
        key, value = _parse_param(raw)
        if key in seen:
            raise CaptureRefusal("duplicate-parameter", f"parameter {key!r} was given more than once")
        seen.add(key)

        bound = policy.allowed_params.get(key)
        if bound is None:
            raise CaptureRefusal(
                "unknown-parameter", f"parameter {key!r} is not declared by this endpoint's capture policy"
            )
        try:
            int_value = int(value)
        except ValueError:
            raise CaptureRefusal(
                "invalid-parameter-type", f"parameter {key!r} must be an integer (got {value!r})"
            ) from None
        if not bound.validate(int_value):
            raise CaptureRefusal(
                "parameter-out-of-bounds",
                f"parameter {key!r}={int_value} is outside [{bound.minimum}, {bound.maximum}]",
            )
        result[key] = int_value
    return result


def fetch_raw(
    config: PfSenseConfig, api_key: str, endpoint: EndpointInfo, params: dict[str, str | int]
) -> dict[str, Any]:
    verify = resolve_verify(config.tls_mode, config.tls_ca_file)
    transport = HttpTransport(config.base_url, api_key, verify)
    try:
        rest_client = RestApiClient(transport, identity=config.identity, api_version=config.api_version)
        return rest_client.get(endpoint, params=params)
    finally:
        transport.close()


def check_size(raw: dict[str, Any], policy: CapturePolicy, max_items: int, max_bytes: int) -> tuple[int, int]:
    data = raw.get("data")
    if policy.result_shape == "list":
        if not isinstance(data, list):
            raise CaptureRefusal("shape-mismatch", "policy declares 'list' but response 'data' is not a list")
        item_count = len(data)
        if item_count > max_items:
            raise CaptureRefusal("too-many-items", f"response has {item_count} items, limit is {max_items}")
    else:
        if not isinstance(data, dict):
            raise CaptureRefusal("shape-mismatch", "policy declares 'object' but response 'data' is not an object")
        item_count = 1

    serialized_size = len(json.dumps(raw, separators=(",", ":")).encode("utf-8"))
    if serialized_size > max_bytes:
        raise CaptureRefusal(
            "input-too-large", f"serialized JSON input is {serialized_size} bytes, limit is {max_bytes}"
        )
    return item_count, serialized_size


def _derive_output_name(endpoint: EndpointInfo) -> str:
    return endpoint.path_suffix.strip("/").replace("/", "_") + "_response"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capture_fixture.py",
        description="Capture a sanitized fixture proposal from a verified, policy-approved GET endpoint.",
    )
    parser.add_argument("endpoint", help="Endpoints attribute name, e.g. FIREWALL_STATES")
    parser.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Repeatable. Only parameters declared by the endpoint's capture policy are accepted.",
    )
    parser.add_argument("--max-items", type=int, default=None, help="Override the policy's default_max_items.")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="Maximum serialized-JSON input size in bytes (checked after parsing, before sanitization).",
    )
    parser.add_argument("--output-name", default=None, help="Base filename for the proposal (default: derived).")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        endpoint, policy = resolve_endpoint_and_policy(args.endpoint)
        params = validate_params(policy, args.param)
        max_items = args.max_items if args.max_items is not None else policy.default_max_items

        config = load_config()
        api_key = load_api_key(config)
        raw = fetch_raw(config, api_key, endpoint, params)

        item_count, serialized_input_size = check_size(raw, policy, max_items, args.max_bytes)

        sanitizer = Sanitizer(policy)
        result = sanitizer.run(raw)

        proposal_bytes = (json.dumps(result.sanitized, indent=2, sort_keys=True) + "\n").encode("utf-8")
        digest = hashlib.sha256(proposal_bytes).hexdigest()

        PROPOSALS_DIR.mkdir(exist_ok=True)
        base_name = args.output_name or _derive_output_name(endpoint)
        proposal_path = PROPOSALS_DIR / f"{base_name}.proposed.json"
        manifest_path = PROPOSALS_DIR / f"{base_name}.manifest.json"

        manifest = {
            "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
            "endpoint_symbol": args.endpoint,
            "endpoint_path": endpoint.path_suffix,
            "api_version": config.api_version.value,
            "captured_at_utc": datetime.now(timezone.utc).isoformat(),
            "query_parameters": params,
            "response_shape": policy.result_shape,
            "item_count": item_count,
            "serialized_input_size_bytes": serialized_input_size,
            "sanitized_proposal_size_bytes": len(proposal_bytes),
            "substitution_counts": result.substitution_counts,
            "redacted_field_names": sorted(result.redacted_field_names),
            "sha256_sanitized_proposal": digest,
        }

        proposal_path.write_bytes(proposal_bytes)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(f"capture_fixture: OK -> {proposal_path}")
        print(f"  manifest: {manifest_path}")
        print(f"  item_count={item_count} sha256={digest[:16]}...")
        print("  This is a PROPOSAL, not a fixture. Run `make audit-fixture` next.")
        return 0

    except CaptureRefusal as exc:
        print(f"capture_fixture: REFUSED [{exc.category}] {exc.reason}", file=sys.stderr)
        return 1
    except SanitizationRefusal as exc:
        print(f"capture_fixture: REFUSED [{exc.category}] field={exc.field_path} {exc.reason}", file=sys.stderr)
        return 1
    except PfSenseMCPError as exc:
        print(f"capture_fixture: ERROR {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
