"""Deterministic, offline measurement of the real `tools/list` MCP payload.

Boots the actual `pfsense-mcp-server` binary as a subprocess (a real MCP
stdio handshake -- `mcp.client.stdio.stdio_client` + `mcp.ClientSession`,
the same mechanism used to independently verify the public contract
elsewhere in this project) using a placeholder, non-network-reaching
config (`PFSENSE_API_URL=https://pfsense-benchmark.invalid`, a local dummy
key file). `list_tools()` never makes a live pfSense call -- tool
registration is static per capability profile -- so this captures the
exact, real `tools/list` response bytes the server would ever produce for
the default (auditor/read-only) profile, without any network or LAB
dependency.

This is benchmark-only infrastructure. It imports nothing from the
production runtime except by launching the real installed console script
as an external process (the same boundary a real MCP client crosses) --
it is not itself importable from `src/pfsense_mcp` and adds no new code
path to the shipped package.

Usage:
    python3 benchmarks/tool_surface_efficiency/measure_schema_cost.py
"""

from __future__ import annotations

import asyncio
import json
import os
import resource
import statistics
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__file__).resolve().parent / "results"

#: Documented estimation method (Phase 1 requires this be explicit): no
#: `tiktoken`/`anthropic` tokenizer is installed in this environment (both
#: import-checked and absent). Estimated tokens use the widely-cited
#: OpenAI/Anthropic rule-of-thumb approximation of ~4 characters per token
#: for English/JSON-ish text -- this is an APPROXIMATION, not exact model
#: prompt-token accounting for any specific tokenizer (Claude's or GPT's).
#: Reported separately from exact byte counts throughout, never conflated.
_CHARS_PER_TOKEN_ESTIMATE = 4.0


def _env_for_dummy_server() -> dict[str, str]:
    key_file = os.environ.get("BENCH_DUMMY_KEY_FILE")
    if not key_file:
        raise RuntimeError("BENCH_DUMMY_KEY_FILE must be set by the caller")
    env = dict(os.environ)
    env.update(
        {
            "PFSENSE_API_URL": "https://pfsense-benchmark.invalid",
            "PFSENSE_IDENTITY": "benchmark-only-never-used",
            "PFSENSE_API_KEY_FILE": key_file,
            "PFSENSE_TLS_MODE": "strict",
        }
    )
    return env


async def _capture_tools_list() -> tuple[list[dict[str, Any]], float, float]:
    """Returns (raw tool dicts as sent over the wire, startup_seconds,
    tools_list_seconds). Uses the real `mcp` client SDK exactly like a
    real MCP client would -- never hand-parses or reimplements the wire
    format."""

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server_bin = str(REPO_ROOT / ".venv" / "bin" / "pfsense-mcp-server")
    params = StdioServerParameters(command=server_bin, args=[], env=_env_for_dummy_server())

    t0 = time.monotonic()
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        t_ready = time.monotonic()
        result = await session.list_tools()
        t_listed = time.monotonic()

    startup_seconds = t_ready - t0
    tools_list_seconds = t_listed - t_ready

    raw_tools = []
    for tool in result.tools:
        raw_tools.append(
            {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": tool.inputSchema,
            }
        )
    return raw_tools, startup_seconds, tools_list_seconds


def _byte_len(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _measure_memory_rss_kb() -> int | None:
    """Best-effort peak RSS of this benchmark process's own children so
    far (the subprocess we spawned), via `resource.getrusage(RUSAGE_CHILDREN)`
    -- Linux-only, reported as None if unavailable rather than guessed."""

    try:
        return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    except Exception:
        return None


def build_report(raw_tools: list[dict[str, Any]], startup_s: float, tools_list_s: float) -> dict[str, Any]:
    per_tool = []
    for tool in raw_tools:
        name_bytes = _byte_len(tool["name"])
        desc_bytes = len(tool["description"].encode("utf-8"))
        schema_bytes = _byte_len(tool["inputSchema"])
        total_bytes = _byte_len(tool)
        per_tool.append(
            {
                "name": tool["name"],
                "description_bytes": desc_bytes,
                "input_schema_bytes": schema_bytes,
                "total_tool_bytes": total_bytes,
                "name_bytes": name_bytes,
            }
        )

    per_tool.sort(key=lambda t: t["total_tool_bytes"])
    total_bytes_list = [t["total_tool_bytes"] for t in per_tool]
    desc_bytes_list = [t["description_bytes"] for t in per_tool]
    schema_bytes_list = [t["input_schema_bytes"] for t in per_tool]

    full_payload = {"tools": raw_tools}
    full_payload_bytes = _byte_len(full_payload)
    total_description_bytes = sum(desc_bytes_list)
    total_schema_bytes = sum(schema_bytes_list)

    report = {
        "methodology": {
            "capture_method": "real MCP stdio handshake via the `mcp` client SDK "
            "(session.initialize() + session.list_tools()) against the actual installed "
            "pfsense-mcp-server binary, default (auditor/read-only) capability profile, "
            "PFSENSE_API_URL pointed at a non-resolving placeholder host -- list_tools() "
            "makes no live pfSense call, so this is a fully offline, deterministic "
            "measurement of the real wire-format tools/list payload.",
            "byte_counting": "UTF-8 encoded length of the canonical (sorted-key, "
            "no-whitespace) JSON serialization of each tool/the full tools array -- "
            "an exact, reproducible byte count, not an estimate.",
            "token_estimation": f"~{_CHARS_PER_TOKEN_ESTIMATE:g} characters per token "
            "(the commonly-cited OpenAI/Anthropic rule-of-thumb approximation for "
            "English/JSON-ish text). No tokenizer (tiktoken, anthropic SDK) is installed "
            "in this environment -- this is an approximation, reported separately from "
            "exact byte counts, never as exact model prompt-token accounting.",
        },
        "totals": {
            "tool_count": len(raw_tools),
            "full_tools_list_payload_bytes": full_payload_bytes,
            "full_tools_list_payload_estimated_tokens": round(full_payload_bytes / _CHARS_PER_TOKEN_ESTIMATE),
            "total_description_bytes": total_description_bytes,
            "total_input_schema_bytes": total_schema_bytes,
            "total_description_estimated_tokens": round(total_description_bytes / _CHARS_PER_TOKEN_ESTIMATE),
            "total_input_schema_estimated_tokens": round(total_schema_bytes / _CHARS_PER_TOKEN_ESTIMATE),
        },
        "distribution": {
            "median_tool_bytes": statistics.median(total_bytes_list),
            "mean_tool_bytes": round(statistics.fmean(total_bytes_list), 1),
            "stdev_tool_bytes": round(statistics.pstdev(total_bytes_list), 1),
            "min_tool_bytes": min(total_bytes_list),
            "max_tool_bytes": max(total_bytes_list),
        },
        "largest_10": per_tool[-10:][::-1],
        "smallest_10": per_tool[:10],
        "latency": {
            "startup_to_initialized_seconds": round(startup_s, 4),
            "tools_list_seconds": round(tools_list_s, 4),
        },
        "memory": {
            "note": "Best-effort RUSAGE_CHILDREN peak RSS (KB) across the whole benchmark "
            "process's child processes measured so far -- Linux-specific, approximate "
            "(includes Python interpreter startup, not isolated to the MCP server alone).",
            "ru_maxrss_kb": _measure_memory_rss_kb(),
        },
        "per_tool": per_tool,
    }
    return report


async def main() -> None:
    scratch = Path(os.environ.get("BENCH_SCRATCH_DIR", "/tmp"))
    key_file = scratch / "api-key"
    key_file.write_text("benchmark-placeholder-key-not-real\n")
    key_file.chmod(0o600)
    os.environ["BENCH_DUMMY_KEY_FILE"] = str(key_file)
    os.environ["BENCH_SCRATCH_DIR"] = str(scratch)

    # Two independent process launches: first for a clean startup-latency
    # measurement, second (discarded timing, kept payload) as a sanity
    # cross-check that the payload itself is deterministic run-to-run.
    raw_tools_1, startup_s, tools_list_s = await _capture_tools_list()
    raw_tools_2, _, _ = await _capture_tools_list()

    payload_1 = json.dumps({"tools": raw_tools_1}, sort_keys=True)
    payload_2 = json.dumps({"tools": raw_tools_2}, sort_keys=True)
    deterministic = payload_1 == payload_2

    report = build_report(raw_tools_1, startup_s, tools_list_s)
    report["deterministic_across_runs"] = deterministic

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "schema_cost_report.json"
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True))

    print(f"tool_count={report['totals']['tool_count']}")
    print(f"full_payload_bytes={report['totals']['full_tools_list_payload_bytes']}")
    print(f"full_payload_estimated_tokens={report['totals']['full_tools_list_payload_estimated_tokens']}")
    print(f"median_tool_bytes={report['distribution']['median_tool_bytes']}")
    print(f"deterministic_across_runs={deterministic}")
    print(f"startup_seconds={report['latency']['startup_to_initialized_seconds']}")
    print(f"tools_list_seconds={report['latency']['tools_list_seconds']}")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
