# Performance review

Measured: 2026-08-06 UTC  
Host Python: CPython 3.12.3  
Scope: offline, credential-free, no pfSense calls

## Method

Cold-process timings were measured over 30 subprocess invocations per command
using `time.perf_counter()`. Every `PFSENSE_*` environment variable was removed.
Startup measurement invokes the installed console script only far enough to
fail closed for missing configuration.

Pytest timings use the complete offline suite with `--durations=25`. File sizes
come from the working tree and exclude caches/build output. Results are local
engineering measurements, not cross-platform benchmarks.

## Import and startup time

| Operation | Median | p95 | Minimum | Maximum |
|---|---:|---:|---:|---:|
| `import pfsense_mcp` | 11.56 ms | 12.63 ms | 11.23 ms | 12.71 ms |
| `import pfsense_mcp.application` | 457.86 ms | 474.04 ms | 448.27 ms | 478.24 ms |
| Console startup to fail-closed configuration exit | 466.68 ms | 499.31 ms | 452.87 ms | 502.53 ms |

The package root is lightweight. Importing `Application` eagerly imports the
MCP/FastMCP stack and accounts for almost all cold-start cost. Fail-closed
bootstrap adds roughly 9 ms over the application import median.

Import-time tracing for `pfsense_mcp.application` reported approximately:

| Import subtree | Cumulative time |
|---|---:|
| `pfsense_mcp.application` | 401 ms |
| `mcp.server.fastmcp` / `mcp` | 349 ms |
| `mcp.client.session` | 226 ms |
| server session/FastMCP internals | 116 ms |
| `mcp.types` | 91 ms |

These subtrees overlap; they are diagnostic cumulative import times, not values
to sum. The dominant cost is upstream MCP SDK loading rather than repository
models or endpoint definitions.

## Test performance

Complete result: **1,125 passed, 42 skipped in 2.22 seconds**.

Slowest tests:

| Test | Time |
|---|---:|
| `test_checkpoint.py::test_main_generates_both_output_files` | 0.32 s |
| `test_checkpoint.py::test_main_creates_checkpoint_dir_if_missing` | 0.31 s |
| auth-key MCP schema enumeration | 0.07 s |
| successful application bootstrap | 0.06 s |
| complete prohibited-property MCP schema enumeration | 0.06 s |
| registered auth-key signature enumeration | 0.06 s |
| generated-code Ruff validation | 0.04 s |

The checkpoint tests dominate because they execute repository/test-report
subprocesses. The complete suite is already fast; parallel pytest or selective
test execution would add complexity with negligible developer benefit.

## Largest Python modules

| Bytes | File |
|---:|---|
| 154,768 | `tests/test_pfsense_client.py` |
| 80,334 | `tests/test_tool_registry.py` |
| 49,814 | `src/pfsense_mcp/pfsense_client.py` |
| 35,052 | `scripts/scaffold_capability.py` |
| 33,243 | `tests/test_scaffold_capability.py` |
| 29,554 | `scripts/lib/code_templates.py` |
| 21,655 | `scripts/lib/capture_policies.py` |
| 19,732 | `scripts/lib/sanitizer.py` |
| 19,034 | `tests/test_code_templates.py` |
| 16,930 | `tests/test_endpoints_verified.py` |
| 15,139 | `src/pfsense_mcp/tools/registry.py` |

Module size is currently a maintainability concern, not a measured runtime
bottleneck.

## Obvious optimization opportunities

### Worth doing when convenient

- Split large test modules for navigation and review; performance should remain
  unchanged.
- Avoid importing FastMCP from scripts that do not need registration. Current
  production startup still needs it, so gains are limited to tooling.
- Cache parsed static manifests inside a single scaffolding process if future
  batch generation is added.
- Keep list limits bounded and prefer upstream filtering over mapping discarded
  results.

### Not justified now

- Lazy-loading tool modules: it complicates explicit registration and saves
  little compared with MCP SDK import time.
- Parallel pytest: a 2.22-second suite does not warrant scheduler overhead.
- Caching pfSense READ results: it creates freshness, authorization, and secret-
  lifetime questions for network-latency savings that have not been measured.
- Replacing Pydantic validation: typed boundary safety is more valuable than
  speculative micro-optimization.
- Async conversion: the stdio server and upstream traffic have not shown a
  concurrency bottleneck, and a rewrite would carry significant API/test risk.

## Recommended future measurements

If performance becomes operationally relevant, measure with synthetic or
explicitly approved sanitized infrastructure:

- end-to-end MCP request latency separated into transport, JSON parsing, model
  validation, and serialization;
- peak memory for the largest bounded list responses;
- startup time on Python 3.11–3.13 in CI;
- repeated MCP tool enumeration cost;
- log rotation overhead under sustained request volume.

No performance change is recommended for v0.2.2.
