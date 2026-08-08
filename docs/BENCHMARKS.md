# Benchmark methodology and baseline

This document defines reproducible, offline performance measurements for
`pfsense-mcp-server`. Performance is subordinate to correctness, explicit
capability boundaries, secret non-disclosure, and GET-only enforcement. No
optimization may weaken those properties.

## Scope

The public baseline covers:

- cold Python imports;
- fail-closed console startup without credentials;
- complete offline test-suite duration;
- source-module size as a maintainability indicator.

It does not measure a live pfSense appliance. Network latency, appliance load,
REST API implementation, and private topology would make such numbers neither
publicly reproducible nor safe to collect without separate approval.

## Reference environment

Baseline captured: 2026-08-06 UTC

| Property | Reference value |
|---|---|
| CPU architecture | x86-64 |
| Allocated CPU | 2 cores, 1 thread per core |
| Processor | 12th Gen Intel Core i5-12600T |
| Memory | 1.9 GiB allocated |
| Operating system | Linux 6.8, x86-64 |
| Python | CPython 3.12.3 |
| Installation | local `.venv`, project and development extras installed |
| Network/appliance access | none |

These are context, not minimum requirements. Compare absolute values only on a
similar host; use percentage changes on the same host for regression analysis.

## Baseline numbers

Thirty fresh subprocesses were used for each cold-start measurement. Times use
`time.perf_counter()` in a parent process, with all `PFSENSE_*` variables
removed from the child environment.

| Operation | Median | p95 | Minimum | Maximum |
|---|---:|---:|---:|---:|
| `import pfsense_mcp` | 11.56 ms | 12.63 ms | 11.23 ms | 12.71 ms |
| `import pfsense_mcp.application` | 457.86 ms | 474.04 ms | 448.27 ms | 478.24 ms |
| Console startup to missing-configuration exit | 466.68 ms | 499.31 ms | 452.87 ms | 502.53 ms |

The full offline suite completed with **1,125 passed, 42 skipped in 2.22
seconds**. The slowest individual tests were two checkpoint-generation tests at
approximately 0.32 and 0.31 seconds. See
[`reports/performance.md`](https://github.com/night4me/pfsense-mcp-server/blob/main/reports/performance.md) for the detailed profile
and largest-module inventory.

## Measurement procedure

### Environment preparation

Use a clean checkout and install the project exactly as documented:

```console
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

Record the commit SHA, Python patch version, operating system/kernel, allocated
CPU, available memory, and whether the filesystem is local. Stop background
jobs likely to cause sustained contention. Do not tune the host solely for a
favourable result.

### Import and startup

Use a parent Python process to run each command in 30 new subprocesses. Remove
every environment key whose name starts with `PFSENSE_`. Measure:

```console
.venv/bin/python -c "import pfsense_mcp"
.venv/bin/python -c "import pfsense_mcp.application"
.venv/bin/pfsense-mcp-server
```

For the console command, success means a sanitized, non-zero fail-closed exit
because required configuration is absent. A successful connection attempt is
invalid for this benchmark. Report minimum, median, p95, maximum, and raw sample
count. Do not mix warm in-process imports with cold subprocess results.

### Offline tests

Ensure `PFSENSE_RUN_LIVE_TESTS` is absent, then run:

```console
.venv/bin/python -m pytest -q --durations=25
```

Record passed/skipped counts, wall-clock duration, and the slowest tests. A run
that executes live tests is invalid and must not be published.

### Module size

Measure tracked Python source bytes, excluding virtual environments, caches,
build output, and generated reports. Module size is not a speed metric; use it
to identify review and navigation costs.

## Comparing future results

1. Use the same benchmark commands and sample count.
2. Compare the same Python minor version first, then report cross-version
   results separately.
3. Run old and new commits on the same host in alternating order when
   investigating a suspected regression.
4. Report median and p95 deltas, not only the best run.
5. Repeat a noisy series; do not discard inconvenient samples without recording
   the reason.
6. Attribute changes using import-time profiles or test durations before
   proposing an optimization.
7. Keep raw benchmark output outside committed reports if it contains host or
   filesystem details.

## Performance acceptance criteria

These criteria are review triggers, not automatic CI wall-clock gates. Shared
CI runners are too variable for stable microbenchmark enforcement.

- No statistically credible regression greater than 25% in both median and p95
  application-import or fail-closed startup time on a comparable host without a
  documented reason.
- Fail-closed startup remains below 1 second median on the reference-class host.
- The complete offline suite remains below 10 seconds on the reference-class
  host; crossing that point requires profiling before adding parallelism.
- No new test should add more than 0.5 seconds of deterministic wall time when
  an equivalent fake clock or `MockTransport` assertion is practical.
- Collection processing remains bounded by public `limit` validation.
- Memory and CPU optimizations must preserve model validation, audit semantics,
  credential handling, and all architecture security checks.

A threshold breach does not justify skipping validation, weakening security, or
caching appliance data. It requires investigation and an explicit trade-off.

## Future benchmark extensions

The next useful measurements are all offline:

- MCP initialization and tool-enumeration time;
- per-tool mapping/serialization time using approved fixtures and
  `MockTransport`;
- peak memory for the largest bounded collection fixture;
- audit-log overhead using synthetic records and a temporary directory;
- Python 3.11, 3.12, and 3.13 comparison on a controlled runner.

End-to-end appliance measurements require explicit approval, sanitized result
handling, and a separately documented private acceptance protocol. Future Tier
1 benchmarks must additionally prove that timing work cannot bypass Recovery
Contract persistence, state transitions, or HTTP outcome validation.
