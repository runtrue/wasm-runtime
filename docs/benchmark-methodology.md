# Benchmark methodology

Performance claims must be reproducible, labeled, and separated by the work
actually measured. Results include raw samples, p50, p95, exact component
digest, WASI world/profile, Wasmtime version, comparison-runner version, host
OS/architecture, CPU, memory, and command line.

## Required measurements

1. Direct handler calls: cold compile, authenticated disk AOT, in-memory AOT
   (warmish), paused-resident (warm), and idle eviction.
2. TCP: process-to-ready, first request, sequential keep-alive latency, fresh
   connection latency, throughput, and latency at concurrency 1, 8, and 32.
3. Identical component comparison: raw Wasmtime embedding, `wasmtime serve`,
   and this standalone package. The shared WASI HTTP 0.2 fixture is the
   portability baseline; a WASI HTTP 0.3 fixture is reported separately because
   current release-candidate WIT snapshots are not interchangeable.
4. Capacity: source component bytes, authenticated AOT bytes, baseline and
   incremental RSS, resident-worker RSS, and measured or clearly labeled
   projected instances per GiB for 1, 100, 1,000, and 10,000 packages.
5. Stress: single-flight preparation, cache corruption and eviction, request
   timeouts, same-service concurrency, and multi-service concurrency.

Cold process readiness is not a request latency. Direct calls are not TCP
latency. Disk AOT includes reading and authenticating the AOT file but reports
source-package I/O separately. A projection is never presented as a measured
10,000-instance result.

Before collecting release numbers, build in release mode, stop unrelated
loads, record CPU governor and container limits, prefetch no files unless the
case explicitly says so, run at least 20 cold samples and 1,000 warm requests,
and retain the full JSON output in `benchmarks/results/`.

## Pinned comparison tools

- Wasmtime CLI and embedding: 46.0.1
- JSON tool portability fixture: `wasip2` 1.0.4 / WASI HTTP 0.2.12
- Native WASI HTTP 0.3 fixture: Wasmtime 46 WIT at `wasi:http@0.3.0`

The bootstrap script downloads pinned official binaries and verifies versions.
The harness never downloads a tool during a timed sample.

The cold TCP comparison disables the Wasmtime CLI's shared compilation cache
with `-C cache=n`. All three runners use a 10,000-request reuse limit and a
30-second idle worker timeout. The raw embedding uses the package's hardened
engine settings; `wasmtime serve` retains its official CLI engine defaults, so
its process-ready result is a runner comparison, not an isolated measurement
of package wrapper overhead.
