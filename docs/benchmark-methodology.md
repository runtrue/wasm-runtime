# Benchmark methodology

Performance claims must be reproducible and explicit about the work being
timed. Every retained result includes raw samples, p50 and p95, component
digest, WASI profile, Wasmtime and package versions, host OS and architecture,
CPU, memory, and command line.

## Measurement boundaries

Keep these measurements separate:

1. **Direct tier calls:** cold validation and compilation, authenticated disk
   AOT, in-memory AOT deserialization (warmish), resident dispatch (warm), and
   idle eviction.
2. **TCP:** process-to-ready, first request, fresh-connection latency,
   keep-alive latency, and throughput/latency at concurrency 1, 8, and 32.
3. **Identical-component hosts:** raw Wasmtime embedding, `wasmtime serve`, and
   this package's streaming server. The shared WASI HTTP 0.2 fixture is the
   portability baseline. WASI HTTP 0.3 is reported separately because current
   release-candidate WIT snapshots are not interchangeable.
4. **Capacity:** source bytes, authenticated AOT bytes, baseline RSS, marginal
   resident-worker RSS, and measured 1/100/1,000/10,000-worker results.
5. **Stress:** single-flight preparation, cache corruption and eviction,
   request timeouts, same-service concurrency, and multi-service concurrency.

Process readiness is not request latency. A direct call is not TCP latency.
Disk AOT includes file reading and authentication; source-package I/O is
reported separately. A projected capacity is never presented as a measured
worker count.

## Collection procedure

Before collecting release numbers:

1. Use the pinned release toolchain and release builds.
2. Stop unrelated workloads and record CPU governor, CPU allocation, container
   limits, kernel, and mitigation profile.
3. Do not prefetch files unless the scenario explicitly measures a warm OS
   page cache.
4. Run at least 20 cold samples and 1,000 warm requests.
5. Retain complete JSON under `benchmarks/results/`; never keep only a summary.

Run every script through `uv`:

```text
cargo run --locked --release --example http_benchmark -- 100 5000 > http.json
cargo run --locked --release --example http_capacity_benchmark -- 10000 > capacity.json
uv run benchmarks/bootstrap_tools.py
uv run benchmarks/http_compare.py --cold-iterations 20 --warm-requests 1000 > tcp.json
```

Run the TCP comparison at least three times, rotating the three valid
`--runner-order` permutations so a fixed order cannot turn cache heat or CPU
boost into an overhead claim:

```text
--runner-order raw-wasmtime-embedding,wasmtime-serve,standalone-package
--runner-order standalone-package,raw-wasmtime-embedding,wasmtime-serve
--runner-order wasmtime-serve,standalone-package,raw-wasmtime-embedding
```

Compare per-run distributions and the median result for each host. Treat
latency differences below 25 microseconds as runner noise unless a stable,
isolated host reproduces them.

## Pinned comparison tools

- Wasmtime CLI and embedding: 46.0.1
- WASI HTTP 0.2 fixture: `wasip2` 1.0.4 / WASI HTTP 0.2.12
- WASI HTTP 0.3 fixture: Wasmtime 46 WIT at `wasi:http@0.3.0`

`benchmarks/bootstrap_tools.py` downloads pinned official binaries and verifies
their versions before measurement. A timed sample never downloads a tool.

The TCP harness disables the Wasmtime CLI's shared compilation cache with
`-C cache=n`. All hosts use a 10,000-request reuse limit and a 30-second idle
worker timeout. The raw embedding uses the package's hardened engine settings;
`wasmtime serve` uses official CLI defaults, so its process-ready number is a
host comparison rather than isolated package overhead.

The standalone server uses `HttpService::handle_streaming`. The buffered
convenience API is measured by the direct-call benchmark and must not be mixed
into streaming-host claims.
