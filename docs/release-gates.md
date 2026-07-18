# 0.1 release gates

The repository stays private and the crate stays non-publishable until all
gates have recorded evidence.

- Standard conformance: run the shared WASI testsuite for 0.3 and the selected
  0.2 compatibility profile on Linux and macOS, x86-64 and ARM64.
- Safety: fuzz component admission and authenticated AOT metadata; reject
  modified, truncated, wrong-version, wrong-target, and wrong-key artifacts.
- Isolation: prove no inherited environment, arguments, files, sockets, or
  process handles; test fresh Store and resource cleanup after every call.
- Async: test streams, futures, backpressure, cancellation during host waits,
  timeout of CPU-bound guests, resident pause/resume, idle eviction to warmish,
  and cleanup of guest task trees.
- Concurrency: prove one compilation per digest, bounded preparation workers,
  parallel fresh invocations, deterministic eviction, and a stable 10,000-load
  memory plateau.
- Performance: publish p50/p95 cold, disk AOT, warmish, and warm results plus
  throughput, AOT size, RSS, and 0.2-versus-0.3 comparisons. Compare the same
  component through raw Wasmtime embedding, `wasmtime serve`, and this package;
  keep direct handler and actual TCP results separate.
- Compatibility: include WASI version, world/profile, exact Wasmtime version,
  target, CPU floor, compiler settings, and mitigation profile in cache keys.
- Packaging: complete API docs, examples, license audit, advisory audit, SBOM,
  provenance, signed tags, and reproducible source archives.
- Capabilities: a real JSON tool performs outbound HTTP only through an exact,
  method-bound, body-limited grant; default deny and private-network policy are
  covered by integration tests and documented in `docs/security.md`.

Current evidence commands:

```text
cargo test --test http_security --test http_stress
cargo run --release --example http_benchmark -- 20 1000
cargo run --release --example http_capacity_benchmark -- 10000
uv run benchmarks/bootstrap_tools.py
uv run benchmarks/http_compare.py --cold-iterations 20 --warm-requests 1000
```
