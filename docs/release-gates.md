# 0.1 release gates

The repository remains private until the `0.1` evidence is complete. Workflow
files are automation, not proof by themselves: every claim needs a retained
test, benchmark, report, or operator record from the release candidate.

The current release target is **Linux x86_64**. macOS, ARM64, and other targets
are expansion work, not implied support and not blockers for this target.

## Blocking evidence

| Gate | Required evidence |
| --- | --- |
| Standards | Supported WASI 0.3 and 0.2 command and HTTP fixtures pass on the release target; unsupported worlds fail clearly |
| Failure containment | Traps, CPU deadlines, memory limits, oversized I/O, cancellation, dropped handles, and concurrent failures do not poison later work |
| AOT safety | Modified, truncated, wrong-version, wrong-target, wrong-profile, and wrong-key artifacts fail closed before deserialization |
| Isolation | No inherited environment, arguments, files, sockets, proxies, credentials, or process handles; every command receives a fresh Store |
| Async lifecycle | Host waits, cancellation, pause/resume, idle eviction, worker cleanup, and guest task cleanup are bounded |
| Concurrency | Preparation is single-flight per digest; worker, request, cache, and background limits remain effective under load |
| Capacity | AOT size, baseline RSS, marginal resident-worker RSS, and measured 1/100/1,000/10,000-worker results are retained |
| HTTP capabilities | A real JSON tool reaches only an exact method-bound, body-limited outbound grant; default deny and private-network policy are tested |
| Performance | Cold, disk AOT, warmish, warm, TCP, throughput, and RSS evidence follows the benchmark methodology and compares identical components with raw Wasmtime |
| Packaging | API docs, examples, license and advisory checks, SBOM, provenance where available, checksums, signed tags, and a clean packaged consumer pass |
| Operations | Cache recovery, production isolation, and the seven-day private service soak have operator evidence |

## Local evidence commands

Run the canonical correctness and packaging gate:

```text
scripts/release-check.sh
```

Collect the performance and soak evidence separately so correctness CI does
not hide measurement boundaries:

```text
cargo run --locked --release --example http_benchmark -- 100 5000 > http.json
cargo run --locked --release --example http_capacity_benchmark -- 10000 > capacity.json
uv run benchmarks/bootstrap_tools.py
uv run benchmarks/http_compare.py --cold-iterations 20 --warm-requests 1000 > tcp.json
uv run benchmarks/check_regression.py BASELINE.json CANDIDATE.json
uv run benchmarks/http_soak.py --duration-seconds 60 --concurrency 8 > soak.json
```

Run the TCP comparison three times with rotated `--runner-order` values as
defined in [benchmark methodology](benchmark-methodology.md). A single shared
runner result is not release-grade sub-millisecond evidence.

Release mechanics, protected-environment configuration, trusted publishing,
SBOM generation, checksums, and the operator checklist are defined in the
[release process](releasing.md).
