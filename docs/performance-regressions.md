# Performance regression policy

Performance evidence is collected independently from correctness CI. Shared
GitHub runners are suitable for finding large changes, but not for enforcing
sub-millisecond latency claims. The scheduled workflow therefore reports
threshold violations without blocking development by default.

The workflow records raw samples and host metadata for cold compilation,
authenticated disk AOT, warmish restart, resident calls, throughput, AOT size,
resident RSS, marginal worker RSS, and workers per GiB. Current alert thresholds
are 30% for latency and throughput, 25% for memory, and 5% for artifact size.
Latency changes smaller than 25 microseconds are treated as measurement noise
even when their relative percentage is large.

Actual TCP results for raw embedding, the standard Wasmtime CLI, and this
package are collected as a separate artifact rather than mixed with direct
handler thresholds.

Set the repository variable `PERFORMANCE_RUNNER` to a stable self-hosted runner
label before treating comparisons as release evidence. That runner should have
a fixed CPU allocation and governor, reserved memory, no unrelated workloads,
and a documented kernel and mitigation profile. Run the workflow manually with
`enforce` only after a baseline from that same runner has been committed.

Local comparison remains alert-only unless `--mode fail` is selected:

```text
uv run benchmarks/check_regression.py \
  benchmarks/results/http-direct-linux-x86_64-2026-07-18.json candidate.json
```

Never publish only the summary table. Keep the candidate JSON, host metadata,
component digest, concurrency, and measurement boundaries with every claim.
