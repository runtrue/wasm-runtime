# Service soak testing

The tagged release candidate must run as a real TCP service before public
release. The soak harness starts the standalone streaming HTTP example, creates
fresh TCP connections at bounded concurrency, records errors and latency
histogram bounds, and samples Linux RSS without retaining every request
measurement.

Run a short validation locally:

```text
uv run benchmarks/http_soak.py --duration-seconds 60 --concurrency 8 > soak.json
```

For the release gate, run the same tagged binary continuously for at least seven
days on the target Linux host. Preserve the JSON, service logs, kernel and
OOM events, deployment configuration, component digest, restart count, and
cache metrics. A passing run has zero request errors, zero unexpected process
restarts or OOM events, and no unexplained monotonic RSS growth.

The local harness cannot replace production observation: outbound policy,
tenant separation, host load, DNS, storage pressure, and rolling deployment
must be exercised in the target environment. Apply the collection rules in
[benchmark methodology](benchmark-methodology.md) when publishing soak data.
