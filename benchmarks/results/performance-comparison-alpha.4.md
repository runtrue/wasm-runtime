# Runtime performance comparison

Thresholds are alert-only unless enforcement is selected.
Latency changes below 25 microseconds are treated as timer/runner noise.

| Metric | Baseline | Candidate | Change | Status |
| --- | ---: | ---: | ---: | --- |
| Cold total p50 | 289.427 ms | 296.012 ms | +2.3% | ok |
| Cold total p95 | 299.256 ms | 308.102 ms | +3.0% | ok |
| Disk AOT total p50 | 7.043 ms | 6.969 ms | -1.0% | ok |
| Disk AOT total p95 | 7.685 ms | 7.479 ms | -2.7% | ok |
| Warmish request p50 | 0.884 ms | 1.103 ms | +24.8% | ok |
| Warmish request p95 | 1.104 ms | 1.318 ms | +19.4% | ok |
| Resident request p50 | 0.031 ms | 0.042 ms | +33.1% | ok |
| Resident request p95 | 0.110 ms | 0.077 ms | -30.3% | ok |
| AOT artifact bytes | 812.5 KiB | 812.5 KiB | +0.0% | ok |
| Throughput c1 | 15,448 req/s | 16,427 req/s | +6.3% | ok |
| Latency c1 p95 | 0.053 ms | 0.068 ms | +29.2% | ok |
| Throughput c8 | 48,437 req/s | 49,746 req/s | +2.7% | ok |
| Latency c8 p95 | 0.101 ms | 0.095 ms | -5.3% | ok |
| Throughput c32 | 60,969 req/s | 85,660 req/s | +40.5% | ok |
| Latency c32 p95 | 0.203 ms | 0.168 ms | -17.1% | ok |
| Capacity AOT bytes | 812.5 KiB | 812.5 KiB | +0.0% | ok |
| Resident RSS at 10000 | 614504.0 KiB | 614668.0 KiB | +0.0% | ok |
| Marginal RSS per worker | 58.9 KiB | 58.9 KiB | +0.0% | ok |
| Projected workers per GiB | 17,809 workers | 17,808 workers | -0.0% | ok |

Regressions outside thresholds: **0**
