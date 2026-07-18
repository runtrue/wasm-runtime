#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# ///
"""Compare runtime benchmark JSON while preserving an alert-first workflow."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ABSOLUTE_LATENCY_FLOOR_NS = 25_000


@dataclass(frozen=True)
class Metric:
    name: str
    baseline: float
    candidate: float
    direction: str
    threshold: float
    unit: str

    @property
    def delta(self) -> float:
        if self.baseline == 0:
            return 0.0 if self.candidate == 0 else float("inf")
        return (self.candidate - self.baseline) / self.baseline

    @property
    def regressed(self) -> bool:
        if self.unit == "ns" and abs(self.candidate - self.baseline) < ABSOLUTE_LATENCY_FLOOR_NS:
            return False
        return (
            self.delta > self.threshold
            if self.direction == "lower"
            else self.delta < -self.threshold
        )


def load(path: Path) -> dict[str, Any]:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read benchmark {path}: {error}") from error
    if not isinstance(result, dict):
        raise ValueError(f"benchmark {path} is not a JSON object")
    return result


def value(report: dict[str, Any], *path: str) -> float:
    current: Any = report
    for segment in path:
        if not isinstance(current, dict) or segment not in current:
            raise ValueError(f"missing metric {'.'.join(path)}")
        current = current[segment]
    if not isinstance(current, (int, float)):
        raise ValueError(f"metric {'.'.join(path)} is not numeric")
    return float(current)


def list_value(
    report: dict[str, Any], collection: str, selector: str, expected: int, field: str
) -> float:
    entries = report.get(collection)
    if not isinstance(entries, list):
        raise ValueError(f"missing {collection} samples")
    for entry in entries:
        if isinstance(entry, dict) and entry.get(selector) == expected:
            result = entry.get(field)
            if isinstance(result, (int, float)):
                return float(result)
    raise ValueError(f"missing {collection} {selector}={expected} field={field}")


def http_metrics(
    baseline: dict[str, Any], candidate: dict[str, Any], latency: float, size: float
) -> list[Metric]:
    metrics: list[Metric] = []
    for tier, label, field in (
        ("cold", "Cold total", "harness_total_ns"),
        ("disk_aot", "Disk AOT total", "harness_total_ns"),
        ("warmish_restart", "Warmish request", "request_ns"),
        ("paused_resident", "Resident request", "request_ns"),
    ):
        for percentile in ("p50", "p95"):
            metrics.append(
                Metric(
                    f"{label} {percentile}",
                    value(baseline, tier, percentile, field),
                    value(candidate, tier, percentile, field),
                    "lower",
                    latency,
                    "ns",
                )
            )
    metrics.append(
        Metric(
            "AOT artifact bytes",
            value(baseline, "disk_aot_artifact_bytes"),
            value(candidate, "disk_aot_artifact_bytes"),
            "lower",
            size,
            "bytes",
        )
    )
    for concurrency in (1, 8, 32):
        metrics.extend(
            [
                Metric(
                    f"Throughput c{concurrency}",
                    list_value(
                        baseline,
                        "throughput",
                        "concurrency",
                        concurrency,
                        "requests_per_second",
                    ),
                    list_value(
                        candidate,
                        "throughput",
                        "concurrency",
                        concurrency,
                        "requests_per_second",
                    ),
                    "higher",
                    latency,
                    "rps",
                ),
                Metric(
                    f"Latency c{concurrency} p95",
                    list_value(
                        baseline,
                        "throughput",
                        "concurrency",
                        concurrency,
                        "latency_p95_ns",
                    ),
                    list_value(
                        candidate,
                        "throughput",
                        "concurrency",
                        concurrency,
                        "latency_p95_ns",
                    ),
                    "lower",
                    latency,
                    "ns",
                ),
            ]
        )
    return metrics


def capacity_metrics(
    baseline: dict[str, Any], candidate: dict[str, Any], memory: float, size: float
) -> list[Metric]:
    measured = int(value(candidate, "worker_projection_basis", "measured_workers"))
    return [
        Metric(
            "Capacity AOT bytes",
            value(baseline, "authenticated_aot_bytes"),
            value(candidate, "authenticated_aot_bytes"),
            "lower",
            size,
            "bytes",
        ),
        Metric(
            f"Resident RSS at {measured}",
            list_value(baseline, "resident_workers", "workers", measured, "rss_bytes"),
            list_value(candidate, "resident_workers", "workers", measured, "rss_bytes"),
            "lower",
            memory,
            "bytes",
        ),
        Metric(
            "Marginal RSS per worker",
            value(baseline, "worker_projection_basis", "marginal_rss_per_worker_bytes"),
            value(candidate, "worker_projection_basis", "marginal_rss_per_worker_bytes"),
            "lower",
            memory,
            "bytes",
        ),
        Metric(
            "Projected workers per GiB",
            value(baseline, "worker_projection_basis", "projected_workers_per_gib"),
            value(candidate, "worker_projection_basis", "projected_workers_per_gib"),
            "higher",
            memory,
            "workers",
        ),
    ]


def formatted(number: float, unit: str) -> str:
    if unit == "ns":
        return f"{number / 1_000_000:.3f} ms"
    if unit == "bytes":
        return f"{number / 1024:.1f} KiB"
    if unit == "rps":
        return f"{number:,.0f} req/s"
    return f"{number:,.0f} {unit}"


def comparability(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    warnings = []
    for field in ("host_os", "host_arch", "wasmtime_version"):
        before, after = baseline.get(field), candidate.get(field)
        if before != after:
            warnings.append(f"{field} changed from {before!r} to {after!r}")
    return warnings


def markdown(metrics: list[Metric], warnings: list[str]) -> str:
    lines = [
        "# Runtime performance comparison",
        "",
        "Thresholds are alert-only unless enforcement is selected.",
        "Latency changes below 25 microseconds are treated as timer/runner noise.",
        "",
    ]
    if warnings:
        lines.extend(["## Comparability warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")
    lines.extend(
        [
            "| Metric | Baseline | Candidate | Change | Status |",
            "| --- | ---: | ---: | ---: | --- |",
        ]
    )
    for metric in metrics:
        status = "REGRESSION" if metric.regressed else "ok"
        lines.append(
            f"| {metric.name} | {formatted(metric.baseline, metric.unit)} "
            f"| {formatted(metric.candidate, metric.unit)} | {metric.delta:+.1%} | {status} |"
        )
    lines.extend(
        ["", f"Regressions outside thresholds: **{sum(m.regressed for m in metrics)}**", ""]
    )
    return "\n".join(lines)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--capacity-baseline", type=Path)
    parser.add_argument("--capacity-candidate", type=Path)
    parser.add_argument("--latency-threshold", type=float, default=0.30)
    parser.add_argument("--memory-threshold", type=float, default=0.25)
    parser.add_argument("--size-threshold", type=float, default=0.05)
    parser.add_argument("--mode", choices=("warn", "fail"), default="warn")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    options = arguments()
    try:
        baseline, candidate = load(options.baseline), load(options.candidate)
        warnings = comparability(baseline, candidate)
        metrics = http_metrics(
            baseline, candidate, options.latency_threshold, options.size_threshold
        )
        if bool(options.capacity_baseline) != bool(options.capacity_candidate):
            raise ValueError("both capacity files must be supplied together")
        if options.capacity_baseline and options.capacity_candidate:
            capacity_before = load(options.capacity_baseline)
            capacity_after = load(options.capacity_candidate)
            warnings.extend(comparability(capacity_before, capacity_after))
            metrics.extend(
                capacity_metrics(
                    capacity_before,
                    capacity_after,
                    options.memory_threshold,
                    options.size_threshold,
                )
            )
    except ValueError as error:
        print(f"benchmark comparison failed: {error}", file=sys.stderr)
        return 2
    report = markdown(metrics, list(dict.fromkeys(warnings)))
    print(report)
    if options.output:
        options.output.write_text(report, encoding="utf-8")
    return int(options.mode == "fail" and any(metric.regressed for metric in metrics))


if __name__ == "__main__":
    raise SystemExit(main())
