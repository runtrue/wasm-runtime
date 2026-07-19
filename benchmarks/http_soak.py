#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# ///
"""Drive the standalone HTTP example over real TCP for a bounded soak run."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import socket
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/p3-http-hello.component.wasm"
SERVER = ROOT / "target/release/examples/http_server"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_ready(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"server exited before readiness: {stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.01)
    raise TimeoutError("server did not listen within 20 seconds")


def rss_bytes(pid: int) -> int | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return None


def percentile(histogram: Counter[int], percentile_value: int) -> int:
    total = sum(histogram.values())
    target = max(1, (total * percentile_value + 99) // 100)
    observed = 0
    for bucket, count in sorted(histogram.items()):
        observed += count
        if observed >= target:
            return 1 << (bucket + 1)
    return 0


async def one_request(port: int) -> int:
    started = time.perf_counter_ns()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /soak HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
    await writer.drain()
    response = await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    await writer.wait_closed()
    if not response.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(response[:100].decode("utf-8", "replace"))
    return time.perf_counter_ns() - started


async def run_soak(port: int, pid: int, duration: float, concurrency: int) -> dict[str, Any]:
    deadline = time.monotonic() + duration
    lock = asyncio.Lock()
    histogram: Counter[int] = Counter()
    requests = 0
    errors = 0
    error_samples: list[str] = []
    rss_samples: list[int] = []

    async def worker() -> None:
        nonlocal requests, errors
        while time.monotonic() < deadline:
            try:
                elapsed = await one_request(port)
                async with lock:
                    requests += 1
                    histogram[max(0, elapsed.bit_length() - 1)] += 1
            except Exception as error:  # noqa: BLE001 - errors are soak evidence.
                async with lock:
                    errors += 1
                    if len(error_samples) < 20:
                        error_samples.append(str(error))

    async def sample_memory() -> None:
        while time.monotonic() < deadline:
            sample = rss_bytes(pid)
            if sample is not None:
                rss_samples.append(sample)
            await asyncio.sleep(1)

    started = time.monotonic()
    await asyncio.gather(
        *(worker() for _ in range(concurrency)),
        sample_memory(),
    )
    elapsed = time.monotonic() - started
    return {
        "duration_seconds": elapsed,
        "concurrency": concurrency,
        "requests": requests,
        "errors": errors,
        "requests_per_second": requests / elapsed if elapsed else 0,
        "latency_p50_ns_upper_bound": percentile(histogram, 50),
        "latency_p95_ns_upper_bound": percentile(histogram, 95),
        "latency_p99_ns_upper_bound": percentile(histogram, 99),
        "rss_first_bytes": rss_samples[0] if rss_samples else None,
        "rss_last_bytes": rss_samples[-1] if rss_samples else None,
        "rss_max_bytes": max(rss_samples) if rss_samples else None,
        "error_samples": error_samples,
    }


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration-seconds", type=float, default=60)
    parser.add_argument("--concurrency", type=int, default=8)
    return parser.parse_args()


def main() -> int:
    options = arguments()
    if options.duration_seconds <= 0 or options.concurrency <= 0:
        raise SystemExit("duration and concurrency must be positive")
    subprocess.run(
        ["cargo", "build", "--locked", "--release", "--example", "http_server"],
        cwd=ROOT,
        check=True,
    )
    port = free_port()
    process = subprocess.Popen(
        [str(SERVER), str(FIXTURE), f"127.0.0.1:{port}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout = ""
    try:
        wait_ready(process, port)
        report = asyncio.run(
            run_soak(port, process.pid, options.duration_seconds, options.concurrency)
        )
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            stdout, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, _ = process.communicate(timeout=10)
    report.update(
        {
            "schema": "runtrue-wasm-http-soak-v1",
            "host_os": platform.system().lower(),
            "host_arch": platform.machine(),
            "python": platform.python_version(),
            "runtime_version": json.loads(
                subprocess.check_output(
                    [
                        "cargo",
                        "metadata",
                        "--locked",
                        "--no-deps",
                        "--format-version",
                        "1",
                    ],
                    cwd=ROOT,
                    text=True,
                )
            )["packages"][0]["version"],
            "server_ready": stdout.splitlines()[0] if stdout else None,
            "pid": process.pid,
        }
    )
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return int(report["errors"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
