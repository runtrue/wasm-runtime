#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# ///
"""Measure identical WASI HTTP components over actual TCP."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import platform
import socket
import subprocess
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "tests/fixtures/p2-http-hello.component.wasm"
TOOLS = ROOT / ".benchmark-tools"


def percentile(samples: list[int], percent: int) -> int:
    ordered = sorted(samples)
    return ordered[max(0, (len(ordered) * percent + 99) // 100 - 1)]


def distribution(samples: list[int]) -> dict[str, object]:
    return {"samples_ns": samples, "p50_ns": percentile(samples, 50), "p95_ns": percentile(samples, 95)}


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(port: int) -> int:
    started = time.perf_counter_ns()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", "/")
    response = connection.getresponse()
    body = response.read()
    connection.close()
    if response.status != 200 or body != b"Hello, WASI!":
        raise RuntimeError(f"unexpected response: {response.status} {body!r}")
    return time.perf_counter_ns() - started


def keep_alive_requests(port: int, requests: int) -> list[int]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    samples: list[int] = []
    try:
        for _ in range(requests):
            started = time.perf_counter_ns()
            connection.request("GET", "/")
            response = connection.getresponse()
            body = response.read()
            if response.status != 200 or body != b"Hello, WASI!":
                raise RuntimeError(f"unexpected response: {response.status} {body!r}")
            samples.append(time.perf_counter_ns() - started)
    finally:
        connection.close()
    return samples


def throughput(port: int, requests: int, concurrency: int) -> dict[str, object]:
    started = time.perf_counter_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        samples = list(pool.map(lambda _: request(port), range(requests)))
    elapsed = time.perf_counter_ns() - started
    return {
        "concurrency": concurrency,
        "requests": requests,
        "elapsed_ns": elapsed,
        "requests_per_second": requests * 1_000_000_000 // max(1, elapsed),
        "latency": distribution(samples),
    }


def wait_ready(process: subprocess.Popen[bytes], port: int, started: int) -> int:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read().decode(errors="replace") if process.stdout else ""
            raise RuntimeError(f"runner exited {process.returncode}: {output}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return time.perf_counter_ns() - started
        except OSError:
            time.sleep(0.001)
    raise TimeoutError("runner did not listen within 20 seconds")


def rss_bytes(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except FileNotFoundError:
        return None
    return None


def host_metadata() -> dict[str, object]:
    cpu = "unknown"
    memory = None
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            memory = int(line.split()[1]) * 1024
            break
    return {
        "os": platform.system(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu": cpu,
        "logical_cpus": os.cpu_count(),
        "memory_total_bytes": memory,
        "python": platform.python_version(),
    }


def output(*arguments: str) -> str:
    return subprocess.check_output(arguments, text=True).strip()


def command(name: str, port: int) -> tuple[list[str], dict[str, str]]:
    environment = os.environ.copy()
    if name == "standalone-package":
        return ([str(ROOT / "target/release/examples/http_server"), str(COMPONENT), f"127.0.0.1:{port}"], environment)
    if name == "raw-wasmtime-embedding":
        return ([str(ROOT / "target/release/examples/raw_wasmtime_http_server"), str(COMPONENT), f"127.0.0.1:{port}"], environment)
    if name == "wasmtime-serve":
        return ([str(TOOLS / "wasmtime"), "serve", "-C", "cache=n", "--max-instance-reuse-count", "10000", "--idle-instance-timeout", "30s", "--addr", f"127.0.0.1:{port}", str(COMPONENT)], environment)
    raise ValueError(name)


def stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def benchmark(name: str, cold_iterations: int, warm_requests: int) -> dict[str, object]:
    readiness: list[int] = []
    first: list[int] = []
    warm: list[int] = []
    keep_alive: list[int] = []
    throughput_results: list[dict[str, object]] = []
    observed_rss: list[int] = []
    for iteration in range(cold_iterations):
        port = free_port()
        argv, environment = command(name, port)
        started = time.perf_counter_ns()
        process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            readiness.append(wait_ready(process, port, started))
            first.append(request(port))
            value = rss_bytes(process.pid)
            if value is not None:
                observed_rss.append(value)
            if iteration == cold_iterations - 1:
                warm.extend(request(port) for _ in range(warm_requests))
                keep_alive.extend(keep_alive_requests(port, warm_requests))
                throughput_results.extend(
                    throughput(port, warm_requests, concurrency)
                    for concurrency in (1, 8, 32)
                )
        finally:
            stop(process)
    return {
        "runner": name,
        "process_ready": distribution(readiness),
        "first_tcp_request": distribution(first),
        "fresh_connection_warm": distribution(warm),
        "keep_alive_warm": distribution(keep_alive),
        "throughput": throughput_results,
        "rss_bytes": observed_rss,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cold-iterations", type=int, default=5)
    parser.add_argument("--warm-requests", type=int, default=200)
    args = parser.parse_args()
    if args.cold_iterations < 1 or args.warm_requests < 1:
        parser.error("sample counts must be positive")
    required = [TOOLS / "wasmtime", ROOT / "target/release/examples/http_server", ROOT / "target/release/examples/raw_wasmtime_http_server"]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit("build the server and bootstrap tools first; missing: " + ", ".join(missing))
    report = {
        "schema": "standalone-wasm-http-tcp-comparison-v1",
        "component": str(COMPONENT.relative_to(ROOT)),
        "component_bytes": COMPONENT.stat().st_size,
        "component_sha256": hashlib.sha256(COMPONENT.read_bytes()).hexdigest(),
        "wasi_profile": "wasi:http/proxy@0.2.12",
        "host": host_metadata(),
        "versions": {
            "wasmtime": output(str(TOOLS / "wasmtime"), "--version"),
            "rustc": output("rustc", "--version"),
            "standalone_package": tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"],
        },
        "settings": {
            "wasmtime_serve_cache": False,
            "max_instance_reuse_count": 10_000,
            "idle_instance_timeout_seconds": 30,
            "tcp_mode": "HTTP/1.1 loopback; fresh-connection and keep-alive measured separately",
        },
        "cold_iterations": args.cold_iterations,
        "warm_requests": args.warm_requests,
        "runners": [benchmark(name, args.cold_iterations, args.warm_requests) for name in ("raw-wasmtime-embedding", "wasmtime-serve", "standalone-package")],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
