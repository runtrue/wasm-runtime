#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# ///
"""Build standard WASI HTTP fixtures with the pinned official proxy adapter."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / ".benchmark-tools/wasi_snapshot_preview1.proxy.wasm"
FIXTURES = {
    "p2-http-hello": "p2_http_hello.wasm",
    "json-http-tool": "json_http_tool.wasm",
}


def run(*arguments: str) -> None:
    subprocess.run(arguments, cwd=ROOT, check=True)


def main() -> None:
    if not ADAPTER.is_file():
        raise SystemExit("run `uv run benchmarks/bootstrap_tools.py` first")
    oversized_source = ROOT / "tests/fixtures/oversized_output.rs"
    oversized_output = ROOT / "tests/fixtures/oversized-output.component.wasm"
    run(
        "rustc",
        "--edition=2024",
        "--crate-name",
        "oversized_output",
        "--target",
        "wasm32-wasip2",
        "-C",
        "opt-level=z",
        "-C",
        "lto=fat",
        "-C",
        "panic=abort",
        "-C",
        "strip=debuginfo",
        str(oversized_source),
        "-o",
        str(oversized_output),
    )
    print(
        f"{oversized_output.relative_to(ROOT)} "
        f"sha256={hashlib.sha256(oversized_output.read_bytes()).hexdigest()}"
    )
    for package, artifact in FIXTURES.items():
        manifest = ROOT / f"benchmarks/fixtures/{package}/Cargo.toml"
        run(
            "cargo",
            "build",
            "--manifest-path",
            str(manifest),
            "--target",
            "wasm32-wasip1",
            "--release",
        )
        module = manifest.parent / f"target/wasm32-wasip1/release/{artifact}"
        output = ROOT / f"tests/fixtures/{package}.component.wasm"
        run(
            "cargo",
            "run",
            "--quiet",
            "--example",
            "componentize",
            "--",
            str(module),
            str(ADAPTER),
            str(output),
        )
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        print(f"{output.relative_to(ROOT)} sha256={digest}")


if __name__ == "__main__":
    main()
