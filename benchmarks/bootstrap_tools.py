#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# ///
"""Install pinned benchmark CLIs without pip or global machine changes."""

from __future__ import annotations

import hashlib
import io
import platform
import stat
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / ".benchmark-tools"
ASSETS = {
    "wasm-opt": (
        "https://github.com/WebAssembly/binaryen/releases/download/version_131/binaryen-version_131-x86_64-linux.tar.gz",
        "b5bf1f0eaf17c63ee588ff7a5954dc8f6ce2c26989051c66f24dfe9ece3e46db",
        "binaryen-version_131/bin/wasm-opt",
    ),
    "wasmtime": (
        "https://github.com/bytecodealliance/wasmtime/releases/download/v46.0.1/wasmtime-v46.0.1-x86_64-linux.tar.xz",
        "9ae0b17ea298bcc52277a8208d6ab7fae8e1a89579672f9d82f9d86c116edb62",
        "wasmtime-v46.0.1-x86_64-linux/wasmtime",
    ),
    "wasi_snapshot_preview1.proxy.wasm": (
        "https://github.com/bytecodealliance/wasmtime/releases/download/v46.0.1/wasi_snapshot_preview1.proxy.wasm",
        "82b0c20205fe8fab16c9e6a48fb044c61f8e439a1d40a456f5bb2f9b31518b4e",
        None,
    ),
}


def main() -> None:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("the first pinned comparison matrix supports Linux x86_64 only")
    DESTINATION.mkdir(mode=0o755, exist_ok=True)
    for name, (url, expected, member) in ASSETS.items():
        output = DESTINATION / name
        if output.exists():
            continue
        with urllib.request.urlopen(url, timeout=60) as response:
            archive = response.read()
        actual = hashlib.sha256(archive).hexdigest()
        if actual != expected:
            raise SystemExit(f"{name} archive SHA-256 mismatch: {actual}")
        if member is None:
            output.write_bytes(archive)
        else:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
                source = bundle.extractfile(member)
                if source is None:
                    raise SystemExit(f"{member} missing from {name} archive")
                output.write_bytes(source.read())
            output.chmod(output.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"installed {name}: {output}")


if __name__ == "__main__":
    main()
