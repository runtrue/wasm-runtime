#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

version="$(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[0].version')"
workspace="$(mktemp -d)"
trap 'rm -rf "$workspace"' EXIT
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    if [[ "$CARGO_TARGET_DIR" = /* ]]; then
        package_target="$CARGO_TARGET_DIR"
    else
        package_target="$repository_root/$CARGO_TARGET_DIR"
    fi
else
    package_target="$workspace/package-build"
fi
archive="$package_target/package/runtrue-wasm-runtime-$version.crate"

package_arguments=(--locked --target-dir "$package_target")
if [[ "${RUNTRUE_ALLOW_DIRTY_PACKAGE:-0}" == "1" ]]; then
    package_arguments+=(--allow-dirty)
fi
cargo package "${package_arguments[@]}"
mkdir "$workspace/package"
tar -xzf "$archive" -C "$workspace/package"
packaged_crate="$workspace/package/runtrue-wasm-runtime-$version"

cargo init --quiet --bin --name packaged-runtime-consumer "$workspace/consumer"
install -m 0644 scripts/package-consumer/main.rs "$workspace/consumer/src/main.rs"
install -m 0644 \
    "$packaged_crate/tests/fixtures/p3-http-hello.component.wasm" \
    "$workspace/consumer/p3-http-hello.component.wasm"

cd "$workspace/consumer"
cargo add --quiet --path "$packaged_crate" runtrue-wasm-runtime
cargo add --quiet tokio@=1.51.1 --features io-util,macros,net,rt-multi-thread
cargo add --quiet wat@=1.251.0
CARGO_TARGET_DIR="$package_target" cargo run --locked --quiet

echo "packaged consumer smoke passed for runtrue-wasm-runtime $version"
