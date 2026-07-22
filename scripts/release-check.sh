#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

version="$(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[0].version')"
tag="${1:-}"

if [[ -n "$tag" ]]; then
    if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
        echo "release tag must look like v0.1.0 or v0.1.0-alpha.1" >&2
        exit 1
    fi
    if [[ "${tag#v}" != "$version" ]]; then
        echo "tag $tag does not match Cargo.toml version $version" >&2
        exit 1
    fi
    if [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null || true)" != "tag" ]]; then
        echo "release tag $tag must exist and be annotated" >&2
        exit 1
    fi
    if [[ "$(git rev-parse "$tag^{commit}")" != "$(git rev-parse HEAD)" ]]; then
        echo "release tag $tag does not point at the checked-out commit" >&2
        exit 1
    fi
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "release checks require a clean tracked worktree" >&2
    exit 1
fi

if git ls-files --error-unmatch .benchmark-tools/wasmtime >/dev/null 2>&1; then
    echo "downloaded benchmark tools must not be tracked" >&2
    exit 1
fi

if ! grep -Fq "## [$version]" CHANGELOG.md; then
    echo "CHANGELOG.md has no entry for $version" >&2
    exit 1
fi

cargo fmt --all -- --check
cargo check --locked --all-targets
cargo check --locked --all-targets --all-features
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
cargo package --locked

package_files="$(cargo package --locked --list)"
if grep -Eq '^(\.github/|benchmarks/results/)' <<<"$package_files"; then
    echo "private automation or benchmark evidence leaked into the source package" >&2
    exit 1
fi

scripts/package-consumer-smoke.sh

echo "release checks passed for runtrue-wasm-runtime $version"
