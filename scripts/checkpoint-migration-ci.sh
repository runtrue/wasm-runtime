#!/usr/bin/env bash
set -euo pipefail

expected_test="${RUNTRUE_CHECKPOINT_MIGRATION_TEST:-moves_a_checkpoint_from_one_worker_to_another}"
success_sentinel="RUNTRUE_WASIX_CHECKPOINT_MIGRATION_OK value=424242 workers=distinct"

test_list="$(
    cargo test --locked --all-features \
        --test wasix_worker_migration -- --list
)"
match_count="$(
    grep -Fxc -- "$expected_test: test" <<<"$test_list" || true
)"
if [[ "$match_count" != "1" ]]; then
    printf 'expected exactly one WASIX checkpoint migration test named %q, found %s\n' \
        "$expected_test" "$match_count" >&2
    exit 1
fi

output="$(mktemp)"
trap 'rm -f "$output"' EXIT
cargo test --locked --all-features \
    --test wasix_worker_migration -- \
    --exact "$expected_test" --nocapture --test-threads=1 2>&1 | tee "$output"

sentinel_count="$(
    { grep -Fo -- "$success_sentinel" "$output" || true; } | wc -l
)"
sentinel_count="${sentinel_count//[[:space:]]/}"
if [[ "$sentinel_count" != "1" ]]; then
    printf 'expected exactly one completed WASIX checkpoint migration sentinel, found %s\n' \
        "$sentinel_count" >&2
    exit 1
fi
