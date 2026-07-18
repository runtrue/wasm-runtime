#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: cache-admin.sh inspect <cache-directory>" >&2
    echo "       cache-admin.sh clear <cache-directory> --confirm <canonical-cache-directory>" >&2
    exit 2
}

[[ $# -ge 2 ]] || usage
operation="$1"
cache_directory="$2"

[[ -d "$cache_directory" ]] || {
    echo "cache path is not a directory: $cache_directory" >&2
    exit 1
}
[[ ! -L "$cache_directory" ]] || {
    echo "refusing a symlink cache directory: $cache_directory" >&2
    exit 1
}

canonical_directory="$(realpath "$cache_directory")"
case "$canonical_directory" in
    /|"${HOME:-/nonexistent}"|/root|/home|/tmp|/var|/var/tmp)
        echo "refusing broad or sensitive directory: $canonical_directory" >&2
        exit 1
        ;;
esac

inspect() {
    artifact_count="$(find "$canonical_directory" -mindepth 1 -maxdepth 1 -type f -name '*.aot' -print | wc -l)"
    metadata_count="$(find "$canonical_directory" -mindepth 1 -maxdepth 1 -type f -name '*.aot.json' -print | wc -l)"
    temporary_count="$(find "$canonical_directory" -mindepth 1 -maxdepth 1 -type f \( -name '*.tmp-*' -o -name '*.aot.tmp-*' \) -print | wc -l)"
    byte_count="$(find "$canonical_directory" -mindepth 1 -maxdepth 1 -type f \( -name '*.aot' -o -name '*.aot.json' -o -name '*.tmp-*' -o -name '*.aot.tmp-*' \) -printf '%s\n' | awk '{ total += $1 } END { print total + 0 }')"
    echo "cache=$canonical_directory"
    echo "artifacts=$artifact_count metadata=$metadata_count temporary=$temporary_count bytes=$byte_count"
    if [[ "$artifact_count" != "$metadata_count" || "$temporary_count" != 0 ]]; then
        echo "status=attention-required"
        return 1
    fi
    echo "status=consistent-file-counts"
}

case "$operation" in
    inspect)
        [[ $# -eq 2 ]] || usage
        inspect
        ;;
    clear)
        [[ $# -eq 4 && "$3" == "--confirm" ]] || usage
        confirmation="$(realpath -m "$4")"
        [[ "$confirmation" == "$canonical_directory" ]] || {
            echo "confirmation does not exactly match $canonical_directory" >&2
            exit 1
        }
        find "$canonical_directory" -mindepth 1 -maxdepth 1 -type f \
            \( -name '*.aot' -o -name '*.aot.json' -o -name '*.tmp-*' -o -name '*.aot.tmp-*' \) \
            -delete
        echo "cleared=$canonical_directory"
        ;;
    *)
        usage
        ;;
esac
