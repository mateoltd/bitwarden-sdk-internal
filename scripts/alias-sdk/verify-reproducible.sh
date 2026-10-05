#!/usr/bin/env bash
set -euo pipefail

first_path="${1:-}"
second_path="${2:-}"
[[ -e "$first_path" && -e "$second_path" ]] || {
    echo "Usage: $0 FIRST_ARTIFACT SECOND_ARTIFACT" >&2
    exit 2
}

digest_file() {
    shasum -a 256 "$1" | awk '{print $1}'
}

if [[ -d "$first_path" || -d "$second_path" ]]; then
    [[ -d "$first_path" && -d "$second_path" ]] || {
        echo "Reproducibility failed: both inputs must have the same type" >&2
        exit 1
    }
    first_manifest="$(mktemp "${TMPDIR:-/tmp}/alias-first.XXXXXX")"
    second_manifest="$(mktemp "${TMPDIR:-/tmp}/alias-second.XXXXXX")"
    trap 'rm -f "$first_manifest" "$second_manifest"' EXIT
    (
        cd "$first_path"
        find . -type f -print | LC_ALL=C sort | while IFS= read -r file; do
            printf '%s  %s\n' "$(digest_file "$file")" "$file"
        done
    ) >"$first_manifest"
    (
        cd "$second_path"
        find . -type f -print | LC_ALL=C sort | while IFS= read -r file; do
            printf '%s  %s\n' "$(digest_file "$file")" "$file"
        done
    ) >"$second_manifest"
    cmp -s "$first_manifest" "$second_manifest" || {
        diff -u "$first_manifest" "$second_manifest" >&2 || true
        echo "Reproducibility failed: directory trees differ" >&2
        exit 1
    }
    digest="$(shasum -a 256 "$first_manifest" | awk '{print $1}')"
else
    first_digest="$(digest_file "$first_path")"
    second_digest="$(digest_file "$second_path")"
    [[ "$first_digest" == "$second_digest" ]] || {
        echo "Reproducibility failed: $first_digest != $second_digest" >&2
        exit 1
    }
    digest="$first_digest"
fi

printf 'reproducible=true\nsha256=%s\n' "$digest"
