#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
version="$(tr -d '[:space:]' <"$repository_root/support/alias-sdk-release/VERSION")"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
    echo "Alias SDK release version is not valid SemVer: $version" >&2
    exit 1
}

printf '%s\n' "$version"
