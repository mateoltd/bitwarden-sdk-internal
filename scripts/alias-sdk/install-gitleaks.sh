#!/usr/bin/env bash
set -euo pipefail

output_directory="${1:-}"
[[ -n "$output_directory" ]] || {
    echo "Usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
}

version="8.30.1"
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
        platform="linux_x64"
        checksum="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
        ;;
    Linux-aarch64|Linux-arm64)
        platform="linux_arm64"
        checksum="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
        ;;
    Darwin-x86_64)
        platform="darwin_x64"
        checksum="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
        ;;
    Darwin-arm64)
        platform="darwin_arm64"
        checksum="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
        ;;
    *)
        echo "Gitleaks install gate failed: unsupported host $(uname -s)-$(uname -m)" >&2
        exit 1
        ;;
esac

command -v curl >/dev/null 2>&1 || {
    echo "Gitleaks install gate failed: curl is unavailable" >&2
    exit 1
}
command -v tar >/dev/null 2>&1 || {
    echo "Gitleaks install gate failed: tar is unavailable" >&2
    exit 1
}

mkdir -p "$output_directory"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-gitleaks.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
archive="gitleaks_${version}_${platform}.tar.gz"
curl --fail --location --silent --show-error \
    "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}" \
    --output "$temporary_directory/$archive"

actual_checksum="$(shasum -a 256 "$temporary_directory/$archive" | awk '{print $1}')"
[[ "$actual_checksum" == "$checksum" ]] || {
    echo "Gitleaks install gate failed: checksum mismatch for $archive" >&2
    exit 1
}

tar -xzf "$temporary_directory/$archive" -C "$output_directory" gitleaks
"$output_directory/gitleaks" version
