#!/usr/bin/env bash
set -euo pipefail

output_file="${1:-}"
[[ -n "$output_file" ]] || {
    echo "Usage: $0 OUTPUT_FILE" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$(dirname "$output_file")"
output_file="$(cd "$(dirname "$output_file")" && pwd)/$(basename "$output_file")"

{
    cargo tree --locked --manifest-path "$repository_root/Cargo.toml" \
        --package bitwarden-alias \
        --all-features \
        --edges normal,build \
        --target all \
        --prefix none \
        --format '{p}'
    cargo tree --locked --manifest-path "$repository_root/Cargo.toml" \
        --package bitwarden-uniffi \
        --edges normal,build \
        --target all \
        --prefix none \
        --format '{p}'
    cargo tree --locked --manifest-path "$repository_root/Cargo.toml" \
        --package bitwarden-wasm-internal \
        --edges normal,build \
        --target wasm32-unknown-unknown \
        --prefix none \
        --format '{p}'
} | sed -nE 's/^([^ ]+) v([^ ]+).*/\1@\2/p' | LC_ALL=C sort -u >"$output_file"

for root_package in bitwarden-alias bitwarden-uniffi bitwarden-wasm-internal; do
    grep -q "^${root_package}@" "$output_file" || {
        echo "Cargo SBOM graph failed: missing $root_package" >&2
        exit 1
    }
done
if grep -Eq '^bitwarden-(commercial-vault|pam|sm)@' "$output_file"; then
    echo "Cargo SBOM graph failed: commercial or PAM package is active" >&2
    exit 1
fi

echo "Recorded $(wc -l <"$output_file" | tr -d ' ') active public Cargo packages"
