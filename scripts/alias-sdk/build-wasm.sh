#!/usr/bin/env bash
set -euo pipefail

output_directory="${1:-}"
[[ -n "$output_directory" ]] || {
    echo "Usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$repository_root/node_modules/.bin:$PATH"
for command_name in node npm wasm-opt wasm2js; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "WASM release host gate failed: missing $command_name" >&2
        exit 1
    }
done

output_directory="$(mkdir -p "$output_directory" && cd "$output_directory" && pwd)"
"$repository_root/crates/bitwarden-wasm-internal/build.sh" -r
"$repository_root/scripts/check-oss-artifact-boundary.sh" \
    --wasm "$repository_root/crates/bitwarden-wasm-internal/npm"
(
    cd "$repository_root/crates/bitwarden-wasm-internal/npm"
    npm pack --ignore-scripts --pack-destination "$output_directory"
)

echo "WASM alias SDK artifact built at $output_directory"
