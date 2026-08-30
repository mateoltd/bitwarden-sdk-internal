#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
package_directory="$repository_root/crates/bitwarden-wasm-internal/npm"
test_directory="$repository_root/crates/bitwarden-wasm-internal/integration-tests"

[[ -f "$package_directory/bitwarden_wasm_internal_bg.wasm" ]] || {
    echo "WASM conformance gate requires a built package; run scripts/alias-sdk/build-wasm.sh first" >&2
    exit 1
}

(
    cd "$test_directory"
    npm ci --ignore-scripts
    npm test -- --runInBand \
        tests/alias/reference.test.ts \
        tests/alias/adversarial.test.ts
)

echo "Alias SDK WASM security conformance passed"
