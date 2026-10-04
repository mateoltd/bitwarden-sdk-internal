#!/usr/bin/env bash
set -euo pipefail

# v1.8.0 is a rolling prerelease whose assets are replaced by upstream builds.
# Pin the official stable release's asset identity as well as its content hash.
readonly TLA_VERSION="1.7.4"
readonly TLA_ASSET_ID="184694200"
readonly TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
readonly FORMAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TOOL_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bitwarden-alias-tla-${TLA_VERSION}-${TLA_ASSET_ID}"
readonly TLA_JAR="${TOOL_DIR}/tla2tools.jar"
readonly MODEL_DIR="${TOOL_DIR}/model"

if grep -Eq '^[[:space:]]*(ASSUME|AXIOM)([[:space:]]|$)' "${FORMAL_DIR}"/*.tla; then
    echo "Unchecked TLA+ assumptions and axioms are forbidden in the alias security model" >&2
    exit 1
fi

mkdir -p "${TOOL_DIR}"
if [[ ! -f "${TLA_JAR}" ]]; then
    curl --fail --location --silent --show-error \
        --header "Accept: application/octet-stream" \
        "https://api.github.com/repos/tlaplus/tlaplus/releases/assets/${TLA_ASSET_ID}" \
        --output "${TLA_JAR}"
fi

if command -v shasum >/dev/null 2>&1; then
    actual_sha256="$(shasum -a 256 "${TLA_JAR}")"
elif command -v sha256sum >/dev/null 2>&1; then
    actual_sha256="$(sha256sum "${TLA_JAR}")"
else
    echo "No SHA-256 implementation found (requires shasum or sha256sum)" >&2
    exit 1
fi
actual_sha256="${actual_sha256%% *}"
if [[ "${actual_sha256}" != "${TLA_SHA256}" ]]; then
    echo "TLA+ ${TLA_VERSION} asset ${TLA_ASSET_ID} SHA-256 mismatch: expected ${TLA_SHA256}, got ${actual_sha256}" >&2
    exit 1
fi

mkdir -p "${MODEL_DIR}"
cp "${FORMAL_DIR}"/*.tla "${FORMAL_DIR}"/*.cfg "${MODEL_DIR}/"

for config in AliasVault AliasJournal AliasLifecycle AliasLifecycleQuiescent; do
    java -XX:+UseParallelGC -jar "${TLA_JAR}" \
        -cleanup -workers auto -config "${MODEL_DIR}/${config}.cfg" \
        "${MODEL_DIR}/${config%%Quiescent}.tla"
done
