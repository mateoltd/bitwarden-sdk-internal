#!/usr/bin/env bash
set -euo pipefail

readonly TLA_VERSION="1.8.0"
readonly TLA_SHA256="ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f"
readonly FORMAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TOOL_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bitwarden-alias-tla-${TLA_VERSION}"
readonly TLA_JAR="${TOOL_DIR}/tla2tools.jar"
readonly MODEL_DIR="${TOOL_DIR}/model"

if grep -Eq '^[[:space:]]*(ASSUME|AXIOM)([[:space:]]|$)' "${FORMAL_DIR}"/*.tla; then
    echo "Unchecked TLA+ assumptions and axioms are forbidden in the alias security model" >&2
    exit 1
fi

mkdir -p "${TOOL_DIR}"
if [[ ! -f "${TLA_JAR}" ]]; then
    curl --fail --location --silent --show-error \
        "https://github.com/tlaplus/tlaplus/releases/download/v${TLA_VERSION}/tla2tools.jar" \
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
    echo "TLA+ tools SHA-256 mismatch" >&2
    exit 1
fi

mkdir -p "${MODEL_DIR}"
cp "${FORMAL_DIR}"/*.tla "${FORMAL_DIR}"/*.cfg "${MODEL_DIR}/"

for config in AliasVault AliasLifecycle AliasLifecycleQuiescent; do
    java -XX:+UseParallelGC -jar "${TLA_JAR}" \
        -cleanup -workers auto -config "${MODEL_DIR}/${config}.cfg" \
        "${MODEL_DIR}/${config%%Quiescent}.tla"
done
