#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

integration_base="$(tr -d '[:space:]' \
    <"$repository_root/support/alias-sdk-release/INTEGRATION_BASE")"
[[ "$integration_base" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Alias SDK integration base is not a full commit ID" >&2
    exit 1
}
fail() {
    echo "Alias SDK external-source pin gate failed: $*" >&2
    exit 1
}
git -C "$repository_root" cat-file -e "$integration_base^{commit}" 2>/dev/null \
    || fail "INTEGRATION_BASE is not present in repository history"
git -C "$repository_root" merge-base --is-ancestor "$integration_base" HEAD \
    || fail "INTEGRATION_BASE is not an ancestor of the candidate"

simplelogin_commit="$(tr -d '[:space:]' <"$repository_root/support/simplelogin/SIMPLELOGIN_COMMIT")"
[[ "$simplelogin_commit" =~ ^[0-9a-f]{40}$ ]] \
    || fail "SIMPLELOGIN_COMMIT must be one full Git SHA"
[[ "$(grep -Ec '^(node_image|ubuntu_image)="[^"[:space:]]+@sha256:[0-9a-f]{64}"$' \
    "$repository_root/support/simplelogin/lab.sh")" == "2" ]] \
    || fail "SimpleLogin build base images must be pinned by platform manifest digest"

while IFS= read -r image; do
    [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] \
        || fail "container image is not digest-pinned: $image"
done < <(
    sed -nE 's/^[[:space:]]*image:[[:space:]]*([^[:space:]]+).*$/\1/p' \
        "$repository_root/support/simplelogin/compose.yml" \
        | grep -v '^bitwarden-simplelogin-lab:'
)

grep -Eq '^distributionSha256Sum=[0-9a-f]{64}$' \
    "$repository_root/crates/bitwarden-uniffi/kotlin/gradle/wrapper/gradle-wrapper.properties" \
    || fail "the Gradle distribution must have a SHA-256 pin"

for target in \
    aarch64-linux-android \
    armv7-linux-androideabi \
    i686-linux-android \
    x86_64-linux-android; do
    grep -Eq \
        "^image = \"ghcr[.]io/cross-rs/${target}@sha256:[0-9a-f]{64}\"$" \
        "$repository_root/Cross.toml" \
        || fail "the cross image for $target must be pinned by manifest digest"
done

clients_contract="$repository_root/support/alias-sdk-release/consumers/typescript/bitwarden-clients-contract.json"
node -e '
  const fs = require("node:fs");
  const contract = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (!/^[0-9a-f]{40}$/.test(contract.commit)) process.exit(1);
' "$clients_contract" || fail "the bitwarden/clients contract must record one full commit SHA"

release_version="$("$repository_root/scripts/alias-sdk/read-release-version.sh")" \
    || fail "the alias SDK release version is invalid"
alias_reference_schema_version="$(tr -d '[:space:]' \
    <"$repository_root/support/alias-sdk-release/ALIAS_REFERENCE_SCHEMA_VERSION")"
[[ "$alias_reference_schema_version" == "1" ]] \
    || fail "the alias reference schema version must be 1"
node -e '
  const fs = require("node:fs");
  const releaseVersion = process.argv[1];
  const packageManifest = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const integration = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
  const conformance = JSON.parse(fs.readFileSync(process.argv[4], "utf8"));
  const aliasReferenceSchemaVersion = Number.parseInt(process.argv[5], 10);
  if (packageManifest.name !== "@bitwarden/sdk-internal") process.exit(1);
  if (packageManifest.version !== releaseVersion) process.exit(1);
  if (packageManifest.aliasReferenceSchemaVersion !== aliasReferenceSchemaVersion) process.exit(1);
  if (integration.schemaVersion !== 1) process.exit(1);
  if (integration.aliasReferenceSchemaVersion !== aliasReferenceSchemaVersion) process.exit(1);
  if (conformance.referenceSchema?.version !== integration.aliasReferenceSchemaVersion) process.exit(1);
  if (!Array.isArray(integration.requiredClientIntegrationSteps)) process.exit(1);
  if (integration.requiredClientIntegrationSteps.length === 0) process.exit(1);
' "$release_version" \
    "$repository_root/crates/bitwarden-wasm-internal/npm/package.json" \
    "$repository_root/support/alias-sdk-release/client-integration.json" \
    "$repository_root/formal/alias-security/conformance-vectors.json" \
    "$alias_reference_schema_version" \
    || fail "release version, TypeScript package, and client handoff metadata must agree"

typescript_fixture="$repository_root/support/alias-sdk-release/consumers/typescript"
node -e '
  const fs = require("node:fs");
  const root = process.argv[1];
  const manifest = JSON.parse(fs.readFileSync(`${root}/package.json`, "utf8"));
  const lock = JSON.parse(fs.readFileSync(`${root}/package-lock.json`, "utf8"));
  for (const [name, version] of Object.entries(manifest.devDependencies ?? {})) {
    if (!/^[0-9]+[.][0-9]+[.][0-9]+$/.test(version)) process.exit(1);
    const resolved = lock.packages?.[`node_modules/${name}`];
    if (resolved?.version !== version || !resolved.integrity?.startsWith("sha512-")) process.exit(1);
  }
  for (const [path, resolved] of Object.entries(lock.packages ?? {})) {
    if (!path || !path.startsWith("node_modules/")) continue;
    if (!/^[0-9]+[.][0-9]+[.][0-9]+/.test(resolved.version ?? "")) process.exit(1);
    if (!resolved.integrity?.startsWith("sha512-")) process.exit(1);
  }
' "$typescript_fixture" \
    || fail "the TypeScript fixture dependencies must be exact and integrity-locked"

if grep -En 'uses:[[:space:]]+[^[:space:]#]+@(main|master|v[0-9]+([.]?[0-9]+)*)($|[[:space:]#])' \
    "$repository_root/.github/workflows/alias-sdk-release.yml" \
    "$repository_root/.github/workflows/alias-sdk-upstream.yml"; then
    fail "alias SDK workflows contain a floating action reference"
fi

echo "Alias SDK external sources are pinned"
