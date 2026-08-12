#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() {
    echo "Alias SDK external-source pin gate failed: $*" >&2
    exit 1
}

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

clients_contract="$repository_root/support/alias-sdk-release/consumers/typescript/bitwarden-clients-contract.json"
node -e '
  const fs = require("node:fs");
  const contract = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (!/^[0-9a-f]{40}$/.test(contract.commit)) process.exit(1);
' "$clients_contract" || fail "the bitwarden/clients contract must record one full commit SHA"

if grep -En 'uses:[[:space:]]+[^[:space:]#]+@(main|master|v[0-9]+([.]?[0-9]+)*)($|[[:space:]#])' \
    "$repository_root/.github/workflows/alias-sdk-release.yml" \
    "$repository_root/.github/workflows/alias-sdk-upstream.yml"; then
    fail "alias SDK workflows contain a floating action reference"
fi

echo "Alias SDK external sources are pinned"
