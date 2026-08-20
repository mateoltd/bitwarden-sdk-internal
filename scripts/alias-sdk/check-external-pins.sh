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

previous_public_alias_head="$(tr -d '[:space:]' \
    <"$repository_root/support/alias-sdk-release/PREVIOUS_PUBLIC_ALIAS_HEAD")"
[[ "$previous_public_alias_head" == "4a08b5fe81c363169d36f582cc13c03b59d212d8" ]] \
    || fail "PREVIOUS_PUBLIC_ALIAS_HEAD is not the reviewed unreleased public SDK head"
git -C "$repository_root" merge-base --is-ancestor "$previous_public_alias_head" HEAD \
    || fail "PREVIOUS_PUBLIC_ALIAS_HEAD is not an ancestor of the candidate"

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
  if (contract.repository !== "https://github.com/mateoltd/bitwarden-clients.git") process.exit(1);
  if (contract.branch !== "integration/public-alias-clients") process.exit(1);
  if (contract.commit !== "4f6804e8c44b482bece57654afaa23980c71332a") process.exit(1);
' "$clients_contract" || fail "the bitwarden/clients contract pin is not the reviewed public integration commit"

ios_contract="$repository_root/support/alias-sdk-release/ios-integration.json"
node -e '
  const fs = require("node:fs");
  const contract = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (contract.commit !== "736a85b5d3f2afbdb46b61b7698ebd0828e7481d") process.exit(1);
  if (contract.currentSdkSwift?.commit !== "858d31ac18214e47c5264fc73da8c9885565bda0") process.exit(1);
  if (contract.aliasReferenceSchemaVersion !== 1) process.exit(1);
  if (contract.integrationStatus !== "requires-provider-neutral-repin") process.exit(1);
' "$ios_contract" || fail "the iOS feature and current sdk-swift consumer pins are not reviewed"

release_version="$("$repository_root/scripts/alias-sdk/read-release-version.sh")" \
    || fail "the alias SDK release version is invalid"
[[ "$release_version" == "0.3.0-alias-provider-neutral.1" ]] \
    || fail "the unreleased provider-neutral v1 candidate version is not pinned"
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

grep -Fqx 'arrayref = { path = "support/vendor/arrayref" }' "$repository_root/Cargo.toml" \
    || fail "arrayref must resolve from the reviewed vendored source"
node - "$repository_root/support/vendor/arrayref" <<'NODE' \
    || fail "vendored arrayref source does not match reviewed provenance"
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = process.argv[2];
const expected = new Map([
  ["Cargo.toml", "122da2bce2d1aea793e4dc4d38a98966c67f3339a4db2f8fc740bd74ce97e668"],
  ["LICENSE", "1bc7e6f475b3ec99b7e2643411950ae2368c250dd4c5c325f80f9811362a94a1"],
  ["PROVENANCE.md", "367c62030c4d35b8fd160c41b83c16bf3488c664bf4d912238c1899a621d912d"],
  ["README.md", "039b4028d39ba4ec049041dbbf949555bcc42aa7bced920725c5573d2b6cad24"],
  ["src/lib.rs", "b74872c9bb2b836132817e024a3f9205f83a6864de1a9bfb46acc1bfbbc1873a"],
]);
const actual = [];
const visit = (directory, prefix = "") => {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) visit(path.join(directory, entry.name), relative);
    else if (entry.isFile()) actual.push(relative);
    else process.exit(1);
  }
};
visit(root);
actual.sort();
if (JSON.stringify(actual) !== JSON.stringify([...expected.keys()])) process.exit(1);
for (const [relative, digest] of expected) {
  const actualDigest = crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(root, relative)))
    .digest("hex");
  if (actualDigest !== digest) process.exit(1);
}
NODE

cargo_metadata_file="$(mktemp "${TMPDIR:-/tmp}/alias-cargo-metadata.XXXXXX")"
trap 'rm -f "$cargo_metadata_file"' EXIT
cargo metadata --locked --no-deps --format-version 1 \
    --manifest-path "$repository_root/Cargo.toml" >"$cargo_metadata_file" \
    || fail "Cargo workspace metadata could not be evaluated"
node -e '
  const fs = require("node:fs");
  const metadata = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const packages = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const defaults = metadata.workspace_default_members.map((id) => packages.get(id));
  if (defaults.length === 0 || defaults.some((pkg) => !pkg)) process.exit(1);
  if (defaults.some((pkg) => pkg.manifest_path.includes("/bitwarden_license/"))) process.exit(1);
' "$cargo_metadata_file" || fail "the default Cargo workspace includes commercial or PAM crates"
default_cargo_graph="$(cargo tree --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --edges normal,build \
    --prefix none \
    --format '{p}')" \
    || fail "the default Cargo dependency graph could not be evaluated"
if grep -Eq '^bitwarden-(commercial-vault|pam|sm) v' <<<"$default_cargo_graph"; then
    fail "the default Cargo dependency graph activates commercial or PAM code"
fi

if grep -En '(npm publish|cargo publish|git tag|gh release create)' \
    "$repository_root/.github/workflows/alias-sdk-release.yml"; then
    fail "the candidate workflow contains a publication, tag, or release command"
fi

echo "Alias SDK external sources are pinned"
