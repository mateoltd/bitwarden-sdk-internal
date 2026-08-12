#!/usr/bin/env bash
set -euo pipefail

output_directory="${1:-}"
[[ -n "$output_directory" ]] || {
    echo "Usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_version="$("$repository_root/scripts/alias-sdk/read-release-version.sh")"
alias_reference_schema_version="$(tr -d '[:space:]' <"$repository_root/support/alias-sdk-release/ALIAS_REFERENCE_SCHEMA_VERSION")"
"$repository_root/scripts/alias-sdk/check-host.sh" swift
[[ -z "$(git -C "$repository_root" status --porcelain --untracked-files=normal)" ]] || {
    echo "Swift artifact gate failed: release artifacts require a clean worktree" >&2
    exit 1
}
output_directory="$(mkdir -p "$output_directory" && cd "$output_directory" && pwd)"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-swift-package.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

"$repository_root/crates/bitwarden-uniffi/swift/build.sh"
package_directory="$temporary_directory/sdk"
mkdir -p "$package_directory"
cp "$repository_root/crates/bitwarden-uniffi/swift/Package.swift" "$package_directory/"
cp "$repository_root/crates/bitwarden-uniffi/swift/README.md" "$package_directory/"
cp "$repository_root/crates/bitwarden-uniffi/swift/LICENSE_GPL.txt" "$package_directory/"
cp -R "$repository_root/crates/bitwarden-uniffi/swift/Sources" "$package_directory/"
cp -R "$repository_root/crates/bitwarden-uniffi/swift/Tests" "$package_directory/"
cp -R "$repository_root/crates/bitwarden-uniffi/swift/BitwardenFFI.xcframework" "$package_directory/"
git -C "$repository_root" rev-parse HEAD >"$package_directory/VERSION"
printf '%s\n' "$release_version" >"$package_directory/PACKAGE_VERSION"
printf '%s\n' "$alias_reference_schema_version" \
    >"$package_directory/ALIAS_REFERENCE_SCHEMA_VERSION"

archive="$output_directory/bitwarden-alias-sdk-swift-${release_version}.tar.gz"
COPYFILE_DISABLE=1 tar -C "$package_directory" -czf "$archive" .
cp "$package_directory/VERSION" "$output_directory/VERSION"
cp "$package_directory/PACKAGE_VERSION" "$output_directory/PACKAGE_VERSION"
cp "$package_directory/ALIAS_REFERENCE_SCHEMA_VERSION" "$output_directory/ALIAS_REFERENCE_SCHEMA_VERSION"
"$repository_root/scripts/check-oss-artifact-boundary.sh" --swift-release "$package_directory"

echo "Swift alias SDK artifact built at $archive"
