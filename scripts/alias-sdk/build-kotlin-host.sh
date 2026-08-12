#!/usr/bin/env bash
set -euo pipefail

output_directory="${1:-}"
[[ -n "$output_directory" ]] || {
    echo "Usage: $0 OUTPUT_DIRECTORY" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$repository_root/scripts/alias-sdk/check-host.sh" kotlin
[[ -z "$(git -C "$repository_root" status --porcelain --untracked-files=normal)" ]] || {
    echo "Kotlin host artifact gate failed: release artifacts require a clean worktree" >&2
    exit 1
}

case "$(uname -s)" in
    Linux) native_library="libbitwarden_uniffi.so" ;;
    Darwin) native_library="libbitwarden_uniffi.dylib" ;;
    *)
        echo "Kotlin host artifact gate failed: unsupported native host $(uname -s)" >&2
        exit 1
        ;;
esac

output_directory="$(mkdir -p "$output_directory" && cd "$output_directory" && pwd)"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-kotlin-host.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

cargo build --locked --release --package bitwarden-uniffi --manifest-path "$repository_root/Cargo.toml"
target_directory="${CARGO_TARGET_DIR:-$repository_root/target}"
native_path="$target_directory/release/$native_library"
[[ -f "$native_path" ]] || {
    echo "Kotlin host artifact gate failed: native library is missing at $native_path" >&2
    exit 1
}

cargo run --locked --manifest-path "$repository_root/Cargo.toml" --package uniffi-bindgen -- \
    generate "$native_path" \
    --language kotlin \
    --config "$repository_root/support/alias-sdk-release/kotlin-host-uniffi.toml" \
    --no-format \
    --out-dir "$temporary_directory/generated"

gradle_wrapper="$repository_root/crates/bitwarden-uniffi/kotlin/gradlew"
"$gradle_wrapper" --no-daemon \
    --project-dir "$repository_root/support/alias-sdk-release/kotlin-host-sdk" \
    -PgeneratedSources="$temporary_directory/generated" \
    -PlicenseFile="$repository_root/LICENSE_GPL.txt" \
    clean jar

jar_path="$repository_root/support/alias-sdk-release/kotlin-host-sdk/build/libs/bitwarden-alias-sdk-kotlin-host.jar"
[[ -f "$jar_path" ]] || {
    echo "Kotlin host artifact gate failed: Gradle did not produce $jar_path" >&2
    exit 1
}

cp "$jar_path" "$output_directory/"
cp "$native_path" "$output_directory/"
git -C "$repository_root" rev-parse HEAD >"$output_directory/VERSION"
"$repository_root/scripts/check-oss-artifact-boundary.sh" \
    --kotlin-host "$output_directory/bitwarden-alias-sdk-kotlin-host.jar"

echo "Kotlin host alias SDK artifact built at $output_directory"
