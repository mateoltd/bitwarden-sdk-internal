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

host_config="$temporary_directory/host-uniffi.toml"
cp "$repository_root/support/alias-sdk-release/kotlin-host-uniffi.toml" "$host_config"

# UniFFI 0.32 layers global per-crate overrides after each authoritative
# uniffi.toml. Disable only the Android cleaner for the JVM package while
# preserving package names, custom types, and every other crate-owned option.
component_count=0
while IFS= read -r component_config; do
    component_directory="$(basename "$(dirname "$component_config")")"
    component_crate="${component_directory//-/_}"
    printf '\n[crates.%s.bindings.kotlin]\nandroid = false\n' \
        "$component_crate" >>"$host_config"
    component_count=$((component_count + 1))
done < <(
    find "$repository_root/crates" -type f -name uniffi.toml \
        -exec grep -l '^android = true$' {} + \
        | LC_ALL=C sort
)
[[ "$component_count" -gt 0 ]] || {
    echo "Kotlin host artifact gate failed: no Android UniFFI components were found" >&2
    exit 1
}

cargo run --locked --manifest-path "$repository_root/Cargo.toml" --package uniffi-bindgen -- \
    generate "$native_path" \
    --language kotlin \
    --config "$host_config" \
    --no-format \
    --out-dir "$temporary_directory/generated"

android_imports="$(
    find "$temporary_directory/generated" -type f -name '*.kt' \
        -exec grep -nH '^import android\.' {} + || true
)"
if [[ -n "$android_imports" ]]; then
    printf '%s\n' "$android_imports" >&2
    echo "Kotlin host artifact gate failed: Android-only imports remain in JVM bindings" >&2
    exit 1
fi

gradle_wrapper="$repository_root/crates/bitwarden-uniffi/kotlin/gradlew"
"$repository_root/scripts/alias-sdk/retry-command.sh" 3 20 \
    "$gradle_wrapper" --no-daemon \
    --project-cache-dir "$temporary_directory/gradle-project-cache" \
    --project-dir "$repository_root/support/alias-sdk-release/kotlin-host-sdk" \
    -PgeneratedSources="$temporary_directory/generated" \
    -PlicenseFile="$repository_root/LICENSE_GPL.txt" \
    -PreleaseVersion="$release_version" \
    clean jar

jar_name="bitwarden-alias-sdk-kotlin-host-${release_version}.jar"
jar_path="$repository_root/support/alias-sdk-release/kotlin-host-sdk/build/libs/$jar_name"
[[ -f "$jar_path" ]] || {
    echo "Kotlin host artifact gate failed: Gradle did not produce $jar_path" >&2
    exit 1
}

cp "$jar_path" "$output_directory/"
"$repository_root/scripts/alias-sdk/normalize-archive.sh" zip \
    "$output_directory/$jar_name"
cp "$native_path" "$output_directory/"
git -C "$repository_root" rev-parse HEAD >"$output_directory/VERSION"
printf '%s\n' "$release_version" >"$output_directory/PACKAGE_VERSION"
printf '%s\n' "$alias_reference_schema_version" \
    >"$output_directory/ALIAS_REFERENCE_SCHEMA_VERSION"
"$repository_root/scripts/check-oss-artifact-boundary.sh" \
    --kotlin-host "$output_directory/$jar_name"

echo "Kotlin host alias SDK artifact built at $output_directory"
