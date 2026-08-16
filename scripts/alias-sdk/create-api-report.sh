#!/usr/bin/env bash
set -euo pipefail

platform="${1:-}"
artifact="${2:-}"
output_file="${3:-}"
[[ -n "$platform" && -f "$artifact" && -n "$output_file" ]] || {
    echo "Usage: $0 {typescript|swift|kotlin|android} ARTIFACT OUTPUT_FILE" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact="$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")"
mkdir -p "$(dirname "$output_file")"
output_file="$(cd "$(dirname "$output_file")" && pwd)/$(basename "$output_file")"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-api-report.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT

write_header() {
    printf '# Bitwarden alias SDK public API report\n'
    printf 'format-version: 1\n'
    printf 'platform: %s\n' "$platform"
    printf 'package-version: %s\n' \
        "$("$repository_root/scripts/alias-sdk/read-release-version.sh")"
    printf 'artifact-sha256: %s\n' \
        "$(shasum -a 256 "$artifact" | awk '{print $1}')"
}

report_text_sources() {
    source_root="$1"
    shift
    mapfile_path="$temporary_directory/sources"
    find "$source_root" -type f "$@" -print | LC_ALL=C sort >"$mapfile_path"
    [[ -s "$mapfile_path" ]] || {
        echo "API report failed: no public definition sources found for $platform" >&2
        exit 1
    }
    while IFS= read -r source_file; do
        relative_path="${source_file#"$source_root"/}"
        printf '\n## %s\n' "$relative_path"
        case "$platform" in
            typescript)
                sed 's/[[:space:]]\+$//' "$source_file"
                ;;
            swift)
                printf 'sha256: %s\n' "$(shasum -a 256 "$source_file" | awk '{print $1}')"
                sed -nE '/^[[:space:]]*(open|public)[[:space:]]/p' "$source_file" \
                    | sed 's/[[:space:]]\+$//'
                ;;
        esac
    done <"$mapfile_path"
}

report_jvm_archive() {
    class_archive="$1"
    command -v javap >/dev/null 2>&1 || {
        echo "API report failed: javap is required for $platform" >&2
        exit 1
    }
    jar tf "$class_archive" \
        | sed -nE '/[.]class$/p' \
        | grep -v '^META-INF/' \
        | grep -vE '(^|/)(module-info|R([$].*)?|BuildConfig)[.]class$' \
        | sed 's#[/]#.#g; s#[.]class$##' \
        | LC_ALL=C sort >"$temporary_directory/classes"
    [[ -s "$temporary_directory/classes" ]] || {
        echo "API report failed: no JVM classes found for $platform" >&2
        exit 1
    }
    while IFS= read -r class_name; do
        printf '\n## %s\n' "$class_name"
        javap -classpath "$class_archive" -public -constants "$class_name" \
            | sed 's/[[:space:]]\+$//'
    done <"$temporary_directory/classes"
}

{
    write_header
    case "$platform" in
        typescript)
            tar -xzf "$artifact" -C "$temporary_directory"
            report_text_sources "$temporary_directory" \( -name '*.d.ts' -o -name '*.d.mts' \)
            ;;
        swift)
            tar -xzf "$artifact" -C "$temporary_directory"
            if find "$temporary_directory" -type f -name '*.swiftinterface' -print -quit \
                | grep -q .; then
                report_text_sources "$temporary_directory" -name '*.swiftinterface'
            else
                report_text_sources "$temporary_directory" -name '*.swift'
            fi
            ;;
        kotlin)
            report_jvm_archive "$artifact"
            ;;
        android)
            unzip -q "$artifact" classes.jar -d "$temporary_directory"
            report_jvm_archive "$temporary_directory/classes.jar"
            ;;
        *)
            echo "API report failed: unknown platform $platform" >&2
            exit 2
            ;;
    esac
} >"$output_file"

echo "Created $platform API report at $output_file"
