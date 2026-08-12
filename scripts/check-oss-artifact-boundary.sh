#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FORBIDDEN_PACKAGES='^bitwarden-(commercial-vault|pam|sm) '
FORBIDDEN_EXPORTS='CommercialPasswordManagerClient|CommercialVaultClient|PamClient|PAMClient'

fail() {
    echo "OSS artifact boundary check failed: $*" >&2
    exit 1
}

check_dependency_graph() {
    local package="$1"
    local tree

    tree="$(
        cd "$REPOSITORY_ROOT"
        cargo tree --locked --package "$package" --edges normal,build --prefix none --format '{p}'
    )"

    if grep -E "$FORBIDDEN_PACKAGES" <<<"$tree"; then
        fail "$package resolves a commercial-only crate"
    fi
}

check_licensed_dependency_graph() {
    local tree
    local package

    tree="$(
        cd "$REPOSITORY_ROOT"
        cargo tree --locked --package bitwarden-wasm-internal --features bitwarden-license \
            --edges normal,build --prefix none --format '{p}'
    )"

    for package in bitwarden-commercial-vault bitwarden-pam; do
        grep -Eq "^${package} " <<<"$tree" \
            || fail "the licensed WASM feature no longer resolves $package"
    done
}

check_hardened_alias_generator() {
    local package="$1"
    local features

    features="$(
        cd "$REPOSITORY_ROOT"
        cargo tree --locked --package "$package" --edges features
    )"
    grep -Fq 'bitwarden-generators feature "alias"' <<<"$features" \
        || fail "$package does not route SimpleLogin generation through the hardened alias client"
}

check_paths() {
    local path="$1"
    local forbidden

    forbidden="$(
        find "$path" -print \
            | grep -Ei '(^|/)([^/]*(bitwarden[_-]?license|commercial)[^/]*|LICENSE_SDK[^/]*)(/|$)' \
            || true
    )"
    if [[ -n "$forbidden" ]]; then
        printf '%s\n' "$forbidden" >&2
        fail "$path contains a commercial-only path"
    fi
}

check_generated_exports() {
    local path="$1"
    local forbidden

    forbidden="$(
        find "$path" -type f \( -name '*.d.ts' -o -name '*.js' -o -name '*.swift' -o -name '*.kt' \) \
            -exec grep -El "$FORBIDDEN_EXPORTS" {} + 2>/dev/null || true
    )"
    if [[ -n "$forbidden" ]]; then
        printf '%s\n' "$forbidden" >&2
        fail "$path exposes a commercial-only API"
    fi
}

check_wasm() {
    local path="$1"
    local expected_source_commit
    local packaged_source_commit

    [[ -f "$path/package.json" ]] || fail "$path/package.json is missing"
    [[ -f "$path/LICENSE" ]] || fail "$path/LICENSE is missing"
    [[ -f "$path/VERSION" ]] || fail "$path/VERSION is missing"
    [[ -f "$path/bitwarden_wasm_internal.d.ts" ]] \
        || fail "$path/bitwarden_wasm_internal.d.ts is missing"
    [[ -f "$path/bitwarden_wasm_internal_bg.wasm" ]] \
        || fail "$path/bitwarden_wasm_internal_bg.wasm is missing"
    grep -Eq '"license": "GPL-3.0-only"' "$path/package.json" \
        || fail "$path/package.json must declare GPL-3.0-only"
    grep -q 'GNU GENERAL PUBLIC LICENSE' "$path/LICENSE" \
        || fail "$path/LICENSE is not the GPL text"
    expected_source_commit="$(git -C "$REPOSITORY_ROOT" rev-parse HEAD)"
    if [[ -n "$(git -C "$REPOSITORY_ROOT" status --porcelain --untracked-files=normal)" ]]; then
        expected_source_commit="${expected_source_commit}-dirty"
    fi
    packaged_source_commit="$(tr -d '[:space:]' <"$path/VERSION")"
    [[ "$packaged_source_commit" == "$expected_source_commit" ]] \
        || fail "$path/VERSION does not identify the source commit"
    check_paths "$path"
    check_generated_exports "$path"

    (
        cd "$path"
        npm pack --dry-run --ignore-scripts >/dev/null
    )
}

check_swift() {
    local path="$1"

    [[ -f "$path/LICENSE_GPL.txt" ]] || fail "$path/LICENSE_GPL.txt is missing"
    [[ -d "$path/BitwardenFFI.xcframework" ]] \
        || fail "$path/BitwardenFFI.xcframework is missing"
    find "$path/Sources/BitwardenSdk" -type f -name '*.swift' -print -quit | grep -q . \
        || fail "$path has no generated Swift sources"
    grep -q 'GNU GENERAL PUBLIC LICENSE' "$path/LICENSE_GPL.txt" \
        || fail "$path/LICENSE_GPL.txt is not the GPL text"
    check_paths "$path/BitwardenFFI.xcframework"
    check_generated_exports "$path/Sources/BitwardenSdk"
}

check_kotlin() {
    local aar="$1"
    local temporary_dir
    local jar
    local jar_index=0
    local forbidden
    local license_path

    [[ -f "$aar" ]] || fail "$aar is missing"

    temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/bitwarden-oss-aar.XXXXXX")"
    trap 'rm -rf "$temporary_dir"' RETURN
    unzip -qq "$aar" -d "$temporary_dir"

    while IFS= read -r -d '' jar; do
        mkdir -p "$temporary_dir/jars/$jar_index"
        unzip -qq "$jar" -d "$temporary_dir/jars/$jar_index"
        jar_index=$((jar_index + 1))
    done < <(find "$temporary_dir" -type f -name '*.jar' -print0)

    license_path="$(
        find "$temporary_dir/jars" -path '*/META-INF/LICENSE_GPL.txt' -print -quit
    )"
    [[ -n "$license_path" ]] \
        || fail "$aar classes.jar does not contain META-INF/LICENSE_GPL.txt"
    check_paths "$temporary_dir"
    grep -q 'GNU GENERAL PUBLIC LICENSE' "$license_path" \
        || fail "$aar does not contain the GPL text"
    forbidden="$(
        find "$temporary_dir" -type f \( -name '*.class' -o -name '*.so' \) \
            -exec grep -aEl "$FORBIDDEN_EXPORTS" {} + 2>/dev/null || true
    )"
    if [[ -n "$forbidden" ]]; then
        printf '%s\n' "$forbidden" >&2
        fail "$aar contains a commercial-only API or native symbol"
    fi
    rm -rf "$temporary_dir"
    trap - RETURN
}

check_kotlin_host() {
    local jar="$1"
    local temporary_dir
    local forbidden

    [[ -f "$jar" ]] || fail "$jar is missing"

    temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/bitwarden-oss-kotlin-host.XXXXXX")"
    trap 'rm -rf "$temporary_dir"' RETURN
    unzip -qq "$jar" -d "$temporary_dir"

    [[ -f "$temporary_dir/META-INF/LICENSE_GPL.txt" ]] \
        || fail "$jar does not contain META-INF/LICENSE_GPL.txt"
    grep -q 'GNU GENERAL PUBLIC LICENSE' "$temporary_dir/META-INF/LICENSE_GPL.txt" \
        || fail "$jar does not contain the GPL text"
    check_paths "$temporary_dir"
    forbidden="$(
        find "$temporary_dir" -type f -name '*.class' \
            -exec grep -aEl "$FORBIDDEN_EXPORTS" {} + 2>/dev/null || true
    )"
    if [[ -n "$forbidden" ]]; then
        printf '%s\n' "$forbidden" >&2
        fail "$jar contains a commercial-only API"
    fi
    rm -rf "$temporary_dir"
    trap - RETURN
}

check_dependency_graph bitwarden-wasm-internal
check_dependency_graph bitwarden-uniffi
check_hardened_alias_generator bitwarden-wasm-internal
check_hardened_alias_generator bitwarden-uniffi
check_licensed_dependency_graph

grep -Eq '"license": "GPL-3.0-only"' \
    "$REPOSITORY_ROOT/crates/bitwarden-wasm-internal/npm/package.json" \
    || fail "the OSS npm manifest must declare GPL-3.0-only"
grep -q 'GNU GENERAL PUBLIC LICENSE' \
    "$REPOSITORY_ROOT/crates/bitwarden-uniffi/swift/LICENSE_GPL.txt" \
    || fail "the Swift package GPL license is missing"
grep -q 'GNU GENERAL PUBLIC LICENSE' \
    "$REPOSITORY_ROOT/crates/bitwarden-uniffi/kotlin/sdk/src/main/resources/META-INF/LICENSE_GPL.txt" \
    || fail "the Kotlin package GPL license is missing"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wasm)
            [[ $# -ge 2 ]] || fail "--wasm requires a package directory"
            check_wasm "$2"
            shift 2
            ;;
        --swift)
            [[ $# -ge 2 ]] || fail "--swift requires a package directory"
            check_swift "$2"
            shift 2
            ;;
        --kotlin)
            [[ $# -ge 2 ]] || fail "--kotlin requires an AAR path"
            check_kotlin "$2"
            shift 2
            ;;
        --kotlin-host)
            [[ $# -ge 2 ]] || fail "--kotlin-host requires a JAR path"
            check_kotlin_host "$2"
            shift 2
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

echo "OSS artifact boundary verified"
