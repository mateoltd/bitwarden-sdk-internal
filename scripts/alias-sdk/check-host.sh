#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

fail() {
    echo "Alias SDK $target host gate failed: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing '$1'. Reproduce with: $repository_root/scripts/alias-sdk/check-host.sh $target"
}

case "$target" in
    typescript)
        require_command node
        require_command npm
        node -e '
          const [major, minor] = process.versions.node.split(".").map(Number);
          if (major < 24 || (major === 24 && minor < 17)) process.exit(1);
        ' || fail "Node >=24.17.0 is required to match bitwarden/clients; found $(node --version)"
        ;;
    swift)
        [[ "$(uname -s)" == "Darwin" ]] || fail "the Swift artifact consumer requires a macOS host"
        require_command swift
        require_command xcodebuild
        require_command xcrun
        xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1 \
            || fail "the iOS Simulator SDK is unavailable; install the Xcode iOS platform"
        ;;
    kotlin)
        require_command cargo
        require_command java
        java -version >/dev/null 2>&1 || fail "the Java launcher exists but no working JDK is configured"
        [[ -x "$repository_root/crates/bitwarden-uniffi/kotlin/gradlew" ]] \
            || fail "the repository Gradle wrapper is unavailable"
        ;;
    android)
        require_command java
        java -version >/dev/null 2>&1 || fail "the Java launcher exists but no working JDK is configured"
        android_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
        [[ -n "$android_sdk" && -d "$android_sdk" ]] \
            || fail "ANDROID_SDK_ROOT or ANDROID_HOME must name an installed Android SDK"
        [[ -f "$android_sdk/platforms/android-35/android.jar" ]] \
            || fail "Android platform 35 is unavailable; install 'platforms;android-35'"
        android_ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
        [[ -n "$android_ndk" && -d "$android_ndk" ]] \
            || fail "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must name an installed Android NDK"
        [[ -x "$repository_root/crates/bitwarden-uniffi/kotlin/gradlew" ]] \
            || fail "the repository Gradle wrapper is unavailable"
        ;;
    *)
        fail "expected one of: typescript, swift, kotlin, android"
        ;;
esac

echo "Alias SDK $target host gate passed"
