#!/usr/bin/env bash
set -euo pipefail

consumer="${1:-}"
artifact="${2:-}"
[[ -n "$consumer" && -n "$artifact" ]] || {
    echo "Usage: $0 {typescript|swift|kotlin|android} ARTIFACT" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_root="$repository_root/support/alias-sdk-release/consumers/$consumer"
[[ -e "$artifact" ]] || {
    echo "Alias SDK $consumer consumer gate failed: artifact is missing at $artifact" >&2
    exit 1
}
artifact="$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")"
"$repository_root/scripts/alias-sdk/check-host.sh" "$consumer"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-${consumer}-consumer.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
cp -R "$fixture_root" "$temporary_directory/consumer"

case "$consumer" in
    typescript)
        (
            cd "$temporary_directory/consumer"
            npm ci --ignore-scripts
            npm install --no-save --ignore-scripts "$artifact"
            npm run check
        )
        ;;
    swift)
        mkdir "$temporary_directory/sdk"
        tar -xzf "$artifact" -C "$temporary_directory/sdk"
        (
            cd "$temporary_directory/consumer"
            xcodebuild \
                -scheme AliasReleaseConsumer \
                -destination "generic/platform=iOS Simulator" \
                -derivedDataPath "$temporary_directory/DerivedData" \
                CODE_SIGN_IDENTITY="" \
                CODE_SIGNING_REQUIRED=NO \
                build
        )
        ;;
    kotlin)
        [[ -d "$artifact" ]] || {
            echo "Kotlin consumer gate failed: artifact must be the host bundle directory" >&2
            exit 1
        }
        jar_path="$(find "$artifact" -maxdepth 1 -type f -name '*.jar' -print -quit)"
        [[ -n "$jar_path" ]] || {
            echo "Kotlin consumer gate failed: host bundle contains no JAR" >&2
            exit 1
        }
        "$repository_root/scripts/alias-sdk/retry-command.sh" 3 20 \
            "$repository_root/crates/bitwarden-uniffi/kotlin/gradlew" --no-daemon \
            --project-dir "$temporary_directory/consumer" \
            -PsdkJar="$jar_path" \
            -PsdkNativeDirectory="$artifact" \
            run
        ;;
    android)
        mkdir -p "$temporary_directory/consumer/app/libs"
        cp "$artifact" "$temporary_directory/consumer/app/libs/bitwarden-alias-sdk.aar"
        "$repository_root/scripts/alias-sdk/retry-command.sh" 3 20 \
            "$repository_root/crates/bitwarden-uniffi/kotlin/gradlew" --no-daemon \
            --project-dir "$temporary_directory/consumer" \
            :app:assembleDebug
        ;;
    *)
        echo "Unknown alias SDK consumer: $consumer" >&2
        exit 2
        ;;
esac

echo "Alias SDK $consumer clean-room consumer passed"
