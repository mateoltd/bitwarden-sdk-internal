#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Generate an xcframework for the Swift bindings.
../../../scripts/check-oss-artifact-boundary.sh

SDK_REPO_ROOT="$(git rev-parse --show-toplevel)"
TARGET_DIRECTORY="${CARGO_TARGET_DIR:-$SDK_REPO_ROOT/target}"

# Cleanup dirs
rm -rf BitwardenFFI.xcframework
rm -rf tmp
# Generated component names can change when a crate gains an explicit UniFFI configuration.
# Remove only generated Swift files so stale component modules cannot survive regeneration.
find ./Sources/BitwardenSdk -maxdepth 1 -type f -name '*.swift' -delete

# Build native library
export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
if [[ $DEBUG_MODE = "true" ]]; then
  PROFILE="debug"
  PROFILE_FLAG=""
else
  PROFILE="release"
  PROFILE_FLAG="--release"
fi
echo "$PROFILE_FLAG"
cargo build --package bitwarden-uniffi --target aarch64-apple-ios-sim $PROFILE_FLAG
cargo build --package bitwarden-uniffi --target aarch64-apple-ios $PROFILE_FLAG
cargo build --package bitwarden-uniffi --target x86_64-apple-ios $PROFILE_FLAG

mkdir -p tmp/target/universal-ios-sim/$PROFILE

# Create universal libraries
lipo -create "$TARGET_DIRECTORY/aarch64-apple-ios-sim/$PROFILE/libbitwarden_uniffi.a" \
  "$TARGET_DIRECTORY/x86_64-apple-ios/$PROFILE/libbitwarden_uniffi.a" \
  -output ./tmp/target/universal-ios-sim/$PROFILE/libbitwarden_uniffi.a

# Generate swift bindings
cargo run -p uniffi-bindgen generate \
  "$TARGET_DIRECTORY/aarch64-apple-ios-sim/$PROFILE/libbitwarden_uniffi.dylib" \
  --language swift \
  --no-format \
  --out-dir tmp/bindings

# Move generated swift bindings
mv ./tmp/bindings/*.swift ./Sources/BitwardenSdk/

# Massage the generated files to fit xcframework
mkdir tmp/Headers
mv ./tmp/bindings/*.h ./tmp/Headers/
cat ./tmp/bindings/*.modulemap > ./tmp/Headers/module.modulemap

# Build xcframework
xcodebuild -create-xcframework \
  -library "$TARGET_DIRECTORY/aarch64-apple-ios/$PROFILE/libbitwarden_uniffi.a" \
  -headers ./tmp/Headers \
  -library ./tmp/target/universal-ios-sim/$PROFILE/libbitwarden_uniffi.a \
  -headers ./tmp/Headers \
  -output ./BitwardenFFI.xcframework

# xcodebuild does not guarantee the order of AvailableLibraries. Canonicalize the
# two validated slices so byte-for-byte release rebuilds cannot differ only by
# plist array order.
XCFRAMEWORK_PLIST="./BitwardenFFI.xcframework/Info.plist"
DEVICE_IDENTIFIER="ios-arm64"
SIMULATOR_IDENTIFIER="ios-arm64_x86_64-simulator"
FIRST_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :AvailableLibraries:0:LibraryIdentifier' "$XCFRAMEWORK_PLIST")"
SECOND_IDENTIFIER="$(/usr/libexec/PlistBuddy -c 'Print :AvailableLibraries:1:LibraryIdentifier' "$XCFRAMEWORK_PLIST")"
case "$FIRST_IDENTIFIER:$SECOND_IDENTIFIER" in
  "$DEVICE_IDENTIFIER:$SIMULATOR_IDENTIFIER")
    ;;
  "$SIMULATOR_IDENTIFIER:$DEVICE_IDENTIFIER")
    /usr/libexec/PlistBuddy -c 'Copy :AvailableLibraries:0 :CanonicalLibrary' "$XCFRAMEWORK_PLIST"
    /usr/libexec/PlistBuddy -c 'Delete :AvailableLibraries:0' "$XCFRAMEWORK_PLIST"
    /usr/libexec/PlistBuddy -c 'Copy :CanonicalLibrary :AvailableLibraries:1' "$XCFRAMEWORK_PLIST"
    /usr/libexec/PlistBuddy -c 'Delete :CanonicalLibrary' "$XCFRAMEWORK_PLIST"
    ;;
  *)
    echo "Unexpected XCFramework library identifiers: $FIRST_IDENTIFIER, $SECOND_IDENTIFIER" >&2
    exit 1
    ;;
esac
plutil -convert xml1 "$XCFRAMEWORK_PLIST"

../../../scripts/check-oss-artifact-boundary.sh --swift "$PWD"

# Cleanup temporary files
rm -rf tmp
