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

# Build native library
export IPHONEOS_DEPLOYMENT_TARGET="13.0"
# Fail if a commercial bitwarden_license crate leaks in (see bitwarden-commercial-marker).
export RUSTFLAGS="-C link-arg=-Wl,-application_extension --cfg bitwarden_ensure_non_commercial"
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

../../../scripts/check-oss-artifact-boundary.sh --swift "$PWD"

# Cleanup temporary files
rm -rf tmp
