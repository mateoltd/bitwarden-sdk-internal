# Android

Android builds needs vendored OpenSSL to function correctly. The easiest way to build this is by
using [cross](https://github.com/cross-rs/cross).

The pinned `cross` revision lives in the root `Cargo.toml` under `[workspace.metadata.bin]`. Install
the bootstrap once and invoke `cross` via `cargo bin`:

```bash
cargo install cargo-run-bin --locked
```

## Development

When building the Android SDK using Android Studio on MacOS you will need access to the local
`$PATH`, where cargo is installed. This can be done by starting Android Studio from the terminal.

```bash
open -a /Applications/Android\ Studio.app
```

## Building

Depending on which CPU architecture you will need to specify different targets. Please refer to the
[Android ABIs](https://developer.android.com/ndk/guides/abis) for more details.

```bash
mkdir -p ./sdk/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64,x86}

cargo bin cross build -p bitwarden-uniffi --release --target=aarch64-linux-android
mv ../../../target/aarch64-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so

cargo bin cross build -p bitwarden-uniffi --release --target=armv7-linux-androideabi
mv ../../../target/armv7-linux-androideabi/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/armeabi-v7a/libbitwarden_uniffi.so

cargo bin cross build -p bitwarden-uniffi --release --target=x86_64-linux-android
mv ../../../target/x86_64-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/x86_64/libbitwarden_uniffi.so

cargo bin cross build -p bitwarden-uniffi --release --target=i686-linux-android
mv ../../../target/i686-linux-android/release/libbitwarden_uniffi.so ./sdk/src/main/jniLibs/x86/libbitwarden_uniffi.so
```

### Schemas

```bash
./build-schemas.sh
```

### Publish

```bash
export GITHUB_ACTOR=username
export GITHUB_TOKEN=token

./gradlew sdk:publish
```

The Android SDK is an OSS artifact. `publish-local.sh` checks its resolved Cargo graph before the
native build and verifies that the resulting AAR contains the GPL license and no commercial-only
paths or generated APIs. The same package check can be run directly from the repository root:

```bash
scripts/check-oss-artifact-boundary.sh \
  --kotlin crates/bitwarden-uniffi/kotlin/sdk/build/outputs/aar/sdk-release.aar
```

The generated Kotlin sources can also be compiled into a host JVM JAR for local consumers. Such a
JAR depends on JNA and Kotlin coroutines at runtime, and on the Android/AndroidX annotation APIs
used by the generated cleaner implementation. Verify its package boundary with:

```bash
scripts/check-oss-artifact-boundary.sh --kotlin-host path/to/bitwarden-sdk-kotlin-host.jar
```
