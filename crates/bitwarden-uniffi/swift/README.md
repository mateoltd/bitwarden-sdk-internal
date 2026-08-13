# Swift

Ensure the necessary targets are installed.

```bash
rustup target install aarch64-apple-ios-sim
rustup target install aarch64-apple-ios
rustup target install x86_64-apple-ios
```

## Build

```bash
./build.sh
```

The build checks the OSS Cargo dependency boundary before compiling, then verifies the generated
Swift sources, GPL license, XCFramework paths, and public exports. The completed package can be
checked again from the repository root:

```bash
scripts/check-oss-artifact-boundary.sh --swift crates/bitwarden-uniffi/swift
```

## Deploy

Checkout `https://github.com/bitwarden/sdk-swift`.

Copy the following files to the root of the sdk-swift repository.

- `BitwardenFFI.xcframework`
- `Sources/BitwardenSdk/BitwardenSDK.swift`

Push the modified files.
