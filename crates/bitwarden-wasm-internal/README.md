# bitwarden-wasm-internal

**Note:** This is only for internal use. Bitwarden will not provide any support for this crate.

Bitwarden WASM internal exposes WebAssembly bindings for the Bitwarden SDK. This crate should
contain no logic but rather only handle WASM unique conversions and bindings. Business logic
**MUST** be placed in the relevant feature crates.

## Getting Started

### Requirements

- `wasm32-unknown-unknown` rust target.
- `binaryen` installed for `wasm-opt` and `wasm2js`.
- npm packages must be installed in the `npm` folder. Run `npm ci` inside:
  - **OSS:** `crates/bitwarden-wasm-internal/npm`
  - **Commercial:** `crates/bitwarden-wasm-internal/bitwarden_license/npm`

```bash
rustup target add wasm32-unknown-unknown
brew install binaryen
```

### Building

```bash
# dev
./build.sh

# dev with commercial license
./build.sh -b

# release
./build.sh -r

# release with commercial license
./build.sh -r -b
```

The build without `-b` is the GPL/OSS package. It fails before compilation if Cargo resolves any
commercial-only SDK crate and validates the generated npm package's license, paths, and exports
after compilation. You can rerun that validation independently from the repository root:

```bash
scripts/check-oss-artifact-boundary.sh --wasm crates/bitwarden-wasm-internal/npm
```
