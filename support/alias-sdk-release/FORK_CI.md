# Fork PR build verification

`build-wasm-internal.yml` delivers the OSS build as `fork-sdk-oss-SOURCE_SHA`. `BUILD-ONLY.json`
records the full source commit, package version, size and SHA-256. The verifier checks the embedded
npm `VERSION`, OSS package identity, archive paths and checksum before extraction. This is ordinary
same-run CI delivery, not a security-qualified candidate, provenance attestation or permission to
repin.

The SDK-owned client job reads `fork-clients.json`, clones that public consumer without credentials,
verifies its frozen-base ancestry and exports only OSS source. It installs the consumer's checked-in
lockfile without lifecycle scripts, then physically substitutes both installed SDK package names
with the verified build. Manifests, lockfile, vendored package and qualification pins stay
unchanged. The existing strict compiler and every library project are compiled serially, with every
child exit observed. No release verifier is bypassed or reported as passing: this separate route
establishes compilation compatibility only.

Reproduce with the pinned Node/npm versions from `fork-clients.json`:

```sh
scripts/alias-sdk/test-fork-clients.sh BUILD_DIRECTORY SOURCE_SHA
```

For Android, all four native targets record their checked-out source alongside the library. Combine
rejects mixed sources, generates bindings, builds the SDK and demo, checks OSS contents and compiles
the existing alias AAR consumer. Forks upload `fork-sdk-android-SOURCE_SHA` with the AAR and
build-only checksum manifest; they do not publish to a Maven registry or dispatch an upstream
Android update. This does not run an emulator or execute Android alias FFI calls. Existing JVM
runtime coverage and Apple qualification remain separate native-owner evidence.

Upstream Bitwarden retains its existing dispatch and publication routes. Fork checks need no Azure,
OIDC, Key Vault, GitHub App or registry credentials. The RSA audit, candidate assembly, qualified
artifact validators and consumer repin gates are unchanged. A passing regression build does not
resolve those gates.
