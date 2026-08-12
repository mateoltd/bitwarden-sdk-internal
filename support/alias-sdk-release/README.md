# Alias SDK release lane

This directory contains clean-room consumers and pinned maintenance inputs for the GPL-only alias
SDK artifacts. It does not define product behavior. The Rust API and the existing WASM and UniFFI
bindings remain authoritative.

## Gates

The release workflow must pass all of these gates before it assembles a candidate:

1. Gitleaks scan of the complete alias patch stack since `UPSTREAM_BASE`, using the pinned,
   checksum-verified scanner;
2. Cargo dependency and packaged-artifact commercial-boundary checks;
3. alias crate tests;
4. TypeScript, Swift, Kotlin/JVM, and Android clean-room consumer builds;
5. a source-commit manifest, SHA-256 checksums, and GitHub build provenance.

Every consumer is copied to a temporary directory and receives only the packaged artifact. A
missing compiler, SDK, or NDK is a failed prerequisite gate with a reproduction command; it is not
reported as a passing or skipped consumer.

The release workflow publishes only tags named `alias-sdk-v*`. Pull requests, branch pushes, and
manual runs produce retained release-candidate artifacts but do not create a GitHub release.

## Upstream maintenance

`UPSTREAM_BASE` records the canonical SDK commit on which the alias patch stack is based. The
scheduled maintenance workflow fetches current `bitwarden/sdk-internal`, creates an ephemeral merge
commit, and runs the focused contract and boundary gates on that exact tree. It also compares the
TypeScript fixture contract with current `bitwarden/clients`.

To reproduce a reported SDK merge locally:

```bash
git fetch https://github.com/bitwarden/sdk-internal.git <reported-sha>
scripts/alias-sdk/check-upstream-merge.sh FETCH_HEAD
```

After deliberately rebasing or merging the patch stack, replace `UPSTREAM_BASE` with the reviewed
canonical SDK commit. When the clients compiler contract changes, update
`consumers/typescript/bitwarden-clients-contract.json`, its package lock, and the fixture together.
