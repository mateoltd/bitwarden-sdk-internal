# Canonical alias SDK release lane

This directory contains clean-room consumers and pinned maintenance inputs for the GPL-only alias
SDK artifacts. It does not define product behavior. The Rust API, formal security contract, and
generated WASM and UniFFI bindings in this repository are the single authoritative implementation
for clients. Historical topic branches are reference inputs only and are not release inputs or
ancestors of the public branch.

## Gates

The release workflow must pass all of these gates before it assembles a candidate:

1. Gitleaks scan of the complete alias patch stack since `UPSTREAM_BASE`, using the pinned,
   checksum-verified scanner;
2. Cargo dependency and packaged-artifact commercial-boundary checks;
3. the TLA+ model and Rust, UniFFI, and WASM conformance vectors;
4. TypeScript, Swift, Kotlin/JVM, and Android clean-room consumer builds;
5. the pinned real SimpleLogin lifecycle on the candidate source and on the synthetic upstream merge
   used by the drift workflow;
6. a versioned machine-readable handoff manifest with source commit, provider pin, client steps,
   per-package paths and versions, SHA-256 checksums, and GitHub build provenance.

Every consumer is copied to a temporary directory and receives only the packaged artifact. A missing
compiler, SDK, or NDK is a failed prerequisite gate with a reproduction command; it is not reported
as a passing or skipped consumer.

`VERSION` is the canonical candidate version, `ALIAS_REFERENCE_SCHEMA_VERSION` is the canonical
wire-schema version stamped into every candidate package directory, and `INTEGRATION_BASE` records
the exact `origin/main` commit from which the clean public history begins. The release workflow is
candidate-only. Pull requests, pushes to `integration/public-alias-sdk` or `main`, and manual runs
produce retained GitHub Actions artifacts; it never publishes to a registry or creates a GitHub
release. After this work is merged, `main` is the canonical source and continues to run the same
contract.

Every package record and the top-level handoff manifest declare alias reference schema version 1.
Artifacts from the earlier `0.2.0-alias-platform.1` development candidate encoded version 2 and are
invalid inputs; clients must not decode or migrate them.

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
