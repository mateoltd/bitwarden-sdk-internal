# Canonical alias SDK release lane

This directory contains clean-room consumers and pinned maintenance inputs for the GPL-only alias
SDK artifacts. It does not define product behavior. The Rust API, formal security contract, and
generated WASM and UniFFI bindings in this repository are the authoritative implementation.
Historical topic branches are reference inputs only, not release inputs or ancestors of this public
branch.

`VERSION` is the canonical unreleased prerelease, and `ALIAS_REFERENCE_SCHEMA_VERSION` is the
canonical wire-schema version stamped into every package. The current candidate is
`0.3.0-alias-provider-neutral.2`, schema v1. It corrects the unreleased v1 shape directly; no
migration, legacy decoder, dual schema, or deprecated provider-specific form belongs in an artifact.
`PREVIOUS_PUBLIC_ALIAS_HEAD` records the exact unreleased public SDK head whose v1 contract this
candidate replaces directly. `ios-integration.json` records the exact iOS feature consumer and its
pre-candidate sdk-swift pin; the handoff manifest marks it as requiring the provider-neutral Swift
artifact repin.

## Locked release decisions

- Alias identity is exactly connection scoped: `version`, stable `connectionId`, opaque bounded
  `aliasId`, and canonical `address`. Provider instance and endpoint are encrypted connection
  metadata, not identity.
- Adapter identifiers and negotiated capabilities are extensible validated values. SimpleLogin is a
  concrete adapter and appears only in adapter implementation tests and its source pin.
- Credentials, endpoints, provider-native payloads, provider error bodies, and provider-specific IDs
  are forbidden from references, vault bindings, journals, generated common definitions, telemetry,
  logs, API reports, and release metadata.
- Generated username requests are now pure and local. The credential-bearing `Forwarded` service
  union, including its SimpleLogin-only form, is removed; remote alias creation goes through an
  explicitly injected provider-neutral `AliasClient`.
- Every public package is GPL-only. The root Cargo workspace keeps commercial crates available as
  explicit members for internal builds, but its default member graph contains only `crates/*` and
  never activates the commercial or PAM feature edge.

## Candidate gates

The full release workflow must pass all of these gates before assembling a candidate:

1. Gitleaks scan of the complete patch stack since `UPSTREAM_BASE`, using the pinned,
   checksum-verified scanner;
2. default Cargo graph, packaged-artifact, secret, and commercial-boundary checks;
3. TLA+ models plus Rust, UniFFI, and WASM adversarial and conformance vectors;
4. TypeScript, Swift, Kotlin/JVM, and Android clean-room consumer builds using only the packaged
   artifacts;
5. a second clean package build on the same pinned runner with exact normalized-byte comparison;
6. deterministic API reports for every language artifact;
7. Cargo and npm vulnerability audits plus a deterministic CycloneDX 1.6 SBOM for artifact and
   active public dependency graphs;
8. the pinned real SimpleLogin lifecycle on candidate source;
9. a machine-readable handoff manifest with source and consumer pins, decisions, package paths,
   SHA-256 digests, audit/SBOM evidence, and per-package reproducibility evidence;
10. signed GitHub provenance for non-pull-request runs, verified against the exact source,
    repository, ref, and workflow before consumer integration.

The launch integration branch assembles a scoped JavaScript candidate. It runs Rust and UniFFI
security checks, WASM conformance, dependency audits, two WASM builds, and the TypeScript consumer.
Swift, Kotlin, Android, full formal qualification, and the live provider lifecycle are separate
qualification obligations. A scoped candidate does not establish that those checks passed.

Every consumer is copied to a temporary directory and receives only a packaged artifact. A missing
compiler, SDK, NDK, audit tool, or attestation permission is a failed prerequisite gate, never a
passing or skipped consumer. Reproducibility is an exact comparison of two normalized packages on
the same immutable runner image. It detects nondeterminism within that environment; it does not by
itself prove bit-identical output across different OS or toolchain versions. Cargo and npm audits
use their current upstream advisory databases at workflow runtime, so an older candidate's audit
report is historical evidence, not a substitute for re-auditing before integration.

The current Cargo graph has one unresolved active finding: `RUSTSEC-2023-0071` in `rsa 0.10.0-rc.18`
through `bitwarden-crypto -> rsa`. RustSec provides no patched release. Alias lifecycle operations
do not call RSA private-key operations, but the shared SDK includes RSA key decapsulation and the
WASM PureCrypto RSA primitive. Consumer exposure must be assessed at those boundaries; a practical
remote timing oracle has not been established here. The previous narrow exception expired on
2026-10-01. It is not current risk acceptance, and CI rejects it. A new documented, time-bounded
security-owner decision is a possible disposition, not an existing approval. No policy renewal or
cryptographic remediation is implied by this document. The machine-readable policy remains
`audit-policy.json`.

The workflow is candidate-only. It never publishes a registry package, creates a Git tag, creates a
GitHub release, opens a pull request, or pushes a branch. Pull-request runs produce unsigned preview
artifacts. Push and manual candidate runs request a signed provenance bundle through GitHub Actions.
The handoff manifest records the attestation strategy for its actual run. Verify downloaded files
against `SHA256SUMS` and verify the signed provenance with `gh attestation verify`, restricting the
source repository, ref, workflow, and commit. Historical successful attestations establish their
exact candidate identity; they do not satisfy a current expired audit gate.

## Clean-room reproduction

The workflow records its exact runner image and compiler versions in each platform directory.
Locally, build twice and compare with the same commands used by CI:

```bash
scripts/alias-sdk/build-wasm.sh /tmp/alias-wasm-a
scripts/alias-sdk/build-wasm.sh /tmp/alias-wasm-b
scripts/alias-sdk/verify-reproducible.sh \
  /tmp/alias-wasm-a/bitwarden-sdk-internal-0.3.0-alias-provider-neutral.2.tgz \
  /tmp/alias-wasm-b/bitwarden-sdk-internal-0.3.0-alias-provider-neutral.2.tgz
```

Equivalent jobs run for Swift, Kotlin/JVM, Android, and Android native libraries. Package archives
use fixed timestamps, stable path order, fixed tar ownership, gzip without a timestamp, and ZIP/JAR
metadata stripping before comparison and handoff.

## Upstream maintenance

`INTEGRATION_BASE` records the exact `origin/main` commit from which the clean public history began.
`UPSTREAM_BASE` records the canonical SDK commit underlying the alias patch stack. The scheduled
maintenance workflow fetches current `bitwarden/sdk-internal`, creates an ephemeral merge tree, and
runs focused contract and boundary gates. It also compares the TypeScript fixture contract with the
pinned public `bitwarden/clients` commit.

To reproduce a reported SDK merge locally:

```bash
git fetch https://github.com/bitwarden/sdk-internal.git <reported-sha>
scripts/alias-sdk/check-upstream-merge.sh FETCH_HEAD
```

After deliberately rebasing the patch stack, replace `UPSTREAM_BASE` with the reviewed canonical SDK
commit. When the client compiler contract changes, update
`consumers/typescript/bitwarden-clients-contract.json`, its package lock, and the fixture together.
