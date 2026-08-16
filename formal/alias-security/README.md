# Alias formal security model

This directory contains the normative provider-neutral alias
[security contract](SECURITY-CONTRACT.md), three TLA+ transition systems, the
[proof inventory and gap matrix](PROOF-COVERAGE.md), and the canonical cross-language
conformance vectors.

The version 1 vault reference is exactly the four-field, connection-scoped shape
`version`, `connectionId`, opaque string `aliasId`, and canonical `address`. Adapter identifier,
endpoint, credentials, and provider-native data are connection implementation metadata and never
part of identity. There is no provider enum, legacy decoder, migration shape, or dual schema.

The checked models have separate responsibilities:

- `AliasVault` checks stable identity, exact reference fields, reconciliation authorization and
  idempotence, vault frame conditions, and connection-metadata and credential exclusion.
- `AliasJournal` checks connection-scoped causal append, validated set-union merge, deterministic
  reduction, explicit conflicts and unknown outcomes, and non-resurrecting tombstones.
- `AliasLifecycle` checks capability-gated desired-state transitions, fresh-read success, replay and
  unknown-outcome discipline, delete/disable separation, bounded interference, and liveness.

Run the consolidated machine-checked contract with:

```bash
scripts/alias-sdk/check-security-contract.sh
```

The formal script obtains TLA+ 1.8.0 from the official release and verifies its pinned SHA-256
digest before checking all four configurations. Java 11 or newer and `curl` are required. The
consolidated gate then runs the Rust and UniFFI refinement tests. Versioned WASM conformance consumes
the same `conformance-vectors.json`; no copied binding-specific vector is authoritative.
