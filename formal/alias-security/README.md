# Alias formal security model

This directory contains the normative alias [security contract](SECURITY-CONTRACT.md), two TLA+
transition systems, the [proof inventory and gap matrix](PROOF-COVERAGE.md), and canonical
cross-language conformance vectors.

The canonical wire format is the six-field, connection-scoped version 1 schema. All non-version-1
inputs fail closed; the model and vectors define no development-schema decoder or migration path.

Run the consolidated machine-checked contract with:

```bash
scripts/alias-sdk/check-security-contract.sh
```

The script downloads TLA+ 1.8.0 from the official release, verifies its pinned SHA-256 digest,
checks the vault safety model, adversarial concurrent lifecycle model, and reliable/quiescent
liveness model, then runs the Rust and UniFFI refinement gates. Java 11 or newer and `curl` are
required.

After building the versioned WASM package, `scripts/alias-sdk/test-wasm-conformance.sh` reads the
same `conformance-vectors.json` and drives the exported reference/reconciliation functions and
replay-sensitive lifecycle client.
