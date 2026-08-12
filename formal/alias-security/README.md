# Alias formal security model

This directory contains the normative alias [security contract](SECURITY-CONTRACT.md), two TLA+
transition systems, the [proof inventory and gap matrix](PROOF-COVERAGE.md), and canonical
cross-language conformance vectors.

Run the machine checker with:

```bash
./formal/alias-security/check.sh
```

The script downloads TLA+ 1.8.0 from the official release, verifies its pinned SHA-256 digest, and
checks the vault safety model, adversarial concurrent lifecycle model, and reliable/quiescent
liveness model. Java 11 or newer and `curl` are required.

Run the native refinement gates with:

```bash
cargo test -p bitwarden-alias --test security_conformance
cargo test -p bitwarden-uniffi security_conformance
```

The WASM build's Jest suite reads the same `conformance-vectors.json` and drives the exported
reference/reconciliation functions and replay-sensitive lifecycle client.
