# Alias formal security model

This directory contains the normative alias [security contract](SECURITY-CONTRACT.md), two TLA+
transition systems, the [proof inventory and gap matrix](PROOF-COVERAGE.md), and canonical
cross-language conformance vectors.

The compositional [end-to-end assurance case](../../docs/alias-security-assurance/README.md) places
this finite-state evidence inside the larger client, vault, provider, mail, and operational trust
boundaries. Its machine-readable traceability manifest deliberately distinguishes checked claims
from assumptions and known gaps.

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
