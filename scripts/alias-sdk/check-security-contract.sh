#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository_root"

python3 scripts/alias-sdk/validate_security_assurance.py
./formal/alias-security/check.sh
cargo test --locked --package bitwarden-alias --all-features
cargo test --locked --package bitwarden-uniffi security_conformance

echo "Alias SDK assurance, formal, Rust, and UniFFI security contract passed"
