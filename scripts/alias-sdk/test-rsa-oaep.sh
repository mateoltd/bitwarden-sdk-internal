#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository_root"
python3 scripts/alias-sdk/check-rsa-patch.py
manifest="support/vendor/rsa/Cargo.toml"
cargo test --manifest-path "$manifest" --locked --features getrandom --lib algorithms::pad::tests
cargo test --manifest-path "$manifest" --locked --features getrandom --lib oaep::tests
cargo test --manifest-path "$manifest" --locked --features getrandom --test oaep_boundary
cargo test --manifest-path "$manifest" --locked --lib oaep_without_entropy_fails_closed
cargo test --manifest-path "$manifest" --locked --lib oaep_entropy_failure_never_falls_back
cargo check --manifest-path "$manifest" --locked --no-default-features --features encoding,getrandom
