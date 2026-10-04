#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository_root"
manifest="support/rsa-division-probe/Cargo.toml"
probe_target="$(mktemp -d)"
trap 'rm -rf "$probe_target"' EXIT

for profile in release speed; do
  CARGO_TARGET_DIR="$probe_target" cargo build --manifest-path "$manifest" --locked --profile "$profile"
  binary="$probe_target/$profile/rsa-division-probe"
  for value in zero high; do
    # The actual original dependency must expose the property, calibrating the detector.
    original_status=0
    valgrind --tool=memcheck --error-exitcode=77 "$binary" original "$value" || original_status=$?
    if [[ "$original_status" != 77 ]]; then
      echo "Original division control did not expose the secret-dependent operation" >&2
      exit 1
    fi
    valgrind --tool=memcheck --error-exitcode=77 "$binary" candidate "$value"
  done
done
