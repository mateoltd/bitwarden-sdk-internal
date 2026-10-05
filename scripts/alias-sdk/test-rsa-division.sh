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
  for reduction in rem rem-vartime; do
    for value in zero high; do
      for implementation in original candidate; do
        prefix="$probe_target/$profile-$reduction-$value-$implementation"
        status=0
        valgrind --tool=memcheck --xml=yes --xml-file="$prefix.xml" --error-exitcode=77 \
          "$binary" "$implementation" "$value" "$reduction" >"$prefix.stdout" || status=$?
        cat "$prefix.stdout"
        python3 scripts/alias-sdk/check-rsa-division.py \
          "$implementation" "$value" "$reduction" "$status" "$prefix.xml" "$prefix.stdout"
      done
    done
  done
done
