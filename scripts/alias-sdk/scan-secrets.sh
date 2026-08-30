#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gitleaks_binary="${GITLEAKS_BIN:-}"
base_ref="${GITLEAKS_BASE_REF:-$(tr -d '[:space:]' <"$repository_root/support/alias-sdk-release/UPSTREAM_BASE")}"
head_ref="${GITLEAKS_HEAD_REF:-HEAD}"

if [[ -z "$gitleaks_binary" ]]; then
    gitleaks_binary="$(command -v gitleaks || true)"
fi
[[ -n "$gitleaks_binary" && -x "$gitleaks_binary" ]] || {
    echo "Alias SDK secret scan gate failed: gitleaks is unavailable." >&2
    echo "Install the pinned binary with: scripts/alias-sdk/install-gitleaks.sh <directory>" >&2
    exit 1
}

git -C "$repository_root" rev-parse --is-inside-work-tree >/dev/null
base_sha="$(git -C "$repository_root" rev-parse "${base_ref}^{commit}")"
head_sha="$(git -C "$repository_root" rev-parse "${head_ref}^{commit}")"
git -C "$repository_root" merge-base --is-ancestor "$base_sha" "$head_sha" || {
    echo "Alias SDK secret scan gate failed: $base_sha is not an ancestor of $head_sha" >&2
    exit 1
}
"$gitleaks_binary" git "$repository_root" \
    --config "$repository_root/.gitleaks.toml" \
    --log-opts="$base_sha..$head_sha" \
    --redact \
    --no-banner \
    --verbose

echo "Alias SDK patch-history secret scan passed ($base_sha..$head_sha)"
