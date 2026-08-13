#!/usr/bin/env bash
set -euo pipefail

upstream_ref="${1:-}"
[[ -n "$upstream_ref" ]] || {
    echo "Usage: $0 UPSTREAM_GIT_REF" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
branch_sha="$(git -C "$repository_root" rev-parse HEAD)"
upstream_sha="$(git -C "$repository_root" rev-parse "${upstream_ref}^{commit}")"
pinned_base="$(tr -d '[:space:]' <"$repository_root/support/alias-sdk-release/UPSTREAM_BASE")"
actual_base="$(git -C "$repository_root" merge-base "$branch_sha" "$upstream_sha")"

git -C "$repository_root" cat-file -e "${pinned_base}^{commit}" || {
    echo "Alias SDK upstream gate failed: pinned base $pinned_base is not present" >&2
    exit 1
}
[[ "$actual_base" == "$pinned_base" ]] || {
    echo "Alias SDK upstream gate failed: UPSTREAM_BASE is stale." >&2
    echo "Pinned: $pinned_base" >&2
    echo "Actual: $actual_base" >&2
    exit 1
}

ahead="$(git -C "$repository_root" rev-list --count "$upstream_sha..$branch_sha")"
behind="$(git -C "$repository_root" rev-list --count "$branch_sha..$upstream_sha")"
echo "Alias branch: $branch_sha"
echo "Canonical SDK: $upstream_sha"
echo "Pinned merge base: $pinned_base"
echo "Patch commits: $ahead"
echo "Upstream commits pending: $behind"

if ! merge_tree="$(git -C "$repository_root" merge-tree --write-tree "$branch_sha" "$upstream_sha")"; then
    echo "Alias SDK upstream gate failed: the patch stack conflicts with $upstream_sha" >&2
    exit 1
fi
echo "Synthetic merge tree: $merge_tree"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    {
        echo "branch_sha=$branch_sha"
        echo "upstream_sha=$upstream_sha"
        echo "upstream_base=$pinned_base"
        echo "ahead=$ahead"
        echo "behind=$behind"
        echo "merge_tree=$merge_tree"
    } >>"$GITHUB_OUTPUT"
fi

echo "Alias SDK upstream merge gate passed"
