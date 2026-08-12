#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:-}"
upstream_ref="${2:-}"
report_path="${3:-}"
[[ -n "$base_ref" && -n "$upstream_ref" && -n "$report_path" ]] || {
    echo "Usage: $0 BASE_REF UPSTREAM_REF REPORT_PATH" >&2
    exit 2
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
base_sha="$(git -C "$repository_root" rev-parse "${base_ref}^{commit}")"
upstream_sha="$(git -C "$repository_root" rev-parse "${upstream_ref}^{commit}")"
mkdir -p "$(dirname "$report_path")"
all_changes="$(git -C "$repository_root" diff --name-only "$base_sha..$upstream_sha")"
relevant_changes="$(
    grep -E \
        '^(Cargo\.(toml|lock)|rust-toolchain\.toml|scripts/|\.github/workflows/(build-(android|swift|wasm-internal)|rust-test|lint)\.yml|crates/bitwarden-(alias|api-base|core|generators|pm|sensitive-value|uniffi|vault|wasm-internal)/)' \
        <<<"$all_changes" || true
)"

{
    echo "# Alias SDK upstream drift report"
    echo
    echo "- Pinned upstream base: \`$base_sha\`"
    echo "- Fetched upstream commit: \`$upstream_sha\`"
    echo "- Total changed paths: $(grep -c . <<<"$all_changes" || true)"
    echo "- Alias-relevant changed paths: $(grep -c . <<<"$relevant_changes" || true)"
    echo
    echo "## Relevant paths"
    echo
    if [[ -n "$relevant_changes" ]]; then
        sed 's/^/- `/' <<<"$relevant_changes" | sed 's/$/`/'
    else
        echo "No paths matched the maintained alias compatibility surface. The security and compatibility gates still run."
    fi
    echo
    echo "## Reproduce"
    echo
    echo '```bash'
    echo "git fetch https://github.com/bitwarden/sdk-internal.git $upstream_sha"
    echo "scripts/alias-sdk/check-upstream-merge.sh FETCH_HEAD"
    echo '```'
} >"$report_path"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    if [[ -n "$relevant_changes" ]]; then
        echo "relevant=true" >>"$GITHUB_OUTPUT"
    else
        echo "relevant=false" >>"$GITHUB_OUTPUT"
    fi
    echo "upstream_sha=$upstream_sha" >>"$GITHUB_OUTPUT"
fi

echo "Classified upstream changes from $base_sha to $upstream_sha"
