#!/usr/bin/env bash
set -euo pipefail

candidate_directory="${1:-}"
[[ -d "$candidate_directory" ]] || {
    echo "Usage: $0 CANDIDATE_DIRECTORY" >&2
    exit 2
}

fail() {
    echo "Alias SDK candidate evidence gate failed: $*" >&2
    exit 1
}

for required_file in handoff-manifest.json SHA256SUMS SBOM.cdx.json; do
    [[ -f "$candidate_directory/$required_file" ]] || fail "missing $required_file"
done

api_reports="$(find "$candidate_directory/artifacts" -type f -name API-REPORT.txt -print | LC_ALL=C sort)"
[[ "$(grep -c . <<<"$api_reports")" -eq 4 ]] || fail "expected four public API reports"

while IFS= read -r report; do
    if grep -Ein \
        '(provider[_-]?instance|alias[_-]?(api[_-]?key|access[_-]?token|credential|endpoint|error[_-]?body|raw[_-]?(response|payload)|signed[_-]?suffix)|(api[_-]?key|access[_-]?token|credential|endpoint|error[_-]?body|raw[_-]?(response|payload)|signed[_-]?suffix)[_-]?alias|ForwarderServiceType|simple[_-]?login)' \
        "$report"; then
        fail "sensitive connection or provider-native vocabulary entered $(basename "$report")"
    fi
done <<<"$api_reports"

text_evidence="$(find "$candidate_directory" -type f \
    \( -name '*.json' -o -name '*.txt' -o -name SHA256SUMS \) -print)"
if xargs grep -En \
    '(/Users/[^/[:space:]]+|/home/runner/work/|[A-Za-z]:\\Users\\)' \
    <<<"$text_evidence"; then
    fail "a host-specific absolute path entered candidate evidence"
fi

if grep -Eiq \
    '"name"[[:space:]]*:[[:space:]]*"bitwarden-(commercial-vault|pam|sm)"' \
    "$candidate_directory/SBOM.cdx.json"; then
    fail "commercial or PAM packages entered the candidate SBOM"
fi

node -e '
  const fs = require("node:fs");
  const root = process.argv[1];
  const manifest = JSON.parse(fs.readFileSync(`${root}/handoff-manifest.json`, "utf8"));
  const audit = JSON.parse(
    fs.readFileSync(`${root}/artifacts/alias-sdk-assurance/AUDIT-REPORT.json`, "utf8"),
  );
  if (manifest.releaseChannel !== "unreleased-prerelease") process.exit(1);
  if (Object.values(manifest.candidatePolicy ?? {}).some(Boolean)) process.exit(1);
  if (audit.cargo?.unacceptedVulnerabilityCount !== 0) process.exit(1);
  if (!Array.isArray(audit.cargo?.acceptedRisks)) process.exit(1);
  if (audit.npm?.vulnerabilities?.total !== 0) process.exit(1);
' "$candidate_directory" || fail "candidate policy or dependency audit evidence is invalid"

echo "Alias SDK candidate evidence is provider-neutral, path-clean, audited, and candidate-only"
