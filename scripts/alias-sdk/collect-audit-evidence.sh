#!/usr/bin/env bash
set -euo pipefail
output="${1:?Usage: collect-audit-evidence.sh OUTPUT_DIRECTORY}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository_root"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
scripts/alias-sdk/create-cargo-package-list.sh "$output/cargo-active.txt"
python3 scripts/alias-sdk/rsa-remediation.py source \
    --output "$output/SOURCE-REMEDIATION.json"
python3 scripts/alias-sdk/rsa-remediation.py identity-lock \
    --output "$output/upstream-identity.lock"
# Only the first audit fetches. Both reports must name the same advisory database.
set +e
cargo audit --json >"$output/cargo-audit.json" 2>"$output/cargo-audit.stderr"
cargo_exit=$?
set -e
database="${CARGO_HOME:-$HOME/.cargo}/advisory-db"
python3 - "$database" "$output/DATABASE-IDENTITY.json" <<'PY'
import json, pathlib, subprocess, sys
database, output = sys.argv[1:]
def git(*args):
    return subprocess.check_output(['git', '-C', database, *args]).decode().strip()
if git('status', '--porcelain'):
    raise ValueError('advisory database has local modifications')
record = {'schemaVersion': 1, 'origin': git('remote', 'get-url', 'origin'),
          'commit': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
          'toolVersion': subprocess.check_output(['cargo-audit', '--version']).decode().strip()}
pathlib.Path(output).write_text(json.dumps(record, indent=2) + '\n')
PY
set +e
cargo audit --json --no-fetch --file "$output/upstream-identity.lock" \
    >"$output/upstream-identity-audit.json" 2>"$output/upstream-identity-audit.stderr"
upstream_exit=$?
set -e
python3 - "$database" "$output/DATABASE-IDENTITY.json" <<'PY'
import json, pathlib, subprocess, sys
database, file = sys.argv[1:]
record = json.loads(pathlib.Path(file).read_text())
def git(*args):
    return subprocess.check_output(['git', '-C', database, *args]).decode().strip()
if (git('rev-parse', 'HEAD') != record['commit'] or
        git('rev-parse', 'HEAD^{tree}') != record['tree'] or git('status', '--porcelain')):
    raise ValueError('advisory database changed during audit collection')
PY
set +e
npm audit --json >"$output/npm-audit.json" 2>"$output/npm-audit.stderr"
npm_exit=$?
set -e
printf '{"cargo":%s,"upstreamIdentity":%s,"npm":%s}\n' \
    "$cargo_exit" "$upstream_exit" "$npm_exit" >"$output/AUDIT-TOOL-STATUS.json"
python3 - "$output" <<'PY'
from datetime import datetime, timezone
import json, pathlib, subprocess, sys
output = pathlib.Path(sys.argv[1])
source = json.loads((output / 'SOURCE-REMEDIATION.json').read_text())
record = {'schemaVersion': 1, 'collectedAt': datetime.now(timezone.utc).isoformat(),
          'sourceCommit': subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
          'sourceCatalog': source['sourceCatalog']}
(output / 'COLLECTION-IDENTITY.json').write_text(json.dumps(record, indent=2) + '\n')
PY
scripts/alias-sdk/create-audit-report.mjs "$output" "$output/cargo-active.txt" \
    support/alias-sdk-release/audit-policy.json "$output/AUDIT-REPORT.json"
echo "Source-bound patch and independent audits recorded. OAEP delivery qualification remains required."
