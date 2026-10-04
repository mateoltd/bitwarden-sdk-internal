#!/usr/bin/env bash
set -euo pipefail

artifact="${1:?Usage: test-fork-clients.sh BUILD_DIRECTORY SOURCE_SHA}"
source_commit="${2:?Expected immutable SDK source SHA}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact="$(cd "$artifact" && pwd)"
pin="$repository_root/support/alias-sdk-release/fork-clients.json"
read_pin() { node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]]' "$pin" "$1"; }
[[ "$(node --version)" == "v$(read_pin node)" && "$(npm --version)" == "$(read_pin npm)" ]] || {
    echo "Use the pinned consumer Node/npm toolchain from $pin" >&2
    exit 1
}
python3 "$repository_root/scripts/alias-sdk/regression-artifact.py" verify typescript "$artifact" "$source_commit"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/alias-fork-clients.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
export GIT_TERMINAL_PROMPT=0
git -c credential.helper= clone --filter=blob:none --no-checkout "$(read_pin repository)" "$temporary_directory/source"
git -C "$temporary_directory/source" -c credential.helper= fetch origin "$(read_pin commit)"
git -C "$temporary_directory/source" merge-base --is-ancestor "$(read_pin base)" "$(read_pin commit)"
mkdir "$temporary_directory/consumer"
git -C "$temporary_directory/source" archive "$(read_pin commit)" -- . ':!bitwarden_license' \
    | tar -x -C "$temporary_directory/consumer"
python3 "$repository_root/scripts/alias-sdk/regression-artifact.py" extract typescript "$artifact" "$source_commit" "$temporary_directory/sdk"
cd "$temporary_directory/consumer"
export PATH="$PWD/node_modules/.bin:$PATH"
# Reuse the public consumer's OSS export boundary, without running its historical
# candidate qualification or modifying its checked-in SDK/provenance pins.
node scripts/release/prepare-clean-room.mjs
sha256sum package.json package-lock.json > "$temporary_directory/consumer-pins.sha256"
npm ci --ignore-scripts --no-audit --no-fund
for package in sdk-internal alias-sdk-internal; do
    [[ -d "node_modules/@bitwarden/$package" && ! -L "node_modules/@bitwarden/$package" ]] || {
        echo "Expected a physical locked SDK installation: $package" >&2
        exit 1
    }
    node - "$temporary_directory/sdk/package/package.json" "node_modules/@bitwarden/$package/package.json" <<'NODE'
const fs = require("node:fs");
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8")).dependencies ?? {};
if (JSON.stringify(read(process.argv[2])) !== JSON.stringify(read(process.argv[3]))) {
  throw new Error("SDK dependencies changed; the pinned consumer lockfile needs owner review");
}
NODE
    # Keep the consumer's locked nested dependencies (notably type-fest 5).
    mv "node_modules/@bitwarden/$package/node_modules" "$temporary_directory/$package-dependencies"
    rm -rf "node_modules/@bitwarden/$package"
    cp -R "$temporary_directory/sdk/package" "node_modules/@bitwarden/$package"
    diff -qr "$temporary_directory/sdk/package" "node_modules/@bitwarden/$package"
    mv "$temporary_directory/$package-dependencies" "node_modules/@bitwarden/$package/node_modules"
done
node "$repository_root/scripts/alias-sdk/compile-fork-clients.cjs"
# Observe rejection by the real consumer compiler, not a mocked compiler exit.
negative_file="libs/common/src/__sdk_ci_reject.ts"
test ! -e "$negative_file"
printf '// @ts-strict\nexport const invalid: string = 1;\n' > "$negative_file"
if node "$repository_root/scripts/alias-sdk/compile-fork-clients.cjs" > "$temporary_directory/negative.log" 2>&1; then
    echo "Consumer compiler accepted an intentional type error" >&2
    exit 1
fi
cat "$temporary_directory/negative.log"
grep -F '__sdk_ci_reject.ts(2,14): error TS2322' "$temporary_directory/negative.log"
rm "$negative_file"
echo "Real failing-consumer rejection passed"
sha256sum --check "$temporary_directory/consumer-pins.sha256"
printf 'BUILD-ONLY compatibility passed: consumer=%s SDK=%s\n' "$(read_pin commit)" "$source_commit"
