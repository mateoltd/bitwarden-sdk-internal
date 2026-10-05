#!/usr/bin/env python3
"""Verify the complete vendored RSA candidate without declaring the advisory fixed."""
import hashlib
import json
from pathlib import Path
import tomllib
root = Path(__file__).resolve().parents[2]

def require(condition, message):
    if not condition:
        raise ValueError(message)
vendor = root / 'support/vendor/rsa'
source = json.loads((vendor / 'SOURCE.json').read_text())
require(source['package'] == 'rsa' and source['version'] == '0.10.0-rc.18', 'RSA provenance invariant mismatch')
require(source['originalRegistrySha256'] == '30b2aa4ba0d89f73d1e332df05be0eeab8840351c36ca5654341dfdb57bb3caf', 'RSA provenance invariant mismatch')
require(source['originalCommit'] == 'e31a0209de98cce82de44a5efc241912eb38f6ea', 'RSA provenance invariant mismatch')
require(source['advisory'] == 'RUSTSEC-2023-0071', 'RSA provenance invariant mismatch')
actual = {file.relative_to(vendor).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest() for file in vendor.rglob('*') if file.is_file() and file.name != 'SOURCE.json'}
require(actual == source['patchedFiles'], 'RSA candidate file set or checksum mismatch')
changed = {name for name, digest in source['originalFiles'].items() if actual.get(name) != digest}
require(changed == {'Cargo.toml', 'Cargo.lock', 'src/algorithms/pad.rs', 'src/algorithms/rsa.rs', 'src/algorithms/mgf.rs', 'src/key.rs', 'src/oaep.rs'}, 'RSA provenance invariant mismatch')
manifest = tomllib.loads((root / 'Cargo.toml').read_text())
require(manifest['workspace']['dependencies']['rsa']['version'] == '=0.10.0-rc.18', 'RSA provenance invariant mismatch')
require('getrandom' in manifest['workspace']['dependencies']['rsa']['features'], 'RSA provenance invariant mismatch')
require(manifest['patch']['crates-io']['rsa'] == {'path': 'support/vendor/rsa'}, 'RSA provenance invariant mismatch')
lock = tomllib.loads((root / 'Cargo.lock').read_text())
packages = [entry for entry in lock['package'] if entry['name'] == 'rsa']
require(len(packages) == 1 and packages[0]['version'] == '0.10.0-rc.18', 'RSA provenance invariant mismatch')
require('source' not in packages[0], 'RSA did not resolve to the local patch')
test_lock = tomllib.loads((vendor / 'Cargo.lock').read_text())
for name, version in {'crypto-bigint': '0.7.5', 'crypto-common': '0.2.2', 'digest': '0.11.3', 'getrandom': '0.4.3', 'zeroize': '1.9.0'}.items():
    for graph in [lock, test_lock]:
        require(any((entry['name'] == name and entry['version'] == version for entry in graph['package'])), f'{name} does not match the production boundary')
bigint = root / 'support/vendor/crypto-bigint'
bigint_source = json.loads((bigint / 'SOURCE.json').read_text())
require(bigint_source['package'] == 'crypto-bigint' and bigint_source['version'] == '0.7.5', 'Integer provenance invariant mismatch')
require(bigint_source['originalRegistrySha256'] == '1a52aa3fcda4e6302a9f48734f234d35d4721b96f8fe07d073f07ce9df4f0271', 'Integer provenance invariant mismatch')
require(bigint_source['originalCommit'] == '2b54d248cce00457e3afb5650d9b14632ef4a116', 'Integer provenance invariant mismatch')
require(bigint_source['advisory'] == 'RUSTSEC-2023-0071', 'Integer provenance invariant mismatch')
bigint_actual = {file.relative_to(bigint).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest() for file in bigint.rglob('*') if file.is_file() and file.name != 'SOURCE.json'}
require(bigint_actual == bigint_source['patchedFiles'], 'Integer candidate file set or checksum mismatch')
bigint_changed = {name for name, digest in bigint_source['originalFiles'].items() if bigint_actual.get(name) != digest}
require(bigint_changed == {'Cargo.toml', 'src/modular/safegcd/boxed.rs', 'src/uint/boxed/gcd.rs', 'src/uint/ref_type/div.rs'}, 'Integer patch exceeded its scope')
require(manifest['patch']['crates-io']['crypto-bigint'] == {'path': 'support/vendor/crypto-bigint'}, 'Integer production patch route mismatch')
require(tomllib.loads((vendor / 'Cargo.toml').read_text())['patch']['crates-io']['crypto-bigint'] == {'path': '../crypto-bigint'}, 'Integer test patch route mismatch')
for graph in [lock, test_lock]:
    bigints = [entry for entry in graph['package'] if entry['name'] == 'crypto-bigint' and entry['version'] == '0.7.5']
    require(len(bigints) == 1 and 'source' not in bigints[0], 'RSA integer boundary did not resolve to the local patch')
require(tomllib.loads((bigint / 'Cargo.toml').read_text())['package']['rust-version'] == '1.86', 'Integer const barrier minimum mismatch')
require(tomllib.loads((vendor / 'Cargo.toml').read_text())['package']['rust-version'] == '1.86', 'RSA boundary minimum mismatch')
print('Exact RSA and integer patches verified; RUSTSEC-2023-0071 remains explicitly tracked')
