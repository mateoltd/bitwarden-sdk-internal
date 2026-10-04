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
require(changed == {'Cargo.toml', 'Cargo.lock', 'src/algorithms/pad.rs', 'src/algorithms/rsa.rs', 'src/algorithms/mgf.rs', 'src/oaep.rs'}, 'RSA provenance invariant mismatch')
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
print('Exact RSA patch verified; RUSTSEC-2023-0071 remains explicitly tracked')
