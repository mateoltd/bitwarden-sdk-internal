#!/usr/bin/env python3
"""Source-bound OAEP evidence, independent advisory reporting and delivery qualification."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
ADVISORY = 'RUSTSEC-2023-0071'
PACKAGES = {'rsa': '0.10.0-rc.18', 'crypto-bigint': '0.7.5'}
PRIVATE_CALLERS = {'crates/bitwarden-crypto/src/enc_string/asymmetric.rs',
                   'crates/bitwarden-wasm-internal/src/pure_crypto.rs',
                   'crates/bitwarden-importers/src/importers/onepassword/access/rsa.rs'}
SOURCE_ROOTS = ['crates', 'bitwarden_license', 'support/vendor', '.cargo']
SOURCE_FILES = ['Cargo.toml', 'Cargo.lock', 'Cross.toml', 'rust-toolchain.toml',
                'package.json', 'package-lock.json', 'scripts/alias-sdk/check-rsa-patch.py',
                'scripts/alias-sdk/build-wasm.sh', 'scripts/alias-sdk/build-swift.sh',
                'scripts/alias-sdk/build-kotlin-host.sh']
REQUIRED_PROOFS = {'optimized-code', 'runtime', 'bindings', 'vectors', 'entropy',
                   'property', 'review', 'build-provenance'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_json(file):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f'duplicate JSON key: {key}')
            result[key] = value
        return result
    return json.loads(Path(file).read_text(), object_pairs_hook=unique_pairs)


def write_json(file, value):
    Path(file).parent.mkdir(parents=True, exist_ok=True)
    Path(file).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def integer(value):
    return type(value) is int and value >= 0


def same_json(left, right):
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def file_record(root, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute()
            and '..' not in Path(name).parts, 'invalid evidence path')
    file = root / name
    require(file.is_file() and not file.is_symlink()
            and root.resolve() in file.resolve().parents, f'missing or unsafe file: {name}')
    data = file.read_bytes()
    return {'path': name, 'bytes': len(data), 'sha256': digest(data)}


def source_catalog(root):
    # Inventory, not a decrypt-name search: new callers, features, build scripts and included
    # data all invalidate the reviewed closure. Git supplies the source set, never build output.
    names = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--cached',
                                     '--others', '--exclude-standard', '--', *SOURCE_ROOTS])
    files = sorted(set(names.decode().strip('\0').split('\0') + SOURCE_FILES))
    records = [file_record(root, name) for name in files]
    encoded = ''.join(f"{r['sha256']}  {r['path']}\n" for r in records).encode()
    return {'algorithm': 'sha256(sorted-sha256-path-lines)', 'fileCount': len(records),
            'sha256': digest(encoded)}


def committed_catalog(root, commit):
    archive = subprocess.check_output(['git', '-C', str(root), 'archive', commit,
                                      *SOURCE_ROOTS, *SOURCE_FILES])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        records = []
        for member in tar.getmembers():
            if member.isdir():
                continue
            require(member.isfile(), 'nonregular committed source')
            records.append((member.name, digest(tar.extractfile(member).read())))
    encoded = ''.join(f'{sha}  {name}\n' for name, sha in sorted(records)).encode()
    return {'algorithm': 'sha256(sorted-sha256-path-lines)', 'fileCount': len(records),
            'sha256': digest(encoded)}


def load_policy(file):
    policy = read_json(file)
    require(policy.get('schemaVersion') == 2 and policy.get('exceptions') == [],
            'unsupported audit policy or risk exception')
    patch = policy.get('oaepRemediation')
    require(isinstance(patch, dict) and patch.get('advisoryId') == ADVISORY
            and patch.get('packages') == PACKAGES and patch.get('genericPkcs1v15Qualified') is False,
            'invalid scoped remediation identity')
    require(isinstance(patch.get('approvedDeliveries'), list), 'missing delivery catalog')
    require(isinstance(patch.get('privateCallers'), dict)
            and set(patch['privateCallers']) == PRIVATE_CALLERS, 'unsupported private caller set')
    return policy


def verify_source(root, policy):
    patch = policy['oaepRemediation']
    require(source_catalog(root) == patch['sourceCatalog'], 'source/caller/feature catalog changed')
    require(all(file_record(root, name)['sha256'] == sha for name, sha in patch['privateCallers'].items()),
            'private OAEP caller changed')
    subprocess.run(['python3', str(root / 'scripts/alias-sdk/check-rsa-patch.py')],
                   check=True, stdout=subprocess.DEVNULL)
    lineage = {}
    catalogs = {}
    for name in PACKAGES:
        source = read_json(root / 'support/vendor' / name / 'SOURCE.json')
        catalogs[name] = source
        lineage[name] = {key: source[key] for key in
                         ['package', 'version', 'originalRegistrySha256', 'originalCommit']}
        lineage[name]['provenanceSha256'] = digest(
            (root / 'support/vendor' / name / 'SOURCE.json').read_bytes())
    require(lineage == patch['lineage'], 'original/patch/license provenance changed')
    return {'sourceCatalog': patch['sourceCatalog'], 'lineage': lineage,
            'patchCatalogs': catalogs,
            'advisoryId': ADVISORY, 'genericPkcs1v15Qualified': False,
            'scope': patch['scope'],
            'privateCallers': patch['privateCallers'],
            'disposition': 'SOURCE_BOUND_PATCH_VERIFIED_DELIVERY_REQUIRED',
            'securityQualified': False}


def identity_lock(root, policy, output):
    verify_source(root, policy)
    text = (root / 'Cargo.lock').read_text()
    chunks = text.split('[[package]]')
    found = set()
    for i in range(1, len(chunks)):
        package = tomllib.loads('[[package]]' + chunks[i])['package'][0]
        name = package['name']
        if name not in PACKAGES or package['version'] != PACKAGES[name]:
            continue
        require(name not in found and 'source' not in package and 'checksum' not in package,
                'patch did not resolve exactly once as a path dependency')
        found.add(name)
        sha = policy['oaepRemediation']['lineage'][name]['originalRegistrySha256']
        chunks[i] = chunks[i].replace(f'version = "{package["version"]}"',
                                     f'version = "{package["version"]}"\nsource = "{REGISTRY}"\nchecksum = "{sha}"', 1)
    require(found == set(PACKAGES), 'missing patched identity')
    restored = '[[package]]'.join(chunks)
    require(Path(output).resolve() != (root / 'Cargo.lock').resolve(),
            'audit identity lock must never overwrite the build lock')
    # This is an audit-only projection of original identities, never a build input.
    Path(output).write_text(restored)


def validate_cargo(raw, exit_code, database_identity):
    require(isinstance(raw, dict) and 'error' not in raw, 'cargo audit operational failure')
    database, lock, settings, vulns, warnings = [raw.get(key) for key in
                                              ['database', 'lockfile', 'settings', 'vulnerabilities', 'warnings']]
    # rustsec 0.33 may leave the two optional git fields null. Independently captured
    # database provenance is mandatory; null is never promoted to an invented SHA.
    require(isinstance(database_identity, dict) and type(database_identity.get('schemaVersion')) is int
            and database_identity.get('schemaVersion') == 1
            and database_identity.get('origin') == 'https://github.com/RustSec/advisory-db.git'
            and re.fullmatch(r'[0-9a-f]{40}', database_identity.get('commit', ''))
            and re.fullmatch(r'[0-9a-f]{40}', database_identity.get('tree', ''))
            and database_identity.get('toolVersion') == 'cargo-audit 0.22.2',
            'missing advisory database provenance')
    require(isinstance(database, dict) and set(database) == {'last-commit', 'last-updated', 'advisory-count'}
            and database.get('last-commit') in [None, database_identity['commit']]
            and integer(database.get('advisory-count')) and database['advisory-count'] > 0
            and (database.get('last-updated') is None or isinstance(database['last-updated'], str)),
            'malformed advisory database metadata')
    require(isinstance(lock, dict) and integer(lock.get('dependency-count'))
            and lock['dependency-count'] > 0, 'malformed audit dependency count')
    require(isinstance(settings, dict) and settings.get('ignore') == []
            and settings.get('target_arch') == [] and settings.get('target_os') == []
            and settings.get('severity') is None
            and settings.get('informational_warnings') == ['unmaintained', 'unsound', 'notice'],
            'filtered or malformed cargo audit')
    require(isinstance(vulns, dict) and isinstance(vulns.get('list'), list)
            and type(vulns.get('found')) is bool and integer(vulns.get('count'))
            and vulns['count'] == len(vulns['list']) and vulns['found'] == bool(vulns['list']),
            'malformed vulnerability population')
    require(type(exit_code) is int and exit_code == (1 if vulns['found'] else 0),
            'cargo audit exit disagrees with raw findings')
    for entry in vulns['list']:
        require(isinstance(entry, dict) and isinstance(entry.get('advisory'), dict)
                and isinstance(entry.get('package'), dict)
                and re.fullmatch(r'RUSTSEC-\d{4}-\d{4}', entry['advisory'].get('id', ''))
                and isinstance(entry['package'].get('name'), str)
                and isinstance(entry['package'].get('version'), str), 'malformed advisory finding')
    require(isinstance(warnings, dict), 'missing informational warnings')
    for kind, entries in warnings.items():
        require(kind in ['unmaintained', 'unsound', 'notice', 'yanked']
                and isinstance(entries, list), 'malformed warning population')
        for entry in entries:
            require(isinstance(entry, dict) and isinstance(entry.get('package'), dict)
                    and (isinstance(entry.get('advisory'), dict)
                         or (kind == 'yanked' and entry.get('advisory') is None)),
                    'malformed informational warning')
            require(kind != 'unsound', 'unsound dependency warning requires separate remediation')
    return vulns['list']


def audit_report(root, policy, directory, active_file):
    source = verify_source(root, policy)
    collection = read_json(directory / 'COLLECTION-IDENTITY.json')
    require(type(collection.get('schemaVersion')) is int and collection.get('schemaVersion') == 1
            and re.fullmatch(r'[0-9a-f]{40}', collection.get('sourceCommit', ''))
            and collection.get('sourceCatalog') == policy['oaepRemediation']['sourceCatalog']
            and committed_catalog(root, collection['sourceCommit']) == collection['sourceCatalog'],
            'audit collection has mismatched source')
    collected = datetime.fromisoformat(collection.get('collectedAt', ''))
    require(collected.tzinfo is not None
            and 0 <= (datetime.now(timezone.utc) - collected).total_seconds() <= 86400,
            'audit collection is stale or has an invalid clock')
    current = read_json(directory / 'cargo-audit.json')
    upstream = read_json(directory / 'upstream-identity-audit.json')
    npm = read_json(directory / 'npm-audit.json')
    status = read_json(directory / 'AUDIT-TOOL-STATUS.json')
    database = read_json(directory / 'DATABASE-IDENTITY.json')
    current_findings = validate_cargo(current, status.get('cargo'), database)
    findings = validate_cargo(upstream, status.get('upstreamIdentity'), database)
    require(current['database']['advisory-count'] == upstream['database']['advisory-count'],
            'audit database changed between projections')
    require(len(findings) == 1, 'upstream identities have additional or missing advisories')
    finding = findings[0]
    require(finding['advisory'] == policy['oaepRemediation']['originalAdvisory']
            and finding.get('versions') == {'patched': [], 'unaffected': []}
            and finding.get('affected') is None
            and finding['package'].get('name') == 'rsa'
            and finding['package'].get('version') == PACKAGES['rsa']
            and finding['package'].get('source') == REGISTRY
            and finding['package'].get('checksum') == source['lineage']['rsa']['originalRegistrySha256'],
            'changed upstream advisory or package identity requires reassessment')
    require(all(entry['advisory'] == finding['advisory']
                and entry['package'].get('name') == 'rsa'
                and entry['package'].get('version') == PACKAGES['rsa']
                and entry.get('versions') == finding['versions'] and entry.get('affected') is None
                for entry in current_findings),
            'current dependency graph has an unremediated advisory')
    expected_lock = directory / 'expected-identity.lock'
    identity_lock(root, policy, expected_lock)
    try:
        require(expected_lock.read_bytes() == (directory / 'upstream-identity.lock').read_bytes(),
                'wrong upstream identity audit lock')
    finally:
        expected_lock.unlink(missing_ok=True)
    require('error' not in npm and type(npm.get('auditReportVersion')) is int
            and npm.get('auditReportVersion') == 2,
            'npm audit operational failure or unsupported report')
    totals = npm.get('metadata', {}).get('vulnerabilities', {})
    require(set(totals) == {'info', 'low', 'moderate', 'high', 'critical', 'total'}
            and all(integer(v) for v in totals.values())
            and totals['total'] == sum(totals[k] for k in totals if k != 'total')
            and isinstance(npm.get('vulnerabilities'), dict)
            and integer(npm.get('metadata', {}).get('dependencies', {}).get('total')),
            'npm audit has malformed findings')
    require(type(status.get('npm')) is int and status['npm'] == (1 if totals['total'] else 0),
            'npm audit exit disagrees with findings')
    require(totals['total'] == 0 and npm['vulnerabilities'] == {},
            f"npm audit has {totals['total']} unresolved vulnerabilities")
    active = Path(active_file).read_text().splitlines()
    require(Path(active_file).read_bytes() == (directory / 'cargo-active.txt').read_bytes(),
            'audit active inventory differs from delivered inventory')
    require(active and len(set(active)) == len(active)
            and all(re.fullmatch(r'[A-Za-z0-9_-]+@[^\s]+', line) for line in active)
            and all(f'{name}@{version}' in active for name, version in PACKAGES.items()),
            'active package inventory is malformed or omits patched packages')
    raw_files = [file_record(directory, name) for name in
                 ['cargo-audit.json', 'upstream-identity-audit.json', 'upstream-identity.lock',
                  'npm-audit.json', 'AUDIT-TOOL-STATUS.json', 'DATABASE-IDENTITY.json',
                  'COLLECTION-IDENTITY.json', 'cargo-active.txt']]
    return {'schemaVersion': 2, 'candidateOnly': True, 'securityQualified': False,
            'sourceCommit': collection['sourceCommit'],
            'sourceRemediation': source, 'rawEvidence': raw_files,
            'cargo': {'auditedDependencies': current['lockfile']['dependency-count'],
                      'activeDependencyCount': len(active), 'vulnerabilityCount': 1,
                      'unacceptedVulnerabilityCount': 1, 'acceptedRisks': [],
                      'advisories': [finding], 'informationalWarnings': upstream['warnings'],
                      'globalRustSecClosure': False},
            'npm': {'auditedDependencies': npm['metadata']['dependencies']['total'],
                    'vulnerabilities': totals}}


def qualify_delivery(root, policy, artifacts, platforms, commit):
    verify_source(root, policy)
    require(re.fullmatch(r'[0-9a-f]{40}', commit or ''), 'invalid delivered source commit')
    require(committed_catalog(root, commit) == policy['oaepRemediation']['sourceCatalog'],
            'delivery does not match reviewed production source')
    require(platforms and len(set(platforms)) == len(platforms), 'invalid platform population')
    assurance = artifacts / 'alias-sdk-assurance'
    audit = audit_report(root, policy, assurance, assurance / 'cargo-active.txt')
    recorded = read_json(assurance / 'AUDIT-REPORT.json')
    verifier_commit = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    require(re.fullmatch(r'[0-9a-f]{40}', recorded.get('sourceCommit', '')),
            'audit source commit is absent')
    audit['sourceCommit'] = recorded['sourceCommit']
    require(recorded == audit and committed_catalog(root, recorded['sourceCommit'])
            == policy['oaepRemediation']['sourceCatalog'], 'changed or stale audit report')
    audit['sourceCommit'] = commit
    audit['verifierCommit'] = verifier_commit
    records = []
    for platform in platforms:
        require(platform in ['typescript', 'swift', 'kotlin', 'android'], 'unsupported platform')
        directory = artifacts / f'alias-sdk-{platform}'
        record = file_record(directory, 'RSA-OAEP-DELIVERY.json')
        manifest = read_json(directory / record['path'])
        require(type(manifest.get('schemaVersion')) is int and manifest.get('schemaVersion') == 1
                and manifest.get('sourceCommit') == commit
                and manifest.get('sourceCatalog') == policy['oaepRemediation']['sourceCatalog']
                and manifest.get('platform') == platform, 'wrong artifact/source pairing')
        approved = [entry for entry in policy['oaepRemediation']['approvedDeliveries']
                    if entry.get('manifest') == record and entry.get('sourceCommit') == commit
                    and entry.get('platform') == platform]
        require(len(approved) == 1, f'no reviewed delivered compiler/profile/target/feature evidence: {platform}')
        build = manifest.get('build')
        require(isinstance(build, dict) and same_json(build, approved[0].get('build'))
                and isinstance(build.get('rustc'), str) and build['rustc']
                and isinstance(build.get('llvm'), str) and build['llvm']
                and isinstance(build.get('targets'), list) and build['targets']
                and len(set(build['targets'])) == len(build['targets'])
                and isinstance(build.get('profile'), dict)
                and re.fullmatch(r'[0-9a-f]{64}', build.get('featureGraphSha256', '')),
                'unsupported delivered build')
        require(isinstance(manifest.get('files'), list) and manifest['files'], 'missing delivered files')
        names = [entry.get('path') for entry in manifest['files']]
        require(len(set(names)) == len(names), 'duplicate delivered file')
        actual_names = {file.relative_to(directory).as_posix() for file in directory.rglob('*')
                        if file.is_file()}
        require(actual_names == set(names) | {'RSA-OAEP-DELIVERY.json'},
                'delivery contains missing or unreviewed bytes')
        for entry in manifest['files']:
            require(same_json(entry, file_record(directory, entry.get('path'))), 'delivered checksum mismatch')
        proofs = manifest.get('proofs')
        require(isinstance(proofs, dict) and set(proofs) == REQUIRED_PROOFS,
                'missing security, generated-binding, runtime or provenance evidence')
        indexed = {entry['path']: entry for entry in manifest['files']}
        for kind, name in proofs.items():
            require(name in indexed, f'unhashed {kind} proof')
            proof = read_json(directory / name)
            require(type(proof.get('schemaVersion')) is int and proof.get('schemaVersion') == 1
                    and proof.get('passed') is True
                    and proof.get('kind') == kind and proof.get('sourceCommit') == commit
                    and same_json(proof.get('build'), manifest['build'])
                    and same_json(proof.get('subjects'), manifest.get('subjects')) and bool(proof.get('subjects')),
                    f'failed or mismatched {kind} proof')
        require(isinstance(manifest.get('subjects'), list) and len(manifest['subjects']) >= 2
                and all(subject in manifest['files'] for subject in manifest['subjects']),
                'binary and generated-binding subjects are absent')
        records.append({'platform': platform, 'manifest': record})
    audit['securityQualified'] = True
    audit['cargo']['unacceptedVulnerabilityCount'] = 0
    audit['sourceRemediation']['disposition'] = 'SDK_OAEP_EXACT_BYTES_REMEDIATED'
    audit['sourceRemediation']['securityQualified'] = True
    audit['deliveredEvidence'] = records
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['source', 'identity-lock', 'audit', 'qualify'])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--policy', type=Path, default=ROOT / 'support/alias-sdk-release/audit-policy.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--active', type=Path)
    parser.add_argument('--platforms')
    parser.add_argument('--commit')
    args = parser.parse_args()
    if args.mode != 'identity-lock':
        args.output.unlink(missing_ok=True)
    policy = load_policy(args.policy)
    if args.mode == 'identity-lock':
        identity_lock(args.root, policy, args.output)
        return
    if args.mode == 'source':
        result = verify_source(args.root, policy)
    elif args.mode == 'audit':
        require(args.input and args.active, 'audit requires raw directory and active inventory')
        result = audit_report(args.root, policy, args.input, args.active)
    else:
        require(args.input and args.platforms, 'qualification requires artifacts and platforms')
        result = qualify_delivery(args.root, policy, args.input, args.platforms.split(','), args.commit)
    write_json(args.output, result)


if __name__ == '__main__':
    main()
