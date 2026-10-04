"""Exercise production validators. Synthetic delivery proofs never qualify real SDK bytes."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('rsa_remediation', Path(__file__).with_name('rsa-remediation.py'))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class RemediationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name) / 'source'
        cls.root.mkdir()
        archive = subprocess.check_output(['git', '-C', str(contract.ROOT), 'archive', 'HEAD',
                                          *contract.SOURCE_ROOTS, *contract.SOURCE_FILES])
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(cls.root, filter='data')
        subprocess.run(['git', '-C', str(cls.root), 'init', '-q'], check=True)
        subprocess.run(['git', '-C', str(cls.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(cls.root), '-c', 'user.name=Contract test',
                        '-c', 'user.email=contract-test@example.invalid', 'commit', '-qm', 'Synthetic test source'],
                       check=True)
        cls.commit = subprocess.check_output(['git', '-C', str(cls.root), 'rev-parse', 'HEAD']).decode().strip()
        cls.base_policy = contract.load_policy(contract.ROOT / 'support/alias-sdk-release/audit-policy.json')

    def setUp(self):
        self.policy = copy.deepcopy(self.base_policy)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.artifacts = Path(self.tmp.name) / 'artifacts'
        self.raw = self.artifacts / 'alias-sdk-assurance'
        self.raw.mkdir(parents=True)
        self.database = {'schemaVersion': 1, 'origin': 'https://github.com/RustSec/advisory-db.git',
                         'commit': 'a' * 40, 'tree': 'b' * 40, 'toolVersion': 'cargo-audit 0.22.2'}
        self.current = {
            'database': {'advisory-count': 1, 'last-commit': 'a' * 40, 'last-updated': '2026-10-05T00:00:00Z'},
            'lockfile': {'dependency-count': 1},
            'settings': {'ignore': [], 'severity': None, 'target_arch': [], 'target_os': [],
                         'informational_warnings': ['unmaintained', 'unsound', 'notice']},
            'vulnerabilities': {'found': False, 'count': 0, 'list': []}, 'warnings': {}}
        self.upstream = copy.deepcopy(self.current)
        self.finding = {
            'advisory': self.policy['oaepRemediation']['originalAdvisory'],
            'versions': {'patched': [], 'unaffected': []}, 'affected': None,
            'package': {'name': 'rsa', 'version': '0.10.0-rc.18', 'source': contract.REGISTRY,
                        'checksum': self.policy['oaepRemediation']['lineage']['rsa']['originalRegistrySha256']}}
        self.upstream['vulnerabilities'] = {'found': True, 'count': 1, 'list': [self.finding]}
        self.npm = {'auditReportVersion': 2, 'vulnerabilities': {}, 'metadata': {
            'vulnerabilities': {key: 0 for key in ['info', 'low', 'moderate', 'high', 'critical', 'total']},
            'dependencies': {'total': 1}}}
        self.status = {'cargo': 0, 'upstreamIdentity': 1, 'npm': 0}
        self.collection = {'schemaVersion': 1, 'collectedAt': datetime.now(timezone.utc).isoformat(),
                           'sourceCommit': self.commit,
                           'sourceCatalog': self.policy['oaepRemediation']['sourceCatalog']}
        (self.raw / 'cargo-active.txt').write_text('rsa@0.10.0-rc.18\ncrypto-bigint@0.7.5\n')
        contract.identity_lock(self.root, self.policy, self.raw / 'upstream-identity.lock')
        self.save_raw()

    def save_raw(self):
        for name, data in [('cargo-audit.json', self.current), ('upstream-identity-audit.json', self.upstream),
                           ('npm-audit.json', self.npm), ('AUDIT-TOOL-STATUS.json', self.status),
                           ('DATABASE-IDENTITY.json', self.database),
                           ('COLLECTION-IDENTITY.json', self.collection)]:
            contract.write_json(self.raw / name, data)

    def audit(self):
        return contract.audit_report(self.root, self.policy, self.raw, self.raw / 'cargo-active.txt')

    def prepare_delivery(self):
        contract.write_json(self.raw / 'AUDIT-REPORT.json', self.audit())
        self.delivery = self.artifacts / 'alias-sdk-typescript'
        self.delivery.mkdir()
        (self.delivery / 'sdk.wasm').write_bytes(b'synthetic binary, not SDK code')
        (self.delivery / 'sdk.d.ts').write_bytes(b'synthetic generated declarations')
        subjects = [contract.file_record(self.delivery, name) for name in ['sdk.wasm', 'sdk.d.ts']]
        build = {'rustc': '1.98.0', 'llvm': '22.1.8', 'targets': ['wasm32-unknown-unknown'],
                 'profile': {'opt-level': 'z', 'lto': True, 'codegen-units': 1},
                 'featureGraphSha256': 'c' * 64, 'node': '24.21.0', 'v8': '13.6.233.17-node.53'}
        proofs = {}
        for kind in contract.REQUIRED_PROOFS:
            name = kind + '.json'
            contract.write_json(self.delivery / name, {'schemaVersion': 1, 'passed': True, 'kind': kind,
                                                       'sourceCommit': self.commit, 'build': build,
                                                       'subjects': subjects})
            proofs[kind] = name
        self.manifest = {'schemaVersion': 1, 'sourceCommit': self.commit, 'platform': 'typescript',
                         'sourceCatalog': self.policy['oaepRemediation']['sourceCatalog'],
                         'build': build, 'subjects': subjects, 'proofs': proofs}
        self.approve_synthetic_delivery()

    def approve_synthetic_delivery(self):
        self.manifest['files'] = [contract.file_record(self.delivery, f.name)
                                  for f in sorted(self.delivery.iterdir()) if f.name != 'RSA-OAEP-DELIVERY.json']
        contract.write_json(self.delivery / 'RSA-OAEP-DELIVERY.json', self.manifest)
        self.policy['oaepRemediation']['approvedDeliveries'] = [{
            'manifest': contract.file_record(self.delivery, 'RSA-OAEP-DELIVERY.json'),
            'sourceCommit': self.commit, 'platform': 'typescript', 'build': self.manifest['build']}]

    def qualify(self):
        return contract.qualify_delivery(self.root, self.policy, self.artifacts, ['typescript'], self.commit)

    def test_source_and_original_identity_audit_remain_unqualified(self):
        report = self.audit()
        self.assertFalse(report['securityQualified'])
        self.assertEqual(report['cargo']['unacceptedVulnerabilityCount'], 1)
        self.assertEqual(report['cargo']['acceptedRisks'], [])
        self.assertFalse(report['cargo']['globalRustSecClosure'])
        self.assertEqual(report['cargo']['advisories'][0]['advisory']['id'], contract.ADVISORY)

    def test_synthetic_delivered_evidence_exercises_positive_contract(self):
        self.prepare_delivery()
        result = self.qualify()
        self.assertTrue(result['securityQualified'])
        self.assertEqual(result['cargo']['unacceptedVulnerabilityCount'], 0)
        self.assertFalse(result['cargo']['globalRustSecClosure'])

    def test_real_policy_does_not_approve_synthetic_bytes(self):
        self.prepare_delivery()
        self.policy['oaepRemediation']['approvedDeliveries'] = []
        with self.assertRaisesRegex(ValueError, 'no reviewed delivered'):
            self.qualify()

    def test_upstream_substitution_patch_provenance_and_new_route(self):
        cases = [('Cargo.toml', b'\n# substitute dependency\n'),
                 ('support/vendor/rsa/src/oaep.rs', b'\n// altered patch\n'),
                 ('support/vendor/crypto-bigint/SOURCE.json', b' '),
                 ('crates/bitwarden-crypto/src/new_decrypt_route.rs', b'// new private caller\n')]
        for name, delta in cases:
            with self.subTest(name=name):
                file = self.root / name
                before = file.read_bytes() if file.exists() else None
                if name == 'Cargo.toml':
                    changed = before.replace(b'rsa = { path = "support/vendor/rsa" }', b'')
                    self.assertNotEqual(changed, before)
                    file.write_bytes(changed)
                else:
                    file.write_bytes((before or b'') + delta)
                try:
                    with self.assertRaisesRegex(ValueError, 'catalog changed'):
                        contract.verify_source(self.root, self.policy)
                finally:
                    if before is None:
                        file.unlink()
                    else:
                        file.write_bytes(before)

    def test_changed_provenance_and_risk_exception(self):
        self.policy['oaepRemediation']['lineage']['rsa']['originalRegistrySha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'provenance changed'):
            contract.verify_source(self.root, self.policy)
        file = Path(self.tmp.name) / 'policy.json'
        self.policy['exceptions'] = [{'advisoryId': contract.ADVISORY}]
        contract.write_json(file, self.policy)
        with self.assertRaisesRegex(ValueError, 'risk exception'):
            contract.load_policy(file)

    def test_malformed_audit_and_operational_failures(self):
        for edit in [lambda: self.current.pop('vulnerabilities'),
                     lambda: self.current['vulnerabilities'].update(count=True),
                     lambda: self.current['vulnerabilities'].update(found=True),
                     lambda: self.current['settings'].update(ignore=[contract.ADVISORY]),
                     lambda: self.status.update(cargo=2),
                     lambda: self.database.update(toolVersion='cargo-audit 0.22.3'),
                     lambda: self.database.update(origin='https://example.invalid/db')]:
            saved = copy.deepcopy((self.current, self.status, self.database))
            edit(); self.save_raw()
            with self.assertRaises(ValueError):
                self.audit()
            self.current, self.status, self.database = saved

    def test_additional_advisory_changed_advisory_and_npm_findings(self):
        self.upstream['vulnerabilities']['list'].append(copy.deepcopy(self.finding))
        self.upstream['vulnerabilities']['list'][1]['advisory']['id'] = 'RUSTSEC-2026-9999'
        self.upstream['vulnerabilities']['count'] = 2
        self.save_raw()
        with self.assertRaisesRegex(ValueError, 'additional or missing'):
            self.audit()
        self.upstream['vulnerabilities']['list'].pop()
        self.upstream['vulnerabilities']['count'] = 1
        self.upstream['vulnerabilities']['list'][0]['versions']['patched'] = ['>=0.10.0']
        self.save_raw()
        with self.assertRaisesRegex(ValueError, 'changed upstream advisory'):
            self.audit()
        self.upstream['vulnerabilities']['list'][0]['versions']['patched'] = []
        self.npm['metadata']['vulnerabilities'].update(high=1, total=1)
        self.status['npm'] = 1
        self.save_raw()
        with self.assertRaises(ValueError):
            self.audit()

    def test_upstream_audit_lock_is_not_arbitrary_or_the_build_lock(self):
        (self.raw / 'upstream-identity.lock').write_text('version = 4\n')
        with self.assertRaisesRegex(ValueError, 'wrong upstream identity audit lock'):
            self.audit()
        with self.assertRaisesRegex(ValueError, 'never overwrite'):
            contract.identity_lock(self.root, self.policy, self.root / 'Cargo.lock')

    def test_duplicate_json_and_missing_provenance(self):
        (self.raw / 'cargo-audit.json').write_text('{"vulnerabilities":{},"vulnerabilities":{}}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.audit()
        self.save_raw()
        (self.raw / 'DATABASE-IDENTITY.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.audit()

    def test_wrong_source_bytes_target_profile_compiler_and_features(self):
        self.prepare_delivery()
        for field, value in [('sourceCommit', 'd' * 40), ('platform', 'swift')]:
            saved = copy.deepcopy(self.manifest)
            self.manifest[field] = value
            contract.write_json(self.delivery / 'RSA-OAEP-DELIVERY.json', self.manifest)
            with self.assertRaisesRegex(ValueError, 'artifact/source'):
                self.qualify()
            self.manifest = saved
        contract.write_json(self.delivery / 'RSA-OAEP-DELIVERY.json', self.manifest)
        for field, value in [('rustc', '1.99.0'), ('targets', ['unsupported-target']),
                             ('profile', {'opt-level': 1}), ('featureGraphSha256', 'd' * 64)]:
            modified = copy.deepcopy(self.manifest)
            modified['build'][field] = value
            contract.write_json(self.delivery / 'RSA-OAEP-DELIVERY.json', modified)
            with self.assertRaisesRegex(ValueError, 'no reviewed delivered'):
                self.qualify()
        contract.write_json(self.delivery / 'RSA-OAEP-DELIVERY.json', self.manifest)
        (self.delivery / 'sdk.wasm').write_bytes(b'wrong artifact')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.qualify()

    def test_failed_missing_runtime_bindings_and_property_evidence(self):
        self.prepare_delivery()
        for kind in sorted(contract.REQUIRED_PROOFS):
            name = self.manifest['proofs'][kind]
            file = self.delivery / name
            proof = contract.read_json(file)
            proof['passed'] = False
            contract.write_json(file, proof)
            self.approve_synthetic_delivery()  # Even an authenticated catalog cannot turn failure into pass.
            with self.assertRaisesRegex(ValueError, f'failed or mismatched {kind}'):
                self.qualify()
            proof['passed'] = True
            contract.write_json(file, proof)
        self.approve_synthetic_delivery()
        (self.delivery / self.manifest['proofs']['runtime']).unlink()
        with self.assertRaisesRegex(ValueError, 'missing or unreviewed'):
            self.qualify()

    def test_stale_audit_and_uninvented_null_database_metadata(self):
        self.current['database'].update({'last-commit': None, 'last-updated': None})
        self.upstream['database'] = copy.deepcopy(self.current['database'])
        self.save_raw()
        self.assertFalse(self.audit()['securityQualified'])
        self.prepare_delivery()
        report = contract.read_json(self.raw / 'AUDIT-REPORT.json')
        report['cargo']['unacceptedVulnerabilityCount'] = 0
        contract.write_json(self.raw / 'AUDIT-REPORT.json', report)
        with self.assertRaisesRegex(ValueError, 'changed or stale audit'):
            self.qualify()

    def test_old_audit_future_clock_and_wrong_source_collection(self):
        for delta in [timedelta(days=-2), timedelta(days=1)]:
            self.collection['collectedAt'] = (datetime.now(timezone.utc) + delta).isoformat()
            self.save_raw()
            with self.assertRaisesRegex(ValueError, 'stale or has an invalid clock'):
                self.audit()
        self.collection['collectedAt'] = datetime.now(timezone.utc).isoformat()
        self.collection['sourceCatalog'] = {}
        self.save_raw()
        with self.assertRaisesRegex(ValueError, 'mismatched source'):
            self.audit()

    def test_real_cli_cannot_leave_a_cached_passing_report(self):
        policy = Path(self.tmp.name) / 'policy.json'
        output = Path(self.tmp.name) / 'report.json'
        contract.write_json(policy, self.policy)
        command = [sys.executable, str(contract.ROOT / 'scripts/alias-sdk/rsa-remediation.py'),
                   'audit', '--root', str(self.root), '--policy', str(policy),
                   '--input', str(self.raw), '--active', str(self.raw / 'cargo-active.txt'),
                   '--output', str(output)]
        passed = subprocess.run(command, capture_output=True)
        self.assertEqual(passed.returncode, 0, passed.stderr.decode())
        self.assertFalse(contract.read_json(output)['securityQualified'])
        (self.raw / 'cargo-audit.json').write_text('invalid JSON')
        rejected = subprocess.run(command, capture_output=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(output.exists())

    def test_review_catalog_followup_does_not_require_rebuilding_qualified_bytes(self):
        self.prepare_delivery()
        file = self.root / 'contract-only-followup.txt'
        file.write_text('Synthetic verifier metadata, outside production source catalog\n')
        subprocess.run(['git', '-C', str(self.root), 'add', file.name], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Contract test',
                        '-c', 'user.email=contract-test@example.invalid', 'commit', '-qm', 'Synthetic verifier followup'],
                       check=True)
        result = self.qualify()
        self.assertEqual(result['sourceCommit'], self.commit)
        self.assertNotEqual(result['verifierCommit'], self.commit)


if __name__ == '__main__':
    unittest.main()
