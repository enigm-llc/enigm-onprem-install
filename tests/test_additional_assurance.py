"""Synthetic local assurance: real Compose config, intercepted runtime only.

No container startup, image download, cloud access, or deployment claims.
"""
import copy
import io
import sys
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader('enigm_additional_assurance', str(Path(__file__).parents[1] / 'bin/enigm-install'))
spec = importlib.util.spec_from_loader(loader.name, loader)
policy = importlib.util.module_from_spec(spec)
loader.exec_module(policy)
PROJECT = 'enigm-' + 'a' * 24


def model():
    return {'services': {'fixture': {'image': 'example.invalid/fixture@sha256:' + 'a' * 64,
        'security_opt': ['no-new-privileges:true'], 'logging': {'driver': 'none'},
        'healthcheck': {'test': ['CMD', 'true']},
        'env_file': ['${ENIGM_SECRET_FIXTURE:?private file reference required}'],
        'volumes': [{'type': 'volume', 'source': 'data', 'target': '/data'}]}},
        'volumes': {'data': {}}, 'networks': {'default': {}}}


class OwnerFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='enigm-assurance-', dir=Path.home())
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.base.chmod(0o700)
        home = patch.dict(os.environ, {'HOME': str(self.base)})
        home.start()
        self.addCleanup(home.stop)
        for ancestor in [self.base, *self.base.parents]:
            info = ancestor.stat()
            self.assertIn(info.st_uid, (0, os.getuid()))
            self.assertEqual(info.st_mode & 0o022, 0)
        self.root, self.release = self.base / 'runtime', self.base / 'release'
        self.root.mkdir(mode=0o700)
        self.release.mkdir(mode=0o700)
        self.private(self.release / 'compose.json', json.dumps(model()).encode())
        self.private(self.release / 'manifest.json', json.dumps({
            'contract': 'enigm-onprem-release-v2', 'product': '2.1',
            'authAuthority': 'ENIGM_CENTRAL_BACKEND_V2', 'offlineUnlock': False,
            'assets': {'compose.json': {'sha256': policy.digest(self.release / 'compose.json'),
                'size': (self.release / 'compose.json').stat().st_size}}}).encode())
        self.secret = self.private(self.base / 'fixture.env', b'FIXTURE_TOKEN=$POISON\nLITERAL=${POISON:-unchanged}\n')
        self.reference = self.private(self.base / 'references.json', json.dumps({
            'contract': 'enigm-onprem-secret-references-v2',
            'serviceFiles': {'fixture': str(self.secret)}}).encode())
        self.private(self.root / 'state.json', json.dumps({'project': PROJECT}).encode())

    def private(self, path, data):
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def openssl(self, *arguments):
        return subprocess.run(['openssl', *map(str, arguments)], check=True, capture_output=True)


class PublisherAlgorithm(OwnerFixture):
    def test_valid_64_byte_ec_signature_cannot_substitute_for_ed25519(self):
        key, public = self.base / 'ec.key', self.base / 'ec.pub'
        self.openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp224r1', '-out', key)
        key.chmod(0o600)
        self.openssl('pkey', '-in', key, '-pubout', '-out', public)
        public.chmod(0o600)
        signature = self.release / 'manifest.sig'
        # DER ECDSA length varies; 64 bytes is a valid secp224r1 representation.
        for _ in range(512):
            self.openssl('pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', self.release / 'manifest.json', '-out', signature)
            signature.chmod(0o600)
            if signature.stat().st_size == 64:
                break
        self.assertEqual(signature.stat().st_size, 64)
        self.openssl('pkeyutl', '-verify', '-pubin', '-inkey', public, '-rawin', '-in', self.release / 'manifest.json', '-sigfile', signature)
        with self.assertRaisesRegex(policy.Rejected, '^PUBLISHER_KEY_ALGORITHM_INVALID$'):
            policy.verify(self.release, policy.digest(self.release / 'manifest.json'), public, policy.digest(public))
        self.assertFalse(list(self.base.glob('.enigm-signature-*')))


class CurrentCommit(OwnerFixture):
    def test_legacy_residue_does_not_block_commit_and_directory_is_synced(self):
        pin = 'b' * 64
        stale = self.root / 'current.new'
        stale.symlink_to('releases/' + 'c' * 64)
        synced = []
        fsync = os.fsync
        def record_sync(descriptor):
            synced.append(stat.S_ISDIR(os.fstat(descriptor).st_mode))
            return fsync(descriptor)
        with patch.object(policy.os, 'fsync', side_effect=record_sync):
            policy.switch(self.root, pin)
        self.assertEqual(os.readlink(self.root / 'current'), 'releases/' + pin)
        self.assertTrue(stale.is_symlink())
        self.assertIn(True, synced, 'Commit durability requires an actual directory fsync')
        self.assertFalse(list(self.root.glob('.current-*')))

    def test_failed_replace_cleanup_and_subsequent_switch_preserve_database(self):
        old, committed = 'c' * 64, 'b' * 64
        policy.switch(self.root, old)
        database = self.private(self.root / 'database.fixture', b'existing-customer-rows')
        before = database.read_bytes(), database.stat().st_ino
        replace = os.replace
        def fail_current(source, target):
            if Path(target) == self.root / 'current':
                raise OSError('synthetic interrupted commit')
            return replace(source, target)
        with patch.object(policy.os, 'replace', side_effect=fail_current):
            with self.assertRaises(OSError):
                policy.switch(self.root, committed)
        self.assertEqual(os.readlink(self.root / 'current'), 'releases/' + old)
        self.assertFalse(list(self.root.glob('.current-*')))
        policy.switch(self.root, committed)
        self.assertEqual(os.readlink(self.root / 'current'), 'releases/' + committed)
        self.assertEqual((database.read_bytes(), database.stat().st_ino), before)
        self.assertFalse(list(self.root.glob('.current-*')))


class FullComposePipeline(OwnerFixture):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which('docker')
        if not cls.docker or subprocess.run([cls.docker, 'compose', 'version'], capture_output=True).returncode:
            raise unittest.SkipTest('Docker Compose config-only parser unavailable')

    def execute(self, runtime_code=0, transform=None, after_config=None, after_runtime=None, bootstrap=False):
        if bootstrap:
            manifest = json.loads((self.release / 'manifest.json').read_text())
            manifest['providerBootstrapRequired'] = True
            self.private(self.release / 'manifest.json', json.dumps(manifest).encode())
        run = subprocess.run
        self.config_calls, self.runtime_calls, self.snapshots = [], [], []
        def dispatch(command, **kwargs):
            if command[:2] == ['docker', 'info']:
                return subprocess.CompletedProcess(command, 0, b'["name=rootless"]', b'')
            self.assertEqual(command[:2], ['docker', 'compose'])
            effective = Path(command[command.index('--file') + 1])
            if 'config' in command:
                self.config_calls.append(command)
                result = run([self.docker, *command[1:]], **kwargs)
                self.assertEqual(result.returncode, 0, 'Config-only Compose parsing failed')
                if transform:
                    result.stdout = json.dumps(transform(json.loads(result.stdout), len(self.config_calls))).encode()
                if after_config and len(self.config_calls) == 2:
                    after_config(effective)
                return result
            self.assertEqual(effective.name, 'effective-compose.json')
            self.assertEqual(effective.stat().st_mode & 0o777, 0o600)
            normalized = json.loads(effective.read_bytes())
            snapshot = Path(normalized['services']['fixture']['env_file'][0]['path'])
            self.snapshots.append(snapshot)
            self.assertEqual(snapshot.read_bytes(), self.secret.read_bytes())
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('environment', normalized['services']['fixture'])
            self.assertNotIn('POISON', kwargs['env'])
            self.assertNotIn('COMPOSE_FILE', kwargs['env'])
            self.runtime_calls.append((command, effective, copy.deepcopy(normalized)))
            if after_runtime:
                after_runtime(effective, len(self.runtime_calls))
            return subprocess.CompletedProcess(command, runtime_code, b'', b'unhealthy' if runtime_code else b'')
        with patch.dict(os.environ, {'POISON': 'changed', 'COMPOSE_FILE': '/foreign.yml', 'COMPOSE_PROJECT_NAME': 'foreign'}), patch.object(policy.subprocess, 'run', side_effect=dispatch):
            policy.compose(self.root, self.release, 'up', self.reference, endpoint='unix:///synthetic-docker.sock')

    def assert_cleaned(self):
        self.assertFalse(list(self.root.glob('.runtime-*')))
        self.assertTrue(all(not path.exists() for path in self.snapshots))

    def test_all_bootstrap_runtime_steps_use_one_validated_effective_file(self):
        self.execute(bootstrap=True)
        self.assertEqual(len(self.config_calls), 2)
        self.assertEqual(len(self.runtime_calls), 5)
        self.assertEqual(len({str(call[1]) for call in self.runtime_calls}), 1)
        self.assertTrue(all(call[2] == self.runtime_calls[0][2] for call in self.runtime_calls))
        self.assert_cleaned()

    def test_runtime_failure_removes_secret_and_configuration_snapshots(self):
        with self.assertRaisesRegex(policy.Rejected, 'CONTAINER_UNHEALTHY'):
            self.execute(runtime_code=1)
        self.assertEqual(len(self.runtime_calls), 1)
        self.assert_cleaned()

    def test_malicious_normalized_results_rejected_before_runtime(self):
        mutations = [lambda value: value['services']['fixture'].update(privileged=True),
            lambda value: value['volumes']['data'].update(name='foreign_data'),
            lambda value: value['services']['fixture'].update(environment={'TOKEN': 'inline'}),
            lambda value: value['services']['fixture'].update(command=['echo', '$POISON']),
            lambda value: value['services']['fixture']['env_file'][0].update(format='dotenv')]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                def transform(value, ordinal):
                    if ordinal == 1:
                        mutate(value)
                    return value
                with self.assertRaises(policy.Rejected):
                    self.execute(transform=transform)
                self.assertFalse(self.runtime_calls)
                self.assert_cleaned()

    def test_safe_but_nonidempotent_second_parse_rejected_before_runtime(self):
        def transform(value, ordinal):
            if ordinal == 2:
                value['services']['fixture']['command'] = ['true']
            return value
        with self.assertRaisesRegex(policy.Rejected, 'COMPOSE_REINTERPRETATION_REJECTED'):
            self.execute(transform=transform)
        self.assertFalse(self.runtime_calls)
        self.assert_cleaned()

    def test_effective_file_mutation_after_validation_rejected_before_runtime(self):
        def replace_file(path):
            value = json.loads(path.read_bytes())
            value['services']['fixture']['privileged'] = True
            self.private(path, json.dumps(value).encode())
        with self.assertRaisesRegex(policy.Rejected, 'COMPOSE_CONFIGURATION_CHANGED'):
            self.execute(after_config=replace_file)
        self.assertFalse(self.runtime_calls)
        self.assert_cleaned()

    def test_mutation_between_bootstrap_steps_stops_subsequent_execution(self):
        def mutate(path, ordinal):
            if ordinal == 1:
                value = json.loads(path.read_bytes())
                value['services']['fixture']['command'] = ['echo', 'changed']
                self.private(path, json.dumps(value).encode())
        with self.assertRaisesRegex(policy.Rejected, 'COMPOSE_CONFIGURATION_CHANGED'):
            self.execute(after_runtime=mutate, bootstrap=True)
        self.assertEqual(len(self.runtime_calls), 1)
        self.assert_cleaned()

    def test_signed_dollar_expression_rejected_before_any_compose_parse(self):
        value = model()
        value['services']['fixture']['command'] = ['echo', '${POISON:-safe}']
        self.private(self.release / 'compose.json', json.dumps(value).encode())
        with self.assertRaises(policy.Rejected):
            self.execute()
        self.assertFalse(self.config_calls)
        self.assertFalse(self.runtime_calls)
        self.assert_cleaned()


if __name__ == '__main__':
    unittest.main()


class SubprocessPrivacy(unittest.TestCase):
    def test_timeout_returns_redacted_json_without_command_or_private_path(self):
        arguments = ['enigm-install', 'install', '--root', '/private/root', '--bundle', '/private/bundle',
                     '--manifest-sha256', 'a' * 64, '--trust-key', '/private/key',
                     '--trust-key-sha256', 'b' * 64, '--secrets-file', '/private/references']
        output = io.StringIO()
        with patch.object(sys, 'argv', arguments), patch.object(sys, 'stderr', output), \
                patch.object(policy, 'lifecycle', side_effect=subprocess.TimeoutExpired(['private-command', '/private/token'], 600)):
            self.assertEqual(policy.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {'result': 'REJECTED', 'runtimeVerified': False})
        self.assertNotIn('/private', output.getvalue())

    def test_loader_wrapper_can_use_larger_bound_than_individual_phases(self):
        with patch.object(policy.subprocess, 'run', return_value=subprocess.CompletedProcess(['fixture'], 0, stdout=b'{}')) as invocation:
            self.assertEqual(policy.run(['fixture'], True, timeout=600), b'{}')
        self.assertEqual(invocation.call_args.kwargs['timeout'], 600)

    def test_invalid_local_endpoint_is_rejected_before_execution(self):
        for endpoint in ('unix:////remote/socket', 'unix:///run/../socket', 'unix:///run/socket?query',
                         'unix:///run/socket#fragment', 'unix:///run/$SOCKET', 'unix:///run/space socket'):
            with self.subTest(endpoint=endpoint), self.assertRaises(policy.Rejected):
                policy.command_environment(Path.home(), endpoint)
