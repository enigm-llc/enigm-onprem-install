import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader('installer', str(Path(__file__).parents[1] / 'bin/enigm-install'))
spec = importlib.util.spec_from_loader(loader.name, loader)
installer = importlib.util.module_from_spec(spec)
loader.exec_module(installer)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.key = self.base / 'publisher.key'
        self.pub = self.base / 'publisher.pub'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(self.key)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.key.chmod(0o600)
        subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.pub)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.service_secret = self.base / 'fixture.env'
        self.service_secret.write_text('SYNTHETIC_SECRET=only-a-fixture\n')
        self.service_secret.chmod(0o600)
        self.secret = self.base / 'secret-references.json'
        self.secret.write_text(json.dumps({'contract': 'enigm-onprem-secret-references-v2',
                                          'serviceFiles': {'fixture': str(self.service_secret)}}))
        self.secret.chmod(0o600)
        self.root = self.base / 'runtime'
        self.bundle, self.pin = self.release('first')

    def tearDown(self):
        self.temp.cleanup()

    def release(self, name, previous=None, compose=None):
        bundle = self.base / name
        bundle.mkdir()
        compose = compose or {'services': {'fixture': {
            'image': 'example.invalid/fixture@sha256:' + 'a' * 64,
            'security_opt': ['no-new-privileges:true'], 'logging': {'driver': 'none'},
            'healthcheck': {'test': ['CMD', 'true']},
            'env_file': ['${ENIGM_SECRET_FIXTURE:?private file reference required}'],
            'ports': [{'host_ip': '127.0.0.1', 'published': '19800', 'target': 8000}],
            'volumes': [{'type': 'volume', 'source': 'data', 'target': '/data'}]}},
            'volumes': {'data': {}}}
        asset = bundle / 'compose.json'
        asset.write_text(json.dumps(compose))
        manifest = {'contract': 'enigm-onprem-release-v2', 'product': '2.1',
                    'authAuthority': 'ENIGM_CENTRAL_BACKEND_V2', 'offlineUnlock': False,
                    'assets': {'compose.json': {'sha256': installer.digest(asset), 'size': asset.stat().st_size}},
                    'upgradesFrom': [previous] if previous else []}
        path = bundle / 'manifest.json'
        path.write_text(json.dumps(manifest))
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(self.key), '-rawin', '-in', str(path),
                        '-out', str(bundle / 'manifest.sig')], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return bundle, installer.digest(path)

    def args(self, command='install', bundle=None, pin=None, prepare=False):
        return argparse.Namespace(command=command, root=str(self.root), bundle=str(bundle or self.bundle),
                                  manifest_sha256=pin or self.pin, trust_key=str(self.pub),
                                  trust_key_sha256=installer.digest(self.pub), secrets_file=str(self.secret),
                                  prepare_only=prepare, backup_receipt=None)

    def test_signature_and_asset_tamper_rejected(self):
        (self.bundle / 'compose.json').write_text('{}')
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(self.args())
        self.assertFalse((self.root / 'state.json').exists())

    def test_wrong_signer_or_pin_rejected(self):
        args = self.args()
        args.manifest_sha256 = 'f' * 64
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(args)
        (self.bundle / 'manifest.sig').write_bytes(os.urandom(64))
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(self.args())

    def test_preparation_is_repeatable_and_never_claims_runtime(self):
        with patch.object(installer, 'compose', side_effect=AssertionError('PREPARATION_MUST_NOT_START_DOCKER')):
            for _ in range(2):
                self.assertEqual(installer.lifecycle(self.args(prepare=True)),
                                 {'result': 'VERIFIED_PREPARED', 'runtimeVerified': False})
        state = json.loads((self.root / 'state.json').read_text())
        self.assertIsNone(state['active'])
        self.assertNotIn('only-a-fixture', (self.root / 'state.json').read_text())

    def test_install_recovery_update_keep_volume_project_and_secret_reference(self):
        # Runtime is injected here; this is filesystem lifecycle evidence, not Docker/Supabase proof.
        with patch.object(installer, 'compose') as runtime:
            installer.lifecycle(self.args())
            initial = json.loads((self.root / 'state.json').read_text())
            installer.lifecycle(self.args(command='recover'))
            next_bundle, next_pin = self.release('second', self.pin)
            args = self.args('update', next_bundle, next_pin)
            with self.assertRaises(installer.Rejected):
                installer.lifecycle(args)
            encrypted = self.base / 'backup.enc'
            encrypted.write_bytes(os.urandom(64))
            encrypted.chmod(0o600)
            receipt = self.base / 'backup-receipt.json'
            receipt.write_text(json.dumps({'release': self.pin, 'restoreDrillPassed': True,
                                          'encryptedBackupReference': str(encrypted), 'sha256': installer.digest(encrypted)}))
            receipt.chmod(0o600)
            args.backup_receipt = str(receipt)
            installer.lifecycle(args)
            state = json.loads((self.root / 'state.json').read_text())
            self.assertEqual(state['project'], initial['project'])
            self.assertEqual(state['secretReference'], str(self.secret))
            self.assertEqual(state['active'], next_pin)
            self.assertEqual(state['previous'], self.pin)
            self.assertEqual(self.root.joinpath('current').resolve(), self.root / 'releases' / next_pin)
            self.assertEqual(runtime.call_count, 3)

    def test_failed_runtime_never_commits_new_release(self):
        with patch.object(installer, 'compose', side_effect=installer.Rejected('COMPOSE_HEALTH_FAILED')):
            with self.assertRaises(installer.Rejected):
                installer.lifecycle(self.args())
        self.assertIsNone(json.loads((self.root / 'state.json').read_text())['active'])
        self.assertFalse((self.root / 'current').exists())

    def test_privilege_namespace_socket_inline_secret_and_public_port_rejected(self):
        base = json.loads((self.bundle / 'compose.json').read_text())
        mutations = [{'privileged': True}, {'network_mode': 'host'}, {'pid': 'host'},
                     {'image': 'postgres:latest'}, {'environment': {'PASSWORD': 'secret'}},
                     {'ports': [{'host_ip': '0.0.0.0', 'target': 8000, 'published': '8000'}]},
                     {'volumes': [{'type': 'bind', 'source': '/var/run/docker.sock', 'target': '/socket'}]}]
        for change in mutations:
            compose = json.loads(json.dumps(base))
            compose['services']['fixture'].update(change)
            with self.assertRaises(installer.Rejected):
                installer.validate_compose(compose)

    def test_secret_permissions_and_symlinks_rejected(self):
        self.secret.chmod(0o644)
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(self.args(prepare=True))
        self.secret.chmod(0o600)
        original = self.secret.with_suffix('.original')
        self.secret.rename(original)
        self.secret.symlink_to(original)
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(self.args(prepare=True))

    def test_per_service_secret_scope_and_reuse_rejected(self):
        self.secret.write_text(json.dumps({'contract': 'enigm-onprem-secret-references-v2',
                                          'serviceFiles': {'foreign': str(self.service_secret)}}))
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(self.args(prepare=True))
        compose = json.loads((self.bundle / 'compose.json').read_text())
        compose['services']['other'] = dict(compose['services']['fixture'])
        compose['services']['other']['env_file'] = ['${ENIGM_SECRET_OTHER:?private file reference required}']
        bundle, pin = self.release('two-services', compose=compose)
        self.secret.write_text(json.dumps({'contract': 'enigm-onprem-secret-references-v2',
                                          'serviceFiles': {'fixture': str(self.service_secret), 'other': str(self.service_secret)}}))
        with self.assertRaises(installer.Rejected):
            installer.lifecycle(self.args(bundle=bundle, pin=pin, prepare=True))

    def test_remote_docker_endpoint_is_rejected_before_secret_transfer(self):
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://remote.invalid:2375'}), \
                patch.object(installer, 'run', side_effect=AssertionError('NO_REMOTE_DOCKER_IO')):
            with self.assertRaises(installer.Rejected):
                installer.compose(self.root, self.bundle, 'up', self.secret)

    def test_named_volume_host_bind_escape_is_rejected(self):
        compose = json.loads((self.bundle / 'compose.json').read_text())
        compose['volumes']['data'] = {'driver': 'local', 'driver_opts': {'type': 'none', 'o': 'bind', 'device': '/'}}
        with self.assertRaises(installer.Rejected):
            installer.validate_compose(compose)


if __name__ == '__main__':
    unittest.main()
