"""Ownership changes are confined to the stopped installation's Storage volume."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from test_lifecycle import installer

PROJECT = 'enigm-' + 'a' * 24
VOLUME = PROJECT + '_storage_data'
IMAGE = 'sha256:' + 'b' * 64


class StorageOwnership(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temp.name)
        self.state = {'project': PROJECT, 'active': 'c' * 64}
        installer.atomic_json(self.root/'state.json', self.state)
        self.before = (self.root/'state.json').read_bytes()
        self.release = self.root/('d'*64)
        self.effective = self.root/'effective.json'
        self.model = {'services': {'storage': {'image': IMAGE, 'volumes': [{'type': 'volume', 'source': 'storage_data', 'target': '/var/lib/storage'}]}},
                      'volumes': {'storage_data': {'name': VOLUME}}}
        self.write_model()
        self.details = {'Name': VOLUME, 'Driver': 'local', 'Options': None,
                        'Labels': {'com.docker.compose.project': PROJECT, 'com.docker.compose.volume': 'storage_data'}}
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def write_model(self):
        installer.atomic_json(self.effective, self.model)

    def docker(self, args, env):
        self.calls.append(args)
        if args[:2] == ['image', 'inspect']:
            return b'"1000:1000"'
        if args[:2] == ['volume', 'ls']:
            return (VOLUME+'\n').encode()
        if args[:2] == ['volume', 'inspect']:
            return json.dumps([self.details]).encode()
        if args[0] == 'create':
            return b'a'*64
        if args[0] == 'ps':
            return b''
        if args[0] == 'start':
            return b'{"contract":"enigm-storage-volume-ownership-v2","uid":1000,"gid":1000,"contentVerified":true}'
        self.fail('Unexpected Docker operation')

    def prepare(self, backup=True):
        installer.prepare_storage_ownership(self.root, self.release, {'storageImage': IMAGE}, {},
                                            ['docker', 'compose'], self.effective, installer.digest(self.effective), backup)

    def test_exact_volume_backup_and_stopped_provider_precede_migration(self):
        with patch.object(installer, 'migration_docker_call', side_effect=self.docker), patch.object(installer, 'checked_compose_call', return_value=subprocess.CompletedProcess([], 0)) as compose:
            self.prepare()
        self.assertEqual(compose.call_args_list[0].args[0][-5:], ['stop', '--timeout', '30', 'channel', 'storage'])
        self.assertEqual(compose.call_args_list[1].args[0][-3:], ['create', '--no-deps', 'storage'])
        operation = next(call for call in self.calls if call[0] == 'create')
        self.assertEqual(operation[0], 'create')
        self.assertIn('type=volume,source='+VOLUME+',target=/var/lib/storage,volume-nocopy', operation)
        self.assertIn('--read-only', operation)
        self.assertIn('--cap-drop=ALL', operation)
        self.assertIn('--cap-add=CHOWN', operation)
        self.assertIn('--cap-add=DAC_READ_SEARCH', operation)
        self.assertNotIn('--env', operation)
        self.assertEqual(operation[operation.index('--network')+1], 'none')
        self.assertEqual((self.root/'state.json').read_bytes(), self.before)

    def test_missing_backup_never_stops_or_migrates_an_existing_installation(self):
        with patch.object(installer, 'migration_docker_call', side_effect=self.docker), patch.object(installer, 'checked_compose_call') as compose:
            with self.assertRaisesRegex(installer.Rejected, 'STORAGE_MIGRATION_BACKUP_REQUIRED'):
                self.prepare(False)
            compose.assert_not_called()
        self.assertEqual(len(self.calls), 1)

    def test_foreign_volume_is_rejected_before_create_or_mount(self):
        self.details['Labels']['com.docker.compose.project'] = 'another-project'
        with patch.object(installer, 'migration_docker_call', side_effect=self.docker), patch.object(installer, 'checked_compose_call', return_value=subprocess.CompletedProcess([], 0)) as compose:
            with self.assertRaisesRegex(installer.Rejected, 'STORAGE_VOLUME_OWNERSHIP_INVALID'):
                self.prepare()
            self.assertEqual(compose.call_count, 1)
        self.assertFalse(any(call[0] == 'create' for call in self.calls))

    def test_bind_external_extra_mount_and_driver_options_are_rejected(self):
        models = []
        for field, value in [('type', 'bind'), ('source', 'db_data'), ('target', '/elsewhere')]:
            model = copy.deepcopy(self.model); model['services']['storage']['volumes'][0][field] = value; models.append(model)
        model = copy.deepcopy(self.model); model['services']['storage']['volumes'].append({'type':'volume','source':'db_data','target':'/db'}); models.append(model)
        for field, value in [('external', True), ('driver', 'remote'), ('driver_opts', {'device': '/host'})]:
            model = copy.deepcopy(self.model); model['volumes']['storage_data'][field] = value; models.append(model)
        for model in models:
            with self.subTest(model=model), self.assertRaises(installer.Rejected):
                installer.storage_volume_reference(model, PROJECT)

    def test_root_image_and_incomplete_proof_are_rejected_without_state_commit(self):
        for response in [b'""', b'"0:0"']:
            with patch.object(installer, 'migration_docker_call', return_value=response), patch.object(installer, 'checked_compose_call') as compose:
                with self.assertRaisesRegex(installer.Rejected, 'STORAGE_NONROOT_IMAGE_REQUIRED'):
                    self.prepare()
                compose.assert_not_called()
        original = self.docker
        def incomplete(args, env):
            return b'{}' if args[0] == 'start' else original(args, env)
        with patch.object(installer, 'migration_docker_call', side_effect=incomplete), patch.object(installer, 'checked_compose_call', return_value=subprocess.CompletedProcess([], 0)):
            with self.assertRaisesRegex(installer.Rejected, 'STORAGE_OWNERSHIP_PROOF_INVALID'):
                self.prepare()
        self.assertEqual((self.root/'state.json').read_bytes(), self.before)

    def test_timeout_removes_only_exact_owned_migrator(self):
        calls = []
        identity = {}
        def execute(args, env):
            calls.append(args)
            if args[0] == 'create':
                identity['name'] = args[args.index('--name')+1]
                identity['nonce'] = args[args.index('--label')+1].split('=', 1)[1]
                return b'a'*64
            if args[0] == 'start':
                raise subprocess.TimeoutExpired('docker', 300)
            if args[0] == 'ps':
                return b'' if '-q' in args else b'a'*64
            if args[0] == 'inspect':
                return json.dumps([{'Id':'a'*64,'Name':'/'+identity['name'],'Image':IMAGE,
                    'Config':{'Labels':{'enigm.storage-migration':identity['nonce']}}}]).encode()
            if args[0] == 'rm':
                return b''
            self.fail('Unexpected operation')
        with patch.object(installer, 'migration_docker_call', side_effect=execute):
            with self.assertRaises(subprocess.TimeoutExpired):
                installer.run_storage_migrator(VOLUME, IMAGE, {})
        self.assertEqual(calls[-1], ['rm', '--force', 'a'*64])

    def test_cleanup_rejects_foreign_container(self):
        with patch.object(installer, 'migration_docker_call', side_effect=[b'a'*64,
                json.dumps([{'Id':'a'*64,'Name':'/foreign','Image':IMAGE}]).encode()]) as call:
            with self.assertRaisesRegex(installer.Rejected, 'STORAGE_MIGRATOR_IDENTITY_INVALID'):
                installer.cleanup_storage_migrator('expected', 'nonce', IMAGE, {})
            self.assertEqual(call.call_count, 2)

    def test_active_volume_consumer_blocks_new_migration_without_killing_it(self):
        with patch.object(installer, 'migration_docker_call', return_value=b'a'*64) as call:
            with self.assertRaisesRegex(installer.Rejected, 'STORAGE_VOLUME_IN_USE'):
                installer.run_storage_migrator(VOLUME, IMAGE, {})
            call.assert_called_once_with(['ps','-q','--filter','volume='+VOLUME], {})
