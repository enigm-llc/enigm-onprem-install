"""Compose policy regressions; config-only checks never start a container."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).parents[1] / 'bin/enigm-install'
loader = importlib.machinery.SourceFileLoader('enigm_compose_isolation', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
policy = importlib.util.module_from_spec(spec)
loader.exec_module(policy)


def model():
    return {
        'services': {'db': {
            'image': 'example.invalid/database@sha256:' + 'a' * 64,
            'security_opt': ['no-new-privileges:true'],
            'logging': {'driver': 'none'},
            'healthcheck': {'test': ['CMD', 'true']},
            'volumes': [{'type': 'volume', 'source': 'data', 'target': '/data'}],
        }},
        'volumes': {'data': {}},
        'networks': {'default': {}},
    }


def secret_reference(service='db'):
    return '${ENIGM_SECRET_' + service.upper() + ':?private file reference required}'


class SignedComposeIsolation(unittest.TestCase):
    def test_project_scoped_empty_resources_are_accepted(self):
        policy.validate_compose(model())

    def test_dollar_is_rejected_in_every_non_reference_position(self):
        mutations = [
            ('command', ['echo', '${MODE:-safe}']),
            ('command', ['echo', '$MODE']),
            ('command', ['echo', '$$MODE']),
            ('healthcheck', {'test': ['CMD-SHELL', 'echo ${HEALTH}']}),
            ('network_mode', '${NETWORK_MODE:-bridge}'),
            ('pid', '${PID_MODE:-private}'),
            ('ipc', '${IPC_MODE:-private}'),
            ('ports', [{'target': 5432, 'published': '${PORT:-5432}', 'host_ip': '127.0.0.1'}]),
            ('volumes', [{'type': 'volume', 'source': '${DATA}', 'target': '/data'}]),
            ('labels', {'example.test': '$VALUE'}),
            ('labels', {'$KEY': 'value'}),
            ('x-settings', {'nested': [{'value': '$VALUE'}]}),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                compose = model()
                compose['services']['db'][field] = value
                with self.assertRaises(policy.Rejected):
                    policy.validate_compose(compose)
        for field, value in [('x-value', '$ROOT'), ('x-$key', 'value')]:
            with self.subTest(top_level=field):
                compose = model()
                compose[field] = value
                with self.assertRaises(policy.Rejected):
                    policy.validate_compose(compose)

    def test_only_exact_service_env_reference_is_accepted(self):
        compose = model()
        compose['services']['db']['env_file'] = [secret_reference()]
        policy.validate_compose(compose)
        invalid = [
            [secret_reference('other')],
            [secret_reference() + '/suffix'],
            ['${ENIGM_SECRET_DB:-fallback}'],
            [{'path': secret_reference()}],
            [secret_reference(), secret_reference()],
        ]
        for value in invalid:
            with self.subTest(env_file=value):
                compose['services']['db']['env_file'] = value
                with self.assertRaises(policy.Rejected):
                    policy.validate_compose(compose)
        compose['services']['db']['env_file'] = [secret_reference()]
        compose['services']['db']['command'] = [secret_reference()]
        with self.assertRaises(policy.Rejected):
            policy.validate_compose(compose)

    def test_signed_global_resource_names_and_external_resources_are_rejected(self):
        for section in ('volumes', 'networks'):
            for definition in ({'name': 'decoy_external'}, {'name': 'own_project_data'},
                               {'external': True}, {'external': {'name': 'decoy_external'}}):
                with self.subTest(section=section, definition=definition):
                    compose = model()
                    key = 'data' if section == 'volumes' else 'default'
                    compose[section][key] = definition
                    with self.assertRaises(policy.Rejected):
                        policy.validate_compose(compose)

    def test_undeclared_or_anonymous_volume_cannot_adopt_daemon_state(self):
        for mount in ({'type': 'volume', 'source': 'decoy_external', 'target': '/data'},
                      {'type': 'volume', 'target': '/data'}):
            with self.subTest(mount=mount):
                compose = model()
                compose['services']['db']['volumes'] = [mount]
                with self.assertRaises(policy.Rejected):
                    policy.validate_compose(compose)

    def test_external_namespace_joins_are_rejected(self):
        for field in ('network_mode', 'pid', 'ipc'):
            for value in ('host', 'container:decoy_external', 'service:db', 'unexpected'):
                with self.subTest(field=field, mode=value):
                    compose = model()
                    compose['services']['db'][field] = value
                    with self.assertRaises(policy.Rejected):
                        policy.validate_compose(compose)


class EffectiveComposeIsolation(unittest.TestCase):
    def effective(self, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa'):
        compose = model()
        compose['name'] = project
        compose['volumes']['data'] = {'name': project + '_data'}
        compose['networks']['default'] = {'name': project + '_default'}
        return compose

    def test_effective_names_must_match_resource_and_current_project(self):
        policy.validate_compose(self.effective(), project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={})
        for section, key in [('volumes', 'data'), ('networks', 'default')]:
            for foreign in ('enigm-bbbbbbbbbbbbbbbbbbbbbbbb_' + key, 'decoy_external', 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa_other', 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa_' + key + '_suffix'):
                with self.subTest(section=section, name=foreign):
                    compose = self.effective()
                    compose[section][key]['name'] = foreign
                    with self.assertRaises(policy.Rejected):
                        policy.validate_compose(compose, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={})

    def test_effective_env_file_is_only_the_service_raw_snapshot(self):
        snapshot = Path('/private-fixture/db.env')
        compose = self.effective()
        compose['services']['db']['env_file'] = [{'path': str(snapshot), 'required': True, 'format': 'raw'}]
        policy.validate_compose(compose, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={'db': snapshot})
        for item in ({'path': '/original/db.env', 'required': True, 'format': 'raw'},
                     {'path': str(snapshot), 'required': True},
                     {'path': str(snapshot), 'required': False, 'format': 'raw'},
                     str(snapshot)):
            with self.subTest(env_file=item):
                compose['services']['db']['env_file'] = [item]
                with self.assertRaises(policy.Rejected):
                    policy.validate_compose(compose, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={'db': snapshot})


class ComposeConfigMaterialization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which('docker')
        if not cls.docker:
            raise unittest.SkipTest('Docker Compose is unavailable; policy unit checks still run')
        checked = subprocess.run([cls.docker, 'compose', 'version'], capture_output=True, check=False)
        if checked.returncode:
            raise unittest.SkipTest('Docker Compose is unavailable; policy unit checks still run')
        cls.version = checked.stdout.decode().strip()

    def config(self, compose, project, directory, extra_env=None):
        directory = Path(directory)
        source = directory / 'compose.json'
        source.write_text(json.dumps(compose))
        empty = directory / 'empty.env'
        empty.write_text('')
        environment = {'PATH': os.defpath, 'HOME': str(directory), 'COMPOSE_DISABLE_ENV_FILE': '1'}
        environment.update(extra_env or {})
        result = subprocess.run([
            self.docker, 'compose', '--project-name', project,
            '--project-directory', str(directory), '--env-file', str(empty),
            '--file', str(source), 'config', '--format', 'json', '--no-env-resolution',
        ], env=environment, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, 'Compose config failed without starting services')
        return json.loads(result.stdout)

    def test_two_projects_and_decoy_global_resources_remain_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.config(model(), 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa', directory)
            second = self.config(model(), 'enigm-bbbbbbbbbbbbbbbbbbbbbbbb', directory)
            for section, key in [('volumes', 'data'), ('networks', 'default')]:
                self.assertEqual(first[section][key]['name'], 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa_' + key)
                self.assertEqual(second[section][key]['name'], 'enigm-bbbbbbbbbbbbbbbbbbbbbbbb_' + key)
                self.assertNotEqual(first[section][key]['name'], second[section][key]['name'])
                decoy = model()
                decoy[section][key] = {'name': 'decoy_external'}
                normalized = self.config(decoy, 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa', directory)
                self.assertEqual(normalized[section][key]['name'], 'decoy_external')
                with self.assertRaises(policy.Rejected):
                    policy.validate_compose(normalized, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={})
            policy.validate_compose(first, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={})
            policy.validate_compose(second, project='enigm-bbbbbbbbbbbbbbbbbbbbbbbb', snapshots={})

    def test_hostile_environment_cannot_authorize_interpolated_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            compose = model()
            compose['services']['db']['network_mode'] = '${NETWORK_MODE:-bridge}'
            normalized = self.config(compose, 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa', directory, {'NETWORK_MODE': 'host'})
            self.assertEqual(normalized['services']['db']['network_mode'], 'host')
            with self.assertRaises(policy.Rejected):
                policy.validate_compose(compose)
            with self.assertRaises(policy.Rejected):
                policy.validate_compose(normalized, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={})

    def test_config_preserves_external_namespace_joins_but_policy_rejects_them(self):
        with tempfile.TemporaryDirectory() as directory:
            for field in ('network_mode', 'pid', 'ipc'):
                with self.subTest(field=field):
                    compose = model()
                    compose['services']['db'][field] = 'container:decoy_external'
                    normalized = self.config(compose, 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa', directory)
                    self.assertEqual(normalized['services']['db'][field], 'container:decoy_external')
                    with self.assertRaises(policy.Rejected):
                        policy.validate_compose(normalized, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={})

    def test_raw_snapshot_values_never_enter_normalized_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / 'db.env'
            snapshot.write_text('FIXTURE_TOKEN=$POISON\n')
            compose = model()
            compose['services']['db']['env_file'] = [{'path': str(snapshot), 'required': True, 'format': 'raw'}]
            (Path(directory) / '.env').write_text('COMPOSE_PROJECT_NAME=decoy_external\nPOISON=untrusted\n')
            normalized = self.config(compose, 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa', directory)
            self.assertEqual(normalized['name'], 'enigm-aaaaaaaaaaaaaaaaaaaaaaaa')
            self.assertNotIn('environment', normalized['services']['db'])
            self.assertEqual(normalized['services']['db']['env_file'], [{'path': str(snapshot), 'format': 'raw'}])
            self.assertNotIn('FIXTURE_TOKEN', json.dumps(normalized))
            policy.validate_compose(normalized, project='enigm-aaaaaaaaaaaaaaaaaaaaaaaa', snapshots={'db': snapshot})


if __name__ == '__main__':
    unittest.main()
