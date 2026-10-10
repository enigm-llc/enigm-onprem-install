"""Installer command ordering only; Docker effects are explicit doubles."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

SCRIPT=Path(__file__).parents[1]/'bin/enigm-install'
loader=importlib.machinery.SourceFileLoader('bootstrap_order_policy',str(SCRIPT))
spec=importlib.util.spec_from_loader(loader.name,loader)
policy=importlib.util.module_from_spec(spec);loader.exec_module(policy)

class BootstrapOrder(unittest.TestCase):
    def exercise(self, fail_bootstrap=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            (root/'state.json').write_text(json.dumps({'project':'enigm-fixture'}))
            release=root/'release';release.mkdir()
            (release/'manifest.json').write_text(json.dumps({'providerBootstrapRequired':True}))
            commands=[]
            def run_command(argv,**kwargs):
                commands.append(argv)
                failure=fail_bootstrap and 'run' in argv
                return subprocess.CompletedProcess(argv,1 if failure else 0,b'',b'')
            def rootless_info(argv,capture=False):
                return '["name=rootless"]' if 'info' in argv else '"unix:///tmp/fixture.sock"'
            with patch.object(policy,'run',side_effect=rootless_info),patch.object(policy,'secret_references',return_value={}),patch.object(policy.subprocess,'run',side_effect=run_command):
                if fail_bootstrap:
                    with self.assertRaisesRegex(policy.Rejected,'PRIVATE_PROVIDER_BOOTSTRAP_FAILED'):
                        policy.compose(root,release,'up',root/'private-reference.json')
                else:policy.compose(root,release,'up',root/'private-reference.json')
            return commands

    def test_verified_provider_dependencies_then_same_image_bootstrap_before_channel(self):
        commands=self.exercise()
        self.assertEqual(len(commands),5)
        self.assertEqual(commands[0][-1:],['db'])
        self.assertEqual(commands[1][-1:],[ '--upstream-roles'])
        self.assertEqual(commands[2][-4:],['db','rest','storage','realtime'])
        self.assertEqual(commands[3][-2:],['channel','dist/modules/onprem/onprem-provider-bootstrap-v2.js'])
        self.assertIn('--no-deps',commands[3]);self.assertIn('--rm',commands[3])
        self.assertEqual(commands[4][-5:],['up','--detach','--wait','--wait-timeout','180'])

    def test_failed_bootstrap_never_starts_protected_channel(self):
        commands=self.exercise(True)
        self.assertEqual(len(commands),2)
        self.assertEqual(commands[-1][-1:],[ '--upstream-roles'])
