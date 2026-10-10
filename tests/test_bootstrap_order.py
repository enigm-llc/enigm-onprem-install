"""Installer command ordering only; Docker effects are explicit doubles."""
import importlib.machinery
import importlib.util
import json
import os
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
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root=Path(directory);root.chmod(0o700)
            project='enigm-'+'a'*24
            state=root/'state.json'
            state.write_text(json.dumps({'project':project}));state.chmod(0o600)
            release=root/'release';release.mkdir(mode=0o700)
            services={}
            references={}
            for name in ('db','rest','storage','realtime','channel'):
                services[name]={
                    'image':'example.invalid/'+name+'@sha256:'+'a'*64,
                    'security_opt':['no-new-privileges:true'],
                    'logging':{'driver':'none'},'healthcheck':{'test':['CMD','true']},
                    'env_file':['${ENIGM_SECRET_'+name.upper()+':?private file reference required}']}
                secret=root/(name+'.env')
                secret.write_text('SYNTHETIC_SECRET='+name+'-fixture\n');secret.chmod(0o600)
                references[name]=str(secret)
            (release/'compose.json').write_text(json.dumps({'services':services}))
            (release/'manifest.json').write_text(json.dumps({
                'providerBootstrapRequired':True,'privateChannelRequired':False}))
            for name in ('compose.json','manifest.json'):
                (release/name).chmod(0o600)
            reference=root/'private-reference.json'
            reference.write_text(json.dumps({'contract':'enigm-onprem-secret-references-v2',
                                            'serviceFiles':references}));reference.chmod(0o600)
            commands=[];configuration=[];environments=[]
            def run_command(argv,**kwargs):
                env=kwargs['env']
                self.assertNotIn('ENIGM_TEST_AMBIENT',env)
                self.assertNotIn('COMPOSE_FILE',env)
                if argv[1:3]==['context','inspect']:
                    return subprocess.CompletedProcess(argv,0,b'"unix:///tmp/fixture.sock"',b'')
                self.assertEqual(env['DOCKER_HOST'],'unix:///tmp/fixture.sock')
                if argv[1]=='info':
                    return subprocess.CompletedProcess(argv,0,b'["name=rootless"]',b'')
                self.assertEqual(set(env),{'PATH','HOME','LANG','LC_ALL','COMPOSE_DISABLE_ENV_FILE',
                                           'DOCKER_HOST','DOCKER_CONFIG'})
                source=Path(argv[argv.index('--file')+1])
                if 'config' in argv:
                    configuration.append(source)
                    model=json.loads(source.read_bytes())
                    model['name']=project
                    # Match Compose config --no-env-resolution output. The installer
                    # validates both outputs and their equality before runtime calls.
                    for name,service in model['services'].items():
                        snapshot=Path(service['env_file'][0]['path'])
                        self.assertNotEqual(str(snapshot),references[name])
                        self.assertEqual(snapshot.read_text(),'SYNTHETIC_SECRET='+name+'-fixture\n')
                        self.assertEqual(snapshot.stat().st_mode & 0o777,0o600)
                    return subprocess.CompletedProcess(argv,0,json.dumps(model).encode(),b'')
                self.assertEqual(len(configuration),2)
                commands.append(argv);environments.append(dict(env))
                self.assertEqual(source.name,'effective-compose.json')
                self.assertEqual(source.stat().st_mode & 0o777,0o600)
                failure=fail_bootstrap and 'run' in argv
                return subprocess.CompletedProcess(argv,1 if failure else 0,b'',b'')
            with patch.dict(os.environ,{'ENIGM_TEST_AMBIENT':'not-forwarded','COMPOSE_FILE':'untrusted.json'}):
                os.environ.pop('DOCKER_HOST',None)
                with patch.object(policy.subprocess,'run',side_effect=run_command):
                    if fail_bootstrap:
                        with self.assertRaisesRegex(policy.Rejected,'PRIVATE_PROVIDER_BOOTSTRAP_FAILED'):
                            policy.compose(root,release,'up',reference)
                    else:policy.compose(root,release,'up',reference)
            self.assertEqual([path.name for path in configuration],
                             ['source-compose.json','effective-compose.json'])
            self.assertEqual(len({argv[argv.index('--file')+1] for argv in commands}),1)
            self.assertTrue(all(env==environments[0] for env in environments))
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
