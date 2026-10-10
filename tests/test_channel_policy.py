import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT=Path(__file__).parents[1]/'bin/enigm-install'
loader=importlib.machinery.SourceFileLoader('enigm_public_channel_policy',str(SCRIPT))
spec=importlib.util.spec_from_loader(loader.name,loader)
policy=importlib.util.module_from_spec(spec);loader.exec_module(policy)


class ChannelPolicy(unittest.TestCase):
    def test_signed_release_requires_private_channel_without_silent_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            (root/'manifest.json').write_text(json.dumps({'privateChannelRequired':True}))
            with self.assertRaisesRegex(policy.Rejected,'PRIVATE_CHANNEL_REQUIRED'):
                policy.validate_private_channel({},root)

    def test_central_private_key_cannot_be_shipped_in_provider_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            (root/'manifest.json').write_text(json.dumps({'backendArtifact':'1'*64,'privateChannelRequired':True}))
            manifest={'contract':'enigm-onprem-channel-preparation-v2','product':'2.1','phase':'PREPARED','centralActivationRequired':True,'admissionEnabled':False}
            provider={'clientKeyPem':'forbidden central material field'}
            for name,value in [('channel.json',manifest),('provider.json',provider)]:
                target=root/name;target.write_text(json.dumps(value));target.chmod(0o600)
            with self.assertRaisesRegex(policy.Rejected,'PRIVATE_CHANNEL_SCOPE_INVALID'):
                policy.validate_private_channel({'privateChannel':{'manifestFile':str(root/'channel.json'),'providerRuntimeFile':str(root/'provider.json')}},root)

    def test_local_image_id_is_channel_only_and_never_falls_back_to_registry(self):
        service={'image':'sha256:'+'a'*64,'pull_policy':'never','security_opt':['no-new-privileges:true'],'logging':{'driver':'none'},'healthcheck':{'test':['CMD','true']}}
        policy.validate_compose({'services':{'channel':service}})
        with self.assertRaisesRegex(policy.Rejected,'IMAGE_DIGEST_REQUIRED'):
            policy.validate_compose({'services':{'db':service}})
        with self.assertRaisesRegex(policy.Rejected,'IMAGE_DIGEST_REQUIRED'):
            policy.validate_compose({'services':{'channel':{**service,'pull_policy':'always'}}})
        with self.assertRaisesRegex(policy.Rejected,'IMAGE_DIGEST_REQUIRED'):
            policy.validate_compose({'services':{'channel':{**service,'image':'enigm-common:latest'}}})
