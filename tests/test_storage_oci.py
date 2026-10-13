"""Signed Storage image binding and bounded OCI parsing without Docker or services."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_channel_policy import policy
import test_lifecycle
installer = test_lifecycle.installer
import test_oci_image
oci, SOURCE = test_oci_image.oci, test_oci_image.SOURCE

IMAGE = 'sha256:' + 'a' * 64
SERVICE = {'image': IMAGE, 'pull_policy': 'never', 'security_opt': ['no-new-privileges:true'],
           'logging': {'driver': 'none'}, 'healthcheck': {'test': ['CMD', 'true']}}

class StorageOci(unittest.TestCase):
    def binding(self):
        return {'storageImage': IMAGE, 'storageSourceSha': SOURCE, 'ociLoaderSha256': 'b'*64,
                'assets': {'storage-v2.oci.tar': {'sha256': 'c'*64, 'size': 1024}}}

    def test_storage_exact_service_policy_and_legacy_registry(self):
        policy.validate_compose({'services': {'storage': SERVICE}})
        policy.validate_storage_image(self.binding(), {'services': {'storage': SERVICE}})
        for name in ['db', 'rest', 'realtime']:
            with self.assertRaises(policy.Rejected):
                policy.validate_compose({'services': {name: SERVICE}})
        for change in [{'pull_policy': 'always'}, {'image': 'candidate:latest'}]:
            with self.assertRaises(policy.Rejected):
                policy.validate_compose({'services': {'storage': {**SERVICE, **change}}})
        policy.validate_storage_image({'assets': {}}, {'services': {'storage': {'image': 'vendor/storage@sha256:'+'d'*64}}})

    def test_missing_partial_wrong_image_source_and_extra_asset_fail_closed(self):
        base = self.binding()
        candidates = []
        for field in ['storageImage', 'storageSourceSha', 'ociLoaderSha256']:
            changed = copy.deepcopy(base); del changed[field]; candidates.append(changed)
        for field, value in [('storageImage', 'sha256:'+'d'*64), ('storageSourceSha', 'not-a-source')]:
            changed = copy.deepcopy(base); changed[field] = value; candidates.append(changed)
        changed = copy.deepcopy(base); changed['assets'] = {}; candidates.append(changed)
        changed = copy.deepcopy(base); changed['assets']['unbound.oci.tar'] = {}; candidates.append(changed)
        for value in candidates:
            with self.subTest(value=list(value)), self.assertRaises(policy.Rejected):
                policy.validate_storage_image(value, {'services': {'storage': SERVICE}})
        with self.assertRaises(policy.Rejected):
            policy.validate_storage_image(base, {'services': {'storage': {'image': 'vendor/storage@sha256:'+'d'*64}}})

    def test_storage_archive_real_blob_source_and_pin_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'storage-v2.oci.tar'
            test_oci_image.OciPayload().fixture(path)
            pin = hashlib.sha256(path.read_bytes()).hexdigest()
            image, _, _, _ = oci.checked_image(path, SOURCE, pin)
            self.assertTrue(image.startswith('sha256:'))
            with self.assertRaisesRegex(ValueError, 'OCI_SOURCE_MISMATCH'):
                oci.checked_image(path, 'b'*40, pin)
            with self.assertRaisesRegex(ValueError, 'OCI_ARCHIVE_PIN_INVALID'):
                oci.checked_image(path, SOURCE, '0'*64)

    def test_signed_manifest_binds_storage_and_rejects_unsigned_tamper(self):
        fixture = test_lifecycle.Lifecycle(); fixture.setUp()
        try:
            bundle, _ = fixture.release('storage', compose={'services': {'storage': SERVICE}})
            archive = bundle/'storage-v2.oci.tar'; test_oci_image.OciPayload().fixture(archive)
            manifest_path = bundle/'manifest.json'; manifest = json.loads(manifest_path.read_text())
            manifest.update(self.binding()); manifest['assets']['compose.json'] = {'sha256': installer.digest(bundle/'compose.json'), 'size': (bundle/'compose.json').stat().st_size}
            manifest['assets']['storage-v2.oci.tar'] = {'sha256': installer.digest(archive), 'size': archive.stat().st_size}
            manifest_path.write_text(json.dumps(manifest))
            subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(fixture.key), '-rawin', '-in', str(manifest_path), '-out', str(bundle/'manifest.sig')], check=True, capture_output=True)
            installer.verify(bundle, installer.digest(manifest_path), fixture.pub, installer.digest(fixture.pub))
            manifest['storageImage'] = 'sha256:'+'e'*64; manifest_path.write_text(json.dumps(manifest))
            with self.assertRaises(installer.Rejected):
                installer.verify(bundle, installer.digest(manifest_path), fixture.pub, installer.digest(fixture.pub))
        finally:
            fixture.tearDown()

    def test_expansion_budget_is_shared_and_cannot_be_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'storage-v2.oci.tar'
            _, raw = test_oci_image.OciPayload().fixture(path)
            pin = hashlib.sha256(path.read_bytes()).hexdigest()
            oci.checked_image(path, SOURCE, pin, len(raw))
            for budget in [len(raw)-1, 0, oci.MAX_BYTES+1, True]:
                with self.subTest(budget=budget), self.assertRaises(ValueError):
                    oci.checked_image(path, SOURCE, pin, budget)

    def test_second_load_failure_never_switches_existing_runtime(self):
        from unittest.mock import patch
        fixture = test_lifecycle.Lifecycle(); fixture.setUp()
        try:
            with patch.object(installer,'compose'):
                installer.lifecycle(fixture.args())
            old_state = (fixture.root/'state.json').read_bytes()
            old_current = (fixture.root/'current').readlink()
            bundle, pin = fixture.release('second-load-fails', fixture.pin)
            manifest = json.loads((bundle/'manifest.json').read_text())
            for name in ['backend-v2.oci.tar','storage-v2.oci.tar']:
                p = bundle/name; p.write_bytes(b'load-double-fixture'); p.chmod(0o600)
                manifest['assets'][name]={'sha256':installer.digest(p),'size':p.stat().st_size}
            loader_source=Path(installer.__file__).with_name('enigm-image-load-v2.py')
            loader_file=fixture.base/'enigm-image-load-v2.py'
            loader_file.write_bytes(loader_source.read_bytes()); loader_file.chmod(0o600)
            manifest.update(backendChannelImage=IMAGE,backendSourceSha=SOURCE,storageImage='sha256:'+'d'*64,storageSourceSha='b'*40,ociLoaderSha256=installer.digest(loader_file))
            backup=fixture.base/'backup.enc'; backup.write_bytes(b'synthetic encrypted backup'); backup.chmod(0o600)
            receipt=fixture.base/'backup-receipt.json';receipt.write_text(json.dumps({'release':fixture.pin,'restoreDrillPassed':True,'encryptedBackupReference':str(backup),'sha256':installer.digest(backup)}));receipt.chmod(0o600)
            args=fixture.args('update',bundle,pin);args.backup_receipt=str(receipt)
            loads=[]
            def loading(argv,*_a,**_kw):
                loads.append(argv)
                if len(loads)==2:raise installer.Rejected('STORAGE_LOAD_FAILED')
                return json.dumps({'imageId':IMAGE,'rootlessLoaded':True,'expandedLayerBytes':1024})
            with patch.object(installer,'__file__',str(fixture.base/'enigm-install')),patch.object(installer,'verify',return_value=manifest),patch.object(installer,'local_docker_endpoint',return_value='unix:///fixture'),patch.object(installer,'run',side_effect=loading),patch.object(installer,'compose') as compose:
                with self.assertRaisesRegex(installer.Rejected,'STORAGE_LOAD_FAILED'):
                    installer.lifecycle(args)
                compose.assert_not_called()
            self.assertEqual(len(loads),2)
            self.assertIn(str(2*1024*1024*1024-1024),loads[1])
            self.assertEqual((fixture.root/'state.json').read_bytes(),old_state)
            self.assertEqual((fixture.root/'current').readlink(),old_current)
        finally:
            fixture.tearDown()
