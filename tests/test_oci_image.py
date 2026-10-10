"""Real OCI blob/config/layer hashes and Docker conversion, without Docker execution."""
import gzip, hashlib, importlib.util, io, json, os, pathlib, subprocess, sys, tarfile, tempfile, unittest
from unittest import mock
MODULE=pathlib.Path(__file__).resolve().parents[1]/'bin/enigm-image-load-v2.py'
spec=importlib.util.spec_from_file_location('oci',MODULE);oci=importlib.util.module_from_spec(spec);spec.loader.exec_module(oci)
SOURCE='a'*40
class OciPayload(unittest.TestCase):
    def fixture(self,path,extra=False,source=SOURCE):
        layer=io.BytesIO()
        with tarfile.open(fileobj=layer,mode='w') as archive:
            item=tarfile.TarInfo('app/dist/bootstrap.js');value=b'fixture code';item.size=len(value);archive.addfile(item,io.BytesIO(value))
        raw=layer.getvalue();packed=gzip.compress(raw,mtime=0);blobs={}
        def blob(value,kind):
            pin=hashlib.sha256(value).hexdigest();blobs['blobs/sha256/'+pin]=value
            return {'mediaType':kind,'digest':'sha256:'+pin,'size':len(value)}
        config=json.dumps({'architecture':'amd64','os':'linux','config':{'Labels':{'org.opencontainers.image.revision':source}},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(raw).hexdigest()]}}).encode()
        manifest=json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':blob(config,'application/vnd.oci.image.config.v1+json'),'layers':[blob(packed,'application/vnd.oci.image.layer.v1.tar+gzip')]}).encode()
        descriptor=blob(manifest,'application/vnd.oci.image.manifest.v1+json')
        blobs.update({'oci-layout':b'{"imageLayoutVersion":"1.0.0"}','index.json':json.dumps({'schemaVersion':2,'manifests':[descriptor]}).encode()})
        if extra:blobs['blobs/sha256/'+hashlib.sha256(b'extra').hexdigest()]=b'extra'
        with tarfile.open(path,'w') as archive:
            for name,value in blobs.items():
                item=tarfile.TarInfo(name);item.size=len(value);archive.addfile(item,io.BytesIO(value))
        path.chmod(0o600)
        return config,raw
    def test_exact_config_and_layers_survive_docker_load_conversion(self):
        with tempfile.TemporaryDirectory() as temp:
            archive=pathlib.Path(temp)/'image.oci.tar';config,raw=self.fixture(archive)
            image_id,actual,layers,_=oci.checked_image(archive,SOURCE,hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(actual,config);self.assertEqual(layers,[raw]);self.assertEqual(image_id,'sha256:'+hashlib.sha256(config).hexdigest())
            load=pathlib.Path(temp)/'load.tar';oci.docker_archive(load,image_id,actual,layers)
            with tarfile.open(load) as result:
                manifest=json.load(result.extractfile('manifest.json'))[0]
                self.assertEqual(manifest['RepoTags'],[])
                self.assertEqual(result.extractfile(manifest['Config']).read(),config)
                self.assertEqual(result.extractfile(manifest['Layers'][0]).read(),raw)
    def test_wrong_source_and_unreferenced_blobs_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            archive=pathlib.Path(temp)/'image.oci.tar';self.fixture(archive,source='b'*40)
            with self.assertRaisesRegex(ValueError,'OCI_SOURCE_MISMATCH'):oci.checked_image(archive,SOURCE,hashlib.sha256(archive.read_bytes()).hexdigest())
            self.fixture(archive,extra=True)
            with self.assertRaisesRegex(ValueError,'OCI_EXTRA_BLOB_REJECTED'):oci.checked_image(archive,SOURCE,hashlib.sha256(archive.read_bytes()).hexdigest())
    def test_blob_tamper_and_manifest_descriptor_substitution_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            original=pathlib.Path(temp)/'image.oci.tar';self.fixture(original)
            changed=pathlib.Path(temp)/'tampered.oci.tar'
            with tarfile.open(original) as source,tarfile.open(changed,'w') as archive:
                mutated=False
                for item in source:
                    data=source.extractfile(item).read()
                    if item.name.startswith('blobs/') and not mutated:data+=b'tamper';mutated=True
                    item.size=len(data);archive.addfile(item,io.BytesIO(data))
            changed.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'OCI_BLOB_DIGEST_INVALID'):oci.checked_image(changed,SOURCE,hashlib.sha256(changed.read_bytes()).hexdigest())
    def test_credentials_traversal_and_symlink_ancestors_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);archive=root/'image.oci.tar';self.fixture(archive)
            pin=hashlib.sha256(archive.read_bytes()).hexdigest()
            secret=root/'operator-secret.json';secret.write_bytes(b'private-fixture')
            with mock.patch.object(oci.os,'open',wraps=os.open) as opening:
                with self.assertRaisesRegex(ValueError,'OCI_REFERENCE_INVALID'):
                    oci.checked_image(secret,SOURCE,hashlib.sha256(secret.read_bytes()).hexdigest())
                opening.assert_not_called()
            with self.assertRaisesRegex(ValueError,'OCI_REFERENCE_INVALID'):
                oci.checked_image(root/'..'/root.name/'image.oci.tar',SOURCE,pin)
            link=root/'ancestor';link.symlink_to(root,target_is_directory=True)
            with self.assertRaises(OSError):oci.checked_image(link/'image.oci.tar',SOURCE,pin)
            leaf=root/'runtime.oci.tar';leaf.symlink_to(archive)
            with self.assertRaises(OSError):oci.checked_image(leaf,SOURCE,pin)
            hard=root/'tampered.oci.tar';os.link(archive,hard)
            with self.assertRaisesRegex(ValueError,'OCI_REFERENCE_INVALID'):oci.checked_image(hard,SOURCE,pin)
    def test_pin_is_validated_once_and_parser_uses_that_snapshot_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            archive=pathlib.Path(temp)/'image.oci.tar';config,_=self.fixture(archive)
            pin=hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError,'OCI_ARCHIVE_PIN_INVALID'):oci.checked_image(archive,SOURCE,'0'*64)
            original=oci.pinned_archive
            def replace_after_pin(reference,digest):
                snapshot=original(reference,digest)
                self.fixture(archive,extra=True)
                return snapshot
            with mock.patch.object(oci,'pinned_archive',side_effect=replace_after_pin):
                _,actual,_,_=oci.checked_image(archive,SOURCE,pin)
            self.assertEqual(actual,config)
    def test_exclusive_output_creation_cannot_overwrite_an_existing_or_raced_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);archive=root/'image.oci.tar';self.fixture(archive)
            image_id,config,layers,_=oci.checked_image(archive,SOURCE,hashlib.sha256(archive.read_bytes()).hexdigest())
            output=root/'load.tar';output.write_bytes(b'sentinel')
            with self.assertRaises(FileExistsError):oci.docker_archive(output,image_id,config,layers)
            self.assertEqual(output.read_bytes(),b'sentinel');output.unlink()
            original=os.open
            def race(name,flags,*args,**kwargs):
                if name=='load.tar' and flags & os.O_EXCL:
                    fd=original(name,flags,*args,**kwargs)
                    try:os.write(fd,b'raced-sentinel')
                    finally:os.close(fd)
                return original(name,flags,*args,**kwargs)
            with mock.patch.object(oci.os,'open',side_effect=race):
                with self.assertRaises(FileExistsError):oci.docker_archive(output,image_id,config,layers)
            self.assertEqual(output.read_bytes(),b'raced-sentinel')
    def test_failed_conversion_cleans_only_its_own_output_and_success_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);archive=root/'image.oci.tar';self.fixture(archive)
            image_id,config,layers,_=oci.checked_image(archive,SOURCE,hashlib.sha256(archive.read_bytes()).hexdigest())
            output=root/'load.tar'
            with mock.patch.object(oci.tarfile.TarFile,'addfile',side_effect=RuntimeError('fixture conversion failure')):
                with self.assertRaises(RuntimeError):oci.docker_archive(output,image_id,config,layers)
            self.assertFalse(output.exists())
            oci.docker_archive(output,image_id,config,layers)
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            self.assertEqual(output.stat().st_nlink,1)
    def test_cli_pin_and_safe_fixed_output_are_compatible_without_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);archive=root/'runtime.oci.tar';self.fixture(archive)
            output=root/'runtime.tar';pin=hashlib.sha256(archive.read_bytes()).hexdigest()
            result=subprocess.run([sys.executable,str(MODULE),'--archive',str(archive),'--source-sha',SOURCE,'--archive-sha256',pin,'--docker-archive-output',str(output)],capture_output=True,check=True)
            receipt=json.loads(result.stdout)
            self.assertEqual(receipt['archiveSha256'],pin)
            self.assertEqual(receipt['sourceSha'],SOURCE)
            self.assertFalse(receipt['rootlessLoaded'])
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
    def test_failure_cleanup_does_not_remove_a_replacement_reference(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);archive=root/'image.oci.tar';self.fixture(archive)
            image_id,config,layers,_=oci.checked_image(archive,SOURCE,hashlib.sha256(archive.read_bytes()).hexdigest())
            output=root/'load.tar';sentinel=root/'sentinel';sentinel.write_bytes(b'keep-private-fixture')
            def replace_then_fail(*_args,**_kwargs):
                output.unlink();output.symlink_to(sentinel)
                raise RuntimeError('fixture replacement failure')
            with mock.patch.object(oci.tarfile.TarFile,'addfile',side_effect=replace_then_fail):
                with self.assertRaises(RuntimeError):oci.docker_archive(output,image_id,config,layers)
            self.assertTrue(output.is_symlink())
            self.assertEqual(sentinel.read_bytes(),b'keep-private-fixture')
if __name__=='__main__':unittest.main()
