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
    def test_compressed_outer_archive_is_rejected_before_tar_parsing(self):
        with tempfile.TemporaryDirectory() as temp:
            archive=pathlib.Path(temp)/'image.oci.tar';self.fixture(archive)
            archive.write_bytes(gzip.compress(archive.read_bytes(),mtime=0))
            archive_digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            with mock.patch.object(oci.tarfile,'open') as parsing:
                with self.assertRaisesRegex(ValueError,'OCI_OUTER_TAR_INVALID'):
                    oci.checked_image(archive,SOURCE,archive_digest)
                parsing.assert_not_called()
    def test_directory_headers_count_toward_member_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            archive=pathlib.Path(temp)/'image.oci.tar'
            with tarfile.open(archive,'w') as output:
                for index in range(5):
                    item=tarfile.TarInfo('directories/'+str(index));item.type=tarfile.DIRTYPE;output.addfile(item)
            archive.chmod(0o600)
            archive_digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            with mock.patch.object(oci,'MAX_MEMBERS',4),mock.patch.object(oci.tarfile,'open') as parsing:
                with self.assertRaisesRegex(ValueError,'OCI_BOUND_EXCEEDED'):
                    oci.checked_image(archive,SOURCE,archive_digest)
                parsing.assert_not_called()
    def test_pax_and_sparse_metadata_rejected_before_expansion(self):
        for kind in (tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_SPARSE,tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                archive=pathlib.Path(temp)/'image.oci.tar'
                item=tarfile.TarInfo('metadata');item.type=kind;item.size=1
                archive.write_bytes(item.tobuf()+b'x'+b'\0'*511+b'\0'*1024);archive.chmod(0o600)
                archive_digest=hashlib.sha256(archive.read_bytes()).hexdigest()
                with mock.patch.object(oci.tarfile,'open') as parsing:
                    with self.assertRaisesRegex(ValueError,'OCI_LAYOUT_INVALID'):
                        oci.checked_image(archive,SOURCE,archive_digest)
                    parsing.assert_not_called()
    def test_explicit_local_endpoint_is_pinned_despite_hostile_ambient_configuration(self):
        image_id='sha256:'+'b'*64;endpoint='unix:///run/user/1000/docker.sock';calls=[]
        def run(command,**kwargs):
            calls.append((command,kwargs))
            config=pathlib.Path(command[command.index('--config')+1])
            self.assertEqual(config.stat().st_mode & 0o777,0o700)
            self.assertEqual(list(config.iterdir()),[])
            self.assertEqual(set(kwargs['env']),{'PATH','HOME','LANG','DOCKER_CONFIG'})
            self.assertEqual(kwargs['env']['DOCKER_CONFIG'],str(config))
            self.assertEqual(command[command.index('--host')+1],endpoint)
            value=b'[]' if '{{json .DriverStatus}}' in command else b'["name=rootless"]' if 'info' in command else image_id.encode()+b'\n'
            return subprocess.CompletedProcess(command,0,stdout=value)
        with mock.patch.dict(os.environ,{'DOCKER_HOST':'tcp://remote:2376','DOCKER_CONTEXT':'remote','DOCKER_CONFIG':'/hostile','DOCKER_TLS_VERIFY':'1','DOCKER_CERT_PATH':'/credentials','PATH':'/hostile','HOME':'/hostile'}),mock.patch.object(oci.os,'getuid',return_value=1000),mock.patch.object(oci,'docker_archive') as conversion,mock.patch.object(oci.subprocess,'run',side_effect=run):
            oci.load_rootless(image_id,b'config',[b'layer'],endpoint)
        self.assertEqual(len(calls),4)
        self.assertEqual([next(value for value in ['info','info','load','image'] if value in command) for command,_ in calls],['info','info','load','image'])
        self.assertTrue(all(command[:5]==calls[0][0][:5] for command,_ in calls))
        conversion.assert_called_once()
    def test_clean_discovery_precedes_pinned_info_and_remote_target_is_rejected(self):
        image_id='sha256:'+'b'*64;endpoint='unix:///run/user/1000/docker.sock';calls=[]
        def run(command,**kwargs):
            calls.append(command)
            self.assertNotIn('DOCKER_CONTEXT',kwargs['env']);self.assertNotIn('DOCKER_HOST',kwargs['env'])
            if 'context' in command:
                self.assertNotIn('--host',command);value=json.dumps(endpoint).encode()
            else:
                self.assertEqual(command[command.index('--host')+1],endpoint)
                value=b'[]' if '{{json .DriverStatus}}' in command else b'["name=rootless"]' if 'info' in command else image_id.encode()
            return subprocess.CompletedProcess(command,0,stdout=value)
        with mock.patch.object(oci.os,'getuid',return_value=1000),mock.patch.object(oci,'docker_archive'),mock.patch.object(oci.subprocess,'run',side_effect=run):
            oci.load_rootless(image_id,b'config',[])
        self.assertEqual(len(calls),5);self.assertIn('context',calls[0]);self.assertIn('info',calls[1])
        with mock.patch.object(oci.os,'getuid',return_value=1000),mock.patch.object(oci.subprocess,'run') as execution:
            for remote in ('tcp://remote:2376','ssh://remote','unix://remote/path','unix:////remote/path','unix:///run/../docker.sock','unix:///run/socket --host=remote','unix:///run/socket;command','unix:///run/socket$VAR'):
                with self.subTest(endpoint=remote),self.assertRaisesRegex(ValueError,'LOCAL_ROOTLESS_REQUIRED'):
                    oci.load_rootless(image_id,b'config',[],remote)
            execution.assert_not_called()
    def test_containerd_store_rejected_before_conversion_or_load(self):
        calls=[]
        def run(command,**kwargs):
            calls.append(command)
            value=b'[["driver-type","io.containerd.snapshotter.v1"]]' if '{{json .DriverStatus}}' in command else b'["name=rootless"]'
            return subprocess.CompletedProcess(command,0,stdout=value)
        with mock.patch.object(oci.os,'getuid',return_value=1000),mock.patch.object(oci,'docker_archive') as conversion,mock.patch.object(oci.subprocess,'run',side_effect=run):
            with self.assertRaisesRegex(ValueError,'OCI_CLASSIC_IMAGE_STORE_REQUIRED'):
                oci.load_rootless('sha256:'+'b'*64,b'config',[],'unix:///run/user/1000/docker.sock')
            conversion.assert_not_called()
        self.assertFalse(any('load' in command for command in calls))

if __name__=='__main__':unittest.main()
