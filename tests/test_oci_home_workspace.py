"""Bounded conversion workspace behavior; no Docker process or real image."""
import importlib.util, pathlib, subprocess, tempfile, unittest
from unittest import mock
MODULE=pathlib.Path(__file__).resolve().parents[1]/'bin/enigm-image-load-v2.py'
spec=importlib.util.spec_from_file_location('loader_home',MODULE);oci=importlib.util.module_from_spec(spec);spec.loader.exec_module(oci)
class HomeWorkspace(unittest.TestCase):
    def exercise(self, fail=None):
        image='sha256:'+'b'*64;seen=[];workspace=[]
        original=oci.docker_archive
        with tempfile.TemporaryDirectory(dir='/tmp') as parent:
            home=pathlib.Path(parent)
            def conversion(destination,*args):
                workspace.append(destination.parent)
                self.assertEqual(destination.parent.parent,home)
                self.assertEqual(destination.parent.stat().st_mode&0o777,0o700)
                original(destination,*args)
                self.assertEqual(destination.stat().st_mode&0o777,0o600)
                if fail=='conversion':raise OSError('synthetic failure')
            def run(command,**kwargs):
                step='info' if 'info' in command else 'load' if 'load' in command else 'inspect'
                seen.append(step)
                temp=pathlib.Path(kwargs['env']['HOME']);self.assertEqual(temp.parent,home)
                self.assertEqual(temp.stat().st_mode&0o777,0o700)
                if temp not in workspace:workspace.append(temp)
                if step=='load':self.assertTrue((temp/'image.tar').is_file())
                if fail==step:raise subprocess.CalledProcessError(1,command,stderr=b'synthetic-private-marker')
                return subprocess.CompletedProcess(command,0,stdout=b'["name=rootless"]' if step=='info' else image.encode())
            with mock.patch.object(oci.Path,'home',return_value=home),mock.patch.object(oci.subprocess,'run',side_effect=run),mock.patch.object(oci,'docker_archive',side_effect=conversion):
                if fail:
                    with self.assertRaises((OSError,subprocess.CalledProcessError)):oci.load_rootless(image,b'config',[b'layer'],'unix:///run/user/1000/docker.sock')
                else:oci.load_rootless(image,b'config',[b'layer'],'unix:///run/user/1000/docker.sock')
            self.assertTrue(workspace);self.assertTrue(all(not p.exists() for p in workspace));self.assertEqual(list(home.iterdir()),[])
        return seen
    def test_home_conversion_and_success_cleanup(self):self.assertEqual(self.exercise(),['info','load','inspect'])
    def test_info_failure_cleans_workspace(self):self.assertEqual(self.exercise('info'),['info'])
    def test_conversion_failure_cleans_archive(self):self.assertEqual(self.exercise('conversion'),['info'])
    def test_load_failure_cleans_archive_and_skips_inspect(self):self.assertEqual(self.exercise('load'),['info','load'])
    def test_inspect_failure_cleans_archive(self):self.assertEqual(self.exercise('inspect'),['info','load','inspect'])
    def test_group_writable_ancestor_rejected_before_docker(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as parent:
            home=pathlib.Path(parent)/'shared';home.mkdir(mode=0o700);home.chmod(0o770)
            with mock.patch.object(oci.Path,'home',return_value=home),mock.patch.object(oci.subprocess,'run') as execute:
                with self.assertRaisesRegex(ValueError,'OCI_DIRECTORY_INVALID'):oci.load_rootless('sha256:'+'b'*64,b'',[],'unix:///run/user/1000/docker.sock')
                execute.assert_not_called();self.assertEqual(list(home.iterdir()),[])
    def test_symlink_home_rejected_before_docker(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as parent:
            base=pathlib.Path(parent);home=base/'real';home.mkdir(mode=0o700);link=base/'link';link.symlink_to(home,target_is_directory=True)
            with mock.patch.object(oci.Path,'home',return_value=link),mock.patch.object(oci.subprocess,'run') as execute:
                with self.assertRaises(OSError):oci.load_rootless('sha256:'+'b'*64,b'',[],'unix:///run/user/1000/docker.sock')
                execute.assert_not_called();self.assertEqual(list(home.iterdir()),[])
if __name__=='__main__':unittest.main()
