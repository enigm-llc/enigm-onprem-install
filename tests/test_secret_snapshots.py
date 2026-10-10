"""Synthetic filesystem regressions for private descriptor reads and snapshots."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / 'bin/enigm-install'
loader = importlib.machinery.SourceFileLoader('enigm_secret_snapshots', str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
policy = importlib.util.module_from_spec(spec)
loader.exec_module(policy)


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        # /tmp is intentionally unsuitable for positive secret-path checks.
        # All real positive cases use a private tree below the owner's home.
        self.temporary = tempfile.TemporaryDirectory(prefix='enigm-secret-test-', dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.source = self.base / 'source'
        self.source.mkdir(mode=0o700)

    def private_file(self, name='fixture.json', value=None, parent=None):
        target = (parent or self.source) / name
        target.write_text(json.dumps(value or {'fixture': 'original'}))
        target.chmod(0o600)
        return target



class PrivateFiles(PrivateFixture):
    def test_private_json_is_read_without_disclosing_fixture_content(self):
        source = self.private_file()
        self.assertEqual(policy.private_json_reference(source), {'fixture': 'original'})

    def test_shared_ancestor_is_rejected_even_when_leaf_is_private(self):
        for mode in (0o720, 0o702, 0o770, 0o777):
            with self.subTest(mode=oct(mode)):
                source = self.private_file()
                self.source.chmod(mode)
                try:
                    with self.assertRaises(policy.Rejected):
                        policy.private_json_reference(source)
                finally:
                    self.source.chmod(0o700)

    def test_tmp_sticky_bit_does_not_make_secret_ancestors_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            source = self.private_file(parent=root)
            with self.assertRaises(policy.Rejected):
                policy.private_json_reference(source)

    def test_symlink_leaf_and_symlink_ancestor_are_rejected(self):
        source = self.private_file()
        leaf = self.base / 'linked.json'
        leaf.symlink_to(source)
        ancestor = self.base / 'linked-source'
        ancestor.symlink_to(self.source, target_is_directory=True)
        for target in (leaf, ancestor / source.name):
            with self.subTest(target=target.name):
                with self.assertRaises(policy.Rejected):
                    policy.private_json_reference(target)

    def test_hardlinked_private_file_is_rejected(self):
        source = self.private_file()
        os.link(source, self.base / 'second.json')
        with self.assertRaises(policy.Rejected):
            policy.private_json_reference(source)

    def test_nonregular_and_oversized_private_files_are_rejected(self):
        fifo = self.source / 'fixture.fifo'
        os.mkfifo(fifo, mode=0o600)
        with self.assertRaises(policy.Rejected):
            policy.private_json_reference(fifo)
        source = self.private_file()
        source.write_bytes(b' ' * 65537)
        with self.assertRaises(policy.Rejected):
            policy.private_json_reference(source)

    def test_leaf_symlink_substitution_at_open_is_rejected(self):
        source = self.private_file()
        replacement = self.private_file('replacement.json', {'fixture': 'substituted'})
        open_real = os.open
        raced = False

        def substitute(path, flags, *args, **kwargs):
            nonlocal raced
            if Path(path).name == source.name and not raced:
                raced = True
                source.unlink()
                source.symlink_to(replacement)
            return open_real(path, flags, *args, **kwargs)

        with patch.object(policy.os, 'open', side_effect=substitute):
            with self.assertRaises(policy.Rejected):
                policy.private_json_reference(source)
        self.assertTrue(raced, 'The regression must reach the descriptor-open boundary')

    def test_in_place_modification_during_descriptor_read_is_rejected(self):
        source = self.private_file()
        read_real = os.read
        changed = False

        def modify_after_read(descriptor, size):
            nonlocal changed
            encoded = read_real(descriptor, size)
            if encoded and not changed:
                changed = True
                source.write_text(json.dumps({'fixture': 'replaced'}))
                source.chmod(0o600)
            return encoded

        with patch.object(policy.os, 'read', side_effect=modify_after_read):
            with self.assertRaises(policy.Rejected):
                policy.read_private_bytes(source)
        self.assertTrue(changed)

    def test_link_created_during_descriptor_read_is_rejected(self):
        source = self.private_file()
        read_real = os.read
        changed = False

        def link_after_read(descriptor, size):
            nonlocal changed
            encoded = read_real(descriptor, size)
            if encoded and not changed:
                changed = True
                os.link(source, self.base / 'raced-hardlink.json')
            return encoded

        with patch.object(policy.os, 'read', side_effect=link_after_read):
            with self.assertRaises(policy.Rejected):
                policy.read_private_bytes(source)
        self.assertTrue(changed)

    def test_parent_rename_cannot_redirect_an_open_ancestor_descriptor(self):
        source = self.private_file()
        attacker = self.base / 'replacement-directory'
        attacker.mkdir(mode=0o700)
        self.private_file(source.name, {'fixture': 'substituted'}, attacker)
        retired = self.base / 'retired-source'
        open_real = os.open
        raced = False

        def rename_parent(path, flags, *args, **kwargs):
            nonlocal raced
            if Path(path).name == source.name and not raced:
                raced = True
                self.source.rename(retired)
                attacker.rename(self.source)
            return open_real(path, flags, *args, **kwargs)

        with patch.object(policy.os, 'open', side_effect=rename_parent):
            try:
                result = policy.private_json_reference(source)
            except policy.Rejected:
                result = None
        self.assertTrue(raced, 'The regression must race after opening the ancestor')
        self.assertIn(result, (None, {'fixture': 'original'}))


class SecretSnapshots(PrivateFixture):
    def test_snapshots_are_private_copies_not_original_paths_or_hardlinks(self):
        source = self.private_file('db.env', {'fixture': 'original'})
        destination = self.base / 'runtime'
        destination.mkdir(mode=0o700)
        snapshots = policy.snapshot_secret_files({'db': source}, destination)
        self.assertEqual(set(snapshots), {'db'})
        snapshot = Path(snapshots['db'])
        self.assertTrue(snapshot.is_relative_to(destination))
        self.assertNotEqual(snapshot, source)
        self.assertFalse(snapshot.is_symlink())
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(snapshot.parent.stat().st_mode), 0o700)
        self.assertEqual(snapshot.stat().st_nlink, 1)
        self.assertEqual(snapshot.stat().st_uid, os.getuid())
        self.assertNotEqual((snapshot.stat().st_dev, snapshot.stat().st_ino),
                            (source.stat().st_dev, source.stat().st_ino))
        original = source.read_bytes()
        source.unlink()
        source.write_text('replacement fixture')
        source.chmod(0o600)
        self.assertEqual(snapshot.read_bytes(), original)

    def test_parent_replacement_after_snapshot_cannot_change_consumed_bytes(self):
        source = self.private_file('db.env', {'fixture': 'original'})
        destination = self.base / 'runtime'
        destination.mkdir(mode=0o700)
        snapshots = policy.snapshot_secret_files({'db': source}, destination)
        self.source.rename(self.base / 'retired-source')
        self.source.mkdir(mode=0o700)
        self.private_file(source.name, {'fixture': 'substituted'})
        self.assertEqual(json.loads(Path(snapshots['db']).read_bytes()), {'fixture': 'original'})

    def test_each_service_has_an_independent_snapshot(self):
        first = self.private_file('db.env', {'fixture': 'db'})
        second = self.private_file('api.env', {'fixture': 'api'})
        destination = self.base / 'runtime'
        destination.mkdir(mode=0o700)
        snapshots = policy.snapshot_secret_files({'db': first, 'api': second}, destination)
        self.assertEqual(set(snapshots), {'db', 'api'})
        self.assertNotEqual(snapshots['db'], snapshots['api'])
        self.assertEqual(json.loads(Path(snapshots['db']).read_bytes()), {'fixture': 'db'})
        self.assertEqual(json.loads(Path(snapshots['api']).read_bytes()), {'fixture': 'api'})

    def test_snapshot_rejects_shared_or_symlink_source_ancestors(self):
        source = self.private_file('db.env')
        destination = self.base / 'runtime'
        destination.mkdir(mode=0o700)
        self.source.chmod(0o770)
        try:
            with self.assertRaises(policy.Rejected):
                policy.snapshot_secret_files({'db': source}, destination)
        finally:
            self.source.chmod(0o700)
        linked = self.base / 'linked-source'
        linked.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(policy.Rejected):
            policy.snapshot_secret_files({'db': linked / source.name}, destination)

    def test_snapshot_rejects_hardlinked_source(self):
        source = self.private_file('db.env')
        os.link(source, self.base / 'second.env')
        destination = self.base / 'runtime'
        destination.mkdir(mode=0o700)
        with self.assertRaises(policy.Rejected):
            policy.snapshot_secret_files({'db': source}, destination)

    def test_snapshot_destination_cannot_be_shared_or_symlinked(self):
        source = self.private_file('db.env')
        destination = self.base / 'runtime'
        destination.mkdir(mode=0o770)
        with self.assertRaises(policy.Rejected):
            policy.snapshot_secret_files({'db': source}, destination)
        destination.chmod(0o700)
        linked = self.base / 'linked-runtime'
        linked.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(policy.Rejected):
            policy.snapshot_secret_files({'db': source}, linked)


if __name__ == '__main__':
    unittest.main()
