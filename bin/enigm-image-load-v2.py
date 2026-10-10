#!/usr/bin/env python3
"""Validate one Linux AMD64 OCI image and optionally load its exact config ID locally."""
import argparse, contextlib, gzip, hashlib, io, json, os, re, stat, subprocess, tarfile, tempfile
from pathlib import Path
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 4096
INPUT_NAMES = frozenset(['enigm-backend-v2.oci.tar', 'backend-v2.oci.tar', 'runtime.oci.tar', 'image.oci.tar', 'tampered.oci.tar'])
OUTPUT_NAMES = frozenset(['runtime.tar', 'load.tar', 'image.tar'])

@contextlib.contextmanager
def artifact_parent(reference, output=False):
    # Only named OCI artifacts/output archives, never arbitrary credential files.
    raw = os.fspath(reference)
    if not isinstance(raw, str) or not raw or raw.startswith('//') or '..' in raw.split('/'):
        raise ValueError('OCI_REFERENCE_INVALID')
    path = Path(os.path.abspath(raw))
    names = OUTPUT_NAMES if output else INPUT_NAMES
    if path.name not in names: raise ValueError('OCI_REFERENCE_INVALID')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    private = False
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            held = os.fstat(fd)
            sticky_system = held.st_uid == 0 and bool(held.st_mode & stat.S_ISVTX)
            if held.st_uid not in [0, os.getuid()] or (held.st_mode & 0o022 and not sticky_system):
                raise ValueError('OCI_DIRECTORY_INVALID')
            private = private or (held.st_uid == os.getuid() and held.st_mode & 0o077 == 0)
        public_release = (not output and path.name == 'enigm-backend-v2.oci.tar'
                          and path.parent == Path(__file__).absolute().parents[1] / 'release')
        if (not private and not public_release) or os.fstat(fd).st_uid != os.getuid():
            raise ValueError('OCI_DIRECTORY_INVALID')
        yield fd, path.name
    finally:
        os.close(fd)

def pinned_archive(reference, expected_digest):
    if not isinstance(expected_digest, str) or not re.fullmatch('[a-f0-9]{64}', expected_digest):
        raise ValueError('OCI_ARCHIVE_PIN_INVALID')
    with artifact_parent(reference) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            held = os.fstat(fd)
            if not stat.S_ISREG(held.st_mode) or held.st_uid != os.getuid() or held.st_nlink != 1 or held.st_mode & 0o022 or held.st_size > MAX_BYTES:
                raise ValueError('OCI_REFERENCE_INVALID')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                value = stream.read(MAX_BYTES + 1)
            after = os.fstat(fd)
            if len(value) > MAX_BYTES or (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns, held.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('OCI_REFERENCE_CHANGED')
            if hashlib.sha256(value).hexdigest() != expected_digest:
                raise ValueError('OCI_ARCHIVE_PIN_INVALID')
            return value
        finally:
            os.close(fd)

def checked_outer_headers(snapshot):
    # Inspect fixed-size headers before tarfile can expand PAX/GNU metadata.
    # The release envelope is an uncompressed tar; only its layer blobs may gzip.
    offset = 0; members = 0
    while offset + tarfile.BLOCKSIZE <= len(snapshot):
        header = snapshot[offset:offset + tarfile.BLOCKSIZE]
        if header == b'\0' * tarfile.BLOCKSIZE: return
        try:
            item = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        except (tarfile.HeaderError, UnicodeError, ValueError) as error:
            raise ValueError('OCI_OUTER_TAR_INVALID') from error
        members += 1
        if members > MAX_MEMBERS: raise ValueError('OCI_BOUND_EXCEEDED')
        if item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise ValueError('OCI_LAYOUT_INVALID')
        if item.size < 0 or item.size > MAX_BYTES or (item.isdir() and item.size):
            raise ValueError('OCI_BOUND_EXCEEDED')
        offset += tarfile.BLOCKSIZE + ((item.size + 511) // 512) * 512
        if offset > len(snapshot): raise ValueError('OCI_OUTER_TAR_INVALID')
    raise ValueError('OCI_OUTER_TAR_INVALID')

def checked_image(path, source, archive_sha256):
    if not isinstance(source, str) or not re.fullmatch('[a-f0-9]{40}', source): raise ValueError('OCI_REFERENCE_INVALID')
    snapshot = pinned_archive(path, archive_sha256)
    checked_outer_headers(snapshot)
    entries = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(snapshot), mode='r:') as archive:
        for item in archive:
            if item.isdir(): continue
            name = item.name.removeprefix('./')
            if not item.isfile() or name in entries or not (name in ['index.json', 'oci-layout'] or re.fullmatch(r'blobs/sha256/[a-f0-9]{64}', name)):
                raise ValueError('OCI_LAYOUT_INVALID')
            total += item.size
            if total > MAX_BYTES: raise ValueError('OCI_BOUND_EXCEEDED')
            data = archive.extractfile(item).read()
            if name.startswith('blobs/') and hashlib.sha256(data).hexdigest() != name.split('/')[-1]:
                raise ValueError('OCI_BLOB_DIGEST_INVALID')
            entries[name] = data
    if json.loads(entries['oci-layout']) != {'imageLayoutVersion': '1.0.0'}: raise ValueError('OCI_LAYOUT_VERSION_INVALID')
    index = json.loads(entries['index.json'])
    if index.get('schemaVersion') != 2 or len(index.get('manifests', [])) != 1: raise ValueError('OCI_SINGLE_IMAGE_REQUIRED')
    used = {'index.json', 'oci-layout'}
    def blob(descriptor):
        digest = descriptor.get('digest', '')
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest): raise ValueError('OCI_DESCRIPTOR_INVALID')
        name = 'blobs/sha256/' + digest.split(':')[1]; value = entries[name]; used.add(name)
        if len(value) != descriptor.get('size'): raise ValueError('OCI_DESCRIPTOR_SIZE_INVALID')
        return value
    if index['manifests'][0].get('mediaType') != 'application/vnd.oci.image.manifest.v1+json': raise ValueError('OCI_INDEX_DESCRIPTOR_INVALID')
    manifest = json.loads(blob(index['manifests'][0]))
    if manifest.get('schemaVersion') != 2 or manifest.get('mediaType') != 'application/vnd.oci.image.manifest.v1+json': raise ValueError('OCI_MANIFEST_INVALID')
    if manifest['config'].get('mediaType') != 'application/vnd.oci.image.config.v1+json': raise ValueError('OCI_CONFIG_TYPE_INVALID')
    config_data = blob(manifest['config']); config = json.loads(config_data)
    if config.get('architecture') != 'amd64' or config.get('os') != 'linux': raise ValueError('OCI_PLATFORM_UNPROVED')
    if config.get('config', {}).get('Labels', {}).get('org.opencontainers.image.revision') != source: raise ValueError('OCI_SOURCE_MISMATCH')
    layers = []; diff_ids = config.get('rootfs', {}).get('diff_ids', [])
    if config.get('rootfs', {}).get('type') != 'layers' or len(diff_ids) != len(manifest.get('layers', [])): raise ValueError('OCI_LAYERS_INVALID')
    expanded = 0
    for descriptor, diff_id in zip(manifest['layers'], diff_ids):
        value = blob(descriptor)
        media = descriptor.get('mediaType')
        if media == 'application/vnd.oci.image.layer.v1.tar+gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(value)) as stream:
                value = stream.read(MAX_BYTES + 1)
        elif media != 'application/vnd.oci.image.layer.v1.tar': raise ValueError('OCI_LAYER_TYPE_INVALID')
        expanded += len(value)
        if expanded > MAX_BYTES or 'sha256:' + hashlib.sha256(value).hexdigest() != diff_id: raise ValueError('OCI_LAYER_CONTENT_INVALID')
        layers.append(value)
    if set(entries) != used: raise ValueError('OCI_EXTRA_BLOB_REJECTED')
    image_id = 'sha256:' + hashlib.sha256(config_data).hexdigest()
    return image_id, config_data, layers, index['manifests'][0]['digest']

def docker_archive(destination, image_id, config, layers):
    # Docker's classic store does not load OCI layouts directly. Convert only
    # already verified blobs, preserving config bytes and all layer diff IDs.
    with artifact_parent(destination, output=True) as (parent, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        created = os.fstat(fd)
        try:
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                with tarfile.open(fileobj=stream, mode='w') as archive:
                    def add(entry, value):
                        info = tarfile.TarInfo(entry); info.size = len(value); archive.addfile(info, io.BytesIO(value))
                    config_name = image_id.split(':')[1] + '.json'; add(config_name, config)
                    names = []
                    for i, layer in enumerate(layers):
                        entry = str(i) + '/layer.tar'; add(entry, layer); names.append(entry)
                    add('manifest.json', json.dumps([{'Config': config_name, 'RepoTags': [], 'Layers': names}], separators=(',', ':')).encode())
                stream.flush(); os.fsync(fd)
        except Exception:
            # Never remove an attacker replacement/symlink when cleaning a failed write.
            try:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino): os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(fd)

def load_rootless(image_id, config, layers, endpoint=None):
    # Ambient Docker context/configuration, credentials and endpoint selectors
    # cannot change the target between verification, loading and inspection.
    with tempfile.TemporaryDirectory(prefix='enigm-docker-') as directory:
        home = Path(directory); docker_config = home / 'config'; docker_config.mkdir(mode=0o700)
        environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home),
                       'LANG': 'C', 'DOCKER_CONFIG': str(docker_config)}
        base = ['docker', '--config', str(docker_config)]
        if endpoint is None:
            endpoint = os.environ.get('DOCKER_HOST')
        if endpoint is None:
            discovery = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C'}
            context = subprocess.run(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'],
                                     env=discovery, capture_output=True, timeout=30, check=True)
            endpoint = json.loads(context.stdout)
        if (os.getuid() == 0 or not isinstance(endpoint, str)
                or not endpoint.startswith('unix:///') or endpoint.startswith('unix:////')
                or any(character.isspace() for character in endpoint)
                or any(character in endpoint for character in ['?', '#', '\\', '$', '\x00'])
                or '..' in endpoint[7:].split('/')):
            raise ValueError('LOCAL_ROOTLESS_REQUIRED')
        command = base + ['--host', endpoint]
        result = subprocess.run(command + ['info', '--format', '{{json .SecurityOptions}}'],
                                env=environment, capture_output=True, timeout=30, check=True)
        if not any('rootless' in value for value in json.loads(result.stdout)):
            raise ValueError('LOCAL_ROOTLESS_REQUIRED')
        load = home / 'image.tar'; docker_archive(load, image_id, config, layers)
        subprocess.run(command + ['load', '--input', str(load)],
                       env=environment, capture_output=True, timeout=180, check=True)
        result = subprocess.run(command + ['image', 'inspect', '--format', '{{.Id}}', image_id],
                                env=environment, capture_output=True, timeout=30, check=True)
        if result.stdout.decode().strip() != image_id: raise ValueError('OCI_LOADED_ID_MISMATCH')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True); parser.add_argument('--source-sha', required=True)
    parser.add_argument('--archive-sha256', required=True); parser.add_argument('--load-rootless', action='store_true'); parser.add_argument('--docker-archive-output')
    parser.add_argument('--docker-host', help='Explicit local Unix Docker endpoint for rootless loading')
    args = parser.parse_args()
    image_id, config, layers, manifest = checked_image(args.archive, args.source_sha, args.archive_sha256)
    if args.docker_archive_output:
        docker_archive(args.docker_archive_output, image_id, config, layers)
    if args.load_rootless:
        load_rootless(image_id, config, layers, args.docker_host)
    print(json.dumps({'contract': 'enigm-common-oci-image-v2', 'imageId': image_id, 'manifestDigest': manifest, 'sourceSha': args.source_sha, 'platform': 'linux/amd64', 'archiveSha256': args.archive_sha256, 'rootlessLoaded': args.load_rootless}))
if __name__ == '__main__':
    try: main()
    except Exception: raise SystemExit('COMMON_OCI_IMAGE_REJECTED')
