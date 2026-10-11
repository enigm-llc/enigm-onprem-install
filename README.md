# Enigm On-Prem Installer

A verifiable installation path for infrastructure you control.

Enigm On-Prem Installer is an open-source Linux tool for installing signed Enigm deployment bundles. It checks release integrity, stages protected configuration, and manages installation, upgrades, and recovery with rootless Docker.

## Deployment controls

- SHA-256 pins and Ed25519 signatures verify the release and its publisher key.
- Content-addressed images keep deployments tied to approved release bytes.
- Rootless containers, restricted Compose settings, and owner-only configuration files limit exposure.
- Explicit upgrade paths and backup receipts help preserve installation state and data.

The installer source is open. Deployment bundles, service configuration, and publisher trust material are distributed separately.

## Requirements

- Linux with Python 3.9 or later.
- OpenSSL with Ed25519 support.
- A configured local [rootless Docker Engine](https://docs.docker.com/engine/security/rootless/). Local signed OCI bundles currently require the classic image store. Docker 29 installations using the default containerd image store are not supported for this loading path; the installer stops with `OCI_CLASSIC_IMAGE_STORE_REQUIRED` before loading an image. It does not change your Docker configuration.
- Docker Compose 5.5.0, the version verified by this repository’s CI. It must preserve raw `env_file` entries with `config --no-env-resolution` and support `up --wait`. Older parsers can resolve secret files despite the flag; the installer rejects that altered model before startup.
- A signed deployment bundle and independently trusted SHA-256 values for its manifest and publisher public key.

Run as the installation owner. Prepare the host before using the installer; it does not install host packages or configure Docker for you.

## Install

Clone this repository, then validate and stage your release:

```sh
python3 bin/enigm-install install \
  --root /home/user/.local/share/enigm-onprem \
  --bundle /path/to/verified-release \
  --manifest-sha256 MANIFEST_SHA256 \
  --trust-key /path/to/enigm-release.pub \
  --trust-key-sha256 PUBLIC_KEY_SHA256 \
  --secrets-file /path/to/service-references.json \
  --prepare-only
```

Replace the placeholders with trusted release values. The service reference document and each service configuration file must be owned by the installation user with permissions `0600`. The installation directory uses `0700`. Every ancestor directory of configuration, bundle, trust-key, and installation paths must be owned by root or the installation user, without group or other write permission. Symlinks and hardlinked files are rejected. Keep these files under a protected home directory; shared temporary directories are unsuitable.

For example, a release with a service named `app` can use this reference document:

```json
{
  "contract": "enigm-onprem-secret-references-v2",
  "serviceFiles": {
    "app": "/home/user/.config/enigm-onprem/app.env"
  }
}
```

Use the service names required by your signed bundle. Follow the reference document supplied with the release for any additional required fields.

Run the same command without `--prepare-only` to start services and wait for their health checks. Service health confirms startup; verify your application's behavior before putting the installation into use.

To inspect the available options:

```sh
python3 bin/enigm-install --help
```

## Runtime isolation

The installer resolves a local Unix Docker endpoint once, checks rootless operation, and uses that endpoint throughout loading and startup. Set `DOCKER_HOST=unix:///path/to/docker.sock` when selecting a specific local daemon. Remote endpoints and inherited Docker context overrides are rejected or excluded.

Compose runs with a controlled environment. Only the release-approved secret-file references are accepted; shell-style interpolation elsewhere is rejected. Configuration files are copied to owner-only snapshots inside the installation directory, used as raw environment files, and removed after the operation. The effective Compose model is materialized, validated again, and checked for stable interpretation before runtime commands use it.

Volumes and networks belong to the installation’s random project name. Explicit global resource names, external resources, host namespaces, container namespace joins, bind mounts, and additional privileges are rejected. Releases relying on these mechanisms must be repackaged. A release must also pin the matching OCI loader when its signed bundle uses local image loading.

The controlled Docker configuration does not inherit registry credentials. Preload approved digest-pinned images using a separately authenticated process when needed, or use the signed local OCI loading path. The installation owner and host administrator remain trusted: rootless operation does not protect secrets from an administrator or a compromised process running as that owner. Obtain installer source and release pins through independently trusted channels; a checksum cannot establish trust in the channel that supplied it.

## Upgrade and recovery

Use `update` with the installation parameters above and `--backup-receipt /path/to/backup-receipt.json`. The signed release must explicitly permit an upgrade from the installed version.

A backup receipt records the current release digest, an encrypted backup file reference, its SHA-256 digest, and confirmation of a completed restore check. Complete that check before issuing the receipt. The installer verifies the record and backup bytes; it does not perform or independently verify the restore exercise.

Example backup receipt:

```json
{
  "release": "CURRENT_MANIFEST_SHA256",
  "encryptedBackupReference": "/home/user/backups/enigm-backup.enc",
  "sha256": "ENCRYPTED_BACKUP_SHA256",
  "restoreDrillPassed": true
}
```

Set `restoreDrillPassed` to `true` only after a successful restore check, and replace the placeholder digests with the verified values.

Use `recover` with the same signed bundle and service references to restart the committed release. Installation and recovery preserve data volumes. Review release compatibility before an upgrade or recovery operation.

## Development

Run the local verification suite:

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile bin/enigm-install bin/enigm-image-load-v2.py
```

The suite verifies signatures, filesystem protections, lifecycle behavior, and OCI integrity with isolated fixtures. Compose materialization tests invoke the installed Compose parser without starting services. Container operations in lifecycle tests use test doubles; validate an actual deployment separately.

Contributions are welcome through pull requests. Keep changes focused, add relevant tests, and use the existing checks before submission.

## Support and security

Use [GitHub issues](https://github.com/enigm-llc/enigm-onprem-installer/issues) for reproducible bugs and improvement requests. Report vulnerabilities through [private vulnerability reporting](https://github.com/enigm-llc/enigm-onprem-installer/security/advisories/new). Never include credentials, signing keys, or private deployment data in public reports.

## License

Copyright 2026 Enigm LLC. Licensed under the [Apache License 2.0](LICENSE).

The license covers the installer source in this repository. Deployment bundles and third-party software retain their own licensing terms. Enigm names and trademarks are not licensed by this source-code license.
