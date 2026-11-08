# Running hostlint as a container

Each release is also published as an image, `ghcr.io/with-developer/hostlint`, for linux/amd64 and linux/arm64:
the static binary on a minimal base (CA certificates, no shell, no package manager; about 40 MB). hostlint only
reads, so the host's root is mounted read-only and scanned the way `--root` scans a mounted filesystem:

```sh
docker run --rm -v /:/host:ro ghcr.io/with-developer/hostlint:0.26.0 scan --root /host
docker run --rm -v /:/host:ro ghcr.io/with-developer/hostlint:0.26.0 scan --root /host --fail-on high --format json > web-01.json
```

Use a version tag in anything you keep (`:0.26.0`); `:latest` follows the newest release and never a pre-release.

## What it scans

The files of the host (configuration, accounts, permissions, packages), through the mount. What exists only in a
running system (kernel parameters in `/proc/sys`, listening sockets, the effective `sshd -T` value) is not seen from a
container, so those checks report `ERROR` or `NOT_APPLICABLE` or use the file defaults, exactly as for
`--root /mnt/image`. For a complete scan of a live host install the binary (`install.sh`, `.deb`, `.rpm`) and run it
there.

The image is a good fit for CI, for scanning a mounted disk or a snapshot, and for sending results to a fleet
server:

```sh
docker run --rm -v /:/host:ro -v /etc/hostlint:/etc/hostlint:ro ghcr.io/with-developer/hostlint:0.26.0 \
  scan --root /host --fail-on none --push https://hostlint.example.org:8443 --token-file /etc/hostlint/token
```

A scan of a mounted root reports the host name the mounted system has (`/host/etc/hostname`), not the container's.

## Verifying the image

The image is signed by the release pipeline (Sigstore keyless) and carries build provenance and an SBOM:

```sh
cosign verify ghcr.io/with-developer/hostlint:0.26.0 \
  --certificate-identity-regexp '^https://github\.com/with-developer/hostlint/\.github/workflows/container\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/with-developer/hostlint:0.26.0 --repo with-developer/hostlint
```

The binary inside is the one of the release archive (`checksums.txt` is verified, then each file, before the image is
built); it prints the version of the tag it is named for. The image writes nothing, so `--read-only`
is fine.
