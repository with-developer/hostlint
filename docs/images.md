# Scanning container images

`vmsctl scan --image-tar FILE` checks the filesystem of a container image from the archive that
`docker save` (or `skopeo copy ... oci-archive:FILE`) wrote, with the same checks and the same result
document as a scan of a host or of a mounted root (`--root`). Nothing is mounted, run or written, and no
container engine, daemon or registry is involved:

```sh
docker save app:1.4 -o app.tar
vmsctl scan --image-tar app.tar --fail-on high --format sarif --output vmsctl.sarif
```

The report names the image: `host.hostname` is its reference (the first tag of the archive, else the file
name) and `scan.target.root` is `image:<reference>`, and `scan.target.kind` is `root`, as for `--root`.

## What an image scan covers

The filesystem the layers make, as a container starts from it. Like any scan of a root that is not
running, it cannot know the live state: sockets, running services and commands report `NOT_APPLICABLE`
or `ERROR` as with `--root`. It does not see what the runtime adds or decides: `/etc/hosts`,
`/etc/resolv.conf`, mounted volumes, the user the container runs as, capabilities, seccomp and a
read-only root filesystem are not in the layers. A pass means "the image filesystem is configured like
this", not "the container is hardened".

An image and a container made from it agree: the end-to-end tests scan the stock image of every supported
distribution from its archive and compare every control and check with the scan inside a running
container.

Many controls are about a host that runs services and has people logging in: a time synchronization service,
account lockout, password aging. A container image does not run them (its host does), so such controls usually
`FAIL` for an image although they are not a defect of it. Choose what you gate on: `--fail-on high`, a
[waiver](configuration.md#waivers) with a reason for the controls that are the host's job (a waiver for an image
names the image reference as the host name: `hosts: ["app:*"]`), or a [policy pack](packs.md) with the controls
that matter for your images. The kernel parameters, the firewall and the automatic updates of the `essentials` profile do not apply to an image.

Some images cannot be judged and are refused or report `ERROR`:

- An image without an operating system (`scratch`, most distroless images: no `os-release`) is refused,
  because an absent file would read as a pass.
- Alpine (no `apk` reader) and images without a package database (distroless, `ubi-micro`) report `ERROR`
  for the package checks.

## Archives it reads

- `docker save` archives, and OCI layouts (`index.json`, `blobs/sha256/...`), with layers uncompressed or
  gzip. The archive itself must be a plain tar: unpack a `.tar.gz` first.
- One image, for one platform, per archive. An archive that holds several images or a multi-platform
  index is refused: save one (`docker save --platform linux/amd64`, or `skopeo copy --override-arch`).
- Only `linux` images. zstd, xz and bzip2 layers are refused with a message, not skipped; layers that
  are not in the archive (URLs) too.
- The digests are checked: every layer against the digest in the manifest (OCI) and the one in the image
  configuration, so a damaged or altered archive is refused.

## It is untrusted input

The archive can be hostile, so the loader is strict. Anything ambiguous, over a limit or different from
what a container runtime would see refuses the scan with an error: a partial filesystem would make
checks for absent files pass.

- Entry names are cleaned like a runtime does; a name that climbs out of the image is refused.
  Symbolic links resolve inside the image, never outside it. Hard links take mode and owner from the file
  they link to, and a hard link to a file on the sensitive-path denylist is still denied.
- Layers are applied in order: whiteouts (`.wh.NAME`) and opaque directories (`.wh..wh..opq`) remove what
  the layers before had, wherever they are in the layer; what the same layer added stays.
- Limits: 1,000,000 files, 3,000,000 archive entries, 16 GiB unpacked, paths of 4096 bytes and names of
  255 bytes, and 512 MiB of file contents in memory.
- File contents are kept in memory for files up to 1 MiB, and for the package databases
  (`/var/lib/dpkg/status`, the rpm database) up to what the collectors read of them. A larger file is
  kept as metadata; reading it fails as "too large", never as "absent", so a check that needs it reports
  `ERROR` or `MANUAL` instead of passing.

## Sending the result to a fleet server

An image is an asset of its own on a [fleet server](fleet.md), next to the hosts: the dashboard has an **Images** list, and an
image is never "stale" (nothing reports for it on a schedule) and not one of the fleet's hosts in its numbers.

```sh
docker save ghcr.io/acme/app:1.4 -o app.tar
VMSCTL_TOKEN=hlt_ing_... vmsctl scan --image-tar app.tar --push https://vmsctl.example.org:8443 --fail-on high
```

The image goes by its repository (`ghcr.io/acme/app`: the reference of the archive without its tag), so the tags of one
image are one history: every scan records the tag and the image ID (the digest of its configuration). An archive that names
no image (saved without a tag) needs `--name ghcr.io/acme/app`, and `--name` overrides the name of a tagged one. The token
of CI is bound to a prefix, so one token serves an organization and no further:

```sh
vmsctl server token create --name ci --host 'ghcr.io/acme/*'
```

A name is a host or an image, never both, and an image has no host ID. Results can be signed like any other (`--sign-key`).

## Not yet

Streaming from a registry, zstd layers, a directory-form OCI layout, and file capabilities
(`security.capability`), which the set-ID checks cannot see in an image.
