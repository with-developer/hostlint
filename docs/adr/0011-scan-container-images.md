# 0011. Scanning container images from a tar

- Status: Accepted
- Date: 2026-11-07

## Context

Golden images are a first-class target (ADR 0008): `--root` scans a mounted root, where nothing runs and
no command may be run. A container image is the same kind of target, but it is not a directory: it is a
stack of layer tarballs, and mounting one needs a container engine or root privileges. DevOps and SRE
engineers (VISION) want to check an image in CI, before it is deployed, with nothing but the file `docker
save` or `skopeo copy ... oci-archive:` wrote.

## Decision

- `hostlint scan --image-tar FILE` scans the merged filesystem of an image archive, with the same checks
  and the same result document as `--root`. The target is a non-live root (`target.kind` stays `root`,
  `target.root` is `image:<reference or file name>` and the host name is the reference, cleaned to printable characters),
  so no check that needs a running system (sockets, commands, `/proc`) applies, and no schema change is
  needed.
- **Strict loader.** The archive is untrusted. Anything ambiguous, over a limit or possibly different
  from what a container runtime sees refuses the whole scan; a partial filesystem is never scanned,
  because absent-file checks would pass on it. Entry names that climb out of the image, an unsupported
  entry type, a link loop in a parent path, a hard link to nothing, a digest that does not match, a
  `os` other than linux, more than one image or platform in the archive, layers that are not in the
  archive and layers in a compression the loader does not read (zstd, xz, bzip2) are all refusals.
- **Formats** (standard library only): the `docker save` layout (`manifest.json`, layer files, links to
  shared layers resolved inside the archive) and OCI layouts (`index.json`, `blobs/sha256/...`), layers
  uncompressed or gzip, the archive itself a plain tar read from a regular file (a table of its entries is
  made first, because `manifest.json` comes last). Layers are checked against the digests of the manifest
  and of the image configuration (`diff_ids`).
- **A tree of its own.** The merged filesystem is `hostfs.ImageFS`, built by `hostfs.ImageBuilder`:
  a tree of directories with maps (a directory listing costs its children, not the whole image, which
  matters for the filesystem walk), not `MemFS`, whose flat map is for test fixtures, scans every node
  per listing and panics on malformed input. It is immutable once built, so collectors may read it
  concurrently, and its builder returns errors instead of panicking.
- **Layers.** Applied in order. A whiteout or an opaque directory removes only what lower layers have,
  wherever it is in its layer (each node knows its layer). A file over a directory replaces the whole
  directory, a directory entry merges into an existing directory, parents are created as `0755 root:root`
  and symbolic links in parents are followed inside the image. Hard links share the contents (charged to
  the budget once) and take mode and owner from the target; a hard link to a denylisted file stays
  denied. Owners are the numeric IDs, never the names. Files are retained in memory up to 1 MiB, and the
  package databases up to what the collectors read; a larger file is metadata only and reads as "too
  large", never as empty or absent (a size of zero would read as a masked service). Limits: 1,000,000
  nodes, 3,000,000 entries, 16 GiB unpacked, 4096-byte paths, 255-byte names, 512 MiB of retained
  contents; hitting one refuses the scan.
- **Host.** `hostfs.NewImageHost`: not live, no command can run, the mount table is known to be empty,
  and the walk's exclusions of `/proc`, `/sys` and container storage do not apply (an image can hold
  files there; only `/dev` is walked on its own).
- Nothing is written to disk and nothing is run. Reading the archive is the only access, and the
  sensitive-path denylist applies to the merged filesystem like to any other.
- An image has no host identity (no machine ID, no kernel hostname), so `--push` is refused for an image
  scan until the fleet server has a place for one.

## Consequences

- A CI pipeline can fail a build on an image with `hostlint scan --image-tar app.tar --fail-on high`.
  The end-to-end tests scan the stock image of every supported distribution from its archive and require
  the same status for every control and check as the scan inside a running container.
- Memory use is bounded but real (up to 512 MiB of file contents and the tree); the limits are in
  docs/images.md.
- An image PASS means the image filesystem is configured so, not that the container is hardened: what the
  runtime adds (`/etc/hosts`, volumes, user, capabilities, seccomp) is not in the layers. Alpine and
  images without a package database report `ERROR` for the package checks; `scratch` and distroless
  images (no `os-release`) are refused.
- File capabilities (`security.capability`) are not modeled, so a `cap_setuid` binary is invisible to the
  set-ID checks.
- Streaming from a registry, zstd layers, directory-form OCI layouts and pushing image scans to the fleet
  server are later decisions.
