# Releasing hostlint

A release is built, signed and published by [`release.yml`](../.github/workflows/release.yml)
when a `v*` tag is pushed. Nothing is built or signed on a laptop. CI builds the same artifacts as
a snapshot on every pull request, so the pipeline is tested before a tag needs it.

## What a release contains

| File | What it is |
|---|---|
| `hostlint_<version>_linux_{amd64,arm64}.tar.gz` | The static binary, `LICENSE` and `README.md` |
| `hostlint_<version>_{amd64,arm64}.deb`, `hostlint-<version>-1.{x86_64,aarch64}.rpm` | Packages installing `/usr/bin/hostlint` |
| `<file>.sbom.json` | An SPDX SBOM for each archive and package (syft) |
| `checksums.txt` | The SHA-256 of every file above |
| `checksums.txt.sigstore.json` | Sigstore bundle for `checksums.txt`: keyless, signed by `release.yml` at the tag |

Every file in `checksums.txt` also gets a build provenance attestation (`gh attestation verify`).
The release notes list the `feat:` and `fix:` commits since the previous tag; `docs:`, `test:`,
`ci:`, `chore:` and `refactor:` commits are left out.

[`install.sh`](../install.sh) installs the archive for the machine's architecture. It refuses an
archive whose SHA-256 does not match `checksums.txt`. When cosign is installed, it first verifies
the signature of `checksums.txt` against the release workflow's identity for that tag.

## Checklist

Before tagging:

1. The milestone's issues are closed or moved to a later milestone.
2. `main` is green (`ci-ok`, which includes the `release-snapshot` job).
3. The docs describe what is being released: README (and its Korean translation) and the
   ROADMAP status.
4. Choose the version (semver; before 1.0, a minor version for features and a patch version for
   fixes).
5. **`v0.1.0` only:** the owner approves the exact commit. Open a `needs-approval` issue naming
   the SHA, and tag only that commit.

Tag and push. The tag must point at a commit on `main`:

```sh
git fetch origin
git tag -a v0.1.0 -m "hostlint v0.1.0" <commit on main>
git push origin v0.1.0
```

A release candidate and its release may share a commit: the workflow builds the tag that was
pushed (`GORELEASER_CURRENT_TAG`). That was not always so: git sorts `v0.1.0-rc.1` after
`v0.1.0`, GoReleaser took the candidate for the version of the `v0.1.0` build, and the
workflow failed uploading files the candidate's release already had. `v0.1.0` was tagged,
never released, and the first release is the next patch version.

The workflow then:

1. refuses a tag whose commit is not on `main`, and runs the tests;
2. builds the binaries, archives, packages and SBOMs, signs `checksums.txt` with cosign (GitHub
   OIDC), and uploads everything to a **draft** release;
3. runs [`scripts/check-release.sh`](../scripts/check-release.sh): checksums, SBOMs, archive and
   package contents, and `install.sh` installing the release (verifying its signature) and
   refusing a tampered archive;
4. verifies the signature, attests build provenance for every file, and publishes the draft.

After it is published:

- From a clean machine, install with `install.sh` (with cosign installed) on Ubuntu and on Rocky
  Linux, and check `hostlint version`.
- Verify the signature and provenance as the release notes show.
- Check that `go install github.com/with-developer/hostlint/cmd/hostlint@<version>` works.
- Announcements (Hacker News, Reddit, GeekNews, social media) need the owner's approval.

## When something goes wrong

- **A pushed tag is permanent.** The Go module proxy may already have it. Never delete or move a
  tag. Fix forward with the next patch version.
- **Failure before publishing.** The release stays a draft. A transient failure can be re-run. If
  the fix needs a code change, delete the draft, fix `main`, and tag the next patch version.
- **A published release is broken.** Mark it as a pre-release with a note pointing to the fixed
  version. Do not delete its files: people may have verified or pinned them.

## Locally

`make snapshot` builds every artifact into `dist/` without publishing or signing. SBOMs need
[syft](https://github.com/anchore/syft); without it, use `make snapshot SNAPSHOT_SKIP=sign,sbom`.
`SKIP_SBOM=1 scripts/check-release.sh dist` checks the result on Linux, for example in a container.

## Not yet

- Signed apt and yum repositories. They need a signing key held as a secret, which requires the
  owner's approval. Until then, packages are verified through `checksums.txt` and its signature.
- Container images and Homebrew.
