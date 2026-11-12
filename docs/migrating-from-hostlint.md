# Moving from hostlint to vmsctl

hostlint was renamed vmsctl in v0.27.0 ([ADR 0017](adr/0017-rename-to-vmsctl.md)): the name hostlint is also the
name of an unrelated hosting company, which made the project hard to find. Nothing about what the program checks,
its results, tokens, signatures or the server's database changes. What you type changes.

[한국어](migrating-from-hostlint.ko.md)

## What to change

| Before (up to v0.26.0) | Now (v0.27.0 and later) |
|---|---|
| `hostlint scan ...` | `vmsctl scan ...` |
| `/usr/local/bin/hostlint`, `/usr/bin/hostlint` | `vmsctl` (the `.deb` and `.rpm` keep a `hostlint` link for a while; `install.sh` links an old `hostlint` to the new binary; both print that the name is deprecated) |
| `ghcr.io/with-developer/hostlint:0.26.0` | `ghcr.io/with-developer/vmsctl:0.27.0` (the old image stays, and its `:latest` stops at 0.26.0) |
| `uses: with-developer/hostlint@v0.26.0` | `uses: with-developer/vmsctl@v0.27.0` |
| `go install github.com/with-developer/hostlint/cmd/hostlint@...` | `go install github.com/with-developer/vmsctl/cmd/vmsctl@v0.27.0` (`@latest` of the old path stays at v0.26.0) |
| `HOSTLINT_TOKEN`, `HOSTLINT_PACK`, `HOSTLINT_WEBHOOK_URL` | `VMSCTL_TOKEN`, `VMSCTL_PACK`, `VMSCTL_WEBHOOK_URL` |
| `hostlint.yaml`, `/etc/hostlint/hostlint.yaml` | `vmsctl.yaml`, `/etc/vmsctl/vmsctl.yaml` |
| `hostlint-server.db` (the default database file) | `vmsctl-server.db` |
| `requires_hostlint:` in `pack.yaml` | `requires_vmsctl:` |
| `hostlint-scan.service`, `hostlint-agent.service`, `hostlint-server.service` (the unit names in the docs) | `vmsctl-scan.service` and so on; unit names are yours to choose |

The old environment variables, configuration file names and database file name still work. The new name wins when
both are set (`VMSCTL_PACK` replaces `HOSTLINT_PACK` rather than adding to it). A directory that has both `vmsctl.yaml`
and `hostlint.yaml` uses `vmsctl.yaml`, so a fleet that mixes v0.26 and v0.27 hosts can keep both files; the scan
says on standard error which one it did not use. A directory that has both database files is an error: remove or rename
one, or pass `--db`. A scan that finds only `hostlint.yaml` says so on standard error and goes on.

## What stays as it was

These are written into stored data or spoken between programs of different versions, so they keep their names:
host IDs, the signing key format and the signature domain, the `X-Hostlint-*` HTTP headers (including the
webhook's `X-Hostlint-Signature-256`), the token prefixes (`hlt_ing_`, `hlt_api_`, `hlt_opr_`) and the session
cookie. A v0.26 agent can push to a v0.27 server and the reverse; tokens and signed results carry over.

## Things that notice the new name

- **Results and SARIF.** `scan.tool.name` is `vmsctl` (the schema accepts `hostlint` too, so older results stay
  valid). The SARIF tool name is `vmsctl`, so code scanning treats it as a new tool: existing hostlint alerts are not
  closed by it, and a scan with the Action under the new name opens its own.
- **Webhooks.** The text of the message starts with `vmsctl:` instead of `hostlint:`, and the user agent is
  `vmsctl-server`; a receiver that filters on either has to change. The JSON fields, the event `id` and the signature
  header are the same.
- **Pinned old releases.** The Action with `version: v0.26.0` and `install.sh -v v0.26.0` install the old binary under its
  old name (the Action links `vmsctl` to it): it reads only `hostlint.yaml` and the `HOSTLINT_*` variables.
- **Packs.** A pack that has to run on both a v0.26 and a v0.27 binary keeps `requires_hostlint:` (v0.26 rejects the
  new key). Use `requires_vmsctl:` once every host runs v0.27 or later. Editing `pack.yaml` changes the pack's digest.
- **Verifying a release.** Releases up to v0.26.0 are signed by the repository under its old name:
  `cosign verify-blob ... --certificate-identity https://github.com/with-developer/hostlint/.github/workflows/release.yml@refs/tags/vX.Y.Z`
  and `gh attestation verify FILE -R with-developer/hostlint`. From v0.27.0 on the name is `vmsctl`. `install.sh`
  chooses by the version you ask for.
- **Installer.** Pin it to a tag (`.../vmsctl/v0.27.0/install.sh`) as the documentation does: `install.sh` from `main`
  installs the latest release, and installs older ones under their old names.
- **GitHub.** The repository is `with-developer/vmsctl`; GitHub redirects the old address (clones, releases, the
  Action). The project page is now at `https://with-developer.github.io/vmsctl/`; the old address does not redirect.
