# 0017. The project is renamed from hostlint to vmsctl

- Status: Accepted (the owner chose the name `vmsctl` on 2026-11-09)
- Date: 2026-11-09

## Context

`hostlint.com` is an existing company in the same sector (managed hosting). The name made the project hard to find and
easy to confuse before it had any users to speak of. The owner decided to rename it. The search that led to the name:

- "Vulnerability Management System" and its acronym VMS are generic: government and vendor products, OpenVAS and
  others use them, and `vms` itself is taken on npm, PyPI and crates.io and as a `.com`, `.net` and `.org` domain.
- `vmsctl` is free on those registries, on GitHub and as a domain, and it keeps the link to the owner's first
  project (VMS, 2023-2024; hostlint is its rewrite). Trademarks were not checked.
- In Korean, KISA calls configuration weaknesses "취약점" (vulnerabilities), so "서버 취약점 점검·관리" describes the
  product to Korean readers; in English the honest description is a *security configuration audit*, not
  "vulnerability management" (which means tracking CVEs). The name is `vmsctl`; the descriptions differ by language.

## Decision

Everything the user types or reads becomes `vmsctl`: the binary, the Go module path and repository
(`github.com/with-developer/vmsctl`), the release archives, `.deb` and `.rpm` packages, the container image
(`ghcr.io/with-developer/vmsctl`), the GitHub Action, the installer, the dashboard, the documentation and the project
page. It ships as **v0.27.0**, with nothing else in it.

**Names kept, because they are identifiers that stored data or other software depend on:**

| Kept | Why |
|---|---|
| The key of the host ID (`hostlint host id v1`) | A host ID is an HMAC of the machine ID under this key. Changing it would give every machine a second ID and refuse every known host name ("a known name never gets a second host ID"). |
| The signing domain (`hostlint result v1`) | Stored signatures verify against it; a change would fail `server verify` for every signed result. |
| HTTP header names (`X-Hostlint-*`), including the webhook signature header | An old agent talks to a new server and the other way round; webhook receivers verify the header by name. |
| Token prefixes (`hlt_ing_`, `hlt_api_`, `hlt_opr_`) and the `hl_session` cookie | Issued tokens and sessions keep working. |
| The audit chain and database schema | No migration is needed. |
| The `localStorage` keys of the dashboard (`hostlint.theme`, `.lang`, `.profile`) | They are not data, but renaming them only resets everyone's saved choices. |
| `docs/adr/` and the earlier changelog entries | They record what was decided under the old name. |

Tests pin the first four (a known host ID key, a known signature, the header and cookie names, the token prefixes), so
a later search and replace of the old name cannot change them silently.

Renamed although they look like identifiers, because nothing stored or matched depends on them: the TLS certificate
name of a newly generated server certificate (clients pin the public key), the demo seed, the temporary file of a
written report, the `Content-Disposition` file name of the CSV, `WWW-Authenticate realm`, the user agent of the
server's webhook, and the text of webhook messages (`vmsctl: web-01 got worse ...`; a receiver that filters on the
old prefix has to change, which the migration guide says). The SARIF tool name changes too: GitHub code scanning keys
its alerts by tool name, so alerts of the old name are not closed by a scan under the new one.

**Names accepted both ways for the transition** (the new name wins when both are set; an empty variable counts as unset):

- The environment variables `VMSCTL_TOKEN`, `VMSCTL_PACK`, `VMSCTL_WEBHOOK_URL` are read first; `HOSTLINT_TOKEN` and
  `HOSTLINT_WEBHOOK_URL` work as before. (The installer's `VMSCTL_DOWNLOAD_URL`, which only CI uses to test a snapshot
  build, has no old-name fallback.) `HOSTLINT_PACK` is
  a list of directories like `VMSCTL_PACK`; when `VMSCTL_PACK` is set it wins and the old list is ignored, so a stale
  old variable never loads a second pack.
- The configuration file is looked up per place: `vmsctl.yaml` or `hostlint.yaml` in the working directory, then
  `/etc/vmsctl/vmsctl.yaml` or `/etc/hostlint/hostlint.yaml`. A place that has both names uses the new one and says on
  standard error that the old one is not used: a release before v0.27.0 reads only the old name, so a fleet that
  mixes both keeps both files. Finding only the old name prints a note too.
  The trust rules (owner, no group or other write access) are the same for both names.
- A policy pack may say `requires_vmsctl` or the old `requires_hostlint` (not both). A release before v0.27.0 reads
  only the old key, so a pack that must run on both keeps it.
- The server's database default is `vmsctl-server.db`. Without `--db`, when only `hostlint-server.db` exists in the
  working directory the server keeps using it and says so; when both exist it refuses and asks for `--db` (`server demo`
  keeps its data in memory and is not affected).
- The result document's `scan.tool.name` is `vmsctl`; the schema accepts `hostlint` too, so results written by older
  releases stay valid. Nothing in the code compares the name, so old and new agents and servers work together.
- `install.sh` installs a release older than v0.27.0 under its old name (archive, binary and signing identity),
  and for a new one links an existing `hostlint` binary in the same directory to `vmsctl`.
- The `.deb` and `.rpm` packages replace `hostlint` (`Replaces`, `Provides` and, for the `.deb`, `Conflicts`) and ship a
  `/usr/bin/hostlint` link to `vmsctl` (all three declarations are in the `.rpm` too; installing over `hostlint` was
  tested with dnf on Rocky 9 and dpkg on Ubuntu 24.04); running the program under the name `hostlint` in a terminal
  says the name is deprecated (nothing is printed for cron and units, whose standard error may be mailed or read as
  a failure). The link goes away in a later release. `install.sh` replaces an existing `hostlint` only when it is a
  file that reports itself as hostlint.

## What cannot be undone

Go module tags and the versions of `github.com/with-developer/hostlint` stay in the module proxy for good, and the
old container image stays on ghcr.io: they keep working but are no longer updated. Renaming the GitHub repository
makes GitHub redirect the old repository URLs (clones, releases, `uses:` of the Action), but the redirect ends if a
repository named `hostlint` is ever created again, so the account must not reuse the name. The project page moves
from `/hostlint/` to `/vmsctl/`; GitHub Pages does not redirect it.

## Consequences

- Users of v0.26.0 and earlier change the binary name in scripts, units and CI, and move to the new image and Action
  names; the release notes of v0.27.0 say so and list the pairs. Nothing about stored data, tokens, host IDs, signatures or
  the server database needs migrating. [docs/migrating-from-hostlint.md](../migrating-from-hostlint.md) lists the pairs.
- The name no longer says "lint": the tagline ("eslint for Linux servers", "a security configuration audit") has to
  carry that.
- `ghcr.io/with-developer/hostlint:latest` and `@latest` of the old Go module path stop at v0.26.0 without an error; the
  migration guide and the release notes say so. The container workflow refuses a manual build of a tag older than
  v0.27.0, whose archives and signing identity carry the old name.
- The signing identity is the repository's name, so the repository is renamed before v0.27.0 is tagged.
