# hostlint

[![CI](https://github.com/with-developer/hostlint/actions/workflows/ci.yml/badge.svg)](https://github.com/with-developer/hostlint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**eslint for Linux servers.** One static Go binary that checks a host's security configuration
against a hardening baseline and reports a result for every control — with the evidence behind
it — and a dashboard that shows the whole fleet.

[한국어](README.ko.md)

![Animated terminal: hostlint scan lists failed controls with the evidence behind each](docs/demo/scan.gif)

```text
$ sudo hostlint scan
hostlint v0.2.1 · kisa-2026 · web-01 (Debian GNU/Linux 12 (bookworm))

✗ FAIL   U-01   Restrict direct remote root login [high]
    ✗ ssh.permit-root-login — SSH does not allow direct root login
        "yes" (explicit); expected one of [no]  /etc/ssh/sshd_config:33
    ? services.review-remote-root-login — Review root login through telnet and other remote terminal services
        Check that root cannot log in through the service (pam_securetty in its auth stack and no pts/N line in /etc/securetty, where that module exists). Better, turn the service off.
        telnet (inetd) at /etc/inetd.conf:42
? MANUAL U-07   Remove unneeded accounts [low]
    ? accounts.review-login-accounts — Review accounts that can log in
        Confirm that every listed account is still needed, especially accounts of people who have left. Default accounts such as lp, uucp or games appear here only when they were given a login shell, which they should not have.
        root (uid 0, /bin/bash)
✗ FAIL   U-18   Ownership and permissions of /etc/shadow [high]
    ✗ files.shadow-perms — /etc/shadow is owned by root and readable by root only
        /etc/shadow: root:shadow 0640 — mode 0640 exceeds 0400
✗ FAIL   U-52   Telnet is off [medium]
    ✗ services.no-telnet — Telnet is not started
        telnet (inetd, /usr/sbin/telnetd) at /etc/inetd.conf:42
...

kisa-2026: 67 controls — 10 FAIL, 11 MANUAL, 29 PASS, 17 NOT_APPLICABLE
```

The output above is abridged, from a Debian 12 container with `PermitRootLogin yes` and an inetd
telnet service added (the host name is shortened).

## A dashboard for the whole fleet

Hosts scan themselves and push the result to `hostlint server`, which keeps the history and shows the
fleet in a web dashboard (English and Korean, light and dark, fits a phone):

![A tour of the hostlint dashboard: overview, hosts, a host with evidence and how to fix it, a control, the matrix, Korean](docs/demo/dashboard-tour.gif)

```sh
hostlint server demo      # a made-up fleet of twelve hosts, nothing scanned, nothing written: open the address it prints
```

- **Pass rate over time** for the whole fleet (7, 30 or 90 days), and a trend line on every host.
- **What fails most, and what just got worse:** the controls that fail on most hosts, and the regressions of the last scans.
- **The evidence behind every result,** the file and the line, with **how to fix it** next to each failure.
- **A matrix of every control on every host,** one click from a cell to the host.
- **One profile at a time** (KISA, essentials, your own policy pack), with host OS and labels in the list.
- **Images from CI:** `scan --image-tar app.tar --push` gives every image its own page: one history, a tag for every build.
- **Scan now:** an agent on a host dials out and scans when someone asks, with a profile the host allows; the
  server never connects to a host.
- **Signed results:** every stored result can be checked against the key its host signs with.

Try it in ten seconds with the demo above, or send real results: [docs/fleet.md](docs/fleet.md).

> 🚧 **Early release.** Expect rough edges in the less common setups, and report them. See the
> [roadmap](docs/ROADMAP.md) and the [release history](docs/RELEASING.md).

## Why hostlint

- **Every verdict shows its evidence** — the value, the file and line it came from, and whether it
  is set explicitly or a built-in default. No more "FAIL" without knowing why.
- **No false PASS.** If something cannot be decided — an unreadable file, a collector that timed
  out, a walk that hit its limit — the result is `ERROR` or `MANUAL`, never a guessed `PASS`.
  Settings are read the way the programs read them: PAM stacks are evaluated like libpam does,
  `login.defs` like shadow-utils, startup files in the order bash reads them.
- **Observation only.** A scan never changes the host. Rules are data, not scripts: they cannot
  run commands. Password hashes, keys and tokens never appear in the output.
- **Standards as overlays.** Checks are written once and mapped to controls; the first profile is
  the 2026 edition of Korea's KISA CII technical vulnerability guide (Unix U-01–U-67).
- **Live hosts and images.** Scan the running system, a root filesystem mounted elsewhere
  (`--root`), or a container image straight from the archive `docker save` wrote (`--image-tar`).
- **A fleet view without an agent to trust.** Hosts push; the server never connects, keeps the history
  and signed results, and shows trends, regressions and a matrix ([above](#a-dashboard-for-the-whole-fleet)).
- **Built for pipelines.** Terminal table, JSON (with a schema), SARIF and JUnit; the exit code
  follows the severity you choose. A failed check says how to fix it: in `explain`, the JSON
  (`remediation`), SARIF (the rule's help, which code scanning shows with the alert), the Markdown summary,
  the HTML report and the dashboard.

## Quick start

Install a release (Linux, amd64 or arm64). `install.sh` verifies the SHA-256 of the archive and,
when `cosign` is installed, the Sigstore signature of the checksums:

```sh
curl -fsSLO https://raw.githubusercontent.com/with-developer/hostlint/v0.23.0/install.sh
sudo sh install.sh -v v0.23.0     # read it first; without root, add -b DIR to choose where it goes
sudo hostlint scan
```

Or run the image (the host's root mounted read-only; [docs/container.md](docs/container.md)):

```sh
docker run --rm -v /:/host:ro ghcr.io/with-developer/hostlint:0.21.0 scan --root /host
```

Each [release](https://github.com/with-developer/hostlint/releases) also has `.deb` and `.rpm`
packages, SBOMs and build provenance (`gh attestation verify FILE -R with-developer/hostlint`).
To build instead (Go 1.26 or later; the binary itself has no dependencies):

```sh
go install github.com/with-developer/hostlint/cmd/hostlint@v0.23.0
sudo "$(go env GOPATH)/bin/hostlint" scan
```

Without root, checks that need protected files (such as `/etc/shadow`) report `ERROR`.

```sh
# Machine-readable results
sudo hostlint scan --format json --output web-01.json

# A mounted root filesystem (an image, a VM disk); live-only checks report ERROR or NOT_APPLICABLE
sudo hostlint scan --root /mnt/image

# A container image, from the archive docker save wrote: nothing is mounted, run or written
docker save app:1.4 -o app.tar && hostlint scan --image-tar app.tar --fail-on high

# CI: fail only on high-severity controls (GitHub Action, GitLab and others: docs/ci.md)
sudo hostlint scan --fail-on high --format junit --output hostlint.xml

# One HTML report for many hosts: a single file that makes no network requests
hostlint report results/*.json --output report.html

# What a failed control means and how to fix it
hostlint explain U-02 ssh.permit-root-login

# What changed since the last scan: new failures, fixes, and the checks behind them
hostlint diff before.json after.json
hostlint diff baseline.json current.json --fail-on-regression   # exit 1 when a control got worse

# A fleet server that collects results from many hosts (early; see docs/fleet.md)
hostlint server run --db server.db --listen :8443
sudo HOSTLINT_TOKEN=hlt_ing_... hostlint scan --push https://hostlint.example.org:8443

# Pick the profile, tighten thresholds and accept findings you decided to live with
sudo hostlint scan --config hostlint.yaml
```

The checks that decide each result are listed in the output; `--config` and the file format are
described in [docs/configuration.md](docs/configuration.md).

| Flag | Meaning |
|---|---|
| `-p, --profile` | Profile to check against (default `kisa-2026`); repeat it to check several at once |
| `-f, --format` | `table`, `json`, `sarif`, `junit` or `markdown` (for a job summary or a comment) |
| `-o, --output` | Write the report to a file |
| `--fail-on` | Exit with status 1 when a control of this severity or higher fails or cannot be checked (`ERROR`): `low` (default), `medium`, `high`, `none` |
| `--pack DIR` | Load a policy pack: your own checks and profiles ([docs/packs.md](docs/packs.md)); select its profile with `-p` |
| `--root` | Scan a filesystem mounted at this directory (it must hold an operating system) |
| `--image-tar` | Scan the filesystem of a container image from this archive ([docs/images.md](docs/images.md)); with `--push` the image is an asset of its own on the fleet server, `--name` gives it a name |
| `--config` | Configuration file (default: `./hostlint.yaml`, then `/etc/hostlint/hostlint.yaml`, if present) |
| `--label key=value` | Add a label to the host in the report |
| `--color` | `auto` (default), `always` or `never` |
| `-v, --verbose` | Also list passing and not-applicable controls |

## Results

| Status | Meaning |
|---|---|
| `PASS` | The control is met, and the evidence shows why |
| `FAIL` | The control is not met; the evidence lists what fails |
| `MANUAL` | A person has to decide; the facts to review are shown |
| `NOT_APPLICABLE` | The control does not apply (for example, the service is not installed) |
| `ERROR` | It could not be decided reliably; the reason is shown |
| `WAIVED` | A waiver in the configuration accepted a `FAIL` or `MANUAL` result; the original status and evidence are kept (see [docs/configuration.md](docs/configuration.md)) |

A control's status is the worst of its checks: `FAIL` > `ERROR` > `MANUAL` > `WAIVED` >
`PASS` > `NOT_APPLICABLE`.

Exit codes: 0 when nothing failed at or above `--fail-on`, 1 when something did, 2 for a usage error
or a scan that could not run, 130 when interrupted.

## What it checks

The `kisa-2026` profile maps all 67 Unix controls of the KISA guide (2026 edition); the
[rule reference](docs/rules.md) lists every control with the checks, parameters and fixes behind it:

- **Accounts (U-01–U-13):** remote root login, password length, complexity and aging, lockout,
  password file protection, UID 0, `su` restriction, session timeout, password hashing.
- **Files and directories (U-14–U-33):** `PATH`, ownership and permissions of system files,
  start-up scripts, set-ID programs, world-writable files, files in `/dev`, `.rhosts`, `umask`,
  home directories — including a bounded walk of local filesystems.
- **Services, patching and logging (U-34–U-67):** finger, r-services, telnet, tftp, NFS, NIS,
  SNMP and other legacy services (enabled units, running units, init scripts, inetd and xinetd),
  SNMP community strings and access (read from `snmpd.conf`, never copied into the result), Postfix
  open relay and VRFY, BIND zone transfers and updates, NFS exports, vsftpd banner, TLS, root login and anonymous access, Samba guest shares, cron and sudoers permissions, time synchronization.

Controls that need a person's judgment (accounts to keep, banners, logging policy, patch level, who may
reach a service) and the settings of servers whose configuration is not parsed yet (mail servers other
than Postfix, DNS servers other than BIND, FTP servers other than vsftpd) are `MANUAL`, with the facts to
review listed under them, and `NOT_APPLICABLE` where the software is not running. Supported targets: Ubuntu 22.04/24.04/26.04, Debian 12/13, RHEL-compatible 9/10
(Rocky Linux, AlmaLinux), Amazon Linux 2023, and CentOS/RHEL 7 best-effort; other versions are scanned
best-effort and marked as such.

The `essentials` profile (`--profile essentials`) is a short baseline that most Linux hardening guides
agree on, outside any national standard: SSH (no root login, no password logins, no empty passwords, few
attempts, no X11 forwarding, and no `Match` block that undoes them), UID 0 and password files, password
length, hashing, aging and lockout, `su` and sudo, cron, legacy remote services, risky file permissions,
time synchronization and the kernel parameters that matter (address randomization, `kptr_restrict`, ICMP redirects,
reverse path filtering, SYN cookies, ...). It has 22 controls with its own IDs (`ES-01`–`ES-22`), mostly over the checks
of the other profile plus eight new SSH checks and eleven of kernel parameters; the kernel parameters do not apply to a
container image, which has no kernel of its own.

Your own standard goes into a [policy pack](docs/packs.md): a directory of checks and profiles in the same
YAML format, tested with `hostlint pack test`, reviewed with `hostlint pack show`, used with `hostlint scan
--pack`. A pack adds no capability (it cannot run anything or read anything a built-in check cannot), and its
results name the pack and its digest.

Titles and descriptions are hostlint's own; profiles reference control IDs only.

## The dashboard in pictures

| Overview | Hosts, with trend, OS and labels |
|---|---|
| ![The overview of the dashboard: pass rate, pass rate over time, what fails most](docs/demo/dashboard-overview.png) | ![The list of hosts](docs/demo/dashboard-hosts.png) |

| A host: its controls, the evidence and how to fix each failure | Matrix of every control on every host (dark) |
|---|---|
| ![A host](docs/demo/dashboard-host.png) | ![The matrix](docs/demo/dashboard-matrix.png) |

| Images that CI pushed: one history per image, a tag for every build |
|---|
| ![The list of images](docs/demo/dashboard-images.png) |

How it works, the API, signing, notifications and the agent: [docs/fleet.md](docs/fleet.md).

## Principles

hostlint is built around a few rules that are not negotiable — see the [vision](docs/VISION.md)
and the [architecture decisions](docs/adr/):

1. Observation only — no code path changes the scanned host ([ADR 0004](docs/adr/0004-observation-only.md)).
2. Secrets never leave the host.
3. No false PASS ([ADR 0006](docs/adr/0006-rule-format-evaluation-results.md)).
4. Clean-room content.
5. Boring to install and run.

## Status

hostlint is under active development. The KISA 2026 profile (U-01–U-67), the
collectors, the terminal, JSON, SARIF, JUnit and multi-host HTML outputs, the configuration file
with waivers, the release pipeline (signed archives, packages, SBOMs and `install.sh`), a
container test matrix over every supported distribution, scanning container images
([docs/images.md](docs/images.md)), a GitHub Action ([docs/ci.md](docs/ci.md)) and the fleet server with its
dashboard, signed results and webhook ([docs/fleet.md](docs/fleet.md)) are in place, and v0.23.0 is the
latest release. The outbound agent for on-demand scans ([docs/fleet.md](docs/fleet.md)) and a container image
([docs/container.md](docs/container.md)) are in place too. See the [roadmap](docs/ROADMAP.md).

## License

[Apache-2.0](LICENSE)
