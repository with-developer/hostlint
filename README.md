# hostlint

[![CI](https://github.com/with-developer/hostlint/actions/workflows/ci.yml/badge.svg)](https://github.com/with-developer/hostlint/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**eslint for Linux servers.** One static Go binary that checks a host's security configuration
against a hardening baseline and reports a result for every control — with the evidence behind
it.

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

> 🚧 **Early release.** v0.1.1 is the first release (v0.1.0 exists as a tag only; its release
> build failed, see [docs/RELEASING.md](docs/RELEASING.md)). Expect rough edges in the less
> common setups, and report them. See the [roadmap](docs/ROADMAP.md).

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
- **Live hosts and images.** Scan the running system, or a root filesystem mounted elsewhere
  (`--root`) such as a golden image in CI.
- **Built for pipelines.** Terminal table, JSON (with a schema), SARIF and JUnit; the exit code
  follows the severity you choose.

## Quick start

Install a release (Linux, amd64 or arm64). `install.sh` verifies the SHA-256 of the archive and,
when `cosign` is installed, the Sigstore signature of the checksums:

```sh
curl -fsSLO https://raw.githubusercontent.com/with-developer/hostlint/v0.5.0/install.sh
sh install.sh -v v0.5.0          # read it first; add -b DIR to choose where it goes
sudo hostlint scan
```

Each [release](https://github.com/with-developer/hostlint/releases) also has `.deb` and `.rpm`
packages, SBOMs and build provenance (`gh attestation verify FILE -R with-developer/hostlint`).
To build instead (Go 1.26 or later; the binary itself has no dependencies):

```sh
go install github.com/with-developer/hostlint/cmd/hostlint@v0.5.0
sudo "$(go env GOPATH)/bin/hostlint" scan
```

Without root, checks that need protected files (such as `/etc/shadow`) report `ERROR`.

```sh
# Machine-readable results
sudo hostlint scan --format json --output web-01.json

# A mounted root filesystem (an image, a VM disk); live-only checks report ERROR or NOT_APPLICABLE
sudo hostlint scan --root /mnt/image

# CI: fail only on high-severity controls
sudo hostlint scan --fail-on high --format junit --output hostlint.xml

# One HTML report for many hosts: a single file that makes no network requests
hostlint report results/*.json --output report.html

# Pick the profile, tighten thresholds and accept findings you decided to live with
sudo hostlint scan --config hostlint.yaml
```

The checks that decide each result are listed in the output; `--config` and the file format are
described in [docs/configuration.md](docs/configuration.md).

| Flag | Meaning |
|---|---|
| `-p, --profile` | Profile to check against (default `kisa-2026`) |
| `-f, --format` | `table`, `json`, `sarif` or `junit` |
| `-o, --output` | Write the report to a file |
| `--fail-on` | Exit with status 1 when a control of this severity or higher fails or cannot be checked (`ERROR`): `low`, `medium`, `high`, `none` |
| `--root` | Scan a filesystem mounted at this directory (it must hold an operating system) |
| `--config` | Configuration file (default: `./hostlint.yaml`, then `/etc/hostlint/hostlint.yaml`, if present) |
| `--label key=value` | Add a label to the host in the report |
| `-v, --verbose` | Also list passing and not-applicable controls |

## Results

| Status | Meaning |
|---|---|
| `PASS` | The control is met, and the evidence shows why |
| `FAIL` | The control is not met; the evidence lists what fails |
| `MANUAL` | A person has to decide; the facts to review are shown |
| `NOT_APPLICABLE` | The control does not apply (for example, the service is not installed) |
| `ERROR` | It could not be decided reliably; the reason is shown |

A control's status is the worst of its checks: `FAIL` > `ERROR` > `MANUAL` > `PASS` >
`NOT_APPLICABLE`.

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

Controls that need configuration parsers not written yet (mail servers other than Postfix, DNS servers other than BIND, FTP servers other than vsftpd,
banners, logging policy) are `MANUAL` with guidance, and `NOT_APPLICABLE` where the software is
not running. Supported targets: Ubuntu 22.04/24.04/26.04, Debian 12/13, RHEL-compatible 9/10
(Rocky Linux, AlmaLinux), and CentOS/RHEL 7 best-effort; other versions are scanned
best-effort and marked as such.

Titles and descriptions are hostlint's own; profiles reference control IDs only.

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
with waivers, the release pipeline (signed archives, packages, SBOMs and `install.sh`) and a
container test matrix over every supported distribution are in place, and v0.5.0 is the latest release.
Fleet mode (an agent and a server with a web UI) is planned. See the [roadmap](docs/ROADMAP.md).

## License

[Apache-2.0](LICENSE)
