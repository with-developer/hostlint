# 0013. The essentials profile

- Status: Accepted
- Date: 2026-11-07

## Context

The only profile is `kisa-2026` (ADR 0007), the Korean CII guide. It is the right first profile, but its
control IDs mean nothing to most users, it follows the structure of one national guide, and it has two
SSH checks. The vision says the same checks map onto other baselines; a short, neutral profile is the
first of them, and a way for a user outside the KISA context to get a useful result from `hostlint scan`.

## Decision

- A second built-in profile, **`essentials`**, with 20 controls (`ES-01`–`ES-20`, 22 since revision 2: see the amendment) over the existing checks
  and eight new SSH checks. The IDs, titles and grouping are hostlint's own; nothing is copied from a
  benchmark (VISION principle 5). It is selected with `--profile essentials`; **the default stays
  `kisa-2026`**, so no existing scan, result or golden changes.
- New SSH checks: `ssh.password-authentication`, `ssh.permit-empty-passwords`, `ssh.x11-forwarding`,
  `ssh.max-auth-tries`, `ssh.ignore-rhosts`, `ssh.hostbased-authentication`,
  `ssh.permit-user-environment`, and `ssh.match-hardening`, which lists the `Match` blocks that undo any
  of them (a global value alone would pass while a `Match` block re-enables the weak setting for a group
  or a network). They use the existing `sshd` facts: no collector changes.
- **No false PASS for passwords.** `PasswordAuthentication no` alone still lets a password be typed
  through PAM with keyboard-interactive authentication, so `ssh.password-authentication` requires that
  one to be off as well (`ChallengeResponseAuthentication` before OpenSSH 8.7). Where sshd's own defaults
  are not known (a mounted root or an image), an unset keyword is `ERROR`, as for the existing checks.
- The first value of a keyword in the configuration wins, as sshd reads it; the collector already
  reports that, and a real Debian configuration, whose stock `X11Forwarding yes` comes before a later
  `X11Forwarding no`, fails `ssh.x11-forwarding` correctly.
- The end-to-end tests compare both profiles with goldens, for every supported distribution and for an
  image scanned from `docker save`.

## Consequences

- A user can run `hostlint scan --profile essentials` (also as `profile:` of the GitHub Action) and read
  20 controls instead of 67.
- Another profile means another set of goldens to review when a check changes.
- Not decided: a profile that maps CIS benchmark control IDs (IDs only, ADR 0003), and making
  `essentials` the default outside Korea.

## Amendment: kernel parameters (revision 2)

`essentials` revision 2 adds two controls, `ES-21` (the network stack) and `ES-22` (what the kernel lets
unprivileged code see and do), over eleven new `sysctl.*` checks and a `sysctl` collector. The collector reads
a fixed list of fifteen parameters, never a path a rule or a file chooses: on a running host from `/proc/sys`
(the kernel is the truth, and a parameter it does not have is absent, so a check cannot decide), on a mounted
root from the files of sysctl.d(5) in the order systemd-sysctl applies them (a file of an earlier directory hides
the one of that name later, a link to `/dev/null` masks it, `/etc/sysctl.conf` last, the last line wins; a
wildcard key is not read as setting any parameter, so what only a wildcard sets stays unknown instead of guessed).
A container image shares the kernel of its host, so the checks do not apply to it (`target.image`).
The end-to-end goldens leave the results of these checks out: a container's parameters are those of the machine
that runs Docker, which differ between a laptop and a CI runner; the rule tests and the collector tests (with
the `sysctl.d` files of Ubuntu, Rocky Linux, CentOS and Amazon Linux) cover them.

## Amendment: revision 3 (2026-11-08, issue #212, approved by the owner)

`essentials` revision 3 adds `ES-23` (a host firewall is enabled) and `ES-24` (security updates are installed automatically): 24
controls. Both read configuration files with two small collectors, `firewall` (ufw.conf) and `updates` (APT::Periodic,
dnf-automatic, yum-cron), plus the unit and package facts that exist. They do not apply to an image (`target.image`) or to a
target without systemd, and they never read a command.

- **ES-23** is two checks. `firewall.enabled` passes when ufw is on (`ENABLED=yes` and its unit enabled: installing ufw enables the
  unit and leaves it off, which is what a real Ubuntu does), or firewalld, nftables, netfilter-persistent or an iptables service is
  enabled; it fails when none is. `firewall.review-rules` is a manual check that applies only when the sole firewall is an nftables or
  iptables service: a service that starts says nothing about its rules, and hostlint does not read them, so the control is
  `MANUAL` there instead of a guessed `PASS`.
- **ES-24** `updates.security-automatic`: Debian and Ubuntu need unattended-upgrades installed, `Unattended-Upgrade` and
  `Update-Package-Lists` not 0, `APT::Periodic::Enable` not 0 (container images set it to 0) and the apt-daily and apt-daily-upgrade
  timers enabled; RHEL and its relatives need dnf-automatic's install timer enabled, or its timer with `apply_updates = yes`, or
  yum-cron enabled with `apply_updates = yes`. What may be installed (the origins, `upgrade_type`) is not read.
- Not added: auditd and persistent-journal checks (a legitimate "no" is too common for a default `FAIL`).
- The e2e goldens leave the results of these controls out for containers, like the kernel's.

## Amendment: revision 4 (2026-11-11, decided by the maintainer: the owner asked for choices like this to be made without asking)

`essentials` revision 4 adds `ES-25` (mandatory access control is on): 25 controls. One check, `mac.enabled`, over a small collector
`mac` (`/etc/selinux/config`) and the package and unit facts that exist. It passes when SELinux is set to `enforcing` in its
configuration, or the `apparmor` package is installed and its unit is enabled (what Ubuntu and Debian do by default); `permissive`,
`disabled` and no mandatory access control at all fail. It reads what the next boot does, not the running kernel (a kernel started
without the module, or `setenforce 0` since boot, is not seen), and it says so. It does not apply to an image or to a target without systemd.

- The configuration files of Rocky Linux 9, AlmaLinux 9, CentOS 7 and Amazon Linux 2023 are real (taken from their `selinux-policy`
  packages): the first three ship `enforcing`, and Amazon Linux 2023 ships `permissive`, so a stock Amazon Linux 2023 fails this
  control, which is what the control is for.
- Like every revision that adds a control, it changes the revision, so a waiver of an `essentials` control (which names the revision it
  was written for) stops applying until it is written again for revision 4 (the scan says which).

## Amendment: revision 5 (2026-11-12, decided by the maintainer)

`essentials` revision 5 maps a check written by a contributor (#259, thank you), `ssh.login-grace-time`, into `ES-04`, which is now "SSH limits
attempts, time and features". The check passes when `LoginGraceTime` is between 1 and 60 seconds (a parameter); the OpenSSH default of 120 and 0
(no limit) fail. `ES-04` already failed on a stock OpenSSH (`MaxAuthTries` defaults to 6, the profile asks for 4), so a stock host fails as before; a host that
was hardened for `MaxAuthTries` and `X11Forwarding` passed before and now also needs `LoginGraceTime 60` (the end-to-end hardening script sets it). The revision changes, so waivers of `essentials` controls have to be written again for revision 5. A value with a unit
(`1m`) read from the files of a mounted root is `ERROR`, not a guess (a live host prints seconds).

## Amendment: revision 6 (2026-11-12, decided by the maintainer)

`essentials` revision 6 adds two controls, 27 in all, each over one new check that needs no new collector:

- `ES-26` (no account has an empty password): `accounts.no-empty-passwords` lists the accounts whose `/etc/shadow` password field is empty
  (the `shadow` facts already know the state "empty"; locked accounts are not listed). A stock container image or host passes unless a
  distribution ships an account with an empty password.
- `ES-27` (printing and network discovery are off unless needed): `services.no-print-discovery` lists the ways CUPS (`cups`, `cups-browsed`)
  and Avahi (`avahi-daemon`) are started, by service name like the other service checks. A server rarely needs either, and flaws in `cups-browsed`
  and Avahi have been exploited from the network. A desktop or a print server waives the control with its reason.

Like every revision that adds controls, it changes the revision, so waivers of `essentials` controls have to be written again for revision 6
(the scan says which). Both checks apply to a container image too: the shadow file and the started services are in the image.

## Amendment: revision 7 (2026-11-12, decided by the maintainer)

`essentials` revision 7 adds two controls over two new SSH checks, 29 in all; neither needs a new collector (the `sshd` facts hold every keyword):

- `ES-28` (SSH offers no broken ciphers, MACs or key exchanges): `ssh.weak-algorithms` fails when the effective `Ciphers`, `MACs` or `KexAlgorithms`
  list includes 3des-cbc, blowfish-cbc, cast128-cbc, the arcfour family, hmac-md5, hmac-md5-96, hmac-sha1-96, umac-64 (and their `-etm` forms),
  diffie-hellman-group1-sha1 or gss-group1-sha1. Only clearly broken names are listed (hmac-sha1 and the CBC modes of AES are left to the reader's
  policy). On a live host the lists come from `sshd -T`, so a stock CentOS/RHEL 7 (OpenSSH 7.4, whose defaults include 3des-cbc) fails; modern
  distributions pass. Without `sshd -T` an unset list is unknown (`ERROR`), and a list that starts with `-` is not judged.
- `ES-29` (SSH logs who logs in): `ssh.log-level` requires `LogLevel` INFO or VERBOSE (any case); QUIET, FATAL, ERROR and the DEBUG levels fail.

The revision changes, so waivers of `essentials` controls have to be written again for revision 7 (the scan says which). The end-to-end hardening
script sets modern lists so that the hardened hosts keep passing.

