# 0013. The essentials profile

- Status: Accepted
- Date: 2026-11-07

## Context

The only profile is `kisa-2026` (ADR 0007), the Korean CII guide. It is the right first profile, but its
control IDs mean nothing to most users, it follows the structure of one national guide, and it has two
SSH checks. The vision says the same checks map onto other baselines; a short, neutral profile is the
first of them, and a way for a user outside the KISA context to get a useful result from `hostlint scan`.

## Decision

- A second built-in profile, **`essentials`**, with 20 controls (`ES-01`–`ES-20`) over the existing checks
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
a fixed list of fourteen parameters, never a path a rule or a file chooses: on a running host from `/proc/sys`
(the kernel is the truth, and a parameter it does not have is absent, so a check cannot decide), on a mounted
root from the files of sysctl.d(5) in the order systemd-sysctl applies them (a file of an earlier directory hides
the one of that name later, a link to `/dev/null` masks it, `/etc/sysctl.conf` last, the last line wins; a
wildcard key is not read as setting any parameter, so what only a wildcard sets stays unknown instead of guessed).
A container image shares the kernel of its host, so the checks do not apply to it (`target.image`).
The end-to-end goldens leave the results of these checks out: a container's parameters are those of the machine
that runs Docker, which differ between a laptop and a CI runner; the rule tests and the collector tests (with
the `sysctl.d` files of Ubuntu, Rocky Linux, CentOS and Amazon Linux) cover them.
