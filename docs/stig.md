# The DISA STIG profile (Ubuntu 22.04)

`stig-ubuntu2204` checks a host against the controls of the
[Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide](https://public.cyber.mil/stigs/) (STIG), version V2R8, that
the US Department of Defense publishes through DISA. It is vmsctl's profile for a US baseline.

```sh
sudo vmsctl scan --profile stig-ubuntu2204
vmsctl explain UBTU-22-255040          # what a control looks at, why, how to fix it
```

## What it covers, and what it does not

**This is not a complete STIG assessment.** The profile has the 65 controls (of the 188 of V2R8) that vmsctl can decide, and says
nothing about the other 123: the audit rules for system calls, the ownership and mode of system commands and libraries, smart cards and PKI, FIPS, the
boot loader password, the graphical session, `sudo` policy details and most of the PAM settings are not checked yet. A scan that passes
the profile means those 65 controls pass; it does not mean the host meets the STIG. Use the STIG's own SCAP content or checklist for an
assessment, and this profile for what it checks, with the evidence behind each result.

| Area | Controls |
|---|---|
| Boot and kernel | `UBTU-22-211015` (Ctrl-Alt-Delete masked), `UBTU-22-213010` (kernel log), `UBTU-22-213020` (ASLR), `UBTU-22-253010` (SYN cookies) |
| Packages | installed: `215010` (libpam-pwquality), `215015` (chrony), `251010` (ufw), `255010` (openssh-server), `431010` (apparmor), `653010` (auditd); not installed: `215020` (systemd-timesyncd), `215025` (ntp), `215030` (rsh-server), `215035` (telnetd), `215040` (nfs-kernel-server) |
| Firewall | `251015` (ufw turned on), `251020` (the ufw service starts at boot) |
| SSH | `255015` (the service starts at boot), `255025` (no empty passwords, no user environment), `255040` (no X11 forwarding) |
| Audit rules | the commands: `654010`, `654015`, `654020`, `654025`, `654030`, `654035`, `654040` (apparmor_parser, chacl, chage, chcon, chfn, chsh, crontab), `654050`, `654065`, `654070`, `654075`, `654080`, `654085`, `654090`, `654095`, `654100`, `654105`, `654110`, `654115`, `654120`, `654125` (gpasswd, mount, newgrp, pam_timestamp_check, passwd, setfacl, ssh-agent, ssh-keysign, su, sudo, sudoedit, umount, unix_update, usermod); the programs watched with `-w`: `654045` (fdisk), `654055` (kmod), `654060` (modprobe); the files: `654130`, `654135`, `654140`, `654145`, `654150` (group, gshadow, opasswd, passwd, shadow), `654190`, `654195`, `654200`, `654205`, `654210`, `654215` (the journal, btmp, wtmp, utmp, faillog, lastlog), `654220`, `654225` (sudoers, sudoers.d), `654235` (sudo.log) |
| Accounts and passwords | `411010` (root locked), `411015` (unique UIDs), `411025` (minimum age 1 day), `411030` (maximum age 60 days), `412030` (idle shell timeout 15 minutes), `611035` (15 characters), `611065` (no empty passwords) |

(Control IDs are `UBTU-22-` followed by the number.)

## How a control is mapped

A check is mapped to a control only when it decides exactly what the STIG requires, with the STIG's own number as a parameter where it
fixes one (60 days, 15 characters, 900 seconds). A looser check would let a host pass a control that it fails, which vmsctl does not do:
for example the STIG asks for `SHA512` password hashing, and `accounts.password-hash-method` also accepts yescrypt, so that STIG control is
not mapped. Where a control needs a package, a unit or a number, a small generic check takes it as a parameter (`packages.installed`,
`packages.absent`, `services.unit-enabled`, `services.unit-masked`), and the profile says which.

The control IDs and their importance (CAT I is `high`, CAT II `medium`, CAT III `low`) are the STIG's; the STIG is a US government work.
The titles are vmsctl's own short wording. The mapping was made against the control list that
[ComplianceAsCode](https://github.com/ComplianceAsCode/content) publishes for this STIG and checked against each control's requirement.
The profile names the system it is for (`os: [ubuntu-22.04]`): on any other host every control is `NOT_APPLICABLE`, with the reason, because a
standard written for Ubuntu 22.04 says nothing true about another system.

Two mappings are stricter than the STIG, never looser: `UBTU-22-611035` uses `accounts.password-min-length`, which subtracts positive
`dcredit` and `ucredit` credits from `minlen`, so a host that sets `minlen = 15` together with a positive credit can fail where the STIG would
pass it; and `accounts.password-max-age` also fails a value of 0 or less. The audit rules are read from the files that the host loads at boot (`/etc/audit/rules.d/*.rules`, or `/etc/audit/audit.rules` without them),
not from the running kernel: a rule added with `auditctl` since boot is not seen, and a line that vmsctl cannot read makes the result `ERROR`,
never a pass. A command rule counts only in the form the STIG gives (`-a always,exit -F path=... -F perm=x -F auid>=1000 -F auid!=unset`); the
path must be the STIG's own (`/bin/su`, not `/usr/bin/su`). A rule narrowed by another filter (a user, an exit code, success) does not count, a
`never` rule for a path removes it, and a `never` rule that names no path makes the result `ERROR`; a rule on a directory counts for the directory
only. More controls come as the checks they need exist (the audit rules for system
calls are the largest group left).
