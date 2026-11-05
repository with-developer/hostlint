# 0008. Package, service and socket facts

- Status: Accepted
- Date: 2026-11-03

## Context

The KISA services controls (U-34–U-63) ask whether legacy services — telnet, r-services, finger,
tftp, NFS, NIS, SNMP and more — are installed, set to start, or running. Issue #6 adds the facts
behind them. Three constraints shape how:

- **Observation only** (ADR 0004). We measured `rpm -qa` as root: on Rocky Linux 9 it rewrites
  `rpmdb.sqlite-shm` (SQLite readers update the shared index), and on CentOS 7 it rewrites the
  Berkeley DB environment files `__db.00*`. Running rpm changes the host.
- **Golden images** (`--root`) are a first-class target, where nothing runs and no command may
  be run.
- **No false PASS** (ADR 0006). A service that is not enabled can still run (`systemctl start`,
  a unit pulled in by another), and a port number alone proves nothing: RPC services get theirs
  from rpcbind, and a daemon can listen anywhere.

## Decision

- **Packages** come from the package database files, never from running the package manager.
  dpkg: `/var/lib/dpkg/status` plus the journal in `/var/lib/dpkg/updates`, applied in order as
  dpkg does; every state other than `not-installed` and `config-files` counts as installed.
  rpm's SQLite database (EL9 and later) is read directly with a small read-only parser of the
  SQLite file format and rpm headers. The Berkeley DB hash file of EL7 and EL8 is read the same
  way (hash version 9, little-endian; key = package number, value = the header, in overflow pages
  when large). A format that is not read (SUSE's ndb) makes the `packages` collector fail, so
  checks that read it are ERROR instead of seeing an empty list.
- **Services** are read from the files that decide them, the same way live and under `--root`:
  systemd units on the unit search path (enabled through `.wants`, `.requires` and `.upholds`
  links; masked through `/dev/null` links or empty files; aliases; template instances; the
  program of `ExecStart=`), SysV init scripts with their boot runlevel links, the active lines
  of `inetd.conf` and `/etc/inetd.d`, and xinetd services with their `disable` setting and the
  `defaults` section's lists.
- On a live target where systemd runs (`/run/systemd/system` exists), `services.active` lists
  the units systemd reports active, from `systemctl list-units` (a read-only query). Without
  systemd nothing is active; when systemd runs but cannot be asked, the field is unknown.
- A built-in **`target`** variable says whether the target is live. Checks that need live facts
  write `!target.live || <live condition>`, so under `--root` they are decided from the files
  instead of ERROR, and on a live host the live facts are required.
- **Sockets** (`sockets.listening`: listening TCP and unconnected UDP sockets, with a loopback
  flag) come from `/proc/net`, on live targets only. The collector refuses to report when
  hostlint runs in a different network namespace from process 1, whose sockets it would not
  see, and is incomplete when it cannot tell (not root). Which process owns a socket is not
  recorded yet: without root that mapping is partial, and a partial mapping must not let a check
  pass.
- Checks decide whether a service is present or enabled from several signals (unit, init script,
  inetd/xinetd entry, package, socket) and never from one negative signal alone.

## Consequences

- Package checks are ERROR on EL7 and EL8 until a Berkeley DB reader lands; service checks,
  which do not depend on packages alone, work everywhere.
- Image and host scans agree on what is enabled, because both read the same files.
- Known gaps, documented on the facts: units started only through `Wants=`/`Requires=` in other
  unit files or drop-ins, and units that presets enable on an image's first boot, do not show as
  enabled. On a live host, `services.active` shows them if they run.
- `/proc/net/tcp` lists every connection; on hosts with more than about 100,000 connections it
  exceeds the file read limit and the collector fails (ERROR) rather than reading part of it.

## Alternatives considered

- **Running `rpm -qa`** — simplest and complete, but it writes to the rpm database on EL7 and EL9.
- **`systemctl list-unit-files` for enablement on live hosts** — systemd's own answer, including
  drop-ins and generators, but it would make an image and the host built from it disagree, and
  it is unavailable under `--root`. The live active state covers what the files miss.
- **Socket owners from `/proc/<pid>/fd`** — catches daemons on unusual ports, but without root
  only some processes can be inspected; it can follow once facts can be partly incomplete.
