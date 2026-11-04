# 0009. Bounded filesystem walks

- Status: Accepted
- Date: 2026-11-03

## Context

Several KISA file controls (U-15 unowned files, U-23 SUID/SGID files, U-25 world-writable
files, U-26 regular files in `/dev`) need a walk of the whole filesystem. On a production host
a walk can be slow, can hang on a dead network mount, can take a lot of memory in one huge
directory, and can visit the same tree twice through a bind mount. Under `--root`, a chroot
build may have the build host's `/proc` and `/dev` bind-mounted inside the image. A walk that
stops early must not make a check pass.

## Decision

- One `filesystem` collector walks `/` once and lists set-ID files, world-writable files and
  directories, and entries whose owner or group has no name; a second, small walk of `/dev`
  lists regular files there (outside `/dev/shm` and `/dev/mqueue`).
- Only local disk and memory filesystems are walked (ext2/3/4, xfs, btrfs, zfs, f2fs, jfs,
  reiserfs, bcachefs, vfat, exfat, ntfs, tmpfs, ramfs). Mounts of other types — pseudo
  filesystems, network shares, FUSE, squashfs, container engine mounts — and `/proc`, `/sys`
  and container storage directories are not walked. The mount table comes from hostlint's
  `/proc/self/mountinfo` when the target is opened, for live hosts and mounted roots alike, and
  excluded mount points are skipped **by path, before their metadata is read**, so a dead
  network mount cannot hang the walk. What was excluded is part of the facts.
- Bounds: 5,000,000 entries, depth 64, 100,000 entries per directory, 10,000 items per list,
  and a time budget that ends before the collector's own timeout (five minutes; a collector may
  now ask for more than the scan's default). A directory already walked (same device and inode)
  is not walked again.
- Anything the walk could not see — an unreadable directory, a bound, the time budget — makes
  the affected lists **partial**: a new `Facts.Partial` marks single fields as holding part of
  what exists. A check over a partial list can FAIL on what it holds and is ERROR otherwise;
  checks over the collector's other fields are unaffected.
- Without a readable `/etc/passwd` and `/etc/group`, the unowned list is unknown, not empty.

## Consequences

- Network shares and container images are out of scope for these checks; the excluded list
  shows what was not walked.
- On very large hosts the walk can hit its bounds; the affected checks are ERROR with the
  reason, rather than a PASS that only covers part of the disk.
- The bounds are constants for now; the configuration file (#12) can make them tunable.

## Alternatives considered

- **One walk per check** — simpler checks, but the disk is read several times.
- **Excluding only by device number (`find -xdev`)** — misses separate local partitions such as
  `/home` and `/var`.
- **Pruning mounts after reading their metadata** — reading the metadata of a dead network
  mount point is exactly what hangs.
