package collect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Filesystem are the `filesystem` facts: files of concern found by walking
// the target's local filesystems. Mounts of other kinds (pseudo filesystems
// such as /proc, network shares, container storage) are not walked and are
// listed in Excluded; a list is partial when the walk could not see
// everything, so what it holds can fail a check but never make one pass.
type Filesystem struct {
	// SetID are regular files with the set-user-ID or set-group-ID bit.
	SetID []FileEntry `json:"setid"`
	// WorldWritable are regular files and directories every user can write.
	WorldWritable []FileEntry `json:"world_writable"`
	// Unowned are entries whose owner or group has no name in /etc/passwd
	// or /etc/group.
	Unowned []FileEntry `json:"unowned"`
	// DevFiles are regular files under /dev (outside /dev/shm and
	// /dev/mqueue), where only device nodes and directories belong.
	DevFiles []FileEntry `json:"dev_files"`
	// OddNames are files and directories whose name is only dots and spaces
	// (other than "." and ".."), such as "..." or ". ": a way to hide a
	// directory in a listing.
	OddNames []FileEntry `json:"odd_names"`
	// LogFiles are the files and directories under /var/log that root does not
	// own.
	LogFiles []FileEntry `json:"log_files"`
	// Excluded lists the mount points that were not walked, as
	// "path (type)".
	Excluded []string `json:"excluded"`
	// Entries is the number of entries the walk visited.
	Entries int64 `json:"entries"`
}

// FileEntry is one file found by the walk.
type FileEntry struct {
	Path string `json:"path"`
	Type string `json:"type"` // file, dir, symlink, socket, fifo, char, block
	// Mode is the permission and special bits in octal, e.g. "4755", "1777".
	Mode  string `json:"mode"`
	UID   int64  `json:"uid"`
	GID   int64  `json:"gid"`
	Owner string `json:"owner"` // "" when the uid has no name
	Group string `json:"group"` // "" when the gid has no name
}

// Walk bounds. The walk may take minutes on a large server, so the
// collector asks for more time than the default collector timeout.
const (
	walkTimeout    = 5 * time.Minute
	walkMaxEntries = 5_000_000
	walkMaxDepth   = 64
)

// walkMaxListed bounds each list (a variable for tests).
var walkMaxListed = 10_000

// walkedTypes are the filesystem types whose mounts are walked: local disks
// and memory. Everything else (proc, sysfs, devpts, cgroup, nfs, cifs,
// fuse.*, squashfs, overlay mounts of container engines, ...) is excluded.
var walkedTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"jfs": true, "reiserfs": true, "bcachefs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true,
	"tmpfs": true, "ramfs": true, "fuseblk": true, "erofs": true, "ufs": true, "hfsplus": true,
}

// excludedPaths are never walked: kernel interfaces, /dev (walked on its
// own), and the storage of container engines, which holds container images
// rather than the host's files.
var excludedPaths = map[string]string{
	"/proc": "proc", "/sys": "sysfs", "/dev": "walked separately",
	"/var/lib/docker": "container storage", "/var/lib/containers": "container storage",
	"/var/lib/containerd": "container storage",
}

type filesystemCollector struct{}

func (filesystemCollector) Name() string           { return "filesystem" }
func (filesystemCollector) Version() int           { return 4 }
func (filesystemCollector) Access() engine.Access  { return engine.AccessFilesystem }
func (filesystemCollector) Type() reflect.Type     { return reflect.TypeFor[Filesystem]() }
func (filesystemCollector) Timeout() time.Duration { return walkTimeout }

func (filesystemCollector) Collect(ctx context.Context, h *hostfs.Host) (engine.Facts, error) {
	fsf := &Filesystem{SetID: []FileEntry{}, WorldWritable: []FileEntry{}, Unowned: []FileEntry{}, DevFiles: []FileEntry{}, OddNames: []FileEntry{}, LogFiles: []FileEntry{}, Excluded: []string{}}
	w := &walker{facts: fsf, partial: map[string]bool{}}
	w.users, w.groups = w.names(h.FS)

	excluded := map[string]string{}
	for p, why := range excludedPaths {
		// An image can hold files anywhere; only /dev is walked on its own.
		if !h.Image || p == "/dev" {
			excluded[p] = why
		}
	}
	if h.Mounts == nil {
		w.skipped = append(w.skipped, "the mount table is unknown, so only well-known paths are excluded from the walk")
	}
	// A later mount on the same point hides the earlier ones: its type counts.
	top := map[string]string{}
	for _, m := range h.Mounts {
		top[m.Path] = m.Type
	}
	for p, typ := range top {
		if p != "/" && !walkedTypes[typ] {
			excluded[p] = typ
		}
	}
	var listed []string
	for _, p := range slices.Sorted(maps.Keys(excluded)) {
		// A mount below an excluded path is not reached anyway.
		if !slices.ContainsFunc(listed, func(e string) bool { return strings.HasPrefix(p, e+"/") }) {
			listed = append(listed, p)
			fsf.Excluded = append(fsf.Excluded, fmt.Sprintf("%s (%s)", p, excluded[p]))
		}
	}
	skip := func(p string) bool { _, ok := excluded[p]; return ok }

	// budget is what a walk may still use: stop in time to return what was seen.
	budget := func() time.Duration {
		if deadline, ok := ctx.Deadline(); ok {
			return max(time.Until(deadline)-5*time.Second, time.Second)
		}
		return walkTimeout
	}
	res, err := hostfs.Walk(ctx, h.FS, "/", hostfs.WalkOptions{
		MaxEntries: walkMaxEntries, MaxDepth: walkMaxDepth, Timeout: budget(), Skip: skip,
	}, w.visit)
	if err != nil && ctx.Err() == nil {
		return engine.Facts{}, err
	}
	fsf.Entries = int64(res.Entries)
	if !res.Complete {
		w.markPartial(res.Problems, "setid", "world_writable", "unowned", "odd_names", "log_files")
	}
	for _, p := range res.NotEntered {
		fsf.Excluded = append(fsf.Excluded, p+" (automount)")
	}

	// /dev on its own: regular files and odd names matter there.
	devSkip := func(p string) bool { return p == "/dev/shm" || p == "/dev/mqueue" || skip(p) }
	devRes, err := hostfs.Walk(ctx, h.FS, "/dev", hostfs.WalkOptions{MaxEntries: 200_000, MaxDepth: 8, Timeout: budget(), Skip: devSkip},
		func(fi hostfs.FileInfo) error {
			if fi.IsRegular() {
				w.add(&fsf.DevFiles, "dev_files", fi)
			}
			if isOddName(path.Base(fi.Path)) { // "..." is a place to hide files in /dev too
				w.add(&w.facts.OddNames, "odd_names", fi)
			}
			return nil
		})
	switch {
	case err != nil && ctx.Err() == nil && !isNotExist(err):
		return engine.Facts{}, err
	case err != nil && !isNotExist(err), err == nil && !devRes.Complete:
		// Out of time or interrupted: /dev was not fully seen.
		w.markPartial(devRes.Problems, "dev_files", "odd_names")
	}

	f := engine.Facts{Value: fsf, Complete: true, Skipped: w.skipped, Partial: slices.Sorted(maps.Keys(w.partial))}
	if w.users == nil || w.groups == nil {
		f.Unknown = []string{"unowned"}
	}
	return f, nil
}

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// walker records what the walk finds.
type walker struct {
	facts         *Filesystem
	users, groups map[int64]string // nil when the file could not be read
	partial       map[string]bool
	skipped       []string
}

// names reads the user and group names; a table is nil when its file cannot
// be read, so unowned files cannot be told.
func (w *walker) names(fsys hostfs.FS) (users, groups map[int64]string) {
	read := func(file string) map[int64]string {
		m := map[int64]string{}
		err := eachRecord(fsys, file, 3, func(f []string, _ string) error {
			id, err := strconv.ParseInt(f[2], 10, 64)
			if err != nil {
				return errMalformed
			}
			if _, dup := m[id]; !dup {
				m[id] = f[0]
			}
			return nil
		}, &w.skipped)
		if err != nil {
			w.skipped = append(w.skipped, err.Error())
			return nil
		}
		return m
	}
	return read("/etc/passwd"), read("/etc/group")
}

func (w *walker) visit(fi hostfs.FileInfo) error {
	perm := fi.Perm()
	if fi.IsRegular() && perm&0o6000 != 0 {
		w.add(&w.facts.SetID, "setid", fi)
	}
	if (fi.IsRegular() || fi.IsDir()) && perm&0o002 != 0 {
		w.add(&w.facts.WorldWritable, "world_writable", fi)
	}
	if isOddName(path.Base(fi.Path)) {
		w.add(&w.facts.OddNames, "odd_names", fi)
	}
	if fi.UID != 0 && (fi.Path == "/var/log" || strings.HasPrefix(fi.Path, "/var/log/")) && (fi.IsRegular() || fi.IsDir()) {
		w.add(&w.facts.LogFiles, "log_files", fi)
	}
	if w.users != nil && w.groups != nil {
		_, uok := w.users[fi.UID]
		_, gok := w.groups[fi.GID]
		if !uok || !gok {
			w.add(&w.facts.Unowned, "unowned", fi)
		}
	}
	return nil
}

// isOddName reports whether a name is only dots and spaces, and not "." or "..".
func isOddName(name string) bool {
	if name == "." || name == ".." || name == "" {
		return false
	}
	return strings.Trim(name, ". ") == ""
}

// add appends fi to a list, up to walkMaxListed entries; beyond that the
// list is partial.
func (w *walker) add(list *[]FileEntry, field string, fi hostfs.FileInfo) {
	if len(*list) >= walkMaxListed {
		if !w.partial[field] {
			w.markPartial([]string{fmt.Sprintf("more than %d %s entries; the rest are not listed", walkMaxListed, field)}, field)
		}
		return
	}
	*list = append(*list, FileEntry{
		Path: fi.Path, Type: fileType(fi.Mode), Mode: fmt.Sprintf("%04o", fi.Perm()),
		UID: fi.UID, GID: fi.GID, Owner: w.users[fi.UID], Group: w.groups[fi.GID],
	})
}

func (w *walker) markPartial(problems []string, fields ...string) {
	for _, f := range fields {
		w.partial[f] = true
	}
	for _, p := range problems {
		if !slices.Contains(w.skipped, p) {
			w.skipped = append(w.skipped, p)
		}
	}
}

func fileType(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeCharDevice != 0:
		return "char"
	case m&fs.ModeDevice != 0:
		return "block"
	}
	return "other"
}
