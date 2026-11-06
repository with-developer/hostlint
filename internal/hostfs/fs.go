// Package hostfs is hostlint's only access to the host it scans (ADR 0004).
//
// It provides a read-only filesystem rooted at "/" (the running system) or at
// a mounted root (--root), a sensitive-path denylist enforced on content reads,
// bounded globbing and walking that report what they could not see, a runner
// for a fixed set of commands, and OS detection. Code outside this package must
// not read the host, run commands or make raw system calls; the lint rules in
// .golangci.yml catch the common ways of doing so, and review catches the rest.
package hostfs

import (
	"errors"
	"io/fs"
	"path"
	"strings"
	"syscall"
	"time"
)

// FS is a read-only view of the scanned host's filesystem.
//
// Paths are absolute and slash-separated, and are interpreted inside the scan
// root: with --root /mnt/img, "/etc/passwd" means /mnt/img/etc/passwd, and
// symbolic links resolve as if /mnt/img were "/" (they can never escape it).
// A symbolic link is only followed when it is owned by root or by the
// scanning user; anyone else could have pointed it at a secret.
// Errors are *fs.PathError values; use errors.Is with fs.ErrNotExist,
// fs.ErrPermission, ErrDenied, ErrNotRegular, ErrTooLarge and
// ErrUnsafeSymlink.
type FS interface {
	// Stat returns metadata for name, following symbolic links.
	Stat(name string) (FileInfo, error)
	// Lstat returns metadata for name without following a final symbolic link.
	Lstat(name string) (FileInfo, error)
	// ReadLink returns the target of the symbolic link name.
	ReadLink(name string) (string, error)
	// ReadFile returns the contents of the regular file name, following
	// symbolic links. It refuses denylisted files, anything that is not a
	// regular file, and files larger than MaxReadSize.
	ReadFile(name string) ([]byte, error)
	// ReadDir returns the entries of directory name, sorted by name, with
	// Lstat metadata.
	ReadDir(name string) ([]FileInfo, error)
}

// MaxReadSize is the largest file ReadFile returns.
const MaxReadSize = 16 << 20

var (
	// ErrDenied is returned when reading a file on the sensitive-path denylist.
	ErrDenied = errors.New("sensitive file: hostlint does not read its contents")
	// ErrNotRegular is returned when reading something that is not a regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge is returned when a file is larger than MaxReadSize.
	ErrTooLarge = errors.New("file too large")
	// ErrInvalidPath is returned for paths that are not absolute and clean.
	ErrInvalidPath = errors.New("path must be absolute and clean")
	// ErrUnsafeSymlink is returned when a path goes through a symbolic link
	// owned by someone other than root or the scanning user.
	ErrUnsafeSymlink = errors.New("symbolic link not owned by root; not followed")
	// ErrAutomount is returned when listing an automount point, which would
	// mount a filesystem on the scanned host.
	ErrAutomount = errors.New("automount point: not entered")
)

// FileInfo is metadata about one file.
type FileInfo struct {
	// Path is the absolute path inside the scan root.
	Path string
	// Mode holds the type and permission bits, including setuid, setgid and
	// sticky.
	Mode    fs.FileMode
	UID     int64
	GID     int64
	Size    int64
	ModTime time.Time
	Nlink   int64
	// Dev and Ino identify the file on the host; they are zero in MemFS.
	Dev uint64
	Ino uint64
}

// Name returns the last element of Path.
func (fi FileInfo) Name() string { return path.Base(fi.Path) }

// IsDir reports whether the file is a directory.
func (fi FileInfo) IsDir() bool { return fi.Mode.IsDir() }

// IsRegular reports whether the file is a regular file.
func (fi FileInfo) IsRegular() bool { return fi.Mode.IsRegular() }

// IsSymlink reports whether the file is a symbolic link.
func (fi FileInfo) IsSymlink() bool { return fi.Mode&fs.ModeSymlink != 0 }

// Perm returns the permission bits plus setuid, setgid and sticky, in the
// classic octal layout (e.g. 04755).
func (fi FileInfo) Perm() uint32 {
	p := uint32(fi.Mode.Perm())
	if fi.Mode&fs.ModeSetuid != 0 {
		p |= 0o4000
	}
	if fi.Mode&fs.ModeSetgid != 0 {
		p |= 0o2000
	}
	if fi.Mode&fs.ModeSticky != 0 {
		p |= 0o1000
	}
	return p
}

// checkPath validates that name is absolute, clean and NUL-free.
func checkPath(op, name string) error {
	if !strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsRune(name, 0) {
		return &fs.PathError{Op: op, Path: name, Err: ErrInvalidPath}
	}
	return nil
}

// largeReader is implemented by this package's filesystems.
type largeReader interface {
	readLarge(name string, limit int64) ([]byte, error)
}

// ReadLargeFile is ReadFile for a file that may be larger than MaxReadSize
// (a package database), up to limit bytes. The denylist applies.
func ReadLargeFile(fsys FS, name string, limit int64) ([]byte, error) {
	lr, ok := fsys.(largeReader)
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errors.ErrUnsupported}
	}
	return lr.readLarge(name, limit)
}

// IsMissing reports whether err says that nothing is at a path: it does not
// exist, or a part of it is not a directory (a path below a regular file).
func IsMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}
