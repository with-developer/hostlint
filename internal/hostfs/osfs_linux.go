//go:build linux

package hostfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// osFS is the real filesystem of a Linux host, rooted at "/" or at a mounted
// root.
//
// Paths are resolved here, one component at a time, never by the kernel:
// every component is opened with openat(O_PATH|O_NOFOLLOW) relative to the
// directory before it, ".." never climbs above the root, and a symbolic link
// is followed only when it is owned by root or by the scanning user. So a
// link planted by another user (say ~/.rhosts -> /etc/wireguard/wg0.conf) is
// never followed, a mounted root can never be escaped, magic /proc links are
// only followed as text, and no kernel feature newer than O_PATH is needed
// (CentOS 7 included). O_PATH lookups do not trigger automounts either.
//
// Content reads check type, identity and the denylist on an O_PATH
// descriptor, which has no side effects even on device files, then reopen
// exactly that file through /proc/self/fd.
type osFS struct {
	root     string // absolute path of the root on this system, as given
	live     bool
	euid     uint32
	identity map[fileID]string // denylisted files, by device and inode

	mu     sync.RWMutex
	rootFD int // O_PATH descriptor of the root; -1 once closed
}

type fileID struct{ dev, ino uint64 }

// maxSymlinks bounds symlink resolution, like the kernel's ELOOP limit.
const maxSymlinks = 40

// errClosed is returned by a closed osFS.
var errClosed = errors.New("host is closed")

// newOSFS opens root. The root is used as given, not canonicalized: with
// /proc/<pid>/root (a running container) the kernel's magic link reaches the
// container's root, which is a mounted root, not the running system. Only
// "/" itself is the live system.
func newOSFS(root string) (*osFS, error) {
	if root == "" {
		return nil, errors.New("scan root must not be empty")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("scan root: %w", err)
	}
	fd, err := retry(func() (int, error) { return unix.Open(abs, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0) })
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: abs, Err: err}
	}
	o := &osFS{root: abs, rootFD: fd, live: abs == "/", euid: uint32(os.Geteuid())} //nolint:gosec // G115: uids are non-negative
	o.identity = make(map[fileID]string)
	for _, p := range identityPaths {
		fi, err := o.Stat(p)
		switch {
		case err == nil && fi.IsRegular():
			o.identity[fileID{fi.Dev, fi.Ino}] = p
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			// Fail closed: without the identity, a hard link could expose it.
			_ = o.close()
			return nil, fmt.Errorf("cannot identify %s: %w", p, err)
		}
	}
	return o, nil
}

func (o *osFS) close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.rootFD < 0 {
		return nil
	}
	err := unix.Close(o.rootFD)
	o.rootFD = -1
	return err
}

// dupRoot returns a new descriptor for the root, or errClosed.
func (o *osFS) dupRoot() (int, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.rootFD < 0 {
		return -1, errClosed
	}
	return unix.FcntlInt(uintptr(o.rootFD), unix.F_DUPFD_CLOEXEC, 0)
}

// retry repeats a system call interrupted by a signal.
func retry[T any](call func() (T, error)) (T, error) {
	for {
		v, err := call()
		if !errors.Is(err, unix.EINTR) {
			return v, err
		}
	}
}

func fstat(fd int, st *unix.Stat_t) error {
	_, err := retry(func() (struct{}, error) { return struct{}{}, unix.Fstat(fd, st) })
	return err
}

// resolved is an O_PATH descriptor and where it is inside the root.
type resolved struct {
	fd        int
	path      string // canonical path inside the root
	parentUID uint32 // owner of the directory that holds it
}

// resolve walks name from the root. With follow false a final symlink is
// returned itself. The caller closes r.fd.
func (o *osFS) resolve(name string, follow bool) (r resolved, err error) {
	type dir struct {
		fd   int
		path string
		uid  uint32
	}
	rootFD, err := o.dupRoot()
	if err != nil {
		return r, err
	}
	var st unix.Stat_t
	if err := fstat(rootFD, &st); err != nil {
		_ = unix.Close(rootFD)
		return r, err
	}
	stack := []dir{{rootFD, "/", st.Uid}}
	defer func() {
		for _, d := range stack {
			if err != nil || d.fd != r.fd {
				_ = unix.Close(d.fd)
			}
		}
	}()

	parts, links := splitPath(name), 0
	for len(parts) > 0 {
		comp := parts[0]
		parts = parts[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				_ = unix.Close(stack[len(stack)-1].fd)
				stack = stack[:len(stack)-1]
			}
			continue
		}
		cur := stack[len(stack)-1]
		fd, err := retry(func() (int, error) {
			return unix.Openat(cur.fd, comp, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		})
		if err != nil {
			return r, err
		}
		if err := fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return r, err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK && (len(parts) > 0 || follow) {
			target, err := o.followable(fd, &st, &links)
			_ = unix.Close(fd)
			if err != nil {
				return r, err
			}
			if strings.HasPrefix(target, "/") {
				for _, d := range stack[1:] {
					_ = unix.Close(d.fd)
				}
				stack = stack[:1]
			}
			parts = append(splitPath(target), parts...)
			continue
		}
		if len(parts) > 0 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(fd)
			return r, unix.ENOTDIR
		}
		stack = append(stack, dir{fd, path.Join(cur.path, comp), st.Uid})
	}
	top := stack[len(stack)-1]
	r = resolved{fd: top.fd, path: top.path, parentUID: top.uid}
	if len(stack) > 1 {
		r.parentUID = stack[len(stack)-2].uid
	}
	return r, nil
}

// followable returns the target of the symlink fd if vmsctl may follow it.
func (o *osFS) followable(fd int, st *unix.Stat_t, links *int) (string, error) {
	if st.Uid != 0 && st.Uid != o.euid {
		return "", fmt.Errorf("owned by uid %d: %w", st.Uid, ErrUnsafeSymlink)
	}
	if *links++; *links > maxSymlinks {
		return "", unix.ELOOP
	}
	target, err := readlinkFD(fd)
	if err == nil && target == "" {
		err = unix.ENOENT
	}
	return target, err
}

func readlinkFD(fd int) (string, error) {
	for size := 256; size <= 1<<16; size *= 2 {
		buf := make([]byte, size)
		n, err := retry(func() (int, error) { return unix.Readlinkat(fd, "", buf) })
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", unix.ENAMETOOLONG
}

func (o *osFS) stat(op, name string, follow bool) (FileInfo, error) {
	if err := checkPath(op, name); err != nil {
		return FileInfo{}, err
	}
	r, err := o.resolve(name, follow)
	if err != nil {
		return FileInfo{}, pathErr(op, name, err)
	}
	defer unix.Close(r.fd)
	var st unix.Stat_t
	if err := fstat(r.fd, &st); err != nil {
		return FileInfo{}, pathErr(op, name, err)
	}
	return fileInfo(name, &st), nil
}

func (o *osFS) Stat(name string) (FileInfo, error)  { return o.stat("stat", name, true) }
func (o *osFS) Lstat(name string) (FileInfo, error) { return o.stat("lstat", name, false) }

func (o *osFS) ReadLink(name string) (string, error) {
	if err := checkPath("readlink", name); err != nil {
		return "", err
	}
	r, err := o.resolve(name, false)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	defer unix.Close(r.fd)
	target, err := readlinkFD(r.fd)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	return target, nil
}

func (o *osFS) ReadFile(name string) ([]byte, error) { return o.read(name, true, MaxReadSize) }

// readSensitive reads a denylisted file for a parser in this package.
func (o *osFS) readSensitive(name string) ([]byte, error) { return o.read(name, false, MaxReadSize) }

// readLarge reads a file that may be larger than MaxReadSize, up to limit.
func (o *osFS) readLarge(name string, limit int64) ([]byte, error) { return o.read(name, true, limit) }

func (o *osFS) read(name string, enforceDenylist bool, limit int64) ([]byte, error) {
	if err := checkPath("read", name); err != nil {
		return nil, err
	}
	if enforceDenylist && denied(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
	}
	r, err := o.resolve(name, true)
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	defer unix.Close(r.fd)
	var st unix.Stat_t
	if err := fstat(r.fd, &st); err != nil {
		return nil, pathErr("read", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrNotRegular}
	}
	if enforceDenylist {
		if _, bad := o.identity[fileID{st.Dev, st.Ino}]; bad || denied(r.path) {
			return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
		}
		// A hard link that another user's file has in this directory: with
		// fs.protected_hardlinks off, anyone can link to files they cannot read.
		if st.Nlink > 1 && st.Uid != r.parentUID {
			return nil, &fs.PathError{Op: "read", Path: name, Err: fmt.Errorf("hard link to a file owned by uid %d: %w", st.Uid, ErrDenied)}
		}
	}
	if st.Size > limit {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrTooLarge}
	}
	rfd, err := reopen(r.fd, &st, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	defer unix.Close(rfd)
	data, err := readAll(rfd, st.Size, limit)
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	return data, nil
}

// readAll reads a file with plain read(2) calls on its non-blocking
// descriptor. Unlike *os.File, this never parks on a pollable file (such as
// a tracing pipe) waiting for data that may never come.
func readAll(fd int, size, limit int64) ([]byte, error) {
	buf := make([]byte, 0, min(size, limit)+512)
	for {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := retry(func() (int, error) { return unix.Read(fd, buf[len(buf):cap(buf)]) })
		switch {
		case errors.Is(err, unix.EAGAIN):
			return nil, errors.New("file would block: not an ordinary file")
		case err != nil:
			return nil, err
		case n == 0:
			return buf, nil
		}
		buf = buf[:len(buf)+n]
		if int64(len(buf)) > limit {
			return nil, ErrTooLarge
		}
	}
}

// reopen opens the file behind the O_PATH descriptor fd and verifies it is
// the file described by want. There is deliberately no fallback to opening
// the name again: that could open a different file (or a device) swapped in
// meanwhile.
func reopen(fd int, want *unix.Stat_t, flags int) (int, error) {
	rfd, err := retry(func() (int, error) {
		return unix.Open("/proc/self/fd/"+strconv.Itoa(fd), flags|unix.O_CLOEXEC, 0)
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, errors.New("cannot reopen through /proc/self/fd: is /proc mounted?")
		}
		return -1, err
	}
	var st unix.Stat_t
	if err := fstat(rfd, &st); err != nil {
		_ = unix.Close(rfd)
		return -1, err
	}
	if st.Dev != want.Dev || st.Ino != want.Ino {
		_ = unix.Close(rfd)
		return -1, errors.New("file changed while it was being opened")
	}
	return rfd, nil
}

func (o *osFS) ReadDir(name string) ([]FileInfo, error) {
	entries, _, err := o.readDirN(name, -1, nil)
	return entries, err
}

// readDirN lists at most n entries (all if n < 0); truncated reports whether
// more were left. Automount points are not entered: reading one would mount
// a filesystem on the scanned host.
func (o *osFS) readDirN(name string, n int, skip func(string) bool) (entries []FileInfo, truncated bool, err error) {
	if err := checkPath("readdir", name); err != nil {
		return nil, false, err
	}
	r, err := o.resolve(name, true)
	if err != nil {
		return nil, false, pathErr("readdir", name, err)
	}
	defer unix.Close(r.fd)
	var st unix.Stat_t
	if err := fstat(r.fd, &st); err != nil {
		return nil, false, pathErr("readdir", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, false, pathErr("readdir", name, unix.ENOTDIR)
	}
	if isAutomount(r.fd) {
		return nil, false, &fs.PathError{Op: "readdir", Path: name, Err: ErrAutomount}
	}
	dfd, err := reopen(r.fd, &st, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, false, pathErr("readdir", name, err)
	}
	f := os.NewFile(uintptr(dfd), name)
	defer f.Close()
	var names []string
	if n < 0 {
		names, err = f.Readdirnames(-1)
	} else {
		// Read one more name than allowed to tell whether any were left.
		if names, err = f.Readdirnames(n + 1); errors.Is(err, io.EOF) {
			err = nil
		}
		if len(names) > n {
			names, truncated = names[:n], true
		}
	}
	if err != nil {
		return nil, false, pathErr("readdir", name, err)
	}
	sort.Strings(names)
	entries = make([]FileInfo, 0, len(names))
	for _, child := range names {
		if skip != nil && skip(path.Join(name, child)) {
			continue // never stat it: a dead network mount would hang
		}
		_, err := retry(func() (struct{}, error) {
			return struct{}{}, unix.Fstatat(dfd, child, &st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
		})
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed while listing
			}
			return nil, false, pathErr("readdir", path.Join(name, child), err)
		}
		entries = append(entries, fileInfo(path.Join(name, child), &st))
	}
	return entries, truncated, nil
}

// isAutomount reports whether fd is an automount trigger (statx, Linux 4.11+)
// or an autofs mount; older kernels only get the autofs check.
func isAutomount(fd int) bool {
	var stx unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_TYPE, &stx)
	if err == nil && stx.Attributes_mask&unix.STATX_ATTR_AUTOMOUNT != 0 && stx.Attributes&unix.STATX_ATTR_AUTOMOUNT != 0 {
		return true
	}
	var sfs unix.Statfs_t
	return unix.Fstatfs(fd, &sfs) == nil && sfs.Type == unix.AUTOFS_SUPER_MAGIC
}

func pathErr(op, name string, err error) error {
	if errors.Is(err, unix.ENOTDIR) {
		err = fs.ErrNotExist // a path component is not a directory
	}
	return &fs.PathError{Op: op, Path: name, Err: err}
}

func fileInfo(name string, st *unix.Stat_t) FileInfo {
	return FileInfo{
		Path:    name,
		Mode:    fileMode(st.Mode),
		UID:     int64(st.Uid),
		GID:     int64(st.Gid),
		Size:    st.Size,
		ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UTC(),
		Nlink:   int64(st.Nlink), //nolint:gosec // G115: link counts never exceed MaxInt64
		Dev:     st.Dev,
		Ino:     st.Ino,
	}
}

func fileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFBLK:
		mode |= fs.ModeDevice
	case unix.S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFSOCK:
		mode |= fs.ModeSocket
	}
	if m&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}
