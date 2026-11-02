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
// never followed, a mounted root can never be escaped, and no kernel feature
// newer than O_PATH is needed (CentOS 7 included).
//
// Content reads check type, identity and the denylist on an O_PATH
// descriptor, which has no side effects even on device files, then reopen
// exactly that file through /proc/self/fd.
type osFS struct {
	root     string // real absolute path of the root on this system
	rootFD   int    // O_PATH descriptor of the root
	live     bool
	euid     uint32
	identity map[fileID]string // denylisted files, by device and inode
}

type fileID struct{ dev, ino uint64 }

// maxSymlinks bounds symlink resolution, like the kernel's ELOOP limit.
const maxSymlinks = 40

func newOSFS(root string) (*osFS, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err == nil {
		resolved, err = filepath.Abs(resolved)
	}
	if err != nil {
		return nil, fmt.Errorf("scan root: %w", err)
	}
	fd, err := unix.Open(resolved, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: resolved, Err: err}
	}
	o := &osFS{root: resolved, rootFD: fd, live: resolved == "/", euid: uint32(os.Geteuid())} //nolint:gosec // G115: uids are non-negative
	o.identity = make(map[fileID]string)
	for _, p := range identityPaths {
		if fi, err := o.Stat(p); err == nil && fi.IsRegular() {
			o.identity[fileID{fi.Dev, fi.Ino}] = p
		}
	}
	return o, nil
}

func (o *osFS) close() error { return unix.Close(o.rootFD) }

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
	rootFD, err := unix.FcntlInt(uintptr(o.rootFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return r, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(rootFD, &st); err != nil {
		_ = unix.Close(rootFD)
		return r, err
	}
	stack := []dir{{rootFD, "/", st.Uid}}
	defer func() {
		for _, d := range stack {
			if d.fd != r.fd || err != nil {
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
		fd, err := unix.Openat(cur.fd, comp, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return r, err
		}
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return r, err
		}
		isLink := st.Mode&unix.S_IFMT == unix.S_IFLNK
		if isLink && (len(parts) > 0 || follow) {
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

// followable returns the target of the symlink fd if hostlint may follow it.
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
		n, err := unix.Readlinkat(fd, "", buf)
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
	if err := unix.Fstat(r.fd, &st); err != nil {
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

func (o *osFS) ReadFile(name string) ([]byte, error) { return o.read(name, true) }

// readSensitive reads a denylisted file for a parser in this package.
func (o *osFS) readSensitive(name string) ([]byte, error) { return o.read(name, false) }

func (o *osFS) read(name string, enforceDenylist bool) ([]byte, error) {
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
	if err := unix.Fstat(r.fd, &st); err != nil {
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
	if st.Size > MaxReadSize {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrTooLarge}
	}
	rfd, err := reopen(r.fd, &st, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY)
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	f := os.NewFile(uintptr(rfd), name)
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	if len(data) > MaxReadSize {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrTooLarge}
	}
	return data, nil
}

// reopen opens the file behind the O_PATH descriptor fd and verifies it is
// the file described by want. There is deliberately no fallback to opening
// the name again: that could open a different file (or a device) swapped in
// meanwhile.
func reopen(fd int, want *unix.Stat_t, flags int) (int, error) {
	rfd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), flags|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, errors.New("cannot reopen through /proc/self/fd: is /proc mounted?")
		}
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(rfd, &st); err != nil {
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
	if err := checkPath("readdir", name); err != nil {
		return nil, err
	}
	r, err := o.resolve(name, true)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	defer unix.Close(r.fd)
	var st unix.Stat_t
	if err := unix.Fstat(r.fd, &st); err != nil {
		return nil, pathErr("readdir", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, pathErr("readdir", name, unix.ENOTDIR)
	}
	dfd, err := reopen(r.fd, &st, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	f := os.NewFile(uintptr(dfd), name)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	sort.Strings(names)
	out := make([]FileInfo, 0, len(names))
	for _, n := range names {
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed while listing
			}
			return nil, pathErr("readdir", path.Join(name, n), err)
		}
		out = append(out, fileInfo(path.Join(name, n), &st))
	}
	return out, nil
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
		Nlink:   int64(st.Nlink),
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
