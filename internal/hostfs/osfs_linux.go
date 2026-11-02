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
// root. Every lookup starts from a file descriptor for the root:
//   - with openat2(2) (Linux 5.6+) and RESOLVE_IN_ROOT, the kernel resolves
//     ".." and absolute symlinks as if the root were "/", so nothing outside
//     it can be reached, even through concurrent renames;
//   - without openat2, only the running system ("/") can be scanned, where
//     ordinary resolution is already confined.
//
// Content reads first open an O_PATH descriptor (which has no side effects,
// even on device files), check the file type and identity on that
// descriptor, then reopen that exact file for reading.
type osFS struct {
	root     string // real absolute path of the root on this system
	rootFD   int    // O_PATH descriptor of the root
	live     bool
	openat2  bool
	identity map[fileID]string // denylisted files, by device and inode
}

type fileID struct{ dev, ino uint64 }

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
	o := &osFS{root: resolved, rootFD: fd, live: resolved == "/", openat2: probeOpenat2(fd)}
	if !o.live && !o.openat2 {
		_ = unix.Close(fd)
		return nil, errors.New("scanning a mounted root needs Linux 5.6 or later (openat2)")
	}
	o.identity = make(map[fileID]string)
	for _, p := range identityPaths {
		if fi, err := o.Stat(p); err == nil && fi.IsRegular() {
			o.identity[fileID{fi.Dev, fi.Ino}] = p
		}
	}
	return o, nil
}

func probeOpenat2(rootFD int) bool {
	fd, err := unix.Openat2(rootFD, ".", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT,
	})
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func (o *osFS) close() error { return unix.Close(o.rootFD) }

// open resolves name inside the root and opens it; O_CLOEXEC is always added.
func (o *osFS) open(name string, flags int) (int, error) {
	rel := strings.TrimPrefix(name, "/")
	if rel == "" {
		rel = "."
	}
	flags |= unix.O_CLOEXEC
	if !o.openat2 {
		return unix.Openat(o.rootFD, rel, flags, 0)
	}
	how := &unix.OpenHow{
		Flags:   uint64(flags), //nolint:gosec // G115: open flags are non-negative
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	for attempt := 0; ; attempt++ {
		fd, err := unix.Openat2(o.rootFD, rel, how)
		// EAGAIN: the kernel saw a concurrent rename and refused to guess.
		if errors.Is(err, unix.EAGAIN) && attempt < 8 {
			continue
		}
		return fd, err
	}
}

func (o *osFS) Stat(name string) (FileInfo, error) {
	if err := checkPath("stat", name); err != nil {
		return FileInfo{}, err
	}
	fd, err := o.open(name, unix.O_PATH)
	if err != nil {
		return FileInfo{}, pathErr("stat", name, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return FileInfo{}, pathErr("stat", name, err)
	}
	return fileInfo(name, &st), nil
}

func (o *osFS) Lstat(name string) (FileInfo, error) {
	if err := checkPath("lstat", name); err != nil {
		return FileInfo{}, err
	}
	if name == "/" {
		return o.Stat(name)
	}
	dfd, err := o.open(path.Dir(name), unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return FileInfo{}, pathErr("lstat", name, err)
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, path.Base(name), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return FileInfo{}, pathErr("lstat", name, err)
	}
	return fileInfo(name, &st), nil
}

func (o *osFS) ReadLink(name string) (string, error) {
	if err := checkPath("readlink", name); err != nil {
		return "", err
	}
	if name == "/" {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: unix.EINVAL}
	}
	dfd, err := o.open(path.Dir(name), unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return "", pathErr("readlink", name, err)
	}
	defer unix.Close(dfd)
	for size := 256; size <= 1<<16; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dfd, path.Base(name), buf)
		if err != nil {
			return "", pathErr("readlink", name, err)
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", &fs.PathError{Op: "readlink", Path: name, Err: unix.ENAMETOOLONG}
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
	fd, err := o.open(name, unix.O_PATH)
	if err != nil {
		return nil, pathErr("read", name, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, pathErr("read", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrNotRegular}
	}
	if enforceDenylist {
		if _, bad := o.identity[fileID{st.Dev, st.Ino}]; bad {
			return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
		}
		if resolved, ok := o.realPath(fd); ok && denied(resolved) {
			return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
		}
	}
	if st.Size > MaxReadSize {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrTooLarge}
	}
	rfd, err := o.reopen(fd, name, &st)
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

// reopen opens the file behind the O_PATH descriptor fd for reading and
// verifies it is still the file described by want.
func (o *osFS) reopen(fd int, name string, want *unix.Stat_t) (int, error) {
	const flags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOCTTY | unix.O_NONBLOCK
	rfd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd), flags, 0)
	if err != nil {
		// No /proc: resolve the name again; the identity check below catches a swap.
		if rfd, err = o.open(name, flags); err != nil {
			return -1, err
		}
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

// realPath returns where fd actually points, as a path inside the root.
func (o *osFS) realPath(fd int) (string, bool) {
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !strings.HasPrefix(p, "/") {
		return "", false
	}
	switch {
	case o.live:
		return p, true
	case p == o.root:
		return "/", true
	case strings.HasPrefix(p, o.root+"/"):
		return strings.TrimPrefix(p, o.root), true
	}
	return "", false
}

func (o *osFS) ReadDir(name string) ([]FileInfo, error) {
	if err := checkPath("readdir", name); err != nil {
		return nil, err
	}
	fd, err := o.open(name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, pathErr("readdir", name, err)
	}
	sort.Strings(names)
	out := make([]FileInfo, 0, len(names))
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
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
