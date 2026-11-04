package hostfs

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
	"time"
)

// MemFS is an in-memory FS for tests. It follows the rules of the real
// filesystem: symbolic links resolve inside the root, the denylist applies to
// content reads, and only regular files can be read. It does not check
// permissions; use SetError to simulate an unreadable path.
type MemFS struct {
	nodes map[string]*memNode
	// ScannerUID is the user the scan runs as; symlinks owned by root or by
	// this user are followed (default 0).
	ScannerUID int64
}

type memNode struct {
	mode     fs.FileMode
	uid, gid int64
	data     []byte
	target   string // for symbolic links
	err      error  // returned for any access through this path
}

// memModTime is the fixed modification time of every MemFS file.
var memModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// errLoop is returned when symbolic links nest too deeply.
var errLoop = errors.New("too many levels of symbolic links")

// NewMemFS returns a MemFS holding only the root directory (0755, root:root).
func NewMemFS() *MemFS {
	return &MemFS{nodes: map[string]*memNode{"/": {mode: fs.ModeDir | 0o755}}}
}

// AddFile adds a regular file with the given contents, permissions (classic
// octal, e.g. 0o644 or 0o4755) and owner. Missing parent directories are
// created as 0755 root:root.
func (m *MemFS) AddFile(name, content string, perm uint32, uid, gid int64) *MemFS {
	m.add(name, &memNode{mode: modeFromPerm(perm), uid: uid, gid: gid, data: []byte(content)})
	return m
}

// AddDir adds a directory.
func (m *MemFS) AddDir(name string, perm uint32, uid, gid int64) *MemFS {
	m.add(name, &memNode{mode: fs.ModeDir | modeFromPerm(perm), uid: uid, gid: gid})
	return m
}

// AddSymlink adds a symbolic link to target, owned by root.
func (m *MemFS) AddSymlink(name, target string) *MemFS {
	m.add(name, &memNode{mode: fs.ModeSymlink | 0o777, target: target})
	return m
}

// SetOwner changes the owner of an existing path (without following links).
func (m *MemFS) SetOwner(name string, uid, gid int64) *MemFS {
	n, ok := m.nodes[m.key(name)]
	if !ok {
		panic(fmt.Sprintf("hostfs.MemFS: SetOwner of missing path %q", name))
	}
	n.uid, n.gid = uid, gid
	return m
}

// AddSpecial adds a non-regular, non-directory file of the given type
// (fs.ModeNamedPipe, fs.ModeSocket, fs.ModeDevice, ...).
func (m *MemFS) AddSpecial(name string, typ fs.FileMode, perm uint32, uid, gid int64) *MemFS {
	m.add(name, &memNode{mode: typ | modeFromPerm(perm), uid: uid, gid: gid})
	return m
}

// SetError makes reading name, or looking anything up through it, fail with
// err (e.g. fs.ErrPermission), like a directory without search permission or
// an unreadable file. Its own metadata stays visible, as on Linux. The path
// is created as an empty directory if missing.
func (m *MemFS) SetError(name string, err error) *MemFS {
	if name == "/" {
		m.nodes["/"].err = err
		return m
	}
	if n, ok := m.nodes[m.key(name)]; ok {
		n.err = err
		return m
	}
	m.add(name, &memNode{mode: fs.ModeDir | 0o755, err: err})
	return m
}

// add stores n at name. Missing parent directories are created (0755,
// root:root); parents that are symlinks are followed, as a real filesystem
// would, so the node is reachable through every path that leads to it.
func (m *MemFS) add(name string, n *memNode) {
	if checkPath("add", name) != nil || name == "/" {
		panic(fmt.Sprintf("hostfs.MemFS: invalid path %q", name))
	}
	m.nodes[m.key(name)] = n
}

// key returns the canonical path of name for fixture building: parents are
// resolved through symlinks (without the scan-time checks) and created when
// missing; the last element is kept as is.
func (m *MemFS) key(name string) string {
	stack := []string{"/"}
	parts := splitPath(path.Dir(name))
	for links := 0; len(parts) > 0; {
		comp := parts[0]
		parts = parts[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		next := path.Join(stack[len(stack)-1], comp)
		n, ok := m.nodes[next]
		switch {
		case !ok:
			m.nodes[next] = &memNode{mode: fs.ModeDir | 0o755}
		case n.mode&fs.ModeSymlink != 0:
			if links++; links > 40 {
				panic(fmt.Sprintf("hostfs.MemFS: symlink loop under %q", name))
			}
			if path.IsAbs(n.target) {
				stack = stack[:1]
			}
			parts = append(splitPath(n.target), parts...)
			continue
		}
		stack = append(stack, next)
	}
	return path.Join(stack[len(stack)-1], path.Base(name))
}

func modeFromPerm(perm uint32) fs.FileMode {
	mode := fs.FileMode(perm & 0o777)
	if perm&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if perm&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if perm&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

// resolve walks name from the root with the rules of the real filesystem:
// one component at a time, ".." never above the root, symlinks followed only
// when owned by root or ScannerUID (a final one only if follow is set). An
// error set with SetError applies when looking something up through that
// node. It returns the canonical path and the node.
func (m *MemFS) resolve(name string, follow bool) (string, *memNode, error) {
	stack := []string{"/"}
	parts := splitPath(name)
	for links := 0; len(parts) > 0; {
		comp := parts[0]
		parts = parts[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		cur := stack[len(stack)-1]
		if err := m.nodes[cur].err; err != nil {
			return "", nil, err
		}
		next := path.Join(cur, comp)
		n, ok := m.nodes[next]
		if !ok {
			return "", nil, fs.ErrNotExist
		}
		if n.mode&fs.ModeSymlink != 0 && (len(parts) > 0 || follow) {
			if n.uid != 0 && n.uid != m.ScannerUID {
				return "", nil, fmt.Errorf("owned by uid %d: %w", n.uid, ErrUnsafeSymlink)
			}
			if links++; links > 40 {
				return "", nil, errLoop
			}
			if path.IsAbs(n.target) {
				stack = stack[:1]
			}
			parts = append(splitPath(n.target), parts...)
			continue
		}
		if len(parts) > 0 && !n.mode.IsDir() {
			return "", nil, fs.ErrNotExist
		}
		stack = append(stack, next)
	}
	p := stack[len(stack)-1]
	return p, m.nodes[p], nil
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func (m *MemFS) info(name string, n *memNode) FileInfo {
	return FileInfo{
		Path: name, Mode: n.mode, UID: n.uid, GID: n.gid,
		Size: int64(len(n.data)), ModTime: memModTime, Nlink: 1,
	}
}

// Stat implements FS.
func (m *MemFS) Stat(name string) (FileInfo, error) {
	if err := checkPath("stat", name); err != nil {
		return FileInfo{}, err
	}
	_, n, err := m.resolve(name, true)
	if err != nil {
		return FileInfo{}, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return m.info(name, n), nil
}

// Lstat implements FS.
func (m *MemFS) Lstat(name string) (FileInfo, error) {
	if err := checkPath("lstat", name); err != nil {
		return FileInfo{}, err
	}
	_, n, err := m.resolve(name, false)
	if err != nil {
		return FileInfo{}, &fs.PathError{Op: "lstat", Path: name, Err: err}
	}
	return m.info(name, n), nil
}

// ReadLink implements FS.
func (m *MemFS) ReadLink(name string) (string, error) {
	if err := checkPath("readlink", name); err != nil {
		return "", err
	}
	_, n, err := m.resolve(name, false)
	if err == nil && n.mode&fs.ModeSymlink == 0 {
		err = errors.New("not a symbolic link")
	}
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return n.target, nil
}

// ReadFile implements FS.
func (m *MemFS) ReadFile(name string) ([]byte, error) { return m.read(name, true, MaxReadSize) }

// readSensitive reads a denylisted file for a parser in this package.
func (m *MemFS) readSensitive(name string) ([]byte, error) { return m.read(name, false, MaxReadSize) }

// readLarge reads a file that may be larger than MaxReadSize, up to limit.
func (m *MemFS) readLarge(name string, limit int64) ([]byte, error) { return m.read(name, true, limit) }

func (m *MemFS) read(name string, enforceDenylist bool, limit int64) ([]byte, error) {
	if err := checkPath("read", name); err != nil {
		return nil, err
	}
	if enforceDenylist && denied(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
	}
	resolved, n, err := m.resolve(name, true)
	switch {
	case err != nil:
	case n.err != nil:
		err = n.err
	case !n.mode.IsRegular():
		err = ErrNotRegular
	case enforceDenylist && denied(resolved):
		err = ErrDenied
	case int64(len(n.data)) > limit:
		err = ErrTooLarge
	}
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	return append([]byte(nil), n.data...), nil
}

// ReadDir implements FS.
func (m *MemFS) ReadDir(name string) ([]FileInfo, error) {
	entries, _, err := m.readDirN(name, -1, nil)
	return entries, err
}

func (m *MemFS) readDirN(name string, limit int, skip func(string) bool) ([]FileInfo, bool, error) {
	entries, err := m.readDir(name)
	if err == nil && skip != nil {
		entries = slices.DeleteFunc(entries, func(e FileInfo) bool { return skip(e.Path) })
	}
	if err != nil || limit < 0 || len(entries) <= limit {
		return entries, false, err
	}
	return entries[:limit], true, nil
}

func (m *MemFS) readDir(name string) ([]FileInfo, error) {
	if err := checkPath("readdir", name); err != nil {
		return nil, err
	}
	resolved, n, err := m.resolve(name, true)
	switch {
	case err != nil:
	case n.err != nil:
		err = n.err
	case !n.mode.IsDir():
		err = fs.ErrNotExist
	}
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	var out []FileInfo
	for p, child := range m.nodes {
		if p != "/" && path.Dir(p) == resolved {
			out = append(out, m.info(path.Join(name, path.Base(p)), child))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
