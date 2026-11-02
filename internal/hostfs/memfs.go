package hostfs

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
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

// AddSymlink adds a symbolic link to target.
func (m *MemFS) AddSymlink(name, target string) *MemFS {
	m.add(name, &memNode{mode: fs.ModeSymlink | 0o777, target: target})
	return m
}

// AddSpecial adds a non-regular, non-directory file of the given type
// (fs.ModeNamedPipe, fs.ModeSocket, fs.ModeDevice, ...).
func (m *MemFS) AddSpecial(name string, typ fs.FileMode, perm uint32, uid, gid int64) *MemFS {
	m.add(name, &memNode{mode: typ | modeFromPerm(perm), uid: uid, gid: gid})
	return m
}

// SetError makes every access through name fail with err (e.g.
// fs.ErrPermission). The path is created as an empty directory if missing.
func (m *MemFS) SetError(name string, err error) *MemFS {
	if n, ok := m.nodes[name]; ok {
		n.err = err
		return m
	}
	m.add(name, &memNode{mode: fs.ModeDir | 0o755, err: err})
	return m
}

func (m *MemFS) add(name string, n *memNode) {
	if checkPath("add", name) != nil || name == "/" {
		panic(fmt.Sprintf("hostfs.MemFS: invalid path %q", name))
	}
	for dir := path.Dir(name); dir != "/"; dir = path.Dir(dir) {
		if _, ok := m.nodes[dir]; !ok {
			m.nodes[dir] = &memNode{mode: fs.ModeDir | 0o755}
		}
	}
	m.nodes[name] = n
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

// resolve walks name from the root, following symbolic links inside the
// root (a final link only if follow is set). It returns the resolved path.
func (m *MemFS) resolve(name string, follow bool) (string, *memNode, error) {
	parts := splitPath(name)
	cur, links := "/", 0
	for i := 0; i < len(parts); i++ {
		next := path.Join(cur, parts[i])
		n, ok := m.nodes[next]
		if !ok {
			return "", nil, fs.ErrNotExist
		}
		if n.err != nil {
			return "", nil, n.err
		}
		last := i == len(parts)-1
		if n.mode&fs.ModeSymlink != 0 && (follow || !last) {
			if links++; links > 40 {
				return "", nil, errLoop
			}
			base := cur
			if path.IsAbs(n.target) {
				base = "/"
			}
			// path.Join never climbs above "/", which gives chroot semantics.
			parts = append(splitPath(path.Join(base, n.target)), parts[i+1:]...)
			cur, i = "/", -1
			continue
		}
		if !last && !n.mode.IsDir() {
			return "", nil, fs.ErrNotExist
		}
		cur = next
	}
	return cur, m.nodes[cur], nil
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
func (m *MemFS) ReadFile(name string) ([]byte, error) { return m.read(name, true) }

// readSensitive reads a denylisted file for a parser in this package.
func (m *MemFS) readSensitive(name string) ([]byte, error) { return m.read(name, false) }

func (m *MemFS) read(name string, enforceDenylist bool) ([]byte, error) {
	if err := checkPath("read", name); err != nil {
		return nil, err
	}
	if enforceDenylist && denied(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
	}
	resolved, n, err := m.resolve(name, true)
	switch {
	case err != nil:
	case !n.mode.IsRegular():
		err = ErrNotRegular
	case enforceDenylist && denied(resolved):
		err = ErrDenied
	case len(n.data) > MaxReadSize:
		err = ErrTooLarge
	}
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	return append([]byte(nil), n.data...), nil
}

// ReadDir implements FS.
func (m *MemFS) ReadDir(name string) ([]FileInfo, error) {
	if err := checkPath("readdir", name); err != nil {
		return nil, err
	}
	resolved, n, err := m.resolve(name, true)
	if err == nil && !n.mode.IsDir() {
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
