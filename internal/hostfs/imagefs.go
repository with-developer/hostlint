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

// ImageFS is the merged filesystem of a container image, held in memory (ADR 0011). It is built once by
// an ImageBuilder from untrusted layers and never changes afterwards, so collectors may read it from
// several goroutines. Like every FS here it is read-only, symbolic links resolve inside it, the denylist
// applies to content reads, and only regular files can be read.
//
// Nothing outside the image is reachable, so symbolic links are followed whoever owns them.
type ImageFS struct {
	root *imgNode
}

type imgNode struct {
	mode     fs.FileMode
	uid, gid int64
	size     int64
	mtime    time.Time
	content  *imgContent
	// notKept is a regular file whose contents the loader did not keep (too large): it reads as "too
	// large", never as empty or absent.
	notKept  bool
	denied   bool // content reads refused (a hard link to a denylisted file)
	target   string
	children map[string]*imgNode
	layer    int
}

// imgContent is the bytes of a regular file; hard links share it.
type imgContent struct {
	data []byte
	refs int
}

var _ FS = (*ImageFS)(nil)

// Limits an ImageBuilder holds an image to. They keep a hostile layer from using the memory of the scanner.
const (
	// MaxImageNodes is the most files, directories and links an image may have.
	MaxImageNodes = 1_000_000
	// MaxImageContent is the most bytes of file contents kept in memory.
	MaxImageContent = 512 << 20
	// ImageKeepSize is the largest file whose contents are kept; bigger files are metadata only,
	// except the package databases (see ImageKeeps).
	ImageKeepSize = 1 << 20
	maxImagePath  = 4096
	maxImageName  = 255
	maxImageLinks = 40
)

// ErrImageLimit is returned when an image goes past a limit: the scan is refused, because a partial
// filesystem would make checks for absent files pass.
var ErrImageLimit = errors.New("the image is past a limit")

// ImageKeeps reports whether the contents of the regular file at name, size bytes long, are kept: small
// files always, the package databases up to what the collectors read of them.
func ImageKeeps(name string, size int64) bool {
	if size <= ImageKeepSize {
		return true
	}
	if size > MaxImageContent {
		return false
	}
	return name == "/var/lib/dpkg/status" || strings.HasPrefix(name, "/var/lib/rpm/") || strings.HasPrefix(name, "/usr/lib/sysimage/rpm/")
}

// ImageEntryType is what an entry of a layer is.
type ImageEntryType int

// The entry types of a layer that an image filesystem can hold.
const (
	ImageDir ImageEntryType = iota
	ImageFile
	ImageSymlink
	ImageHardlink
	ImageSpecial
)

// ImageEntry is one entry of a layer, with its path already made absolute and clean by the loader.
type ImageEntry struct {
	Path    string
	Type    ImageEntryType
	Perm    uint32 // classic octal permission bits, including 04000, 02000 and 01000
	UID     int64
	GID     int64
	ModTime time.Time
	// Size is the size of a regular file. Data holds its contents when Keep is set.
	Size int64
	Data []byte
	Keep bool
	// Target is the target of a symbolic link, or the absolute path of the file a hard link points to.
	Target string
	// Special is the file type of a device or a pipe (fs.ModeDevice, fs.ModeCharDevice, fs.ModeNamedPipe).
	Special fs.FileMode
}

// ImageBuilder applies the layers of an image in order.
type ImageBuilder struct {
	root  *imgNode
	layer int
	nodes int
	kept  int64
	done  bool
}

// NewImageBuilder returns a builder holding an empty root directory.
func NewImageBuilder() *ImageBuilder {
	return &ImageBuilder{root: &imgNode{mode: fs.ModeDir | 0o755, children: map[string]*imgNode{}, mtime: memModTime}, layer: 0}
}

// BeginLayer starts the next layer. A whiteout or an opaque directory of a layer only removes what the
// layers before it made, wherever in the layer it is.
func (b *ImageBuilder) BeginLayer() { b.layer++ }

// Finish ends the build. The builder cannot be used after that.
func (b *ImageBuilder) Finish() *ImageFS {
	b.done = true
	return &ImageFS{root: b.root}
}

// Nodes is the number of files, directories and links so far.
func (b *ImageBuilder) Nodes() int { return b.nodes }

func newDir(layer int) *imgNode {
	return &imgNode{mode: fs.ModeDir | 0o755, children: map[string]*imgNode{}, mtime: memModTime, layer: layer}
}

// parent returns the directory that holds the last element of p, following symbolic links in the parents
// as a real extraction does (an absolute target starts at the image root), and creating the parents that
// are missing (0755, root:root). p is absolute and clean, and not "/".
func (b *ImageBuilder) parent(p string, create bool) (*imgNode, string, error) {
	dir, name := path.Split(p)
	parts := splitPath(dir)
	cur := b.root
	stack := []*imgNode{b.root}
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
			cur = stack[len(stack)-1]
			continue
		}
		next, ok := cur.children[comp]
		if !ok {
			if !create {
				return nil, "", fs.ErrNotExist
			}
			if err := b.count(); err != nil {
				return nil, "", err
			}
			next = newDir(b.layer)
			cur.children[comp] = next
		}
		switch {
		case next.mode&fs.ModeSymlink != 0:
			if links++; links > maxImageLinks {
				return nil, "", fmt.Errorf("%s: %w", p, errLoop)
			}
			if path.IsAbs(next.target) {
				stack = stack[:1]
				cur = b.root
			}
			parts = append(splitPath(next.target), parts...)
			continue
		case !next.mode.IsDir():
			return nil, "", fmt.Errorf("%s: a parent is not a directory", p)
		}
		stack = append(stack, next)
		cur = next
	}
	return cur, name, nil
}

// lookup finds the node at p, following symbolic links in the parents but not in the last element.
func (b *ImageBuilder) lookup(p string) (*imgNode, error) {
	if p == "/" {
		return b.root, nil
	}
	dir, name, err := b.parent(p, false)
	if err != nil {
		return nil, err
	}
	n, ok := dir.children[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return n, nil
}

func (b *ImageBuilder) count() error {
	if b.nodes++; b.nodes > MaxImageNodes {
		return fmt.Errorf("more than %d files: %w", MaxImageNodes, ErrImageLimit)
	}
	return nil
}

// release gives back what a node that leaves the image held.
func (b *ImageBuilder) release(n *imgNode) {
	if n.mode.IsDir() {
		for _, c := range n.children {
			b.release(c)
		}
	}
	if n.content != nil {
		if n.content.refs--; n.content.refs == 0 {
			b.kept -= int64(len(n.content.data))
		}
	}
	b.nodes--
}

// Add applies one entry of the current layer.
func (b *ImageBuilder) Add(e ImageEntry) error {
	if b.done {
		return errors.New("the image is finished")
	}
	if e.Path == "/" {
		if e.Type != ImageDir {
			return errors.New("the root of the image is not a directory")
		}
		b.root.mode = fs.ModeDir | modeFromPerm(e.Perm)
		b.root.uid, b.root.gid = e.UID, e.GID
		return nil
	}
	if err := checkImagePath(e.Path); err != nil {
		return err
	}
	dir, name, err := b.parent(e.Path, true)
	if err != nil {
		return err
	}
	old := dir.children[name]
	if e.Type == ImageDir && old != nil && old.mode.IsDir() {
		old.mode = fs.ModeDir | modeFromPerm(e.Perm) // a directory entry of a layer merges into the directory
		old.uid, old.gid, old.mtime, old.layer = e.UID, e.GID, e.ModTime, b.layer
		return nil
	}
	n := &imgNode{uid: e.UID, gid: e.GID, mtime: e.ModTime, layer: b.layer}
	switch e.Type {
	case ImageDir:
		n.mode, n.children = fs.ModeDir|modeFromPerm(e.Perm), map[string]*imgNode{}
	case ImageFile:
		n.mode, n.size = modeFromPerm(e.Perm), e.Size
		if e.Keep {
			if int64(len(e.Data)) != e.Size {
				return fmt.Errorf("%s: %d bytes kept of %d", e.Path, len(e.Data), e.Size)
			}
			if b.kept+e.Size > MaxImageContent {
				return fmt.Errorf("more than %d MiB of file contents: %w", MaxImageContent>>20, ErrImageLimit)
			}
			b.kept += e.Size
			n.content = &imgContent{data: e.Data, refs: 1}
		} else {
			n.notKept = true
		}
	case ImageSymlink:
		if e.Target == "" || len(e.Target) > maxImagePath || strings.ContainsRune(e.Target, 0) {
			return fmt.Errorf("%s: not a usable link target", e.Path)
		}
		n.mode, n.target = fs.ModeSymlink|0o777, e.Target
	case ImageSpecial:
		n.mode = e.Special | modeFromPerm(e.Perm)
	case ImageHardlink:
		if err := checkImagePath(e.Target); err != nil {
			return fmt.Errorf("%s: hard link target: %w", e.Path, err)
		}
		t, err := b.lookup(e.Target)
		if err != nil {
			return fmt.Errorf("%s: hard link to %s: %w", e.Path, e.Target, err)
		}
		if t.mode.IsDir() {
			return fmt.Errorf("%s: hard link to a directory", e.Path)
		}
		// A hard link is the same file: mode and owner come from it, not from the link's header.
		c := *t
		c.layer = b.layer
		c.denied = t.denied || denied(e.Target)
		if c.content != nil {
			c.content.refs++
		}
		n = &c
	default:
		return fmt.Errorf("%s: unsupported entry type", e.Path)
	}
	if old != nil {
		b.release(old) // replaced: a file over a directory removes the whole directory
		delete(dir.children, name)
	}
	if err := b.count(); err != nil {
		return err
	}
	dir.children[name] = n
	return nil
}

// Whiteout removes what the layers before this one have at p. Entries of this layer stay.
func (b *ImageBuilder) Whiteout(p string) error {
	if p == "/" {
		return errors.New("the root of the image cannot be removed")
	}
	if err := checkImagePath(p); err != nil {
		return err
	}
	dir, name, err := b.parent(p, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // nothing to remove
	}
	if err != nil {
		return err
	}
	b.removeLower(dir, name)
	return nil
}

// Opaque removes everything the layers before this one have in directory p.
func (b *ImageBuilder) Opaque(p string) error {
	if err := checkImagePath(p); err != nil {
		return err
	}
	n, err := b.lookup(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !n.mode.IsDir() {
		return nil
	}
	for name := range n.children {
		b.removeLower(n, name)
	}
	return nil
}

// removeLower removes the node dir/name unless it is of the current layer; a directory that still has
// entries of the current layer stays.
func (b *ImageBuilder) removeLower(dir *imgNode, name string) {
	n, ok := dir.children[name]
	if !ok {
		return
	}
	if n.mode.IsDir() {
		for c := range n.children {
			b.removeLower(n, c)
		}
		if len(n.children) > 0 || n.layer >= b.layer {
			return
		}
	} else if n.layer >= b.layer {
		return
	}
	b.release(n)
	delete(dir.children, name)
}

func checkImagePath(p string) error {
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return fmt.Errorf("%q: %w", p, ErrInvalidPath)
	}
	if len(p) > maxImagePath {
		return fmt.Errorf("a path of %d bytes: %w", len(p), ErrImageLimit)
	}
	for _, c := range splitPath(p) {
		if len(c) > maxImageName {
			return fmt.Errorf("a name of %d bytes: %w", len(c), ErrImageLimit)
		}
	}
	return nil
}

// resolve finds the node at name: one component at a time, ".." never above the root, symbolic links
// followed (the last one only if follow is set). It returns the canonical path and the node.
func (f *ImageFS) resolve(name string, follow bool) (string, *imgNode, error) {
	stack := []string{}
	nodes := []*imgNode{f.root}
	parts := splitPath(name)
	for links := 0; len(parts) > 0; {
		comp := parts[0]
		parts = parts[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack, nodes = stack[:len(stack)-1], nodes[:len(nodes)-1]
			}
			continue
		}
		cur := nodes[len(nodes)-1]
		if !cur.mode.IsDir() {
			return "", nil, fs.ErrNotExist
		}
		n, ok := cur.children[comp]
		if !ok {
			return "", nil, fs.ErrNotExist
		}
		if n.mode&fs.ModeSymlink != 0 && (len(parts) > 0 || follow) {
			if links++; links > maxImageLinks {
				return "", nil, errLoop
			}
			if path.IsAbs(n.target) {
				stack, nodes = stack[:0], nodes[:1]
			}
			parts = append(splitPath(n.target), parts...)
			continue
		}
		stack, nodes = append(stack, comp), append(nodes, n)
	}
	return "/" + strings.Join(stack, "/"), nodes[len(nodes)-1], nil
}

func (f *ImageFS) info(name string, n *imgNode) FileInfo {
	nlink := int64(1)
	if n.content != nil && n.content.refs > 1 {
		nlink = int64(n.content.refs)
	}
	return FileInfo{Path: name, Mode: n.mode, UID: n.uid, GID: n.gid, Size: n.size, ModTime: n.mtime, Nlink: nlink}
}

// Stat implements FS.
func (f *ImageFS) Stat(name string) (FileInfo, error) {
	if err := checkPath("stat", name); err != nil {
		return FileInfo{}, err
	}
	_, n, err := f.resolve(name, true)
	if err != nil {
		return FileInfo{}, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	return f.info(name, n), nil
}

// Lstat implements FS.
func (f *ImageFS) Lstat(name string) (FileInfo, error) {
	if err := checkPath("lstat", name); err != nil {
		return FileInfo{}, err
	}
	_, n, err := f.resolve(name, false)
	if err != nil {
		return FileInfo{}, &fs.PathError{Op: "lstat", Path: name, Err: err}
	}
	return f.info(name, n), nil
}

// ReadLink implements FS.
func (f *ImageFS) ReadLink(name string) (string, error) {
	if err := checkPath("readlink", name); err != nil {
		return "", err
	}
	_, n, err := f.resolve(name, false)
	if err == nil && n.mode&fs.ModeSymlink == 0 {
		err = errors.New("not a symbolic link")
	}
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return n.target, nil
}

// ReadFile implements FS.
func (f *ImageFS) ReadFile(name string) ([]byte, error) { return f.read(name, true, MaxReadSize) }

// readSensitive reads a denylisted file for a parser in this package.
func (f *ImageFS) readSensitive(name string) ([]byte, error) { return f.read(name, false, MaxReadSize) }

// readLarge reads a file that may be larger than MaxReadSize, up to limit.
func (f *ImageFS) readLarge(name string, limit int64) ([]byte, error) {
	return f.read(name, true, limit)
}

func (f *ImageFS) read(name string, enforceDenylist bool, limit int64) ([]byte, error) {
	if err := checkPath("read", name); err != nil {
		return nil, err
	}
	if enforceDenylist && denied(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrDenied}
	}
	resolved, n, err := f.resolve(name, true)
	switch {
	case err != nil:
	case !n.mode.IsRegular():
		err = ErrNotRegular
	case enforceDenylist && (n.denied || denied(resolved)):
		err = ErrDenied
	case n.size > limit:
		err = ErrTooLarge
	case n.notKept:
		err = fmt.Errorf("the image loader did not keep the contents: %w", ErrTooLarge)
	}
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	out := []byte{}
	if n.content != nil {
		out = append(out, n.content.data...)
	}
	return out, nil
}

// ReadDir implements FS.
func (f *ImageFS) ReadDir(name string) ([]FileInfo, error) {
	entries, _, err := f.readDirN(name, -1, nil)
	return entries, err
}

func (f *ImageFS) readDirN(name string, limit int, skip func(string) bool) ([]FileInfo, bool, error) {
	if err := checkPath("readdir", name); err != nil {
		return nil, false, err
	}
	_, n, err := f.resolve(name, true)
	if err == nil && !n.mode.IsDir() {
		err = fs.ErrNotExist
	}
	if err != nil {
		return nil, false, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	names := make([]string, 0, len(n.children))
	for c := range n.children {
		names = append(names, c)
	}
	sort.Strings(names)
	out := make([]FileInfo, 0, len(names))
	for _, c := range names {
		p := path.Join(name, c)
		if skip != nil && skip(p) {
			continue
		}
		out = append(out, f.info(p, n.children[c]))
	}
	if limit < 0 || len(out) <= limit {
		return out, false, nil
	}
	return out[:limit], true, nil
}
