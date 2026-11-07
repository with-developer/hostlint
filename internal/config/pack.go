package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
	"github.com/with-developer/hostlint/internal/version"
)

// Limits on a policy pack (ADR 0012): it is read from a directory anyone with the right to write there
// could have changed, so how much is read from it is bounded.
const (
	maxPackBytes   = 4 << 20
	maxPackFile    = 256 << 10
	maxPackChecks  = 300
	maxPackProfile = 50
	maxPackEntries = 200
)

var (
	packNameRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	packFileRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*\.yaml$`)
	packAreaRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	packSemverR = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)
)

// PackManifest is pack.yaml.
type PackManifest struct {
	// Format is the version of the pack format: 1.
	Format int `yaml:"format"`
	// Name is the name of the pack in kebab case, as results will name it.
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	// RequiresHostlint is the oldest hostlint release the pack works with, such as v0.15.0.
	RequiresHostlint string `yaml:"requires_hostlint"`
}

// Pack is a policy pack read from a directory (ADR 0012).
type Pack struct {
	PackManifest
	// Digest identifies the pack: the SHA-256 over the sorted paths and the contents of the files that
	// were parsed.
	Digest string
	// Files lists the files that were read, sorted.
	Files  []string
	Source engine.PackSource
}

// LoadPack reads the pack in dir. Every file is opened once, through a root that cannot be left (no
// symbolic link, nothing outside), checked, read, hashed and parsed from those same bytes: nothing is
// checked at one time and used at another. The directory and everything in it is owned by root or by the
// user and is not writable by group or others, and the pack holds nothing but pack.yaml, rules/<area>/<name>.yaml
// and profiles/<id>.yaml: any other file is an error, not something that is skipped.
func LoadPack(dir string) (*Pack, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", dir, err)
	}
	defer root.Close()
	l := &packLoader{root: root, dir: dir, files: map[string][]byte{}}
	if err := l.checkDir("."); err != nil {
		return nil, err
	}
	top, err := l.list(".")
	if err != nil {
		return nil, err
	}
	var haveManifest bool
	for _, e := range top {
		switch {
		case e.Name() == "pack.yaml" && e.Type().IsRegular():
			haveManifest = true
		case e.Name() == "rules" && e.IsDir(), e.Name() == "profiles" && e.IsDir():
		default:
			return nil, fmt.Errorf("pack %s: %s is not part of a pack (only pack.yaml, rules/ and profiles/)", dir, e.Name())
		}
	}
	if !haveManifest {
		return nil, fmt.Errorf("pack %s: pack.yaml is missing", dir)
	}
	raw, err := l.read("pack.yaml")
	if err != nil {
		return nil, err
	}
	var m PackManifest
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("pack %s: pack.yaml: %w", dir, err)
	}
	if err := checkManifest(&m); err != nil {
		return nil, fmt.Errorf("pack %s: pack.yaml: %w", dir, err)
	}
	if err := l.readRules(); err != nil {
		return nil, err
	}
	if err := l.readProfiles(); err != nil {
		return nil, err
	}
	paths := slices.Sorted(func(yield func(string) bool) {
		for p := range l.files {
			if !yield(p) {
				return
			}
		}
	})
	h := sha256.New()
	for _, p := range paths {
		sum := sha256.Sum256(l.files[p])
		fmt.Fprintf(h, "%s\x00%x\n", p, sum)
	}
	mem := newMemFS(l.files)
	rules, _ := fs.Sub(mem, "rules")
	profiles, _ := fs.Sub(mem, "profiles")
	return &Pack{
		PackManifest: m,
		Digest:       "sha256:" + hex.EncodeToString(h.Sum(nil)),
		Files:        paths,
		Source:       engine.PackSource{Name: m.Name, Rules: rules, Profiles: profiles},
	}, nil
}

func checkManifest(m *PackManifest) error {
	switch {
	case m.Format != 1:
		return fmt.Errorf("format must be 1, not %d", m.Format)
	case !packNameRe.MatchString(m.Name) || len(m.Name) > 40:
		return errors.New("name must be lowercase kebab case, at most 40 characters")
	case strings.TrimSpace(m.Version) == "" || len(m.Version) > 40 || strings.ContainsAny(m.Version, "\n\r\x00 "):
		return errors.New("version is required: a short word without spaces, such as 1.2.0")
	case len(m.Description) > 300:
		return errors.New("description is at most 300 characters")
	}
	if m.RequiresHostlint != "" {
		need := packSemverR.FindStringSubmatch(m.RequiresHostlint)
		if need == nil {
			return fmt.Errorf("requires_hostlint %q is not a release such as v0.15.0", m.RequiresHostlint)
		}
		if cur := packSemverR.FindStringSubmatch(version.Get().Version); cur != nil && semverLess(cur, need) {
			return fmt.Errorf("the pack needs hostlint %s or later; this is %s", m.RequiresHostlint, version.Get().Version)
		}
	}
	return nil
}

func semverLess(a, b []string) bool {
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x < y
		}
	}
	return false
}

type packLoader struct {
	root  *os.Root
	dir   string
	files map[string][]byte
	total int
}

func (l *packLoader) fail(p, format string, args ...any) error {
	return fmt.Errorf("pack %s: %s: %s", l.dir, p, fmt.Sprintf(format, args...))
}

// trust checks what a file or directory of the pack would have to be for the pack to be trusted.
func (l *packLoader) trust(p string, fi fs.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return l.fail(p, "writable by group or others (mode %04o); hostlint does not trust a pack anyone else could change (chmod go-w)", fi.Mode().Perm())
	}
	if uid, ok := hostfs.Owner(fi); ok && uid != 0 && int64(uid) != int64(os.Getuid()) {
		return l.fail(p, "owned by uid %d, neither root nor you; hostlint does not trust it (chown it, or copy the pack)", uid)
	}
	return nil
}

func (l *packLoader) checkDir(p string) error {
	f, err := l.root.Open(p)
	if err != nil {
		return l.fail(p, "%v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return l.fail(p, "%v", err)
	}
	if !fi.IsDir() {
		return l.fail(p, "not a directory")
	}
	return l.trust(p, fi)
}

// list reads a directory of the pack, which is trusted like a file, and refuses one with too many entries.
func (l *packLoader) list(p string) ([]fs.DirEntry, error) {
	if err := l.checkDir(p); err != nil {
		return nil, err
	}
	f, err := l.root.Open(p)
	if err != nil {
		return nil, l.fail(p, "%v", err)
	}
	defer f.Close()
	ents, err := f.ReadDir(maxPackEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, l.fail(p, "%v", err)
	}
	if len(ents) > maxPackEntries {
		return nil, l.fail(p, "more than %d entries", maxPackEntries)
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	return ents, nil
}

// read reads one regular file, once, and keeps its bytes.
func (l *packLoader) read(p string) ([]byte, error) {
	f, err := l.root.Open(p)
	if err != nil {
		return nil, l.fail(p, "%v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, l.fail(p, "%v", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, l.fail(p, "not a regular file (a pack holds no links and no special files)")
	}
	if err := l.trust(p, fi); err != nil {
		return nil, err
	}
	if fi.Size() > maxPackFile {
		return nil, l.fail(p, "larger than %d KiB", maxPackFile>>10)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPackFile+1))
	if err != nil {
		return nil, l.fail(p, "%v", err)
	}
	if len(data) > maxPackFile {
		return nil, l.fail(p, "larger than %d KiB", maxPackFile>>10)
	}
	if l.total += len(data); l.total > maxPackBytes {
		return nil, l.fail(p, "the pack is larger than %d MiB", maxPackBytes>>20)
	}
	l.files[p] = data
	return data, nil
}

func (l *packLoader) readRules() error {
	areas, err := l.dirIfPresent("rules")
	if err != nil || areas == nil {
		return err
	}
	n := 0
	for _, a := range areas {
		if !a.IsDir() || !packAreaRe.MatchString(a.Name()) {
			return l.fail("rules/"+a.Name(), "a pack's checks are in rules/<area>/<name>.yaml")
		}
		files, err := l.list(path.Join("rules", a.Name()))
		if err != nil {
			return err
		}
		for _, f := range files {
			p := path.Join("rules", a.Name(), f.Name())
			if !f.Type().IsRegular() || !packFileRe.MatchString(f.Name()) {
				return l.fail(p, "a pack's checks are rules/<area>/<name>.yaml files, and nothing else is allowed there")
			}
			if n++; n > maxPackChecks {
				return l.fail("rules", "more than %d checks", maxPackChecks)
			}
			if _, err := l.read(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *packLoader) readProfiles() error {
	files, err := l.dirIfPresent("profiles")
	if err != nil || files == nil {
		return err
	}
	if len(files) > maxPackProfile {
		return l.fail("profiles", "more than %d profiles", maxPackProfile)
	}
	for _, f := range files {
		p := path.Join("profiles", f.Name())
		if !f.Type().IsRegular() || !packFileRe.MatchString(f.Name()) {
			return l.fail(p, "a pack's profiles are profiles/<id>.yaml files, and nothing else is allowed there")
		}
		if _, err := l.read(p); err != nil {
			return err
		}
	}
	return nil
}

// dirIfPresent lists a directory that the pack may not have: nil, nil when it does not.
func (l *packLoader) dirIfPresent(p string) ([]fs.DirEntry, error) {
	if _, err := l.root.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	ents, err := l.list(p)
	if ents == nil && err == nil {
		ents = []fs.DirEntry{}
	}
	return ents, err
}

// memFS is the pack, held in memory after it was read: what is parsed is what was hashed.
type memFS struct {
	files map[string][]byte
	dirs  map[string][]string
}

func newMemFS(files map[string][]byte) *memFS {
	m := &memFS{files: files, dirs: map[string][]string{".": nil}}
	// Directories and their entries.
	seen := map[string]bool{}
	for p := range files {
		for cur := p; cur != "."; cur = path.Dir(cur) {
			parent := path.Dir(cur)
			if !seen[cur] {
				seen[cur] = true
				m.dirs[parent] = append(m.dirs[parent], path.Base(cur))
			}
		}
	}
	for d := range m.dirs {
		sort.Strings(m.dirs[d])
	}
	return m
}

func (m *memFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if data, ok := m.files[name]; ok {
		return &memFile{name: name, data: data, r: bytes.NewReader(data)}, nil
	}
	if _, ok := m.dirs[name]; ok {
		return &memDir{m: m, name: name}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

type memFile struct {
	name string
	data []byte
	r    *bytes.Reader
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return memInfo{name: path.Base(f.name), size: int64(len(f.data))}, nil
}
func (f *memFile) Read(b []byte) (int, error) { return f.r.Read(b) }
func (f *memFile) Close() error               { return nil }

type memDir struct {
	m    *memFS
	name string
	read int
}

func (d *memDir) Stat() (fs.FileInfo, error) { return memInfo{name: path.Base(d.name), dir: true}, nil }
func (d *memDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *memDir) Close() error { return nil }
func (d *memDir) ReadDir(n int) ([]fs.DirEntry, error) {
	names := d.m.dirs[d.name]
	var out []fs.DirEntry
	for ; d.read < len(names) && (n <= 0 || len(out) < n); d.read++ {
		child := path.Join(d.name, names[d.read])
		if d.name == "." {
			child = names[d.read]
		}
		_, isFile := d.m.files[child]
		out = append(out, fs.FileInfoToDirEntry(memInfo{name: names[d.read], dir: !isFile, size: int64(len(d.m.files[child]))}))
	}
	if n > 0 && len(out) == 0 {
		return nil, io.EOF
	}
	return out, nil
}

type memInfo struct {
	name string
	size int64
	dir  bool
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64  { return i.size }
func (i memInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.dir }
func (i memInfo) Sys() any           { return nil }
