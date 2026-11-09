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
	"testing/fstest"

	"go.yaml.in/yaml/v3"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
	"github.com/with-developer/vmsctl/internal/version"
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
	packNameRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	packFileRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*\.yaml$`)
	packAreaRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	// packSemverR reads a release number, with a pre-release suffix (v0.15.0-rc1, v0.15.0-3-gabc123).
	packSemverR   = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.+-]+)?$`)
	packVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$`)
)

// PackManifest is pack.yaml.
type PackManifest struct {
	// Format is the version of the pack format: 1.
	Format int `yaml:"format"`
	// Name is the name of the pack in kebab case, as results will name it.
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description"`
	// RequiresVmsctl is the oldest vmsctl release the pack works with, such as v0.27.0.
	RequiresVmsctl string `yaml:"requires_vmsctl"`
	// RequiresHostlint is the same, under the key the manifest had before the rename (ADR 0017). A release
	// before v0.27.0 reads only this key, so a pack for a mixed fleet keeps it.
	RequiresHostlint string `yaml:"requires_hostlint"`
}

// Requires is the oldest release the pack works with, from whichever of the two keys the manifest uses.
func (m *PackManifest) Requires() string {
	if m.RequiresVmsctl != "" {
		return m.RequiresVmsctl
	}
	return m.RequiresHostlint
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
			return nil, fmt.Errorf("pack %s: %q is not part of a pack (only pack.yaml, rules/ and profiles/)", dir, e.Name())
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
	var second yaml.Node
	if err := dec.Decode(&second); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("pack %s: pack.yaml: more than one YAML document", dir)
	}
	if err := checkManifest(&m, version.Get().Version); err != nil {
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
	// The pack is held in memory after it was read: what is parsed is what was hashed.
	mem := fstest.MapFS{}
	for p, data := range l.files {
		mem[p] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	rules, _ := fs.Sub(mem, "rules")
	profiles, _ := fs.Sub(mem, "profiles")
	return &Pack{
		PackManifest: m,
		Digest:       "sha256:" + hex.EncodeToString(h.Sum(nil)),
		Files:        paths,
		Source:       engine.PackSource{Name: m.Name, Rules: rules, Profiles: profiles},
	}, nil
}

// checkManifest validates pack.yaml; current is the version of this vmsctl, which a development build
// (not a release number) does not hold the pack to.
func checkManifest(m *PackManifest, current string) error {
	switch {
	case m.Format != 1:
		return fmt.Errorf("format must be 1, not %d", m.Format)
	case !packNameRe.MatchString(m.Name) || len(m.Name) > 40:
		return errors.New("name must be lowercase kebab case, at most 40 characters")
	case !packVersionRe.MatchString(m.Version):
		return errors.New("version is required: letters, digits and . _ + - only, at most 40 characters, such as 1.2.0")
	case len(m.Description) > 300:
		return errors.New("description is at most 300 characters")
	}
	if m.RequiresVmsctl != "" && m.RequiresHostlint != "" {
		return errors.New("name the release once: requires_vmsctl, or the old requires_hostlint (not both)")
	}
	if req := m.Requires(); req != "" {
		key := "requires_vmsctl"
		if m.RequiresVmsctl == "" {
			key = "requires_hostlint"
		}
		need := packSemverR.FindStringSubmatch(req)
		if need == nil {
			return fmt.Errorf("%s %q is not a release such as v0.15.0", key, req)
		}
		if cur := packSemverR.FindStringSubmatch(current); cur != nil && semverLess(cur, need) {
			return fmt.Errorf("the pack needs vmsctl %s or later; this is %s", req, current)
		}
	}
	return nil
}

// semverLess reports whether the release a is older than b; a pre-release is older than its release.
func semverLess(a, b []string) bool {
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(a[i])
		y, _ := strconv.Atoi(b[i])
		if x != y {
			return x < y
		}
	}
	return a[4] != "" && b[4] == ""
}

type packLoader struct {
	root  *os.Root
	dir   string
	files map[string][]byte
	total int
}

func (l *packLoader) fail(p, format string, args ...any) error {
	return fmt.Errorf("pack %s: %q: %s", l.dir, p, fmt.Sprintf(format, args...))
}

// trust checks what a file or directory of the pack would have to be for the pack to be trusted.
func (l *packLoader) trust(p string, fi fs.FileInfo) error {
	if fi.Mode().Perm()&0o022 != 0 {
		return l.fail(p, "writable by group or others (mode %04o); vmsctl does not trust a pack anyone else could change (chmod go-w)", fi.Mode().Perm())
	}
	if uid, ok := hostfs.Owner(fi); ok && uid != 0 && int64(uid) != int64(os.Getuid()) {
		return l.fail(p, "owned by uid %d, neither root nor you; vmsctl does not trust it (chown it, or copy the pack)", uid)
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
