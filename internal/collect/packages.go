package collect

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Packages are the `packages` facts: what the package manager has installed.
type Packages struct {
	// Manager is the package database the list comes from: "dpkg" or "rpm".
	Manager string `json:"manager"`
	// Installed maps a package name to its installed instances, in
	// architecture order; a name has several on multi-arch systems. A
	// package that is removed but has its configuration files left is not
	// installed.
	Installed map[string][]Package `json:"installed"`
}

// Package is one installed package.
type Package struct {
	// Version is the full version: [epoch:]upstream[-revision] for dpkg,
	// [epoch:]version-release for rpm.
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// State is the dpkg status: "installed", or a partly installed state
	// such as "unpacked" or "half-configured"; "installed" for rpm.
	State  string `json:"state"`
	Source string `json:"source"`
}

const (
	dpkgStatus  = "/var/lib/dpkg/status"
	dpkgUpdates = "/var/lib/dpkg/updates"
)

// rpmDatabase is a place and format of an rpm database. A nil parse is a
// format that is not read (ndb on SUSE): the collector fails, so checks that
// read the packages are ERROR.
type rpmDatabase struct {
	path  string
	parse func([]byte) ([]rpmPackage, error)
	// pending are files holding changes the database file does not have yet.
	pending []string
}

// rpmDatabases are tried in order: SQLite (EL9 and later), the Berkeley DB of
// EL7 and EL8, then the ndb of SUSE.
var rpmDatabases = []rpmDatabase{
	{"/var/lib/rpm/rpmdb.sqlite", readRPMSQLite, []string{"-wal", "-journal"}},
	{"/usr/lib/sysimage/rpm/rpmdb.sqlite", readRPMSQLite, []string{"-wal", "-journal"}},
	{"/var/lib/rpm/Packages", readRPMBDB, nil},
	{"/usr/lib/sysimage/rpm/Packages.db", nil, nil},
}

// maxRPMDB bounds how much of an rpm database is read into memory.
const maxRPMDB = 512 << 20

type packagesCollector struct{}

func (packagesCollector) Name() string          { return "packages" }
func (packagesCollector) Version() int          { return 1 }
func (packagesCollector) Access() engine.Access { return engine.AccessFilesystem }
func (packagesCollector) Type() reflect.Type    { return reflect.TypeFor[Packages]() }

// Collect reads the package database files directly: running rpm would write
// to its database (SQLite and Berkeley DB readers update their shared files).
// A database format that is not read (ndb on SUSE) leaves the targets without
// package facts, and checks that read them are ERROR, never shown an empty
// list.
func (packagesCollector) Collect(ctx context.Context, h *hostfs.Host) (engine.Facts, error) {
	data, err := readBig(h.FS, dpkgStatus)
	switch {
	case err == nil:
		return readDpkg(h.FS, data)
	case !errors.Is(err, fs.ErrNotExist):
		return engine.Facts{}, err
	}
	for _, db := range rpmDatabases {
		switch _, err := h.FS.Stat(db.path); {
		case err == nil && db.parse == nil:
			return engine.Facts{}, fmt.Errorf("%s: reading this rpm database format (ndb on SUSE) is not supported yet", db.path)
		case err == nil:
			return readRPM(ctx, h.FS, db)
		case !errors.Is(err, fs.ErrNotExist):
			return engine.Facts{}, err
		}
	}
	return engine.Facts{}, errors.New("no dpkg or rpm package database found")
}

// readRPM reads an rpm database with parse. Changes still in the write-ahead
// log or a rollback journal of a SQLite database are not in the file yet: the
// list may be outdated.
func readRPM(ctx context.Context, fsys hostfs.FS, rdb rpmDatabase) (engine.Facts, error) {
	db := rdb.path
	// rpm may be writing the live database: read it again when its size or
	// time changed while it was read, so the pages are not from two states.
	var data []byte
	for attempt := 0; ; attempt++ {
		before, err := fsys.Stat(db)
		if err != nil {
			return engine.Facts{}, err
		}
		if data, err = hostfs.ReadLargeFile(fsys, db, maxRPMDB); err != nil {
			return engine.Facts{}, err
		}
		after, err := fsys.Stat(db)
		if err != nil {
			return engine.Facts{}, err
		}
		if before.Size == after.Size && before.ModTime.Equal(after.ModTime) {
			break
		}
		if attempt == 2 {
			return engine.Facts{}, fmt.Errorf("%s: changed while being read (is rpm running?)", db)
		}
		select { // let a transaction go on before reading again
		case <-ctx.Done():
			return engine.Facts{}, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 500 * time.Millisecond):
		}
	}
	pkgs, err := rdb.parse(data)
	if err != nil {
		return engine.Facts{}, fmt.Errorf("%s: %w", db, err)
	}
	p := &Packages{Manager: "rpm", Installed: map[string][]Package{}}
	for _, pkg := range pkgs {
		p.Installed[pkg.name] = append(p.Installed[pkg.name], Package{Version: pkg.fullVersion(), Arch: pkg.arch, State: "installed", Source: db})
	}
	for _, instances := range p.Installed {
		slices.SortFunc(instances, func(a, b Package) int {
			return cmp.Or(strings.Compare(a.Arch, b.Arch), strings.Compare(a.Version, b.Version))
		})
	}
	f := engine.Facts{Value: p, Complete: true}
	for _, suffix := range rdb.pending {
		side := db + suffix
		if fi, err := fsys.Stat(side); err == nil && fi.Size > 0 {
			f.Complete = false
			f.Skipped = append(f.Skipped, side+": the rpm database has changes not yet written to "+path.Base(db))
		}
	}
	return f, nil
}

// dpkgEntry is one stanza of the dpkg database.
type dpkgEntry struct {
	name, arch, version, status, source string
}

// readDpkg reads the status file, then the journal of changes dpkg has not
// merged into it yet (/var/lib/dpkg/updates, applied in order), as dpkg does.
func readDpkg(fsys hostfs.FS, status []byte) (engine.Facts, error) {
	entries, err := parseDpkg(dpkgStatus, status)
	if err != nil {
		return engine.Facts{}, err
	}
	byID := map[string]dpkgEntry{}
	var order []string
	add := func(e dpkgEntry) {
		id := e.name + ":" + e.arch
		if _, seen := byID[id]; !seen {
			order = append(order, id)
		}
		byID[id] = e
	}
	for _, e := range entries {
		add(e)
	}
	updates, err := fsys.ReadDir(dpkgUpdates)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return engine.Facts{}, err
	}
	for _, u := range updates {
		name := path.Base(u.Path)
		if strings.Trim(name, "0123456789") != "" || u.IsDir() {
			continue // only numbered files are journal entries
		}
		data, err := fsys.ReadFile(u.Path)
		if err != nil {
			return engine.Facts{}, err
		}
		changes, err := parseDpkg(u.Path, data)
		if err != nil {
			return engine.Facts{}, err
		}
		for _, e := range changes {
			add(e)
		}
	}
	p := &Packages{Manager: "dpkg", Installed: map[string][]Package{}}
	var skipped []string
	for _, id := range order {
		e := byID[id]
		// The third word of Status is the package state; "not-installed"
		// and "config-files" (removed, configuration kept) leave no program
		// behind. Any other state counts as installed, so a half-installed
		// service is never taken for an absent one.
		fields := strings.Fields(e.status)
		if len(fields) != 3 {
			// A damaged stanza: whether the package is installed is unknown,
			// not absent.
			skipped = append(skipped, fmt.Sprintf("%s: package %s has no valid Status field", e.source, e.name))
			continue
		}
		if fields[2] == "not-installed" || fields[2] == "config-files" {
			continue
		}
		if e.arch == "" {
			// dpkg tells packages apart by name and architecture; without one
			// a journal entry cannot be matched to its status entry.
			skipped = append(skipped, fmt.Sprintf("%s: package %s has no Architecture field", e.source, e.name))
		}
		p.Installed[e.name] = append(p.Installed[e.name], Package{Version: e.version, Arch: e.arch, State: fields[2], Source: e.source})
	}
	for _, instances := range p.Installed {
		slices.SortFunc(instances, func(a, b Package) int { return strings.Compare(a.Arch, b.Arch) })
	}
	return engine.Facts{Value: p, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// parseDpkg reads the stanzas of a dpkg database file.
func parseDpkg(file string, data []byte) ([]dpkgEntry, error) {
	var out []dpkgEntry
	var cur dpkgEntry
	flush := func() {
		if cur.name != "" {
			out = append(out, cur)
		}
		cur = dpkgEntry{}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		switch {
		case text == "":
			flush()
			continue
		case text[0] == ' ' || text[0] == '\t':
			continue // continuation of a multi-line field
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Package":
			flush()
			cur.name, cur.source = value, fmt.Sprintf("%s:%d", file, line)
		case "Status":
			cur.status = value
		case "Version":
			cur.version = value
		case "Architecture":
			cur.arch = value
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	flush()
	return out, nil
}
