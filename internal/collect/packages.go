package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Packages are the `packages` facts: what the package manager has installed.
type Packages struct {
	// Manager is the package database the list comes from: "dpkg".
	Manager string `json:"manager"`
	// Installed maps a package name to its installed instances, in
	// architecture order; a name has several on multi-arch systems. A
	// package that is removed but has its configuration files left is not
	// installed.
	Installed map[string][]Package `json:"installed"`
}

// Package is one installed package.
type Package struct {
	// Version is the full version, [epoch:]upstream[-revision].
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// State is the dpkg status: "installed", or a partly installed state
	// such as "unpacked" or "half-configured".
	State  string `json:"state"`
	Source string `json:"source"`
}

const (
	dpkgStatus  = "/var/lib/dpkg/status"
	dpkgUpdates = "/var/lib/dpkg/updates"
)

// rpmDatabases are where an rpm database is found (SQLite since EL9, Berkeley
// DB before; SUSE uses ndb).
var rpmDatabases = []string{"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages.db"}

type packagesCollector struct{}

func (packagesCollector) Name() string          { return "packages" }
func (packagesCollector) Version() int          { return 1 }
func (packagesCollector) Access() engine.Access { return engine.AccessFilesystem }
func (packagesCollector) Type() reflect.Type    { return reflect.TypeFor[Packages]() }

// Collect reads the dpkg database. The rpm database is not read yet: running
// rpm would write to it (SQLite and Berkeley DB readers update their shared
// files), so rpm targets have no package facts and checks that read them are
// ERROR, never shown an empty list.
func (packagesCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	data, err := h.FS.ReadFile(dpkgStatus)
	switch {
	case err == nil:
		return readDpkg(h.FS, data)
	case !errors.Is(err, fs.ErrNotExist):
		return engine.Facts{}, err
	}
	for _, db := range rpmDatabases {
		if _, err := h.FS.Stat(db); err == nil {
			return engine.Facts{}, fmt.Errorf("%s: reading the rpm database is not supported yet", db)
		}
	}
	return engine.Facts{}, errors.New("no dpkg or rpm package database found")
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
	for _, id := range order {
		e := byID[id]
		// The third word of Status is the package state; "not-installed"
		// and "config-files" (removed, configuration kept) leave no program
		// behind. Any other state counts as installed, so a half-installed
		// service is never taken for an absent one.
		fields := strings.Fields(e.status)
		if len(fields) != 3 || fields[2] == "not-installed" || fields[2] == "config-files" {
			continue
		}
		p.Installed[e.name] = append(p.Installed[e.name], Package{Version: e.version, Arch: e.arch, State: fields[2], Source: e.source})
	}
	for _, instances := range p.Installed {
		slices.SortFunc(instances, func(a, b Package) int { return strings.Compare(a.Arch, b.Arch) })
	}
	return engine.Facts{Value: p, Complete: true}, nil
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
