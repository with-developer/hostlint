package engine

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// fileCollector observes the files that the planned file checks name: glob
// matches, metadata, links to missing targets, and the user and group names
// that owners are compared with. It runs like any other collector, bounded
// by the collector timeout, so evaluating file checks does no I/O
// (ADR 0006 §1). Rules cannot reference it.
type fileCollector struct {
	patterns []string // absolute paths and globs
}

// fileFacts is what the file collector observed.
type fileFacts struct {
	Globs map[string]globObservation // by pattern
	Files map[string]fileObservation // by path
	IDs   *idMap
}

// globObservation is the result of expanding one glob.
type globObservation struct {
	Matches []string
	// Problems are directories that could not be read; the matches are
	// incomplete when there are any.
	Problems []string
}

// fileObservation is the metadata of one path.
type fileObservation struct {
	Info hostfs.FileInfo // valid when the path exists and Err is empty
	// Missing is true when nothing exists at the path.
	Missing bool
	// DanglingTarget is set when the path is a symbolic link whose target
	// does not exist.
	DanglingTarget string
	// Err is set when the path could not be observed.
	Err string
}

const fileCollectorName = "files"

func (*fileCollector) Name() string       { return fileCollectorName }
func (*fileCollector) Version() int       { return 1 }
func (*fileCollector) Access() Access     { return AccessFilesystem }
func (*fileCollector) Type() reflect.Type { return reflect.TypeFor[fileFacts]() }

func (c *fileCollector) Collect(ctx context.Context, h *hostfs.Host) (Facts, error) {
	ff := &fileFacts{Globs: map[string]globObservation{}, Files: map[string]fileObservation{}}
	var paths []string
	for _, pattern := range c.patterns {
		if err := ctx.Err(); err != nil {
			return Facts{}, err
		}
		if !isGlob(pattern) {
			paths = append(paths, pattern)
			continue
		}
		matches, problems, err := hostfs.Glob(h.FS, pattern)
		if err != nil {
			return Facts{}, err
		}
		ff.Globs[pattern] = globObservation{Matches: matches, Problems: problems}
		paths = append(paths, matches...)
	}
	for _, p := range paths {
		if _, seen := ff.Files[p]; seen {
			continue
		}
		if err := ctx.Err(); err != nil {
			return Facts{}, err
		}
		ff.Files[p] = observeFile(h.FS, p)
	}
	ff.IDs = loadIDMap(h.FS)

	f := Facts{Value: ff, Complete: true}
	for _, g := range ff.Globs {
		f.Skipped = append(f.Skipped, g.Problems...)
	}
	for _, p := range sortedKeys(ff.Files) {
		if e := ff.Files[p].Err; e != "" {
			f.Skipped = append(f.Skipped, e)
		}
	}
	if len(f.Skipped) > 0 {
		f.Complete = false
		f.Skipped = boundList(f.Skipped, maxSkipped)
	}
	return f, nil
}

// observeFile records the metadata of p, telling a missing file apart from a
// symbolic link to a missing target.
func observeFile(fsys hostfs.FS, p string) fileObservation {
	fi, err := fsys.Stat(p)
	if err == nil {
		return fileObservation{Info: fi}
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return fileObservation{Err: err.Error()}
	}
	li, lerr := fsys.Lstat(p)
	switch {
	case errors.Is(lerr, fs.ErrNotExist):
		return fileObservation{Missing: true}
	case lerr != nil:
		return fileObservation{Err: lerr.Error()}
	case !li.IsSymlink():
		return fileObservation{Err: err.Error()}
	}
	target, err := fsys.ReadLink(p)
	switch {
	case err != nil:
		return fileObservation{Err: err.Error()}
	case target == "":
		target = "an empty target"
	}
	return fileObservation{DanglingTarget: target}
}

func isGlob(p string) bool { return strings.ContainsAny(p, `*?[`) }
