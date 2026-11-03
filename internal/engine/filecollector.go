package engine

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"strings"
	"sync"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// fileCollector observes the files that the planned file checks name: glob
// matches, metadata, links to missing targets, and the user and group names
// that owners are compared with. It runs like any other collector, bounded
// by the collector timeout, so evaluating file checks does no I/O
// (ADR 0006 §1). Rules cannot reference it.
//
// Patterns are observed independently, a few at a time. When the timeout
// expires, what was observed is kept: a path that hangs (a dead network
// mount) or a pattern that cannot be expanded only affects the checks that
// name it.
type fileCollector struct {
	patterns []string // absolute paths and globs
}

// fileFacts is what the file collector observed.
type fileFacts struct {
	// Patterns has an entry for each pattern observed before the timeout.
	Patterns map[string]patternObservation
	IDs      *idMap
}

// patternObservation is what one path or glob resolved to.
type patternObservation struct {
	// Err is set when the pattern could not be expanded at all.
	Err string
	// Problems are what a glob could not see (unreadable directories, links
	// to missing targets on the way); its matches are incomplete then.
	Problems []string
	// Files are the path itself, or the glob's matches in lexical order.
	Files []fileObservation
}

// fileObservation is the metadata of one path.
type fileObservation struct {
	Path string
	Info hostfs.FileInfo // valid when the path exists and Err is empty
	// Missing is true when nothing exists at the path.
	Missing bool
	// DanglingLink is set when the path does not resolve because it, or a
	// directory on the way, is a symbolic link whose target (DanglingTarget)
	// does not exist. Creating the target would create the file.
	DanglingLink, DanglingTarget string
	// Err is set when the path could not be observed.
	Err string
}

const (
	fileCollectorName = "files"
	fileWorkers       = 8
	notObserved       = ": not observed before the collector timeout"
)

func (*fileCollector) Name() string       { return fileCollectorName }
func (*fileCollector) Version() int       { return 1 }
func (*fileCollector) Access() Access     { return AccessFilesystem }
func (*fileCollector) Type() reflect.Type { return reflect.TypeFor[fileFacts]() }

func (c *fileCollector) Collect(ctx context.Context, h *hostfs.Host) (Facts, error) {
	var (
		mu       sync.Mutex
		observed = map[string]patternObservation{}
		ids      *idMap
		wg       sync.WaitGroup
	)
	work := make(chan string)
	for range fileWorkers {
		wg.Go(func() {
			for pattern := range work {
				if o, ok := observePattern(ctx, h.FS, pattern); ok {
					mu.Lock()
					observed[pattern] = o
					mu.Unlock()
				}
			}
		})
	}
	wg.Go(func() {
		m := loadIDMap(h.FS)
		mu.Lock()
		ids = m
		mu.Unlock()
	})
	go func() {
		defer close(work)
		for _, p := range c.patterns {
			select {
			case work <- p:
			case <-ctx.Done():
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// Keep what was observed; workers still blocked in I/O write to
		// the original map, not to this copy.
	}
	mu.Lock()
	ff := &fileFacts{Patterns: maps.Clone(observed), IDs: ids}
	mu.Unlock()
	if ff.IDs == nil {
		err := errors.New("/etc/passwd and /etc/group" + notObserved)
		ff.IDs = &idMap{users: idTable{err: err}, groups: idTable{err: err}}
	}

	var skipped []string
	for _, p := range c.patterns {
		o, ok := ff.Patterns[p]
		switch {
		case !ok:
			skipped = append(skipped, p+notObserved)
		case o.Err != "":
			skipped = append(skipped, o.Err)
		default:
			skipped = append(skipped, o.Problems...)
			for _, f := range o.Files {
				if f.Err != "" {
					skipped = append(skipped, f.Err)
				}
			}
		}
	}
	skipped = append(skipped, ff.IDs.problems()...)
	f := Facts{Value: ff, Complete: true}
	if len(skipped) > 0 {
		f.Complete = false
		f.Skipped = boundList(distinct(skipped), maxSkipped)
	}
	return f, nil
}

// observePattern observes one path, or expands a glob and observes its
// matches. It reports false when ctx ended before it was done.
func observePattern(ctx context.Context, fsys hostfs.FS, pattern string) (patternObservation, bool) {
	if !isGlob(pattern) {
		return patternObservation{Files: []fileObservation{observeFile(fsys, pattern)}}, true
	}
	matches, problems, err := hostfs.Glob(fsys, pattern)
	if err != nil {
		return patternObservation{Err: err.Error()}, true
	}
	o := patternObservation{Problems: problems, Files: make([]fileObservation, 0, len(matches))}
	for _, m := range matches {
		if ctx.Err() != nil {
			return patternObservation{}, false
		}
		o.Files = append(o.Files, observeFile(fsys, m))
	}
	return o, true
}

// observeFile records the metadata of p. When p does not resolve, it is
// missing only if no element on the way is a symbolic link to a missing
// target.
func observeFile(fsys hostfs.FS, p string) fileObservation {
	fi, err := fsys.Stat(p)
	switch {
	case err == nil:
		return fileObservation{Path: p, Info: fi}
	case !errors.Is(err, fs.ErrNotExist):
		return fileObservation{Path: p, Err: err.Error()}
	}
	q := "/"
	for _, elem := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		q = path.Join(q, elem)
		li, err := fsys.Lstat(q)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fileObservation{Path: p, Missing: true}
		case err != nil:
			return fileObservation{Path: p, Err: err.Error()}
		case !li.IsSymlink():
			continue
		}
		if target, ok := hostfs.DanglingLink(fsys, q); ok {
			return fileObservation{Path: p, DanglingLink: q, DanglingTarget: target}
		}
	}
	return fileObservation{Path: p, Err: p + ": changed while being observed"}
}

// isGlob reports whether a file check path is a glob (hostfs.Glob syntax).
func isGlob(p string) bool { return hostfs.HasMeta(p) }
