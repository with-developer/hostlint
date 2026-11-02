package hostfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// Bounds on what a Glob or Walk records and returns.
const (
	maxProblems    = 50
	maxGlobMatches = 100_000
)

// Glob returns the paths matching pattern, in lexical order. Each element of
// the absolute pattern uses path.Match syntax ("*" also matches names starting
// with a dot). Symbolic links in the middle of a path are followed.
//
// Unlike filepath.Glob, it never hides what it could not see: directories it
// could not read are returned as problems, and the caller must treat the
// matches as incomplete when there are any.
func Glob(fsys FS, pattern string) (matches, problems []string, err error) {
	if err := checkPath("glob", pattern); err != nil {
		return nil, nil, err
	}
	elems := splitPath(pattern)
	for _, elem := range elems {
		if _, err := path.Match(elem, ""); err != nil {
			return nil, nil, fmt.Errorf("glob %q: %w", pattern, err)
		}
	}
	paths := []string{"/"}
	for _, elem := range elems {
		var next []string
		for _, dir := range paths {
			if !strings.ContainsAny(elem, `*?[\`) {
				p := path.Join(dir, elem)
				if _, err := fsys.Lstat(p); err == nil {
					next = append(next, p)
				} else if !errors.Is(err, fs.ErrNotExist) {
					problems = addProblem(problems, err)
				}
				continue
			}
			entries, err := fsys.ReadDir(dir)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					problems = addProblem(problems, err)
				}
				continue
			}
			for _, e := range entries {
				if ok, _ := path.Match(elem, e.Name()); ok {
					next = append(next, e.Path)
				}
			}
		}
		if len(next) > maxGlobMatches {
			problems = addProblem(problems, fmt.Errorf("%s: more than %d matches; the rest were not examined", pattern, maxGlobMatches))
			next = next[:maxGlobMatches]
		}
		paths = next
	}
	sort.Strings(paths)
	return paths, problems, nil
}

// WalkOptions bounds a Walk.
type WalkOptions struct {
	// MaxEntries stops the walk after this many entries (default 1,000,000).
	MaxEntries int
	// MaxDepth stops descending below this depth; the root is depth 0
	// (default 32).
	MaxDepth int
	// Timeout stops the walk after this long (default 60s).
	Timeout time.Duration
	// Prune, if set, is called for every directory below the root; returning
	// true skips its contents without making the walk incomplete (e.g.
	// pseudo-filesystems).
	Prune func(FileInfo) bool
}

// dirLister is implemented by filesystems that can list a bounded number of
// directory entries, so a huge directory cannot exhaust a walk's memory.
type dirLister interface {
	readDirN(name string, n int) (entries []FileInfo, truncated bool, err error)
}

// WalkResult says how much a Walk saw.
type WalkResult struct {
	Entries int
	// Complete is false if any directory could not be read or a limit was
	// reached; then some files were not visited.
	Complete bool
	// Problems describes what could not be seen (bounded).
	Problems []string
	// NotEntered lists automount points that were deliberately not entered:
	// listing them would mount a filesystem on the scanned host.
	NotEntered []string
}

// Walk visits root and everything below it, in lexical order, without
// following symbolic links (a symlinked root is followed), and calls fn with
// the Lstat metadata of each entry. If fn returns fs.SkipDir for a directory,
// its contents are skipped; any other error stops the walk and is returned.
//
// The result is Complete only if everything below root was visited: an
// unreadable or vanished directory, a limit, an interruption or an early stop
// all make it incomplete.
func Walk(ctx context.Context, fsys FS, root string, opts WalkOptions, fn func(FileInfo) error) (WalkResult, error) {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1_000_000
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 32
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	deadline := time.Now().Add(opts.Timeout)
	res := WalkResult{Complete: true}

	fi, err := fsys.Lstat(root)
	if err == nil && fi.IsSymlink() {
		fi, err = fsys.Stat(root)
	}
	if err != nil {
		res.stop(err.Error())
		return res, err
	}
	type item struct {
		fi    FileInfo
		depth int
	}
	stack := []item{{fi, 0}}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			res.stop("interrupted")
			return res, err
		}
		if time.Now().After(deadline) {
			res.stop(fmt.Sprintf("stopped after %s", opts.Timeout))
			return res, nil
		}
		if res.Entries >= opts.MaxEntries {
			res.stop(fmt.Sprintf("stopped after %d entries", opts.MaxEntries))
			return res, nil
		}
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		res.Entries++
		if err := fn(it.fi); err != nil {
			if errors.Is(err, fs.SkipDir) && it.fi.IsDir() {
				continue
			}
			res.stop("stopped early: " + err.Error())
			return res, err
		}
		if !it.fi.IsDir() || (it.depth > 0 && opts.Prune != nil && opts.Prune(it.fi)) {
			continue
		}
		if it.depth >= opts.MaxDepth {
			res.stop(fmt.Sprintf("%s: deeper than %d levels", it.fi.Path, opts.MaxDepth))
			continue
		}
		var entries []FileInfo
		var truncated bool
		if dl, ok := fsys.(dirLister); ok {
			entries, truncated, err = dl.readDirN(it.fi.Path, max(opts.MaxEntries-res.Entries-len(stack), 0))
		} else {
			entries, err = fsys.ReadDir(it.fi.Path)
		}
		switch {
		case errors.Is(err, ErrAutomount):
			res.NotEntered = append(res.NotEntered, it.fi.Path)
			continue
		case err != nil:
			// Includes a directory that vanished or was renamed since it was
			// listed: what it held was not seen.
			res.stop(err.Error())
			continue
		case truncated:
			res.stop(fmt.Sprintf("%s: too many entries to list within the limit", it.fi.Path))
		}
		for i := len(entries) - 1; i >= 0; i-- {
			stack = append(stack, item{entries[i], it.depth + 1})
		}
	}
	return res, nil
}

func (r *WalkResult) stop(problem string) {
	r.Complete = false
	r.Problems = addProblem(r.Problems, errors.New(problem))
}

func addProblem(problems []string, err error) []string {
	switch {
	case len(problems) < maxProblems:
		return append(problems, err.Error())
	case len(problems) == maxProblems:
		return append(problems, "… more problems not shown")
	}
	return problems
}
