package hostfs

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func walkFixture() *MemFS {
	return NewMemFS().
		AddFile("/etc/a.conf", "", 0o644, 0, 0).
		AddFile("/etc/b.conf", "", 0o644, 0, 0).
		AddFile("/etc/notes.txt", "", 0o644, 0, 0).
		AddFile("/home/u/.rhosts", "", 0o600, 1000, 1000).
		AddFile("/home/v/.rhosts", "", 0o600, 1001, 1001).
		AddDir("/home/w", 0o700, 1002, 1002).
		AddSymlink("/home/link", "/etc").
		AddFile("/proc/1/status", "", 0o444, 0, 0)
}

func TestGlob(t *testing.T) {
	fsys := walkFixture().SetError("/home/w", fs.ErrPermission)
	tests := []struct {
		pattern      string
		want         []string
		wantProblems int
	}{
		{pattern: "/etc/*.conf", want: []string{"/etc/a.conf", "/etc/b.conf"}},
		{pattern: "/etc/a.conf", want: []string{"/etc/a.conf"}},
		{pattern: "/etc/missing.conf", want: nil},
		{pattern: "/nowhere/*", want: nil},
		// The unreadable /home/w is reported, never silently skipped.
		{pattern: "/home/*/.rhosts", want: []string{"/home/u/.rhosts", "/home/v/.rhosts"}, wantProblems: 1},
		// "*" matches dot files; a symlinked directory is followed.
		{pattern: "/home/u/*", want: []string{"/home/u/.rhosts"}},
		{pattern: "/home/link/a.*", want: []string{"/home/link/a.conf"}},
		{pattern: "/", want: []string{"/"}},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			got, problems, err := Glob(fsys, tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if !equal(got, tt.want) {
				t.Errorf("matches = %v, want %v", got, tt.want)
			}
			if len(problems) != tt.wantProblems {
				t.Errorf("problems = %v, want %d", problems, tt.wantProblems)
			}
		})
	}
	for _, bad := range []string{"etc/*", "/etc/[", "/etc/../x"} {
		if _, _, err := Glob(fsys, bad); err == nil {
			t.Errorf("Glob(%q) succeeded, want an error", bad)
		}
	}
}

func TestWalk(t *testing.T) {
	collect := func(fsys FS, opts WalkOptions) ([]string, WalkResult, error) {
		var seen []string
		res, err := Walk(context.Background(), fsys, "/", opts, func(fi FileInfo) error {
			seen = append(seen, fi.Path)
			return nil
		})
		return seen, res, err
	}

	t.Run("visits everything in order without following links", func(t *testing.T) {
		seen, res, err := collect(walkFixture(), WalkOptions{})
		want := []string{"/", "/etc", "/etc/a.conf", "/etc/b.conf", "/etc/notes.txt",
			"/home", "/home/link", "/home/u", "/home/u/.rhosts", "/home/v", "/home/v/.rhosts", "/home/w",
			"/proc", "/proc/1", "/proc/1/status"}
		if err != nil || !res.Complete || !equal(seen, want) {
			t.Errorf("seen %v (complete %v, err %v), want %v", seen, res.Complete, err, want)
		}
		if res.Entries != len(want) {
			t.Errorf("Entries = %d, want %d", res.Entries, len(want))
		}
	})

	t.Run("pruned directories keep the walk complete", func(t *testing.T) {
		seen, res, _ := collect(walkFixture(), WalkOptions{Prune: func(fi FileInfo) bool { return fi.Path == "/proc" }})
		if !res.Complete || strings.Contains(strings.Join(seen, " "), "/proc/1") {
			t.Errorf("seen %v, complete %v", seen, res.Complete)
		}
	})

	t.Run("an unreadable directory makes the walk incomplete", func(t *testing.T) {
		seen, res, err := collect(walkFixture().SetError("/home/w", fs.ErrPermission), WalkOptions{})
		if err != nil || res.Complete || len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "/home/w") {
			t.Errorf("result %+v, err %v", res, err)
		}
		if seen[len(seen)-1] != "/proc/1/status" {
			t.Errorf("walk stopped early: %v", seen)
		}
	})

	t.Run("limits make the walk incomplete", func(t *testing.T) {
		_, res, _ := collect(walkFixture(), WalkOptions{MaxEntries: 3})
		if res.Complete || res.Entries != 3 {
			t.Errorf("MaxEntries: %+v", res)
		}
		seen, res, _ := collect(walkFixture(), WalkOptions{MaxDepth: 1})
		if res.Complete || strings.Contains(strings.Join(seen, " "), "/etc/a.conf") {
			t.Errorf("MaxDepth: seen %v, %+v", seen, res)
		}
	})

	t.Run("fn errors and cancellation stop the walk", func(t *testing.T) {
		stop := errors.New("stop")
		_, err := Walk(context.Background(), walkFixture(), "/", WalkOptions{}, func(FileInfo) error { return stop })
		if !errors.Is(err, stop) {
			t.Errorf("err = %v, want stop", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := Walk(ctx, walkFixture(), "/", WalkOptions{}, func(FileInfo) error { return nil })
		if !errors.Is(err, context.Canceled) || res.Complete {
			t.Errorf("canceled walk: %+v, %v", res, err)
		}
	})

	t.Run("missing root", func(t *testing.T) {
		_, err := Walk(context.Background(), walkFixture(), "/nope", WalkOptions{}, func(FileInfo) error { return nil })
		checkErr(t, err, fs.ErrNotExist)
	})
}
