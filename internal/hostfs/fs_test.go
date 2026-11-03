package hostfs

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// fixture builds the same tree in any FS implementation.
type fixture interface {
	file(name, content string, perm uint32)
	dir(name string, perm uint32)
	symlink(name, target string)
	fifo(name string)
	// chownLink makes a symlink owned by uid; false if unsupported here.
	chownLink(name string, uid int64) bool
	fs() FS
}

type memFixture struct{ m *MemFS }

func (f memFixture) file(name, content string, perm uint32) { f.m.AddFile(name, content, perm, 0, 0) }
func (f memFixture) dir(name string, perm uint32)           { f.m.AddDir(name, perm, 0, 0) }
func (f memFixture) symlink(name, target string)            { f.m.AddSymlink(name, target) }
func (f memFixture) fifo(name string)                       { f.m.AddSpecial(name, fs.ModeNamedPipe, 0o644, 0, 0) }
func (f memFixture) fs() FS                                 { return f.m }
func (f memFixture) chownLink(name string, uid int64) bool {
	f.m.SetOwner(name, uid, uid)
	return true
}

func TestMemFSConformance(t *testing.T) {
	testConformance(t, func(*testing.T) fixture { return memFixture{NewMemFS()} })
}

// buildTree creates the shared fixture tree. "inside" content proves a path
// resolved inside the root, never on the machine running the tests.
func buildTree(f fixture) {
	f.dir("/etc", 0o755)
	f.file("/etc/hostname", "inside-hostname\n", 0o644)
	f.file("/etc/target", "inside", 0o644)
	f.file("/etc/shadow", "root:$6$secret:19000:0:99999:7:::\n", 0o640)
	f.file("/usr/bin/su", "", 0o4755)
	f.symlink("/rel", "etc/target")
	f.symlink("/abs", "/etc/target")
	f.symlink("/escape-dotdot", "../../../../../../etc/hostname")
	f.symlink("/escape-abs", "/../../etc/hostname")
	f.symlink("/etc/dirlink", "/usr/bin")
	f.symlink("/loop-a", "/loop-b")
	f.symlink("/loop-b", "/loop-a")
	f.dir("/home/u/.ssh", 0o700)
	f.file("/home/u/.ssh/id_rsa", "PRIVATE KEY", 0o600)
	f.symlink("/home/u/.rhosts", "/etc/shadow")
	f.symlink("/home/u/.plan", "/home/u/.ssh/id_rsa")
	f.fifo("/run/fifo")
	f.file("/proc/123/task/123/environ", "DB_PASSWORD=secret", 0o400)
	f.symlink("/proc/thread-self", "123/task/123")
	f.symlink("/home/u/.forward", "/etc/target")
	f.file("/usr/hostname", "usr-hostname", 0o644)
	f.symlink("/dotdot", "/etc/dirlink/../hostname")
}

func testConformance(t *testing.T, newFixture func(t *testing.T) fixture) {
	f := newFixture(t)
	buildTree(f)
	fsys := f.fs()

	t.Run("ReadFile", func(t *testing.T) {
		tests := []struct {
			name, path string
			want       string
			wantErr    error
		}{
			{name: "regular file", path: "/etc/target", want: "inside"},
			{name: "relative symlink", path: "/rel", want: "inside"},
			{name: "absolute symlink resolves inside the root", path: "/abs", want: "inside"},
			{name: "dot-dot symlink cannot escape", path: "/escape-dotdot", want: "inside-hostname\n"},
			{name: "absolute dot-dot symlink cannot escape", path: "/escape-abs", want: "inside-hostname\n"},
			{name: "symlinked directory", path: "/etc/dirlink/su", want: ""},
			{name: "dot-dot after a followed directory link", path: "/dotdot", want: "usr-hostname"},
			{name: "missing", path: "/etc/missing", wantErr: fs.ErrNotExist},
			{name: "component is a file", path: "/etc/target/x", wantErr: fs.ErrNotExist},
			{name: "directory", path: "/etc", wantErr: ErrNotRegular},
			{name: "fifo is never opened for reading", path: "/run/fifo", wantErr: ErrNotRegular},
			{name: "symlink loop", path: "/loop-a", wantErr: errAny},
			{name: "denylisted path", path: "/etc/shadow", wantErr: ErrDenied},
			{name: "denylisted directory", path: "/home/u/.ssh/id_rsa", wantErr: ErrDenied},
			{name: "symlink to a denylisted file", path: "/home/u/.rhosts", wantErr: ErrDenied},
			{name: "symlink into a denylisted directory", path: "/home/u/.plan", wantErr: ErrDenied},
			{name: "task environ", path: "/proc/123/task/123/environ", wantErr: ErrDenied},
			{name: "thread-self resolves to a denylisted task path", path: "/proc/thread-self/environ", wantErr: ErrDenied},
			{name: "relative path", path: "etc/target", wantErr: ErrInvalidPath},
			{name: "unclean path", path: "/etc/../etc/target", wantErr: ErrInvalidPath},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := fsys.ReadFile(tt.path)
				checkErr(t, err, tt.wantErr)
				if tt.wantErr == nil && string(got) != tt.want {
					t.Errorf("ReadFile(%q) = %q, want %q", tt.path, got, tt.want)
				}
			})
		}
	})

	// A symlink another user planted is never followed, whatever it points to.
	t.Run("untrusted symlink", func(t *testing.T) {
		if !f.chownLink("/home/u/.forward", 1000) {
			t.Skip("changing a symlink's owner needs root")
		}
		fsys := f.fs()
		_, err := fsys.ReadFile("/home/u/.forward")
		checkErr(t, err, ErrUnsafeSymlink)
		_, err = fsys.Stat("/home/u/.forward")
		checkErr(t, err, ErrUnsafeSymlink)
		fi, err := fsys.Lstat("/home/u/.forward")
		if err != nil || !fi.IsSymlink() || fi.UID != 1000 {
			t.Errorf("Lstat = %+v, %v; want the symlink itself", fi, err)
		}
		if got, err := fsys.ReadFile("/abs"); err != nil || string(got) != "inside" {
			t.Errorf("a root-owned symlink must still be followed: %q, %v", got, err)
		}
	})

	t.Run("Stat and Lstat", func(t *testing.T) {
		fi, err := fsys.Lstat("/abs")
		if err != nil || !fi.IsSymlink() || fi.Path != "/abs" {
			t.Errorf("Lstat(/abs) = %+v, %v; want a symlink", fi, err)
		}
		fi, err = fsys.Stat("/abs")
		if err != nil || !fi.IsRegular() || fi.Size != int64(len("inside")) {
			t.Errorf("Stat(/abs) = %+v, %v; want the regular target", fi, err)
		}
		fi, err = fsys.Stat("/usr/bin/su")
		if err != nil || fi.Perm() != 0o4755 {
			t.Errorf("Stat(/usr/bin/su).Perm() = %#o, %v; want 04755", fi.Perm(), err)
		}
		fi, err = fsys.Stat("/")
		if err != nil || !fi.IsDir() {
			t.Errorf("Stat(/) = %+v, %v; want a directory", fi, err)
		}
		// Metadata of denylisted files stays readable: permission checks need it.
		if _, err := fsys.Stat("/etc/shadow"); err != nil {
			t.Errorf("Stat(/etc/shadow) = %v, want metadata", err)
		}
		_, err = fsys.Stat("/missing")
		checkErr(t, err, fs.ErrNotExist)
	})

	t.Run("ReadLink", func(t *testing.T) {
		got, err := fsys.ReadLink("/escape-dotdot")
		if err != nil || got != "../../../../../../etc/hostname" {
			t.Errorf("ReadLink = %q, %v", got, err)
		}
		_, err = fsys.ReadLink("/etc/target")
		checkErr(t, err, errAny)
	})

	t.Run("ReadDir", func(t *testing.T) {
		entries, err := fsys.ReadDir("/home/u")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range entries {
			kind := "file"
			switch {
			case e.IsDir():
				kind = "dir"
			case e.IsSymlink():
				kind = "link"
			}
			got = append(got, e.Path+":"+kind)
		}
		want := []string{"/home/u/.forward:link", "/home/u/.plan:link", "/home/u/.rhosts:link", "/home/u/.ssh:dir"}
		if !equal(got, want) {
			t.Errorf("ReadDir(/home/u) = %v, want %v", got, want)
		}
		// A symlinked directory lists its target, with paths under the name used.
		entries, err = fsys.ReadDir("/etc/dirlink")
		if err != nil || len(entries) != 1 || entries[0].Path != "/etc/dirlink/su" {
			t.Errorf("ReadDir(/etc/dirlink) = %+v, %v", entries, err)
		}
		_, err = fsys.ReadDir("/etc/target")
		checkErr(t, err, fs.ErrNotExist)
	})

	// A link to a missing target is not an empty directory or a missing
	// file (on Linux, through the real path resolution).
	t.Run("DanglingLink", func(t *testing.T) {
		g := newFixture(t)
		g.dir("/etc", 0o755)
		g.dir("/etc/real.d", 0o755)
		g.symlink("/etc/cron.daily", "/nowhere")
		fsys := g.fs()
		if target, ok := DanglingLink(fsys, "/etc/cron.daily"); !ok || target != "/nowhere" {
			t.Errorf("DanglingLink = %q, %v", target, ok)
		}
		if _, ok := DanglingLink(fsys, "/etc/real.d"); ok {
			t.Error("a directory is reported as a dangling link")
		}
		for _, pattern := range []string{"/etc/cron.daily/*", "/etc/cron.daily/job"} {
			_, problems, err := Glob(fsys, pattern)
			if err != nil || len(problems) != 1 || !strings.Contains(problems[0], "/etc/cron.daily: symbolic link to /nowhere") {
				t.Errorf("Glob(%s): problems %q, err %v", pattern, problems, err)
			}
		}
		if _, err := fsys.Lstat("/etc/cron.daily/job"); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Lstat through the link: %v", err)
		}
	})
}

// errAny matches any non-nil error in checkErr.
var errAny = errors.New("any error")

func checkErr(t *testing.T, err, want error) {
	t.Helper()
	switch {
	case want == nil && err != nil:
		t.Errorf("unexpected error: %v", err)
	case errors.Is(want, errAny) && err == nil:
		t.Errorf("got no error, want one")
	case want != nil && !errors.Is(want, errAny) && !errors.Is(err, want):
		t.Errorf("error = %v, want %v", err, want)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
