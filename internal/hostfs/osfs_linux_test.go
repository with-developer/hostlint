//go:build linux

package hostfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// osFixture builds the tree in a temporary directory used as a mounted root.
type osFixture struct {
	t    *testing.T
	root string
}

func (f osFixture) p(name string) string { return filepath.Join(f.root, name) }

func (f osFixture) parent(name string) {
	if err := os.MkdirAll(filepath.Dir(f.p(name)), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f osFixture) file(name, content string, perm uint32) {
	f.parent(name)
	if err := os.WriteFile(f.p(name), []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.p(name), modeFromPerm(perm)); err != nil {
		f.t.Fatal(err)
	}
}

func (f osFixture) dir(name string, perm uint32) {
	if err := os.MkdirAll(f.p(name), fs.FileMode(perm)); err != nil {
		f.t.Fatal(err)
	}
}

func (f osFixture) symlink(name, target string) {
	f.parent(name)
	if err := os.Symlink(target, f.p(name)); err != nil {
		f.t.Fatal(err)
	}
}

func (f osFixture) fifo(name string) {
	f.parent(name)
	if err := unix.Mkfifo(f.p(name), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f osFixture) fs() FS {
	o, err := newOSFS(f.root)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = o.close() })
	return o
}

func newOSFixture(t *testing.T) osFixture {
	t.Helper()
	o, err := newOSFS(t.TempDir())
	if err != nil {
		t.Skipf("mounted-root scanning unavailable here: %v", err)
	}
	_ = o.close()
	return osFixture{t: t, root: t.TempDir()}
}

func TestOSFSConformance(t *testing.T) {
	testConformance(t, func(t *testing.T) fixture { return newOSFixture(t) })
}

// A hard link gives /etc/shadow a second name outside the denylist; the
// device-and-inode check still refuses it.
func TestOSFSDeniesHardLinkToShadow(t *testing.T) {
	f := newOSFixture(t)
	f.file("/etc/shadow", "root:$6$secret:::", 0o640)
	f.dir("/home/u", 0o755)
	if err := os.Link(f.p("/etc/shadow"), f.p("/home/u/notes")); err != nil {
		t.Fatal(err)
	}
	_, err := f.fs().ReadFile("/home/u/notes")
	checkErr(t, err, ErrDenied)
}

func TestOSFSUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any directory")
	}
	f := newOSFixture(t)
	f.file("/secret/file", "x", 0o644)
	if err := os.Chmod(f.p("/secret"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.p("/secret"), 0o755) })
	fsys := f.fs()
	_, err := fsys.ReadDir("/secret")
	checkErr(t, err, fs.ErrPermission)
	_, err = fsys.ReadFile("/secret/file")
	checkErr(t, err, fs.ErrPermission)
}

func TestOSFSLive(t *testing.T) {
	o, err := newOSFS("/")
	if err != nil {
		t.Fatal(err)
	}
	defer o.close()
	if !o.live {
		t.Fatal("root / is not live")
	}
	if _, err := o.Stat("/proc/self"); err != nil {
		t.Errorf("Stat(/proc/self): %v", err)
	}
	_, err = o.ReadFile("/proc/self/environ")
	checkErr(t, err, ErrDenied)
	if _, err := o.ReadFile("/proc/self/status"); err != nil {
		t.Errorf("ReadFile(/proc/self/status): %v", err)
	}
}

func TestOpen(t *testing.T) {
	h, err := Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if !h.Live || h.Root != "/" {
		t.Errorf("Open(/) = live %v root %q", h.Live, h.Root)
	}
	if _, ok := h.Runner.(execRunner); !ok {
		t.Errorf("Open(/) runner = %T, want execRunner", h.Runner)
	}

	f := newOSFixture(t)
	h2, err := Open(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	if h2.Live {
		t.Error("a mounted root must not be live")
	}
	if _, err := h2.Runner.Run(t.Context(), Command{name: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("runner on a mounted root: %v, want ErrUnavailable", err)
	}

	if _, err := Open(filepath.Join(f.root, "missing")); err == nil {
		t.Error("Open(missing dir) succeeded")
	}
}
