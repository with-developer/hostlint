package hostfs

import (
	"io/fs"
	"testing"
)

// Fixtures written through a symlinked parent are reachable both ways, like
// on merged-/usr systems where /sbin -> usr/sbin.
func TestMemFSAddThroughSymlinkedParent(t *testing.T) {
	m := NewMemFS().AddDir("/usr/sbin", 0o755, 0, 0).AddSymlink("/sbin", "usr/sbin").
		AddFile("/sbin/sshd", "binary", 0o755, 0, 0)
	for _, p := range []string{"/sbin/sshd", "/usr/sbin/sshd"} {
		if got, err := m.ReadFile(p); err != nil || string(got) != "binary" {
			t.Errorf("ReadFile(%s) = %q, %v", p, got, err)
		}
	}
}

// Like a directory without search permission: its own metadata is visible,
// its contents are not.
func TestMemFSSetError(t *testing.T) {
	m := NewMemFS().AddFile("/secret/file", "x", 0o644, 0, 0).SetError("/secret", fs.ErrPermission)
	if fi, err := m.Stat("/secret"); err != nil || !fi.IsDir() {
		t.Errorf("Stat(/secret) = %+v, %v; want its metadata", fi, err)
	}
	if _, err := m.ReadDir("/secret"); err == nil {
		t.Error("ReadDir(/secret) succeeded")
	}
	if _, err := m.Stat("/secret/file"); err == nil {
		t.Error("Stat(/secret/file) succeeded through an unsearchable directory")
	}
	root := NewMemFS().AddFile("/etc/hostname", "x", 0o644, 0, 0).SetError("/", fs.ErrPermission)
	if _, err := root.ReadFile("/etc/hostname"); err == nil {
		t.Error("SetError(/) had no effect")
	}
}
