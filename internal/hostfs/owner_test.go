//go:build unix

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestOwner(t *testing.T) {
	name := filepath.Join(t.TempDir(), "hostlint.yaml")
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := Owner(fi); !ok || int(uid) != os.Getuid() {
		t.Errorf("Owner = %d, %v; want %d, true", uid, ok, os.Getuid())
	}

	// A FileInfo that is not from the os package has no known owner.
	other, err := fstest.MapFS{"f": {}}.Stat("f")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Owner(other); ok {
		t.Error("Owner of a non-os FileInfo is known")
	}
}
