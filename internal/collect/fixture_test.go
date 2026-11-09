package collect

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// fixtureFS loads testdata/<name> (files captured from a real distribution)
// into a MemFS, every file 0644 root:root; symbolic links stay links.
func fixtureFS(t *testing.T, name string) *hostfs.MemFS {
	t.Helper()
	m := hostfs.NewMemFS()
	root := filepath.Join("testdata", name)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		target := "/" + filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))
		if d.Type()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			m.AddSymlink(target, link)
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m.AddFile(target, string(data), 0o644, 0, 0)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
