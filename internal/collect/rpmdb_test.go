package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// rpmFixture is an rpm SQLite database built on Rocky Linux 9 with the
// headers of 40 real packages (rpm --dbpath ... -i --justdb), and the
// `rpm -qa` listing of the same database.
func rpmFixture(t testing.TB) ([]byte, []string) {
	t.Helper()
	f, err := os.Open("testdata/rocky-9-rpmdb.sqlite.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/rocky-9-rpmdb.expected")
	if err != nil {
		t.Fatal(err)
	}
	return data, strings.Split(strings.TrimSpace(string(want)), "\n")
}

// The reader lists exactly what rpm -qa lists for the same database.
func TestReadRPMSQLite(t *testing.T) {
	data, want := rpmFixture(t)
	pkgs, err := readRPMSQLite(data)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pkgs {
		got = append(got, fmt.Sprintf("%s\t%d\t%s\t%s\t%s", p.name, p.epoch, p.version, p.release, p.arch))
	}
	slices.Sort(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("packages:\n%s\nwant (rpm -qa):\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestPackagesRPM(t *testing.T) {
	data, _ := rpmFixture(t)
	m := hostfs.NewMemFS().AddFile("/var/lib/rpm/rpmdb.sqlite", string(data), 0o644, 0, 0)
	f, err := packagesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	p := f.Value.(*Packages)
	if p.Manager != "rpm" || len(p.Installed) != 40 || !f.Complete {
		t.Fatalf("manager %q, %d packages, complete %v", p.Manager, len(p.Installed), f.Complete)
	}
	if v := p.Installed["telnet-server"]; len(v) != 1 || !strings.HasPrefix(v[0].Version, "1:0.17-") || v[0].Arch == "" {
		t.Errorf("telnet-server = %+v", v)
	}
	// Changes still in the write-ahead log may be missing from the file.
	m.AddFile("/var/lib/rpm/rpmdb.sqlite-wal", "x", 0o644, 0, 0)
	f, err = packagesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil || f.Complete {
		t.Errorf("complete %v, err %v; want incomplete with a pending WAL", f.Complete, err)
	}
}

// A damaged database is an error, never a short list.
func TestReadRPMSQLiteDamaged(t *testing.T) {
	data, _ := rpmFixture(t)
	tests := map[string][]byte{
		"empty":          nil,
		"not sqlite":     []byte(strings.Repeat("x", 4096)),
		"truncated":      data[:len(data)/3],
		"bad page size":  append(append([]byte{}, data[:16]...), append([]byte{0x01, 0x23}, data[18:]...)...),
		"root page loop": rootLoop(data),
	}
	for name, d := range tests {
		if pkgs, err := readRPMSQLite(d); err == nil {
			t.Errorf("%s: read %d packages without an error", name, len(pkgs))
		}
	}
}

// rootLoop makes the Packages root page point to itself.
func rootLoop(data []byte) []byte {
	d := bytes.Clone(data)
	db, _ := openSQLite(d)
	root, _ := db.tableRoot("Packages")
	off := int(root-1) * db.pageSize
	if d[off] == 0x05 {
		copy(d[off+8:], []byte{byte(root >> 24), byte(root >> 16), byte(root >> 8), byte(root)})
	} else {
		d[off] = 0x05 // claim it is an interior page
	}
	return d
}

func FuzzReadRPMSQLite(f *testing.F) {
	data, _ := rpmFixture(f)
	f.Add(data)
	f.Add(data[:8192])
	f.Fuzz(func(_ *testing.T, d []byte) {
		_, _ = readRPMSQLite(d) // must not panic or hang
	})
}

func FuzzParseRPMHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 3, 0xe8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 'b', 'a', 's', 0})
	f.Fuzz(func(_ *testing.T, d []byte) {
		_, _ = parseRPMHeader(d)
	})
}
