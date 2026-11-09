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

	"github.com/with-developer/vmsctl/internal/hostfs"
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

// rpmHeader builds an exported header of string tags: (tag, offset) pairs
// point into the data.
func rpmHeader(entries [][2]uint32) []byte {
	const data = "pkg\x001.0\x002.el9\x00"
	b := make([]byte, 8, 8+16*len(entries)+len(data))
	b[3], b[7] = byte(len(entries)), byte(len(data))
	for _, e := range entries {
		x := make([]byte, 16)
		x[0], x[1], x[2], x[3] = byte(e[0]>>24), byte(e[0]>>16), byte(e[0]>>8), byte(e[0])
		x[7] = rpmTypeString
		x[8], x[9], x[10], x[11] = byte(e[1]>>24), byte(e[1]>>16), byte(e[1]>>8), byte(e[1])
		x[15] = 1
		b = append(b, x...)
	}
	return append(b, data...)
}

// A header whose tags are missing, empty or point outside it is an error,
// not a package with an empty version.
func TestParseRPMHeaderDamaged(t *testing.T) {
	ok := [][2]uint32{{rpmTagName, 0}, {rpmTagVersion, 4}, {rpmTagRelease, 8}}
	if p, err := parseRPMHeader(rpmHeader(ok)); err != nil || p.fullVersion() != "1.0-2.el9" {
		t.Fatalf("valid header: %+v, %v", p, err)
	}
	for name, h := range map[string][]byte{
		"offset outside": rpmHeader([][2]uint32{{rpmTagName, 0}, {rpmTagVersion, 4}, {rpmTagRelease, 99}}),
		"no release":     rpmHeader(ok[:2]),
		"empty version":  rpmHeader([][2]uint32{{rpmTagName, 0}, {rpmTagVersion, 3}, {rpmTagRelease, 8}}),
		"arch outside":   rpmHeader(append(append([][2]uint32{}, ok...), [2]uint32{rpmTagArch, 500})),
	} {
		if p, err := parseRPMHeader(h); err == nil {
			t.Errorf("%s: read %+v without an error", name, p)
		}
	}
}

// A page reached twice, or rows that hold more than the file, are not read
// as a list with duplicates.
func TestReadRPMSQLiteRepeatedPage(t *testing.T) {
	data, _ := rpmFixture(t)
	d := bytes.Clone(data)
	db, _ := openSQLite(d)
	root, _ := db.tableRoot("Packages")
	off := int(root-1) * db.pageSize
	if d[off] != 0x05 || int(d[off+3])<<8|int(d[off+4]) < 1 {
		t.Skip("the fixture's root page is not an interior page with cells")
	}
	// The first cell's child becomes the right-most child.
	cell := int(d[off+12])<<8 | int(d[off+13])
	copy(d[off+cell:off+cell+4], d[off+8:off+12])
	if pkgs, err := readRPMSQLite(d); err == nil {
		t.Errorf("read %d packages from a tree that repeats a page", len(pkgs))
	}
}

// A database that cannot be examined is reported, not taken for absent.
func TestPackagesRPMUnreadable(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/var/lib/rpm/rpmdb.sqlite", "x", 0o600, 0, 0).SetError("/var/lib/rpm/rpmdb.sqlite", os.ErrPermission)
	_, err := packagesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err == nil || strings.Contains(err.Error(), "no dpkg or rpm") {
		t.Errorf("err = %v, want the permission error", err)
	}
}
