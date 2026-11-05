package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// bdbFixtures are rpm Berkeley DB Packages files of CentOS 7 (rpm 4.11.3) and
// Rocky Linux 8 (rpm 4.14.3), each rebuilt (rpm --rebuilddb) with the headers of
// 10 real packages left, and the `rpm -qa` listing of the same database.
var bdbFixtures = []string{"centos-7", "rocky-8"}

func bdbFixture(t testing.TB, name string) ([]byte, []string) {
	t.Helper()
	f, err := os.Open("testdata/" + name + "-rpmdb.Packages.gz")
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
	want, err := os.ReadFile("testdata/" + name + "-rpmdb.expected")
	if err != nil {
		t.Fatal(err)
	}
	return data, strings.Split(strings.TrimSpace(string(want)), "\n")
}

func listPackages(pkgs []rpmPackage) string {
	var got []string
	for _, p := range pkgs {
		got = append(got, fmt.Sprintf("%s\t%d\t%s\t%s\t%s", p.name, p.epoch, p.version, p.release, p.arch))
	}
	slices.Sort(got)
	return strings.Join(got, "\n")
}

// The reader lists exactly what rpm -qa lists for the same database.
func TestReadRPMBDB(t *testing.T) {
	for _, name := range bdbFixtures {
		t.Run(name, func(t *testing.T) {
			data, want := bdbFixture(t, name)
			pkgs, err := readRPMBDB(data)
			if err != nil {
				t.Fatal(err)
			}
			if got := listPackages(pkgs); got != strings.Join(want, "\n") {
				t.Errorf("packages:\n%s\nwant (rpm -qa):\n%s", got, strings.Join(want, "\n"))
			}
		})
	}
}

func TestPackagesRPMBDB(t *testing.T) {
	data, _ := bdbFixture(t, "centos-7")
	m := hostfs.NewMemFS().AddFile("/var/lib/rpm/Packages", string(data), 0o644, 0, 0)
	f, err := packagesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	p := f.Value.(*Packages)
	if p.Manager != "rpm" || len(p.Installed) != 10 || !f.Complete {
		t.Fatalf("manager %q, %d packages, complete %v", p.Manager, len(p.Installed), f.Complete)
	}
	if v := p.Installed["openssl-libs"]; len(v) != 1 || !strings.HasPrefix(v[0].Version, "1:1.0.2k-") {
		t.Errorf("openssl-libs = %+v", v)
	}
}

// bdbPageOf returns the offset of the first page of the given type.
func bdbPageOf(t *testing.T, d []byte, typ byte) int {
	t.Helper()
	ps := int(binary.LittleEndian.Uint32(d[20:]))
	for off := ps; off+ps <= len(d); off += ps {
		if d[off+25] == typ {
			return off
		}
	}
	t.Fatalf("no page of type %d", typ)
	return 0
}

// A damaged database is an error, never a short list.
func TestReadRPMBDBDamaged(t *testing.T) {
	data, _ := bdbFixture(t, "centos-7")
	ps := int(binary.LittleEndian.Uint32(data[20:]))
	tests := []struct {
		name   string
		damage func(d []byte) []byte
	}{
		{"too short", func(d []byte) []byte { return d[:100] }},
		{"not a hash file", func(d []byte) []byte { d[12] ^= 0xff; return d }},
		{"another hash version", func(d []byte) []byte { d[16] = 8; return d }},
		{"odd page size", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[20:], 3000); return d }},
		{"cut in the middle of a page", func(d []byte) []byte { return d[:len(d)-17] }},
		{"cut after the last page", func(d []byte) []byte { return d[:ps*10] }},
		{"hash page with another number", func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[bdbPageOf(t, d, bdbPageHash)+8:], 99)
			return d
		}},
		{"hash page with an odd number of items", func(d []byte) []byte {
			binary.LittleEndian.PutUint16(d[bdbPageOf(t, d, bdbPageHash)+20:], 3)
			return d
		}},
		{"overflow page that is not one", func(d []byte) []byte {
			d[bdbPageOf(t, d, bdbPageOverflow)+25] = 0
			return d
		}},
		{"overflow chain with a cycle", func(d []byte) []byte {
			o := bdbPageOf(t, d, bdbPageOverflow)
			binary.LittleEndian.PutUint32(d[o+16:], binary.LittleEndian.Uint32(d[o+8:]))
			return d
		}},
		{"hash page of unknown type", func(d []byte) []byte {
			d[bdbPageOf(t, d, bdbPageHash)+25] = 1
			return d
		}},
		{"hash page that looks free", func(d []byte) []byte {
			d[bdbPageOf(t, d, bdbPageHash)+25] = 0
			return d
		}},
		{"hash page past the last page the metadata counts", func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[32:], 1)
			return d
		}},
		{"overflow page that no value uses", func(d []byte) []byte {
			// Point the first off-page value at a one-page chain, orphaning the rest.
			o := bdbPageOf(t, d, bdbPageHash)
			n := int(binary.LittleEndian.Uint16(d[o+20:]))
			for i := 1; i < n; i += 2 {
				v := o + int(binary.LittleEndian.Uint16(d[o+bdbPageHeader+2*i:]))
				if d[v] == bdbItemOffPage {
					binary.LittleEndian.PutUint32(d[v+8:], 10) // a total that ends early
					return d
				}
			}
			t.Fatal("no off-page item")
			return d
		}},
		{"item over the offset table", func(d []byte) []byte {
			o := bdbPageOf(t, d, bdbPageHash)
			binary.LittleEndian.PutUint16(d[o+bdbPageHeader:], bdbPageHeader)
			return d
		}},
		{"package counter missing", func(d []byte) []byte {
			// Rename key 0 to a package number.
			o := bdbPageOf(t, d, bdbPageHash)
			k := o + int(binary.LittleEndian.Uint16(d[o+bdbPageHeader:]))
			binary.LittleEndian.PutUint32(d[k+1:], 12345)
			return d
		}},
		{"overflow page claiming too much", func(d []byte) []byte {
			binary.LittleEndian.PutUint16(d[bdbPageOf(t, d, bdbPageOverflow)+22:], uint16(ps))
			return d
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, err := readRPMBDB(tt.damage(bytes.Clone(data)))
			if err == nil {
				t.Errorf("read %d packages from a damaged file", len(pkgs))
			}
		})
	}
}

func FuzzReadRPMBDB(f *testing.F) {
	data, _ := bdbFixture(f, "rocky-8")
	f.Add(data[:8*4096])
	f.Add(data)
	f.Fuzz(func(_ *testing.T, d []byte) {
		_, _ = readRPMBDB(d) // must not panic or hang
	})
}
