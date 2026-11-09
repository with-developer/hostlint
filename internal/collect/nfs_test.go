package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

func collectNFS(t *testing.T, m *hostfs.MemFS) (*NFS, bool) {
	t.Helper()
	f, err := nfsCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return f.Value.(*NFS), f.Complete
}

func exportsConf(text string) *hostfs.MemFS {
	return hostfs.NewMemFS().AddFile(nfsExports, text, 0o644, 0, 0)
}

// The packaged /etc/exports of Ubuntu 24.04 holds only comments.
func TestNFSPackagedExports(t *testing.T) {
	n, complete := collectNFS(t, fixtureFS(t, "ubuntu-24.04"))
	if !n.Present || !complete || len(n.Exports) != 0 {
		t.Errorf("%+v complete %v", n, complete)
	}
}

func TestNFSExports(t *testing.T) {
	tests := []struct {
		name, conf string
		want       []NFSExport
	}{
		{"hosts with options", "/srv/homes host1(rw,sync,no_subtree_check) host2(ro,sync)\n", []NFSExport{
			{Path: "/srv/homes", Client: "host1", Writable: true}, {Path: "/srv/homes", Client: "host2"}}},
		{"everyone", "/pub *(ro)\n", []NFSExport{{Path: "/pub", Client: "*", Everyone: true}}},
		{"every address as a network", "/a 0.0.0.0/0(rw) ::/0(ro) 0.0.0.0/0.0.0.0(ro) 10.0.0.0/8(ro)\n", []NFSExport{
			{Path: "/a", Client: "0.0.0.0/0", Everyone: true, Writable: true}, {Path: "/a", Client: "::/0", Everyone: true},
			{Path: "/a", Client: "0.0.0.0/0.0.0.0", Everyone: true}, {Path: "/a", Client: "10.0.0.0/8"}}},
		{"all_squash maps root too", "/a h1(rw,all_squash,no_root_squash)\n", []NFSExport{{Path: "/a", Client: "h1", Writable: true}}},
		{"a network", "/data 192.0.2.0/24(rw,no_root_squash)\n", []NFSExport{{Path: "/data", Client: "192.0.2.0/24", Writable: true, NoRootSquash: true}}},
		{"no client", "/pub\n", []NFSExport{{Path: "/pub", Client: "*", Everyone: true}}},
		{"only options", "/pub (rw)\n", []NFSExport{{Path: "/pub", Client: "*", Everyone: true, Writable: true}}},
		{"a space before the options", "/pub host1 (rw)\n", []NFSExport{
			{Path: "/pub", Client: "host1"}, {Path: "/pub", Client: "*", Everyone: true, Writable: true}}},
		{"kerberos and netgroups", "/srv/nfs4 gss/krb5i(rw,sync,fsid=0) @trusted(rw)\n", []NFSExport{
			{Path: "/srv/nfs4", Client: "gss/krb5i", Writable: true}, {Path: "/srv/nfs4", Client: "@trusted", Writable: true}}},
		{"a wildcard host name", "/pub *.example.org(ro)\n", []NFSExport{{Path: "/pub", Client: "*.example.org"}}},
		{"a continued line", "/srv/a host1(rw) \\\n    host2(rw,no_root_squash)\n", []NFSExport{
			{Path: "/srv/a", Client: "host1", Writable: true}, {Path: "/srv/a", Client: "host2", Writable: true, NoRootSquash: true}}},
		{"a quoted path", "\"/srv/with space\" host1(ro)\n", []NFSExport{{Path: "/srv/with space", Client: "host1"}}},
		{"comments and blank lines", "# c\n\n  # indented\n/a h(ro) # not a comment in exports(5), but part of the line\n", []NFSExport{{Path: "/a", Client: "h"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, _ := collectNFS(t, exportsConf(tt.conf))
			for i := range n.Exports {
				n.Exports[i].Where = ""
			}
			if len(n.Exports) < len(tt.want) {
				t.Fatalf("exports %+v, want %+v", n.Exports, tt.want)
			}
			for i, e := range tt.want {
				if n.Exports[i] != e {
					t.Errorf("export %d = %+v, want %+v", i, n.Exports[i], e)
				}
			}
		})
	}
}

func TestNFSExportsDirectoryAndProblems(t *testing.T) {
	m := exportsConf("/a h(ro)\n").
		AddDir(nfsExportsDir, 0o755, 0, 0).
		AddFile(nfsExportsDir+"/extra.exports", "/b *(rw,no_root_squash)\n", 0o644, 0, 0).
		AddFile(nfsExportsDir+"/notes.txt", "/c *(rw)\n", 0o644, 0, 0)
	n, complete := collectNFS(t, m)
	if !complete || len(n.Exports) != 2 || n.Exports[1].Path != "/b" || !n.Exports[1].NoRootSquash {
		t.Errorf("%+v complete %v", n.Exports, complete)
	}
	// A line that is not an export leaves the facts incomplete: it may be an export.
	if _, complete := collectNFS(t, exportsConf("not a path *(rw)\n")); complete {
		t.Error("a line that is not an export must make the facts incomplete")
	}
	if n, complete := collectNFS(t, hostfs.NewMemFS()); n.Present || !complete {
		t.Errorf("%+v complete %v", n, complete)
	}
	bad := exportsConf("/a h(ro)\n").SetError(nfsExports, fsErrPermission)
	if _, err := (nfsCollector{}).Collect(context.Background(), hostfs.NewTestHost(bad, nil, false)); err == nil || !strings.Contains(err.Error(), "run vmsctl as root") {
		t.Errorf("err = %v", err)
	}
}

func FuzzNFSExports(f *testing.F) {
	f.Add([]byte("/srv h1(rw) \\\n h2(ro,no_root_squash)\n\"/a b\" *(ro)\n"))
	f.Add([]byte("\"unterminated\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = nfsCollector{}.Collect(context.Background(), hostfs.NewTestHost(exportsConf(string(data)), nil, false))
	})
}
