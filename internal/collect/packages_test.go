package collect

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func packagesFacts(t *testing.T, h *hostfs.Host) (*Packages, error) {
	t.Helper()
	f, err := packagesCollector{}.Collect(context.Background(), h)
	if err != nil {
		return nil, err
	}
	if !f.Complete {
		t.Errorf("incomplete: %v", f.Skipped)
	}
	return f.Value.(*Packages), nil
}

func TestPackagesDpkg(t *testing.T) {
	p, err := packagesFacts(t, hostfs.NewTestHost(fixtureFS(t, "debian-12"), nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if p.Manager != "dpkg" || len(p.Installed) < 100 {
		t.Fatalf("manager %q, %d packages", p.Manager, len(p.Installed))
	}
	ssh := p.Installed["openssh-server"]
	if len(ssh) != 1 || ssh[0].Version != "1:9.2p1-2+deb12u10" || ssh[0].Arch != "arm64" || ssh[0].State != "installed" ||
		!strings.HasPrefix(ssh[0].Source, "/var/lib/dpkg/status:") {
		t.Errorf("openssh-server = %+v", ssh)
	}
	for _, name := range []string{"telnetd", "inetutils-telnetd", "rsh-server", "tftpd-hpa", "snmpd"} {
		if _, ok := p.Installed[name]; !ok {
			t.Errorf("%s is not listed", name)
		}
	}
}

func TestPackagesDpkgStates(t *testing.T) {
	status := `Package: removed
Status: deinstall ok config-files
Version: 1.0

Package: half
Status: install reinstreq half-configured
Architecture: amd64
Version: 2.0
Description: a package
 with a long description
 Package: not-a-package

Package: libc6
Status: install ok installed
Architecture: arm64
Version: 2.36-9

Package: libc6
Status: install ok installed
Architecture: armhf
Version: 2.36-9

Package: gone
Status: purge ok not-installed
`
	p, err := packagesFacts(t, hostfs.NewTestHost(hostfs.NewMemFS().AddFile(dpkgStatus, status, 0o644, 0, 0), nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Installed["removed"]; ok {
		t.Error("a package with only its configuration left is listed")
	}
	if _, ok := p.Installed["gone"]; ok {
		t.Error("a purged package is listed")
	}
	if h := p.Installed["half"]; len(h) != 1 || h[0].State != "half-configured" {
		t.Errorf("half = %+v, want listed as half-configured", h)
	}
	if _, ok := p.Installed["not-a-package"]; ok {
		t.Error("a description line was read as a package")
	}
	if l := p.Installed["libc6"]; len(l) != 2 || l[0].Arch != "arm64" || l[1].Arch != "armhf" {
		t.Errorf("libc6 = %+v", l)
	}
}

// Changes dpkg has journaled but not merged into the status file count.
func TestPackagesDpkgJournal(t *testing.T) {
	m := fixtureFS(t, "debian-12").
		AddFile(dpkgUpdates+"/0000", "Package: telnetd\nStatus: deinstall ok config-files\nArchitecture: all\nVersion: 0.17+2.4-2+deb12u3\n", 0o644, 0, 0).
		AddFile(dpkgUpdates+"/0001", "Package: rsh-redone-server\nStatus: install ok unpacked\nArchitecture: arm64\nVersion: 85-3\n", 0o644, 0, 0).
		AddFile(dpkgUpdates+"/tmp.i", "Package: ignored\nStatus: install ok installed\n", 0o644, 0, 0)
	p, err := packagesFacts(t, hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Installed["telnetd"]; ok {
		t.Error("telnetd was removed in the journal")
	}
	if r := p.Installed["rsh-redone-server"]; len(r) != 1 || r[0].State != "unpacked" || r[0].Source != dpkgUpdates+"/0001:1" {
		t.Errorf("rsh-redone-server = %+v", r)
	}
	if _, ok := p.Installed["ignored"]; ok {
		t.Error("a non-journal file in updates was read")
	}
}

// Without a database hostlint reads there are no package facts, rather than
// an empty list that would make every package look absent.
func TestPackagesUnavailable(t *testing.T) {
	tests := []struct {
		name string
		fsys hostfs.FS
		want string
	}{
		{"rpm", hostfs.NewMemFS().AddFile("/var/lib/rpm/rpmdb.sqlite", "", 0o644, 0, 0), "reading the rpm database is not supported yet"},
		{"no database", hostfs.NewMemFS(), "no dpkg or rpm package database"},
		{"unreadable dpkg status", hostfs.NewMemFS().AddFile(dpkgStatus, "", 0o600, 0, 0).SetError(dpkgStatus, os.ErrPermission), "permission"},
		{"unreadable journal", fixtureFS(t, "debian-12").AddDir(dpkgUpdates, 0o755, 0, 0).SetError(dpkgUpdates, os.ErrPermission), "permission"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := packagesFacts(t, hostfs.NewTestHost(tt.fsys, nil, false)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

// A stanza that cannot be read as installed or not leaves the facts
// incomplete: the package is unknown, not absent.
func TestPackagesDpkgDamagedStanza(t *testing.T) {
	for name, status := range map[string]string{
		"truncated status": "Package: telnetd\nStatus: install ok\nArchitecture: amd64\n",
		"no status":        "Package: telnetd\nArchitecture: amd64\n",
		"no architecture":  "Package: telnetd\nStatus: install ok installed\n",
	} {
		h := hostfs.NewTestHost(hostfs.NewMemFS().AddFile(dpkgStatus, status, 0o644, 0, 0), nil, false)
		f, err := packagesCollector{}.Collect(context.Background(), h)
		if err != nil || f.Complete || len(f.Skipped) != 1 || !strings.Contains(f.Skipped[0], "/var/lib/dpkg/status:1") {
			t.Errorf("%s: complete %v, skipped %v, err %v; want one note at the stanza", name, f.Complete, f.Skipped, err)
		}
	}
}
