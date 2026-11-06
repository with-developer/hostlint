package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func collectSamba(t *testing.T, m *hostfs.MemFS) (*Samba, bool) {
	t.Helper()
	f, err := sambaCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return f.Value.(*Samba), f.Complete
}

func smbConf(text string) *hostfs.MemFS {
	return hostfs.NewMemFS().AddFile(sambaConfig, text, 0o644, 0, 0)
}

// The packaged smb.conf of Ubuntu 24.04 defines print$ (a disk share without guests)
// and the printers template.
func TestSambaPackagedConfiguration(t *testing.T) {
	s, complete := collectSamba(t, fixtureFS(t, "ubuntu-24.04"))
	if !s.Present || !complete || len(s.Shares) != 1 || s.Shares[0].Name != "print$" || s.Shares[0].Guest {
		t.Errorf("%+v complete %v", s, complete)
	}
}

// Rocky Linux 9's smb.conf includes usershares.conf, which does not exist until a user share is made.
func TestSambaRockyConfiguration(t *testing.T) {
	s, complete := collectSamba(t, fixtureFS(t, "rocky-9"))
	if !s.Present || !complete {
		t.Errorf("%+v complete %v", s, complete)
	}
	for _, sh := range s.Shares {
		if sh.Guest {
			t.Errorf("share %+v", sh)
		}
	}
}

func TestSambaGuestShares(t *testing.T) {
	tests := []struct {
		name, conf string
		want       map[string]bool
	}{
		{"guest ok on a share", "[global]\n  workgroup = X\n[pub]\n  path = /srv/pub\n  guest ok = yes\n[priv]\n  path = /srv/priv\n  guest ok = no\n", map[string]bool{"pub": true, "priv": false}},
		{"public is a synonym", "[pub]\n  public = yes\n", map[string]bool{"pub": true}},
		{"other spellings of yes", "[a]\n  Guest   OK = True\n[b]\n  guest ok = 1\n[c]\n  guest ok=on\n", map[string]bool{"a": true, "b": true, "c": true}},
		{"a share says nothing", "[a]\n  path = /x\n", map[string]bool{"a": false}},
		{"the global default", "[global]\n  guest ok = yes\n[a]\n  path = /x\n[b]\n  guest ok = no\n", map[string]bool{"a": true, "b": false}},
		{"the printers template is not a share", "[global]\n[printers]\n  guest ok = yes\n", map[string]bool{}},
		{"print$ is a disk share", "[print$]\n  path = /var/lib/samba/drivers\n  guest ok = yes\n", map[string]bool{"print$": true}},
		{"a global default after a share does not reach it", "[a]\n  path = /x\n[global]\n  guest ok = yes\n[b]\n  path = /y\n", map[string]bool{"a": false, "b": true}},
		{"names ignore case and spaces", "[a]\n  GuestOK = yes\n[b]\n  guest  ok = yes\n", map[string]bool{"a": true, "b": true}},
		{"a section named twice is one share, the last word wins", "[pub]\n  guest ok = yes\n[other]\n  path = /o\n[pub]\n  guest ok = no\n", map[string]bool{"pub": false, "other": false}},
		{"carriage returns", "[pub]\r\n  comment = a \\\r\n   b\r\n  guest ok = yes\r\n", map[string]bool{"pub": true}},
		{"comments and continuation", "; c\n# c\n[pub]\n  comment = a \\\n   long one\n  guest ok = yes\n", map[string]bool{"pub": true}},
		{"a parameter commented out", "[a]\n  # guest ok = yes\n", map[string]bool{"a": false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, complete := collectSamba(t, smbConf(tt.conf))
			if !complete || len(s.Shares) != len(tt.want) {
				t.Fatalf("shares %+v complete %v, want %v", s.Shares, complete, tt.want)
			}
			for _, sh := range s.Shares {
				if sh.Guest != tt.want[sh.Name] {
					t.Errorf("%s guest = %v, want %v", sh.Name, sh.Guest, tt.want[sh.Name])
				}
			}
		})
	}
}

// The line that opens a share to guests is reported, not the share's header.
func TestSambaWhere(t *testing.T) {
	s, _ := collectSamba(t, smbConf("[global]\n  guest ok = yes\n[a]\n  path = /x\n[b]\n  path = /y\n  guest ok = yes\n"))
	if len(s.Shares) != 2 || !strings.HasSuffix(s.Shares[0].Where, "smb.conf:2") || !strings.HasSuffix(s.Shares[1].Where, "smb.conf:7") {
		t.Errorf("%+v", s.Shares)
	}
}

// An include is read in place; a missing one is ignored (RHEL's smb.conf names usershares.conf).
func TestSambaIncludes(t *testing.T) {
	m := smbConf("[global]\n  include = /etc/samba/usershares.conf\n  include = /etc/samba/gone.conf\n[a]\n  include = extra.conf\n").
		AddFile("/etc/samba/usershares.conf", "[pub]\n  guest ok = yes\n", 0o644, 0, 0).
		AddFile("/etc/samba/extra.conf", "guest ok = yes\n  include = /etc/samba/smb.conf\n", 0o644, 0, 0)
	s, complete := collectSamba(t, m)
	if !complete || len(s.Shares) != 2 || s.Shares[0].Name != "pub" || !s.Shares[0].Guest || s.Shares[1].Name != "a" || !s.Shares[1].Guest {
		t.Errorf("%+v complete %v", s.Shares, complete)
	}
	if !strings.HasSuffix(s.Shares[1].Where, "extra.conf:1") {
		t.Errorf("where %s", s.Shares[1].Where)
	}
}

func TestSambaIncompleteAndAbsent(t *testing.T) {
	for name, conf := range map[string]string{
		"an include with a macro": "include = /etc/samba/%m.conf\n[a]\n",
		"a config file":           "[global]\n  config file = /etc/samba/%m.conf\n",
		"a value not a bool":      "[a]\n  guest ok = maybe\n",
		"an open bracket":         "[a\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, complete := collectSamba(t, smbConf(conf)); complete {
				t.Error("the facts must be incomplete")
			}
		})
	}
	other := smbConf("[a]\n").AddFile("/etc/samba/other.conf", "[a]\n guest ok = yes\n", 0o644, 0, 0)
	if _, complete := collectSamba(t, other); complete {
		t.Error("another Samba configuration must make the facts incomplete")
	}
	if s, complete := collectSamba(t, hostfs.NewMemFS()); s.Present || !complete {
		t.Errorf("%+v complete %v", s, complete)
	}
	bad := smbConf("[a]\n").SetError(sambaConfig, fsErrPermission)
	if _, err := (sambaCollector{}).Collect(context.Background(), hostfs.NewTestHost(bad, nil, false)); err == nil || !strings.Contains(err.Error(), "run hostlint as root") {
		t.Errorf("err = %v", err)
	}
}

func FuzzSambaConfig(f *testing.F) {
	f.Add([]byte(loadTree(f, "ubuntu-24.04")["/etc/samba/smb.conf"]))
	f.Add([]byte("[a]\n guest ok = yes \\\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = sambaCollector{}.Collect(context.Background(), hostfs.NewTestHost(smbConf(string(data)), nil, false))
	})
}
