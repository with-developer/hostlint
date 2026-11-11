package collect

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

func macOf(t *testing.T, m *hostfs.MemFS) (*MAC, bool, []string) {
	t.Helper()
	got, err := macCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return got.Value.(*MAC), got.Complete, got.Skipped
}

// The /etc/selinux/config that the selinux-policy package of each distribution installs (taken from the packages in a
// container): the mode it starts in differs, and Amazon Linux 2023 ships SELinux in permissive mode.
func TestSelinuxConfigOfRealDistributions(t *testing.T) {
	for name, want := range map[string]string{"rocky-9": "enforcing", "almalinux-9": "enforcing", "centos-7": "enforcing", "amazonlinux-2023": "permissive"} {
		f, complete, skipped := macOf(t, fixtureFS(t, "mac/"+name))
		if !complete {
			t.Fatalf("%s incomplete: %v", name, skipped)
		}
		s := f.Selinux
		if !s.Present || s.Settings["mode"].Value != want || !s.Settings["mode"].Explicit || s.Settings["type"].Value != "targeted" {
			t.Errorf("%s: %+v, want mode %s", name, s, want)
		}
		if !strings.HasPrefix(s.Settings["mode"].Source, "/etc/selinux/config:") {
			t.Errorf("%s source: %q", name, s.Settings["mode"].Source)
		}
	}
}

// A host without the file (Debian, Ubuntu, a container image) has no SELinux: absent, and complete.
func TestNoSelinuxConfig(t *testing.T) {
	f, complete, skipped := macOf(t, hostfs.NewMemFS())
	if !complete || len(skipped) != 0 || f.Selinux.Present || len(f.Selinux.Settings) != 0 {
		t.Errorf("no file: %+v complete %v %v", f.Selinux, complete, skipped)
	}
}

func TestSelinuxConfigSyntax(t *testing.T) {
	for name, tc := range map[string]struct {
		text, mode, typ string
	}{
		"the last line wins":       {"SELINUX=disabled\nSELINUX=enforcing\n", "enforcing", ""},
		"quotes and case":          {"SELINUX=\"Enforcing\"\nSELINUXTYPE='targeted'\n", "enforcing", "targeted"},
		"a comment is not a value": {"# SELINUX=enforcing\nSELINUX=permissive # for now\n", "permissive", ""},
		"an unknown value is kept": {"SELINUX=on\n", "on", ""},
		"spaces around the sign":   {"SELINUX = enforcing\n", "enforcing", ""},
		"a prefix of the key":      {"SELINUXTYPE=targeted\n", "", "targeted"},
	} {
		m := hostfs.NewMemFS()
		m.AddFile("/etc/selinux/config", tc.text, 0o644, 0, 0)
		f, complete, _ := macOf(t, m)
		if !complete || f.Selinux.Settings["mode"].Value != tc.mode || f.Selinux.Settings["type"].Value != tc.typ {
			t.Errorf("%s: %+v", name, f.Selinux.Settings)
		}
		if tc.mode == "" {
			if _, ok := f.Selinux.Settings["mode"]; ok {
				t.Errorf("%s: a mode where the file sets none", name)
			}
		}
	}
}

// An unreadable file is incomplete, so a check says ERROR and never takes it for "no SELinux".
func TestSelinuxConfigUnreadableIsIncomplete(t *testing.T) {
	m := hostfs.NewMemFS()
	m.AddFile("/etc/selinux/config", "SELINUX=enforcing\n", 0o644, 0, 0)
	m.SetError("/etc/selinux/config", errors.New("permission denied"))
	f, complete, skipped := macOf(t, m)
	if complete || len(skipped) == 0 || f.Selinux.Present {
		t.Errorf("unreadable: %+v complete %v skipped %v", f.Selinux, complete, skipped)
	}
}
