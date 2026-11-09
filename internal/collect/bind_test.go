package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

func collectBind(t *testing.T, m *hostfs.MemFS) (*Bind, bool) {
	t.Helper()
	f, err := bindCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return f.Value.(*Bind), f.Complete
}

// The packaged configurations of Ubuntu 24.04 (bind9) and Rocky Linux 9 (bind).
func TestBindDistributionDefaults(t *testing.T) {
	for _, name := range []string{"ubuntu-24.04", "rocky-9"} {
		t.Run(name, func(t *testing.T) {
			b, complete := collectBind(t, fixtureFS(t, name))
			if !b.Present || !complete || len(b.Zones) < 4 {
				t.Fatalf("present %v, complete %v, zones %+v", b.Present, complete, b.Zones)
			}
			for _, z := range b.Zones {
				// Every packaged zone is one for the host itself, and takes BIND's defaults.
				if !z.Local || z.Transfer != "any" || z.Update != "none" {
					t.Errorf("zone %+v", z)
				}
			}
		})
	}
}

func TestBindFactsHoldNoSecret(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/named.conf", `key "k" { secret "Sup3r-Secret-Tsig=="; };
zone "example.org" { type master; allow-update { key k; }; };`, 0o644, 0, 0)
	b, _ := collectBind(t, m)
	if len(b.Zones) != 1 || b.Zones[0].Update != "restricted" {
		t.Fatalf("%+v", b.Zones)
	}
}

func TestBindIncompleteAndAbsent(t *testing.T) {
	if b, complete := collectBind(t, hostfs.NewMemFS()); b.Present || !complete {
		t.Errorf("%+v complete %v", b, complete)
	}
	m := hostfs.NewMemFS().AddFile("/etc/named.conf", `include "/etc/named.missing"; zone "a" { type master; };`, 0o644, 0, 0)
	if _, complete := collectBind(t, m); complete {
		t.Error("a missing include must make the facts incomplete")
	}
	m = hostfs.NewMemFS().AddFile("/etc/named.conf", "zone", 0o644, 0, 0).SetError("/etc/named.conf", fsErrPermission)
	if _, err := (bindCollector{}).Collect(context.Background(), hostfs.NewTestHost(m, nil, false)); err == nil || !strings.Contains(err.Error(), "run vmsctl as root") {
		t.Errorf("err = %v", err)
	}
}
