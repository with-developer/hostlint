package collect

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func collectSNMP(t *testing.T, m *hostfs.MemFS) (*SNMP, bool) {
	t.Helper()
	f, err := snmpCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return f.Value.(*SNMP), f.Complete
}

func snmpConf(text string) *hostfs.MemFS {
	return hostfs.NewMemFS().AddFile("/etc/snmp/snmpd.conf", text, 0o644, 0, 0)
}

// The packaged configurations of Ubuntu 24.04 and Rocky Linux 9.
func TestSNMPDistributionDefaults(t *testing.T) {
	t.Run("ubuntu 24.04: public, from the host only", func(t *testing.T) {
		s, complete := collectSNMP(t, fixtureFS(t, "ubuntu-24.04"))
		if !complete || !s.Present || !s.LoopbackOnly || len(s.Communities) != 2 {
			t.Fatalf("%+v complete %v", s, complete)
		}
		c := s.Communities[0]
		if c.Directive != "rocommunity" || c.Weak != "a well-known name" || !c.Unrestricted || !strings.HasSuffix(c.Where, "snmpd.conf:71") {
			t.Errorf("community %+v", c)
		}
	})
	t.Run("rocky 9: public from any address, on every interface", func(t *testing.T) {
		s, _ := collectSNMP(t, fixtureFS(t, "rocky-9"))
		if !s.Present || s.LoopbackOnly || len(s.Listen) != 0 || len(s.Communities) != 1 {
			t.Fatalf("%+v", s)
		}
		if c := s.Communities[0]; c.Directive != "com2sec" || c.Weak != "a well-known name" || !c.Unrestricted {
			t.Errorf("community %+v", c)
		}
	})
}

// A community string is a password: no field of the facts holds one.
func TestSNMPFactsHoldNoCommunityString(t *testing.T) {
	s, _ := collectSNMP(t, snmpConf("rocommunity Zx9-unique-string-4711 10.0.0.0/8\ncom2sec n default Another-Unique-Secret-82\ncreateUser carol SHA Passphrase-Of-Carol\n"))
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Zx9-unique-string-4711", "Another-Unique-Secret-82", "Passphrase-Of-Carol"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the facts hold a secret: %s", data)
		}
	}
}

func TestSNMPNoAgentConfiguration(t *testing.T) {
	s, complete := collectSNMP(t, hostfs.NewMemFS())
	if s.Present || !complete {
		t.Errorf("%+v complete %v", s, complete)
	}
}

func TestSNMPUnreadableFile(t *testing.T) {
	m := snmpConf("rocommunity x\n").SetError("/etc/snmp/snmpd.conf", fsErrPermission)
	_, err := snmpCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err == nil || !strings.Contains(err.Error(), "run hostlint as root") {
		t.Errorf("err = %v, want one telling to run as root", err)
	}
}
