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
	return hostfs.NewMemFS().AddFile(snmpdConfig, text, 0o644, 0, 0)
}

// The packaged configurations of Ubuntu 24.04 and Rocky Linux 9.
func TestSNMPDistributionDefaults(t *testing.T) {
	t.Run("ubuntu 24.04: public, from the host only", func(t *testing.T) {
		s, complete := collectSNMP(t, fixtureFS(t, "ubuntu-24.04"))
		if !complete || !s.Present || !s.LoopbackOnly || s.V3Users != 1 || len(s.Communities) != 2 {
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

func TestSNMPCommunities(t *testing.T) {
	tests := []struct {
		name, conf string
		want       []SNMPCommunity
	}{
		{"a strong community limited to a network", "rocommunity 'V3ry-long-string' 10.1.0.0/16\n",
			[]SNMPCommunity{{Directive: "rocommunity", Source: "10.1.0.0/16"}}},
		{"a short one", "rwcommunity abc localhost\n", []SNMPCommunity{{Directive: "rwcommunity", Weak: "shorter than 8 characters", Source: "localhost"}}},
		{"the default source", "rocommunity Str0ng-and-long default\n", []SNMPCommunity{{Directive: "rocommunity", Unrestricted: true}}},
		{"no source", "rocommunity6 Str0ng-and-long\n", []SNMPCommunity{{Directive: "rocommunity6", Unrestricted: true}}},
		{"the whole address space", "rocommunity Str0ng-and-long 0.0.0.0/0\n", []SNMPCommunity{{Directive: "rocommunity", Unrestricted: true}}},
		{"authcommunity takes types first", "authcommunity log,net Private-but-long 192.0.2.7\n", []SNMPCommunity{{Directive: "authcommunity", Source: "192.0.2.7"}}},
		{"com2sec with a context", "com2sec -Cn ctx sec 192.0.2.0/24 private\n", []SNMPCommunity{{Directive: "com2sec", Weak: "a well-known name", Source: "192.0.2.0/24"}}},
		{"case does not hide a well-known name", "rocommunity PUBLIC 192.0.2.1\n", []SNMPCommunity{{Directive: "rocommunity", Weak: "a well-known name", Source: "192.0.2.1"}}},
		{"a comment is not a directive", "# rocommunity public\nsysName x # rocommunity public\n", []SNMPCommunity{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, complete := collectSNMP(t, snmpConf(tt.conf))
			for i := range s.Communities {
				s.Communities[i].Where = "" // positions are covered elsewhere
			}
			if !complete || len(s.Communities) != len(tt.want) {
				t.Fatalf("communities %+v complete %v, want %+v", s.Communities, complete, tt.want)
			}
			for i, c := range tt.want {
				if s.Communities[i] != c {
					t.Errorf("community %d = %+v, want %+v", i, s.Communities[i], c)
				}
			}
		})
	}
}

// A community string is a password: no field of the facts holds one.
func TestSNMPFactsHoldNoCommunityString(t *testing.T) {
	s, _ := collectSNMP(t, snmpConf("rocommunity Zx9-unique-string-4711 10.0.0.0/8\ncom2sec n default Another-Unique-Secret-82\n"))
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"Zx9-unique-string-4711", "Another-Unique-Secret-82"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the facts hold a community string: %s", data)
		}
	}
}

func TestSNMPListenAndUsers(t *testing.T) {
	tests := []struct {
		name, conf string
		loopback   bool
		listen     int
		v3         int64
	}{
		{"loopback only", "agentaddress 127.0.0.1,[::1]\n", true, 2, 0},
		{"with protocols and ports", "agentAddress udp:127.0.0.1:161,udp6:[::1]:161\n", true, 2, 0},
		{"a bare port is every interface", "agentaddress udp:161\n", false, 1, 0},
		{"an external address", "agentaddress 127.0.0.1,192.0.2.5:161\n", false, 2, 0},
		{"unix socket", "agentaddress unix:/var/run/snmp.sock\n", true, 1, 0},
		{"not set", "sysName x\n", false, 0, 0},
		{"users", "rouser alice authpriv\nrwuser bob\ncreateUser carol SHA pass AES pass2\n", false, 0, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := collectSNMP(t, snmpConf(tt.conf))
			if s.LoopbackOnly != tt.loopback || len(s.Listen) != tt.listen || s.V3Users != tt.v3 {
				t.Errorf("%+v, want loopback %v, %d addresses, %d users", s, tt.loopback, tt.listen, tt.v3)
			}
		})
	}
}

func TestSNMPIncludes(t *testing.T) {
	m := snmpConf("includeFile /etc/snmp/extra.conf\nincludeDir /etc/snmp/snmpd.conf.d\nincludeFile missing.conf\n").
		AddFile("/etc/snmp/extra.conf", "rocommunity Longer-string-1 192.0.2.1\n", 0o644, 0, 0).
		AddDir("/etc/snmp/snmpd.conf.d", 0o755, 0, 0).
		AddFile("/etc/snmp/snmpd.conf.d/local.conf", "rwcommunity private 192.0.2.2\n", 0o644, 0, 0).
		AddFile("/etc/snmp/snmpd.conf.d/notes.txt", "rwcommunity ignored 192.0.2.3\n", 0o644, 0, 0)
	s, complete := collectSNMP(t, m)
	if len(s.Communities) != 2 || s.Communities[0].Directive != "rocommunity" || s.Communities[1].Directive != "rwcommunity" {
		t.Errorf("communities %+v", s.Communities)
	}
	// An include that cannot be read could hold a community: the facts are incomplete.
	if complete {
		t.Error("a missing included file must make the facts incomplete")
	}
}

func TestSNMPNoAgentConfiguration(t *testing.T) {
	s, complete := collectSNMP(t, hostfs.NewMemFS())
	if s.Present || !complete {
		t.Errorf("%+v complete %v", s, complete)
	}
}

func TestSNMPUnreadableFile(t *testing.T) {
	m := snmpConf("rocommunity x\n").SetError(snmpdConfig, fsErrPermission)
	if _, err := (snmpCollector{}).Collect(context.Background(), hostfs.NewTestHost(m, nil, false)); err == nil {
		t.Error("an unreadable snmpd.conf must fail the collector")
	}
}

func TestSNMPFields(t *testing.T) {
	for in, want := range map[string]string{
		`rocommunity "a b" 10.0.0.0/8`: "rocommunity|a b|10.0.0.0/8",
		`rocommunity 'x y'   # note`:   "rocommunity|x y",
		`  # only a comment`:           "",
		`rocommunity a#b src`:          "rocommunity|a#b|src",
		"\trocommunity\tpublic\t":      "rocommunity|public",
	} {
		got, ok := snmpFields(in)
		if !ok || strings.Join(got, "|") != want {
			t.Errorf("snmpFields(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := snmpFields(`rocommunity "unterminated`); ok {
		t.Error("an unbalanced quote must be reported")
	}
}

func FuzzSNMPConfig(f *testing.F) {
	for _, name := range []string{"ubuntu-24.04", "rocky-9"} {
		f.Add([]byte(loadTree(f, name)["/etc/snmp/snmpd.conf"]))
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = snmpCollector{}.Collect(context.Background(), hostfs.NewTestHost(snmpConf(string(data)), nil, false))
	})
}
