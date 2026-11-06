package hostfs

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func snmpMem(text string) *MemFS {
	return NewMemFS().AddFile("/etc/snmp/snmpd.conf", text, 0o644, 0, 0)
}

func readSNMP(t *testing.T, m *MemFS) *SNMPConfig {
	t.Helper()
	cfg, err := ReadSNMPConfig(m)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
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
		{"other spellings of the whole address space", "rocommunity Str0ng-and-long 0/0\nrocommunity Str0ng-and-long ::0/0\nrocommunity Str0ng-and-long 10.0.0.0/0\nrocommunity Str0ng-and-long 10.0.0.0/0.0.0.0\n",
			[]SNMPCommunity{{Directive: "rocommunity", Unrestricted: true}, {Directive: "rocommunity", Unrestricted: true}, {Directive: "rocommunity", Unrestricted: true}, {Directive: "rocommunity", Unrestricted: true}}},
		{"a narrow prefix is a restriction", "rocommunity Str0ng-and-long 10.0.0.0/8\nrocommunity Str0ng-and-long 192.0.2.1/32\n",
			[]SNMPCommunity{{Directive: "rocommunity", Source: "10.0.0.0/8"}, {Directive: "rocommunity", Source: "192.0.2.1/32"}}},
		{"authcommunity takes types first", "authcommunity log,net Private-but-long 192.0.2.7\n", []SNMPCommunity{{Directive: "authcommunity", Source: "192.0.2.7"}}},
		{"com2sec with a context", "com2sec -Cn ctx sec 192.0.2.0/24 private\n", []SNMPCommunity{{Directive: "com2sec", Weak: "a well-known name", Source: "192.0.2.0/24"}}},
		{"case does not hide a well-known name", "rocommunity PUBLIC 192.0.2.1\n", []SNMPCommunity{{Directive: "rocommunity", Weak: "a well-known name", Source: "192.0.2.1"}}},
		{"a comment is not a directive", "# rocommunity public\nsysName x # rocommunity public\n", []SNMPCommunity{}},
		{"an apostrophe inside a word", "sysLocation Bob's server room\nsyscontact O'Brien <ops@example.org>\nrocommunity Str0ng-and-long 192.0.2.1\n",
			[]SNMPCommunity{{Directive: "rocommunity", Source: "192.0.2.1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := readSNMP(t, snmpMem(tt.conf))
			if len(cfg.Skipped) != 0 {
				t.Errorf("skipped %v", cfg.Skipped)
			}
			if len(cfg.Communities) != len(tt.want) {
				t.Fatalf("communities %+v, want %+v", cfg.Communities, tt.want)
			}
			for i, c := range tt.want {
				got := cfg.Communities[i]
				got.Where = ""
				if got != c {
					t.Errorf("community %d = %+v, want %+v", i, got, c)
				}
			}
		})
	}
}

func TestSNMPListen(t *testing.T) {
	tests := []struct {
		name, conf string
		loopback   bool
		listen     int
	}{
		{"loopback only", "agentaddress 127.0.0.1,[::1]\n", true, 2},
		{"with protocols and ports", "agentAddress udp:127.0.0.1:161,udp6:[::1]:161\n", true, 2},
		{"a bare port is every interface", "agentaddress udp:161\n", false, 1},
		{"an external address", "agentaddress 127.0.0.1,192.0.2.5:161\n", false, 2},
		{"unix socket", "agentaddress unix:/var/run/snmp.sock\n", true, 1},
		{"not set", "sysName x\n", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := readSNMP(t, snmpMem(tt.conf))
			if cfg.LoopbackOnly != tt.loopback || len(cfg.Listen) != tt.listen {
				t.Errorf("%+v, want loopback %v, %d addresses", cfg, tt.loopback, tt.listen)
			}
		})
	}
}

func TestSNMPIncludes(t *testing.T) {
	m := snmpMem("includeFile /etc/snmp/extra.conf\nincludeDir /etc/snmp/snmpd.conf.d\nincludeFile extra.conf\n").
		AddFile("/etc/snmp/extra.conf", "rocommunity Longer-string-1 192.0.2.1\nincludeFile /etc/snmp/snmpd.conf\n", 0o644, 0, 0).
		AddDir("/etc/snmp/snmpd.conf.d", 0o755, 0, 0).
		AddFile("/etc/snmp/snmpd.conf.d/local.conf", "rwcommunity private 192.0.2.2\n", 0o644, 0, 0).
		AddFile("/etc/snmp/snmpd.conf.d/notes.txt", "rwcommunity ignored 192.0.2.3\n", 0o644, 0, 0)
	cfg := readSNMP(t, m)
	// extra.conf is read once, though two lines name it, and it includes the main file: a cycle.
	if len(cfg.Communities) != 2 || cfg.Communities[0].Directive != "rocommunity" || cfg.Communities[1].Directive != "rwcommunity" || len(cfg.Skipped) != 0 {
		t.Errorf("communities %+v, skipped %v", cfg.Communities, cfg.Skipped)
	}
	// snmpd.local.conf is read too.
	m.AddFile("/etc/snmp/snmpd.local.conf", "rocommunity Local-string-9 192.0.2.9\n", 0o644, 0, 0)
	if cfg = readSNMP(t, m); len(cfg.Communities) != 3 {
		t.Errorf("snmpd.local.conf was not read: %+v", cfg.Communities)
	}
	// A file named by includeFile that is nowhere could hold anything.
	cfg = readSNMP(t, snmpMem("includeFile missing.conf\n"))
	if len(cfg.Skipped) != 1 || !strings.Contains(cfg.Skipped[0], "missing.conf") {
		t.Errorf("skipped %v", cfg.Skipped)
	}
	// A missing includeDir is ignored, as net-snmp does.
	if cfg = readSNMP(t, snmpMem("includeDir /etc/snmp/none.d\n")); len(cfg.Skipped) != 0 {
		t.Errorf("skipped %v", cfg.Skipped)
	}
}

// A line longer than the scanner's limit stops the read: the rest of the file
// is not seen, and the config says so.
func TestSNMPLongLineIsIncomplete(t *testing.T) {
	cfg := readSNMP(t, snmpMem("sysName "+strings.Repeat("x", 2<<20)+"\nrocommunity public\n"))
	if len(cfg.Skipped) != 1 || !strings.Contains(cfg.Skipped[0], "the rest of the file was not read") {
		t.Errorf("skipped %v", cfg.Skipped)
	}
}

func TestSNMPFields(t *testing.T) {
	for in, want := range map[string]string{
		`rocommunity "a b" 10.0.0.0/8`: "rocommunity|a b|10.0.0.0/8",
		`rocommunity 'x y'   # note`:   "rocommunity|x y",
		`  # only a comment`:           "",
		`rocommunity a#b src`:          "rocommunity|a#b|src",
		"\trocommunity\tpublic\t":      "rocommunity|public",
		`sysLocation Bob's room`:       "sysLocation|Bob's|room",
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

// The agent's files hold secrets: generic reads are refused.
func TestSNMPFilesAreDenied(t *testing.T) {
	m := snmpMem("rocommunity secret\n").
		AddFile("/etc/snmp/snmpd.local.conf", "x", 0o644, 0, 0).
		AddFile("/etc/snmp/snmpd.conf.d/a.conf", "x", 0o644, 0, 0).
		AddFile("/var/lib/net-snmp/snmpd.conf", "usmUser x", 0o600, 0, 0)
	for _, name := range []string{"/etc/snmp/snmpd.conf", "/etc/snmp/snmpd.local.conf", "/etc/snmp/snmpd.conf.d/a.conf", "/var/lib/net-snmp/snmpd.conf"} {
		if _, err := m.ReadFile(name); !errors.Is(err, ErrDenied) {
			t.Errorf("ReadFile(%s) err = %v, want ErrDenied", name, err)
		}
	}
}

func TestSNMPUnreadable(t *testing.T) {
	m := snmpMem("rocommunity x\n").SetError("/etc/snmp/snmpd.conf", fs.ErrPermission)
	if _, err := ReadSNMPConfig(m); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("err = %v", err)
	}
}

func FuzzSNMPConfig(f *testing.F) {
	f.Add("rocommunity public default\ncom2sec n 10.0.0.0/8 secret\nagentaddress 127.0.0.1,[::1]\nincludeDir /etc/snmp/snmpd.conf.d\n")
	f.Add("rocommunity \"unterminated\n")
	f.Fuzz(func(_ *testing.T, text string) {
		_, _ = ReadSNMPConfig(snmpMem(text))
	})
}

// A symbolic link to a .conf file in an include directory is followed, as net-snmp does.
func TestSNMPIncludeDirFollowsLinks(t *testing.T) {
	m := snmpMem("includeDir /etc/snmp/snmpd.conf.d\n").
		AddDir("/etc/snmp/snmpd.conf.d", 0o755, 0, 0).
		AddFile("/srv/cfg/site.conf", "rocommunity public\n", 0o644, 0, 0).
		AddSymlink("/etc/snmp/snmpd.conf.d/site.conf", "/srv/cfg/site.conf")
	cfg := readSNMP(t, m)
	if len(cfg.Communities) != 1 || cfg.Communities[0].Weak != "a well-known name" {
		t.Errorf("communities %+v, skipped %v", cfg.Communities, cfg.Skipped)
	}
}

// A path a configuration names is read as any file is: the denylist applies to it.
func TestSNMPIncludeOfASecretFileIsRefused(t *testing.T) {
	m := snmpMem("includeFile /etc/ssh/ssh_host_rsa_key\n").
		AddFile("/etc/ssh/ssh_host_rsa_key", "rocommunity public\n", 0o600, 0, 0)
	cfg := readSNMP(t, m)
	if len(cfg.Communities) != 0 || len(cfg.Skipped) != 1 {
		t.Errorf("communities %+v, skipped %v", cfg.Communities, cfg.Skipped)
	}
}
