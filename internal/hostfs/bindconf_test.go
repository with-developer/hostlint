package hostfs

import (
	"errors"
	"strings"
	"testing"
)

func bindMem(files map[string]string) *MemFS {
	m := NewMemFS()
	for name, text := range files {
		m.AddFile(name, text, 0o644, 0, 0)
	}
	return m
}

func readBind(t *testing.T, files map[string]string) *BindConfig {
	t.Helper()
	cfg, err := ReadBindConfig(bindMem(files))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func zoneOf(t *testing.T, cfg *BindConfig, name string) BindZone {
	t.Helper()
	for _, z := range cfg.Zones {
		if z.Name == name {
			return z
		}
	}
	t.Fatalf("no zone %s in %+v", name, cfg.Zones)
	return BindZone{}
}

func TestBindTransfer(t *testing.T) {
	tests := []struct {
		name, conf, want string
	}{
		{"the default is everyone", `zone "a" { type master; file "a"; };`, "any"},
		{"none", `zone "a" { type master; allow-transfer { none; }; };`, "none"},
		{"an empty list", `zone "a" { type master; allow-transfer { }; };`, "none"},
		{"addresses", `zone "a" { type master; allow-transfer { 192.0.2.1; 10.0.0.0/8; }; };`, "restricted"},
		{"a key", `zone "a" { type master; allow-transfer { key xfer; }; };`, "restricted"},
		{"any", `zone "a" { type master; allow-transfer { any; }; };`, "any"},
		{"any after a negation", `zone "a" { type master; allow-transfer { !10.0.0.0/8; any; }; };`, "any"},
		{"the whole address space", `zone "a" { type master; allow-transfer { 0.0.0.0/0; }; };`, "any"},
		{"an acl", `acl "slaves" { 192.0.2.1; }; zone "a" { type master; allow-transfer { slaves; }; };`, "restricted"},
		{"an acl that is any", `acl "world" { any; }; zone "a" { type master; allow-transfer { world; }; };`, "any"},
		{"an acl of an acl that is any", `acl "x" { any; }; acl "y" { x; }; zone "a" { type master; allow-transfer { y; }; };`, "any"},
		{"the global option", `options { allow-transfer { 192.0.2.1; }; }; zone "a" { type master; };`, "restricted"},
		{"the zone overrides the option", `options { allow-transfer { none; }; }; zone "a" { type master; allow-transfer { any; }; };`, "any"},
		{"a secondary zone", `zone "a" { type secondary; masters { 192.0.2.1; }; };`, "any"},
		{"comments of three kinds", "// c\n# c\n/* c\n c */ zone \"a\" { type master; /* x */ allow-transfer { none; }; // y\n };", "none"},
		{"the last option wins", `zone "a" { type master; allow-transfer { any; }; allow-transfer { none; }; };`, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := readBind(t, map[string]string{"/etc/named.conf": tt.conf})
			if len(cfg.Skipped) != 0 {
				t.Fatalf("skipped %v", cfg.Skipped)
			}
			if got := zoneOf(t, cfg, "a").Transfer; got != tt.want {
				t.Errorf("transfer = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBindUpdate(t *testing.T) {
	tests := []struct {
		name, zone, want string
	}{
		{"the default is none", `type master;`, "none"},
		{"none", `type master; allow-update { none; };`, "none"},
		{"addresses", `type master; allow-update { 192.0.2.1; };`, "restricted"},
		{"a key", `type master; allow-update { key dhcp; };`, "restricted"},
		{"any", `type master; allow-update { any; };`, "any"},
		{"an update policy", `type master; update-policy { grant dhcp-key zonesub any; };`, "restricted"},
		{"a secondary is never updated", `type slave; allow-update { any; };`, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := readBind(t, map[string]string{"/etc/named.conf": `zone "a" { ` + tt.zone + ` };`})
			if got := zoneOf(t, cfg, "a").Update; got != tt.want {
				t.Errorf("update = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBindViewsAndKinds(t *testing.T) {
	cfg := readBind(t, map[string]string{"/etc/named.conf": `
options { allow-transfer { any; }; };
view "internal" {
  allow-transfer { 10.0.0.0/8; };
  zone "corp.example" { type master; };
  zone "open.example" { type master; allow-transfer { any; }; };
};
view "external" { zone "corp.example" { type master; }; };
zone "." { type hint; };
zone "fwd.example" { type forward; forwarders { 192.0.2.1; }; };
`})
	if len(cfg.Zones) != 3 {
		t.Fatalf("zones %+v", cfg.Zones)
	}
	if z := cfg.Zones[0]; z.View != "internal" || z.Transfer != "restricted" {
		t.Errorf("view option: %+v", z)
	}
	if z := cfg.Zones[1]; z.Transfer != "any" {
		t.Errorf("zone over view: %+v", z)
	}
	if z := cfg.Zones[2]; z.View != "external" || z.Transfer != "any" {
		t.Errorf("a view without its own option uses the global one: %+v", z)
	}
}

func TestBindIncludesAndLocalZones(t *testing.T) {
	cfg := readBind(t, map[string]string{
		"/etc/bind/named.conf": "include \"/etc/bind/zones.conf\";\nzone \"localhost\" { type master; };\n",
		"/etc/bind/zones.conf": "zone \"Example.COM.\" { type master; allow-transfer { none; }; };\ninclude \"/etc/bind/named.conf\";\n",
	})
	if len(cfg.Skipped) != 0 || len(cfg.Zones) != 2 {
		t.Fatalf("zones %+v, skipped %v", cfg.Zones, cfg.Skipped)
	}
	if z := zoneOf(t, cfg, "example.com"); z.Local || z.Transfer != "none" {
		t.Errorf("%+v", z)
	}
	if z := zoneOf(t, cfg, "localhost"); !z.Local {
		t.Errorf("%+v", z)
	}
}

func TestBindIncompleteConfigurations(t *testing.T) {
	for name, conf := range map[string]string{
		"a missing include":       `include "/etc/bind/none.conf"; zone "a" { type master; };`,
		"unbalanced braces":       `zone "a" { type master;`,
		"an unterminated string":  `zone "a { type master; };`,
		"an unterminated comment": `/* zone "a" { type master; };`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := readBind(t, map[string]string{"/etc/named.conf": conf})
			if len(cfg.Skipped) == 0 {
				t.Error("the configuration must be reported incomplete")
			}
		})
	}
}

// A TSIG key is a secret: nothing of a key statement is kept.
func TestBindKeepsNoSecret(t *testing.T) {
	cfg := readBind(t, map[string]string{"/etc/named.conf": `key "xfer" { algorithm hmac-sha256; secret "Sup3r-Secret-Tsig=="; };
zone "a" { type master; allow-transfer { key xfer; }; };`})
	if got := zoneOf(t, cfg, "a"); got.Transfer != "restricted" {
		t.Errorf("%+v", got)
	}
	if strings.Contains(strings.Join(append([]string{}, cfg.Skipped...), " "), "Sup3r") {
		t.Error("a secret was reported")
	}
}

func TestBindFilesAreDenied(t *testing.T) {
	m := bindMem(map[string]string{"/etc/bind/named.conf": "x", "/etc/bind/rndc.key": "y", "/etc/named.conf": "z", "/etc/bind/named.conf.local": "w"})
	for _, name := range []string{"/etc/bind/named.conf", "/etc/bind/rndc.key", "/etc/named.conf", "/etc/bind/named.conf.local"} {
		if _, err := m.ReadFile(name); !errors.Is(err, ErrDenied) {
			t.Errorf("ReadFile(%s) err = %v, want ErrDenied", name, err)
		}
	}
}

func TestBindNoConfiguration(t *testing.T) {
	if cfg := readBind(t, map[string]string{"/etc/hostname": "x"}); cfg.Present || len(cfg.Zones) != 0 {
		t.Errorf("%+v", cfg)
	}
}

func FuzzBindConfig(f *testing.F) {
	f.Add(`options { allow-transfer { none; }; }; zone "a" { type master; allow-update { key k; }; }; acl x { any; }; include "/etc/named.conf";`)
	f.Add("zone \"a\" { { { { ; } } } ")
	f.Fuzz(func(_ *testing.T, text string) {
		_, _ = ReadBindConfig(bindMem(map[string]string{"/etc/named.conf": text}))
	})
}
