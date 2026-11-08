package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

func updatesOf(t *testing.T, m *hostfs.MemFS) (*Updates, bool, []string) {
	t.Helper()
	got, err := updatesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return got.Value.(*Updates), got.Complete, got.Skipped
}

func firewallOf(t *testing.T, m *hostfs.MemFS) (*Firewall, bool) {
	t.Helper()
	got, err := firewallCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return got.Value.(*Firewall), got.Complete
}

// The files of a real Ubuntu 24.04 with ufw and unattended-upgrades installed (in a container image, which is why
// docker-disable-periodic-update turns the periodic runs off): the ufw unit is enabled by the package, and the firewall is off.
func TestUbuntuUpdatesAndUfw(t *testing.T) {
	m := fixtureFS(t, "updates/ubuntu-24.04")
	fw, complete := firewallOf(t, m)
	if !complete || !fw.Ufw.Present || fw.Ufw.Settings["enabled"].Value != "no" || !fw.Ufw.Settings["enabled"].Explicit || fw.Ufw.Settings["enabled"].Source != "/etc/ufw/ufw.conf:6" {
		t.Errorf("ufw: %+v (complete %v)", fw.Ufw, complete)
	}
	u, complete, skipped := updatesOf(t, m)
	if !complete {
		t.Fatalf("incomplete: %v", skipped)
	}
	a := u.Apt
	if !a.Present || a.Settings["update_package_lists"].Value != "1" || a.Settings["unattended_upgrade"].Value != "1" {
		t.Errorf("apt: %+v", a)
	}
	// 20auto-upgrades comes before docker-disable-periodic-update: the later file turns the whole of it off.
	if a.Settings["enable"].Value != "0" || a.Settings["enable"].Source != "/etc/apt/apt.conf.d/docker-disable-periodic-update:1" {
		t.Errorf("apt Enable: %+v", a.Settings["enable"])
	}
	if u.Dnf.Present || u.Yum.Present {
		t.Errorf("dnf or yum-cron on an Ubuntu: %+v %+v", u.Dnf, u.Yum)
	}
}

// The file of a real Rocky Linux 9 with dnf-automatic: it reports, and applies nothing, unless configured.
func TestRockyDnfAutomatic(t *testing.T) {
	u, complete, skipped := updatesOf(t, fixtureFS(t, "updates/rocky-9"))
	if !complete {
		t.Fatalf("incomplete: %v", skipped)
	}
	d := u.Dnf
	if !d.Present || d.Settings["apply_updates"].Value != "no" || d.Settings["upgrade_type"].Value != "default" || d.Settings["apply_updates"].Source != "/etc/dnf/automatic.conf:22" {
		t.Errorf("dnf-automatic: %+v", d)
	}
	if u.Apt.Present {
		t.Errorf("apt on a Rocky: %+v", u.Apt)
	}
}

func TestNothingConfigured(t *testing.T) {
	u, complete, _ := updatesOf(t, hostfs.NewMemFS())
	if !complete || u.Apt.Present || u.Dnf.Present || u.Yum.Present || u.Apt.Settings["unattended_upgrade"].Explicit {
		t.Errorf("an empty host: %+v (complete %v)", u, complete)
	}
	fw, complete := firewallOf(t, hostfs.NewMemFS())
	if !complete || fw.Ufw.Present {
		t.Errorf("an empty host: %+v", fw)
	}
}

func TestParseAptPeriodic(t *testing.T) {
	read := func(files map[string]string) (AptPeriodic, []string) {
		m := hostfs.NewMemFS().AddDir("/etc/apt/apt.conf.d", 0o755, 0, 0)
		for name, body := range files {
			m.AddFile(name, body, 0o644, 0, 0)
		}
		u, _, skipped := updatesOf(t, m)
		return u.Apt, skipped
	}
	// the last statement wins, across files in the order of their names, and apt.conf after them
	a, _ := read(map[string]string{
		"/etc/apt/apt.conf.d/10periodic":      "APT::Periodic::Unattended-Upgrade \"0\";\nAPT::Periodic::Update-Package-Lists \"7\";\n",
		"/etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n",
		"/etc/apt/apt.conf.d/99local.conf":    "// APT::Periodic::Unattended-Upgrade \"0\";\n# APT::Periodic::Unattended-Upgrade \"0\";\n",
		"/etc/apt/apt.conf.d/20auto.dpkg-old": "APT::Periodic::Unattended-Upgrade \"0\";\n", // a name apt does not read
		"/etc/apt/apt.conf.d/70backup~":       "APT::Periodic::Unattended-Upgrade \"0\";\n",
		"/etc/apt/apt.conf":                   "apt::periodic::update-package-lists \"3\";\n", // the keys do not care about case
	})
	if a.Settings["unattended_upgrade"].Value != "1" || a.Settings["update_package_lists"].Value != "3" || a.Settings["enable"].Explicit {
		t.Errorf("last wins: %+v", a)
	}
	// a value is an interval, in whatever unit apt takes: "1d" is 1, "12h" 12, "always" 1 (every time), "0" off
	a, skipped := read(map[string]string{"/etc/apt/apt.conf.d/20x": "APT::Periodic::Unattended-Upgrade \"always\";\nAPT::Periodic::Update-Package-Lists \"12h\";\nAPT::Periodic::Enable \"0\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\n"})
	if a.Settings["unattended_upgrade"].Value != "1" || a.Settings["update_package_lists"].Value != "12" || a.Settings["enable"].Value != "0" || len(skipped) != 0 {
		t.Errorf("intervals: %+v %v", a, skipped)
	}
	// what is not an interval ("true", a negative number) is kept as 0 and says so: apt reads 0, the author may have meant more
	_, skipped = read(map[string]string{"/etc/apt/apt.conf.d/20y": "APT::Periodic::Unattended-Upgrade \"true\";\n"})
	if len(skipped) != 1 || !strings.Contains(skipped[0], "not an interval") {
		t.Errorf("a value that is not an interval: %v", skipped)
	}
	// every other way to write Periodic is not read, and says so: a check cannot decide on a value that may be old or wrong
	for name, body := range map[string]string{
		"block form":            "APT::Periodic {\n  Unattended-Upgrade \"1\";\n};\n",
		"nested on a line":      "APT { Periodic { Unattended-Upgrade \"1\"; }; };\n",
		"two statements":        "APT::Periodic::Enable \"0\"; APT::Periodic::Unattended-Upgrade \"1\";\n",
		"a block comment":       "/* APT::Periodic::Unattended-Upgrade \"0\";\n*/\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		"a #clear":              "#clear APT::Periodic;\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
		"a statement continued": "APT::Periodic::Unattended-Upgrade\n  \"1\";\n",
	} {
		_, skipped := read(map[string]string{"/etc/apt/apt.conf.d/20z": body})
		if len(skipped) == 0 {
			t.Errorf("%s: read as if it were plain", name)
		}
	}
	// a file with nothing about Periodic is nothing to be unsure about, whatever else it has
	_, skipped = read(map[string]string{"/etc/apt/apt.conf.d/50u": "Unattended-Upgrade::Allowed-Origins {\n  \"${distro_id}:${distro_codename}-security\";\n};\n/* a comment */\n"})
	if len(skipped) != 0 {
		t.Errorf("a file that does not mention Periodic: %v", skipped)
	}
}

func TestParseAutomatic(t *testing.T) {
	a := Automatic{Settings: map[string]facts.Setting{}}
	parseAutomatic("/etc/dnf/automatic.conf", []byte("[base]\napply_updates = yes\n[commands]\nupgrade_type = security\t; only these\napply_updates = True # all of them\n[email]\napply_updates = no\n"), [2]string{"apply_updates", "upgrade_type"}, &a)
	if a.Settings["apply_updates"].Value != "yes" || a.Settings["upgrade_type"].Value != "security" || a.Settings["apply_updates"].Source != "/etc/dnf/automatic.conf:5" {
		t.Errorf("sections and spellings: %+v", a)
	}
	typo := Automatic{Settings: map[string]facts.Setting{}}
	parseAutomatic("f", []byte("[commands]\napply_updates = ys\n"), [2]string{"apply_updates", "update_cmd"}, &typo)
	if typo.Settings["apply_updates"].Value != "ys" { // neither yes nor no
		t.Errorf("a typo is kept as it is: %+v", typo)
	}
}

// The file of a real CentOS 7 with yum-cron: it only downloads, and applies nothing, unless configured.
func TestCentosYumCron(t *testing.T) {
	u, complete, skipped := updatesOf(t, fixtureFS(t, "updates/centos-7"))
	if !complete {
		t.Fatalf("incomplete: %v", skipped)
	}
	y := u.Yum
	if !y.Present || y.Settings["apply_updates"].Value != "no" || y.Settings["upgrade_type"].Value != "default" || y.Settings["apply_updates"].Source != "/etc/yum/yum-cron.conf:20" {
		t.Errorf("yum-cron: %+v", y)
	}
}

func TestUfwEnabled(t *testing.T) {
	for in, want := range map[string]string{
		"ENABLED=yes # on\n":          "yes", // sourced by a shell: the comment is not part of the value
		"ENABLED=yes\t# on\n":         "yes",
		"ENABLED=yes\n":               "yes",
		"ENABLED=\"YES\"\n":           "yes",
		"# ENABLED=yes\nENABLED=no\n": "no",
		"ENABLED=no\nENABLED=yes\n":   "yes", // sourced by a shell: the last wins
		"ENABLED=maybe\n":             "maybe",
	} {
		got, ok := ufwEnabled([]byte(in))
		if !ok || got.Value != want {
			t.Errorf("%q = %+v, want %q", in, got, want)
		}
	}
	if _, ok := ufwEnabled([]byte("LOGLEVEL=low\n# ENABLED=yes\n")); ok {
		t.Error("ENABLED in a comment is not set")
	}
}

// No input makes the parsers fail; the files come from the host that is scanned.
func FuzzUpdates(f *testing.F) {
	f.Add([]byte("APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic { Enable \"0\"; };\n"), []byte("[commands]\napply_updates = yes\n"), []byte("ENABLED=yes\n"))
	f.Fuzz(func(t *testing.T, apt, auto, ufw []byte) {
		m := hostfs.NewMemFS().
			AddFile("/etc/apt/apt.conf.d/20x", string(apt), 0o644, 0, 0).
			AddFile("/etc/dnf/automatic.conf", string(auto), 0o644, 0, 0).
			AddFile("/etc/ufw/ufw.conf", string(ufw), 0o644, 0, 0)
		h := hostfs.NewTestHost(m, nil, false)
		if _, err := (updatesCollector{}).Collect(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		if _, err := (firewallCollector{}).Collect(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	})
}
