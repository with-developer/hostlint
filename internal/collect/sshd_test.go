package collect

import (
	"context"
	"io/fs"
	"testing"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// A Debian 12 style configuration: drop-in directory included first, a
// Match block at the end.
func sshdFixture() *hostfs.MemFS {
	return hostfs.NewMemFS().
		AddFile("/usr/sbin/sshd", "", 0o755, 0, 0).
		AddFile("/etc/ssh/sshd_config", `Include /etc/ssh/sshd_config.d/*.conf
# PermitRootLogin prohibit-password
PermitRootLogin yes
PasswordAuthentication=no
AllowUsers alice
AllowUsers bob
UsePAM yes

Match Address 10.0.0.0/8
    PermitRootLogin Yes
    X11Forwarding no
`, 0o644, 0, 0).
		AddFile("/etc/ssh/sshd_config.d/50-hardening.conf", "PermitRootLogin no\nMaxAuthTries 3\n", 0o644, 0, 0)
}

// sshdT is what `sshd -T` prints for that configuration (trimmed).
const sshdT = `port 22
permitrootlogin no
maxauthtries 3
passwordauthentication no
pubkeyauthentication yes
allowusers alice
allowusers bob
usepam yes
x11forwarding no
`

func TestSSHDLive(t *testing.T) {
	h := hostfs.NewTestHost(sshdFixture(), hostfs.RecordedRunner{"sshd -T": {Stdout: sshdT}}, true)
	f, err := sshdCollector{}.Collect(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	s := f.Value.(*SSHD)
	want := map[string]facts.Setting{
		// The drop-in is read first, so its value wins over the main file.
		"permitrootlogin":        {Value: "no", Explicit: true, Source: "/etc/ssh/sshd_config.d/50-hardening.conf:1"},
		"maxauthtries":           {Value: "3", Explicit: true, Source: "/etc/ssh/sshd_config.d/50-hardening.conf:2"},
		"passwordauthentication": {Value: "no", Explicit: true, Source: "/etc/ssh/sshd_config:4"},
		"pubkeyauthentication":   {Value: "yes", Source: "sshd -T (default)"},
		"allowusers":             {Value: "alice bob", Explicit: true, Source: "/etc/ssh/sshd_config:5"},
	}
	if !s.Present || !f.Complete {
		t.Fatalf("present %v complete %v", s.Present, f.Complete)
	}
	for k, w := range want {
		if s.Config[k] != w {
			t.Errorf("%s = %+v, want %+v", k, s.Config[k], w)
		}
	}
	if len(s.Match) != 1 {
		t.Fatalf("match blocks = %+v", s.Match)
	}
	m := s.Match[0]
	if m.Criteria != "Address 10.0.0.0/8" || m.Source != "/etc/ssh/sshd_config:9" ||
		m.Settings["permitrootlogin"].Value != "yes" || m.Settings["x11forwarding"].Value != "no" {
		t.Errorf("match = %+v", m)
	}
}

// On a mounted root no command runs: only explicit values are known, and
// defaults stay unknown (absent).
func TestSSHDMountedRoot(t *testing.T) {
	f, err := sshdCollector{}.Collect(context.Background(), hostfs.NewTestHost(sshdFixture(), nil, false))
	if err != nil {
		t.Fatal(err)
	}
	s := f.Value.(*SSHD)
	if s.Config["permitrootlogin"].Value != "no" || !s.Config["permitrootlogin"].Explicit {
		t.Errorf("permitrootlogin = %+v", s.Config["permitrootlogin"])
	}
	if _, ok := s.Config["pubkeyauthentication"]; ok {
		t.Error("a default must stay unknown without sshd -T")
	}
}

func TestSSHDNotInstalled(t *testing.T) {
	f, err := sshdCollector{}.Collect(context.Background(), hostfs.NewTestHost(hostfs.NewMemFS(), nil, true))
	if err != nil || f.Value.(*SSHD).Present {
		t.Errorf("no sshd: %+v, %v", f.Value, err)
	}
}

func TestSSHDCommandFailure(t *testing.T) {
	h := hostfs.NewTestHost(sshdFixture(), hostfs.RecordedRunner{"sshd -T": {ExitCode: 255, Stderr: "sshd: no hostkeys available -- exiting."}}, true)
	if _, err := (sshdCollector{}).Collect(context.Background(), h); err == nil {
		t.Error("a failing sshd -T must fail the collector, not fall back to guesses")
	}
}

func TestSSHDUnreadableInclude(t *testing.T) {
	m := sshdFixture().SetError("/etc/ssh/sshd_config.d", fs.ErrPermission)
	f, err := sshdCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	// The unreadable drop-in could set anything: the facts are incomplete.
	if f.Complete || len(f.Skipped) == 0 {
		t.Errorf("complete %v, skipped %v", f.Complete, f.Skipped)
	}
}

// An included file's Match block ends with the file, as in sshd; hidden
// files are not included.
func TestSSHDIncludeScope(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/usr/sbin/sshd", "", 0o755, 0, 0).
		AddFile("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nUsePAM yes\n", 0o644, 0, 0).
		AddFile("/etc/ssh/sshd_config.d/10-sftp.conf", "Match Group sftponly\n    ForceCommand internal-sftp\n", 0o644, 0, 0).
		AddFile("/etc/ssh/sshd_config.d/.05-disabled.conf", "PermitRootLogin yes\n", 0o644, 0, 0)
	f, err := sshdCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	s := f.Value.(*SSHD)
	if s.Config["permitrootlogin"].Value != "no" || s.Config["usepam"].Value != "yes" {
		t.Errorf("global config = %+v", s.Config)
	}
	if len(s.Match) != 1 || len(s.Match[0].Settings) != 1 {
		t.Errorf("match = %+v", s.Match)
	}
}
