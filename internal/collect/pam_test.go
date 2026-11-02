package collect

import (
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

func pamFacts(t *testing.T, m *hostfs.MemFS) *PAM {
	t.Helper()
	f, err := collect(t, pamCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Fatalf("incomplete: %v", f.Skipped)
	}
	return f.Value.(*PAM)
}

func modules(rules []PAMRule, typ string) string {
	var m []string
	for _, r := range rules {
		if r.Type == typ {
			m = append(m, r.Module)
		}
	}
	return strings.Join(m, " ")
}

func TestPAMDebian12(t *testing.T) {
	p := pamFacts(t, fixtureFS(t, "debian-12"))
	// passwd -> @include common-password
	if got := modules(p.Stacks["passwd"], "password"); got != "pam_pwquality.so pam_unix.so pam_deny.so pam_permit.so" {
		t.Errorf("passwd password stack = %q", got)
	}
	q := p.PasswordQuality
	if q.Module != "pam_pwquality.so" {
		t.Fatalf("quality module = %q", q.Module)
	}
	if s := q.Settings["retry"]; s.Value != "3" || !s.Explicit || !strings.HasPrefix(s.Source, "/etc/pam.d/common-password:") {
		t.Errorf("retry = %+v", s)
	}
	// No pwquality.conf on stock Debian: the documented default applies.
	if s := q.Settings["minlen"]; s != (facts.Setting{Value: "8", Source: "default (pwquality.conf(5))"}) {
		t.Errorf("minlen = %+v", s)
	}
	if l := p.Lockout["login"]; l.Module != "" {
		t.Errorf("stock Debian has no lockout, got %+v", l)
	}
	if got := modules(p.Stacks["su"], "auth"); !strings.HasPrefix(got, "pam_rootok.so pam_unix.so") {
		t.Errorf("su auth stack = %q (common-auth must be expanded)", got)
	}
}

func TestPAMRocky9(t *testing.T) {
	m := fixtureFS(t, "rocky-9")
	p := pamFacts(t, m)
	q := p.PasswordQuality
	if q.Module != "pam_pwquality.so" || q.Settings["retry"].Value != "3" || q.Settings["local_users_only"].Value != "1" || q.Settings["authtok_type"].Value != "" {
		t.Errorf("quality = %+v", q)
	}
	// sshd uses "auth substack password-auth".
	if got := modules(p.Stacks["sshd"], "auth"); !strings.Contains(got, "pam_unix.so") {
		t.Errorf("sshd auth stack = %q", got)
	}

	// authselect's with-faillock feature, plus a faillock.conf.
	sysAuth, _ := m.ReadFile("/etc/pam.d/system-auth")
	withFaillock := strings.Replace(string(sysAuth), "auth        required      pam_env.so",
		"auth        required      pam_env.so\nauth        required      pam_faillock.so preauth silent\nauth        [default=die] pam_faillock.so authfail", 1)
	m.AddFile("/etc/pam.d/system-auth", withFaillock, 0o644, 0, 0).
		AddFile("/etc/security/faillock.conf", "# deny = 3\ndeny = 5\neven_deny_root\n", 0o644, 0, 0)
	l := pamFacts(t, m).Lockout["login"]
	want := map[string]facts.Setting{
		"deny":           {Value: "5", Explicit: true, Source: "/etc/security/faillock.conf:2"},
		"even_deny_root": {Value: "1", Explicit: true, Source: "/etc/security/faillock.conf:3"},
		"unlock_time":    {Value: "600", Source: "default (faillock.conf(5))"},
	}
	if l.Module != "pam_faillock.so" {
		t.Fatalf("login lockout = %+v", l)
	}
	for k, w := range want {
		if l.Settings[k] != w {
			t.Errorf("%s = %+v, want %+v", k, l.Settings[k], w)
		}
	}
}

func TestPAMTally2AndOther(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/pam.d/system-auth", "auth required pam_tally2.so deny=5 onerr=fail unlock_time=900\nauth sufficient pam_unix.so\n", 0o644, 0, 0).
		AddFile("/etc/pam.d/login", "auth include system-auth\n", 0o644, 0, 0).
		AddFile("/etc/pam.d/other", "auth required pam_deny.so\n", 0o644, 0, 0)
	p := pamFacts(t, m)
	if l := p.Lockout["login"]; l.Module != "pam_tally2.so" || l.Settings["deny"].Value != "5" {
		t.Errorf("tally2 lockout = %+v", l)
	}
	// No /etc/pam.d/sshd: PAM uses "other".
	if got := modules(p.Stacks["sshd"], "auth"); got != "pam_deny.so" {
		t.Errorf("sshd falls back to other: %q", got)
	}
}

func TestPAMUnreadableInclude(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/pam.d/login", "@include common-auth\n", 0o644, 0, 0).
		AddFile("/etc/pam.d/common-auth", "auth required pam_faillock.so\n", 0o600, 0, 0).
		SetError("/etc/pam.d/common-auth", fsErrPermission)
	f, err := collect(t, pamCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	if f.Complete {
		t.Error("an unreadable include must make the PAM facts incomplete")
	}
}
