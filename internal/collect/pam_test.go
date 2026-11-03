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
	if s := q.Settings["enforcing"]; s.Value != "1" || s.Explicit {
		t.Errorf("enforcing = %+v, want the default 1", s)
	}
	if p.SuWheel != (facts.Setting{}) {
		t.Errorf("stock Debian su has no pam_wheel line, got %+v", p.SuWheel)
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
	if l.Module != "pam_faillock.so" || !l.Enforced || strings.Join(l.Actions, ",") != "preauth,authfail" {
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
	if l := p.Lockout["login"]; l.Module != "pam_tally2.so" || !l.Enforced || l.Settings["deny"].Value != "5" {
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

func TestPAMSuWheel(t *testing.T) {
	tests := []struct {
		name, su string
		want     string // "" when unset
	}{
		{"none", "auth sufficient pam_rootok.so\nauth required pam_unix.so\n", ""},
		{"required", "auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid\n", "restricted"},
		{"requisite with group", "auth requisite pam_wheel.so group=admins\n", "restricted"},
		{"bracketed die", "auth [default=die] pam_wheel.so\n", "restricted"},
		{"trust only", "auth sufficient pam_wheel.so trust use_uid\n", "not restricted: trust (users outside the group are not denied)"},
		{"trust then required", "auth sufficient pam_wheel.so trust use_uid\nauth required pam_wheel.so use_uid\n", "restricted"},
		{"deny", "auth required pam_wheel.so deny group=nosu\n", "not restricted: deny (the check is reversed)"},
		{"optional", "auth optional pam_wheel.so\n", "not restricted: control optional does not deny"},
		{"bracketed ignore", "auth [success=ok default=ignore] pam_wheel.so\n", "not restricted: control [success=ok default=ignore] does not deny"},
		{"after sufficient", "auth sufficient pam_unix.so\nauth required pam_wheel.so\n", "not restricted: sufficient pam_unix.so comes first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pamFacts(t, hostfs.NewMemFS().AddFile("/etc/pam.d/su", tt.su, 0o644, 0, 0))
			if p.SuWheel.Value != tt.want || (tt.want != "") != p.SuWheel.Explicit {
				t.Errorf("su_wheel = %+v, want %q", p.SuWheel, tt.want)
			}
			if tt.want != "" && !strings.HasPrefix(p.SuWheel.Source, "/etc/pam.d/su:") {
				t.Errorf("source = %q", p.SuWheel.Source)
			}
		})
	}
	// Both distributions ship the pam_wheel lines commented out.
	for _, distro := range []string{"debian-12", "rocky-9"} {
		if w := pamFacts(t, fixtureFS(t, distro)).SuWheel; w != (facts.Setting{}) {
			t.Errorf("%s: su_wheel = %+v", distro, w)
		}
	}
}

// libpwquality reads pwquality.conf.d first and pwquality.conf last; option
// names are case-insensitive and "#" starts a comment anywhere.
func TestPAMPwqualityConfig(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/pam.d/passwd", "password requisite pam_pwquality.so retry=3 DCREDIT=-1\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf.d/10-site.conf", "minlen = 10\nMinClass = 3\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf", "minlen = 14 # site policy\nenforcing = 0\n", 0o644, 0, 0)
	q := pamFacts(t, m).PasswordQuality
	want := map[string]facts.Setting{
		"minlen":    {Value: "14", Explicit: true, Source: "/etc/security/pwquality.conf:1"},
		"minclass":  {Value: "3", Explicit: true, Source: "/etc/security/pwquality.conf.d/10-site.conf:2"},
		"enforcing": {Value: "0", Explicit: true, Source: "/etc/security/pwquality.conf:2"},
		"dcredit":   {Value: "-1", Explicit: true, Source: "/etc/pam.d/passwd:1"},
	}
	for k, w := range want {
		if q.Settings[k] != w {
			t.Errorf("%s = %+v, want %+v", k, q.Settings[k], w)
		}
	}
}

func TestPAMLockoutEnforcement(t *testing.T) {
	module := "/usr/lib64/security/pam_faillock.so"
	tests := []struct {
		name, login string
		actions     string
		enforced    bool
	}{
		{"preauth only never counts", "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so\n", "preauth", false},
		{"authfail without a check", "auth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\n", "authfail", false},
		{"preauth and authfail", "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\n", "preauth,authfail", true},
		{"authfail and account", "auth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\naccount required pam_faillock.so\n", "authfail,account", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hostfs.NewMemFS().
				AddFile("/etc/pam.d/login", tt.login, 0o644, 0, 0).
				AddFile(module, "/etc/security/faillock.conf\n/var/run/faillock\n", 0o755, 0, 0)
			l := pamFacts(t, m).Lockout["login"]
			if l.Module != "pam_faillock.so" || strings.Join(l.Actions, ",") != tt.actions || l.Enforced != tt.enforced {
				t.Errorf("lockout = %+v, want actions %s, enforced %v", l, tt.actions, tt.enforced)
			}
		})
	}
	t.Run("module not found", func(t *testing.T) {
		m := hostfs.NewMemFS().AddFile("/etc/pam.d/login", "auth required pam_faillock.so preauth\n", 0o644, 0, 0)
		f, err := collect(t, pamCollector{}, m)
		if err != nil || f.Complete || !strings.Contains(strings.Join(f.Skipped, ";"), "faillock.conf") {
			t.Errorf("complete %v, skipped %v, err %v", f.Complete, f.Skipped, err)
		}
	})
}

// pwhistory.conf only applies where pam_pwhistory reads it: Rocky 9's PAM
// does, Debian 12's (PAM 1.5.2) does not.
func TestPAMHistoryConfByVersion(t *testing.T) {
	tests := []struct {
		distro, remember string
		explicit         bool
	}{
		{"rocky-9", "5", true},
		{"debian-12", "10", false},
	}
	for _, tt := range tests {
		t.Run(tt.distro, func(t *testing.T) {
			m := fixtureFS(t, tt.distro).
				AddFile("/etc/pam.d/passwd", "password requisite pam_pwhistory.so use_authtok\npassword sufficient pam_unix.so sha512\n", 0o644, 0, 0).
				AddFile("/etc/security/pwhistory.conf", "remember = 5\nenforce_for_root\n", 0o644, 0, 0)
			h := pamFacts(t, m).PasswordHistory
			if s := h.Settings["remember"]; h.Module != "pam_pwhistory.so" || s.Value != tt.remember || s.Explicit != tt.explicit {
				t.Errorf("history = %+v", h)
			}
		})
	}
	legacy := hostfs.NewMemFS().AddFile("/etc/pam.d/passwd", "password sufficient pam_unix.so sha512 remember=4\n", 0o644, 0, 0)
	if h := pamFacts(t, legacy).PasswordHistory; h.Module != "pam_unix.so" || h.Settings["remember"].Value != "4" {
		t.Errorf("pam_unix remember = %+v", h)
	}
}

func TestPAMPasswordHash(t *testing.T) {
	deb := pamFacts(t, fixtureFS(t, "debian-12")).PasswordHash
	if deb.Value != "yescrypt" || !strings.HasPrefix(deb.Source, "/etc/pam.d/common-password:") {
		t.Errorf("debian 12 = %+v", deb)
	}
	if rocky := pamFacts(t, fixtureFS(t, "rocky-9")).PasswordHash; rocky.Value != "sha512" {
		t.Errorf("rocky 9 = %+v", rocky)
	}
	none := hostfs.NewMemFS().AddFile("/etc/pam.d/passwd", "password required pam_unix.so use_authtok\n", 0o644, 0, 0)
	if h := pamFacts(t, none).PasswordHash; h != (facts.Setting{}) {
		t.Errorf("no hash option = %+v", h)
	}
}
