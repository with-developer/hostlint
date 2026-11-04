package collect

import (
	"encoding/json"
	"fmt"
	"os"
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
	if s := q.Settings["minlen"]; s != (facts.Setting{Value: "8", Source: "default (pwquality.conf(5), libpwquality 1.3 and later)"}) {
		t.Errorf("minlen = %+v", s)
	}
	if s := q.Settings["enforcing"]; s.Value != "1" || s.Explicit {
		t.Errorf("enforcing = %+v, want the default 1", s)
	}
	if s, ok := p.Effective["su_wheel"]; ok {
		t.Errorf("stock Debian su has no pam_wheel line, got %+v", s)
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
	withFaillock := strings.Replace(string(sysAuth), "auth        sufficient    pam_unix.so try_first_pass nullok",
		"auth        required      pam_faillock.so preauth silent\nauth        sufficient    pam_unix.so try_first_pass nullok\nauth        [default=die] pam_faillock.so authfail", 1)
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

// su is restricted when the su stack, evaluated as libpam does, denies a
// user outside the group who knows root's password.
func TestPAMSuWheel(t *testing.T) {
	const tail = "auth required pam_unix.so\n"
	tests := []struct {
		name, su string
		want     string // "" when unset
	}{
		{"none", "auth sufficient pam_rootok.so\n" + tail, ""},
		{"required", "auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid\n" + tail, "restricted"},
		{"requisite with group", "auth requisite pam_wheel.so group=admins\n" + tail, "restricted"},
		{"bracketed die", "auth [default=die] pam_wheel.so\n" + tail, "restricted"},
		{"keywords ignore case", "auth Required pam_wheel.so use_uid\n" + tail, "restricted"},
		// trust only makes members succeed at once; others are still denied.
		{"required trust", "auth required pam_wheel.so trust use_uid\n" + tail, "restricted"},
		{"sufficient trust only", "auth sufficient pam_wheel.so trust use_uid\n" + tail, "not restricted: pam_wheel.so does not deny users outside the group"},
		{"trust then required", "auth sufficient pam_wheel.so trust use_uid\nauth required pam_wheel.so use_uid\n" + tail, "restricted"},
		{"deny", "auth required pam_wheel.so deny group=nosu\n" + tail, "not restricted: pam_wheel.so does not deny users outside the group"},
		{"optional", "auth optional pam_wheel.so\n" + tail, "not restricted: pam_wheel.so does not deny users outside the group"},
		{"bracketed ignore", "auth [success=ok default=ignore] pam_wheel.so\n" + tail, "not restricted: pam_wheel.so does not deny users outside the group"},
		{"after sufficient", "auth sufficient pam_unix.so\nauth required pam_wheel.so\n", "not restricted: pam_wheel.so is not reached: a rule before it ends the stack"},
		{"after Sufficient", "auth Sufficient pam_unix.so\nauth required pam_wheel.so\n", "not restricted: pam_wheel.so is not reached: a rule before it ends the stack"},
		{"after success=done", "auth [success=done new_authtok_reqd=done default=ignore] pam_unix.so\nauth required pam_wheel.so\n", "not restricted: pam_wheel.so is not reached: a rule before it ends the stack"},
		{"after Include", "auth sufficient pam_rootok.so\nauth Include system-auth\nauth required pam_wheel.so use_uid\n", "not restricted: pam_wheel.so is not reached: a rule before it ends the stack"},
		// A substack's sufficient only ends the substack.
		{"after substack", "auth sufficient pam_rootok.so\nauth substack system-auth\nauth required pam_wheel.so use_uid\n", "restricted"},
		// A comment ending in a backslash does not swallow the next rule.
		{"comment with backslash", "auth sufficient pam_rootok.so\n# old rule \\\nauth sufficient pam_unix.so\nauth required pam_wheel.so\n", "not restricted: pam_wheel.so is not reached: a rule before it ends the stack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hostfs.NewMemFS().AddFile("/etc/pam.d/su", tt.su, 0o644, 0, 0).
				AddFile("/etc/pam.d/system-auth", "auth required pam_env.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n", 0o644, 0, 0)
			p := pamFacts(t, m)
			s, ok := p.Effective["su_wheel"]
			if s.Value != tt.want || ok != (tt.want != "") || ok != s.Explicit {
				t.Errorf("su_wheel = %+v (present %v), want %q", s, ok, tt.want)
			}
			if ok && !strings.HasPrefix(s.Source, "/etc/pam.d/su:") {
				t.Errorf("source = %q", s.Source)
			}
		})
	}
	// Both distributions ship the pam_wheel lines commented out.
	for _, distro := range []string{"debian-12", "rocky-9"} {
		if w, ok := pamFacts(t, fixtureFS(t, distro)).Effective["su_wheel"]; ok {
			t.Errorf("%s: su_wheel = %+v", distro, w)
		}
	}
}

// pwqualityHost is a host with a libpwquality captured from a distribution.
func pwqualityHost(t *testing.T, lib string) *hostfs.MemFS {
	t.Helper()
	data, err := os.ReadFile("testdata/" + lib)
	if err != nil {
		t.Fatal(err)
	}
	return hostfs.NewMemFS().AddFile("/usr/lib64/libpwquality.so.1", string(data), 0o755, 0, 0)
}

const (
	modernPwquality = "rocky-9/usr/lib64/libpwquality.so.1"
	legacyPwquality = "centos-7/usr/lib64/libpwquality.so.1"
)

// libpwquality reads pwquality.conf.d first and pwquality.conf last; names
// are case-insensitive, "#" starts a comment anywhere, and "=" is optional.
func TestPAMPwqualityConfig(t *testing.T) {
	m := pwqualityHost(t, modernPwquality).
		AddFile("/etc/pam.d/passwd", "password requisite pam_pwquality.so retry=3 DCREDIT=-1\npassword sufficient pam_unix.so\npassword required pam_deny.so\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf.d/10-site.conf", "minlen = 10\nMinClass 3\n", 0o644, 0, 0).
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

// libpwquality 1.4.5 (settings.c): a flag is set whatever its value, a
// number is read by strtol, every name whose first ".conf" ends it is a
// drop-in (hidden files too), and a module argument it rejects is ignored.
func TestPAMPwqualityAsLibpwquality(t *testing.T) {
	const passwd = "password requisite pam_pwquality.so\npassword sufficient pam_unix.so use_authtok\npassword required pam_deny.so\n"
	m := pwqualityHost(t, modernPwquality).
		AddFile("/etc/pam.d/passwd", passwd, 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf.d/.site.conf", "dcredit = -1\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf.d/a.conf.conf", "ucredit = -9\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf.d/b.confx", "lcredit = -9\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf", "enforce_for_root = 0\nminlen = 6\nenforcing = 00\nocredit = +2\n", 0o644, 0, 0)
	q := pamFacts(t, m).PasswordQuality
	want := map[string]string{"enforce_for_root": "1", "minlen": "6", "enforcing": "0", "ocredit": "2", "dcredit": "-1"}
	for k, w := range want {
		if q.Settings[k].Value != w {
			t.Errorf("%s = %+v, want %q", k, q.Settings[k], w)
		}
	}
	for _, k := range []string{"ucredit", "lcredit"} {
		if q.Settings[k].Explicit {
			t.Errorf("%s = %+v, from a file libpwquality does not read", k, q.Settings[k])
		}
	}

	// Arguments: a bare number setting is rejected and ignored, so the
	// configuration's enforcing = 0 stands; the module's own options are not
	// settings.
	m = pwqualityHost(t, modernPwquality).
		AddFile("/etc/pam.d/passwd", "password requisite pam_pwquality.so enforcing try_first_pass minlen=x retry=3\npassword sufficient pam_unix.so use_authtok\npassword required pam_deny.so\n", 0o644, 0, 0).
		AddFile("/etc/security/pwquality.conf", "enforcing = 0\nminlen = 12\n", 0o644, 0, 0)
	q = pamFacts(t, m).PasswordQuality
	if q.Settings["enforcing"].Value != "0" || q.Settings["minlen"].Value != "12" || q.Settings["retry"].Value != "3" {
		t.Errorf("arguments: %+v", q.Settings)
	}
	if _, ok := q.Settings["try_first_pass"]; ok {
		t.Errorf("try_first_pass reported as a setting: %+v", q.Settings)
	}
}

// enforce_for_root and local_users_only on the module line: up to 1.4.0
// pam_pwquality compares the argument with strncmp (case-sensitive, any
// suffix); later versions read them as case-insensitive settings.
func TestPAMPwqualityModuleFlags(t *testing.T) {
	const tail = "\npassword sufficient pam_unix.so use_authtok\npassword required pam_deny.so\n"
	tests := []struct {
		name, lib, args string
		want            map[string]bool
	}{
		{"legacy bare flags", legacyPwquality, "try_first_pass local_users_only retry=3 authtok_type= enforce_for_root", map[string]bool{"enforce_for_root": true, "local_users_only": true}},
		{"modern bare flags", modernPwquality, "try_first_pass local_users_only retry=3 authtok_type= enforce_for_root", map[string]bool{"enforce_for_root": true, "local_users_only": true}},
		{"legacy suffix is ignored", legacyPwquality, "enforce_for_root=0", map[string]bool{"enforce_for_root": true}},
		{"modern value is ignored", modernPwquality, "enforce_for_root=0", map[string]bool{"enforce_for_root": true}},
		{"legacy case matters", legacyPwquality, "ENFORCE_FOR_ROOT Local_Users_Only", nil},
		{"modern case does not", modernPwquality, "ENFORCE_FOR_ROOT", map[string]bool{"enforce_for_root": true}},
		{"absent", legacyPwquality, "retry=3", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := pwqualityHost(t, tt.lib).AddFile("/etc/pam.d/passwd", "password requisite pam_pwquality.so "+tt.args+tail, 0o644, 0, 0)
			q := pamFacts(t, m).PasswordQuality
			for _, k := range []string{"enforce_for_root", "local_users_only"} {
				s := q.Settings[k]
				if got := s.Explicit && s.Value == "1"; got != tt.want[k] {
					t.Errorf("%s = %+v, want set %v", k, s, tt.want[k])
				}
				if tt.want[k] && s.Source != "/etc/pam.d/passwd:1" {
					t.Errorf("%s source = %q", k, s.Source)
				}
			}
		})
	}
}

// What libpwquality does not apply is not reported as set.
func TestPAMPwqualityReading(t *testing.T) {
	const passwd = "password requisite pam_pwquality.so\npassword sufficient pam_unix.so\npassword required pam_deny.so\n"
	tests := []struct {
		name, lib, dropIn, main string
		minlen, source          string
	}{
		// An unknown setting stops the reading, so pwquality.conf is unread.
		{"unknown setting", modernPwquality, "difignore = 23\n", "minlen = 14\n", "8", "default"},
		// A non-breaking space makes the value invalid to libpwquality.
		{"non-breaking space", modernPwquality, "", "minlen = 14\u00a0\n", "8", "default"},
		// 1.2 (EL7) reads no drop-ins, does not know enforce_for_root and
		// has other defaults.
		{"legacy drop-in", legacyPwquality, "minlen = 14\n", "", "9", "default (libpwquality 1.2)"},
		{"legacy unknown setting", legacyPwquality, "", "enforce_for_root\nminlen = 14\n", "9", "default (libpwquality 1.2)"},
		{"legacy", legacyPwquality, "", "minlen = 12\n", "12", "/etc/security/pwquality.conf:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := pwqualityHost(t, tt.lib).AddFile("/etc/pam.d/passwd", passwd, 0o644, 0, 0)
			if tt.dropIn != "" {
				m.AddFile("/etc/security/pwquality.conf.d/50-site.conf", tt.dropIn, 0o644, 0, 0)
			}
			if tt.main != "" {
				m.AddFile("/etc/security/pwquality.conf", tt.main, 0o644, 0, 0)
			}
			s := pamFacts(t, m).PasswordQuality.Settings["minlen"]
			if s.Value != tt.minlen || !strings.HasPrefix(s.Source, tt.source) {
				t.Errorf("minlen = %+v, want %s from %s", s, tt.minlen, tt.source)
			}
		})
	}
	m := pwqualityHost(t, legacyPwquality).AddFile("/etc/pam.d/passwd", passwd, 0o644, 0, 0)
	if c := pamFacts(t, m).PasswordQuality.Settings["dcredit"]; c.Value != "1" {
		t.Errorf("legacy dcredit = %+v, want the 1.2 default 1", c)
	}
	// Without the library, its version and defaults are unknown.
	f, err := collect(t, pamCollector{}, hostfs.NewMemFS().AddFile("/etc/pam.d/passwd", passwd, 0o644, 0, 0))
	if err != nil || strings.Join(f.Unknown, ",") != "password_quality" {
		t.Errorf("unknown %v, err %v", f.Unknown, err)
	}
}

// A policy module that a rule before it skips, or whose failure is ignored,
// enforces nothing.
func TestPAMPolicyReach(t *testing.T) {
	tests := []struct {
		name, passwd, quality, history string
	}{
		{"stock order", "password requisite pam_pwquality.so\npassword requisite pam_pwhistory.so remember=5\npassword sufficient pam_unix.so use_authtok\npassword required pam_deny.so\n", "pam_pwquality.so", "pam_pwhistory.so"},
		{"history after sufficient pam_unix", "password requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so sha512 shadow use_authtok\npassword required pam_pwhistory.so remember=5 use_authtok\n", "pam_pwquality.so", ""},
		{"history skipped by a jump", "password [success=1 default=ignore] pam_unix.so\npassword required pam_pwhistory.so remember=5\npassword required pam_permit.so\n", "", ""},
		{"optional quality", "password optional pam_pwquality.so\npassword sufficient pam_unix.so\npassword required pam_deny.so\n", "", ""},
		{"pam_unix remember", "password requisite pam_pwquality.so\npassword sufficient pam_unix.so remember=4\npassword required pam_deny.so\n", "pam_pwquality.so", "pam_unix.so"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := pwqualityHost(t, modernPwquality).AddFile("/etc/pam.d/passwd", tt.passwd, 0o644, 0, 0).
				AddFile("/usr/lib64/security/pam_pwhistory.so", "/etc/security/pwhistory.conf\n", 0o755, 0, 0)
			p := pamFacts(t, m)
			if p.PasswordQuality.Module != tt.quality || p.PasswordHistory.Module != tt.history {
				t.Errorf("quality %q (ignored %v), history %q (ignored %v); want %q, %q",
					p.PasswordQuality.Module, p.PasswordQuality.Ignored, p.PasswordHistory.Module, p.PasswordHistory.Ignored, tt.quality, tt.history)
			}
		})
	}
}

// pwhistory.conf is read as pam_modutil_search_key does: the first value of
// a key counts, whatever its case.
func TestPAMPwhistoryConf(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/pam.d/passwd", "password requisite pam_pwhistory.so\npassword sufficient pam_unix.so\npassword required pam_deny.so\n", 0o644, 0, 0).
		AddFile("/usr/lib64/security/pam_pwhistory.so", "/etc/security/pwhistory.conf\n", 0o755, 0, 0).
		AddFile("/etc/security/pwhistory.conf", "REMEMBER = 2\nremember = 24\n", 0o644, 0, 0)
	if s := pamFacts(t, m).PasswordHistory.Settings["remember"]; s.Value != "2" {
		t.Errorf("remember = %+v, want the first value", s)
	}
}

// A lockout is enforced when a wrong password is counted and a locked
// account is denied even with the right password (pam_faillock(8)).
func TestPAMLockoutEnforcement(t *testing.T) {
	module := "/usr/lib64/security/pam_faillock.so"
	tests := []struct {
		name, login string
		actions     string
		enforced    bool
	}{
		{"preauth only never counts", "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so\nauth required pam_deny.so\n", "preauth", false},
		{"authfail without a check", "auth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth required pam_deny.so\n", "authfail", false},
		{"preauth and authfail", "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth required pam_deny.so\n", "preauth,authfail", true},
		// The account phase only audits and resets: it never denies.
		{"authfail and account", "auth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth required pam_deny.so\naccount required pam_faillock.so\n", "authfail,account", false},
		// pam_faillock(8)'s first example: authsucc instead of preauth.
		{"authfail and authsucc", "auth [success=1 default=bad] pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc\nauth required pam_deny.so\n", "authfail,authsucc", true},
		{"preauth after sufficient pam_unix", "auth sufficient pam_unix.so\nauth required pam_faillock.so preauth\nauth [default=die] pam_faillock.so authfail\nauth required pam_deny.so\n", "preauth,authfail", false},
		{"authfail after requisite pam_unix", "auth required pam_faillock.so preauth\nauth requisite pam_unix.so\nauth [default=die] pam_faillock.so authfail\n", "preauth,authfail", false},
		// A non-breaking space hides the mode, so pam_faillock runs it as preauth.
		{"non-breaking space", "auth required pam_faillock.so preauth\nauth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail\u00a0\nauth required pam_deny.so\n", "preauth", false},
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
	t.Run("tally2 after sufficient pam_unix", func(t *testing.T) {
		m := hostfs.NewMemFS().AddFile("/etc/pam.d/login", "auth sufficient pam_unix.so\nauth required pam_tally2.so deny=5\n", 0o644, 0, 0)
		if l := pamFacts(t, m).Lockout["login"]; l.Enforced {
			t.Errorf("lockout = %+v", l)
		}
	})
	t.Run("module not found", func(t *testing.T) {
		m := hostfs.NewMemFS().AddFile("/etc/pam.d/login", "auth required pam_faillock.so preauth\n", 0o644, 0, 0)
		f, err := collect(t, pamCollector{}, m)
		if err != nil || strings.Join(f.Unknown, ",") != "lockout" || !strings.Contains(strings.Join(f.Skipped, ";"), "faillock.conf") {
			t.Errorf("unknown %v, skipped %v, err %v", f.Unknown, f.Skipped, err)
		}
	})
}

// faillock.conf is read as pam_faillock does: the key ends at whitespace
// or "="; conf= names another file; the checking line's arguments count.
func TestPAMFaillockConf(t *testing.T) {
	const stack = "auth required pam_faillock.so preauth%s\nauth sufficient pam_unix.so\nauth [default=die] pam_faillock.so authfail deny=5\nauth required pam_deny.so\n"
	tests := []struct {
		name, args, conf, deny string
	}{
		{"space separated", "", "deny 0\n", "0"},
		{"conf argument", " conf=/etc/security/faillock-off.conf", "deny = 4\n", "0"},
		{"preauth argument", " deny=100", "deny = 4\n", "100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hostfs.NewMemFS().
				AddFile("/etc/pam.d/login", fmt.Sprintf(stack, tt.args), 0o644, 0, 0).
				AddFile("/usr/lib64/security/pam_faillock.so", "/etc/security/faillock.conf\n", 0o755, 0, 0).
				AddFile("/etc/security/faillock.conf", tt.conf, 0o644, 0, 0).
				AddFile("/etc/security/faillock-off.conf", "deny = 0\n", 0o644, 0, 0)
			if s := pamFacts(t, m).Lockout["login"].Settings["deny"]; s.Value != tt.deny {
				t.Errorf("deny = %+v, want %s", s, tt.deny)
			}
		})
	}
}

// Credentials in module arguments never become facts.
func TestPAMRedactsSecrets(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/pam.d/sshd",
		"auth sufficient pam_tacplus.so server=10.0.0.5 secret=S3cretTacKey\nauth required pam_yubico.so id=16 key=abcdef\n"+
			"auth optional pam_exec.so expose_authtok /usr/local/bin/check --token xyz\nauth required pam_mysql.so user=pam passwd=hunter2\n", 0o644, 0, 0)
	data, err := json.Marshal(pamFacts(t, m).Stacks["sshd"])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"S3cretTacKey", "abcdef", "xyz", "/usr/local/bin/check", "hunter2"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("%q leaked into the facts: %s", secret, data)
		}
	}
	if !strings.Contains(string(data), "server=10.0.0.5") {
		t.Errorf("ordinary arguments were dropped: %s", data)
	}
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

// A rejection only counts when it keeps the password from being stored:
// pam_unix after it must take the password from the stack (use_authtok),
// and must not have run before it (verified in debian:12: chpasswd stores
// the reused password in both failing stacks below).
func TestPAMRejectionBeforeStore(t *testing.T) {
	tests := []struct {
		name, stack string
		enforced    bool
	}{
		{"history first, pam_unix use_authtok",
			"password required pam_pwhistory.so remember=4 use_authtok\npassword [success=1 default=ignore] pam_unix.so obscure use_authtok yescrypt\npassword requisite pam_deny.so\npassword required pam_permit.so\n", true},
		{"history after pam_unix",
			"password [success=1 default=ignore] pam_unix.so obscure yescrypt\npassword requisite pam_deny.so\npassword required pam_permit.so\npassword requisite pam_pwhistory.so remember=5 use_authtok enforce_for_root\n", false},
		{"required history, pam_unix asks again",
			"password required pam_pwhistory.so remember=4\npassword [success=1 default=ignore] pam_unix.so obscure yescrypt\npassword requisite pam_deny.so\npassword required pam_permit.so\n", false},
		{"requisite history stops the stack",
			"password requisite pam_pwhistory.so remember=4\npassword sufficient pam_unix.so sha512\npassword required pam_deny.so\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hostfs.NewMemFS().AddFile("/etc/pam.d/passwd", tt.stack, 0o644, 0, 0)
			h := pamFacts(t, m).PasswordHistory
			if got := h.Module == "pam_pwhistory.so"; got != tt.enforced {
				t.Errorf("enforced = %v (module %q, ignored %v), want %v", got, h.Module, h.Ignored, tt.enforced)
			}
		})
	}
	quality := hostfs.NewMemFS().AddFile("/etc/pam.d/passwd",
		"password required pam_pwquality.so retry=3\npassword sufficient pam_unix.so sha512 shadow\npassword required pam_deny.so\n", 0o644, 0, 0)
	if q := pamFacts(t, quality).PasswordQuality; q.Module != "" || len(q.Ignored) == 0 || !strings.Contains(q.Ignored[0], "from storing the password") {
		t.Errorf("required pwquality before a prompting pam_unix = %+v", q)
	}
}

func TestPAMPasswordHash(t *testing.T) {
	deb := pamFacts(t, fixtureFS(t, "debian-12")).Effective["password_hash"]
	if deb.Value != "yescrypt" || !strings.HasPrefix(deb.Source, "/etc/pam.d/common-password:") {
		t.Errorf("debian 12 = %+v", deb)
	}
	if rocky := pamFacts(t, fixtureFS(t, "rocky-9")).Effective["password_hash"]; rocky.Value != "sha512" {
		t.Errorf("rocky 9 = %+v", rocky)
	}
	none := hostfs.NewMemFS().AddFile("/etc/pam.d/passwd", "password required pam_unix.so use_authtok\n", 0o644, 0, 0)
	if h, ok := pamFacts(t, none).Effective["password_hash"]; ok {
		t.Errorf("no hash option = %+v", h)
	}
	tests := []struct{ name, line, defs, want string }{
		// pam_unix applies its options in order: the last hash wins.
		{"last option wins", "password sufficient pam_unix.so obscure sha512 md5 shadow use_authtok", "", "md5"},
		{"des", "password sufficient pam_unix.so des", "", "des"},
		// Without an option, pam_unix reads the first ENCRYPT_METHOD.
		{"first ENCRYPT_METHOD", "password sufficient pam_unix.so shadow", "ENCRYPT_METHOD MD5\nENCRYPT_METHOD SHA512\n", "md5"},
	}
	for _, tt := range tests {
		m := hostfs.NewMemFS().AddFile("/etc/pam.d/passwd", tt.line+"\npassword required pam_deny.so\n", 0o644, 0, 0)
		if tt.defs != "" {
			m.AddFile("/etc/login.defs", tt.defs, 0o644, 0, 0)
		}
		if h := pamFacts(t, m).Effective["password_hash"]; h.Value != tt.want {
			t.Errorf("%s: password_hash = %+v, want %s", tt.name, h, tt.want)
		}
	}
}

// su restricted by its permissions counts as restricted: only members of its
// group can run it.
func TestPAMSuPermissions(t *testing.T) {
	const su = "auth sufficient pam_rootok.so\nauth required pam_unix.so\n"
	tests := []struct {
		name string
		mode uint32
		uid  int64
		gid  int64
		want string
	}{
		{"setuid root:wheel 4750", 0o4750, 0, 10, "restricted"},
		{"stock root:root 4755", 0o4755, 0, 0, ""},
		{"others can still run it", 0o4751, 0, 10, ""},
		{"not setuid", 0o750, 0, 10, ""},
		{"group is root's", 0o4750, 0, 0, ""},
		{"owned by a user", 0o4750, 1000, 10, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hostfs.NewMemFS().AddFile("/etc/pam.d/su", su, 0o644, 0, 0).AddFile("/usr/bin/su", "", tt.mode, tt.uid, tt.gid)
			s := pamFacts(t, m).Effective["su_wheel"]
			if s.Value != tt.want {
				t.Errorf("su_wheel = %+v, want %q", s, tt.want)
			}
			if tt.want != "" && !strings.Contains(s.Source, "/usr/bin/su") {
				t.Errorf("source = %q", s.Source)
			}
		})
	}
}
