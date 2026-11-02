package collect

import (
	"io/fs"
	"testing"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

func TestLoginDefs(t *testing.T) {
	const debian = "# comment\nMAIL_DIR        /var/mail\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_MAX_DAYS 30\nENCRYPT_METHOD SHA512\n"
	f, err := collect(t, loginDefsCollector{}, hostfs.NewMemFS().AddFile("/etc/login.defs", debian, 0o644, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	ld := f.Value.(*LoginDefs)
	want := map[string]facts.Setting{
		// The last occurrence wins, like shadow-utils.
		"PASS_MAX_DAYS":  {Value: "30", Explicit: true, Source: "/etc/login.defs:5"},
		"PASS_MIN_DAYS":  {Value: "0", Explicit: true, Source: "/etc/login.defs:4"},
		"ENCRYPT_METHOD": {Value: "SHA512", Explicit: true, Source: "/etc/login.defs:6"},
		"MAIL_DIR":       {Value: "/var/mail", Explicit: true, Source: "/etc/login.defs:2"},
		// Absent keys with a documented default.
		"PASS_WARN_AGE": {Value: "-1", Source: "default (login.defs(5))"},
		"UMASK":         {Value: "022", Source: "default (login.defs(5))"},
	}
	if !ld.Present || len(ld.Settings) != len(want) {
		t.Fatalf("present %v, settings %v", ld.Present, ld.Settings)
	}
	for k, w := range want {
		if ld.Settings[k] != w {
			t.Errorf("%s = %+v, want %+v", k, ld.Settings[k], w)
		}
	}
}

func TestLoginDefsMissingAndUnreadable(t *testing.T) {
	f, err := collect(t, loginDefsCollector{}, hostfs.NewMemFS())
	if err != nil {
		t.Fatal(err)
	}
	ld := f.Value.(*LoginDefs)
	// Without the file the defaults apply: "no limit" is a FAIL for a max-age check, never a PASS.
	if ld.Present || ld.Settings["PASS_MAX_DAYS"].Value != "-1" || ld.Settings["PASS_MAX_DAYS"].Explicit {
		t.Errorf("missing login.defs: %+v", ld)
	}
	if _, ok := ld.Settings["ENCRYPT_METHOD"]; ok {
		t.Error("ENCRYPT_METHOD has no documented default and must stay unknown")
	}
	_, err = collect(t, loginDefsCollector{}, hostfs.NewMemFS().AddFile("/etc/login.defs", "", 0o600, 0, 0).SetError("/etc/login.defs", fs.ErrPermission))
	if err == nil {
		t.Error("an unreadable login.defs must be an error")
	}
}
