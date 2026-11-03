package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
)

func content() *engine.Content {
	return &engine.Content{
		Checks: map[string]*engine.Check{
			"accounts.password-max-age": {ID: "accounts.password-max-age", Params: map[string]engine.ParamSpec{
				"max_days": {Type: "int", Default: 90, Stricter: "lower"}, "label": {Type: "string", Default: "x"},
			}},
			"files.shadow-perms": {ID: "files.shadow-perms"},
		},
		Profiles: map[string]*engine.Profile{"kisa-2026": {ID: "kisa-2026", Revision: 1, Controls: []engine.Control{{ID: "U-18"}}}},
	}
}

func write(t *testing.T, dir, name, text string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `profile: kisa-2026
params:
  accounts.password-max-age: {max_days: 60}
waivers:
  - check: files.shadow-perms
    reason: Debian's unix_chkpwd reads it through group shadow
    expires: 2027-06-30
    hosts: ["web-*"]
  - control: U-18
    revision: 1
    reason: accepted by the security team
    expires: 2027-01-31
`

func TestLoadAndValidate(t *testing.T) {
	p := write(t, t.TempDir(), "hostlint.yaml", valid, 0o644)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(content(), "kisa-2026"); err != nil {
		t.Fatal(err)
	}
	params, waivers := f.Engine()
	if params["accounts.password-max-age"]["max_days"] != 60 || len(waivers) != 2 || waivers[0].Expires.Format("2006-01-02") != "2027-06-30" || waivers[1].Revision != 1 {
		t.Errorf("params %v, waivers %+v", params, waivers)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct{ name, text, want string }{
		{"unknown key", "profil: kisa-2026\n", "field profil not found"},
		{"unknown profile", "profile: cis\n", `profile "cis" does not exist`},
		{"unknown check", "params:\n  x.y: {a: 1}\n", `unknown check "x.y"`},
		{"unknown parameter", "params:\n  accounts.password-max-age: {days: 1}\n", `has no parameter "days"`},
		{"string parameter", "params:\n  accounts.password-max-age: {label: y}\n", "cannot be overridden"},
		{"not an integer", "params:\n  accounts.password-max-age: {max_days: soon}\n", "must be an integer"},
		{"no reason", "waivers:\n  - check: files.shadow-perms\n    expires: 2027-01-01\n", "reason is required"},
		{"no expiry", "waivers:\n  - check: files.shadow-perms\n    reason: r\n", "expires must be a date"},
		{"both targets", "waivers:\n  - check: files.shadow-perms\n    control: U-18\n    reason: r\n    expires: 2027-01-01\n", "exactly one of check and control"},
		{"unknown control", "waivers:\n  - control: U-99\n    revision: 1\n    reason: r\n    expires: 2027-01-01\n", `no control "U-99"`},
		{"control without revision", "waivers:\n  - control: U-18\n    reason: r\n    expires: 2027-01-01\n", "needs the profile revision"},
		{"bad host glob", "waivers:\n  - check: files.shadow-perms\n    reason: r\n    expires: 2027-01-01\n    hosts: [\"[\"]\n", "host pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := write(t, t.TempDir(), "hostlint.yaml", tt.text, 0o644)
			f, err := Load(p)
			if err == nil {
				err = f.Validate(content(), "kisa-2026")
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
}

// A configuration others could have written is refused: waivers hide
// findings.
func TestUntrustedFile(t *testing.T) {
	dir := t.TempDir()
	notRegular := filepath.Join(dir, "dir.yaml")
	if err := os.Mkdir(notRegular, 0o755); err != nil {
		t.Fatal(err)
	}
	type test struct{ name, path, want string }
	tests := []test{
		{"writable by others", write(t, dir, "writable.yaml", valid, 0o666), "writable by group or others"},
		{"not a regular file", notRegular, "not a regular file"},
	}
	if os.Getuid() == 0 {
		// Only root can give a file away (Docker runs cover this case).
		other := write(t, dir, "other.yaml", valid, 0o644)
		if err := os.Chown(other, 12345, 12345); err != nil {
			t.Fatal(err)
		}
		tests = append(tests, test{"owned by another user", other, "neither root nor you"})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(tt.path); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v; want %q", err, tt.want)
			}
		})
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	defer func(l []string) { Locations = l }(Locations)
	Locations = []string{"hostlint.yaml", filepath.Join(dir, "etc.yaml")}
	if p, err := Find(""); err != nil || p != "" {
		t.Errorf("no file: %q, %v", p, err)
	}
	write(t, dir, "etc.yaml", valid, 0o644)
	if p, err := Find(""); err != nil || p != filepath.Join(dir, "etc.yaml") {
		t.Errorf("second location: %q, %v", p, err)
	}
	write(t, dir, "hostlint.yaml", valid, 0o644)
	if p, err := Find(""); err != nil || p != "hostlint.yaml" {
		t.Errorf("working directory first: %q, %v", p, err)
	}
	if _, err := Find(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing --config file was accepted")
	}
}
