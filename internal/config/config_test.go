package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall" //nolint:depguard // the test makes a FIFO
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/engine"
)

func content() *engine.Content {
	return &engine.Content{
		Checks: map[string]*engine.Check{
			"accounts.password-max-age": {ID: "accounts.password-max-age", Params: map[string]engine.ParamSpec{
				"max_days": {Type: "int", Default: 90, Stricter: "lower"}, "label": {Type: "string", Default: "x"},
			}},
			"files.shadow-perms": {ID: "files.shadow-perms"},
			"accounts.review":    {ID: "accounts.review", Manual: &engine.ManualSpec{Guidance: "g", Show: "accounts.users"}},
			"accounts.plain":     {ID: "accounts.plain", Manual: &engine.ManualSpec{Guidance: "g"}},
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
	p := write(t, t.TempDir(), "vmsctl.yaml", valid, 0o644)
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

const digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func attestation(extra string) string {
	return "attestations:\n  - check: accounts.review\n    status: PASS\n    digest: " + digest + "\n    evidence_digest: " + digest +
		"\n    by: alice\n    at: 2026-11-01\n    expires: 2027-01-31\n    reason: reviewed\n" + extra
}

func TestAttestations(t *testing.T) {
	p := write(t, t.TempDir(), "vmsctl.yaml", attestation("    hosts: [\"web-*\"]\n"), 0o644)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(content(), "kisa-2026"); err != nil {
		t.Fatal(err)
	}
	got := f.EngineAttestations()
	if len(got) != 1 || got[0].Check != "accounts.review" || got[0].Status != engine.StatusPass || got[0].By != "alice" ||
		got[0].Expires.Format("2006-01-02") != "2027-01-31" || got[0].At.Format("2006-01-02") != "2026-11-01" ||
		got[0].Note != "reviewed" || got[0].EvidenceDigest != digest || got[0].Digest != digest || got[0].Hosts[0] != "web-*" {
		t.Errorf("attestations %+v", got)
	}
}

func TestAttestationErrors(t *testing.T) {
	plain := "attestations:\n  - check: accounts.plain\n    status: FAIL\n    digest: " + digest + "\n    by: bob\n    at: 2026-11-01\n    expires: 2027-01-31\n    reason: r\n"
	tests := []struct{ name, text, want string }{
		{"unknown check", strings.Replace(attestation(""), "accounts.review", "x.y", 1), `unknown check "x.y"`},
		{"status", strings.Replace(attestation(""), "PASS", "WAIVED", 1), "status must be PASS or FAIL"},
		{"no digest", strings.Replace(attestation(""), "digest: "+digest+"\n    evidence_digest", "evidence_digest", 1), "digest is required"},
		{"malformed evidence digest", strings.Replace(attestation(""), "evidence_digest: "+digest, "evidence_digest: abc", 1), "evidence_digest must look like"},
		{"no author", strings.Replace(attestation(""), "by: alice", "by: \" \"", 1), "by is required"},
		{"no reason", strings.Replace(attestation(""), "reason: reviewed", "reason: \"\"", 1), "reason is required"},
		{"no expiry", strings.Replace(attestation(""), "expires: 2027-01-31", "expires: never", 1), "expires must be a date"},
		{"expires before at", strings.Replace(attestation(""), "expires: 2027-01-31", "expires: 2026-10-01", 1), "expires is before at"},
		{"bad host glob", attestation("    hosts: [\"[\"]\n"), "host pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := write(t, t.TempDir(), "vmsctl.yaml", tt.text, 0o644)
			f, err := Load(p)
			if err == nil {
				err = f.Validate(content(), "kisa-2026")
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want one mentioning %q", err, tt.want)
			}
		})
	}
	// A check that shows nothing is attested without an evidence digest.
	p := write(t, t.TempDir(), "vmsctl.yaml", plain, 0o644)
	f, err := Load(p)
	if err == nil {
		err = f.Validate(content(), "kisa-2026")
	}
	if err != nil {
		t.Errorf("an attestation of a check that shows nothing: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct{ name, text, want string }{
		{"unknown key", "profil: kisa-2026\n", "field profil not found"},
		{"unknown check", "params:\n  x.y: {a: 1}\n", `unknown check "x.y"`},
		{"unknown parameter", "params:\n  accounts.password-max-age: {days: 1}\n", `has no parameter "days"`},
		{"string parameter", "params:\n  accounts.password-max-age: {label: y}\n", "cannot be overridden"},
		{"not an integer", "params:\n  accounts.password-max-age: {max_days: soon}\n", "must be an integer"},
		{"no reason", "waivers:\n  - check: files.shadow-perms\n    expires: 2027-01-01\n", "reason is required"},
		{"no expiry", "waivers:\n  - check: files.shadow-perms\n    reason: r\n", "expires must be a date"},
		{"both targets", "waivers:\n  - check: files.shadow-perms\n    control: U-18\n    reason: r\n    expires: 2027-01-01\n", "exactly one of check and control"},
		{"unknown control", "waivers:\n  - control: U-99\n    revision: 1\n    reason: r\n    expires: 2027-01-01\n", `no control "U-99"`},
		{"control without revision", "waivers:\n  - control: U-18\n    reason: r\n    expires: 2027-01-01\n", "needs the profile revision"},
		{"zero parameter", "params:\n  accounts.password-max-age: {max_days: 0}\n", "must be 1 or more"},
		{"negative parameter", "params:\n  accounts.password-max-age: {max_days: -1}\n", "must be 1 or more"},
		{"errors on a control waiver", "waivers:\n  - control: U-18\n    revision: 1\n    reason: r\n    expires: 2027-01-01\n    errors: true\n", "errors applies to check waivers"},
		{"second document", "profile: kisa-2026\n---\nwaivers:\n  - check: files.shadow-perms\n    reason: r\n    expires: 2027-01-01\n", "only one YAML document"},
		{"bad host glob", "waivers:\n  - check: files.shadow-perms\n    reason: r\n    expires: 2027-01-01\n    hosts: [\"[\"]\n", "host pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := write(t, t.TempDir(), "vmsctl.yaml", tt.text, 0o644)
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

// A FIFO at the config path is refused instead of blocking until a writer opens it.
func TestLoadRefusesFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "vmsctl.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := Load(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load blocked on a FIFO")
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	defer func(l [][]string) { Locations = l }(Locations)
	Locations = [][]string{{"vmsctl.yaml", "hostlint.yaml"}, {filepath.Join(dir, "etc.yaml")}}
	if p, err := Find(""); err != nil || p != "" {
		t.Errorf("no file: %q, %v", p, err)
	}
	write(t, dir, "etc.yaml", valid, 0o644)
	if p, err := Find(""); err != nil || p != filepath.Join(dir, "etc.yaml") {
		t.Errorf("second location: %q, %v", p, err)
	}
	write(t, dir, "vmsctl.yaml", valid, 0o644)
	if p, err := Find(""); err != nil || p != "vmsctl.yaml" {
		t.Errorf("working directory first: %q, %v", p, err)
	}
	if _, err := Find(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing --config file was accepted")
	}
}

// The old name of the file is still found; when a place has both names, the new one is used and the old one is reported.
func TestFindOldName(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	defer func(l [][]string) { Locations = l }(Locations)
	Locations = [][]string{{"vmsctl.yaml", "hostlint.yaml"}, {filepath.Join(dir, "etc.yaml")}}
	write(t, dir, "hostlint.yaml", valid, 0o644)
	p, err := Find("")
	if err != nil || p != "hostlint.yaml" || !LegacyName(p) {
		t.Errorf("old name: %q, %v", p, err)
	}
	write(t, dir, "vmsctl.yaml", valid, 0o644)
	p, unused, err := FindNotes("")
	if err != nil || p != "vmsctl.yaml" || len(unused) != 1 || unused[0] != "hostlint.yaml" {
		t.Errorf("both names: %q, unused %v, %v", p, unused, err)
	}
	if LegacyName("/etc/vmsctl/vmsctl.yaml") {
		t.Error("the new name counts as the old one")
	}
}

// A file over the size limit is refused, not cut off.
func TestLoadTooLarge(t *testing.T) {
	text := "# " + strings.Repeat("x", maxFile) + "\nprofile: kisa-2026\n"
	if _, err := Load(write(t, t.TempDir(), "vmsctl.yaml", text, 0o644)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("err = %v", err)
	}
}

// The profile named in the file matters only when it is the one scanned:
// --profile overrides it.
func TestValidateProfileOverridden(t *testing.T) {
	f, err := Load(write(t, t.TempDir(), "vmsctl.yaml", "profile: kisa-2027\n", 0o644))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(content(), "kisa-2026"); err != nil {
		t.Errorf("a stale profile in the file stopped a scan that names another: %v", err)
	}
	if err := f.Validate(content(), "kisa-2027"); err == nil {
		t.Error("an unknown profile in use was accepted")
	}
}
