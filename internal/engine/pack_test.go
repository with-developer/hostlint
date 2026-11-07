package engine_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/with-developer/hostlint/internal/collect"
	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

const packCheck = `id: x-acme.motd-present
version: 1
title: /etc/motd is owned by root
severity: low
description: Checks the owner of /etc/motd.
rationale: A banner anyone can edit is no banner.
remediation: chown root /etc/motd
file:
  paths: [/etc/motd]
  owner: [root]
  mode: "0644"
  missing: error
tests:
  - name: as required
    files:
      /etc/motd: {mode: "0644"}
    want: PASS
  - name: writable
    files:
      /etc/motd: {mode: "0666"}
    want: FAIL
  - name: missing
    input: absent
    want: ERROR
`

const packProfile = `id: x-acme-baseline
revision: 1
title: Acme baseline
controls:
  - id: A-01
    title: Root login is off and the banner is root's
    severity: low
    checks: [ssh.permit-root-login, x-acme.motd-present]
`

func builtin(t *testing.T) *engine.Content {
	t.Helper()
	c, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func source(checks map[string]string, profs map[string]string) engine.PackSource {
	r, p := fstest.MapFS{}, fstest.MapFS{}
	for name, body := range checks {
		r[name] = &fstest.MapFile{Data: []byte(body)}
	}
	for name, body := range profs {
		p[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return engine.PackSource{Name: "acme", Rules: r, Profiles: p}
}

func TestExtendAddsAPack(t *testing.T) {
	c := builtin(t)
	pc, err := c.Extend(source(map[string]string{"x-acme/motd-present.yaml": packCheck}, map[string]string{"x-acme-baseline.yaml": packProfile}))
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.Checks) != 1 || pc.Checks[0] != "x-acme.motd-present" || len(pc.Profiles) != 1 {
		t.Fatalf("%+v", pc)
	}
	// ssh.permit-root-login is high: a control of a pack's profile is at least as severe as what it maps.
	if got := c.Profiles["x-acme-baseline"].Controls[0].Severity; got != engine.SeverityHigh {
		t.Errorf("severity = %s", got)
	}
	if len(pc.Notes) != 1 || !strings.Contains(pc.Notes[0], "raised from low to high") {
		t.Errorf("notes = %v", pc.Notes)
	}
	// The built-in content is untouched.
	if c.Profiles["kisa-2026"] == nil || c.Checks["ssh.permit-root-login"] == nil {
		t.Error("the built-in content changed")
	}
}

func TestExtendRefuses(t *testing.T) {
	check := func(id string) string { return strings.Replace(packCheck, "x-acme.motd-present", id, 1) }
	for name, tc := range map[string]struct {
		checks, profs map[string]string
		want          string
	}{
		"a built-in area": {
			checks: map[string]string{"files/motd-present.yaml": check("files.motd-present")},
			want:   `starts with "x-"`,
		},
		"a profile without the prefix": {
			checks: map[string]string{"x-acme/motd-present.yaml": packCheck},
			profs:  map[string]string{"acme-baseline.yaml": strings.Replace(packProfile, "x-acme-baseline", "acme-baseline", 1)},
			want:   `starts with "x-"`,
		},
		"the title of KISA": {
			checks: map[string]string{"x-acme/motd-present.yaml": packCheck},
			profs:  map[string]string{"x-acme-baseline.yaml": strings.Replace(packProfile, "Acme baseline", "KISA CII technical vulnerability assessment guide, 2026 edition — Unix servers", 1)},
			want:   "title of another profile",
		},
		"an unknown check": {
			profs: map[string]string{"x-acme-baseline.yaml": strings.Replace(packProfile, "x-acme.motd-present", "x-acme.nothing", 1)},
			want:  "unknown check",
		},
		"a check without tests": {
			checks: map[string]string{"x-acme/motd-present.yaml": strings.SplitN(packCheck, "tests:", 2)[0]},
			want:   "tests need at least one PASS case",
		},
		"a weaker parameter": {
			profs: map[string]string{"x-acme-baseline.yaml": `id: x-acme-baseline
revision: 1
title: Acme baseline
controls:
  - id: A-01
    title: Passwords expire, in time
    severity: medium
    checks: [accounts.password-max-age]
    params:
      accounts.password-max-age: {max_days: 9999}
`},
			want: "weaker than the check's own 90",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := builtin(t)
			if _, err := c.Extend(source(tc.checks, tc.profs)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
			// A refused pack adds nothing.
			if len(c.Profiles) != 2 {
				t.Errorf("%d profiles", len(c.Profiles))
			}
		})
	}
}

func TestExtendAllowsAStricterParameter(t *testing.T) {
	prof := func(days string) string {
		return `id: x-acme-baseline
revision: 1
title: Acme baseline
controls:
  - id: A-01
    title: Passwords expire, in time
    severity: medium
    checks: [accounts.password-max-age]
    params:
      accounts.password-max-age: {max_days: ` + days + `}
`
	}
	for _, days := range []string{"30", "90"} {
		if _, err := builtin(t).Extend(source(nil, map[string]string{"x-acme-baseline.yaml": prof(days)})); err != nil {
			t.Errorf("max_days %s: %v", days, err)
		}
	}
}

func TestPacksCannotCollide(t *testing.T) {
	c := builtin(t)
	s := source(map[string]string{"x-acme/motd-present.yaml": packCheck}, map[string]string{"x-acme-baseline.yaml": packProfile})
	if _, err := c.Extend(s); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Extend(s); err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Errorf("a second pack with the same IDs: %v", err)
	}
}

func TestExtendLimitsAPacksFileChecks(t *testing.T) {
	withPaths := func(paths string) string {
		return strings.Replace(packCheck, "paths: [/etc/motd]", "paths: "+paths, 1)
	}
	for name, paths := range map[string]string{
		"under /proc":        "[/proc/sys/kernel/modprobe]",
		"under /sys":         "[/sys/kernel/x]",
		"under /dev":         "[/dev/shm/x]",
		"too many wildcards": "[/home/*/*/*]",
		"too many paths":     "[/a, /b, /c, /d, /e, /f, /g, /h, /i, /j, /k]",
	} {
		_, err := builtin(t).Extend(source(map[string]string{"x-acme/motd-present.yaml": withPaths(paths)}, nil))
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, paths := range []string{"[/etc/motd]", "[/home/*/.ssh]", "[/home/*/.config/*]"} {
		// no_match is required for a glob
		spec := withPaths(paths)
		if strings.Contains(paths, "*") {
			spec = strings.Replace(spec, "missing: error", "missing: error\n  no_match: pass", 1)
		}
		if _, err := builtin(t).Extend(source(map[string]string{"x-acme/motd-present.yaml": spec}, nil)); err != nil {
			t.Errorf("%s: %v", paths, err)
		}
	}
}

func TestTwoProfilesOfOnePackCannotShareATitle(t *testing.T) {
	other := strings.Replace(packProfile, "x-acme-baseline", "x-acme-other", 1)
	_, err := builtin(t).Extend(source(map[string]string{"x-acme/motd-present.yaml": packCheck}, map[string]string{"x-acme-baseline.yaml": packProfile, "x-acme-other.yaml": other}))
	if err == nil || !strings.Contains(err.Error(), "title of another profile") {
		t.Errorf("err = %v", err)
	}
}

func TestRunRuleTestsOfRunsOnlyTheNamedChecks(t *testing.T) {
	c := builtin(t)
	if _, err := c.Extend(source(map[string]string{"x-acme/motd-present.yaml": packCheck + "  - name: expects the wrong thing\n    files:\n      /etc/motd: {mode: \"0666\"}\n    want: PASS\n"}, nil)); err != nil {
		t.Fatal(err)
	}
	e, err := engine.New(c, collect.All()...)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.RunRuleTestsOf(t.Context(), nil); len(got) != 0 {
		t.Errorf("no IDs ran %d tests", len(got))
	}
	if got := e.RunRuleTestsOf(t.Context(), []string{"x-acme.motd-present"}); len(got) != 1 {
		t.Errorf("failures = %v", got)
	}
}

func TestExtendRefusesControlCharactersInTitles(t *testing.T) {
	check := strings.Replace(packCheck, "title: /etc/motd is owned by root", `title: "motd \e[2K\r is owned by root"`, 1)
	if _, err := builtin(t).Extend(source(map[string]string{"x-acme/motd-present.yaml": check}, nil)); err == nil || !strings.Contains(err.Error(), "title has a control character") {
		t.Errorf("a check title: %v", err)
	}
	prof := strings.Replace(packProfile, "title: Root login is off and the banner is root's", `title: "A \e[1A overwritten"`, 1)
	if _, err := builtin(t).Extend(source(map[string]string{"x-acme/motd-present.yaml": packCheck}, map[string]string{"x-acme-baseline.yaml": prof})); err == nil || !strings.Contains(err.Error(), "has a control character") {
		t.Errorf("a control title: %v", err)
	}
	prof = strings.Replace(packProfile, "id: A-01", `id: "A-\e[2K01"`, 1)
	if _, err := builtin(t).Extend(source(map[string]string{"x-acme/motd-present.yaml": packCheck}, map[string]string{"x-acme-baseline.yaml": prof})); err == nil || !strings.Contains(err.Error(), "control id has a control character") {
		t.Errorf("a control id: %v", err)
	}
}

// The digest of a pack's profile follows what the pack's mapped checks do; that of a built-in profile
// does not depend on the packs.
func TestProfileDigestCoversThePacksChecks(t *testing.T) {
	digestWith := func(check string) string {
		c := builtin(t)
		if _, err := c.Extend(source(map[string]string{"x-acme/motd-present.yaml": check}, map[string]string{"x-acme-baseline.yaml": packProfile})); err != nil {
			t.Fatal(err)
		}
		return c.ProfileDigest(c.Profiles["x-acme-baseline"])
	}
	a := digestWith(packCheck)
	if b := digestWith(packCheck); a != b {
		t.Error("the digest is not stable")
	}
	// A broader file check: the mapping is the same, what the check does is not.
	if b := digestWith(strings.Replace(packCheck, "mode: \"0644\"", "mode: \"0666\"", 1)); a == b {
		t.Error("the digest ignores what the pack's check does")
	}
	// Prose is not logic.
	if b := digestWith(strings.Replace(packCheck, "A banner anyone can edit is no banner.", "Another sentence.", 1)); a != b {
		t.Error("the digest follows the prose of a check")
	}
	before := builtin(t)
	d1 := before.ProfileDigest(before.Profiles["kisa-2026"])
	after := builtin(t)
	if _, err := after.Extend(source(map[string]string{"x-acme/motd-present.yaml": packCheck}, map[string]string{"x-acme-baseline.yaml": packProfile})); err != nil {
		t.Fatal(err)
	}
	if d2 := after.ProfileDigest(after.Profiles["kisa-2026"]); d1 != d2 {
		t.Error("a pack changed the digest of a built-in profile")
	}
}

func TestFactCatalog(t *testing.T) {
	e, err := engine.New(builtin(t), collect.All()...)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	for _, f := range e.FactCatalog() {
		have[f.Path] = f.Type
	}
	for path, typ := range map[string]string{
		"sshd":                           "object",
		"sshd.present":                   "bool",
		"sshd.config":                    "map of setting",
		"sshd.config{}.value":            "string",
		"sshd.match":                     "list of object",
		"sshd.match[].criteria":          "string",
		"sshd.match[].settings{}.value":  "string",
		"login_defs.settings{}.explicit": "bool",
	} {
		if have[path] != typ {
			t.Errorf("%s = %q, want %q", path, have[path], typ)
		}
	}
}
