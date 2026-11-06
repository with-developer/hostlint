package engine

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
)

// ruleFailures loads one rule file and runs its tests; a load error is
// returned as the only failure.
func ruleFailures(t *testing.T, rule string) []string {
	t.Helper()
	c, err := Load(fstest.MapFS{"x/y.yaml": {Data: []byte(rule)}}, fstest.MapFS{})
	if err != nil {
		return []string{"load: " + err.Error()}
	}
	e, err := New(c, demoSvc())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range e.RunRuleTests(context.Background()) {
		out = append(out, f.Error())
	}
	return out
}

const fileRule = `id: x.y
version: 1
title: T
severity: low
file:
  paths: [/etc/app.conf]
  owner: [root]
  group: [root, sys]
  mode: "0644"
  missing: error
tests:
  - name: p
    files:
      /etc/app.conf: {mode: "0644"}
    want: PASS
  - name: f
    files:
      /etc/app.conf: {mode: "0666"}
    want: FAIL
  - name: g
    input: absent
    want: ERROR
`

const svcRule = `id: x.y
version: 1
title: T
severity: low
platforms: [rhel]
expect: svc.present
tests:
  - name: p
    os: rhel
    facts:
      svc: {present: true}
    want: PASS
  - name: f
    os: rhel
    facts:
      svc: {present: false}
    want: FAIL
  - name: g
    input: unavailable
    os: rhel
    unavailable: [svc]
    want: ERROR
`

// Mistakes in a rule's test fixtures are errors, not silent defaults.
func TestRuleTestFixturesAreValidated(t *testing.T) {
	tests := []struct {
		name, rule, old, new, want string
	}{
		{"owner typo", fileRule, `{mode: "0644"}`, `{mode: "0644", owner: usr}`, `owner "usr" is not a number or a test account`},
		{"unknown error kind", fileRule, `{mode: "0644"}`, `{mode: "0644", error: denied}`, `error must be permission, not "denied"`},
		{"relative path", fileRule, `/etc/app.conf: {mode: "0644"}`, `etc/app.conf: {mode: "0644"}`, "the path must be absolute and clean"},
		{"symlink without target", fileRule, `{mode: "0644"}`, `{type: symlink}`, "a symlink needs a target"},
		{"mis-cased fact key", svcRule, `svc: {present: true}`, `svc: {Present: true}`, `unknown field "Present"`},
		{"unknown nested key", svcRule, `svc: {present: true}`, `svc: {present: true, users: [{name: a, UID: 0}]}`, `users[0]: unknown field "UID"`},
		{"unavailable typo", svcRule, `unavailable: [svc]`, `unavailable: [svcc]`, "the check does not read svcc"},
		{"facts for an unread collector", svcRule, `facts:
      svc: {present: true}`, `facts:
      svc: {present: true}
      shadow: {}`, "facts for shadow, which the check does not read"},
		{"os twice", svcRule, `    os: rhel
    facts:
      svc: {present: true}`, `    os: rhel
    facts:
      os: {id: rocky, family: rhel}
      svc: {present: true}`, "give os or facts.os, not both"},
		{"input label without input", svcRule, `    unavailable: [svc]
`, ``, "input unavailable needs an unavailable collector"},
		{"unlabeled unavailable case", svcRule, `    input: unavailable
`, ``, "needs input unavailable or incomplete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.rule, tt.old) {
				t.Fatalf("rule does not contain %q", tt.old)
			}
			got := strings.Join(ruleFailures(t, strings.Replace(tt.rule, tt.old, tt.new, 1)), "\n")
			if !strings.Contains(got, tt.want) {
				t.Errorf("failures %q, want one mentioning %q", got, tt.want)
			}
		})
	}
	for _, rule := range []string{fileRule, svcRule} {
		if got := ruleFailures(t, rule); len(got) > 0 {
			t.Errorf("valid rule failed: %v", got)
		}
	}
}

// A rule test decides platforms from the OS its case describes, as a scan
// does.
func TestRuleTestPlatformsFollowFacts(t *testing.T) {
	rule := strings.NewReplacer("    os: rhel\n    facts:\n      svc: {present: true}",
		"    facts:\n      os: {id: rocky, family: rhel, version_id: \"9\", version_major: 9}\n      svc: {present: true}").Replace(svcRule)
	if got := ruleFailures(t, rule); len(got) > 0 {
		t.Errorf("facts.os was not used for platforms: %v", got)
	}
	// An unavailable OS cannot be matched against platforms.
	rule = strings.Replace(svcRule, "unavailable: [svc]", "unavailable: [os]\n    facts:\n      svc: {present: true}", 1)
	if got := ruleFailures(t, rule); len(got) > 0 {
		t.Errorf("unavailable os: %v", got)
	}
}

// Listing /etc/group in a case changes its metadata, not the test accounts.
func TestRuleTestAccountFiles(t *testing.T) {
	rule := strings.NewReplacer("paths: [/etc/app.conf]", "paths: [/etc/group, /etc/app.conf]",
		`/etc/app.conf: {mode: "0644"}`, "/etc/group: {mode: \"0644\"}\n      /etc/app.conf: {mode: \"0644\", group: sys}").Replace(fileRule)
	if got := ruleFailures(t, rule); len(got) > 0 {
		t.Errorf("failures: %v", got)
	}
}

// A show expression that fails at run time still leaves the check MANUAL, so a
// rule test has to report the error itself.
func TestRuleTestReportsShowErrors(t *testing.T) {
	rule := `id: x.y
version: 1
title: T
severity: low
manual:
  guidance: look
  show: svc.users.map(u, int(u.name))
tests:
  - name: shows
    facts:
      svc: {users: [{name: root, uid: 0}]}
    want: MANUAL
`
	got := ruleFailures(t, rule)
	if len(got) != 1 || !strings.Contains(got[0], "show:") {
		t.Errorf("failures %q, want one about show", got)
	}
}

// A path below a regular file does not exist: the missing policy applies, not an error.
func TestFileBelowARegularFileIsMissing(t *testing.T) {
	rule := `id: x.y
version: 1
title: T
severity: low
file:
  paths: [/etc/app/conf.d/x.conf]
  owner: [root]
  mode: "0644"
  missing: pass
tests:
  - name: an ancestor is a file
    files:
      /etc/app: {type: file}
    want: PASS
  - name: present and wrong
    files:
      /etc/app/conf.d/x.conf: {mode: "0666"}
    want: FAIL
  - name: unreadable
    input: unavailable
    files:
      /etc/app/conf.d: {type: dir, mode: "0700", error: permission}
    want: ERROR
`
	if got := ruleFailures(t, rule); len(got) != 0 {
		t.Errorf("failures %q", got)
	}
}
