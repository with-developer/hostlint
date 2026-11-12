package rules_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/collect"
	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/profiles"
	"github.com/with-developer/vmsctl/rules"
)

// TestBuiltinContent loads every built-in check and profile, compiles them
// against the real collectors, and runs the tests in each check.
func TestBuiltinContent(t *testing.T) {
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.New(content, collect.All()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range e.RunRuleTests(context.Background()) {
		t.Error(f)
	}
	if len(content.Checks) == 0 || content.Profiles["kisa-2026"] == nil {
		t.Errorf("loaded %d checks and profiles %v", len(content.Checks), content.Profiles)
	}
	used := map[string]bool{}
	for _, p := range content.Profiles {
		for _, c := range p.Controls {
			for _, id := range c.Checks {
				used[id] = true
			}
		}
	}
	for id := range content.Checks {
		if !used[id] && !awaitingProfile[id] {
			t.Errorf("check %s is not mapped to any profile control", id)
		}
	}
	for id := range awaitingProfile {
		switch {
		case content.Checks[id] == nil:
			t.Errorf("awaitingProfile lists %s, which is not a built-in check", id)
		case used[id]:
			t.Errorf("check %s is mapped to a profile control: remove it from awaitingProfile", id)
		}
	}
}

// awaitingProfile lists built-in checks that are merged before a profile
// revision maps them to a control. Mapping a check changes the profile
// revision, which is the maintainer's decision; remove an entry when its
// check is mapped.
var awaitingProfile = map[string]bool{
	"ssh.login-grace-time": true,
}

// TestRuleFilesAreEmbedded fails on a file under rules/ that go:embed would
// silently leave out (a .yml file, a nested directory), which would drop a
// check from the binary without any error.
func TestRuleFilesAreEmbedded(t *testing.T) {
	areas, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, area := range areas {
		if !area.IsDir() {
			continue
		}
		files, err := os.ReadDir(area.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
				t.Errorf("rules/%s/%s is not embedded: a rule is rules/<area>/<name>.yaml", area.Name(), f.Name())
			}
		}
	}
}
