package rules_test

import (
	"context"
	"testing"

	"github.com/with-developer/hostlint/internal/collect"
	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
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
		if !used[id] {
			t.Errorf("check %s is not mapped to any profile control", id)
		}
	}
}
