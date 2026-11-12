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
var awaitingProfile = map[string]bool{}

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

// The Korean text of a check is optional, but where it is there it is a translation of text that exists (an English one), and
// it is Korean: a field that holds English, or no letter of Korean at all, is a paste that went to the wrong key.
func TestKoreanGuidanceIsKorean(t *testing.T) {
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	hangul := func(s string) bool {
		for _, r := range s {
			if r >= 0xAC00 && r <= 0xD7A3 {
				return true
			}
		}
		return false
	}
	for id, c := range content.Checks {
		for name, pair := range map[string][2]string{
			"description": {c.Description, c.DescriptionKo}, "rationale": {c.Rationale, c.RationaleKo}, "remediation": {c.Remediation, c.RemediationKo},
		} {
			en, ko := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
			switch {
			case ko == "":
			case en == "":
				t.Errorf("%s has %s_ko and no %s", id, name, name)
			case !hangul(ko):
				t.Errorf("%s: %s_ko has no Korean in it", id, name)
			}
		}
		if c.Manual != nil && strings.TrimSpace(c.Manual.GuidanceKo) != "" {
			if strings.TrimSpace(c.Manual.Guidance) == "" {
				t.Errorf("%s has manual.guidance_ko and no manual.guidance", id)
			}
			if !hangul(c.Manual.GuidanceKo) {
				t.Errorf("%s: manual.guidance_ko has no Korean in it", id)
			}
		}
	}
	for pid, p := range content.Profiles {
		for _, ctl := range p.Controls {
			switch ko := strings.TrimSpace(ctl.ManualKo); {
			case ko == "":
			case strings.TrimSpace(ctl.Manual) == "":
				t.Errorf("%s %s has manual_ko and no manual", pid, ctl.ID)
			case !hangul(ko):
				t.Errorf("%s %s: manual_ko has no Korean in it", pid, ctl.ID)
			}
		}
	}
}
