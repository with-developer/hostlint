package engine

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

func manyUsers(n int) *fakeCollector {
	svc := demoSvc()
	svc.facts.Users = nil
	for i := range n {
		svc.facts.Users = append(svc.facts.Users, svcUser{Name: fmt.Sprintf("u%02d", i), UID: int64(1000 + i)})
	}
	return svc
}

// The per-element evaluations of a violations check share one cost budget,
// so a where that scans the population cannot run unbounded.
func TestViolationsCostIsBounded(t *testing.T) {
	const n = 2000 // quadratic: about twice the budget
	svc := manyUsers(n)
	c := &Check{ID: "x.uniq", Violations: &ViolationsSpec{Over: "svc.users", As: "u",
		Where: `svc.users.filter(o, o.uid == u.uid).size() > 1`, Key: "u.name", Text: "u.name"}}
	got := scanOne(t, c, svc, demoHost())
	if got.Status != StatusError || !strings.Contains(got.Reason, "cost limit") {
		t.Errorf("%s (%q), want ERROR at the cost limit", got.Status, got.Reason)
	}
	// A match found before the budget ran out still fails the check.
	svc.facts.Users[1].UID = svc.facts.Users[0].UID
	got = scanOne(t, c, svc, demoHost())
	if got.Status != StatusFail || got.Coverage == nil || got.Coverage.Count >= n {
		t.Errorf("%s, coverage %+v; want FAIL with partial coverage", got.Status, got.Coverage)
	}
}

// A key or text that cannot be evaluated does not undo a match (ADR 0006 §5).
func TestViolationsKeyTextErrors(t *testing.T) {
	svc := demoSvc()
	svc.facts.Users = []svcUser{{"toor", 0}, {"evil", 0}}
	svc.facts.Config["toor"] = facts.Setting{Value: "x", Explicit: true}
	c := &Check{ID: "x.uid0", Violations: &ViolationsSpec{Over: "svc.users", As: "u", Where: `u.uid == 0`,
		Key: "u.name", Text: `"UID 0: " + svc.config[u.name].value`}}
	got := scanOne(t, c, svc, demoHost())
	want := `evil: matched; its text could not be evaluated: no such key: evil | toor: UID 0: x`
	if got.Status != StatusFail || !strings.Contains(text(got), want) {
		t.Errorf("%s (%q), want FAIL with %q", got.Status, text(got), want)
	}
}

// On partial data, an element that was seen fails on its own facts only:
// what the unreadable part might hold never makes it fail.
func TestViolationsPartialData(t *testing.T) {
	tests := []struct {
		where string
		want  Status
	}{
		{`u.uid == 0 && u.name != "root"`, StatusFail},
		{`u.uid == 0 && !(("allow_" + u.name) in svc.config)`, StatusError},
	}
	for _, tt := range tests {
		svc := demoSvc()
		svc.complete = false
		c := &Check{ID: "x.uid0", Violations: &ViolationsSpec{Over: "svc.users", As: "u", Where: tt.where, Key: "u.name", Text: "u.name"}}
		got := scanOne(t, c, svc, demoHost())
		if got.Status != tt.want {
			t.Errorf("where %s: %s (%q), want %s", tt.where, got.Status, text(got), tt.want)
		}
	}
}

// show lists items in their order, as they are, and keeps the first ones.
func TestManualShowEvidence(t *testing.T) {
	svc := manyUsers(60)
	svc.facts.Users[3].Name = "admin\""
	got := scanOne(t, &Check{ID: "x.review", Manual: &ManualSpec{Guidance: "g", Show: "svc.users.map(u, u.name)"}}, svc, demoHost())
	if len(got.Evidence) != maxEvidence || got.EvidenceOmitted != 10 {
		t.Fatalf("%d items, %d omitted", len(got.Evidence), got.EvidenceOmitted)
	}
	for i, ev := range got.Evidence {
		want := svc.facts.Users[i].Name
		if ev.Key != fmt.Sprintf("show[%d]", i) || ev.Text != want {
			t.Errorf("item %d = %s: %q, want show[%d]: %q", i, ev.Key, ev.Text, i, want)
		}
	}
}

// An OS without a version keeps its id and family: only checks that read
// the version cannot decide.
func TestOSWithoutVersion(t *testing.T) {
	m := demoHost().AddFile("/etc/os-release", "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux forky/sid\"\n", 0o644, 0, 0)
	tests := []struct {
		applies, expect string
		want            Status
		text            string
	}{
		{`os.id == "debian"`, "svc.present", StatusPass, ""},
		{"", `os.family == "debian" && os.version_major >= 12`, StatusError, "os.version_major: not determined (the OS version is missing"},
		{"", `os.id == "ubuntu" && os.version_major >= 24`, StatusFail, ""},
	}
	for _, tt := range tests {
		got := scanOne(t, &Check{ID: "x.os", Applies: tt.applies, Expect: tt.expect}, demoSvc(), m)
		if got.Status != tt.want || !strings.Contains(got.Reason, tt.text) {
			t.Errorf("%s / %s: %s (%q), want %s", tt.applies, tt.expect, got.Status, got.Reason, tt.want)
		}
	}
}

func TestNoFalsePassGuards(t *testing.T) {
	unknownOS := demoHost().AddFile("/etc/os-release", "ID=plan9\n", 0o644, 0, 0)
	got := scanOne(t, &Check{ID: "x.deb", Platforms: []string{"debian"}, Expect: "svc.present"}, demoSvc(), unknownOS)
	if got.Status != StatusError {
		t.Errorf("unrecognized OS: %s (%q), want ERROR", got.Status, got.Reason)
	}

	svc := demoSvc()
	svc.facts.Config["maxauthtries"] = facts.Setting{Value: "3", Source: "default (svc 1.0)"}
	c := &Check{ID: "x.tries", Setting: &SettingSpec{Fact: "svc.config.maxauthtries", In: []string{"3"}, Absent: "fail"}}
	if got := scanOne(t, c, svc, demoHost()); got.Status != StatusFail {
		t.Errorf("absent: fail with a default value: %s (%q), want FAIL", got.Status, text(got))
	}
}

// NOT_APPLICABLE shows the facts that decided it (ADR 0006 §8).
func TestNotApplicableEvidence(t *testing.T) {
	svc := demoSvc()
	svc.facts.Present = false
	got := scanOne(t, &Check{ID: "x.svc", Applies: "svc.present", Expect: `svc.config.permitrootlogin.value == "no"`}, svc, demoHost())
	if got.Status != StatusNotApplicable || len(got.Evidence) != 1 || got.Evidence[0].Text != "svc.present = false" {
		t.Errorf("%s, evidence %+v", got.Status, got.Evidence)
	}
}

func TestCheckDigestIgnoresProse(t *testing.T) {
	a := &Check{ID: "x.y", Version: 1, Params: map[string]ParamSpec{"n": {Type: "int", Default: 1, Stricter: "lower", Description: "Max days"}}, Expect: "true"}
	b := &Check{ID: "x.y", Version: 1, Params: map[string]ParamSpec{"n": {Type: "int", Default: 1, Stricter: "lower", Description: "Maximum days"}}, Expect: "true"}
	if checkDigest(a) != checkDigest(b) {
		t.Error("rewording a parameter description changed the digest")
	}
	b.Params["n"] = ParamSpec{Type: "int", Default: 2, Stricter: "lower"}
	if checkDigest(a) == checkDigest(b) {
		t.Error("changing a parameter default kept the digest")
	}
}

func TestBoundResolve(t *testing.T) {
	b := &Bound{Param: "max"}
	if _, err := b.resolve(map[string]any{}); err == nil {
		t.Error("a missing parameter resolved")
	}
	if v, err := b.resolve(map[string]any{"max": int64(7)}); err != nil || v != 7 {
		t.Errorf("resolve = %d, %v", v, err)
	}
}

// The host ID is absent when there is no valid machine ID.
func TestHostIdentity(t *testing.T) {
	for _, id := range []string{"uninitialized\n", "", "XYZ"} {
		m := demoHost().AddFile("/etc/machine-id", id, 0o444, 0, 0)
		res := scanChecks(t, demoSvc(), m, time.Second, &Check{ID: "x.y", Expect: "svc.present"})
		if res.Host.HostID != "" {
			t.Errorf("machine-id %q gave host ID %s", id, res.Host.HostID)
		}
	}
	res := scanChecks(t, demoSvc(), demoHost(), time.Second, &Check{ID: "x.y", Expect: "svc.present"})
	if res.Host.HostID == "" || res.Host.Hostname != "web-01" {
		t.Errorf("host %+v", res.Host)
	}
}

func TestCollectorMetadataIsChecked(t *testing.T) {
	empty := &Content{Checks: map[string]*Check{}, Profiles: map[string]*Profile{}}
	for _, c := range []Collector{
		&fakeCollector{name: "Bad-Name", access: AccessFilesystem},
		&fakeCollector{name: "params", access: AccessFilesystem},
		&fakeCollector{name: "svc", access: "Live"},
	} {
		if _, err := New(empty, c); err == nil {
			t.Errorf("collector %q (%q) accepted", c.Name(), c.Access())
		}
	}
}

// A collector that marks a field unknown must name a real field.
func TestUnknownFieldsAreChecked(t *testing.T) {
	c := runCollector(t.Context(), unknownCollector{field: "nope"}, hostfs.NewTestHost(hostfs.NewMemFS(), nil, false), time.Second)
	if c.ok() {
		t.Error("an unknown field that does not exist was accepted")
	}
	c = runCollector(t.Context(), unknownCollector{field: "present"}, hostfs.NewTestHost(hostfs.NewMemFS(), nil, false), time.Second)
	if !c.ok() || c.run.Complete {
		t.Errorf("run %+v, want ok and not complete", c.run)
	}
}

type unknownCollector struct{ field string }

func (unknownCollector) Name() string       { return "svc" }
func (unknownCollector) Version() int       { return 1 }
func (unknownCollector) Access() Access     { return AccessFilesystem }
func (unknownCollector) Type() reflect.Type { return reflect.TypeFor[svcFacts]() }
func (u unknownCollector) Collect(context.Context, *hostfs.Host) (Facts, error) {
	return Facts{Value: &svcFacts{}, Complete: true, Unknown: []string{u.field}}, nil
}
