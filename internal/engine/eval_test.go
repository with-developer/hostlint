package engine

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/facts"
	"github.com/with-developer/vmsctl/internal/hostfs"
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

// target.live lets a check require live facts only on a live target, so it
// is decided under --root instead of ERROR.
func TestTargetLive(t *testing.T) {
	absent := demoSvc()
	absent.facts.Present = false
	tests := []struct {
		live bool
		svc  *fakeCollector
		want Status
	}{
		{false, &fakeCollector{name: "svc", access: AccessLive}, StatusPass}, // unavailable, not read
		{true, demoSvc(), StatusPass},
		{true, absent, StatusFail},
	}
	for _, tt := range tests {
		content := &Content{
			Checks: map[string]*Check{"x.live": {ID: "x.live", Version: 1, Title: "T", Severity: SeverityLow, Expect: "!target.live || svc.present"}},
			Profiles: map[string]*Profile{"p": {ID: "p", Revision: 1, Title: "P", Controls: []Control{
				{ID: "C", Title: "C", Severity: SeverityLow, Checks: []string{"x.live"}}}}},
		}
		e, err := New(content, tt.svc)
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Scan(context.Background(), hostfs.NewTestHost(demoHost(), nil, tt.live), Options{Profile: "p"})
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Checks[0]; got.Status != tt.want {
			t.Errorf("live %v: %s (%q), want %s", tt.live, got.Status, got.Reason, tt.want)
		}
	}
}

// A partial field can fail a check through what it holds, never pass one;
// the collector's other fields stay decidable.
func TestPartialFields(t *testing.T) {
	tests := []struct {
		users []svcUser
		check *Check
		want  Status
	}{
		{[]svcUser{{"root", 0}, {"toor", 0}}, uid0Check(), StatusFail},
		{[]svcUser{{"root", 0}}, uid0Check(), StatusError},
		{[]svcUser{{"root", 0}}, &Check{ID: "x.present", Expect: "svc.present"}, StatusPass},
		{[]svcUser{{"root", 0}}, &Check{ID: "x.count", Expect: "svc.users.size() == 1"}, StatusError},
	}
	for _, tt := range tests {
		svc := demoSvc()
		svc.facts.Users, svc.partial = tt.users, []string{"users"}
		got := scanOne(t, tt.check, svc, demoHost())
		if got.Status != tt.want {
			t.Errorf("%s with %v: %s (%q), want %s", tt.check.ID, tt.users, got.Status, got.Reason, tt.want)
		}
		if tt.want == StatusError && !strings.Contains(got.Reason, "svc.users: incomplete observation") {
			t.Errorf("%s: reason %q", tt.check.ID, got.Reason)
		}
	}
}

func uid0Check() *Check {
	return &Check{ID: "x.uid0", Violations: &ViolationsSpec{Over: "svc.users", As: "u", Where: `u.uid == 0 && u.name != "root"`, Key: "u.name", Text: "u.name"}}
}

// A collector can ask for more time than the scan's collector timeout.
func TestCollectorTimeout(t *testing.T) {
	h := hostfs.NewTestHost(hostfs.NewMemFS(), nil, false)
	if c := runCollector(t.Context(), slowCollector{need: 300 * time.Millisecond, takes: 100 * time.Millisecond}, h, 20*time.Millisecond); !c.ok() {
		t.Errorf("slow collector with its own timeout: %v", c.err)
	}
	if c := runCollector(t.Context(), slowCollector{takes: 300 * time.Millisecond}, h, 20*time.Millisecond); c.ok() {
		t.Error("slow collector without its own timeout finished")
	}
}

type slowCollector struct{ need, takes time.Duration }

func (slowCollector) Name() string             { return "svc" }
func (slowCollector) Version() int             { return 1 }
func (slowCollector) Access() Access           { return AccessFilesystem }
func (slowCollector) Type() reflect.Type       { return reflect.TypeFor[svcFacts]() }
func (s slowCollector) Timeout() time.Duration { return s.need }
func (s slowCollector) Collect(ctx context.Context, _ *hostfs.Host) (Facts, error) {
	select {
	case <-time.After(s.takes):
		return Facts{Value: &svcFacts{}, Complete: true}, nil
	case <-ctx.Done():
		return Facts{}, ctx.Err()
	}
}

// A value a collector marks as unreadable by the program is out of range, not
// an evaluation error: the program falls back to its default.
func TestCompareSettingInvalidValue(t *testing.T) {
	spec := &SettingSpec{Range: &RangeSpec{Min: &Bound{Value: 1}, Max: &Bound{Value: 90}}}
	for value, want := range map[string]bool{"30": true, "91": false, "invalid: 090": false} {
		ok, err := compareSetting(spec, 1, 90, value)
		if err != nil || ok != want {
			t.Errorf("%q: %v, %v; want %v", value, ok, err, want)
		}
	}
	if _, err := compareSetting(spec, 1, 90, "soon"); err == nil {
		t.Error("a word that no collector marked was accepted as a number")
	}
	if _, err := compareSetting(spec, 1, 90, "invalid:"); err == nil {
		t.Error("a value that is not a marker made by facts.Invalid was taken for one")
	}
	if ok, err := compareSetting(&SettingSpec{Matches: ".*"}, 0, 0, facts.Invalid("090")); err != nil || ok {
		t.Errorf("a permissive pattern accepted an unreadable value: %v, %v", ok, err)
	}
}

// Evidence keys stay in a total order when indexed and other keys mix.
func TestCompareKeysIsATotalOrder(t *testing.T) {
	keys := []string{"show[10]", "show[2]", "show[1a]", "show[1]", "show", "show[]", "other[3]", "show[002]"}
	for _, a := range keys {
		for _, b := range keys {
			for _, c := range keys {
				if compareKeys(a, b) < 0 && compareKeys(b, c) < 0 && compareKeys(a, c) >= 0 {
					t.Errorf("%s < %s < %s, but not %s < %s", a, b, c, a, c)
				}
			}
		}
	}
	if compareKeys("show[2]", "show[10]") >= 0 {
		t.Error("show[2] must come before show[10]")
	}
}
