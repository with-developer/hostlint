package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// attestScan scans demoHost (hostname web-01) on 2026-11-03 with MANUAL checks
// that show a value (x.show), show nothing (x.plain) and show a value that
// cannot be computed (x.broken), and a check that FAILs (x.fail).
func attestScan(t *testing.T, opts Options) *Result {
	t.Helper()
	return attestScanOf(t, opts, demoSvc())
}

func attestScanOf(t *testing.T, opts Options, svc *fakeCollector) *Result {
	t.Helper()
	checks := []*Check{
		{ID: "x.show", Manual: &ManualSpec{Guidance: "look", Show: "svc.users.map(u, u.name)"}},
		{ID: "x.plain", Manual: &ManualSpec{Guidance: "look"}},
		{ID: "x.broken", Manual: &ManualSpec{Guidance: "look", Show: "svc.config.nosuchkey.value"}},
		{ID: "x.fail", Expect: `svc.config.permitrootlogin.value == "yes"`},
	}
	content := &Content{Checks: map[string]*Check{}, Profiles: map[string]*Profile{"p": {ID: "p", Revision: 1, Title: "P"}}}
	for i, c := range checks {
		c.Version, c.Title, c.Severity = 1, "T", SeverityLow
		content.Checks[c.ID] = c
		content.Profiles["p"].Controls = append(content.Profiles["p"].Controls,
			Control{ID: "C-0" + string(rune('1'+i)), Title: "C", Severity: SeverityLow, Checks: []string{c.ID}})
	}
	e, err := New(content, svc)
	if err != nil {
		t.Fatal(err)
	}
	opts.Profile = "p"
	opts.Now = func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }
	res, err := e.Scan(context.Background(), hostfs.NewTestHost(demoHost(), nil, false), opts)
	if err != nil {
		t.Fatal(err)
	}
	validateSchema(t, res)
	return res
}

func checkOf(t *testing.T, res *Result, id string) CheckResult {
	t.Helper()
	for _, c := range res.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no result for %s", id)
	return CheckResult{}
}

func TestAttestations(t *testing.T) {
	base := attestScan(t, Options{})
	show, plain, fail := checkOf(t, base, "x.show"), checkOf(t, base, "x.plain"), checkOf(t, base, "x.fail")
	if show.Status != StatusManual || !strings.HasPrefix(show.EvidenceDigest, "sha256:") {
		t.Fatalf("x.show: %s, digest %q", show.Status, show.EvidenceDigest)
	}
	if plain.EvidenceDigest != "" || checkOf(t, base, "x.broken").EvidenceDigest != "" {
		t.Error("a check that shows nothing, or whose value cannot be computed, has no evidence digest")
	}

	attest := func(id string, c CheckResult) Attestation {
		return Attestation{Check: id, Status: StatusPass, Digest: c.Digest, EvidenceDigest: c.EvidenceDigest,
			By: "alice", At: day("2026-11-01"), Expires: day("2026-12-31"), Note: "reviewed the list"}
	}
	tests := []struct {
		name   string
		att    Attestation
		check  string
		want   Status
		source string
		note   string
	}{
		{"applies", attest("x.show", show), "x.show", StatusPass, "attested", ""},
		{"attested FAIL", func() Attestation { a := attest("x.show", show); a.Status = StatusFail; return a }(), "x.show", StatusFail, "attested", ""},
		{"nothing to show: until it expires", attest("x.plain", plain), "x.plain", StatusPass, "attested", ""},
		{"expires today still applies", func() Attestation { a := attest("x.show", show); a.Expires = day("2026-11-03"); return a }(), "x.show", StatusPass, "attested", ""},
		{"expired", func() Attestation { a := attest("x.show", show); a.Expires = day("2026-11-02"); return a }(), "x.show", StatusManual, "observed", "expired"},
		{"the check changed", func() Attestation {
			a := attest("x.show", show)
			a.Digest = "sha256:" + strings.Repeat("0", 64)
			return a
		}(), "x.show", StatusManual, "observed", "logic changed"},
		{"the observed value changed", func() Attestation {
			a := attest("x.show", show)
			a.EvidenceDigest = "sha256:" + strings.Repeat("1", 64)
			return a
		}(), "x.show", StatusManual, "observed", "observed value changed"},
		{"evidence incomplete", attest("x.broken", checkOf(t, base, "x.broken")), "x.broken", StatusManual, "observed", "incomplete"},
		{"never a result that is not MANUAL", attest("x.fail", fail), "x.fail", StatusFail, "observed", "only a MANUAL result"},
		{"the check now shows a value", func() Attestation { a := attest("x.show", show); a.EvidenceDigest = ""; return a }(), "x.show", StatusManual, "observed", "now shows a value"},
		{"the check no longer shows a value", func() Attestation { a := attest("x.plain", plain); a.EvidenceDigest = show.EvidenceDigest; return a }(), "x.plain", StatusManual, "observed", "no longer shows a value"},
		{"dated in the future", func() Attestation { a := attest("x.show", show); a.At = day("2026-11-04"); return a }(), "x.show", StatusManual, "observed", "in the future"},
		{"other host", func() Attestation { a := attest("x.show", show); a.Hosts = []string{"db-*"}; return a }(), "x.show", StatusManual, "observed", ""},
		{"matching host", func() Attestation { a := attest("x.show", show); a.Hosts = []string{"web-*"}; return a }(), "x.show", StatusPass, "attested", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := attestScan(t, Options{Attestations: []Attestation{tt.att}})
			got := checkOf(t, res, tt.check)
			if got.Status != tt.want || got.StatusSource != tt.source {
				t.Errorf("status %s (%s), want %s (%s); reason %q", got.Status, got.StatusSource, tt.want, tt.source, got.Reason)
			}
			if tt.source == "attested" {
				if got.OriginalStatus != StatusManual || got.Attestation == nil || got.Attestation.By != "alice" || !strings.Contains(got.Reason, "reviewed the list") {
					t.Errorf("attested result: original %s, attestation %+v, reason %q", got.OriginalStatus, got.Attestation, got.Reason)
				}
			}
			switch {
			case tt.note == "" && len(res.Attestations) != 0:
				t.Errorf("notes %+v, want none", res.Attestations)
			case tt.note != "" && (len(res.Attestations) != 1 || !strings.Contains(res.Attestations[0].Problem, tt.note)):
				t.Errorf("notes %+v, want one mentioning %q", res.Attestations, tt.note)
			}
		})
	}

	t.Run("a control passes through an attested check", func(t *testing.T) {
		res := attestScan(t, Options{Attestations: []Attestation{attest("x.show", show)}})
		if res.Controls[0].Status != StatusPass {
			t.Errorf("control C-01 is %s, want PASS", res.Controls[0].Status)
		}
	})
	t.Run("a waiver still applies to an attested FAIL", func(t *testing.T) {
		a := attest("x.show", show)
		a.Status = StatusFail
		res := attestScan(t, Options{Attestations: []Attestation{a}, Waivers: []Waiver{{Check: "x.show", Reason: "accepted", Expires: day("2026-12-31")}}})
		if got := checkOf(t, res, "x.show"); got.Status != StatusWaived || got.StatusSource != "attested" {
			t.Errorf("status %s (%s), want WAIVED (attested)", got.Status, got.StatusSource)
		}
	})
	t.Run("one attestation at a time", func(t *testing.T) {
		second := attest("x.show", show)
		second.By = "bob"
		res := attestScan(t, Options{Attestations: []Attestation{attest("x.show", show), second}})
		if got := checkOf(t, res, "x.show"); got.Attestation == nil || got.Attestation.By != "alice" {
			t.Errorf("attestation %+v, want alice's", got.Attestation)
		}
		if len(res.Attestations) != 1 || !strings.Contains(res.Attestations[0].Problem, "already applies") {
			t.Errorf("notes %+v", res.Attestations)
		}
	})
}

// The evidence digest covers the whole value, including where a setting came
// from: a change a reviewer would care about changes it.
func TestEvidenceDigestCoversTheWholeValue(t *testing.T) {
	digest := func(mutate func(*svcFacts)) string {
		svc := demoSvc()
		mutate(svc.facts)
		res := attestScanOf(t, Options{}, svc)
		return checkOf(t, res, "x.show").EvidenceDigest
	}
	base := digest(func(*svcFacts) {})
	if again := digest(func(*svcFacts) {}); again != base {
		t.Errorf("the digest changes between scans: %s and %s", base, again)
	}
	if digest(func(f *svcFacts) { f.Users = append(f.Users, svcUser{"carol", 1001}) }) == base {
		t.Error("a new account does not change the digest")
	}
}

func TestShowDigestIsFalseWhenPartOfTheValueIsUnknown(t *testing.T) {
	adapter := types.DefaultTypeAdapter
	whole := types.NewStringList(adapter, []string{"root", "toor"})
	if d, ok := showDigest(whole); !ok || !strings.HasPrefix(d, "sha256:") {
		t.Fatalf("digest %q, ok %v", d, ok)
	}
	partial := types.NewRefValList(adapter, []ref.Val{types.String("root"), types.NewUnknown(1, nil)})
	if d, ok := showDigest(partial); ok {
		t.Errorf("digest %q of a list with an unknown element", d)
	}
	nested := types.NewRefValList(adapter, []ref.Val{whole, partial})
	if _, ok := showDigest(nested); ok {
		t.Error("a nested unknown element must make the value incomplete")
	}
}

// An attestation covers every instance of its check, and says when it did not.
func TestAttestationNamesInstancesItDidNotCover(t *testing.T) {
	manual := func(ref, evidence string) *CheckResult {
		return &CheckResult{Ref: ref, ID: "x.show", Digest: "sha256:" + strings.Repeat("a", 64), Status: StatusManual, StatusSource: "observed", EvidenceDigest: evidence, shows: true}
	}
	checks := map[string]*CheckResult{"x.show#1": manual("x.show#1", "sha256:one"), "x.show#2": manual("x.show#2", "sha256:two")}
	a := Attestation{Check: "x.show", Status: StatusPass, Digest: "sha256:" + strings.Repeat("a", 64), EvidenceDigest: "sha256:one",
		By: "alice", At: day("2026-11-01"), Expires: day("2026-12-31"), Note: "n"}
	notes := attestChecks([]Attestation{a}, checks, "web-01", day("2026-11-03"))
	if checks["x.show#1"].StatusSource != "attested" || checks["x.show#2"].StatusSource != "observed" {
		t.Errorf("sources %s and %s", checks["x.show#1"].StatusSource, checks["x.show#2"].StatusSource)
	}
	if len(notes) != 1 || !strings.Contains(notes[0].Problem, "observed value changed") {
		t.Errorf("notes %+v, want one about the second instance", notes)
	}
}
