package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// waiverScan scans demoHost (hostname web-01) with checks that FAIL
// (x.fail), are MANUAL (x.manual) and ERROR (x.error), each its own control
// C-01..C-03 of profile p at revision 2, on 2026-11-03.
func waiverScan(t *testing.T, opts Options) *Result {
	t.Helper()
	svc := demoSvc()
	checks := []*Check{
		{ID: "x.fail", Expect: `svc.config.permitrootlogin.value == "yes"`},
		{ID: "x.manual", Manual: &ManualSpec{Guidance: "look", GuidanceKo: "확인하세요"}},
		{ID: "x.error", Expect: `svc.config.nosuchkey.value == "x"`},
		{ID: "x.age", Params: map[string]ParamSpec{"max_days": {Type: "int", Default: 90, Stricter: "lower"}},
			Setting: &SettingSpec{Fact: "svc.config.PASS_MAX_DAYS", Range: &RangeSpec{Min: &Bound{Value: 1}, Max: &Bound{Param: "max_days"}}, Absent: "fail"}},
	}
	content := &Content{Checks: map[string]*Check{}, Profiles: map[string]*Profile{"p": {ID: "p", Revision: 2, Title: "P"}}}
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

func day(s string) time.Time {
	d, err := time.Parse(dateLayout, s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestCheckWaivers(t *testing.T) {
	tests := []struct {
		name   string
		waiver Waiver
		check  string
		want   Status
		note   string
	}{
		{"fail waived", Waiver{Check: "x.fail", Reason: "accepted", Expires: day("2026-12-31")}, "x.fail", StatusWaived, ""},
		{"manual waived", Waiver{Check: "x.manual", Reason: "reviewed", Expires: day("2026-12-31")}, "x.manual", StatusWaived, ""},
		{"expires today still applies", Waiver{Check: "x.fail", Reason: "r", Expires: day("2026-11-03")}, "x.fail", StatusWaived, ""},
		{"expired", Waiver{Check: "x.fail", Reason: "r", Expires: day("2026-11-02")}, "x.fail", StatusFail, "expired"},
		{"error needs errors: true", Waiver{Check: "x.error", Reason: "r", Expires: day("2026-12-31")}, "x.error", StatusError, "not applied: the check is ERROR here; set errors: true to accept that it cannot run"},
		{"a check that is not in the profile", Waiver{Check: "x.nowhere", Reason: "r", Expires: day("2026-12-31")}, "x.fail", StatusFail, "not applied: the check is not in the scanned profile"},
		{"error with errors: true", Waiver{Check: "x.error", Reason: "r", Expires: day("2026-12-31"), Errors: true}, "x.error", StatusWaived, ""},
		{"other host", Waiver{Check: "x.fail", Reason: "r", Expires: day("2026-12-31"), Hosts: []string{"db-*"}}, "x.fail", StatusFail, ""},
		{"matching host", Waiver{Check: "x.fail", Reason: "r", Expires: day("2026-12-31"), Hosts: []string{"db-*", "web-*"}}, "x.fail", StatusWaived, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := waiverScan(t, Options{Waivers: []Waiver{tt.waiver}})
			var got CheckResult
			for _, c := range res.Checks {
				if c.ID == tt.check {
					got = c
				}
			}
			if got.Status != tt.want {
				t.Fatalf("%s = %s (%q), want %s", tt.check, got.Status, got.Reason, tt.want)
			}
			if tt.want == StatusWaived && (got.OriginalStatus == "" || got.Waiver == nil || !strings.HasPrefix(got.Reason, "waived: ")) {
				t.Errorf("waived result %+v", got)
			}
			// The Korean guidance of a review is not the reason of a waived check: only the waiver's own text is.
			if (tt.want == StatusWaived) != (got.ReasonKo == "") && tt.check == "x.manual" {
				t.Errorf("reasonKo = %q for %s", got.ReasonKo, got.Status)
			}
			if notes := len(res.Waivers); (tt.note == "") != (notes == 0) || notes > 0 && res.Waivers[0].Problem != tt.note {
				t.Errorf("notes %+v, want %q", res.Waivers, tt.note)
			}
		})
	}
}

func TestControlWaivers(t *testing.T) {
	tests := []struct {
		name    string
		waiver  Waiver
		control string
		want    Status
		note    string
	}{
		{"applies", Waiver{Control: "C-01", Revision: 2, Reason: "r", Expires: day("2026-12-31")}, "C-01", StatusWaived, ""},
		{"stale revision", Waiver{Control: "C-01", Revision: 1, Reason: "r", Expires: day("2026-12-31")}, "C-01", StatusFail, "stale"},
		{"blocked by an error", Waiver{Control: "C-03", Revision: 2, Reason: "r", Expires: day("2026-12-31")}, "C-03", StatusError, "not applied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := waiverScan(t, Options{Waivers: []Waiver{tt.waiver}})
			for _, c := range res.Controls {
				if c.ID == tt.control && c.Status != tt.want {
					t.Errorf("%s = %s (%q), want %s", c.ID, c.Status, c.Reason, tt.want)
				}
			}
			if notes := len(res.Waivers); (tt.note == "") != (notes == 0) || notes > 0 && !strings.HasPrefix(res.Waivers[0].Problem, tt.note) {
				t.Errorf("notes %+v, want %q", res.Waivers, tt.note)
			}
		})
	}
}

// Overrides may only make a check stricter than the profile, and mark the
// results customized.
func TestParamOverrides(t *testing.T) {
	res := waiverScan(t, Options{Params: map[string]map[string]any{"x.age": {"max_days": 60}}})
	var got CheckResult
	for _, c := range res.Checks {
		if c.ID == "x.age" {
			got = c
		}
	}
	// PASS_MAX_DAYS is 75 in demoSvc: within 90, not within 60.
	if got.Status != StatusFail || !got.Customized || got.Params["max_days"] != int64(60) || !strings.Contains(got.Ref, "#") {
		t.Errorf("x.age = %+v", got)
	}
	if res.Summary["p"].Customized != 1 {
		t.Errorf("summary = %+v", res.Summary["p"])
	}
	for _, c := range res.Controls {
		if c.ID == "C-04" && !c.Customized {
			t.Errorf("control %+v is not marked customized", c)
		}
	}
	for _, bad := range []map[string]any{{"max_days": 120}, {"max_days": "60"}, {"min_days": 1}} {
		svc := demoSvc()
		c := &Check{ID: "x.age", Version: 1, Title: "T", Severity: SeverityLow, Params: map[string]ParamSpec{"max_days": {Type: "int", Default: 90, Stricter: "lower"}},
			Setting: &SettingSpec{Fact: "svc.config.PASS_MAX_DAYS", Range: &RangeSpec{Min: &Bound{Value: 1}, Max: &Bound{Param: "max_days"}}, Absent: "fail"}}
		content := &Content{Checks: map[string]*Check{"x.age": c}, Profiles: map[string]*Profile{"p": {ID: "p", Revision: 1, Title: "P",
			Controls: []Control{{ID: "C", Title: "C", Severity: SeverityLow, Checks: []string{"x.age"}}}}}}
		e, err := New(content, svc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Scan(context.Background(), hostfs.NewTestHost(demoHost(), nil, false), Options{Profile: "p", Params: map[string]map[string]any{"x.age": bad}}); err == nil {
			t.Errorf("override %v accepted", bad)
		}
	}
}

// A profile that names its OS says nothing about another one: every control is NOT_APPLICABLE, with the reason; on the OS it
// is for, the controls are decided as usual. demoHost is ubuntu-24.04.
func TestProfileOS(t *testing.T) {
	scan := func(os []string) *Result {
		svc := demoSvc()
		checks := []*Check{{ID: "x.fail", Version: 1, Title: "T", Severity: SeverityLow, Expect: `svc.config.permitrootlogin.value == "yes"`}}
		content := &Content{Checks: map[string]*Check{"x.fail": checks[0]}, Profiles: map[string]*Profile{"p": {
			ID: "p", Revision: 1, Title: "P", OS: os, Controls: []Control{{ID: "C-01", Title: "C", Severity: SeverityLow, Checks: []string{"x.fail"}}},
		}}}
		e, err := New(content, svc)
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Scan(context.Background(), hostfs.NewTestHost(demoHost(), nil, false), Options{Profile: "p"})
		if err != nil {
			t.Fatal(err)
		}
		validateSchema(t, res)
		return res
	}
	for _, tc := range []struct {
		name string
		os   []string
		want Status
	}{
		{"no OS named: any host", nil, StatusFail},
		{"the OS it is for", []string{"ubuntu-24.04"}, StatusFail},
		{"one of several", []string{"ubuntu-22.04", "ubuntu-24.04"}, StatusFail},
		{"another version", []string{"ubuntu-22.04"}, StatusNotApplicable},
		{"another distribution", []string{"debian-12"}, StatusNotApplicable},
	} {
		got := scan(tc.os).Controls[0]
		if got.Status != tc.want {
			t.Errorf("%s: %s (%q), want %s", tc.name, got.Status, got.Reason, tc.want)
		}
		if tc.want == StatusNotApplicable && (!strings.Contains(got.Reason, strings.Join(tc.os, " or ")) || !strings.Contains(got.Reason, "ubuntu-24.04")) {
			t.Errorf("%s: the reason does not say which systems: %q", tc.name, got.Reason)
		}
	}
	// A profile without an OS has the digest it had before the field existed; one with an OS has another.
	c := &Content{Checks: map[string]*Check{}}
	plain := &Profile{ID: "p", Revision: 1, Controls: nil}
	withOS := &Profile{ID: "p", Revision: 1, OS: []string{"ubuntu-22.04"}}
	if c.ProfileDigest(plain) == c.ProfileDigest(withOS) {
		t.Error("the OS is not part of the profile digest")
	}
}

func TestProfileOSIsValidated(t *testing.T) {
	for os, ok := range map[string]bool{"ubuntu-22.04": true, "rocky-9": true, "amzn-2023": true, "ubuntu": false, "Ubuntu-22.04": false, "ubuntu 22.04": false, "": false} {
		pr := &Profile{ID: "p", Revision: 1, Title: "P", OS: []string{os}}
		err := validateProfile("p.yaml", pr, map[string]*Check{})
		if (err == nil) != ok {
			t.Errorf("os %q: err = %v", os, err)
		}
	}
}
