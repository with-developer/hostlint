package server

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Hosts that scan with different profiles are not added up: every number of the dashboard is of one profile.
func TestProfilesAreNotAddedUp(t *testing.T) {
	f := newAPIFixture(t) // web-01 and db-01 scan with kisa-2026
	ingest := token(t, f.store, ScopeIngest, "")
	as := func(host, profile string, n int) []byte {
		doc := bytes.ReplaceAll(fixture(t, "web-01.json"), []byte(`"hostname": "web-01"`), []byte(`"hostname": "`+host+`"`))
		doc = bytes.ReplaceAll(doc, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(host+"-"+profile))
		doc = bytes.ReplaceAll(doc, []byte(`"kisa-2026"`), []byte(`"`+profile+`"`))
		return bytes.ReplaceAll(doc, []byte(`"startedAt": "2026-11-02T12:00:00Z"`), []byte(`"startedAt": "2026-11-02T12:`+string(rune('0'+n))+`0:00Z"`))
	}
	for i, d := range []struct{ host, profile string }{{"ess-01", "essentials"}, {"mixed-01", "kisa-2026"}, {"mixed-01", "essentials"}} {
		if code, out := post(t, f.srv, ingest, as(d.host, d.profile, i+1)); code != http.StatusCreated {
			t.Fatalf("%v: %d %v", d, code, out)
		}
	}
	// kisa-2026: web-01, db-01 (the latest scan of mixed-01 is essentials). essentials: ess-01 and mixed-01.
	var pr struct {
		Profiles []ProfileUse      `json:"profiles"`
		Default  string            `json:"default"`
		Titles   map[string]string `json:"titles"`
	}
	f.json(t, "/api/v1/profiles", &pr)
	if len(pr.Profiles) != 2 || pr.Profiles[0].Hosts != 2 || pr.Profiles[1].Hosts != 2 || pr.Default != "essentials" && pr.Default != "kisa-2026" {
		t.Fatalf("profiles = %+v default %q", pr.Profiles, pr.Default)
	}
	var kisa, ess Overview
	f.json(t, "/api/v1/overview?profile=kisa-2026", &kisa)
	f.json(t, "/api/v1/overview?profile=essentials", &ess)
	if kisa.Profile != "kisa-2026" || kisa.Hosts != 2 || kisa.HostsOther != 2 {
		t.Errorf("kisa overview: hosts %d other %d profile %q", kisa.Hosts, kisa.HostsOther, kisa.Profile)
	}
	if ess.Hosts != 2 || ess.HostsOther != 2 {
		t.Errorf("essentials overview: hosts %d other %d", ess.Hosts, ess.HostsOther)
	}
	// The numbers are of one profile: ess-01 and mixed-01 are the same document as web-01 (the fixture), 11 controls each.
	if got := kisa.Counts["FAIL"] + kisa.Counts["PASS"] + kisa.Counts["ERROR"] + kisa.Counts["MANUAL"] + kisa.Counts["WAIVED"] + kisa.Counts["NOT_APPLICABLE"]; got == 0 {
		t.Errorf("kisa counts: %v", kisa.Counts)
	}
	for _, c := range kisa.TopFailing {
		if c.Profile != "kisa-2026" {
			t.Errorf("a control of %s in the kisa top list", c.Profile)
		}
	}
	// The host list: a host of another profile has no counts and says so.
	var hl struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?profile=kisa-2026", &hl)
	other := map[string]bool{}
	for _, h := range hl.Hosts {
		other[h.Name] = h.OtherProfile
		if h.OtherProfile && len(h.Counts) != 0 {
			t.Errorf("%s has counts of a profile it was not scanned with: %v", h.Name, h.Counts)
		}
	}
	if !other["ess-01"] || !other["mixed-01"] || other["web-01"] || other["db-01"] {
		t.Errorf("other profile = %v", other)
	}
	// The matrix leaves the other hosts out and says how many.
	var m Matrix
	f.json(t, "/api/v1/matrix?profile=essentials", &m)
	if m.Profile != "essentials" || len(m.Hosts) != 2 || m.Other != 2 {
		t.Errorf("matrix: %d hosts, %d other, profile %q", len(m.Hosts), m.Other, m.Profile)
	}
	for _, c := range m.Controls {
		if c.Profile != "essentials" {
			t.Errorf("a control of %s in the essentials matrix", c.Profile)
		}
	}
	// The control list, and the history of a host (its counts are of the profile too).
	var cl struct {
		Controls []ControlSummary `json:"controls"`
	}
	f.json(t, "/api/v1/controls?profile=essentials", &cl)
	for _, c := range cl.Controls {
		if c.Profile != "essentials" {
			t.Errorf("a control of %s in the essentials list", c.Profile)
		}
	}
	var hd HostDetail
	f.json(t, "/api/v1/hosts/"+strconv.FormatInt(hl.Hosts[0].ID, 10)+"?profile=essentials", &hd)
	if hd.Profile != "essentials" {
		t.Errorf("host profile = %q", hd.Profile)
	}
	// Without a choice the profile of most hosts is used, and a bad one is refused.
	var def Overview
	f.json(t, "/api/v1/overview", &def)
	if def.Profile != pr.Default {
		t.Errorf("the default overview is of %q, want %q", def.Profile, pr.Default)
	}
	if code, _ := f.get(t, f.api, "/api/v1/overview?profile=A%20b"); code != http.StatusBadRequest {
		t.Errorf("a bad profile: %d", code)
	}
	if !strings.Contains(string(mustGet(t, f, "/api/v1/hosts?profile=essentials&format=csv")), "ess-01") {
		t.Error("the export does not follow the profile")
	}
}

func mustGet(t *testing.T, f *apiFixture, path string) []byte {
	t.Helper()
	code, body := f.get(t, f.api, path)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, code, body)
	}
	return body
}
