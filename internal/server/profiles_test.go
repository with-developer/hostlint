package server

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
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
	csvText := string(mustGet(t, f, "/api/v1/hosts?profile=essentials&format=csv"))
	rows := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(csvText), "\n")[1:] {
		rows[strings.SplitN(line, ",", 2)[0]] = line
	}
	if !strings.HasSuffix(rows["ess-01"], ",essentials,false") || !strings.HasSuffix(rows["web-01"], ",essentials,true") {
		t.Errorf("the export does not follow the profile:\n%s", csvText)
	}
	if !strings.HasPrefix(csvText, "\xef\xbb\xbfhost,host_id,last_scan,stale,score,FAIL,ERROR,MANUAL,WAIVED,PASS,NOT_APPLICABLE,profile,other_profile") {
		t.Errorf("the columns of the export: %s", strings.SplitN(csvText, "\n", 2)[0])
	}
	// ?profile=all adds every profile up, as the dashboard did before there were several.
	var all Overview
	f.json(t, "/api/v1/overview?profile=all", &all)
	if all.Profile != "" || all.Hosts != 4 || all.HostsOther != 0 {
		t.Errorf("all profiles: hosts %d other %d profile %q", all.Hosts, all.HostsOther, all.Profile)
	}
	// The host page: the controls are those of the selected profile, and the profiles of the scan are named.
	var web HostDetail
	f.json(t, "/api/v1/hosts/"+strconv.FormatInt(hostID(t, hl.Hosts, "web-01"), 10)+"?profile=essentials", &web)
	if !web.OtherProfile || len(web.Controls) != 0 || len(web.Profiles) != 1 || web.Profiles[0] != "kisa-2026" {
		t.Errorf("a host of another profile: other %v controls %d profiles %v", web.OtherProfile, len(web.Controls), web.Profiles)
	}
	f.json(t, "/api/v1/hosts/"+strconv.FormatInt(hostID(t, hl.Hosts, "web-01"), 10)+"?profile=kisa-2026", &web)
	for _, c := range web.Controls {
		if c.Profile != "kisa-2026" {
			t.Errorf("a control of %s on the kisa page", c.Profile)
		}
	}
	if web.OtherProfile || len(web.Controls) == 0 {
		t.Errorf("web-01 under its own profile: other %v controls %d", web.OtherProfile, len(web.Controls))
	}
}

func hostID(t *testing.T, hosts []HostSummary, name string) int64 {
	t.Helper()
	for _, h := range hosts {
		if h.Name == name {
			return h.ID
		}
	}
	t.Fatalf("no host %s", name)
	return 0
}

// That a host is silent does not depend on the profile it scanned with, and a scan with no controls is not a scan of another profile.
func TestProfilesAndStaleHostsAndEmptyScans(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	doc := bytes.ReplaceAll(fixture(t, "web-01.json"), []byte(`"hostname": "web-01"`), []byte(`"hostname": "silent-ess"`))
	doc = bytes.ReplaceAll(doc, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte("silent-1"))
	doc = bytes.ReplaceAll(doc, []byte(`"kisa-2026"`), []byte(`"essentials"`))
	if code, out := post(t, f.srv, ingest, doc); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	f.clock = f.clock.Add(30 * 24 * time.Hour) // everyone is silent now
	var o Overview
	f.json(t, "/api/v1/overview?profile=kisa-2026", &o)
	if o.HostsStale != 3 || o.HostsOther != 1 {
		t.Errorf("stale %d other %d: the silent host of another profile is stale too", o.HostsStale, o.HostsOther)
	}
	// A scan whose document has no controls: not "another profile".
	if _, err := f.store.db.Exec(`DELETE FROM scan_controls WHERE scan_row = (SELECT MAX(id) FROM scans)`); err != nil {
		t.Fatal(err)
	}
	var hl struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?profile=kisa-2026", &hl)
	for _, h := range hl.Hosts {
		if h.Name == "silent-ess" && h.OtherProfile {
			t.Error("a scan without controls was called a scan of another profile")
		}
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
