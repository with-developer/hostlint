package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
)

func TestTrendOfTheFleet(t *testing.T) {
	f := newAPIFixture(t)
	points, err := f.store.Trend(t.Context(), 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 3 {
		t.Fatalf("%d points, want 3", len(points))
	}
	// Oldest first; before the first scan there is no host, and the last point is the fleet now.
	if points[0].Hosts != 0 || points[0].Score != nil || len(points[0].Counts) != 0 {
		t.Errorf("before any scan: %+v", points[0])
	}
	last := points[len(points)-1]
	if last.Hosts != 2 || last.Score == nil || last.Counts["FAIL"] == 0 || last.Failing == 0 || last.Failing > last.Hosts {
		t.Errorf("now: %+v", last)
	}
	// The same numbers as the overview, which counts the latest scan of every host.
	var ov Overview
	f.json(t, "/api/v1/overview", &ov)
	if ov.Hosts != last.Hosts || ov.Counts["FAIL"] != last.Counts["FAIL"] || ov.Counts["PASS"] != last.Counts["PASS"] {
		t.Errorf("overview %+v, trend %+v", ov.Counts, last.Counts)
	}
	var out struct {
		Points []TrendPoint `json:"points"`
	}
	f.json(t, "/api/v1/trend?days=2", &out)
	if len(out.Points) != 2 {
		t.Errorf("days=2: %d points", len(out.Points))
	}
	for _, bad := range []string{"days=0", "days=91", "days=x"} {
		if code, _ := f.get(t, f.api, "/api/v1/trend?"+bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
	if code, _ := f.get(t, "", "/api/v1/trend"); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
}

func TestHostListShowsOSLabelsTrendAndAgent(t *testing.T) {
	f := newAPIFixture(t)
	var list struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts", &list)
	byName := map[string]HostSummary{}
	for _, h := range list.Hosts {
		byName[h.Name] = h
	}
	web, db := byName["web-01"], byName["db-01"]
	if len(web.Trend) != 2 || len(db.Trend) != 1 {
		t.Errorf("trends: web %v, db %v", web.Trend, db.Trend)
	}
	for _, v := range web.Trend {
		if v < 0 || v > 1 {
			t.Errorf("a pass rate of %v", v)
		}
	}
	if web.OS == "" {
		t.Error("the OS of the latest result is not kept")
	}
	if web.AgentOnline {
		t.Error("a host with no agent is shown as having one")
	}
	// An agent that polled lately shows.
	agent := token(t, f.store, ScopeIngest, "web-01")
	if _, err := f.store.AgentSeen(t.Context(), mustAuth(t, f.store, agent), []string{"kisa-2026"}); err != nil {
		t.Fatal(err)
	}
	f.json(t, "/api/v1/hosts", &list)
	for _, h := range list.Hosts {
		if h.Name == "web-01" && !h.AgentOnline {
			t.Error("an agent that polled is not shown")
		}
	}
	// The export has no trends.
	code, body := f.get(t, f.api, "/api/v1/hosts?format=csv")
	if code != http.StatusOK || strings.Contains(string(body), "trend") {
		t.Errorf("csv: %d", code)
	}
}

func mustAuth(t *testing.T, s *Store, tok string) *Credential {
	t.Helper()
	c, err := s.Authenticate(t.Context(), tok, ScopeIngest)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// What a host says about itself is bounded and printable before the list shows it on every page.
func TestHostInfoIsBounded(t *testing.T) {
	res := &engine.Result{Host: engine.HostInfo{
		OS:     engine.OSInfo{ID: "ubuntu", VersionID: "24.04", Name: "Ubuntu 24.04\x1b[2J"},
		Labels: map[string]string{"env": "prod", "bad\nkey": "x", "ok": "fine", "long": strings.Repeat("v", maxLabelValue+1), "": "empty key"},
	}}
	osName, labels := hostInfo(res)
	if osName != "" {
		t.Errorf("a name with an escape sequence is kept: %q", osName)
	}
	if labels != `{"env":"prod","ok":"fine"}` {
		t.Errorf("labels = %s", labels)
	}
	res.Host.OS.Name = ""
	if osName, _ = hostInfo(res); osName != "ubuntu 24.04" {
		t.Errorf("os from id and version: %q", osName)
	}
	many := map[string]string{}
	for i := range 25 {
		many[fmt.Sprintf("k%02d", i)] = "v"
	}
	res.Host.Labels = many
	_, labels = hostInfo(res)
	if n := strings.Count(labels, `":"`); n != maxLabels {
		t.Errorf("%d labels kept, want %d", n, maxLabels)
	}
	res.Host.OS.Name = strings.Repeat("x", 3*maxOSName)
	if osName, _ = hostInfo(res); len(osName) > maxOSName+3 {
		t.Errorf("a name of %d bytes", len(osName))
	}
}
