package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/engine"
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
	if code != http.StatusOK || !strings.HasPrefix(string(body), "host,host_id") {
		t.Errorf("csv: %d %.60s", code, body)
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
	osName, _ := hostInfo(res)
	if osName != "ubuntu 24.04" {
		t.Errorf("a name with an escape sequence falls back to the ID and version: %q", osName)
	}
	// Format characters (the right-to-left override, zero-width ones) would let a host dress its text up as another's.
	res.Host.OS.Name = "Ubuntu \u202e24.04"
	res.Host.Labels = map[string]string{"env": "pr\u200bod", "role": "web"}
	osName, labels := hostInfo(res)
	if osName != "ubuntu 24.04" || labels != `{"role":"web"}` {
		t.Errorf("format characters: %q %s", osName, labels)
	}
	res.Host.OS.Name = "Ubuntu 24.04\x1b[2J"
	res.Host.Labels = map[string]string{"env": "prod", "bad\nkey": "x", "ok": "fine", "long": strings.Repeat("v", maxLabelValue+1), "": "empty key", "a=b": "no filter could split it"}
	_, labels = hostInfo(res)
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

// A trend is the fleet as of each day: a host counts from its first scan, its latest scan until then is what counts, and
// a profile narrows the controls.
func TestTrendAsOfEachDay(t *testing.T) {
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := testNow
	srv := New(Config{Store: store, Rate: 100000, Now: func() time.Time { return clock }})
	ingest := token(t, store, ScopeIngest, "")
	push := func(name string) {
		t.Helper()
		// the scan starts when the clock says: a result from the future is refused
		doc := startedAtRe.ReplaceAll(fixture(t, name), []byte(`"startedAt": "`+clock.Add(-time.Minute).Format(time.RFC3339)+`"`))
		if code, out := post(t, srv, ingest, doc); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// db-01 reports four days ago; web-01 (old, then the worse one) two days ago and now.
	clock = testNow.Add(-4 * 24 * time.Hour)
	push("db-01.json")
	clock = testNow.Add(-2 * 24 * time.Hour)
	push("web-01-old.json")
	clock = testNow
	push("web-01.json")

	points, err := store.Trend(t.Context(), 5, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 5 {
		t.Fatalf("%d points", len(points))
	}
	hosts := []int{points[0].Hosts, points[1].Hosts, points[2].Hosts, points[3].Hosts, points[4].Hosts}
	if want := []int{1, 1, 2, 2, 2}; !equalInts(hosts, want) {
		t.Errorf("hosts per day = %v, want %v (db-01 from day 1, web-01 from day 3)", hosts, want)
	}
	// Day 3 has web-01's older scan; today has its latest: they differ.
	if points[2].Counts["FAIL"] == points[4].Counts["FAIL"] && points[2].Counts["PASS"] == points[4].Counts["PASS"] {
		t.Errorf("the second scan of web-01 changed nothing: %v vs %v", points[2].Counts, points[4].Counts)
	}
	for _, p := range points {
		if p.Failing > p.Hosts {
			t.Errorf("%d hosts failing of %d", p.Failing, p.Hosts)
		}
	}
	// A profile narrows the controls: the fixtures are of kisa-2026, so another one has none.
	same, err := store.Trend(t.Context(), 5, "kisa-2026")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.Trend(t.Context(), 5, "essentials")
	if err != nil {
		t.Fatal(err)
	}
	if same[4].Hosts != points[4].Hosts || same[4].Counts["FAIL"] != points[4].Counts["FAIL"] {
		t.Errorf("kisa-2026 differs from every profile: %+v vs %+v", same[4], points[4])
	}
	if other[4].Hosts != 0 || other[4].Score != nil {
		t.Errorf("a profile nobody scanned: %+v", other[4])
	}
}

var startedAtRe = regexp.MustCompile(`"startedAt": "[^"]*"`)

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The host list shows what the latest result says: a retry of an older result, acknowledged as a duplicate, does not
// put its labels back.
func TestRetryOfAnOlderResultKeepsTheLatestLabels(t *testing.T) {
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := testNow
	srv := New(Config{Store: store, Rate: 100000, Now: func() time.Time { return clock }})
	ingest := token(t, store, ScopeIngest, "")
	with := func(id, env string, n int) []byte {
		var doc map[string]any
		if err := json.Unmarshal(fixture(t, "web-01.json"), &doc); err != nil {
			t.Fatal(err)
		}
		doc["scan"].(map[string]any)["id"] = id
		doc["scan"].(map[string]any)["startedAt"] = fmt.Sprintf("2026-11-02T12:%02d:00Z", n)
		doc["host"].(map[string]any)["labels"] = map[string]string{"env": env}
		out, _ := json.Marshal(doc)
		return out
	}
	a, b := with("scan-a", "prod", 1), with("scan-b", "staging", 2)
	for _, doc := range [][]byte{a, b} {
		if code, out := post(t, srv, ingest, doc); code != http.StatusCreated {
			t.Fatalf("%d %v", code, out)
		}
		clock = clock.Add(time.Minute)
	}
	// The retry of scan A is acknowledged and changes nothing.
	if code, out := post(t, srv, ingest, a); code != http.StatusOK || out["duplicate"] != true {
		t.Fatalf("retry: %d %v", code, out)
	}
	hosts, _, err := store.Hosts(t.Context(), HostFilter{})
	if err != nil || len(hosts) != 1 {
		t.Fatalf("%v %v", hosts, err)
	}
	if hosts[0].Labels["env"] != "staging" {
		t.Errorf("labels after the retry: %v", hosts[0].Labels)
	}
}

// The trend is served again for a short time, and computed again after it.
func TestTrendIsCachedBriefly(t *testing.T) {
	f := newAPIFixture(t)
	var first, again, later struct {
		Points []TrendPoint `json:"points"`
	}
	f.json(t, "/api/v1/trend?days=2", &first)
	ingest := token(t, f.store, ScopeIngest, "")
	doc := bytes.ReplaceAll(fixture(t, "db-01.json"), []byte(`"hostname": "db-01"`), []byte(`"hostname": "db-new"`))
	doc = bytes.ReplaceAll(doc, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f20`), []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f99`))
	if code, out := post(t, f.srv, ingest, doc); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	f.json(t, "/api/v1/trend?days=2", &again)
	if again.Points[1].Hosts != first.Points[1].Hosts {
		t.Errorf("not served from the cache: %d then %d hosts", first.Points[1].Hosts, again.Points[1].Hosts)
	}
	f.clock = f.clock.Add(trendTTL + time.Second)
	f.json(t, "/api/v1/trend?days=2", &later)
	if later.Points[1].Hosts != first.Points[1].Hosts+1 {
		t.Errorf("not computed again after the cache expired: %d hosts", later.Points[1].Hosts)
	}
}
