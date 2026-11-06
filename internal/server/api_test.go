package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// apiFixture is a server with three scans received an hour apart: web-01 twice (U-01 got worse
// in the second) and db-01 once.
type apiFixture struct {
	srv   *Server
	store *Store
	api   string
	clock time.Time
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	f := &apiFixture{clock: testNow}
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.store = store
	f.srv = New(Config{Store: store, Now: func() time.Time { return f.clock }})
	ingest := token(t, store, ScopeIngest, "")
	f.api = token(t, store, ScopeAPI, "")
	for _, name := range []string{"web-01-old.json", "web-01.json", "db-01.json"} {
		if code, out := post(t, f.srv, ingest, fixture(t, name)); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		f.clock = f.clock.Add(time.Hour)
	}
	return f
}

func (f *apiFixture) get(t *testing.T, tok, path string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (f *apiFixture) json(t *testing.T, path string, into any) {
	t.Helper()
	code, body := f.get(t, f.api, path)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, code, body)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("GET %s: %v\n%s", path, err, body)
	}
}

func TestReadAPIAuth(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	for name, tok := range map[string]string{"no token": "", "an unknown token": "hlt_api_nope", "an ingest token": ingest} {
		for _, path := range []string{"/api/v1/overview", "/api/v1/hosts", "/api/v1/hosts/1", "/api/v1/scans/1", "/api/v1/diff?old=1&new=2"} {
			if code, _ := f.get(t, tok, path); code != http.StatusUnauthorized {
				t.Errorf("%s on %s: %d, want 401", name, path, code)
			}
		}
	}
	// A read token cannot ingest.
	if code, _ := post(t, f.srv, f.api, fixture(t, "web-01.json")); code != http.StatusUnauthorized {
		t.Errorf("a read token ingested: %d", code)
	}
}

func TestOverview(t *testing.T) {
	f := newAPIFixture(t)
	var o Overview
	f.json(t, "/api/v1/overview", &o)
	if o.Hosts != 2 || o.HostsFailing < 1 || o.HostsStale != 0 {
		t.Errorf("overview = %+v", o)
	}
	if len(o.TopFailing) == 0 || o.TopFailing[0].ID != "U-01" {
		t.Errorf("top failing = %+v", o.TopFailing)
	}
	// U-01 went from PASS to FAIL on web-01 in its latest scan.
	found := false
	for _, r := range o.RecentRegression {
		found = found || (r.Host == "web-01" && r.ControlID == "U-01" && r.Status == "FAIL")
	}
	if !found {
		t.Errorf("regressions = %+v", o.RecentRegression)
	}
	if o.Counts["FAIL"] < 1 || o.Score == nil {
		t.Errorf("counts = %v, score %v", o.Counts, o.Score)
	}
	// A month later nobody has reported: both hosts are stale, and nothing is recent.
	f.clock = f.clock.Add(30 * 24 * time.Hour)
	var late Overview
	f.json(t, "/api/v1/overview", &late)
	if late.HostsStale != 2 || len(late.RecentRegression) != 0 {
		t.Errorf("a month later: %+v", late)
	}
	if code, _ := f.get(t, f.api, "/api/v1/overview?staleDays=0"); code != http.StatusBadRequest {
		t.Errorf("staleDays=0: %d", code)
	}
}

func TestHostsListAndHost(t *testing.T) {
	f := newAPIFixture(t)
	var list struct {
		Hosts []HostSummary `json:"hosts"`
		Total int           `json:"total"`
	}
	f.json(t, "/api/v1/hosts", &list)
	if list.Total != 2 || len(list.Hosts) != 2 || list.Hosts[0].Name != "db-01" || list.Hosts[1].Name != "web-01" {
		t.Fatalf("hosts = %+v", list)
	}
	web := list.Hosts[1]
	if web.Counts["FAIL"] != 1 || web.LatestScan == 0 || web.Score == nil {
		t.Errorf("web-01 = %+v", web)
	}
	f.json(t, "/api/v1/hosts?q=web", &list)
	if list.Total != 1 || list.Hosts[0].Name != "web-01" {
		t.Errorf("q=web: %+v", list)
	}
	f.json(t, "/api/v1/hosts?q=%25", &list) // a wildcard in the query is text
	if list.Total != 0 {
		t.Errorf("q=%%: %+v", list)
	}
	f.json(t, "/api/v1/hosts?status=failing&limit=1&offset=0", &list)
	if len(list.Hosts) > 1 {
		t.Errorf("limit ignored: %+v", list)
	}
	for _, bad := range []string{"status=bogus", "limit=x", "offset=-1"} {
		if code, _ := f.get(t, f.api, "/api/v1/hosts?"+bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, code)
		}
	}

	var d HostDetail
	f.json(t, "/api/v1/hosts/"+itoa(web.ID), &d)
	if len(d.Controls) != 5 || len(d.Scans) != 2 || d.Scans[0].ID <= d.Scans[1].ID {
		t.Fatalf("detail = %+v", d)
	}
	if d.Scans[0].Counts["FAIL"] != 1 || d.Scans[1].Counts["FAIL"] != 0 {
		t.Errorf("history counts: %+v", d.Scans)
	}
	if code, _ := f.get(t, f.api, "/api/v1/hosts/999"); code != http.StatusNotFound {
		t.Errorf("unknown host: %d", code)
	}
	if code, _ := f.get(t, f.api, "/api/v1/hosts/x"); code != http.StatusBadRequest {
		t.Errorf("bad host ID: %d", code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestScanDocAndDiff(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, f.api, "/api/v1/scans/2")
	if code != http.StatusOK || !bytes.Equal(body, fixture(t, "web-01.json")) {
		t.Errorf("the stored document differs from the received one (%d)", code)
	}
	if code, _ := f.get(t, f.api, "/api/v1/scans/99"); code != http.StatusNotFound {
		t.Errorf("unknown scan: %d", code)
	}
	var d struct {
		Regressed []struct{ ID string } `json:"regressed"`
	}
	f.json(t, "/api/v1/diff?old=1&new=2", &d)
	if len(d.Regressed) != 1 || d.Regressed[0].ID != "U-01" {
		t.Errorf("diff = %+v", d)
	}
	for _, q := range []string{"", "old=1", "old=x&new=2"} {
		if code, _ := f.get(t, f.api, "/api/v1/diff?"+q); code != http.StatusBadRequest {
			t.Errorf("diff?%s: %d", q, code)
		}
	}
	if code, _ := f.get(t, f.api, "/api/v1/diff?old=1&new=99"); code != http.StatusNotFound {
		t.Errorf("diff with an unknown scan: %d", code)
	}
}

func TestHostsCSV(t *testing.T) {
	f := newAPIFixture(t)
	code, body := f.get(t, f.api, "/api/v1/hosts?format=csv")
	if code != http.StatusOK || !strings.HasPrefix(string(body), "host,host_id,last_scan,stale,score,FAIL") || !strings.Contains(string(body), "web-01,") {
		t.Errorf("csv (%d):\n%s", code, body)
	}
	for in, want := range map[string]string{"=SUM(A1)": "'=SUM(A1)", "+1": "'+1", "-1": "'-1", "@x": "'@x", "web-01": "web-01", "": ""} {
		if got := csvText(in); got != want {
			t.Errorf("csvText(%q) = %q, want %q", in, got, want)
		}
	}
}

// The API is read only and sends nothing a browser could run.
func TestAPIResponsesAreJSONAndWritesAreRefused(t *testing.T) {
	f := newAPIFixture(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/hosts/1", nil)
	req.Header.Set("Authorization", "Bearer "+f.api)
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("DELETE: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+f.api)
	f.srv.Handler().ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", rec.Header())
	}
}
