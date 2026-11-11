package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/signing"
	"github.com/with-developer/vmsctl/profiles"
	"github.com/with-developer/vmsctl/rules"
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
	f.srv = New(Config{Store: store, Rate: 100000, Now: func() time.Time { return f.clock }})
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

// The history is limited by scans, not by rows: every scan listed has all of its counts.
func TestHostHistoryIsLimitedByScans(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	web := fixture(t, "web-01.json")
	for i := range 230 {
		doc := bytes.ReplaceAll(web, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte("scan-"+strconv.Itoa(i)))
		if code, out := post(t, f.srv, ingest, doc); code != http.StatusCreated {
			t.Fatalf("scan %d: %d %v", i, code, out)
		}
		f.clock = f.clock.Add(time.Second)
	}
	var list struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?q=web", &list)
	var d HostDetail
	f.json(t, "/api/v1/hosts/"+itoa(list.Hosts[0].ID), &d)
	if len(d.Scans) != 200 {
		t.Fatalf("%d scans in the history, want 200", len(d.Scans))
	}
	for _, s := range d.Scans {
		total := 0
		for _, n := range s.Counts {
			total += n
		}
		if total != 5 {
			t.Fatalf("scan %d has %d counted controls, want 5: %v", s.ID, total, s.Counts)
		}
	}
}

// "Last used" is written once a minute, not on every request.
func TestLastUsedIsThrottled(t *testing.T) {
	f := newAPIFixture(t)
	read := func() string {
		var last string
		if err := f.store.db.QueryRow(`SELECT last_used_at FROM credentials WHERE scope = 'api'`).Scan(&last); err != nil {
			t.Fatal(err)
		}
		return last
	}
	f.get(t, f.api, "/api/v1/overview")
	first := read()
	f.clock = f.clock.Add(10 * time.Second)
	f.get(t, f.api, "/api/v1/overview")
	if got := read(); got != first {
		t.Errorf("last_used_at changed within a minute: %s -> %s", first, got)
	}
	f.clock = f.clock.Add(2 * time.Minute)
	f.get(t, f.api, "/api/v1/overview")
	if got := read(); got == first {
		t.Error("last_used_at was not updated after two minutes")
	}
}

// The export holds every host, however many there are.
func TestHostsCSVIsComplete(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	web := fixture(t, "web-01.json")
	for i := range 520 {
		doc := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "h`+strconv.Itoa(i)+`"`))
		doc = bytes.ReplaceAll(doc, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte("c-"+strconv.Itoa(i)))
		if code, out := post(t, f.srv, ingest, doc); code != http.StatusCreated {
			t.Fatalf("host %d: %d %v", i, code, out)
		}
	}
	code, body := f.get(t, f.api, "/api/v1/hosts?format=csv")
	if lines := strings.Count(string(body), "\n"); code != http.StatusOK || lines != 1+522 {
		t.Errorf("csv has %d lines (%d), want %d", lines, code, 1+522)
	}
}

func TestMatrixAndSort(t *testing.T) {
	f := newAPIFixture(t)
	var m Matrix
	f.json(t, "/api/v1/matrix", &m)
	if len(m.Hosts) != 2 || len(m.Controls) == 0 {
		t.Fatalf("matrix = %d hosts, %d controls", len(m.Hosts), len(m.Controls))
	}
	for _, h := range m.Hosts {
		if len(h.Statuses) != len(m.Controls) || strings.Trim(h.Statuses, "FEMWPN-") != "" {
			t.Errorf("host %s statuses %q for %d controls", h.Name, h.Statuses, len(m.Controls))
		}
	}
	// Hosts that fail most come first (ties by name).
	for i := 1; i < len(m.Hosts); i++ {
		if strings.Count(m.Hosts[i-1].Statuses, "F") < strings.Count(m.Hosts[i].Statuses, "F") {
			t.Errorf("hosts not ordered by failures: %+v", m.Hosts)
		}
	}
	for i := 1; i < len(m.Controls); i++ {
		if m.Controls[i-1].Profile == m.Controls[i].Profile && naturalLess(m.Controls[i].ID, m.Controls[i-1].ID) {
			t.Errorf("controls not in natural order: %s before %s", m.Controls[i-1].ID, m.Controls[i].ID)
		}
	}
	// Sorted by score, the worst host comes first.
	var list struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?sort=score", &list)
	if len(list.Hosts) != 2 || (list.Hosts[0].Score != nil && list.Hosts[1].Score != nil && *list.Hosts[0].Score > *list.Hosts[1].Score) {
		t.Errorf("by score: %+v", list.Hosts)
	}
	f.json(t, "/api/v1/hosts?sort=last", &list)
	if list.Hosts[0].LastScanAt > list.Hosts[1].LastScanAt {
		t.Errorf("by last scan: %+v", list.Hosts)
	}
	if code, _ := f.get(t, f.api, "/api/v1/hosts?sort=bogus"); code != http.StatusBadRequest {
		t.Errorf("sort=bogus: %d", code)
	}
	if code, _ := f.get(t, "", "/api/v1/matrix"); code != http.StatusUnauthorized {
		t.Errorf("matrix without a token: %d", code)
	}
}

func TestNaturalLess(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{{"U-2", "U-10", true}, {"U-10", "U-2", false}, {"U-02", "U-2", false}, {"U-1", "U-1", false}, {"A-1", "U-1", true}, {"U-1", "U-1a", true}} {
		if got := naturalLess(tt.a, tt.b); got != tt.want {
			t.Errorf("naturalLess(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// A list with no entries is [] in the JSON, never null: the dashboard reads .length of it.
func TestEmptyListsAreNotNull(t *testing.T) {
	f := newAPIFixture(t)
	for _, path := range []string{"/api/v1/hosts?status=stale", "/api/v1/hosts?q=nomatch", "/api/v1/hosts?offset=100"} {
		code, body := f.get(t, f.api, path)
		if code != http.StatusOK || !strings.Contains(string(body), `"hosts":[]`) {
			t.Errorf("%s: %d %s", path, code, body)
		}
	}
}

func TestControlsAndControl(t *testing.T) {
	f := newAPIFixture(t)
	var list struct {
		Controls []ControlSummary `json:"controls"`
	}
	f.json(t, "/api/v1/controls", &list)
	if len(list.Controls) < 4 {
		t.Fatalf("controls = %+v", list.Controls)
	}
	var u01 *ControlSummary
	for i, c := range list.Controls {
		if c.ID == "U-01" {
			u01 = &list.Controls[i]
		}
	}
	if u01 == nil || u01.Counts["FAIL"] != 1 || u01.Title == "" {
		t.Fatalf("U-01 = %+v", u01)
	}
	var d struct {
		Control ControlDetail `json:"control"`
		Info    *ControlInfo  `json:"info"`
	}
	f.json(t, "/api/v1/controls/kisa-2026/U-01", &d)
	if len(d.Control.Hosts) == 0 || d.Control.Hosts[0].Status != "FAIL" || d.Control.Hosts[0].Host != "web-01" {
		t.Errorf("hosts of U-01 = %+v", d.Control.Hosts)
	}
	if d.Info != nil {
		t.Errorf("info without profiles: %+v", d.Info)
	}
	// With the profiles, the answer says what the control checks and how to fix it.
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Content = content
	f.json(t, "/api/v1/controls/kisa-2026/U-01", &d)
	if d.Info == nil || len(d.Info.Checks) == 0 || d.Info.Checks[0].Remediation == "" || d.Info.Checks[0].Rationale == "" {
		t.Errorf("info = %+v", d.Info)
	}
	if code, _ := f.get(t, f.api, "/api/v1/controls/kisa-2026/U-99"); code != http.StatusNotFound {
		t.Errorf("unknown control: %d", code)
	}
	if code, _ := f.get(t, "", "/api/v1/controls"); code != http.StatusUnauthorized {
		t.Errorf("without a token: %d", code)
	}
}

// With the profiles loaded, the answers carry the Korean title of each control.
func TestKoreanTitlesFromTheProfiles(t *testing.T) {
	f := newAPIFixture(t)
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.cfg.Content = content
	for _, path := range []string{"/api/v1/controls", "/api/v1/matrix", "/api/v1/overview", "/api/v1/hosts/1"} {
		code, body := f.get(t, f.api, path)
		if code != http.StatusOK || !strings.Contains(string(body), `"titleKo":"`) {
			t.Errorf("%s: %d, no titleKo in %.300s", path, code, body)
		}
	}
	// Without the profiles there is none, and nothing breaks.
	f.srv.cfg.Content = nil
	if _, body := f.get(t, f.api, "/api/v1/controls"); strings.Contains(string(body), "titleKo") {
		t.Errorf("titleKo without profiles: %.200s", body)
	}
}

// ---- signed results ----

func signedDoc(t *testing.T, keyPath string, doc []byte) (key, sig string) {
	t.Helper()
	k, err := signing.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	sig, key = signing.Sign(k, doc)
	return key, sig
}

func postSigned(t *testing.T, f *apiFixture, tok string, body []byte, key, sig string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/results", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	if key != "" {
		req.Header.Set(signing.HeaderKey, key)
		req.Header.Set(signing.HeaderSignature, sig)
	}
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSignedResults(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	dir := t.TempDir()
	keyA, keyB := filepath.Join(dir, "a.key"), filepath.Join(dir, "b.key")
	if _, err := signing.Generate(keyA); err != nil {
		t.Fatal(err)
	}
	if _, err := signing.Generate(keyB); err != nil {
		t.Fatal(err)
	}
	web := fixture(t, "web-01.json") // web-01 already has unsigned scans in the fixture; use another host
	doc := func(id string) []byte {
		out := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "signer"`))
		return laterScan(bytes.ReplaceAll(out, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(id)), scanNumber(id))
	}
	d1 := doc("s-1")
	k, s := signedDoc(t, keyA, d1)
	if code, out := postSigned(t, f, ingest, d1, k, s); code != http.StatusCreated {
		t.Fatalf("first signed result: %d %v", code, out)
	}
	// The key is registered: the host's list entry shows it.
	var list struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?q=signer", &list)
	if len(list.Hosts) != 1 || !list.Hosts[0].Signed || !strings.HasPrefix(list.Hosts[0].KeyFingerprint, "SHA256:") {
		t.Fatalf("host = %+v", list.Hosts)
	}

	// A document changed after it was signed does not verify.
	d2 := doc("s-2")
	k2, s2 := signedDoc(t, keyA, d2)
	if code, out := postSigned(t, f, ingest, append(d2, ' '), k2, s2); code != http.StatusUnprocessableEntity {
		t.Errorf("a changed document: %d %v", code, out)
	}
	// Unsigned, or signed with another key: refused for a host that signs.
	if code, out := postSigned(t, f, ingest, d2, "", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), "not signed") {
		t.Errorf("an unsigned result: %d %v", code, out)
	}
	kb, sb := signedDoc(t, keyB, d2)
	if code, out := postSigned(t, f, ingest, d2, kb, sb); code != http.StatusConflict || !strings.Contains(out["error"].(string), "another key") {
		t.Errorf("another key: %d %v", code, out)
	}
	// Half a signature is refused; the right key still works.
	if code, _ := postSigned(t, f, ingest, d2, k2, ""); code != http.StatusUnprocessableEntity {
		t.Errorf("a key without a signature: %d", code)
	}
	if code, out := postSigned(t, f, ingest, d2, k2, s2); code != http.StatusCreated {
		t.Errorf("the same key: %d %v", code, out)
	}

	// The stored scans verify; a changed stored document does not.
	ctx := context.Background()
	rep, err := f.store.VerifySignatures(ctx)
	if err != nil || rep.Signed != 2 || rep.Unsigned != 3 || !rep.OK() {
		t.Fatalf("verify: %+v, %v", rep, err)
	}
	var id int64
	if err := f.store.db.QueryRow(`SELECT id FROM scans WHERE signature != '' ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	altered := bytes.ReplaceAll(d1, []byte(`"status": "FAIL"`), []byte(`"status": "PASS"`))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(altered)
	_ = zw.Close()
	if _, err := f.store.db.Exec(`UPDATE scans SET doc = ? WHERE id = ?`, gz.Bytes(), id); err != nil {
		t.Fatal(err)
	}
	if rep, _ := f.store.VerifySignatures(ctx); len(rep.Mismatched) != 1 || rep.Mismatched[0] != id {
		t.Errorf("a stored document that was changed went unnoticed: %+v", rep)
	}
	// Removing the signature of a stored scan of a host that signs is found as well.
	if _, err := f.store.db.Exec(`UPDATE scans SET signature = '', pubkey = '' WHERE id = ?`, id+1); err != nil {
		t.Fatal(err)
	}
	if rep, _ := f.store.VerifySignatures(ctx); len(rep.Mismatched) != 2 {
		t.Errorf("a removed signature went unnoticed: %+v", rep)
	}

	// An operator can reset the registered key (a re-installed machine), and the new key registers.
	hostID := list.Hosts[0].ID
	if _, err := f.store.ResetHostKey(ctx, hostID, "not a key"); err == nil {
		t.Error("a garbage key was accepted")
	}
	if ok, err := f.store.ResetHostKey(ctx, hostID, ""); !ok || err != nil {
		t.Fatalf("reset: %v %v", ok, err)
	}
	if ok, _ := f.store.ResetHostKey(ctx, hostID, ""); ok {
		t.Error("a key was reset twice")
	}
	d3 := doc("s-3")
	k3, s3 := signedDoc(t, keyB, d3)
	if code, out := postSigned(t, f, ingest, d3, k3, s3); code != http.StatusCreated {
		t.Errorf("the new key after a reset: %d %v", code, out)
	}
	if _, _, err := f.store.VerifyAudit(ctx); err != nil {
		t.Errorf("audit chain: %v", err)
	}
}

// laterScan gives a copy of a fixture document the start time of its n-th scan, one minute apart: a signed
// host does not accept a scan that is not newer than its latest one.
func laterScan(doc []byte, n int) []byte {
	return bytes.ReplaceAll(doc, []byte(`"startedAt": "2026-11-02T12:00:00Z"`), []byte(fmt.Sprintf(`"startedAt": "2026-11-02T12:%02d:00Z"`, n)))
}

func scanNumber(id string) int {
	n, _ := strconv.Atoi(id[strings.LastIndex(id, "-")+1:])
	return n
}

// An unsigned host has no key and no fingerprint; replacing a key with a given one leaves no gap.
func TestUnsignedHostsHaveNoFingerprintAndKeysCanBeReplaced(t *testing.T) {
	f := newAPIFixture(t)
	var list struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts", &list)
	for _, h := range list.Hosts {
		if h.Signed || h.KeyFingerprint != "" {
			t.Errorf("%s is unsigned but has %+v", h.Name, h)
		}
	}
	ingest := token(t, f.store, ScopeIngest, "")
	dir := t.TempDir()
	pubA, _ := signing.Generate(filepath.Join(dir, "a"))
	pubB, _ := signing.Generate(filepath.Join(dir, "b"))
	web := fixture(t, "web-01.json")
	doc := func(id string) []byte {
		out := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "rotating"`))
		return laterScan(bytes.ReplaceAll(out, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(id)), scanNumber(id))
	}
	kA, sA := signedDoc(t, filepath.Join(dir, "a"), doc("k-1"))
	if kA != pubA {
		t.Fatal("key mismatch")
	}
	if code, out := postSigned(t, f, ingest, doc("k-1"), kA, sA); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	f.json(t, "/api/v1/hosts?q=rotating", &list)
	id := list.Hosts[0].ID
	if ok, err := f.store.ResetHostKey(context.Background(), id, pubB); !ok || err != nil {
		t.Fatalf("replace: %v %v", ok, err)
	}
	// Unsigned is still refused after the replacement; the new key works, the old one does not.
	if code, _ := postSigned(t, f, ingest, doc("k-2"), "", ""); code != http.StatusConflict {
		t.Errorf("unsigned after a replacement: %d", code)
	}
	if code, _ := postSigned(t, f, ingest, doc("k-2"), kA, sA); code != http.StatusUnprocessableEntity && code != http.StatusConflict {
		t.Errorf("the old key after a replacement: %d", code)
	}
	k2, s2 := signedDoc(t, filepath.Join(dir, "b"), doc("k-2"))
	if code, out := postSigned(t, f, ingest, doc("k-2"), k2, s2); code != http.StatusCreated {
		t.Errorf("the new key: %d %v", code, out)
	}
}

// A token bound to a key: no trust on first use. A thief of the token cannot register another key.
func TestTokenBoundToAKey(t *testing.T) {
	f := newAPIFixture(t)
	dir := t.TempDir()
	pubA, _ := signing.Generate(filepath.Join(dir, "a"))
	_, _ = signing.Generate(filepath.Join(dir, "thief"))
	tok, _, err := f.store.CreateCredential(context.Background(), ScopeIngest, "bound", "", 0, WithKey(pubA))
	if err != nil {
		t.Fatal(err)
	}
	web := fixture(t, "web-01.json")
	doc := func(id string) []byte {
		out := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "keyed"`))
		return laterScan(bytes.ReplaceAll(out, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(id)), scanNumber(id))
	}
	d := doc("b-1")
	if code, out := postSigned(t, f, tok, d, "", ""); code != http.StatusConflict || !strings.Contains(out["error"].(string), "only accepts") {
		t.Errorf("unsigned with a bound token: %d %v", code, out)
	}
	kt, st := signedDoc(t, filepath.Join(dir, "thief"), d)
	if code, out := postSigned(t, f, tok, d, kt, st); code != http.StatusConflict {
		t.Errorf("another key with a bound token: %d %v", code, out)
	}
	k, s := signedDoc(t, filepath.Join(dir, "a"), d)
	if code, out := postSigned(t, f, tok, d, k, s); code != http.StatusCreated {
		t.Errorf("the bound key: %d %v", code, out)
	}
	// A token with a key is listed, but never shows anything secret.
	list, err := f.store.ListCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range list {
		found = found || c.PubKey == pubA
	}
	if !found {
		t.Error("the bound key is not on the credential")
	}
}

// A signed host does not go back in time (a captured result cannot be replayed), a retry of its latest
// scan still succeeds, and verification finds what was changed behind the server's back.
func TestSignedReplayAndTampering(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	key := filepath.Join(t.TempDir(), "k")
	if _, err := signing.Generate(key); err != nil {
		t.Fatal(err)
	}
	web := fixture(t, "web-01.json")
	doc := func(n int) []byte {
		out := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "replayed"`))
		return laterScan(bytes.ReplaceAll(out, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(fmt.Sprintf("r-%d", n))), n)
	}
	for _, n := range []int{1, 2, 3} {
		k, s := signedDoc(t, key, doc(n))
		if code, out := postSigned(t, f, ingest, doc(n), k, s); code != http.StatusCreated {
			t.Fatalf("scan %d: %d %v", n, code, out)
		}
	}
	// An older signed result (one captured earlier) is refused; the latest one sent again is a retry.
	k, s := signedDoc(t, key, doc(2))
	if code, out := postSigned(t, f, ingest, laterScan(doc(2), 2), k, s); code != http.StatusOK {
		t.Errorf("a retry of an earlier scan that is stored: %d %v", code, out)
	}
	old := bytes.ReplaceAll(doc(1), []byte("r-1"), []byte("r-0"))
	k, s = signedDoc(t, key, old)
	if code, out := postSigned(t, f, ingest, old, k, s); code != http.StatusConflict || !strings.Contains(out["error"].(string), "newer") {
		t.Errorf("a replayed older result: %d %v", code, out)
	}
	k, s = signedDoc(t, key, doc(3))
	if code, out := postSigned(t, f, ingest, doc(3), k, s); code != http.StatusOK {
		t.Errorf("a retry of the latest: %d %v", code, out)
	}

	ctx := context.Background()
	if rep, err := f.store.VerifySignatures(ctx); err != nil || !rep.OK() || rep.Signed != 3 {
		t.Fatalf("verify: %+v %v", rep, err)
	}
	var id, host int64
	if err := f.store.db.QueryRow(`SELECT s.id, s.host_row FROM scans s JOIN hosts h ON h.id = s.host_row WHERE h.name = 'replayed' ORDER BY s.id LIMIT 1`).Scan(&id, &host); err != nil {
		t.Fatal(err)
	}
	// The controls the dashboard shows are changed, the document is not.
	if _, err := f.store.db.Exec(`UPDATE scan_controls SET status = 'PASS' WHERE scan_row = ?`, id); err != nil {
		t.Fatal(err)
	}
	if rep, _ := f.store.VerifySignatures(ctx); len(rep.Derived) != 1 || rep.Derived[0] != id {
		t.Errorf("changed controls went unnoticed: %+v", rep)
	}
	// A scan moved to another host.
	var other int64
	if err := f.store.db.QueryRow(`SELECT id FROM hosts WHERE id != ? LIMIT 1`, host).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE scans SET host_row = ? WHERE id = ?`, other, id); err != nil {
		t.Fatal(err)
	}
	if rep, _ := f.store.VerifySignatures(ctx); len(rep.Derived) == 0 || rep.OK() {
		t.Errorf("a moved scan went unnoticed: %+v", rep)
	}
	// A scan the server never received: no ingest record accounts for it.
	if _, err := f.store.db.Exec(`UPDATE audit SET digest = 'sha256:00' WHERE action = 'ingest' AND detail LIKE '%r-3'`); err != nil {
		t.Fatal(err)
	}
	if rep, _ := f.store.VerifySignatures(ctx); len(rep.Unrecorded) != 1 {
		t.Errorf("a scan without an ingest record went unnoticed: %+v", rep)
	}
	if _, _, err := f.store.VerifyAudit(ctx); err == nil {
		t.Error("an edited audit row went unnoticed")
	}
}

// A stored scan can be downloaded as the CSV report of `vmsctl scan --format csv`; it needs the same token as the JSON.
func TestScanDocAsCSV(t *testing.T) {
	f := newAPIFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/2?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+f.api)
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if d := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(d, `attachment; filename="vmsctl-web-01-20`) || !strings.HasSuffix(d, `-scan-2.csv"`) {
		t.Errorf("Content-Disposition = %q: the file should say the host and the day", d)
	}
	body := rec.Body.Bytes()
	if !bytes.HasPrefix(body, []byte("\xef\xbb\xbf")) || !bytes.Contains(body, []byte("host,profile,control,title,title_ko,severity,status")) || bytes.Count(body, []byte("\n")) < 3 {
		t.Errorf("not the CSV report: %q", body[:min(120, len(body))])
	}
	if code, _ := f.get(t, f.api, "/api/v1/scans/2?format=xml"); code != http.StatusBadRequest {
		t.Errorf("an unknown format: %d", code)
	}
	if code, body := f.get(t, f.api, "/api/v1/scans/2?format="); code != http.StatusOK || !bytes.Equal(body, fixture(t, "web-01.json")) {
		t.Errorf("an empty format is the JSON result: %d", code)
	}
	if code, _ := f.get(t, f.api, "/api/v1/scans/99?format=csv"); code != http.StatusNotFound {
		t.Errorf("an unknown scan: %d", code)
	}
	if code, _ := f.get(t, "", "/api/v1/scans/2?format=csv"); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
}

// What a host reports is untrusted: a host name or a title that starts a formula must not reach a spreadsheet as one, and the
// name of the download keeps only safe characters, whatever the host called itself.
func TestScanCSVOfAHostileResult(t *testing.T) {
	f := newAPIFixture(t)
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "db-01.json"), &doc); err != nil {
		t.Fatal(err)
	}
	host := doc["host"].(map[string]any)
	host["hostname"] = `=HYPERLINK("http://evil.example/")/../a b"`
	host["hostId"] = strings.Repeat("ab", 16)
	doc["scan"].(map[string]any)["id"] = "hostile-scan"
	for i, c := range doc["controls"].([]any) {
		c.(map[string]any)["title"] = "@SUM(1+1)"
		delete(c.(map[string]any), "titleKo") // the server fills the Korean title in
		if i == 0 {
			c.(map[string]any)["profile"], c.(map[string]any)["id"] = "kisa-2026", "U-01"
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ingest := token(t, f.store, ScopeIngest, "")
	code, out := post(t, f.srv, ingest, raw)
	if code != http.StatusCreated {
		t.Fatalf("the hostile result was not stored: %d %v", code, out)
	}
	var scans struct {
		Scans []struct{ ID int64 } `json:"scans"`
	}
	var hosts struct {
		Hosts []struct {
			ID   int64
			Name string
		} `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?q=HYPERLINK", &hosts)
	if len(hosts.Hosts) != 1 {
		t.Fatalf("hosts = %+v", hosts)
	}
	f.json(t, "/api/v1/hosts/"+itoa(hosts.Hosts[0].ID), &scans)
	if len(scans.Scans) == 0 {
		t.Fatal("no scan stored")
	}
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Config{Store: f.store, Rate: 100000, Now: func() time.Time { return f.clock }, Content: content})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+itoa(scans.Scans[0].ID)+"?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+f.api)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if d := rec.Header().Get("Content-Disposition"); strings.ContainsAny(strings.TrimSuffix(strings.TrimPrefix(d, `attachment; filename="`), `"`), `"/\ =(),:;`) {
		t.Errorf("the file name keeps unsafe characters: %q", d)
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(rec.Body.Bytes(), []byte("\xef\xbb\xbf")))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for r, row := range rows {
		for c, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("row %d column %d starts a formula: %q", r, c, cell)
			}
		}
	}
	if len(rows) < 2 || rows[1][0] != `'=HYPERLINK("http://evil.example/")/../a b"` || rows[1][3] != "'@SUM(1+1)" {
		t.Errorf("the first row = %q", rows[1])
	}
	if rows[1][2] != "U-01" || rows[1][4] == "" {
		t.Errorf("a control that came without a Korean title gets the server's, as in the dashboard: %q", rows[1])
	}
}
