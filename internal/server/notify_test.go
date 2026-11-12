package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type hookSink struct {
	mu     sync.Mutex
	events []Event
	status int
	sigs   []string
	bodies [][]byte
}

func (h *hookSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.status != 0 && h.status != 200 {
		w.WriteHeader(h.status)
		return
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err == nil {
		h.events = append(h.events, ev)
	}
	h.sigs = append(h.sigs, r.Header.Get(HeaderWebhookSignature))
	h.bodies = append(h.bodies, body)
}

func (h *hookSink) take() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.events
	h.events = nil
	return out
}

func TestNotifierReportsRegressionsAndSilentHostsOnce(t *testing.T) {
	sink := &hookSink{}
	ts := httptest.NewServer(sink)
	defer ts.Close()

	f := &apiFixture{clock: testNow}
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f.store = store
	store.now = func() time.Time { return f.clock }
	f.srv = New(Config{Store: store, Rate: 100000, Now: func() time.Time { return f.clock }})
	ingest := token(t, store, ScopeIngest, "")

	secret := []byte("s3cret")
	n := &Notifier{Store: store, Hook: &Webhook{URL: ts.URL, Secret: secret}, StaleAfter: 7 * 24 * time.Hour}
	ctx := context.Background()
	if err := n.Tick(ctx); err != nil { // an empty database: the cursor is set
		t.Fatal(err)
	}
	for _, name := range []string{"web-01-old.json", "web-01.json", "db-01.json"} {
		if code, out := post(t, f.srv, ingest, fixture(t, name)); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		f.clock = f.clock.Add(time.Hour)
	}
	// A webhook that is down gets the event when it is back: the cursor stays where it was.
	sink.mu.Lock()
	sink.status = 500
	sink.mu.Unlock()
	if err := n.Tick(ctx); err == nil {
		t.Fatal("a failing webhook was not reported")
	}
	sink.mu.Lock()
	sink.status = 0
	sink.mu.Unlock()
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	evs := sink.take()
	if len(evs) != 1 || evs[0].Event != "regression" || evs[0].Host != "web-01" || len(evs[0].Regressed) == 0 {
		t.Fatalf("events = %+v", evs)
	}
	if !strings.Contains(evs[0].Text, "web-01") || strings.Contains(string(sink.bodies[0]), "evidence") {
		t.Errorf("text %q, body %s", evs[0].Text, sink.bodies[0])
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(sink.bodies[0])
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); sink.sigs[0] != want {
		t.Errorf("signature %q, want %q", sink.sigs[0], want)
	}
	// Nothing is reported twice.
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := sink.take(); len(evs) != 0 {
		t.Errorf("reported again: %+v", evs)
	}

	// Silent hosts: once per latest scan.
	f.clock = f.clock.Add(8 * 24 * time.Hour)
	sink.mu.Lock()
	sink.status = 503
	sink.mu.Unlock()
	if err := n.Tick(ctx); err == nil || !strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), ts.URL) {
		t.Errorf("a failing webhook: %v", err)
	}
	sink.mu.Lock()
	sink.status = 0
	sink.mu.Unlock()
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	evs = sink.take()
	if len(evs) != 2 {
		t.Fatalf("silent: %+v", evs)
	}
	for _, e := range evs {
		if e.Event != "stale" || e.LastScan == "" {
			t.Errorf("event %+v", e)
		}
	}
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := sink.take(); len(evs) != 0 {
		t.Errorf("silent hosts reported again: %+v", evs)
	}
}

func TestValidateWebhookURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://hooks.example.com/x":   true,
		"http://127.0.0.1:9000/x":       true,
		"http://localhost:9000/x":       true,
		"http://hooks.example.com/x":    false,
		"https://user:pw@example.com/x": false,
		"ftp://example.com/x":           false,
		"not a url":                     false,
		"https:///path":                 false,
	} {
		if err := ValidateWebhookURL(url); (err == nil) != ok {
			t.Errorf("%q: %v", url, err)
		}
	}
}

// Enabling the webhook reports no history, not even the hosts that are silent already; an event the
// webhook refuses for good does not hold back the ones after it; a scan that reuses a deleted row's ID
// is still seen.
func TestNotifierBaselineRejectionAndReusedRows(t *testing.T) {
	sink := &hookSink{}
	ts := httptest.NewServer(sink)
	defer ts.Close()
	f := newAPIFixture(t) // three scans an hour apart, then the clock moves
	ingest := token(t, f.store, ScopeIngest, "")
	f.store.now = func() time.Time { return f.clock }
	n := &Notifier{Store: f.store, Hook: &Webhook{URL: ts.URL}, StaleAfter: 24 * time.Hour}
	ctx := context.Background()

	f.clock = f.clock.Add(10 * 24 * time.Hour) // every host is silent when the webhook is first enabled
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if evs := sink.take(); len(evs) != 0 {
		t.Errorf("history was reported: %+v", evs)
	}

	// The newest scan is deleted with its host, a new scan reuses the row: it is still looked at.
	ingestAt(t, f, ingest, 1, f.clock) // web-01, after the old state
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	sink.take()
	var id int64
	if err := f.store.db.QueryRow(`SELECT MAX(id) FROM scans`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	var host int64
	if err := f.store.db.QueryRow(`SELECT host_row FROM scans WHERE id = ?`, id).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DeleteHost(ctx, host); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(time.Hour)
	for _, name := range []string{"web-01-old.json", "web-01.json"} {
		if code, out := post(t, f.srv, ingest, fixture(t, name)); code != http.StatusCreated {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		f.clock = f.clock.Add(time.Hour)
	}
	// A webhook that refuses the event for good (400) is not asked again, and the next tick is quiet.
	sink.mu.Lock()
	sink.status = 400
	sink.mu.Unlock()
	if err := n.Tick(ctx); err != nil {
		t.Fatalf("a refused event wedged the notifier: %v", err)
	}
	sink.mu.Lock()
	sink.status = 0
	sink.mu.Unlock()
	if err := n.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, e := range sink.take() {
		if e.Event == "regression" {
			t.Errorf("a refused event was sent again: %+v", e)
		}
	}
}

func TestNotifierTextLanguage(t *testing.T) {
	for _, tc := range []struct {
		lang, regression, stale string
	}{
		{"", "vmsctl: web-01 got worse: 2 control(s) now fail (U-01, U-02)", "vmsctl: web-01 has not reported since 2026-11-01"},
		{"en", "vmsctl: web-01 got worse: 2 control(s) now fail (U-01, U-02)", "vmsctl: web-01 has not reported since 2026-11-01"},
		{"ko", "vmsctl: 호스트 web-01에서 점검 항목 2개가 새로 실패했습니다 (U-01, U-02)", "vmsctl: 호스트 web-01의 결과가 2026-11-01 이후 오지 않습니다"},
	} {
		n := &Notifier{Lang: tc.lang}
		if got := n.regressionText("web-01", 2, "U-01, U-02"); got != tc.regression {
			t.Errorf("lang %q regression = %q, want %q", tc.lang, got, tc.regression)
		}
		if got := n.staleText("web-01", "2026-11-01"); got != tc.stale {
			t.Errorf("lang %q stale = %q, want %q", tc.lang, got, tc.stale)
		}
	}
}
