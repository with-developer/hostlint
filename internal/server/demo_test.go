package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/server"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

func seeded(t *testing.T) (*server.Server, string) {
	t.Helper()
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	n, err := server.SeedDemo(context.Background(), store, content, "kisa-2026", now)
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("only %d demo results", n)
	}
	srv := server.New(server.Config{Store: store, Rate: 100000, Now: func() time.Time { return now }})
	tok, _, err := store.CreateCredential(context.Background(), server.ScopeAPI, "t", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return srv, tok
}

func TestDemoFleetShowsWhatTheDashboardIsFor(t *testing.T) {
	srv, tok := seeded(t)
	get := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	overview := get("/api/v1/overview")
	for _, want := range []string{`"hosts":12`, `"hostsStale":1`, `"recentRegressions":[{`, `"topFailing":[{`} {
		if !strings.Contains(overview, want) {
			t.Errorf("overview lacks %s:\n%.600s", want, overview)
		}
	}
	// Every kind of status is there, so every color of the dashboard is used.
	hosts := get("/api/v1/hosts?limit=500")
	for _, want := range []string{`"FAIL"`, `"PASS"`, `"MANUAL"`, `"NOT_APPLICABLE"`, `"ERROR"`, `"name":"batch-01"`, `"stale":true`, `"signed":true`, `"keyFingerprint":"SHA256:`} {
		if !strings.Contains(hosts, want) {
			t.Errorf("hosts lack %s", want)
		}
	}
	// A host with a history has scans to compare.
	if !strings.Contains(get("/api/v1/hosts/1"), `"scans":[{`) {
		t.Error("no history for the first host")
	}
}

// The same inputs give the same fleet: a demo is reproducible.
func TestDemoIsDeterministic(t *testing.T) {
	a, ta := seeded(t)
	b, tb := seeded(t)
	fetch := func(srv *server.Server, tok string) string {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/matrix", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if fetch(a, ta) != fetch(b, tb) {
		t.Error("two demo fleets differ")
	}
}

func TestDemoUnknownProfile(t *testing.T) {
	content, _ := engine.Load(rules.FS, profiles.FS)
	store, _ := server.OpenStore(":memory:")
	t.Cleanup(func() { _ = store.Close() })
	if _, err := server.SeedDemo(context.Background(), store, content, "nope", time.Now()); err == nil {
		t.Error("an unknown profile was accepted")
	}
}
