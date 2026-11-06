package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "output", "testdata", "report", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return New(Config{Store: store, Now: func() time.Time { return testNow }}), store
}

func token(t *testing.T, store *Store, scope, bound string) string {
	t.Helper()
	tok, _, err := store.CreateCredential(context.Background(), scope, "test", bound, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func post(t *testing.T, srv *Server, tok string, body []byte) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/results", bytes.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func count(t *testing.T, store *Store, query string) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestIngestStoresTheResult(t *testing.T) {
	srv, store := newTestServer(t)
	tok := token(t, store, ScopeIngest, "web-01")
	code, out := post(t, srv, tok, fixture(t, "web-01.json"))
	if code != http.StatusCreated || out["digest"] == nil {
		t.Fatalf("status %d: %v", code, out)
	}
	for q, want := range map[string]int{
		`SELECT COUNT(*) FROM hosts`:                       1,
		`SELECT COUNT(*) FROM scans`:                       1,
		`SELECT COUNT(*) FROM scan_controls`:               5,
		`SELECT COUNT(*) FROM scan_checks`:                 3, // FAIL, ERROR and MANUAL; PASS and N/A are in the document
		`SELECT COUNT(*) FROM audit WHERE action='ingest'`: 1,
	} {
		if got := count(t, store, q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	// The stored document is the one received.
	var doc []byte
	if err := store.db.QueryRow(`SELECT doc FROM scans`).Scan(&doc); err != nil || len(doc) == 0 {
		t.Fatalf("doc: %v", err)
	}
	if rows, _, err := store.VerifyAudit(context.Background()); err != nil || rows < 2 {
		t.Errorf("audit chain: %d rows, %v", rows, err)
	}
}

func TestIngestRefusals(t *testing.T) {
	srv, store := newTestServer(t)
	bound := token(t, store, ScopeIngest, "web-01")
	wild := token(t, store, ScopeIngest, "")
	api := token(t, store, ScopeAPI, "")
	web := fixture(t, "web-01.json")

	tests := []struct {
		name string
		tok  string
		body []byte
		want int
	}{
		{"no token", "", web, http.StatusUnauthorized},
		{"unknown token", "hlt_ing_nope", web, http.StatusUnauthorized},
		{"a read token cannot ingest", api, web, http.StatusUnauthorized},
		{"not a result", bound, []byte("<html>"), http.StatusUnprocessableEntity},
		{"a token for another host", bound, fixture(t, "db-01.json"), http.StatusConflict},
		{"too large", wild, append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), DefaultMaxBody)...), http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code, out := post(t, srv, tt.tok, tt.body); code != tt.want {
				t.Errorf("status %d (%v), want %d", code, out, tt.want)
			}
		})
	}
	if n := count(t, store, `SELECT COUNT(*) FROM scans`); n != 0 {
		t.Errorf("%d scans stored from refused requests", n)
	}
	// Refusals of a request with a valid token are audited; those without one are not (anyone could
	// fill the table).
	if n := count(t, store, `SELECT COUNT(*) FROM audit WHERE action LIKE 'reject%'`); n != 3 {
		t.Errorf("%d refusals audited, want 3 (not a result, another host, too large)", n)
	}
}

// A result is stored once per host: a replay is refused. A known name with another host ID
// is not merged, and a token bound to a host pins the host ID at its first use.
func TestIngestReplayAndIdentity(t *testing.T) {
	srv, store := newTestServer(t)
	web := fixture(t, "web-01.json")
	variant := func(hostID, scanID string) []byte {
		out := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "web-01", "hostId": "`+hostID+`"`))
		return bytes.ReplaceAll(out, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte(scanID))
	}
	if bytes.Equal(variant("a", "x"), web) {
		t.Fatal("the fixture does not hold the text this test edits")
	}

	wild := token(t, store, ScopeIngest, "")
	if code, _ := post(t, srv, wild, variant("aaaa", "scan-1")); code != http.StatusCreated {
		t.Fatalf("first: %d", code)
	}
	// The same document again is a retry: acknowledged, not stored twice.
	if code, out := post(t, srv, wild, variant("aaaa", "scan-1")); code != http.StatusOK || out["duplicate"] != true {
		t.Errorf("retry: %d %v", code, out)
	}
	if n := count(t, store, `SELECT COUNT(*) FROM scans`); n != 1 {
		t.Errorf("%d scans after a retry, want 1", n)
	}
	// Another document under the same scan ID is a conflict.
	changed := bytes.ReplaceAll(variant("aaaa", "scan-1"), []byte(`"SSH does not allow direct root login"`), []byte(`"edited"`))
	if bytes.Equal(changed, variant("aaaa", "scan-1")) {
		t.Fatal("the fixture does not hold the text this test edits")
	}
	if code, out := post(t, srv, wild, changed); code != http.StatusConflict || !strings.Contains(out["error"].(string), "different content") {
		t.Errorf("scan ID reused with other content: %d %v", code, out)
	}
	if code, out := post(t, srv, wild, variant("aaaa", "scan-2")); code != http.StatusCreated {
		t.Errorf("a new scan of the same host: %d %v", code, out)
	}
	if code, out := post(t, srv, wild, variant("bbbb", "scan-3")); code != http.StatusConflict || !strings.Contains(out["error"].(string), "another host ID") {
		t.Errorf("a known name with another host ID: %d %v", code, out)
	}
	if n := count(t, store, `SELECT COUNT(*) FROM hosts`); n != 1 {
		t.Errorf("%d hosts, want 1", n)
	}

	// A bound token pins the host ID at its first use.
	srv2, store2 := newTestServer(t)
	bound := token(t, store2, ScopeIngest, "web-01")
	if code, _ := post(t, srv2, bound, variant("cccc", "scan-4")); code != http.StatusCreated {
		t.Fatalf("bound token, first use: %d", code)
	}
	if code, out := post(t, srv2, bound, variant("dddd", "scan-5")); code != http.StatusConflict || !strings.Contains(out["error"].(string), "first used") {
		t.Errorf("bound token, another host ID: %d %v", code, out)
	}
}

// A start time the server cannot believe is refused.
func TestIngestStartTime(t *testing.T) {
	srv, store := newTestServer(t)
	tok := token(t, store, ScopeIngest, "")
	for name, ts := range map[string]string{"future": "2026-11-03T00:10:00Z", "ancient": "2024-01-01T00:00:00Z"} {
		body := bytes.ReplaceAll(fixture(t, "web-01.json"), []byte(`"startedAt": "2026-11-02T12:00:00Z"`), []byte(`"startedAt": "`+ts+`"`))
		if code, out := post(t, srv, tok, body); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestTokenLifecycle(t *testing.T) {
	_, store := newTestServer(t)
	ctx := context.Background()
	tok, id, err := store.CreateCredential(ctx, ScopeIngest, "web", "web-01", time.Hour)
	if err != nil || !strings.HasPrefix(tok, "hlt_ing_") || len(tok) < 40 {
		t.Fatalf("token %q: %v", tok, err)
	}
	if _, err := store.Authenticate(ctx, tok, ScopeIngest); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if _, err := store.Authenticate(ctx, tok, ScopeAPI); err == nil {
		t.Error("a token worked for another scope")
	}
	// Only its hash is stored.
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE hash = ? OR prefix = ?`, tok, tok).Scan(&n); err != nil || n != 0 {
		t.Errorf("the token is stored in clear: %d, %v", n, err)
	}
	list, err := store.ListCredentials(ctx)
	if err != nil || len(list) != 1 || list[0].LastUsedAt == "" || len(list[0].Prefix) > 16 {
		t.Errorf("list = %+v, %v", list, err)
	}
	// It expires.
	store.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := store.Authenticate(ctx, tok, ScopeIngest); err == nil {
		t.Error("an expired token worked")
	}
	store.now = time.Now
	if ok, err := store.RevokeCredential(ctx, id); !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if _, err := store.Authenticate(ctx, tok, ScopeIngest); err == nil {
		t.Error("a revoked token worked")
	}
	if ok, _ := store.RevokeCredential(ctx, id); ok {
		t.Error("a token was revoked twice")
	}
	if _, _, err := store.CreateCredential(ctx, "root", "x", "", 0); err == nil {
		t.Error("an unknown scope was accepted")
	}
}

func TestRateLimit(t *testing.T) {
	store, _ := OpenStore(":memory:")
	t.Cleanup(func() { _ = store.Close() })
	srv := New(Config{Store: store, Rate: 2, Now: func() time.Time { return testNow }})
	tok := token(t, store, ScopeIngest, "")
	codes := map[int]int{}
	for range 4 {
		code, _ := post(t, srv, tok, []byte("{}"))
		codes[code]++
	}
	if codes[http.StatusTooManyRequests] != 2 {
		t.Errorf("codes = %v, want two 429", codes)
	}
}

// Changing or removing an audit row breaks the chain.
func TestAuditChainDetectsTampering(t *testing.T) {
	srv, store := newTestServer(t)
	tok := token(t, store, ScopeIngest, "")
	post(t, srv, tok, fixture(t, "web-01.json"))
	post(t, srv, "", nil)
	ctx := context.Background()
	if _, _, err := store.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE audit SET detail = 'nothing happened' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.VerifyAudit(ctx); err == nil {
		t.Error("an edited audit row went unnoticed")
	}
}

func TestHealthzAndHeaders(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != 200 || rec.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("%d %v", rec.Code, rec.Header())
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	for range 2 {
		s, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
	}
}

func TestPlainHTTPOnlyOnLoopback(t *testing.T) {
	srv, _ := newTestServer(t)
	err := srv.Serve(context.Background(), ListenConfig{Addr: "0.0.0.0:0", PlainHTTP: true}, nil)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("err = %v", err)
	}
}

// A host that first sent no ID and later sends one is the same host.
func TestHostIDIsAdoptedByTheNameKnownWithout(t *testing.T) {
	srv, store := newTestServer(t)
	wild := token(t, store, ScopeIngest, "")
	web := fixture(t, "web-01.json")
	if code, _ := post(t, srv, wild, web); code != http.StatusCreated {
		t.Fatalf("without an ID: %d", code)
	}
	with := bytes.ReplaceAll(web, []byte(`"hostname": "web-01"`), []byte(`"hostname": "web-01", "hostId": "aaaa"`))
	with = bytes.ReplaceAll(with, []byte(`019a43c2-6f0e-7b51-9b5f-3c2e8d1a4f10`), []byte("scan-2"))
	if code, out := post(t, srv, wild, with); code != http.StatusCreated {
		t.Fatalf("with an ID: %d %v", code, out)
	}
	if n := count(t, store, `SELECT COUNT(*) FROM hosts`); n != 1 {
		t.Errorf("%d host rows, want 1", n)
	}
	if n := count(t, store, `SELECT COUNT(*) FROM hosts WHERE host_id = 'aaaa'`); n != 1 {
		t.Errorf("the host did not take the ID")
	}
}

// Text that would forge a log line is refused, not stored.
func TestIngestRefusesUnprintableIdentifiers(t *testing.T) {
	srv, store := newTestServer(t)
	wild := token(t, store, ScopeIngest, "")
	body := bytes.ReplaceAll(fixture(t, "web-01.json"), []byte(`"hostname": "web-01"`), []byte(`"hostname": "web-01\nINFO forged"`))
	if code, out := post(t, srv, wild, body); code != http.StatusUnprocessableEntity {
		t.Errorf("%d %v", code, out)
	}
	if n := count(t, store, `SELECT COUNT(*) FROM hosts`); n != 0 {
		t.Errorf("%d hosts stored", n)
	}
}

// Anyone can send requests with a bad token; they are throttled and leave nothing in the database.
func TestBadTokensAreThrottledAndNotAudited(t *testing.T) {
	store, _ := OpenStore(":memory:")
	t.Cleanup(func() { _ = store.Close() })
	srv := New(Config{Store: store, Rate: 5, Now: func() time.Time { return testNow }})
	codes := map[int]int{}
	for range 30 {
		code, _ := post(t, srv, "hlt_ing_nope", []byte("{}"))
		codes[code]++
	}
	if codes[http.StatusUnauthorized] != 10 || codes[http.StatusTooManyRequests] != 20 {
		t.Errorf("codes = %v, want 10 x 401 then 429", codes)
	}
	if n := count(t, store, `SELECT COUNT(*) FROM audit`); n != 0 {
		t.Errorf("%d audit rows from bad requests", n)
	}
}

// The database holds the raw results of the fleet: it is created private, and one that others can read is refused.
func TestDatabaseFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO hosts (name, created_at) VALUES ('a', 'x')`); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	for _, name := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(name)
		if err != nil {
			continue // the WAL files are removed when the last connection closes
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %04o", name, fi.Mode().Perm())
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "can be read by other users") {
		t.Errorf("a world-readable database was opened: %v", err)
	}
}
