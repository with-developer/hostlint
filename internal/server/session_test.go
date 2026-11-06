package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func login(t *testing.T, f *apiFixture, tok string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"token":"`+tok+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return rec, c
		}
	}
	return rec, nil
}

func (f *apiFixture) getWithCookie(path string, c *http.Cookie, method string) int {
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	return rec.Code
}

func TestLoginSessionLifecycle(t *testing.T) {
	f := newAPIFixture(t)
	rec, c := login(t, f, f.api)
	if rec.Code != http.StatusOK || c == nil {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.MaxAge <= 0 {
		t.Errorf("cookie = %+v", c)
	}
	if strings.Contains(rec.Body.String(), c.Value) {
		t.Error("the cookie value is in the body")
	}
	// Only the hash of the cookie is stored.
	if n := count(t, f.store, `SELECT COUNT(*) FROM sessions WHERE hash = '`+c.Value+`'`); n != 0 {
		t.Error("the cookie value is stored in clear")
	}
	if code := f.getWithCookie("/api/v1/overview", c, http.MethodGet); code != http.StatusOK {
		t.Errorf("overview with the cookie: %d", code)
	}
	if code := f.getWithCookie("/api/v1/session", c, http.MethodGet); code != http.StatusOK {
		t.Errorf("session: %d", code)
	}
	// A cookie never authenticates anything but a GET, and not the ingest route.
	if code := f.getWithCookie("/api/v1/results", c, http.MethodPost); code != http.StatusUnauthorized {
		t.Errorf("POST with a cookie: %d", code)
	}
	// It idles out and expires.
	f.clock = f.clock.Add(9 * time.Hour)
	if code := f.getWithCookie("/api/v1/overview", c, http.MethodGet); code != http.StatusUnauthorized {
		t.Errorf("an idle session: %d", code)
	}
	f.clock = f.clock.Add(-9 * time.Hour)

	// Logout ends it.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(c)
	out := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("logout: %d", out.Code)
	}
	if code := f.getWithCookie("/api/v1/overview", c, http.MethodGet); code != http.StatusUnauthorized {
		t.Errorf("after logout: %d", code)
	}
}

func TestLoginRefusals(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	for name, tok := range map[string]string{"unknown": "hlt_api_nope", "an ingest token": ingest, "empty": ""} {
		if rec, c := login(t, f, tok); rec.Code != http.StatusUnauthorized || c != nil {
			t.Errorf("%s: %d, cookie %v", name, rec.Code, c)
		}
	}
	// A form post (what another site can send without a preflight) is refused.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader("token="+f.api))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form login: %d", rec.Code)
	}
	// Attempts are throttled per address.
	codes := map[int]int{}
	for range 15 {
		rec, _ := login(t, f, "hlt_api_nope")
		codes[rec.Code]++
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Errorf("no throttling: %v", codes)
	}
}

// A session ends with the token that opened it.
func TestSessionEndsWithItsToken(t *testing.T) {
	f := newAPIFixture(t)
	_, c := login(t, f, f.api)
	if c == nil {
		t.Fatal("no cookie")
	}
	var id int64
	if err := f.store.db.QueryRow(`SELECT id FROM credentials WHERE scope = 'api'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.store.RevokeCredential(context.Background(), id); !ok || err != nil {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if code := f.getWithCookie("/api/v1/overview", c, http.MethodGet); code != http.StatusUnauthorized {
		t.Errorf("a session outlived its token: %d", code)
	}
}

func TestSecureCookieFollowsTLS(t *testing.T) {
	f := newAPIFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader([]byte(`{"token":"`+f.api+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Secure {
		t.Errorf("forwarded proto was trusted without --behind-proxy: %+v", c)
	}
	f.srv.cfg.BehindProxy = true
	req = httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader([]byte(`{"token":"`+f.api+`"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, req)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Errorf("behind a TLS proxy the cookie is not Secure: %+v", c)
	}
	tlsReq := httptest.NewRequest(http.MethodPost, "https://example.org/api/v1/login", bytes.NewReader([]byte(`{"token":"`+f.api+`"}`)))
	tlsReq.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(rec, tlsReq)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Errorf("over TLS the cookie is not Secure: %+v", c)
	}
}

func TestDashboardFiles(t *testing.T) {
	store, _ := OpenStore(":memory:")
	t.Cleanup(func() { _ = store.Close() })
	web := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><script src=/assets/app-1a2b.js></script>")},
		"assets/a.js":   {Data: []byte("console.log(1)")},
		"assets/a.css":  {Data: []byte("body{}")},
		"favicon.svg":   {Data: []byte("<svg/>")},
		"secret/../x":   {Data: []byte("x")},
		"assets/b.json": {Data: []byte("{}")},
	}
	srv := New(Config{Store: store, Web: web})
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	if rec := get("/"); rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("/: %d %v", rec.Code, rec.Header())
	}
	// An application route in the browser is the page; a missing file is not.
	if rec := get("/hosts/3"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "<script") {
		t.Errorf("/hosts/3: %d", rec.Code)
	}
	if rec := get("/assets/missing.js"); rec.Code != 404 {
		t.Errorf("a missing asset: %d", rec.Code)
	}
	if rec := get("/assets/a.js"); rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Errorf("asset: %d %v", rec.Code, rec.Header())
	}
	if rec := get("/api/v1/nothing"); rec.Code != 404 || !strings.Contains(rec.Body.String(), "no such endpoint") {
		t.Errorf("unknown api path: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/..%2f..%2fetc/passwd"); rec.Code == 200 && !strings.Contains(rec.Body.String(), "<!doctype") {
		t.Errorf("path traversal: %d %s", rec.Code, rec.Body)
	}
	// Without a dashboard in the build the server says so and still serves the API.
	bare := New(Config{Store: store, Web: nil})
	bare.cfg.Web = nil
	rec := httptest.NewRecorder()
	bare.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "no dashboard") {
		t.Errorf("a build without the dashboard: %d %s", rec.Code, rec.Body)
	}
}
