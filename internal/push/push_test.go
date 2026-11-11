package push

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/signing"
)

func opts(url string) Options {
	return Options{URL: url, Token: "hlt_ing_test", Timeout: 5 * time.Second}
}

// The result goes out with the token as a bearer credential, the signature and key of the host, and the job it answers.
func TestSendSendsTheTokenTheSignatureAndTheJob(t *testing.T) {
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/results" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"scan":7,"host":3,"receivedAt":"2026-11-11T00:00:00Z","digest":"sha256:abc"}`)
	}))
	defer srv.Close()
	keyPath := t.TempDir() + "/sign.key"
	pub, err := signing.Generate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	key, err := signing.Load(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	o := opts(srv.URL)
	o.SignKey, o.JobID = key, 42
	doc := []byte(`{"schemaVersion":1}`)
	resp, err := Send(context.Background(), doc, o)
	if err != nil || resp.Scan != 7 || resp.Host != 3 || resp.Duplicate {
		t.Fatalf("%+v %v", resp, err)
	}
	if got.Get("Authorization") != "Bearer hlt_ing_test" || got.Get("Content-Type") != "application/json" || got.Get("X-Hostlint-Job") != "42" {
		t.Errorf("headers = %v", got)
	}
	if string(body) != string(doc) {
		t.Errorf("body = %q", body)
	}
	if got.Get(signing.HeaderKey) != pub || signing.Verify(pub, got.Get(signing.HeaderSignature), doc) != nil {
		t.Errorf("the signature or the key does not match the document: %v", got)
	}
}

// A document the server already has is 200, and says so: a retry is not an error.
func TestSendDuplicateIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"scan":7,"host":3,"receivedAt":"x","digest":"d","duplicate":true}`)
	}))
	defer srv.Close()
	if resp, err := Send(context.Background(), []byte(`{}`), opts(srv.URL)); err != nil || !resp.Duplicate {
		t.Errorf("%+v %v", resp, err)
	}
}

// What the server refuses with is an error that carries its message, on one line: the text is shown on a terminal.
func TestSendRefusalCarriesTheMessageWithoutControlCharacters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"bad token\u001b[2J\nsecond line"}`)
	}))
	defer srv.Close()
	_, err := Send(context.Background(), []byte(`{}`), opts(srv.URL))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusUnauthorized || !strings.Contains(se.Message, "bad token") {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsAny(err.Error(), "\x1b\n") {
		t.Errorf("a control character reached the terminal text: %q", err.Error())
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "not json") }))
	defer srv2.Close()
	if _, err := Send(context.Background(), []byte(`{}`), opts(srv2.URL)); err == nil || !strings.Contains(err.Error(), "not understood") {
		t.Errorf("an answer that is not JSON: %v", err)
	}
}

// The token is only sent over https, or plain http to the machine itself; and not at all without one.
func TestSendRefusesToSendTheTokenInTheClear(t *testing.T) {
	for _, u := range []string{"http://example.org:8443", "http://192.0.2.10", "ftp://example.org", "example.org", "https://", ""} {
		if _, err := Send(context.Background(), []byte(`{}`), opts(u)); err == nil {
			t.Errorf("%q was accepted", u)
		}
	}
	o := opts("https://example.org")
	o.Token = ""
	if _, err := Send(context.Background(), []byte(`{}`), o); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Errorf("no token: %v", err)
	}
}

// A redirect would carry the token elsewhere: it is not followed, and the other server never sees the request.
func TestSendDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v1/results", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, err := Send(context.Background(), []byte(`{}`), opts(srv.URL))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusTemporaryRedirect {
		t.Errorf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Error("the redirect was followed with the token")
	}
}

func pinOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

// A self-signed server is trusted by its pin and by nothing else: a wrong pin fails before anything is sent, and without a
// pin the certificate is checked against the system roots (which do not know the test server).
func TestPinTrustsTheKeyAndNothingElse(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"scan":1,"host":1,"receivedAt":"x","digest":"d"}`)
	}))
	defer srv.Close()
	o := opts(srv.URL)
	o.Pin = pinOf(t, srv)
	if _, err := Send(context.Background(), []byte(`{}`), o); err != nil {
		t.Fatalf("the right pin: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
	wrong := sha256.Sum256([]byte("another key"))
	o.Pin = "sha256/" + base64.StdEncoding.EncodeToString(wrong[:])
	if _, err := Send(context.Background(), []byte(`{}`), o); err == nil || !strings.Contains(err.Error(), "does not match --pin") {
		t.Errorf("the wrong pin: %v", err)
	}
	o.Pin = ""
	if _, err := Send(context.Background(), []byte(`{}`), o); err == nil {
		t.Error("a self-signed certificate was trusted without a pin")
	}
	if hits.Load() != 1 {
		t.Errorf("a request reached the server through a connection that failed its check: %d hits", hits.Load())
	}
}

func TestParsePin(t *testing.T) {
	good := "sha256/" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if b, err := parsePin(good); err != nil || len(b) != sha256.Size {
		t.Errorf("%v", err)
	}
	for _, bad := range []string{"", "sha256/", "sha256/!!!", "sha1/" + base64.StdEncoding.EncodeToString(make([]byte, 20)), base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)), "sha256/" + base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := parsePin(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	o := opts("https://example.org")
	o.Pin = "sha256/x"
	if _, err := Send(context.Background(), []byte(`{}`), o); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("a pin that is not a hash is refused before connecting: %v", err)
	}
}

// serverAnswering is a server whose /api/v1/agent/poll answers with the status and body given, and which records the allowed
// profiles it was sent; /api/v1/agent/jobs/9/fail answers 200 for the one reason the test sends, and 404 otherwise.
func serverAnswering(t *testing.T, status int, body string, allowed *[]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Allow []string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if allowed != nil {
			*allowed = in.Allow
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("POST /api/v1/agent/jobs/{id}/fail", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Error string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.PathValue("id") != "9" || in.Error != "the profile is not allowed" {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestPollAnswers(t *testing.T) {
	ctx := context.Background()
	var allowed []string
	srv := serverAnswering(t, http.StatusNoContent, "", &allowed)
	if job, err := Poll(ctx, opts(srv.URL), []string{"kisa-2026", "essentials"}); job != nil || err != nil {
		t.Errorf("no job: %+v %v", job, err)
	}
	if len(allowed) != 2 || allowed[0] != "kisa-2026" || allowed[1] != "essentials" {
		t.Errorf("the allowed profiles went out as %v", allowed)
	}
	for name, tc := range map[string]struct {
		status  int
		body    string
		wantJob bool
		wantErr string
	}{
		"a job":                {http.StatusOK, `{"job":{"id":9,"profile":"kisa-2026"}}`, true, ""},
		"a job without an ID":  {http.StatusOK, `{"job":{"id":0,"profile":"x"}}`, false, "not understood"},
		"no job in the answer": {http.StatusOK, `{}`, false, "not understood"},
		"not JSON":             {http.StatusOK, `nope`, false, "not understood"},
		"a refusal":            {http.StatusForbidden, `{"error":"an operator token is not an agent"}`, false, "403"},
	} {
		srv := serverAnswering(t, tc.status, tc.body, nil)
		job, err := Poll(ctx, opts(srv.URL), []string{"kisa-2026"})
		switch {
		case tc.wantJob && (err != nil || job == nil || job.ID != 9 || job.Profile != "kisa-2026"):
			t.Errorf("%s: %+v %v", name, job, err)
		case !tc.wantJob && (job != nil || err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: %+v %v", name, job, err)
		}
	}
}

func TestFailJob(t *testing.T) {
	srv := serverAnswering(t, http.StatusNoContent, "", nil)
	if err := FailJob(context.Background(), opts(srv.URL), 9, "the profile is not allowed"); err != nil {
		t.Errorf("FailJob: %v", err)
	}
	var se *StatusError
	if err := FailJob(context.Background(), opts(srv.URL), 10, "x"); !errors.As(err, &se) || se.Status != http.StatusNotFound {
		t.Errorf("a refused FailJob is an error with the status: %v", err)
	}
}
