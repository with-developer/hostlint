package server_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/push"
	"github.com/with-developer/hostlint/internal/server"
)

// The client sends a result to a real TLS server, trusting its public key by pin.
func TestPushEndToEnd(t *testing.T) {
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := server.New(server.Config{Store: store, Now: func() time.Time { return time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC) }})
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	leaf, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pin := server.SPKIPin(leaf)
	tok, _, err := store.CreateCredential(context.Background(), server.ScopeIngest, "web", "web-01", 0)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(filepath.Join("..", "output", "testdata", "report", "web-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := push.Send(ctx, doc, push.Options{URL: ts.URL, Token: tok}); err == nil {
		t.Error("a self-signed server was trusted without a pin")
	}
	if _, err := push.Send(ctx, doc, push.Options{URL: ts.URL, Token: tok, Pin: "sha256/" + strings.Repeat("A", 43) + "="}); err == nil || !strings.Contains(err.Error(), "does not match --pin") {
		t.Errorf("a wrong pin was accepted: %v", err)
	}
	if _, err := push.Send(ctx, doc, push.Options{URL: ts.URL, Token: "hlt_ing_wrong", Pin: pin}); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("a wrong token: %v", err)
	}
	got, err := push.Send(ctx, doc, push.Options{URL: ts.URL, Token: tok, Pin: pin})
	if err != nil || got.Digest == "" {
		t.Fatalf("send: %v, %+v", err, got)
	}
	// The same result again is a retry: acknowledged, not an error.
	again, err := push.Send(ctx, doc, push.Options{URL: ts.URL, Token: tok, Pin: pin})
	if err != nil || !again.Duplicate || again.Digest != got.Digest {
		t.Errorf("a retry: %v, %+v", err, again)
	}
}

func TestPushRefusesWhatIsUnsafe(t *testing.T) {
	ctx := context.Background()
	for name, o := range map[string]push.Options{
		"plain http to a remote host": {URL: "http://example.org", Token: "t"},
		"not a URL":                   {URL: "example.org", Token: "t"},
		"no token":                    {URL: "https://example.org"},
		"a bad pin":                   {URL: "https://example.org", Token: "t", Pin: "md5/xx"},
	} {
		if _, err := push.Send(ctx, []byte("{}"), o); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A server's error text is shown without control characters.
func TestPushErrorTextHasNoControlCharacters(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("{\"error\": \"bad\\u001b[2J\\nresult\"}"))
	}))
	t.Cleanup(ts.Close)
	_, err := push.Send(context.Background(), []byte("{}"), push.Options{URL: ts.URL, Token: "hlt_ing_x"})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\n") {
		t.Errorf("err = %q", err)
	}
}
