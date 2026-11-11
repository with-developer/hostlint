package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func readLeaf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The certificate the server makes for itself: its key is private to the owner, it is for serving and nothing else, it
// lasts a year, and it names the address the server listens on (a wildcard address names nobody).
func TestGeneratedCertificate(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, err := generateCertificate("vms.example.org:8443", crt, key); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("the private key is %v, want 0600 (%v)", fi.Mode().Perm(), err)
		}
	}
	c := readLeaf(t, crt)
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("public key %T", c.PublicKey)
	}
	if c.IsCA || c.KeyUsage&x509.KeyUsageCertSign != 0 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("the certificate is for more than serving: CA %v, key usage %v, extended %v", c.IsCA, c.KeyUsage, c.ExtKeyUsage)
	}
	if d := time.Until(c.NotAfter); d < 360*24*time.Hour || d > 366*24*time.Hour {
		t.Errorf("valid for %v", d)
	}
	if c.NotBefore.After(time.Now()) {
		t.Errorf("not valid yet: %v", c.NotBefore)
	}
	names := strings.Join(c.DNSNames, ",")
	if !strings.Contains(names, "localhost") || !strings.Contains(names, "vms.example.org") {
		t.Errorf("DNS names = %v", c.DNSNames)
	}
	has := func(ip string) bool {
		for _, a := range c.IPAddresses {
			if a.Equal(net.ParseIP(ip)) {
				return true
			}
		}
		return false
	}
	if !has("127.0.0.1") || !has("::1") {
		t.Errorf("IP addresses = %v", c.IPAddresses)
	}
	c2 := func(addr string) *x509.Certificate {
		dir := t.TempDir()
		if _, err := generateCertificate(addr, filepath.Join(dir, "c"), filepath.Join(dir, "k")); err != nil {
			t.Fatal(err)
		}
		return readLeaf(t, filepath.Join(dir, "c"))
	}
	for _, a := range c2("0.0.0.0:8443").IPAddresses {
		if a.IsUnspecified() {
			t.Errorf("the certificate names the wildcard address %v", a)
		}
	}
	if got := c2("192.0.2.7:8443"); len(got.IPAddresses) != 3 || !got.IPAddresses[2].Equal(net.ParseIP("192.0.2.7")) {
		t.Errorf("IP addresses = %v", got.IPAddresses)
	}
}

// The certificate is made once and reused (a pin printed at the first start still holds at the next), and given certificate files
// come as a pair.
func TestCertificateIsReusedAndFilesComeInAPair(t *testing.T) {
	dir := t.TempDir()
	lc := ListenConfig{Addr: "127.0.0.1:8443", GeneratedDir: dir}
	first, err := loadOrCreateCertificate(lc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateCertificate(lc)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := x509.ParseCertificate(first.Certificate[0])
	b, _ := x509.ParseCertificate(second.Certificate[0])
	if SPKIPin(a) != SPKIPin(b) {
		t.Error("the certificate changed between two starts: the pin of the first would stop working")
	}
	for _, lc := range []ListenConfig{{CertFile: "a.crt"}, {KeyFile: "a.key"}} {
		if _, err := loadOrCreateCertificate(lc); err == nil || !strings.Contains(err.Error(), "go together") {
			t.Errorf("%+v: %v", lc, err)
		}
	}
}

// The server speaks TLS 1.2 or later with the certificate whose pin it prints, and stops when it is told to.
func TestServeOverTLSWithThePinItPrints(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	type ready struct{ addr, pin string }
	readyc := make(chan ready, 1)
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, ListenConfig{Addr: "127.0.0.1:0", GeneratedDir: t.TempDir()}, func(addr, pin string) { readyc <- ready{addr, pin} })
	}()
	var r ready
	select {
	case r = <-readyc:
	case err := <-done:
		t.Fatalf("Serve ended: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not start")
	}
	if !strings.HasPrefix(r.pin, "sha256/") {
		t.Fatalf("pin = %q", r.pin)
	}
	conn, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	if got := SPKIPin(conn.ConnectionState().PeerCertificates[0]); got != r.pin {
		t.Errorf("the certificate served has pin %s, the server printed %s", got, r.pin)
	}
	_ = conn.Close()
	if old, err := tls.Dial("tcp", r.addr, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}); err == nil {
		_ = old.Close()
		t.Error("a TLS 1.1 connection was accepted")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + r.addr + "/api/v1/overview")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a request without a token: %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve ended with %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the server did not stop")
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:8443": true, "[::1]:8443": true, "localhost:8443": true, "127.5.6.7:1": true,
		"0.0.0.0:8443": false, ":8443": false, "192.0.2.1:8443": false, "example.org:443": false, "nonsense": false} {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v", addr, got)
		}
	}
}
