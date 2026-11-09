package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

// ListenConfig says where and how the server listens.
type ListenConfig struct {
	Addr string
	// CertFile and KeyFile are the certificate to serve. When both are empty and TLS is
	// not off, a self-signed certificate is made in GeneratedDir (and reused after that).
	CertFile, KeyFile string
	GeneratedDir      string
	// PlainHTTP serves without TLS. Only a loopback address may do so, unless BehindProxy.
	PlainHTTP, BehindProxy bool
}

// SPKIPin is the pin of a certificate's public key, as `vmsctl push --pin` takes it.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(sum[:])
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Serve listens and serves until ctx ends. onReady is called with the address and, when
// TLS is on, the pin of the certificate.
func (s *Server) Serve(ctx context.Context, lc ListenConfig, onReady func(addr, pin string)) error {
	if lc.PlainHTTP && !isLoopback(lc.Addr) && !lc.BehindProxy {
		return errors.New("plain HTTP is only allowed on a loopback address, or behind a TLS proxy with --behind-proxy")
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	pin := ""
	if !lc.PlainHTTP {
		cert, err := loadOrCreateCertificate(lc)
		if err != nil {
			return err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		pin = SPKIPin(leaf)
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	ln, err := net.Listen("tcp", lc.Addr) //nolint:forbidigo // the fleet server listens; scanning packages cannot import this one (ADR 0010)
	if err != nil {
		return err
	}
	if onReady != nil {
		onReady(ln.Addr().String(), pin)
	}
	errc := make(chan error, 1)
	go func() {
		if lc.PlainHTTP {
			errc <- srv.Serve(ln)
		} else {
			errc <- srv.ServeTLS(ln, "", "")
		}
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func loadOrCreateCertificate(lc ListenConfig) (tls.Certificate, error) {
	if lc.CertFile != "" || lc.KeyFile != "" {
		if lc.CertFile == "" || lc.KeyFile == "" {
			return tls.Certificate{}, errors.New("--tls-cert and --tls-key go together")
		}
		return tls.LoadX509KeyPair(lc.CertFile, lc.KeyFile)
	}
	crt, key := lc.GeneratedDir+"/tls.crt", lc.GeneratedDir+"/tls.key"
	if cert, err := tls.LoadX509KeyPair(crt, key); err == nil {
		return cert, nil
	}
	return generateCertificate(lc.Addr, crt, key)
}

// generateCertificate makes a self-signed certificate for the listen address, valid for a year.
func generateCertificate(addr, crtPath, keyPath string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "vmsctl server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsUnspecified() {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			}
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil { //nolint:forbidigo // the server writes its own certificate, not the scanned host
		return tls.Certificate{}, fmt.Errorf("writing the certificate key: %w", err)
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil { //nolint:forbidigo,gosec // the server writes its own public certificate
		return tls.Certificate{}, fmt.Errorf("writing the certificate: %w", err)
	}
	return tls.X509KeyPair(crtPEM, keyPEM)
}
