// Package push sends a scan result to a hostlint server (ADR 0010). It is the only
// part of hostlint that makes a network connection, and only when the user runs
// `hostlint push`: scanning never does.
package push

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options say where to send a result and how to trust the server.
type Options struct {
	// URL is the server's base URL, such as https://hostlint.example.org:8443.
	URL string
	// Token is the ingest token.
	Token string
	// Pin is a public key pin ("sha256/<base64>", as the server prints it) that replaces the
	// check of the server certificate against the system roots: for a self-signed server.
	Pin string
	// Timeout of the whole request; 30 seconds when 0.
	Timeout time.Duration
}

// Response is what the server answers to an accepted result.
type Response struct {
	Scan       int64  `json:"scan"`
	Host       int64  `json:"host"`
	ReceivedAt string `json:"receivedAt"`
	Digest     string `json:"digest"`
}

// Send posts a result document. A response other than 201 is an error carrying the
// server's message.
func Send(ctx context.Context, doc []byte, opts Options) (*Response, error) {
	u, err := url.Parse(strings.TrimRight(opts.URL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("%q is not a server URL (use https://host:port)", opts.URL)
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return nil, errors.New("a token is only sent over https (plain http only to a loopback address)")
	}
	if opts.Token == "" {
		return nil, errors.New("no token: set HOSTLINT_TOKEN or use --token-file")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // a redirect would carry the token elsewhere
	}}
	if opts.Pin != "" {
		want, err := parsePin(opts.Pin)
		if err != nil {
			return nil, err
		}
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The pin replaces the chain check: the server's own key is what is trusted.
			InsecureSkipVerify: true, //nolint:gosec // verified by VerifyConnection against the pin
			// VerifyConnection runs on every connection, resumed or not.
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("the server sent no certificate")
				}
				leaf := cs.PeerCertificates[0]
				if sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo); !bytes.Equal(sum[:], want) {
					return errors.New("the server's public key does not match --pin")
				}
				return nil
			},
		}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+"/api/v1/results", bytes.NewReader(doc))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return nil, fmt.Errorf("the server answered %d: %s", resp.StatusCode, msg)
	}
	var out Response
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("the server's answer is not understood: %w", err)
	}
	return &out, nil
}

func parsePin(pin string) ([]byte, error) {
	b64, ok := strings.CutPrefix(pin, "sha256/")
	if !ok {
		return nil, errors.New(`--pin looks like "sha256/<base64>", as the server prints it`)
	}
	sum, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sum) != sha256.Size {
		return nil, errors.New("--pin is not a SHA-256 value in base64")
	}
	return sum, nil
}

func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
