// Package push sends a scan result to a vmsctl server (ADR 0010). It is the only
// part of vmsctl that makes a network connection, and only when the user runs
// `vmsctl push`: scanning never does.
package push

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/with-developer/vmsctl/internal/signing"
)

// Options say where to send a result and how to trust the server.
type Options struct {
	// URL is the server's base URL, such as https://vmsctl.example.org:8443.
	URL string
	// Token is the ingest token.
	Token string
	// Pin is a public key pin ("sha256/<base64>", as the server prints it) that replaces the
	// check of the server certificate against the system roots: for a self-signed server.
	Pin string
	// SignKey, when set, signs the document: the server keeps the signature and key, and refuses
	// later results of the host that are unsigned or signed with another key.
	SignKey ed25519.PrivateKey
	// Timeout of the whole request; 30 seconds when 0 (45 for a poll).
	Timeout time.Duration
	// JobID, when set, says that the result answers this job of the agent (ADR 0014).
	JobID int64
}

// Response is what the server answers to an accepted result.
type Response struct {
	Scan       int64  `json:"scan"`
	Host       int64  `json:"host"`
	ReceivedAt string `json:"receivedAt"`
	Digest     string `json:"digest"`
	// Duplicate is true when the server had this very document already: a retry.
	Duplicate bool `json:"duplicate"`
}

// Send posts a result document. The server answers 201 for a result it stored and 200 for
// one it already had (a retry is not an error); any other response is an error carrying the
// server's message.
func Send(ctx context.Context, doc []byte, opts Options) (*Response, error) {
	base, client, err := connect(opts, 30*time.Second)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/results", bytes.NewReader(doc))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.Token)
	req.Header.Set("Content-Type", "application/json")
	if opts.JobID > 0 {
		req.Header.Set("X-Hostlint-Job", strconv.FormatInt(opts.JobID, 10))
	}
	if opts.SignKey != nil {
		sig, key := signing.Sign(opts.SignKey, doc)
		req.Header.Set(signing.HeaderSignature, sig)
		req.Header.Set(signing.HeaderKey, key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, serverError(resp.StatusCode, body)
	}
	var out Response
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("the server's answer is not understood: %w", err)
	}
	return &out, nil
}

// connect checks the options and makes the client that talks to the server: no redirects, and the pin when given.
func connect(opts Options, defaultTimeout time.Duration) (string, *http.Client, error) {
	u, err := url.Parse(strings.TrimRight(opts.URL, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", nil, fmt.Errorf("%q is not a server URL (use https://host:port)", opts.URL)
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return "", nil, errors.New("a token is only sent over https (plain http only to a loopback address)")
	}
	if opts.Token == "" {
		return "", nil, errors.New("no token: set VMSCTL_TOKEN or use --token-file")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // a redirect would carry the token elsewhere
	}}
	if opts.Pin != "" {
		want, err := parsePin(opts.Pin)
		if err != nil {
			return "", nil, err
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
	return u.String(), client, nil
}

// serverError turns a refusal into an error carrying the server's message.
func serverError(status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	// Text from the server is shown on a terminal: no control characters.
	msg = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, msg)
	return &StatusError{Status: status, Message: msg}
}

// StatusError is a refusal by the server.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("the server answered %d: %s", e.Status, e.Message)
}

// Job is a request of the server to the agent: scan now, with this profile.
type Job struct {
	ID      int64  `json:"id"`
	Profile string `json:"profile"`
}

// Poll asks the server for a job and waits for one for about half a minute (a long poll). It says which profiles
// the agent allows. It returns nil with no error when there was none; the caller polls again.
func Poll(ctx context.Context, opts Options, allow []string) (*Job, error) {
	base, client, err := connect(opts, 45*time.Second)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string][]string{"allow": allow})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/agent/poll", bytes.NewReader(body))
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
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var out struct {
			Job *Job `json:"job"`
		}
		if err := json.Unmarshal(data, &out); err != nil || out.Job == nil || out.Job.ID < 1 {
			return nil, errors.New("the server's job is not understood")
		}
		return out.Job, nil
	default:
		return nil, serverError(resp.StatusCode, data)
	}
}

// FailJob tells the server the agent could not do a job.
func FailJob(ctx context.Context, opts Options, id int64, reason string) error {
	base, client, err := connect(opts, 30*time.Second)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"error": reason})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/agent/jobs/%d/fail", base, id), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+opts.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return serverError(resp.StatusCode, data)
	}
	return nil
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
