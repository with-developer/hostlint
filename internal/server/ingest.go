package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/output"
	"github.com/with-developer/hostlint/internal/signing"
)

// Limits on what a host may send (ADR 0010). A full scan of a stock host is about 125 KiB.
const (
	DefaultMaxBody = 2 << 20
	maxControls    = 500
	maxChecks      = 5000
	maxText        = 4096
	maxFuture      = 5 * time.Minute
	maxScanAge     = 400 * 24 * time.Hour
)

// Config configures a Server.
type Config struct {
	Store   *Store
	MaxBody int64 // bytes of one result; DefaultMaxBody when 0
	Logger  *slog.Logger
	// Rate is how many results one token may send per minute (60 when 0).
	Rate int
	// BehindProxy trusts X-Forwarded-Proto from a TLS proxy in front of the server (for the
	// Secure attribute of the session cookie).
	BehindProxy bool
	Now         func() time.Time
	// Content, when set, adds what each control checks and how to fix it (the rule text of
	// the built-in profiles) to the answers about a control.
	Content *engine.Content
	// PollHold is how long an agent's poll waits for a job (25 seconds when 0).
	PollHold time.Duration
	// Web holds the dashboard's files (index.html and assets/). Nil means the build has none
	// and the server answers with the API only; the `web` build tag embeds the real one.
	Web fs.FS
}

// Server handles the HTTP API.
type Server struct {
	cfg     Config
	limiter *limiter
	jobs    jobWaiters
	trends  trendCache
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.MaxBody == 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.Rate == 0 {
		cfg.Rate = 60
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	} else {
		cfg.Store.now = cfg.Now
	}
	if cfg.Web == nil {
		cfg.Web = webAssets()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{cfg: cfg, limiter: newLimiter(cfg.Now)}
}

// Handler returns the HTTP handler of the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/results", s.handleIngest)
	mux.HandleFunc("POST /api/v1/agent/poll", s.handleAgentPoll)
	mux.HandleFunc("POST /api/v1/agent/jobs/{id}/fail", s.handleJobFail)
	mux.HandleFunc("POST /api/v1/hosts/{id}/scan", s.handleScanRequest)
	s.routesRead(mux)
	mux.Handle("GET /{path...}", s.webHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return secure(mux)
}

// secure sets the headers every response carries. The API returns JSON only.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// bearer returns the token of an Authorization: Bearer header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// remote is the client's address. Behind a proxy the peer is the proxy, so the last address the
// proxy added to X-Forwarded-For is used, when the server was told to trust it (--behind-proxy).
func (s *Server) remote(r *http.Request) string {
	if s.cfg.BehindProxy {
		if parts := strings.Split(r.Header.Get("X-Forwarded-For"), ","); len(parts) > 0 {
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return remoteAddr(r)
}

func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	remote := s.remote(r)
	// Requests that have not proven anything are throttled per address, and are logged but
	// not audited: an audit row per bad request would let anyone fill the database.
	if !s.limiter.allow("ip:"+remote, s.cfg.Rate*2) {
		s.cfg.Logger.Warn("request refused", "reason", "address rate limit", "remote", remote)
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many requests from this address")
		return
	}
	cred, err := s.cfg.Store.Authenticate(ctx, bearer(r), ScopeIngest)
	if errors.Is(err, ErrUnauthorized) {
		s.cfg.Logger.Warn("request refused", "reason", "bad token", "remote", remote)
		w.Header().Set("WWW-Authenticate", `Bearer realm="hostlint"`)
		writeError(w, http.StatusUnauthorized, "a valid ingest token is required")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if !s.limiter.allow(fmt.Sprintf("cred:%d", cred.ID), s.cfg.Rate) {
		s.cfg.Logger.Warn("request refused", "reason", "token rate limit", "remote", remote, "credential", cred.ID)
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many results from this token")
		return
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.reject(ctx, cred.ID, remote, "too large", fmt.Sprintf("more than %d bytes", s.cfg.MaxBody))
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("a result may not exceed %d bytes", s.cfg.MaxBody))
			return
		}
		writeError(w, http.StatusBadRequest, "the request body could not be read")
		return
	}
	var opts []IngestOption
	if key, sig := r.Header.Get(signing.HeaderKey), r.Header.Get(signing.HeaderSignature); key != "" || sig != "" {
		if len(key) > 128 || len(sig) > 256 {
			s.reject(ctx, cred.ID, remote, "bad signature", "the signature headers are too long")
			writeError(w, http.StatusBadRequest, "the signature headers are too long")
			return
		}
		if err := signing.Verify(key, sig, raw); err != nil {
			s.reject(ctx, cred.ID, remote, "bad signature", err.Error())
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		opts = append(opts, WithSignature(key, sig))
	}
	res, err := output.ReadResult(bytes.NewReader(raw))
	if err == nil {
		err = checkLimits(res, s.cfg.Now())
	}
	if err != nil {
		s.reject(ctx, cred.ID, remote, "invalid result", err.Error())
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	got, err := s.cfg.Store.IngestScan(ctx, cred, res, raw, remote, opts...)
	switch {
	case errors.Is(err, ErrDuplicate):
		s.reject(ctx, cred.ID, remote, "duplicate", "scan "+res.Scan.ID)
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrIdentity):
		s.reject(ctx, cred.ID, remote, "identity", err.Error())
		writeError(w, http.StatusConflict, err.Error())
	case err != nil:
		s.fail(w, err)
	default:
		// A result that answers a job of the agent says so; the host's own job, and only a claimed one, is finished.
		if v := r.Header.Get("X-Hostlint-Job"); v != "" && !got.Duplicate {
			if id, err := strconv.ParseInt(v, 10, 64); err == nil && id > 0 {
				if err := s.cfg.Store.FinishJob(context.WithoutCancel(ctx), id, got.HostRow, got.ScanRow); err != nil {
					s.cfg.Logger.Error("job", "error", err)
				}
			}
		}
		status := http.StatusCreated
		if got.Duplicate {
			status = http.StatusOK // a retry of a result that was stored: nothing to do again
		}
		writeJSON(w, status, map[string]any{
			"scan": got.ScanRow, "host": got.HostRow, "receivedAt": got.ReceivedAt, "digest": got.Digest, "duplicate": got.Duplicate,
		})
	}
}

// reject records a refused request in the audit table and the log.
func (s *Server) reject(ctx context.Context, credID int64, remote, action, detail string) {
	s.cfg.Logger.Warn("result refused", "reason", action, "remote", remote, "credential", credID)
	if err := s.cfg.Store.Audit(context.WithoutCancel(ctx), credID, remote, "reject: "+action, detail); err != nil {
		s.cfg.Logger.Error("audit", "error", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.cfg.Logger.Error("request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "the server could not complete the request")
}

// checkLimits bounds a result that passed ReadResult, which only checks that it is well formed.
func checkLimits(res *engine.Result, now time.Time) error {
	switch {
	case len(res.Controls) > maxControls:
		return fmt.Errorf("more than %d controls", maxControls)
	case len(res.Checks) > maxChecks:
		return fmt.Errorf("more than %d checks", maxChecks)
	case len(res.Host.Hostname) > 253 || len(res.Host.HostID) > 128 || len(res.Scan.ID) > 128 || len(res.Scan.Tool.Version) > 128:
		return errors.New("a host or scan identifier is too long")
	case res.Scan.ID == "":
		return errors.New("the result has no scan ID")
	}
	// What is shown and logged later must not carry line breaks or escape sequences.
	for what, v := range map[string]string{"host name": res.Host.Hostname, "host ID": res.Host.HostID, "scan ID": res.Scan.ID, "tool version": res.Scan.Tool.Version} {
		if !printable(v) {
			return fmt.Errorf("the %s has characters that are not printable", what)
		}
	}
	for _, c := range res.Controls {
		if len(c.ID) > 64 || len(c.Profile) > 64 || len(c.Title) > maxText || len(c.Reason) > maxText {
			return fmt.Errorf("control %.40q has text that is too long", c.ID)
		}
		if !printable(c.ID) || !printable(c.Profile) {
			return fmt.Errorf("control %.40q has characters that are not printable", c.ID)
		}
	}
	for _, c := range res.Checks {
		if len(c.Ref) > 256 || len(c.Title) > maxText || len(c.Reason) > maxText {
			return fmt.Errorf("check %.40q has text that is too long", c.Ref)
		}
		// The fix hint is shown as guidance: bounded, and text (line breaks and tabs are fine).
		if len(c.Remediation) > maxRemediation || !utf8.ValidString(c.Remediation) || strings.ContainsFunc(c.Remediation, func(r rune) bool { return r != '\n' && r != '\t' && unicode.IsControl(r) }) {
			return fmt.Errorf("check %.40q has a remediation that is too long or not text", c.Ref)
		}
	}
	// The packs a result names are shown on the host's page: a few, short, and text.
	if len(res.Scan.Packs) > maxPacks {
		return fmt.Errorf("the result names %d policy packs, at most %d are kept", len(res.Scan.Packs), maxPacks)
	}
	for _, p := range res.Scan.Packs {
		if len(p.Name) > maxPackText || len(p.Version) > maxPackText || len(p.Digest) > maxPackDigest || !plainText(p.Name) || !plainText(p.Version) || !plainText(p.Digest) {
			return errors.New("a policy pack of the result has a name, version or digest that is too long or not text")
		}
	}
	// The server orders scans by its own clock; a start time far from it is not believed.
	started, err := time.Parse(time.RFC3339, res.Scan.StartedAt)
	if err != nil {
		return errors.New("scan.startedAt is not a timestamp")
	}
	switch {
	case started.After(now.Add(maxFuture)):
		return errors.New("scan.startedAt is in the future")
	case started.Before(now.Add(-maxScanAge)):
		return errors.New("scan.startedAt is older than the server keeps")
	}
	return nil
}

// maxPacks, maxPackText and maxPackDigest bound the packs a received result names.
const (
	maxPacks      = 8
	maxPackText   = 100
	maxPackDigest = 100
)

// maxRemediation bounds the fix hint of a check in a received result (the engine writes at most 1500 bytes).
const maxRemediation = 2000

// printable reports whether s is valid UTF-8 without control characters.
func printable(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// limiter is a token bucket per key (a credential, an address).
type limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

const maxBuckets = 10000

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, buckets: map[string]*bucket{}}
}

// allow takes one of the perMinute results the key may send each minute.
func (l *limiter) allow(key string, perMinute int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.buckets) >= maxBuckets {
		// Forget what is full again; if that is not enough, start over (the table is bounded).
		for k, b := range l.buckets {
			if now.Sub(b.at) > time.Minute {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) >= maxBuckets {
			clear(l.buckets)
		}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(perMinute), at: now}
		l.buckets[key] = b
	}
	// A clock that steps back must not take tokens away.
	b.tokens = min(float64(perMinute), b.tokens+max(0, now.Sub(b.at).Minutes())*float64(perMinute))
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
